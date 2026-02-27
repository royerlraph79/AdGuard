#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import requests
from publicsuffix2 import PublicSuffixList
from requests import RequestException

# ============================================================
# Config / Constants
# ============================================================

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
TRAILING_OPTIONS_RE = re.compile(r"\$.*$")
WWW_PREFIX_RE = re.compile(r"^www\d*\.", re.IGNORECASE)

VALID_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

USER_AGENT = "royerlraph79-AdGuardBlocklist/6.0"

DEFAULT_SOURCE_FILE = "sources.txt"
DEFAULT_OUTPUT_BASE = "adguard_blocklist"
DEFAULT_CACHE_FILE = "cache.json"

SAFE_TLD_THRESHOLD = 3
AGGRESSIVE_TLD_THRESHOLD = 2

# Never allow a collapsed token to be one of these.
# (Also avoids garbage like ||lan^, ||local^, etc.)
DO_NOT_COLLAPSE = {
    # Common TLD-ish / suffix-ish tokens
    "com", "net", "org", "edu", "gov", "mil", "int",
    "co", "uk", "ru", "de", "fr", "it", "es", "nl", "be", "ca", "us", "au",
    "jp", "cn", "br", "mx", "in", "ch", "se", "no", "fi", "dk", "ie",
    # Local/reserved
    "lan", "local", "home", "arpa",
    # Generic infra words that are too risky to collapse globally
    "cdn", "static", "img", "api", "www", "mail", "smtp", "ns", "dns",
}

SAFE_KEYWORDS: set[str] = {
    "doubleclick",
    "googlesyndication",
    "adservice",
    "scorecardresearch",
    "taboola",
    "outbrain",
}

# Aggressive but still specific (avoid plain "ads" or "pub")
AGGRESSIVE_EXTRA_KEYWORDS: set[str] = {
    "pubads",
    "pubadx",
    "adserver",
    "adsystem",
    "adsrv",
    "tracking",
    "analytics",
    "telemetry",
    "metrics",
}

# ============================================================
# Logging
# ============================================================

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

# ============================================================
# Helpers
# ============================================================

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

def normalize_token(token: str) -> str:
    """
    Normalize to a strict DNS hostname:
    - lowercase
    - strip scheme/path/query/fragment
    - strip www\d*.
    - strip port
    - reject wildcards, whitelist markers, bad leading chars
    - strict hostname validation
    """
    d = token.strip().lower()
    if not d:
        return ""

    if d.startswith("@@"):
        return ""

    if "*" in d:
        return ""

    if d.startswith(("-", ".", "_")):
        return ""

    # URL parsing if scheme present
    if d.startswith(("http://", "https://")):
        parsed = urlsplit(d)
        d = parsed.hostname or ""
    else:
        # Remove scheme if it sneaked in
        d = SCHEME_RE.sub("", d)
        for sep in ("/", "?", "#"):
            if sep in d:
                d = d.split(sep, 1)[0]

    # Remove port
    if ":" in d:
        d = d.split(":", 1)[0]

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not VALID_HOST_RE.fullmatch(d):
        return ""

    return d

def extract_from_adblock_rule(line: str) -> str:
    ln = line.strip()
    if ln.startswith("@@"):
        return ""
    ln = TRAILING_OPTIONS_RE.sub("", ln)
    m = re.match(r"^\|\|([^\^/]+)", ln)
    return m.group(1) if m else ""

def choose_token(raw_line: str) -> str:
    ln = raw_line.strip()
    ad = extract_from_adblock_rule(ln)
    if ad:
        return ad
    hm = HOSTS_RE.match(ln)
    if hm:
        return hm.group(1)
    return ln.split()[0] if ln else ""

# ============================================================
# Reverse Trie subdomain dedupe
# ============================================================

class DomainTrie:
    def __init__(self) -> None:
        self.root: dict[str, dict] = {}

    def insert(self, domain: str) -> bool:
        node = self.root
        parts = domain.split(".")[::-1]
        for part in parts:
            if "__end__" in node:
                return False
            node = node.setdefault(part, {})
        node["__end__"] = {}
        return True

def remove_redundant_subdomains(domains: Iterable[str]) -> set[str]:
    trie = DomainTrie()
    kept: set[str] = set()
    for d in sorted(domains, key=lambda x: (x.count("."), x)):
        if trie.insert(d):
            kept.add(d)
    return kept

# ============================================================
# Cache for conditional requests
# ============================================================

@dataclass
class CacheEntry:
    etag: str | None = None
    last_modified: str | None = None

def load_cache(path: Path) -> dict[str, CacheEntry]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        out: dict[str, CacheEntry] = {}
        if isinstance(raw, dict):
            for url, meta in raw.items():
                if isinstance(meta, dict):
                    out[url] = CacheEntry(
                        etag=meta.get("etag"),
                        last_modified=meta.get("last_modified"),
                    )
        return out
    except Exception as e:
        logging.warning("Failed to read cache %s: %s (starting fresh)", path, e)
        return {}

def save_cache(path: Path, cache: dict[str, CacheEntry]) -> None:
    raw: dict[str, dict[str, str]] = {}
    for url, entry in cache.items():
        obj: dict[str, str] = {}
        if entry.etag:
            obj["etag"] = entry.etag
        if entry.last_modified:
            obj["last_modified"] = entry.last_modified
        raw[url] = obj
    path.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")

# ============================================================
# Fetch
# ============================================================

def load_domains_from_url(
    session: requests.Session,
    url: str,
    seen: set[str],
    cache: dict[str, CacheEntry],
) -> tuple[set[str], dict[str, int]]:

    stats = {
        "total_lines": 0,
        "invalid_lines": 0,
        "duplicates": 0,
        "added": 0,
        "skipped": 0,
        "not_modified": 0,
    }
    found: set[str] = set()

    headers = {"User-Agent": USER_AGENT}
    cached = cache.get(url)
    if cached:
        if cached.etag:
            headers["If-None-Match"] = cached.etag
        if cached.last_modified:
            headers["If-Modified-Since"] = cached.last_modified

    try:
        r = session.get(url, timeout=60, headers=headers)
        if r.status_code == 304:
            stats["not_modified"] += 1
            logging.info("Not modified: %s", url)
            return found, stats

        r.raise_for_status()

        cache[url] = CacheEntry(
            etag=r.headers.get("ETag"),
            last_modified=r.headers.get("Last-Modified"),
        )
        text = r.text

    except RequestException as e:
        logging.error("Error fetching %s: %s", url, e)
        return found, stats

    for raw in text.splitlines():
        stats["total_lines"] += 1
        ln = raw.strip()

        if ln.startswith("@@") or is_comment_or_empty(ln):
            stats["invalid_lines"] += 1
            continue

        token = choose_token(ln)
        d = normalize_token(token)
        if not d:
            stats["invalid_lines"] += 1
            continue

        if d in seen:
            stats["duplicates"] += 1
            continue

        seen.add(d)
        found.add(d)
        stats["added"] += 1

    stats["skipped"] = stats["invalid_lines"] + stats["duplicates"]
    return found, stats

# ============================================================
# Collapse logic
# ============================================================

@dataclass(frozen=True)
class Mode:
    name: str
    tld_threshold: int
    min_label_length: int
    keywords: set[str]
    collapsed_suffix: str  # safe ".^" boundary, aggressive "^"

SAFE_MODE = Mode(
    name="SAFE",
    tld_threshold=SAFE_TLD_THRESHOLD,
    min_label_length=7,              # stricter
    keywords=SAFE_KEYWORDS,
    collapsed_suffix=".^",
)

AGGRESSIVE_MODE = Mode(
    name="AGGRESSIVE",
    tld_threshold=AGGRESSIVE_TLD_THRESHOLD,
    min_label_length=6,              # still conservative
    keywords=SAFE_KEYWORDS | AGGRESSIVE_EXTRA_KEYWORDS,
    collapsed_suffix="^",
)

def registrable(psl: PublicSuffixList, domain: str) -> str:
    try:
        return psl.get_sld(domain) or ""
    except Exception:
        return ""

def base_label(reg: str) -> str:
    return reg.split(".", 1)[0] if reg else ""

def is_forbidden_collapse_token(token: str) -> bool:
    """
    IMPORTANT: do NOT use PSL checks on single tokens — it causes false positives.
    Only use deterministic guards here.
    """
    t = token.strip().lower()
    if not t:
        return True
    if t in DO_NOT_COLLAPSE:
        return True
    if len(t) < 4:
        return True
    if t.isdigit():
        return True
    return False

def keyword_hits_for_domain(psl: PublicSuffixList, domain: str, keywords: set[str]) -> set[str]:
    """
    Label-aware keyword detection:
    - Determine public suffix labels (e.g. co.uk)
    - Only scan labels BEFORE the public suffix (core labels)
    - Match keyword as substring inside core labels
    """
    labels = domain.split(".")
    ps = psl.get_public_suffix(domain) or ""
    ps_labels = ps.split(".") if ps else []

    cut = len(labels) - len(ps_labels)
    if cut < 1:
        # fallback: at least ignore the last label
        cut = max(1, len(labels) - 1)

    core_labels = labels[:cut]

    hits: set[str] = set()
    for lbl in core_labels:
        for kw in keywords:
            if kw in lbl:
                hits.add(kw)
    return hits

@dataclass
class BuildReport:
    keyword_collapse_rules: int
    keyword_collapsed_domains: int
    tld_collapse_rules: int
    tld_collapsed_registrables: int
    final_rules: int

def build_rules(domains: set[str], mode: Mode, psl: PublicSuffixList) -> tuple[set[str], BuildReport]:
    keyword_domains_count = 0
    keyword_hits: set[str] = set()
    registrables_set: set[str] = set()

    # 1) Split into keyword-hit vs registrable domains
    for d in domains:
        hits = keyword_hits_for_domain(psl, d, mode.keywords)
        hits = {h for h in hits if not is_forbidden_collapse_token(h)}
        if hits:
            keyword_domains_count += 1
            keyword_hits |= hits
        else:
            reg = registrable(psl, d)
            if reg:
                registrables_set.add(reg)

    # 2) Remove redundant subdomains among registrables
    registrables_set = remove_redundant_subdomains(registrables_set)

    # 3) Group by base label and decide TLD collapses
    groups: dict[str, set[str]] = defaultdict(set)
    for reg in registrables_set:
        lbl = base_label(reg)
        if lbl:
            groups[lbl].add(reg)

    collapsed_labels: set[str] = set()
    for lbl, regs in groups.items():
        if len(lbl) < mode.min_label_length:
            continue
        if is_forbidden_collapse_token(lbl):
            continue
        if len(regs) >= mode.tld_threshold:
            collapsed_labels.add(lbl)

    # 4) Build rules
    rules: set[str] = set()

    # Keyword collapse rules
    for kw in sorted(keyword_hits):
        rules.add(f"||{kw}{mode.collapsed_suffix}")

    # TLD collapse rules
    for lbl in sorted(collapsed_labels):
        rules.add(f"||{lbl}{mode.collapsed_suffix}")

    # Remaining registrables
    for reg in registrables_set:
        if base_label(reg) in collapsed_labels:
            continue
        rules.add(f"||{reg}^")

    tld_collapsed_regs = sum(len(groups[l]) for l in collapsed_labels)

    report = BuildReport(
        keyword_collapse_rules=len(keyword_hits),
        keyword_collapsed_domains=keyword_domains_count,
        tld_collapse_rules=len(collapsed_labels),
        tld_collapsed_registrables=tld_collapsed_regs,
        final_rules=len(rules),
    )

    return rules, report

# ============================================================
# Output
# ============================================================

def write_blocklist(path: Path, rules: set[str], title: str, report: BuildReport) -> None:
    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")
    header = (
        f"! Title: {title}\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now}\n"
        f"! Rules: {len(rules)}\n"
        f"! Keyword collapses: {report.keyword_collapse_rules} (domains matched: {report.keyword_collapsed_domains})\n"
        f"! TLD collapses: {report.tld_collapse_rules} (registrables collapsed: {report.tld_collapsed_registrables})\n\n"
    )
    path.write_text(header + "".join(f"{r}\n" for r in sorted(rules)), encoding="utf-8")

# ============================================================
# Main
# ============================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate AdGuard blocklists (safe + aggressive) with sane compression.")
    p.add_argument("-s", "--source", default=DEFAULT_SOURCE_FILE, help="Path to sources file")
    p.add_argument("-b", "--output-base", default=DEFAULT_OUTPUT_BASE, help="Base name for outputs")
    p.add_argument("-c", "--cache", default=DEFAULT_CACHE_FILE, help="Cache JSON file for conditional requests")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    source_path = Path(args.source)
    cache_path = Path(args.cache)

    safe_out = Path(f"{args.output_base}_safe.txt")
    aggressive_out = Path(f"{args.output_base}_aggressive.txt")

    if not source_path.exists():
        logging.error("Source file not found: %s", source_path)
        return

    urls = [
        line.strip()
        for line in source_path.read_text(encoding="utf-8").splitlines()
        if not is_comment_or_empty(line)
    ]
    if not urls:
        logging.error("No sources found in %s", source_path)
        return

    psl = PublicSuffixList()
    cache = load_cache(cache_path)

    all_normalized: set[str] = set()
    global_stats = defaultdict(int)

    logging.info("Starting generation. Sources: %d", len(urls))

    with requests.Session() as session:
        for url in urls:
            found, stats = load_domains_from_url(session, url, all_normalized, cache)
            for k, v in stats.items():
                global_stats[k] += v

    save_cache(cache_path, cache)

    logging.info("Normalized domains collected: %d", len(all_normalized))
    logging.info("Global stats: %s", dict(global_stats))

    safe_rules, safe_report = build_rules(all_normalized, SAFE_MODE, psl)
    aggressive_rules, aggressive_report = build_rules(all_normalized, AGGRESSIVE_MODE, psl)

    # Last-resort scrub: never allow the truly forbidden tokens as standalone rules
    def scrub(rules: set[str]) -> set[str]:
        cleaned: set[str] = set()
        for r in rules:
            if not r.startswith("||"):
                continue
            token = r[2:]
            if token.endswith(".^"):
                token = token[:-2]
            elif token.endswith("^"):
                token = token[:-1]
            token = token.strip(".").lower()
            if token in DO_NOT_COLLAPSE:
                continue
            cleaned.add(r)
        return cleaned

    safe_rules = scrub(safe_rules)
    aggressive_rules = scrub(aggressive_rules)

    write_blocklist(safe_out, safe_rules, "royerlraph79 AdGuard Blocklist (SAFE)", safe_report)
    write_blocklist(aggressive_out, aggressive_rules, "royerlraph79 AdGuard Blocklist (AGGRESSIVE)", aggressive_report)

    logging.info(
        "[SAFE] rules=%d keyword_rules=%d tld_rules=%d",
        len(safe_rules), safe_report.keyword_collapse_rules, safe_report.tld_collapse_rules
    )
    logging.info(
        "[AGGRESSIVE] rules=%d keyword_rules=%d tld_rules=%d",
        len(aggressive_rules), aggressive_report.keyword_collapse_rules, aggressive_report.tld_collapse_rules
    )
    logging.info("Wrote: %s", safe_out)
    logging.info("Wrote: %s", aggressive_out)
    logging.info("Done.")

if __name__ == "__main__":
    main()
