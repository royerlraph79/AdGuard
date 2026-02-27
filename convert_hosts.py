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

TRAILING_OPTIONS_RE = re.compile(r"\$.*$")
WWW_PREFIX_RE = re.compile(r"^www\d*\.", re.IGNORECASE)

VALID_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

USER_AGENT = "royerlraph79-AdGuardBlocklist/3.0"

DEFAULT_SOURCE_FILE = "sources.txt"
DEFAULT_OUTPUT_BASE = "adguard_blocklist"
DEFAULT_CACHE_FILE = "cache.json"

# If a registrable base-label appears in >= this many distinct TLD variants,
# collapse to a single "label" rule (safe or aggressive form depending on mode).
TLD_COLLAPSE_THRESHOLD = 3

# Tracker/ad-tech keyword collapsing.
# You can expand this list over time, but be mindful of false positives.
TRACKER_KEYWORDS: set[str] = {
    "doubleclick",
    "googlesyndication",
    "adservice",
    "scorecardresearch",
    "taboola",
    "outbrain",
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
# Stats
# ============================================================

def make_stats() -> dict[str, int]:
    return {
        "total_lines": 0,
        "invalid_lines": 0,
        "duplicates": 0,
        "added": 0,
        "skipped": 0,
        "not_modified": 0,
    }

# ============================================================
# Helpers
# ============================================================

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

def normalize_token(token: str) -> str:
    """
    Returns a normalized DNS hostname (lowercase, no scheme/path/port/www, strict validation),
    or "" if token is invalid/unwanted.
    """
    d = token.strip().lower()
    if not d:
        return ""

    # Reject whitelist artifacts
    if d.startswith("@@"):
        return ""

    # Reject wildcards (DNS cannot use them directly)
    if "*" in d:
        return ""

    # Reject invalid starting chars
    if d.startswith(("-", ".", "_")):
        return ""

    # Proper URL parsing if scheme present
    if d.startswith(("http://", "https://")):
        parsed = urlsplit(d)
        d = parsed.hostname or ""

    # Remove path/query/fragment if still present
    for sep in ("/", "?", "#"):
        if sep in d:
            d = d.split(sep, 1)[0]

    # Remove port
    if ":" in d:
        d = d.split(":", 1)[0]

    # Remove www, www1, www2 etc.
    d = WWW_PREFIX_RE.sub("", d)

    # Remove trailing rule chars
    d = d.rstrip(".^")

    # Strict DNS hostname validation
    if not VALID_HOST_RE.fullmatch(d):
        return ""

    return d

def extract_from_adblock_rule(line: str) -> str:
    """
    Extract domain from Adblock-style rule like:
      ||example.com^
    Optionally with $options. Returns "" if not matched.
    """
    ln = line.strip()

    # Reject whitelist rules immediately
    if ln.startswith("@@"):
        return ""

    # Strip options suffix
    ln = TRAILING_OPTIONS_RE.sub("", ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)
    return m.group(1) if m else ""

def choose_token(raw_line: str) -> str:
    """
    Returns a candidate domain token from:
    - Adblock rule
    - hosts file line
    - plain domain
    """
    ln = raw_line.strip()

    ad = extract_from_adblock_rule(ln)
    if ad:
        return ad

    hm = HOSTS_RE.match(ln)
    if hm:
        return hm.group(1)

    return ln.split()[0] if ln else ""

def find_tracker_keyword(domain: str, keywords: set[str]) -> str | None:
    """
    Substring-based keyword detection on the full normalized domain.
    Returns the keyword if matched, else None.
    """
    for kw in keywords:
        if kw in domain:
            return kw
    return None

# ============================================================
# Reverse Trie (Optional improvement kept)
# ============================================================

class DomainTrie:
    def __init__(self) -> None:
        self.root: dict[str, dict] = {}

    def insert(self, domain: str) -> bool:
        """
        Insert domain into reverse trie.
        Returns True if inserted, False if redundant because a parent is already present.
        """
        node = self.root
        parts = domain.split(".")[::-1]

        for part in parts:
            if "__end__" in node:
                return False
            node = node.setdefault(part, {})

        node["__end__"] = {}
        return True

def remove_redundant_subdomains(domains: Iterable[str]) -> set[str]:
    """
    Removes redundant subdomains when a parent domain is already present.
    """
    trie = DomainTrie()
    kept: set[str] = set()

    for d in sorted(domains, key=lambda x: (x.count("."), x)):
        if trie.insert(d):
            kept.add(d)

    return kept

# ============================================================
# Cache (ETag/Last-Modified conditional fetch)
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
# Fetch + aggregate (raw normalized hostnames)
# ============================================================

def load_domains_from_url(
    session: requests.Session,
    url: str,
    seen: set[str],
    cache: dict[str, CacheEntry],
) -> tuple[set[str], dict[str, int]]:

    logging.info("Fetching %s", url)
    stats = make_stats()
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

        # Update cache headers
        etag = r.headers.get("ETag")
        last_modified = r.headers.get("Last-Modified")
        cache[url] = CacheEntry(etag=etag, last_modified=last_modified)

        text = r.text

    except RequestException as e:
        logging.error("Error fetching %s: %s", url, e)
        return found, stats

    for raw in text.splitlines():
        stats["total_lines"] += 1
        ln = raw.strip()

        # Reject whitelist rules first
        if ln.startswith("@@") or is_comment_or_empty(ln):
            stats["invalid_lines"] += 1
            continue

        token = choose_token(ln)
        domain = normalize_token(token)

        if not domain:
            stats["invalid_lines"] += 1
            continue

        if domain in seen:
            stats["duplicates"] += 1
            continue

        seen.add(domain)
        found.add(domain)
        stats["added"] += 1

    stats["skipped"] = stats["invalid_lines"] + stats["duplicates"]
    logging.debug("Stats for %s: %s", url, stats)
    return found, stats

# ============================================================
# Compression logic: registrable domains, TLD collapsing, keyword collapsing
# ============================================================

def registrable_domain(psl: PublicSuffixList, domain: str) -> str:
    """
    Returns eTLD+1 for domain, or "" if not determinable.
    """
    try:
        sld = psl.get_sld(domain)
        return sld or ""
    except Exception:
        return ""

def base_label(registrable: str) -> str:
    """
    For registrable domain like 'ticketmaster.co.uk' returns 'ticketmaster'.
    """
    return registrable.split(".", 1)[0] if registrable else ""

@dataclass(frozen=True)
class Mode:
    name: str
    # For collapsed label/keyword rules:
    # safe -> '||label.^' (boundary-safe across TLDs)
    # aggressive -> '||label^' (broader; can match notlabel.com etc.)
    collapsed_suffix: str

SAFE_MODE = Mode(name="safe", collapsed_suffix=".^")
AGGRESSIVE_MODE = Mode(name="aggressive", collapsed_suffix="^")

def build_rules(
    *,
    normalized_domains: set[str],
    psl: PublicSuffixList,
    keywords: set[str],
    tld_collapse_threshold: int,
    mode: Mode,
) -> set[str]:
    """
    Builds a set of AdGuard rules (strings like '||example.com^' or '||label.^') for a given mode.
    """

    # 1) Keyword collapse candidates (keyword-based rules)
    keyword_hits: set[str] = set()

    # 2) Registrable domains (eTLD+1) for all non-keyword items
    registrables: set[str] = set()

    for d in normalized_domains:
        kw = find_tracker_keyword(d, keywords)
        if kw:
            keyword_hits.add(kw)
            continue

        reg = registrable_domain(psl, d)
        if reg:
            registrables.add(reg)

    # Remove redundant subdomains among registrables (optional improvement retained)
    registrables = remove_redundant_subdomains(registrables)

    # Group registrables by base label for cross-TLD collapsing
    groups: dict[str, set[str]] = defaultdict(set)
    for reg in registrables:
        lbl = base_label(reg)
        if lbl:
            groups[lbl].add(reg)

    # Decide which labels to collapse (threshold)
    collapsed_labels: set[str] = set()
    for lbl, regs in groups.items():
        if len(regs) >= tld_collapse_threshold:
            # A very small extra guard against collapsing overly-generic labels.
            # Still heuristic — you can tune this.
            if len(lbl) >= 5:
                collapsed_labels.add(lbl)

    # Build final rule set
    rules: set[str] = set()

    # Keyword rules first
    for kw in sorted(keyword_hits):
        rules.add(f"||{kw}{mode.collapsed_suffix}")

    # TLD-collapsed labels
    for lbl in sorted(collapsed_labels):
        rules.add(f"||{lbl}{mode.collapsed_suffix}")

    # Non-collapsed registrables: output full registrable domains
    for reg in registrables:
        lbl = base_label(reg)
        if lbl in collapsed_labels:
            continue
        rules.add(f"||{reg}^")

    return rules

# ============================================================
# Output
# ============================================================

def write_blocklist(path: Path, rules: set[str], title: str) -> None:
    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")

    header = (
        f"! Title: {title}\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now}\n"
        f"! Rules: {len(rules)}\n\n"
    )

    content = header + "".join(f"{r}\n" for r in sorted(rules))
    path.write_text(content, encoding="utf-8")

# ============================================================
# Main
# ============================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate optimized AdGuard blocklists (safe + aggressive).")
    p.add_argument("-s", "--source", default=DEFAULT_SOURCE_FILE, help="Path to sources file")
    p.add_argument(
        "-b",
        "--output-base",
        default=DEFAULT_OUTPUT_BASE,
        help="Output base name (produces *_safe.txt and *_aggressive.txt)",
    )
    p.add_argument("-c", "--cache", default=DEFAULT_CACHE_FILE, help="Cache JSON file for conditional requests")
    p.add_argument("--tld-threshold", type=int, default=TLD_COLLAPSE_THRESHOLD, help="TLD-collapse threshold")
    p.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="Add an extra tracker keyword (can be used multiple times)",
    )
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

    # Combine built-in keywords with user extras
    keywords = set(TRACKER_KEYWORDS)
    for k in args.keyword:
        k = (k or "").strip().lower()
        if k:
            keywords.add(k)

    logging.info("Starting generation")
    logging.info("Sources: %d", len(urls))
    logging.info("TLD collapse threshold: %d", args.tld_threshold)
    logging.info("Tracker keywords: %d", len(keywords))

    # PSL instance (uses package snapshot)
    psl = PublicSuffixList()

    cache = load_cache(cache_path)

    all_normalized: set[str] = set()
    global_stats = make_stats()

    with requests.Session() as session:
        for url in urls:
            _, stats = load_domains_from_url(session, url, all_normalized, cache)
            for k in global_stats:
                global_stats[k] += stats.get(k, 0)

    # Ensure cache.json always exists/updated for your workflow
    save_cache(cache_path, cache)

    logging.info("Normalized domains collected: %d", len(all_normalized))
    logging.info("Global stats: %s", global_stats)

    safe_rules = build_rules(
        normalized_domains=all_normalized,
        psl=psl,
        keywords=keywords,
        tld_collapse_threshold=args.tld_threshold,
        mode=SAFE_MODE,
    )

    aggressive_rules = build_rules(
        normalized_domains=all_normalized,
        psl=psl,
        keywords=keywords,
        tld_collapse_threshold=args.tld_threshold,
        mode=AGGRESSIVE_MODE,
    )

    write_blocklist(safe_out, safe_rules, "royerlraph79 AdGuard Blocklist (SAFE)")
    write_blocklist(aggressive_out, aggressive_rules, "royerlraph79 AdGuard Blocklist (AGGRESSIVE)")

    logging.info("Wrote: %s (%d rules)", safe_out, len(safe_rules))
    logging.info("Wrote: %s (%d rules)", aggressive_out, len(aggressive_rules))
    logging.info("Done.")

if __name__ == "__main__":
    main()
