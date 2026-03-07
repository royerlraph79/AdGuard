#!/usr/bin/env python3
from __future__ import annotations

import re
import logging
import argparse
from pathlib import Path
from typing import Iterable
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests
import tldextract
from requests import RequestException

# ============================================================
# Configuration
# ============================================================

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

TRAILING_OPTIONS_RE = re.compile(r"\$.*$")
WWW_PREFIX_RE = re.compile(r"^www\d*\.", re.IGNORECASE)

VALID_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

VALID_DOMAIN_OR_WILDCARD_RE = re.compile(
    r"^(?:\*|[a-z0-9][a-z0-9\-*]{0,61})"
    r"(?:\.(?:\*|[a-z0-9][a-z0-9\-*]{0,61}))+?$",
    re.IGNORECASE,
)

USER_AGENT = "royerlraph79-AdGuardBlocklist/4.0"

DEDUP_SUBDOMAINS = True
DEDUP_PLAIN_COVERED_BY_WILDCARDS = True
COLLAPSE_TO_REGISTRABLE = True

# ============================================================
# Logging Setup
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
        "adblock_rules": 0,
        "hosts_rules": 0,
        "plain_domains": 0,
        "invalid_lines": 0,
        "duplicates": 0,
        "added": 0,
        "skipped": 0,
    }

# ============================================================
# Helpers
# ============================================================

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

# ============================================================
# Normalization
# ============================================================

def normalize_token(token: str) -> str:
    d = token.strip().lower()
    if not d:
        return ""

    if d.startswith("@@"):
        return ""

    if d.startswith(("-", ".", "_")):
        return ""

    if d.startswith(("http://", "https://")):
        parsed = urlsplit(d)
        d = parsed.hostname or ""

    for sep in ("/", "?", "#"):
        if sep in d:
            d = d.split(sep, 1)[0]

    if ":" in d:
        d = d.split(":", 1)[0]

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not d or "." not in d or any(ch.isspace() for ch in d):
        return ""

    if "*" in d:
        return d if VALID_DOMAIN_OR_WILDCARD_RE.match(d) else ""

    return d if VALID_HOST_RE.match(d) else ""

# ============================================================
# Extract domain
# ============================================================

def extract_from_adblock_rule(line: str) -> str:
    ln = line.strip()

    if ln.startswith("@@"):
        return ""

    ln = TRAILING_OPTIONS_RE.sub("", ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)
    return m.group(1) if m else ""

def choose_token(raw_line: str) -> tuple[str, str]:
    ln = raw_line.strip()

    ad = extract_from_adblock_rule(ln)
    if ad:
        return ("adblock", ad)

    hm = HOSTS_RE.match(ln)
    if hm:
        return ("hosts", hm.group(1))

    return ("plain", ln.split()[0] if ln else "")

# ============================================================
# Reverse Trie Deduplication
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
    logging.info("Removing redundant plain subdomains (reverse trie)...")

    trie = DomainTrie()
    result: set[str] = set()

    for domain in sorted(domains, key=lambda d: (d.count("."), d)):
        if trie.insert(domain):
            result.add(domain)

    logging.info("Plain subdomain dedupe complete.")
    return result

# ============================================================
# Wildcard-aware dedupe
# ============================================================

def remove_plain_covered_by_wildcards(
    plain: set[str],
    wildcards: set[str],
) -> set[str]:
    """Drop plain domains already matched by a wildcard rule."""
    if not wildcards:
        return plain

    def glob_to_regex(glob: str) -> re.Pattern[str]:
        esc = re.escape(glob.lower())
        esc = esc.replace(r"\*", r"[a-z0-9.-]*")
        return re.compile(rf"^{esc}$", re.IGNORECASE)

    wildcard_res = [glob_to_regex(w) for w in sorted(wildcards)]
    out: set[str] = set()

    for d in plain:
        if not any(rx.match(d) for rx in wildcard_res):
            out.add(d)

    removed = len(plain) - len(out)
    logging.info("Plain domains removed (covered by wildcards): %d", removed)
    return out

def remove_wildcards_covered_by_plain(
    plain: set[str],
    wildcards: set[str],
) -> set[str]:
    """Drop *.example.com when ||example.com^ already covers all subdomains."""
    if not plain:
        return wildcards

    out: set[str] = set()
    for w in wildcards:
        base = w[2:] if w.startswith("*.") else w
        parts = base.split(".")
        # Walk up the hierarchy: sub.example.com → example.com
        covered = any(
            ".".join(parts[i:]) in plain
            for i in range(len(parts) - 1)
        )
        if not covered:
            out.add(w)

    removed = len(wildcards) - len(out)
    logging.info("Wildcards removed (covered by plain): %d", removed)
    return out

def remove_redundant_wildcards(wildcards: set[str]) -> set[str]:
    """Drop *.sub.example.com when *.example.com already covers it."""
    if not wildcards:
        return wildcards

    logging.info("Deduplicating wildcard rules via trie...")
    trie = DomainTrie()
    result: set[str] = set()

    # Strip leading "*." so trie logic works the same as for plain domains
    normalized = [
        (w, w[2:]) if w.startswith("*.") else (w, w)
        for w in wildcards
    ]

    for orig, base in sorted(normalized, key=lambda x: (x[1].count("."), x[1])):
        if trie.insert(base):
            result.add(orig)

    logging.info("Wildcard dedupe: %d -> %d", len(wildcards), len(result))
    return result

# ============================================================
# Registrable-domain collapse
# ============================================================

def registrable_domain(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"

def collapse_plain_to_registrable(domains: set[str]) -> set[str]:
    logging.info("Collapsing plain domains to registrable domains...")

    collapsed = {registrable_domain(d) for d in domains}

    logging.info(
        "Registrable collapse complete: %d -> %d",
        len(domains),
        len(collapsed),
    )
    return collapsed

# ============================================================
# Deduplication Pipeline
# ============================================================

def dedupe_domains(domains: set[str]) -> set[str]:
    logging.info("Starting final deduplication pipeline...")

    wildcards = {d for d in domains if "*" in d}
    plain = {d for d in domains if "*" not in d}

    logging.info("Plain: %d | Wildcards: %d", len(plain), len(wildcards))

    # 1. Collapse plain subdomains to registrable domain (sub.example.com → example.com)
    if COLLAPSE_TO_REGISTRABLE:
        plain = collapse_plain_to_registrable(plain)

    # 2. Deduplicate plain subdomains via trie (broader/shorter wins)
    if DEDUP_SUBDOMAINS:
        plain = remove_redundant_subdomains(plain)

    # 3. Drop plain domains already covered by a wildcard rule
    if DEDUP_PLAIN_COVERED_BY_WILDCARDS:
        plain = remove_plain_covered_by_wildcards(plain, wildcards)

    # 4. Drop wildcards made redundant by a plain rule (||example.com^ covers *.example.com)
    wildcards = remove_wildcards_covered_by_plain(plain, wildcards)

    # 5. Drop wildcards covered by broader wildcards (*.example.com covers *.sub.example.com)
    wildcards = remove_redundant_wildcards(wildcards)

    result = plain | wildcards
    logging.info("Final deduplication complete. Total: %d", len(result))
    return result

# ============================================================
# Fetch + Aggregate
# ============================================================

def load_domains_from_url(
    session: requests.Session,
    url: str,
    seen: set[str],
) -> tuple[set[str], dict[str, int]]:
    logging.info("Fetching %s", url)

    stats = make_stats()
    found: set[str] = set()

    try:
        r = session.get(
            url,
            timeout=60,
            headers={"User-Agent": USER_AGENT},
        )
        r.raise_for_status()
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

        kind, token = choose_token(ln)

        if kind == "adblock":
            stats["adblock_rules"] += 1
        elif kind == "hosts":
            stats["hosts_rules"] += 1
        else:
            stats["plain_domains"] += 1

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
    logging.info(
        "Done %s | lines=%d added=%d skipped=%d dup=%d invalid=%d",
        url,
        stats["total_lines"],
        stats["added"],
        stats["skipped"],
        stats["duplicates"],
        stats["invalid_lines"],
    )
    return found, stats

# ============================================================
# Write Output
# ============================================================

def write_output(output_path: Path, domains: set[str]) -> None:
    logging.info("Writing output to %s", output_path)

    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")

    header = (
        "! Title: royerlraph79 AdGuard Blocklist\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now}\n"
        f"! Domains: {len(domains)}\n\n"
    )

    lines = [f"||{domain}^\n" for domain in sorted(domains)]
    output_path.write_text(header + "".join(lines), encoding="utf-8")

# ============================================================
# Main
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate optimized AdGuard blocklist."
    )
    parser.add_argument(
        "-s", "--source",
        default="sources.txt",
        help="Path to sources file",
    )
    parser.add_argument(
        "-o", "--output",
        default="adguard_blocklist.txt",
        help="Output file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    source_path = Path(args.source)
    output_path = Path(args.output)

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

    logging.info("Starting blocklist generation")
    logging.info("Sources count: %d", len(urls))

    all_domains: set[str] = set()
    global_stats = make_stats()

    with requests.Session() as session:
        for url in urls:
            _, stats = load_domains_from_url(session, url, all_domains)
            for k in global_stats:
                global_stats[k] += stats[k]

    logging.info("Raw domains: %d", len(all_domains))

    final_domains = dedupe_domains(all_domains)

    logging.info("Final domains: %d", len(final_domains))
    logging.info("Global stats: %s", global_stats)

    write_output(output_path, final_domains)

    logging.info("Done.")

if __name__ == "__main__":
    main()
