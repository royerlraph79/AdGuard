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
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

USER_AGENT = "royerlraph79-AdGuardBlocklist/2.0"

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

    if "*" in d:
        return ""

    if d.startswith(("-", ".", "_")):
        return ""

    # Proper URL parsing
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

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not VALID_HOST_RE.match(d):
        return ""

    return d

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
# Reverse Trie Deduplication (Scales to Millions)
# ============================================================

class DomainTrie:
    def __init__(self) -> None:
        self.root: dict[str, dict] = {}

    def insert(self, domain: str) -> bool:
        """
        Insert domain into reverse trie.
        Returns True if inserted, False if redundant.
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
    logging.info("Removing redundant subdomains (reverse trie)...")

    trie = DomainTrie()
    result: set[str] = set()

    # shortest first for deterministic behavior
    for domain in sorted(domains, key=lambda d: (d.count("."), d)):
        if trie.insert(domain):
            result.add(domain)

    logging.info("Subdomain dedupe complete.")
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
# Write Output
# ============================================================

def write_output(output_path: Path, domains: set[str]) -> None:
    logging.info("Writing output to %s", output_path)

    now = datetime.now(timezone.utc).strftime(
        "%a %b %d %H:%M:%S %Y UTC"
    )

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

    final_domains = remove_redundant_subdomains(all_domains)

    logging.info("Final domains: %d", len(final_domains))
    logging.info("Global stats: %s", global_stats)

    write_output(output_path, final_domains)

    logging.info("Done.")

# ============================================================

if __name__ == "__main__":
    main()
