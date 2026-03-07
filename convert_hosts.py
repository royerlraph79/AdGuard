#!/usr/bin/env python3
"""
/convert_hosts.py

Generate an optimized AdGuard blocklist from a list of source URLs.
- Fast wildcard coverage using suffix checks (no regex).
- Correct subdomain dedupe using a pruning reverse trie (broader wins).
- Optional registrable-domain collapsing (OFF by default due to over-blocking risk).

Usage:
  python convert_hosts.py -s sources.txt -o adguard_blocklist.txt
  python convert_hosts.py -s sources.txt -o out.txt --collapse-registrable
"""

from __future__ import annotations

import argparse
import fnmatch
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit

import requests
import tldextract
from requests import RequestException

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

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

USER_AGENT = "royerlraph79-AdGuardBlocklist/5.0"


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def make_stats() -> dict[str, int]:
    return {
        "total_lines": 0,
        "adblock_rules": 0,
        "hosts_rules": 0,
        "plain_domains": 0,
        "ignored_lines": 0,   # comments/empty/exception rules
        "invalid_lines": 0,
        "duplicates": 0,
        "added": 0,
        "skipped": 0,
    }


def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)


def is_regex_rule(line: str) -> bool:
    ln = line.strip()
    return len(ln) >= 2 and ln[0] == "/" and ln[-1] == "/"


def strip_adblock_options(line: str) -> str:
    """
    Strip $options only for non-regex rules.
    This is intentionally conservative to avoid breaking regex filters.
    """
    ln = line.strip()
    if is_regex_rule(ln):
        return ln
    if "$" not in ln:
        return ln
    before, _, _ = ln.partition("$")
    return before.strip()


def extract_from_adblock_rule(line: str) -> str:
    """
    Extract host from common Adblock/AdGuard patterns, e.g.:
      ||example.com^
      ||example.com/path
      |https://example.com^
    Returns the raw host token (may include wildcard), or "".
    """
    ln = line.strip()
    if ln.startswith("@@"):
        return ""

    ln = strip_adblock_options(ln)

    # Common: ||host^
    m = re.match(r"^\|\|([^\^/]+)", ln)
    if m:
        return m.group(1)

    # Anchored URL: |https://host/...
    if ln.startswith("|http://") or ln.startswith("|https://"):
        ln2 = ln.lstrip("|")
        host = urlsplit(ln2).hostname or ""
        return host

    return ""


def choose_token(raw_line: str) -> tuple[str, str]:
    ln = raw_line.strip()

    ad = extract_from_adblock_rule(ln)
    if ad:
        return ("adblock", ad)

    hm = HOSTS_RE.match(ln)
    if hm:
        return ("hosts", hm.group(1))

    # plain: first token
    return ("plain", ln.split()[0] if ln else "")


def normalize_token(token: str) -> str:
    """
    Normalize a domain-like token to:
      - plain host: example.com
      - wildcard: *.example.com or ad*.example.com
    Returns "" if invalid/ignored.
    """
    d = token.strip().lower()
    if not d:
        return ""

    # ignore exception rules
    if d.startswith("@@"):
        return ""

    # ignore obviously non-host tokens
    if d.startswith(("-", ".", "_")):
        return ""

    # URLs -> host
    if d.startswith(("http://", "https://")):
        d = urlsplit(d).hostname or ""

    # Trim common separators after host
    for sep in ("/", "?", "#"):
        if sep in d:
            d = d.split(sep, 1)[0]

    # Remove port
    if ":" in d:
        d = d.split(":", 1)[0]

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not d or "." not in d or any(ch.isspace() for ch in d):
        return ""

    if "*" in d:
        return d if VALID_DOMAIN_OR_WILDCARD_RE.match(d) else ""

    return d if VALID_HOST_RE.match(d) else ""


def registrable_domain(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


class DomainTrie:
    """
    Reverse-label trie where inserting a broader domain prunes narrower children.
    Semantics:
      - If any ancestor node has __end__, the domain is already covered => reject insert.
      - When inserting, set __end__ and delete any children to keep state consistent.
    """

    def __init__(self) -> None:
        self.root: dict[str, dict] = {}

    def insert_broader_wins(self, domain: str) -> bool:
        node = self.root
        parts = domain.split(".")[::-1]

        for part in parts:
            if "__end__" in node:
                return False
            node = node.setdefault(part, {})

        # mark as terminal and prune children (broader wins)
        node.clear()
        node["__end__"] = {}
        return True


def dedupe_plain_subdomains(domains: Iterable[str]) -> set[str]:
    """
    Remove redundant plain subdomains (broader wins).
    e.g. keep example.com, drop a.example.com
    """
    trie = DomainTrie()
    out: set[str] = set()
    # broader first => fewer labels first
    for d in sorted(domains, key=lambda x: (x.count("."), x)):
        if trie.insert_broader_wins(d):
            out.add(d)
    return out


@dataclass(frozen=True)
class SuffixWildcard:
    """
    Represents patterns like:
      *.example.com
      *.*.example.com
    Coverage check is suffix-based and enforces at least N labels before the base.
    """
    base: str
    min_labels_before_base: int  # number of "*" labels in front (>=1)

    def covers_plain(self, host: str) -> bool:
        if host == self.base:
            return False
        if not host.endswith("." + self.base):
            return False
        prefix = host[: -(len(self.base) + 1)]
        labels = [p for p in prefix.split(".") if p]
        return len(labels) >= self.min_labels_before_base

    def covers_wildcard(self, other: "SuffixWildcard") -> bool:
        # This wildcard covers the other if:
        # - other's base ends with self.base (suffix)
        # - and other requires >= labels before its base; ensure our required labels
        #   are <= the labels implied by other's structure.
        if other.base == self.base:
            return self.min_labels_before_base <= other.min_labels_before_base
        if not other.base.endswith("." + self.base):
            return False
        extra_prefix = other.base[: -(len(self.base) + 1)]
        extra_labels = [p for p in extra_prefix.split(".") if p]
        # other host must have at least other.min labels before other.base.
        # our requirement must be satisfiable within that structure.
        # When shifting from other.base to our base, extra_labels become "before base".
        # So required labels before our base is other.min + len(extra_labels).
        other_implied_before_our_base = other.min_labels_before_base + len(extra_labels)
        return self.min_labels_before_base <= other_implied_before_our_base


def parse_suffix_wildcard(pattern: str) -> Optional[SuffixWildcard]:
    """
    Parse only pure leading-star label patterns: (*. or *.*. etc) + base with no other '*'.
    Returns None if pattern is not in that form.
    """
    p = pattern.lower().strip()
    if "*" not in p:
        return None

    labels = p.split(".")
    star_prefix = 0
    for lab in labels:
        if lab == "*":
            star_prefix += 1
        else:
            break

    if star_prefix == 0:
        return None

    base_labels = labels[star_prefix:]
    if not base_labels:
        return None

    base = ".".join(base_labels)
    if "*" in base:
        return None

    if not VALID_HOST_RE.match(base):
        return None

    return SuffixWildcard(base=base, min_labels_before_base=star_prefix)


def split_wildcards(wildcards: set[str]) -> tuple[list[SuffixWildcard], list[str]]:
    """
    Separate wildcard patterns into:
      - fast suffix-wildcards: *.example.com, *.*.example.com
      - complex globs: ad*.example.com, *ad.example.com, etc (fnmatch fallback)
    """
    suffix: list[SuffixWildcard] = []
    complex_globs: list[str] = []
    for w in wildcards:
        sw = parse_suffix_wildcard(w)
        if sw is not None:
            suffix.append(sw)
        else:
            complex_globs.append(w.lower())
    # sort suffix wildcards by (base labels asc, min_labels asc) => broader first
    suffix.sort(key=lambda x: (x.base.count("."), x.min_labels_before_base, x.base))
    complex_globs.sort()
    return suffix, complex_globs


def remove_plain_covered_by_wildcards(plain: set[str], wildcards: set[str]) -> set[str]:
    if not wildcards or not plain:
        return plain

    suffix_wildcards, complex_globs = split_wildcards(wildcards)

    out: set[str] = set()
    for host in plain:
        covered = False

        for sw in suffix_wildcards:
            if sw.covers_plain(host):
                covered = True
                break

        if not covered and complex_globs:
            # fnmatch is slower than suffix checks; only used for non-suffix patterns.
            for g in complex_globs:
                if fnmatch.fnmatchcase(host, g):
                    covered = True
                    break

        if not covered:
            out.add(host)

    logging.info("Plain domains removed (covered by wildcards): %d", len(plain) - len(out))
    return out


def remove_wildcards_covered_by_plain(plain: set[str], wildcards: set[str]) -> set[str]:
    """
    Drop wildcard patterns whose base (or ancestors) are in plain.
    e.g. if plain contains example.com then *.example.com is redundant.
    """
    if not plain or not wildcards:
        return wildcards

    out: set[str] = set()
    for w in wildcards:
        base = w[2:] if w.startswith("*.") else w
        base = base.lower()

        parts = base.split(".")
        redundant = any(".".join(parts[i:]) in plain for i in range(len(parts) - 1))
        if not redundant:
            out.add(w)

    logging.info("Wildcards removed (covered by plain): %d", len(wildcards) - len(out))
    return out


def remove_redundant_wildcards(wildcards: set[str]) -> set[str]:
    """
    Remove wildcard patterns covered by broader wildcard patterns.
    Optimizes suffix-wildcards using trie; keeps complex globs as-is.
    """
    if not wildcards:
        return wildcards

    suffix_wildcards, complex_globs = split_wildcards(wildcards)

    # Deduplicate suffix wildcards by coverage.
    kept_suffix: list[SuffixWildcard] = []
    for sw in suffix_wildcards:
        if any(prev.covers_wildcard(sw) for prev in kept_suffix):
            continue
        kept_suffix.append(sw)

    kept: set[str] = {("*." * (sw.min_labels_before_base - 1) + "*." + sw.base).replace("*.*.", "*.*.") for sw in kept_suffix}
    # The above reconstruction is safe for min_labels>=1, produces:
    # 1 -> "*.base", 2 -> "*.*.base", etc.
    # NOTE: the replace is harmless; kept format is consistent.

    # Keep complex globs; optionally dedupe exact duplicates
    kept |= set(complex_globs)

    logging.info("Wildcard dedupe: %d -> %d", len(wildcards), len(kept))
    return kept


def collapse_plain_to_registrable(domains: set[str]) -> set[str]:
    collapsed = {registrable_domain(d) for d in domains}
    logging.info("Registrable collapse: %d -> %d", len(domains), len(collapsed))
    return collapsed


def dedupe_domains(
    domains: set[str],
    *,
    dedupe_subdomains: bool,
    dedupe_plain_covered_by_wildcards: bool,
    collapse_to_registrable: bool,
) -> set[str]:
    wildcards = {d for d in domains if "*" in d}
    plain = {d for d in domains if "*" not in d}

    logging.info("Plain: %d | Wildcards: %d", len(plain), len(wildcards))

    if collapse_to_registrable:
        plain = collapse_plain_to_registrable(plain)

    if dedupe_subdomains:
        logging.info("Deduping plain subdomains (broader wins)...")
        plain = dedupe_plain_subdomains(plain)

    if dedupe_plain_covered_by_wildcards:
        plain = remove_plain_covered_by_wildcards(plain, wildcards)

    wildcards = remove_wildcards_covered_by_plain(plain, wildcards)
    wildcards = remove_redundant_wildcards(wildcards)

    result = plain | wildcards
    logging.info("Final total domains/patterns: %d", len(result))
    return result


def load_domains_from_url(
    session: requests.Session,
    url: str,
    seen: set[str],
) -> tuple[set[str], dict[str, int]]:
    logging.info("Fetching %s", url)

    stats = make_stats()
    found: set[str] = set()

    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            logging.error("Invalid URL (skipping): %s", url)
            return found, stats

        r = session.get(
            url,
            timeout=(10, 60),
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

        if is_comment_or_empty(ln) or ln.startswith("@@"):
            stats["ignored_lines"] += 1
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

    stats["skipped"] = stats["invalid_lines"] + stats["duplicates"] + stats["ignored_lines"]
    logging.info(
        "Done %s | lines=%d added=%d skipped=%d dup=%d invalid=%d ignored=%d",
        url,
        stats["total_lines"],
        stats["added"],
        stats["skipped"],
        stats["duplicates"],
        stats["invalid_lines"],
        stats["ignored_lines"],
    )
    return found, stats


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate optimized AdGuard blocklist.")
    parser.add_argument("-s", "--source", default="sources.txt", help="Path to sources file")
    parser.add_argument("-o", "--output", default="adguard_blocklist.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    parser.add_argument(
        "--collapse-registrable",
        action="store_true",
        help="Collapse plain domains to registrable domains (aggressive; may over-block).",
    )
    parser.add_argument(
        "--no-dedupe-subdomains",
        action="store_true",
        help="Disable plain subdomain deduplication.",
    )
    parser.add_argument(
        "--no-dedupe-plain-covered-by-wildcards",
        action="store_true",
        help="Disable removing plain domains covered by wildcard patterns.",
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

    logging.info("Starting blocklist generation | sources=%d", len(urls))

    all_domains: set[str] = set()
    global_stats = make_stats()

    with requests.Session() as session:
        for url in urls:
            _, stats = load_domains_from_url(session, url, all_domains)
            for k in global_stats:
                global_stats[k] += stats[k]

    logging.info("Raw unique tokens: %d", len(all_domains))

    final_domains = dedupe_domains(
        all_domains,
        dedupe_subdomains=not args.no_dedupe_subdomains,
        dedupe_plain_covered_by_wildcards=not args.no_dedupe_plain_covered_by_wildcards,
        collapse_to_registrable=args.collapse_registrable,
    )

    logging.info("Final count: %d", len(final_domains))
    logging.info("Global stats: %s", global_stats)

    write_output(output_path, final_domains)
    logging.info("Done.")


if __name__ == "__main__":
    main()
