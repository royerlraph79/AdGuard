#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fnmatch
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# Broad AdGuard "host pattern" (not necessarily a valid hostname).
# Examples: doubleclick*, ads*, *tracker*, foo.bar*, *.example.com, ad*.example.net
VALID_ADGUARD_HOST_PATTERN_RE = re.compile(r"^[a-z0-9*.-]{2,255}$", re.IGNORECASE)

USER_AGENT = "royerlraph79-AdGuardBlocklist/6.0"

# Use bundled PSL snapshot to avoid network call in CI
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)

DEFAULT_KEYWORDS = {
    "doubleclick",
    "googlesyndication",
    "googleadservices",
    "adsystem",
    "adservice",
    "adservices",
    "adserver",
    "adservers",
    "ads",
    "advert",
    "advertising",
    "analytics",
    "pixel",
    "tracker",
    "track",
    "beacon",
    "telemetry",
    "criteo",
    "taboola",
    "outbrain",
    "scorecardresearch",
    "adnxs",
    "rubiconproject",
    "openx",
    "pubmatic",
    "adform",
    "teads",
}


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def make_stats() -> dict[str, int]:
    return {
        "total_lines": 0,
        "adblock_rules": 0,
        "hosts_rules": 0,
        "plain_domains": 0,
        "ignored_lines": 0,
        "invalid_lines": 0,
        "added": 0,
    }


def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)


def is_regex_rule(line: str) -> bool:
    ln = line.strip()
    return len(ln) >= 2 and ln[0] == "/" and ln[-1] == "/"


def strip_adblock_options(line: str) -> str:
    ln = line.strip()
    if is_regex_rule(ln):
        return ln
    if "$" not in ln:
        return ln
    before, _, _ = ln.partition("$")
    return before.strip()


def extract_from_adblock_rule(line: str) -> str:
    ln = line.strip()
    if ln.startswith("@@"):
        return ""

    ln = strip_adblock_options(ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)
    if m:
        return m.group(1)

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

    return ("plain", ln.split()[0] if ln else "")


def normalize_token_to_entry(token: str) -> str:
    """
    Normalize a token to either:
      - plain host: example.com
      - wildcard glob host: *.example.com or ad*.example.com
    Returns "" if invalid/ignored.
    """
    d = token.strip().lower()
    if not d:
        return ""

    if d.startswith("@@"):
        return ""

    if d.startswith(("-", ".", "_")):
        return ""

    if d.startswith(("http://", "https://")):
        d = urlsplit(d).hostname or ""

    for sep in ("/", "?", "#"):
        if sep in d:
            d = d.split(sep, 1)[0]

    if ":" in d:
        d = d.split(":", 1)[0]

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not d or any(ch.isspace() for ch in d):
        return ""

    if "*" in d:
        if "." not in d:
            return ""
        return d if VALID_DOMAIN_OR_WILDCARD_RE.match(d) else ""

    if "." not in d:
        return ""

    return d if VALID_HOST_RE.match(d) else ""


def registrable_domain(host: str) -> str:
    ext = _EXTRACT(host)
    if not ext.domain or not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"


class DomainTrie:
    """
    Reverse-label trie where inserting a broader domain prunes narrower children.
      - If any ancestor node has __end__, the domain is already covered => reject.
      - When inserting, clear children and set __end__ so broader always wins.
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

        node.clear()
        node["__end__"] = {}
        return True


def dedupe_plain_subdomains(domains: Iterable[str]) -> set[str]:
    trie = DomainTrie()
    out: set[str] = set()
    for d in sorted(domains, key=lambda x: (x.count("."), x)):
        if trie.insert_broader_wins(d):
            out.add(d)
    return out


@dataclass(frozen=True)
class SuffixWildcard:
    base: str
    min_labels_before_base: int

    def covers_plain(self, host: str) -> bool:
        if host == self.base:
            return False
        if not host.endswith("." + self.base):
            return False
        prefix = host[: -(len(self.base) + 1)]
        labels = [p for p in prefix.split(".") if p]
        return len(labels) >= self.min_labels_before_base

    def covers_wildcard(self, other: "SuffixWildcard") -> bool:
        if other.base == self.base:
            return self.min_labels_before_base <= other.min_labels_before_base
        if not other.base.endswith("." + self.base):
            return False
        extra_prefix = other.base[: -(len(self.base) + 1)]
        extra_labels = [p for p in extra_prefix.split(".") if p]
        other_implied_before_our_base = other.min_labels_before_base + len(extra_labels)
        return self.min_labels_before_base <= other_implied_before_our_base


def parse_suffix_wildcard(pattern: str) -> Optional[SuffixWildcard]:
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
    suffix: list[SuffixWildcard] = []
    complex_globs: list[str] = []
    for w in wildcards:
        sw = parse_suffix_wildcard(w)
        if sw is not None:
            suffix.append(sw)
        else:
            complex_globs.append(w.lower())
    suffix.sort(key=lambda x: (x.base.count("."), x.min_labels_before_base, x.base))
    complex_globs.sort()
    return suffix, complex_globs


def remove_plain_covered_by_wildcards(plain: set[str], wildcards: set[str]) -> set[str]:
    if not wildcards or not plain:
        return plain

    suffix_wildcards, complex_globs = split_wildcards(wildcards)
    out: set[str] = set()

    for host in plain:
        covered = any(sw.covers_plain(host) for sw in suffix_wildcards)
        if not covered and complex_globs:
            covered = any(fnmatch.fnmatchcase(host, g) for g in complex_globs)
        if not covered:
            out.add(host)

    logging.info("Plain domains removed (covered by wildcards): %d", len(plain) - len(out))
    return out


def remove_wildcards_covered_by_plain(plain: set[str], wildcards: set[str]) -> set[str]:
    if not plain or not wildcards:
        return wildcards

    out: set[str] = set()
    for w in wildcards:
        base = (w[2:] if w.startswith("*.") else w).lower()
        parts = base.split(".")
        redundant = any(".".join(parts[i:]) in plain for i in range(len(parts) - 1))
        if not redundant:
            out.add(w)

    logging.info("Wildcards removed (covered by plain): %d", len(wildcards) - len(out))
    return out


def remove_redundant_wildcards(wildcards: set[str]) -> set[str]:
    if not wildcards:
        return wildcards

    suffix_wildcards, complex_globs = split_wildcards(wildcards)

    kept_suffix: list[SuffixWildcard] = []
    for sw in suffix_wildcards:
        if not any(prev.covers_wildcard(sw) for prev in kept_suffix):
            kept_suffix.append(sw)

    kept: set[str] = {"*." * sw.min_labels_before_base + sw.base for sw in kept_suffix}
    kept |= set(complex_globs)

    logging.info("Wildcard dedupe: %d -> %d", len(wildcards), len(kept))
    return kept


def collapse_plain_to_registrable(domains: set[str]) -> set[str]:
    collapsed = {registrable_domain(d) for d in domains}
    logging.info("Registrable collapse: %d -> %d", len(domains), len(collapsed))
    return collapsed


def dedupe_domains(
    entries: set[str],
    *,
    dedupe_subdomains: bool,
    dedupe_plain_covered_by_wildcards: bool,
    collapse_to_registrable: bool,
) -> set[str]:
    wildcards = {d for d in entries if "*" in d}
    plain = {d for d in entries if "*" not in d}

    logging.info("Plain: %d | Wildcards: %d", len(plain), len(wildcards))

    if collapse_to_registrable:
        plain = collapse_plain_to_registrable(plain)

    if dedupe_subdomains:
        plain = dedupe_plain_subdomains(plain)

    if dedupe_plain_covered_by_wildcards:
        plain = remove_plain_covered_by_wildcards(plain, wildcards)

    wildcards = remove_wildcards_covered_by_plain(plain, wildcards)
    wildcards = remove_redundant_wildcards(wildcards)

    result = plain | wildcards
    logging.info("Final total entries: %d", len(result))
    return result


def _parse_source_text(text: str) -> tuple[set[str], dict[str, int]]:
    stats = make_stats()
    found: set[str] = set()

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

        entry = normalize_token_to_entry(token)
        if not entry:
            stats["invalid_lines"] += 1
            continue

        found.add(entry)
        stats["added"] += 1

    return found, stats


def _fetch_one(session: requests.Session, url: str) -> tuple[str, str]:
    r = session.get(url, timeout=(10, 60), headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return url, r.text


def load_all_sources_concurrently(urls: list[str], threads: int) -> tuple[set[str], dict[str, int]]:
    """
    Fetch sources concurrently, parse per-source, then union.
    Duplicates are computed globally after union.
    """
    merged: set[str] = set()
    global_stats = make_stats()
    total_pre_union = 0

    threads = max(1, threads)
    logging.info("Fetching with threads=%d", threads)

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(_fetch_one, session, url): url for url in urls}

            for fut in as_completed(futs):
                url = futs[fut]
                try:
                    _, text = fut.result()
                except RequestException as e:
                    logging.error("Error fetching %s: %s", url, e)
                    continue
                except Exception as e:  # noqa: BLE001
                    logging.error("Unexpected error fetching %s: %s", url, e)
                    continue

                found, stats = _parse_source_text(text)
                total_pre_union += len(found)

                merged |= found
                for k in global_stats:
                    global_stats[k] += stats[k]

                logging.info(
                    "Done %s | lines=%d parsed=%d invalid=%d ignored=%d",
                    url,
                    stats["total_lines"],
                    len(found),
                    stats["invalid_lines"],
                    stats["ignored_lines"],
                )

    # Compute duplicates approximately as pre-union minus unique.
    # (This treats duplicates across sources and within a single source similarly.)
    duplicates = max(0, total_pre_union - len(merged))
    global_stats["added"] = len(merged)
    global_stats["skipped"] = global_stats["ignored_lines"] + global_stats["invalid_lines"] + duplicates

    logging.info("Pre-union parsed entries: %d", total_pre_union)
    logging.info("Unique entries after union: %d", len(merged))
    logging.info("Estimated duplicates: %d", duplicates)

    return merged, global_stats


def _read_keyword_allowlist(path: Optional[str]) -> set[str]:
    if not path:
        return set(DEFAULT_KEYWORDS)
    p = Path(path)
    if not p.exists():
        logging.error("Keyword allowlist not found: %s (using defaults)", path)
        return set(DEFAULT_KEYWORDS)
    kws: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if not s or s.startswith(COMMENT_PREFIXES):
            continue
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", s):
            kws.add(s)
    return kws or set(DEFAULT_KEYWORDS)


def wildcardize_keywords(
    entries: set[str],
    *,
    enabled: bool,
    keyword_threshold: int,
    keyword_allowlist_path: Optional[str],
) -> set[str]:
    """
    Convert many domains containing certain keywords into one AdGuard host-pattern:
      domains that include 'doubleclick' => add 'PATTERN:doubleclick*' and remove those domains

    Only uses allowlisted keywords and requires threshold count to trigger.
    This is intentionally broad; keep it opt-in.

    Representation:
      - Normal entries: "example.com" or "*.example.com" or "ad*.example.com"
      - Pattern entries: "@pattern doubleclick*" (internal), later emitted as ||doubleclick*^
    """
    if not enabled:
        return entries

    keyword_threshold = max(2, keyword_threshold)
    allow = _read_keyword_allowlist(keyword_allowlist_path)

    plain = {e for e in entries if "*" not in e}
    # For keyword reduction, we only consider plain domains (validated hosts).
    # Wildcard globs are left intact.
    keep_other = entries - plain

    keyword_hits: dict[str, set[str]] = {k: set() for k in allow}

    for host in plain:
        rd = registrable_domain(host)
        sld = rd.split(".", 1)[0]
        for kw in allow:
            if kw in sld:
                keyword_hits[kw].add(host)

    patterns: set[str] = set()
    removed: set[str] = set()

    for kw, hosts in keyword_hits.items():
        if len(hosts) >= keyword_threshold:
            pat = f"@pattern {kw}*"
            patterns.add(pat)
            removed |= hosts

    if patterns:
        logging.warning(
            "Keyword wildcardization enabled: added %d patterns, removed %d domains "
            "(threshold=%d). This may over-block.",
            len(patterns),
            len(removed),
            keyword_threshold,
        )

    return (plain - removed) | keep_other | patterns


def write_output(output_path: Path, entries: set[str]) -> None:
    logging.info("Writing output to %s", output_path)
    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")

    header = (
        "! Title: royerlraph79 AdGuard Blocklist\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now}\n"
        f"! Entries: {len(entries)}\n\n"
    )

    def emit(entry: str) -> str:
        if entry.startswith("@pattern "):
            pat = entry.removeprefix("@pattern ").strip().lower()
            if not pat or not VALID_ADGUARD_HOST_PATTERN_RE.match(pat):
                return ""
            return f"||{pat}^\n"
        return f"||{entry}^\n"

    lines = []
    for e in sorted(entries):
        line = emit(e)
        if line:
            lines.append(line)

    output_path.write_text(header + "".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate optimized AdGuard blocklist.")
    parser.add_argument("-s", "--source", default="sources.txt", help="Path to sources file")
    parser.add_argument("-o", "--output", default="adguard_blocklist.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    parser.add_argument(
        "--threads",
        type=int,
        default=min(32, (os.cpu_count() or 4) * 4),
        help="Number of fetch threads (I/O bound).",
    )

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

    parser.add_argument(
        "--wildcardize-keywords",
        action="store_true",
        help="Reduce many 'obvious adserver' domains into broad keyword patterns like ||doubleclick*^ (very aggressive).",
    )
    parser.add_argument(
        "--keyword-threshold",
        type=int,
        default=10,
        help="Minimum number of domains hit by a keyword before creating a keyword pattern.",
    )
    parser.add_argument(
        "--keyword-allowlist",
        default=None,
        help="Path to allowlisted keywords (one per line). If omitted, uses built-in defaults.",
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

    raw_entries, global_stats = load_all_sources_concurrently(urls, threads=args.threads)
    logging.info("Raw unique entries: %d", len(raw_entries))
    logging.info("Global stats: %s", global_stats)

    # Dedupe domain/wildcard entries first
    deduped = dedupe_domains(
        raw_entries,
        dedupe_subdomains=not args.no_dedupe_subdomains,
        dedupe_plain_covered_by_wildcards=not args.no_dedupe_plain_covered_by_wildcards,
        collapse_to_registrable=args.collapse_registrable,
    )

    # Optional aggressive keyword wildcard reduction
    final_entries = wildcardize_keywords(
        deduped,
        enabled=args.wildcardize_keywords,
        keyword_threshold=args.keyword_threshold,
        keyword_allowlist_path=args.keyword_allowlist,
    )

    logging.info("Final entries: %d", len(final_entries))
    write_output(output_path, final_entries)
    logging.info("Done.")


if __name__ == "__main__":
    main()
