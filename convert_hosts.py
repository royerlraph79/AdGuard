#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import logging
import os
import re
from collections import defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

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

USER_AGENT = "royerlraph79-AdGuardBlocklist/10.1 (+https://github.com/royerlraph79/AdGuard)"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)
OUTPUT_TIMEZONE = ZoneInfo("America/Montreal")


@dataclass(frozen=True)
class ParsedSuffixWildcard:
    original: str
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

    def covers_wildcard(self, other: ParsedSuffixWildcard) -> bool:
        if other.base == self.base:
            return self.min_labels_before_base <= other.min_labels_before_base

        if not other.base.endswith("." + self.base):
            return False

        extra_prefix = other.base[: -(len(self.base) + 1)]
        extra_labels = [p for p in extra_prefix.split(".") if p]
        other_implied_before_our_base = other.min_labels_before_base + len(extra_labels)

        return self.min_labels_before_base <= other_implied_before_our_base


class DomainTrie:
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


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")


def make_stats() -> dict[str, int]:
    return {
        "total_lines": 0,
        "adblock_rules": 0,
        "hosts_rules": 0,
        "plain_candidate_lines": 0,
        "ignored_lines": 0,
        "invalid_lines": 0,
        "valid_entries_seen": 0,
        "unique_entries": 0,
        "fetch_failures": 0,
        "registrable_collapsed": 0,
        "subdomain_pruned": 0,
        "plain_removed_by_wildcards": 0,
        "wildcard_removed_by_plain": 0,
        "wildcard_removed_by_wildcards": 0,
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

    m = re.match(r"^\|\|([a-z0-9.*_-]+(?:\.[a-z0-9.*_-]+)+)\^?", ln, re.IGNORECASE)
    if m:
        return m.group(1)

    if ln.startswith("|http://") or ln.startswith("|https://"):
        return urlsplit(ln.lstrip("|")).hostname or ""

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


def parse_suffix_wildcard(pattern: str) -> ParsedSuffixWildcard | None:
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

    return ParsedSuffixWildcard(
        original=p,
        base=base,
        min_labels_before_base=star_prefix,
    )


def normalize_token_to_entry(token: str) -> str:
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

    # Allow host:port, but reject other colon-containing tokens.
    if re.search(r":\d+$", d):
        d = d.rsplit(":", 1)[0]
    elif ":" in d:
        return ""

    d = WWW_PREFIX_RE.sub("", d)
    d = d.rstrip(".^")

    if not d or any(ch.isspace() for ch in d):
        return ""

    # Only keep suffix-style wildcards:
    #   *.example.com
    #   *.*.example.com
    # Reject complex globs:
    #   ads*.example.com
    #   exa*mple.com
    if "*" in d:
        sw = parse_suffix_wildcard(d)
        return sw.original if sw else ""

    if "." not in d:
        return ""

    return d if VALID_HOST_RE.match(d) else ""


def registrable_domain(host: str) -> str:
    ext = _EXTRACT(host)

    if not ext.domain or not ext.suffix:
        return host

    return f"{ext.domain}.{ext.suffix}"


def collapse_plain_to_registrable(domains: set[str], stats: dict[str, int]) -> set[str]:
    collapsed_map: dict[str, set[str]] = defaultdict(set)

    for d in domains:
        collapsed_map[registrable_domain(d)].add(d)

    collapsed = set(collapsed_map)
    stats["registrable_collapsed"] += len(domains) - len(collapsed)

    logging.info("Registrable collapse: %d -> %d", len(domains), len(collapsed))
    return collapsed


def dedupe_plain_subdomains(domains: Iterable[str], stats: dict[str, int]) -> set[str]:
    ordered = sorted(set(domains), key=lambda x: (x.count("."), x))
    trie = DomainTrie()
    out: set[str] = set()

    for d in ordered:
        if trie.insert_broader_wins(d):
            out.add(d)

    stats["subdomain_pruned"] += len(ordered) - len(out)

    logging.info("Plain subdomain dedupe: %d -> %d", len(ordered), len(out))
    return out


def split_wildcards(wildcards: set[str]) -> tuple[list[ParsedSuffixWildcard], list[str]]:
    suffix: list[ParsedSuffixWildcard] = []
    complex_globs: list[str] = []

    for w in wildcards:
        sw = parse_suffix_wildcard(w)

        if sw is not None:
            suffix.append(sw)
        else:
            complex_globs.append(w.lower())

    suffix.sort(key=lambda x: (x.base.count("."), x.min_labels_before_base, x.base, x.original))
    complex_globs.sort()

    return suffix, complex_globs


def remove_plain_covered_by_wildcards(
    plain: set[str],
    wildcards: set[str],
    stats: dict[str, int],
) -> set[str]:
    if not plain or not wildcards:
        return plain

    suffix_wildcards, complex_globs = split_wildcards(wildcards)
    out: set[str] = set()

    for host in plain:
        covered = any(sw.covers_plain(host) for sw in suffix_wildcards)

        if not covered and complex_globs:
            covered = any(fnmatch.fnmatchcase(host, g) for g in complex_globs)

        if not covered:
            out.add(host)

    removed = len(plain) - len(out)
    stats["plain_removed_by_wildcards"] += removed

    logging.info("Plain domains removed, covered by wildcards: %d", removed)
    return out


def remove_wildcards_covered_by_plain(
    plain: set[str],
    wildcards: set[str],
    stats: dict[str, int],
) -> set[str]:
    if not plain or not wildcards:
        return wildcards

    out: set[str] = set()

    for w in wildcards:
        sw = parse_suffix_wildcard(w)

        if sw is not None:
            base_parts = sw.base.split(".")
            covered = any(
                ".".join(base_parts[i:]) in plain
                for i in range(len(base_parts) - 1)
            )
        else:
            labels = w.lower().split(".")
            covered = any(
                ".".join(labels[i:]) in plain
                for i in range(1, len(labels))
            )

        if covered:
            stats["wildcard_removed_by_plain"] += 1
        else:
            out.add(w)

    logging.info("Wildcards removed, covered by plain: %d", stats["wildcard_removed_by_plain"])
    return out


def remove_redundant_wildcards(
    wildcards: set[str],
    stats: dict[str, int],
    *,
    conservative: bool = False,
) -> set[str]:
    if not wildcards:
        return wildcards

    suffix_wildcards, complex_globs = split_wildcards(wildcards)

    kept_suffix: list[ParsedSuffixWildcard] = []

    for sw in suffix_wildcards:
        if not any(prev.covers_wildcard(sw) for prev in kept_suffix):
            kept_suffix.append(sw)

    kept_complex = set(complex_globs)

    if conservative:
        super_wc_bases = {sw.base for sw in kept_suffix if sw.min_labels_before_base >= 1}
        pruned_complex: set[str] = set()

        for w in kept_complex:
            wl = w.lower()
            redundant = False

            for base in super_wc_bases:
                if wl == "*." + base:
                    continue

                prefix = wl[: -(len(base) + 1)] if wl.endswith("." + base) else ""

                if wl.endswith("." + base) and "." in prefix:
                    redundant = True
                    break

            if not redundant:
                pruned_complex.add(w)

        kept_complex = pruned_complex

    kept = {sw.original for sw in kept_suffix} | kept_complex
    removed = len(wildcards) - len(kept)
    stats["wildcard_removed_by_wildcards"] += removed

    logging.info("Wildcard dedupe: %d -> %d", len(wildcards), len(kept))
    return kept


def dedupe_entries(
    entries: set[str],
    *,
    collapse_to_registrable: bool,
    dedupe_subdomains: bool,
    dedupe_plain_covered_by_wildcards: bool,
    dedupe_wildcards_conservative: bool,
    stats: dict[str, int],
) -> set[str]:
    wildcards = {d for d in entries if "*" in d}
    plain = {d for d in entries if "*" not in d}

    logging.info("Plain: %d | Wildcards: %d", len(plain), len(wildcards))

    if collapse_to_registrable:
        plain = collapse_plain_to_registrable(plain, stats)

    if dedupe_subdomains:
        plain = dedupe_plain_subdomains(plain, stats)

    if dedupe_plain_covered_by_wildcards:
        plain = remove_plain_covered_by_wildcards(plain, wildcards, stats)

    wildcards = remove_wildcards_covered_by_plain(plain, wildcards, stats)

    wildcards = remove_redundant_wildcards(
        wildcards,
        stats,
        conservative=dedupe_wildcards_conservative,
    )

    result = plain | wildcards

    logging.info("Final total entries after dedupe: %d", len(result))
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
            stats["plain_candidate_lines"] += 1

        entry = normalize_token_to_entry(token)

        if not entry:
            stats["invalid_lines"] += 1
            continue

        found.add(entry)
        stats["valid_entries_seen"] += 1

    stats["unique_entries"] = len(found)
    return found, stats


def _fetch_one(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

    r = requests.get(url, timeout=(10, 60), headers={"User-Agent": USER_AGENT})
    r.raise_for_status()

    return url, r.text


def load_all_sources_concurrently(urls: list[str], threads: int) -> tuple[set[str], dict[str, int]]:
    merged: set[str] = set()
    global_stats = make_stats()
    total_unique_per_source = 0

    threads = max(1, threads)

    logging.info("Fetching %d sources with threads=%d", len(urls), threads)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_fetch_one, url): url for url in urls}

        for fut in as_completed(futs):
            url = futs[fut]

            try:
                _, text = fut.result()
            except RequestException as e:
                logging.error("Fetch failed %s: %s", url, e)
                global_stats["fetch_failures"] += 1
                continue
            except Exception as e:
                logging.error("Unexpected error fetching %s: %s", url, e)
                global_stats["fetch_failures"] += 1
                continue

            found, stats = _parse_source_text(text)
            total_unique_per_source += len(found)
            merged |= found

            for k in global_stats:
                if k in stats:
                    global_stats[k] += stats[k]

            logging.info(
                "Done %s | lines=%d unique=%d invalid=%d ignored=%d",
                url,
                stats["total_lines"],
                len(found),
                stats["invalid_lines"],
                stats["ignored_lines"],
            )

    global_stats["unique_entries"] = len(merged)

    logging.info("Per-source unique entries total: %d", total_unique_per_source)
    logging.info("Global unique entries after union: %d", len(merged))
    logging.info("Cross-source overlap estimate: %d", max(0, total_unique_per_source - len(merged)))

    return merged, global_stats


def write_output(output_path: Path, entries: set[str], stats: dict[str, int]) -> None:
    logging.info("Writing output to %s", output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_local = datetime.now(OUTPUT_TIMEZONE).strftime("%a %b %d %Y %I:%M:%S %p %Z")

    header = (
        "! Title: royerlraph79 AdGuard Blocklist\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now_utc} ({now_local})\n"
        f"! Entries: {len(entries)}\n"
        f"! Fetch failures: {stats['fetch_failures']}\n"
        f"! Registrable collapsed: {stats['registrable_collapsed']}\n"
        f"! Subdomains pruned: {stats['subdomain_pruned']}\n"
        f"! Plain removed by wildcards: {stats['plain_removed_by_wildcards']}\n"
        f"! Wildcards removed by plain: {stats['wildcard_removed_by_plain']}\n"
        f"! Wildcards removed by wildcards: {stats['wildcard_removed_by_wildcards']}\n\n"
    )

    lines = []

    for i, e in enumerate(sorted(entries), 1):
        lines.append(f"||{e}^$important\n")

        if i % 20_000 == 0:
            logging.info("  ... prepared %d entries", i)

    output_path.write_text(header + "".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an optimized AdGuard blocklist.")

    parser.add_argument("-s", "--source", default="sources.txt", help="Path to sources file")
    parser.add_argument("-o", "--output", default="adguard_blocklist.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    parser.add_argument(
        "--threads",
        type=int,
        default=min(32, max(4, (os.cpu_count() or 4) * 4)),
        help="Number of fetch threads",
    )

    parser.add_argument(
        "--collapse-registrable",
        action="store_true",
        help="Collapse subdomains to registrable domain, aggressive and may over-block",
    )

    parser.add_argument(
        "--no-dedupe-subdomains",
        action="store_true",
        help="Disable plain subdomain deduplication",
    )

    parser.add_argument(
        "--no-dedupe-plain-covered-by-wildcards",
        action="store_true",
        help="Disable removing plain domains covered by wildcard patterns",
    )

    parser.add_argument(
        "--dedupe-wildcards-conservative",
        action="store_true",
        help="Also prune complex glob wildcards covered by broader suffix wildcard rules",
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Parse and dedupe without writing output",
    )

    args = parser.parse_args()
    setup_logging(args.verbose)

    source_path = Path(args.source)
    output_path = Path(args.output)

    if not source_path.exists():
        logging.error("Source file not found: %s", source_path)
        raise SystemExit(1)

    urls = [
        line.strip()
        for line in source_path.read_text(encoding="utf-8").splitlines()
        if not is_comment_or_empty(line)
    ]

    if not urls:
        logging.error("No sources found in %s", source_path)
        raise SystemExit(1)

    logging.info("Starting blocklist generation | sources=%d", len(urls))

    raw_entries, stats = load_all_sources_concurrently(urls, threads=args.threads)

    if stats["fetch_failures"] == len(urls):
        logging.error("All source fetches failed; refusing to write empty blocklist.")
        raise SystemExit(1)

    logging.info(
        "Raw unique entries: %d | fetch failures: %d",
        len(raw_entries),
        stats["fetch_failures"],
    )

    final_entries = dedupe_entries(
        raw_entries,
        collapse_to_registrable=args.collapse_registrable,
        dedupe_subdomains=not args.no_dedupe_subdomains,
        dedupe_plain_covered_by_wildcards=not args.no_dedupe_plain_covered_by_wildcards,
        dedupe_wildcards_conservative=args.dedupe_wildcards_conservative,
        stats=stats,
    )

    logging.info("Final entries: %d", len(final_entries))

    if args.check:
        logging.info("Check mode enabled; not writing output.")
        return

    write_output(output_path, final_entries, stats)
    logging.info("Done.")


if __name__ == "__main__":
    main()
