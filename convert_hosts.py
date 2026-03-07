#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import logging
import os
import re
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional
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

VALID_DOMAIN_OR_WILDCARD_RE = re.compile(
    r"^(?:\*|[a-z0-9][a-z0-9\-*]{0,61})"
    r"(?:\.(?:\*|[a-z0-9][a-z0-9\-*]{0,61}))+?$",
    re.IGNORECASE,
)

VALID_ADGUARD_HOST_PATTERN_RE = re.compile(r"^[a-z0-9*.-]{2,255}$", re.IGNORECASE)

USER_AGENT = "royerlraph79-AdGuardBlocklist/8.2"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)

DEFAULT_KEYWORDS = {
    "doubleclick",
    "googlesyndication",
    "googleadservices",
    "adsystem",
    "adservice",
    "adserver",
    "advert",
    "advertising",
    "analytics",
    "pixel",
    "tracker",
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

MIN_KEYWORD_LENGTH = 5
MIN_PATTERN_PREFIX_LENGTH = 6
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

    def covers_wildcard(self, other: "ParsedSuffixWildcard") -> bool:
        if other.base == self.base:
            return self.min_labels_before_base <= other.min_labels_before_base
        if not other.base.endswith("." + self.base):
            return False
        extra_prefix = other.base[: -(len(self.base) + 1)]
        extra_labels = [p for p in extra_prefix.split(".") if p]
        other_implied_before_our_base = other.min_labels_before_base + len(extra_labels)
        return self.min_labels_before_base <= other_implied_before_our_base


@dataclass
class ReductionEvent:
    phase: str
    original: str
    replacement: str
    detail: str


class ReductionReport:
    def __init__(self) -> None:
        self.events: list[ReductionEvent] = []
        self.phase_counts: Counter[str] = Counter()
        self.keyword_pattern_host_counts: Counter[str] = Counter()
        self.keyword_pattern_sld_counts: dict[str, int] = {}
        self.source_stats: list[dict[str, object]] = []

    def add(self, phase: str, original: str, replacement: str, detail: str = "") -> None:
        self.events.append(ReductionEvent(phase, original, replacement, detail))
        self.phase_counts[phase] += 1

    def add_source_stat(self, data: dict[str, object]) -> None:
        self.source_stats.append(data)

    def top_events(self, phase: str, limit: int = 10) -> list[tuple[str, int]]:
        counter = Counter(e.replacement for e in self.events if e.phase == phase)
        return counter.most_common(limit)


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
        "parsed_entries": 0,
        "unique_entries": 0,
        "fetch_failures": 0,
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
        host = urlsplit(ln.lstrip("|")).hostname or ""
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


def sld_of(host: str) -> str:
    ext = _EXTRACT(host)
    return ext.domain.lower() if ext.domain else ""


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


def find_covering_parent_domain(domain: str, existing: set[str]) -> Optional[str]:
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in existing:
            return candidate
    return None


def dedupe_plain_subdomains(domains: Iterable[str], report: ReductionReport) -> set[str]:
    ordered = sorted(set(domains), key=lambda x: (x.count("."), x))
    trie = DomainTrie()
    out: set[str] = set()

    for d in ordered:
        if trie.insert_broader_wins(d):
            out.add(d)
        else:
            parent = find_covering_parent_domain(d, out)
            report.add("subdomain_pruned", d, parent or "", "broader plain domain already present")

    logging.info("Plain subdomain dedupe: %d -> %d", len(ordered), len(out))
    return out


def parse_suffix_wildcard(pattern: str) -> Optional[ParsedSuffixWildcard]:
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


def remove_plain_covered_by_wildcards(plain: set[str], wildcards: set[str], report: ReductionReport) -> set[str]:
    if not wildcards or not plain:
        return plain

    suffix_wildcards, complex_globs = split_wildcards(wildcards)
    out: set[str] = set()

    for host in plain:
        covered_by = None

        for sw in suffix_wildcards:
            if sw.covers_plain(host):
                covered_by = sw.original
                break

        if covered_by is None and complex_globs:
            for g in complex_globs:
                if fnmatch.fnmatchcase(host, g):
                    covered_by = g
                    break

        if covered_by is None:
            out.add(host)
        else:
            report.add("plain_removed_by_wildcard", host, covered_by, "plain covered by wildcard")

    logging.info("Plain domains removed (covered by wildcards): %d", len(plain) - len(out))
    return out


def remove_wildcards_covered_by_plain(plain: set[str], wildcards: set[str], report: ReductionReport) -> set[str]:
    if not plain or not wildcards:
        return wildcards

    out: set[str] = set()

    for w in wildcards:
        labels = w.lower().split(".")
        covered_by = None

        for i in range(1, len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in plain:
                covered_by = candidate
                break

        if covered_by is None:
            out.add(w)
        else:
            report.add("wildcard_removed_by_plain", w, covered_by, "wildcard covered by plain suffix")

    logging.info("Wildcards removed (covered by plain): %d", len(wildcards) - len(out))
    return out


def remove_redundant_wildcards(wildcards: set[str], report: ReductionReport) -> set[str]:
    if not wildcards:
        return wildcards

    suffix_wildcards, complex_globs = split_wildcards(wildcards)

    kept_suffix: list[ParsedSuffixWildcard] = []
    for sw in suffix_wildcards:
        covered_by = None
        for prev in kept_suffix:
            if prev.covers_wildcard(sw):
                covered_by = prev.original
                break

        if covered_by is None:
            kept_suffix.append(sw)
        else:
            report.add("wildcard_removed_by_wildcard", sw.original, covered_by, "wildcard covered by broader wildcard")

    kept = {sw.original for sw in kept_suffix} | set(complex_globs)

    logging.info("Wildcard dedupe: %d -> %d", len(wildcards), len(kept))
    return kept


def collapse_plain_to_registrable(domains: set[str], report: ReductionReport) -> set[str]:
    collapsed_map: dict[str, set[str]] = defaultdict(set)

    for d in domains:
        rd = registrable_domain(d)
        collapsed_map[rd].add(d)

    collapsed = set(collapsed_map)

    for rd, originals in collapsed_map.items():
        for original in originals:
            if original != rd:
                report.add("registrable_collapse", original, rd, "collapsed to registrable domain")

    logging.info("Registrable collapse: %d -> %d", len(domains), len(collapsed))
    return collapsed


def dedupe_domains(
    entries: set[str],
    *,
    dedupe_subdomains: bool,
    dedupe_plain_covered_by_wildcards: bool,
    collapse_to_registrable: bool,
    report: ReductionReport,
) -> set[str]:
    wildcards = {d for d in entries if "*" in d or d.startswith("@pattern ")}
    plain = {d for d in entries if d not in wildcards}

    logging.info("Plain: %d | Wildcards/patterns: %d", len(plain), len(wildcards))

    if collapse_to_registrable:
        plain = collapse_plain_to_registrable(plain, report)

    if dedupe_subdomains:
        plain = dedupe_plain_subdomains(plain, report)

    actual_wildcards = {w for w in wildcards if not w.startswith("@pattern ")}
    patterns = {w for w in wildcards if w.startswith("@pattern ")}

    if dedupe_plain_covered_by_wildcards:
        plain = remove_plain_covered_by_wildcards(plain, actual_wildcards, report)

    actual_wildcards = remove_wildcards_covered_by_plain(plain, actual_wildcards, report)
    actual_wildcards = remove_redundant_wildcards(actual_wildcards, report)

    result = plain | actual_wildcards | patterns
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
            stats["plain_domains"] += 1

        entry = normalize_token_to_entry(token)
        if not entry:
            stats["invalid_lines"] += 1
            continue

        found.add(entry)
        stats["parsed_entries"] += 1

    stats["unique_entries"] = len(found)
    return found, stats


def _fetch_one(url: str) -> tuple[str, str]:
    with requests.Session() as session:
        r = session.get(url, timeout=(10, 60), headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        return url, r.text


def load_all_sources_concurrently(urls: list[str], threads: int, report: ReductionReport) -> tuple[set[str], dict[str, int]]:
    merged: set[str] = set()
    global_stats = make_stats()
    total_unique_per_source = 0

    threads = max(1, threads)
    logging.info("Fetching with threads=%d", threads)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_fetch_one, url): url for url in urls}

        for fut in as_completed(futs):
            url = futs[fut]
            try:
                _, text = fut.result()
            except RequestException as e:
                logging.error("Error fetching %s: %s", url, e)
                global_stats["fetch_failures"] += 1
                report.add_source_stat(
                    {
                        "url": url,
                        "status": "fetch_failed",
                        "error": str(e),
                    }
                )
                continue
            except Exception as e:
                logging.error("Unexpected error fetching %s: %s", url, e)
                global_stats["fetch_failures"] += 1
                report.add_source_stat(
                    {
                        "url": url,
                        "status": "fetch_failed",
                        "error": str(e),
                    }
                )
                continue

            found, stats = _parse_source_text(text)
            total_unique_per_source += len(found)
            merged |= found

            for k in global_stats:
                if k in stats:
                    global_stats[k] += stats[k]

            report.add_source_stat(
                {
                    "url": url,
                    "status": "ok",
                    "lines": stats["total_lines"],
                    "unique_entries": len(found),
                    "invalid_lines": stats["invalid_lines"],
                    "ignored_lines": stats["ignored_lines"],
                }
            )

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


def _read_keyword_allowlist(path: Optional[str]) -> set[str]:
    if not path:
        return {k for k in DEFAULT_KEYWORDS if len(k) >= MIN_KEYWORD_LENGTH}

    p = Path(path)
    if not p.exists():
        logging.error("Keyword allowlist not found: %s (using defaults)", path)
        return {k for k in DEFAULT_KEYWORDS if len(k) >= MIN_KEYWORD_LENGTH}

    kws: set[str] = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip().lower()
        if not s or s.startswith(COMMENT_PREFIXES):
            continue
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", s) and len(s) >= MIN_KEYWORD_LENGTH:
            kws.add(s)

    return kws or {k for k in DEFAULT_KEYWORDS if len(k) >= MIN_KEYWORD_LENGTH}


def _longest_common_prefix(values: Iterable[str]) -> str:
    vals = sorted(set(values))
    if not vals:
        return ""
    if len(vals) == 1:
        return vals[0]

    first = vals[0]
    last = vals[-1]
    i = 0
    limit = min(len(first), len(last))
    while i < limit and first[i] == last[i]:
        i += 1
    return first[:i]


def _trim_pattern_prefix(prefix: str, keyword: str) -> str:
    s = prefix.lower().strip("-.*")
    s = re.sub(r"[^a-z0-9-]+", "", s)
    if len(s) < max(MIN_PATTERN_PREFIX_LENGTH, len(keyword)):
        return ""
    if keyword not in s:
        return ""
    return s.rstrip("-")


def _keyword_pattern_covers_host(pattern_core: str, host: str) -> bool:
    rd = registrable_domain(host)
    sld = sld_of(rd)
    return bool(sld) and pattern_core in sld


def wildcardize_keywords(
    entries: set[str],
    *,
    enabled: bool,
    keyword_threshold: int,
    keyword_allowlist_path: Optional[str],
    report: ReductionReport,
) -> set[str]:
    if not enabled:
        return entries

    keyword_threshold = max(2, keyword_threshold)
    allow = _read_keyword_allowlist(keyword_allowlist_path)

    plain = {e for e in entries if "*" not in e and not e.startswith("@pattern ")}
    keep_other = entries - plain

    groups: dict[str, set[str]] = {k: set() for k in allow}
    sld_groups: dict[str, set[str]] = {k: set() for k in allow}

    for host in plain:
        rd = registrable_domain(host)
        sld = sld_of(rd)
        if not sld:
            continue
        for kw in allow:
            if kw in sld:
                groups[kw].add(host)
                sld_groups[kw].add(sld)

    patterns: set[str] = set()
    removed: set[str] = set()

    for kw in sorted(allow):
        hosts = groups[kw]
        if len(hosts) < keyword_threshold:
            continue

        prefix = _trim_pattern_prefix(_longest_common_prefix(sld_groups[kw]), kw)
        pattern_core = prefix if prefix else kw

        covered_hosts = {h for h in hosts if _keyword_pattern_covers_host(pattern_core, h)}
        if len(covered_hosts) < keyword_threshold:
            continue

        pattern = f"@pattern *{pattern_core}*"
        patterns.add(pattern)
        removed |= covered_hosts

        report.keyword_pattern_host_counts[pattern] = len(covered_hosts)
        report.keyword_pattern_sld_counts[pattern] = len(sld_groups[kw])

        for host in sorted(covered_hosts):
            report.add(
                "keyword_wildcardized",
                host,
                pattern,
                f"keyword={kw}",
            )

        logging.warning(
            "Keyword pattern created: %s from keyword=%s hosts=%d slds=%d",
            pattern,
            kw,
            len(covered_hosts),
            len(sld_groups[kw]),
        )

    if patterns:
        logging.warning(
            "Keyword wildcardization enabled: added %d patterns, removed %d domains. Validate carefully.",
            len(patterns),
            len(removed),
        )
    else:
        logging.info("Keyword wildcardization enabled, but no patterns met the threshold.")

    return (plain - removed) | keep_other | patterns


def write_output(output_path: Path, entries: set[str], report: ReductionReport) -> None:
    logging.info("Writing output to %s", output_path)
    now = datetime.now(OUTPUT_TIMEZONE).strftime("%a %b %d %H:%M:%S %Y %Z")

    header = (
        "! Title: royerlraph79 AdGuard Blocklist\n"
        "! Expires: 24 hours\n"
        f"! Generated: {now}\n"
        f"! Entries: {len(entries)}\n"
        f"! Reductions: {len(report.events)}\n"
        f"! Fetch failures: {sum(1 for s in report.source_stats if s.get('status') != 'ok')}\n\n"
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


def log_report_summary(report: ReductionReport) -> None:
    logging.info("Reduction events total: %d", len(report.events))

    for phase, count in sorted(report.phase_counts.items()):
        logging.info("Reduction phase %-30s -> %d", phase, count)

    if report.keyword_pattern_host_counts:
        logging.info("Top keyword wildcard patterns:")
        for pattern, count in report.keyword_pattern_host_counts.most_common(10):
            slds = report.keyword_pattern_sld_counts.get(pattern, 0)
            logging.info("  %s hosts=%d slds=%d", pattern, count, slds)

    if report.source_stats:
        ok = sum(1 for s in report.source_stats if s.get("status") == "ok")
        failed = sum(1 for s in report.source_stats if s.get("status") != "ok")
        logging.info("Source fetch summary: ok=%d failed=%d", ok, failed)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate optimized AdGuard blocklist.")
    parser.add_argument("-s", "--source", default="sources.txt", help="Path to sources file")
    parser.add_argument("-o", "--output", default="adguard_blocklist.txt", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--threads",
        type=int,
        default=min(32, (os.cpu_count() or 4) * 4),
        help="Number of fetch threads",
    )
    parser.add_argument(
        "--collapse-registrable",
        action="store_true",
        help="Collapse plain domains to registrable domains",
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
        "--wildcardize-keywords",
        action="store_true",
        help="Generate broad keyword host-patterns like ||*doubleclick*^",
    )
    parser.add_argument(
        "--keyword-threshold",
        type=int,
        default=10,
        help="Minimum number of hosts for keyword pattern creation",
    )
    parser.add_argument(
        "--keyword-allowlist",
        default=None,
        help="Path to keyword allowlist file",
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

    report = ReductionReport()

    logging.info("Starting blocklist generation | sources=%d", len(urls))

    raw_entries, global_stats = load_all_sources_concurrently(urls, threads=args.threads, report=report)
    logging.info("Raw unique entries: %d", len(raw_entries))
    logging.info("Global stats: %s", global_stats)

    deduped = dedupe_domains(
        raw_entries,
        dedupe_subdomains=not args.no_dedupe_subdomains,
        dedupe_plain_covered_by_wildcards=not args.no_dedupe_plain_covered_by_wildcards,
        collapse_to_registrable=args.collapse_registrable,
        report=report,
    )

    final_entries = wildcardize_keywords(
        deduped,
        enabled=args.wildcardize_keywords,
        keyword_threshold=args.keyword_threshold,
        keyword_allowlist_path=args.keyword_allowlist,
        report=report,
    )

    logging.info("Final entries: %d", len(final_entries))
    write_output(output_path, final_entries, report)
    log_report_summary(report)
    logging.info("Done.")


if __name__ == "__main__":
    main()
