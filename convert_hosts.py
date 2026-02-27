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
from urllib.parse import urlsplit

import requests
from publicsuffix2 import PublicSuffixList
from requests import RequestException

# ============================================================
# Configuration
# ============================================================

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
TRAILING_OPTIONS_RE = re.compile(r"\$.*$")
WWW_PREFIX_RE = re.compile(r"^www\d*\.", re.IGNORECASE)

# Relaxed but safe hostname validation
VALID_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z0-9-]{2,63}$",
    re.IGNORECASE,
)

USER_AGENT = "royerlraph79-AdGuardBlocklist/7.0"

SAFE_TLD_THRESHOLD = 3
AGGRESSIVE_TLD_THRESHOLD = 2

SAFE_MIN_LABEL_LENGTH = 7
AGGRESSIVE_MIN_LABEL_LENGTH = 6

DO_NOT_COLLAPSE = {
    "com", "net", "org", "edu", "gov", "mil", "int",
    "co", "uk", "ru", "de", "fr", "it", "es", "nl", "be", "ca",
    "lan", "local", "home", "arpa",
    "cdn", "static", "img", "api", "www", "mail",
}

SAFE_KEYWORDS = {
    "doubleclick",
    "googlesyndication",
    "adservice",
    "scorecardresearch",
    "taboola",
    "outbrain",
}

AGGRESSIVE_EXTRA_KEYWORDS = {
    "pubads",
    "pubadx",
    "adserver",
    "adsystem",
    "tracking",
    "analytics",
    "telemetry",
    "metrics",
}

# ============================================================
# Logging
# ============================================================

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

# ============================================================
# Normalization
# ============================================================

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

def normalize_token(token: str) -> str:
    d = token.strip().lower()
    if not d:
        return ""
    if d.startswith("@@") or "*" in d:
        return ""

    if d.startswith(("http://", "https://")):
        parsed = urlsplit(d)
        d = parsed.hostname or ""
    else:
        d = SCHEME_RE.sub("", d)
        for sep in ("/", "?", "#"):
            if sep in d:
                d = d.split(sep, 1)[0]

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
# Subdomain Dedupe
# ============================================================

class DomainTrie:
    def __init__(self):
        self.root = {}

    def insert(self, domain: str) -> bool:
        node = self.root
        parts = domain.split(".")[::-1]
        for part in parts:
            if "__end__" in node:
                return False
            node = node.setdefault(part, {})
        node["__end__"] = {}
        return True

def remove_redundant_subdomains(domains):
    trie = DomainTrie()
    kept = set()
    for d in sorted(domains, key=lambda x: (x.count("."), x)):
        if trie.insert(d):
            kept.add(d)
    return kept

# ============================================================
# Collapse Logic
# ============================================================

@dataclass
class Mode:
    name: str
    threshold: int
    min_len: int
    keywords: set[str]
    suffix: str

SAFE_MODE = Mode(
    "SAFE",
    SAFE_TLD_THRESHOLD,
    SAFE_MIN_LABEL_LENGTH,
    SAFE_KEYWORDS,
    ".^",
)

AGGRESSIVE_MODE = Mode(
    "AGGRESSIVE",
    AGGRESSIVE_TLD_THRESHOLD,
    AGGRESSIVE_MIN_LABEL_LENGTH,
    SAFE_KEYWORDS | AGGRESSIVE_EXTRA_KEYWORDS,
    "^",
)

def is_forbidden(token: str) -> bool:
    t = token.lower()
    if t in DO_NOT_COLLAPSE:
        return True
    if len(t) < 4:
        return True
    if t.isdigit():
        return True
    return False

def build_rules(domains, mode: Mode, psl: PublicSuffixList):

    keyword_hits = set()
    registrables = set()
    keyword_domains = 0

    for d in domains:
        labels = d.split(".")
        ps = psl.get_public_suffix(d)
        ps_labels = ps.split(".") if ps else []
        core = labels[:-len(ps_labels)] if ps_labels else labels[:-1]

        hit = False
        for lbl in core:
            for kw in mode.keywords:
                if kw in lbl and not is_forbidden(kw):
                    keyword_hits.add(kw)
                    hit = True
        if hit:
            keyword_domains += 1
        else:
            reg = psl.get_sld(d)
            if reg:
                registrables.add(reg)

    registrables = remove_redundant_subdomains(registrables)

    groups = defaultdict(set)
    for reg in registrables:
        groups[reg.split(".", 1)[0]].add(reg)

    collapsed = set()
    for lbl, regs in groups.items():
        if len(regs) >= mode.threshold and len(lbl) >= mode.min_len and not is_forbidden(lbl):
            collapsed.add(lbl)

    rules = set()

    for kw in keyword_hits:
        rules.add(f"||{kw}{mode.suffix}")

    for lbl in collapsed:
        rules.add(f"||{lbl}{mode.suffix}")

    for reg in registrables:
        if reg.split(".", 1)[0] not in collapsed:
            rules.add(f"||{reg}^")

    return rules, {
        "keyword_rules": len(keyword_hits),
        "keyword_domains": keyword_domains,
        "tld_rules": len(collapsed),
        "final_rules": len(rules),
    }

# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--source", default="sources.txt")
    parser.add_argument("-b", "--output-base", default="adguard_blocklist")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    source_path = Path(args.source)
    if not source_path.exists():
        logging.error("sources.txt missing")
        return

    urls = [
        line.strip()
        for line in source_path.read_text().splitlines()
        if not is_comment_or_empty(line)
    ]

    psl = PublicSuffixList()

    all_domains = set()

    with requests.Session() as session:
        for url in urls:
            try:
                r = session.get(url, timeout=60)
                r.raise_for_status()
                for raw in r.text.splitlines():
                    token = choose_token(raw)
                    domain = normalize_token(token)
                    if domain:
                        all_domains.add(domain)
            except RequestException as e:
                logging.error(f"Fetch failed: {url} ({e})")

    logging.info("Normalized domains: %d", len(all_domains))

    if not all_domains:
        logging.error("No domains survived normalization.")
        return

    safe_rules, safe_stats = build_rules(all_domains, SAFE_MODE, psl)
    aggressive_rules, aggressive_stats = build_rules(all_domains, AGGRESSIVE_MODE, psl)

    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")

    def write(path, title, rules, stats):
        header = (
            f"! Title: {title}\n"
            "! Expires: 24 hours\n"
            f"! Generated: {now}\n"
            f"! Rules: {len(rules)}\n"
            f"! Keyword collapses: {stats['keyword_rules']} (domains matched: {stats['keyword_domains']})\n"
            f"! TLD collapses: {stats['tld_rules']}\n\n"
        )
        Path(path).write_text(header + "\n".join(sorted(rules)) + "\n")

    write(f"{args.output_base}_safe.txt",
          "royerlraph79 AdGuard Blocklist (SAFE)",
          safe_rules,
          safe_stats)

    write(f"{args.output_base}_aggressive.txt",
          "royerlraph79 AdGuard Blocklist (AGGRESSIVE)",
          aggressive_rules,
          aggressive_stats)

    logging.info("[SAFE] %s", safe_stats)
    logging.info("[AGGRESSIVE] %s", aggressive_stats)
    logging.info("Done.")

if __name__ == "__main__":
    main()
