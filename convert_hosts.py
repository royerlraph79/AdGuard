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

import requests
from publicsuffix2 import PublicSuffixList
from requests import RequestException

# ============================================================
# Config
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

USER_AGENT = "royerlraph79-AdGuardBlocklist/4.0"

SAFE_TLD_THRESHOLD = 3
AGGRESSIVE_TLD_THRESHOLD = 2

SAFE_KEYWORDS = {
    "doubleclick",
    "googlesyndication",
    "adservice",
    "scorecardresearch",
    "taboola",
    "outbrain",
}

AGGRESSIVE_EXTRA_KEYWORDS = {
    "pub",
    "ads",
    "trk",
    "track",
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
# Helpers
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
    if d.startswith(("-", ".", "_")):
        return ""
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
# Core Collapse Logic
# ============================================================

@dataclass
class Mode:
    name: str
    tld_threshold: int
    min_label_length: int
    keywords: set[str]
    collapsed_suffix: str

SAFE_MODE = Mode(
    name="SAFE",
    tld_threshold=SAFE_TLD_THRESHOLD,
    min_label_length=5,
    keywords=SAFE_KEYWORDS,
    collapsed_suffix=".^",
)

AGGRESSIVE_MODE = Mode(
    name="AGGRESSIVE",
    tld_threshold=AGGRESSIVE_TLD_THRESHOLD,
    min_label_length=3,
    keywords=SAFE_KEYWORDS | AGGRESSIVE_EXTRA_KEYWORDS,
    collapsed_suffix="^",
)

def registrable(psl: PublicSuffixList, domain: str) -> str:
    return psl.get_sld(domain) or ""

def base_label(reg: str) -> str:
    return reg.split(".", 1)[0] if reg else ""

def build_rules(domains: set[str], mode: Mode, psl: PublicSuffixList):

    keyword_domains = []
    registrables = []

    for d in domains:
        if any(k in d for k in mode.keywords):
            keyword_domains.append(d)
        else:
            reg = registrable(psl, d)
            if reg:
                registrables.append(reg)

    keyword_hits = {
        k for d in keyword_domains for k in mode.keywords if k in d
    }

    groups = defaultdict(set)
    for reg in registrables:
        groups[base_label(reg)].add(reg)

    collapsed_labels = {
        lbl for lbl, regs in groups.items()
        if len(regs) >= mode.tld_threshold
        and len(lbl) >= mode.min_label_length
    }

    rules = set()

    # Keyword rules
    for kw in keyword_hits:
        rules.add(f"||{kw}{mode.collapsed_suffix}")

    # TLD collapse rules
    for lbl in collapsed_labels:
        rules.add(f"||{lbl}{mode.collapsed_suffix}")

    # Non-collapsed registrables
    for reg in registrables:
        lbl = base_label(reg)
        if lbl not in collapsed_labels:
            rules.add(f"||{reg}^")

    # =======================
    # Analytics
    # =======================

    logging.info(f"[{mode.name}] Total domains: {len(domains)}")
    logging.info(f"[{mode.name}] Keyword collapses: {len(keyword_hits)}")
    logging.info(f"[{mode.name}] Domains via keyword collapse: {len(keyword_domains)}")
    logging.info(f"[{mode.name}] TLD label collapses: {len(collapsed_labels)}")
    logging.info(
        f"[{mode.name}] Domains via TLD collapse: "
        f"{sum(len(groups[l]) for l in collapsed_labels)}"
    )
    logging.info(f"[{mode.name}] Final rules: {len(rules)}")

    return rules

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
        logging.error("Missing sources.txt")
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

    logging.info(f"Normalized domains collected: {len(all_domains)}")

    safe_rules = build_rules(all_domains, SAFE_MODE, psl)
    aggressive_rules = build_rules(all_domains, AGGRESSIVE_MODE, psl)

    now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y UTC")

    def write(path: Path, title: str, rules: set[str]):
        header = (
            f"! Title: {title}\n"
            "! Expires: 24 hours\n"
            f"! Generated: {now}\n"
            f"! Rules: {len(rules)}\n\n"
        )
        path.write_text(header + "\n".join(sorted(rules)) + "\n")

    write(Path(f"{args.output_base}_safe.txt"),
          "royerlraph79 AdGuard Blocklist (SAFE)", safe_rules)

    write(Path(f"{args.output_base}_aggressive.txt"),
          "royerlraph79 AdGuard Blocklist (AGGRESSIVE)", aggressive_rules)

    logging.info("Done.")

if __name__ == "__main__":
    main()
