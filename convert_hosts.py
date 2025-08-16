#!/usr/bin/env python3
import os
import re
import sys
import time
import requests
import idna
from urllib.parse import urlparse
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import Iterable, Set, List, Tuple, Optional

# -----------------------------
# Config (override via env)
# -----------------------------
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "adguard_blocklist.txt")
SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
ALLOWLIST_FILE = os.getenv("ALLOWLIST_FILE", "allowlist.txt")
EXTRAS_BLOCK_FILE = os.getenv("EXTRAS_BLOCK_FILE", "extras_block.txt")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "30"))
USER_AGENT = os.getenv("USER_AGENT", "adguard-hosts-pipeline/1.6")
ENABLE_SUBSUMPTION = os.getenv("ENABLE_SUBSUMPTION", "1") not in ("0", "false", "False")

# Patterns
HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)?\s*([^\s#]+)", re.IGNORECASE)
COMMENT_PREFIXES = ("#", "!", ";")
DOMAIN_CHARS = re.compile(r"^[a-z0-9\-\.\*\_]+$", re.IGNORECASE)


def read_lines_if_exists(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f]


def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    if not d or d.startswith("@@"):
        return ""
    for p in ("http://", "https://", "dns://", "tls://", "udp://"):
        if d.startswith(p):
            d = d[len(p):]
    d = d.split("/")[0].split("?")[0].split("#")[0].split(":")[0]
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("."):
        d = d[1:]
    d = d.rstrip(".")
    if not d or d.startswith(COMMENT_PREFIXES) or d in {"localhost", "broadcasthost"}:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or ":" in d:
        return ""
    if not DOMAIN_CHARS.match(d) or "." not in d:
        return ""
    try:
        return idna.encode(d, uts46=True).decode("ascii")
    except idna.IDNAError:
        return ""


def extract_domain_from_adblock_rule(ln: str) -> Optional[str]:
    s = ln.strip()
    if s.startswith("||"):
        s = s[2:]
        for sep in ("^", "/", "?", "#", "$", "|"):
            idx = s.find(sep)
            if idx != -1:
                s = s[:idx]
        return s.strip() or None
    if s.startswith("|"):
        try:
            parsed = urlparse(s.lstrip("|"))
            return parsed.hostname
        except Exception:
            return None
    if s.startswith(("http://", "https://")):
        try:
            parsed = urlparse(s)
            return parsed.hostname
        except Exception:
            return None
    if "$" in s:
        s = s.split("$", 1)[0].strip()
    return None


def extract_token_from_line(ln: str) -> Optional[str]:
    ln = ln.strip()
    if not ln or ln.startswith(COMMENT_PREFIXES) or ln.startswith("@@"):
        return None
    ab = extract_domain_from_adblock_rule(ln)
    if ab:
        return ab
    m = HOSTS_RE.match(ln)
    token = (m.group(1) if m else ln.split()[0]).split("#")[0].strip()
    return token if token else None


def fetch(url: str) -> str:
    r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.text


def load_domains_from_url(url: str) -> Set[str]:
    print(f"Fetching: {url}", flush=True)
    text = fetch(url)
    domains: Set[str] = set()
    skipped = 0
    adblock = 0
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue
        if ln.startswith("@@"):
            skipped += 1
            continue
        ab = extract_domain_from_adblock_rule(ln)
        token: Optional[str]
        if ab:
            adblock += 1
            token = ab
        else:
            m = HOSTS_RE.match(ln)
            token = (m.group(1) if m else ln.split()[0]).split("#")[0].strip()
        if not token:
            continue
        d = normalize_domain(token)
        if d:
            domains.add(d)
    print(f"  + {len(domains)} domains (skipped '@@': {skipped}; adblock rules parsed: {adblock})")
    return domains


def load_sources(path: str) -> List[str]:
    return [ln.strip() for ln in read_lines_if_exists(path) if ln.strip() and not ln.startswith(COMMENT_PREFIXES)]


def compress_by_subsumption(domains: Set[str]) -> Tuple[Set[str], int]:
    if not domains:
        return set(), 0
    removed = 0
    keep: Set[str] = set()
    for d in domains:
        labels = d.split(".")
        if any(".".join(labels[i:]) in domains for i in range(1, len(labels))):
            removed += 1
            continue
        keep.add(d)
    return keep, removed


def build_comment_header(rule_count: int) -> List[str]:
    now = datetime.now(ZoneInfo("America/New_York"))
    tz_abbr = now.tzname()
    timestamp = now.strftime(f'%Y-%m-%d %H:%M:%S {tz_abbr}')
    print(f"[INFO] Timestamp used for header: {timestamp} (tz = {tz_abbr})")

    return [
        "! Title: Converted hosts → AdGuard DNS filter",
        "! Syntax: AdGuard / uBO style (||domain^)",
        "! Notes:",
        "!  - '@@' exception lines are ignored",
        "!  - Adblock/uBO rules and URLs in sources are parsed and converted to hostnames",
        "!  - Redundant subdomains are removed if a parent rule exists",
        f"! Rule count: {rule_count}",
        f"! Last generated: {timestamp}",
    ]


def write_output(domains: Iterable[str], output_path: str) -> int:
    clean_rules = [f"||{d.strip()}^" for d in sorted(domains) if d.strip()]
    rule_count = len(clean_rules)
    lines = build_comment_header(rule_count) + clean_rules
    text = "\n".join(lines).strip() + "\n"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)
    return rule_count


def main() -> int:
    t0 = time.time()
    sources = load_sources(SOURCES_FILE)
    if not sources:
        print(f"❌ No sources in {SOURCES_FILE}.", file=sys.stderr)
        return 2

    all_domains: Set[str] = set()
    for url in sources:
        try:
            all_domains |= load_domains_from_url(url)
        except Exception as e:
            print(f"  ! Failed {url}: {e}", file=sys.stderr)

    for ln in read_lines_if_exists(EXTRAS_BLOCK_FILE):
        if ln and not ln.startswith(COMMENT_PREFIXES) and not ln.startswith("@@"):
            d = normalize_domain(ln)
            if d:
                all_domains.add(d)

    allow: Set[str] = {normalize_domain(ln) for ln in read_lines_if_exists(ALLOWLIST_FILE) if ln}
    if allow:
        before = len(all_domains)
        all_domains = {d for d in all_domains if d not in allow}
        print(f"Allowlist removed {before - len(all_domains)} domains.")

    if ENABLE_SUBSUMPTION:
        before = len(all_domains)
        all_domains, pruned = compress_by_subsumption(all_domains)
        print(f"Compressed subdomains: {pruned} removed ({before} → {len(all_domains)}).")

    rule_count = write_output(all_domains, OUTPUT_FILE)
    print(f"✅ Wrote {OUTPUT_FILE} with {rule_count} rules in {time.time() - t0:.2f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
