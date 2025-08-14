#!/usr/bin/env python3
import os
import re
import sys
import time
import requests
import idna
from datetime import datetime, timezone
from typing import Iterable, Set, List, Tuple

# -----------------------------
# Config (override via env)
# -----------------------------
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "adguard_blocklist.txt")
SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
ALLOWLIST_FILE = os.getenv("ALLOWLIST_FILE", "allowlist.txt")
EXTRAS_BLOCK_FILE = os.getenv("EXTRAS_BLOCK_FILE", "extras_block.txt")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "30"))
USER_AGENT = os.getenv("USER_AGENT", "adguard-hosts-pipeline/1.4")
ENABLE_SUBSUMPTION = os.getenv("ENABLE_SUBSUMPTION", "1") not in ("0", "false", "False")

COMMENT_HEADER = [
    "! Title: Converted hosts → AdGuard DNS filter",
    "! Syntax: AdGuard / uBO style (||domain^)",
    "! Note: '@@' exception lines are ignored; subdomain rules compressed",
    f"! Last generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
]

HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)?\s*([^\s#]+)", re.IGNORECASE)
COMMENT_PREFIXES = ("#", "!", ";")
DOMAIN_CHARS = re.compile(r"^[a-z0-9\-\.\*\_]+$", re.IGNORECASE)

def read_lines_if_exists(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f]

def normalize_domain(d: str) -> str:
    """Normalize a token to a clean domain for AdGuard '||domain^'."""
    d = d.strip().lower()
    if not d or d.startswith("@@"):
        return ""

    for p in ("http://", "https://", "dns://", "tls://", "udp://"):
        if d.startswith(p):
            d = d[len(p):]

    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0]

    if d.startswith("*."):
        d = d[2:]
    if d.startswith("."):
        d = d[1:]
    d = d.rstrip(".")

    if not d or d.startswith(COMMENT_PREFIXES) or d in {"localhost", "broadcasthost"}:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or ":" in d:
        return ""
    if not DOMAIN_CHARS.match(d):
        return ""
    if "." not in d:
        return ""

    try:
        d = idna.encode(d, uts46=True).decode("ascii")
    except idna.IDNAError:
        return ""
    return d

def tokens_from_hosts_text(text: str) -> Iterable[str]:
    """Yield tokens from hosts or domain-only lists; skip comments and @@ rules."""
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES) or ln.startswith("@@"):
            continue
        m = HOSTS_RE.match(ln)
        token = (m.group(1) if m else ln.split()[0]).split("#")[0].strip()
        if token:
            yield token

def fetch(url: str) -> str:
    r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    return r.text

def load_domains_from_url(url: str) -> Set[str]:
    print(f"Fetching: {url}", flush=True)
    text = fetch(url)
    domains: Set[str] = set()
    skipped_atat = 0

    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue
        if ln.startswith("@@"):
            skipped_atat += 1
            continue
        m = HOSTS_RE.match(ln)
        token = (m.group(1) if m else ln.split()[0]).split("#")[0].strip()
        d = normalize_domain(token)
        if d:
            domains.add(d)

    print(f"  + {len(domains)} domains from {url} (skipped @@: {skipped_atat})")
    return domains

def load_sources(path: str) -> List[str]:
    urls = []
    for ln in read_lines_if_exists(path):
        ln = ln.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue
        urls.append(ln)
    return urls

def compress_by_subsumption(domains: Set[str]) -> Tuple[Set[str], int]:
    """Remove subdomains already covered by a parent rule."""
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

def write_output(domains: Iterable[str], output_path: str) -> int:
    clean_rules = [f"||{d.strip()}^" for d in sorted(domains) if d.strip()]
    lines = [*COMMENT_HEADER, *clean_rules]
    text = "\n".join(lines).strip() + "\n"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)
    return len(clean_rules)

def main() -> int:
    t0 = time.time()
    sources = load_sources(SOURCES_FILE)
    if not sources:
        print(f"❌ No sources in {SOURCES_FILE}. Add at least one URL.", file=sys.stderr)
        return 2

    all_domains: Set[str] = set()
    for url in sources:
        try:
            all_domains |= load_domains_from_url(url)
        except Exception as e:
            print(f"  ! Failed {url}: {e}", file=sys.stderr)

    extras_added = 0
    for ln in read_lines_if_exists(EXTRAS_BLOCK_FILE):
        if not ln or ln.startswith(COMMENT_PREFIXES) or ln.startswith("@@"):
            continue
        d = normalize_domain(ln)
        if d and d not in all_domains:
            all_domains.add(d)
            extras_added += 1
    if extras_added:
        print(f"Added {extras_added} domains from extras.")

    allow: Set[str] = set()
    for ln in read_lines_if_exists(ALLOWLIST_FILE):
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue
        d = normalize_domain(ln)
        if d:
            allow.add(d)
    if allow:
        before = len(all_domains)
        all_domains = {d for d in all_domains if d not in allow}
        print(f"Allowlist removed {before - len(all_domains)} domains.")

    before_dedup = len(all_domains)
    all_domains = set(all_domains)
    after_dedup = len(all_domains)
    if after_dedup < before_dedup:
        print(f"Removed {before_dedup - after_dedup} duplicate entries.")

    if ENABLE_SUBSUMPTION:
        before_comp = len(all_domains)
        all_domains, pruned = compress_by_subsumption(all_domains)
        print(f"Compressed by subsumption: removed {pruned} redundant subdomain rules "
              f"({before_comp} → {len(all_domains)}).")

    rules_count = write_output(all_domains, OUTPUT_FILE)
    print(f"✅ Wrote {OUTPUT_FILE} with {rules_count} rules.")

    dt = time.time() - t0
    print(f"Done in {dt:.2f}s.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
