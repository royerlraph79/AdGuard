#!/usr/bin/env python3
import os
import re
import sys
import time
import hashlib
import requests
import idna
from datetime import datetime, timezone
from typing import Iterable, Set, List, Tuple

# -----------------------------
# Config via env (overridable in workflow)
# -----------------------------
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "adguard_blocklist.txt")
SOURCES_FILE = os.getenv("SOURCES_FILE", "sources.txt")
ALLOWLIST_FILE = os.getenv("ALLOWLIST_FILE", "allowlist.txt")
EXTRAS_BLOCK_FILE = os.getenv("EXTRAS_BLOCK_FILE", "extras_block.txt")
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "30"))

COMMENT_HEADER = [
    "! Title: Converted hosts → AdGuard DNS filter",
    "! Syntax: AdGuard / uBlock Origin style (||domain^)",
    "! Homepage: (your repo URL)",
    "! License: (your choice)",
    f"! Last generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
]

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)?\s*([^\s#]+)",
    re.IGNORECASE,
)

COMMENT_PREFIXES = ("#", "!", ";")

# Very permissive domain-ish pattern (we still validate later)
DOMAIN_CHARS = re.compile(r"^[a-z0-9\-\.\*\_]+$", re.IGNORECASE)

def read_lines_if_exists(path: str) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [ln.strip() for ln in f]

def normalize_domain(d: str) -> str:
    """
    Normalize a raw token to a clean domain suitable for AdGuard '||domain^' rule.
    - Lowercase
    - Strip leading scheme, slashes, and trailing dots
    - Remove leading '*.' or '.'
    - Convert Unicode to punycode using idna
    - Discard obvious non-domains (IPs, localhost, etc.)
    """
    d = d.strip().lower()

    # Remove URL-ish prefixes
    for p in ("http://", "https://", "dns://", "tls://", "udp://"):
        if d.startswith(p):
            d = d[len(p):]

    # Remove path/port if present
    d = d.split("/")[0].split("?")[0].split("#")[0]
    d = d.split(":")[0]

    # Comment or empty?
    if not d or d.startswith(("#", "!", ";")):
        return ""

    # Remove leading map-to markers some lists use (0.0.0.0, 127.0.0.1 already covered by regex)
    if d in {"0.0.0.0", "127.0.0.1", "::1"}:
        return ""

    # Remove wildcards and leading dots
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("."):
        d = d[1:]

    # Remove trailing dot
    d = d.rstrip(".")

    # Skip localhost-like entries
    if d in {"localhost", "broadcasthost"}:
        return ""

    # Skip plain IPs
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d) or ":" in d:
        return ""

    # Basic character filter
    if not DOMAIN_CHARS.match(d):
        return ""

    # Must contain at least one dot to look like a FQDN
    if "." not in d:
        return ""

    # Convert unicode to punycode safely
    try:
        # idna encode/decode round trip to canonical ascii form
        d = idna.encode(d, uts46=True).decode("ascii")
    except idna.IDNAError:
        return ""

    return d

def tokens_from_hosts_text(text: str) -> Iterable[str]:
    """
    Extract candidate tokens from a line-oriented hosts or domain list.
    Accepts:
      - "0.0.0.0 domain.com" / "127.0.0.1 domain.com"
      - "domain.com" lines (domain-only lists)
    Ignores:
      - Comments, blanks
    """
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue

        # If it's in hosts format, HOSTS_RE captures the first token after optional IP.
        m = HOSTS_RE.match(ln)
        if m:
            token = m.group(1)
        else:
            # Fallback: treat entire line as token (domain-only lists)
            token = ln.split()[0]

        # Drop inline comment tail
        token = token.split("#")[0].strip()
        if token:
            yield token

def fetch(url: str) -> Tuple[str, str]:
    """
    Fetch URL and return (text, sha256). Raises for HTTP errors.
    """
    r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "adguard-hosts-pipeline/1.0"})
    r.raise_for_status()
    content = r.text
    digest = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    return content, digest

def load_domains_from_url(url: str) -> Set[str]:
    print(f"Fetching: {url}", flush=True)
    text, _ = fetch(url)
    domains: Set[str] = set()
    for token in tokens_from_hosts_text(text):
        d = normalize_domain(token)
        if d:
            domains.add(d)
    print(f"  + {len(domains)} domains from {url}")
    return domains

def load_sources(path: str) -> List[str]:
    urls = []
    for ln in read_lines_if_exists(path):
        ln = ln.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue
        urls.append(ln)
    return urls

def write_output(domains: Iterable[str], output_path: str) -> None:
    lines = [*COMMENT_HEADER, ""]
    # Convert to AdGuard syntax: ||domain^
    for d in sorted(domains):
        lines.append(f"||{d}^")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")

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

    # Extras
    for ln in read_lines_if_exists(EXTRAS_BLOCK_FILE):
        if ln and not ln.startswith(COMMENT_PREFIXES):
            d = normalize_domain(ln)
            if d:
                all_domains.add(d)

    # Allowlist filter
    allow: Set[str] = set()
    for ln in read_lines_if_exists(ALLOWLIST_FILE):
        if ln and not ln.startswith(COMMENT_PREFIXES):
            d = normalize_domain(ln)
            if d:
                allow.add(d)

    if allow:
        before = len(all_domains)
        all_domains = {d for d in all_domains if d not in allow}
        print(f"Allowlist removed {before - len(all_domains)} domains.")

    write_output(all_domains, OUTPUT_FILE)

    dt = time.time() - t0
    print(f"✅ Wrote {OUTPUT_FILE} with {len(all_domains)} rules in {dt:.2f}s.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
