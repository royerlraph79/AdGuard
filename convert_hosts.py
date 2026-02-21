import re
import sys
import requests
from typing import Set, Tuple, Dict
from datetime import datetime

# ---------------------------
# Config
# ---------------------------

SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
TRAILING_OPTIONS_RE = re.compile(r"\$.*$")

# Remove www, www1, www2, www999 etc.
WWW_PREFIX_RE = re.compile(r"^www\d*\.", re.IGNORECASE)

# Strict DNS hostname validation
VALID_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

DEFAULT_STATS = {
    "total_lines": 0,
    "invalid_lines": 0,
    "duplicates": 0,
    "added": 0,
    "skipped": 0,
}

# ---------------------------
# Helpers
# ---------------------------

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

# ---------------------------
# Normalization
# ---------------------------

def normalize_token(token: str) -> str:

    d = token.strip().lower()

    if not d:
        return ""

    # Reject whitelist artifacts
    if d.startswith("@@"):
        return ""

    # Reject wildcards (DNS cannot use them)
    if "*" in d:
        return ""

    # Reject invalid starting chars
    if d.startswith(("-", ".", "_")):
        return ""

    # Remove scheme/path/query/fragment
    d = SCHEME_RE.sub("", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]

    # Remove www, www1, www2 etc.
    d = WWW_PREFIX_RE.sub("", d)

    # Remove port
    if ":" in d:
        d = d.split(":")[0]

    # Remove trailing rule chars
    d = d.rstrip(".^")

    # Strict DNS hostname validation
    if not VALID_HOST_RE.match(d):
        return ""

    return d

# ---------------------------
# Extract domain
# ---------------------------

def extract_from_adblock_rule(line: str) -> str:

    ln = line.strip()

    # Reject whitelist rules immediately
    if ln.startswith("@@"):
        return ""

    ln = TRAILING_OPTIONS_RE.sub("", ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)

    return m.group(1) if m else ""

def choose_token(raw_line: str) -> Tuple[str, str]:

    ln = raw_line.strip()

    ad = extract_from_adblock_rule(ln)

    if ad:
        return ("adblock", ad)

    hm = HOSTS_RE.match(ln)

    if hm:
        return ("hosts", hm.group(1))

    token = ln.split()[0] if ln else ""

    return ("plain", token)

# ---------------------------
# Correct hierarchy dedupe
# ---------------------------

def remove_redundant_subdomains(domains: Set[str]) -> Set[str]:

    print("🧹 Removing redundant subdomains...")
    sys.stdout.flush()

    # Sort shortest domains first
    ordered = sorted(domains, key=lambda d: d.count("."))

    kept = set()

    for domain in ordered:

        parts = domain.split(".")

        redundant = False

        for i in range(1, len(parts)):

            parent = ".".join(parts[i:])

            if parent in kept:
                redundant = True
                break

        if not redundant:
            kept.add(domain)

    print("✅ Subdomain dedupe complete.")
    sys.stdout.flush()

    return kept

# ---------------------------
# Fetch + aggregate
# ---------------------------

def load_domains_from_url(url: str, seen: Set[str]) -> Tuple[Set[str], Dict[str, int]]:

    print(f"⬇️ Updated: {url}")
    sys.stdout.flush()

    stats = DEFAULT_STATS.copy()
    found = set()

    try:

        r = requests.get(
            url,
            timeout=60,
            headers={
                "User-Agent": "royerlraph79-AdGuardBlocklist/1.0"
            }
        )

        r.raise_for_status()

        text = r.text

    except Exception as e:

        print(f"❌ Error fetching {url}: {e}")
        sys.stdout.flush()
        return found, stats

    for raw in text.splitlines():

        stats["total_lines"] += 1

        ln = raw.strip()

        # Reject whitelist rules FIRST
        if ln.startswith("@@"):
            stats["invalid_lines"] += 1
            continue

        if is_comment_or_empty(ln):
            stats["invalid_lines"] += 1
            continue

        kind, token = choose_token(ln)

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

    return found, stats

# ---------------------------
# Write output
# ---------------------------

def write_output(domains: Set[str]):

    now = datetime.utcnow().strftime("%a %b %d %H:%M:%S %Y")

    print(f"📦 Writing: {OUTPUT_FILE}")
    sys.stdout.flush()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n")
        f.write(f"! Generated: {now}\n")
        f.write(f"! Domains: {len(domains)}\n\n")

        for domain in sorted(domains):
            f.write(f"||{domain}^\n")

# ---------------------------
# Main
# ---------------------------

def main():

    print("🚀 royerlraph79 AdGuard Blocklist generator\n")
    sys.stdout.flush()

    with open(SOURCE_FILE, "r", encoding="utf-8") as f:

        urls = [
            line.strip()
            for line in f
            if not is_comment_or_empty(line)
        ]

    all_domains = set()

    for url in urls:

        load_domains_from_url(url, all_domains)

    print(f"\n🧠 Raw domains: {len(all_domains)}")
    sys.stdout.flush()

    final_domains = remove_redundant_subdomains(all_domains)

    print(f"🧠 Final domains: {len(final_domains)}\n")
    sys.stdout.flush()

    write_output(final_domains)

    print("🏁 Done.")
    sys.stdout.flush()

# ---------------------------

if __name__ == "__main__":
    main()
