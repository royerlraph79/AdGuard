import re
import sys
import requests
from typing import Set, Tuple, Dict

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

DEFAULT_STATS = {
    "total_lines": 0,
    "added": 0,
    "duplicates": 0,
    "invalid": 0,
}

# ---------------------------
# Basic helpers
# ---------------------------

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return not ln or ln.startswith(COMMENT_PREFIXES)

def normalize_token(token: str) -> str:
    d = token.strip().lower()

    if not d:
        return ""

    d = SCHEME_RE.sub("", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]

    if ":" in d:
        d = d.split(":")[0]

    if d.startswith("*."):
        d = d[2:]

    d = d.rstrip(".^")

    if "." not in d:
        return ""

    if any(c.isspace() for c in d):
        return ""

    return d

# ---------------------------
# Extractors
# ---------------------------

def extract_adblock(line: str) -> str:

    if line.startswith("@@"):
        return ""

    line = TRAILING_OPTIONS_RE.sub("", line)

    m = re.match(r"^\|\|([^\^/]+)", line)

    return m.group(1) if m else ""

def choose_token(line: str) -> str:

    ad = extract_adblock(line)
    if ad:
        return ad

    hm = HOSTS_RE.match(line)
    if hm:
        return hm.group(1)

    parts = line.split()
    if parts:
        return parts[0]

    return ""

# ---------------------------
# Correct hierarchy dedupe
# ---------------------------

def remove_redundant_subdomains(domains: Set[str]) -> Set[str]:

    print("🧹 Removing redundant subdomains...")
    sys.stdout.flush()

    plain = {d for d in domains if "*" not in d}
    wild = {d for d in domains if "*" in d}

    # sort shortest first (root domains first)
    ordered = sorted(plain, key=lambda d: d.count("."))

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

    result = kept | wild

    print(f"Removed {len(domains) - len(result)} redundant domains")
    sys.stdout.flush()

    return result

# ---------------------------
# Fetch
# ---------------------------

def fetch_source(url: str, seen: Set[str]) -> Tuple[Set[str], Dict]:

    print(f"⬇️ Fetching {url}")
    sys.stdout.flush()

    stats = DEFAULT_STATS.copy()

    found = set()

    try:

        r = requests.get(
            url,
            timeout=30,
            headers={
                "User-Agent":
                "royerlraph79-blocklist-generator"
            }
        )

        r.raise_for_status()

    except Exception as e:

        print(f"❌ Failed: {e}")
        sys.stdout.flush()

        return found, stats

    for raw in r.text.splitlines():

        stats["total_lines"] += 1

        line = raw.strip()

        if is_comment_or_empty(line):
            continue

        token = choose_token(line)

        domain = normalize_token(token)

        if not domain:
            stats["invalid"] += 1
            continue

        if domain in seen:
            stats["duplicates"] += 1
            continue

        seen.add(domain)
        found.add(domain)
        stats["added"] += 1

    return found, stats

# ---------------------------
# Main
# ---------------------------

def main():

    print("🚀 royerlraph79 AdGuard Blocklist generator\n")
    sys.stdout.flush()

    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        urls = [l.strip() for l in f if not is_comment_or_empty(l)]

    seen = set()

    for url in urls:

        domains, stats = fetch_source(url, seen)

        print(
            f"Lines: {stats['total_lines']}  "
            f"Added: {stats['added']}  "
            f"Dup: {stats['duplicates']}  "
            f"Invalid: {stats['invalid']}\n"
        )

        sys.stdout.flush()

    print(f"\n🧠 Raw unique domains: {len(seen)}")

    final = remove_redundant_subdomains(seen)

    print(f"🧠 Final domains: {len(final)}")

    print(f"\n💾 Writing {OUTPUT_FILE}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n\n")

        for i, d in enumerate(sorted(final), 1):

            f.write(f"||{d}^\n")

            if i % 50000 == 0:
                print(f"Wrote {i}")
                sys.stdout.flush()

    print("\n🏁 Done")

# ---------------------------

if __name__ == "__main__":
    main()
