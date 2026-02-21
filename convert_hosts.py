import re
import json
import time
import requests
import idna
from typing import Set, Dict

SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"
CACHE_FILE = "cache.json"

USER_AGENT = "royerlraph79-blocklist-generator/1.0"

# Reject invalid prefixes
INVALID_PREFIX_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\.",
    re.IGNORECASE,
)

# Reject illegal hostname chars
VALID_HOST_RE = re.compile(r"^[a-z0-9.-]+$")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

ADB_RE = re.compile(r"^\|\|([^\^/]+)")

COMMENT_PREFIXES = ("#", "!", "//", ";")


# ---------------------------
# Cache
# ---------------------------

def load_cache():
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)


# ---------------------------
# Normalization
# ---------------------------

def normalize(domain: str) -> str:
    d = domain.strip().lower()

    if not d:
        return ""

    # remove scheme
    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]

    # remove path
    d = d.split("/")[0].split("?")[0].split("#")[0]

    # remove port
    if ":" in d:
        d = d.split(":")[0]

    # remove wildcard prefix
    if d.startswith("*."):
        d = d[2:]

    # reject wildcard entirely
    if "*" in d:
        return ""

    # reject IP-prefixed garbage
    if INVALID_PREFIX_RE.match(d):
        return ""

    # reject invalid characters
    if not VALID_HOST_RE.fullmatch(d):
        return ""

    # reject illegal hostname forms
    if (
        d.startswith("-")
        or d.endswith("-")
        or ".." in d
        or "." not in d
    ):
        return ""

    # normalize IDN
    try:
        d = idna.encode(d).decode("ascii")
    except:
        return ""

    return d


# ---------------------------
# Parsing
# ---------------------------

def extract(line: str) -> str:

    line = line.strip()

    if not line or line.startswith(COMMENT_PREFIXES):
        return ""

    # AdGuard format
    m = ADB_RE.match(line)
    if m:
        return normalize(m.group(1))

    # hosts format
    m = HOSTS_RE.match(line)
    if m:
        return normalize(m.group(1))

    # plain domain
    return normalize(line.split()[0])


# ---------------------------
# Deduplication (critical)
# ---------------------------

def dedupe(domains: Set[str]) -> Set[str]:

    print("🧹 Deduplicating safely...")

    sorted_domains = sorted(domains, key=lambda d: d.count("."))

    kept = set()

    for d in sorted_domains:

        redundant = False

        for parent in kept:
            if d == parent or d.endswith("." + parent):
                redundant = True
                break

        if not redundant:
            kept.add(d)

    return kept


# ---------------------------
# Fetch
# ---------------------------

def fetch(url: str, cache: Dict) -> Set[str]:

    headers = {"User-Agent": USER_AGENT}

    try:
        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        text = r.text

    except Exception as e:
        print("❌", url, e)
        return set()

    new_hash = hash(text)

    if cache.get(url) == new_hash:
        print("⏭️ Unchanged:", url)
        return set()

    print("⬇️ Updated:", url)

    cache[url] = new_hash

    found = set()

    for line in text.splitlines():
        d = extract(line)
        if d:
            found.add(d)

    return found


# ---------------------------
# Write
# ---------------------------

def write(domains: Set[str]):

    with open(OUTPUT_FILE, "w") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n")
        f.write(f"! Generated: {time.ctime()}\n")
        f.write(f"! Domains: {len(domains)}\n\n")

        for d in sorted(domains):
            f.write(f"||{d}^\n")


# ---------------------------
# Main
# ---------------------------

def main():

    print("🚀 royerlraph79 AdGuard Blocklist generator\n")

    cache = load_cache()

    with open(SOURCE_FILE) as f:
        sources = [
            s.strip()
            for s in f
            if s.strip() and not s.strip().startswith("#")
        ]

    all_domains = set()

    for url in sources:
        all_domains |= fetch(url, cache)

    print("\n🧠 Raw domains:", len(all_domains))

    clean = dedupe(all_domains)

    print("🧠 Final domains:", len(clean))

    write(clean)

    save_cache(cache)

    print("\n🏁 Done.")


if __name__ == "__main__":
    main()
