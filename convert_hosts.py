import re
import json
import time
import requests
import idna
import sys

SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"
CACHE_FILE = "cache.json"

USER_AGENT = "royerlraph79-blocklist-generator/2.0"

COMMENT_PREFIXES = ("#", "!", "//", ";")

INVALID_PREFIX_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\.",
    re.IGNORECASE,
)

VALID_HOST_RE = re.compile(r"^[a-z0-9.-]+$")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

ADB_RE = re.compile(r"^\|\|([^\^/]+)")


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
# Normalize domain safely
# ---------------------------

def normalize(domain):

    d = domain.strip().lower()

    if not d:
        return ""

    if d.startswith("http://") or d.startswith("https://"):
        d = d.split("://", 1)[1]

    d = d.split("/")[0].split("?")[0].split("#")[0]

    if ":" in d:
        d = d.split(":")[0]

    if d.startswith("*."):
        d = d[2:]

    if "*" in d:
        return ""

    if INVALID_PREFIX_RE.match(d):
        return ""

    if (
        d.startswith("-")
        or d.endswith("-")
        or ".." in d
        or "." not in d
    ):
        return ""

    if not VALID_HOST_RE.fullmatch(d):
        return ""

    try:
        d = idna.encode(d).decode("ascii")
    except:
        return ""

    return d


# ---------------------------
# Extract domain
# ---------------------------

def extract(line):

    line = line.strip()

    if not line or line.startswith(COMMENT_PREFIXES):
        return ""

    m = ADB_RE.match(line)
    if m:
        return normalize(m.group(1))

    m = HOSTS_RE.match(line)
    if m:
        return normalize(m.group(1))

    return normalize(line.split()[0])


# ---------------------------
# FAST DEDUPE (O(n log n))
# ---------------------------

def dedupe(domains):

    print("🧹 Deduplicating efficiently...", flush=True)

    domains_sorted = sorted(domains)

    kept = set()

    suffix_tree = {}

    total = len(domains_sorted)

    for i, domain in enumerate(domains_sorted, 1):

        parts = domain.split(".")[::-1]

        node = suffix_tree
        redundant = False

        for part in parts:

            if "_end_" in node:
                redundant = True
                break

            if part not in node:
                node[part] = {}

            node = node[part]

        if not redundant:
            node["_end_"] = True
            kept.add(domain)

        if i % 50000 == 0:
            print(f"   {i}/{total} processed", flush=True)

    print("✅ Deduplication complete", flush=True)

    return kept


# ---------------------------
# Fetch source
# ---------------------------

def fetch(url, cache):

    headers = {"User-Agent": USER_AGENT}

    try:

        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
        text = r.text

    except Exception as e:

        print("❌ Fetch failed:", url, e, flush=True)
        return set()

    new_hash = hash(text)

    if cache.get(url) == new_hash:

        print("⏭️ Unchanged:", url, flush=True)
        return set()

    cache[url] = new_hash

    print("⬇️ Processing:", url, flush=True)

    found = set()

    for line in text.splitlines():

        d = extract(line)

        if d:
            found.add(d)

    print(f"   {len(found)} domains extracted", flush=True)

    return found


# ---------------------------
# Write blocklist
# ---------------------------

def write(domains):

    print("💾 Writing blocklist...", flush=True)

    with open(OUTPUT_FILE, "w") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n")
        f.write(f"! Generated: {time.ctime()}\n")
        f.write(f"! Domains: {len(domains)}\n\n")

        for i, d in enumerate(sorted(domains), 1):

            f.write(f"||{d}^\n")

            if i % 100000 == 0:
                print(f"   {i} written", flush=True)

    print("✅ Write complete", flush=True)


# ---------------------------
# Main
# ---------------------------

def main():

    print("\n🚀 royerlraph79 AdGuard Blocklist Generator\n", flush=True)

    cache = load_cache()

    with open(SOURCE_FILE) as f:

        sources = [
            s.strip()
            for s in f
            if s.strip() and not s.strip().startswith("#")
        ]

    all_domains = set()

    total_sources = len(sources)

    for i, url in enumerate(sources, 1):

        print(f"\n🌐 Source {i}/{total_sources}", flush=True)

        domains = fetch(url, cache)

        all_domains |= domains

        print(f"   Total collected: {len(all_domains)}", flush=True)

    print("\n🧠 Raw domains:", len(all_domains), flush=True)

    clean = dedupe(all_domains)

    print("🧠 Final domains:", len(clean), flush=True)

    write(clean)

    save_cache(cache)

    print("\n🏁 Done.\n", flush=True)


if __name__ == "__main__":
    main()
