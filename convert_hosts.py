import os
import re
import json
import hashlib
import random
import socket
import requests
from typing import Set, Dict

# ============================================================
# CONFIG
# ============================================================

CACHE_FILE = "cache.json"
OUTPUT_FILE = "adguard_blocklist.txt"
MOBILE_OUTPUT_FILE = "adguard_blocklist_mobile.txt"

TEST_SAMPLE_SIZE = 1000
DEAD_THRESHOLD = 3

TIMEOUT = 20

HEADERS = {
    "User-Agent": "Raph-AdGuard-Blocklist/1.0"
}

# ============================================================
# CACHE HANDLING (AUTO-REPAIR)
# ============================================================

def load_cache() -> Dict:

    if not os.path.exists(CACHE_FILE):
        print("🆕 No cache found, creating new")
        return {}

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        print(f"⚠️ Cache corrupted, resetting: {e}")
        return {}

    migrated = {}
    repaired = False

    for url, entry in raw.items():

        # new format
        if isinstance(entry, dict):

            migrated[url] = {
                "sha": entry.get("sha", ""),
                "etag": entry.get("etag", ""),
                "last_modified": entry.get("last_modified", ""),
                "dead_score": entry.get("dead_score", 0),
            }

        # old format
        elif isinstance(entry, str):

            migrated[url] = {
                "sha": entry,
                "etag": "",
                "last_modified": "",
                "dead_score": 0,
            }

            repaired = True

        else:

            repaired = True

    if repaired:
        print("🔧 Cache auto-repaired")

    return migrated


def save_cache(cache: Dict):

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

HOSTS_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE,
)

ADBLOCK_RE = re.compile(r"^\|\|([^\^\/]+)")

SCHEME_RE = re.compile(r"^https?:\/\/", re.IGNORECASE)


def normalize(domain: str) -> str:

    d = domain.strip().lower()

    d = SCHEME_RE.sub("", d)
    d = d.split("/")[0]
    d = d.split(":")[0]

    if d.startswith("*."):
        d = d[2:]

    d = d.rstrip(".^")

    if "." not in d:
        return ""

    return d


def extract(line: str) -> str:

    line = line.strip()

    if not line:
        return ""

    if line.startswith("#") or line.startswith("!"):
        return ""

    if line.startswith("@@"):
        return ""

    m = ADBLOCK_RE.match(line)
    if m:
        return normalize(m.group(1))

    m = HOSTS_RE.match(line)
    if m:
        return normalize(m.group(1))

    token = line.split()[0]
    return normalize(token)


# ============================================================
# FETCH
# ============================================================

def fetch(url: str, cache: Dict) -> Set[str]:

    try:

        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

        if r.status_code != 200:
            print(f"❌ HTTP {r.status_code}: {url}")
            return set()

        text = r.text

        sha = hashlib.sha256(text.encode()).hexdigest()

        cached_sha = cache.get(url, {}).get("sha", "")

        if sha == cached_sha:

            print(f"⏭️ Unchanged: {url}")
            return set()

        print(f"🔄 Updated: {url}")

        cache[url] = {
            "sha": sha,
            "etag": r.headers.get("ETag", ""),
            "last_modified": r.headers.get("Last-Modified", ""),
            "dead_score": 0,
        }

        domains = set()

        for line in text.splitlines():

            d = extract(line)

            if d:
                domains.add(d)

        return domains

    except Exception as e:

        print(f"❌ Error {url}: {e}")
        return set()


# ============================================================
# DEAD DOMAIN TEST
# ============================================================

def is_dead(domain: str) -> bool:

    try:

        socket.gethostbyname(domain)

        return False

    except:

        return True


def test_dead(domains: Set[str], cache: Dict) -> Set[str]:

    if not domains:
        return domains

    sample = random.sample(list(domains), min(TEST_SAMPLE_SIZE, len(domains)))

    dead = set()

    print("\n🧪 Testing sample for dead domains...")

    for d in sample:

        if is_dead(d):
            dead.add(d)

    print(f"🪦 Dead in sample: {len(dead)}")

    result = set()

    for d in domains:

        score = cache.get(d, {}).get("dead_score", 0)

        if d in dead:
            score += 1
        else:
            score = 0

        cache[d] = {"dead_score": score}

        if score < DEAD_THRESHOLD:
            result.add(d)

    removed = len(domains) - len(result)

    print(f"🧹 Removed dead domains: {removed}")

    return result


# ============================================================
# DEDUPE
# ============================================================

def dedupe(domains: Set[str]) -> Set[str]:

    print("\n🧹 Deduplicating safely...")

    plain = {d for d in domains if "*" not in d}

    final = set()

    for d in plain:

        parts = d.split(".")

        redundant = False

        for i in range(1, len(parts)):

            parent = ".".join(parts[i:])

            if parent in plain:
                redundant = True
                break

        if not redundant:
            final.add(d)

    print(f"🧠 Final domains: {len(final)}")

    return final


# ============================================================
# MOBILE OPTIMIZATION
# ============================================================

def mobile_optimize(domains: Set[str]) -> Set[str]:

    print("\n📱 Creating mobile optimized version...")

    result = set()

    for d in domains:

        if len(d) > 60:
            continue

        if d.count(".") > 4:
            continue

        result.add(d)

    print(f"📱 Mobile domains: {len(result)}")

    return result


# ============================================================
# WRITE
# ============================================================

def write_file(path: str, domains: Set[str]):

    with open(path, "w", encoding="utf-8") as f:

        f.write("! Title: Raph AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n\n")

        for d in sorted(domains):

            f.write(f"||{d}^\n")


# ============================================================
# MAIN
# ============================================================

def main():

    print("🚀 Blocklist generator with incremental updates\n")

    cache = load_cache()

    with open("sources.txt", "r", encoding="utf-8") as f:

        urls = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

    domains = set()

    for url in urls:

        domains |= fetch(url, cache)

    print(f"\n🧠 Raw domains: {len(domains)}")

    domains = test_dead(domains, cache)

    domains = dedupe(domains)

    mobile = mobile_optimize(domains)

    write_file(OUTPUT_FILE, domains)

    write_file(MOBILE_OUTPUT_FILE, mobile)

    save_cache(cache)

    print("\n🏁 Done.")


if __name__ == "__main__":
    main()
