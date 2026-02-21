#!/usr/bin/env python3

import requests
import hashlib
import json
import re
import os
from typing import Dict, Set

CACHE_FILE = "cache.json"
OUTPUT_FILE = "adguard_blocklist.txt"
OUTPUT_MOBILE_FILE = "adguard_blocklist_mobile.txt"

HEADERS = {
    "User-Agent": "Raph-AdGuard-Generator/3.0"
}

TIMEOUT = 60


SOURCES = [

    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/urlshortener.txt",
    "https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt",
    "https://blocklistproject.github.io/Lists/basic.txt",
    "https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt",

]


DOMAIN_RE = re.compile(
    r"(?:\|\||0\.0\.0\.0\s+|127\.0\.0\.1\s+)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
)


def load_cache() -> Dict:

    if os.path.exists(CACHE_FILE):

        try:

            with open(CACHE_FILE, "r") as f:
                return json.load(f)

        except:
            return {}

    return {}


def save_cache(cache: Dict):

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def extract(line: str):

    line = line.strip()

    if not line or line.startswith("!") or line.startswith("#"):
        return None

    m = DOMAIN_RE.search(line)

    if not m:
        return None

    d = m.group(1).lower()

    if "." not in d:
        return None

    return d


def fetch(url: str, cache: Dict) -> Set[str]:

    try:

        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)

        if r.status_code != 200:

            print(f"❌ HTTP {r.status_code}: {url}")

            if url in cache:
                print(f"⚠️ Using cached domains")
                return set(cache[url].get("domains", []))

            return set()

        text = r.text

        sha = hashlib.sha256(text.encode()).hexdigest()

        entry = cache.get(url, {})

        cached_sha = entry.get("sha", "")
        cached_domains = set(entry.get("domains", []))

        if sha == cached_sha and cached_domains:

            print(f"⏭️ Unchanged (using cache): {url}")

            return cached_domains

        print(f"🔄 Updated: {url}")

        domains = set()

        for line in text.splitlines():

            d = extract(line)

            if d:
                domains.add(d)

        cache[url] = {

            "sha": sha,
            "etag": r.headers.get("ETag", ""),
            "last_modified": r.headers.get("Last-Modified", ""),
            "domains": list(domains),

        }

        return domains

    except Exception as e:

        print(f"❌ Error {url}: {e}")

        if url in cache:

            print(f"⚠️ Using cached domains")

            return set(cache[url].get("domains", []))

        return set()


def write_adguard(path: str, domains: Set[str]):

    with open(path, "w") as f:

        f.write("! Title: Raph AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n\n")

        for d in sorted(domains):
            f.write(f"||{d}^\n")


def mobile_optimize(domains: Set[str]) -> Set[str]:

    optimized = set()

    for d in domains:

        parts = d.split(".")

        if len(parts) >= 2:

            optimized.add(".".join(parts[-2:]))

    return optimized


def main():

    print("🚀 Blocklist generator with incremental updates\n")

    cache = load_cache()

    all_domains = set()

    for url in SOURCES:

        domains = fetch(url, cache)

        all_domains.update(domains)

    print(f"\n🧠 Raw domains: {len(all_domains)}")

    print("\n🧹 Deduplicating safely...")

    final = set(all_domains)

    print(f"🧠 Final domains: {len(final)}")

    print("\n📱 Creating mobile optimized version...")

    mobile = mobile_optimize(final)

    print(f"📱 Mobile domains: {len(mobile)}")

    write_adguard(OUTPUT_FILE, final)

    write_adguard(OUTPUT_MOBILE_FILE, mobile)

    save_cache(cache)

    print("\n🏁 Done.")


if __name__ == "__main__":

    main()
