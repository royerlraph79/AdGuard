#!/usr/bin/env python3

import requests
import json
import hashlib
import os
import time
import socket
import concurrent.futures

# ================================
# CONFIG
# ================================

OUTPUT_FULL = "adguard_blocklist.txt"
OUTPUT_MOBILE = "adguard_blocklist_mobile.txt"
CACHE_FILE = "cache.json"

DEAD_SCORE_THRESHOLD = 3
DNS_TEST_SAMPLE_RATE = 0.05
DNS_TIMEOUT = 1.5
DNS_THREADS = 32

BLOCKLIST_URLS = [

    "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://badmojr.github.io/1Hosts/Lite/adblock.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/urlshortener.txt",
    "https://blocklistproject.github.io/Lists/adguard/tracking-ags.txt",
    "https://blocklistproject.github.io/Lists/basic.txt",
    "https://blocklistproject.github.io/Lists/adguard/ransomware-ags.txt",
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt"

]

HEADERS = {
    "User-Agent": "AdGuardBlocklistBuilder/2.0"
}

# ================================
# CACHE
# ================================

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

# ================================
# FETCH
# ================================

def fetch(url, cache):

    try:

        r = requests.get(url, headers=HEADERS, timeout=30)

        if r.status_code != 200:
            print(f"❌ Failed: {url}")
            return []

        text = r.text
        sha = hashlib.sha256(text.encode()).hexdigest()

        if url in cache and cache[url]["sha"] == sha:
            print(f"⏩ Unchanged: {url}")
            return cache[url]["domains"]

        print(f"🔄 Updated: {url}")

        domains = parse(text)

        cache[url] = {
            "sha": sha,
            "domains": domains
        }

        return domains

    except Exception as e:
        print(f"❌ Error {url}: {e}")
        return []

# ================================
# PARSER
# ================================

def parse(text):

    result = set()

    for line in text.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("!"):
            continue

        if line.startswith("#"):
            continue

        if line.startswith("["):
            continue

        if line.startswith("||"):
            domain = line[2:].split("^")[0]
            result.add(domain.lower())
            continue

        if line.startswith("0.0.0.0"):
            parts = line.split()
            if len(parts) > 1:
                result.add(parts[1].lower())
            continue

        if "." in line and " " not in line:
            result.add(line.lower())

    return list(result)

# ================================
# DNS TEST
# ================================

def resolves(domain):

    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        socket.gethostbyname(domain)
        return True
    except:
        return False

# ================================
# DEAD DOMAIN SCORING
# ================================

def score_domains(domains, cache):

    print("\n🧪 Testing sample for dead domains...")

    import random

    sample_size = int(len(domains) * DNS_TEST_SAMPLE_RATE)

    sample = random.sample(list(domains), sample_size)

    dead = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_THREADS) as executor:

        futures = {
            executor.submit(resolves, d): d
            for d in sample
        }

        for f in concurrent.futures.as_completed(futures):

            d = futures[f]

            if not f.result():
                dead.add(d)

    print(f"🪦 Dead in sample: {len(dead)}")

    scores = cache.get("dead_scores", {})

    for d in dead:
        scores[d] = scores.get(d, 0) + 1

    cache["dead_scores"] = scores

    filtered = set()

    removed = 0

    for d in domains:

        score = scores.get(d, 0)

        if score >= DEAD_SCORE_THRESHOLD:
            removed += 1
            continue

        filtered.add(d)

    print(f"🧹 Removed dead domains: {removed}")

    return filtered

# ================================
# SAFE DEDUP
# ================================

def dedupe(domains):

    print("\n🧹 Deduplicating safely...")

    domains = set(domains)

    result = set()

    for d in domains:

        parts = d.split(".")

        keep = True

        for i in range(1, len(parts) - 1):

            parent = ".".join(parts[i:])

            if parent in domains:
                keep = False
                break

        if keep:
            result.add(d)

    print(f"🧠 Final domains: {len(result)}")

    return result

# ================================
# MOBILE OPTIMIZATION
# ================================

def create_mobile(domains):

    print("\n📱 Creating mobile optimized version...")

    domain_set = set(domains)

    result = set()

    for d in domains:

        depth = d.count(".")

        if depth <= 2:
            result.add(d)
            continue

        if "*" in d:
            result.add(d)
            continue

        parts = d.split(".")

        parent_exists = False

        for i in range(1, len(parts) - 1):

            parent = ".".join(parts[i:])

            if parent in domain_set:
                parent_exists = True
                break

        if not parent_exists or depth <= 3:
            result.add(d)

    print(f"📱 Mobile domains: {len(result)}")

    return result

# ================================
# WRITE
# ================================

def write_file(filename, domains):

    with open(filename, "w") as f:

        for d in sorted(
            domains,
            key=lambda d: (d.count("."), len(d), d)
        ):
            f.write(f"||{d}^\n")

# ================================
# MAIN
# ================================

def main():

    print("🚀 Blocklist generator with incremental updates\n")

    cache = load_cache()

    raw = set()

    for url in BLOCKLIST_URLS:

        raw.update(fetch(url, cache))

    print(f"\n🧠 Raw domains: {len(raw)}")

    filtered = score_domains(raw, cache)

    final = dedupe(filtered)

    mobile = create_mobile(final)

    write_file(OUTPUT_FULL, final)

    write_file(OUTPUT_MOBILE, mobile)

    save_cache(cache)

    print("\n🏁 Done.")

# ================================

if __name__ == "__main__":
    main()
