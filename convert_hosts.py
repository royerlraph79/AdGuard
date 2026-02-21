#!/usr/bin/env python3
# royerlraph79 AdGuard Blocklist generator
# Optimized for AdGuard iOS DNS-level blocking

import requests
import re
import json
import hashlib
import time
from pathlib import Path

CACHE_FILE = "cache.json"
OUTPUT_FILE = "adguard_blocklist.txt"
SOURCES_FILE = "sources.txt"

# strict domain validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

INVALID_PREFIXES = (
    "-",
    ".",
    "*",
)

INVALID_CHARS = set("* _ / : ? & = %")

HEADERS = {
    "User-Agent": "royerlraph79-adguard-blocklist-generator"
}


# ------------------------------------------------------------
# cache handling
# ------------------------------------------------------------

def load_cache():
    if Path(CACHE_FILE).exists():
        return json.loads(Path(CACHE_FILE).read_text())
    return {}


def save_cache(cache):
    Path(CACHE_FILE).write_text(json.dumps(cache, indent=2))


# ------------------------------------------------------------
# hashing
# ------------------------------------------------------------

def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------
# sources loading
# ------------------------------------------------------------

def load_sources():
    if not Path(SOURCES_FILE).exists():
        print("❌ sources.txt not found")
        exit(1)

    sources = []

    for line in Path(SOURCES_FILE).read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        sources.append(line)

    return sources


# ------------------------------------------------------------
# download
# ------------------------------------------------------------

def download(url):

    try:
        r = requests.get(url, headers=HEADERS, timeout=60)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"❌ Failed: {url} ({e})")
        return None


# ------------------------------------------------------------
# domain cleaning
# ------------------------------------------------------------

def extract_domain(line):

    line = line.strip()

    if not line:
        return None

    if line.startswith("!"):
        return None

    if line.startswith("#"):
        return None

    # remove adguard syntax
    line = line.replace("||", "")
    line = line.replace("^", "")

    # remove hosts prefixes
    if line.startswith("0.0.0.0 "):
        line = line[8:]

    if line.startswith("127.0.0.1 "):
        line = line[10:]

    # remove wildcard prefix
    if line.startswith("*."):
        line = line[2:]

    # reject wildcard anywhere
    if "*" in line:
        return None

    # reject invalid prefixes
    for prefix in INVALID_PREFIXES:
        if line.startswith(prefix):
            return None

    # reject invalid chars
    if any(c in line for c in INVALID_CHARS):
        return None

    line = line.lower().strip()

    if not DOMAIN_REGEX.match(line):
        return None

    return line


# ------------------------------------------------------------
# deduplication
# ------------------------------------------------------------

def deduplicate(domains):

    print("\n🧹 Deduplicating safely...")

    domains = sorted(domains)
    final = set()

    for domain in domains:

        parts = domain.split(".")
        redundant = False

        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in final:
                redundant = True
                break

        if not redundant:
            final.add(domain)

    print(f"🧠 Final domains: {len(final)}")

    return sorted(final)


# ------------------------------------------------------------
# main
# ------------------------------------------------------------

def main():

    print("🚀 royerlraph79 AdGuard Blocklist generator\n")

    cache = load_cache()
    new_cache = {}

    sources = load_sources()

    all_domains = set()

    for url in sources:

        data = download(url)

        if not data:
            continue

        digest = sha256(data)

        new_cache[url] = digest

        if cache.get(url) == digest:
            print(f"⏭️ Unchanged: {url}")
        else:
            print(f"⬇️ Updated: {url}")

        text = data.decode("utf-8", errors="ignore")

        for line in text.splitlines():

            domain = extract_domain(line)

            if domain:
                all_domains.add(domain)

    print(f"\n🧠 Raw domains: {len(all_domains)}")

    domains = deduplicate(all_domains)

    # ------------------------------------------------------------
    # write output
    # ------------------------------------------------------------

    with open(OUTPUT_FILE, "w") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n")
        f.write(f"! Generated: {time.ctime()}\n")
        f.write(f"! Domains: {len(domains)}\n\n")

        for d in domains:
            f.write(f"||{d}^\n")

    save_cache(new_cache)

    print("\n🏁 Done.")


# ------------------------------------------------------------

if __name__ == "__main__":
    main()
