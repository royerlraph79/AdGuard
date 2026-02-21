import re
import sys
import json
import hashlib
import requests
from typing import Set, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter

# ---------------------------
# Config
# ---------------------------

SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"
CACHE_FILE = "cache.json"

MAX_WORKERS = 10

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
TRAILING_OPTIONS_RE = re.compile(r"\$.*$")

# ---------------------------
# HTTP session pooling
# ---------------------------

session = requests.Session()

adapter = HTTPAdapter(
    pool_connections=MAX_WORKERS,
    pool_maxsize=MAX_WORKERS,
)

session.mount("http://", adapter)
session.mount("https://", adapter)

session.headers.update({
    "User-Agent": "blocklist-gen/2.0"
})

# ---------------------------
# Cache handling
# ---------------------------

def load_cache():

    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_cache(cache):

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


# ---------------------------
# Parsing
# ---------------------------

def is_comment_or_empty(line):

    ln = line.strip()

    return (not ln) or ln.startswith(COMMENT_PREFIXES)


def normalize_token(token):

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

    if any(ch.isspace() for ch in d):
        return ""

    return d


def extract_from_adblock_rule(line):

    ln = line.strip()

    if ln.startswith("@@"):
        return ""

    ln = TRAILING_OPTIONS_RE.sub("", ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)

    return m.group(1) if m else ""


def choose_token(line):

    ad = extract_from_adblock_rule(line)

    if ad:
        return ad

    hm = HOSTS_RE.match(line)

    if hm:
        return hm.group(1)

    if line:
        return line.split()[0]

    return ""


# ---------------------------
# Wildcard logic
# ---------------------------

def glob_to_regex(glob):

    esc = re.escape(glob.lower())

    esc = esc.replace(r"\*", r"[a-z0-9][a-z0-9.-]*")

    return re.compile(rf"^{esc}$", re.IGNORECASE)


def remove_plain_covered_by_wildcards(plain, wildcards):

    if not wildcards:
        return plain

    regexes = [glob_to_regex(w) for w in wildcards]

    return {
        d for d in plain
        if not any(rx.match(d) for rx in regexes)
    }


def remove_wildcards_covered_by_base_domain(plain, wildcards):

    result = set()

    for w in wildcards:

        parts = w.split(".")

        redundant = False

        for i in range(len(parts)):

            base = ".".join(parts[i:])

            if base in plain:

                redundant = True
                break

        if not redundant:
            result.add(w)

    return result


# ---------------------------
# Trie redundancy removal (DNS SAFE)
# ---------------------------

class TrieNode:

    __slots__ = ("children", "block")

    def __init__(self):

        self.children = {}
        self.block = False


def remove_redundant_subdomains(domains):

    root = TrieNode()

    result = set()

    for domain in sorted(domains, key=lambda d: d.count(".")):

        node = root

        parts = domain.split(".")

        redundant = False

        for part in reversed(parts):

            if node.block:

                redundant = True
                break

            node = node.children.setdefault(part, TrieNode())

        if not redundant:

            node.block = True

            result.add(domain)

    return result


def dedupe_domains(domains):

    print("🧹 Deduplicating safely for DNS...")

    plain = {d for d in domains if "*" not in d}

    wildcards = {d for d in domains if "*" in d}

    plain = remove_redundant_subdomains(plain)

    wildcards = remove_wildcards_covered_by_base_domain(
        plain,
        wildcards
    )

    plain = remove_plain_covered_by_wildcards(
        plain,
        wildcards
    )

    return plain | wildcards


# ---------------------------
# Fetch with incremental support
# ---------------------------

def fetch_source(url, cache):

    headers = {}

    if url in cache:

        if "etag" in cache[url]:
            headers["If-None-Match"] = cache[url]["etag"]

        if "last_modified" in cache[url]:
            headers["If-Modified-Since"] = cache[url]["last_modified"]

    try:

        r = session.get(url, headers=headers, timeout=30)

        if r.status_code == 304:

            print(f"⚡ Unchanged: {url}")

            return set(cache[url]["domains"])

        r.raise_for_status()

        domains = set()

        for raw in r.text.splitlines():

            if is_comment_or_empty(raw):
                continue

            token = choose_token(raw)

            domain = normalize_token(token)

            if domain:
                domains.add(domain)

        cache[url] = {

            "etag": r.headers.get("ETag"),

            "last_modified": r.headers.get("Last-Modified"),

            "domains": list(domains)
        }

        print(f"🔄 Updated: {url}")

        return domains

    except Exception as e:

        print(f"❌ Failed: {url} → {e}")

        if url in cache:
            return set(cache[url]["domains"])

        return set()


# ---------------------------
# Main
# ---------------------------

def main():

    print("🚀 Blocklist generator with incremental updates\n")

    cache = load_cache()

    with open(SOURCE_FILE) as f:

        urls = [
            l.strip()
            for l in f
            if not is_comment_or_empty(l)
        ]

    all_domains = set()

    with ThreadPoolExecutor(MAX_WORKERS) as executor:

        futures = {
            executor.submit(fetch_source, url, cache): url
            for url in urls
        }

        for future in as_completed(futures):

            domains = future.result()

            all_domains.update(domains)

    print(f"\n🧠 Raw domains: {len(all_domains)}")

    final = dedupe_domains(all_domains)

    print(f"🧠 Final domains: {len(final)}")

    with open(OUTPUT_FILE, "w") as f:

        for d in sorted(final):
            f.write(f"||{d}^\n")

    save_cache(cache)

    print("\n🏁 Done.")


if __name__ == "__main__":
    main()
