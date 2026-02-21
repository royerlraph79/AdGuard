import re
import json
import requests
from typing import Set, Dict

# ============================================================
# CONFIG
# ============================================================

SOURCE_FILE = "sources.txt"

OUTPUT_FILE = "adguard_blocklist.txt"
OUTPUT_MOBILE_FILE = "adguard_blocklist_mobile.txt"

CACHE_FILE = "cache.json"

USER_AGENT = "royerlraph79-AdGuard-Blocklist/1.0"

COMMENT_PREFIXES = ("#", "!", "//", ";")


# ============================================================
# DNS VALIDATION (STRICT RFC)
# ============================================================

LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE
)

TLD_RE = re.compile(
    r"^[a-z]{2,63}$",
    re.IGNORECASE
)


def is_valid_domain(domain: str) -> bool:

    if len(domain) > 253:
        return False

    parts = domain.split(".")

    if len(parts) < 2:
        return False

    for label in parts:

        if not LABEL_RE.match(label):
            return False

    tld = parts[-1]

    if not TLD_RE.match(tld):
        return False

    return True


# ============================================================
# PARSERS
# ============================================================

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

ADB_RULE_RE = re.compile(
    r"^\|\|([a-z0-9.*-]+)\^",
    re.IGNORECASE
)

SCHEME_RE = re.compile(
    r"^https?://",
    re.IGNORECASE
)


def is_comment(line: str) -> bool:

    s = line.strip()

    return not s or s.startswith(COMMENT_PREFIXES)


def extract_domain(line: str) -> str:

    if line.startswith("@@"):
        return ""

    m = ADB_RULE_RE.match(line)
    if m:
        return m.group(1)

    m = HOSTS_RE.match(line)
    if m:
        return m.group(1)

    token = line.split()[0]

    return token


def normalize_domain(token: str) -> str:

    d = token.strip().lower()

    if not d:
        return ""

    d = SCHEME_RE.sub("", d)

    d = d.split("/")[0]
    d = d.split("?")[0]
    d = d.split("#")[0]
    d = d.split(":")[0]

    if d.startswith("*."):
        d = d[2:]

    d = d.strip(".^")

    if "*" in d:
        return d

    if not is_valid_domain(d):
        return ""

    return d


# ============================================================
# CACHE
# ============================================================

def load_cache() -> Dict:

    try:

        with open(CACHE_FILE, "r") as f:
            return json.load(f)

    except:
        return {}


def save_cache(cache: Dict):

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


# ============================================================
# LOAD SOURCES FROM sources.txt
# ============================================================

def load_sources():

    with open(SOURCE_FILE, "r", encoding="utf-8") as f:

        return [
            line.strip()
            for line in f
            if not is_comment(line)
        ]


# ============================================================
# FETCH
# ============================================================

def fetch(url: str) -> str:

    r = requests.get(
        url,
        timeout=60,
        headers={"User-Agent": USER_AGENT}
    )

    r.raise_for_status()

    return r.text


# ============================================================
# BUILD DOMAIN SET
# ============================================================

def build_domains():

    print("🚀 Generating royerlraph79 AdGuard Blocklist")

    cache = load_cache()

    sources = load_sources()

    all_domains: Set[str] = set()

    for url in sources:

        try:

            print(f"🔗 Fetching: {url}")

            text = fetch(url)

            added = 0

            for line in text.splitlines():

                if is_comment(line):
                    continue

                raw = extract_domain(line)

                domain = normalize_domain(raw)

                if not domain:
                    continue

                all_domains.add(domain)

                added += 1

            print(f"   Added: {added}")

            cache[url] = {"ok": True}

        except Exception as e:

            print(f"❌ Error: {url} → {e}")

    save_cache(cache)

    print(f"🧠 Raw domains: {len(all_domains)}")

    return all_domains


# ============================================================
# DEDUPE
# ============================================================

def dedupe(domains: Set[str]) -> Set[str]:

    print("🧹 Deduplicating")

    plain = set()
    wildcards = set()

    for d in domains:

        if "*" in d:
            wildcards.add(d)
        else:
            plain.add(d)

    result = plain | wildcards

    print(f"🧠 Final domains: {len(result)}")

    return result


# ============================================================
# WRITE MAIN LIST
# ============================================================

MAIN_HEADER = """! Title: royerlraph79 AdGuard Blocklist
! Expires: 24 hours

"""


def write_main(domains: Set[str]):

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write(MAIN_HEADER)

        for d in sorted(domains):

            f.write(f"||{d}^\n")


# ============================================================
# WRITE MOBILE LIST
# ============================================================

MOBILE_HEADER = """! Title: royerlraph79 AdGuard Blocklist Mobile
! Expires: 24 hours

"""


def write_mobile(domains: Set[str]):

    mobile = {d for d in domains if "*" not in d}

    print(f"📱 Mobile domains: {len(mobile)}")

    with open(OUTPUT_MOBILE_FILE, "w", encoding="utf-8") as f:

        f.write(MOBILE_HEADER)

        for d in sorted(mobile):

            f.write(f"||{d}^\n")


# ============================================================
# MAIN
# ============================================================

def main():

    domains = build_domains()

    domains = dedupe(domains)

    write_main(domains)

    write_mobile(domains)

    print("🏁 Done")


if __name__ == "__main__":
    main()
