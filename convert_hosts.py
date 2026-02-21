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
# STRICT DNS VALIDATION
# ============================================================

LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE
)

TLD_RE = re.compile(
    r"^[a-z]{2,63}$",
    re.IGNORECASE
)

SCHEME_RE = re.compile(
    r"^https?://",
    re.IGNORECASE
)

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

ADB_RULE_RE = re.compile(
    r"^\|\|([^\^/]+)\^",
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

    if not TLD_RE.match(parts[-1]):
        return False

    return True


# ============================================================
# DOMAIN NORMALIZATION
# ============================================================

def normalize_domain(token: str) -> str:

    d = token.strip().lower()

    if not d:
        return ""

    d = SCHEME_RE.sub("", d)

    d = d.split("/")[0]
    d = d.split("?")[0]
    d = d.split("#")[0]
    d = d.split(":")[0]

    d = d.strip(".^")

    # reject ALL wildcards (useless in DNS if root exists)
    if "*" in d:
        return ""

    if not is_valid_domain(d):
        return ""

    return d


# ============================================================
# PARSING
# ============================================================

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

    return line.split()[0]


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
# LOAD SOURCES
# ============================================================

def load_sources():

    with open(SOURCE_FILE, encoding="utf-8") as f:

        return [
            line.strip()
            for line in f
            if not is_comment(line)
        ]


# ============================================================
# BUILD DOMAIN SET
# ============================================================

def build_domains() -> Set[str]:

    print("🚀 Generating royerlraph79 AdGuard Blocklist")

    domains = set()

    sources = load_sources()

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

                domains.add(domain)

                added += 1

            print(f"   Added: {added}")

        except Exception as e:

            print(f"❌ Error: {url} → {e}")

    print(f"🧠 Raw domains: {len(domains)}")

    return domains


# ============================================================
# ROOT DOMAIN DEDUPLICATION
# ============================================================

def dedupe_domains(domains: Set[str]) -> Set[str]:

    print("🧹 Removing redundant subdomains")

    domain_set = set(domains)

    result = set()

    for domain in sorted(domain_set):

        parts = domain.split(".")

        redundant = False

        for i in range(1, len(parts)):

            parent = ".".join(parts[i:])

            if parent in domain_set:
                redundant = True
                break

        if not redundant:
            result.add(domain)

    print(f"🧠 Final domains: {len(result)}")

    return result


# ============================================================
# WRITE FILES
# ============================================================

MAIN_HEADER = """! Title: royerlraph79 AdGuard Blocklist
! Expires: 24 hours

"""

MOBILE_HEADER = """! Title: royerlraph79 AdGuard Blocklist Mobile
! Expires: 24 hours

"""


def write_main(domains: Set[str]):

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write(MAIN_HEADER)

        for d in sorted(domains):
            f.write(f"||{d}^\n")


def write_mobile(domains: Set[str]):

    mobile = set(domains)

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

    domains = dedupe_domains(domains)

    write_main(domains)

    write_mobile(domains)

    print("🏁 Done")


if __name__ == "__main__":
    main()
