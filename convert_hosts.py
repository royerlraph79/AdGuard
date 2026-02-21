import re
import requests

SOURCE_FILE = "sources.txt"

OUTPUT_FILE = "adguard_blocklist.txt"
OUTPUT_MOBILE_FILE = "adguard_blocklist_mobile.txt"

USER_AGENT = "royerlraph79-AdGuard-Blocklist/1.0"


# ============================================================
# STRICT DOMAIN VALIDATION
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

    if "*" in domain:
        return False

    if domain.startswith("-"):
        return False

    if domain.endswith("-"):
        return False

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
# EXTRACTION
# ============================================================

def extract_domain(line: str) -> str:

    line = line.strip()

    if not line:
        return ""

    if line.startswith(("!", "#", "@@")):
        return ""

    # AdGuard rule
    if line.startswith("||"):

        d = line[2:]

        if "^" in d:
            d = d.split("^", 1)[0]

    # hosts file
    elif line.startswith(("0.0.0.0", "127.0.0.1", "::1")):

        parts = line.split()

        if len(parts) < 2:
            return ""

        d = parts[1]

    else:

        d = line.split()[0]

    # remove scheme
    if d.startswith("http://"):
        d = d[7:]

    if d.startswith("https://"):
        d = d[8:]

    # remove path
    d = d.split("/")[0]

    # remove port
    d = d.split(":")[0]

    d = d.strip(".")

    return d.lower()


# ============================================================
# LOAD SOURCES
# ============================================================

def load_sources():

    with open(SOURCE_FILE, encoding="utf-8") as f:

        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


# ============================================================
# FETCH
# ============================================================

def fetch(url):

    r = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=60
    )

    r.raise_for_status()

    return r.text


# ============================================================
# BUILD DOMAIN SET
# ============================================================

def build_domains():

    domains = set()

    for url in load_sources():

        print("Fetching:", url)

        try:

            text = fetch(url)

        except Exception as e:

            print("Error:", e)
            continue

        for line in text.splitlines():

            domain = extract_domain(line)

            if not domain:
                continue

            if not is_valid_domain(domain):
                continue

            domains.add(domain)

    print("Raw domains:", len(domains))

    return domains


# ============================================================
# REMOVE REDUNDANT SUBDOMAINS
# ============================================================

def dedupe(domains):

    domains = set(domains)

    result = set()

    for domain in sorted(domains):

        parts = domain.split(".")

        redundant = False

        for i in range(1, len(parts)):

            parent = ".".join(parts[i:])

            if parent in domains:

                redundant = True
                break

        if not redundant:
            result.add(domain)

    print("Final domains:", len(result))

    return result


# ============================================================
# WRITE FILES
# ============================================================

def write_main(domains):

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist\n")
        f.write("! Expires: 24 hours\n\n")

        for d in sorted(domains):
            f.write(f"||{d}^\n")


def write_mobile(domains):

    with open(OUTPUT_MOBILE_FILE, "w", encoding="utf-8") as f:

        f.write("! Title: royerlraph79 AdGuard Blocklist Mobile\n")
        f.write("! Expires: 24 hours\n\n")

        for d in sorted(domains):
            f.write(f"||{d}^\n")


# ============================================================
# MAIN
# ============================================================

def main():

    domains = build_domains()

    domains = dedupe(domains)

    write_main(domains)

    write_mobile(domains)

    print("Done.")


if __name__ == "__main__":
    main()
