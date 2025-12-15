import re
import requests
from typing import Set

# Only match explicit 0.0.0.0 / 127.0.0.1 / ::1 entries
HOSTS_RE = re.compile(
    r"^\s*(?P<ip>0\.0\.0\.0|127\.0\.0\.1|::1)\s+(?P<domain>[^\s#]+)",
    re.IGNORECASE
)

# Skip comments starting with any of these
COMMENT_PREFIXES = ("#", "!", "//", ";")

# Sources list file
SOURCE_FILE = "sources.txt"

# Output blocklist file
OUTPUT_FILE = "adguard_blocklist.txt"


def normalize_domain(d: str) -> str:
    """Normalize domain by stripping unwanted parts."""
    d = d.strip().lower()

    # Strip protocol
    if d.startswith("http://") or d.startswith("https://"):
        d = re.sub(r"^https?://", "", d)

    # Remove paths
    d = d.split("/")[0]

    # Handle wildcard entries
    if d.startswith("*."):
        d = d[2:]

    # Remove port numbers
    d = d.split(":")[0]

    # Remove trailing dot
    if d.endswith("."):
        d = d[:-1]

    # Sanity check
    if not d or "." not in d:
        return ""

    return d


def extract_domain_from_adblock_rule(rule: str) -> str:
    """Extract domain from AdBlock-style rule if possible."""
    # Skip exception rules
    if rule.startswith("@@"):
        return ""

    # Try standard AdBlock syntax
    match = re.match(r"^\|\|([^\^/]+)", rule)
    if match:
        return match.group(1)

    return ""


def load_domains_from_url(url: str) -> Set[str]:
    print(f"Fetching: {url}")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return set()

    text = r.text
    domains = set()

    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            continue

        token = None

        # Try to extract domain from AdBlock-style rule
        ab = extract_domain_from_adblock_rule(ln)
        if ab:
            token = ab
        else:
            # Try to match 0.0.0.0 or 127.0.0.1 hosts format
            m = HOSTS_RE.match(ln)
            if m:
                token = m.group("domain")
            else:
                # Try plain domain line
                parts = ln.split()
                if parts:
                    token = parts[0]

        if not token:
            continue

        domain = normalize_domain(token)
        if domain:
            domains.add(domain)

    return domains


def main():
    print("Reading source URLs...")
    with open(SOURCE_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith(COMMENT_PREFIXES)]

    all_domains = set()

    for url in urls:
        domains = load_domains_from_url(url)
        print(f"✔ {len(domains)} domains from {url}")
        all_domains.update(domains)

    print(f"\nTotal unique domains: {len(all_domains)}")
    print(f"Writing to {OUTPUT_FILE}...")

    with open(OUTPUT_FILE, "w") as f:
        for d in sorted(all_domains):
            f.write(f"||{d}^\n")

    print("Done ✅")


if __name__ == "__main__":
    main()
