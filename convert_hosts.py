import re
import requests
from typing import Set, Tuple, Dict

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

COMMENT_PREFIXES = ("#", "!", "//", ";")
SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"

DEFAULT_STATS = {
    "total_lines": 0,
    "adblock_rules": 0,
    "hosts_rules": 0,
    "plain_domains": 0,
    "invalid_lines": 0,
    "duplicates": 0,
    "added": 0,
    "skipped": 0,
}


def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.split(":")[0]
    if d.startswith("*."):
        d = d[2:]
    d = d.rstrip(".^")
    return d if "." in d else ""


def extract_domain_from_adblock_rule(line: str) -> str:
    if line.startswith("@@"):
        return ""  # skip whitelist rules
    m = re.match(r"^\|\|([^\^/]+)", line)
    return m.group(1) if m else ""


def load_domains_from_url(url: str, seen: Set[str]) -> Tuple[Set[str], Dict[str, int]]:
    print(f"\n🔗 Fetching: {url}")
    stats = DEFAULT_STATS.copy()
    domains = set()

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        text = r.text
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        return domains, stats

    for raw in text.splitlines():
        stats["total_lines"] += 1
        ln = raw.strip()

        if not ln or ln.startswith(COMMENT_PREFIXES):
            stats["invalid_lines"] += 1
            continue

        token = ""

        ad = extract_domain_from_adblock_rule(ln)
        if ad:
            token = ad
            stats["adblock_rules"] += 1
        else:
            hm = HOSTS_RE.match(ln)
            if hm:
                token = hm.group(1)
                stats["hosts_rules"] += 1
            else:
                token = ln.split()[0]
                stats["plain_domains"] += 1

        domain = normalize_domain(token)
        if not domain:
            stats["invalid_lines"] += 1
            continue

        if domain in seen:
            stats["duplicates"] += 1
            continue

        seen.add(domain)
        domains.add(domain)
        stats["added"] += 1

    stats["skipped"] = stats["invalid_lines"] + stats["duplicates"]
    return domains, stats


def remove_redundant_subdomains(domains: Set[str]) -> Set[str]:
    """
    Keep base domains and remove any domain that is a subdomain
    of an already-kept base domain.
    """
    final = set()
    for domain in sorted(domains):  # alphabetical sort = stable output
        if any(domain == base or domain.endswith("." + base) for base in final):
            continue
        final.add(domain)
    return final


def main():
    with open(SOURCE_FILE, "r") as f:
        urls = [
            l.strip()
            for l in f
            if l.strip() and not l.startswith(COMMENT_PREFIXES)
        ]

    all_domains = set()
    overall = DEFAULT_STATS.copy()
    overall["sources"] = 0
    overall["parsed_total"] = 0

    for url in urls:
        domains, stats = load_domains_from_url(url, all_domains)
        overall["sources"] += 1
        overall["parsed_total"] += stats["total_lines"]

        for k in DEFAULT_STATS:
            overall[k] += stats[k]

        print(f"📊 Stats for {url}")
        print(f"  Total lines:   {stats['total_lines']}")
        print(f"  Added:         {stats['added']}")
        print(f"  Skipped:       {stats['skipped']}")

    final_domains = remove_redundant_subdomains(all_domains)

    print(f"\n✅ Writing {len(final_domains)} rules to {OUTPUT_FILE}")
    with open(OUTPUT_FILE, "w") as f:
        for d in sorted(final_domains):
            clean = d.rstrip("^")
            f.write(f"||{clean}^\n")

    print("\n📈 Overall Summary")
    print(f"  Sources:        {overall['sources']}")
    print(f"  Lines parsed:   {overall['parsed_total']}")
    print(f"  Unique domains: {len(final_domains)}")
    print(f"  Added:          {overall['added']}")
    print(f"  Duplicates:     {overall['duplicates']}")
    print(f"  Skipped:        {overall['skipped']}")
    print("\n🏁 Done!")


if __name__ == "__main__":
    main()