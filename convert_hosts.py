import re
import requests
from typing import Set, Tuple, Dict

# Match lines like: 0.0.0.0 domain.com
HOSTS_RE = re.compile(
    r"^\s*(?P<ip>0\.0\.0\.0|127\.0\.0\.1|::1)\s+(?P<domain>[^\s#]+)",
    re.IGNORECASE
)

COMMENT_PREFIXES = ("#", "!", "//", ";")
SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"

# Default stat structure for each source
DEFAULT_STATS = {
    "total_lines": 0,
    "adblock_rules": 0,
    "hosts_rules": 0,
    "plain_domains": 0,
    "invalid_lines": 0,
    "added": 0,
    "duplicates": 0
}


def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    if d.startswith("*."):
        d = d[2:]
    d = d.split(":")[0]
    if d.endswith("."):
        d = d[:-1]
    return d if "." in d else ""


def extract_domain_from_adblock_rule(rule: str) -> str:
    if rule.startswith("@@"):
        return ""  # Whitelist rules should be skipped
    match = re.match(r"^\|\|([^\^/]+)", rule)
    return match.group(1) if match else ""


def load_domains_from_url(url: str, seen: Set[str]) -> Tuple[Set[str], Dict[str, int]]:
    print(f"\n🔗 Fetching: {url}")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        return set(), DEFAULT_STATS.copy()

    text = r.text
    domains = set()
    stats = DEFAULT_STATS.copy()

    for raw in text.splitlines():
        stats["total_lines"] += 1
        ln = raw.strip()
        if not ln or ln.startswith(COMMENT_PREFIXES):
            stats["invalid_lines"] += 1
            continue

        token = None

        ab = extract_domain_from_adblock_rule(ln)
        if ab:
            token = ab
            stats["adblock_rules"] += 1
        else:
            m = HOSTS_RE.match(ln)
            if m:
                token = m.group("domain")
                stats["hosts_rules"] += 1
            else:
                parts = ln.split()
                if parts:
                    token = parts[0]
                    stats["plain_domains"] += 1

        if not token:
            stats["invalid_lines"] += 1
            continue

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

    return domains, stats


def main():
    print("📄 Reading source URLs...")
    with open(SOURCE_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith(COMMENT_PREFIXES)]

    all_domains = set()
    overall_stats = DEFAULT_STATS.copy()
    overall_stats["sources"] = 0
    overall_stats["parsed_total"] = 0

    for url in urls:
        domains, stats = load_domains_from_url(url, all_domains)

        overall_stats["sources"] += 1
        overall_stats["parsed_total"] += stats["total_lines"]

        for k in stats:
            overall_stats[k] += stats[k]

        print(f"📊 Stats for {url}")
        print(f"  Total lines:     {stats['total_lines']}")
        print(f"  Adblock rules:   {stats['adblock_rules']}")
        print(f"  Hosts rules:     {stats['hosts_rules']}")
        print(f"  Plain domains:   {stats['plain_domains']}")
        print(f"  Invalid lines:   {stats['invalid_lines']}")
        print(f"  Added domains:   {stats['added']}")

    print(f"\n✅ Writing combined list to: {OUTPUT_FILE}")
    with open(OUTPUT_FILE, "w") as f:
        for d in sorted(all_domains):
            f.write(f"||{d}^\n")

    deduped = overall_stats["parsed_total"] - overall_stats["added"]

    print("\n📈 Overall Summary:")
    print(f"  Sources read:     {overall_stats['sources']}")
    print(f"  Total lines:      {overall_stats['parsed_total']}")
    print(f"  Unique domains:   {len(all_domains)}")
    print(f"  Adblock parsed:   {overall_stats['adblock_rules']}")
    print(f"  Hosts parsed:     {overall_stats['hosts_rules']}")
    print(f"  Plain parsed:     {overall_stats['plain_domains']}")
    print(f"  Invalid lines:    {overall_stats['invalid_lines']}")
    print(f"  Duplicates found: {overall_stats['duplicates']}")
    print(f"  Deduplicated:     {deduped}")
    print("\n🏁 Done!")


if __name__ == "__main__":
    main()