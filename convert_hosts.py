import re
import sys
import requests
from typing import Set, Tuple, Dict

# ---------------------------
# Config
# ---------------------------

SOURCE_FILE = "sources.txt"
OUTPUT_FILE = "adguard_blocklist.txt"

# Optional toggles
DEDUP_SUBDOMAINS = True                 # remove foo.bar.com if bar.com exists
DEDUP_PLAIN_COVERED_BY_WILDCARDS = True # remove plain domains matched by wildcard patterns
DEDUP_WILDCARDS_CONSERVATIVE = False    # optional conservative wildcard-vs-wildcard pruning

COMMENT_PREFIXES = ("#", "!", "//", ";")

HOSTS_RE = re.compile(
    r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+([^\s#]+)",
    re.IGNORECASE
)

SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
TRAILING_OPTIONS_RE = re.compile(r"\$.*$")  # strip $options (cosmetic, etc.)

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

# ---------------------------
# Parsing + normalization
# ---------------------------

def is_comment_or_empty(line: str) -> bool:
    ln = line.strip()
    return (not ln) or ln.startswith(COMMENT_PREFIXES)

def normalize_token(token: str) -> str:
    """
    Normalize a hostname-like token or AdGuard host-pattern.
    Keeps '*' intact.
    Returns "" if it doesn't look like a domain/pattern.
    """
    d = token.strip().lower()
    if not d:
        return ""

    # Remove scheme + path/query/fragment
    d = SCHEME_RE.sub("", d)
    d = d.split("/")[0].split("?")[0].split("#")[0]

    # Remove port
    if ":" in d:
        d = d.split(":")[0]

    # Strip leading "*."
    if d.startswith("*."):
        d = d[2:]

    # Strip trailing delimiters often found in pasted rules
    d = d.rstrip(".^")

    # Basic sanity
    if "." not in d:
        return ""
    if any(ch.isspace() for ch in d):
        return ""

    return d

def extract_from_adblock_rule(line: str) -> str:
    """
    Extract host-pattern from AdGuard/uBO host rules.
      ||example.com^$important -> example.com
      ||device-metrics-*.amazon.com^ -> device-metrics-*.amazon.com
      @@||example.com^ -> "" (ignore allowlist)
    """
    ln = line.strip()
    if ln.startswith("@@"):
        return ""

    ln = TRAILING_OPTIONS_RE.sub("", ln)

    m = re.match(r"^\|\|([^\^/]+)", ln)
    return m.group(1) if m else ""

def choose_token(raw_line: str) -> Tuple[str, str]:
    """
    Return (kind, token) where kind in {"adblock","hosts","plain"}.
    """
    ln = raw_line.strip()

    ad = extract_from_adblock_rule(ln)
    if ad:
        return ("adblock", ad)

    hm = HOSTS_RE.match(ln)
    if hm:
        return ("hosts", hm.group(1))

    token = ln.split()[0] if ln else ""
    return ("plain", token)

# ---------------------------
# Wildcard + subdomain dedupe
# ---------------------------

def glob_to_regex(glob: str) -> re.Pattern:
    """
    Convert a hostname glob with '*' into a safe regex matcher for full hostnames.
    IMPORTANT: no backslash escapes like '\-' so we avoid SyntaxWarning.
    """
    # Escape everything, then unescape the escaped '*' into a hostname-ish wildcard
    esc = re.escape(glob.lower())
    esc = esc.replace(r"\*", r"[a-z0-9.-]*")  # NO backslashes -> no SyntaxWarning
    return re.compile(rf"^{esc}$", re.IGNORECASE)

def remove_plain_redundant_subdomains(plain: Set[str]) -> Set[str]:
    """
    Remove foo.bar.com if bar.com exists in the plain set.
    """
    kept = set()
    for d in plain:
        parts = d.split(".")
        redundant = False
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in plain:
                redundant = True
                break
        if not redundant:
            kept.add(d)
    return kept

def remove_plain_covered_by_wildcards(plain: Set[str], wildcards: Set[str]) -> Set[str]:
    """
    Remove plain domains that match any wildcard pattern already present.
    Example: device-metrics-*.amazon.com covers device-metrics-us.amazon.com
    """
    if not wildcards:
        return plain

    wildcard_res = [glob_to_regex(w) for w in wildcards]
    out = set()

    for d in plain:
        covered = False
        for rx in wildcard_res:
            if rx.match(d):
                covered = True
                break
        if not covered:
            out.add(d)

    return out

def conservative_wildcard_prune(wildcards: Set[str]) -> Set[str]:
    """
    Optional conservative pruning:
    If '*.example.com' exists, drop more specific patterns under that base
    like 'foo*.example.com' or 'device-*.example.com' (since *.example.com covers all subdomains).
    """
    if not wildcards:
        return wildcards

    super_wc_bases = set()
    for w in wildcards:
        wl = w.lower()
        if wl.startswith("*.") and "." in wl[2:]:
            super_wc_bases.add(wl[2:])

    if not super_wc_bases:
        return wildcards

    pruned = set()
    for w in wildcards:
        wl = w.lower()
        redundant = False
        for base in super_wc_bases:
            if wl == "*." + base:
                continue
            if wl.endswith("." + base) and "." in wl[: -(len(base) + 1)]:
                redundant = True
                break
        if not redundant:
            pruned.add(w)

    return pruned

def dedupe_domains(domains: Set[str]) -> Set[str]:
    print("🧹 Deduplicating domains (subdomains + wildcards)...")
    sys.stdout.flush()

    domain_set = set(domains)
    wildcards = {d for d in domain_set if "*" in d}
    plain = {d for d in domain_set if "*" not in d}

    if DEDUP_SUBDOMAINS:
        plain = remove_plain_redundant_subdomains(plain)

    if DEDUP_PLAIN_COVERED_BY_WILDCARDS:
        plain = remove_plain_covered_by_wildcards(plain, wildcards)

    if DEDUP_WILDCARDS_CONSERVATIVE:
        wildcards = conservative_wildcard_prune(wildcards)

    result = plain | wildcards

    print("✅ Deduplication complete.")
    sys.stdout.flush()
    return result

# ---------------------------
# Fetch + aggregate
# ---------------------------

def load_domains_from_url(url: str, seen: Set[str]) -> Tuple[Set[str], Dict[str, int]]:
    print(f"\n🔗 Fetching: {url}")
    sys.stdout.flush()

    stats = DEFAULT_STATS.copy()
    found: Set[str] = set()

    try:
        r = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "blocklist-gen/1.0 (+https://github.com/royerlraph79/AdGuard)"}
        )
        r.raise_for_status()
        text = r.text
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
        sys.stdout.flush()
        return found, stats

    for raw in text.splitlines():
        stats["total_lines"] += 1
        ln = raw.strip()

        if is_comment_or_empty(ln):
            stats["invalid_lines"] += 1
            continue

        kind, token = choose_token(ln)
        if kind == "adblock":
            stats["adblock_rules"] += 1
        elif kind == "hosts":
            stats["hosts_rules"] += 1
        else:
            stats["plain_domains"] += 1

        domain = normalize_token(token)
        if not domain:
            stats["invalid_lines"] += 1
            continue

        if domain in seen:
            stats["duplicates"] += 1
            continue

        seen.add(domain)
        found.add(domain)
        stats["added"] += 1

    stats["skipped"] = stats["invalid_lines"] + stats["duplicates"]
    return found, stats

# ---------------------------
# Main
# ---------------------------

def main():
    print("🚀 Starting blocklist generation...")
    sys.stdout.flush()

    with open(SOURCE_FILE, "r", encoding="utf-8") as f:
        urls = [l.strip() for l in f if not is_comment_or_empty(l)]

    all_domains: Set[str] = set()

    overall = DEFAULT_STATS.copy()
    overall["sources"] = 0
    overall["parsed_total"] = 0

    for url in urls:
        domains, stats = load_domains_from_url(url, all_domains)

        overall["sources"] += 1
        overall["parsed_total"] += stats["total_lines"]
        for k in DEFAULT_STATS:
            overall[k] += stats[k]

        print(f"📊 {url}")
        print(f"  Lines: {stats['total_lines']} | Added: {stats['added']} | Skipped: {stats['skipped']} | Duplicates: {stats['duplicates']} | Invalid: {stats['invalid_lines']}")
        sys.stdout.flush()

    print(f"\n🧠 Raw unique entries: {len(all_domains)}")
    sys.stdout.flush()

    final_domains = dedupe_domains(all_domains)

    print(f"🧠 Final entries: {len(final_domains)}")
    print(f"📦 Writing: {OUTPUT_FILE}")
    sys.stdout.flush()

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for i, d in enumerate(sorted(final_domains), 1):
            f.write(f"||{d}^\n")
            if i % 20000 == 0:
                print(f"  ... wrote {i}")
                sys.stdout.flush()

    print("🏁 Done.")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
