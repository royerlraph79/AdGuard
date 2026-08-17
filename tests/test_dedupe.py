from __future__ import annotations

import pytest

import convert_hosts as ch


def wc(pattern: str) -> ch.ParsedSuffixWildcard:
    parsed = ch.parse_suffix_wildcard(pattern)
    assert parsed is not None, pattern
    return parsed


class TestParsedSuffixWildcardCoversPlain:
    @pytest.mark.parametrize(
        ("pattern", "host", "expected"),
        [
            ("*.example.com", "ads.example.com", True),
            ("*.example.com", "a.b.example.com", True),
            ("*.example.com", "example.com", False),  # the base itself is not covered
            ("*.example.com", "notexample.com", False),
            ("*.example.com", "example.com.evil.net", False),
            ("*.*.example.com", "ads.example.com", False),  # needs two extra labels
            ("*.*.example.com", "a.b.example.com", True),
            ("*.*.example.com", "a.b.c.example.com", True),
        ],
    )
    def test_covers_plain(self, pattern: str, host: str, expected: bool) -> None:
        assert wc(pattern).covers_plain(host) is expected


class TestParsedSuffixWildcardCoversWildcard:
    @pytest.mark.parametrize(
        ("broad", "narrow", "expected"),
        [
            ("*.example.com", "*.example.com", True),
            ("*.example.com", "*.*.example.com", True),
            ("*.*.example.com", "*.example.com", False),
            ("*.example.com", "*.ads.example.com", True),
            ("*.*.example.com", "*.ads.example.com", True),
            ("*.*.*.example.com", "*.ads.example.com", False),
            ("*.example.com", "*.example.org", False),
            ("*.ads.example.com", "*.example.com", False),
        ],
    )
    def test_covers_wildcard(self, broad: str, narrow: str, expected: bool) -> None:
        assert wc(broad).covers_wildcard(wc(narrow)) is expected


class TestDomainTrie:
    def test_broader_domain_blocks_later_subdomains(self) -> None:
        trie = ch.DomainTrie()

        assert trie.insert_broader_wins("example.com") is True
        assert trie.insert_broader_wins("ads.example.com") is False
        assert trie.insert_broader_wins("a.b.example.com") is False

    def test_narrow_first_is_replaced_by_broader(self) -> None:
        trie = ch.DomainTrie()

        assert trie.insert_broader_wins("ads.example.com") is True
        assert trie.insert_broader_wins("example.com") is True
        assert trie.root == {"com": {"example": {"__end__": {}}}}

    def test_duplicate_insert_is_accepted_again(self) -> None:
        trie = ch.DomainTrie()

        assert trie.insert_broader_wins("example.com") is True
        assert trie.insert_broader_wins("example.com") is True
        assert trie.root == {"com": {"example": {"__end__": {}}}}

    def test_sibling_domains_are_independent(self) -> None:
        trie = ch.DomainTrie()

        assert trie.insert_broader_wins("example.com") is True
        assert trie.insert_broader_wins("example.org") is True


def test_collapse_plain_to_registrable() -> None:
    stats = ch.make_stats()

    out = ch.collapse_plain_to_registrable(
        {"ads.example.com", "cdn.example.com", "example.org", "a.b.example.co.uk"},
        stats,
    )

    assert out == {"example.com", "example.org", "example.co.uk"}
    assert stats["registrable_collapsed"] == 1


def test_dedupe_plain_subdomains() -> None:
    stats = ch.make_stats()

    out = ch.dedupe_plain_subdomains(
        ["ads.example.com", "example.com", "a.b.example.com", "other.net"],
        stats,
    )

    assert out == {"example.com", "other.net"}
    assert stats["subdomain_pruned"] == 2


def test_dedupe_plain_subdomains_deduplicates_input() -> None:
    stats = ch.make_stats()

    out = ch.dedupe_plain_subdomains(["example.com", "example.com"], stats)

    assert out == {"example.com"}
    assert stats["subdomain_pruned"] == 0


def test_split_wildcards_separates_and_sorts() -> None:
    suffix, complex_globs = ch.split_wildcards(
        {"*.b.example.com", "*.example.com", "ADS*.example.com", "exa*mple.com"}
    )

    assert [sw.original for sw in suffix] == ["*.example.com", "*.b.example.com"]
    assert complex_globs == ["ads*.example.com", "exa*mple.com"]


class TestRemovePlainCoveredByWildcards:
    def test_suffix_and_glob_coverage(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_plain_covered_by_wildcards(
            {"ads.example.com", "example.com", "adserver.tracker.net", "keep.tracker.net"},
            {"*.example.com", "ads*.tracker.net"},
            stats,
        )

        assert out == {"example.com", "keep.tracker.net"}
        assert stats["plain_removed_by_wildcards"] == 2

    @pytest.mark.parametrize(
        ("plain", "wildcards"),
        [(set(), {"*.example.com"}), ({"example.com"}, set())],
    )
    def test_empty_inputs_are_passthrough(self, plain: set[str], wildcards: set[str]) -> None:
        stats = ch.make_stats()

        assert ch.remove_plain_covered_by_wildcards(plain, wildcards, stats) == plain
        assert stats["plain_removed_by_wildcards"] == 0


class TestRemoveWildcardsCoveredByPlain:
    def test_suffix_wildcard_removed_when_base_or_ancestor_is_blocked(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_wildcards_covered_by_plain(
            {"example.com"},
            {"*.ads.example.com", "*.example.com", "*.other.net"},
            stats,
        )

        assert out == {"*.other.net"}
        assert stats["wildcard_removed_by_plain"] == 2

    def test_complex_glob_removed_when_parent_is_blocked(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_wildcards_covered_by_plain(
            {"example.com"},
            {"ads*.sub.example.com", "ads*.other.net"},
            stats,
        )

        assert out == {"ads*.other.net"}
        assert stats["wildcard_removed_by_plain"] == 1

    @pytest.mark.parametrize(
        ("plain", "wildcards"),
        [(set(), {"*.example.com"}), ({"example.com"}, set())],
    )
    def test_empty_inputs_are_passthrough(self, plain: set[str], wildcards: set[str]) -> None:
        stats = ch.make_stats()

        assert ch.remove_wildcards_covered_by_plain(plain, wildcards, stats) == wildcards
        assert stats["wildcard_removed_by_plain"] == 0


class TestRemoveRedundantWildcards:
    def test_keeps_only_broadest_suffix_wildcards(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_redundant_wildcards(
            {"*.example.com", "*.*.example.com", "*.ads.example.com", "*.other.net"},
            stats,
        )

        assert out == {"*.example.com", "*.other.net"}
        assert stats["wildcard_removed_by_wildcards"] == 2

    def test_complex_globs_kept_by_default(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_redundant_wildcards({"*.example.com", "ads*.sub.example.com"}, stats)

        assert out == {"*.example.com", "ads*.sub.example.com"}
        assert stats["wildcard_removed_by_wildcards"] == 0

    def test_conservative_prunes_deep_complex_globs(self) -> None:
        stats = ch.make_stats()

        out = ch.remove_redundant_wildcards(
            {"*.example.com", "ads*.sub.example.com", "ads*.example.com", "keep*.other.net"},
            stats,
            conservative=True,
        )

        assert out == {"*.example.com", "ads*.example.com", "keep*.other.net"}
        assert stats["wildcard_removed_by_wildcards"] == 1

    def test_empty_input(self) -> None:
        stats = ch.make_stats()

        assert ch.remove_redundant_wildcards(set(), stats) == set()
        assert stats["wildcard_removed_by_wildcards"] == 0


class TestDedupeEntries:
    def test_default_pipeline(self) -> None:
        stats = ch.make_stats()

        out = ch.dedupe_entries(
            {
                "example.com",
                "ads.example.com",
                "tracker.net",
                "pixel.tracker.net",
                "*.tracker.net",
                "*.*.cdn.net",
                "*.cdn.net",
            },
            collapse_to_registrable=False,
            dedupe_subdomains=True,
            dedupe_plain_covered_by_wildcards=True,
            dedupe_wildcards_conservative=False,
            stats=stats,
        )

        assert out == {"example.com", "tracker.net", "*.cdn.net"}
        assert stats["subdomain_pruned"] == 2
        assert stats["wildcard_removed_by_plain"] == 1
        assert stats["wildcard_removed_by_wildcards"] == 1

    def test_collapse_to_registrable(self) -> None:
        stats = ch.make_stats()

        out = ch.dedupe_entries(
            {"ads.example.com", "cdn.example.com", "other.co.uk"},
            collapse_to_registrable=True,
            dedupe_subdomains=True,
            dedupe_plain_covered_by_wildcards=True,
            dedupe_wildcards_conservative=False,
            stats=stats,
        )

        assert out == {"example.com", "other.co.uk"}
        assert stats["registrable_collapsed"] == 1

    def test_all_dedupe_steps_disabled_keeps_plain_entries(self) -> None:
        stats = ch.make_stats()
        entries = {"example.com", "ads.example.com", "*.example.com"}

        out = ch.dedupe_entries(
            entries,
            collapse_to_registrable=False,
            dedupe_subdomains=False,
            dedupe_plain_covered_by_wildcards=False,
            dedupe_wildcards_conservative=False,
            stats=stats,
        )

        # The wildcard is dropped because its base is already blocked as a plain domain.
        assert out == {"example.com", "ads.example.com"}
        assert stats["subdomain_pruned"] == 0
        assert stats["plain_removed_by_wildcards"] == 0
