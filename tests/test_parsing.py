from __future__ import annotations

import logging

import pytest

import convert_hosts as ch


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "\t\n",
        "# comment",
        "  ! adblock comment",
        "// comment",
        "; comment",
    ],
)
def test_is_comment_or_empty_true(line: str) -> None:
    assert ch.is_comment_or_empty(line) is True


@pytest.mark.parametrize("line", ["example.com", "||example.com^", "0.0.0.0 example.com", "a#b"])
def test_is_comment_or_empty_false(line: str) -> None:
    assert ch.is_comment_or_empty(line) is False


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("/ads?/", True),
        ("  /banner/  ", True),
        ("/", False),
        ("", False),
        ("/example.com", False),
        ("example.com/", False),
    ],
)
def test_is_regex_rule(line: str, expected: bool) -> None:
    assert ch.is_regex_rule(line) is expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("||example.com^$third-party", "||example.com^"),
        ("  ||example.com^$image,script  ", "||example.com^"),
        ("||example.com^", "||example.com^"),
        ("/ads\\$/", "/ads\\$/"),
        ("$domain=example.com", ""),
    ],
)
def test_strip_adblock_options(line: str, expected: str) -> None:
    assert ch.strip_adblock_options(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("||example.com^", "example.com"),
        ("||sub.example.com^$third-party", "sub.example.com"),
        ("||example.com", "example.com"),
        ("||*.example.com^", "*.example.com"),
        ("||EXAMPLE.com^", "EXAMPLE.com"),
        ("|http://tracker.example.com/pixel", "tracker.example.com"),
        ("|https://tracker.example.com:8080/pixel", "tracker.example.com"),
        ("@@||allowed.example.com^", ""),
        ("||localhost^", ""),
        ("example.com", ""),
        ("/regex/", ""),
        ("", ""),
    ],
)
def test_extract_from_adblock_rule(line: str, expected: str) -> None:
    assert ch.extract_from_adblock_rule(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("||ads.example.com^", ("adblock", "ads.example.com")),
        ("0.0.0.0 ads.example.com", ("hosts", "ads.example.com")),
        ("127.0.0.1\tads.example.com # inline comment", ("hosts", "ads.example.com")),
        ("::1 ads.example.com", ("hosts", "ads.example.com")),
        ("192.168.1.1 intranet.example.com", ("plain", "192.168.1.1")),
        ("ads.example.com", ("plain", "ads.example.com")),
        ("ads.example.com extra tokens", ("plain", "ads.example.com")),
        ("", ("plain", "")),
    ],
)
def test_choose_token(line: str, expected: tuple[str, str]) -> None:
    assert ch.choose_token(line) == expected


class TestParseSuffixWildcard:
    def test_single_star(self) -> None:
        sw = ch.parse_suffix_wildcard("*.example.com")
        assert sw is not None
        assert (sw.original, sw.base, sw.min_labels_before_base) == (
            "*.example.com",
            "example.com",
            1,
        )

    def test_multiple_stars_and_case_normalization(self) -> None:
        sw = ch.parse_suffix_wildcard("  *.*.EXAMPLE.com  ")
        assert sw is not None
        assert (sw.original, sw.base, sw.min_labels_before_base) == (
            "*.*.example.com",
            "example.com",
            2,
        )

    @pytest.mark.parametrize(
        "pattern",
        [
            "example.com",  # no wildcard at all
            "ads*.example.com",  # star is not a full leading label
            "exa*mple.com",
            "*.exa*mple.com",  # star remains inside the base
            "*",  # no base labels
            "*.*",
            "*.localhost",  # base is not a valid host
            "*.example..com",
        ],
    )
    def test_rejected_patterns(self, pattern: str) -> None:
        assert ch.parse_suffix_wildcard(pattern) is None


class TestNormalizeTokenToEntry:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("Example.COM", "example.com"),
            ("  ads.example.com  ", "ads.example.com"),
            ("www.example.com", "example.com"),
            ("www2.example.com", "example.com"),
            ("http://ads.example.com/path", "ads.example.com"),
            ("https://ads.example.com/path?q=1", "ads.example.com"),
            ("ads.example.com/path", "ads.example.com"),
            ("ads.example.com?q=1", "ads.example.com"),
            ("ads.example.com#frag", "ads.example.com"),
            ("ads.example.com:8080", "ads.example.com"),
            ("ads.example.com.", "ads.example.com"),
            ("ads.example.com^", "ads.example.com"),
            ("*.example.com", "*.example.com"),
            ("*.*.example.com", "*.*.example.com"),
        ],
    )
    def test_valid_tokens(self, token: str, expected: str) -> None:
        assert ch.normalize_token_to_entry(token) == expected

    @pytest.mark.parametrize(
        "token",
        [
            "",
            "   ",
            "@@||example.com^",
            "-example.com",
            ".example.com",
            "_example.com",
            "localhost",  # no dot
            "ads.example.com:notaport",
            "ads example.com",
            "ads*.example.com",  # complex glob is dropped
            "exa*mple.com",
            "example.c",  # suffix too short
            "-bad-.example..com",
        ],
    )
    def test_invalid_tokens(self, token: str) -> None:
        assert ch.normalize_token_to_entry(token) == ""


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("ads.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.c.example.co.uk", "example.co.uk"),
        ("localhost", "localhost"),  # no registrable suffix, returned unchanged
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert ch.registrable_domain(host) == expected


def test_make_stats_starts_at_zero() -> None:
    stats = ch.make_stats()
    assert set(stats) >= {"total_lines", "fetch_failures", "unique_entries"}
    assert all(v == 0 for v in stats.values())


@pytest.mark.parametrize(
    ("verbose", "expected_level"),
    [(False, logging.INFO), (True, logging.DEBUG)],
)
def test_setup_logging_sets_level(
    monkeypatch: pytest.MonkeyPatch,
    verbose: bool,
    expected_level: int,
) -> None:
    captured: dict[str, object] = {}

    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: captured.update(kwargs))
    ch.setup_logging(verbose)

    assert captured["level"] == expected_level


class TestParseSourceText:
    def test_counts_each_line_kind(self) -> None:
        text = "\n".join(
            [
                "# a comment",
                "",
                "@@||allowed.example.com^",
                "||ads.example.com^$third-party",
                "0.0.0.0 tracker.example.com",
                "plain.example.com",
                "not_a_domain",
                "||ads.example.com^",  # duplicate of an earlier entry
            ]
        )

        found, stats = ch._parse_source_text(text)

        assert found == {"ads.example.com", "tracker.example.com", "plain.example.com"}
        assert stats["total_lines"] == 8
        assert stats["ignored_lines"] == 3
        assert stats["adblock_rules"] == 2
        assert stats["hosts_rules"] == 1
        assert stats["plain_candidate_lines"] == 2
        assert stats["invalid_lines"] == 1
        assert stats["valid_entries_seen"] == 4
        assert stats["unique_entries"] == 3

    def test_empty_text(self) -> None:
        found, stats = ch._parse_source_text("")
        assert found == set()
        assert stats["total_lines"] == 0
        assert stats["unique_entries"] == 0
