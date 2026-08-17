from __future__ import annotations

from pathlib import Path

import pytest
from requests import RequestException

import convert_hosts as ch


class FakeResponse:
    def __init__(self, text: str, error: Exception | None = None) -> None:
        self.text = text
        self._error = error

    def raise_for_status(self) -> None:
        if self._error is not None:
            raise self._error


class TestFetchOne:
    def test_returns_url_and_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_get(url: str, **kwargs: object) -> FakeResponse:
            calls.append((url, dict(kwargs)))
            return FakeResponse("||example.com^\n")

        monkeypatch.setattr(ch.requests, "get", fake_get)

        assert ch._fetch_one("https://host/list.txt") == (
            "https://host/list.txt",
            "||example.com^\n",
        )

        url, kwargs = calls[0]
        assert url == "https://host/list.txt"
        assert kwargs["timeout"] == (10, 60)
        assert kwargs["headers"] == {"User-Agent": ch.USER_AGENT}

    @pytest.mark.parametrize("url", ["ftp://host/list.txt", "https://", "not-a-url", ""])
    def test_rejects_invalid_urls_without_requesting(
        self,
        monkeypatch: pytest.MonkeyPatch,
        url: str,
    ) -> None:
        def fail_get(*args: object, **kwargs: object) -> FakeResponse:
            raise AssertionError("no HTTP request should be made")

        monkeypatch.setattr(ch.requests, "get", fail_get)

        with pytest.raises(ValueError, match="Invalid URL"):
            ch._fetch_one(url)

    def test_propagates_http_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            ch.requests,
            "get",
            lambda *a, **k: FakeResponse("", RequestException("boom")),
        )

        with pytest.raises(RequestException):
            ch._fetch_one("https://host/list.txt")


class TestLoadAllSourcesConcurrently:
    def test_merges_sources_and_aggregates_stats(self, monkeypatch: pytest.MonkeyPatch) -> None:
        bodies = {
            "https://a/list.txt": "||ads.example.com^\n0.0.0.0 tracker.net\n",
            "https://b/list.txt": "# comment\n||ads.example.com^\npixel.example.org\n",
        }

        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, bodies[url]))

        merged, stats = ch.load_all_sources_concurrently(list(bodies), threads=2)

        assert merged == {"ads.example.com", "tracker.net", "pixel.example.org"}
        assert stats["unique_entries"] == 3
        assert stats["total_lines"] == 5
        assert stats["adblock_rules"] == 2
        assert stats["hosts_rules"] == 1
        assert stats["fetch_failures"] == 0

    def test_counts_request_and_unexpected_failures(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def fake_fetch(url: str) -> tuple[str, str]:
            if url == "https://ok/list.txt":
                return url, "||ads.example.com^\n"
            if url == "https://net-error/list.txt":
                raise RequestException("network down")
            raise ValueError("unexpected")

        monkeypatch.setattr(ch, "_fetch_one", fake_fetch)

        merged, stats = ch.load_all_sources_concurrently(
            ["https://ok/list.txt", "https://net-error/list.txt", "https://boom/list.txt"],
            threads=4,
        )

        assert merged == {"ads.example.com"}
        assert stats["fetch_failures"] == 2

    def test_thread_count_is_clamped_to_at_least_one(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, "||ads.example.com^\n"))

        merged, _ = ch.load_all_sources_concurrently(["https://a/list.txt"], threads=0)

        assert merged == {"ads.example.com"}

    def test_no_sources(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, ""))

        merged, stats = ch.load_all_sources_concurrently([], threads=2)

        assert merged == set()
        assert stats["unique_entries"] == 0


class TestWriteOutput:
    def test_writes_header_and_sorted_rules(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "blocklist.txt"
        stats = ch.make_stats()
        stats["fetch_failures"] = 2
        stats["subdomain_pruned"] = 7

        ch.write_output(out, {"b.example.com", "a.example.com", "*.example.org"}, stats)

        content = out.read_text(encoding="utf-8")
        header, _, body = content.partition("\n\n")

        assert header.startswith("! Title: royerlraph79 AdGuard Blocklist")
        assert "! Entries: 3" in header
        assert "! Fetch failures: 2" in header
        assert "! Subdomains pruned: 7" in header
        assert body == "||*.example.org^\n||a.example.com^\n||b.example.com^\n"

    def test_empty_entries(self, tmp_path: Path) -> None:
        out = tmp_path / "blocklist.txt"

        ch.write_output(out, set(), ch.make_stats())

        assert out.read_text(encoding="utf-8").endswith("! Entries: 0\n"
                                                        "! Fetch failures: 0\n"
                                                        "! Registrable collapsed: 0\n"
                                                        "! Subdomains pruned: 0\n"
                                                        "! Plain removed by wildcards: 0\n"
                                                        "! Wildcards removed by plain: 0\n"
                                                        "! Wildcards removed by wildcards: 0\n\n")


class TestMain:
    @staticmethod
    def _write_sources(tmp_path: Path) -> Path:
        source = tmp_path / "sources.txt"
        source.write_text("# comment\n\nhttps://a/list.txt\n", encoding="utf-8")
        return source

    def _run(self, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> None:
        monkeypatch.setattr("sys.argv", ["convert_hosts.py", *argv])
        ch.main()

    def test_end_to_end_writes_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = self._write_sources(tmp_path)
        output = tmp_path / "blocklist.txt"

        monkeypatch.setattr(
            ch,
            "_fetch_one",
            lambda url: (url, "||ads.example.com^\n0.0.0.0 example.com\n*.cdn.net\n"),
        )

        self._run(monkeypatch, ["-s", str(source), "-o", str(output), "-v"])

        body = output.read_text(encoding="utf-8").split("\n\n", 1)[1]
        assert body == "||*.cdn.net^\n||example.com^\n"

    def test_check_mode_skips_writing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = self._write_sources(tmp_path)
        output = tmp_path / "blocklist.txt"

        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, "||ads.example.com^\n"))

        self._run(monkeypatch, ["-s", str(source), "-o", str(output), "--check"])

        assert not output.exists()

    def test_missing_source_file_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["-s", str(tmp_path / "missing.txt")])

        assert exc.value.code == 1

    def test_source_file_without_urls_exits(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = tmp_path / "sources.txt"
        source.write_text("# only comments\n\n", encoding="utf-8")

        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["-s", str(source)])

        assert exc.value.code == 1

    def test_all_fetches_failing_refuses_to_write(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = self._write_sources(tmp_path)
        output = tmp_path / "blocklist.txt"

        def fail(url: str) -> tuple[str, str]:
            raise RequestException("network down")

        monkeypatch.setattr(ch, "_fetch_one", fail)

        with pytest.raises(SystemExit) as exc:
            self._run(monkeypatch, ["-s", str(source), "-o", str(output)])

        assert exc.value.code == 1
        assert not output.exists()

    def test_flags_are_forwarded_to_dedupe(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = self._write_sources(tmp_path)
        captured: dict[str, object] = {}

        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, "||ads.example.com^\n"))

        def fake_dedupe(entries: set[str], **kwargs: object) -> set[str]:
            captured.update(kwargs)
            return entries

        monkeypatch.setattr(ch, "dedupe_entries", fake_dedupe)

        self._run(
            monkeypatch,
            [
                "-s",
                str(source),
                "--check",
                "--threads",
                "3",
                "--collapse-registrable",
                "--no-dedupe-subdomains",
                "--no-dedupe-plain-covered-by-wildcards",
                "--dedupe-wildcards-conservative",
            ],
        )

        assert captured["collapse_to_registrable"] is True
        assert captured["dedupe_subdomains"] is False
        assert captured["dedupe_plain_covered_by_wildcards"] is False
        assert captured["dedupe_wildcards_conservative"] is True

    def test_default_flags(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        source = self._write_sources(tmp_path)
        captured: dict[str, object] = {}

        monkeypatch.setattr(ch, "_fetch_one", lambda url: (url, "||ads.example.com^\n"))

        def fake_dedupe(entries: set[str], **kwargs: object) -> set[str]:
            captured.update(kwargs)
            return entries

        monkeypatch.setattr(ch, "dedupe_entries", fake_dedupe)

        self._run(monkeypatch, ["-s", str(source), "--check"])

        assert captured["collapse_to_registrable"] is False
        assert captured["dedupe_subdomains"] is True
        assert captured["dedupe_plain_covered_by_wildcards"] is True
        assert captured["dedupe_wildcards_conservative"] is False
