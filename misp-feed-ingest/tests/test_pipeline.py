"""
Tests for feed parsing, config handling and failure isolation.

The behaviour under test is the one the retrospective called for: a slow or
broken feed must not take down the run. These tests assert that a failing
source is contained and reported, and that the other sources still produce
indicators.

Network calls are stubbed. Nothing here reaches the internet.
"""

from __future__ import annotations

import pytest
import requests

from feedingest import pipeline
from feedingest.pipeline import (ConfigError, FeedResult, enabled_sources,
                                 fetch_one, load_sources, parse_csv, parse_json,
                                 run)

CSV_SOURCE = {
    "id": "csvfeed", "url": "https://example.invalid/f.csv", "format": "csv",
    "comment_prefix": "#", "reliability": 85, "tags": ["source:csvfeed"],
    "columns": ["dateadded", "url", "url_status"],
    "indicator_field": "url", "indicator_type": "url",
    "filter": {"field": "url_status", "equals": "online"},
}
JSON_SOURCE = {
    "id": "jsonfeed", "url": "https://example.invalid/api", "format": "json",
    "json_root": "data", "reliability": 80, "tags": ["source:jsonfeed"],
    "indicator_field": "ioc", "indicator_type_field": "ioc_type",
}


class FakeResponse:
    def __init__(self, text="", payload=None, status=200):
        self.text = text
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


# --- parsing -------------------------------------------------------------

def test_parse_csv_skips_comments_and_uses_configured_columns():
    text = ("# a comment line\n"
            "# another\n"
            "2026-01-01,http://bad.test/a,online\n"
            "2026-01-02,http://old.test/b,offline\n")
    rows = parse_csv(text, CSV_SOURCE)
    assert len(rows) == 2
    assert rows[0]["url"] == "http://bad.test/a"
    assert rows[1]["url_status"] == "offline"


def test_parse_csv_skips_a_quoted_header_row():
    """
    Feodo Tracker ships a quoted header no comment prefix catches. Left in, it
    becomes an indicator named after its own column. It survived here only
    because a filter happened to reject it.
    """
    text = ('"first_seen_utc","url","url_status"\n'
            '"2026-01-01","http://bad.test/a","online"\n')
    rows = parse_csv(text, CSV_SOURCE)
    assert len(rows) == 1
    assert rows[0]["url"] == "http://bad.test/a"


def test_parse_csv_strips_quotes_from_values():
    rows = parse_csv('"2026-01-01","http://bad.test/a","online"\n', CSV_SOURCE)
    assert rows[0]["url_status"] == "online"


def test_parse_csv_tolerates_short_rows():
    """A truncated line should not blow up the whole feed."""
    rows = parse_csv("2026-01-01,http://bad.test/a\n", CSV_SOURCE)
    assert rows[0]["url_status"] == ""


def test_parse_json_unwraps_the_configured_root():
    rows = parse_json({"data": [{"ioc": "bad.test"}], "query_status": "ok"},
                      JSON_SOURCE)
    assert rows == [{"ioc": "bad.test"}]


def test_parse_json_handles_a_bare_list():
    rows = parse_json([{"ioc": "a.test"}, {"ioc": "b.test"}], {"id": "x"})
    assert len(rows) == 2


def test_parse_json_ignores_non_objects():
    rows = parse_json({"data": [{"ioc": "a.test"}, "junk", None]}, JSON_SOURCE)
    assert rows == [{"ioc": "a.test"}]


# --- fetch, and the failure modes that matter ----------------------------

def test_fetch_csv_feed_end_to_end(monkeypatch):
    monkeypatch.setattr(pipeline.requests, "get", lambda *a, **k: FakeResponse(
        text="2026-01-01,http://bad.test/a,online\n2026-01-02,http://x.test/b,offline\n"))
    res = fetch_one(CSV_SOURCE)
    assert res.ok
    assert len(res.indicators) == 1
    assert res.raw_records == 2
    assert res.dropped.get("filtered") == 1


def test_timeout_is_contained_not_raised(monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout()
    monkeypatch.setattr(pipeline.requests, "get", boom)
    res = fetch_one(CSV_SOURCE, timeout=5)
    assert not res.ok
    assert "timed out" in res.error


def test_http_error_is_contained(monkeypatch):
    monkeypatch.setattr(pipeline.requests, "get",
                        lambda *a, **k: FakeResponse(status=503))
    res = fetch_one(CSV_SOURCE)
    assert not res.ok
    assert "503" in res.error


def test_malformed_json_is_contained(monkeypatch):
    class Bad(FakeResponse):
        def json(self):
            raise ValueError("not json")
    monkeypatch.setattr(pipeline.requests, "get", lambda *a, **k: Bad())
    res = fetch_one(JSON_SOURCE)
    assert not res.ok
    assert "parse error" in res.error


def test_unknown_format_is_reported_not_crashed():
    res = fetch_one({"id": "weird", "url": "https://example.invalid",
                     "format": "parquet"})
    assert not res.ok
    assert "parquet" in res.error


# --- isolation across a run ----------------------------------------------

def test_one_failing_feed_does_not_stop_the_others(monkeypatch):
    """The point of the rewrite. A bad source is contained to itself."""
    def fake_get(url, **kwargs):
        if "api" in url:
            raise requests.Timeout()
        return FakeResponse(text="2026-01-01,http://bad.test/a,online\n")
    monkeypatch.setattr(pipeline.requests, "get", fake_get)

    indicators, results = run([CSV_SOURCE, JSON_SOURCE], workers=2)

    by_id = {r.source_id: r for r in results}
    assert by_id["csvfeed"].ok
    assert not by_id["jsonfeed"].ok
    assert len(indicators) == 1, "the healthy feed still produced indicators"


def test_run_deduplicates_across_sources(monkeypatch):
    monkeypatch.setattr(pipeline.requests, "get", lambda url, **k: (
        FakeResponse(payload={"data": [{"ioc": "http://bad.test/a", "ioc_type": "url"}]})
        if "api" in url else
        FakeResponse(text="2026-01-01,http://bad.test/a,online\n")))
    indicators, _ = run([CSV_SOURCE, JSON_SOURCE], workers=2)
    assert len(indicators) == 1
    assert indicators[0].reliability == 85, "keeps the higher-reliability source"


# --- config --------------------------------------------------------------

def test_shipped_sources_file_loads():
    sources = load_sources()
    assert len(sources) >= 4
    assert all(s.get("id") for s in sources)


def test_shipped_sources_carry_a_reliability_and_tags():
    for s in load_sources():
        assert 0 <= int(s.get("reliability", -1)) <= 100, f"{s['id']} reliability"
        assert s.get("tags"), f"{s['id']} has no tags"


def test_missing_sources_file_raises_clearly():
    with pytest.raises(ConfigError, match="not found"):
        load_sources("/nonexistent/sources.yaml")


def test_malformed_sources_file_raises(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("sources:\n  - name: no id here\n")
    with pytest.raises(ConfigError, match="no id"):
        load_sources(p)


def test_disabled_sources_are_skipped():
    out = enabled_sources([{"id": "on"}, {"id": "off", "enabled": False}])
    assert [s["id"] for s in out] == ["on"]


def test_source_needing_an_absent_key_is_skipped_not_failed(monkeypatch):
    """An unset optional API key must not fail the whole run."""
    monkeypatch.delenv("SOME_KEY", raising=False)
    out = enabled_sources([
        {"id": "free"},
        {"id": "paid", "auth": {"type": "header", "header": "X-Key", "env": "SOME_KEY"}},
    ])
    assert [s["id"] for s in out] == ["free"]


def test_source_with_key_present_is_included(monkeypatch):
    monkeypatch.setenv("SOME_KEY", "value")
    out = enabled_sources([
        {"id": "paid", "auth": {"type": "header", "header": "X-Key", "env": "SOME_KEY"}}])
    assert [s["id"] for s in out] == ["paid"]


def test_no_credentials_are_committed():
    """The failure that ends careers. Assert it, do not assume it."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    secretish = re.compile(r"(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}",
                           re.IGNORECASE)
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".py", ".yaml", ".yml", ".toml", ".md"}:
            body = path.read_text(encoding="utf-8", errors="replace")
            assert not secretish.search(body), f"possible credential in {path}"
