"""
Fetch, parse and report on a set of threat feeds.

The design point is per-feed isolation. A single cron-triggered process that
fetches feeds in sequence works fine until one source is slow or returning
errors, at which point it delays or fails the whole run. Here each feed is
fetched independently, failures are contained to the feed that failed, and the
run reports per-source outcomes rather than one exit code.

Network access lives here and nowhere else, so normalise.py stays testable
without it.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import requests
import yaml

from .normalise import Indicator, deduplicate, normalise_all

log = logging.getLogger(__name__)

DEFAULT_SOURCES = Path(__file__).parent / "sources.yaml"
DEFAULT_TIMEOUT = 30
DEFAULT_WORKERS = 4
USER_AGENT = "misp-feed-ingest/0.1 (+https://github.com/chima-ukachukwu-sec/soc-defensive-portfolio)"


class ConfigError(ValueError):
    """Raised when sources.yaml is missing or malformed."""


@dataclass
class FeedResult:
    """Outcome for one feed. Always produced, including on failure."""

    source_id: str
    ok: bool
    indicators: list[Indicator] = field(default_factory=list)
    dropped: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    duration_s: float = 0.0
    raw_records: int = 0

    def summary(self) -> str:
        if not self.ok:
            return f"{self.source_id}: FAILED ({self.error})"
        drop = sum(self.dropped.values())
        return (f"{self.source_id}: {len(self.indicators)} indicators "
                f"from {self.raw_records} records "
                f"({drop} dropped) in {self.duration_s:.1f}s")


def load_sources(path: str | Path | None = None) -> list[dict[str, Any]]:
    p = Path(path) if path else DEFAULT_SOURCES
    if not p.is_file():
        raise ConfigError(f"sources file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict) or not raw.get("sources"):
        raise ConfigError(f"{p} has no 'sources' list")
    for s in raw["sources"]:
        if not s.get("id"):
            raise ConfigError("a source has no id")
    return raw["sources"]


def enabled_sources(sources: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Skip disabled sources, and skip any whose credential is not present.

    Failing a run because an optional API key is unset is a bad default: the
    other feeds are still useful.
    """
    out = []
    for s in sources:
        if s.get("enabled") is False:
            log.info("%s: disabled in config, skipping", s["id"])
            continue
        auth = s.get("auth")
        if auth and auth.get("env") and not os.getenv(auth["env"]):
            log.warning("%s: %s is not set, skipping this source",
                        s["id"], auth["env"])
            continue
        out.append(s)
    return out


def _headers(source: dict[str, Any]) -> dict[str, str]:
    h = {"User-Agent": USER_AGENT}
    auth = source.get("auth")
    if auth and auth.get("type") == "header":
        token = os.getenv(auth.get("env", ""), "")
        if token:
            h[auth["header"]] = token
    return h


def _is_header_row(record: dict[str, str], source: dict[str, Any],
                   cols: list[str]) -> bool:
    """
    Detect a feed's own header row being read as data.

    Some feeds ship a quoted header that no comment prefix catches. Left in, it
    becomes an indicator named after its own column. In the Feodo Tracker case
    it stayed invisible only because a status filter happened to reject it, so
    a feed without a filter would have published it.

    The reliable signal is that the indicator field holds its own name. A
    majority match across columns is kept as a fallback for feeds whose
    configured names were derived from a slightly different header.
    """
    field = source.get("indicator_field")
    if field and record.get(field, "").strip().lower() == field.lower():
        return True
    if not cols:
        return False
    same = sum(1 for c in cols if record.get(c, "").strip().lower() == c.lower())
    return same >= max(2, (len(cols) + 1) // 2)


def parse_csv(text: str, source: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse headerless or commented CSV using the configured column names."""
    prefix = source.get("comment_prefix")
    lines = [ln for ln in text.splitlines()
             if ln.strip() and not (prefix and ln.lstrip().startswith(prefix))]
    cols = source.get("columns")
    if not cols:
        return list(csv.DictReader(io.StringIO("\n".join(lines))))
    out = []
    for row in csv.reader(io.StringIO("\n".join(lines))):
        if not row:
            continue
        record = {c: (row[i].strip().strip('"') if i < len(row) else "")
                  for i, c in enumerate(cols)}
        if _is_header_row(record, source, cols):
            log.debug("%s: skipped header row", source.get("id", "?"))
            continue
        out.append(record)
    return out


def parse_json(payload: Any, source: dict[str, Any]) -> list[dict[str, Any]]:
    root = source.get("json_root")
    data = payload.get(root, []) if root and isinstance(payload, dict) else payload
    if isinstance(data, dict):
        data = [data]
    return [d for d in data if isinstance(d, dict)]


def fetch_one(source: dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> FeedResult:
    """
    Fetch and normalise a single feed.

    Never raises. Every failure mode is captured into a FeedResult so one bad
    source cannot end the run, which is the whole point of the exercise.
    """
    started = time.monotonic()
    sid = source["id"]
    try:
        fmt = source.get("format", "csv")
        if fmt == "misp_feed":
            # MISP's own feed format is a JSON manifest plus per-event files.
            # Not implemented here. Reported as a failure rather than an empty
            # success, because "0 indicators, ok" reads as a working feed with
            # nothing in it.
            return FeedResult(sid, ok=False,
                              error="misp_feed format not implemented",
                              duration_s=time.monotonic() - started)

        # Validate configuration before spending a request on it. Previously
        # an unknown format still made the call and surfaced as a network
        # error, which pointed at the wrong problem.
        if fmt not in {"csv", "json"}:
            return FeedResult(sid, ok=False, error=f"unknown format {fmt!r}",
                              duration_s=time.monotonic() - started)

        resp = requests.get(source["url"], headers=_headers(source), timeout=timeout)
        resp.raise_for_status()

        records = parse_csv(resp.text, source) if fmt == "csv" else parse_json(resp.json(), source)

        indicators, dropped = normalise_all(records, source)
        return FeedResult(sid, ok=True, indicators=indicators, dropped=dropped,
                          duration_s=time.monotonic() - started,
                          raw_records=len(records))

    except requests.Timeout:
        return FeedResult(sid, ok=False, error=f"timed out after {timeout}s",
                          duration_s=time.monotonic() - started)
    except requests.HTTPError as exc:
        return FeedResult(sid, ok=False, error=f"HTTP {exc.response.status_code}",
                          duration_s=time.monotonic() - started)
    except requests.RequestException as exc:
        return FeedResult(sid, ok=False, error=f"{type(exc).__name__}",
                          duration_s=time.monotonic() - started)
    except (ValueError, KeyError) as exc:
        return FeedResult(sid, ok=False, error=f"parse error: {exc}",
                          duration_s=time.monotonic() - started)


def run(sources: list[dict[str, Any]] | None = None,
        workers: int = DEFAULT_WORKERS,
        timeout: int = DEFAULT_TIMEOUT) -> tuple[list[Indicator], list[FeedResult]]:
    """
    Fetch every enabled source concurrently and return deduplicated indicators
    alongside the per-feed results.

    Concurrency here is the cheap version of the queue-based worker this should
    eventually be. It isolates a slow feed from the others without adding a
    broker, which is the right trade at this size.
    """
    srcs = enabled_sources(sources if sources is not None else load_sources())
    results: list[FeedResult] = []

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(fetch_one, s, timeout): s for s in srcs}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            log.info("%s", res.summary())

    all_indicators = [i for r in results if r.ok for i in r.indicators]
    deduped = deduplicate(all_indicators)
    log.info("%d indicators after deduplication (from %d raw)",
             len(deduped), len(all_indicators))
    return deduped, sorted(results, key=lambda r: r.source_id)
