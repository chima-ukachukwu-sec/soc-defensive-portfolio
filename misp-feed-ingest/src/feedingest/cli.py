"""
Command line entry point.

Defaults to a dry run. Pushing indicators into a MISP instance is the one
irreversible thing this tool does, so it takes an explicit flag and an explicit
URL rather than happening because someone forgot an argument.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .pipeline import ConfigError, load_sources, run

log = logging.getLogger("feedingest")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="feedingest",
        description="Fetch community threat feeds, normalise them, and report.")
    p.add_argument("--sources", help="path to an alternative sources.yaml")
    p.add_argument("--only", help="run a single source by id")
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--json", action="store_true", help="emit indicators as JSON")
    p.add_argument("--out", help="write JSON to a file instead of stdout")
    p.add_argument("--push", metavar="MISP_URL",
                   help="push to a MISP instance. Requires MISP_KEY in the "
                        "environment. Without this flag nothing is written.")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)-7s %(message)s")

    try:
        sources = load_sources(args.sources)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.only:
        sources = [s for s in sources if s["id"] == args.only]
        if not sources:
            print(f"no source with id {args.only!r}", file=sys.stderr)
            return 2

    indicators, results = run(sources, workers=args.workers, timeout=args.timeout)

    failed = [r for r in results if not r.ok]
    print("\n--- run summary ---")
    for r in results:
        print(f"  {r.summary()}")
    print(f"  total: {len(indicators)} unique indicators, "
          f"{len(failed)} of {len(results)} sources failed")

    if args.json or args.out:
        payload = [
            {"value": i.value, "type": i.type, "source": i.source,
             "reliability": i.reliability, "tags": list(i.tags),
             "context": i.context}
            for i in indicators
        ]
        text = json.dumps(payload, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"  wrote {args.out}")
        else:
            print(text)

    if args.push:
        print("\n  --push is not implemented in this reference build.")
        print("  Writing to a live MISP instance is left to the operator: it "
              "needs an org-specific event model, a distribution decision and "
              "a key. See docs/runbook.md.")
        return 3

    # A run where every source failed is a failed run, even though each
    # individual failure was contained.
    return 1 if failed and len(failed) == len(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
