# Runbook: MISP feed ingestion

Operational notes for the reference pipeline in `misp-feed-ingest/`. Written
the way a runbook has to be written to survive a 3am read: what to check, in
what order, and what each symptom means.

## Standing up MISP

```bash
cd docker
cp .env.example .env      # then change every value
docker compose up -d
docker compose ps         # all three healthy before continuing
```

MISP binds to `127.0.0.1:8080`. Put a reverse proxy with TLS in front before it
is reachable from anywhere else. The database is not published to the host at
all; it is reachable only on the compose network.

Rolling back is `docker compose down` then `up` with the previous image tag.
Named volumes survive that. Deleting the volumes deletes the data, which is the
one irreversible step here.

## Running an ingest

```bash
cd misp-feed-ingest
pip install -e .
feedingest                      # dry run, prints a summary
feedingest --json --out ind.json
feedingest --only urlhaus -v    # one source, verbose
```

Nothing is written to MISP without `--push`, which is deliberate.

## Reading the summary

```
urlhaus: 1701 indicators from 15240 records (13539 dropped) in 0.6s
feodo: 1 indicators from 5 records (4 dropped) in 0.1s
circl-osint: FAILED (misp_feed format not implemented)
total: 1702 unique indicators, 1 of 3 sources failed
```

The drop count is the number worth watching. A high drop rate is usually
correct, because most feeds publish historical entries and this pipeline
filters to what is currently live. A drop rate that *changes* is the signal: it
means either the feed changed its schema or the pipeline stopped understanding
it. Both look like silence otherwise.

## Symptoms

| Symptom | Likely cause | What to do |
|---|---|---|
| One source `FAILED (HTTP 401)` | Feed moved behind an API key | Set the key in the environment, or disable the source |
| One source `FAILED (timed out)` | Feed slow or down | Nothing. Other sources completed. Investigate if it persists across runs |
| Drop count jumps to near 100% | Feed changed its column order or schema | Compare a raw sample against `columns` in `sources.yaml` |
| Indicators appear with the wrong type | Feed changed its type vocabulary | Check `TYPE_ALIASES` in `normalise.py` |
| Every source failed | Egress blocked, or DNS | Check from the host before touching the config |
| Zero indicators, no failures | Every record filtered | Check the `filter` block; the feed may have gone quiet |

A single failed source does not fail the run. Every source failing does, which
is the distinction between a bad feed and a broken host.

## Before pushing to a live instance

`--push` is not implemented in this reference build, on purpose. Writing to a
real MISP instance needs three decisions this repository cannot make for you:

1. **Event model.** One event per run, per feed, or per campaign. This changes
   how analysts search and how correlation behaves.
2. **Distribution.** MISP's sharing groups decide who sees an indicator.
   Getting this wrong leaks. It is an organisational decision, not a default.
3. **`to_ids` policy.** This pipeline sets `to_ids` from source reliability at
   a threshold of 80. That flag drives whether your SIEM alerts, so the
   threshold belongs to whoever owns the alert queue.

## Feed governance

The judgement calls, which are the actual work:

- **Which feeds to trust.** `reliability` in `sources.yaml` is an operator
  opinion, not a measurement. Revise it from your own false-positive
  experience, and write down why when you do.
- **What auto-ingests.** Indicators from sources below 80 land in MISP for
  context with `to_ids` false. They are searchable and do not alert.
- **What creates alert fatigue.** The filters exist for this. Offline URLs and
  historical C2 are real indicators and useless ones. Ingesting them fills a
  SIEM with things that will never fire, and an analyst who learns to ignore
  the feed is worse than no feed.
