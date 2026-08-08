# misp-feed-ingest

Pulls community threat feeds, normalises them into one indicator shape, and
reports what it dropped and why. Reference implementation of the ingestion
pattern described in the [MISP case study](../README.md#1-misp-threat-intelligence-automation).

```bash
pip install -e .
feedingest
```

```
urlhaus: 1701 indicators from 15240 records (13539 dropped) in 0.6s
feodo: 1 indicators from 5 records (4 dropped) in 0.1s
circl-osint: FAILED (misp_feed format not implemented)
total: 1702 unique indicators, 1 of 3 sources failed
```

That output is a real run against live public feeds. Note the third line: one
source failed and the run still produced 1,702 indicators. That is the point of
the design.

---

## Clean room

This is written fresh for this portfolio against public feeds only. It is not
the code from the internship described in the case study, and it contains no
employer configuration, no internal sources, no indicators and no detection
logic from any client environment. What carries over is the pattern, which is
publishable; the implementation is new.

---

## What it does

- Fetches each configured feed **independently and concurrently**, so a slow or
  failing source is contained rather than delaying or failing the whole run
- Normalises different feed vocabularies into one `Indicator` shape, because a
  SIEM downstream needs one vocabulary and every feed has its own
- **Reports why records were dropped**, not just how many. A feed that silently
  drops most of its records looks identical to one that works
- Deduplicates across sources, keeping the highest reliability and the union of
  tags. Corroboration across independent feeds is a reason to trust an
  indicator more, not to store it twice
- Suppresses noise: RFC1918 and loopback addresses, documentation ranges, and
  well-known resolvers. Pushing those into a SIEM means alerting on your own
  network
- Skips sources whose API key is absent rather than failing the run
- Dry run by default. Writing to MISP requires an explicit flag

## Architecture

```
sources.yaml          per-feed config: URL, schema, filter, reliability, tags
      |
      v
pipeline.py           fetch (concurrent, isolated), parse CSV/JSON
      |               the only module that touches the network
      v
normalise.py          type inference, noise suppression, dedup, MISP shaping
      |               pure: no network, no clock, no MISP client
      v
cli.py                summary, JSON output, --push gate
```

**Why the split.** `normalise.py` holds the logic worth testing and has no
transport in it, so the tests assert real behaviour instead of mocking a
socket. Fetching is a GET; the part that quietly ruins a threat-intel pipeline
is a record misparsed into the wrong indicator type.

**Why concurrency rather than a queue.** The retrospective in the case study
called for a queue-based worker, and that is still the right answer at volume.
A thread pool gets the isolation property without adding a broker, which is the
correct trade at this size. The queue is listed under future work honestly, not
implemented for show.

## Configuration

Feeds are configured in [`sources.yaml`](src/feedingest/sources.yaml), not in
code. Every feed has its own schema, rate limit and reliability profile, and
that variation is the actual work in a threat-intel pipeline.

```yaml
- id: urlhaus
  url: "https://urlhaus.abuse.ch/downloads/csv_recent/"
  format: csv
  reliability: 85
  columns: [id, dateadded, url, url_status, ...]
  indicator_field: url
  indicator_type: url
  filter:
    field: url_status
    equals: online      # offline URLs are historical, not actionable
```

`reliability` drives the MISP `to_ids` flag at a threshold of 80, which decides
whether your SIEM alerts on the indicator or merely stores it for context. It
is an operator judgement, not a measurement.

## Usage

```bash
feedingest                          # all enabled sources, dry run
feedingest --only urlhaus -v        # one source, verbose
feedingest --json --out ind.json    # write indicators as JSON
feedingest --push https://misp.internal   # gated, see the runbook
```

## Security concepts demonstrated

**Feed governance as the real problem.** Deciding which feeds to trust, what
auto-ingests versus what waits for an analyst, and how to keep low-quality
sources from creating alert fatigue downstream. That is a judgement problem,
not an engineering one, and the config is shaped to make those calls explicit
and reviewable rather than buried.

**Failure isolation.** Per-source error containment with a per-source report. A
single failed feed is not a failed run; every feed failing is.

**Noise suppression as a security control.** Private and loopback addresses
reaching a SIEM cause alerts on your own infrastructure. This is tested, and
one of the tests caught a real bug: a URL whose host was `127.0.0.1` passed the
IP check because its type was `url`, not `ip-dst`. A URL is only as routable as
its host.

**Secrets discipline.** No credentials in the repository, asserted by a test
that greps the tree rather than assumed. Keys come from the environment. The
`.env.example` ships non-functional placeholders.

**Irreversible actions are gated.** Writing to a live MISP instance needs an
explicit flag, an explicit URL and a key. See
[`docs/runbook.md`](../docs/runbook.md) for the three decisions it requires
first.

## Testing

```bash
pip install -e ".[dev]"
pytest -q      # 67 tests
```

No network in the test suite. Three bugs were found by these tests during
development and are worth naming, because a test suite that never caught
anything was not testing:

1. A URL with a loopback host passed noise suppression, because the IP check
   only ran for `ip-dst` types.
2. An unknown feed format still made the HTTP request, so a config error
   surfaced as a network error and pointed at the wrong problem.
3. Feodo Tracker's quoted header row parsed as a data record. It stayed
   invisible only because the `online` filter happened to reject it. A feed
   without a filter would have published an indicator named `dst_ip`.

## Limitations

- MISP's own feed format (JSON manifest plus per-event files) is not
  implemented. Configured sources using it report that rather than returning an
  empty success.
- `--push` is not implemented. The reference stops at producing indicators.
- Reliability scores are opinions, not measured false-positive rates.
- No persistence between runs, so there is no first-seen tracking or ageing.
- ThreatFox now requires an API key. Verified: an anonymous request returns
  401. It is configured and skipped unless `ABUSECH_API_KEY` is set.

## Future improvements

1. **Queue-based workers.** The thread pool isolates failures but does not
   survive a restart or scale past one host. Celery and Redis, per the original
   retrospective.
2. **Per-feed reliability scoring from observed data.** Track which sources
   produce indicators that later fire, and let the score move on evidence
   instead of opinion.
3. **Implement `--push`** with an explicit event model and distribution
   setting, plus a dry-run diff of what would be created.
4. **First-seen and ageing.** Persist indicators so an ingest reports what is
   new, and expire what a feed has stopped publishing.
5. **STIX export**, so the output feeds something other than MISP.

## Licence

CC BY 4.0 for the written material in this repository; the code in this
directory is offered under the same terms. See [../LICENSE](../LICENSE) and
[../NOTICE.md](../NOTICE.md).
