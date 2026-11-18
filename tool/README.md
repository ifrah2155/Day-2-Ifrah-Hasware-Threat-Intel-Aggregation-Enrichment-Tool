# ti_enrich.py - tool documentation

## Usage
```bash
# Live mode (needs internet; no API keys)
python tool/ti_enrich.py --input sample_input/iocs.txt --out-dir sample_output
# Offline reproducible demo (synthetic snapshot in the repo)
python tool/ti_enrich.py --input sample_input/iocs.txt --offline --allow-doc-ranges
```
Flags: `--no-geo`, `--no-rdap`, `--timeout N`, `--retries N`, `--snapshot-dir DIR`.

## Input format
Plain text, one IOC per line, `#` comments allowed. IPv4/IPv6, domains, MD5/SHA1/SHA256.
Defanged input (`hxxp://a[.]b/path`) is refanged automatically; duplicates are removed.

## Output
`intel_brief.md` (human brief) and `intel_brief.json` (machine-readable): per-IOC verdict, 0-100 score,
tags, first/last seen, per-source hits, geo/ASN, domain age, plus skipped/rejected IOCs and per-feed status.

## Error and rate-limit handling
Per-host throttling (ip-api: 1 request / 1.5 s), honours `Retry-After` and ip-api `X-Rl`/`X-Ttl`,
exponential backoff on 429/5xx/timeouts, no retry on 4xx. A dead feed is recorded in "Source Status"
and the run continues; if *all* feeds fail the tool exits with code 2 rather than emit a misleading brief.

## Safety
Passive only: the tool never connects to an IOC. Private/reserved IPs are skipped (scope guard).
No keys, no PII, no destructive actions.

## Assumptions and limitations
- Feeds are "recent" exports, so an old IOC can legitimately show no hit. "No detection" is not "clean".
- MD5/SHA1 are parsed but not checked (feeds index SHA256). Scores are a transparent heuristic, not a calibrated model.
- abuse.ch has been moving some services behind free Auth-Keys; a 401/403 shows up in Source Status.
