# Day 2 Mission - Ifrah Hasware- Threat Intel Aggregation & Enrichment Working Tool

- Tool name: `ti_enrich.py` (Threat-Intel IOC Aggregation & Enrichment)
- Time spent: 4 Hrs
- Language/dependencies: Python 3.9+, standard library only
- Run command: `python tool/ti_enrich.py --input sample_input/iocs.txt --out-dir sample_output`
- Repo map:
  - [Report](report.md)
  - [Tool](tool/)
  - [Sample input](sample_input/)
  - [Sample output](sample_output/)
  - [Evidence](evidence/)
  - [Sources](sources/links.md)

## What the Tool Does
Takes an IOC list (IPs / domains / hashes), queries public key-less sources (abuse.ch Feodo Tracker, ThreatFox,
MalwareBazaar, ip-api, RDAP), and writes a scored intel brief in Markdown and JSON. It handles rate limits
(throttling, Retry-After, backoff), survives individual feed failures, and never touches the IOCs themselves.

## Key Results
1. 9 unique IOCs enriched from a synthetic list: 3 malicious, 1 suspicious, 5 no-detection.
2. Scope guard skipped the private IP `10.0.0.5`; the invalid line was rejected; the duplicate and the defanged URL were normalised.
3. Brief shows tags, first/last seen, geo/ASN and domain age (a 10-day-old domain was flagged as newly registered).

## Limitations
Recent-window feeds only; MD5/SHA1 not checked; heuristic scoring; live feeds may require a free abuse.ch key in future.

## Self-Attestation
I self-sourced all materials, used only public/synthetic/self-owned resources, built a working tool, and performed non-destructive work.
