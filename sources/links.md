# Sources

| Source | URL | Used for | Auth |
|---|---|---|---|
| abuse.ch Feodo Tracker | https://feodotracker.abuse.ch/blocklist/ | Botnet C2 IP blocklist (JSON) | none for the public download |
| abuse.ch ThreatFox | https://threatfox.abuse.ch/export/ | Recent IOC export (IP:port, domains, hashes) | none for the public export |
| abuse.ch MalwareBazaar | https://bazaar.abuse.ch/export/ | Recent SHA256 export | none for the public export |
| ip-api.com | https://ip-api.com/docs/api:json | IP geo / ASN / hosting / proxy flags | none (free tier, 45 req/min) |
| RDAP bootstrap | https://rdap.org | Domain registration date | none |
| RFC 5737 | https://datatracker.ietf.org/doc/html/rfc5737 | Documentation IP ranges used in sample data | n/a |

All sample IOCs and the offline feed snapshot in `sample_input/` are **synthetic**. Nothing was organizer-provided.
