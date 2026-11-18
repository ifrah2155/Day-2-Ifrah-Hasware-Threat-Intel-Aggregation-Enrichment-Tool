# Threat Intel Brief

- Generated: `2026-11-18T14:29:12Z`  |  Mode: **offline-snapshot**  |  Input: `sample_input/iocs.txt`
- IOCs analysed: **9**  |  Skipped: **1**  |  Rejected: **1**

## Summary

| IOC | Type | Verdict | Score | Tags | First seen | Last seen |
|---|---|---|---|---|---|---|
| `update-check.evil-cdn.example.com` | domain | **malicious** | 91 | agenttesla, newly-registered, payload_delivery, stealer | 2026-11-14 12:00:00 | 2026-11-17 09:30:00 |
| `198.51.100.23` | ipv4 | **malicious** | 75 | botnet_cc, c2, hosting-provider, proxy/vpn/tor, qakbot | 2026-11-10 08:15:22 | 2026-11-17 02:00:00 |
| `203.0.113.10` | ipv4 | **malicious** | 70 | botnet-c2, emotet, hosting-provider | 2026-10-02 06:11:00 | 2026-11-16 |
| `f458751657fb3d878dd9a8d0cd7ca6262a01b899f5ef1c92fd45cbba0502d190` | sha256 | **suspicious** | 60 | malware-sample | - | - |
| `login-portal-secure.example.net` | domain | **no-detection** | 0 | - | - | - |
| `old-benign-site.example.org` | domain | **no-detection** | 0 | - | - | - |
| `3ffe50f75128a7800a50b81ba1ca1021910606c65cd7bdef5b5331a5b3f2da44` | sha256 | **no-detection** | 0 | - | - | - |
| `c6732372061de8b1c3e8e45f855eff43` | md5 | **no-detection** | 0 | - | - | - |
| `8.8.8.8` | ipv4 | **no-detection** | 0 | hosting-provider | - | - |

## Details

### `update-check.evil-cdn.example.com` (domain) - malicious (91/100)
- **ThreatFox**: payload_delivery / AgentTesla (confidence 90)
- RDAP: registered 2026-11-08T00:00:00Z (age 10 days)
- Note: domain only 10 days old

### `198.51.100.23` (ipv4) - malicious (75/100)
- **ThreatFox**: botnet_cc / QakBot (confidence 75)
- Geo/ASN: Exampleland | AS64501 EXAMPLE-NET | Example VPS

### `203.0.113.10` (ipv4) - malicious (70/100)
- **Feodo Tracker**: botnet C2 (Emotet), status=online, port=443
- Geo/ASN: Exampleland | AS64500 EXAMPLE-AS | Example Hosting

### `f458751657fb3d878dd9a8d0cd7ca6262a01b899f5ef1c92fd45cbba0502d190` (sha256) - suspicious (60/100)
- **MalwareBazaar**: SHA256 in recent malware-sample export

### `login-portal-secure.example.net` (domain) - no-detection (0/100)
- No hits in any queried feed (absence of a hit is not proof of safety).
- RDAP: registered 2026-10-01T00:00:00Z (age 48 days)

### `old-benign-site.example.org` (domain) - no-detection (0/100)
- No hits in any queried feed (absence of a hit is not proof of safety).
- RDAP: registered 2009-03-14T00:00:00Z (age 6458 days)

### `3ffe50f75128a7800a50b81ba1ca1021910606c65cd7bdef5b5331a5b3f2da44` (sha256) - no-detection (0/100)
- No hits in any queried feed (absence of a hit is not proof of safety).

### `c6732372061de8b1c3e8e45f855eff43` (md5) - no-detection (0/100)
- No hits in any queried feed (absence of a hit is not proof of safety).
- Note: feeds used index SHA256 only - hash not checked (see Limitations)

### `8.8.8.8` (ipv4) - no-detection (0/100)
- No hits in any queried feed (absence of a hit is not proof of safety).
- Geo/ASN: United States | AS15169 Google LLC | Google Public DNS

## Skipped / Rejected

- `10.0.0.5` - non-public address (private/reserved/loopback) - not looked up
- `not_an_ioc!!` - unrecognised IOC format

## Source Status

| Feed | OK | Records / Error |
|---|---|---|
| feodo | yes | 1 |
| threatfox | yes | 2 |
| bazaar | yes | 1 |

_Scoring: Feodo hit +70, ThreatFox hit +40 plus 0.4 x confidence, MalwareBazaar +60, proxy flag +5, domain <30 days +15; capped at 100. >=70 malicious, >=30 suspicious._
