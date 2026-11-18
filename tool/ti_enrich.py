#!/usr/bin/env python3
"""ti_enrich.py - Threat-intel IOC aggregation & enrichment tool (Day 2).

Reads an IOC list (IPs / domains / hashes), enriches each from public, key-less
sources, scores it, and writes a structured intel brief (Markdown + JSON).

Sources (all passive; the tool NEVER connects to an IOC itself):
  * abuse.ch Feodo Tracker  - botnet C2 IP blocklist (JSON feed)
  * abuse.ch ThreatFox      - recent IOC export (IPs, domains, hashes)
  * abuse.ch MalwareBazaar  - recent SHA256 export
  * ip-api.com              - IP geo / ASN / hosting flags (free, rate-limited)
  * RDAP (rdap.org)         - domain registration date (domain age)
Offline mode (--offline) replays a synthetic snapshot from the repo instead.
"""
import argparse, ipaddress, json, os, re, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone
from urllib.parse import urlparse

UA = "ti-enrich/1.0 (student lab project; passive lookups only)"
FEEDS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
    "bazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
}
GEO_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,as,org,hosting,proxy"
RDAP_URL = "https://rdap.org/domain/{d}"
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------- HTTP layer
class Http:
    """GET with retries, exponential backoff, Retry-After and per-host throttling."""
    def __init__(self, timeout=15, retries=3, verbose=True):
        self.timeout, self.retries, self.verbose = timeout, retries, verbose
        self.last = {}                 # host -> last request time
        self.min_gap = {"ip-api.com": 1.5}   # free tier: 45 req/min

    def log(self, msg):
        if self.verbose:
            print(f"[http] {msg}", file=sys.stderr)

    def get(self, url):
        host = urlparse(url).netloc
        delay = 2.0
        for attempt in range(1, self.retries + 2):
            gap = self.min_gap.get(host, 0)
            wait = self.last.get(host, 0) + gap - time.time()
            if wait > 0:
                time.sleep(wait)
            self.last[host] = time.time()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    body, hdr = r.read(), r.headers
                    # ip-api tells us when the window is exhausted
                    if hdr.get("X-Rl") == "0":
                        ttl = int(hdr.get("X-Ttl", "5")) + 1
                        self.log(f"{host} quota exhausted; sleeping {ttl}s")
                        time.sleep(ttl)
                    return body
            except urllib.error.HTTPError as e:
                if e.code == 429 or 500 <= e.code < 600:
                    ra = e.headers.get("Retry-After") if e.headers else None
                    sleep = int(ra) if ra and ra.isdigit() else delay
                    self.log(f"{url} -> HTTP {e.code}; retry {attempt}/{self.retries} in {sleep}s")
                    if attempt > self.retries:
                        raise
                    time.sleep(sleep); delay *= 2
                else:
                    raise                      # 401/403/404: retrying will not help
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                self.log(f"{url} -> {e}; retry {attempt}/{self.retries} in {delay}s")
                if attempt > self.retries:
                    raise
                time.sleep(delay); delay *= 2

# ---------------------------------------------------------------- IOC parsing
def refang(s):
    s = s.strip().strip("'\"")
    s = re.sub(r"^hxxps?://", "", s, flags=re.I)
    s = s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return s.split("/")[0] if "/" in s and not re.fullmatch(r"[0-9a-fA-F]+", s) else s

def classify(raw):
    v = refang(raw)
    if not v:
        return None, None
    try:
        ip = ipaddress.ip_address(v.strip("[]"))
        return ("ipv6" if ip.version == 6 else "ipv4"), v.strip("[]")
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASH_LEN:
        return HASH_LEN[len(v)], v.lower()
    if DOMAIN_RE.match(v.lower()):
        return "domain", v.lower()
    return "invalid", v

def load_iocs(path):
    seen, iocs, rejected = set(), [], []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.split("#")[0].strip()
            if not line:
                continue
            t, v = classify(line)
            if t == "invalid":
                rejected.append({"line": n, "value": line, "reason": "unrecognised IOC format"})
            elif (t, v) not in seen:
                seen.add((t, v)); iocs.append({"type": t, "value": v})
    return iocs, rejected

def scope_guard(ioc, allow_doc):
    """Skip non-routable space: never look up internal/reserved addresses."""
    if ioc["type"] not in ("ipv4", "ipv6"):
        return None
    ip = ipaddress.ip_address(ioc["value"])
    if allow_doc and any(ip in n for n in DOC_NETS):
        return None
    if not ip.is_global:
        return "non-public address (private/reserved/loopback) - not looked up"
    return None

# ---------------------------------------------------------------- Feeds
class Intel:
    def __init__(self, http, offline, snap_dir):
        self.http, self.offline, self.snap = http, offline, snap_dir
        self.status = {}
        self.feodo, self.tfox, self.bazaar = {}, {}, set()
        self.geo_cache = self.rdap_cache = {}
        if offline:
            self.geo_cache = self._snap_json("geo.json", {})
            self.rdap_cache = self._snap_json("rdap.json", {})

    def _snap_json(self, name, default):
        p = os.path.join(self.snap, name)
        return json.load(open(p)) if os.path.exists(p) else default

    def _fetch(self, key, parse):
        try:
            if self.offline:
                fn = {"feodo": "feodo.json", "threatfox": "threatfox.json", "bazaar": "bazaar_sha256.txt"}[key]
                raw = open(os.path.join(self.snap, fn), "rb").read()
                src = "offline snapshot (synthetic)"
            else:
                raw, src = self.http.get(FEEDS[key]), FEEDS[key]
            n = parse(raw)
            self.status[key] = {"ok": True, "records": n, "source": src, "fetched": now_iso()}
        except Exception as e:                       # one dead feed must not kill the run
            self.status[key] = {"ok": False, "error": f"{type(e).__name__}: {e}", "source": FEEDS[key]}

    def load_feeds(self):
        def p_feodo(raw):
            data = json.loads(raw)
            data = data if isinstance(data, list) else data.get("blocklist", [])
            for e in data:
                self.feodo[e["ip_address"]] = e
            return len(data)
        def p_tfox(raw):
            data, n = json.loads(raw), 0
            rows = data if isinstance(data, list) else [r for v in data.values() for r in (v if isinstance(v, list) else [v])]
            for r in rows:
                val = str(r.get("ioc_value", "")).lower()
                if r.get("ioc_type") == "ip:port":
                    val = val.rsplit(":", 1)[0]
                self.tfox.setdefault(val, []).append(r); n += 1
            return n
        def p_bazaar(raw):
            hs = {l.strip().lower() for l in raw.decode().splitlines() if l.strip() and not l.startswith("#")}
            self.bazaar |= hs
            return len(hs)
        self._fetch("feodo", p_feodo); self._fetch("threatfox", p_tfox); self._fetch("bazaar", p_bazaar)

    def geo(self, ip, enabled):
        if not enabled:
            return None
        if self.offline:
            return self.geo_cache.get(ip)
        try:
            d = json.loads(self.http.get(GEO_URL.format(ip=ip)))
            return d if d.get("status") == "success" else {"error": d.get("message", "lookup failed")}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

    def rdap(self, domain, enabled):
        if not enabled:
            return None
        if self.offline:
            return self.rdap_cache.get(domain)
        try:
            d = json.loads(self.http.get(RDAP_URL.format(d=domain)))
            ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
            return {"registered": ev.get("registration"), "last_changed": ev.get("last changed")}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}

# ---------------------------------------------------------------- Enrichment & scoring
def enrich(ioc, intel, use_geo, use_rdap):
    t, v = ioc["type"], ioc["value"]
    hits, tags, seen_ts, score, notes = [], set(), [], 0, []
    if t == "ipv4" and v in intel.feodo:
        e = intel.feodo[v]
        score += 70
        hits.append({"source": "Feodo Tracker", "detail": f"botnet C2 ({e.get('malware')}), status={e.get('status')}, port={e.get('port')}"})
        tags |= {"botnet-c2", str(e.get("malware", "")).lower()}
        seen_ts += [e.get("first_seen"), e.get("last_online")]
    for r in intel.tfox.get(v, []):
        conf = int(r.get("confidence_level") or 50)
        score += 40 + int(conf * 0.4)
        hits.append({"source": "ThreatFox", "detail": f"{r.get('threat_type')} / {r.get('malware_printable')} (confidence {conf})"})
        tags |= {(r.get("malware_printable") or "").lower(), (r.get("threat_type") or "").lower()}
        if isinstance(r.get("tags"), str):
            tags |= {x.strip().lower() for x in r["tags"].split(",") if x.strip()}
        seen_ts += [r.get("first_seen_utc"), r.get("last_seen_utc")]
    if t == "sha256" and v in intel.bazaar:
        score += 60
        hits.append({"source": "MalwareBazaar", "detail": "SHA256 in recent malware-sample export"})
        tags.add("malware-sample")
    out = {**ioc, "hits": hits}
    if t in ("ipv4", "ipv6"):
        g = intel.geo(v, use_geo); out["geo_asn"] = g
        if g and not g.get("error"):
            if g.get("hosting"): tags.add("hosting-provider")
            if g.get("proxy"): tags.add("proxy/vpn/tor"); score += 5
    if t == "domain":
        r = intel.rdap(v, use_rdap); out["rdap"] = r
        if r and r.get("registered"):
            try:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(r["registered"].replace("Z", "+00:00"))).days
                r["age_days"] = age
                if age < 30: score += 15; tags.add("newly-registered"); notes.append(f"domain only {age} days old")
            except ValueError:
                pass
    if t in ("md5", "sha1"):
        notes.append("feeds used index SHA256 only - hash not checked (see Limitations)")
    score = min(score, 100)
    ts = sorted(x for x in seen_ts if x)
    out.update(score=score, verdict="malicious" if score >= 70 else "suspicious" if score >= 30 else "no-detection",
               tags=sorted(x for x in tags if x), first_seen=ts[0] if ts else None,
               last_seen=ts[-1] if ts else None, notes=notes)
    return out

# ---------------------------------------------------------------- Reporting
def to_markdown(brief):
    m = brief["meta"]; rs = brief["results"]
    L = ["# Threat Intel Brief", "",
         f"- Generated: `{m['generated']}`  |  Mode: **{m['mode']}**  |  Input: `{m['input']}`",
         f"- IOCs analysed: **{len(rs)}**  |  Skipped: **{len(brief['skipped'])}**  |  Rejected: **{len(brief['rejected'])}**", "",
         "## Summary", "", "| IOC | Type | Verdict | Score | Tags | First seen | Last seen |", "|---|---|---|---|---|---|---|"]
    for r in rs:
        L.append(f"| `{r['value']}` | {r['type']} | **{r['verdict']}** | {r['score']} | {', '.join(r['tags']) or '-'} | {r['first_seen'] or '-'} | {r['last_seen'] or '-'} |")
    L += ["", "## Details", ""]
    for r in rs:
        L.append(f"### `{r['value']}` ({r['type']}) - {r['verdict']} ({r['score']}/100)")
        for h in r["hits"]: L.append(f"- **{h['source']}**: {h['detail']}")
        if not r["hits"]: L.append("- No hits in any queried feed (absence of a hit is not proof of safety).")
        g = r.get("geo_asn")
        if g: L.append("- Geo/ASN: " + (g.get("error") or f"{g.get('country')} | {g.get('as')} | {g.get('org')}"))
        d = r.get("rdap")
        if d: L.append("- RDAP: " + (d.get("error") or f"registered {d.get('registered')} (age {d.get('age_days','?')} days)"))
        for n in r["notes"]: L.append(f"- Note: {n}")
        L.append("")
    if brief["skipped"] or brief["rejected"]:
        L += ["## Skipped / Rejected", ""]
        L += [f"- `{s['value']}` - {s['reason']}" for s in brief["skipped"] + brief["rejected"]] + [""]
    L += ["## Source Status", "", "| Feed | OK | Records / Error |", "|---|---|---|"]
    for k, s in brief["sources"].items():
        L.append(f"| {k} | {'yes' if s['ok'] else 'NO'} | {s.get('records', s.get('error'))} |")
    L += ["", "_Scoring: Feodo hit +70, ThreatFox hit +40 plus 0.4 x confidence, MalwareBazaar +60, "
          "proxy flag +5, domain <30 days +15; capped at 100. >=70 malicious, >=30 suspicious._", ""]
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser(description="IOC enrichment -> intel brief")
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-dir", default="sample_output")
    ap.add_argument("--offline", action="store_true", help="use synthetic snapshot instead of live APIs")
    ap.add_argument("--snapshot-dir", default="sample_input/feeds_snapshot")
    ap.add_argument("--allow-doc-ranges", action="store_true", help="treat RFC5737 documentation IPs as routable (demo data only)")
    ap.add_argument("--no-geo", action="store_true"); ap.add_argument("--no-rdap", action="store_true")
    ap.add_argument("--timeout", type=int, default=15); ap.add_argument("--retries", type=int, default=3)
    a = ap.parse_args()

    iocs, rejected = load_iocs(a.input)
    http = Http(a.timeout, a.retries)
    intel = Intel(http, a.offline, a.snapshot_dir)
    intel.load_feeds()
    if not any(s["ok"] for s in intel.status.values()):
        print("ERROR: all intel sources failed - refusing to emit a misleading brief.", file=sys.stderr)
        sys.exit(2)
    results, skipped = [], []
    for ioc in iocs:
        why = scope_guard(ioc, a.allow_doc_ranges)
        if why: skipped.append({**ioc, "reason": why}); continue
        results.append(enrich(ioc, intel, not a.no_geo, not a.no_rdap))
    results.sort(key=lambda r: -r["score"])
    brief = {"meta": {"generated": now_iso(), "mode": "offline-snapshot" if a.offline else "live", "input": a.input},
             "sources": intel.status, "results": results, "skipped": skipped, "rejected": rejected}
    os.makedirs(a.out_dir, exist_ok=True)
    json.dump(brief, open(os.path.join(a.out_dir, "intel_brief.json"), "w"), indent=2)
    open(os.path.join(a.out_dir, "intel_brief.md"), "w").write(to_markdown(brief))
    print(f"Done: {len(results)} enriched, {len(skipped)} skipped, {len(rejected)} rejected -> {a.out_dir}/")

if __name__ == "__main__":
    main()
