# Domain OSINT Recon

## Purpose

Full passive + active OSINT enumeration of a target domain and all subdomains. Produces a structured report covering DNS architecture, certificate history, subdomain inventory, IP/ASN mapping, infrastructure context, and access surface.

## BluJay Integration

Use `POST /api/domain-osint/start` to kick off a full automated run:

```json
{
  "target": "example.com",
  "dns_baseline": true,
  "crtsh": true,
  "passive_dns": true,
  "shodan": true,
  "external_dns_txt": true,
  "brute_force": false,
  "wordlist_path": null
}
```

Poll `GET /api/domain-osint/{job_id}` for results. The response includes:
- `dns_records` — SOA, NS, A, MX, TXT, zone transfer result
- `subdomains` — merged list from crt.sh + passive DNS sources
- `resolved_hosts` — host → IP map
- `ip_intel` — per-IP ASN/org/country via RDAP
- `shodan` — per-IP open ports and banners from Shodan InternetDB
- `external_dns` — ExternalDNS TXT records → K8s namespace/ingress/owner map
- `cert_history` — per-zone cert table from crt.sh
- `findings` — structured findings list with severity

## Manual Procedure (when running outside BluJay)

### Prerequisites

- `dnspython`: `pip3 install dnspython --break-system-packages`
- `dig`, `whois`, `curl`, `strings` (standard)
- `subfinder` (optional passive source aggregation): `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- Wordlists: `subs-110k.txt` (fast first pass), combined 1.5M list (thorough). Sources: jhaddix all.txt, bitquark subdomains-top1million-110000.txt

### 1. Initialize DB and Session

```bash
TARGET=example.com
DB=~/Projects/inbox/targets/web/$TARGET/current/analysis.db
SCRATCH=<session>/scratch
mkdir -p $(dirname $DB) $SCRATCH

sqlite3 $DB <<'SQL'
CREATE TABLE IF NOT EXISTS dns_records (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), record_type TEXT, name TEXT, value TEXT, source TEXT);
CREATE TABLE IF NOT EXISTS subdomains (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), subdomain TEXT UNIQUE, ip TEXT, source TEXT, status TEXT, http_status INTEGER, notes TEXT);
CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), ip TEXT UNIQUE, asn TEXT, asn_org TEXT, country TEXT, hosting_provider TEXT, ports TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), title TEXT, severity TEXT, description TEXT, evidence TEXT, status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT DEFAULT (datetime('now')), command TEXT, output TEXT, notes TEXT);
SQL
```

### 2. Domain Intelligence

```bash
whois $TARGET | grep -E "(Registrar|Created|Expires|Name Server|DNSSEC)"
dig +short SOA $TARGET
dig +short NS $TARGET
dig +short A $TARGET
dig +short MX $TARGET
dig +short TXT $TARGET
dig axfr $TARGET @$(dig +short NS $TARGET | head -1)
```

### 3. Certificate Transparency

```bash
# Root zone
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import json,sys
d=json.load(sys.stdin)
names=set()
for e in d:
    for n in e.get('name_value','').split('\n'):
        n=n.strip()
        if n: names.add(n)
for n in sorted(names): print(n)
"
# CRITICAL: re-run for each discovered sub-zone apex
# %.domain.com does NOT match *.sub.domain.com
```

### 4. Passive DNS Sources

```bash
# HackerTarget (no key required)
curl -s "https://api.hackertarget.com/hostsearch/?q=$TARGET"

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" \
  | python3 -c "import json,sys; [print(e.get('hostname'), e.get('address')) for e in json.load(sys.stdin).get('passive_dns',[])]"

# Wayback CDX
curl -s "http://web.archive.org/cdx/search/cdx?url=*.$TARGET&output=json&fl=original&collapse=urlkey&limit=100" \
  | python3 -c "
import json,sys
from urllib.parse import urlparse
d=json.load(sys.stdin)
hosts=set()
for item in d[1:]:
    h=urlparse(item[0]).netloc
    if h: hosts.add(h)
for h in sorted(hosts): print(h)
"

# URLScan
curl -s "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=100" \
  | python3 -c "import json,sys; [print(r['page'].get('domain'), r['page'].get('ip')) for r in json.load(sys.stdin).get('results',[])]"
```

### 5. DNS Brute-Force

Use `POST /api/domain-osint/brute-force` with a wordlist, or run the bundled utility:

```bash
python3 backend/core/dnsbrute2.py wordlist.txt -z $TARGET -r 8.8.8.8 1.1.1.1 9.9.9.9 -w 400 -o results.txt
```

### 6. ExternalDNS TXT Extraction (K8s Intelligence)

```bash
for host in $(cat scratch/results-combined.txt | awk '{print $1}'); do
    result=$(dig @1.1.1.1 +short TXT "$host" 2>/dev/null | grep "external-dns")
    [ -n "$result" ] && echo "$host: $result"
done
```

Format: `heritage=external-dns,external-dns/owner=<owner>,external-dns/resource=ingress/<namespace>/<name>`

### 7. IP Range Intelligence

```bash
for ip in <discovered_public_ips>; do
    echo "=== $ip ==="
    curl -s "https://rdap.arin.net/registry/ip/$ip" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('name'), d.get('country'))"
    curl -s "https://internetdb.shodan.io/$ip" | python3 -m json.tool
done
```

### 8. Shodan / Censys Check

```bash
for ip in <discovered_public_ips>; do
    echo "=== $ip ==="
    curl -s "https://internetdb.shodan.io/$ip" | python3 -m json.tool
done
```

## Report Structure

1. **Executive Summary** — BLUF: what the domain is, who operates it, full infrastructure summary.
2. **Domain Intelligence** — WHOIS table: registrar, created, expires, DNSSEC, NS, A, MX, TXT, SOA serial.
3. **DNS Records** — Raw record dump + zone transfer result + wildcard status.
4. **Subdomain Enumeration** — Methods table + full subdomain table grouped by subnet/function.
5. **ExternalDNS Architecture Intelligence** — TXT records → K8s namespace/ingress/owner map.
6. **Architecture Reconstruction** — ASCII diagram mapping all discovered services.
7. **Technology Stack Decoded** — service name → product → language/ecosystem.
8. **TLS Certificate History** — Per-zone cert table: period, issuer, CA, SANs.
9. **Findings Summary** — Table: #, title, severity, notes.
10. **Access Summary** — resource, internet accessible, VPN accessible, notes.
11. **Enumeration Coverage** — method, entries, hits, notes.
12. **Sources** — All references with URLs and access dates.

## Critical Notes

- `%.domain.com` in crt.sh matches only ONE level deep. Always re-run for sub-zone apexes.
- SOA serial = number of zone changes — cross-reference against visible record count.
- ExternalDNS owner `my-identifier` = documentation placeholder default — non-unique, flag as Low.
- PTR sweeps only useful for internet-routable addresses. Cloud providers don't configure reverse DNS for customer workloads.

## Troubleshooting

- **Brute-force rate drops**: Rotate resolvers — 8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222.
- **crt.sh returns 0 for sub-zone**: Use exact sub-zone apex as query, not a wildcard pattern.
