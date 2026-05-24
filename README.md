# recon.sh

> **Live instance: <https://recon-sh.com>** — free to use, under the acceptable-use terms below.

A browser-based, **strictly passive** OSINT recon tool for a single domain. Type a domain, hit **Run scan**, and watch the findings stream in live across a dozen phases.

The application **never connects to, probes, or scans the target itself**. Every result is pulled from public / third-party datasets — there are no port scans, no host pings, no HTTP probes against the target's infrastructure, no DNS zone transfer attempts, no credential testing of any kind.

---

## What it does

For any public domain you give it, recon.sh gathers and cross-references:

- **WHOIS / RDAP** — registrar, dates, status, DNSSEC, nameservers, contacts.
- **DNS** — A / AAAA / MX / NS / TXT / SOA / CNAME / DKIM via DNS-over-HTTPS.
- **Mail providers** — detects the upstream mail platform from MX / SPF / DMARC patterns.
- **Subdomain discovery** — crt.sh certificate transparency, HackerTarget, OTX, ThreatMiner, VirusTotal.
- **Historical URLs** — Wayback Machine CDX archive, surfacing interesting paths and sensitive query parameters.
- **Email harvesting** — RDAP contacts, Skymem, GitHub commit authors, plus name-based permutation.
- **GitHub footprint** — repos / issues / PRs mentioning the domain, plus the matching org's public repos and Gravatar profiles.
- **Search-engine dorking** — DuckDuckGo passive results across a set of recon-friendly dork patterns.
- **Threat-intel** — VirusTotal verdicts (domain, URLs, resolutions), AbuseIPDB cross-reference per IP, Shodan InternetDB (open ports / CPEs / CVEs).
- **ASN / network** — IP → ASN ownership, CDN / proxy classification, origin candidates behind CDNs.
- **Onion mirrors** — Ahmia search for any `.onion` references to the domain.
- **Domain pivots** — sibling domains issued to the same registrant organisation.
- **Summary** — consolidated hit list, exportable as a PDF report.

---

## Usage

### On the hosted instance

1. Go to **<https://recon-sh.com>**.
2. Type a public domain (e.g. `example.com`) into the search bar.
3. Hit **Run scan**. Results stream live, grouped by phase.
4. Switch between **Phases** view (everything) and **Hits** view (just the flagged findings) using the toggle in the header.
5. Use the search box to index-search the output. `n` / `⇧n` jump between matches, `Esc` clears.
6. Click **Download** to export the full report as a PDF.

### Bring-your-own API keys (optional)

A few of the upstream sources require free API keys to unlock their data. The hosted instance does not ship server-side keys — instead, you can paste your own into the **Keys** button in the header:

| Provider          | Unlocks                                                         | Get a free key                                  |
| ----------------- | --------------------------------------------------------------- | ----------------------------------------------- |
| **VirusTotal**    | Domain report, subdomain feed, URL scans, DNS resolutions       | <https://www.virustotal.com/gui/my-apikey>      |
| **AbuseIPDB**     | Per-IP abuse / reports cross-reference                          | <https://www.abuseipdb.com/account/api>         |
| **AlienVault OTX**| Passive DNS at full rate (anonymous is heavily throttled)       | <https://otx.alienvault.com/api>                |

**Keys are temporary.** They live only in your browser tab's `sessionStorage`, are wiped automatically when the tab closes, and are sent per-scan in the request body — never in the URL, never logged, never persisted server-side. There are no accounts and no login.

Leaving any field blank just skips that source's optional phase; the rest of the scan still runs.

---

## Disclaimer & Acceptable Use

This project is published for **defensive security research, attack-surface awareness, and educational purposes only**.

- **I do not condone, endorse, or support any malicious, illegal, or unauthorized use of this application.**
- You are solely responsible for how you use it. Use it only against domains you own, domains you have explicit written authorization to investigate, or domains being researched in a clearly defensive context (e.g. your own bug-bounty program target, your employer's assets, public threat-intel work).
- The tool is intentionally passive — it queries only third-party public datasets — but the information it surfaces can still be misused. Don't.
- **No warranty of any kind.** The author accepts no liability for damages, losses, or consequences arising from use or misuse of this software. By using it you agree you are doing so lawfully and ethically.

If you're not sure whether your use case is appropriate: **stop and ask first.**
