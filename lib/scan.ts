// runScan — the full passive-OSINT pipeline.
//
// Each "phase" emits a stream of ScanEvent objects via `send()`. The route
// handler turns those into SSE messages; the UI groups them by phase id.
// Phases are roughly:
//   meta → whois → dns → wayback → subdomains → emails → github
//        → dorks → threat → asn (+ CDN / origin) → abuseipdb → summary
// Slow upstream calls are kicked off in parallel at the top of the function
// and `await`ed inside the phase that needs them, so the wall-clock cost is
// max(upstream), not sum.

import type { ApiKeys, Send } from "./types";
import {
  emailRegexFor,
  INTERESTING_PATH,
  SENSITIVE_PARAM,
  SENSITIVE_SUB,
} from "./patterns";
import { resolveAll, probeDkim, resolveBulkA } from "./dns";
import { detectMailProviders } from "./mailProviders";
import { lookupDomain, lookupIp, lookupAsn } from "./rdap";
import {
  abuseIpdb,
  combinedOnionHits,
  crtsh,
  crtshByOrg,
  ddgSearch,
  hackerTarget,
  otxGeneral,
  otxPassiveDns,
  shodanInternetDb,
  skymemEmails,
  threatMinerPassiveDns,
  threatMinerSubdomains,
  urlscan,
  vtDomain,
  vtDomainUrls,
  vtResolutions,
  vtSubdomains,
  waybackUrls,
  webSearch,
} from "./sources";
import type { TmPassiveDnsHit } from "./sources";
import {
  ghCollectCommitEmails,
  ghFindOrg,
  ghListOrgRepos,
  ghSearchIssues,
  ghSearchRepos,
} from "./github";
import { classifyIp, isProxyProvider } from "./cdn";
import {
  gravatarLookup,
  permutateEmailsFromName,
} from "./email-extras";
import { pMap } from "./http";

// --- helpers --------------------------------------------------------------

const isDomain = (s: string) =>
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(s);

const ghSearchUrl = (q: string) =>
  `https://github.com/search?q=${encodeURIComponent(q)}&type=code`;

/**
 * Emit a uniform "HIT FOUND — …" line. The frontend renders any line with
 * `hit: true` in red with a Crosshair (scope) icon, so this is the single
 * source of truth for the "this section produced findings" indicator.
 */
function emitHitFound(send: Send, message: string): void {
  send({ type: "line", text: `HIT FOUND — ${message}`, hit: true });
}

/**
 * Worker pool for dork-style fan-outs. Errors per item are swallowed (we
 * always want the rest of the dorks to run) and the loop bails as soon as
 * the abort signal flips.
 */
async function runDorkPool<T>(
  items: T[],
  concurrency: number,
  aborted: () => boolean | undefined,
  fn: (item: T) => Promise<void>
) {
  let cursor = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (!aborted()) {
        const i = cursor++;
        if (i >= items.length) return;
        try { await fn(items[i]); } catch { /* per-dork errors are non-fatal */ }
      }
    }
  );
  await Promise.all(workers);
}


export async function runScan(
  domain: string,
  send: Send,
  abortSignal?: AbortSignal,
  keys: ApiKeys = {}
) {
  const aborted = () => abortSignal?.aborted;

  // Resolve effective keys: caller-supplied (BYO) wins, env is the fallback,
  // and the empty string means "phase will be skipped".
  const vtKey       = keys.virustotal?.trim() || process.env.VIRUSTOTAL_KEY?.trim() || "";
  const abuseIpKey  = keys.abuseipdb?.trim()  || process.env.ABUSEIPDB_KEY?.trim()  || "";
  const otxKey      = keys.otx?.trim()        || process.env.OTX_API_KEY?.trim()    || "";

  if (!isDomain(domain)) {
    send({ type: "error", phase: "input", message: `Invalid domain: ${domain}` });
    send({ type: "done" });
    return;
  }

  const orgHint = domain.split(".")[0];

  // Shared email-harvest state — hoisted so every phase (RDAP, GitHub,
  // dorks, Skymem, …) can contribute. The Emails phase consolidates and the
  // Pivot phase re-uses the registrant org for sibling-domain discovery.
  const emailRe = emailRegexFor(domain);
  const allEmails = new Set<string>();
  const extractEmails = (text: string) => {
    for (const m of text.matchAll(emailRe)) allEmails.add(m[0].toLowerCase());
  };
  // Names collected from RDAP contacts + GitHub commit authors. Fed into
  // the permutation generator at the end of the Emails phase.
  const harvestedNames = new Set<string>();
  // Registrant organisation pulled out of RDAP — used by the Domain Pivot
  // phase to find sibling certs issued to the same legal entity.
  let registrantOrg: string | undefined;

  send({ type: "phase", id: "meta", title: "Overview" });
  send({ type: "banner", text: `Passive OSINT: ${domain} — ${new Date().toISOString()}` });
  send({ type: "line", text: "No direct probing. All sources are third-party / public datasets." });
  send({ type: "kv", key: "Org hint", value: orgHint });

  // Kick off slow tasks in the background — same overlap pattern as recon.sh.
  const pCrtsh = crtsh(domain).catch(() => [] as string[]);
  const pHt = hackerTarget(domain).catch(() => [] as string[]);
  const pOtxPdns = otxPassiveDns(domain, otxKey).catch(() => [] as string[]);
  const pWayback = waybackUrls(domain).catch(() => [] as string[]);
  const pAhmia = combinedOnionHits(domain).catch(() => []);
  const pUrlscan = urlscan(domain).catch(() => null);
  const pOtxGen = otxGeneral(domain, otxKey).catch(() => null);
  const pRdap = lookupDomain(domain).catch(() => null);
  // ThreatMiner — free, no key. Subdomains (rt=5) + passive DNS (rt=2). The
  // endpoint is historically flaky so we let failures fall through silently.
  const pTmSubs = threatMinerSubdomains(domain).catch(() => [] as string[]);
  const pTmPdns = threatMinerPassiveDns(domain).catch(() => [] as TmPassiveDnsHit[]);

  // VirusTotal — optional key. When missing, every VT phase is skipped
  // cleanly; when present we launch the report + subdomain + resolutions +
  // URL fetches in parallel so they overlap with everything else.
  const pVtDomain      = vtKey ? vtDomain(domain, vtKey).catch(() => null)            : Promise.resolve(null);
  const pVtSubdomains  = vtKey ? vtSubdomains(domain, vtKey).catch(() => [])          : Promise.resolve([] as Awaited<ReturnType<typeof vtSubdomains>>);
  const pVtResolutions = vtKey ? vtResolutions(domain, vtKey).catch(() => [])         : Promise.resolve([] as Awaited<ReturnType<typeof vtResolutions>>);
  const pVtUrls        = vtKey ? vtDomainUrls(domain, vtKey).catch(() => [])          : Promise.resolve([] as Awaited<ReturnType<typeof vtDomainUrls>>);

  // ---------- Phase 1: WHOIS via RDAP ----------
  send({ type: "phase", id: "whois", title: "WHOIS / RDAP" });
  send({ type: "section", text: "WHOIS / RDAP — registrar, dates, contacts" });
  const rdap = await pRdap;
  if (!rdap) {
    send({ type: "line", text: "  (RDAP lookup failed — try a browser at https://rdap.org)" });
  } else {
    if (rdap.registrar) send({ type: "kv", key: "Registrar", value: rdap.registrar });
    if (rdap.created) send({ type: "kv", key: "Created", value: rdap.created });
    if (rdap.updated) send({ type: "kv", key: "Updated", value: rdap.updated });
    if (rdap.expires) send({ type: "kv", key: "Expires", value: rdap.expires });
    if (rdap.status.length) send({ type: "kv", key: "Status", value: rdap.status.join(", ") });
    if (rdap.dnssec !== undefined) send({ type: "kv", key: "DNSSEC", value: String(rdap.dnssec) });
    if (rdap.nameservers.length) send({ type: "list", title: "Nameservers", items: rdap.nameservers });
    const contactLines = rdap.contacts
      .filter((c) => c.name || c.org || c.email)
      .map((c) => `  ${c.role}: ${[c.name, c.org, c.email].filter(Boolean).join(" / ")}`);
    if (contactLines.length) send({ type: "list", title: "Contacts (often redacted)", items: contactLines });

    // Pull anything email-shaped out of the RDAP contact set — registrants /
    // abuse / tech contacts often expose real role mailboxes the search
    // engines never indexed. Anything matching the target domain feeds into
    // the consolidated set; the rest is shown for context only. Contact
    // names also feed the email-permutation generator below.
    for (const c of rdap.contacts) {
      if (c.email) extractEmails(c.email);
      if (c.name && c.name.length > 1 && c.name.length < 80) harvestedNames.add(c.name);
    }
    // Cache the registrant organisation for the Domain Pivot phase below.
    const registrant = rdap.contacts.find((c) => /registrant/i.test(c.role ?? "")) ?? rdap.contacts[0];
    registrantOrg = registrant?.org || registrant?.name || undefined;
  }
  if (aborted()) return;

  // ---------- Phase 2: DNS via DoH ----------
  send({ type: "phase", id: "dns", title: "DNS Records" });
  const dns = await resolveAll(domain);
  const dkim = await probeDkim(domain);

  const stripDot = (s: string) => s.replace(/\.$/, "");
  const stripQuotes = (s: string) =>
    s.replace(/^"/, "").replace(/"$/, "").replace(/"\s+"/g, "");
  const humanSec = (s: string) => {
    const n = parseInt(s, 10);
    if (Number.isNaN(n)) return s;
    if (n >= 86400) return `${s} (${(n / 86400).toFixed(n % 86400 ? 1 : 0)}d)`;
    if (n >= 3600) return `${s} (${(n / 3600).toFixed(n % 3600 ? 1 : 0)}h)`;
    if (n >= 60) return `${s} (${Math.round(n / 60)}m)`;
    return `${s}s`;
  };
  const classifyTxt = (txt: string): string => {
    if (/^v=spf1\b/i.test(txt)) return "SPF";
    if (/^v=DMARC1\b/i.test(txt)) return "DMARC";
    if (/^v=DKIM1\b/i.test(txt)) return "DKIM";
    if (/^google-site-verification=/i.test(txt)) return "Google verify";
    if (/^MS=/i.test(txt)) return "Microsoft verify";
    if (/^facebook-domain-verification=/i.test(txt)) return "Facebook verify";
    if (/^atlassian-domain-verification=/i.test(txt)) return "Atlassian verify";
    if (/^apple-domain-verification=/i.test(txt)) return "Apple verify";
    if (/^stripe-verifications?=/i.test(txt)) return "Stripe verify";
    if (/^_?globalsign-domain-verification=/i.test(txt)) return "GlobalSign";
    if (/^docusign=/i.test(txt)) return "DocuSign";
    if (/^adobe-idp-site-verification=/i.test(txt)) return "Adobe verify";
    if (/^zoom_verify_/i.test(txt)) return "Zoom verify";
    if (/-site-verification=/i.test(txt)) return "Site verify";
    return "TXT";
  };

  // ---------- IP addresses ----------
  send({ type: "section", text: "IP addresses (A / AAAA)" });
  const ipv4 = dns.a.map((r) => r.data);
  const ipv6 = dns.aaaa.map((r) => r.data);
  if (ipv4.length) send({ type: "list", title: "IPv4", items: ipv4 });
  if (ipv6.length) send({ type: "list", title: "IPv6", items: ipv6 });
  if (!ipv4.length && !ipv6.length) {
    send({ type: "line", text: "  (apex resolves to no A/AAAA records)" });
  }

  // ---------- MX (with enrichment) ----------
  send({ type: "section", text: "Mail servers (MX)" });
  const mxParsed = dns.mx
    .map((r) => {
      const m = r.data.match(/^(\d+)\s+(\S+)/);
      return m ? { priority: parseInt(m[1], 10), host: stripDot(m[2]) } : null;
    })
    .filter((x): x is { priority: number; host: string } => !!x)
    .sort((a, b) => a.priority - b.priority);

  if (mxParsed.length) {
    const mxHosts = mxParsed.map((m) => m.host);
    const providers = detectMailProviders(mxHosts);

    // Resolve A records for each MX hostname concurrently.
    const mxIps = await resolveBulkA(mxHosts, 10);

    // Detected provider summary at the top.
    if (providers.length) {
      const primary = providers[0];
      send({ type: "kv", key: "Mail provider", value: `${primary.name} (${primary.type})` });
      if (providers.length > 1) {
        send({
          type: "kv",
          key: "Additional infrastructure",
          value: providers.slice(1).map((p) => `${p.name} — ${p.type}`).join(" · "),
        });
      }
    } else {
      send({ type: "kv", key: "Mail provider", value: "Self-hosted or unrecognized" });
    }
    send({ type: "kv", key: "MX hosts", value: String(mxParsed.length) });

    // Per-MX enriched lines: priority, hostname, resolved IPs.
    send({ type: "section", text: "MX hostnames — priority, host, resolved IPs" });
    for (const mx of mxParsed) {
      const ips = mxIps.get(mx.host) ?? [];
      const ipText = ips.length ? ips.join(", ") : "(no A record)";
      send({
        type: "kv",
        key: `Priority ${mx.priority}`,
        value: `${mx.host}  →  ${ipText}`,
      });
    }

    // Cross-reference: do the MX IPs come from the same ASN as the apex?
    // Not pinging anything; just collect unique IPs for the ASN phase to
    // process later. Recorded inline so the user sees the breadth.
    const allMxIps = new Set<string>();
    for (const ips of mxIps.values()) for (const ip of ips) allMxIps.add(ip);
    if (allMxIps.size) {
      send({
        type: "kv",
        key: "Unique mail IPs",
        value: String(allMxIps.size),
      });
    }
  } else {
    send({ type: "line", text: "  (no MX records — domain does not receive mail at the apex)" });
  }

  // ---------- NS ----------
  send({ type: "section", text: "Authoritative nameservers (NS)" });
  const nsList = dns.ns.map((r) => stripDot(r.data)).sort();
  if (nsList.length) {
    send({ type: "list", items: nsList });
  } else {
    send({ type: "line", text: "  (no NS records returned)" });
  }

  // ---------- SOA ----------
  send({ type: "section", text: "Start of Authority (SOA)" });
  if (dns.soa.length) {
    const parts = dns.soa[0].data.split(/\s+/);
    if (parts.length >= 7) {
      send({ type: "kv", key: "Primary NS", value: stripDot(parts[0]) });
      send({ type: "kv", key: "Admin contact", value: stripDot(parts[1]).replace(/\./, "@") });
      send({ type: "kv", key: "Serial", value: parts[2] });
      send({ type: "kv", key: "Refresh", value: humanSec(parts[3]) });
      send({ type: "kv", key: "Retry", value: humanSec(parts[4]) });
      send({ type: "kv", key: "Expire", value: humanSec(parts[5]) });
      send({ type: "kv", key: "Minimum TTL", value: humanSec(parts[6]) });
    } else {
      send({ type: "line", text: dns.soa[0].data });
    }
  } else {
    send({ type: "line", text: "  (no SOA record)" });
  }

  // ---------- CAA ----------
  send({ type: "section", text: "Certificate Authority Authorization (CAA)" });
  if (dns.caa.length) {
    for (const r of dns.caa) {
      const m = r.data.match(/^(\d+)\s+(\S+)\s+"?([^"]+)"?/);
      if (m) {
        const flag = parseInt(m[1], 10);
        const issuer = m[3] || "(none)";
        send({
          type: "kv",
          key: m[2],
          value: `${issuer}${flag !== 0 ? " — critical" : ""}`,
        });
      } else {
        send({ type: "line", text: r.data });
      }
    }
  } else {
    send({ type: "line", text: "  (no CAA records — any CA may issue certificates for this domain)" });
  }

  // ---------- TXT ----------
  send({ type: "section", text: "TXT records" });
  if (dns.txt.length) {
    for (const r of dns.txt) {
      const txt = stripQuotes(r.data);
      send({ type: "kv", key: classifyTxt(txt), value: txt });
    }
  } else {
    send({ type: "line", text: "  (no TXT records)" });
  }

  // ---------- DMARC ----------
  send({ type: "section", text: "DMARC email authentication policy" });
  if (dns.dmarc.length) {
    const dmarcRaw = stripQuotes(dns.dmarc[0].data);
    const policyMap: Record<string, string> = {
      v: "Version", p: "Policy", sp: "Subdomain policy",
      pct: "Percent enforced", rua: "Aggregate report URI",
      ruf: "Forensic report URI", adkim: "DKIM alignment",
      aspf: "SPF alignment", fo: "Failure options", rf: "Report format",
      ri: "Report interval",
    };
    let any = false;
    for (const pair of dmarcRaw.split(/;\s*/)) {
      const idx = pair.indexOf("=");
      if (idx === -1) continue;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (!k || !v) continue;
      send({ type: "kv", key: policyMap[k] ?? k, value: v });
      any = true;
    }
    if (!any) send({ type: "line", text: dmarcRaw });
  } else {
    send({ type: "line", text: "  (no DMARC policy — outgoing email can be spoofed)" });
  }

  // ---------- DKIM ----------
  send({ type: "section", text: "DKIM selectors discovered" });
  if (dkim.length) {
    for (const d of dkim) {
      const rec = stripQuotes(d.record);
      const truncated = rec.length > 90 ? `${rec.slice(0, 90)}…` : rec;
      send({ type: "kv", key: d.selector, value: truncated });
    }
  } else {
    send({ type: "line", text: "  (no DKIM records found at common selectors)" });
  }
  if (aborted()) return;

  // ---------- Phase 3: Subdomain enumeration ----------
  send({ type: "phase", id: "subdomains", title: "Subdomains" });
  send({ type: "section", text: "Subdomains via crt.sh (certificate transparency)" });
  const crtshList = await pCrtsh;
  send({ type: "kv", key: "crt.sh count", value: String(crtshList.length) });
  send({ type: "list", title: "crt.sh", items: crtshList });

  send({ type: "section", text: "HackerTarget host search" });
  const htList = await pHt;
  send({ type: "kv", key: "HackerTarget count", value: String(htList.length) });
  send({ type: "list", title: "HackerTarget", items: htList });

  send({ type: "section", text: "AlienVault OTX passive DNS" });
  const otxPdns = await pOtxPdns;
  send({ type: "kv", key: "OTX pDNS count", value: String(otxPdns.length) });
  if (otxPdns.length === 0) {
    // OTX silently rate-limits anonymous callers. Surface the hint inline so
    // the user knows nothing's broken in the code path.
    if (!otxKey) {
      send({
        type: "line",
        text: "  (no OTX results — anonymous callers are heavily rate-limited; add an OTX key in Settings, or set OTX_API_KEY. Free key: https://otx.alienvault.com/api)",
      });
    } else {
      send({ type: "line", text: "  (no OTX results returned for this domain)" });
    }
  } else {
    send({ type: "list", title: "OTX passive DNS", items: otxPdns });
  }

  // ThreatMiner — free, no key required. Surfaces both subdomain discovery
  // and historical passive-DNS resolutions in one source.
  send({ type: "section", text: "ThreatMiner subdomains + passive DNS" });
  const tmSubs = await pTmSubs;
  const tmPdns = await pTmPdns;
  send({ type: "kv", key: "ThreatMiner subdomains", value: String(tmSubs.length) });
  send({ type: "kv", key: "ThreatMiner passive DNS rows", value: String(tmPdns.length) });
  if (tmSubs.length) {
    send({ type: "list", title: "ThreatMiner subdomains", items: tmSubs });
  }
  if (tmPdns.length) {
    const lines = tmPdns.map((r) =>
      `${r.ip.padEnd(17)} ${r.lastSeen.padEnd(12)} ${r.host}`.trimEnd()
    );
    send({ type: "list", title: "ip · last-seen · host (historical)", items: lines });
  }
  if (tmSubs.length === 0 && tmPdns.length === 0) {
    send({ type: "line", text: "  (no ThreatMiner data — endpoint may be rate-limited or down)" });
  }

  // VirusTotal subdomain feed — only emitted when a key is configured. We
  // flag the rows that already have detections in any VT engine so the user
  // can see "this sub has been flagged before" at a glance.
  send({ type: "section", text: "VirusTotal subdomains (relationships)" });
  if (!vtKey) {
    send({ type: "phase-skipped", phase: "VirusTotal", reason: "No VirusTotal key — add one in Settings or set VIRUSTOTAL_KEY." });
  } else {
    const vtSubs = await pVtSubdomains;
    const vtSubFiltered = vtSubs
      .filter((r) => r.name === domain || r.name.endsWith(`.${domain}`))
      .sort((a, b) => a.name.localeCompare(b.name));
    send({ type: "kv", key: "VT subdomains", value: String(vtSubFiltered.length) });
    if (vtSubFiltered.length) {
      const lines = vtSubFiltered.map((r) =>
        (r.malicious || r.suspicious)
          ? `${r.name}  ⚠ malicious=${r.malicious}, suspicious=${r.suspicious}`
          : r.name
      );
      const hits = vtSubFiltered
        .filter((r) => r.malicious || r.suspicious)
        .map((r) => `${r.name}  ⚠ malicious=${r.malicious}, suspicious=${r.suspicious}`);
      send({ type: "list", title: "VirusTotal", items: lines, hits });
    }
  }

  // ---------- Phase 4: Wayback (run before merging so its subs feed back in) ----------
  send({ type: "phase", id: "wayback", title: "Wayback Machine" });
  send({ type: "section", text: "Wayback Machine — historical URLs" });
  const wayback = await pWayback;
  send({ type: "kv", key: "Historical URLs", value: String(wayback.length) });

  const subsInWayback = new Set<string>();
  if (wayback.length) {
    send({ type: "list", title: "Sample (first 50)", items: wayback.slice(0, 50) });

    const interesting = wayback.filter((u) => INTERESTING_PATH.test(u)).slice(0, 100);
    send({
      type: "list",
      title: "Interesting paths (admin/api/.git/.env/etc) — first 100 (HITS)",
      items: interesting.length ? interesting : ["(none)"],
      hits: interesting,
    });

    const withQuery = wayback.filter((u) => u.includes("?")).slice(0, 60);
    send({ type: "list", title: "URLs with query parameters (first 60)", items: withQuery });

    const sensParam = wayback.filter((u) => SENSITIVE_PARAM.test(u)).slice(0, 40);
    send({
      type: "list",
      title: "URLs with sensitive-looking parameters (HITS)",
      items: sensParam.length ? sensParam : ["(none)"],
      hits: sensParam,
    });

    for (const u of wayback) {
      // strip path/port/userinfo before checking; only accept hosts that
      // sit under the queried apex (prevents `evilexample.com` matches).
      const m = u.match(/^https?:\/\/([^/?#]+)/i);
      if (!m) continue;
      const host = m[1].split("@").pop()!.split(":")[0].toLowerCase();
      if (host === domain || host.endsWith(`.${domain}`)) subsInWayback.add(host);
    }
    send({ type: "list", title: "Subdomains seen in wayback URLs", items: [...subsInWayback].sort() });
  }
  if (aborted()) return;

  // ---------- Merged subdomain list (includes wayback + VT + ThreatMiner) -
  send({ type: "phase", id: "subdomains", title: "Subdomains" });
  send({ type: "section", text: "Merged unique subdomains across sources" });
  const vtSubNames = vtKey ? (await pVtSubdomains).map((r) => r.name) : [];
  const tmPdnsHosts = tmPdns.map((r) => r.host).filter(Boolean);
  const allSubs = [...new Set([
    ...crtshList, ...htList, ...otxPdns, ...subsInWayback, ...vtSubNames,
    ...tmSubs, ...tmPdnsHosts,
  ])]
    .filter((h) => h === domain || h.endsWith(`.${domain}`))
    .sort();
  send({ type: "kv", key: "Total unique", value: String(allSubs.length) });
  send({ type: "list", items: allSubs });

  send({ type: "section", text: "Sensitive / interesting subdomain prefixes (HITS)" });
  const sensitiveSubs = allSubs.filter((s) => SENSITIVE_SUB.test(s));
  if (sensitiveSubs.length) {
    send({ type: "list", items: sensitiveSubs, hits: sensitiveSubs });
  } else {
    send({ type: "line", text: "  (none matched sensitive prefix list)" });
  }
  if (aborted()) return;

  // ---------- Phase 5: Email harvesting (multi-source) ----------
  // emailRe / allEmails / extractEmails are hoisted at the top of runScan so
  // earlier phases (RDAP) can contribute. This phase consolidates and adds
  // its own dedicated sources (wayback, DDG, urlscan, role probes, Skymem).
  send({ type: "phase", id: "emails", title: "Emails" });

  // 1) Archived URLs
  send({ type: "section", text: "Emails referenced in archived URLs" });
  const waybackEmails: string[] = [];
  for (const u of wayback) {
    for (const m of u.matchAll(emailRe)) {
      const e = m[0].toLowerCase();
      if (!allEmails.has(e)) waybackEmails.push(e);
      allEmails.add(e);
    }
  }
  if (waybackEmails.length) {
    const list = [...new Set(waybackEmails)].sort();
    send({ type: "list", items: list, hits: list });
  } else {
    send({ type: "line", text: "  (none found in wayback URL strings)" });
  }

  // 2) urlscan public scans — page URLs sometimes embed the user in the path
  const usForEmail = await pUrlscan;
  for (const r of usForEmail?.results ?? []) extractEmails(r.page?.url ?? "");

  // 3) Dedicated DDG email-harvest search.
  //    NOTE: an earlier version filtered by `requireMentions: @${domain}` —
  //    that's too strict because DDG snippets routinely truncate `"local@"`
  //    leaving only the bare domain visible. We relax the mention filter to
  //    just the domain and let the email regex below decide what's real.
  //    A few query variants improve coverage; results are deduped downstream.
  send({ type: "section", text: 'Emails surfaced via DuckDuckGo "@domain" search' });
  const emailQueries = [`"@${domain}"`, `"contact" "${domain}"`, `"email" "${domain}"`];
  const ddgEmailResults: { title: string; url: string; snippet?: string }[] = [];
  for (const q of emailQueries) {
    const r = await ddgSearch(q, 12, { requireMentions: domain }).catch(() => []);
    ddgEmailResults.push(...r);
  }
  const newFromDdg: string[] = [];
  for (const r of ddgEmailResults) {
    const before = allEmails.size;
    extractEmails(`${r.title} ${r.snippet ?? ""} ${r.url}`);
    if (allEmails.size > before) {
      // Track which result yielded an email so we can show provenance.
      const yielded: string[] = [];
      for (const m of `${r.title} ${r.snippet ?? ""} ${r.url}`.matchAll(emailRe)) {
        yielded.push(m[0].toLowerCase());
      }
      newFromDdg.push(`${[...new Set(yielded)].join(", ")}  ←  ${r.url}`);
    }
  }
  if (newFromDdg.length) {
    send({ type: "list", items: newFromDdg, hits: newFromDdg });
  } else if (ddgEmailResults.length === 0) {
    send({ type: "line", text: "  (DDG returned no results / rate limited — open https://duckduckgo.com/?q=%22%40" + domain + "%22 to retry)" });
  } else {
    send({ type: "line", text: "  (DDG returned results, but none contained extractable email addresses)" });
  }

  // 4) Common-role probes — confirms which standard role mailboxes are
  //    publicly referenced. We require only that the snippet/title/url
  //    mentions the domain (the literal `role@domain` rarely survives DDG
  //    snippet truncation) and that the role local-part appears in the
  //    surrounding text — that pair is enough signal that the email exists.
  const ROLE_LOCALPARTS = ["info", "contact", "sales", "support", "hr", "careers", "security", "admin", "press", "marketing", "legal"];
  send({ type: "section", text: "Role-account probes" });
  const roleHits: string[] = [];
  await runDorkPool(ROLE_LOCALPARTS, 4, aborted, async (role) => {
    const q = `"${role}@${domain}"`;
    const res = await ddgSearch(q, 4, { requireMentions: domain }).catch(() => []);
    if (!res.length) return;
    let confirmed = false;
    for (const r of res.slice(0, 4)) {
      const hay = `${r.title} ${r.snippet ?? ""} ${r.url}`.toLowerCase();
      if (hay.includes(`${role}@`) || hay.includes(`${role} @`) || hay.includes(`${role}<at>`)) {
        confirmed = true;
        roleHits.push(`${role}@${domain}  ←  ${r.url}`);
      }
      extractEmails(`${r.title} ${r.snippet ?? ""}`);
    }
    if (confirmed) allEmails.add(`${role}@${domain}`);
  });
  if (roleHits.length) {
    send({ type: "list", items: roleHits, hits: roleHits });
  } else {
    send({ type: "line", text: "  (no role-account references found in live search)" });
  }

  // 5) Skymem public email index. Last-resort scrape — runs after the
  //    other sources so it only fills gaps when they came up dry. Skymem
  //    has had availability issues historically; we treat failure as
  //    "source down" and continue.
  send({ type: "section", text: "Skymem public email index" });
  const skymemHits = await skymemEmails(domain).catch(() => []);
  if (skymemHits.length) {
    const fresh = skymemHits.filter((e) => !allEmails.has(e));
    for (const e of skymemHits) allEmails.add(e);
    if (fresh.length) {
      emitHitFound(send, `Skymem returned ${skymemHits.length} email(s) (${fresh.length} new)`);
    }
    send({ type: "list", items: skymemHits, hits: skymemHits });
  } else {
    send({ type: "line", text: "  (no Skymem results — source may be rate-limited or down)" });
  }

  // Running tally — useful even if later phases add more.
  send({ type: "kv", key: "Emails so far", value: String(allEmails.size) });

  // ---------- Phase 6: GitHub (REST API + DDG/Bing dorks as fallback) ----------
  //
  // The old DDG-only approach barely worked because DDG's index of github.com
  // is sparse. We now query api.github.com directly for the three things that
  // work unauth (repo / issue / user search) and surface real results, then
  // fall back to DDG+Bing dorks for the file-content side of recon. The
  // GitHub code-search links are kept for one-click manual inspection (code
  // search needs an auth token).
  send({ type: "phase", id: "github", title: "GitHub Dorks" });
  send({ type: "section", text: "GitHub presence" });
  send({ type: "kv", key: "Org page", value: `https://github.com/${orgHint}` });
  send({ type: "kv", key: "Org code search", value: `https://github.com/search?q=org%3A${orgHint}&type=code` });

  // ----- 1. Identify the org / user that owns the domain on GitHub ----------
  const orgUser = await ghFindOrg(orgHint, domain).catch(() => null);
  if (orgUser) {
    send({ type: "section", text: "GitHub org / user match" });
    emitHitFound(send, `GitHub account: ${orgUser.login} (${orgUser.type})`);
    send({ type: "kv", key: "Profile", value: orgUser.html_url });
    if (orgUser.name) send({ type: "kv", key: "Display name", value: orgUser.name });

    // Public repos owned by this account — the bulk of useful recon when the
    // org is real (employees often leave configs / examples / docs in here).
    const orgRepos = await ghListOrgRepos(orgUser.login, 25).catch(() => []);
    if (orgRepos.length) {
      send({ type: "section", text: `Public repos for @${orgUser.login}` });
      emitHitFound(send, `${orgRepos.length} public repo(s)`);
      const items = orgRepos.map((r) => {
        const meta = [r.language, `★${r.stargazers_count}`, `pushed ${r.pushed_at.slice(0, 10)}`]
          .filter(Boolean).join(" · ");
        const desc = r.description ? `\n    ${r.description}` : "";
        return `${r.full_name} — ${r.html_url}  (${meta})${desc}`;
      });
      send({ type: "list", items, hits: items });

      // Harvest author/committer emails from recent commits on the most-
      // recently-pushed repos — historically the single highest-yield free
      // source for real employee addresses.
      const targets = orgRepos.slice(0, 4).map((r) => ({
        owner: r.owner.login,
        name: r.full_name.split("/").pop() ?? "",
      })).filter((r) => r.name);
      const commitEmails = await ghCollectCommitEmails(targets, emailRe).catch(() => []);
      send({ type: "section", text: `Emails extracted from commit metadata (@${orgUser.login} repos)` });
      if (commitEmails.length) {
        emitHitFound(send, `${commitEmails.length} commit author/committer email(s) matching the target domain`);
        const lines = commitEmails.map(
          (c) => `${c.email}${c.name ? `  (${c.name})` : ""}  ←  ${c.repo}`
        );
        send({ type: "list", items: lines, hits: lines });
        // Fold into the consolidated set so Phase 5 / final tally includes them,
        // and feed any associated commit-author names into the permutation pool.
        for (const c of commitEmails) {
          allEmails.add(c.email);
          if (c.name && c.name.length > 1 && c.name.length < 80) harvestedNames.add(c.name);
        }
      } else {
        send({ type: "line", text: "  (no commit emails matched the target domain — contributors may use personal addresses or GitHub noreply)" });
      }
    }
  } else {
    send({ type: "line", text: `  (no GitHub account matched orgHint "${orgHint}" — domain may not have a public org)` });
  }

  // ----- 2. Repos mentioning the domain anywhere ----------------------------
  const repoSearch = await ghSearchRepos(`${domain} in:name,description,readme`, 12).catch(() => ({ total: 0, items: [] }));
  send({ type: "section", text: "Repositories mentioning the domain" });
  send({ type: "kv", key: "Open in GitHub", value: `https://github.com/search?q=${encodeURIComponent(domain)}&type=repositories` });
  if (repoSearch.items.length) {
    emitHitFound(send, `${repoSearch.total} repo(s) total, showing top ${repoSearch.items.length}`);
    const items = repoSearch.items.map((r) => {
      const meta = [`@${r.owner.login}`, r.language, `★${r.stargazers_count}`, `pushed ${r.pushed_at.slice(0, 10)}`]
        .filter(Boolean).join(" · ");
      const desc = r.description ? `\n    ${r.description}` : "";
      return `${r.full_name} — ${r.html_url}  (${meta})${desc}`;
    });
    send({ type: "list", items, hits: items });
  } else {
    send({ type: "line", text: "  (no repos mention this domain — or GitHub API rate-limited)" });
  }

  // ----- 3. Issues and PRs mentioning the domain ----------------------------
  const issueSearch = await ghSearchIssues(`${domain}`, 12).catch(() => ({ total: 0, items: [] }));
  send({ type: "section", text: "Issues / PRs mentioning the domain" });
  send({ type: "kv", key: "Open in GitHub", value: `https://github.com/search?q=${encodeURIComponent(domain)}&type=issues` });
  if (issueSearch.items.length) {
    emitHitFound(send, `${issueSearch.total} issue/PR mentions, showing top ${issueSearch.items.length}`);
    const items = issueSearch.items.map((i) => {
      const kind = i.pull_request ? "PR" : "issue";
      const repo = i.repository_url.replace("https://api.github.com/repos/", "");
      const author = i.user?.login ?? "?";
      const snippet = (i.body ?? "").replace(/\s+/g, " ").trim().slice(0, 160);
      const sn = snippet ? `\n    ${snippet}` : "";
      return `[${kind}] ${repo}: ${i.title}  (by @${author}, ${i.state}) — ${i.html_url}${sn}`;
    });
    send({ type: "list", items, hits: items });
    // Opportunistic email harvest from issue bodies (commit-style emails).
    for (const i of issueSearch.items) extractEmails(i.body ?? "");
  } else {
    send({ type: "line", text: "  (no issue/PR mentions — or GitHub API rate-limited)" });
  }

  // ----- 4. Content-side dorks via DDG + Bing fallback ----------------------
  // These look for actual file contents — code search via API needs OAuth,
  // so we lean on the web indexes here. Each result still falls back to the
  // GitHub code-search link for the one-click manual path.
  type GhDork = { label: string; ddg: string; gh: string };
  const ghDorks: GhDork[] = [
    { label: "passwords in code",       ddg: `"${domain}" password`,            gh: `"${domain}" password` },
    { label: "API keys",                ddg: `"${domain}" api_key`,             gh: `"${domain}" api_key` },
    { label: "tokens",                  ddg: `"${domain}" token`,               gh: `"${domain}" token` },
    { label: "generic secrets",         ddg: `"${domain}" secret`,              gh: `"${domain}" secret` },
    { label: ".env files",              ddg: `"${domain}" ".env"`,              gh: `"${domain}" filename:.env` },
    { label: "config files",            ddg: `"${domain}" config`,              gh: `"${domain}" filename:config` },
    { label: "private keys",            ddg: `"${domain}" "BEGIN PRIVATE KEY"`, gh: `"${domain}" "BEGIN RSA PRIVATE KEY"` },
    { label: "AWS keys",                ddg: `"${domain}" "AKIA"`,              gh: `"${domain}" "AKIA"` },
    { label: "JWTs",                    ddg: `"${domain}" "eyJhbGci"`,          gh: `"${domain}" "eyJhbGci"` },
  ];

  await runDorkPool(ghDorks, 5, aborted, async ({ label, ddg, gh }) => {
    const query = `site:github.com ${ddg}`;
    const { results, engine } = await webSearch(query, 6, {
      requireHost: "github.com",
      requireMentions: domain,
    });
    send({ type: "section", text: `GitHub web-dork: ${label}` });
    send({ type: "kv", key: "Query", value: query });
    send({ type: "kv", key: "GitHub code search", value: ghSearchUrl(gh) });
    if (results.length) {
      for (const r of results) extractEmails(`${r.title} ${r.snippet ?? ""}`);
      emitHitFound(send, `${results.length} result(s) via ${engine === "bing" ? "Bing" : "DuckDuckGo"}`);
      const items = results.map((r) =>
        r.snippet ? `${r.title} — ${r.url}\n    ${r.snippet}` : `${r.title} — ${r.url}`
      );
      send({ type: "list", title: "Live results (HITS)", items, hits: items });
    } else {
      send({ type: "line", text: "  (no live web-index results — code search needs OAuth; use the GitHub link above)" });
    }
  });

  // ---------- Phase 7: Google/DDG dorks ----------
  send({ type: "phase", id: "dorks", title: "Search Dorks (live)" });
  send({ type: "section", text: "Google dorks — live results via DuckDuckGo" });

  // Two queries per dork:
  //   `ddg`    — what we send to DuckDuckGo. Plain text + site: only. DDG
  //              silently ignores chained-OR ext: and unparenthesized
  //              operators, which is why the previous queries returned
  //              irrelevant results.
  //   `google` — the deep dork with full Google syntax, exposed as a
  //              one-click handoff link for advanced inspection.
  //   `host`   — required host on the result URL.
  //   `mention`— required substring in title/url/snippet.
  type Dork = { label: string; ddg: string; google: string; host?: string; mention?: string };
  const dorks: Dork[] = [
    { label: "all indexed content",      ddg: `site:${domain}`,                          google: `site:${domain}`,                                                                            host: domain },
    { label: "non-www subdomains",       ddg: `site:${domain} -www`,                     google: `site:${domain} -www`,                                                                       host: domain },
    { label: "admin surfaces",           ddg: `site:${domain} admin`,                    google: `site:${domain} (inurl:admin OR inurl:dashboard OR inurl:console)`,                          host: domain },
    { label: "login surfaces",           ddg: `site:${domain} login`,                    google: `site:${domain} (inurl:login OR inurl:signin OR inurl:auth)`,                                host: domain },
    { label: "leaked PDFs",              ddg: `site:${domain} filetype:pdf`,             google: `site:${domain} (ext:pdf OR ext:doc OR ext:xls OR ext:csv)`,                                 host: domain },
    { label: "directory listings",       ddg: `site:${domain} "index of"`,               google: `site:${domain} intext:"index of /"`,                                                        host: domain },
    { label: "exposed .git",             ddg: `site:${domain} ".git"`,                   google: `site:${domain} inurl:.git`,                                                                 host: domain },
    { label: "wordpress paths",          ddg: `site:${domain} wp-content`,               google: `site:${domain} (inurl:wp-content OR inurl:wp-includes)`,                                    host: domain },
    { label: "exposed env files",        ddg: `site:${domain} ".env"`,                   google: `site:${domain} (inurl:.env OR ext:env)`,                                                    host: domain },
    { label: "pastebin leaks",           ddg: `site:pastebin.com "${domain}"`,           google: `site:pastebin.com "${domain}"`,                                                             host: "pastebin.com",            mention: domain },
    { label: "trello leaks",             ddg: `site:trello.com "${domain}"`,             google: `site:trello.com "${domain}"`,                                                               host: "trello.com",              mention: domain },
    { label: "linkedin presence",        ddg: `site:linkedin.com "${domain}"`,           google: `site:linkedin.com "${domain}"`,                                                             host: "linkedin.com",            mention: domain },
    { label: "stackoverflow mentions",   ddg: `site:stackoverflow.com "${domain}"`,      google: `site:stackoverflow.com "${domain}"`,                                                        host: "stackoverflow.com",       mention: domain },
    { label: "open S3 buckets",          ddg: `site:s3.amazonaws.com "${domain}"`,       google: `site:s3.amazonaws.com "${domain}"`,                                                         host: "s3.amazonaws.com",        mention: domain },
    { label: "open Azure blobs",         ddg: `site:blob.core.windows.net "${domain}"`,  google: `site:blob.core.windows.net "${domain}"`,                                                    host: "blob.core.windows.net",   mention: domain },
    { label: "open GCS buckets",         ddg: `site:storage.googleapis.com "${domain}"`, google: `site:storage.googleapis.com "${domain}"`,                                                   host: "storage.googleapis.com",  mention: domain },
  ];

  await runDorkPool(dorks, 5, aborted, async ({ label, ddg, google, host, mention }) => {
    const { results, engine } = await webSearch(ddg, 8, {
      requireHost: host,
      requireMentions: mention,
    });
    send({ type: "section", text: label });
    send({ type: "kv", key: "Query", value: ddg });
    send({ type: "kv", key: "Google (advanced)", value: `https://www.google.com/search?q=${encodeURIComponent(google)}` });
    send({ type: "kv", key: "DDG", value: `https://duckduckgo.com/?q=${encodeURIComponent(ddg)}` });
    if (results.length) {
      for (const r of results) extractEmails(`${r.title} ${r.snippet ?? ""}`);
      emitHitFound(send, `${results.length} result(s) via ${engine === "bing" ? "Bing" : "DuckDuckGo"}`);
      const items = results.map((r) =>
        r.snippet ? `${r.title} — ${r.url}\n    ${r.snippet}` : `${r.title} — ${r.url}`
      );
      send({ type: "list", title: "Live results (HITS)", items, hits: items });
    } else {
      send({ type: "line", text: "  (no live results from DDG or Bing — open the Google advanced link for full-operator search)" });
    }
  });

  // Re-enter the Emails phase after the dorks have run.
  send({ type: "phase", id: "emails", title: "Emails" });

  // --- Name-based permutations (MailAccess-style, purely local) ----------
  // Generates the standard ~14 corporate patterns (john.doe@, j.doe@, jdoe@…)
  // for every name harvested from RDAP contacts + GitHub commit authors.
  // No network calls happen here — Gravatar verification below picks the
  // candidates that are real.
  send({ type: "section", text: "Permutated email candidates (from harvested names)" });
  const candidatePermutations = new Set<string>();
  // Cap the name pool so the permutation surface stays reasonable.
  const namesForPermutation = [...harvestedNames].slice(0, 30);
  for (const n of namesForPermutation) {
    for (const e of permutateEmailsFromName(n, domain)) candidatePermutations.add(e);
  }
  // Remove patterns we already confirmed via other sources.
  for (const e of allEmails) candidatePermutations.delete(e);
  if (candidatePermutations.size === 0) {
    if (harvestedNames.size === 0) {
      send({ type: "line", text: "  (no names harvested yet — permutation pool empty)" });
    } else {
      send({ type: "line", text: "  (all permutations were already confirmed via other sources — see below)" });
    }
  } else {
    send({ type: "kv", key: "Names used", value: String(namesForPermutation.length) });
    send({ type: "kv", key: "Candidates generated", value: String(candidatePermutations.size) });
    const sample = [...candidatePermutations].sort().slice(0, 40);
    send({
      type: "list",
      title: `sample (${Math.min(sample.length, 40)} of ${candidatePermutations.size}) — unverified until Gravatar pass below`,
      items: sample,
    });
  }

  // --- Gravatar verification (passive against the mail server) -----------
  // Checks every harvested + permutated email against gravatar.com. A 200
  // means the address is real and someone has registered a Gravatar profile
  // under that exact mailbox. The endpoint is HTTPS-only, unauth, and does
  // not contact the target's mail server in any way.
  send({ type: "section", text: "Gravatar profile verification" });
  const gravatarPool = [...new Set([...allEmails, ...candidatePermutations])];
  const CAP = 80;                                  // keep the pass under ~10s
  const probePool = gravatarPool.slice(0, CAP);
  if (probePool.length === 0) {
    send({ type: "line", text: "  (no addresses to check)" });
  } else {
    send({ type: "kv", key: "Probed", value: `${probePool.length} of ${gravatarPool.length}` });
    const hits = await pMap(probePool, 8, (email) =>
      gravatarLookup(email).catch(() => null)
    );
    const confirmed = hits.filter((h): h is NonNullable<typeof h> => h !== null);
    if (confirmed.length) {
      emitHitFound(send, `${confirmed.length} address(es) verified via public Gravatar profile`);
      const lines = confirmed.map((g) => {
        const who = [g.displayName, g.preferredUsername].filter(Boolean).join(" / ");
        const acc = g.accounts.length ? `\n    linked: ${g.accounts.slice(0, 4).join("  ·  ")}` : "";
        const meta = who ? `  (${who})` : "";
        return `${g.email}${meta}  →  ${g.profileUrl}${acc}`;
      });
      send({ type: "list", items: lines, hits: lines });
      for (const g of confirmed) allEmails.add(g.email);
    } else {
      send({ type: "line", text: "  (no Gravatar profiles found for the probed addresses)" });
    }
    if (gravatarPool.length > CAP) {
      send({
        type: "line",
        text: `  (capped at ${CAP} probes — ${gravatarPool.length - CAP} candidate(s) not checked)`,
      });
    }
  }

  // --- Consolidated set ---------------------------------------------------
  send({ type: "section", text: "Consolidated email findings (all sources)" });
  if (allEmails.size > 0) {
    const list = [...allEmails].sort();
    send({ type: "kv", key: "Total unique emails", value: String(list.length) });
    send({ type: "list", items: list, hits: list });
  } else {
    send({ type: "line", text: "  (no addresses surfaced — try Hunter.io / RocketReach manually)" });
  }

  // ---------- Phase 8: Threat intel & dark web ----------
  send({ type: "phase", id: "threat", title: "Threat Intel & Dark Web" });

  // --- Onion indices (Ahmia RSS + OnionLand HTML, merged by onion address) -
  send({ type: "section", text: "Onion indices (Ahmia RSS + OnionLand)" });
  const onions = await pAhmia;
  if (onions.length) {
    emitHitFound(send, `${onions.length} onion site reference(s) mentioning ${domain}`);
    // Group by source so the user can see provenance at a glance.
    const grouped = new Map<string, typeof onions>();
    for (const h of onions) {
      const list = grouped.get(h.source) ?? [];
      list.push(h);
      grouped.set(h.source, list);
    }
    for (const [src, hits] of grouped) {
      const lines: string[] = [];
      for (const h of hits) {
        const title = h.title ? ` — ${h.title}` : "";
        const date  = h.date ? ` [${h.date}]` : "";
        lines.push(`${h.url}${date}${title}`);
        if (h.snippet) lines.push(`    ${h.snippet}`);
      }
      const label = src === "ahmia" ? "Ahmia" : "OnionLand";
      send({ type: "list", title: `${label} (${hits.length})`, items: lines, hits: lines });
    }
    send({ type: "kv", key: "Total onion references", value: String(onions.length) });
    send({ type: "line", text: "  ⚠ Open onion URLs in Tor Browser only — never on a clearnet browser." });
  } else {
    send({ type: "line", text: "  (no onion mentions found in either index)" });
  }
  send({ type: "line", text: `  Ahmia:     https://ahmia.fi/search/?q=${encodeURIComponent(domain)}` });
  send({ type: "line", text: `  OnionLand: https://onionlandsearchengine.com/search?q=${encodeURIComponent(domain)}` });

  // --- Leak-indicator queries -------------------------------------------------
  // These look for breach-announcement / dump-mention patterns rather than
  // restricting to a specific site. Catches the long tail of leak threads on
  // miscellaneous forums DDG/Bing actually indexes.
  send({ type: "section", text: "Leak-indicator queries (cross-site)" });
  const leakProbes: { label: string; query: string }[] = [
    { label: "leaked database",   query: `"${domain}" ("leaked database" OR "database leak" OR "db leak")` },
    { label: "credentials dump",  query: `"${domain}" ("credentials dump" OR "creds dump" OR "password dump")` },
    { label: "data breach",       query: `"${domain}" ("data breach" OR "data leak")` },
    { label: "user dump",         query: `"${domain}" ("user dump" OR "users.sql" OR "users.csv")` },
    { label: "stealer logs",      query: `"${domain}" ("stealer logs" OR "stealer log" OR "redline" OR "raccoon")` },
    { label: "combo list",        query: `"${domain}" ("combo list" OR "combolist" OR "email:password")` },
    { label: "ransomware mention",query: `"${domain}" (ransomware OR LockBit OR ALPHV OR BlackCat OR Cl0p)` },
  ];

  let anyLeakHit = false;
  await runDorkPool(leakProbes, 4, aborted, async ({ label, query }) => {
    const { results, engine } = await webSearch(query, 6, { requireMentions: domain });
    if (!results.length) return;
    anyLeakHit = true;
    emitHitFound(send, `${label}: ${results.length} result(s) via ${engine === "bing" ? "Bing" : "DuckDuckGo"}`);
    const items = results.map((r) =>
      r.snippet ? `[${label}] ${r.title} — ${r.url}\n    ${r.snippet}` : `[${label}] ${r.title} — ${r.url}`
    );
    send({ type: "list", title: label, items, hits: items });
  });
  if (!anyLeakHit) {
    send({ type: "line", text: "  (no breach-pattern matches in clearnet indices — manual sources below)" });
  }

  // --- Paste / breach-forum surfaces -----------------------------------------
  send({ type: "section", text: "Paste & breach-forum surfaces (site-scoped)" });
  const darkDorks: { label: string; query: string; host: string }[] = [
    { label: "Pastebin",            query: `site:pastebin.com "${domain}"`,           host: "pastebin.com" },
    { label: "ghostbin",            query: `site:ghostbin.com "${domain}"`,           host: "ghostbin.com" },
    { label: "Throwbin",            query: `site:throwbin.io "${domain}"`,            host: "throwbin.io" },
    { label: "Rentry",              query: `site:rentry.co "${domain}"`,              host: "rentry.co" },
    { label: "JustPaste",           query: `site:justpaste.it "${domain}"`,           host: "justpaste.it" },
    { label: "Pastie",              query: `site:paste.ee "${domain}"`,               host: "paste.ee" },
    { label: "controlc",            query: `site:controlc.com "${domain}"`,           host: "controlc.com" },
    { label: "Doxbin (clearnet)",   query: `site:doxbin.org "${domain}"`,             host: "doxbin.org" },
    { label: "BreachForums (.st)",  query: `site:breachforums.st "${domain}"`,        host: "breachforums.st" },
    { label: "BreachForums (.is)",  query: `site:breachforums.is "${domain}"`,        host: "breachforums.is" },
    { label: "RaidForums (mirror)", query: `site:raidforums.uk "${domain}"`,          host: "raidforums.uk" },
    { label: "exposed.lol",         query: `site:exposed.lol "${domain}"`,            host: "exposed.lol" },
    { label: "leakcheck (page)",    query: `site:leakcheck.io "${domain}"`,           host: "leakcheck.io" },
    { label: "Hudson Rock cavalier",query: `site:cavalier.hudsonrock.com "${domain}"`,host: "cavalier.hudsonrock.com" },
    { label: "Have I Been Pwned",   query: `"${domain}" "have i been pwned"`,         host: "haveibeenpwned.com" },
  ];

  let anyDarkHit = false;
  await runDorkPool(darkDorks, 4, aborted, async ({ label, query, host }) => {
    const { results, engine } = await webSearch(query, 6, {
      requireHost: host,
      requireMentions: domain,
    });
    if (!results.length) return;
    anyDarkHit = true;
    emitHitFound(send, `${label}: ${results.length} result(s) via ${engine === "bing" ? "Bing" : "DuckDuckGo"}`);
    const items = results.map((r) =>
      r.snippet ? `[${label}] ${r.title} — ${r.url}\n    ${r.snippet}` : `[${label}] ${r.title} — ${r.url}`
    );
    send({ type: "list", title: label, items, hits: items });
  });
  if (!anyDarkHit) {
    send({ type: "line", text: "  (no live paste / breach-forum hits — manual sources below)" });
  }

  // ---------- VirusTotal: domain report + URL scan archive + resolutions ----
  send({ type: "section", text: "VirusTotal — domain report" });
  if (!vtKey) {
    send({
      type: "phase-skipped",
      phase: "VirusTotal",
      reason: "No VirusTotal key — add one in Settings or set VIRUSTOTAL_KEY in .env.",
    });
  } else {
    const vtRep = await pVtDomain;
    const attrs = vtRep?.data?.attributes;
    if (!attrs) {
      send({ type: "line", text: "  (no VirusTotal record returned — domain unknown to VT or rate-limited)" });
    } else {
      const stats = attrs.last_analysis_stats ?? {};
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const total = (stats.harmless ?? 0) + (stats.malicious ?? 0) + (stats.suspicious ?? 0) +
                    (stats.undetected ?? 0) + (stats.timeout ?? 0);
      const bad = malicious > 0 || suspicious > 0;
      if (bad) {
        emitHitFound(send, `VT engines flagged this domain: ${malicious} malicious, ${suspicious} suspicious (of ${total})`);
      } else {
        send({ type: "kv", key: "VT verdict", value: `clean (${total} engines, 0 malicious)` });
      }
      if (attrs.reputation !== undefined)        send({ type: "kv", key: "Reputation", value: String(attrs.reputation) });
      if (attrs.total_votes) {
        const v = attrs.total_votes;
        send({ type: "kv", key: "Community votes", value: `harmless ${v.harmless ?? 0} · malicious ${v.malicious ?? 0}` });
      }
      if (attrs.categories && Object.keys(attrs.categories).length) {
        const cats = Object.entries(attrs.categories)
          .map(([engine, cat]) => `${engine}: ${cat}`)
          .join(" · ");
        send({ type: "kv", key: "Categories", value: cats });
      }
      if (attrs.tags?.length) send({ type: "kv", key: "Tags", value: attrs.tags.join(", ") });
      if (attrs.creation_date) {
        send({ type: "kv", key: "VT first-seen creation", value: new Date(attrs.creation_date * 1000).toISOString().slice(0, 10) });
      }
    }
    send({ type: "line", text: `  Browse: https://www.virustotal.com/gui/domain/${domain}` });

    // URL scan archive (VT side — distinct from urlscan.io below)
    send({ type: "section", text: "VirusTotal — URLs scanned under this domain" });
    const vtUrls = await pVtUrls;
    if (!vtUrls.length) {
      send({ type: "line", text: "  (no URLs in VT's archive for this domain)" });
    } else {
      const flagged = vtUrls.filter((u) => u.malicious || u.suspicious);
      if (flagged.length) {
        emitHitFound(send, `${flagged.length} of ${vtUrls.length} archived URL(s) flagged by VT engines`);
      } else {
        send({ type: "kv", key: "Archived URLs", value: `${vtUrls.length} (all clean)` });
      }
      const lines = vtUrls.map((u) => {
        const verdict = (u.malicious || u.suspicious)
          ? `⚠ malicious=${u.malicious}, suspicious=${u.suspicious}`
          : "clean";
        const when = u.lastAnalyzed ? `[${u.lastAnalyzed}] ` : "";
        return `${when}${u.url}  (${verdict})`;
      });
      const hits = vtUrls
        .filter((u) => u.malicious || u.suspicious)
        .map((u) => {
          const when = u.lastAnalyzed ? `[${u.lastAnalyzed}] ` : "";
          return `${when}${u.url}  (⚠ malicious=${u.malicious}, suspicious=${u.suspicious})`;
        });
      send({ type: "list", items: lines, hits });
    }

    // Historical DNS resolutions — gold for Crimeflare-style origin hunts:
    // these are IPs the domain *used to* resolve to before it went behind a
    // CDN. Often the box is still alive on the old IP.
    send({ type: "section", text: "VirusTotal — historical DNS resolutions" });
    const vtRes = await pVtResolutions;
    if (!vtRes.length) {
      send({ type: "line", text: "  (no historical resolutions in VT)" });
    } else {
      send({ type: "kv", key: "Historical resolutions", value: String(vtRes.length) });
      const lines = vtRes.map((r) =>
        `${r.ip.padEnd(17)} ${r.date.padEnd(12)} ${r.host ?? ""}`.trimEnd()
      );
      send({ type: "list", title: "ip · last-seen · host", items: lines, hits: lines });
      send({
        type: "line",
        text: "  ⚠ Historical IPs may still serve the same origin and bypass any current CDN/WAF.",
      });
    }
  }

  send({ type: "section", text: "urlscan.io — public scan archive" });
  const us = await pUrlscan;
  const usTotal = us?.total ?? 0;
  if (usTotal && us?.results?.length) {
    send({ type: "kv", key: "Public scans", value: String(usTotal) });
    for (const r of us.results) {
      const date = (r.task.time || "").slice(0, 10);
      const mal = r.verdicts?.overall?.malicious ?? false;
      send({ type: "line", text: `  [${date}] ${r.page.url}  (malicious: ${mal})`, hit: mal });
    }
  } else {
    send({ type: "line", text: "  (no public scans found)" });
  }
  send({ type: "line", text: `  Browse: https://urlscan.io/domain/${domain}` });

  // ---------- web-check style enrichment: tech stack + TLS + page hints ----
  // Pull whatever metadata urlscan already captured on its most-recent scan.
  // All passive — we're reading data urlscan crawled on its own infra.
  const latestUs = us?.results?.[0]?.page;
  if (latestUs && (latestUs.server || latestUs.title || latestUs.tlsIssuer)) {
    send({ type: "section", text: "Tech / page fingerprint (from urlscan)" });
    if (latestUs.title)    send({ type: "kv", key: "Page title",    value: latestUs.title.slice(0, 160) });
    if (latestUs.server)   send({ type: "kv", key: "Server header", value: latestUs.server });
    if (latestUs.mimeType) send({ type: "kv", key: "MIME type",     value: latestUs.mimeType });
    if (latestUs.ip)       send({ type: "kv", key: "Scan resolved IP", value: latestUs.ip });
    if (latestUs.country)  send({ type: "kv", key: "Country (scan)", value: latestUs.country });
    if (latestUs.asnname)  send({ type: "kv", key: "ASN (scan)",     value: `${latestUs.asn ?? "?"} ${latestUs.asnname}` });

    if (latestUs.tlsIssuer || latestUs.tlsValidFrom || latestUs.tlsValidDays !== undefined) {
      send({ type: "section", text: "TLS certificate (from urlscan)" });
      if (latestUs.tlsIssuer)              send({ type: "kv", key: "Issuer",     value: latestUs.tlsIssuer });
      if (latestUs.tlsValidFrom)           send({ type: "kv", key: "Valid from", value: latestUs.tlsValidFrom });
      if (latestUs.tlsValidDays !== undefined) {
        const tooSoon = latestUs.tlsValidDays < 14;
        send({
          type: "line",
          text: `  Days remaining: ${latestUs.tlsValidDays}${tooSoon ? "  ⚠ near expiry" : ""}`,
          hit: tooSoon,
        });
      }
    }
  }

  // robots.txt / sitemap.xml visibility — reuse the wayback corpus rather
  // than fetching the target directly. If wayback has ever captured these,
  // we know they were public at some point and we surface the snapshot link.
  const robotsHit = wayback.find((u) => /\/robots\.txt(\?|$)/i.test(u));
  const sitemapHit = wayback.find((u) => /\/sitemap(?:[-_\w]*)?\.xml(\?|$)/i.test(u));
  if (robotsHit || sitemapHit) {
    send({ type: "section", text: "Crawl rules + sitemap (from wayback)" });
    if (robotsHit)  send({ type: "kv", key: "robots.txt",  value: robotsHit });
    if (sitemapHit) send({ type: "kv", key: "sitemap.xml", value: sitemapHit });
  }

  send({ type: "section", text: "AlienVault OTX — threat-intel pulses" });
  const otx = await pOtxGen;
  const pulseCount = otx?.pulse_info?.count ?? 0;
  if (pulseCount && otx?.pulse_info?.pulses?.length) {
    send({ type: "kv", key: "Pulses", value: String(pulseCount) });
    for (const p of otx.pulse_info.pulses.slice(0, 10)) {
      send({
        type: "line",
        text: `  • ${(p.created || "").slice(0, 10)}  ${p.name}  [tags: ${p.tags.join(",")}]`,
        hit: true,
      });
    }
  } else {
    send({ type: "line", text: "  (no OTX threat reports for this domain)" });
  }
  send({ type: "line", text: `  Browse: https://otx.alienvault.com/indicator/domain/${domain}` });

  send({ type: "section", text: "Manual deep-search pointers (paid / registration-gated)" });
  for (const ln of [
    `  IntelX (leaks/dark web) : https://intelx.io/?s=${domain}`,
    `  HIBP domain breaches    : https://haveibeenpwned.com/DomainSearch`,
    `  DeHashed                : https://dehashed.com/search?query=${domain}`,
    `  LeakCheck               : https://leakcheck.io/?query=${domain}`,
    `  Pulsedive               : https://pulsedive.com/indicator/?ioc=${domain}`,
  ]) send({ type: "line", text: ln });

  // Hoisted bulk DNS resolution. Used by the CDN/origin section below AND by
  // the AbuseIPDB phase further down — running it once saves a 30-wide DoH
  // burst.
  const bulkResolvedSubs = allSubs.length
    ? await resolveBulkA(allSubs, 30)
    : new Map<string, string[]>();
  const bulkResolvedMx = mxParsed.length
    ? await resolveBulkA(mxParsed.map((m) => m.host), 10)
    : new Map<string, string[]>();

  // ---------- Phase 9: ASN / network ----------
  send({ type: "phase", id: "asn", title: "ASN / Network" });
  send({ type: "section", text: "ASN / network ownership for resolved IPs" });
  const apexIps = dns.a.map((a) => a.data).filter((d) => /^\d+\.\d+\.\d+\.\d+$/.test(d));

  // Track apex CDN matches so the next section can highlight origin IP
  // candidates (Crimeflare-style).
  const apexCdnMatches: { ip: string; provider: string; via: "cidr" | "rdap" }[] = [];

  if (!apexIps.length) {
    send({ type: "line", text: "  (no IPs resolved)" });
  } else {
    // Look up every apex IP in parallel — RDAP is slow, so serialising costs us
    // ~2s per IP we don't need to spend.
    const lookups = await Promise.all(
      apexIps.map((ip) =>
        Promise.all([lookupIp(ip), lookupAsn(ip)]).then(([ipInfo, asnInfo]) => ({
          ip, ipInfo, asnInfo,
        }))
      )
    );
    for (const { ip, ipInfo, asnInfo } of lookups) {
      send({ type: "line", text: `  --- ${ip} ---` });
      if (ipInfo?.netname) send({ type: "line", text: `    netname: ${ipInfo.netname}` });
      if (ipInfo?.org) send({ type: "line", text: `    org    : ${ipInfo.org}` });
      if (ipInfo?.country) send({ type: "line", text: `    country: ${ipInfo.country}` });
      if (ipInfo?.cidr) send({ type: "line", text: `    cidr   : ${ipInfo.cidr}` });
      if (asnInfo) send({ type: "line", text: `    AS${asnInfo.asn} ${asnInfo.name} — ${asnInfo.description}` });

      const orgText = [ipInfo?.netname, ipInfo?.org, asnInfo?.name, asnInfo?.description]
        .filter(Boolean).join(" ");
      const m = classifyIp(ip, orgText);
      if (m) {
        send({
          type: "line",
          text: `    🛡  ${m.provider}${m.via === "cidr" ? " (CIDR match)" : " (RDAP org match)"}`,
          hit: true,
        });
        apexCdnMatches.push(m);
      }
    }
  }

  // ---------- CDN / WAF summary + origin IP discovery ----------
  send({ type: "section", text: "CDN / WAF detection (passive)" });
  if (apexCdnMatches.length === 0) {
    send({ type: "line", text: "  (apex IPs do not match any known CDN/WAF range — origin is likely direct)" });
  } else {
    const providers = [...new Set(apexCdnMatches.map((m) => m.provider))];
    emitHitFound(send, `apex is behind ${providers.join(", ")}`);
    for (const p of providers) send({ type: "kv", key: "Provider", value: p });

    // Crimeflare-style origin candidate hunt: when the apex sits behind a
    // pure proxy (Cloudflare, Fastly, Akamai…), enumerate every IP we found
    // via subdomain enumeration + MX hosts, then surface the ones that
    // DON'T live in CDN ranges. Those are leak candidates — typically dev/
    // staging/ftp/mail hosts that were never proxied.
    const isBehindProxy = providers.some(isProxyProvider);
    if (isBehindProxy) {
      send({ type: "section", text: "Potential origin IPs (subdomains/MX not behind CDN)" });

      // ip -> set of hostnames that resolve to it (uses hoisted bulk resolves)
      const ipToHosts = new Map<string, Set<string>>();
      for (const [host, ips] of bulkResolvedSubs) {
        for (const ip of ips) {
          if (!ipToHosts.has(ip)) ipToHosts.set(ip, new Set());
          ipToHosts.get(ip)!.add(host);
        }
      }
      for (const [host, ips] of bulkResolvedMx) {
        for (const ip of ips) {
          if (!ipToHosts.has(ip)) ipToHosts.set(ip, new Set());
          ipToHosts.get(ip)!.add(`MX:${host}`);
        }
      }
      // Historical VT resolutions — these are often pre-CDN IPs and are
      // some of the best origin-IP candidates Crimeflare-style hunts surface.
      if (vtKey) {
        for (const r of await pVtResolutions) {
          if (!ipToHosts.has(r.ip)) ipToHosts.set(r.ip, new Set());
          ipToHosts.get(r.ip)!.add(`VT-historical (${r.date || "?"}${r.host ? ` ${r.host}` : ""})`);
        }
      }
      // ThreatMiner passive DNS — same intent: historical IPs that aren't
      // necessarily fronted by the current CDN. Often complements VT.
      for (const r of tmPdns) {
        if (!ipToHosts.has(r.ip)) ipToHosts.set(r.ip, new Set());
        ipToHosts.get(r.ip)!.add(`TM-historical (${r.lastSeen || "?"}${r.host ? ` ${r.host}` : ""})`);
      }

      const apexIpSet = new Set(apexIps);
      // Don't re-classify every IP via RDAP (would burn the budget). CIDR
      // match alone is enough to rule out CDN-owned IPs here — false
      // positives just appear in the list with a "(via subdomain X)" tag.
      const candidates: { ip: string; hosts: string[] }[] = [];
      for (const [ip, hosts] of ipToHosts) {
        if (apexIpSet.has(ip)) continue;            // same as apex, not a leak
        if (classifyIp(ip)) continue;               // still inside a CDN range
        candidates.push({ ip, hosts: [...hosts].sort() });
      }
      candidates.sort((a, b) => a.ip.localeCompare(b.ip));

      if (candidates.length === 0) {
        send({ type: "line", text: "  (no non-CDN IPs found across subdomains/MX — origin appears fully shielded)" });
      } else {
        emitHitFound(send, `${candidates.length} non-CDN IP(s) reachable via subdomains/MX (likely origin candidates)`);
        const lines = candidates.map(
          (c) => `${c.ip}  ←  ${c.hosts.slice(0, 4).join(", ")}${c.hosts.length > 4 ? ` (+${c.hosts.length - 4} more)` : ""}`
        );
        send({ type: "list", items: lines, hits: lines });
        send({
          type: "line",
          text: "  ⚠ Origin IPs leak the WAF — verifying the box actually serves the same content is a follow-up step.",
        });
      }
    }
  }
  if (aborted()) return;

  // ---------- Phase 10: Bulk DNS resolve + AbuseIPDB ----------
  send({ type: "phase", id: "abuseipdb", title: "Bulk Resolve & AbuseIPDB" });
  send({ type: "section", text: "Bulk DNS resolution of all subdomains (DoH)" });
  const allIps = new Set<string>(apexIps);
  for (const ips of bulkResolvedSubs.values()) for (const ip of ips) allIps.add(ip);
  for (const ips of bulkResolvedMx.values()) for (const ip of ips) allIps.add(ip);
  const allIpsArr = [...allIps].sort();
  send({ type: "kv", key: "Unique IPv4", value: String(allIpsArr.length) });

  send({ type: "section", text: "AbuseIPDB cross-reference (HITS = nonzero)" });
  if (!abuseIpKey) {
    send({
      type: "phase-skipped",
      phase: "AbuseIPDB",
      reason: "No AbuseIPDB key — add one in Settings or set ABUSEIPDB_KEY.",
    });
  } else if (!allIpsArr.length) {
    send({ type: "line", text: "  (no IPs to check)" });
  } else {
    send({
      type: "line",
      text: "  IP                ABUSE   REPORTS COUNTRY ISP                                      LAST_REPORTED",
    });
    let cursor = 0;
    const concurrency = 10;
    const workers = Array.from({ length: Math.min(concurrency, allIpsArr.length) }, async () => {
      while (true) {
        const i = cursor++;
        if (i >= allIpsArr.length) return;
        const row = await abuseIpdb(allIpsArr[i], abuseIpKey);
        if (!row) continue;
        const line = `  ${row.ip.padEnd(17)} ${String(row.score).padEnd(7)} ${String(row.reports).padEnd(9)} ${row.country.padEnd(8)} ${row.isp.padEnd(40)} ${row.lastReported}`;
        send({ type: "line", text: line, hit: row.score > 0 || row.reports > 0 });
      }
    });
    await Promise.all(workers);
  }

  // ---------- Shodan InternetDB cross-reference (open ports / CPEs / CVEs) -
  // Free, no key. Returns per-IP exposure data Shodan already collected.
  // Falls back to nothing for IPs Shodan hasn't crawled.
  send({ type: "section", text: "Shodan InternetDB — open ports, CPEs, CVEs (per IP)" });
  if (!allIpsArr.length) {
    send({ type: "line", text: "  (no IPs to check)" });
  } else {
    const reverseHostnames = new Map<string, string[]>(); // ip -> hostnames (used by Pivot)
    const cvesSeen = new Set<string>();
    let anyHit = false;
    let cursor = 0;
    const workers = Array.from({ length: Math.min(8, allIpsArr.length) }, async () => {
      while (true) {
        const i = cursor++;
        if (i >= allIpsArr.length) return;
        const entry = await shodanInternetDb(allIpsArr[i]).catch(() => null);
        if (!entry) continue;
        if (entry.hostnames.length) reverseHostnames.set(entry.ip, entry.hostnames);
        if (entry.vulns.length) {
          for (const v of entry.vulns) cvesSeen.add(v);
          anyHit = true;
          emitHitFound(send, `${entry.ip}: ${entry.vulns.length} CVE(s) — ${entry.vulns.slice(0, 6).join(", ")}${entry.vulns.length > 6 ? "…" : ""}`);
        }
        const ports = entry.ports.length ? entry.ports.join(", ") : "(none)";
        const cpes = entry.cpes.length ? entry.cpes.slice(0, 3).join(" · ") : "";
        const hosts = entry.hostnames.length ? entry.hostnames.slice(0, 4).join(", ") : "";
        const tail = [cpes && `cpes: ${cpes}`, hosts && `rdns: ${hosts}`].filter(Boolean).join("  |  ");
        send({
          type: "line",
          text: `  ${entry.ip.padEnd(17)} ports: ${ports}${tail ? "  |  " + tail : ""}`,
          hit: entry.vulns.length > 0,
        });
      }
    });
    await Promise.all(workers);
    if (cvesSeen.size > 0) {
      send({ type: "kv", key: "Unique CVEs across all IPs", value: String(cvesSeen.size) });
    }
    if (!anyHit && cvesSeen.size === 0) {
      send({ type: "line", text: "  (no Shodan exposures found across these IPs)" });
    }
    // Stash for the Pivot phase below — used as a "same-IP neighbours" source.
    (globalThis as unknown as { __reverseHostnames?: Map<string, string[]> }).__reverseHostnames =
      reverseHostnames;
  }

  // ---------- Phase 11: Domain Pivot (other domains owned by same entity) --
  send({ type: "phase", id: "pivot", title: "Domain Pivot" });
  send({
    type: "line",
    text:
      "  Goal: starting from this domain, find OTHER domains likely owned by the same person / company. " +
      "All passive — crt.sh by registrant org, shared nameservers/MX in the resolved data, " +
      "and reverse-DNS hostnames Shodan already collected.",
  });

  // -- (a) crt.sh org-name lookup -------------------------------------------
  send({ type: "section", text: "Sibling domains via crt.sh organisation search" });
  if (!registrantOrg) {
    send({ type: "line", text: "  (RDAP did not return a registrant organisation — try a WHOIS-via-key source like WhoisXMLAPI for redacted records)" });
  } else {
    send({ type: "kv", key: "Querying org", value: registrantOrg });
    const siblings = await crtshByOrg(registrantOrg, domain).catch(() => []);
    if (siblings.length) {
      emitHitFound(send, `${siblings.length} domain(s) with certificates issued under "${registrantOrg}"`);
      send({ type: "list", title: "crt.sh org match", items: siblings.slice(0, 50), hits: siblings.slice(0, 50) });
      if (siblings.length > 50) {
        send({ type: "line", text: `  … and ${siblings.length - 50} more — see https://crt.sh/?q=${encodeURIComponent(`o:"${registrantOrg}"`)}` });
      }
    } else {
      send({ type: "line", text: "  (no other domains found in crt.sh under this org)" });
    }
  }

  // -- (b) Shared nameserver / MX pivot -------------------------------------
  // Public-facing nameservers and MX hosts often live under the registrant's
  // own domain — when they do, we surface that apex as a strong pivot candidate.
  send({ type: "section", text: "Shared-infrastructure pivots (NS / MX apex)" });
  const infraApexes = new Set<string>();
  for (const ns of nsList) {
    const apex = ns.split(".").slice(-2).join(".").toLowerCase();
    if (apex && apex !== domain && !apex.endsWith(`.${domain}`)) infraApexes.add(apex);
  }
  for (const mx of mxParsed) {
    const apex = mx.host.split(".").slice(-2).join(".").toLowerCase();
    if (apex && apex !== domain && !apex.endsWith(`.${domain}`)) infraApexes.add(apex);
  }
  if (infraApexes.size) {
    const lines = [...infraApexes].sort().map((a) => `${a}  (from NS or MX records)`);
    send({ type: "list", items: lines, hits: lines });
    send({ type: "line", text: "  ⚠ These may be third-party providers (Cloudflare, Google, etc.) rather than sibling brands — verify before treating as a pivot." });
  } else {
    send({ type: "line", text: "  (NS / MX are all third-party or under the target apex — no infra pivot)" });
  }

  // -- (c) Reverse-DNS neighbours (other domains sharing apex IPs) ----------
  send({ type: "section", text: "Reverse-DNS neighbours (other domains on the same apex IPs)" });
  const rev = (globalThis as unknown as { __reverseHostnames?: Map<string, string[]> }).__reverseHostnames;
  const neighbours = new Set<string>();
  if (rev) {
    for (const ip of apexIps) {
      const hostnames = rev.get(ip) ?? [];
      for (const h of hostnames) {
        const lh = h.toLowerCase();
        if (lh === domain || lh.endsWith(`.${domain}`)) continue;
        neighbours.add(lh);
      }
    }
  }
  if (neighbours.size) {
    const lines = [...neighbours].sort();
    emitHitFound(send, `${neighbours.size} unrelated hostname(s) sharing the apex IP(s)`);
    send({ type: "list", items: lines, hits: lines });
    send({ type: "line", text: "  ⚠ Shared-IP neighbours are weak evidence — common on cloud / shared hosting." });
  } else {
    send({ type: "line", text: "  (no foreign hostnames seen on Shodan's reverse DNS for apex IPs)" });
  }

  // -- (d) Manual deep pivots ------------------------------------------------
  send({ type: "section", text: "Manual reverse-WHOIS / pivot tools" });
  for (const ln of [
    `  ViewDNS reverse whois : https://viewdns.info/reversewhois/?q=${encodeURIComponent(registrantOrg ?? domain)}`,
    `  WhoisXMLAPI           : https://reverse-whois.whoisxmlapi.com/api  (free 500/mo with signup)`,
    `  SecurityTrails         : https://securitytrails.com/list/keyword/${encodeURIComponent(domain)}`,
    `  DNSlytics             : https://dnslytics.com/reverse-whois/${encodeURIComponent(domain)}`,
    `  Shodan free search    : https://www.shodan.io/search?query=ssl:%22${encodeURIComponent(domain)}%22`,
  ]) send({ type: "line", text: ln });
  if (aborted()) return;

  // ---------- Summary ----------
  send({ type: "phase", id: "summary", title: "Summary" });
  send({
    type: "summary",
    data: {
      Domain: domain,
      "Subdomains (crt.sh)": crtshList.length,
      "Subdomains (HackerTarget)": htList.length,
      "Subdomains (OTX pDNS)": otxPdns.length,
      "Subdomains (TOTAL uniq)": allSubs.length,
      "Unique IPs (all subs)": allIpsArr.length,
      "Wayback URLs": wayback.length,
    },
  });
  send({ type: "done" });
}
