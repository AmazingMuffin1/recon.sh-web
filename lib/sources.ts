import { fetchJson, fetchText, fetchWithTimeout } from "./http";
import {
  EMAIL_HARVEST_MAX_CHARS,
  emailRegexFor,
  ONION_RE,
} from "./patterns";

// ---------- Helpers ----------

/**
 * A host `h` belongs to `domain` only when it IS `domain` or ends with `.domain`.
 * Plain `endsWith(domain)` is dangerous because `evilexample.com` also passes.
 */
function isSubOf(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

function normalizeHost(s: string): string {
  return s.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
}

// ---------- Subdomains (replacing subfinder/assetfinder) ----------

interface CrtshRow { name_value: string }

export async function crtsh(domain: string): Promise<string[]> {
  const rows = await fetchJson<CrtshRow[]>(
    `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
    { timeoutMs: 25_000 }
  );
  if (!rows) return [];
  const out = new Set<string>();
  for (const r of rows) {
    for (const name of r.name_value.split(/\n/)) {
      const host = normalizeHost(name);
      // Only keep hosts that actually live under the queried apex.
      if (host && isSubOf(host, domain) && /^[a-z0-9.-]+$/.test(host)) {
        out.add(host);
      }
    }
  }
  return [...out].sort();
}

export async function hackerTarget(domain: string): Promise<string[]> {
  const txt = await fetchText(
    `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
    { timeoutMs: 12_000 }
  );
  if (!txt || /API count exceeded|error/i.test(txt)) return [];
  const out = new Set<string>();
  for (const line of txt.split(/\r?\n/)) {
    const host = normalizeHost(line.split(",")[0] ?? "");
    if (host && isSubOf(host, domain)) out.add(host);
  }
  return [...out].sort();
}

interface OtxPassive {
  passive_dns?: { hostname: string }[];
}

/**
 * OTX rate-limits anonymous callers very aggressively (often silently — you
 * get HTTP 200 with an empty body). A free API key from
 * https://otx.alienvault.com/api lifts the limit dramatically. We accept a
 * caller-supplied key first (BYO via the UI) and fall back to OTX_API_KEY
 * from the environment; the X-OTX-API-KEY header is what they expect.
 */
function otxHeaders(otxKey?: string): Record<string, string> {
  const key = otxKey?.trim() || process.env.OTX_API_KEY?.trim();
  const h: Record<string, string> = {
    Accept: "application/json",
    "User-Agent":
      "Mozilla/5.0 (compatible; recon-web/1.0; +https://otx.alienvault.com)",
  };
  if (key) h["X-OTX-API-KEY"] = key;
  return h;
}

export async function otxPassiveDns(domain: string, otxKey?: string): Promise<string[]> {
  const data = await fetchJson<OtxPassive>(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
    { timeoutMs: 12_000, headers: otxHeaders(otxKey) }
  );
  const out = new Set<string>();
  for (const r of data?.passive_dns ?? []) {
    const h = normalizeHost(r.hostname ?? "");
    if (h && isSubOf(h, domain)) out.add(h);
  }
  return [...out].sort();
}

// ---------- ThreatMiner (free, no auth — 10 req/min per IP) ----------
//
// ThreatMiner has been historically flaky (outages, intermittent TLS issues),
// so we treat every call as best-effort: a hung/erroring endpoint returns []
// and the rest of the scan continues. The two resource types we use:
//   rt=5 → subdomains
//   rt=2 → passive DNS (host ↔ ip resolutions)
// Both are public and require no key.

interface TmDomainResp<T> {
  status_code?: string;
  status_message?: string;
  results?: T[];
}

export async function threatMinerSubdomains(domain: string): Promise<string[]> {
  const data = await fetchJson<TmDomainResp<string>>(
    `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`,
    { timeoutMs: 10_000 }
  );
  if (!data || data.status_code !== "200") return [];
  const out = new Set<string>();
  for (const name of data.results ?? []) {
    const h = normalizeHost(name ?? "");
    if (h && isSubOf(h, domain)) out.add(h);
  }
  return [...out].sort();
}

interface TmPassiveDnsRow {
  ip?: string;
  domain?: string;
  last_seen?: string;
  first_seen?: string;
}

export interface TmPassiveDnsHit { ip: string; host: string; lastSeen: string }

export async function threatMinerPassiveDns(domain: string): Promise<TmPassiveDnsHit[]> {
  const data = await fetchJson<TmDomainResp<TmPassiveDnsRow>>(
    `https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=2`,
    { timeoutMs: 10_000 }
  );
  if (!data || data.status_code !== "200") return [];
  const out: TmPassiveDnsHit[] = [];
  for (const r of data.results ?? []) {
    if (!r.ip || !/^\d+\.\d+\.\d+\.\d+$/.test(r.ip)) continue;
    const host = normalizeHost(r.domain ?? "");
    if (host && !isSubOf(host, domain)) continue;
    out.push({ ip: r.ip, host, lastSeen: r.last_seen ?? "" });
  }
  return out;
}

// ---------- Wayback Machine ----------

export async function waybackUrls(domain: string, limit = 10_000): Promise<string[]> {
  // matchType=domain returns snapshots for the apex AND all subdomains.
  // The old `*.domain/*` wildcard form is unreliable and frequently returns nothing.
  const url =
    `https://web.archive.org/cdx/search/cdx` +
    `?url=${encodeURIComponent(domain)}` +
    `&matchType=domain` +
    `&output=json&fl=original&collapse=urlkey&limit=${limit}`;
  const data = await fetchJson<string[][]>(url, {
    timeoutMs: 30_000,
    headers: {
      // Wayback occasionally 403s anonymous JSON-Accept clients; a browsery UA fixes it.
      "User-Agent":
        "Mozilla/5.0 (compatible; recon-web/1.0; +https://web.archive.org)",
      Accept: "application/json,*/*",
    },
  });
  if (!data || data.length < 2) return [];
  // First row is the column header. Drop URLs that don't actually belong to
  // the requested domain — wayback occasionally returns spurious rows.
  const out: string[] = [];
  for (let i = 1; i < data.length; i++) {
    const u = data[i]?.[0];
    if (!u) continue;
    const m = u.match(/^https?:\/\/([^/?#]+)/i);
    if (!m) continue;
    const host = normalizeHost(m[1].split(":")[0]);
    if (isSubOf(host, domain)) out.push(u);
  }
  return out;
}

// ---------- Threat-intel feeds ----------

interface OtxGeneral {
  pulse_info?: { count?: number; pulses?: { created: string; name: string; tags: string[] }[] };
}
export async function otxGeneral(domain: string, otxKey?: string): Promise<OtxGeneral | null> {
  return fetchJson<OtxGeneral>(
    `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`,
    { timeoutMs: 12_000, headers: otxHeaders(otxKey) }
  );
}

export interface UrlscanResult {
  task: { time: string; url?: string };
  page: {
    url: string;
    domain?: string;
    server?: string;
    ip?: string;
    asn?: string;
    asnname?: string;
    country?: string;
    title?: string;
    mimeType?: string;
    tlsValidFrom?: string;
    tlsValidDays?: number;
    tlsIssuer?: string;
  };
  verdicts?: { overall?: { malicious?: boolean; score?: number } };
}
export interface UrlscanResp { total?: number; results?: UrlscanResult[] }

export async function urlscan(domain: string): Promise<UrlscanResp | null> {
  return fetchJson<UrlscanResp>(
    `https://urlscan.io/api/v1/search/?q=domain%3A${encodeURIComponent(domain)}&size=15`,
    { timeoutMs: 12_000 }
  );
}

// ---------- Dark-web indices ----------

export interface OnionHit {
  url: string;
  title?: string;
  snippet?: string;
  date?: string;
  source: "ahmia" | "onionland";
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
}

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

/**
 * Headers used for direct hits against dark-web-adjacent indices (Ahmia,
 * OnionLand). Privacy posture for these calls:
 *
 *   • Requests originate from the server, never from the user's IP.
 *   • No cookies, no auth, no Referer — fetch in Node never adds Referer
 *     for cross-origin requests, and we don't set one.
 *   • No `recon-web` / `recon-osint` string in any header.
 *   • Generic Chrome User-Agent, common Accept-Language, no exotic Sec-Fetch-*
 *     combination (a half-spoofed browser fingerprint is more identifiable
 *     than a plain HTTP client masquerading as Chrome).
 *
 * What we cannot mask from a determined operator:
 *   • Server IP (use a Tor-routed deployment if that matters).
 *   • TLS JA3/JA4 fingerprint (Node's TLS stack is identifiable).
 *
 * The goal here is to ensure the *content* of the request — headers,
 * cookies, body — doesn't tie this scan back to a specific tool or user.
 */
function darkWebHeaders(): Record<string, string> {
  return {
    "User-Agent": BROWSER_UA,
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
  };
}

/**
 * Ahmia exposes the same search as an RSS feed via `&format=rss`. RSS is
 * structured XML, far more stable to parse than the search-page HTML (which
 * we used to scrape and which broke whenever Ahmia tweaked its markup). Each
 * `<item>` already gives us a clean title, the onion `<link>`, a description
 * snippet, and an updated date.
 */
export async function ahmiaOnionHits(domain: string): Promise<OnionHit[]> {
  const xml = await fetchText(
    `https://ahmia.fi/search/?q=${encodeURIComponent(domain)}&format=rss`,
    {
      timeoutMs: 15_000,
      headers: {
        ...darkWebHeaders(),
        Accept: "application/rss+xml, application/xml;q=0.9, text/xml;q=0.8",
      },
    }
  );
  if (!xml) return [];

  const items: OnionHit[] = [];
  const seen = new Set<string>();
  const itemRe = /<item\b[\s\S]*?<\/item>/gi;
  const fieldRe = (name: string) =>
    new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`, "i");

  let m: RegExpExecArray | null;
  while ((m = itemRe.exec(xml)) !== null) {
    const block = m[0];
    const linkM  = block.match(fieldRe("link"));
    const titleM = block.match(fieldRe("title"));
    const descM  = block.match(fieldRe("description"));
    const dateM  = block.match(fieldRe("updated")) ?? block.match(fieldRe("pubDate"));

    const rawLink = linkM ? decodeXmlEntities(linkM[1].trim()) : "";
    const onion = rawLink.match(ONION_RE)?.[0]?.toLowerCase();
    if (!onion || seen.has(onion)) continue;
    seen.add(onion);

    const title   = titleM ? decodeXmlEntities(titleM[1]).replace(/\s+/g, " ").trim() : undefined;
    const snippet = descM  ? decodeXmlEntities(descM[1]).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 240) : undefined;
    const date    = dateM  ? decodeXmlEntities(dateM[1]).trim().slice(0, 10) : undefined;

    items.push({ url: rawLink, title, snippet, date, source: "ahmia" });
  }
  return items;
}

/**
 * OnionLand Search (`onionlandsearchengine.com`) — a second clearnet portal
 * into .onion indices. Results often complement Ahmia (different crawler
 * scope). HTML scrape, defensive parser.
 */
export async function onionLandSearch(domain: string): Promise<OnionHit[]> {
  const html = await fetchText(
    `https://onionlandsearchengine.com/search?q=${encodeURIComponent(domain)}`,
    {
      timeoutMs: 15_000,
      headers: darkWebHeaders(),
    }
  );
  if (!html) return [];

  const out: OnionHit[] = [];
  const seen = new Set<string>();
  const lc = domain.toLowerCase();

  // Each result is roughly: <h5><a href="...">Title</a></h5><p>snippet</p>
  // Tolerate variations: pull any <a> whose href contains a .onion, with the
  // surrounding text serving as title/snippet context.
  const linkRe = /<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  let scanned = 0;
  while ((m = linkRe.exec(html)) !== null && out.length < 40 && scanned++ < 400) {
    const href = m[1];
    const onion = href.match(ONION_RE)?.[0]?.toLowerCase();
    if (!onion || seen.has(onion)) continue;
    // OnionLand wraps real onion URLs in /tor/?url=… redirects. Pull the
    // real link out so the report sends users to the actual onion.
    let url = href;
    const inner = href.match(/[?&]url=([^&]+)/);
    if (inner) { try { url = decodeURIComponent(inner[1]); } catch { /* keep href */ } }

    const title = m[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    // Require that the surrounding 240-char window contains the domain — drops
    // the navigation links / footer onion mentions.
    const start = Math.max(0, m.index - 120);
    const window = html.slice(start, m.index + m[0].length + 120)
      .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").toLowerCase();
    if (!window.includes(lc)) continue;

    seen.add(onion);
    out.push({ url, title: title || undefined, snippet: window.slice(0, 240), source: "onionland" });
  }
  return out;
}

/**
 * Run Ahmia and OnionLand in parallel and merge by canonical onion address.
 * Each merged hit retains its provenance via the `source` field.
 */
export async function combinedOnionHits(domain: string): Promise<OnionHit[]> {
  const [a, b] = await Promise.all([
    ahmiaOnionHits(domain).catch(() => []),
    onionLandSearch(domain).catch(() => []),
  ]);
  const byOnion = new Map<string, OnionHit>();
  for (const h of [...a, ...b]) {
    const k = h.url.match(ONION_RE)?.[0]?.toLowerCase() ?? h.url;
    if (!byOnion.has(k)) byOnion.set(k, h);
  }
  return [...byOnion.values()];
}

/**
 * Back-compat: bare list of onion URLs.
 */
export async function ahmiaOnions(domain: string): Promise<string[]> {
  const hits = await ahmiaOnionHits(domain);
  return hits.map((h) => h.url);
}

// ---------- VirusTotal (v3 — needs free API key) ----------

const VT_BASE = "https://www.virustotal.com/api/v3";

function vtHeaders(key: string) {
  return {
    "x-apikey": key,
    Accept: "application/json",
    "User-Agent": "recon-web/1.0",
  };
}

export interface VtAnalysisStats {
  harmless?: number;
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  timeout?: number;
}

export interface VtDomainReport {
  data?: {
    id?: string;
    attributes?: {
      reputation?: number;
      categories?: Record<string, string>;
      last_analysis_stats?: VtAnalysisStats;
      total_votes?: { harmless?: number; malicious?: number };
      tags?: string[];
      whois?: string;
      last_dns_records?: { type: string; value: string; ttl: number }[];
      last_https_certificate_date?: number;
      creation_date?: number;
      last_modification_date?: number;
    };
  };
}

export async function vtDomain(domain: string, key: string): Promise<VtDomainReport | null> {
  return fetchJson<VtDomainReport>(
    `${VT_BASE}/domains/${encodeURIComponent(domain)}`,
    { headers: vtHeaders(key), timeoutMs: 15_000 }
  );
}

interface VtRelationshipPage<T> {
  data?: T[];
  meta?: { cursor?: string; count?: number };
}

interface VtSubdomainItem {
  id?: string;
  attributes?: { last_analysis_stats?: VtAnalysisStats };
}

/**
 * Fetch every subdomain VT knows about for `domain`, paginating through the
 * cursor up to `maxPages` * `limit` items. Most domains return everything in
 * one or two pages; the cap is there so we never burn the per-minute quota on
 * a single scan.
 */
export async function vtSubdomains(
  domain: string,
  key: string,
  limit = 40,
  maxPages = 3
): Promise<{ name: string; malicious: number; suspicious: number }[]> {
  const out: { name: string; malicious: number; suspicious: number }[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const url = `${VT_BASE}/domains/${encodeURIComponent(domain)}/subdomains?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const j = await fetchJson<VtRelationshipPage<VtSubdomainItem>>(url, {
      headers: vtHeaders(key), timeoutMs: 15_000,
    });
    if (!j?.data?.length) break;
    for (const row of j.data) {
      if (!row.id) continue;
      const s = row.attributes?.last_analysis_stats ?? {};
      out.push({
        name: row.id.toLowerCase(),
        malicious: s.malicious ?? 0,
        suspicious: s.suspicious ?? 0,
      });
    }
    cursor = j.meta?.cursor;
    if (!cursor) break;
  }
  return out;
}

interface VtResolutionItem {
  id?: string;
  attributes?: {
    ip_address?: string;
    host_name?: string;
    date?: number;
  };
}

export interface VtResolution { ip: string; host: string; date: string }

export async function vtResolutions(
  domain: string,
  key: string,
  limit = 40
): Promise<VtResolution[]> {
  const j = await fetchJson<VtRelationshipPage<VtResolutionItem>>(
    `${VT_BASE}/domains/${encodeURIComponent(domain)}/resolutions?limit=${limit}`,
    { headers: vtHeaders(key), timeoutMs: 15_000 }
  );
  const out: VtResolution[] = [];
  for (const r of j?.data ?? []) {
    const ip = r.attributes?.ip_address;
    if (!ip) continue;
    const date = r.attributes?.date
      ? new Date(r.attributes.date * 1000).toISOString().slice(0, 10)
      : "";
    out.push({ ip, host: r.attributes?.host_name ?? "", date });
  }
  return out;
}

interface VtUrlItem {
  id?: string;
  attributes?: {
    url?: string;
    last_analysis_stats?: VtAnalysisStats;
    last_analysis_date?: number;
    times_submitted?: number;
  };
}

export interface VtUrlHit {
  url: string;
  malicious: number;
  suspicious: number;
  lastAnalyzed: string;
}

/**
 * URLs that VT has analyzed and which live under the queried domain.
 * Equivalent to a VT "URL scan archive" — we surface only the rows that
 * triggered at least one engine, plus the most-recent N regardless.
 */
export async function vtDomainUrls(
  domain: string,
  key: string,
  limit = 30
): Promise<VtUrlHit[]> {
  const j = await fetchJson<VtRelationshipPage<VtUrlItem>>(
    `${VT_BASE}/domains/${encodeURIComponent(domain)}/urls?limit=${limit}`,
    { headers: vtHeaders(key), timeoutMs: 15_000 }
  );
  const out: VtUrlHit[] = [];
  for (const r of j?.data ?? []) {
    const url = r.attributes?.url;
    if (!url) continue;
    const s = r.attributes?.last_analysis_stats ?? {};
    out.push({
      url,
      malicious: s.malicious ?? 0,
      suspicious: s.suspicious ?? 0,
      lastAnalyzed: r.attributes?.last_analysis_date
        ? new Date(r.attributes.last_analysis_date * 1000).toISOString().slice(0, 10)
        : "",
    });
  }
  return out;
}

// ---------- Shodan InternetDB (free, no key) ----------
//
// `internetdb.shodan.io/{IP}` is Shodan's free public lookup — open ports,
// CPEs, CVE list, and reverse-DNS hostnames for any IPv4 address. No auth,
// no rate-limit advertised beyond reasonable use. Major upgrade vs. AbuseIPDB
// alone because it surfaces actual exposure data.

export interface InternetDbEntry {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  vulns: string[];
  tags: string[];
}

interface InternetDbRaw {
  ip?: string;
  ports?: number[];
  hostnames?: string[];
  cpes?: string[];
  vulns?: string[];
  tags?: string[];
}

export async function shodanInternetDb(ip: string): Promise<InternetDbEntry | null> {
  const r = await fetchJson<InternetDbRaw>(
    `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
    { timeoutMs: 10_000 }
  );
  if (!r) return null;
  return {
    ip:        r.ip ?? ip,
    ports:     r.ports ?? [],
    hostnames: r.hostnames ?? [],
    cpes:      r.cpes ?? [],
    vulns:     r.vulns ?? [],
    tags:      r.tags ?? [],
  };
}

// ---------- Domain pivot (crt.sh by organization) ----------

interface CrtshOrgRow {
  name_value?: string;
  common_name?: string;
  issuer_name?: string;
}

/**
 * Search crt.sh for certificates issued under an Organization name (e.g.
 * pulled from RDAP `O=…`). Returns the set of unique apex-style names found
 * in the matching certs MINUS the queried domain and its subdomains, so the
 * caller can use the rest as a "sibling domains likely owned by the same
 * legal entity" list.
 */
export async function crtshByOrg(orgName: string, excludeDomain: string): Promise<string[]> {
  // crt.sh accepts org name in `o:` query syntax. Wrap in quotes so partial
  // matches don't bleed into unrelated orgs.
  const rows = await fetchJson<CrtshOrgRow[]>(
    `https://crt.sh/?q=${encodeURIComponent(`o:"${orgName}"`)}&output=json`,
    { timeoutMs: 25_000 }
  );
  if (!rows) return [];
  const apexes = new Set<string>();
  const ownDomain = excludeDomain.toLowerCase();
  for (const r of rows) {
    const all = (r.name_value ?? r.common_name ?? "").split(/\n+/);
    for (const raw of all) {
      const name = normalizeHost(raw);
      if (!name) continue;
      if (name === ownDomain || name.endsWith(`.${ownDomain}`)) continue;
      // Drop obvious wildcards and labels with no dot.
      if (!name.includes(".") || /[^a-z0-9.-]/.test(name)) continue;
      apexes.add(name);
    }
  }
  return [...apexes].sort();
}

// ---------- Skymem (free public email index, HTML scrape) ----------
//
// Last resort email source. Skymem indexes emails seen in web pages and
// exposes a search interface that returns `mailto:` links plus surrounding
// text. The site has had availability issues historically — we treat any
// failure as "source down" and continue.

export async function skymemEmails(domain: string): Promise<string[]> {
  const html = await fetchText(
    `https://www.skymem.info/srch?q=${encodeURIComponent(domain)}`,
    {
      timeoutMs: 12_000,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml",
      },
    }
  );
  if (!html) return [];
  const re = emailRegexFor(domain);
  const slice = html.length > EMAIL_HARVEST_MAX_CHARS
    ? html.slice(0, EMAIL_HARVEST_MAX_CHARS)
    : html;
  const out = new Set<string>();
  for (const m of slice.matchAll(re)) out.add(m[0].toLowerCase());
  return [...out].sort();
}

// ---------- AbuseIPDB ----------

interface AbuseResp {
  data?: {
    abuseConfidenceScore?: number;
    totalReports?: number;
    countryCode?: string;
    isp?: string;
    lastReportedAt?: string;
  };
}
export interface AbuseRow {
  ip: string; score: number; reports: number;
  country: string; isp: string; lastReported: string;
}
export async function abuseIpdb(ip: string, key: string): Promise<AbuseRow | null> {
  try {
    const r = await fetchWithTimeout(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        timeoutMs: 12_000,
        headers: { Key: key, Accept: "application/json" },
      }
    );
    if (!r.ok) return null;
    const j = (await r.json()) as AbuseResp;
    const d = j.data;
    if (!d) return null;
    return {
      ip,
      score: d.abuseConfidenceScore ?? 0,
      reports: d.totalReports ?? 0,
      country: d.countryCode ?? "?",
      isp: (d.isp ?? "?").slice(0, 38),
      lastReported: d.lastReportedAt ?? "never",
    };
  } catch {
    return null;
  }
}

// ---------- DuckDuckGo HTML scrape (replaces ddg_search.py) ----------

export interface DdgResult { title: string; url: string; snippet?: string }

/**
 * Internal DDG URL/ad-redirect prefixes we always drop — these aren't real
 * search hits, they're DDG navigation / sponsored slots.
 */
const DDG_NOISE = /^https?:\/\/(?:duckduckgo\.com|html\.duckduckgo\.com)/i;

function decodeDdgRedirect(url: string): string {
  // DDG wraps the real URL in /l/?uddg=<encoded>
  const inner = url.match(/[?&]uddg=([^&]+)/);
  if (!inner) return url;
  try { return decodeURIComponent(inner[1]); } catch { return url; }
}

function stripTags(s: string): string {
  return s.replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&#x27;/g, "'")
          .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/\s+/g, " ").trim();
}

/**
 * Scrape DDG HTML and return *cleaned, deduped* results. We:
 *   - decode the /l/?uddg= redirect to the real URL,
 *   - extract the snippet alongside the title,
 *   - dedupe by URL, then by (host + path) to drop near-dupes,
 *   - drop DDG's own navigation/ad/internal URLs.
 *
 * Optional `requireHost` enforces that each result actually lives on the
 * expected host — that's how we keep `site:github.com …` results out of the
 * Google/dorks phase and vice versa.
 */
export async function ddgSearch(
  query: string,
  max = 8,
  opts: { requireHost?: string; requireMentions?: string } = {}
): Promise<DdgResult[]> {
  const html = await fetchText(
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
    {
      timeoutMs: 12_000,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml",
      },
    }
  );
  if (!html) return [];

  // Each result lives inside a result block — pulling the block first lets us
  // grab title + snippet without crossing into the next entry.
  const out: DdgResult[] = [];
  const seenUrls = new Set<string>();
  const seenKeys = new Set<string>();

  const blockRe = /<div[^>]+class="[^"]*\bresult\b(?![^"]*result--ad)[^"]*"[^>]*>([\s\S]*?)<\/div>\s*<\/div>/gi;
  let m: RegExpExecArray | null;
  let scanned = 0;
  while ((m = blockRe.exec(html)) !== null) {
    if (scanned++ > 60) break;            // bound work even if regex over-matches
    if (out.length >= max) break;

    const block = m[1];
    const a = block.match(/<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!a) continue;

    const url = decodeDdgRedirect(a[1]);
    if (!url.startsWith("http") || DDG_NOISE.test(url)) continue;
    if (seenUrls.has(url)) continue;

    let host: string;
    try { host = new URL(url).host.toLowerCase(); } catch { continue; }
    if (opts.requireHost) {
      const need = opts.requireHost.toLowerCase();
      if (host !== need && !host.endsWith(`.${need}`)) continue;
    }

    const title = stripTags(a[2]);
    if (!title) continue;

    const sn = block.match(/<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/i);
    const snippet = sn ? stripTags(sn[1]) : undefined;

    if (opts.requireMentions) {
      const need = opts.requireMentions.toLowerCase();
      const hay = `${url} ${title} ${snippet ?? ""}`.toLowerCase();
      if (!hay.includes(need)) continue;
    }

    // Dedup near-dupes — many dorks return the same article on .com/.co.uk.
    let path: string;
    try { path = new URL(url).pathname; } catch { path = ""; }
    const key = `${host}${path}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);

    seenUrls.add(url);
    out.push({ title, url, snippet });
  }

  // Fallback: if the structured pass returned nothing, fall back to the old
  // anchor-only extractor so a CSS change on DDG doesn't break us silently.
  if (out.length === 0) {
    const re = /<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
    let n = 0;
    while ((m = re.exec(html)) && out.length < max && n++ < 60) {
      const url = decodeDdgRedirect(m[1]);
      if (!url.startsWith("http") || DDG_NOISE.test(url) || seenUrls.has(url)) continue;
      let host: string;
      try { host = new URL(url).host.toLowerCase(); } catch { continue; }
      if (opts.requireHost) {
        const need = opts.requireHost.toLowerCase();
        if (host !== need && !host.endsWith(`.${need}`)) continue;
      }
      const title = stripTags(m[2]);
      if (!title) continue;
      seenUrls.add(url);
      out.push({ title, url });
    }
  }

  return out;
}

// ---------- Bing fallback ----------

/**
 * Scrape Bing's HTML SERP. Bing's coverage of github.com / pastebin / cloud
 * buckets is generally better than DDG's, so we use this as a fallback when
 * DDG returns nothing. Bing also rate-limits aggressively but the failure
 * mode is the same (return []).
 */
export async function bingSearch(
  query: string,
  max = 8,
  opts: { requireHost?: string; requireMentions?: string } = {}
): Promise<DdgResult[]> {
  const html = await fetchText(
    `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=20`,
    {
      timeoutMs: 12_000,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
      },
    }
  );
  if (!html) return [];

  const out: DdgResult[] = [];
  const seenKeys = new Set<string>();
  const blockRe = /<li[^>]+class="[^"]*b_algo[^"]*"[^>]*>([\s\S]*?)<\/li>/gi;

  let m: RegExpExecArray | null;
  let scanned = 0;
  while ((m = blockRe.exec(html)) !== null) {
    if (scanned++ > 40) break;
    if (out.length >= max) break;

    const block = m[1];
    const link = block.match(/<h2[^>]*>\s*<a[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>/i);
    if (!link) continue;

    const url = link[1];
    if (!url.startsWith("http") || /^https?:\/\/(?:www\.)?bing\.com/i.test(url)) continue;

    let host: string;
    try { host = new URL(url).host.toLowerCase(); } catch { continue; }
    if (opts.requireHost) {
      const need = opts.requireHost.toLowerCase();
      if (host !== need && !host.endsWith(`.${need}`)) continue;
    }

    const title = stripTags(link[2]);
    if (!title) continue;

    // Snippet sits in a sibling div with class containing b_caption or b_lineclamp.
    const sn = block.match(/<p[^>]*class="[^"]*b_lineclamp[^"]*"[^>]*>([\s\S]*?)<\/p>/i)
            ?? block.match(/<div[^>]*class="[^"]*b_caption[^"]*"[^>]*>([\s\S]*?)<\/div>/i);
    const snippet = sn ? stripTags(sn[1]) : undefined;

    if (opts.requireMentions) {
      const need = opts.requireMentions.toLowerCase();
      const hay = `${url} ${title} ${snippet ?? ""}`.toLowerCase();
      if (!hay.includes(need)) continue;
    }

    let path: string;
    try { path = new URL(url).pathname; } catch { path = ""; }
    const key = `${host}${path}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);

    out.push({ title, url, snippet });
  }
  return out;
}

/**
 * Try DDG first; if it returns nothing, fall back to Bing. Each engine has
 * different blind spots — querying both raises the floor without burning
 * extra request budget when DDG already worked.
 */
export async function webSearch(
  query: string,
  max = 8,
  opts: { requireHost?: string; requireMentions?: string } = {}
): Promise<{ results: DdgResult[]; engine: "ddg" | "bing" | "none" }> {
  const ddg = await ddgSearch(query, max, opts).catch(() => []);
  if (ddg.length > 0) return { results: ddg, engine: "ddg" };
  const bing = await bingSearch(query, max, opts).catch(() => []);
  if (bing.length > 0) return { results: bing, engine: "bing" };
  return { results: [], engine: "none" };
}
