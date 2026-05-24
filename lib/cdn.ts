// Passive CDN / WAF / cloud-provider detection.
//
// Inspired by Crimeflare's approach: when an apex's A records live in known
// CDN ranges, the "real" origin IPs are hiding. The classic recon technique
// is to enumerate all the subdomains/MX hosts, resolve them, and treat any
// IP that *isn't* in a CDN range as an origin-IP candidate (often dev,
// staging, or mail boxes that were never proxied).
//
// We deliberately stick to passive detection — CIDR matching + RDAP org-name
// keyword matching. No probes, no active fingerprinting.

interface CidrRange { cidr: string; provider: string }

// Curated, frequently-updated public CIDRs. We don't need every micro-range —
// just enough to classify the common cases. When a range goes stale we still
// catch the provider via the RDAP org-keyword path below.
const CDN_RANGES: CidrRange[] = [
  // ---- Cloudflare (IPv4) ----
  { cidr: "173.245.48.0/20",   provider: "Cloudflare" },
  { cidr: "103.21.244.0/22",   provider: "Cloudflare" },
  { cidr: "103.22.200.0/22",   provider: "Cloudflare" },
  { cidr: "103.31.4.0/22",     provider: "Cloudflare" },
  { cidr: "141.101.64.0/18",   provider: "Cloudflare" },
  { cidr: "108.162.192.0/18",  provider: "Cloudflare" },
  { cidr: "190.93.240.0/20",   provider: "Cloudflare" },
  { cidr: "188.114.96.0/20",   provider: "Cloudflare" },
  { cidr: "197.234.240.0/22",  provider: "Cloudflare" },
  { cidr: "198.41.128.0/17",   provider: "Cloudflare" },
  { cidr: "162.158.0.0/15",    provider: "Cloudflare" },
  { cidr: "104.16.0.0/13",     provider: "Cloudflare" },
  { cidr: "104.24.0.0/14",     provider: "Cloudflare" },
  { cidr: "172.64.0.0/13",     provider: "Cloudflare" },
  { cidr: "131.0.72.0/22",     provider: "Cloudflare" },

  // ---- Fastly ----
  { cidr: "23.235.32.0/20",    provider: "Fastly" },
  { cidr: "43.249.72.0/22",    provider: "Fastly" },
  { cidr: "103.244.50.0/24",   provider: "Fastly" },
  { cidr: "103.245.222.0/23",  provider: "Fastly" },
  { cidr: "103.245.224.0/24",  provider: "Fastly" },
  { cidr: "104.156.80.0/20",   provider: "Fastly" },
  { cidr: "140.248.64.0/18",   provider: "Fastly" },
  { cidr: "140.248.128.0/17",  provider: "Fastly" },
  { cidr: "146.75.0.0/17",     provider: "Fastly" },
  { cidr: "151.101.0.0/16",    provider: "Fastly" },
  { cidr: "157.52.64.0/18",    provider: "Fastly" },
  { cidr: "167.82.0.0/17",     provider: "Fastly" },
  { cidr: "172.111.64.0/18",   provider: "Fastly" },
  { cidr: "185.31.16.0/22",    provider: "Fastly" },
  { cidr: "199.27.72.0/21",    provider: "Fastly" },
  { cidr: "199.232.0.0/16",    provider: "Fastly" },

  // ---- Sucuri (WAF) ----
  { cidr: "192.124.249.0/24",  provider: "Sucuri" },
  { cidr: "185.93.228.0/22",   provider: "Sucuri" },
  { cidr: "66.248.200.0/22",   provider: "Sucuri" },

  // ---- Incapsula / Imperva ----
  { cidr: "199.83.128.0/21",   provider: "Imperva" },
  { cidr: "198.143.32.0/19",   provider: "Imperva" },
  { cidr: "149.126.72.0/21",   provider: "Imperva" },
  { cidr: "103.28.248.0/22",   provider: "Imperva" },
  { cidr: "185.11.124.0/22",   provider: "Imperva" },
  { cidr: "192.230.64.0/18",   provider: "Imperva" },
  { cidr: "45.60.0.0/16",      provider: "Imperva" },
  { cidr: "107.154.0.0/16",    provider: "Imperva" },
];

// Falls back to RDAP / IP-ASN org name when no CIDR matches. These are the
// strings recon-web's existing lookupIp / lookupAsn return.
const ORG_KEYWORDS: { rx: RegExp; provider: string }[] = [
  { rx: /cloudflare/i,                          provider: "Cloudflare" },
  { rx: /akamai|akadns|akamaitechnologies/i,    provider: "Akamai" },
  { rx: /fastly/i,                              provider: "Fastly" },
  { rx: /amazon|aws|cloudfront|a100 row/i,      provider: "AWS / CloudFront" },
  { rx: /google|google cloud|gws|googleusercontent/i, provider: "Google Cloud" },
  { rx: /microsoft|azure/i,                     provider: "Microsoft / Azure" },
  { rx: /alibaba|aliyun/i,                      provider: "Alibaba" },
  { rx: /digitalocean/i,                        provider: "DigitalOcean" },
  { rx: /hetzner/i,                             provider: "Hetzner" },
  { rx: /ovh/i,                                 provider: "OVH" },
  { rx: /sucuri/i,                              provider: "Sucuri" },
  { rx: /imperva|incapsula/i,                   provider: "Imperva" },
  { rx: /stackpath|netdna|highwinds/i,          provider: "StackPath" },
  { rx: /bunnyway|bunny\.net|bunny cdn/i,       provider: "BunnyCDN" },
];

// CDN providers that are pure proxies — when an apex resolves to one of
// these, the origin IP is hidden. The "potential origin IP" output only
// makes sense for these. Cloud providers like AWS/GCP/Azure also host
// origin servers directly, so we don't treat them as proxies.
const PROXY_PROVIDERS = new Set([
  "Cloudflare", "Fastly", "Akamai", "Sucuri", "Imperva", "StackPath", "BunnyCDN",
]);

function ipToInt(ip: string): number | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const a = +m[1], b = +m[2], c = +m[3], d = +m[4];
  if (a > 255 || b > 255 || c > 255 || d > 255) return null;
  // unsigned 32-bit
  return ((a * 256 * 256 * 256) + (b * 256 * 256) + (c * 256) + d) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [base, lenStr] = cidr.split("/");
  const len = parseInt(lenStr, 10);
  const ipI = ipToInt(ip);
  const baseI = ipToInt(base);
  if (ipI === null || baseI === null || isNaN(len)) return false;
  if (len === 0) return true;
  const mask = (~0 << (32 - len)) >>> 0;
  return (ipI & mask) === (baseI & mask);
}

export interface CdnMatch { ip: string; provider: string; via: "cidr" | "rdap" }

/** Classify a single IP. Returns null when nothing matched. */
export function classifyIp(ip: string, orgHint?: string): CdnMatch | null {
  for (const r of CDN_RANGES) {
    if (inCidr(ip, r.cidr)) return { ip, provider: r.provider, via: "cidr" };
  }
  if (orgHint) {
    for (const k of ORG_KEYWORDS) {
      if (k.rx.test(orgHint)) return { ip, provider: k.provider, via: "rdap" };
    }
  }
  return null;
}

export function isProxyProvider(provider: string): boolean {
  return PROXY_PROVIDERS.has(provider);
}
