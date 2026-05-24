import { fetchJson } from "./http";

// DNS-over-HTTPS replacement for `dig` — uses Cloudflare 1.1.1.1.
const DOH_BASE = "https://cloudflare-dns.com/dns-query";

interface DoHAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}
interface DoHResp {
  Status: number;
  Answer?: DoHAnswer[];
}

export async function dohQuery(
  name: string,
  type: string
): Promise<DoHAnswer[]> {
  const url = `${DOH_BASE}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const data = await fetchJson<DoHResp>(url, {
    headers: { Accept: "application/dns-json" },
    timeoutMs: 8000,
  });
  return data?.Answer ?? [];
}

export async function resolveAll(domain: string) {
  const types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"] as const;
  const [a, aaaa, mx, ns, txt, soa, caa, dmarc] = await Promise.all([
    ...types.map((t) => dohQuery(domain, t)),
    dohQuery(`_dmarc.${domain}`, "TXT"),
  ]);
  return { a, aaaa, mx, ns, txt, soa, caa, dmarc };
}

export const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "mail", "dkim",
  "k1", "s1", "s2", "mandrill", "mailchimp", "sendgrid",
];

export async function probeDkim(domain: string): Promise<{ selector: string; record: string }[]> {
  const results = await Promise.all(
    DKIM_SELECTORS.map(async (sel) => {
      const ans = await dohQuery(`${sel}._domainkey.${domain}`, "TXT");
      const rec = ans.map((a) => a.data).join(" ").trim();
      return rec ? { selector: sel, record: rec } : null;
    })
  );
  return results.filter((r): r is { selector: string; record: string } => !!r);
}

// Bulk-resolve subdomains to A records.
export async function resolveBulkA(
  hosts: string[],
  concurrency = 20
): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  let cursor = 0;
  const work = async () => {
    while (true) {
      const i = cursor++;
      if (i >= hosts.length) return;
      const host = hosts[i];
      const ans = await dohQuery(host, "A");
      const ips = ans
        .map((a) => a.data)
        .filter((d) => /^\d+\.\d+\.\d+\.\d+$/.test(d));
      if (ips.length) out.set(host, ips);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, work));
  return out;
}
