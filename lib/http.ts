// HTTP helpers shared by every upstream OSINT source.
//
// Every call goes through fetchWithTimeout → fetchText / fetchJson so the
// security primitives live in exactly one place:
//   • per-request AbortController + timeout
//   • response body size cap (defends against a hostile/buggy upstream
//     streaming a multi-GB body)
//   • Content-Type sanity check (defends against fetchJson parsing an HTML
//     rate-limit page as JSON)
//   • neutral default User-Agent / Accept

const DEFAULT_UA = "Mozilla/5.0 (compatible; recon-osint/1.0)";

// 8 MB is comfortably above the largest legitimate body we see (Wayback CDX
// can be a few MB on huge domains) and an order of magnitude below "memory
// pressure on a small VM".
const MAX_BODY_BYTES = 8 * 1024 * 1024;

export async function fetchWithTimeout(
  url: string,
  opts: RequestInit & { timeoutMs?: number } = {}
): Promise<Response> {
  const { timeoutMs = 12_000, headers, ...rest } = opts;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...rest,
      signal: ctl.signal,
      headers: {
        "User-Agent": DEFAULT_UA,
        Accept: "application/json",
        ...(headers || {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Stream the body into a single string, aborting if it crosses MAX_BODY_BYTES.
 * Returns null when the stream is too large — callers treat that as
 * "source failed" and continue.
 */
async function readBodyCapped(response: Response): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) {
    // Some runtimes don't expose a stream — fall back to .text() but still
    // refuse anything obviously over the cap via Content-Length.
    const cl = parseInt(response.headers.get("content-length") ?? "", 10);
    if (Number.isFinite(cl) && cl > MAX_BODY_BYTES) return null;
    return response.text();
  }

  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        try { await reader.cancel("body-too-large"); } catch { /* ignore */ }
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }

  const buf = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { buf.set(c, offset); offset += c.byteLength; }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

const JSON_CONTENT_TYPES = [
  "application/json",
  "application/dns-json",          // Cloudflare DoH
  "application/vnd.github+json",   // GitHub REST v3
  "application/problem+json",      // RFC 7807
  "text/json",                     // some misconfigured servers
];

function looksJson(ct: string | null): boolean {
  if (!ct) return false;
  const v = ct.toLowerCase().split(";")[0].trim();
  return JSON_CONTENT_TYPES.some((t) => v === t || v.endsWith("+json"));
}

export async function fetchJson<T = unknown>(
  url: string,
  opts: RequestInit & { timeoutMs?: number } = {}
): Promise<T | null> {
  try {
    const r = await fetchWithTimeout(url, opts);
    if (!r.ok) return null;
    // Reject HTML rate-limit / login pages masquerading as success. Some
    // upstreams return 200 + an HTML body when throttling — JSON.parse on
    // that would throw and waste a stack trace.
    if (!looksJson(r.headers.get("content-type"))) return null;
    const body = await readBodyCapped(r);
    if (body === null) return null;
    return JSON.parse(body) as T;
  } catch {
    return null;
  }
}

export async function fetchText(
  url: string,
  opts: RequestInit & { timeoutMs?: number } = {}
): Promise<string | null> {
  try {
    const r = await fetchWithTimeout(url, opts);
    if (!r.ok) return null;
    return await readBodyCapped(r);
  } catch {
    return null;
  }
}

/**
 * Concurrent map with a fixed worker pool. Used by upstream sources that need
 * a small inflight cap (RDAP, DoH bulk-resolve, AbuseIPDB).
 */
export async function pMap<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, i: number) => Promise<R>
): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}
