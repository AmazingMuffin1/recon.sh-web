interface Bucket {
  tokens: number;
  updatedAt: number;
}

const BUCKETS = new Map<string, Bucket>();

const SCAN_CAPACITY = 5;
const SCAN_REFILL_PER_SEC = 5 / (10 * 60);

const GLOBAL_KEY = "__global__";
const GLOBAL_CAPACITY = 30;
const GLOBAL_REFILL_PER_SEC = 30 / 60;

const MAX_KEYS = 5000;

export interface LimitResult {
  ok: boolean;
  remaining: number;
  retryAfterSec: number;
}

function consume(
  key: string,
  capacity: number,
  refillPerSec: number
): LimitResult {
  const now = Date.now();
  const bucket = BUCKETS.get(key) ?? { tokens: capacity, updatedAt: now };
  const elapsedSec = (now - bucket.updatedAt) / 1000;
  const refilled = Math.min(capacity, bucket.tokens + elapsedSec * refillPerSec);

  if (refilled < 1) {
    BUCKETS.set(key, { tokens: refilled, updatedAt: now });
    const retryAfterSec = Math.ceil((1 - refilled) / refillPerSec);
    return { ok: false, remaining: 0, retryAfterSec };
  }

  BUCKETS.set(key, { tokens: refilled - 1, updatedAt: now });
  return { ok: true, remaining: Math.floor(refilled - 1), retryAfterSec: 0 };
}

export function checkLimit(key: string): LimitResult {
  if (BUCKETS.size > MAX_KEYS) BUCKETS.clear();

  const global = consume(GLOBAL_KEY, GLOBAL_CAPACITY, GLOBAL_REFILL_PER_SEC);
  if (!global.ok) return global;

  return consume(key, SCAN_CAPACITY, SCAN_REFILL_PER_SEC);
}

const TRUST_PROXY =
  process.env.TRUST_PROXY === "1" || !!process.env.VERCEL;

const TRUSTED_HOPS = (() => {
  const n = parseInt(process.env.TRUSTED_HOPS ?? "", 10);
  if (Number.isFinite(n) && n >= 1 && n <= 10) return n;
  return 1;
})();

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function sanitizeIp(s: string): string | null {
  const v = s.trim();
  if (!v || v.length > 45) return null;
  if (IPV4_RE.test(v)) return v;
  if (IPV6_RE.test(v) && v.includes(":") && /[0-9a-fA-F]/.test(v)) return v;
  return null;
}

export function clientKey(req: Request): string {
  const headers = req.headers;
  if (TRUST_PROXY) {
    const vercelFwd = sanitizeIp(headers.get("x-vercel-forwarded-for") ?? "");
    if (vercelFwd) return vercelFwd;

    // Take the IP appended by the most recent trusted proxy, not the
    // attacker-controlled leftmost entry.
    const fwdRaw = headers.get("x-forwarded-for");
    if (fwdRaw) {
      const parts = fwdRaw.split(",").map((s) => s.trim()).filter(Boolean);
      const idx = parts.length - TRUSTED_HOPS;
      if (idx >= 0 && idx < parts.length) {
        const ip = sanitizeIp(parts[idx]);
        if (ip) return ip;
      }
    }

    const cf = sanitizeIp(headers.get("cf-connecting-ip") ?? "");
    if (cf) return cf;
    const real = sanitizeIp(headers.get("x-real-ip") ?? "");
    if (real) return real;
  }
  // No reliable per-client identifier. Bucket by coarse UA so self-hosters
  // without a trusted proxy don't collapse all clients into a single bucket
  // that any single abuser can exhaust. Global limit still applies on top.
  const ua = (headers.get("user-agent") ?? "").slice(0, 96);
  return ua ? `ua:${ua}` : "shared";
}
