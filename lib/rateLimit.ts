// Lightweight in-memory token-bucket limiter.
// Per-instance only — survives within a single Vercel function instance, not
// across cold starts or regions. Good enough for casual abuse protection on
// the Hobby plan; for production-grade limiting swap to Upstash Redis or
// Vercel KV. The function itself is otherwise fully stateless: every other
// piece of per-scan state lives on the request's stack frame.
//
// Two layers run on every request:
//   1. Per-client bucket (keyed by IP)   – catches one noisy user.
//   2. Global bucket ("__global__")      – defends against distributed abuse
//      where an attacker rotates IPs (cheap with residential-proxy services)
//      to bypass layer 1. The global cap keeps a single instance from being
//      used as an OSINT-scan amplifier or burning the host's free-tier quota.

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const BUCKETS = new Map<string, Bucket>();

// Per-IP: a burst of 5 then ~1 scan per 2 minutes sustained.
const SCAN_CAPACITY = 5;
const SCAN_REFILL_PER_SEC = 5 / (10 * 60);

// Global: at most ~30 scans/minute across all clients on this instance.
// Each scan opens dozens of outbound connections, so this is a sane ceiling
// for the Hobby plan's concurrency + bandwidth allowance.
const GLOBAL_KEY = "__global__";
const GLOBAL_CAPACITY = 30;
const GLOBAL_REFILL_PER_SEC = 30 / 60;

// Soft cap to keep the map from growing unbounded under abuse.
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

  // Global gate first — if the instance is saturated, reject early without
  // even touching the per-IP bucket. Cheap and prevents the per-IP cap from
  // being multiplied by `unlimited unique IPs` in a distributed attack.
  const global = consume(GLOBAL_KEY, GLOBAL_CAPACITY, GLOBAL_REFILL_PER_SEC);
  if (!global.ok) return global;

  return consume(key, SCAN_CAPACITY, SCAN_REFILL_PER_SEC);
}

// Best-effort client IP. Forwarded-for headers are only trusted when we're
// confident a real proxy set them — otherwise an attacker behind no proxy
// could rotate the header per request to bypass the limit. We auto-trust on
// Vercel (which always sets x-vercel-forwarded-for) and otherwise honour
// TRUST_PROXY=1 for self-hosted deployments behind nginx/ALB/Cloudflare.
const TRUST_PROXY =
  process.env.TRUST_PROXY === "1" || !!process.env.VERCEL;

// Validators are deliberately strict: anything that doesn't look like an
// IPv4 dotted quad or an IPv6 address (with at least one ':' and at least
// one hex digit) is rejected. This blocks dot-only / colon-only garbage
// and very-short tokens that would otherwise collide buckets.
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
    // Vercel's own header is set by the edge and not forwardable by clients,
    // so prefer it when present.
    const vercelFwd = sanitizeIp(headers.get("x-vercel-forwarded-for") ?? "");
    if (vercelFwd) return vercelFwd;
    const fwd = headers.get("x-forwarded-for");
    if (fwd) {
      const first = sanitizeIp(fwd.split(",")[0] ?? "");
      if (first) return first;
    }
    const cf = sanitizeIp(headers.get("cf-connecting-ip") ?? "");
    if (cf) return cf;
    const real = sanitizeIp(headers.get("x-real-ip") ?? "");
    if (real) return real;
  }
  // Fallback bucket — everyone shares it when the runtime cannot give us a
  // real peer address. Safer to throttle aggressively than to be spoofable.
  return "shared";
}
