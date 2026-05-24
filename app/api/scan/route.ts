// /api/scan — Server-Sent Events stream of the passive recon pipeline.
//
// Two transports are supported:
//   • GET  /api/scan?domain=…           – uses only env-configured API keys
//   • POST /api/scan { domain, keys }   – caller may pass per-scan BYO keys
//                                         (VirusTotal / AbuseIPDB / OTX).
// Both return identical text/event-stream bodies. POST is preferred when keys
// are present because keys never enter the URL/query log path.
//
// Security surface:
//   • rate-limit (token bucket per client key)
//   • same-origin guard (Origin or same-host Referer required)
//   • strict domain validation (rejects IPs, paths, private TLDs, …)
//   • hard wall-clock ceiling (MAX_SCAN_MS) sized for Vercel Hobby's 60 s cap
//   • error messages scrubbed of paths before being emitted to the client
//   • BYO keys are read from the POST body, never echoed back, never logged

import { runScan } from "@/lib/scan";
import { checkLimit, clientKey } from "@/lib/rateLimit";
import { isValidPublicDomain } from "@/lib/validate";
import type { ApiKeys, ScanEvent } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Vercel Hobby caps function duration at 60 s. We give the watchdog 55 s so
// we close cleanly before the platform yanks the connection.
export const maxDuration = 60;

const MAX_SCAN_MS = 55_000;

// --- helpers --------------------------------------------------------------

function jsonError(
  status: number,
  body: Record<string, unknown>,
  extraHeaders: Record<string, string> = {}
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

/**
 * Strip filesystem-y patterns from an error message before sending it to the
 * client. We keep enough signal for the user to know what failed without
 * leaking absolute paths, hostnames, or query strings.
 */
function sanitizeError(message: string): string {
  return message
    .replace(/file:\/\/\/?[^\s]+/gi, "<path>")
    .replace(/\b[A-Z]:\\[^\s)]+/g, "<path>")          // Windows path
    .replace(/(^|\s)\/(Users|home|root|var|etc|opt|tmp)\/[^\s)]+/g, " <path>")
    .replace(/\s+at\s+[^\s]+:\d+:\d+/g, "")           // stack frames
    .slice(0, 200);
}

/**
 * Same-origin check. Allowed when either:
 *   • Origin header is present AND its host matches our Host (browser-set
 *     Origin is non-spoofable in cross-origin requests), OR
 *   • there is no Origin header AND a Referer is present whose host matches
 *     ours (covers EventSource on older Safari which omits Origin).
 *
 * A request with neither Origin nor Referer is treated as a CLI / curl call
 * and allowed through. Anything explicit but mismatching is rejected.
 */
function isAllowedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");
  const host = (request.headers.get("host") ?? "").toLowerCase();
  if (!origin && !referer) return true;

  const matches = (raw: string | null) => {
    if (!raw) return false;
    try {
      const u = new URL(raw);
      const h = u.host.toLowerCase();
      return h === host || h === "localhost" || h === "127.0.0.1";
    } catch {
      return false;
    }
  };

  return matches(origin) || matches(referer);
}

/**
 * Strip a BYO key down to something we'd accept as a credential: bounded
 * length, no whitespace, no control characters. We never trust caller-shaped
 * strings to be safe upstream HTTP-header values.
 */
function sanitizeKey(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const v = raw.trim();
  if (!v) return undefined;
  if (v.length > 256) return undefined;
  if (!/^[A-Za-z0-9._\-:]+$/.test(v)) return undefined;
  return v;
}

function pickApiKeys(input: unknown): ApiKeys {
  if (!input || typeof input !== "object") return {};
  const o = input as Record<string, unknown>;
  return {
    virustotal: sanitizeKey(o.virustotal),
    abuseipdb:  sanitizeKey(o.abuseipdb),
    otx:        sanitizeKey(o.otx),
  };
}

/**
 * Build the SSE Response. Shared between GET and POST.
 */
function streamScan(request: Request, domain: string, keys: ApiKeys): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const send = (e: ScanEvent) => {
        if (closed) return;
        try {
          controller.enqueue(
            encoder.encode(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`)
          );
        } catch {
          closed = true;
        }
      };

      const abort = new AbortController();
      const onAbort = () => abort.abort();
      request.signal.addEventListener("abort", onAbort);
      const watchdog = setTimeout(onAbort, MAX_SCAN_MS);

      try {
        await runScan(domain, send, abort.signal, keys);
      } catch (err) {
        const raw = err instanceof Error ? err.message : String(err);
        send({ type: "error", phase: "scan", message: sanitizeError(raw) });
        send({ type: "done" });
      } finally {
        clearTimeout(watchdog);
        request.signal.removeEventListener("abort", onAbort);
        closed = true;
        try { controller.close(); } catch { /* already closed */ }
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

/**
 * Parse + validate the domain string used by both transports.
 */
function validateDomain(raw: string): Response | string {
  const d = raw.trim().toLowerCase();
  if (!d) return jsonError(400, { error: "bad_request", message: "Missing domain." });
  if (d.length > 253) return jsonError(400, { error: "bad_request", message: "Domain too long." });
  if (!isValidPublicDomain(d)) {
    return jsonError(400, {
      error: "bad_request",
      message:
        "Invalid or non-public domain. IP addresses, private TLDs, and paths are not allowed.",
    });
  }
  return d;
}

function gateRequest(request: Request): Response | null {
  if (!isAllowedOrigin(request)) {
    return jsonError(403, {
      error: "forbidden",
      message: "Cross-origin request rejected.",
    });
  }
  const limit = checkLimit(clientKey(request));
  if (!limit.ok) {
    return jsonError(
      429,
      {
        error: "rate_limited",
        message: "Too many scans from this client. Please slow down.",
        retryAfterSec: limit.retryAfterSec,
      },
      { "Retry-After": String(limit.retryAfterSec) }
    );
  }
  return null;
}

// --- handlers -------------------------------------------------------------

export async function GET(request: Request) {
  const blocked = gateRequest(request);
  if (blocked) return blocked;

  const url = new URL(request.url);
  const result = validateDomain(url.searchParams.get("domain") || "");
  if (result instanceof Response) return result;

  return streamScan(request, result, {});
}

// Max accepted POST body. The legitimate payload is < 1 KB even with three
// maximum-length keys; 8 KB gives a generous margin without letting an
// attacker stream megabytes into our JSON parser.
const MAX_BODY_BYTES = 8 * 1024;

export async function POST(request: Request) {
  const blocked = gateRequest(request);
  if (blocked) return blocked;

  const declared = parseInt(request.headers.get("content-length") ?? "", 10);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return jsonError(413, { error: "payload_too_large", message: "Body too large." });
  }

  // Read the body manually so we can enforce the size cap even when the
  // client omits or lies about Content-Length.
  let raw: string;
  try {
    const reader = request.body?.getReader();
    if (!reader) {
      raw = await request.text();
      if (raw.length > MAX_BODY_BYTES) {
        return jsonError(413, { error: "payload_too_large", message: "Body too large." });
      }
    } else {
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_BODY_BYTES) {
          try { await reader.cancel("body-too-large"); } catch { /* ignore */ }
          return jsonError(413, { error: "payload_too_large", message: "Body too large." });
        }
        chunks.push(value);
      }
      const buf = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
      raw = new TextDecoder("utf-8", { fatal: false }).decode(buf);
    }
  } catch {
    return jsonError(400, { error: "bad_request", message: "Could not read request body." });
  }

  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    return jsonError(400, { error: "bad_request", message: "Invalid JSON body." });
  }
  if (!body || typeof body !== "object") {
    return jsonError(400, { error: "bad_request", message: "Body must be an object." });
  }
  const o = body as Record<string, unknown>;

  const result = validateDomain(typeof o.domain === "string" ? o.domain : "");
  if (result instanceof Response) return result;

  return streamScan(request, result, pickApiKeys(o.keys));
}
