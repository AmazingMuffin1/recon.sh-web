// Strict input validation for the public-facing API.
//
// We deliberately reject anything that isn't a clearly-public, registrable
// FQDN — IPs, private/reserved TLDs, single labels, URLs, paths, ports, and
// userinfo. The OSINT phases assume a syntactically clean apex domain; loose
// validation here propagates into upstream API calls that we'd rather not make.

const PRIVATE_TLDS = new Set([
  "local", "localhost", "internal", "intranet", "lan", "home", "corp",
  "private", "test", "example", "invalid", "onion", "i2p", "exit",
]);

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function looksLikeIp(s: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)) return true;     // IPv4
  if (/^[0-9a-f:]+$/i.test(s) && s.includes(":")) return true; // IPv6 shorthand
  return false;
}

export function isValidPublicDomain(input: string): boolean {
  if (!input) return false;
  const s = input.trim().toLowerCase();

  // No URLs, paths, schemes, ports, userinfo, whitespace, or query strings.
  if (/[\s/\\?#@:]/.test(s)) return false;
  if (s.length > 253) return false;

  // Strip a single trailing dot (root).
  const bare = s.endsWith(".") ? s.slice(0, -1) : s;

  if (looksLikeIp(bare)) return false;

  const labels = bare.split(".");
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!HOST_LABEL.test(label)) return false;
  }

  const tld = labels[labels.length - 1];
  // TLDs are letters-only and at least 2 chars (xn-- punycode is allowed).
  if (!/^[a-z]{2,}$/.test(tld) && !/^xn--[a-z0-9-]+$/.test(tld)) return false;
  if (PRIVATE_TLDS.has(tld)) return false;

  return true;
}
