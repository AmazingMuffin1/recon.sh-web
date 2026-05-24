// Same regexes used by recon.sh — keep these in sync.
export const SENSITIVE_SUB =
  /^(admin|adm|api|apis?|app|auth|backup|beta|cdn|ci|cms|confluence|control|corp|customer|dashboard|db|dev|developer|devops|docker|docs|elastic|ftp|gateway|git|gitlab|grafana|hidden|host|idp|internal|intranet|jenkins|jira|kibana|legacy|login|m|mail|mgmt|monitor|mx|new|old|owa|panel|partner|payment|portal|preprod|private|prod|qa|redis|registry|repo|s3|sandbox|secret|secure|server|shop|sftp|signin|smtp|sql|ssh|ssl|stage|staging|status|storage|svn|sysadmin|test|uat|vault|vpn|web|webmail|wiki|www2)\./i;

export const INTERESTING_PATH =
  /(admin|login|signin|api\/|config|\.git|\.env|backup|debug|swagger|graphql|\.json|\.xml|\.bak|\.old|\.zip|\.tar|\.sql|\.yml|\.yaml|phpmyadmin|wp-admin|wp-config|secret|token|password|dashboard)/i;

export const SENSITIVE_PARAM =
  /[?&](token|key|api[_-]?key|secret|password|passwd|pwd|sess|sid|auth|jwt|access[_-]?token|redirect|return|callback|debug|admin|file|path|src|url)=/i;

export const ONION_RE = /[a-z2-7]{16,56}\.onion/gi;

/**
 * Build a regex matching emails whose host is `domain` OR a subdomain of it.
 *
 * The earlier version required `[a-zA-Z0-9.-]+\.${domain}` — i.e. *at least one*
 * subdomain label — which silently skipped the most common case: `info@apex.com`.
 * The `(?:[a-zA-Z0-9-]+\.)*` makes the subdomain prefix optional, and the
 * trailing `\b` prevents matches like `…@evilexample.commit` from sneaking in
 * via greedy backtracking.
 */
export function emailRegexFor(domain: string): RegExp {
  const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `[a-zA-Z0-9._%+\\-]+@(?:[a-zA-Z0-9-]+\\.)*${escaped}\\b`,
    "gi"
  );
}
