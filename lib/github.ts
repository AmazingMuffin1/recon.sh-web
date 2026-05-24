import { fetchJson } from "./http";

// GitHub's public REST API. Unauthenticated requests are limited to 60/hr per
// IP — comfortably enough for one scan (we issue ~5 queries here). When the
// limit is hit `api.github.com` returns a 403 with `X-RateLimit-Remaining: 0`;
// fetchJson swallows it and we return [].
//
// We deliberately do NOT call /search/code — that endpoint requires an OAuth
// token. Repo and issue search work unauth and surface most of the signal we
// care about (repos that mention the domain, PRs/issues discussing it, the
// org's own public repo list).

const GH_API = "https://api.github.com";

const GH_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  // GitHub returns a generic UA-reject HTML page if the UA looks like a bot
  // (e.g. our default "recon-osint/1.0"). A browsery UA avoids that pitfall.
  "User-Agent": "recon-web (+https://github.com)",
};

export interface GhRepo {
  full_name: string;
  html_url: string;
  description: string | null;
  stargazers_count: number;
  pushed_at: string;
  language: string | null;
  owner: { login: string };
}

export interface GhIssue {
  title: string;
  html_url: string;
  body: string | null;
  state: string;
  created_at: string;
  user: { login: string } | null;
  repository_url: string;
  pull_request?: unknown;
}

export interface GhUser {
  login: string;
  type: "User" | "Organization";
  html_url: string;
  name?: string | null;
}

interface SearchResp<T> {
  total_count?: number;
  incomplete_results?: boolean;
  items?: T[];
}

export async function ghSearchRepos(q: string, max = 12): Promise<{ total: number; items: GhRepo[] }> {
  const data = await fetchJson<SearchResp<GhRepo>>(
    `${GH_API}/search/repositories?q=${encodeURIComponent(q)}&sort=updated&order=desc&per_page=${max}`,
    { headers: GH_HEADERS, timeoutMs: 12_000 }
  );
  return { total: data?.total_count ?? 0, items: data?.items ?? [] };
}

export async function ghSearchIssues(q: string, max = 12): Promise<{ total: number; items: GhIssue[] }> {
  const data = await fetchJson<SearchResp<GhIssue>>(
    `${GH_API}/search/issues?q=${encodeURIComponent(q)}&sort=updated&order=desc&per_page=${max}`,
    { headers: GH_HEADERS, timeoutMs: 12_000 }
  );
  return { total: data?.total_count ?? 0, items: data?.items ?? [] };
}

export async function ghSearchUsers(q: string, max = 8): Promise<{ total: number; items: GhUser[] }> {
  const data = await fetchJson<SearchResp<GhUser>>(
    `${GH_API}/search/users?q=${encodeURIComponent(q)}&per_page=${max}`,
    { headers: GH_HEADERS, timeoutMs: 10_000 }
  );
  return { total: data?.total_count ?? 0, items: data?.items ?? [] };
}

/**
 * Try to find a GitHub org/user that matches the domain's `orgHint`. We look
 * for an exact-login match first (cheap), then fall back to the `domain in
 * blog/url` qualifier for users whose profile lists the company URL.
 */
export async function ghFindOrg(orgHint: string, domain: string): Promise<GhUser | null> {
  // Exact login probe — single GET, no search budget burned.
  const direct = await fetchJson<GhUser>(
    `${GH_API}/users/${encodeURIComponent(orgHint)}`,
    { headers: GH_HEADERS, timeoutMs: 8000 }
  );
  if (direct && direct.login) return direct;

  // Otherwise look for a profile that lists the target domain in its blog/url.
  const r = await ghSearchUsers(`${domain} in:blog OR ${domain} in:email`, 4);
  return r.items[0] ?? null;
}

export async function ghListOrgRepos(login: string, max = 30): Promise<GhRepo[]> {
  const data = await fetchJson<GhRepo[]>(
    `${GH_API}/users/${encodeURIComponent(login)}/repos?sort=pushed&per_page=${max}`,
    { headers: GH_HEADERS, timeoutMs: 10_000 }
  );
  return data ?? [];
}

interface GhCommitAuthor { name?: string; email?: string; date?: string }
interface GhCommitItem {
  sha?: string;
  commit?: {
    author?: GhCommitAuthor;
    committer?: GhCommitAuthor;
    message?: string;
  };
  html_url?: string;
}

export interface GhCommitEmail {
  email: string;
  name?: string;
  repo: string;
  sha?: string;
  url?: string;
}

/**
 * Pull recent commits from a single repo and extract author/committer emails.
 * The commits endpoint is unauth-readable for public repos (60 req/hr cap
 * shared with the rest of the GitHub API surface).
 */
export async function ghRepoCommits(
  owner: string,
  repo: string,
  perPage = 100
): Promise<GhCommitItem[]> {
  const data = await fetchJson<GhCommitItem[]>(
    `${GH_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits?per_page=${perPage}`,
    { headers: GH_HEADERS, timeoutMs: 12_000 }
  );
  return data ?? [];
}

/**
 * For a list of repos, fetch recent commits in parallel and return any
 * author/committer emails matching `emailFilter`. The filter is what guards
 * against contributor emails that don't belong to the org (drive-by PRs,
 * external collaborators, GitHub-internal noreply addresses, etc.).
 */
export async function ghCollectCommitEmails(
  repos: { owner: string; name: string }[],
  emailFilter: RegExp,
  maxRepos = 4,
  perPage = 100
): Promise<GhCommitEmail[]> {
  const targets = repos.slice(0, maxRepos);
  const results = await Promise.all(
    targets.map((r) => ghRepoCommits(r.owner, r.name, perPage).catch(() => [] as GhCommitItem[]))
  );

  const seen = new Set<string>();
  const out: GhCommitEmail[] = [];
  for (let i = 0; i < targets.length; i++) {
    const repoLabel = `${targets[i].owner}/${targets[i].name}`;
    for (const c of results[i]) {
      for (const who of [c.commit?.author, c.commit?.committer]) {
        if (!who) continue;
        const email = who.email?.toLowerCase();
        if (!email) continue;
        // Regex.test() with /g maintains lastIndex state — reset each call.
        emailFilter.lastIndex = 0;
        if (!emailFilter.test(email)) continue;
        // Skip GitHub's pseudo-email noreply addresses — they're not real
        // mailable addresses and tend to dominate results otherwise.
        if (email.endsWith("@users.noreply.github.com")) continue;
        if (seen.has(email)) continue;
        seen.add(email);
        out.push({ email, name: who.name, repo: repoLabel, sha: c.sha, url: c.html_url });
      }
    }
  }
  return out;
}
