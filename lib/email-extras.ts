// MailAccess-inspired passive email enrichment.
//
// We only borrow the two features that don't probe the target mailserver:
//   • permutateEmailsFromName — local computation of plausible corporate
//     email patterns from a person's display name.
//   • gravatarLookup — hash the email, GET gravatar.com/{hash}.json. If a
//     profile exists, the address is real AND we get linked social accounts
//     for free.
//
// Everything else MailAccess does (Holehe-style signup probes, Hunter.io,
// HIBP, WhatsmyName) is either paid or actively probes the target service —
// excluded.

import { createHash } from "node:crypto";
import { fetchJson } from "./http";

// --- Permutation generator -----------------------------------------------

/**
 * Return the standard 12–14 corporate email patterns built from a person's
 * name + the target domain. Inputs are normalized to lowercase ASCII (accents
 * stripped), so "Renée O'Connor" → "renee oconnor" → "renee.oconnor@…", etc.
 *
 * We only use first + last; middle names balloon the permutation surface
 * without much added signal. Single-name inputs collapse to one pattern.
 */
export function permutateEmailsFromName(fullName: string, domain: string): string[] {
  const cleaned = fullName
    .toLowerCase()
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")        // strip combining accents
    .replace(/[^a-z\s.-]/g, " ")            // drop quotes/apostrophes/etc.
    .trim();

  const parts = cleaned.split(/\s+/).filter((p) => p.length > 0 && p.length <= 30);
  if (parts.length === 0) return [];

  const first = parts[0];
  if (parts.length === 1) return [`${first}@${domain}`];

  const last = parts[parts.length - 1];
  const fi = first[0];
  const li = last[0];

  const patterns = new Set<string>([
    first,
    last,
    `${first}.${last}`,
    `${first}_${last}`,
    `${first}-${last}`,
    `${first}${last}`,
    `${last}.${first}`,
    `${last}_${first}`,
    `${last}${first}`,
    `${fi}.${last}`,
    `${fi}_${last}`,
    `${fi}${last}`,
    `${first}.${li}`,
    `${first}${li}`,
    `${fi}${li}`,
  ]);

  return [...patterns].map((p) => `${p}@${domain}`);
}

// --- Gravatar lookup -----------------------------------------------------

interface GravatarRaw {
  entry?: {
    hash?: string;
    requestHash?: string;
    profileUrl?: string;
    preferredUsername?: string;
    displayName?: string;
    accounts?: { domain?: string; username?: string; url?: string }[];
    aboutMe?: string;
    urls?: { title?: string; value?: string }[];
    name?: { givenName?: string; familyName?: string };
  }[];
}

export interface GravatarHit {
  email: string;
  hash: string;
  profileUrl: string;
  displayName?: string;
  preferredUsername?: string;
  about?: string;
  accounts: string[];
}

/**
 * MD5 of the lower-cased, trimmed email — the format Gravatar still uses
 * for all lookups even though they now also accept SHA-256.
 */
export function emailHash(email: string): string {
  return createHash("md5").update(email.trim().toLowerCase()).digest("hex");
}

/**
 * Lookup the public Gravatar profile for an email. Returns null when no
 * profile is registered. Gravatar's `/{hash}.json` endpoint is unauth and
 * idempotent; we do NOT touch the email's mail server in this call.
 */
export async function gravatarLookup(email: string): Promise<GravatarHit | null> {
  const hash = emailHash(email);
  const data = await fetchJson<GravatarRaw>(
    `https://www.gravatar.com/${hash}.json`,
    {
      timeoutMs: 8_000,
      // Some Gravatar edge nodes refuse non-browser UAs.
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "application/json",
      },
    }
  );
  const entry = data?.entry?.[0];
  if (!entry) return null;

  const accounts: string[] = [];
  for (const a of entry.accounts ?? []) {
    if (a.url) accounts.push(`${a.domain ?? "?"}: ${a.url}`);
    else if (a.username) accounts.push(`${a.domain ?? "?"}:${a.username}`);
  }
  for (const u of entry.urls ?? []) {
    if (u.value) accounts.push(`${u.title ?? "url"}: ${u.value}`);
  }

  return {
    email,
    hash,
    profileUrl: entry.profileUrl ?? `https://www.gravatar.com/${hash}`,
    displayName: entry.displayName,
    preferredUsername: entry.preferredUsername,
    about: entry.aboutMe,
    accounts,
  };
}
