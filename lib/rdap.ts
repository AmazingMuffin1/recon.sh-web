import { fetchJson } from "./http";

// RDAP replaces port-43 `whois`. rdap.org is a redirector that figures
// out the right authoritative server per TLD/IP block.

interface RdapEntity {
  handle?: string;
  roles?: string[];
  vcardArray?: unknown;
  publicIds?: { type: string; identifier: string }[];
}
interface RdapDomain {
  ldhName?: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  nameservers?: { ldhName: string }[];
  entities?: RdapEntity[];
  secureDNS?: { delegationSigned?: boolean };
  registrar?: string;
}
interface RdapIp {
  handle?: string;
  name?: string;
  startAddress?: string;
  endAddress?: string;
  cidr0_cidrs?: { v4prefix?: string; length?: number }[];
  country?: string;
  type?: string;
  entities?: RdapEntity[];
  events?: { eventAction: string; eventDate: string }[];
  remarks?: { description: string[] }[];
}

function vcardField(vcard: unknown, key: string): string | undefined {
  if (!Array.isArray(vcard) || !Array.isArray(vcard[1])) return undefined;
  const rows = vcard[1] as unknown[][];
  for (const row of rows) {
    if (row[0] === key && typeof row[3] === "string") return row[3];
  }
  return undefined;
}

export interface DomainInfo {
  domain: string;
  registrar?: string;
  status: string[];
  created?: string;
  updated?: string;
  expires?: string;
  nameservers: string[];
  dnssec?: boolean;
  contacts: { role: string; name?: string; org?: string; email?: string }[];
}

export async function lookupDomain(domain: string): Promise<DomainInfo | null> {
  const data = await fetchJson<RdapDomain>(
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    { timeoutMs: 10_000 }
  );
  if (!data) return null;
  const events = data.events ?? [];
  const ev = (action: string) =>
    events.find((e) => e.eventAction === action)?.eventDate;

  let registrar = data.registrar;
  const contacts: DomainInfo["contacts"] = [];
  for (const ent of data.entities ?? []) {
    const role = (ent.roles ?? []).join(",");
    const name = vcardField(ent.vcardArray, "fn");
    const org = vcardField(ent.vcardArray, "org");
    const email = vcardField(ent.vcardArray, "email");
    if (role.includes("registrar") && !registrar) {
      registrar = name || org || ent.handle;
    }
    contacts.push({ role: role || "?", name, org, email });
  }

  return {
    domain,
    registrar,
    status: data.status ?? [],
    created: ev("registration"),
    updated: ev("last changed"),
    expires: ev("expiration"),
    nameservers: (data.nameservers ?? []).map((n) => n.ldhName).filter(Boolean),
    dnssec: data.secureDNS?.delegationSigned,
    contacts,
  };
}

export interface IpInfo {
  ip: string;
  netname?: string;
  org?: string;
  country?: string;
  cidr?: string;
  type?: string;
  asn?: string;
}

export async function lookupIp(ip: string): Promise<IpInfo | null> {
  const data = await fetchJson<RdapIp>(
    `https://rdap.org/ip/${encodeURIComponent(ip)}`,
    { timeoutMs: 8000 }
  );
  if (!data) return null;
  const cidr = data.cidr0_cidrs?.[0]
    ? `${data.cidr0_cidrs[0].v4prefix}/${data.cidr0_cidrs[0].length}`
    : undefined;
  let org: string | undefined;
  for (const ent of data.entities ?? []) {
    const role = (ent.roles ?? []).join(",");
    if (role.includes("registrant") || role.includes("administrative")) {
      const o = vcardField(ent.vcardArray, "org") || vcardField(ent.vcardArray, "fn");
      if (o && !org) org = o;
    }
  }
  return {
    ip,
    netname: data.name,
    org,
    country: data.country,
    cidr,
    type: data.type,
  };
}

interface BgpviewIp {
  data?: {
    prefixes?: { asn?: { asn: number; name: string; description: string } }[];
  };
}

// BGPView fills in the ASN/org info that RDAP often omits.
export async function lookupAsn(ip: string): Promise<{ asn: number; name: string; description: string } | null> {
  const r = await fetchJson<BgpviewIp>(`https://api.bgpview.io/ip/${ip}`, { timeoutMs: 8000 });
  const a = r?.data?.prefixes?.[0]?.asn;
  return a ? { asn: a.asn, name: a.name, description: a.description } : null;
}
