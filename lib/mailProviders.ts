// Passive mail-provider fingerprints. Detection is based on common MX hostnames
// and known infrastructure suffixes. Tested against the all-MX-hosts string
// (joined with spaces) so multi-MX setups still match.

interface ProviderRule {
  re: RegExp;
  name: string;
  type: "Productivity" | "Security gateway" | "Marketing/Transactional" | "Hosted email";
}

const RULES: ProviderRule[] = [
  // Productivity suites
  { re: /aspmx\.l\.google\.com|googlemail\.com|google\.com$|aspmx\d?\.googlemail\.com/i, name: "Google Workspace",          type: "Productivity" },
  { re: /mail\.protection\.outlook\.com|olc\.protection\.outlook\.com|onmicrosoft\.com/i, name: "Microsoft 365",              type: "Productivity" },
  { re: /eo\.outlook\.com/i,                                                              name: "Microsoft Exchange Online",  type: "Productivity" },

  // Security gateways
  { re: /pphosted\.com|proofpoint/i,                                                      name: "Proofpoint",                 type: "Security gateway" },
  { re: /mimecast/i,                                                                      name: "Mimecast",                   type: "Security gateway" },
  { re: /messagelabs/i,                                                                   name: "Symantec MessageLabs",       type: "Security gateway" },
  { re: /iphmx\.com/i,                                                                    name: "Cisco IronPort / ESA",       type: "Security gateway" },
  { re: /barracudanetworks/i,                                                             name: "Barracuda",                  type: "Security gateway" },
  { re: /mxlogic/i,                                                                       name: "McAfee MXLogic",             type: "Security gateway" },
  { re: /trendmicro|tmes\.trendmicro/i,                                                   name: "Trend Micro Email Security", type: "Security gateway" },
  { re: /forcepoint/i,                                                                    name: "Forcepoint Email Security",  type: "Security gateway" },
  { re: /sophos/i,                                                                        name: "Sophos Email",               type: "Security gateway" },
  { re: /proxmox/i,                                                                       name: "Proxmox Mail Gateway",       type: "Security gateway" },

  // Hosted / consumer
  { re: /messagingengine\.com|fastmail/i,                                                 name: "Fastmail",                   type: "Hosted email" },
  { re: /protonmail|proton\.me$|proton\.ch/i,                                             name: "ProtonMail",                 type: "Hosted email" },
  { re: /zoho\./i,                                                                        name: "Zoho Mail",                  type: "Hosted email" },
  { re: /secureserver\.net/i,                                                             name: "GoDaddy Email",              type: "Hosted email" },
  { re: /yahoodns|yahoodns\.net|yahoo\.com$/i,                                            name: "Yahoo Mail",                 type: "Hosted email" },
  { re: /aol\.com$/i,                                                                     name: "AOL Mail",                   type: "Hosted email" },
  { re: /migadu/i,                                                                        name: "Migadu",                     type: "Hosted email" },
  { re: /emailsrvr\.com/i,                                                                name: "Rackspace Email",            type: "Hosted email" },
  { re: /hostedemail/i,                                                                   name: "OpenSRS Hosted Email",       type: "Hosted email" },
  { re: /mxroute/i,                                                                       name: "MXroute",                    type: "Hosted email" },
  { re: /tutanota/i,                                                                      name: "Tutanota",                   type: "Hosted email" },
  { re: /ionos|1and1/i,                                                                   name: "IONOS / 1&1",                type: "Hosted email" },
  { re: /ovh\./i,                                                                         name: "OVH Mail",                   type: "Hosted email" },

  // Transactional / marketing senders (less common as primary MX, but possible)
  { re: /sendgrid|sgmail/i,                                                               name: "SendGrid",                   type: "Marketing/Transactional" },
  { re: /mailgun\.org$/i,                                                                 name: "Mailgun",                    type: "Marketing/Transactional" },
  { re: /postmarkapp|mtasv\.net/i,                                                        name: "Postmark",                   type: "Marketing/Transactional" },
  { re: /sparkpostmail/i,                                                                 name: "SparkPost",                  type: "Marketing/Transactional" },
  { re: /amazonses/i,                                                                     name: "Amazon SES",                 type: "Marketing/Transactional" },
];

export interface MailProviderDetection {
  name: string;
  type: ProviderRule["type"];
}

export function detectMailProviders(mxHosts: string[]): MailProviderDetection[] {
  if (mxHosts.length === 0) return [];
  const haystack = mxHosts.join(" ");
  const seen = new Set<string>();
  const out: MailProviderDetection[] = [];
  for (const r of RULES) {
    if (r.re.test(haystack) && !seen.has(r.name)) {
      out.push({ name: r.name, type: r.type });
      seen.add(r.name);
    }
  }
  return out;
}
