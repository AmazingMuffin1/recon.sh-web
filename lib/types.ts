export type PhaseId =
  | "meta"
  | "whois"
  | "dns"
  | "subdomains"
  | "wayback"
  | "emails"
  | "github"
  | "dorks"
  | "threat"
  | "asn"
  | "abuseipdb"
  | "pivot"
  | "summary";

export type ScanEvent =
  | { type: "banner"; text: string }
  | { type: "phase"; id: PhaseId; title: string }
  | { type: "section"; text: string }
  | { type: "line"; text: string; hit?: boolean }
  | { type: "kv"; key: string; value: string }
  | { type: "list"; title?: string; items: string[]; hits?: string[] }
  | { type: "phase-skipped"; phase: string; reason: string }
  | { type: "error"; phase: string; message: string }
  | { type: "summary"; data: Record<string, string | number> }
  | { type: "done" };

export type Send = (e: ScanEvent) => void;

/**
 * API keys that callers can bring per-scan. Each is optional; when missing
 * the scan falls back to the equivalent process.env value, and if neither
 * is present the dependent phase is cleanly skipped.
 */
export interface ApiKeys {
  virustotal?: string;
  abuseipdb?: string;
  otx?: string;
}
