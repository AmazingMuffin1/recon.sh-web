"use client";

import { memo, useEffect, useMemo, useRef, useState, useCallback } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, AlertTriangle, ArrowRight, Atom, Check, ChevronDown, ChevronRight,
  CircleDot, Code2, Copy, Crosshair, Database, Eye, EyeOff, FileDown, FileText, Filter,
  Globe, History, Key, Layers, Mail, Network, Search, Server, Shield,
  ShieldAlert, ShieldCheck, SkipForward, Sparkles, Square, Wifi, X, Zap,
  type LucideIcon,
} from "lucide-react";
import type { PhaseId, ScanEvent } from "@/lib/types";

// ============================================================================
// Types
// ============================================================================

type Item =
  | { kind: "line"; text: string; hit?: boolean }
  | { kind: "kv"; key: string; value: string }
  | { kind: "list"; title?: string; items: string[]; hits: Set<string> }
  | { kind: "skipped"; phase: string; reason: string }
  | { kind: "error"; phase: string; message: string }
  | { kind: "summary"; data: Record<string, string | number> };

interface Section { title: string; items: Item[] }
interface Phase {
  id: PhaseId;
  title: string;
  status: "running" | "done";
  sections: Section[];
}

// ============================================================================
// Constants
// ============================================================================

const PHASE_ORDER: PhaseId[] = [
  "meta", "whois", "dns", "subdomains", "wayback", "emails",
  "github", "dorks", "threat", "asn", "abuseipdb", "pivot", "summary",
];

const PHASE_COLORS: Record<PhaseId, string> = {
  meta:       "#94a3b8",
  whois:      "#06b6d4",
  dns:        "#3b82f6",
  subdomains: "#8b5cf6",
  wayback:    "#f59e0b",
  emails:     "#f43f5e",
  github:     "#ec4899",
  dorks:      "#10b981",
  threat:     "#ef4444",
  asn:        "#14b8a6",
  abuseipdb:  "#f97316",
  pivot:      "#a855f7",
  summary:    "#6366f1",
};

const PHASE_ICON: Record<PhaseId, LucideIcon> = {
  meta:       Sparkles,
  whois:      FileText,
  dns:        Server,
  subdomains: Network,
  wayback:    History,
  emails:     Mail,
  github:     Code2,
  dorks:      Search,
  threat:     ShieldAlert,
  asn:        Globe,
  abuseipdb:  AlertTriangle,
  pivot:      Crosshair,
  summary:    CircleDot,
};

const SOURCES: { name: string; icon: LucideIcon }[] = [
  { name: "crt.sh",       icon: ShieldCheck },
  { name: "OTX",          icon: Atom },
  { name: "urlscan",      icon: Eye },
  { name: "RDAP",         icon: FileText },
  { name: "Wayback",      icon: History },
  { name: "Cloudflare DoH", icon: Wifi },
  { name: "BGPView",      icon: Globe },
  { name: "AbuseIPDB",    icon: AlertTriangle },
  { name: "Ahmia",        icon: Crosshair },
];

const FEATURES: { icon: LucideIcon; title: string; body: string; color: string }[] = [
  { icon: Activity, title: "Live streaming", body: "Results stream in via SSE the moment each source returns — no waiting for the slowest API.", color: "#22d3ee" },
  { icon: Layers, title: "13 recon phases", body: "WHOIS, DNS, subdomains, wayback, GitHub, search dorks, threat intel, ASN, abuse — all in one pass.", color: "#a78bfa" },
  { icon: Crosshair, title: "Cross-phase hit index", body: "Every sensitive finding is flagged and indexed in one searchable list across all phases.", color: "#f87171" },
  { icon: Shield, title: "Zero active probing", body: "Pure passive recon. Only third-party datasets, public APIs, and DoH — never touches the target.", color: "#34d399" },
];

// ============================================================================
// Highlight helpers
// ============================================================================

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

let __idxCounter = 0;
function startHighlightFrame() { __idxCounter = 0; }

function highlight(text: string, filter: string): React.ReactNode {
  if (!filter) return text;
  const re = new RegExp(escapeRegExp(filter), "gi");
  const out: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(
      <mark
        key={`m${n++}`}
        className="idx"
        data-idx={__idxCounter++}
      >
        {m[0]}
      </mark>
    );
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++;
  }
  if (last < text.length) out.push(text.slice(last));
  return <>{out}</>;
}

function linkify(s: string, filter: string) {
  return s.split(/(https?:\/\/[^\s)<>"]+)/g).map((part, i) => {
    if (/^https?:\/\//.test(part)) {
      return (
        <a
          key={i}
          href={part}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-300 hover:text-cyan-200 underline-offset-2 hover:underline break-all"
        >
          {highlight(part, filter)}
        </a>
      );
    }
    return <span key={i}>{highlight(part, filter)}</span>;
  });
}

function countOccurrences(text: string, filter: string): number {
  if (!filter) return 0;
  return (text.match(new RegExp(escapeRegExp(filter), "gi")) ?? []).length;
}

function matches(filter: string, ...texts: string[]) {
  if (!filter) return true;
  const q = filter.toLowerCase();
  return texts.some((t) => t.toLowerCase().includes(q));
}

function itemMatches(item: Item, filter: string): boolean {
  switch (item.kind) {
    case "line": return matches(filter, item.text);
    case "kv": return matches(filter, item.key, item.value);
    case "list": return matches(filter, item.title ?? "", ...item.items);
    case "skipped": return matches(filter, item.phase, item.reason);
    case "error": return matches(filter, item.phase, item.message);
    case "summary":
      return matches(filter, ...Object.entries(item.data).flatMap(([k, v]) => [k, String(v)]));
  }
}

function itemMatchCount(item: Item, filter: string): number {
  if (!filter) return 0;
  switch (item.kind) {
    case "line": return countOccurrences(item.text, filter);
    case "kv": return countOccurrences(item.key, filter) + countOccurrences(item.value, filter);
    case "list": {
      let n = countOccurrences(item.title ?? "", filter);
      for (const it of item.items) n += countOccurrences(it, filter);
      return n;
    }
    case "skipped": return countOccurrences(item.phase, filter) + countOccurrences(item.reason, filter);
    case "error": return countOccurrences(item.phase, filter) + countOccurrences(item.message, filter);
    case "summary": {
      let n = 0;
      for (const [k, v] of Object.entries(item.data))
        n += countOccurrences(k, filter) + countOccurrences(String(v), filter);
      return n;
    }
  }
}

function itemHasHit(item: Item): boolean {
  switch (item.kind) {
    case "line": return !!item.hit;
    case "list": return item.hits.size > 0;
    case "skipped":
    case "error": return true;
    default: return false;
  }
}

function itemHitStrings(item: Item): string[] {
  switch (item.kind) {
    case "line": return item.hit ? [item.text] : [];
    case "list": return [...item.hits];
    case "skipped": return [`${item.phase} — ${item.reason}`];
    case "error": return [`${item.phase}: ${item.message}`];
    default: return [];
  }
}

// ============================================================================
// Build phases from event stream
// ============================================================================

function buildPhases(events: ScanEvent[]): Phase[] {
  const phases: Phase[] = [];
  let currentPhase: Phase | null = null;
  let currentSectionTitle = "";

  const ensureSection = (title: string): Section => {
    if (!currentPhase) {
      currentPhase = { id: "meta", title: "Overview", status: "running", sections: [] };
      phases.push(currentPhase);
    }
    let sec = currentPhase.sections.find((s) => s.title === title);
    if (!sec) {
      sec = { title, items: [] };
      currentPhase.sections.push(sec);
    }
    return sec;
  };

  for (const ev of events) {
    switch (ev.type) {
      case "phase":
        currentPhase = phases.find((p) => p.id === ev.id) ?? null;
        if (!currentPhase) {
          currentPhase = { id: ev.id, title: ev.title, status: "running", sections: [] };
          phases.push(currentPhase);
        }
        currentSectionTitle = "";
        break;
      case "section":
        currentSectionTitle = ev.text;
        ensureSection(ev.text);
        break;
      case "banner":
        ensureSection(currentSectionTitle).items.push({ kind: "line", text: ev.text });
        break;
      case "line":
        ensureSection(currentSectionTitle).items.push({ kind: "line", text: ev.text, hit: ev.hit });
        break;
      case "kv":
        ensureSection(currentSectionTitle).items.push({ kind: "kv", key: ev.key, value: ev.value });
        break;
      case "list":
        ensureSection(currentSectionTitle).items.push({
          kind: "list", title: ev.title, items: ev.items, hits: new Set(ev.hits ?? []),
        });
        break;
      case "phase-skipped":
        ensureSection(currentSectionTitle).items.push({ kind: "skipped", phase: ev.phase, reason: ev.reason });
        break;
      case "error":
        ensureSection(currentSectionTitle).items.push({ kind: "error", phase: ev.phase, message: ev.message });
        break;
      case "summary":
        ensureSection(currentSectionTitle).items.push({ kind: "summary", data: ev.data });
        break;
      case "done":
        for (const p of phases) p.status = "done";
        break;
    }
  }

  phases.sort((a, b) => PHASE_ORDER.indexOf(a.id) - PHASE_ORDER.indexOf(b.id));
  return phases;
}

// ============================================================================
// Donut chart (pure SVG)
// ============================================================================

function DonutChart({
  data, size = 220, thickness = 22, onSliceClick, activeId, totalLabel = "findings",
}: {
  data: { id: string; label: string; value: number; color: string }[];
  size?: number;
  thickness?: number;
  onSliceClick?: (id: string) => void;
  activeId?: string | null;
  totalLabel?: string;
}) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const r = size / 2 - thickness / 2;
  const C = 2 * Math.PI * r;
  const cx = size / 2, cy = size / 2;

  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={thickness} />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize="11" fill="#64748b">no data yet</text>
      </svg>
    );
  }

  const nonZero = data.filter((d) => d.value > 0);
  if (nonZero.length === 1) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={nonZero[0].color} strokeWidth={thickness}
                onClick={() => onSliceClick?.(nonZero[0].id)} style={{ cursor: onSliceClick ? "pointer" : "default" }} />
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize="26" fontWeight="700" fill="#fff">{total}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" fontSize="10" fill="#94a3b8" letterSpacing="0.05em">{totalLabel.toUpperCase()}</text>
      </svg>
    );
  }

  let cumulative = 0;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="block">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={thickness} />
      <g transform={`rotate(-90 ${cx} ${cy})`}>
        {nonZero.map((d) => {
          const offset = (cumulative / total) * C;
          const length = (d.value / total) * C;
          cumulative += d.value;
          const isActive = activeId === d.id;
          const isDimmed = activeId && !isActive;
          return (
            <circle
              key={d.id}
              cx={cx} cy={cy} r={r}
              fill="none"
              stroke={d.color}
              strokeWidth={isActive ? thickness + 4 : thickness}
              strokeDasharray={`${length - 1.2} ${C - length + 1.2}`}
              strokeDashoffset={-offset}
              opacity={isDimmed ? 0.22 : 1}
              onClick={() => onSliceClick?.(d.id)}
              style={{ cursor: onSliceClick ? "pointer" : "default", transition: "opacity 180ms, stroke-width 180ms" }}
            >
              <title>{`${d.label}: ${d.value}`}</title>
            </circle>
          );
        })}
      </g>
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="28" fontWeight="700" fill="#fff">{total}</text>
      <text x={cx} y={cy + 18} textAnchor="middle" fontSize="10" fill="#94a3b8" letterSpacing="0.06em">{totalLabel.toUpperCase()}</text>
    </svg>
  );
}

// ============================================================================
// Small components
// ============================================================================

function Kpi({
  icon: Icon, label, value, sublabel, accent,
}: {
  icon: LucideIcon;
  label: string;
  value: string | number;
  sublabel?: string;
  accent?: string;
}) {
  return (
    <div className="glass rounded-2xl px-5 py-4 relative overflow-hidden">
      {accent && (
        <div
          className="absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-30"
          style={{ background: accent }}
        />
      )}
      <div className="flex items-start justify-between mb-2">
        <span className="text-[11px] uppercase tracking-[0.12em] text-neutral-400">{label}</span>
        <Icon size={16} className="text-neutral-400" />
      </div>
      <div className="text-3xl font-semibold tracking-tight text-white tabular-nums">{value}</div>
      {sublabel && <div className="mt-1 text-xs text-neutral-500">{sublabel}</div>}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      className="opacity-0 group-hover:opacity-100 transition-opacity ml-2 shrink-0 inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-neutral-500 hover:text-cyan-300"
      title="Copy to clipboard"
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? "copied" : "copy"}
    </button>
  );
}

function HitBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md bg-red-500/15 text-red-300 text-[10px] font-semibold tabular-nums border border-red-500/20">
      <Crosshair size={9} />
      {count}
    </span>
  );
}

// ============================================================================
// Main
// ============================================================================

// ============================================================================
// Settings modal — BYO API keys
// ============================================================================
//
// Everything about keys is intentionally ephemeral:
//   • Client: sessionStorage only → keys live for the current tab and are
//     wiped automatically when the tab/window closes. Nothing touches
//     localStorage, IndexedDB, cookies, or any account system — there are no
//     accounts.
//   • Server: keys are read from the POST body, used in-memory for the scan,
//     and discarded. They are never logged, persisted, or echoed back.

const API_KEYS_STORAGE = "recon-web.apiKeys.v1";

interface ApiKeyStore {
  virustotal: string;
  abuseipdb: string;
  otx: string;
}

const EMPTY_KEYS: ApiKeyStore = { virustotal: "", abuseipdb: "", otx: "" };

function loadStoredKeys(): ApiKeyStore {
  if (typeof window === "undefined") return EMPTY_KEYS;
  try {
    // sessionStorage scopes to the tab and is cleared on tab close — keys are
    // temporary by design. We deliberately do NOT use localStorage.
    const raw = window.sessionStorage.getItem(API_KEYS_STORAGE);
    if (!raw) return EMPTY_KEYS;
    const parsed = JSON.parse(raw) as Partial<ApiKeyStore>;
    return {
      virustotal: typeof parsed.virustotal === "string" ? parsed.virustotal : "",
      abuseipdb:  typeof parsed.abuseipdb  === "string" ? parsed.abuseipdb  : "",
      otx:        typeof parsed.otx        === "string" ? parsed.otx        : "",
    };
  } catch {
    return EMPTY_KEYS;
  }
}

interface ApiKeyField {
  id: keyof ApiKeyStore;
  label: string;
  hint: string;
  link: string;
  placeholder: string;
}

const API_KEY_FIELDS: ApiKeyField[] = [
  {
    id: "virustotal",
    label: "VirusTotal",
    hint: "Free key, 500 req/day, 4/min — enables domain report, subdomains, URL & DNS resolutions.",
    link: "https://www.virustotal.com/gui/my-apikey",
    placeholder: "vt_…",
  },
  {
    id: "abuseipdb",
    label: "AbuseIPDB",
    hint: "Free key — enables the per-IP abuse / reports cross-reference.",
    link: "https://www.abuseipdb.com/account/api",
    placeholder: "abuse_…",
  },
  {
    id: "otx",
    label: "AlienVault OTX",
    hint: "Free key — anonymous OTX is heavily rate-limited (often empty).",
    link: "https://otx.alienvault.com/api",
    placeholder: "otx_…",
  },
];

function SettingsModal({
  open,
  initial,
  onClose,
  onSave,
}: {
  open: boolean;
  initial: ApiKeyStore;
  onClose: () => void;
  onSave: (k: ApiKeyStore) => void;
}) {
  const [draft, setDraft] = useState<ApiKeyStore>(initial);
  const [reveal, setReveal] = useState<Record<keyof ApiKeyStore, boolean>>({
    virustotal: false, abuseipdb: false, otx: false,
  });

  // Re-sync the draft whenever the modal is reopened — otherwise a user who
  // cancels and reopens still sees their abandoned edits.
  useEffect(() => {
    if (open) {
      setDraft(initial);
      setReveal({ virustotal: false, abuseipdb: false, otx: false });
    }
  }, [open, initial]);

  // Close on Escape for keyboard parity with the rest of the app.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const clearAll = () => setDraft(EMPTY_KEYS);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="API key settings"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg rounded-2xl border border-white/10 bg-neutral-950 shadow-2xl shadow-black/60"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 py-4 border-b border-white/10 flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-400 to-violet-500 flex items-center justify-center">
            <Key size={14} className="text-black" strokeWidth={2.5} />
          </div>
          <div className="flex-1">
            <div className="text-sm font-semibold text-white">API Keys</div>
            <div className="text-[11px] text-neutral-500">
              Temporary — kept only for this tab, cleared when you close it. Sent per-scan in the request body, never in the URL.
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded-md text-neutral-400 hover:text-white hover:bg-white/10"
            aria-label="Close settings"
          >
            <X size={16} />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4 max-h-[60vh] overflow-y-auto">
          {API_KEY_FIELDS.map((f) => {
            const value = draft[f.id];
            const shown = reveal[f.id];
            return (
              <div key={f.id} className="space-y-1.5">
                <div className="flex items-baseline justify-between">
                  <label className="text-xs font-medium text-neutral-200" htmlFor={`key-${f.id}`}>
                    {f.label}
                  </label>
                  <a
                    href={f.link}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] text-cyan-300/80 hover:text-cyan-200 underline-offset-2 hover:underline"
                  >
                    Get free key ↗
                  </a>
                </div>
                <div className="relative">
                  <input
                    id={`key-${f.id}`}
                    type={shown ? "text" : "password"}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={f.placeholder}
                    value={value}
                    onChange={(e) => setDraft({ ...draft, [f.id]: e.target.value })}
                    className="w-full pl-3 pr-9 py-2 rounded-lg bg-white/5 border border-white/10 outline-none focus:border-cyan-400/60 focus:bg-white/[0.07] focus:ring-2 focus:ring-cyan-400/20 text-xs font-mono placeholder:text-neutral-600"
                  />
                  <button
                    type="button"
                    onClick={() => setReveal({ ...reveal, [f.id]: !shown })}
                    className="absolute right-1.5 top-1/2 -translate-y-1/2 p-1 rounded text-neutral-400 hover:text-white hover:bg-white/10"
                    aria-label={shown ? "Hide key" : "Reveal key"}
                  >
                    {shown ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
                <div className="text-[10px] text-neutral-500 leading-relaxed">{f.hint}</div>
              </div>
            );
          })}

          <div className="text-[10px] text-neutral-500 border-t border-white/5 pt-3 leading-relaxed">
            Leave a field blank to fall back to the server-side env var (if configured) or skip that phase entirely. No accounts; nothing is persisted client- or server-side beyond this tab.
          </div>
        </div>

        <div className="px-5 py-3 border-t border-white/10 flex items-center gap-2">
          <button
            type="button"
            onClick={clearAll}
            className="px-3 py-1.5 rounded-lg text-xs text-neutral-400 hover:text-white hover:bg-white/5 transition"
          >
            Clear all
          </button>
          <div className="flex-1" />
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs border border-white/10 bg-white/5 text-neutral-200 hover:bg-white/[0.08] transition"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onSave(draft)}
            className="px-3 py-1.5 rounded-lg text-xs bg-gradient-to-b from-cyan-400 to-cyan-500 text-black font-medium hover:from-cyan-300 hover:to-cyan-400 transition shadow shadow-cyan-500/20"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Home() {
  const [domain, setDomain] = useState("");
  const [running, setRunning] = useState(false);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [filter, setFilter] = useState("");
  const [hitsOnly, setHitsOnly] = useState(false);
  const [phaseScope, setPhaseScope] = useState<PhaseId | "all">("all");
  const [view, setView] = useState<"phases" | "hits">("phases");
  const [collapsed, setCollapsed] = useState<Set<PhaseId>>(new Set());
  const [scanMeta, setScanMeta] = useState<{ domain: string; startedAt: string } | null>(null);
  const [activeMatch, setActiveMatch] = useState(0);
  const [apiKeys, setApiKeys] = useState<ApiKeyStore>(EMPTY_KEYS);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const scanAbortRef = useRef<AbortController | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const domainRef = useRef<HTMLInputElement | null>(null);
  const contentRef = useRef<HTMLDivElement | null>(null);
  // SSE-event buffer — events accumulate here between paints and get flushed
  // once per animation frame. Without this, each upstream emission triggered a
  // full `setEvents([...prev, ev])` + buildPhases re-run, and a fast phase
  // like wayback (hundreds of items in seconds) would jank the UI badly.
  const eventBufRef = useRef<ScanEvent[]>([]);
  const flushScheduledRef = useRef(false);

  const phases = useMemo(() => {
    const ps = buildPhases(events);
    if (!running && ps.length) ps.forEach((p) => (p.status = "done"));
    return ps;
  }, [events, running]);

  // Hydrate BYO API keys from localStorage on mount. Keys are not used until
  // the user submits a scan.
  useEffect(() => {
    setApiKeys(loadStoredKeys());
  }, []);

  const stop = useCallback(() => {
    scanAbortRef.current?.abort();
    scanAbortRef.current = null;
    setRunning(false);
  }, []);

  // Reset to the empty/home state — used by the brand button.
  const goHome = useCallback(() => {
    scanAbortRef.current?.abort();
    scanAbortRef.current = null;
    setRunning(false);
    setEvents([]);
    setScanMeta(null);
    setDomain("");
    setFilter("");
    setHitsOnly(false);
    setPhaseScope("all");
    setView("phases");
    setCollapsed(new Set());
    // Focus the domain input after the empty state renders.
    setTimeout(() => domainRef.current?.focus(), 0);
  }, []);

  const start = (e?: React.FormEvent) => {
    e?.preventDefault();
    if (running) return;
    const d = domain.trim().toLowerCase();
    if (!d) return;
    eventBufRef.current = [];
    flushScheduledRef.current = false;
    setEvents([]);
    setPhaseScope("all");
    setView("phases");
    setCollapsed(new Set());
    setFilter("");
    setScanMeta({ domain: d, startedAt: new Date().toISOString() });
    setRunning(true);

    const ctl = new AbortController();
    scanAbortRef.current = ctl;

    // Coalesce SSE events: append to a ref buffer, schedule one rAF flush.
    // Dozens of events per frame collapse into one React commit.
    const flush = () => {
      flushScheduledRef.current = false;
      const buf = eventBufRef.current;
      if (buf.length === 0) return;
      eventBufRef.current = [];
      setEvents((prev) => prev.concat(buf));
    };

    const handle = (raw: string) => {
      try {
        const ev = JSON.parse(raw) as ScanEvent;
        eventBufRef.current.push(ev);
        if (!flushScheduledRef.current) {
          flushScheduledRef.current = true;
          requestAnimationFrame(flush);
        }
        if (ev.type === "done") {
          // Flush synchronously so the user doesn't see a delay between
          // "done" landing and the UI marking the scan complete.
          flush();
          stop();
        }
      } catch { /* ignore */ }
    };

    // Only forward keys that are actually populated — keeps the payload small
    // and lets the server cleanly fall back to env vars for missing ones.
    const trimmedKeys: Partial<ApiKeyStore> = {};
    if (apiKeys.virustotal.trim()) trimmedKeys.virustotal = apiKeys.virustotal.trim();
    if (apiKeys.abuseipdb.trim())  trimmedKeys.abuseipdb  = apiKeys.abuseipdb.trim();
    if (apiKeys.otx.trim())        trimmedKeys.otx        = apiKeys.otx.trim();

    (async () => {
      try {
        const resp = await fetch("/api/scan", {
          method: "POST",
          signal: ctl.signal,
          headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
          body: JSON.stringify({ domain: d, keys: trimmedKeys }),
        });
        if (!resp.ok || !resp.body) {
          let msg = `HTTP ${resp.status}`;
          try {
            const data = await resp.json();
            if (data?.message) msg = String(data.message);
          } catch { /* ignore */ }
          handle(JSON.stringify({ type: "error", phase: "scan", message: msg }));
          handle(JSON.stringify({ type: "done" }));
          return;
        }

        // Parse the SSE stream by hand. Each event is separated by "\n\n";
        // we accumulate until we see that boundary, then extract the JSON
        // payload from the `data: …` line.
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const chunk = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const dataLine = chunk
              .split("\n")
              .find((l) => l.startsWith("data:"));
            if (dataLine) handle(dataLine.slice(5).trimStart());
          }
        }
      } catch (err) {
        if ((err as { name?: string })?.name === "AbortError") {
          flush();
          return;
        }
        handle(JSON.stringify({ type: "error", phase: "scan", message: "Network error — scan stream interrupted." }));
      } finally {
        flush();
        stop();
      }
    })();
  };

  useEffect(() => () => scanAbortRef.current?.abort(), []);

  const saveApiKeys = useCallback((next: ApiKeyStore) => {
    setApiKeys(next);
    if (typeof window === "undefined") return;
    try {
      const hasAny = next.virustotal || next.abuseipdb || next.otx;
      if (hasAny) {
        // sessionStorage: lives until the tab closes, scoped to this origin.
        window.sessionStorage.setItem(API_KEYS_STORAGE, JSON.stringify(next));
      } else {
        window.sessionStorage.removeItem(API_KEYS_STORAGE);
      }
    } catch { /* storage may be disabled; settings still apply for this tab */ }
  }, []);

  const apiKeysActive =
    !!apiKeys.virustotal.trim() ||
    !!apiKeys.abuseipdb.trim() ||
    !!apiKeys.otx.trim();

  // ---------- Counts ----------

  const phaseCounts = useMemo(() => {
    const m = new Map<PhaseId, { items: number; hits: number }>();
    for (const p of phases) {
      let items = 0, hits = 0;
      for (const s of p.sections) for (const it of s.items) {
        items++;
        if (itemHasHit(it)) hits++;
      }
      m.set(p.id, { items, hits });
    }
    return m;
  }, [phases]);

  const totals = useMemo(() => {
    let items = 0, hits = 0;
    for (const c of phaseCounts.values()) { items += c.items; hits += c.hits; }
    return { items, hits };
  }, [phaseCounts]);

  const matchCount = useMemo(() => {
    if (!filter) return 0;
    let n = 0;
    for (const p of phases) for (const s of p.sections) for (const it of s.items) {
      n += itemMatchCount(it, filter);
    }
    return n;
  }, [phases, filter]);

  const pieData = useMemo(
    () => phases.map((p) => ({
      id: p.id, label: p.title,
      value: phaseCounts.get(p.id)?.items ?? 0,
      color: PHASE_COLORS[p.id],
    })),
    [phases, phaseCounts]
  );

  const visiblePhases = useMemo(
    () => phases.filter((p) => phaseScope === "all" || p.id === phaseScope),
    [phases, phaseScope]
  );

  const flatHits = useMemo(() => {
    const out: { phaseId: PhaseId; phaseTitle: string; section: string; text: string }[] = [];
    for (const p of phases) {
      for (const s of p.sections) {
        for (const it of s.items) {
          for (const t of itemHitStrings(it)) {
            out.push({ phaseId: p.id, phaseTitle: p.title, section: s.title, text: t });
          }
        }
      }
    }
    return out;
  }, [phases]);

  const visibleHits = useMemo(
    () => flatHits.filter((h) => matches(filter, h.text, h.phaseTitle, h.section)),
    [flatHits, filter]
  );

  // ---------- Match navigation (n/N) ----------

  useEffect(() => { setActiveMatch(0); }, [filter]);

  useEffect(() => {
    if (!filter) return;
    const root = contentRef.current;
    if (!root) return;
    const marks = Array.from(root.querySelectorAll<HTMLElement>("mark.idx"));
    marks.forEach((el) => el.classList.remove("idx-active"));
    if (marks.length === 0) return;
    const idx = ((activeMatch % marks.length) + marks.length) % marks.length;
    const el = marks[idx];
    if (el) {
      el.classList.add("idx-active");
      el.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }, [filter, activeMatch, phases, view, phaseScope, hitsOnly]);

  // ---------- Keyboard shortcuts ----------

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tgt = e.target as HTMLElement;
      const inField = tgt && (tgt.tagName === "INPUT" || tgt.tagName === "TEXTAREA");

      if (e.key === "/" && !inField) {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
        return;
      }
      if (e.key === "Escape" && document.activeElement === searchRef.current) {
        setFilter("");
        searchRef.current?.blur();
        return;
      }
      if ((e.key === "n" || e.key === "N") && filter && !inField) {
        e.preventDefault();
        setActiveMatch((m) => m + (e.shiftKey ? -1 : 1));
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [filter]);

  const togglePhase = (id: PhaseId) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const [printPreparing, setPrintPreparing] = useState(false);
  const [printError, setPrintError] = useState<string | null>(null);

  const exportReport = async () => {
    if (phases.length === 0 || printPreparing) return;
    setPrintError(null);
    setPrintPreparing(true);

    try {
      const { renderReportPdf } = await import("@/lib/pdf/report");

      const pdfPhases = phases.map((p) => {
        const c = phaseCounts.get(p.id) ?? { items: 0, hits: 0 };
        const hitGroups: { section: string; texts: string[] }[] = [];
        for (const sec of p.sections) {
          const texts: string[] = [];
          for (const it of sec.items) for (const t of itemHitStrings(it)) texts.push(t);
          if (texts.length > 0) hitGroups.push({ section: sec.title, texts });
        }
        return {
          id: p.id,
          title: p.title,
          hits: c.hits,
          items: c.items,
          hitGroups,
        };
      });

      const blob = await renderReportPdf({
        domain: scanMeta?.domain ?? "report",
        startedAt: scanMeta?.startedAt ?? new Date().toISOString(),
        running,
        totals,
        phasesDone: phases.filter((p) => p.status === "done").length,
        phaseCount: phases.length,
        phases: pdfPhases,
      });

      const url = URL.createObjectURL(blob);
      const safeDomain = (scanMeta?.domain ?? "report").replace(/[^a-z0-9.-]/gi, "_");
      const date = new Date().toISOString().slice(0, 10);
      const a = document.createElement("a");
      a.href = url;
      a.download = `recon-${safeDomain}-${date}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setPrintError(msg);
      setTimeout(() => setPrintError(null), 6000);
      console.error("[recon.sh] PDF export failed:", err);
    } finally {
      setPrintPreparing(false);
    }
  };

  // Reset highlight counter once per render frame.
  startHighlightFrame();

  // ---------- Render ----------

  return (
    <>
      <main className="screen-view min-h-screen flex flex-col">
        {/* ============== HEADER ============== */}
        <header className="sticky top-0 z-30 chrome border-b border-white/10 safe-px safe-pt">
          <div className="px-3 sm:px-5 py-2.5 sm:py-3 flex flex-wrap xl:flex-nowrap items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={goHome}
              aria-label="Return to home"
              title="Return to home"
              className="flex items-center gap-2 sm:gap-2.5 rounded-lg px-1 -mx-1 py-0.5 hover:bg-white/[0.04] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/40 transition group shrink-0"
            >
              <div className="relative w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-400 to-violet-500 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:shadow-cyan-500/40 transition">
                <Crosshair size={16} className="text-black" strokeWidth={2.5} />
              </div>
              <div className="leading-tight text-left">
                <div className="text-[15px] font-semibold tracking-tight text-white">recon.sh</div>
                <div className="hidden sm:block text-[10px] text-neutral-500 tracking-wider uppercase">passive osint</div>
              </div>
            </button>

            <div className="hidden lg:flex md:order-2 items-center gap-3 select-none pointer-events-none">
              <span className="h-5 w-px bg-white/10" aria-hidden="true" />
              <div className="font-mono text-[13px] tracking-tight">
                <span className="text-neutral-500">{"//"}</span>{" "}
                <span className="bg-gradient-to-r from-cyan-300 to-violet-300 bg-clip-text text-transparent font-semibold">
                  recon.sh
                </span>{" "}
                <span className="text-neutral-500 italic">— indexed in real-time</span>
              </div>
              <span className="h-5 w-px bg-white/10" aria-hidden="true" />
            </div>

            <div className="flex items-center gap-1.5 sm:gap-2 ml-auto md:ml-0 md:order-5 shrink-0">
              <div className="hidden md:flex items-center rounded-xl border border-white/10 bg-white/5 overflow-hidden text-xs">
                <button
                  onClick={() => setView("phases")}
                  className={`px-3 py-2 inline-flex items-center gap-1.5 transition ${view === "phases" ? "bg-white/10 text-white" : "text-neutral-400 hover:text-white"}`}
                  type="button"
                >
                  <Layers size={13} /> Phases
                </button>
                <button
                  onClick={() => setView("hits")}
                  className={`px-3 py-2 inline-flex items-center gap-1.5 border-l border-white/10 transition ${view === "hits" ? "bg-red-500/15 text-red-200" : "text-neutral-400 hover:text-white"}`}
                  type="button"
                >
                  <Crosshair size={13} /> Hits
                  {totals.hits > 0 && (
                    <span className="ml-1 px-1.5 rounded-md bg-red-500/20 text-red-300 text-[10px] tabular-nums">{totals.hits}</span>
                  )}
                </button>
              </div>

              <button
                type="button"
                onClick={() => setView(view === "phases" ? "hits" : "phases")}
                className={`md:hidden inline-flex items-center gap-1 px-2.5 py-2 rounded-xl border text-xs transition ${
                  view === "hits"
                    ? "bg-red-500/15 border-red-500/30 text-red-200"
                    : "bg-white/5 border-white/10 text-neutral-200 hover:bg-white/[0.08]"
                }`}
                aria-label={view === "phases" ? "Switch to hits view" : "Switch to phases view"}
                title={view === "phases" ? "Hits view" : "Phases view"}
              >
                {view === "phases" ? <Layers size={14} /> : <Crosshair size={14} />}
                {view === "hits" && totals.hits > 0 && (
                  <span className="tabular-nums text-[10px]">{totals.hits}</span>
                )}
              </button>

              <label className="hidden md:flex items-center gap-1.5 text-xs text-neutral-300 select-none px-2 py-2 rounded-xl border border-white/10 bg-white/5 cursor-pointer hover:bg-white/[0.08] transition">
                <Filter size={12} />
                <input type="checkbox" checked={hitsOnly} onChange={(e) => setHitsOnly(e.target.checked)} className="accent-cyan-400" />
                Hits only
              </label>

              <button
                onClick={() => setSettingsOpen(true)}
                type="button"
                className={`relative inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-2 rounded-xl border text-xs transition ${
                  apiKeysActive
                    ? "bg-cyan-500/10 border-cyan-400/40 text-cyan-200 hover:bg-cyan-500/15"
                    : "bg-white/5 border-white/10 text-neutral-200 hover:bg-white/[0.08] hover:border-white/20"
                }`}
                title="Manage API keys (stored locally, never logged)"
                aria-label="API key settings"
              >
                <Key size={13} />
                <span className="hidden lg:inline">Keys</span>
                {apiKeysActive && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-cyan-300 shadow-[0_0_6px_rgba(103,232,249,0.7)]" />
                )}
              </button>

              <button
                onClick={exportReport}
                disabled={phases.length === 0 || printPreparing}
                type="button"
                className="inline-flex items-center gap-1.5 px-2.5 sm:px-3 py-2 rounded-xl border border-white/10 bg-white/5 text-xs hover:bg-white/[0.08] hover:border-white/20 transition disabled:opacity-40 disabled:cursor-not-allowed"
                title="Download report as PDF (no print preview)"
                aria-label="Download PDF report"
              >
                {printPreparing ? (
                  <>
                    <span className="inline-block w-3 h-3 rounded-full border-2 border-cyan-300/40 border-t-cyan-300 animate-spin" />
                    <span className="hidden sm:inline">Saving…</span>
                  </>
                ) : (
                  <>
                    <FileDown size={13} />
                    <span className="hidden sm:inline">Download</span>
                  </>
                )}
              </button>
            </div>

            <form onSubmit={start} className="order-3 md:order-3 flex items-center gap-2 w-full xl:flex-1 xl:w-auto xl:max-w-3xl min-w-0">
              <div className="relative flex-1 min-w-[140px]">
                <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500 pointer-events-none" />
                <input
                  ref={domainRef}
                  className="w-full pl-9 pr-3 py-2 rounded-xl bg-white/5 border border-white/10 outline-none focus:border-cyan-400/60 focus:bg-white/[0.07] focus:ring-2 focus:ring-cyan-400/20 transition text-sm sm:text-base placeholder:text-neutral-500 truncate"
                  placeholder="example.com"
                  style={{ textOverflow: "ellipsis" }}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={running}
                  autoFocus
                  autoComplete="off"
                  autoCorrect="off"
                  autoCapitalize="off"
                  spellCheck={false}
                  inputMode="url"
                />
              </div>
              {!running ? (
                <button
                  type="submit"
                  className="shrink-0 inline-flex items-center gap-1.5 px-3 sm:px-4 py-2 rounded-xl bg-gradient-to-b from-cyan-400 to-cyan-500 text-black text-sm font-medium hover:from-cyan-300 hover:to-cyan-400 transition shadow-lg shadow-cyan-500/20"
                >
                  <Zap size={14} strokeWidth={2.5} />
                  Run scan
                </button>
              ) : (
                <button
                  type="button"
                  onClick={stop}
                  className="shrink-0 inline-flex items-center gap-1.5 px-3 sm:px-4 py-2 rounded-xl bg-red-500/20 border border-red-500/40 text-red-200 text-sm font-medium hover:bg-red-500/30 transition"
                >
                  <Square size={12} strokeWidth={3} fill="currentColor" />
                  Stop
                </button>
              )}
            </form>

            <div className={`order-4 md:order-4 relative w-full xl:w-auto xl:flex-1 xl:max-w-2xl min-w-0 ${phases.length === 0 ? "hidden xl:block" : ""}`}>
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
              <input
                ref={searchRef}
                className="w-full pl-9 pr-24 sm:pr-32 py-2 rounded-xl bg-white/5 border border-white/10 outline-none focus:border-violet-400/60 focus:bg-white/[0.07] focus:ring-2 focus:ring-violet-400/20 transition text-sm placeholder:text-neutral-500"
                placeholder="Index search…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
                {filter ? (
                  <>
                    <span className="text-[10px] tabular-nums text-neutral-400">
                      {matchCount > 0 ? `${(((activeMatch % matchCount) + matchCount) % matchCount) + 1}/${matchCount}` : "0"}
                    </span>
                    <button
                      type="button"
                      onClick={() => setFilter("")}
                      className="p-0.5 rounded hover:bg-white/10 text-neutral-400 hover:text-white"
                      aria-label="Clear search"
                    >
                      <X size={12} />
                    </button>
                  </>
                ) : (
                  <span className="hidden sm:inline kbd">/</span>
                )}
              </div>
            </div>
          </div>

          {printError && (
            <div className="px-3 sm:px-5 py-2 flex items-center gap-2 text-[11px] border-t border-red-500/20 bg-red-500/10 text-red-200">
              <AlertTriangle size={12} />
              PDF export failed: {printError}
              <button
                type="button"
                onClick={() => setPrintError(null)}
                className="ml-auto p-0.5 rounded hover:bg-red-500/20"
                aria-label="Dismiss"
              >
                <X size={12} />
              </button>
            </div>
          )}

          {/* Status strip */}
          {scanMeta && (
            <div className="px-3 sm:px-5 py-2 flex flex-wrap items-center gap-x-4 sm:gap-x-5 gap-y-1 text-[11px] border-t border-white/5 bg-black/20">
              <div className="flex items-center gap-2">
                {running ? (
                  <span className="inline-flex items-center gap-1.5 text-amber-300">
                    <span className="live-dot w-2 h-2 rounded-full bg-amber-400" />
                    SCANNING
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-emerald-300">
                    <Check size={11} strokeWidth={3} />
                    COMPLETE
                  </span>
                )}
                <span className="text-neutral-600">·</span>
                <span className="text-white font-medium tabular-nums">{scanMeta.domain}</span>
              </div>
              <span className="text-neutral-500">Started {new Date(scanMeta.startedAt).toLocaleTimeString()}</span>
              <span className="text-neutral-500 tabular-nums">{totals.items} findings · <span className="text-red-300">{totals.hits} hits</span></span>
              <span className="text-neutral-500 tabular-nums">{phases.filter((p) => p.status === "done").length}/{phases.length} phases done</span>
              {filter && (
                <span className="text-neutral-500 inline-flex items-center gap-1.5">
                  Press <span className="kbd">n</span> next · <span className="kbd">⇧n</span> prev · <span className="kbd">Esc</span> clear
                </span>
              )}
            </div>
          )}
        </header>

        {/* ============== EMPTY STATE ============== */}
        {phases.length === 0 ? (
          <div className="flex-1 overflow-y-auto scroll-thin safe-px">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 sm:py-12 md:py-16">
              {/* Hero */}
              <div className="text-center mb-8 sm:mb-14">
                <h1 className="text-3xl sm:text-4xl md:text-6xl font-semibold tracking-tight text-white mb-3 sm:mb-4 leading-[1.1]">
                  Passive recon, <span className="bg-gradient-to-r from-cyan-300 to-violet-400 bg-clip-text text-transparent">indexed in real-time</span>
                </h1>
                <p className="text-neutral-400 text-sm sm:text-base max-w-2xl mx-auto leading-relaxed px-2 sm:px-0">
                  Type a domain. Watch 13 phases of OSINT data — WHOIS, DNS, subdomains, archives, repos, threat intel — stream into a single searchable index. No probes, no noise.
                </p>
                <button
                  onClick={() => {
                    domainRef.current?.focus();
                    domainRef.current?.select();
                  }}
                  type="button"
                  className="mt-5 sm:mt-6 inline-flex items-center gap-2 px-4 py-2 rounded-xl glass text-sm hover:bg-white/[0.08] transition"
                >
                  <ArrowRight size={14} />
                  Enter a domain to start
                </button>
              </div>

              {/* Feature grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4 mb-8 sm:mb-12">
                {FEATURES.map(({ icon: Icon, title, body, color }) => (
                  <div key={title} className="glass rounded-2xl p-4 sm:p-5 relative overflow-hidden group hover:border-white/20 transition">
                    <div
                      className="absolute -top-12 -right-12 w-40 h-40 rounded-full blur-3xl opacity-20 group-hover:opacity-30 transition"
                      style={{ background: color }}
                    />
                    <div className="relative">
                      <div
                        className="inline-flex items-center justify-center w-10 h-10 rounded-xl mb-3 border border-white/10"
                        style={{ background: `${color}15`, color }}
                      >
                        <Icon size={18} />
                      </div>
                      <h3 className="text-base font-semibold text-white mb-1">{title}</h3>
                      <p className="text-sm text-neutral-400 leading-relaxed">{body}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Trust strip */}
              <div className="glass rounded-2xl p-4 sm:p-5">
                <div className="flex items-start sm:items-center justify-between mb-3 sm:mb-4 gap-3">
                  <div className="min-w-0">
                    <div className="text-xs uppercase tracking-[0.14em] text-neutral-500 mb-0.5">Sources</div>
                    <div className="text-xs sm:text-sm text-neutral-300">Aggregated public datasets — zero direct contact with the target</div>
                  </div>
                  <Database size={18} className="text-neutral-500 shrink-0" />
                </div>
                <div className="flex flex-wrap gap-1.5 sm:gap-2">
                  {SOURCES.map(({ name, icon: Icon }) => (
                    <span key={name} className="inline-flex items-center gap-1.5 px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-lg bg-white/5 border border-white/10 text-[11px] sm:text-xs text-neutral-300">
                      <Icon size={12} className="text-neutral-400" />
                      {name}
                    </span>
                  ))}
                </div>
              </div>

              <footer className="mt-10 sm:mt-14 pt-6 border-t border-white/5 flex flex-wrap items-center justify-between gap-3 text-[11px] sm:text-xs text-neutral-500">
                <div className="flex items-center gap-1.5">
                  <Crosshair size={11} className="text-neutral-600" />
                  <span>recon.sh · passive OSINT · no cookies, no accounts</span>
                </div>
                <nav className="flex items-center gap-3 sm:gap-4">
                  <a href="/privacy" className="hover:text-white transition">Privacy</a>
                  <a href="/cookies" className="hover:text-white transition">Cookies</a>
                  <a
                    href="https://github.com/AmazingMuffin1/recon.sh-web"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-white transition"
                  >
                    GitHub
                  </a>
                </nav>
              </footer>
            </div>
          </div>
        ) : (
          /* ============== DASHBOARD ============== */
          <div className="flex flex-1 overflow-hidden">
            {/* Phase rail — hidden on mobile; a horizontal pill strip above
                the content area takes its place there. */}
            <nav className="hidden md:flex md:flex-col w-64 xl:w-72 shrink-0 border-r border-white/5 overflow-y-auto scroll-thin py-4 px-3">
              <div className="px-2 mb-3 text-[10px] uppercase tracking-[0.14em] text-neutral-500">Navigation</div>
              <button
                onClick={() => { setView("phases"); setPhaseScope("all"); }}
                className={`w-full text-left px-2.5 py-2 rounded-lg mb-1 inline-flex items-center justify-between transition ${
                  view === "phases" && phaseScope === "all"
                    ? "bg-white/10 text-white"
                    : "text-neutral-400 hover:bg-white/5 hover:text-white"
                }`}
              >
                <span className="inline-flex items-center gap-2"><Layers size={14} /> All phases</span>
                <span className="text-[10px] tabular-nums text-neutral-500">{phases.length}</span>
              </button>
              <button
                onClick={() => setView("hits")}
                className={`w-full text-left px-2.5 py-2 rounded-lg mb-3 inline-flex items-center justify-between transition ${
                  view === "hits"
                    ? "bg-red-500/15 text-red-200"
                    : "text-neutral-400 hover:bg-white/5 hover:text-white"
                }`}
              >
                <span className="inline-flex items-center gap-2"><Crosshair size={14} /> Hits index</span>
                <HitBadge count={totals.hits} />
              </button>

              <div className="px-2 mb-2 text-[10px] uppercase tracking-[0.14em] text-neutral-500">Phases</div>
              <div className="space-y-0.5">
                {phases.map((p) => {
                  const c = phaseCounts.get(p.id) ?? { items: 0, hits: 0 };
                  const Icon = PHASE_ICON[p.id];
                  const isActive = view === "phases" && phaseScope === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => { setView("phases"); setPhaseScope(p.id); }}
                      className={`w-full px-2.5 py-2 rounded-lg text-left transition flex items-center gap-2.5 ${
                        isActive ? "bg-white/10 text-white" : "text-neutral-400 hover:bg-white/5 hover:text-neutral-200"
                      }`}
                    >
                      <span className="relative flex items-center justify-center w-5 h-5 shrink-0">
                        <span
                          className="absolute inset-0 rounded-md opacity-30"
                          style={{ background: PHASE_COLORS[p.id] }}
                        />
                        <Icon size={12} className="relative" style={{ color: PHASE_COLORS[p.id] }} />
                      </span>
                      <span className="flex-1 truncate text-[13px]">{p.title}</span>
                      {p.status === "running" && (
                        <span className="live-dot w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0" />
                      )}
                      <HitBadge count={c.hits} />
                      <span className="text-[10px] tabular-nums text-neutral-600 shrink-0 min-w-[1.5rem] text-right">{c.items}</span>
                    </button>
                  );
                })}
              </div>
            </nav>

            {/* Content */}
            <div ref={contentRef} className="flex-1 overflow-y-auto scroll-thin">
              {/* Mobile-only horizontal phase rail. Scrolls left-right so the
                  full list is reachable without eating vertical space. */}
              <div className="md:hidden sticky top-0 z-10 chrome border-b border-white/5 overflow-x-auto scroll-thin">
                <div className="flex items-center gap-1.5 px-3 py-2 min-w-max">
                  <button
                    type="button"
                    onClick={() => { setView("phases"); setPhaseScope("all"); }}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs whitespace-nowrap transition ${
                      view === "phases" && phaseScope === "all"
                        ? "bg-white/10 text-white"
                        : "text-neutral-400 hover:text-white border border-white/10"
                    }`}
                  >
                    <Layers size={12} /> All
                    <span className="text-[10px] tabular-nums text-neutral-500">{phases.length}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setView("hits")}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs whitespace-nowrap transition ${
                      view === "hits"
                        ? "bg-red-500/15 text-red-200"
                        : "text-neutral-400 hover:text-white border border-white/10"
                    }`}
                  >
                    <Crosshair size={12} /> Hits
                    {totals.hits > 0 && (
                      <span className="text-[10px] tabular-nums">{totals.hits}</span>
                    )}
                  </button>
                  <span className="w-px h-5 bg-white/10 mx-0.5" />
                  {phases.map((p) => {
                    const c = phaseCounts.get(p.id) ?? { items: 0, hits: 0 };
                    const Icon = PHASE_ICON[p.id];
                    const isActive = view === "phases" && phaseScope === p.id;
                    return (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => { setView("phases"); setPhaseScope(p.id); }}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs whitespace-nowrap transition ${
                          isActive
                            ? "bg-white/10 text-white"
                            : "text-neutral-400 hover:text-white border border-white/10"
                        }`}
                      >
                        <Icon size={12} style={{ color: PHASE_COLORS[p.id] }} />
                        <span>{p.title}</span>
                        {p.status === "running" && (
                          <span className="live-dot w-1.5 h-1.5 rounded-full bg-amber-400" />
                        )}
                        {c.hits > 0 && (
                          <span className="text-[10px] tabular-nums text-red-300">{c.hits}</span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="px-3 sm:px-6 py-3 sm:py-5 max-w-[1700px] mx-auto">
                {view === "hits" ? (
                  <HitsView
                    hits={visibleHits}
                    totalHits={flatHits.length}
                    filter={filter}
                    onJumpToPhase={(id) => {
                      setView("phases");
                      setPhaseScope(id);
                      setCollapsed((prev) => { const n = new Set(prev); n.delete(id); return n; });
                    }}
                  />
                ) : (
                  <>
                    {/* Bento dashboard */}
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 mb-6">
                      {/* KPIs */}
                      <div className="lg:col-span-12 grid grid-cols-2 md:grid-cols-4 gap-3">
                        <Kpi
                          icon={Database}
                          label="Findings"
                          value={totals.items}
                          sublabel="across all phases"
                          accent="rgba(34, 211, 238, 0.6)"
                        />
                        <Kpi
                          icon={Crosshair}
                          label="Hits"
                          value={totals.hits}
                          sublabel="sensitive matches"
                          accent="rgba(248, 113, 113, 0.6)"
                        />
                        <Kpi
                          icon={Layers}
                          label="Phases"
                          value={`${phases.filter((p) => p.status === "done").length}/${phases.length}`}
                          sublabel="completed"
                          accent="rgba(167, 139, 250, 0.6)"
                        />
                        <Kpi
                          icon={Activity}
                          label="Status"
                          value={running ? "Running" : "Complete"}
                          sublabel={running ? "streaming…" : "all sources returned"}
                          accent={running ? "rgba(251, 191, 36, 0.6)" : "rgba(52, 211, 153, 0.6)"}
                        />
                      </div>

                      {/* Donut + breakdown */}
                      <div className="lg:col-span-7 glass rounded-2xl p-5">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h3 className="text-sm font-semibold text-white">Findings by phase</h3>
                            <p className="text-xs text-neutral-500 mt-0.5">Click a slice or row to filter</p>
                          </div>
                          {phaseScope !== "all" && (
                            <button
                              onClick={() => setPhaseScope("all")}
                              className="text-xs text-cyan-300 hover:text-cyan-200 inline-flex items-center gap-1"
                            >
                              <X size={11} /> clear
                            </button>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-6">
                          <DonutChart
                            data={pieData}
                            size={200}
                            onSliceClick={(id) => setPhaseScope(id as PhaseId)}
                            activeId={phaseScope === "all" ? null : phaseScope}
                          />
                          <ul className="flex-1 min-w-[220px] space-y-1">
                            {pieData.map((d) => {
                              const pct = totals.items === 0 ? 0 : Math.round((d.value / totals.items) * 100);
                              const isActive = phaseScope === d.id;
                              const Icon = PHASE_ICON[d.id as PhaseId];
                              return (
                                <li
                                  key={d.id}
                                  onClick={() => setPhaseScope(d.id as PhaseId)}
                                  className={`group flex items-center gap-2.5 px-2 py-1.5 rounded-lg cursor-pointer text-sm transition ${
                                    isActive ? "bg-white/10" : "hover:bg-white/5"
                                  }`}
                                >
                                  <Icon size={12} style={{ color: d.color }} />
                                  <span className="flex-1 truncate text-neutral-200">{d.label}</span>
                                  <span className="text-xs text-neutral-500 tabular-nums">
                                    {d.value} <span className="opacity-50">({pct}%)</span>
                                  </span>
                                </li>
                              );
                            })}
                          </ul>
                        </div>
                      </div>

                      {/* Activity bars */}
                      <div className="lg:col-span-5 glass rounded-2xl p-5">
                        <div className="flex items-center justify-between mb-4">
                          <div>
                            <h3 className="text-sm font-semibold text-white">Hit density</h3>
                            <p className="text-xs text-neutral-500 mt-0.5">Hits / total per phase</p>
                          </div>
                          <Crosshair size={14} className="text-neutral-500" />
                        </div>
                        <div className="space-y-2">
                          {phases.map((p) => {
                            const c = phaseCounts.get(p.id) ?? { items: 0, hits: 0 };
                            const pct = c.items === 0 ? 0 : (c.hits / c.items) * 100;
                            const Icon = PHASE_ICON[p.id];
                            return (
                              <button
                                key={p.id}
                                onClick={() => setPhaseScope(p.id)}
                                className="w-full text-left group"
                              >
                                <div className="flex items-center gap-2 text-xs mb-0.5">
                                  <Icon size={11} style={{ color: PHASE_COLORS[p.id] }} />
                                  <span className="flex-1 text-neutral-300 truncate">{p.title}</span>
                                  <span className="text-[10px] tabular-nums text-neutral-500">
                                    {c.hits}<span className="opacity-50"> / {c.items}</span>
                                  </span>
                                </div>
                                <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
                                  <div
                                    className="h-full rounded-full transition-all"
                                    style={{
                                      width: `${pct}%`,
                                      background: pct > 0
                                        ? "linear-gradient(90deg, #f87171, #fb7185)"
                                        : "transparent",
                                    }}
                                  />
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>

                    {/* Phase content */}
                    <AnimatePresence>
                      {visiblePhases.map((phase) => {
                        const visibleSections = phase.sections
                          .map((sec) => {
                            const filtered = sec.items
                              .filter((it) => itemMatches(it, filter))
                              .filter((it) => !hitsOnly || itemHasHit(it));
                            return { ...sec, items: filtered };
                          })
                          .filter((sec) => sec.items.length > 0);
                        if (visibleSections.length === 0 && (filter || hitsOnly)) return null;

                        const isCollapsed = collapsed.has(phase.id);
                        const Icon = PHASE_ICON[phase.id];
                        const c = phaseCounts.get(phase.id) ?? { items: 0, hits: 0 };

                        return (
                          <motion.section
                            key={phase.id}
                            initial={{ opacity: 0, y: 8 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0 }}
                            transition={{ duration: 0.22 }}
                            className="mb-5"
                          >
                            <button
                              type="button"
                              onClick={() => togglePhase(phase.id)}
                              className="w-full glass rounded-2xl px-5 py-3 flex items-center gap-3 hover:bg-white/[0.07] transition group"
                            >
                              {isCollapsed
                                ? <ChevronRight size={14} className="text-neutral-500" />
                                : <ChevronDown size={14} className="text-neutral-500" />}
                              <div
                                className="w-8 h-8 rounded-lg flex items-center justify-center"
                                style={{ background: `${PHASE_COLORS[phase.id]}20`, color: PHASE_COLORS[phase.id] }}
                              >
                                <Icon size={15} />
                              </div>
                              <div className="flex-1 text-left min-w-0">
                                <div className="text-base font-semibold text-white">{highlight(phase.title, filter)}</div>
                                <div className="text-xs text-neutral-500">{phase.sections.length} section{phase.sections.length === 1 ? "" : "s"} · {c.items} item{c.items === 1 ? "" : "s"}</div>
                              </div>
                              {phase.status === "running" && (
                                <span className="inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-amber-300">
                                  <span className="live-dot w-1.5 h-1.5 rounded-full bg-amber-400" />
                                  running
                                </span>
                              )}
                              <HitBadge count={c.hits} />
                            </button>

                            {!isCollapsed && (
                              <div className="mt-2 space-y-2">
                                {visibleSections.length === 0 ? (
                                  <div className="text-neutral-600 text-sm italic px-5 py-3">(no items yet)</div>
                                ) : (
                                  visibleSections.map((sec, i) => (
                                    <Card key={i} title={sec.title} filter={filter}>
                                      {sec.items.map((it, j) => <ItemView key={j} item={it} filter={filter} />)}
                                    </Card>
                                  ))
                                )}
                              </div>
                            )}
                          </motion.section>
                        );
                      })}
                    </AnimatePresence>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </main>

      <SettingsModal
        open={settingsOpen}
        initial={apiKeys}
        onClose={() => setSettingsOpen(false)}
        onSave={(next) => { saveApiKeys(next); setSettingsOpen(false); }}
      />

    </>
  );
}

// ============================================================================
// Hits view
// ============================================================================

function HitsView({
  hits, totalHits, filter, onJumpToPhase,
}: {
  hits: { phaseId: PhaseId; phaseTitle: string; section: string; text: string }[];
  totalHits: number;
  filter: string;
  onJumpToPhase: (id: PhaseId) => void;
}) {
  const grouped = useMemo(() => {
    const m = new Map<PhaseId, { phaseTitle: string; rows: typeof hits }>();
    for (const h of hits) {
      const g = m.get(h.phaseId);
      if (g) g.rows.push(h);
      else m.set(h.phaseId, { phaseTitle: h.phaseTitle, rows: [h] });
    }
    return [...m.entries()].sort(
      (a, b) => PHASE_ORDER.indexOf(a[0]) - PHASE_ORDER.indexOf(b[0])
    );
  }, [hits]);

  return (
    <section>
      <div className="glass rounded-2xl p-5 mb-5">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/20 flex items-center justify-center">
            <Crosshair size={18} className="text-red-300" />
          </div>
          <div className="flex-1">
            <h2 className="text-lg font-semibold text-white">Hits index</h2>
            <p className="text-sm text-neutral-400">
              {hits.length}{filter && hits.length !== totalHits ? ` of ${totalHits}` : ""} sensitive finding{hits.length === 1 ? "" : "s"} across {grouped.length} phase{grouped.length === 1 ? "" : "s"}
            </p>
          </div>
        </div>
      </div>

      {hits.length === 0 ? (
        <div className="glass rounded-2xl px-6 py-10 text-center">
          <Sparkles size={28} className="mx-auto text-neutral-600 mb-3" />
          <div className="text-sm text-neutral-400">
            {totalHits === 0
              ? "No hits surfaced yet. Hits include sensitive subdomains, interesting wayback paths, threat-intel matches, and live repo/dork results."
              : "No hits match your search filter."}
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {grouped.map(([phaseId, { phaseTitle, rows }]) => {
            const Icon = PHASE_ICON[phaseId];
            return (
              <div key={phaseId} className="glass rounded-2xl overflow-hidden">
                <button
                  type="button"
                  onClick={() => onJumpToPhase(phaseId)}
                  className="w-full flex items-center gap-3 px-5 py-3 border-b border-white/5 hover:bg-white/[0.04] transition group"
                >
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{ background: `${PHASE_COLORS[phaseId]}20`, color: PHASE_COLORS[phaseId] }}
                  >
                    <Icon size={14} />
                  </div>
                  <span className="font-medium text-white">{phaseTitle}</span>
                  <span className="text-xs text-neutral-500 ml-auto tabular-nums">{rows.length} hit{rows.length === 1 ? "" : "s"}</span>
                  <ArrowRight size={13} className="text-neutral-500 group-hover:text-cyan-300 group-hover:translate-x-0.5 transition" />
                </button>
                <ul className="divide-y divide-white/5">
                  {rows.map((h, i) => (
                    <li key={i} className="group flex items-start gap-3 px-5 py-2.5 text-[13px] hover:bg-white/[0.03] transition">
                      <span className="w-1 h-4 rounded-full mt-1 shrink-0" style={{ background: PHASE_COLORS[h.phaseId] }} />
                      <span className="text-[10px] uppercase tracking-wider text-neutral-500 mt-1 shrink-0 max-w-[200px] truncate" title={h.section}>
                        {h.section || "—"}
                      </span>
                      <span className="text-red-300 font-medium break-all flex-1 leading-relaxed">
                        {linkify(h.text, filter)}
                      </span>
                      <CopyButton text={h.text} />
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

// ============================================================================
// Card / Items
// ============================================================================

function Card({ title, filter, children }: { title?: string; filter: string; children: React.ReactNode }) {
  return (
    <div className="glass rounded-2xl overflow-hidden">
      {title && (
        <div className="px-5 py-2.5 border-b border-white/5 text-xs uppercase tracking-[0.12em] text-neutral-400 font-medium bg-white/[0.02]">
          {highlight(title, filter)}
        </div>
      )}
      <div className="px-5 py-3 text-[13px] leading-relaxed space-y-1">{children}</div>
    </div>
  );
}

function ItemView({ item, filter }: { item: Item; filter: string }) {
  switch (item.kind) {
    case "line":
      return (
        <div className={`stream-in group flex items-start ${item.hit ? "text-red-300 font-medium" : "text-neutral-200"}`}>
          {item.hit && <Crosshair size={11} className="mr-2 mt-1 shrink-0 text-red-400" />}
          <div className="whitespace-pre-wrap break-words flex-1">
            {linkify(item.text, filter)}
          </div>
          <CopyButton text={item.text} />
        </div>
      );
    case "kv":
      return (
        <div className="stream-in group grid grid-cols-[160px_1fr_auto] gap-3 items-start">
          <div className="text-neutral-500 text-xs uppercase tracking-wider mt-0.5">{highlight(item.key, filter)}</div>
          <div className="break-words text-neutral-200">{linkify(item.value, filter)}</div>
          <CopyButton text={item.value} />
        </div>
      );
    case "list":
      return (
        <div className="stream-in">
          {item.title && (
            <div className="text-neutral-500 text-[10px] uppercase tracking-[0.14em] mb-2 font-medium">
              {highlight(item.title, filter)}
            </div>
          )}
          {item.items.length === 0 ? (
            <div className="text-neutral-600 italic text-xs">(none)</div>
          ) : (
            <ul className="space-y-0.5">
              {item.items.map((it, i) => (
                <li
                  key={i}
                  className={`group flex items-start ${item.hits.has(it) ? "text-red-300 font-medium" : "text-neutral-200"}`}
                >
                  {item.hits.has(it) && <Crosshair size={11} className="mr-2 mt-1 shrink-0 text-red-400" />}
                  <span className="break-all flex-1 leading-relaxed">{linkify(it, filter)}</span>
                  <CopyButton text={it} />
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    case "skipped":
      return (
        <div className="stream-in inline-flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-200 text-xs">
          <SkipForward size={13} className="mt-0.5 shrink-0" />
          <div>
            <div className="font-semibold">{highlight(item.phase, filter)} — SKIPPED</div>
            <div className="text-amber-200/80 mt-0.5">{highlight(item.reason, filter)}</div>
          </div>
        </div>
      );
    case "error":
      return (
        <div className="stream-in inline-flex items-start gap-2 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-200 text-xs">
          <AlertTriangle size={13} className="mt-0.5 shrink-0" />
          <div>
            <span className="font-semibold">{highlight(item.phase, filter)}:</span> {highlight(item.message, filter)}
          </div>
        </div>
      );
    case "summary":
      return (
        <div className="stream-in grid grid-cols-2 md:grid-cols-3 gap-2">
          {Object.entries(item.data).map(([k, v]) => (
            <div key={k} className="px-3 py-2 rounded-lg bg-white/[0.03] border border-white/5">
              <div className="text-[10px] uppercase tracking-wider text-neutral-500 mb-0.5">{highlight(k, filter)}</div>
              <div className="text-base font-semibold tabular-nums text-white">{highlight(String(v), filter)}</div>
            </div>
          ))}
        </div>
      );
  }
}

