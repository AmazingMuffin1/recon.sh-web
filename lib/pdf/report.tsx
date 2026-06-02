import React from "react";
import {
  Document,
  Font,
  Page,
  StyleSheet,
  Text,
  View,
  pdf,
} from "@react-pdf/renderer";

Font.registerHyphenationCallback((word) =>
  word.length <= 24 ? [word] : (word.match(/.{1,16}/g) ?? [word])
);

const C = {
  bg: "#0a0c12",
  surface: "#13161f",
  border: "#1f2331",
  borderLight: "#2a2f3d",
  text: "#f5f7fb",
  body: "#cbd5e1",
  muted: "#94a3b8",
  subtle: "#64748b",
  hit: "#fca5a5",
  hitBg: "#241115",
  hitBorder: "#5a1d24",
  hitDot: "#ef4444",
  warn: "#fcd34d",
  warnBg: "#1d1710",
  warnBorder: "#5b421d",
  ok: "#86efac",
  okBg: "#0e2118",
  okBorder: "#1f4a37",
  brandFrom: "#22d3ee",
  brandMid: "#a78bfa",
  brandTo: "#f43f5e",
};

export interface PdfPhase {
  id: string;
  title: string;
  hits: number;
  items: number;
  hitGroups: { section: string; texts: string[] }[];
}

export interface PdfReportProps {
  domain: string;
  startedAt: string;
  running: boolean;
  totals: { items: number; hits: number };
  phasesDone: number;
  phaseCount: number;
  phases: PdfPhase[];
}

const s = StyleSheet.create({
  page: {
    backgroundColor: C.bg,
    color: C.body,
    fontFamily: "Helvetica",
    fontSize: 9,
    paddingTop: 38,
    paddingBottom: 44,
    paddingHorizontal: 40,
    lineHeight: 1.45,
  },

  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 4,
  },
  brand: {
    fontSize: 13,
    fontFamily: "Helvetica-Bold",
    color: C.text,
  },
  brandTag: {
    fontSize: 7,
    color: C.muted,
    letterSpacing: 1.6,
    marginTop: 2,
  },
  date: { fontSize: 8.5, color: C.muted },

  h2Wrap: {
    flexDirection: "row",
    alignItems: "baseline",
    marginTop: 14,
    paddingBottom: 4,
    borderBottomWidth: 0.7,
    borderBottomColor: C.border,
  },
  h2: {
    fontSize: 13,
    color: C.text,
    fontFamily: "Helvetica-Bold",
    letterSpacing: -0.2,
  },
  h2Sub: {
    fontSize: 7.5,
    color: C.muted,
    letterSpacing: 1.1,
    marginLeft: 8,
  },

  kvRow: {
    flexDirection: "row",
    paddingVertical: 3.5,
    borderBottomWidth: 0.4,
    borderBottomColor: C.border,
  },
  kvKey: { width: 110, color: C.muted, fontSize: 9 },
  kvVal: { flex: 1, color: C.text, fontSize: 9 },
  kvValMono: {
    flex: 1,
    color: C.text,
    fontSize: 9.5,
    fontFamily: "Courier-Bold",
  },

  pill: {
    fontSize: 7.5,
    paddingVertical: 1.5,
    paddingHorizontal: 6,
    borderRadius: 3,
    borderWidth: 0.6,
    letterSpacing: 0.5,
    alignSelf: "flex-start",
    fontFamily: "Helvetica-Bold",
  },

  table: { marginTop: 6 },
  trHead: {
    flexDirection: "row",
    paddingVertical: 4,
    borderBottomWidth: 0.7,
    borderBottomColor: C.borderLight,
  },
  tr: {
    flexDirection: "row",
    paddingVertical: 3,
    borderBottomWidth: 0.4,
    borderBottomColor: C.border,
  },
  th: {
    fontSize: 7.5,
    color: C.muted,
    letterSpacing: 1.2,
    fontFamily: "Helvetica-Bold",
  },
  td: { fontSize: 9, color: C.body },
  colPhase: { flex: 1 },
  colHits: { width: 50, textAlign: "right" },
  colItems: { width: 50, textAlign: "right", color: C.muted },
  colDensity: { width: 60, textAlign: "right", color: C.muted },

  phaseBlock: { marginTop: 12 },
  phaseHead: {
    flexDirection: "row",
    alignItems: "baseline",
    paddingBottom: 4,
    marginBottom: 5,
    borderBottomWidth: 0.5,
    borderBottomColor: C.borderLight,
  },
  phaseTitle: {
    fontSize: 11,
    color: C.text,
    fontFamily: "Helvetica-Bold",
  },
  phaseHits: { fontSize: 8, color: C.hit, marginLeft: 8 },

  sectionHead: {
    fontSize: 7.5,
    color: C.muted,
    letterSpacing: 1.2,
    fontFamily: "Helvetica-Bold",
    marginTop: 6,
    marginBottom: 3,
  },

  hitRow: {
    flexDirection: "row",
    paddingVertical: 3,
    paddingHorizontal: 7,
    marginBottom: 2,
    backgroundColor: C.hitBg,
    borderLeftWidth: 1.6,
    borderLeftColor: C.hitDot,
  },
  hitText: {
    flex: 1,
    fontSize: 8.5,
    color: C.hit,
    fontFamily: "Helvetica-Bold",
  },

  footer: {
    position: "absolute",
    bottom: 16,
    left: 40,
    right: 40,
    flexDirection: "row",
    justifyContent: "space-between",
    fontSize: 7.5,
    color: C.subtle,
  },
  stripe: {
    position: "absolute",
    bottom: 0,
    left: 0,
    right: 0,
    height: 2,
    flexDirection: "row",
  },
});

function Pill({
  tone,
  children,
}: {
  tone: "hit" | "ok" | "warn";
  children: string;
}) {
  const palette =
    tone === "hit"
      ? { color: C.hit, bg: C.hitBg, border: C.hitBorder }
      : tone === "warn"
      ? { color: C.warn, bg: C.warnBg, border: C.warnBorder }
      : { color: C.ok, bg: C.okBg, border: C.okBorder };
  return (
    <Text
      style={[
        s.pill,
        {
          color: palette.color,
          backgroundColor: palette.bg,
          borderColor: palette.border,
        },
      ]}
    >
      {children.toUpperCase()}
    </Text>
  );
}

function H2({ title, sub }: { title: string; sub?: string }) {
  return (
    <View style={s.h2Wrap} wrap={false}>
      <Text style={s.h2}>{title}</Text>
      {sub && <Text style={s.h2Sub}>{sub.toUpperCase()}</Text>}
    </View>
  );
}

function KvRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <View style={s.kvRow} wrap={false}>
      <Text style={s.kvKey}>{label}</Text>
      <View style={{ flex: 1 }}>{children}</View>
    </View>
  );
}

export function ReportPdf(props: PdfReportProps) {
  const { domain, startedAt, running, totals, phasesDone, phaseCount, phases } =
    props;
  const dateStr = new Date(startedAt).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  const hitPhases = phases.filter((p) => p.hits > 0);

  return (
    <Document
      title={`recon.sh — ${domain}`}
      author="recon.sh"
      subject="Passive OSINT report"
      creator="recon.sh"
      producer="recon.sh"
    >
      <Page size="A4" style={s.page} wrap>
        <View style={s.header} fixed>
          <View>
            <Text style={s.brand}>recon.sh</Text>
            <Text style={s.brandTag}>PASSIVE OSINT REPORT</Text>
          </View>
          <Text style={s.date}>{dateStr}</Text>
        </View>

        <H2 title="Summary" />
        <View>
          <KvRow label="Target">
            <Text style={s.kvValMono}>{domain}</Text>
          </KvRow>
          <KvRow label="Analysis date">
            <Text style={s.kvVal}>{dateStr}</Text>
          </KvRow>
          <KvRow label="Verdict">
            {totals.hits > 0 ? (
              <Pill tone="hit">{`${totals.hits} sensitive finding${
                totals.hits === 1 ? "" : "s"
              }`}</Pill>
            ) : (
              <Pill tone="ok">Clean</Pill>
            )}
          </KvRow>
          <KvRow label="Status">
            {running ? (
              <Pill tone="warn">Partial</Pill>
            ) : (
              <Pill tone="ok">Complete</Pill>
            )}
          </KvRow>
          <KvRow label="Phases">
            <Text style={s.kvVal}>
              {phasesDone}/{phaseCount} completed
            </Text>
          </KvRow>
          <KvRow label="Findings">
            <Text style={s.kvVal}>{totals.items} total</Text>
          </KvRow>
          <KvRow label="Methodology">
            <Text style={s.kvVal}>
              Passive recon only — no direct contact with the target.
            </Text>
          </KvRow>
        </View>

        <H2 title="Phase breakdown" sub="hits / items" />
        <View style={s.table}>
          <View style={s.trHead} wrap={false}>
            <Text style={[s.th, s.colPhase]}>Phase</Text>
            <Text style={[s.th, s.colHits]}>Hits</Text>
            <Text style={[s.th, s.colItems]}>Items</Text>
            <Text style={[s.th, s.colDensity]}>Density</Text>
          </View>
          {phases.map((p) => {
            const pct =
              p.items === 0
                ? "—"
                : `${Math.round((p.hits / p.items) * 100)}%`;
            const hitsCellStyle = [
              s.td,
              s.colHits,
              p.hits > 0
                ? { color: C.hit, fontFamily: "Helvetica-Bold" as const }
                : { color: C.body },
            ];
            return (
              <View style={s.tr} wrap={false} key={p.id}>
                <Text style={[s.td, s.colPhase]}>{p.title}</Text>
                <Text style={hitsCellStyle}>{p.hits}</Text>
                <Text style={[s.td, s.colItems]}>{p.items}</Text>
                <Text style={[s.td, s.colDensity]}>
                  {p.hits > 0 ? pct : "—"}
                </Text>
              </View>
            );
          })}
        </View>

        {hitPhases.length > 0 ? (
          <>
            <H2
              title="Sensitive findings"
              sub={`${totals.hits} hit${totals.hits === 1 ? "" : "s"} · ${
                hitPhases.length
              } phase${hitPhases.length === 1 ? "" : "s"}`}
            />
            {hitPhases.map((p) => (
              <View
                key={p.id}
                style={s.phaseBlock}
                minPresenceAhead={48}
              >
                <View style={s.phaseHead} wrap={false}>
                  <Text style={s.phaseTitle}>{p.title}</Text>
                  <Text style={s.phaseHits}>
                    {p.hits} hit{p.hits === 1 ? "" : "s"}
                  </Text>
                </View>
                {p.hitGroups.map((g, gi) => (
                  <View key={gi} minPresenceAhead={26}>
                    {g.section ? (
                      <Text style={s.sectionHead}>{g.section}</Text>
                    ) : null}
                    {g.texts.map((t, ti) => (
                      <View key={ti} style={s.hitRow} wrap={false}>
                        <Text style={s.hitText}>{t}</Text>
                      </View>
                    ))}
                  </View>
                ))}
              </View>
            ))}
          </>
        ) : (
          <>
            <H2 title="Sensitive findings" />
            <View style={{ paddingVertical: 8 }}>
              <Text style={{ fontSize: 9, color: C.subtle, fontStyle: "italic" }}>
                No sensitive findings surfaced for this target.
              </Text>
            </View>
          </>
        )}

        <View style={s.footer} fixed>
          <Text>recon.sh · passive OSINT · zero active probing</Text>
          <Text
            render={({ pageNumber, totalPages }) =>
              `Page ${pageNumber} / ${totalPages}`
            }
          />
        </View>
        <View style={s.stripe} fixed>
          <View style={{ flex: 1, backgroundColor: C.brandFrom }} />
          <View style={{ flex: 1, backgroundColor: C.brandMid }} />
          <View style={{ flex: 1, backgroundColor: C.brandTo }} />
        </View>
      </Page>
    </Document>
  );
}

export async function renderReportPdf(props: PdfReportProps): Promise<Blob> {
  return pdf(<ReportPdf {...props} />).toBlob();
}
