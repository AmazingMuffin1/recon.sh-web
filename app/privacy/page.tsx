import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, ShieldCheck } from "lucide-react";

export const metadata: Metadata = {
  title: "Privacy Policy — recon.sh",
  description: "How recon.sh handles (and doesn't store) your data.",
};

const LAST_UPDATED = "2026-05-28";

export default function PrivacyPage() {
  return (
    <main className="min-h-screen flex flex-col safe-px safe-pt">
      <div className="max-w-3xl mx-auto w-full px-4 sm:px-6 py-8 sm:py-12">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-neutral-400 hover:text-white mb-6 transition"
        >
          <ArrowLeft size={12} /> Back to recon.sh
        </Link>

        <div className="flex items-center gap-3 mb-2">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-400 to-violet-500 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <ShieldCheck size={18} className="text-black" strokeWidth={2.5} />
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">Privacy Policy</h1>
        </div>
        <p className="text-xs text-neutral-500 mb-8">Last updated: {LAST_UPDATED}</p>

        <div className="prose prose-invert prose-sm sm:prose-base max-w-none space-y-6 text-neutral-300 leading-relaxed">
          <Section title="Summary">
            <p>
              recon.sh is a stateless, in-browser passive OSINT tool. There are no accounts,
              no tracking cookies, no analytics, no advertising, and no database. We do not
              build profiles of visitors. The shortest accurate version of this policy is:
              we do not store your personal data because we do not collect it.
            </p>
          </Section>

          <Section title="Who we are">
            <p>
              recon.sh is an open-source project. The service is hosted at{" "}
              <a className="text-cyan-300 hover:text-cyan-200" href="https://recon-sh.com">https://recon-sh.com</a>.
              The source code is publicly available at{" "}
              <a
                className="text-cyan-300 hover:text-cyan-200"
                href="https://github.com/AmazingMuffin1/recon.sh-web"
                target="_blank"
                rel="noopener noreferrer"
              >
                github.com/AmazingMuffin1/recon.sh-web
              </a>
              . For privacy-related questions you can open an issue on the repository or email{" "}
              <a className="text-cyan-300 hover:text-cyan-200" href="mailto:privacy@recon-sh.com">privacy@recon-sh.com</a>.
            </p>
          </Section>

          <Section title="What we do not collect">
            <ul className="list-disc pl-5 space-y-1">
              <li>No account information (there are no accounts).</li>
              <li>No cookies of any kind. See the <Link className="text-cyan-300 hover:text-cyan-200" href="/cookies">Cookie Policy</Link> for details.</li>
              <li>No analytics (Google Analytics, Plausible, PostHog, Fathom, etc. — none).</li>
              <li>No advertising or tracking pixels.</li>
              <li>No fingerprinting.</li>
              <li>No persistent storage of the domains you scan.</li>
            </ul>
          </Section>

          <Section title="What we process, and only briefly">
            <p>
              When you submit a scan request, the following data is processed in memory for
              the duration of that single request, then discarded:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li><strong className="text-white">The domain you typed.</strong> Used to query third-party OSINT datasets (RDAP, DNS-over-HTTPS, certificate transparency, archive.org, etc.). Not written to disk.</li>
              <li><strong className="text-white">Optional API keys you paste in the Settings panel.</strong> Sent in the POST request body, attached as outbound headers to the relevant upstream service, and discarded when the request ends. Never logged. Never persisted server-side.</li>
              <li><strong className="text-white">Your IP address.</strong> Available to the server only via the hosting provider&apos;s standard request headers. Used solely for in-memory rate limiting (token-bucket counters that exist only inside a warm function instance). We do not store IP addresses to disk or share them with anyone.</li>
            </ul>
          </Section>

          <Section title="What stays only in your browser">
            <p>
              If you save API keys via the Settings (Keys) panel, those values are written to
              your browser&apos;s <code className="px-1 py-0.5 rounded bg-white/5 border border-white/10 text-cyan-200 text-[0.9em]">sessionStorage</code>. That data:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Lives only inside the current browser tab.</li>
              <li>Is automatically wiped when you close the tab or window.</li>
              <li>Is never transmitted to us except as needed to perform a scan you triggered.</li>
              <li>Is not a cookie and is not accessible to other websites.</li>
            </ul>
          </Section>

          <Section title="Third-party services">
            <p>
              When you run a scan, our server makes outbound HTTPS requests to public OSINT
              sources on your behalf (a non-exhaustive list: rdap.org, crt.sh, hackertarget,
              AlienVault OTX, ThreatMiner, urlscan.io, ahmia, web.archive.org, gravatar.com,
              api.github.com, html.duckduckgo.com, bgpview.io, shodan.io InternetDB, and —
              if you provide the relevant API key — VirusTotal and AbuseIPDB). Each provider
              has its own privacy policy. The only data we share with them is the domain you
              entered (or IP addresses we derive from it during the scan).
            </p>
            <p>
              We do not embed third-party scripts, fonts, or content from any of those
              services on the page you see. The browser only talks to recon.sh itself.
            </p>
          </Section>

          <Section title="Hosting and infrastructure processor">
            <p>
              The site is hosted on Vercel Inc. As an infrastructure provider, Vercel
              processes standard request metadata at the platform level — timestamp,
              request path, response status, user-agent, and the client IP address that
              connected to its edge network — for the purposes of routing traffic,
              capacity planning, abuse detection, and incident response. We have not
              instrumented any additional logging on top of that; we do not query,
              export, ship to a SIEM, or otherwise use those logs to build a profile of
              you.
            </p>
            <p>
              Vercel acts as a <em>processor</em> for the personal data it handles on
              our behalf. The terms governing that relationship — including the security
              measures Vercel applies, the categories of data processed, and the
              applicable retention periods — are set out in Vercel&apos;s Data Processing
              Addendum, which we have entered into by operating on the platform. The
              authoritative documents are linked below; if Vercel updates them, the
              linked version is what applies.
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>
                <a
                  className="text-cyan-300 hover:text-cyan-200"
                  href="https://vercel.com/legal/privacy-policy"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Vercel Privacy Policy
                </a>
              </li>
              <li>
                <a
                  className="text-cyan-300 hover:text-cyan-200"
                  href="https://vercel.com/legal/dpa"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Vercel Data Processing Addendum (DPA)
                </a>{" "}
                — incorporates the EU Standard Contractual Clauses for transfers outside
                the EEA/UK; specifies log retention windows.
              </li>
              <li>
                <a
                  className="text-cyan-300 hover:text-cyan-200"
                  href="https://vercel.com/legal/subprocessors"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Vercel Subprocessor List
                </a>
              </li>
            </ul>
            <p className="text-xs text-neutral-500">
              In short: Vercel keeps platform logs only as long as their published
              retention period requires, we add no logging of our own, and the
              authoritative figures live in the documents above rather than being
              restated (and potentially going stale) here.
            </p>
          </Section>

          <Section title="Legal basis (GDPR)">
            <p>
              For visitors in the European Economic Area, United Kingdom, and Switzerland:
              the limited, transient processing described above relies on our{" "}
              <em>legitimate interest</em> (Article 6(1)(f) GDPR) in operating and protecting
              the service from abuse. Where you voluntarily paste API keys into the Settings
              panel, processing of those keys relies on your <em>consent</em> (Article 6(1)(a)
              GDPR), which you withdraw simply by clearing the field or closing the tab.
            </p>
          </Section>

          <Section title="Your rights">
            <p>
              The GDPR gives you the following rights. Because we do not maintain
              identified records of users, several of them have nothing concrete to act
              on for the data we process — we list them all explicitly so you can see
              that and exercise any that apply.
            </p>
            <ul className="list-disc pl-5 space-y-1.5">
              <li>
                <strong className="text-white">Access (Art. 15)</strong>, <strong className="text-white">rectification (Art. 16)</strong>, <strong className="text-white">erasure (Art. 17)</strong>, <strong className="text-white">portability (Art. 20)</strong>, <strong className="text-white">restriction (Art. 18)</strong> — there is no stored profile of you to retrieve, correct, export, delete, or restrict. The only personal data we ever touch (your IP and the domain you submitted) is processed in memory for the duration of a single request and is not retained by us afterwards. Vercel platform logs are addressed in the Hosting section above and are subject to their DPA.
              </li>
              <li>
                <strong className="text-white">Right to object (Art. 21)</strong> — you may object at any time to processing carried out on legitimate-interest grounds. The only such processing we perform is short-lived rate-limiting that uses your IP address to prevent abuse. Because preventing fraud and securing the service are themselves recognised by the GDPR as compelling legitimate interests (Recital 47, 49), we may continue that specific processing where strictly necessary to protect the service; you can in any case stop all processing immediately by not submitting further scans, or write to <a className="text-cyan-300 hover:text-cyan-200" href="mailto:privacy@recon-sh.com">privacy@recon-sh.com</a> and we will discuss your specific situation.
              </li>
              <li>
                <strong className="text-white">Withdraw consent (Art. 7(3))</strong> — for the only consent-based processing we perform (API keys you paste into Settings), you withdraw consent simply by clearing the field or closing the tab. We cannot retain those keys against your wishes because we never wrote them anywhere persistent in the first place.
              </li>
              <li>
                <strong className="text-white">Lodge a complaint</strong> — you always have the right to complain to your local supervisory authority (the ICO in the UK, the CNIL in France, the AEPD in Spain, etc.). You do not need to contact us first.
              </li>
            </ul>
            <p>
              For any of the above, write to{" "}
              <a className="text-cyan-300 hover:text-cyan-200" href="mailto:privacy@recon-sh.com">privacy@recon-sh.com</a>{" "}
              or open an issue on the{" "}
              <a
                className="text-cyan-300 hover:text-cyan-200"
                href="https://github.com/AmazingMuffin1/recon.sh-web"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub repository
              </a>
              .
            </p>
          </Section>

          <Section title="Children">
            <p>
              recon.sh is a security-research tool and is not directed at children under 16.
              We do not knowingly process data from anyone under 16.
            </p>
          </Section>

          <Section title="International transfers">
            <p>
              Vercel may serve requests from edge locations around the world. The third-party
              OSINT providers we query are based in multiple jurisdictions. By using the
              service you understand that the domain you submit may be forwarded to those
              providers wherever they operate.
            </p>
          </Section>

          <Section title="Changes to this policy">
            <p>
              When this policy changes we update the &quot;Last updated&quot; date at the top.
              Material changes will also be noted in the project&apos;s GitHub commit history,
              which is the canonical, tamper-evident audit trail.
            </p>
          </Section>
        </div>
      </div>
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-base sm:text-lg font-semibold text-white mb-2">{title}</h2>
      <div className="space-y-3 text-sm sm:text-[15px]">{children}</div>
    </section>
  );
}
