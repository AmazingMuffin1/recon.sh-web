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
              The source code is publicly available on GitHub. For privacy-related questions
              you can open an issue on the repository or email{" "}
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

          <Section title="Hosting">
            <p>
              The site is hosted on Vercel. Vercel may log standard request metadata
              (timestamp, request path, response status, user-agent, client IP) at the
              infrastructure level — this is outside our control and follows{" "}
              <a className="text-cyan-300 hover:text-cyan-200" href="https://vercel.com/legal/privacy-policy" target="_blank" rel="noopener noreferrer">Vercel&apos;s privacy policy</a>.
              We do not query, export, or otherwise use those logs to build a profile of
              you.
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
              Because we do not maintain identified records of users, most data-subject
              rights (access, rectification, erasure, portability, restriction) have nothing
              to act on — there is no profile of you to retrieve, correct, or export. You
              can nonetheless contact{" "}
              <a className="text-cyan-300 hover:text-cyan-200" href="mailto:privacy@recon-sh.com">privacy@recon-sh.com</a>{" "}
              if you have any question, and you always have the right to lodge a complaint
              with your local data-protection authority.
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
