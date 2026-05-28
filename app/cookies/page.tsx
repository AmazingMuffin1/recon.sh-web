import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft, CircleDot } from "lucide-react";

export const metadata: Metadata = {
  title: "Cookie Policy — recon.sh",
  description: "recon.sh does not use cookies. What we do use, and why no banner.",
};

const LAST_UPDATED = "2026-05-28";

export default function CookiesPage() {
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
            <CircleDot size={18} className="text-black" strokeWidth={2.5} />
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">Cookie Policy</h1>
        </div>
        <p className="text-xs text-neutral-500 mb-8">Last updated: {LAST_UPDATED}</p>

        <div className="space-y-6 text-neutral-300 leading-relaxed">
          <Section title="Short version">
            <p>
              recon.sh does not set any cookies — not first-party, not third-party, not
              analytics, not advertising, not session, not preference. Because there is no
              cookie use, there is no cookie-consent banner; under both the ePrivacy
              Directive and GDPR, consent is only required when cookies (or comparable
              tracking technologies) are actually placed.
            </p>
          </Section>

          <Section title="Why no cookies">
            <p>
              recon.sh is stateless. There are no accounts, no logins, no sessions to keep
              alive, and we do not run analytics or advertising. None of the things cookies
              are typically used for apply here.
            </p>
          </Section>

          <Section title="What we use instead">
            <p>
              If you paste API keys into the Settings (Keys) panel, those values are stored
              in your browser&apos;s{" "}
              <code className="px-1 py-0.5 rounded bg-white/5 border border-white/10 text-cyan-200 text-[0.9em]">sessionStorage</code>{" "}
              under the key{" "}
              <code className="px-1 py-0.5 rounded bg-white/5 border border-white/10 text-cyan-200 text-[0.9em]">recon-web.apiKeys.v1</code>.
              sessionStorage is similar in spirit to a cookie but materially different in scope:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Scoped to a single browser tab.</li>
              <li>Cleared automatically when that tab is closed.</li>
              <li>Never sent on outbound requests automatically (cookies, by contrast, attach to every same-origin request).</li>
              <li>Not accessible to other websites, not accessible to subdomains.</li>
              <li>Only set when you explicitly type something into the Settings form and press Save.</li>
            </ul>
            <p>
              Most data-protection authorities treat strictly-necessary client storage like
              this — storage that the user actively populated to make the service work for
              them — as not requiring consent under the ePrivacy Directive&apos;s &quot;strictly
              necessary&quot; carve-out. We mention it anyway because we&apos;d rather over-explain
              than surprise you.
            </p>
          </Section>

          <Section title="Clearing the storage">
            <p>You can wipe the saved keys at any time by any of:</p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Opening the Settings panel and pressing &quot;Clear all&quot; → Save.</li>
              <li>Closing the browser tab.</li>
              <li>Clearing site data from your browser&apos;s developer tools (Application → Storage).</li>
            </ul>
          </Section>

          <Section title="Third-party content">
            <p>
              recon.sh does not embed third-party scripts, iframes, fonts loaded at runtime,
              or images from other origins on the pages you see. There are no third parties
              setting cookies through us because there are no third parties on the page.
            </p>
            <p>
              When you run a scan, our server queries public OSINT providers on your behalf,
              but those requests happen server-side. Their cookies (if any) never reach your
              browser.
            </p>
          </Section>

          <Section title="If this ever changes">
            <p>
              If at some future point recon.sh introduces any cookie use — for example, an
              optional self-hosted analytics tool — we will (a) update this policy and the
              &quot;Last updated&quot; date, (b) only set the cookie after a clear opt-in, and (c)
              never use it for advertising. The full change history is visible on GitHub.
            </p>
          </Section>

          <Section title="Related">
            <p>
              See also the <Link className="text-cyan-300 hover:text-cyan-200" href="/privacy">Privacy Policy</Link>.
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
