import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const jetbrains = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "recon.sh — Passive OSINT",
  description: "Passive OSINT recon with live streaming results and cross-phase hit indexing.",
};

// Mobile rendering: without this, iOS Safari and Android Chrome render the
// page at 980px wide and scale down, making every UI element tiny and
// unusable on phones. `viewportFit: "cover"` opts the page into the
// safe-area-inset CSS env() values so we can avoid the notch / home-indicator
// strip without losing edge-to-edge dark background.
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  viewportFit: "cover",
  themeColor: "#06070b",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrains.variable}`}>
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
