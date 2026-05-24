/** @type {import('next').NextConfig} */

// Content-Security-Policy
//
// Notes:
// - 'unsafe-inline' for style-src is required because framer-motion injects
//   inline `style="..."` attributes for animations and we use inline style
//   props in print/SVG.
// - 'unsafe-inline' for script-src is needed for Next.js's hydration runtime
//   inline bootstrap. Migrating to a nonce-based CSP would require a custom
//   middleware; not worth the complexity for this app.
// - 'unsafe-eval' is added ONLY in development because React DevTools / fast
//   refresh use eval() to reconstruct stack traces. React itself never uses
//   eval in production builds, so it's stripped out of the CSP for prod.
// - connect-src in dev allows webpack-hmr WebSocket connections; prod is
//   restricted to self because the only network call from the browser is the
//   SSE endpoint at /api/scan. All upstream OSINT calls happen server-side
//   and never expose those origins to the client.
const isDev = process.env.NODE_ENV !== "production";

const csp = [
  "default-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "style-src 'self' 'unsafe-inline'",
  isDev
    ? "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
    : "script-src 'self' 'unsafe-inline'",
  isDev ? "connect-src 'self' ws: wss:" : "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];

const nextConfig = {
  reactStrictMode: true,
  // Hide the floating Next.js dev-tools indicator in dev mode.
  devIndicators: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};
export default nextConfig;
