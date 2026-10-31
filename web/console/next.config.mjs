// Production build is a static export (`npm run build:static`) that the Go control plane serves
// from the same origin, so the session cookie stays SameSite=Strict and no CORS is needed.
// In dev, Next proxies API paths to the control plane so the browser still sees one origin.
const isExport = process.env.NEXT_OUTPUT === "export";
const api = process.env.LANYARD_API_ORIGIN ?? "http://localhost:8080";

const config = {
  output: isExport ? "export" : undefined,
  trailingSlash: true, // /login/ -> login/index.html, which the Go file server resolves
  images: { unoptimized: true },
  reactStrictMode: true,
};

if (!isExport) {
  config.rewrites = async () =>
    ["auth/:path*", "admin/:path*", "approve", "revoke", "events/:path*", "healthz", "readyz"].map((p) => ({
      source: `/${p}`,
      destination: `${api}/${p}`,
    }));
}

export default config;
