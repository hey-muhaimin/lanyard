// Static export for production (`npm run build:static`), served on its own internal domain.
// In dev, Next proxies /ops/* to the control plane's admin listener so the browser sees one origin.
const isExport = process.env.NEXT_OUTPUT === "export";
const api = process.env.LANYARD_API_ORIGIN ?? "http://localhost:8082";

const config = {
  output: isExport ? "export" : undefined,
  trailingSlash: true,
  images: { unoptimized: true },
  reactStrictMode: true,
};

if (!isExport) {
  config.rewrites = async () => [{ source: "/ops/:path*", destination: `${api}/ops/:path*` }];
}

export default config;
