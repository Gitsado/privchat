import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
