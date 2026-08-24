import type { Metadata, Viewport } from "next";
import { connection } from "next/server";
import "./globals.css";

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000";
const description = "Ucdan-uca şifrəli və quraşdırıla bilən şəxsi mesajlaşma tətbiqi.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: { default: "PrivChat — Söhbət səndə qalır", template: "%s | PrivChat" },
  description,
  manifest: "/manifest.webmanifest",
  applicationName: "PrivChat",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg", apple: "/favicon.svg" },
  appleWebApp: { capable: true, title: "PrivChat", statusBarStyle: "black-translucent" },
  formatDetection: { telephone: false },
  openGraph: {
    type: "website",
    siteName: "PrivChat",
    title: "PrivChat — Söhbət səndə qalır",
    description,
    images: [{ url: "/og.png", width: 1733, height: 909, alt: "PrivChat — təhlükəsiz mesajlaşma" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "PrivChat — Söhbət səndə qalır",
    description,
    images: ["/og.png"],
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  themeColor: "#080913",
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  await connection();
  return (
    <html lang="az">
      <body>{children}</body>
    </html>
  );
}
