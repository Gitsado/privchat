import { NextRequest, NextResponse } from "next/server";

const permissionsPolicy = [
  "accelerometer=()",
  "ambient-light-sensor=()",
  "autoplay=()",
  "battery=()",
  "browsing-topics=()",
  "camera=()",
  "display-capture=()",
  "document-domain=()",
  "encrypted-media=()",
  "geolocation=()",
  "gyroscope=()",
  "join-ad-interest-group=()",
  "magnetometer=()",
  "microphone=()",
  "midi=()",
  "payment=()",
  "picture-in-picture=()",
  "publickey-credentials-get=()",
  "run-ad-auction=()",
  "screen-wake-lock=()",
  "usb=()",
  "xr-spatial-tracking=()",
].join(", ");

function connectionOrigins() {
  const value = process.env.NEXT_PUBLIC_SUPABASE_URL;
  if (!value) return "";
  try {
    const origin = new URL(value).origin;
    if (!origin.startsWith("https://")) return "";
    return `${origin} ${origin.replace("https://", "wss://")}`;
  } catch {
    return "";
  }
}

function contentSecurityPolicy(nonce: string) {
  const connections = connectionOrigins();
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "script-src-attr 'none'",
    "style-src 'self'",
    "style-src-attr 'none'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src 'self'${connections ? ` ${connections}` : ""}`,
    "media-src 'self' blob:",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "frame-src 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "upgrade-insecure-requests",
  ].join("; ");
}

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", contentSecurityPolicy(nonce));
  response.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  response.headers.set("Cross-Origin-Resource-Policy", "same-origin");
  response.headers.set("Origin-Agent-Cluster", "?1");
  response.headers.set("Permissions-Policy", permissionsPolicy);
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-DNS-Prefetch-Control", "off");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Permitted-Cross-Domain-Policies", "none");
  response.headers.set("X-XSS-Protection", "0");

  if (request.nextUrl.pathname.startsWith("/chat") || request.nextUrl.pathname.startsWith("/admin")) {
    response.headers.set("Cache-Control", "private, no-store, max-age=0, must-revalidate");
    response.headers.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  }

  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.svg|manifest.webmanifest|og.png|sw.js).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
