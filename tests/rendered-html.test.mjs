import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

const require = createRequire(import.meta.url);
const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const nextBin = require.resolve("next/dist/bin/next");
const port = 44000 + (process.pid % 1000);
let server;
let serverOutput = "";

before(async () => {
  server = spawn(process.execPath, [nextBin, "start", "-p", String(port)], {
    cwd: projectRoot,
    env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  server.stdout.on("data", (chunk) => { serverOutput += chunk.toString(); });
  server.stderr.on("data", (chunk) => { serverOutput += chunk.toString(); });

  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`Next server stopped early:\n${serverOutput}`);
    try {
      const response = await fetch(`http://127.0.0.1:${port}/`);
      if (response.ok) return;
    } catch {
      // The server is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Next server did not become ready:\n${serverOutput}`);
}, { timeout: 30_000 });

after(() => {
  server?.kill();
});

async function render(path = "/") {
  const response = await fetch(`http://127.0.0.1:${port}${path}`);
  return { response, html: await response.text() };
}

test("renders the landing page with a nonce-bound strict CSP", async () => {
  const { response, html } = await render();
  assert.equal(response.status, 200);
  assert.match(html, /<html lang="az">/i);
  assert.match(html, /<title>PrivChat — Söhbət səndə qalır<\/title>/i);
  assert.match(html, /Söhbət səndə/);
  assert.match(html, /Minimum metadata/);
  assert.match(html, /manifest\.webmanifest/);
  assert.match(html, /Tətbiqi endir/);
  assert.doesNotMatch(html, /Supabase|Realtime|Canlı və sürətli/i);

  const csp = response.headers.get("content-security-policy") ?? "";
  assert.match(csp, /script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  assert.match(csp, /script-src-attr 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
  assert.ok(nonce);
  assert.match(html, new RegExp(`nonce=["']${nonce}["']`));
  const scriptTags = [...html.matchAll(/<script\b[^>]*>/gi)].map((match) => match[0]);
  assert.ok(scriptTags.length > 0);
  assert.ok(scriptTags.every((tag) => new RegExp(`nonce=["']${nonce}["']`).test(tag)));
  assert.doesNotMatch(csp, /\*\./);
  const secondCsp = (await render()).response.headers.get("content-security-policy") ?? "";
  assert.notEqual(secondCsp.match(/'nonce-([^']+)'/)?.[1], nonce);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
});

test("protects chat and admin responses from caching and indexing", async () => {
  const [{ response: chatResponse, html: chatHtml }, { response: adminResponse, html: adminHtml }] = await Promise.all([
    render("/chat/"),
    render("/admin/"),
  ]);
  assert.match(chatHtml, /Təhlükəsiz açar hazırlanır/);
  assert.match(chatHtml, /Mesajlar — PrivChat/);
  assert.match(adminHtml, /İcazələr yoxlanılır/);
  assert.match(adminHtml, /İdarəetmə — PrivChat/);
  assert.doesNotMatch(`${chatHtml}${adminHtml}`, /Supabase|Realtime/i);
  for (const response of [chatResponse, adminResponse]) {
    assert.match(response.headers.get("cache-control") ?? "", /no-store/);
    assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
  }
});

test("keeps cryptography, least privilege, abuse controls, and Vercel headers in place", async () => {
  const [cryptoSource, schema, hardening, abuseControls, messenger, admin, proxySource, vercelConfig] = await Promise.all([
    readFile(new URL("../lib/crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../supabase/schema.sql", import.meta.url), "utf8"),
    readFile(new URL("../supabase/migrations/003_final_security_hardening.sql", import.meta.url), "utf8"),
    readFile(new URL("../supabase/migrations/004_abuse_and_privilege_hardening.sql", import.meta.url), "utf8"),
    readFile(new URL("../components/MessengerApp.tsx", import.meta.url), "utf8"),
    readFile(new URL("../components/AdminDashboard.tsx", import.meta.url), "utf8"),
    readFile(new URL("../proxy.ts", import.meta.url), "utf8"),
    readFile(new URL("../vercel.json", import.meta.url), "utf8"),
  ]);

  assert.match(cryptoSource, /ECDH-P256-EPHEMERAL\/HKDF-SHA256\/AES-256-GCM\+ECDSA-P256/);
  assert.match(cryptoSource, /generateKey\([\s\S]*false,[\s\S]*\["sign", "verify"\]/);
  assert.match(cryptoSource, /checkTrustedDevice/);
  assert.match(cryptoSource, /additionalData:\s*encoder\.encode\(aad\)/);
  assert.match(cryptoSource, /invalid_signature/);

  assert.match(schema, /alter table public\.encrypted_messages enable row level security/);
  assert.match(schema, /create table public\.blocks/);
  assert.match(schema, /client_nonce uuid not null/);
  assert.match(hardening, /create or replace function public\.revoke_device/);
  assert.match(hardening, /revoke all on all tables in schema public from anon/);
  assert.doesNotMatch(hardening, /public\.app_role/);
  assert.match(abuseControls, /create or replace function public\.submit_report/);
  assert.match(abuseControls, /message_rate_limit/);
  assert.match(abuseControls, /revoke execute on all functions in schema public/);
  assert.match(abuseControls, /purge_expired_messages/);

  assert.match(messenger, /disappearing_seconds/);
  assert.match(messenger, /submit_report/);
  assert.match(messenger, /verifyDeviceRegistration/);
  assert.match(messenger, /removeDeviceKeys/);
  assert.match(admin, /CSV ixrac/);
  assert.match(admin, /Moderasiya növbəsi/);

  assert.match(proxySource, /strict-dynamic/);
  assert.doesNotMatch(proxySource, /unsafe-inline|unsafe-eval/);
  const vercel = JSON.parse(vercelConfig);
  assert.equal(vercel.framework, "nextjs");
  assert.equal(vercel.public, false);
  assert.ok(vercel.headers.some((rule) => rule.source === "/sw.js"));
  assert.ok(vercel.headers.flatMap((rule) => rule.headers).some((header) => header.key === "Strict-Transport-Security"));
});
