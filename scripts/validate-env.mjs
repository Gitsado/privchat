const backendUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL;

function fail(message) {
  console.error(`Environment validation failed: ${message}`);
  process.exit(1);
}

function exactHttpsOrigin(name, value) {
  if (!value) fail(`${name} is required.`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${name} must be a valid URL.`);
  }
  if (parsed.protocol !== "https:") fail(`${name} must use HTTPS.`);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) fail(`${name} contains forbidden URL parts.`);
  if (parsed.pathname !== "/") fail(`${name} must be an origin without a path.`);
  return parsed.origin;
}

exactHttpsOrigin("NEXT_PUBLIC_SUPABASE_URL", backendUrl);

if (!publishableKey) fail("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY is required.");
if (publishableKey.startsWith("sb_secret_")) fail("A secret backend key cannot be exposed to the browser.");
if (!publishableKey.startsWith("sb_publishable_")) {
  const parts = publishableKey.split(".");
  if (parts.length !== 3) fail("The browser key must be a publishable key or an anon JWT.");
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (payload.role !== "anon") fail("Only an anon JWT can be used in the browser.");
  } catch {
    fail("The browser key is not a valid anon JWT.");
  }
}

if (process.env.PRIVCHAT_VERCEL_BUILD === "1" || process.env.VERCEL === "1" || siteUrl) {
  exactHttpsOrigin("NEXT_PUBLIC_SITE_URL", siteUrl);
}

console.log("Environment validation passed.");
