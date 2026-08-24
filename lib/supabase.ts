import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
const supabasePublishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

if (!supabaseUrl || !supabasePublishableKey) {
  throw new Error("NEXT_PUBLIC_SUPABASE_URL və NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY təyin edilməyib.");
}

export const supabase = createClient(supabaseUrl, supabasePublishableKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    flowType: "pkce",
    storageKey: "privchat-auth-v1",
  },
  realtime: {
    params: { eventsPerSecond: 10 },
  },
});
