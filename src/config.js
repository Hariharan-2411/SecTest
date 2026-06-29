// Public configuration. Safe to ship: the Supabase anon key is a public,
// RLS-guarded key by design. Replace the placeholders with your project's
// values (Supabase dashboard → Project Settings → API), and EDGE_FN_URL with
// your deployed groq-proxy Edge Function URL (added in a later step).

export const SUPABASE_URL = 'https://YOUR-PROJECT-REF.supabase.co';
export const SUPABASE_ANON_KEY = 'YOUR-SUPABASE-ANON-KEY';

// e.g. https://YOUR-PROJECT-REF.supabase.co/functions/v1/groq-proxy
export const EDGE_FN_URL = 'https://YOUR-PROJECT-REF.supabase.co/functions/v1/groq-proxy';

// True once the placeholders above have been replaced with real values.
export const isConfigured = () =>
  !SUPABASE_URL.includes('YOUR-PROJECT-REF') &&
  !SUPABASE_ANON_KEY.includes('YOUR-SUPABASE-ANON-KEY');
