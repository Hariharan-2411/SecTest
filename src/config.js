// Public configuration. Safe to ship: the Supabase anon key is a public,
// RLS-guarded key by design. Replace the placeholders with your project's
// values (Supabase dashboard → Project Settings → API), and EDGE_FN_URL with
// your deployed groq-proxy Edge Function URL (added in a later step).

export const SUPABASE_URL = 'https://yohvxqjdqbbkrclxyeqd.supabase.co';
export const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlvaHZ4cWpkcWJia3JjbHh5ZXFkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODI2OTk0NzksImV4cCI6MjA5ODI3NTQ3OX0.9-gNXLyLM7Ah7xt3iMLtbykoR5obhxI7oMvrLbNlEIw';

export const EDGE_FN_URL = 'https://yohvxqjdqbbkrclxyeqd.supabase.co/functions/v1/groq-proxy';

// True once the placeholders above have been replaced with real values.
export const isConfigured = () =>
  !SUPABASE_URL.includes('YOUR-PROJECT-REF') &&
  !SUPABASE_ANON_KEY.includes('YOUR-SUPABASE-ANON-KEY');
