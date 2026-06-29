import { createClient } from '@supabase/supabase-js';
import { SUPABASE_URL, SUPABASE_ANON_KEY } from '../config';
import { chromeStorageAdapter } from './chromeStorageAdapter';

// Single Supabase client for the extension. Sessions persist in
// chrome.storage.local via the adapter; tokens auto-refresh. detectSessionInUrl
// is off because the popup is not loaded from an auth-redirect URL — we use
// email OTP codes instead of magic links.

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    storage: chromeStorageAdapter,
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: false,
  },
});

export default supabase;
