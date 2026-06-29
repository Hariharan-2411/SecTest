import supabase from './supabaseClient';

// Thin, throwing wrappers around Supabase GoTrue. Each returns data on success
// and throws the Supabase error on failure, so callers use try/catch + toasts.
// Email verification and password recovery use 6-digit OTP codes (not magic
// links), which is the only flow that works inside an extension popup.

export async function signUp(email, password) {
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) throw error;
  return data;
}

export async function verifyOtp(email, token) {
  const { data, error } = await supabase.auth.verifyOtp({
    email,
    token,
    type: 'signup',
  });
  if (error) throw error;
  return data;
}

export async function signIn(email, password) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });
  if (error) throw error;
  return data;
}

export async function requestPasswordReset(email) {
  const { data, error } = await supabase.auth.resetPasswordForEmail(email);
  if (error) throw error;
  return data;
}

export async function confirmPasswordReset(email, token, newPassword) {
  // Recovery OTP establishes a session, then we set the new password.
  const { error: verifyError } = await supabase.auth.verifyOtp({
    email,
    token,
    type: 'recovery',
  });
  if (verifyError) throw verifyError;
  const { data, error } = await supabase.auth.updateUser({
    password: newPassword,
  });
  if (error) throw error;
  return data;
}

// Re-send the OTP for either signup verification or password recovery.
export async function resendCode(email, kind = 'signup') {
  if (kind === 'recovery') {
    const { error } = await supabase.auth.resetPasswordForEmail(email);
    if (error) throw error;
    return;
  }
  const { error } = await supabase.auth.resend({ type: 'signup', email });
  if (error) throw error;
}

// In-session password change (caller must be logged in).
export async function changePassword(newPassword) {
  const { data, error } = await supabase.auth.updateUser({
    password: newPassword,
  });
  if (error) throw error;
  return data;
}

export async function signOut() {
  const { error } = await supabase.auth.signOut();
  if (error) throw error;
}

export async function getSession() {
  const { data } = await supabase.auth.getSession();
  return (data && data.session) || null;
}

export async function getAccessToken() {
  const session = await getSession();
  return (session && session.access_token) || null;
}

export function onAuthStateChange(callback) {
  return supabase.auth.onAuthStateChange(callback);
}

// Whether the session's user has a confirmed email.
export function isVerified(session) {
  const user = session && session.user;
  if (!user) return false;
  return Boolean(user.email_confirmed_at || user.confirmed_at);
}
