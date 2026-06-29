import React, { useState, useEffect } from 'react';
import { useToast } from '../../components/ToastProvider';
import * as auth from '../../utils/auth';
import { isConfigured } from '../../config';

const COOLDOWN_SECONDS = 60;

// Module-level so its identity is stable across renders (a component defined
// inside render would remount on every keystroke and drop input focus).
function PasswordInput({ value, onChange, placeholder, autoComplete, show, onToggle }) {
  return (
    <div className="pw-field">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        required
      />
      <button
        type="button"
        className="pw-toggle"
        onClick={onToggle}
        aria-label={show ? 'Hide password' : 'Show password'}
        title={show ? 'Hide password' : 'Show password'}
        tabIndex={-1}
      >
        {show ? '🙈' : '👁️'}
      </button>
    </div>
  );
}

// Gated auth screen. One component, five modes:
//   login  → signInWithPassword
//   signup → signUp, then verify (OTP)
//   verify → verifyOtp (signup)
//   forgot → requestPasswordReset, then reset
//   reset  → confirmPasswordReset (recovery OTP + new password)
export default function Login({ onAuthed }) {
  const toast = useToast();
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  const configured = isConfigured();

  // Resend cooldown ticker.
  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const run = async (fn) => {
    if (!configured) {
      toast.error('Supabase is not configured yet — add your URL + anon key in src/config.js.');
      return;
    }
    if (busy) return;
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast.error((e && e.message) || 'Something went wrong');
    } finally {
      setBusy(false);
    }
  };

  const goLogin = () => run(async () => {
    await auth.signIn(email, password);
    onAuthed && onAuthed();
  });

  const goSignup = () => run(async () => {
    await auth.signUp(email, password);
    toast.success('Account created — check your email for a verification code.');
    setCode('');
    setCooldown(COOLDOWN_SECONDS);
    setMode('verify');
  });

  const goVerify = () => run(async () => {
    await auth.verifyOtp(email, code.trim());
    toast.success('Email verified!');
    onAuthed && onAuthed();
  });

  const goForgot = () => run(async () => {
    await auth.requestPasswordReset(email);
    toast.success('If that account exists, a reset code is on its way.');
    setCode('');
    setNewPassword('');
    setCooldown(COOLDOWN_SECONDS);
    setMode('reset');
  });

  const goReset = () => run(async () => {
    await auth.confirmPasswordReset(email, code.trim(), newPassword);
    toast.success('Password updated!');
    onAuthed && onAuthed();
  });

  const resend = (kind) => run(async () => {
    await auth.resendCode(email, kind);
    toast.info('Code resent.');
    setCooldown(COOLDOWN_SECONDS);
  });

  const onSubmit = (fn) => (e) => {
    e.preventDefault();
    fn();
  };

  const togglePw = () => setShowPw((s) => !s);

  const resendButton = (kind) => (
    <button
      type="button"
      className="link-btn"
      onClick={() => resend(kind)}
      disabled={cooldown > 0 || busy}
    >
      {cooldown > 0 ? `Resend code (${cooldown}s)` : 'Resend code'}
    </button>
  );

  return (
    <div className="auth-screen">
      {!configured && (
        <div className="warning-banner auth-config-warn">
          Supabase not configured. Add your project URL + anon key in <code>src/config.js</code>.
        </div>
      )}

      {mode === 'login' && (
        <form className="auth-form" onSubmit={onSubmit(goLogin)}>
          <h3>Sign in</h3>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" autoComplete="username" required />
          <PasswordInput value={password} onChange={setPassword} placeholder="Password" autoComplete="current-password" show={showPw} onToggle={togglePw} />
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? '…' : 'Sign in'}</button>
          <div className="auth-links">
            <button type="button" className="link-btn" onClick={() => setMode('forgot')}>Forgot password?</button>
            <button type="button" className="link-btn" onClick={() => setMode('signup')}>Create account</button>
          </div>
        </form>
      )}

      {mode === 'signup' && (
        <form className="auth-form" onSubmit={onSubmit(goSignup)}>
          <h3>Create account</h3>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" autoComplete="username" required />
          <PasswordInput value={password} onChange={setPassword} placeholder="Password (min 6 chars)" autoComplete="new-password" show={showPw} onToggle={togglePw} />
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? '…' : 'Sign up'}</button>
          <div className="auth-links">
            <button type="button" className="link-btn" onClick={() => setMode('login')}>Back to sign in</button>
          </div>
        </form>
      )}

      {mode === 'verify' && (
        <form className="auth-form" onSubmit={onSubmit(goVerify)}>
          <h3>Verify your email</h3>
          <p className="auth-hint">Enter the verification code sent to {email || 'your email'}.</p>
          <input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Verification code" maxLength={8} required />
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? '…' : 'Verify'}</button>
          <div className="auth-links">
            {resendButton('signup')}
            <button type="button" className="link-btn" onClick={() => setMode('login')}>Back to sign in</button>
          </div>
        </form>
      )}

      {mode === 'forgot' && (
        <form className="auth-form" onSubmit={onSubmit(goForgot)}>
          <h3>Reset password</h3>
          <p className="auth-hint">We'll email you a verification code.</p>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" autoComplete="username" required />
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? '…' : 'Send code'}</button>
          <div className="auth-links">
            <button type="button" className="link-btn" onClick={() => setMode('login')}>Back to sign in</button>
          </div>
        </form>
      )}

      {mode === 'reset' && (
        <form className="auth-form" onSubmit={onSubmit(goReset)}>
          <h3>Set a new password</h3>
          <p className="auth-hint">Enter the code sent to {email || 'your email'} and a new password.</p>
          <input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} placeholder="Verification code" maxLength={8} required />
          <PasswordInput value={newPassword} onChange={setNewPassword} placeholder="New password (min 6 chars)" autoComplete="new-password" show={showPw} onToggle={togglePw} />
          <button type="submit" className="btn-primary" disabled={busy}>{busy ? '…' : 'Update password'}</button>
          <div className="auth-links">
            {resendButton('recovery')}
            <button type="button" className="link-btn" onClick={() => setMode('login')}>Back to sign in</button>
          </div>
        </form>
      )}
    </div>
  );
}
