import React, { useState } from 'react';
import { useToast } from '../../components/ToastProvider';
import * as auth from '../../utils/auth';

const IconUser = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
    <circle cx="12" cy="7" r="4"/>
  </svg>
);
const EyeOpen = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
    <circle cx="12" cy="12" r="3"/>
  </svg>
);
const EyeOff = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
    <line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
);

// Header account dropdown: shows the signed-in email, an in-session change
// password form, and log out.
export default function AccountMenu({ email, onSignedOut }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [changing, setChanging] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [busy, setBusy] = useState(false);

  const handleChange = async (e) => {
    e.preventDefault();
    if (newPassword.length < 6) {
      toast.error('Password must be at least 6 characters.');
      return;
    }
    setBusy(true);
    try {
      await auth.changePassword(newPassword);
      toast.success('Password changed.');
      setNewPassword('');
      setChanging(false);
    } catch (err) {
      toast.error((err && err.message) || 'Could not change password.');
    } finally {
      setBusy(false);
    }
  };

  const handleLogout = async () => {
    try {
      await auth.signOut();
    } catch (_) {
      // even if the network call fails, drop local state
    }
    setOpen(false);
    onSignedOut && onSignedOut();
  };

  return (
    <div className="account-menu">
      <button
        className="account-btn"
        onClick={() => setOpen((o) => !o)}
        title={email || 'Account'}
        aria-label="Account menu"
      >
        <IconUser />
      </button>
      {open && (
        <div className="account-dropdown">
          <div className="account-email" title={email}>{email || 'Signed in'}</div>

          {!changing ? (
            <button className="link-btn" onClick={() => setChanging(true)}>
              Change password
            </button>
          ) : (
            <form className="account-change" onSubmit={handleChange}>
              <div className="pw-field">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="New password"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="pw-toggle"
                  onClick={() => setShowPw((s) => !s)}
                  tabIndex={-1}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                >
                  {showPw ? <EyeOff /> : <EyeOpen />}
                </button>
              </div>
              <div className="account-change-actions">
                <button type="submit" className="btn-primary" disabled={busy}>
                  {busy ? '…' : 'Save'}
                </button>
                <button type="button" className="link-btn" onClick={() => { setChanging(false); setNewPassword(''); }}>
                  Cancel
                </button>
              </div>
            </form>
          )}

          <button className="account-logout" onClick={handleLogout}>Log out</button>
        </div>
      )}
    </div>
  );
}
