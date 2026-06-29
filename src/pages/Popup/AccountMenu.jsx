import React, { useState } from 'react';
import { useToast } from '../../components/ToastProvider';
import * as auth from '../../utils/auth';

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
        👤
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
                  {showPw ? '🙈' : '👁️'}
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
