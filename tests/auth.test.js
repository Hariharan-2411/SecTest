import { describe, it, expect, jest, beforeEach } from '@jest/globals';

// Mock the Supabase client so the auth helpers are tested in isolation.
jest.mock('../src/utils/supabaseClient', () => {
  const auth = {
    signUp: jest.fn(),
    verifyOtp: jest.fn(),
    signInWithPassword: jest.fn(),
    resetPasswordForEmail: jest.fn(),
    updateUser: jest.fn(),
    resend: jest.fn(),
    signOut: jest.fn(),
    getSession: jest.fn(),
    onAuthStateChange: jest.fn(),
  };
  return { __esModule: true, default: { auth } };
});

import supabase from '../src/utils/supabaseClient';
import * as auth from '../src/utils/auth';
import { chromeStorageAdapter } from '../src/utils/chromeStorageAdapter';

const ok = (data = {}) => ({ data, error: null });
const fail = (msg) => ({ data: null, error: new Error(msg) });

describe('auth helpers', () => {
  it('signUp calls supabase with credentials and returns data', async () => {
    supabase.auth.signUp.mockResolvedValue(ok({ user: { id: '1' } }));
    const data = await auth.signUp('a@b.com', 'pw123456');
    expect(supabase.auth.signUp).toHaveBeenCalledWith({
      email: 'a@b.com',
      password: 'pw123456',
    });
    expect(data.user.id).toBe('1');
  });

  it('signUp throws on error', async () => {
    supabase.auth.signUp.mockResolvedValue(fail('already registered'));
    await expect(auth.signUp('a@b.com', 'pw')).rejects.toThrow('already registered');
  });

  it('verifyOtp uses type "signup"', async () => {
    supabase.auth.verifyOtp.mockResolvedValue(ok({ session: {} }));
    await auth.verifyOtp('a@b.com', '123456');
    expect(supabase.auth.verifyOtp).toHaveBeenCalledWith({
      email: 'a@b.com',
      token: '123456',
      type: 'signup',
    });
  });

  it('signIn calls signInWithPassword', async () => {
    supabase.auth.signInWithPassword.mockResolvedValue(ok());
    await auth.signIn('a@b.com', 'pw');
    expect(supabase.auth.signInWithPassword).toHaveBeenCalledWith({
      email: 'a@b.com',
      password: 'pw',
    });
  });

  it('requestPasswordReset calls resetPasswordForEmail', async () => {
    supabase.auth.resetPasswordForEmail.mockResolvedValue(ok());
    await auth.requestPasswordReset('a@b.com');
    expect(supabase.auth.resetPasswordForEmail).toHaveBeenCalledWith('a@b.com');
  });

  it('confirmPasswordReset verifies recovery OTP then updates the password', async () => {
    supabase.auth.verifyOtp.mockResolvedValue(ok({ session: {} }));
    supabase.auth.updateUser.mockResolvedValue(ok({ user: {} }));
    await auth.confirmPasswordReset('a@b.com', '654321', 'newpw1234');
    expect(supabase.auth.verifyOtp).toHaveBeenCalledWith({
      email: 'a@b.com',
      token: '654321',
      type: 'recovery',
    });
    expect(supabase.auth.updateUser).toHaveBeenCalledWith({ password: 'newpw1234' });
  });

  it('confirmPasswordReset does not update password if OTP verify fails', async () => {
    supabase.auth.verifyOtp.mockResolvedValue(fail('invalid code'));
    await expect(
      auth.confirmPasswordReset('a@b.com', 'bad', 'newpw')
    ).rejects.toThrow('invalid code');
    expect(supabase.auth.updateUser).not.toHaveBeenCalled();
  });

  it('resendCode("signup") calls auth.resend', async () => {
    supabase.auth.resend.mockResolvedValue({ error: null });
    await auth.resendCode('a@b.com', 'signup');
    expect(supabase.auth.resend).toHaveBeenCalledWith({ type: 'signup', email: 'a@b.com' });
  });

  it('resendCode("recovery") re-triggers resetPasswordForEmail', async () => {
    supabase.auth.resetPasswordForEmail.mockResolvedValue(ok());
    await auth.resendCode('a@b.com', 'recovery');
    expect(supabase.auth.resetPasswordForEmail).toHaveBeenCalledWith('a@b.com');
    expect(supabase.auth.resend).not.toHaveBeenCalled();
  });

  it('changePassword calls updateUser', async () => {
    supabase.auth.updateUser.mockResolvedValue(ok());
    await auth.changePassword('brandnewpw');
    expect(supabase.auth.updateUser).toHaveBeenCalledWith({ password: 'brandnewpw' });
  });

  it('signOut resolves on success and throws on error', async () => {
    supabase.auth.signOut.mockResolvedValue({ error: null });
    await expect(auth.signOut()).resolves.toBeUndefined();
    supabase.auth.signOut.mockResolvedValue({ error: new Error('nope') });
    await expect(auth.signOut()).rejects.toThrow('nope');
  });

  it('getAccessToken returns the session token, or null when signed out', async () => {
    supabase.auth.getSession.mockResolvedValue({ data: { session: { access_token: 'tok' } } });
    expect(await auth.getAccessToken()).toBe('tok');
    supabase.auth.getSession.mockResolvedValue({ data: { session: null } });
    expect(await auth.getAccessToken()).toBeNull();
  });

  it('isVerified reflects the user email-confirmation state', () => {
    expect(auth.isVerified(null)).toBe(false);
    expect(auth.isVerified({ user: {} })).toBe(false);
    expect(auth.isVerified({ user: { email_confirmed_at: '2026-01-01' } })).toBe(true);
    expect(auth.isVerified({ user: { confirmed_at: '2026-01-01' } })).toBe(true);
  });
});

describe('chromeStorageAdapter', () => {
  beforeEach(() => {
    const store = {};
    global.chrome = {
      storage: {
        local: {
          get: jest.fn((keys, cb) => cb({ [keys[0]]: store[keys[0]] })),
          set: jest.fn((obj, cb) => {
            Object.assign(store, obj);
            cb && cb();
          }),
          remove: jest.fn((keys, cb) => {
            delete store[keys[0]];
            cb && cb();
          }),
        },
      },
    };
    global.__store = store;
  });

  it('setItem then getItem round-trips a value', async () => {
    await chromeStorageAdapter.setItem('sb-session', 'abc');
    expect(global.__store['sb-session']).toBe('abc');
    expect(await chromeStorageAdapter.getItem('sb-session')).toBe('abc');
  });

  it('getItem returns null for a missing key', async () => {
    expect(await chromeStorageAdapter.getItem('nope')).toBeNull();
  });

  it('removeItem deletes the key', async () => {
    await chromeStorageAdapter.setItem('k', 'v');
    await chromeStorageAdapter.removeItem('k');
    expect(await chromeStorageAdapter.getItem('k')).toBeNull();
  });

  it('getItem resolves to null instead of throwing when chrome is unavailable', async () => {
    global.chrome = undefined;
    await expect(chromeStorageAdapter.getItem('k')).resolves.toBeNull();
  });
});
