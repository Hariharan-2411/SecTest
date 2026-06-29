import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

jest.mock('../src/config', () => ({ isConfigured: () => true }));
jest.mock('../src/utils/auth', () => ({
  signIn: jest.fn(),
  signUp: jest.fn(),
  verifyOtp: jest.fn(),
  requestPasswordReset: jest.fn(),
  confirmPasswordReset: jest.fn(),
  resendCode: jest.fn(),
}));

import * as auth from '../src/utils/auth';
import { ToastProvider } from '../src/components/ToastProvider';
import Login from '../src/pages/Popup/Login';

function renderLogin() {
  const onAuthed = jest.fn();
  const utils = render(
    <ToastProvider>
      <Login onAuthed={onAuthed} />
    </ToastProvider>
  );
  return { ...utils, onAuthed };
}

const type = (el, value) => fireEvent.change(el, { target: { value } });
const submit = (container) => fireEvent.submit(container.querySelector('form'));

describe('Login', () => {
  beforeEach(() => {
    auth.signIn.mockResolvedValue({});
    auth.signUp.mockResolvedValue({});
    auth.verifyOtp.mockResolvedValue({});
    auth.requestPasswordReset.mockResolvedValue({});
    auth.confirmPasswordReset.mockResolvedValue({});
    auth.resendCode.mockResolvedValue(undefined);
  });

  it('signs in with email + password and calls onAuthed', async () => {
    const { container, onAuthed } = renderLogin();
    type(screen.getByPlaceholderText('Email'), 'a@b.com');
    type(screen.getByPlaceholderText('Password'), 'pw123456');
    submit(container);
    await waitFor(() => expect(auth.signIn).toHaveBeenCalledWith('a@b.com', 'pw123456'));
    await waitFor(() => expect(onAuthed).toHaveBeenCalled());
  });

  it('signup moves to the verify screen', async () => {
    const { container } = renderLogin();
    fireEvent.click(screen.getByText('Create account'));
    type(screen.getByPlaceholderText('Email'), 'new@b.com');
    type(screen.getByPlaceholderText('Password (min 6 chars)'), 'pw123456');
    submit(container);
    await waitFor(() => expect(auth.signUp).toHaveBeenCalledWith('new@b.com', 'pw123456'));
    expect(await screen.findByText('Verify your email')).toBeInTheDocument();
  });

  it('verifies the OTP code and calls onAuthed', async () => {
    const { container, onAuthed } = renderLogin();
    // get to verify via signup
    fireEvent.click(screen.getByText('Create account'));
    type(screen.getByPlaceholderText('Email'), 'new@b.com');
    type(screen.getByPlaceholderText('Password (min 6 chars)'), 'pw123456');
    submit(container);
    await screen.findByText('Verify your email');

    type(screen.getByPlaceholderText('123456'), '654321');
    submit(container);
    await waitFor(() => expect(auth.verifyOtp).toHaveBeenCalledWith('new@b.com', '654321'));
    await waitFor(() => expect(onAuthed).toHaveBeenCalled());
  });

  it('forgot-password requests a reset code and moves to the reset screen', async () => {
    const { container } = renderLogin();
    fireEvent.click(screen.getByText('Forgot password?'));
    type(screen.getByPlaceholderText('Email'), 'a@b.com');
    submit(container);
    await waitFor(() => expect(auth.requestPasswordReset).toHaveBeenCalledWith('a@b.com'));
    expect(await screen.findByText('Set a new password')).toBeInTheDocument();
  });

  it('show/hide toggles the password input type', () => {
    renderLogin();
    const input = screen.getByPlaceholderText('Password');
    expect(input).toHaveAttribute('type', 'password');
    fireEvent.click(screen.getByLabelText('Show password'));
    expect(input).toHaveAttribute('type', 'text');
  });

  it('disables the resend button during the cooldown after signup', async () => {
    const { container } = renderLogin();
    fireEvent.click(screen.getByText('Create account'));
    type(screen.getByPlaceholderText('Email'), 'new@b.com');
    type(screen.getByPlaceholderText('Password (min 6 chars)'), 'pw123456');
    submit(container);
    await screen.findByText('Verify your email');
    // Cooldown starts at 60s, so the resend button is disabled.
    expect(screen.getByText(/Resend code \(\d+s\)/)).toBeDisabled();
  });
});
