import { describe, it, expect, jest, beforeEach, afterEach } from '@jest/globals';
import '@testing-library/jest-dom';
import React from 'react';
import { render, screen, act } from '@testing-library/react';
import { ToastProvider, useToast } from '../src/components/ToastProvider';
import ErrorBoundary from '../src/components/ErrorBoundary';

// Test harness: a button that pushes a toast of a given type when clicked.
function Pusher({ type = 'info', message = 'hello', ttl }) {
  const toast = useToast();
  return (
    <button onClick={() => toast[type](message, ttl)}>push</button>
  );
}

describe('ToastProvider', () => {
  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('shows a toast with the right type class and auto-dismisses after the ttl', () => {
    render(
      <ToastProvider>
        <Pusher type="success" message="saved" ttl={4000} />
      </ToastProvider>
    );

    act(() => {
      screen.getByText('push').click();
    });

    const toast = screen.getByText('saved');
    expect(toast).toBeInTheDocument();
    expect(toast.className).toContain('toast-success');

    // After the ttl elapses it should be gone.
    act(() => {
      jest.advanceTimersByTime(4000);
    });
    expect(screen.queryByText('saved')).toBeNull();
  });

  it('dismisses on click', () => {
    render(
      <ToastProvider>
        <Pusher type="error" message="boom" ttl={0} />
      </ToastProvider>
    );
    act(() => screen.getByText('push').click());
    const toast = screen.getByText('boom');
    expect(toast.className).toContain('toast-error');
    act(() => toast.click());
    expect(screen.queryByText('boom')).toBeNull();
  });

  it('useToast outside a provider throws', () => {
    // Silence the expected React error log for this assertion.
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => render(<Pusher />)).toThrow(/ToastProvider/);
    spy.mockRestore();
  });
});

describe('ErrorBoundary', () => {
  it('renders the fallback when a child throws', () => {
    const Boom = () => {
      throw new Error('kaboom');
    };
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Boom />
      </ErrorBoundary>
    );
    expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument();
    expect(screen.getByText('kaboom')).toBeInTheDocument();
    spy.mockRestore();
  });

  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>all good</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('all good')).toBeInTheDocument();
  });
});
