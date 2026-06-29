import React from 'react';
import { createRoot } from 'react-dom/client';

import Popup from './Popup';
import ErrorBoundary from '../../components/ErrorBoundary';
import { ToastProvider } from '../../components/ToastProvider';
import './index.css';

const container = document.getElementById('app-container');
const root = createRoot(container); // createRoot(container!) if you use TypeScript
root.render(
  <ErrorBoundary>
    <ToastProvider>
      <Popup />
    </ToastProvider>
  </ErrorBoundary>
);
