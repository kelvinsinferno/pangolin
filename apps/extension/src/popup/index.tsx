// SPDX-License-Identifier: AGPL-3.0-or-later
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '../tokens.css';
import { Popup } from './Popup';

const mount = document.getElementById('popup-root');
if (mount === null) {
  throw new Error('popup-root mount node missing');
}
createRoot(mount).render(
  <StrictMode>
    <Popup />
  </StrictMode>,
);
