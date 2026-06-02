// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MVP-4-M L3: Settings screen — currently hosts only the Browser
 * connection panel. Designed as a fan-out: future settings (theme,
 * locale, auto-lock timer, etc.) land here as additional sections.
 */
import { useState } from 'react';

import { Button, IconButton } from '@pangolin/component-library';

import { BrowserConnectionPanel } from '../components/BrowserConnectionPanel';

export interface SettingsScreenProps {
  /** Return to the active account list. */
  onClose: () => void;
  /** Toast-worthy errors. */
  onError: (message: string) => void;
}

type Section = 'index' | 'browser-connection';

export function SettingsScreen({ onClose, onError }: SettingsScreenProps): React.JSX.Element {
  const [section, setSection] = useState<Section>('index');

  if (section === 'browser-connection') {
    return (
      <BrowserConnectionPanel
        onClose={() => setSection('index')}
        onError={onError}
      />
    );
  }

  return (
    <div className="settings-screen">
      <div className="settings-screen__header">
        <h1>Settings</h1>
        <IconButton
          onClick={onClose}
          aria-label="Back to accounts"
          icon={<>←</>}
          data-testid="settings-back"
        />
      </div>

      <ul className="settings-screen__sections">
        <li className="settings-screen__section-row">
          <div className="settings-screen__section-text">
            <strong>Browser connection</strong>
            <p>
              Connect the optional Pangolin browser extension to enable autofill.
              You can also disconnect from here.
            </p>
          </div>
          <Button
            variant="secondary"
            onClick={() => setSection('browser-connection')}
            data-testid="settings-open-browser-connection"
          >
            Configure
          </Button>
        </li>
      </ul>
    </div>
  );
}
