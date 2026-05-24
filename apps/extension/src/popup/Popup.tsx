// SPDX-License-Identifier: AGPL-3.0-or-later
import { Button, Card, Text } from './Placeholder';
import './Popup.css';

/**
 * The MVP-4-C scaffold popup. Hard-coded "disconnected" state. No autofill,
 * no native-messaging — those land in MVP-4-E (host) and MVP-4-G (autofill).
 */
export function Popup() {
  const isConnected = false;
  return (
    <div className="pcl-popup-root">
      <h1 className="pcl-popup-brand">Pangolin</h1>
      <Card>
        <div
          className="pcl-popup-status"
          role="status"
          aria-live="polite"
        >
          <span
            className="pcl-popup-status-dot"
            data-connected={String(isConnected)}
            aria-hidden="true"
          />
          <span>Desktop not connected</span>
        </div>
        <div className="pcl-popup-body">
          <Text variant="body">
            Open the Pangolin desktop app to start using your vault.
          </Text>
        </div>
        <Button
          onClick={() => {
            console.log('Open Pangolin clicked (placeholder; no action)');
          }}
        >
          Open Pangolin
        </Button>
      </Card>
    </div>
  );
}
