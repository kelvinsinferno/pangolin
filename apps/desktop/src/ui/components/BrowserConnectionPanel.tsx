// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MVP-4-M L3 + plan-LOCK Q-d / Q-L3 LOCKED Option 1: in-app wizard for
 * connecting the Pangolin desktop to the browser extension.
 *
 * Per Q-L3 the extension is OPTIONAL — this panel is reached via
 * `Settings → Browser connection` and is a non-blocking flow. The
 * first-launch banner (`ExtensionBanner`) links here.
 *
 * The user:
 *   1. Has already loaded the Pangolin extension zip via
 *      chrome://extensions → Load Unpacked.
 *   2. Copies the extension ID Chrome assigned (32-char a..p string)
 *      back into this panel.
 *   3. Locates the `pangolin-native-messaging-host` binary path
 *      (alongside the desktop install — pre-filled with our best
 *      guess but editable, since closed-beta installer layouts vary
 *      by package format).
 *   4. Clicks "Connect" — we invoke `install_native_host` which
 *      writes the per-browser manifest JSONs.
 *
 * If a manifest is already present, the panel renders a "Connected"
 * status with a per-browser checklist + a "Disconnect" button.
 *
 * Failure modes surfaced inline:
 *   - extension_id_length / extension_id_alphabet — validation errors
 *     from the Rust side (typed Validation envelope)
 *   - Internal — generic write failures (file path doesn't exist,
 *     permissions, etc.) — shown verbatim
 */
import { useEffect, useState } from 'react';

import { Button, IconButton, Input, Label } from '@pangolin/component-library';

import {
  installNativeHost,
  isDesktopError,
  nativeHostStatus,
  uninstallNativeHost,
  type NativeHostStatus,
} from '../lib/invoke';

export interface BrowserConnectionPanelProps {
  /** Called when the user clicks "Back". */
  onClose: () => void;
  /** Called with a string for the parent's toast region on errors that
   *  shouldn't block the panel (post-success uninstall failure, etc.). */
  onError: (message: string) => void;
}

/** Default binary path guess per OS. On Linux .deb installs the
 *  native-host binary lands at `/usr/bin/pangolin-native-messaging-host`;
 *  on AppImage / portable builds the user resolves the path themselves.
 *  We pre-fill the most common Linux path; macOS/Windows users tweak. */
function defaultBinaryPath(): string {
  if (typeof navigator !== 'undefined') {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('win')) {
      return 'C:\\Program Files\\Pangolin\\pangolin-native-messaging-host.exe';
    }
    if (ua.includes('mac')) {
      return '/Applications/Pangolin.app/Contents/MacOS/pangolin-native-messaging-host';
    }
  }
  return '/usr/bin/pangolin-native-messaging-host';
}

export function BrowserConnectionPanel({
  onClose,
  onError,
}: BrowserConnectionPanelProps): React.JSX.Element {
  const [status, setStatus] = useState<NativeHostStatus | null>(null);
  const [extensionId, setExtensionId] = useState('');
  const [binaryPath, setBinaryPath] = useState(defaultBinaryPath());
  const [busy, setBusy] = useState(false);
  const [inlineError, setInlineError] = useState<string | null>(null);

  // Initial status read on mount + after any connect/disconnect action.
  const refreshStatus = async () => {
    try {
      const s = await nativeHostStatus();
      setStatus(s);
    } catch (e) {
      const msg = isDesktopError(e) ? e.message : String(e);
      onError(`Failed to read browser connection status: ${msg}`);
    }
  };

  useEffect(() => {
    void refreshStatus();
    // refreshStatus is recreated each render but reads from no
    // captured state, so omitting it from deps is safe.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onConnect = async () => {
    setInlineError(null);
    setBusy(true);
    try {
      await installNativeHost(binaryPath.trim(), extensionId.trim());
      setExtensionId('');
      await refreshStatus();
    } catch (e) {
      if (isDesktopError(e)) {
        // Surface validation errors inline; treat other kinds as
        // toast-worthy and bubble up.
        if (e.kind === 'Validation') {
          setInlineError(typeof e.message === 'string' ? e.message : e.kind);
        } else {
          const msg = typeof e.message === 'string' ? e.message : e.kind;
          onError(`Connect failed: ${msg}`);
        }
      } else {
        onError(`Connect failed: ${String(e)}`);
      }
    } finally {
      setBusy(false);
    }
  };

  const onDisconnect = async () => {
    setInlineError(null);
    setBusy(true);
    try {
      await uninstallNativeHost();
      await refreshStatus();
    } catch (e) {
      const msg = isDesktopError(e)
        ? typeof e.message === 'string'
          ? e.message
          : e.kind
        : String(e);
      onError(`Disconnect failed: ${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const connected = status?.connected ?? false;

  return (
    <div className="browser-connection-panel">
      <div className="browser-connection-panel__header">
        <h2>Browser connection</h2>
        <IconButton
          onClick={onClose}
          aria-label="Back to settings"
          icon={<>←</>}
          data-testid="browser-connection-back"
        />
      </div>

      <p className="browser-connection-panel__intro">
        Connect Pangolin to a Chromium-based browser (Chrome / Brave / Edge / Chromium)
        so the extension can autofill from your vault. <strong>The browser extension is optional</strong> —
        the desktop vault works fully without it.
      </p>

      {status === null && (
        <p className="browser-connection-panel__loading" data-testid="browser-connection-loading">
          Reading status…
        </p>
      )}

      {status !== null && connected && (
        <section className="browser-connection-panel__status" data-testid="browser-connection-status-connected">
          <h3>✓ Connected</h3>
          <p>The native-messaging manifest is installed for these browsers:</p>
          <ul className="browser-connection-panel__browsers">
            {status.browsers
              .filter((b) => b.present)
              .map((b) => (
                <li key={b.browser}>
                  <strong>{b.browser}</strong>: <code>{b.manifestPath}</code>
                </li>
              ))}
          </ul>
          <div className="browser-connection-panel__actions">
            <Button
              variant="secondary"
              onClick={() => void onDisconnect()}
              disabled={busy}
              data-testid="browser-connection-disconnect"
            >
              Disconnect
            </Button>
          </div>
        </section>
      )}

      {status !== null && !connected && (
        <section className="browser-connection-panel__form" data-testid="browser-connection-form">
          <h3>Connect</h3>
          <ol className="browser-connection-panel__steps">
            <li>
              Download <code>pangolin-extension-&lt;version&gt;.zip</code> from the latest GitHub Release
              and unzip it somewhere persistent.
            </li>
            <li>
              Open <code>chrome://extensions</code> → enable <strong>Developer mode</strong> → click{' '}
              <strong>Load unpacked</strong> → select the unzipped folder.
            </li>
            <li>
              Copy the extension ID Chrome assigned (under the extension name in the extensions list).
            </li>
            <li>Paste it below + verify the native-host binary path, then click Connect.</li>
          </ol>

          <div className="browser-connection-panel__field">
            <Label htmlFor="extension-id-input">Extension ID</Label>
            <Input
              id="extension-id-input"
              value={extensionId}
              onChange={(e) => setExtensionId(e.target.value)}
              placeholder="32-character extension ID from chrome://extensions"
              data-testid="extension-id-input"
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          <div className="browser-connection-panel__field">
            <Label htmlFor="binary-path-input">Native-host binary path</Label>
            <Input
              id="binary-path-input"
              value={binaryPath}
              onChange={(e) => setBinaryPath(e.target.value)}
              placeholder="/usr/bin/pangolin-native-messaging-host"
              data-testid="binary-path-input"
              autoComplete="off"
              spellCheck={false}
            />
            <p className="browser-connection-panel__field-hint">
              Pre-filled with the most common path for this OS. Edit if your install layout differs.
            </p>
          </div>

          {inlineError !== null && (
            <p className="browser-connection-panel__error" data-testid="browser-connection-error">
              {inlineError}
            </p>
          )}

          <div className="browser-connection-panel__actions">
            <Button
              variant="primary"
              onClick={() => void onConnect()}
              disabled={busy || extensionId.trim().length === 0 || binaryPath.trim().length === 0}
              data-testid="browser-connection-connect"
            >
              {busy ? 'Connecting…' : 'Connect'}
            </Button>
          </div>
        </section>
      )}
    </div>
  );
}
