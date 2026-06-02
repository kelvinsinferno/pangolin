// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MVP-4-M L3 + plan-LOCK Q-L3 LOCKED Option 1: soft, non-blocking
 * banner suggesting the user connect a browser extension.
 *
 * Shows when:
 *   - the native-host manifest is NOT installed in any Chromium-family
 *     browser (per `nativeHostStatus`), AND
 *   - the user has not dismissed the banner this session.
 *
 * Dismissal is intentionally NOT persisted — restart re-shows the
 * banner. Users who genuinely don't want the extension simply ignore
 * it; users who haven't gotten around to it get a gentle nudge each
 * launch. The Settings → Browser connection panel is always accessible
 * via the regular Settings entry regardless of banner state.
 */
import { useEffect, useState } from 'react';

import { Button } from '@pangolin/component-library';

import { isDesktopError, nativeHostStatus } from '../lib/invoke';

export interface ExtensionBannerProps {
  /** Called when the user clicks "Configure" — caller navigates to the
   *  Settings → Browser connection panel. */
  onConfigure: () => void;
}

export function ExtensionBanner({ onConfigure }: ExtensionBannerProps): React.JSX.Element | null {
  const [showBanner, setShowBanner] = useState(false);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const status = await nativeHostStatus();
        if (cancelled) return;
        setShowBanner(!status.connected);
      } catch (e) {
        // Stay hidden on read error — don't display a phantom banner.
        // Logging the error is enough; the Settings panel surfaces a
        // detailed error if the user proactively visits.
        if (!cancelled) setShowBanner(false);
        console.warn('ExtensionBanner status read failed:', isDesktopError(e) ? e.message : e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!showBanner || dismissed) return null;

  return (
    <div className="extension-banner" data-testid="extension-banner" role="status">
      <div className="extension-banner__text">
        <strong>Connect your browser extension?</strong>
        <p>
          Pangolin can autofill from your vault if you install the optional Chromium
          extension. Configure later in Settings → Browser connection.
        </p>
      </div>
      <div className="extension-banner__actions">
        <Button
          variant="primary"
          onClick={onConfigure}
          data-testid="extension-banner-configure"
        >
          Configure
        </Button>
        <Button
          variant="ghost"
          onClick={() => setDismissed(true)}
          data-testid="extension-banner-dismiss"
        >
          Maybe later
        </Button>
      </div>
    </div>
  );
}
