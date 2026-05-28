// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react';
import { Badge, Button, ListRow } from '@pangolin/component-library';

import { isDesktopError, pairingDeviceList, type DeviceInfo } from '../lib/invoke';
import { AddDeviceWizard } from './AddDeviceWizard';
import { JoinVaultWizard } from './JoinVaultWizard';

export interface DevicesScreenProps {
  /** Return to the account list. */
  onClose: () => void;
  /** Surface a non-fatal error as a toast. */
  onError: (message: string) => void;
  /** After a successful join, unlock the now-shared vault + land on the
   *  account list. */
  onJoined: (newPassword: string) => Promise<void>;
}

type Mode = 'landing' | 'add' | 'join';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Devices screen (MVP-4-I). Landing surface lists the vault's paired
 * devices (read-only this slice — removal is MVP-4-J) and launches the
 * add-a-device / join-a-vault wizards. Carries a persistent testnet
 * banner: pairing performs real Base Sepolia transactions, and the whole
 * multi-device surface is testnet-only until the D-011 audit clears.
 */
export function DevicesScreen({ onClose, onError, onJoined }: DevicesScreenProps) {
  const [mode, setMode] = useState<Mode>('landing');
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loaded, setLoaded] = useState(false);

  const refresh = () => {
    void (async () => {
      try {
        setDevices(await pairingDeviceList());
      } catch (e) {
        onError(errMessage(e));
      } finally {
        setLoaded(true);
      }
    })();
  };

  useEffect(refresh, []); // eslint-disable-line react-hooks/exhaustive-deps

  const backToLanding = () => {
    setMode('landing');
    refresh();
  };

  if (mode === 'add') {
    return (
      <main className="devices-screen" aria-labelledby="devices-title">
        <AddDeviceWizard onError={onError} onClose={backToLanding} />
      </main>
    );
  }
  if (mode === 'join') {
    return (
      <main className="devices-screen" aria-labelledby="devices-title">
        <JoinVaultWizard onError={onError} onClose={backToLanding} onJoined={onJoined} />
      </main>
    );
  }

  return (
    <main className="devices-screen" aria-labelledby="devices-title">
      <header className="devices-screen__header">
        <h1 id="devices-title">Devices</h1>
        <Button variant="ghost" onClick={onClose} data-testid="devices-back">
          Back
        </Button>
      </header>

      <p className="devices-screen__testnet" role="note" data-testid="devices-testnet-banner">
        Testnet only — pairing publishes to Base Sepolia. Multi-device stays
        on testnet until the external audit (D-011) clears.
      </p>

      <section className="devices-screen__list" aria-label="Paired devices">
        {!loaded ? (
          <p>Loading devices…</p>
        ) : devices.length === 0 ? (
          <p className="devices-screen__empty">No devices recorded yet.</p>
        ) : (
          <ul data-testid="devices-list">
            {devices.map((d) => (
              <li key={d.id}>
                <ListRow
                  title={d.label === '' ? d.id.slice(0, 12) : d.label}
                  subtitle={d.evmAddress === '' ? '' : `0x${d.evmAddress}`}
                  rightAction={
                    d.isCurrent ? <Badge tone="accent">This device</Badge> : undefined
                  }
                />
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="devices-screen__actions">
        <Button onClick={() => setMode('add')} data-testid="devices-add">
          Add a device
        </Button>
        <Button variant="secondary" onClick={() => setMode('join')} data-testid="devices-join">
          Join a vault
        </Button>
      </div>
    </main>
  );
}
