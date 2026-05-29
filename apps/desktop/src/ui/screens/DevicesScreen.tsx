// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useRef, useState } from 'react';
import { Badge, Button, Input, ListRow } from '@pangolin/component-library';

import {
  isDesktopError,
  pairingCancelPromotion,
  pairingCompleteRotation,
  pairingDeviceList,
  pairingFinalizePromotion,
  pairingListAuthorizedDevices,
  pairingPendingPromotion,
  pairingPendingRotations,
  pairingProposePromotion,
  type AuthorizedDevice,
  type DeviceInfo,
  type PromotionPending,
  type RotationPending,
} from '../lib/invoke';
import { AddDeviceWizard } from './AddDeviceWizard';
import { JoinVaultWizard } from './JoinVaultWizard';
import { RemoveDeviceWizard } from './RemoveDeviceWizard';

export interface DevicesScreenProps {
  onClose: () => void;
  onError: (message: string) => void;
  /** After a successful join, unlock the now-shared vault. */
  onJoined: (newPassword: string) => Promise<void>;
  /** After a removal+re-key (or a resumed pending re-key), unlock the
   *  now-rotated (Locked) vault. */
  onRekeyed: (password: string) => Promise<void>;
}

type Mode = 'landing' | 'add' | 'join' | 'remove' | 'rekey';

function errMessage(e: unknown): string {
  if (isDesktopError(e)) {
    return typeof e.message === 'string' ? e.message : e.kind;
  }
  return e instanceof Error ? e.message : 'unexpected error';
}

/**
 * Devices screen (MVP-4-I add/join + MVP-4-J remove/re-key). The landing
 * lists the vault's LIVE on-chain authorized devices (the authoritative,
 * removable set — vs the local-only `device_list`) and, when this device is
 * the manager, offers a Remove action per peer. A persistent banner surfaces
 * any pending VDK rotation (a removal whose re-key did not finish) so the
 * forward-secrecy gap is impossible to miss. Testnet-only.
 */
export function DevicesScreen({ onClose, onError, onJoined, onRekeyed }: DevicesScreenProps) {
  const [mode, setMode] = useState<Mode>('landing');
  const [authorized, setAuthorized] = useState<AuthorizedDevice[] | null>(null);
  const [localDevices, setLocalDevices] = useState<DeviceInfo[]>([]);
  const [pending, setPending] = useState<RotationPending[]>([]);
  const [promotion, setPromotion] = useState<PromotionPending | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<string | null>(null);
  const [rekeyPassword, setRekeyPassword] = useState('');
  const rekeyGuard = useRef(false);
  const promoGuard = useRef(false);

  const refresh = () => {
    setLoaded(false);
    void (async () => {
      // Pending rotations are a local read (no chain) — always safe.
      try {
        setPending(await pairingPendingRotations());
      } catch (e) {
        onError(errMessage(e));
      }
      // The authorized set + pending promotion are on-chain reads; they fail
      // for a vault not yet bootstrapped / with no chain config. Fall back to
      // the local device list (read-only) in that case.
      try {
        setAuthorized(await pairingListAuthorizedDevices());
        setPromotion(await pairingPendingPromotion());
      } catch {
        // On-chain read failed — fall back to the local device list.
        setAuthorized(null);
        setPromotion(null);
        try {
          setLocalDevices(await pairingDeviceList());
        } catch {
          /* local list is best-effort in the fallback */
        }
      } finally {
        setLoaded(true);
      }
    })();
  };

  useEffect(refresh, []); // eslint-disable-line react-hooks/exhaustive-deps

  const backToLanding = () => {
    setMode('landing');
    setRemoveTarget(null);
    refresh();
  };

  const thisIsManager =
    authorized !== null && authorized.some((d) => d.isCurrent && d.isManager);
  const thisSigner = authorized?.find((d) => d.isCurrent)?.signer ?? null;
  // This device is an authorized non-manager device that could take over.
  const canProposeSelf =
    authorized !== null && !thisIsManager && thisSigner !== null && promotion === null;
  const promotionIsForThisDevice =
    promotion !== null && thisSigner !== null && promotion.candidate === thisSigner;
  const promotionReadyNow =
    promotion !== null && Date.now() / 1000 >= promotion.readyAt;

  // Run a promotion lifecycle action through a shared re-entry guard, then
  // refresh the on-chain state.
  const runPromo = (action: () => Promise<void>) => {
    if (promoGuard.current) return;
    promoGuard.current = true;
    void (async () => {
      try {
        await action();
      } catch (e) {
        onError(errMessage(e));
      } finally {
        promoGuard.current = false;
        refresh();
      }
    })();
  };

  const completePendingRekey = async () => {
    if (rekeyGuard.current) return;
    rekeyGuard.current = true;
    try {
      await pairingCompleteRotation(rekeyPassword);
      const pw = rekeyPassword;
      setRekeyPassword('');
      await onRekeyed(pw);
    } catch (e) {
      onError(errMessage(e));
      rekeyGuard.current = false;
    }
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
  if (mode === 'remove' && removeTarget !== null) {
    return (
      <main className="devices-screen" aria-labelledby="devices-title">
        <RemoveDeviceWizard
          signer={removeTarget}
          onError={onError}
          onClose={backToLanding}
          onRekeyed={onRekeyed}
        />
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
        Testnet only — pairing + removal publish to Base Sepolia. Multi-device
        stays on testnet until the external audit (D-011) clears.
      </p>

      {pending.length > 0 && mode === 'landing' && (
        <section className="devices-screen__pending" role="alert" data-testid="rotation-pending-banner">
          <p>
            A device removal has not finished re-keying. Until you complete it,
            the removed device can still read newly-added data. Finish now to
            fully lock it out.
          </p>
          <Button onClick={() => setMode('rekey')} data-testid="rotation-complete">
            Finish re-key
          </Button>
        </section>
      )}

      {promotion !== null && mode === 'landing' && (
        <section className="devices-screen__pending" role="note" data-testid="promotion-pending-banner">
          {promotionIsForThisDevice ? (
            <>
              <p>
                This device is proposed as the vault&apos;s next manager. The
                transfer can be finalized after the 48-hour safety delay
                {promotionReadyNow ? ' — ready now.' : '.'}
              </p>
              <Button
                onClick={() => runPromo(pairingFinalizePromotion)}
                disabled={!promotionReadyNow}
                data-testid="promotion-finalize"
              >
                {promotionReadyNow ? 'Finalize — become manager' : 'Waiting for the 48h delay'}
              </Button>
            </>
          ) : thisIsManager ? (
            <>
              <p>
                A device (0x{promotion.candidate.slice(0, 12)}…) has asked to
                become this vault&apos;s manager. If you did not expect this,
                veto it before the 48-hour delay elapses.
              </p>
              <Button onClick={() => runPromo(pairingCancelPromotion)} data-testid="promotion-veto">
                Veto this promotion
              </Button>
            </>
          ) : (
            <p>
              A manager promotion (0x{promotion.candidate.slice(0, 12)}…) is
              pending; it can be finalized after the 48-hour delay.
            </p>
          )}
        </section>
      )}

      {mode === 'rekey' && (
        <section className="devices-screen__rekey" data-testid="rekey-form">
          <p>Enter your master password to finish re-keying the vault.</p>
          <Input
            type="password"
            value={rekeyPassword}
            onChange={(e) => setRekeyPassword(e.target.value)}
            placeholder="Master password"
            data-testid="rekey-password"
          />
          <div className="devices-wizard__actions">
            <Button
              onClick={() => void completePendingRekey()}
              disabled={rekeyPassword === ''}
              data-testid="rekey-run"
            >
              Re-key vault
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                setRekeyPassword('');
                setMode('landing');
              }}
            >
              Cancel
            </Button>
          </div>
        </section>
      )}

      <section className="devices-screen__list" aria-label="Devices">
        {!loaded ? (
          <p>Loading devices…</p>
        ) : authorized !== null ? (
          <ul data-testid="authorized-list">
            {authorized.map((d) => {
              const removable = thisIsManager && !d.isCurrent && !d.isManager;
              return (
                <li key={d.signer}>
                  <ListRow
                    title={`0x${d.signer.slice(0, 12)}…`}
                    subtitle={d.deviceId === '' ? '' : `device ${d.deviceId.slice(0, 8)}…`}
                    rightAction={
                      <span className="devices-screen__row-actions">
                        {d.isCurrent && <Badge tone="accent">This device</Badge>}
                        {d.isManager && <Badge tone="success">Manager</Badge>}
                        {removable && (
                          <Button
                            variant="ghost"
                            onClick={() => {
                              setRemoveTarget(d.signer);
                              setMode('remove');
                            }}
                            data-testid={`remove-${d.signer}`}
                          >
                            Remove
                          </Button>
                        )}
                      </span>
                    }
                  />
                </li>
              );
            })}
          </ul>
        ) : (
          <>
            <p className="devices-screen__note" data-testid="auth-fallback-note">
              On-chain device management is unavailable (the vault may not be
              set up on-chain yet — add a device first). Showing this device
              only.
            </p>
            <ul data-testid="devices-list">
              {localDevices.map((d) => (
                <li key={d.id}>
                  <ListRow
                    title={d.label === '' ? d.id.slice(0, 12) : d.label}
                    subtitle={d.evmAddress === '' ? '' : `0x${d.evmAddress}`}
                    rightAction={d.isCurrent ? <Badge tone="accent">This device</Badge> : undefined}
                  />
                </li>
              ))}
            </ul>
          </>
        )}
      </section>

      {mode === 'landing' && (
        <div className="devices-screen__actions">
          <Button onClick={() => setMode('add')} data-testid="devices-add">
            Add a device
          </Button>
          <Button variant="secondary" onClick={() => setMode('join')} data-testid="devices-join">
            Join a vault
          </Button>
          {canProposeSelf && (
            <Button
              variant="ghost"
              onClick={() => runPromo(async () => {
                await pairingProposePromotion();
              })}
              data-testid="promotion-propose"
            >
              Become this vault&apos;s manager
            </Button>
          )}
        </div>
      )}
    </main>
  );
}
