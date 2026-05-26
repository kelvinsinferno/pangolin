// SPDX-License-Identifier: AGPL-3.0-or-later
import { useEffect, useState } from 'react';
import { Button, Card } from '@pangolin/component-library';

import type { AccountSummary } from '../lib/invoke';

export interface AccountDetailScreenProps {
  account: AccountSummary;
  onBack: () => void;
  /** Reveal-to-view: bytes cross V8 (L1 carve-out, 10s clear). */
  onReveal: () => Promise<{ ok: true; password: string } | { ok: false }>;
  /** Copy-only: plaintext NEVER crosses V8 — Rust reads the password
   *  via FFI + writes to the OS clipboard internally (audit H-1
   *  hardening). The screen invokes this for the "Copy" button. */
  onCopyPassword: () => Promise<{ ok: true } | { ok: false }>;
}

/**
 * Account detail screen — the read-only metadata view + the
 * reveal-and-copy affordance.
 *
 * L1 carve-out (per MVP-4-B plan §6): the revealed plaintext lives in
 * `useState` for at most 10 s, after which a `useEffect` clears it.
 * Per Browser-Ext spec §4.7 memory-hygiene rule.
 */
const REVEAL_CLEAR_MS = 10_000;

export function AccountDetailScreen({
  account,
  onBack,
  onReveal,
  onCopyPassword,
}: AccountDetailScreenProps) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [copyConfirmed, setCopyConfirmed] = useState(false);

  // 10 s memory-hygiene clear. Per the plan, this is the LOAD-BEARING
  // host-side discipline that compensates for the L1 carve-out (the
  // plaintext crosses the FFI as a String for the reveal flow).
  useEffect(() => {
    if (revealed === null) return;
    const timer = setTimeout(() => {
      setRevealed(null);
    }, REVEAL_CLEAR_MS);
    return () => clearTimeout(timer);
  }, [revealed]);

  const handleReveal = async () => {
    if (pending) return;
    setPending(true);
    const result = await onReveal();
    setPending(false);
    if (result.ok) {
      setRevealed(result.password);
    }
  };

  // Audit H-1 hardening: the Copy button calls onCopyPassword() which
  // routes through the new `copy_password_to_clipboard` Tauri command
  // — Rust reads the password via FFI + writes to the clipboard plugin
  // in the same `tauri::command` body. The plaintext NEVER crosses
  // V8. The previously-revealed `revealed` state (if the user clicked
  // Reveal first) is left untouched; it continues its 10s clear timer.
  const handleCopy = async () => {
    if (pending) return;
    setPending(true);
    const result = await onCopyPassword();
    setPending(false);
    if (result.ok) {
      setCopyConfirmed(true);
      setTimeout(() => setCopyConfirmed(false), 2000);
    }
  };

  return (
    <main className="account-detail-screen" aria-labelledby="account-detail-title">
      <header className="account-detail-screen__header">
        <Button variant="ghost" onClick={onBack} data-testid="back-button">
          Back
        </Button>
        <h1 id="account-detail-title">{account.displayName}</h1>
      </header>
      <Card elevation="md">
        <dl className="account-detail-screen__fields">
          {account.usernames.length > 0 && (
            <>
              <dt>Username</dt>
              <dd data-testid="username">{account.usernames[0]}</dd>
            </>
          )}
          {account.urls.length > 0 && (
            <>
              <dt>URL</dt>
              <dd data-testid="url">{account.urls[0]}</dd>
            </>
          )}
          <dt>Password</dt>
          <dd data-testid="password-cell">
            {revealed === null ? (
              <span className="account-detail-screen__masked" aria-label="Hidden password">
                ••••••••
              </span>
            ) : (
              <code data-testid="revealed-password">{revealed}</code>
            )}
          </dd>
        </dl>
        <div className="account-detail-screen__actions">
          <Button
            onClick={handleReveal}
            disabled={pending || revealed !== null}
            data-testid="reveal-button"
          >
            {revealed === null ? 'Reveal Password' : 'Password revealed (auto-clears)'}
          </Button>
          <Button
            variant="secondary"
            onClick={handleCopy}
            disabled={pending}
            data-testid="copy-button"
          >
            {copyConfirmed ? 'Copied!' : 'Copy'}
          </Button>
        </div>
      </Card>
    </main>
  );
}
