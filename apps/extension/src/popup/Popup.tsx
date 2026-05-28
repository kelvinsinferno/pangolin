// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Popup top-level component.
//
// Plan-LOCK: docs/issue-plans/mvp4-g-extension-e2e.md section 1
// (apps/extension/src/popup/Popup.tsx).
//
// State machine (delegated to useNativeHost):
//   loading      -> initial token-storage read
//   provisioning -> textarea + Save button (Q-a Option 1)
//   connecting   -> spinner-equivalent text
//   connected    -> account list with per-row Copy button
//   error        -> typed error label + Retry button
//
// data-testid attributes are stable test selectors used by the
// Puppeteer specs (apps/extension/e2e/).

import * as React from "react";
import { useState } from "react";
import { Button, Card, Text } from "./Placeholder";
import { accountSubtitle, sortAccounts } from "./account-list";
import { useNativeHost } from "./use-native-host";
import "./Popup.css";

export function Popup(): React.JSX.Element {
  const { state, submitToken, copyPassword, retry } = useNativeHost();

  return (
    <div className="pcl-popup-root" data-testid="popup-root">
      <h1 className="pcl-popup-brand">Pangolin</h1>
      <Card>
        {state.kind === "loading" ? <LoadingView /> : null}
        {state.kind === "provisioning" ? (
          <ProvisioningView onSubmit={submitToken} />
        ) : null}
        {state.kind === "connecting" ? <ConnectingView /> : null}
        {state.kind === "connected" ? (
          <ConnectedView
            session={state.session}
            accounts={state.accounts}
            onCopy={copyPassword}
          />
        ) : null}
        {state.kind === "error" ? (
          <ErrorView label={state.label} message={state.message} onRetry={retry} />
        ) : null}
      </Card>
    </div>
  );
}

function LoadingView(): React.JSX.Element {
  return (
    <div className="pcl-popup-body" data-testid="view-loading">
      <Text variant="body">Loading...</Text>
    </div>
  );
}

interface ProvisioningViewProps {
  onSubmit: (token: string) => Promise<void>;
}

function ProvisioningView({ onSubmit }: ProvisioningViewProps): React.JSX.Element {
  const [value, setValue] = useState<string>("");
  const [busy, setBusy] = useState<boolean>(false);
  const handleSave = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await onSubmit(value);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="pcl-popup-body" data-testid="view-provisioning">
      <Text variant="body">
        Paste the extension token printed by the Pangolin desktop install
        wizard:
      </Text>
      <textarea
        className="pcl-popup-token-input"
        data-testid="token-input"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        rows={3}
        autoFocus
        spellCheck={false}
        aria-label="Extension token"
      />
      <span data-testid="save-button-wrap">
        <Button onClick={handleSave} disabled={busy || value.trim().length === 0}>
          Save
        </Button>
      </span>
    </div>
  );
}

function ConnectingView(): React.JSX.Element {
  return (
    <div className="pcl-popup-body" data-testid="view-connecting">
      <div
        className="pcl-popup-status"
        role="status"
        aria-live="polite"
      >
        <span
          className="pcl-popup-status-dot"
          data-connected="false"
          aria-hidden="true"
        />
        <span>Connecting to desktop...</span>
      </div>
    </div>
  );
}

interface ConnectedViewProps {
  session: { vault_open: boolean; vault_unlocked: boolean };
  accounts: import("./native-host").FfiAccountSummary[];
  onCopy: (id: string) => Promise<void>;
}

function ConnectedView({
  session,
  accounts,
  onCopy,
}: ConnectedViewProps): React.JSX.Element {
  const sorted = sortAccounts(accounts);
  return (
    <div className="pcl-popup-body" data-testid="view-connected">
      <div
        className="pcl-popup-status"
        role="status"
        aria-live="polite"
      >
        <span
          className="pcl-popup-status-dot"
          data-connected="true"
          aria-hidden="true"
        />
        <span data-testid="status-text">Connected</span>
      </div>
      {!session.vault_unlocked ? (
        <Text variant="body">
          Desktop is connected but the vault is locked. Open the Pangolin
          desktop app to unlock.
        </Text>
      ) : null}
      {session.vault_unlocked && sorted.length === 0 ? (
        <Text variant="body">No accounts in this vault yet.</Text>
      ) : null}
      {session.vault_unlocked && sorted.length > 0 ? (
        <ul className="pcl-popup-account-list" data-testid="account-list">
          {sorted.map((a) => (
            <AccountRow key={a.id} account={a} onCopy={onCopy} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

interface AccountRowProps {
  account: import("./native-host").FfiAccountSummary;
  onCopy: (id: string) => Promise<void>;
}

function AccountRow({ account, onCopy }: AccountRowProps): React.JSX.Element {
  const [busy, setBusy] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const handleClick = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await onCopy(account.id);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li
      className="pcl-popup-account-row"
      data-testid="account-row"
      data-account-id={account.id}
    >
      <div className="pcl-popup-account-text">
        <div
          className="pcl-popup-account-name"
          data-testid="account-name"
        >
          {account.display_name}
        </div>
        <div
          className="pcl-popup-account-subtitle"
          data-testid="account-subtitle"
        >
          {accountSubtitle(account)}
        </div>
      </div>
      <span data-testid="copy-button-wrap">
        <Button onClick={handleClick} disabled={busy}>
          {copied ? "Copied" : "Copy"}
        </Button>
      </span>
    </li>
  );
}

interface ErrorViewProps {
  label: string;
  message: string;
  onRetry: () => Promise<void>;
}

function ErrorView({ label, message, onRetry }: ErrorViewProps): React.JSX.Element {
  const [busy, setBusy] = useState<boolean>(false);
  const handleRetry = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await onRetry();
    } finally {
      setBusy(false);
    }
  };
  const headline =
    label === "transport"
      ? "Desktop not running"
      : label === "session_locked"
        ? "Vault locked"
        : "Connection error";
  return (
    <div className="pcl-popup-body" data-testid="view-error">
      <div className="pcl-popup-status">
        <span
          className="pcl-popup-status-dot"
          data-connected="false"
          aria-hidden="true"
        />
        <span data-testid="error-headline">{headline}</span>
      </div>
      <Text variant="body">
        <span data-testid="error-label">{label}</span>: {message}
      </Text>
      <span data-testid="retry-button-wrap">
        <Button onClick={handleRetry} disabled={busy}>
          Retry
        </Button>
      </span>
    </div>
  );
}
