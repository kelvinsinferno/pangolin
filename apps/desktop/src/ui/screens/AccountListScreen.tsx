// SPDX-License-Identifier: AGPL-3.0-or-later
import { Button, ListRow } from '@pangolin/component-library';

import type { AccountSummary } from '../lib/invoke';

export interface AccountListScreenProps {
  accounts: AccountSummary[];
  onSelect: (id: string) => Promise<void>;
  onLock: () => Promise<void>;
}

/**
 * Account list — the post-unlock landing surface. Renders one
 * `ListRow` per account; clicking a row drives the state machine into
 * the detail screen.
 *
 * No search this slice (per plan §0b — deferred to MVP-4 back-half).
 */
export function AccountListScreen({ accounts, onSelect, onLock }: AccountListScreenProps) {
  return (
    <main className="account-list-screen" aria-labelledby="account-list-title">
      <header className="account-list-screen__header">
        <h1 id="account-list-title">Accounts</h1>
        <Button variant="ghost" onClick={onLock} data-testid="lock-button">
          Lock
        </Button>
      </header>
      {accounts.length === 0 ? (
        <p className="account-list-screen__empty">No accounts in this vault.</p>
      ) : (
        // MVP-4-F E2E gate: the wrapper carries `accounts-list` (the plan
        // §3.4 stable ID) while the `<ul>` keeps the Vitest contract
        // (`data-testid="account-list"`). The plan's WebDriverIO selector
        // is `accounts-list`; the existing Vitest selector is preserved.
        <div data-testid="accounts-list">
          <ul className="account-list-screen__list" data-testid="account-list">
            {accounts.map((acct, index) => (
              <li key={acct.id} data-testid={`account-row-${index}`}>
                <ListRow
                  interactive
                  title={acct.displayName}
                  subtitle={acct.usernames[0] ?? ''}
                  onClick={() => {
                    void onSelect(acct.id);
                  }}
                  data-testid={`account-row-${acct.id}`}
                />
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  );
}
