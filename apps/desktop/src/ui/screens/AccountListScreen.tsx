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
        <ul className="account-list-screen__list" data-testid="account-list">
          {accounts.map((acct) => (
            <li key={acct.id}>
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
      )}
    </main>
  );
}
