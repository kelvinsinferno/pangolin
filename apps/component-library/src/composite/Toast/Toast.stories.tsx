// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Toast } from './Toast';

const meta: Meta<typeof Toast> = {
  title: 'Composite/Toast',
  component: Toast,
};

export default meta;
type Story = StoryObj<typeof Toast>;

export const Success: Story = {
  args: { variant: 'success', children: 'Account created successfully.', durationMs: 0 },
};
export const Warning: Story = {
  args: { variant: 'warning', children: 'Vault auto-locked after 5 minutes.', durationMs: 0 },
};
export const Danger: Story = {
  args: { variant: 'danger', children: 'Failed to broadcast revision.', durationMs: 0 },
};
