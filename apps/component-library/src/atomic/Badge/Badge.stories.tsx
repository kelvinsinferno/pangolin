// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Badge } from './Badge';

const meta: Meta<typeof Badge> = {
  title: 'Atomic/Badge',
  component: Badge,
};

export default meta;
type Story = StoryObj<typeof Badge>;

export const Neutral: Story = { args: { children: 'Beta' } };
export const Success: Story = { args: { tone: 'success', children: 'Connected' } };
export const Warning: Story = { args: { tone: 'warning', children: 'Pending' } };
export const Danger: Story = { args: { tone: 'danger', children: 'Locked' } };
