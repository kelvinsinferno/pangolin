// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Avatar } from './Avatar';

const meta: Meta<typeof Avatar> = {
  title: 'Atomic/Avatar',
  component: Avatar,
};

export default meta;
type Story = StoryObj<typeof Avatar>;

export const InitialsFallback: Story = { args: { name: 'Satoshi Nakamoto' } };
export const SmallInitials: Story = { args: { name: 'Alice', size: 'sm' } };
export const LargeInitials: Story = {
  args: { name: 'Wallet of Pangolin', size: 'lg' },
};
