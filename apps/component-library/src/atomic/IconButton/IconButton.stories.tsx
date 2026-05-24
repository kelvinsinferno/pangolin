// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { IconButton } from './IconButton';
import { Copy } from '../../icons/Copy';
import { X } from '../../icons/X';

const meta: Meta<typeof IconButton> = {
  title: 'Atomic/IconButton',
  component: IconButton,
};

export default meta;
type Story = StoryObj<typeof IconButton>;

export const CopyAction: Story = {
  args: { 'aria-label': 'Copy address', icon: <Copy /> },
};

export const Close: Story = {
  args: { 'aria-label': 'Close', icon: <X />, size: 'sm' },
};
