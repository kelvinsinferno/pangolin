// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Code } from './Code';

const meta: Meta<typeof Code> = {
  title: 'Atomic/Code',
  component: Code,
};

export default meta;
type Story = StoryObj<typeof Code>;

export const Inline: Story = {
  args: { variant: 'inline', children: '0xabc...def' },
};
export const Block: Story = {
  args: {
    variant: 'block',
    children: '$ pangolin account list\nWallet of Satoshi  m/44h/60h/0h/0/0',
  },
};
