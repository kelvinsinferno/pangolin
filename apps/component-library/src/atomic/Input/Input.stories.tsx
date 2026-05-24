// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Input } from './Input';
import { Lock } from '../../icons/Lock';

const meta: Meta<typeof Input> = {
  title: 'Atomic/Input',
  component: Input,
};

export default meta;
type Story = StoryObj<typeof Input>;

export const Text: Story = {
  args: { label: 'Account name', placeholder: 'Wallet of Satoshi' },
};

export const Password: Story = {
  args: {
    label: 'Password',
    placeholder: 'Enter master password',
    type: 'password',
    leadingIcon: <Lock />,
  },
};
