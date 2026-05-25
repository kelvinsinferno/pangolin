// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { PasswordMeter } from './PasswordMeter';

const meta: Meta<typeof PasswordMeter> = {
  title: 'Composite/PasswordMeter',
  component: PasswordMeter,
};

export default meta;
type Story = StoryObj<typeof PasswordMeter>;

export const VeryWeak: Story = { args: { password: 'abc' } };
export const Fair: Story = { args: { password: 'Sunshine99' } };
export const Strong: Story = { args: { password: 'Tr0ub4dor&3-Tr0ub4dor' } };
export const VeryStrong: Story = {
  args: { password: 'correct-horse-battery-staple-9!Q' },
};
