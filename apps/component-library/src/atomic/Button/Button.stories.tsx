// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Button } from './Button';
import { Plus } from '../../icons/Plus';

const meta: Meta<typeof Button> = {
  title: 'Atomic/Button',
  component: Button,
  args: { children: 'Continue' },
  argTypes: {
    variant: { control: 'select', options: ['primary', 'secondary', 'ghost', 'danger'] },
    size: { control: 'select', options: ['sm', 'md'] },
  },
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Primary: Story = { args: { variant: 'primary' } };
export const Secondary: Story = { args: { variant: 'secondary' } };
export const Ghost: Story = { args: { variant: 'ghost' } };
export const Danger: Story = { args: { variant: 'danger', children: 'Delete account' } };
export const Small: Story = { args: { variant: 'primary', size: 'sm' } };
export const WithLeadingIcon: Story = {
  args: { variant: 'primary', leadingIcon: <Plus />, children: 'Add account' },
};
export const Disabled: Story = { args: { variant: 'primary', disabled: true } };
