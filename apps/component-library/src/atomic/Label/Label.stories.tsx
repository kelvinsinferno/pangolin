// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Label } from './Label';

const meta: Meta<typeof Label> = {
  title: 'Atomic/Label',
  component: Label,
};

export default meta;
type Story = StoryObj<typeof Label>;

export const Default: Story = { args: { children: 'Password', htmlFor: 'demo' } };
export const Muted: Story = {
  args: { children: 'Must be at least 12 characters', muted: true, htmlFor: 'demo' },
};
