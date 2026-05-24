// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Tag } from './Tag';

const meta: Meta<typeof Tag> = {
  title: 'Atomic/Tag',
  component: Tag,
};

export default meta;
type Story = StoryObj<typeof Tag>;

export const Plain: Story = { args: { children: 'base-sepolia' } };
export const Removable: Story = {
  args: { children: 'hardware-key', onRemove: () => undefined },
};
