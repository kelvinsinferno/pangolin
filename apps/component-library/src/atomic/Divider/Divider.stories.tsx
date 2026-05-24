// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Divider } from './Divider';

const meta: Meta<typeof Divider> = {
  title: 'Atomic/Divider',
  component: Divider,
};

export default meta;
type Story = StoryObj<typeof Divider>;

export const Horizontal: Story = { args: { orientation: 'horizontal' } };
export const Vertical: Story = {
  args: { orientation: 'vertical' },
  decorators: [
    (Story) => (
      <div style={{ display: 'inline-flex', alignItems: 'stretch', height: 40, gap: 8 }}>
        <span>left</span>
        <Story />
        <span>right</span>
      </div>
    ),
  ],
};
