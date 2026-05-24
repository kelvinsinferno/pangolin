// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { Card } from './Card';

const meta: Meta<typeof Card> = {
  title: 'Composite/Card',
  component: Card,
};

export default meta;
type Story = StoryObj<typeof Card>;

export const Default: Story = {
  args: { elevation: 'sm', children: <p>Default surface with sm elevation.</p> },
};

export const Elevated: Story = {
  args: { elevation: 'lg', children: <p>High-elevation surface (modal-tier).</p> },
};
