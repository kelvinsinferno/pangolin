// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { QRCode } from './QRCode';

const meta: Meta<typeof QRCode> = {
  title: 'Composite/QRCode',
  component: QRCode,
};

export default meta;
type Story = StoryObj<typeof QRCode>;

export const Default: Story = {
  args: { value: 'pangolin-pairing:abcdef0123456789', size: 200 },
};

export const Small: Story = {
  args: { value: 'pangolin-pairing:abcdef0123456789', size: 120 },
};

export const LongPayload: Story = {
  args: {
    value: 'a'.repeat(200),
    size: 240,
    label: 'Pairing payload QR',
  },
};
