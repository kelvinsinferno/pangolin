// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { ListRow } from './ListRow';
import { Avatar } from '../../atomic/Avatar/Avatar';
import { IconButton } from '../../atomic/IconButton/IconButton';
import { Chevron } from '../../icons/Chevron';

const meta: Meta<typeof ListRow> = {
  title: 'Composite/ListRow',
  component: ListRow,
};

export default meta;
type Story = StoryObj<typeof ListRow>;

export const Account: Story = {
  args: {
    icon: <Avatar name="Wallet of Satoshi" size="sm" />,
    title: 'Wallet of Satoshi',
    subtitle: '0xabc...def — base-sepolia',
    rightAction: <IconButton aria-label="Open" icon={<Chevron direction="right" />} />,
  },
};

export const TitleOnly: Story = {
  args: { title: 'Simple list row' },
};
