// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Meta, StoryObj } from '@storybook/react';
import { SeedPhraseGrid } from './SeedPhraseGrid';

const meta: Meta<typeof SeedPhraseGrid> = {
  title: 'Composite/SeedPhraseGrid',
  component: SeedPhraseGrid,
};

export default meta;
type Story = StoryObj<typeof SeedPhraseGrid>;

const TWELVE = [
  'witch', 'collapse', 'practice', 'feed',
  'shame', 'open', 'despair', 'creek',
  'road', 'again', 'ice', 'least',
];

const TWENTY_FOUR = [
  ...TWELVE,
  'echo', 'border', 'jaguar', 'silk',
  'planet', 'orbit', 'thicket', 'render',
  'meadow', 'siren', 'velvet', 'kindred',
];

export const TwelveWords: Story = { args: { words: TWELVE } };
export const TwentyFourWords: Story = { args: { words: TWENTY_FOUR } };
