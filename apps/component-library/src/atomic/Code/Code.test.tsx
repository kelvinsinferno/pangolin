// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Code } from './Code';

describe('Code', () => {
  it('renders an inline <code> by default', () => {
    render(<Code>0xabc</Code>);
    const el = screen.getByText('0xabc');
    expect(el.tagName).toBe('CODE');
    expect(el).toHaveClass('pcl-code--inline');
  });

  it('wraps block variant in a <pre>', () => {
    const { container } = render(<Code variant="block">$ ls</Code>);
    expect(container.querySelector('pre')).not.toBeNull();
    expect(container.querySelector('pre > code')).not.toBeNull();
  });
});
