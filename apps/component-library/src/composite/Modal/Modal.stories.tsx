// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import type { Meta, StoryObj } from '@storybook/react';
import { Modal } from './Modal';
import { Button } from '../../atomic/Button/Button';

const meta: Meta<typeof Modal> = {
  title: 'Composite/Modal',
  component: Modal,
};

export default meta;
type Story = StoryObj<typeof Modal>;

function ModalDemo() {
  const [open, setOpen] = useState(true);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Open modal</Button>
      <Modal open={open} onClose={() => setOpen(false)} title="Confirm delete">
        <p>This will permanently remove the account. This cannot be undone.</p>
        <div style={{ display: 'flex', gap: 8, marginTop: 16, justifyContent: 'flex-end' }}>
          <Button variant="secondary" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={() => setOpen(false)}>
            Delete
          </Button>
        </div>
      </Modal>
    </>
  );
}

export const Default: Story = {
  render: () => <ModalDemo />,
};
