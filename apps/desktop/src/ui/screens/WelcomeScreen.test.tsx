// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import { WelcomeScreen } from './WelcomeScreen';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';

vi.mock('@tauri-apps/plugin-dialog', () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

const mockedOpen = openDialog as unknown as ReturnType<typeof vi.fn>;
const mockedSave = saveDialog as unknown as ReturnType<typeof vi.fn>;

describe('WelcomeScreen (MVP-4-N)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders both action buttons enabled by default', () => {
    render(
      <WelcomeScreen onOpen={vi.fn()} onCreate={vi.fn()} />,
    );
    const create = screen.getByTestId('welcome-create-button');
    const open = screen.getByTestId('welcome-open-button');
    expect(create).toBeEnabled();
    expect(open).toBeEnabled();
    expect(create).toHaveTextContent('Create new vault');
    expect(open).toHaveTextContent('Open existing vault');
  });

  it('Create button opens the save dialog with .pvf filter + calls onCreate with the chosen path', async () => {
    mockedSave.mockResolvedValue('/home/user/vault.pvf');
    const onCreate = vi.fn(async () => {});
    render(<WelcomeScreen onOpen={vi.fn()} onCreate={onCreate} />);
    fireEvent.click(screen.getByTestId('welcome-create-button'));
    await waitFor(() => {
      expect(mockedSave).toHaveBeenCalledWith(
        expect.objectContaining({
          defaultPath: 'vault.pvf',
          filters: [{ name: 'Pangolin vault', extensions: ['pvf'] }],
        }),
      );
    });
    await waitFor(() => {
      expect(onCreate).toHaveBeenCalledWith('/home/user/vault.pvf');
    });
  });

  it('Create with cancelled dialog (null) does NOT call onCreate', async () => {
    mockedSave.mockResolvedValue(null);
    const onCreate = vi.fn(async () => {});
    render(<WelcomeScreen onOpen={vi.fn()} onCreate={onCreate} />);
    fireEvent.click(screen.getByTestId('welcome-create-button'));
    await waitFor(() => {
      expect(mockedSave).toHaveBeenCalled();
    });
    expect(onCreate).not.toHaveBeenCalled();
  });

  it('Open button uses native open dialog + calls onOpen with the selected file', async () => {
    mockedOpen.mockResolvedValue('/home/user/existing.pvf');
    const onOpen = vi.fn(async () => {});
    render(<WelcomeScreen onOpen={onOpen} onCreate={vi.fn()} />);
    fireEvent.click(screen.getByTestId('welcome-open-button'));
    await waitFor(() => {
      expect(mockedOpen).toHaveBeenCalledWith(
        expect.objectContaining({
          multiple: false,
          directory: false,
          filters: [{ name: 'Pangolin vault', extensions: ['pvf'] }],
        }),
      );
    });
    await waitFor(() => {
      expect(onOpen).toHaveBeenCalledWith('/home/user/existing.pvf');
    });
  });

  it('Open with cancelled dialog (null) does NOT call onOpen', async () => {
    mockedOpen.mockResolvedValue(null);
    const onOpen = vi.fn(async () => {});
    render(<WelcomeScreen onOpen={onOpen} onCreate={vi.fn()} />);
    fireEvent.click(screen.getByTestId('welcome-open-button'));
    await waitFor(() => {
      expect(mockedOpen).toHaveBeenCalled();
    });
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('Dialog plugin throw surfaces via onError, not as a crash', async () => {
    mockedSave.mockRejectedValue(new Error('dialog plugin not registered'));
    const onError = vi.fn();
    render(
      <WelcomeScreen onOpen={vi.fn()} onCreate={vi.fn()} onError={onError} />,
    );
    fireEvent.click(screen.getByTestId('welcome-create-button'));
    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(
        expect.stringContaining('dialog plugin not registered'),
      );
    });
  });
});
