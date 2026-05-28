// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

interface MV3Manifest {
  manifest_version: number;
  name: string;
  key?: string;
  version: string;
  description: string;
  action: { default_popup: string };
  background: { service_worker: string; type: string };
  content_scripts: Array<{ matches: string[]; js: string[]; run_at: string }>;
  permissions: string[];
  host_permissions: string[];
  icons: Record<string, string>;
}

// Per plan-LOCK §0a the manifest permission set is locked to exactly these
// four. Adding/removing a permission requires a plan-LOCK update.
const ALLOWED_PERMISSIONS = new Set<string>([
  'storage',
  'activeTab',
  'scripting',
  'nativeMessaging',
]);

function loadManifest(): MV3Manifest {
  const path = resolve(__dirname, '..', 'manifest.json');
  return JSON.parse(readFileSync(path, 'utf8')) as MV3Manifest;
}

describe('manifest.json', () => {
  const m = loadManifest();

  it('is Manifest V3', () => {
    expect(m.manifest_version).toBe(3);
  });

  it('declares a module service worker', () => {
    expect(m.background.service_worker).toBeTruthy();
    expect(m.background.type).toBe('module');
  });

  it('registers a content script matching <all_urls> at document_idle', () => {
    expect(m.content_scripts.length).toBeGreaterThanOrEqual(1);
    const first = m.content_scripts[0];
    expect(first).toBeDefined();
    expect(first!.matches).toContain('<all_urls>');
    expect(first!.run_at).toBe('document_idle');
  });

  it('declares only the four MVP-4-C permissions (no drift)', () => {
    for (const p of m.permissions) {
      expect(
        ALLOWED_PERMISSIONS.has(p),
        `Permission "${p}" is not in the MVP-4-C allowed set; update plan-LOCK §0a first.`,
      ).toBe(true);
    }
    // And every allowed permission is present (catches accidental removal).
    for (const p of ALLOWED_PERMISSIONS) {
      expect(m.permissions).toContain(p);
    }
  });

  it('grants <all_urls> host_permissions', () => {
    expect(m.host_permissions).toContain('<all_urls>');
  });

  it('does NOT declare the forbidden permissions (tabs, webRequest, unlimitedStorage)', () => {
    const forbidden = ['tabs', 'webRequest', 'unlimitedStorage'];
    for (const p of forbidden) {
      expect(m.permissions).not.toContain(p);
    }
  });

  it('declares the four icon sizes (16/32/48/128)', () => {
    expect(m.icons['16']).toBeDefined();
    expect(m.icons['32']).toBeDefined();
    expect(m.icons['48']).toBeDefined();
    expect(m.icons['128']).toBeDefined();
  });
});
