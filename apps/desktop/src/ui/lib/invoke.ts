// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Typed wrappers around Tauri v2's `invoke()` bridge.
 *
 * Mirrors the Rust-side `tauri::command` surface in `apps/desktop/src/
 * commands/` 1:1. Every wrapper:
 *
 * - takes a typed argument record (no positional args; Tauri's bridge
 *   passes by-name);
 * - returns a typed `Promise<T>`;
 * - throws `DesktopError` (the typed envelope from `error.rs`) for the
 *   error arm so the React side can discriminate on `kind`.
 *
 * The wrappers re-throw raw error envelopes; the calling hook
 * (`useVault`) is the layer that branches on `kind`.
 */
import { invoke as tauriInvoke } from '@tauri-apps/api/core';

// ---- Error envelope (mirror of Rust `DesktopError`) -------------------

export type DesktopErrorKind =
  | 'Session'
  | 'Validation'
  | 'Chain'
  | 'Store'
  | 'Recovery'
  | 'Sync'
  | 'Crypto'
  | 'Internal'
  | 'AuthenticationFailed';

export interface DesktopError {
  kind: DesktopErrorKind;
  /** Present on every variant except `AuthenticationFailed`. The
   *  `Validation` variant carries a nested `{ kind, message }` record
   *  but the Rust side flattens it through `#[serde(tag, content)]`
   *  so the wire shape is uniform: `{ kind: "Validation", message: { kind: "...", message: "..." } }`.
   *  We model the `message` field as `unknown` so callers narrow
   *  explicitly. */
  message?: unknown;
}

/** Type guard for `DesktopError`. Tauri's invoke() throws the JSON
 *  envelope as-is; this guard recovers the typed shape. */
export function isDesktopError(e: unknown): e is DesktopError {
  if (typeof e !== 'object' || e === null) return false;
  const k = (e as { kind?: unknown }).kind;
  return (
    k === 'Session' ||
    k === 'Validation' ||
    k === 'Chain' ||
    k === 'Store' ||
    k === 'Recovery' ||
    k === 'Sync' ||
    k === 'Crypto' ||
    k === 'Internal' ||
    k === 'AuthenticationFailed'
  );
}

// ---- Account DTO (mirror of Rust `AccountSummaryDto`) -----------------

export interface AccountSummary {
  /** 64-character lowercase hex of the 32-byte account id. */
  id: string;
  /** User-visible display name. */
  displayName: string;
  tags: string[];
  usernames: string[];
  urls: string[];
  passwordHistoryCount: number;
  hasTotp: boolean;
  /** Wall-clock unix-second timestamp of the most recent password
   *  rotation; `0` if the history is somehow empty. */
  currentPasswordChangedAt: number;
}

/** Internal wire shape — Rust's serde renames are camelCase-free
 *  (it's a Rust struct, so `display_name` etc. cross the wire as
 *  snake_case). We translate at the boundary so the React side only
 *  ever sees camelCase. */
interface AccountSummaryWire {
  id: string;
  display_name: string;
  tags: string[];
  usernames: string[];
  urls: string[];
  password_history_count: number;
  has_totp: boolean;
  current_password_changed_at: number;
}

function fromWire(w: AccountSummaryWire): AccountSummary {
  return {
    id: w.id,
    displayName: w.display_name,
    tags: w.tags,
    usernames: w.usernames,
    urls: w.urls,
    passwordHistoryCount: w.password_history_count,
    hasTotp: w.has_totp,
    currentPasswordChangedAt: w.current_password_changed_at,
  };
}

// ---- Command wrappers --------------------------------------------------

/** Open a vault file. */
export async function vaultOpen(path: string): Promise<void> {
  await tauriInvoke<void>('vault_open', { path });
}

/** Unlock the currently-open vault with the supplied master password. */
export async function vaultUnlock(password: string): Promise<void> {
  await tauriInvoke<void>('vault_unlock', { password });
}

/** Lock the currently-open vault (the handle stays open; subsequent
 *  `vault_unlock` re-activates the session). */
export async function vaultLock(): Promise<void> {
  await tauriInvoke<void>('vault_lock');
}

/** Close the currently-open vault. Returns to the Welcome screen. */
export async function vaultClose(): Promise<void> {
  await tauriInvoke<void>('vault_close');
}

/** List every account in the unlocked vault. */
export async function accountsList(): Promise<AccountSummary[]> {
  const list = await tauriInvoke<AccountSummaryWire[]>('accounts_list');
  return list.map(fromWire);
}

/** Fetch a single account's metadata. */
export async function accountShow(id: string): Promise<AccountSummary> {
  const wire = await tauriInvoke<AccountSummaryWire>('account_show', { id });
  return fromWire(wire);
}

/** Reveal the current head-of-history plaintext password for an
 *  account. The caller MUST clear the local state slot within 10 s per
 *  Browser-Ext spec §4.7 (the AccountDetailScreen's useEffect enforces
 *  this). */
export async function revealPassword(id: string): Promise<string> {
  return tauriInvoke<string>('reveal_password', { id });
}

/** Write `text` to the OS clipboard. For PASSWORD copies prefer
 *  {@link copyPasswordToClipboard} — it keeps the plaintext entirely
 *  Rust-side, never crossing it through V8. This wrapper stays for
 *  non-secret strings (e.g. an account username). */
export async function copyToClipboard(text: string): Promise<void> {
  await tauriInvoke<void>('copy_to_clipboard', { text });
}

/** **Copy the head-of-history plaintext password directly to the OS
 *  clipboard** — the plaintext NEVER crosses the FFI boundary back
 *  into V8 (audit HIGH H-1 hardening, 2026-05-25). The Rust side
 *  reads the password via FFI + writes to the clipboard plugin in
 *  the same `tauri::command` body that holds the zeroizing buffer.
 *
 *  Use this for the AccountDetailScreen's "Copy" button. For the
 *  reveal-to-view flow (the user wants to SEE the password before
 *  deciding to copy) use {@link revealPassword}. */
export async function copyPasswordToClipboard(id: string): Promise<void> {
  await tauriInvoke<void>('copy_password_to_clipboard', { id });
}

// ---- Pairing DTOs (mirror of Rust commands::pairing) -----------------
// MVP-4-I multi-device pairing (add-device). Every field below is
// non-secret (the pairing payload + sealed envelope are exactly what a QR
// exposes; the SAS is shown to the human). The only secrets are the
// master passwords, which cross via the same direct-invoke path as
// `vaultUnlock` — see plan §4 L1.

/** The non-secret pairing payload, in the shapes the wizard needs. */
export interface PairingPayload {
  /** Length-strict payload byte-form (for the QR render + to pass back to
   *  the byte-taking commands). */
  bytes: number[];
  /** Copy-pasteable base32 + checksum text form (also what the QR
   *  encodes, so a scan round-trips through `pairingDecodeString`). */
  stringForm: string;
  /** 64-char lowercase hex of the 32-byte vault id this payload joins
   *  (device B passes this to `pairingOpenAndJoin`). */
  vaultId: string;
  /** 64-char lowercase hex of the 32-byte device id. */
  deviceId: string;
  /** 40-char lowercase hex of the 20-byte EVM signer address. */
  signer: string;
}

/** The non-secret sealed-VDK envelope (manager → new device). */
export interface SealedEnvelope {
  bytes: number[];
  stringForm: string;
}

/** One paired device (read-only list). */
export interface DeviceInfo {
  /** 64-char lowercase hex of the 32-byte device id. */
  id: string;
  label: string;
  isCurrent: boolean;
  registeredAt: number;
  /** Lowercase hex of the 20-byte per-device EVM address ('' until
   *  back-filled on first unlock). */
  evmAddress: string;
}

interface PairingPayloadWire {
  bytes: number[];
  string_form: string;
  vault_id: string;
  device_id: string;
  signer: string;
}

interface SealedEnvelopeWire {
  bytes: number[];
  string_form: string;
}

interface DeviceInfoWire {
  id: string;
  label: string;
  is_current: boolean;
  registered_at: number;
  evm_address: string;
}

function payloadFromWire(w: PairingPayloadWire): PairingPayload {
  return {
    bytes: w.bytes,
    stringForm: w.string_form,
    vaultId: w.vault_id,
    deviceId: w.device_id,
    signer: w.signer,
  };
}

function envelopeFromWire(w: SealedEnvelopeWire): SealedEnvelope {
  return { bytes: w.bytes, stringForm: w.string_form };
}

function deviceFromWire(w: DeviceInfoWire): DeviceInfo {
  return {
    id: w.id,
    label: w.label,
    isCurrent: w.is_current,
    registeredAt: w.registered_at,
    evmAddress: w.evm_address,
  };
}

// ---- Pairing command wrappers ----------------------------------------

/** **NEW device, step 1.** Generate this device's pairing payload. */
export async function pairingBeginNewDevice(): Promise<PairingPayload> {
  return payloadFromWire(
    await tauriInvoke<PairingPayloadWire>('pairing_begin_new_device'),
  );
}

/** Validate + decode a scanned/pasted payload (byte form). The UI moves
 *  blobs as base64 of these bytes, so this is the only decode the UI needs.
 *  Also how device B learns the manager's `vaultId`. */
export async function pairingDecodeBytes(bytes: number[]): Promise<PairingPayload> {
  return payloadFromWire(
    await tauriInvoke<PairingPayloadWire>('pairing_decode_bytes', { bytes }),
  );
}

/** **MANAGER, step 2.** Build the manager's mirror payload, re-bound to
 *  device B's freshness nonce. `theirBytes` is B's payload byte-form. */
export async function pairingLocalPayload(theirBytes: number[]): Promise<PairingPayload> {
  return payloadFromWire(
    await tauriInvoke<PairingPayloadWire>('pairing_local_payload', { theirBytes }),
  );
}

/** **Both roles.** Derive the 6-digit SAS over the two payload byte-forms
 *  (canonical-symmetric). */
export async function pairingDeriveSas(
  aBytes: number[],
  bBytes: number[],
): Promise<string> {
  return tauriInvoke<string>('pairing_derive_sas', { aBytes, bBytes });
}

/** **NEW device, FINAL step.** Open the sealed envelope, install the VDK
 *  under a NEW master password, adopt the manager's vault id. Leaves the
 *  vault Locked — follow with {@link vaultUnlock}. */
export async function pairingOpenAndJoin(args: {
  sealedBytes: number[];
  vaultId: string;
  epoch: number;
  newPassword: string;
}): Promise<void> {
  await tauriInvoke<void>('pairing_open_and_join', args);
}

/** Read the read-only paired-device list. */
export async function pairingDeviceList(): Promise<DeviceInfo[]> {
  const list = await tauriInvoke<DeviceInfoWire[]>('pairing_device_list');
  return list.map(deviceFromWire);
}

/** **MANAGER.** Bootstrap the vault's on-chain device set (once per
 *  vault, before the first add-device). */
export async function pairingChainBootstrap(password: string): Promise<void> {
  await tauriInvoke<void>('pairing_chain_bootstrap', { password });
}

/** **MANAGER, FINAL CONFIRMATION.** After the human confirms the SAS,
 *  authorize device B on-chain + return the sealed envelope. `theirBytes`
 *  is B's payload byte-form. */
export async function pairingAddDevice(
  theirBytes: number[],
  password: string,
): Promise<SealedEnvelope> {
  return envelopeFromWire(
    await tauriInvoke<SealedEnvelopeWire>('pairing_add_device', {
      theirBytes,
      password,
    }),
  );
}

// ---- MVP-4-J: device removal + authorized-set / manager / rotation ----

/** One device in the vault's live on-chain authorized set. */
export interface AuthorizedDevice {
  /** 40-char hex of the 20-byte EVM signer (pass to {@link pairingRemoveDevice}). */
  signer: string;
  isCurrent: boolean;
  isManager: boolean;
  /** 64-char hex device id if known locally, else ''. */
  deviceId: string;
}

/** An outstanding VDK rotation owed after a removal. */
export interface RotationPending {
  removedSigner: string;
  observedEpoch: number;
}

/** The outcome of a completed rotation. */
export interface RotationResult {
  newEpoch: number;
  unknownSurvivors: string[];
}

interface AuthorizedDeviceWire {
  signer: string;
  is_current: boolean;
  is_manager: boolean;
  device_id: string;
}

interface RotationPendingWire {
  removed_signer: string;
  observed_epoch: number;
}

interface RotationResultWire {
  new_epoch: number;
  unknown_survivors: string[];
}

function authorizedFromWire(w: AuthorizedDeviceWire): AuthorizedDevice {
  return {
    signer: w.signer,
    isCurrent: w.is_current,
    isManager: w.is_manager,
    deviceId: w.device_id,
  };
}

/** List the vault's LIVE on-chain authorized devices (the removable list). */
export async function pairingListAuthorizedDevices(): Promise<AuthorizedDevice[]> {
  const list = await tauriInvoke<AuthorizedDeviceWire[]>('pairing_list_authorized_devices');
  return list.map(authorizedFromWire);
}

/** **MANAGER-ONLY.** Remove a device (broadcast removeDevice + queue the
 *  rotation). MUST be followed by {@link pairingCompleteRotation}. */
export async function pairingRemoveDevice(signer: string): Promise<void> {
  await tauriInvoke<void>('pairing_remove_device', { signer });
}

/** Read outstanding rotation-pending rows (non-empty ⇒ a removal's re-key
 *  is not yet finished). */
export async function pairingPendingRotations(): Promise<RotationPending[]> {
  const list = await tauriInvoke<RotationPendingWire[]>('pairing_pending_rotations');
  return list.map((w) => ({
    removedSigner: w.removed_signer,
    observedEpoch: w.observed_epoch,
  }));
}

/** Complete the VDK rotation owed after a removal (re-key survivors, advance
 *  the epoch). Leaves the vault Locked — follow with {@link vaultUnlock}. */
export async function pairingCompleteRotation(password: string): Promise<RotationResult> {
  const w = await tauriInvoke<RotationResultWire>('pairing_complete_rotation', { password });
  return { newEpoch: w.new_epoch, unknownSurvivors: w.unknown_survivors };
}

// ---- MVP-4-K: manager handoff / promotion ----

/** An in-flight manager promotion. */
export interface PromotionPending {
  /** 40-char hex of the candidate's EVM signer. */
  candidate: string;
  /** Unix-second timestamp the 48h delay elapses. */
  readyAt: number;
}

interface PromotionPendingWire {
  candidate: string;
  ready_at: number;
}

function promotionFromWire(w: PromotionPendingWire): PromotionPending {
  return { candidate: w.candidate, readyAt: w.ready_at };
}

/** **CANDIDATE-INITIATED.** Propose THIS device as the vault's next manager
 *  (starts the 48h delay). Returns the pending promotion. */
export async function pairingProposePromotion(): Promise<PromotionPending> {
  return promotionFromWire(
    await tauriInvoke<PromotionPendingWire>('pairing_propose_promotion'),
  );
}

/** **PERMISSIONLESS.** Finalize a pending promotion after its 48h delay. */
export async function pairingFinalizePromotion(): Promise<void> {
  await tauriInvoke<void>('pairing_finalize_promotion');
}

/** **MANAGER-ONLY.** Veto a pending promotion. */
export async function pairingCancelPromotion(): Promise<void> {
  await tauriInvoke<void>('pairing_cancel_promotion');
}

/** Read the in-flight manager promotion, if any (drives the banner +
 *  countdown + veto). */
export async function pairingPendingPromotion(): Promise<PromotionPending | null> {
  const w = await tauriInvoke<PromotionPendingWire | null>('pairing_pending_promotion');
  return w === null ? null : promotionFromWire(w);
}

// ---- MVP-4-L (L-D): recovery backup + health panel ----

/** A freshly-created recovery backup. The seed phrase is the ONE secret —
 *  recorded offline, never stored. The backup ALWAYS requires guardians to
 *  actually recover (it is an aid to the guardian flow, not a standalone
 *  key). */
export interface Backup {
  /** The 24 BIP-39 words, shown ONCE. */
  seedPhraseWords: string[];
  /** The encrypted envelope, byte form (save to a file). */
  bytes: number[];
  /** The encrypted envelope, copy-paste text form. */
  text: string;
}

/** Read-only recovery-health summary for this vault. */
export interface RecoveryHealth {
  /** 40-char hex of the current on-chain vault authority ('' / zeros if
   *  none). */
  authority: string;
  /** 0=None, 1=Pending, 2=Finalized, 3=Canceled. */
  recoveryStatus: number;
  /** 40-char hex of an in-flight recovery's proposed authority ('' if
   *  none). */
  proposedAuthority: string;
  attemptNonce: number;
}

interface BackupWire {
  seed_phrase_words: string[];
  bytes: number[];
  text: string;
}

interface RecoveryHealthWire {
  authority: string;
  recovery_status: number;
  proposed_authority: string;
  attempt_nonce: number;
}

/** Create a recovery backup (24-word phrase + envelope). Requires guardians
 *  to have been onboarded first. The phrase is shown once + never stored. */
export async function recoveryCreateBackup(password: string): Promise<Backup> {
  const w = await tauriInvoke<BackupWire>('recovery_create_backup', { password });
  return { seedPhraseWords: w.seed_phrase_words, bytes: w.bytes, text: w.text };
}

/** Read this vault's recovery health (current authority + any in-flight
 *  recovery). Throws if the vault isn't set up on-chain for recovery. */
export async function recoveryHealth(): Promise<RecoveryHealth> {
  const w = await tauriInvoke<RecoveryHealthWire>('recovery_health');
  return {
    authority: w.authority,
    recoveryStatus: w.recovery_status,
    proposedAuthority: w.proposed_authority,
    attemptNonce: w.attempt_nonce,
  };
}

// ---- MVP-4-L (L-A): guardian-onboarding wizard surface ----

/** A guardian invite — the non-secret (sealing-pubkey, signer-address)
 *  pair the owner needs to set up social recovery. Hex-encoded for direct
 *  display + transport via the wizard. */
export interface GuardianInvite {
  /** 64-char lowercase hex of the 32-byte X25519 sealing pubkey. The
   *  off-chain Shamir share for this guardian is sealed against this key. */
  x25519SealingPub: string;
  /** 40-char lowercase hex of the 20-byte secp256k1 EVM signer address. The
   *  on-chain merkle root commits all M of these. */
  signer: string;
  /** The canonical base32 + 4-byte-checksum text form. Echoed back so the
   *  UI can show / copy it without re-encoding. */
  stringForm: string;
}

interface GuardianInviteWire {
  x25519_sealing_pub: string;
  signer: string;
  string_form: string;
}

function inviteFromWire(w: GuardianInviteWire): GuardianInvite {
  return {
    x25519SealingPub: w.x25519_sealing_pub,
    signer: w.signer,
    stringForm: w.string_form,
  };
}

/** Result of recoveryOnboardGuardians — the epoch the off-chain escrow was
 *  written at (genesis 0 for the first onboard on a vault). */
export interface OnboardingResult {
  epoch: number;
}

interface OnboardingResultWire {
  epoch: number;
}

/** Receipt anchor returned from any chain-mutating recovery command. */
export interface TxOutcome {
  /** 64-char lowercase hex of the 32-byte transaction hash. */
  txHash: string;
  /** Block number the tx was included in (1-conf receipt). */
  blockNumber: number;
}

interface TxOutcomeWire {
  tx_hash: string;
  block_number: number;
}

/** **THIS DEVICE.** Export this device's guardian identity. The L-A wizard
 *  uses this for the self-as-guardian guard (Q-d) — refuses any ingested
 *  invite whose pubkey matches this. */
export async function guardianIdentityExport(): Promise<GuardianInvite> {
  const w = await tauriInvoke<GuardianInviteWire>('guardian_identity_export');
  return inviteFromWire(w);
}

/** Decode a guardian-supplied invite TEXT into the structured DTO.
 *  Length-strict + domain-checked + version-gated FFI-side; throws
 *  Validation on any malformed input. */
export async function guardianInviteDecodeText(text: string): Promise<GuardianInvite> {
  const w = await tauriInvoke<GuardianInviteWire>('guardian_invite_decode_text', { text });
  return inviteFromWire(w);
}

/** **OWNER, step 1 of 2.** Seed the off-chain escrow: Shamir-split a fresh
 *  RecoveryWrapKey into M shares + seal to each guardian's pubkey.
 *  `x25519Pubs` is the M hex-encoded sealing pubkeys collected from the
 *  guardian invites (each 64 hex chars); `threshold` is t. The FFI
 *  revalidates t/M bounds. */
export async function recoveryOnboardGuardians(
  threshold: number,
  x25519Pubs: string[],
): Promise<OnboardingResult> {
  const w = await tauriInvoke<OnboardingResultWire>('recovery_onboard_guardians', {
    threshold,
    x25519Pubs,
  });
  return { epoch: w.epoch };
}

/** **OWNER, step 2 of 2.** Commit the on-chain guardian merkle root +
 *  self-bootstrap this device's EVM wallet as the vault authority. The FFI
 *  computes the merkle root engine-side. */
export async function recoverySetGuardianSet(
  password: string,
  evmAddrs: string[],
  threshold: number,
): Promise<TxOutcome> {
  const w = await tauriInvoke<TxOutcomeWire>('recovery_set_guardian_set', {
    password,
    evmAddrs,
    threshold,
  });
  return { txHash: w.tx_hash, blockNumber: w.block_number };
}
