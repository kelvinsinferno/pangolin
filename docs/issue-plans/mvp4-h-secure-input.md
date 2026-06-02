<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-H — secure-input plugin (native password widget) — plan-gate LOCKED

**Status: LOCKED — Kelvin call 2026-06-01.** Q-a..d all resolved.

## 0. One-paragraph summary

Replace every React `<Input type="password">` in `apps/desktop/` with an
OS-native password dialog, so plaintext passwords never enter the V8 heap.
Today (option 1, MVP-4-B): React holds the password as a JS string, then
`invoke('vault_unlock', { password })` ships it through Tauri's bridge into
`SecretPassword::new(bytes)` which immediately zeroizes; the JS string
lingers in V8 until GC (ms to seconds). MVP-4-H ships option 2: a
per-OS native password dialog (Win32 `TaskDialogIndirect` with edit
control / macOS `NSAlert` + `NSSecureTextField` / Linux `GtkDialog` +
`GtkEntry`) that takes input directly into Rust, never crossing JS at
all. Ships BEFORE mainnet, alongside the D-011 external audit. Closes
the V8-heap-residue surface the closed-beta accepted under option 1.

Reference posture memory: [`pangolin_secure_input.md`](../../.claude/projects/C--Users-kelvi/memory/pangolin_secure_input.md).

## 0a. LOCKED decisions

**Kelvin-approved (2026-06-01):**

- **Q-a — Architecture = OS-standard native dialog.** Per OS: Win32
  `TaskDialogIndirect` with a custom edit control on Windows, `NSAlert`
  with `NSSecureTextField` accessory view on macOS, `GtkDialog` +
  `GtkEntry visibility=FALSE` on Linux. Smallest new attack surface;
  leverages well-tested OS primitives. UX varies per platform (matches
  what users see in native apps on each OS — accepted trade-off).
- **Q-b — Scope = all 11 password inputs upgrade.** No partial
  migration; coherent posture across the whole desktop app. List in §1.
- **Q-c — Plugin-failure behavior = hard-fail.** Missing OS support /
  dev sandbox / plugin link error → typed `DesktopError::Validation
  { kind: "secure_input_unavailable", message: "..." }` and the wizard
  refuses to proceed. The whole point of MVP-4-H is to close the
  V8-password path; a silent fallback would defeat the audit posture.
- **Q-d — Test strategy = hybrid.** Wizard-level wdio E2Es use a
  `__test__secure_input_inject` test-hook (mirrors the existing
  `__test__force_unlock` from MVP-4-F); a SEPARATE small native-widget
  integration suite uses OS automation (AutoIt on Windows / AppleScript
  on macOS / xdotool on Linux) to exercise the actual per-OS code paths
  in CI. Best of both: real-widget signal + bounded flake blast radius.

**Self-locked (no Kelvin gate needed):**

- **Plugin code lives in `apps/desktop/src/secure_input/`** as a module
  (not a separate `crates/pangolin-secure-input/` crate). pangolin-desktop
  is the only consumer; embedding avoids a new crate's audit/dep
  surface for a desktop-only feature. Three per-OS sub-modules
  (`windows.rs`, `macos.rs`, `linux.rs`) gated via `cfg(target_os)`.
- **Per-OS native deps**: `windows` 0.59 (Win32 bindings on Windows),
  `cocoa` 0.26 + `objc2` 0.5 (macOS), `gtk` 0.18 (already in Tauri's
  Linux dep tree — reuse). No new heavy deps.
- **No bytes ever cross the Tauri bridge as `Vec<u8>` / `String`.** The
  React side calls a new family of "operation-via-secure-prompt" Tauri
  commands (e.g. `vault_unlock_via_secure_prompt()`) which drive the
  native dialog INSIDE the command handler + immediately call the
  matching FFI op with the resulting `SecretPassword`. The bytes never
  return to JS; only a typed result (success / typed-error) does.
- **AGPL-3.0-or-later SPDX header** on every new file.

## 0b. What NOT to ship in this slice

- A custom-styled native widget (rejected as Q-a Option 2). If
  design-token consistency across OSes becomes a UX gripe later, a
  follow-up sub-issue can revisit.
- An overlay-on-WebView widget (rejected as Q-a Option 3 — DPI/scroll
  bugs).
- Stronghold integration. MVP-4-H is about input, not at-rest storage;
  Stronghold (or its equivalent) is a separate post-mainnet sub-issue.
- Biometric unlock (TouchID/Windows Hello). Real password entry is the
  baseline; biometric is a UX nicety for after MVP-4-H lands.
- A plugin published to crates.io as `tauri-plugin-secure-input`. The
  module stays in-tree; if a future external consumer needs it,
  factor-out is a follow-up.

## 1. Surface that needs to change

The 11 React password-input sites currently in `apps/desktop/src/ui/screens/`:

| File | Line | Context |
|---|---|---|
| `UnlockScreen.tsx` | 56 | Vault unlock master password |
| `AddDeviceWizard.tsx` | 128 | Owner master password for VDK seal |
| `JoinVaultWizard.tsx` | 190 | New device master password |
| `RecoverVaultWizard.tsx` | 420 | Init-recovery master password |
| `RecoverVaultWizard.tsx` | 521 | Post-recovery NEW master password |
| `DevicesScreen.tsx` | 238 | Manager password for promotion |
| `RemoveDeviceWizard.tsx` | 116 | Master password for rotation |
| `RemoveDeviceWizard.tsx` | 148 | Master password for revocation |
| `RecoveryScreen.tsx` | 283 | Master password for backup-create |
| `SetupGuardiansWizard.tsx` | 430 | Master password for chain broadcast |
| `SetupGuardiansWizard.tsx` | 480 | Master password (resume path) |

Every one of these currently:
1. Holds the password in a React `useState<string>` slot
2. Passes it to a Tauri command as a `String` arg via `invoke()`
3. Rust handler wraps in `SecretPassword::new(bytes)` immediately

MVP-4-H replaces this with:
1. React renders a `<SecurePasswordButton label="..." onSubmit={...}>` instead of an `<Input>`
2. Button click invokes a new `*_via_secure_prompt` Tauri command (one per existing op)
3. Rust command opens the native dialog, gets the password directly, calls the matching FFI op, returns

## 2. Architecture overview

```text
React side                      Rust side
──────────                      ─────────
<SecurePasswordButton>          #[tauri::command]
   │ click                      vault_unlock_via_secure_prompt(
   │                              app: AppHandle,
   ▼                              state: State<VaultState>,
invoke('vault_unlock_           ) -> Result<(), DesktopError> {
  via_secure_prompt')              let pw_bytes =
   │                                 secure_input::prompt_password(
   ▼                                   parent_window(&app),
[native OS dialog]                     "Unlock vault",
   │ user types password                "Enter your master password"
   ▼                                  )?;
   (bytes stay Rust-side)            let secret =
                                       SecretPassword::new(pw_bytes);
                                     vault_unlock(handle, secret, ...)?
                                   }
```

Module layout:

```text
apps/desktop/src/secure_input/
├── mod.rs              # public surface + dispatch by target_os
├── error.rs            # SecureInputError variants
├── windows.rs          # cfg(target_os = "windows")
├── macos.rs            # cfg(target_os = "macos")
├── linux.rs            # cfg(target_os = "linux")
├── stub.rs             # cfg(test) + cfg(feature = "test-hooks")
└── tests.rs            # unit tests (stub-only)
```

Public surface (`mod.rs`):

```rust
pub fn prompt_password(
    parent: ParentWindow,
    title: &str,
    body: &str,
) -> Result<Zeroizing<Vec<u8>>, SecureInputError>;
```

Returns `Zeroizing<Vec<u8>>` — the buffer zeroes on drop; the caller
moves it directly into `SecretPassword::new(...)`.

## 3. Implementation layers

### Layer 1 — secure_input module (per-OS native widgets)

Each per-OS module exposes the same `prompt_password` signature. The
mod.rs dispatcher picks at compile time. Returns
`Zeroizing<Vec<u8>>` of UTF-8 bytes (no `String` — we control the
buffer's drop).

**Windows (`windows.rs`):** `TaskDialogIndirect` with `TDF_USE_HICON_MAIN`
+ a custom edit control (`ES_PASSWORD`). Sources the parent HWND from
the Tauri AppHandle. Returns `SecureInputError::Cancelled` on user
dismissal.

**macOS (`macos.rs`):** `NSAlert` with `runModal`, `accessoryView` =
`NSSecureTextField`. Sources the parent NSWindow from the Tauri
AppHandle.

**Linux (`linux.rs`):** `gtk::Dialog::new_with_buttons` + `GtkEntry`
with `set_visibility(false)` + `set_input_purpose(InputPurpose::Password)`.
Sources the parent GtkWindow from the Tauri AppHandle.

### Layer 2 — Tauri commands

For each of the 11 password-input sites, add a `*_via_secure_prompt`
command in `apps/desktop/src/commands/`. Examples:

- `vault_unlock_via_secure_prompt(app, state) -> Result<(), DesktopError>`
- `recovery_create_backup_via_secure_prompt(app, state) -> Result<BackupDto, DesktopError>`
- `pairing_add_device_via_secure_prompt(app, state, sealed: Vec<u8>) -> Result<DeviceDto, DesktopError>`
- ...

Each command's body:
1. Call `secure_input::prompt_password(parent_window(&app), TITLE, BODY)` with site-specific localization.
2. Wrap result in `SecretPassword::new(bytes)`.
3. Call the matching existing FFI op.
4. Return its result (or typed error) — bytes never leak back.

The OLD commands (`vault_unlock`, etc.) stay live for the test-hooks build
ONLY (gated on `feature = "test-hooks"` — same gating as the existing
`__test__force_unlock` from MVP-4-F). Release builds register only the
`*_via_secure_prompt` variants.

### Layer 3 — React-side wrapper

A new `SecurePasswordButton` component in `apps/component-library/`:

```tsx
<SecurePasswordButton
  label="Unlock vault"
  onSubmit={async () => {
    await invoke('vault_unlock_via_secure_prompt');
    /* success path */
  }}
  onError={(e) => onError(errMessage(e))}
  data-testid="unlock-submit"
/>
```

Replace every `<Input type="password">` + accompanying `<Button>` pair
across the 11 sites with this single button. The button never holds
plaintext.

### Layer 4 — test-hook bypass

Mirrors the existing MVP-4-F posture. `apps/desktop/src/secure_input/
stub.rs` (gated `cfg(any(test, feature = "test-hooks"))`):

```rust
pub fn prompt_password(...) -> Result<Zeroizing<Vec<u8>>, SecureInputError> {
    let mut queue = INJECTED_PASSWORDS.lock();
    let bytes = queue.pop_front()
        .ok_or(SecureInputError::TestHookEmpty)?;
    Ok(Zeroizing::new(bytes))
}

#[tauri::command]
#[cfg(feature = "test-hooks")]
pub fn __test__secure_input_inject(password: String) {
    INJECTED_PASSWORDS.lock().push_back(password.into_bytes());
}
```

Test-hooks builds compile only the stub; release builds compile only
the OS modules. `cfg` guards in `mod.rs` enforce this at compile time.

### Layer 5 — OS-automation integration suite

New test directory `apps/desktop/tests/secure-input-integration/`:

- `windows.spec.ts` — uses AutoIt v3 + `WinWait`/`ControlSend` to drive the TaskDialog
- `macos.spec.ts` — uses `osascript` + `System Events` to type into NSAlert
- `linux.spec.ts` — uses `xdotool` + `wmctrl` to type into GtkDialog

Each spec:
1. Launches the desktop app (release build, no test-hooks feature)
2. Triggers a password-prompt path (e.g. unlocks a fresh test vault)
3. Drives the OS automation tool to type a known password
4. Asserts the FFI succeeded

CI matrix gates each spec to its OS (`runs-on: windows-latest` etc.).
**Bounded flake blast radius**: these tests don't gate the wizard E2E
suite — only the small native-widget integration tests fail if AutoIt
flakes.

## 4. Test plan

| Layer | Unit tests | Integration |
|---|---|---|
| secure_input::stub | `injected_password_round_trips`, `empty_queue_returns_test_hook_empty` | n/a |
| Tauri commands | `vault_unlock_via_secure_prompt_rejects_when_locked` etc. (one per command, with stub injecting a known password) | wdio wizard E2Es (already exist; updated to use `__test__secure_input_inject` first) |
| SecurePasswordButton | vitest: renders, click invokes the supplied async fn, surface error on rejection | — |
| Native widgets | n/a (no isolated unit test possible without OS automation) | OS-automation suite (one spec per OS) |

No LOWs left deferred. Per [[feedback_no_low_defers]] every audit
finding gets closed before merge.

## 5. CI gate

The existing CI gate (workspace clippy + audit + deny + workspace test,
plus pnpm typecheck/lint/vitest + forge fmt/test) stays unchanged. New
additions:

- The OS-automation integration suite runs as a new matrix job (`secure-input-e2e`) parallel to the existing `desktop-e2e` job. One leg per OS.
- Workspace clippy gains the new `apps/desktop/src/secure_input/` module — Rust-side flake risk is the per-OS cfg-gated code (only one variant builds on each CI worker so coverage is bounded).
- Per [[feedback_ci_full_local_gate]] Rule 6: re-run the FULL gate after any audit-fix edit.

## 6. L-invariants honoured

- **L1.** Plaintext password NEVER crosses Tauri bridge as JS string (the whole point of this slice). Only typed results (success enum, typed errors) cross out. The bytes live in `Zeroizing<Vec<u8>>` from native-widget-return through `SecretPassword::new` consumption.
- **L3.** Fail-closed: plugin load failure → `SecureInputError::Unavailable` → `DesktopError::Validation { kind: "secure_input_unavailable" }`. No silent fallback (Q-c locked).
- **L4.** Active-session gates inside the inner FFI ops are unchanged (the `*_via_secure_prompt` commands defer to them, don't reimplement).
- **L6.** New deps: `windows` (already in `apps/desktop` Linux build for cargo metadata only — moves to direct dep on Windows), `cocoa` + `objc2` (new on macOS), `gtk` (already there via Tauri). Audit pass adds them to deny.toml allowlist.

## 7. Build order

1. **L1**: secure_input module skeleton + stub.rs + tests (compile on all OSes via cfg gating). One commit.
2. **L1 cont'd**: per-OS native widget impls (one commit per OS, in this order: Linux → Windows → macOS — Linux first because the agent's dev machine is Linux/WSL).
3. **L2**: `*_via_secure_prompt` Tauri commands + register only those in release builds. One commit (touches all 11 sites' commands).
4. **L3**: `SecurePasswordButton` component in component-library + every wizard updated to use it. One commit.
5. **L4**: `__test__secure_input_inject` test-hook + update existing wdio E2Es to inject via it. One commit.
6. **L5**: OS-automation integration suite. One commit per OS.
7. **Audit + merge**: full gate + adversarial self-audit (no deferred LOWs) + `--no-ff` merge to main + CI watch.

## 8. References

- `pangolin_secure_input.md` memory — staged decision rationale
- `mvp4-b-desktop-shell.md` §0a — option-1 baseline + the staged plan reference
- `mvp4-f-desktop-e2e.md` — `__test__force_unlock` precedent for the test-hook posture
- Tauri v2 docs — `AppHandle::get_webview_window(_).hwnd()` / `.ns_window()` / `.gtk_window()` for parent-window source
- Microsoft `TaskDialogIndirect`: <https://learn.microsoft.com/en-us/windows/win32/api/commctrl/nf-commctrl-taskdialogindirect>
- Apple `NSAlert.runModal`: <https://developer.apple.com/documentation/appkit/nsalert>
- GTK `Dialog`: <https://docs.gtk.org/gtk3/class.Dialog.html>
