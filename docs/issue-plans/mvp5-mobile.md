<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-5 — mobile (Android first, iOS to follow) — overview plan-gate LOCKED

**Status: LOCKED — Kelvin call 2026-06-02.** Q-a..f all resolved.

## 0. One-paragraph summary

Pangolin currently ships as a desktop app (Tauri v2 / React / Rust) +
Chromium browser extension, distributed via GitHub Releases as of
v0.1.0-beta.1 (2026-06-02). MVP-5 brings the same vault + multi-device
+ social-recovery story to iOS and Android. The Rust core (`pangolin-core`,
`pangolin-crypto`, `pangolin-store`, `pangolin-chain`, `pangolin-ffi`)
is the SAME on every target — only the shell + platform-glue + UI
chrome differ. Closed beta runs unsigned / sideloaded (where possible)
on the same posture as desktop: testnet only, unaudited, do not store
production secrets. Per [[feedback_audit_funding_pivot]] mainnet is
NOT gated on a paid audit; community review + tester feedback gate it.

Reference posture memories:
- [[pangolin_state]] — MVP-4 closed, v0.1.0-beta.1 live, next = MVP-5
- [[feedback_audit_funding_pivot]] — paid audit deferred indefinitely
- [[pangolin_recovery_model]] — Shamir threshold + sealed-share transport
- [[pangolin_signing]] — deployed Base Sepolia contract addresses

## 0a. LOCKED decisions (proposed — Kelvin to confirm)

### Kelvin-locked decisions (2026-06-02)

- **Q-a — UI framework = Tauri 2 Mobile.** Same React + Rust
  architecture as desktop. ~90% UI code reuse (existing
  `SetupGuardiansWizard`, `RecoverVaultWizard`, etc. ship as-is with
  mobile-layout tweaks). Platform-specific Tauri plugins for
  biometric / camera / Keychain. The competing options (Native
  SwiftUI+Compose, React Native, Flutter) all sacrifice desktop
  code reuse and add a second codebase to maintain forever — for
  the closed-beta scope where the vault is mostly forms + lists +
  modals, Tauri 2 Mobile's edge-case weakness on heavy animations /
  gestures doesn't apply.

  **Key clarification** (per Kelvin's 2026-06-02 framing):
  "React Native" and "Tauri 2 Mobile" are not interchangeable.
  React Native renders native widgets (`<View>` / `<Text>` / etc.)
  via a separate React runtime; web React (`<div>` / `<Input>`)
  doesn't run on it. Tauri 2 Mobile = same React-in-WebView as
  desktop, so the JSX from `apps/desktop/src/ui/screens/` actually
  runs on mobile too.

- **Q-b — Platform sequencing = Android first, iOS to follow.**
  Android sideload (`.apk` direct download + "unknown sources"
  toggle) is cheap and works without paid dev accounts. iOS
  sideload in 2026 effectively requires AltStore + macOS +
  paid Apple Developer ($99/yr); gate iOS until Android proves
  the mobile architecture. When iOS happens, it's a follow-on
  sub-slice (not in MVP-5's initial scope).

- **Q-c — Distribution = Android `.apk` on GitHub Releases.**
  Same workflow as desktop's `release.yml`. Tag-triggered job
  produces `Pangolin-<version>.apk` and attaches it to the
  GitHub Release. Mirrors the unsigned / friction-OK posture
  of the desktop builds. iOS distribution (when it lands) will
  use TestFlight, gated on a $99/yr Apple Developer Program
  seat — separate decision when iOS sub-slice opens.

- **Q-d — Biometric = augments, doesn't replace, the master
  password.** Standard 1Password / Bitwarden pattern. First
  vault unlock: user types master password via native secure
  widget; with user consent, the master password is stored in
  Android Keystore (iOS: Keychain when iOS sub-slice ships)
  under biometric protection (`setUserAuthenticationRequired(true)`
  + `setUnlockedDeviceRequired(true)` + `setInvalidatedByBiometricEnrollment(true)`).
  Subsequent unlocks: biometric prompt → Keystore returns master
  password → existing FFI unlock path runs.

- **Q-e — Recovery = typed + QR-imported seed phrase.** Mobile
  recovery wizard accepts either. QR generation is added to the
  desktop's existing backup-create UX so users can scan on
  mobile; the typed path stays for "lost the QR, only have the
  paper words." The QR carries plaintext seed phrase — same
  display-once posture as the existing desktop seed-phrase UX,
  with the same "do not photograph / do not share" warning copy.

- **Q-f — Android system Autofill Service in MVP-5.** The mobile
  shell registers a Kotlin `AutofillService` subclass so Pangolin
  becomes a system-level autofill provider — works in **every**
  browser + every app on the device (Chrome, Firefox, Brave,
  Edge, banking apps, etc.). User toggles "Use Pangolin for
  autofill" once in Android Settings. New sub-slice MVP-5-I
  covers this. iOS equivalent (`ASCredentialProviderExtension`)
  ships when the iOS sub-slice happens — not in MVP-5 scope.

  Initial Q-f framing offered "Android Chrome MV3 sideload" as
  an option; that was a misframing — Chrome MV3 on Android is
  dev-channel-only and would only cover Chrome. The
  `AutofillService` API is the standard Android pattern (used by
  every major password manager) and covers the whole OS.

### Self-locked (no gate needed)

- **Rust core is unchanged.** `pangolin-core` + `pangolin-crypto` +
  `pangolin-store` + `pangolin-chain` + `pangolin-ffi` compile to
  mobile targets (aarch64-apple-ios, aarch64-linux-android) with no
  algorithm changes. The same `VaultHandle`, the same
  `RecoveryV2.sol`, the same Shamir threshold-share scheme. Only the
  shell + platform-glue changes.
- **Contracts unchanged.** The same Base Sepolia RecoveryV2 +
  RevisionLogV2 + EntitlementRegistry contracts the desktop is paired
  against. Mobile devices join existing vaults via the same QR/short-
  code pairing protocol that desktops use.
- **Versioning**: continue the semver pre-release pattern. Mobile
  releases are tagged `mobile-v0.1.0-beta.N` to keep them visually
  distinct from desktop's `v*` tags on the same Releases page.
- **No code-signing certs paid for this MVP.** Same posture as MVP-4-M
  — friction-OK closed beta. Apple Developer ID + Authenticode +
  Google Play signing remain post-mainnet workstreams.
- **Same release workflow pattern.** Tag-triggered `.github/workflows/
  release-mobile.yml`, mirrors the existing `release.yml` shape. Per-
  OS matrix builds `.apk` (Android) + `.ipa` (iOS, when Q-c picks an
  iOS-inclusive option).
- **No auto-updater.** Same reason as desktop: unsigned releases can't
  be cryptographically verified; users re-download manually.
- **AGPL-3.0-or-later SPDX header** on every new file.

## 0b. What NOT to ship in this MVP

- **Native messaging-host equivalent on mobile.** Browser extension
  ↔ desktop IPC is desktop-only by design; mobile autofill (if Q-f
  ships) uses platform-native autofill APIs, not native messaging.
- **App Store / Play Store reviewable production builds.** Paid
  dev accounts + review process are explicitly deferred to MVP-6
  unless Q-c picks Option 2.
- **iOS App Clips / Android Instant Apps.** Out of scope.
- **Apple Watch / Wear OS companions.** Out of scope.
- **Push notifications.** Pangolin is local-first; there's no Pangolin-
  controlled server to push from. The on-chain RecoveryV2 event
  listener (for guardian-help-incoming) is a desktop-only concern
  this MVP (mobile users can poll the chain on app foreground).
- **Multi-device pairing FROM mobile** (mobile as the *manager*
  inviting a desktop). The mobile in MVP-5 joins an EXISTING vault
  managed by a desktop. Manager-on-mobile is a follow-on UX slice.
- **Mainnet contracts.** Same Base Sepolia testnet as desktop.

## 1. Sub-slice breakdown (LOCKED)

Sub-slice plan-LOCKs draft separately once dispatched. The sequence
below is the build order; each lands as its own PR against main with
its own merge boundary.

| Sub-slice | What it ships | Depends on |
|---|---|---|
| **MVP-5-A** | Tauri 2 Mobile Android scaffold; minimal "open vault file picker" + "unlock with typed master password" flow; CI matrix extension for the Android target; verify Rust core compiles for `aarch64-linux-android` | (none) |
| **MVP-5-B** | Vault open / unlock / lock / accounts-list / account-detail UX — port the desktop screens with mobile layout tweaks (touch targets, scroll behavior, soft-keyboard handling, status-bar styling) | A |
| **MVP-5-C** | Secure mobile input widget for Android — Kotlin plugin wrapping `EditText` with `inputType=textPassword` + `setShowSoftInputOnFocus(true)`. Mobile equivalent of the desktop's MVP-4-H per-OS secure widgets (no V8 residue path) | A |
| **MVP-5-D** | Biometric integration per Q-d — Android Keystore + `BiometricPrompt` API. Kotlin plugin stores the master password under `setUserAuthenticationRequired(true)` + `setUnlockedDeviceRequired(true)` + `setInvalidatedByBiometricEnrollment(true)`; biometric prompt unlocks for subsequent vault opens | B + C |
| **MVP-5-E** | Multi-device pairing — mobile joins an existing desktop vault via camera QR scan + short-code paste fallback. Reuses `pangolin-ffi` pairing API; camera permission flow; QR decoding via `tauri-plugin-camera` or in-tree Kotlin equivalent | B + secure input from C |
| **MVP-5-F** | Recovery flow per Q-e — typed seed phrase wizard + QR-import flow. QR generation lands on the desktop side too (new "Show QR" button on the existing backup-create wizard) | E |
| **MVP-5-G** | Settings + first-launch posture — beta warning modal ports as-is, BetaChip ports as-is, ExtensionBanner is replaced with a "Connect to your desktop" banner that links into the pairing wizard | B |
| **MVP-5-H** | Packaged release workflow — `.github/workflows/release-mobile.yml` tag-triggered on `mobile-v*.*.*-*`, produces signed `.apk` (debug-signed for closed beta) and uploads to GitHub Releases. Mirrors `release.yml` shape | A through G |
| **MVP-5-I** | Android system `AutofillService` Kotlin plugin per Q-f. Registers Pangolin as system autofill provider; IPC from autofill service back to the main app to query the vault; biometric prompt fires if vault is locked. UX: a "Use Pangolin for autofill" Settings entry that deep-links to Android Settings → Autofill | D + B |

Total ~9 sub-slices. Roughly comparable to MVP-4's A-M arc.

**Not in MVP-5 (deferred to a separate iOS-mvp slice):**
- iOS scaffold + Swift secure-input widget + iOS Keychain + iOS biometric
- iOS recovery flow port
- iOS `ASCredentialProviderExtension` (the iOS equivalent of MVP-5-I)
- TestFlight distribution + Apple Developer Program seat decision

## 2. Surface that needs to change (overview level)

The detail will land in each sub-slice's plan-LOCK; high-level the
new surface is:

| Layer | New / changed |
|---|---|
| Rust core | unchanged |
| `pangolin-ffi` | likely 0-3 small additions for biometric-keychain bindings (depends on Q-d) |
| `apps/desktop` | unchanged |
| `apps/extension` | unchanged |
| `apps/mobile-android/` (new) | Tauri 2 Android shell + Kotlin platform-glue plugins (if Q-a = Option 1) |
| `apps/mobile-ios/` (new) | Tauri 2 iOS shell + Swift platform-glue plugins (if Q-a = Option 1 and Q-b/c include iOS) |
| `apps/mobile-shared/` (new) | Shared mobile React UI components (mostly re-exports from `@pangolin/component-library` with mobile-layout overrides) |
| `.github/workflows/release-mobile.yml` (new) | Tag-triggered mobile release workflow |
| `.github/workflows/ci.yml` | New mobile CI matrix legs (toolchain install, build, mobile-specific tests) |

## 3. Threat model + posture notes

- **Mobile key storage** is the highest-risk new surface. iOS Keychain
  + Android Keystore are both hardware-backed on modern devices
  (Secure Enclave / TEE) and the right choice — but new code calls
  the platform-native APIs, which haven't seen the same internal
  scrutiny as the desktop crypto path.
- **Closed-beta posture remains**: testnet only, unaudited binaries,
  "do not store production secrets." Mobile users see the same
  BetaWarningModal on first launch.
- **Biometric ≠ authorization**. A biometric prompt that fails open
  on the OS side must NOT unlock the vault. The Keychain/Keystore
  entry must be `access_control: biometryAny` / `setUserAuthenticationRequired(true)`
  + `setUnlockedDeviceRequired(true)` — verified per sub-slice audit.
- **QR-imported seed phrase** (if Q-e = Option 1): the QR is plaintext
  seed phrase. Generation on desktop must explicitly warn — same
  posture as the existing display-once seed-phrase UX.
- **Sideloaded Android builds** lose the Play Store's malware scan
  + reproducible-build guarantees. Tester onboarding doc needs a
  SHA-256 fingerprint to verify the downloaded `.apk` matches the
  workflow output.

## 4. Adversarial-audit prompts

Each sub-slice plan-LOCK should list its own audit prompts. Overview-
level prompts that apply across sub-slices:

- **Master password lifecycle on mobile**: typed via native widget →
  passed to Rust → zeroized after use. Confirm: no JS/React-side
  storage; Keychain store happens AFTER unlock succeeds (not before);
  biometric-required flag is set on Keychain item.
- **App backgrounding**: when user backgrounds the app mid-unlock or
  mid-account-view, what happens to in-memory secrets? Desktop's
  `vault_lock` on app blur isn't currently a thing; mobile MUST
  enforce it.
- **iOS / Android backup exclusion**: vault file paths must be
  excluded from iCloud / Google One auto-backup. Tag with
  `kCFURLIsExcludedFromBackupKey` (iOS) / set
  `android:allowBackup="false"` in manifest (Android).
- **Screenshot blocking on Account Detail screen**: iOS doesn't
  block by default; Android needs `FLAG_SECURE` on the window. Both
  should be set when the vault is unlocked.
- **Deep-link handlers**: if we register URL schemes for pairing
  QR codes, ensure they don't accept arbitrary input from other apps.

## 5. CI cost notes

- Each new mobile platform leg adds ~10-15 min to CI per build
  (Android NDK build is slow; iOS needs macOS runner). On every PR
  this is borderline acceptable for a public repo (free runner
  minutes).
- Mobile e2e on emulators (Android) / simulators (iOS) is heavy;
  start with compile-only + unit tests; e2e is a follow-on sub-slice.
- The release-mobile.yml workflow runs only on tag push, same as
  the existing release.yml.

## 6. Out-of-band coordination

- **Test Android device or emulator**: Kelvin or a closed-beta
  tester needs one to actually run the binary. Android Studio's
  AVD emulator works for CI + early dev; physical-device smoke
  is required before each release tag (same posture as the
  desktop macOS smoke per [[pangolin_macos_release_smoke]]).
- **First mobile release tag** (`mobile-v0.1.0-beta.1`): same
  workflow-trigger pattern as desktop. Manual install + unlock
  smoke on a real Android device required before the tag is
  announced.
- **iOS sub-slice (separate MVP)**: when that opens, decide
  whether to acquire an Apple Developer Program seat ($99/yr)
  for TestFlight distribution. Until then iOS is out of scope.

## 7. Merge-boundary policy

Per [[feedback_pangolin_autonomy]] this MVP closes at the **first
successful mobile release tag** (`mobile-v0.1.0-beta.1`) producing
downloadable artifacts on the GitHub Releases page. Each sub-slice
A-H (and optionally I) has its own merge boundary (a green PR CI →
merge to main → next sub-slice). Sub-slice plan-LOCKs lock
contingent decisions; the overview Q-a..f are the architectural
locks.

## 8. Risks (known up front)

- **Tauri 2 Mobile is younger than Tauri 2 Desktop.** Some plugins
  we relied on for desktop (clipboard, dialog) may not have stable
  mobile equivalents yet. Per-sub-slice prototypes will surface
  gaps; mitigation is to fall back to in-tree native plugins for
  anything missing.
- **iOS sideload friction**: even with TestFlight, every closed-beta
  tester needs Apple ID + invite link + 90-day TestFlight build
  expiry. Re-issuing TestFlight builds is a recurring cost.
- **Apple App Store rejection risk** (if Q-c picks public release):
  Apple's policy on apps that interact with cryptocurrency / public
  blockchains is restrictive. Pangolin isn't a wallet (no asset
  custody), but the on-chain RecoveryV2 contract calls may trigger
  guideline 3.1.5(b) scrutiny.
- **Android API level fragmentation**: Keystore behavior differs
  meaningfully between Android 6/7/8 and modern (10+). Target API
  policy needs setting per-sub-slice (recommend Android 10+ = API 29+
  as floor).
- **Mobile workflow CI minutes**: macOS-latest runners are 10x more
  expensive than Linux on private repos; for public repos they're
  free but slower. If the project ever flips private, mobile CI
  cost is real.
