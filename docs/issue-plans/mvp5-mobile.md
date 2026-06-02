<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-5 — mobile (iOS + Android parallel) — overview plan-gate LOCKED

**Status: LOCKED — Kelvin call 2026-06-02.** Q-a..f resolved (Q-b updated 2026-06-02 to parallel after PANGOLIN_PLAN.md alignment review).

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

- **Q-b — Platform sequencing = iOS + Android in parallel** (revised
  2026-06-02 after PANGOLIN_PLAN.md §8 alignment check). Each sub-
  slice plan-LOCK covers the architecture for BOTH OSes; both
  implementations land in the same sub-slice. Reasoning: iOS-specific
  constraints (App Groups for autofill ↔ main-app keychain sharing,
  Keychain access-groups, App Extension sandboxing) often FORCE design
  decisions that retroactively rework Android code if Android ships
  first in isolation. Designing both together = ~1-2 extra hours per
  sub-slice plan-LOCK, no incremental implementation cost since the
  iOS code would be written either way (just later). Initial Q-b
  lock had iOS deferred; that was reverted to better honor
  PANGOLIN_PLAN.md §8's "2 in parallel" intent while keeping the
  cost-asymmetric distribution model from Q-c.

- **Q-c — Distribution: Android `.apk` immediate / iOS `.ipa` as
  workflow artifact pending dev-account decision.** Tag-triggered
  `release-mobile.yml` produces both `Pangolin-<version>.apk` (Android)
  AND `Pangolin-<version>.ipa` (iOS) on every release tag. The `.apk`
  attaches to the GitHub Release immediately (mirrors desktop's
  unsigned/friction-OK posture). The `.ipa` uploads as a workflow
  artifact ONLY — NOT attached to the Release — until either:
  (a) an Apple Developer Program seat ($99/yr) is acquired and
  the `.ipa` is signed + submitted to TestFlight, or
  (b) a sideload-via-AltStore path is documented.
  Same two-phase pattern as desktop's macOS-pending-smoke gate
  (Q-e on MVP-4-M). iOS code still ships in CI; iOS releases are
  blocked on the account-acquisition decision.

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
- **No prices in the mobile UI — ever.** Per PANGOLIN_PLAN.md §8.1.5
  + "iOS entitlement-state model" + pricing-spec rule. The mobile
  app MUST NOT render currency strings, payment buttons, "Subscribe"
  CTAs, billing-tier comparison tables, or any UI that implies
  in-app purchase. Pricing copy lives on a website. The app reads
  an entitlement state (ACTIVE / LIMITED_WRITES / IMPORT_RESTRICTED
  / RECOVERY_ONLY / SUSPENDED) from the chain (or a future server)
  and renders feature-gating based on it. Closed-beta has no
  pricing yet; this invariant is documented now so no future
  contributor accidentally adds a price string the App Store
  reviewer would reject. Same rule applies to Android by symmetry,
  even though Play Store is more permissive — keeps a single
  pricing-display posture across both OSes.
- **PANGOLIN_PLAN.md §8 issue numbering** (8.1.1 iOS shell, 8.1.2
  Keychain, 8.1.3 ASCredentialProviderExtension, 8.1.4 iOS
  recovery, 8.1.5 entitlement-state, 8.1.6 design-system port,
  8.2.1 Android shell, 8.2.2 Keystore, 8.2.3 AutofillService,
  8.2.4 Android recovery, 8.2.5 Android design system) maps to
  our sub-slice A-I structure — each sub-slice carries an
  explicit reference to the 8.x.y items it implements in §1.

## 0b. What NOT to ship in this MVP

- **Native messaging-host equivalent on mobile.** Browser extension
  ↔ desktop IPC is desktop-only by design; mobile autofill uses
  platform-native autofill APIs (per Q-f), not native messaging.
- **App Store / Play Store reviewable production builds.** Paid dev
  accounts + review process deferred. iOS `.ipa` builds in CI but
  doesn't ship to TestFlight until an Apple Developer seat is
  acquired (per Q-c two-phase distribution). Android `.apk` ships
  via GitHub Releases unsigned; Play Store deferred indefinitely.
- **In-app pricing UI.** Per the no-prices-in-app self-locked
  invariant — no $ strings, no payment buttons, no Subscribe CTAs.
  Pricing lives on a website (when there is one); the app reads
  entitlement state and renders feature-gating. No closed-beta
  pricing infra exists; this is documented for future safety.
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

Each sub-slice covers BOTH iOS and Android implementations (per Q-b
parallel decision). Sub-slice plan-LOCKs draft separately once
dispatched. The table below is the build order; each sub-slice lands
as its own PR against main with its own merge boundary.

| Sub-slice | What it ships (both OSes) | Maps to PANGOLIN_PLAN.md §8 | Depends on |
|---|---|---|---|
| **MVP-5-A** | Tauri 2 Mobile scaffolds — Android (`aarch64-linux-android` target, Kotlin plugin host) AND iOS (`aarch64-apple-ios` target, Swift plugin host); minimal "open vault + unlock with typed master password" flow on both; CI matrix extension (Android NDK build + iOS Xcode build legs) | 8.1.1, 8.2.1 | (none) |
| **MVP-5-B** | Vault open / unlock / lock / accounts-list / account-detail UX — port desktop React screens with mobile layout tweaks (touch targets, scroll behavior, soft-keyboard handling, status-bar styling). Same React JSX renders on both via Tauri 2 Mobile's WebView | (no §8 mapping — UX layer) | A |
| **MVP-5-C** | Secure mobile input widgets — Kotlin plugin wrapping `EditText` (`inputType=textPassword`) for Android; Swift plugin wrapping `UITextField` (`isSecureTextEntry = true`) for iOS. Mobile equivalents of the desktop's MVP-4-H per-OS secure widgets (no V8 residue path on either) | (no §8 mapping — secure-input dependency for 8.1.2, 8.2.2) | A |
| **MVP-5-D** | Biometric integration per Q-d — Android: Keystore + `BiometricPrompt` API (`setUserAuthenticationRequired(true)` + `setUnlockedDeviceRequired(true)` + `setInvalidatedByBiometricEnrollment(true)`). iOS: Keychain Services with `kSecAttrAccessControl` = `.biometryCurrentSet`, App Group set up so the autofill extension can later share access. Both unlock the vault via the existing FFI path after biometric success | 8.1.2 (iOS Keychain + Secure Enclave) + 8.2.2 (Android Keystore) | B + C |
| **MVP-5-E** | Multi-device pairing — mobile joins existing desktop vault via camera QR scan + short-code paste fallback. Camera permission flow on both OSes (`AVCaptureDevice` on iOS, `Camera2 API` on Android). Reuses `pangolin-ffi` pairing API | (no §8 mapping — uses MVP-4-I existing infrastructure) | B + secure input from C |
| **MVP-5-F** | Recovery flow per Q-e — typed seed phrase wizard + QR-import flow on both OSes. QR generation lands on the desktop side too (new "Show QR" button on the existing backup-create wizard). Re-uses MVP-4-L recovery FFI | 8.1.4 (iOS guardian + recovery) + 8.2.4 (Android guardian + recovery) | E |
| **MVP-5-G** | Settings + first-launch posture — BetaWarningModal + BetaChip port as-is on both. ExtensionBanner is replaced with a "Connect to your desktop" banner that links into the pairing wizard. Per the **no-prices-in-app invariant**, Settings shows entitlement state (ACTIVE / LIMITED_WRITES / etc.) read-only — no purchase UI | 8.1.5 (iOS entitlement-state model — display only this slice) | B |
| **MVP-5-H** | Packaged release workflow — `.github/workflows/release-mobile.yml` tag-triggered on `mobile-v*.*.*-*`. Android: produces `.apk`, attaches to Release immediately. iOS: produces `.ipa`, uploads as workflow artifact ONLY (NOT attached to Release) per Q-c — pending Apple Developer Program seat. Same two-phase pattern as MVP-4-M's macOS gate | 8.1.7, 8.2.6 (TestFlight + Play Console builds — iOS half pending seat) | A through G |
| **MVP-5-I** | System autofill on both OSes — Android: Kotlin `AutofillService` subclass registers Pangolin as system autofill provider. iOS: `ASCredentialProviderExtension` (App Group sharing with main app for Keychain access). Biometric prompts fire if vault is locked. "Use Pangolin for autofill" Settings entry deep-links into OS Settings → Autofill / Passwords  | 8.1.3 (iOS ASCredentialProviderExtension) + 8.2.3 (Android Autofill Service + Inline Suggestions) | D + B |
| **MVP-5-J** (cross-platform) | Mobile design system port — same color/type/motion tokens as desktop; vertical stacking; thumb-friendly spacing; iOS-side Material → SwiftUI-look mapping; Android-side Material 3 mapping. Most of this can land alongside G but breaks out for visibility | 8.1.6 (iOS) + 8.2.5 (Android) | B |

Total ~10 sub-slices. Roughly comparable to MVP-4's A-M arc, but
each sub-slice now ships both OS implementations.

**iOS-specific design notes that bake in NOW** (per parallel design
discipline):
- **App Groups**: iOS Keychain entries that need to be shared between
  the main app and the `ASCredentialProviderExtension` (MVP-5-I)
  require an App Group + `kSecAttrAccessGroup` configured at
  Keychain-write time. MVP-5-D Keychain plumbing MUST set the access
  group from day one — not retrofittable without a vault-data
  migration.
- **App Extension sandboxing**: iOS extensions run in a separate
  sandbox from the main app. The autofill extension (MVP-5-I) cannot
  spawn the main app or share memory; it reads the vault via
  Keychain-shared encrypted store + biometric prompt. Architecture
  must match: vault accessor in the extension is read-only via
  Keychain-shared FFI, not via cross-process IPC.
- **Sandboxed file system**: iOS apps have NSDocumentDirectory +
  NSCachesDirectory; the vault file lives in Documents (excluded
  from iCloud backup via `kCFURLIsExcludedFromBackupKey`). MVP-5-A
  must wire the Tauri path resolver to use these — different from
  Android's `getFilesDir()`.

## 2. Surface that needs to change (overview level)

The detail will land in each sub-slice's plan-LOCK; high-level the
new surface is:

| Layer | New / changed |
|---|---|
| Rust core | unchanged |
| `pangolin-ffi` | likely 0-3 small additions for biometric-keychain bindings (depends on Q-d) |
| `apps/desktop` | unchanged (except for the new "Show QR" button on the backup-create wizard for MVP-5-F's QR-import flow) |
| `apps/extension` | unchanged |
| `apps/mobile-android/` (new) | Tauri 2 Android shell + Kotlin platform-glue plugins. Per-sub-slice Kotlin plugins for secure input (C), biometric+Keystore (D), camera+QR (E), autofill service (I) |
| `apps/mobile-ios/` (new) | Tauri 2 iOS shell + Swift platform-glue plugins. Per-sub-slice Swift plugins for secure input (C), biometric+Keychain (D), camera+QR (E), `ASCredentialProviderExtension` (I). App Groups configured from day one |
| `apps/mobile-shared/` (new) | Shared mobile React UI components (mostly re-exports from `@pangolin/component-library` with mobile-layout overrides). One JSX tree renders on both Android + iOS |
| `.github/workflows/release-mobile.yml` (new) | Tag-triggered mobile release workflow. Matrix: ubuntu-latest (Android build) + macos-14 (iOS build via Xcode). Android `.apk` attaches to Release; iOS `.ipa` uploads as workflow artifact only per Q-c |
| `.github/workflows/ci.yml` | New mobile CI matrix legs (Android NDK install + Kotlin build, iOS Xcode build, both compile-only unit tests this MVP — emulator/simulator e2e is a follow-on) |

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
- **Test iOS device or simulator**: needed for iOS code review,
  even though iOS doesn't ship to TestFlight without an Apple
  Developer seat. macOS host + Xcode simulator is the minimum
  bar. Without one, MVP-5-A iOS scaffold can't be smoke-tested
  locally and merges only on CI's signal.
- **Apple Developer Program seat decision** ($99/yr): unblocks the
  iOS Phase 2 release attach. Decision can be deferred indefinitely
  per the audit-funding-pivot posture — code ships in CI as a
  workflow artifact in the interim. Whenever the seat is acquired,
  attaching `.ipa` to existing Releases is a single `gh release
  upload` step (mirrors macOS Phase 2 from MVP-4-M).
- **First mobile release tag** (`mobile-v0.1.0-beta.1`): same
  workflow-trigger pattern as desktop. Manual install + unlock
  smoke on a real Android device required before the tag is
  announced. iOS smoke (on simulator + a physical device if
  available) is the analogous gate for iOS `.ipa` attach.

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
