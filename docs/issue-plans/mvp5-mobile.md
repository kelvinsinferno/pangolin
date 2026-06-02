<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-5 — mobile (iOS + Android) — overview plan-gate DRAFT

**Status: DRAFT — awaiting Kelvin call on Q-a..f.** Other decisions self-locked.

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

### Open questions (need Kelvin's call)

- **Q-a — UI framework / shell**. Drives every downstream sub-slice
  decision.
  - **Option 1 (recommended): Tauri 2 Mobile.** Same React + Rust
    architecture as desktop. ~90% UI code reuse (the existing
    `SetupGuardiansWizard`, `RecoverVaultWizard`, etc. ship as-is
    minus mobile-specific tweaks). Platform-specific Tauri plugins
    for biometric / camera / Keychain. Tauri 2 Mobile is stable as
    of late 2024; tracks the same toolchain we already know.
  - **Option 2: Native SwiftUI + Jetpack Compose.** Best mobile UX
    polish; matches platform conventions exactly. But three
    independent codebases (desktop React + iOS Swift + Android
    Kotlin) for the same product — long-term maintenance multiplier.
  - **Option 3: React Native (single mobile codebase, separate from
    desktop).** Unifies iOS+Android but forks from desktop. Rust
    bridge via uniffi-rs's foreign-function support.
  - **Option 4: Flutter.** Single mobile codebase, Dart instead of
    Rust/JS — biggest cognitive switch for the team.

- **Q-b — Platform sequencing.** iOS and Android have very different
  distribution/signing constraints; doing them in parallel is feasible
  but doubles closed-beta tester pool work.
  - **Option 1 (recommended): Android first, iOS to follow.**
    Android sideload is cheap + works (.apk direct download, "unknown
    sources" toggle). $25 Play Store fee is one-time. iOS sideload
    in 2026 effectively requires AltStore / paid Apple Developer
    account ($99/yr) — gate iOS until Android proves the mobile
    architecture.
  - **Option 2: iOS first.** Apple Dev account ($99/yr) is the cost;
    TestFlight closed-beta distribution is clean. But the architecture
    is unproven and iOS has more constraints.
  - **Option 3: Both in parallel.** Maximum surface to test
    simultaneously. Doubles the closed-beta tester ask + double the
    cost ($99 + $25 = $124).

- **Q-c — Closed-beta distribution model.** Determines the "click
  to download" story on mobile.
  - **Option 1 (recommended): Android-side direct .apk on GitHub
    Releases (same workflow as desktop), iOS via TestFlight if/when
    Apple Dev account ($99/yr) is acquired.** Mirrors the desktop
    posture: unsigned, friction-OK closed beta. Android users toggle
    "install from unknown sources." iOS waits until we're willing
    to pay $99/yr.
  - **Option 2: Public Google Play + Apple App Store releases.**
    Requires paid dev accounts on both ($25 + $99/yr) + the review
    process. Store reviewers won't have testnet vaults; review may
    fail until we provide explicit "demo vault" tooling.
  - **Option 3: Sideload-only on both (no TestFlight).** Android
    is fine; iOS effectively shut out (sideload on iOS in 2026
    requires AltStore + macOS box + USB cable for non-dev users).

- **Q-d — Mobile unlock + biometric integration.** Desktop's
  master-password-only flow doesn't translate cleanly to mobile.
  Mobile users expect Face ID / Touch ID / Fingerprint.
  - **Option 1 (recommended): Biometric AUGMENTS, doesn't replace,
    the master password.** On first vault unlock, user types the
    master password into a native widget. With user consent, the
    master password is stored in iOS Keychain / Android Keystore
    under biometric protection. Subsequent unlocks: biometric prompt
    → Keychain returns master password → existing FFI unlock path
    runs. Same pattern as 1Password, Bitwarden.
  - **Option 2: Biometric REPLACES master password.** The biometric
    is the only unlock. Master password becomes recovery-only. Risk:
    if biometric fails (changed face, broken sensor, OS reset), user
    is locked out. Recovery flow is the only escape.
  - **Option 3: Master password only, no biometric this MVP.**
    Simplest; worst UX. Mobile users will hate it.

- **Q-e — Recovery flow on mobile.** 24-word seed-phrase typing on
  mobile is painful.
  - **Option 1 (recommended): Both — typed seed phrase + QR-imported
    seed phrase.** Recovery wizard accepts either. QR generated on
    desktop during backup creation; user scans on mobile. Typed
    path remains for "lost the QR, only have the paper words."
  - **Option 2: Typed only.** Same as desktop. Hostile mobile UX.
  - **Option 3: Mobile recovery is "view-only" — full restore must
    happen on desktop, mobile re-pairs to the desktop after.**
    Simplest mobile codebase; pushes friction onto the user.

- **Q-f — Mobile browser autofill.** The biggest fork from desktop.
  iOS Safari uses AutoFill Credentials API (system-level extension,
  totally different code from Chromium MV3). Android Chrome supports
  MV3 extensions in dev channel as of 2026 but stable Chrome doesn't
  yet.
  - **Option 1 (recommended): Punt to MVP-6.** Ship the mobile vault
    + multi-device + recovery in MVP-5; defer autofill until either
    iOS AutoFill Credentials integration is built OR Chrome Android
    MV3 stabilizes. Mobile users can copy-paste from the vault to
    the browser manually in the interim — matches the closed-beta
    "friction OK" posture.
  - **Option 2: Ship iOS AutoFill Credentials in MVP-5.** Native
    Swift implementation of `ASCredentialProviderExtension`. New
    code surface, significant audit cost. Worth it if mobile-first
    users won't tolerate copy-paste.
  - **Option 3: Android Chrome MV3 sideload in MVP-5.** Distribute
    the existing browser extension as an Android Chrome-loadable
    add-on. Limited browser support (dev channel only) but minimal
    code change.

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

## 1. Sub-slice breakdown (proposed)

Contingent on Q-a = Option 1 (Tauri 2 Mobile). Sub-slice plan-LOCKs
draft separately once this overview is locked.

| Sub-slice | What it ships | Depends on |
|---|---|---|
| **MVP-5-A** | Tauri 2 Mobile scaffold for chosen first platform (Q-b); minimal "open vault file picker" + "unlock with typed master password" flow; CI matrix extension for the new platform target | Q-a + Q-b |
| **MVP-5-B** | Vault open / unlock / lock / accounts-list / account-detail UX — port the desktop screens with mobile layout tweaks (touch targets, scroll behavior) | A |
| **MVP-5-C** | Secure mobile input widget — native iOS `UITextField` (secureTextEntry) + Android `EditText` (`inputType=textPassword`). Mobile equivalent of the desktop's MVP-4-H per-OS secure widgets. | A |
| **MVP-5-D** | Biometric integration per Q-d (Keychain/Keystore-protected master password if Q-d = Option 1) | B + C |
| **MVP-5-E** | Multi-device pairing — mobile joins an existing desktop vault via QR scan (camera) + short-code paste fallback. Reuses pangolin-ffi pairing FFI. | B + secure input from C |
| **MVP-5-F** | Recovery flow per Q-e (typed + QR-imported seed phrase if Q-e = Option 1) | E |
| **MVP-5-G** | Settings + first-launch posture (extension banner from desktop becomes a "manage paired devices" panel; beta warning modal ports as-is) | B |
| **MVP-5-H** | Packaged release workflow — tag-triggered `.apk` (and `.ipa` if Q-b/c include iOS); GitHub Releases attachment; release-notes template mirrors MVP-4-M's | A through G |
| **MVP-5-I** (optional, depends on Q-f) | Autofill — iOS AutoFill Credentials Provider OR Android Chrome MV3 sideload | F |

Total ~6-9 sub-slices depending on Q-f. Roughly comparable to MVP-4's
A-M arc.

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

- **Q-c Option 1**: requires Kelvin to decide whether to acquire an
  Apple Developer Program seat ($99/yr) for TestFlight iOS
  distribution. If skipped, iOS is effectively shut out of closed
  beta.
- **Q-b Option 1 (Android first)**: requires a test Android device or
  emulator setup. Kelvin or a closed-beta tester needs one.
- **First mobile release tag** (`mobile-v0.1.0-beta.1`): same
  workflow-trigger pattern as desktop. macOS-style "PENDING SMOKE"
  applies if Q-c includes iOS (TestFlight processing takes ~24h).

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
