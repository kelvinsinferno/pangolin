# Release runbook (Pangolin PoC)

This document is the **publisher's** runbook. It documents how Kelvin
produces a Pangolin PoC release artefact set on a Windows-x64 host:
how the build pipeline runs, how the GPG-signed manifest is produced,
and what gets uploaded to the GitHub Releases page.

The **user's** verify-and-run instructions live in
[`POC_README.md`](../POC_README.md) under "Download a prebuilt
binary" — that's the audience the manifest signature is for.

> **Spec reference:** `docs/issue-plans/P12.md` §A1 (signing approach),
> §A2 (target OS), §A3 (versioning), §A15 (pre-flight gate).
> Decisions D-002 (Apache-2.0) and D-013 (Windows host).

---

## Prerequisites

1. **Rust toolchain** — stable 1.83 or newer (workspace `rust-version`
   pin is `1.83`). Install via [rustup](https://rustup.rs/). Verify:

   ```powershell
   rustc --version
   cargo --version
   ```

2. **Windows-x64 host** — the PoC release ships only a Windows-x64
   binary set; macOS / Linux / mobile are deferred to MVP-1+ packaging
   per `docs/issue-plans/P12.md` §A2. Run the script from **PowerShell 7
   or newer** (`pwsh.exe`); it does NOT require WSL.

   Why 7+ specifically: the script invokes `cargo` and other native
   exes whose stderr output (e.g., cargo's `Finished` success line)
   trips PowerShell 5.1's `NativeCommandError` wrapping, causing
   spurious failures even on successful builds. PowerShell 7 handles
   native-exe stderr cleanly. Install via
   [Microsoft's PowerShell 7 page](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows)
   or `winget install --id Microsoft.Powershell`.

3. **GnuPG** with Kelvin's signing key available in the host keyring.
   Install via [Gpg4win](https://www.gpg4win.org/) (recommended) or
   the upstream [GnuPG Windows builds](https://www.gnupg.org/download/).
   Verify:

   ```powershell
   gpg --version
   gpg --list-secret-keys
   ```

   The signing key fingerprint is documented inline below (post-merge
   Kelvin fills in the actual fingerprint; until then this README's
   "Verifying a release" section uses a placeholder).

4. **Working tree on the release commit** — the script reads
   `target/release/` after a clean release build, snapshots the
   working-tree `POC_README.md` and `docs/E2E_REPRODUCER.md` into the
   distributable, and computes hashes. Releasing from a dirty tree is
   not recommended; the pre-flight gate (`cargo fmt` / `clippy` /
   `test`) will fail-fast if the tree is in a non-shipping state.

---

## Running the release pipeline

From the repository root, in PowerShell:

```powershell
.\scripts\release-windows.ps1
```

The script:

1. Runs the **pre-flight gate** (per `P12.md` §A15) — `cargo fmt
   --check`, `cargo clippy -- -D warnings`, `cargo test --workspace
   --lib`. Aborts the release if any of these fails.
2. Runs `cargo build --workspace --release`.
3. Verifies `target/release/pangolin-cli.exe` and
   `target/release/chaincli.exe` exist and are non-empty.
4. Clears and recreates `dist/windows-x64/`.
5. Copies the binaries plus `LICENSE`, `POC_README.md`, and
   `docs/E2E_REPRODUCER.md` into the dist directory.
6. Computes a sorted SHA-256 manifest at
   `dist/windows-x64/SHA256SUMS` (Linux-style `<hex-hash>  <relative-path>`,
   LF line endings, UTF-8 without BOM).
7. **GPG-signs** the manifest into `dist/windows-x64/SHA256SUMS.asc`
   via `gpg --detach-sign --armor`. Skipped when `-SkipSign` is set.
8. Bundles the directory into
   `pangolin-poc-v0.0.0-poc-windows-x64.zip` at the repository root.
9. Prints a summary with the dist path, the zip path, and the
   verification commands the user runs locally.

### Flags

- `-SkipSign` — skip the GPG signing step. Use in CI, on hosts
  without the signing key, or for repeated re-runs while debugging
  the script. The resulting zip ships without `SHA256SUMS.asc` and
  is **not** suitable for the user-facing release.
- `-SkipPreflight` — skip the `cargo fmt` / `clippy` / `test` gate.
  Fastest re-run; for script-debug only.
- `-Version <tag>` — override the version embedded in the zip
  filename. Defaults to `0.0.0-poc` per `P12.md` §A3.

### Idempotency

The script clobbers `dist/windows-x64/` at step 4 before recreating
it, and overwrites the upload zip at step 8. Re-running is safe.

`dist/` is already covered by the repository `.gitignore` (line 15),
so the generated artefacts never accidentally land in a commit. Run
`git status` after the pipeline completes — it should be clean.

---

## Verifying a release artefact (publisher-side smoke)

Before uploading to GitHub Releases, smoke the artefact set on the
publisher host:

```powershell
# 1. Confirm the manifest signature verifies against your own key.
gpg --verify .\dist\windows-x64\SHA256SUMS.asc .\dist\windows-x64\SHA256SUMS

# 2. Confirm each binary's hash matches its manifest entry.
Get-FileHash -Algorithm SHA256 .\dist\windows-x64\pangolin-cli.exe
Get-FileHash -Algorithm SHA256 .\dist\windows-x64\chaincli.exe
# Compare against the SHA256SUMS file by eye, or:
Get-Content .\dist\windows-x64\SHA256SUMS

# 3. Smoke-run each binary so a packaging mistake (missing DLL,
#    bad architecture) surfaces before the user sees it.
.\dist\windows-x64\pangolin-cli.exe --help
.\dist\windows-x64\chaincli.exe --help
```

If any of these fails, do not upload; debug the release script
locally first.

---

## Uploading to GitHub Releases

1. Push the release commit to `main` (or whichever branch carries
   the SIGNOFF) — typically the merge commit that closes the P12
   issue branch.
2. Tag the release commit with the version tag:

   ```bash
   git tag -s v0.0.0-poc -m "Pangolin PoC release"
   git push origin v0.0.0-poc
   ```

   `-s` produces a GPG-signed tag using the same key the manifest
   is signed with. Optional but recommended for tag-trust parity.

3. Open the GitHub Releases page → **Draft a new release** →
   select the `v0.0.0-poc` tag.
4. Title: `Pangolin PoC v0.0.0-poc — Windows-x64`.
5. Body: copy the verification one-liners from the
   "Verifying a downloaded release" section of `POC_README.md`,
   plus a one-line link to the screencast.
6. Attach as release assets:
   - `pangolin-poc-v0.0.0-poc-windows-x64.zip` (the bundle the
     script produces at the repository root).
   - `dist/windows-x64/SHA256SUMS` (the manifest, also bundled
     inside the zip but uploaded separately so users can verify
     before downloading the zip itself).
   - `dist/windows-x64/SHA256SUMS.asc` (the detached GPG
     signature; required for trust).
7. Publish (not Pre-release — `0.0.0-poc` already conveys
   pre-release status; "pre-release" tag would be redundant).

---

## Signing key fingerprint

> **Placeholder.** Fill in the actual fingerprint at SIGNOFF time.

```
KEY OWNER:    Kelvin (Kelvinsinferno Studio)
KEY TYPE:     <ed25519 / rsa4096 — to be filled in>
FINGERPRINT:  <40-character hex fingerprint — to be filled in>
KEYSERVER:    https://keys.openpgp.org/search?q=<fingerprint>
PUBLISHED:    <yes/no — fill in at SIGNOFF>
```

Per `P12.md` §A1 + Q6, the fingerprint is documented inline (so a
user can verify offline) and also referenced via a public keyserver
(so rotation has a single source of truth). If Kelvin rotates the
release key in MVP-1, this section is updated as part of the MVP-1
packaging-cycle SIGNOFF; the previous fingerprint is preserved for
historical verification of the v0.0.0-poc release.

### Acquiring the public key (user-side)

Users verifying a downloaded release fetch the public key once:

```bash
# Option A — keyserver fetch (preferred):
gpg --keyserver hkps://keys.openpgp.org --recv-keys <fingerprint>

# Option B — local import from a trusted out-of-band copy:
gpg --import kelvin-pangolin-release.asc
```

Then verify the manifest signature:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

Both must return success for the artefact set to be trusted.

---

## What the script does NOT do

These are intentional out-of-scope items per `P12.md` §"Out of scope":

- **Authenticode signing.** Deferred to MVP-1's packaging cycle;
  the PoC ships unsigned binaries plus a GPG-signed manifest.
  Windows SmartScreen may flag the binary on first run; users
  click "More info → Run anyway" if they trust the verified hash.
  Documented in `POC_README.md`'s known-issues section.
- **macOS / Linux / mobile builds.** MVP-1 packaging cycle adds
  `scripts/release-{macos,linux}.sh` siblings. PoC is Windows-x64
  only.
- **Reproducible builds.** PoC binaries are built once on Kelvin's
  host. MVP-1+ may target reproducibility if it matters for trust.
- **Crates.io publishing.** The workspace is `publish = false` per
  `Cargo.toml`. Out of scope.
- **CI-driven releases.** The release script runs manually on
  Kelvin's host; the GPG private key is never uploaded as a CI
  secret. MVP-1+ may add a CI release pipeline once the trust
  surface is reviewed.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Pre-flight `cargo fmt --check` fails. | Local format drift. | `cargo fmt --all` on the working tree, commit the fix, re-run. |
| Pre-flight `cargo clippy` fails. | New lint introduced or toolchain bumped. | Address the lint or pin the toolchain in `rust-toolchain.toml`. Do not skip the gate to ship. |
| Pre-flight `cargo test --lib` fails. | Test regression. | Stop the release. Open an issue. Do not ship from a red tree. |
| `gpg --detach-sign` returns exit code 2. | Key not in keyring or pinentry not configured. | `gpg --list-secret-keys` to confirm the key; `gpg-agent --reload` if pinentry is misbehaving; configure `gpg.exe` per Gpg4win docs. |
| `Compress-Archive` fails with "path too long". | Windows MAX_PATH on a deep working tree. | Move the worktree closer to drive root, or enable LongPathsEnabled. |
| Release zip is larger than expected (~50 MB+). | Debug symbols not stripped. | Confirm `Cargo.toml`'s `[profile.release]` has `strip = "symbols"` (already set as of P0). |
| `dist/` shows up in `git status`. | `.gitignore` rule was edited or the dist tree is at an unexpected path. | Confirm `.gitignore` line `dist/` is intact; the script writes to `dist/windows-x64/` only. |

---

## Operational notes

- **Re-running:** safe; the script clobbers `dist/windows-x64/` at
  step 4 and the zip at step 8.
- **Cancelling mid-run:** safe; partial outputs may exist under
  `dist/windows-x64/` but a re-run will clean them. The release zip
  is only written at step 8 and is atomic from PowerShell's
  perspective.
- **Working from a non-default branch:** the script does not pin a
  branch. It builds whatever the working tree has. Confirm
  `git status` and `git log -1` show the expected release commit
  before running.
- **Multiple concurrent releases:** not supported; the script
  assumes exclusive access to `dist/windows-x64/` and
  `target/release/`.

---

*End of runbook. For background on why GPG-signed manifest rather
than Authenticode, see `docs/issue-plans/P12.md` §A1.*
