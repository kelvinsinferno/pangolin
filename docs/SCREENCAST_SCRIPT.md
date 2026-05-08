# Pangolin PoC screencast — beat-by-beat script

> **Purpose.** This file is the recording protocol for Kelvin's
> 5-minute Pangolin PoC walkthrough. It names every beat: what
> the camera frames, what the narrator says (verbatim), and the
> visual notes a viewer needs. Kelvin records the actual video
> separately; this script is the agent-shipped artefact.
>
> **Spec reference:** `docs/issue-plans/P12.md` §A7 (YouTube
> hosting), §A8 ("no test password visible on screen" review),
> §A11 (author-attestation verification protocol).

---

## Total runtime budget

**5:00 target; 5:30 hard cap.** If a recorded take exceeds 5:30,
re-record with tighter pacing rather than ship a long-running
demo. Per `P12.md` §A11 the master-plan §3.7 P12-3 spec says
"5-minute" but does not make it a hard constraint; minor overruns
are documented in the SIGNOFF DEVLOG entry.

| Beat block       | Time budget | Cumulative |
|------------------|------------:|-----------:|
| Title + intro    |      0:15   |     0:15   |
| Setup            |      1:15   |     1:30   |
| Scenario 1       |      1:15   |     2:45   |
| Scenario 2       |      1:00   |     3:45   |
| Scenario 3       |      0:45   |     4:30   |
| Closing          |      0:30   |     5:00   |

The Setup block runs longer than the per-scenario blocks because
it sets context (what the binary is, what the deployed contract
is, why testnet) that does not need to be repeated mid-demo.

---

## Pre-recording protocol

Before pressing record, walk the following checklist. **Each
item is load-bearing for §A8 (no plaintext on screen) and for
the recording's reproducibility.**

1. **Terminal config.**
   - Recording resolution: **1920×1080** (1080p). Anything
     smaller cuts off the lower portion of the deepest output
     blocks (the publish summary spans 6+ lines).
   - Terminal: **Windows Terminal** (recommended) with
     **18pt** font. Cascadia Code or Consolas; the goal is
     legibility on 1080p H.264 compressed video.
   - Color theme: **high-contrast** — black-on-white or
     solarized-light. The default Windows Terminal dark theme
     loses contrast under typical YouTube compression.
2. **Working directory.** `cd C:\Users\kelvi\Projects\pangolin`
   (or wherever the release binaries are installed). Clear the
   `tmp/` directory so the demo starts from a clean state:
   `Remove-Item -Recurse -Force tmp; mkdir tmp`.
3. **Funded keystore.** Confirm `pangolin-dev` (or the named
   keystore the demo uses) has Base Sepolia testnet ETH:
   `cast balance <address> --rpc-url https://sepolia.base.org`.
   Do **NOT** show the keystore password during the recording.
   The demo uses `--password-stdin` for vault passwords (so the
   password never appears in terminal echo) and lets the
   keystore prompt fire interactively (`getpass()` suppresses
   character echo by default — verify this on the host before
   recording).
4. **No-plaintext-on-screen review (§A8).** Walk every beat in
   this script and confirm:
   - The vault sentinel password
     `pangolin-poc-test-vault-do-not-reuse` is piped in via
     `echo '...' | pangolin-cli ... --password-stdin` and never
     typed visibly.
   - The keystore password prompt is suppressed
     (`getpass()` shows `*` placeholders or no characters at
     all).
   - Generated account passwords (printed on stderr by
     `account add --generate-password`) appear in the recording
     because that's the value Pangolin guarantees the user
     captures — that's expected and intentional. **Do not
     re-use any displayed generated password elsewhere.**
5. **Recording tool.** **OBS Studio** (the locked default per
   `P12.md` §A7 alternatives consideration). Output: **MP4
   H.264 1080p30**. Bitrate 8000 Kbps CBR (sufficient for
   terminal text at 1080p; YouTube re-encodes anyway).
6. **Audio.** Quiet room; USB mic preferred over laptop mic.
   Record voice and screen on the same track; no post-sync
   needed. Sample rate 48 kHz mono.
7. **Test takes.** Record one 30-second test run before the
   real take to verify font legibility, mic level, and that
   no surprise notification banners appear.

---

## Beat 0 — Title + intro (00:00 – 00:15)

**Camera frames:** A static 1080p title card with the text
`Pangolin (PoC) — five-minute walkthrough` plus the repository
URL `github.com/kelvinsinferno/pangolin` underneath. No terminal
visible yet.

**Narrator says (verbatim):**

> "This is a five-minute walkthrough of Pangolin, a local-first
> password manager proof-of-concept. We'll cover three end-to-end
> scenarios: two-vault sync, conflict resolve, and offline edit.
> Everything runs against the deployed Base Sepolia testnet
> contract — no real credentials, no mainnet."

**Visual notes:**
- Title-card duration: 12 seconds. Cross-fade to the terminal at
  00:13.
- Optional callout overlay at 00:08–00:13: a small bottom-left
  badge `Base Sepolia testnet only — not for real credentials.`

---

## Beat 1 — Setup (00:15 – 01:30)

**What the camera frames:** Windows Terminal at 18pt; cwd is
`C:\Users\kelvi\Projects\pangolin`; the prompt is visible. The
demo begins from a freshly cleared `tmp/` directory.

### Sub-beat 1.1 — Show the build is healthy (00:15 – 00:35)

**Type into terminal (or paste pre-built command):**

```powershell
.\dist\windows-x64\pangolin-cli.exe --version
.\dist\windows-x64\chaincli.exe --version
```

**Narrator says:**

> "We're using the prebuilt Windows binary from the GitHub
> Releases page. Two binaries: `pangolin-cli` is the user-facing
> CLI; `chaincli` is the debug oracle for inspecting the
> deployed contract."

**Visual notes:**
- Both `--version` outputs print on stdout. Resize terminal
  beforehand so the prompt sits about 30% from the top — leaves
  room for output blocks below.

### Sub-beat 1.2 — Inspect the deployed contract (00:35 – 01:00)

**Type:**

```powershell
.\dist\windows-x64\chaincli.exe status `
  --address 0x8566D3de653ee55775783bD7918Fe91b66373896 `
  --rpc-url https://sepolia.base.org
```

**Narrator says:**

> "The deployed RevisionLogV0 contract on Base Sepolia. `chaincli
> status` reads the contract's current sequence count and
> bytecode hash directly from chain — confirming the binary
> we're about to use talks to the right address."

**Visual notes:**
- Output prints the sequence counter and the runtime keccak256.
  Pangolin's POC_README documents the canonical hash; the
  recording can briefly highlight the matching value.
- A **callout overlay** (lower-third, semi-transparent):
  `D-014 deployed address; D-015 redeploy proof exists at
  0x74f2…A9c4 (not wired into the CLI).`

### Sub-beat 1.3 — Create vault A and add an account (01:00 – 01:30)

**Type:**

```powershell
'pangolin-poc-test-vault-do-not-reuse' | `
  .\dist\windows-x64\pangolin-cli.exe vault create `
    --path .\tmp\vault-A.pvf `
    --password-stdin

.\dist\windows-x64\pangolin-cli.exe account add `
  --vault-path .\tmp\vault-A.pvf `
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' `
  --name 'github-work' `
  --username 'octocat@example.com' `
  --url 'https://github.com' `
  --generate-password `
  --no-totp
```

**Narrator says:**

> "Create a vault A with a sentinel password — this password is
> public-record per the test protocol; do not reuse it. Then add
> a github-work account with a generated password. The generated
> password is shown once on stderr — that's the only chance to
> capture it."

**Visual notes:**
- The `vault create` command pipes the password via stdin so it
  never appears in terminal echo (§A8). The vault-password
  argument to `account add` is a flag value — visible on screen
  but again is the public-record sentinel.
- Brief callout: `Sentinel password is non-secret — do not
  re-use elsewhere.`
- Capture the printed `<account_id>` for Beat 3 (Scenario 2);
  Kelvin can paste it into the next command via terminal copy.

---

## Beat 2 — Scenario 1: two-vault sync (01:30 – 02:45)

Reference: `docs/E2E_REPRODUCER.md` § Scenario 1, Live-mode
steps 4–8.

### Sub-beat 2.1 — Publish vault A (01:30 – 02:00)

**Type:**

```powershell
.\dist\windows-x64\pangolin-cli.exe publish `
  --vault-path .\tmp\vault-A.pvf `
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' `
  --account pangolin-dev
```

**Narrator says:**

> "Publish vault A's queued entry to the chain. The CLI prompts
> for the keystore password — that's the testnet wallet that
> pays for the on-chain write. The publish summary confirms one
> entry landed."

**Visual notes:**
- The keystore-password prompt fires interactively. Confirm on
  the host beforehand that `getpass()` suppresses characters
  (it does on Windows Terminal by default).
- The publish summary spans 2-3 lines — keep the terminal tall
  enough that nothing scrolls off.

### Sub-beat 2.2 — Copy vault A to vault B and pull (02:00 – 02:45)

**Type:**

```powershell
Copy-Item .\tmp\vault-A.pvf .\tmp\vault-B.pvf

.\dist\windows-x64\pangolin-cli.exe pull `
  --vault-path .\tmp\vault-B.pvf `
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

**Narrator says:**

> "Copy the vault file to a second device — for the demo we're
> just copying it locally; in real use it travels via any
> out-of-band channel. Then pull on B. We expect a freeze: B
> sees A's entry on chain but cannot use it until B explicitly
> ratifies it. That's the PoC two-key safety surface."

**Visual notes:**
- The pull summary line ends with `1 frozen account(s)` — the
  load-bearing observation. Highlight it briefly with a callout
  overlay: `Freeze sentinel: PoC two-key requires explicit
  resolve before B can use the entry. MVP-1's single-key model
  removes this.`

---

## Beat 3 — Scenario 2: conflict + resolve (02:45 – 03:45)

Reference: `docs/E2E_REPRODUCER.md` § Scenario 2, Live-mode
steps 1–4.

### Sub-beat 3.1 — Resolve on B (02:45 – 03:30)

**Type (substitute `<account_id>` and `<keep-revision-id>` with
the values captured in Beat 1.3 and Beat 2.1 respectively):**

```powershell
.\dist\windows-x64\pangolin-cli.exe resolve `
  --vault-path .\tmp\vault-B.pvf `
  --vault-password 'pangolin-poc-test-vault-do-not-reuse' `
  --account-id <account_id> `
  --keep <keep-revision-id> `
  --account pangolin-dev `
  --yes
```

**Narrator says:**

> "Resolve on B picks the revision we want as canonical and
> publishes a merge revision back to chain. The keystore prompt
> fires again. After resolve, B's freeze clears."

**Visual notes:**
- Pre-paste the account_id and revision_id into the command
  before recording — typing 64 hex chars on camera burns 30
  seconds of budget.
- Callout: `--yes skips the type-yes confirm prompt; the
  keystore prompt is independent.`

### Sub-beat 3.2 — Confirm B's freeze cleared (03:30 – 03:45)

**Type:**

```powershell
.\dist\windows-x64\pangolin-cli.exe pull `
  --vault-path .\tmp\vault-B.pvf `
  --vault-password 'pangolin-poc-test-vault-do-not-reuse'
```

**Narrator says:**

> "Pull on B again. The freeze is gone — `0 frozen accounts`.
> B's view has converged. Note: vault A would also need to
> resolve B's merge revision before A converges — the PoC's
> multi-resolve walk under two-key. MVP-1 closes this."

**Visual notes:**
- The pull-summary line shows `0 frozen account(s)` — the
  load-bearing observation. Brief callout overlay.

---

## Beat 4 — Scenario 3: offline edit (03:45 – 04:30)

Reference: `docs/E2E_REPRODUCER.md` § Scenario 3, **Mock mode**.
The Live-mode walkthrough requires an actual network outage
(disable wifi) which is fragile to record on a single take;
Mock mode is the recommended demo path.

### Sub-beat 4.1 — Run the offline-mode test (03:45 – 04:30)

**Type:**

```powershell
cargo test -p pangolin-cli --test offline_mode
```

**Narrator says:**

> "Scenario 3 — offline edit. The Mock-mode test spins up a mock
> chain adapter, marks it disconnected, runs an account add, then
> fails a publish. After reconnect, a single publish call drains
> the queue. Three sub-tests pass: offline edit, no-op publish
> on empty dirty queue, and offline session safety."

**Visual notes:**
- The test runtime is ~5 seconds; perfect for a 45-second beat.
- Callout: `Cardinal Principle 1: edits must succeed without
  connectivity. The dirty queue is the seam that makes this
  work.`
- The `3 passed` line is the load-bearing observation.

> **Production note.** If Kelvin prefers to keep the demo fully
> Live-mode, swap this beat for an actual disconnect via the
> Windows network-adapter toggle; budget another 30 seconds
> minimum for the disconnect/reconnect dance. The default
> recommendation is the Mock-mode path because it is
> deterministic across takes.

---

## Beat 5 — Closing (04:30 – 05:00)

**Camera frames:** Terminal still visible; the narrator's voice
overlays a final command and a callout pointing at the README
URL.

**Type:**

```powershell
.\dist\windows-x64\chaincli.exe status `
  --address 0x8566D3de653ee55775783bD7918Fe91b66373896 `
  --rpc-url https://sepolia.base.org
```

**Narrator says:**

> "Final check — `chaincli status` against the deployed
> contract. Sequence count has bumped to reflect the publish and
> resolve we just ran. Full reproducer walkthroughs and
> verification details are in the repository's POC_README and
> docs/E2E_REPRODUCER.md. Thanks for watching."

**Visual notes:**
- The sequence-count number visibly differs from the value
  printed at Sub-beat 1.2 — that's the demo's "this is real
  on-chain state, not a recording" payoff.
- Closing callout (full-width, last 5 seconds):
  `github.com/kelvinsinferno/pangolin · POC_README.md`.
- Hard cut to black at 5:00 (or 5:15 latest) — do not let the
  recording drift into commentary.

---

## Post-recording checklist

Before uploading to YouTube unlisted (per `P12.md` §A7):

1. **Total runtime ≤ 5:30.** If over, re-record. The 5:00 target
   has 30 seconds of slack; budget overruns are documented in
   SIGNOFF DEVLOG.
2. **All three scenarios visible on camera.** Setup +
   Scenario 1 + Scenario 2 + Scenario 3 + Closing — five blocks.
3. **No test password visible on screen** in any frame. The
   sentinel password is intentional public-record content but
   should appear only in the command-flag arguments where it
   serves a documentary purpose, not as keyboard input the
   viewer can mistake for "the user typed this".
4. **No notification banners** caught the recording (Slack /
   Discord / mail / Windows Update toasts). If any appear,
   re-record. (DND mode + Focus Assist before pressing Record.)
5. **Audio level peaks at ≈-6 dB** (not clipping). YouTube
   normalises but local level matters for compressibility.
6. **Title-card text spelt correctly.** Read the title card on
   playback before upload — typo-fixing post-upload requires
   re-recording the title card and stitching the takes.
7. **YouTube upload settings:** Privacy = **Unlisted**;
   Description includes one line linking to POC_README;
   Captions = auto-generate accept (Kelvin proofreads on
   upload page; corrections optional, the script-text is the
   authoritative source).
8. **Capture the unlisted URL** and paste into the
   POC_README placeholder + the P12 SIGNOFF DEVLOG entry
   (`docs/issue-plans/P12.md` §A11 protocol).

---

## What this script does NOT cover

- **Vault creation safety story.** The recording shows the
  output of `vault create`; the security model behind it
  (Argon2id KDF, ChaCha20-Poly1305 envelope, etc.) is out of
  scope for a 5-minute demo. Viewers wanting depth click
  through to `THREAT_MODEL.md`.
- **Tombstones / soft-delete walkthrough.** `account delete`
  exists and works; demoing it adds another 60 seconds and a
  visual conflict with Scenario 3's offline narrative. Skip.
- **Multi-resolve on the A side.** Scenario 2 only resolves on
  B; the multi-resolve A-side walk is mentioned in narration
  but not demoed. Saves ~45 seconds; the reproducer covers it.
- **Funder service / payment flow.** The PoC has no
  user-facing payment surface (D-006 funder is MVP-2). The demo
  uses Kelvin's pre-funded keystore directly.

---

## Spec references

- **Hosting decision:** `docs/issue-plans/P12.md` §A7 — YouTube
  unlisted; alternatives (GitHub Releases asset, self-host,
  Loom) considered and rejected.
- **No-plaintext-on-screen protocol:** `P12.md` §A8.
- **Verification protocol:** `P12.md` §A11 — author attestation
  (Kelvin's word, recorded in SIGNOFF DEVLOG); agent does not
  re-watch.
- **Production tooling:** OBS Studio (locked default per §A7's
  alternatives walk).
- **Reproducer walkthroughs (long-form):**
  `docs/E2E_REPRODUCER.md` § Scenario 1 / 2 / 3.

---

*End of script. The recorded video is the evaluator's first
contact with Pangolin; the script is what the recording
documents back into the repository.*
