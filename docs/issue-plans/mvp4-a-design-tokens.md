<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# MVP-4-A — Design tokens (foundation; lands first) — plan-gate LOCKED

**Status: LOCKED — self-locked 2026-05-24.** No Kelvin gate per MVP-4 overview §6 (pure data + generator; no architectural decisions). Decisions pre-resolved in §0a below.

## 0. One-paragraph summary

Stand up a single canonical JSON source of truth for **all UI design tokens** (color, typography, spacing, motion, radius, elevation) and a Rust generator that emits two artifacts — `tokens.css` (CSS custom properties for the Tauri WebView + the Chromium MV3 extension popup) and `tokens.rs` (a Rust constants module for any Rust-side rendering: notifications, system-tray badges, native fallbacks). **Every later MVP-4 sub-issue depends on this** — locking the shape down before any UI work prevents downstream churn when the values inevitably get refined.

This slice ships the **format + generator + a tasteful default token set**. The actual Design-Spec-fidelity values get refined in MVP-4-D (component library) and at the closed-beta visual gate; the discipline being installed here is the canonical JSON → multi-target output pipeline + the schema-version + the round-trip tests.

## 0a. RESOLVED decisions (self-locked 2026-05-24)

- **Source format = JSON** (UTF-8, deterministic key order, 2-space indent). Single file `apps/design-tokens/tokens.json` is the source of truth; everything else is generated. Rationale: trivial to diff, no Rust-specific tooling required for designers, the format is the "what we ship to humans + machines."
- **Generator = Rust binary in a new tools crate** `tools/design-tokens-gen/` (NOT a `build.rs` — the generator is invoked explicitly by `cargo run -p design-tokens-gen` and by CI; build-scripts hide artifact churn from `git diff`, which is anti-pattern for design tokens). The generator is `pub fn main()` only; no runtime API.
- **Output layout**: emitted into `apps/design-tokens/dist/` (checked into git; CI verifies they're up-to-date by re-running the generator + asserting no diff). Two output files: `tokens.css` + `tokens.rs`. A future cycle can add `tokens.ts` for the extension if the React side prefers typed access (deferred — CSS vars cover the MV3 popup just fine).
- **Schema-version** on the JSON source (`"schema_version": 1`) so future format changes (new categories, breaking renames) bump the version + the generator gates on it.
- **Token categories shipped this slice** (each generator-supported):
  - `color` — semantic palette (primary, secondary, surface, text, success, warning, danger) + neutral grays + dark/light pairs.
  - `typography` — type scale (xs / sm / base / lg / xl / 2xl / display), font families (sans / mono), weights (regular / medium / semibold / bold), line-heights, letter-spacings.
  - `spacing` — 8pt-grid base (0.5 / 1 / 2 / 3 / 4 / 6 / 8 / 12 / 16 / 24 in rem units).
  - `radius` — sm / md / lg / full.
  - `elevation` — none / sm / md / lg (CSS box-shadow stacks).
  - `motion` — duration (fast / base / slow) + easing (standard / decelerate / accelerate / spring).
- **Tasteful defaults** for the first cut (clearly marked as "first-pass; refines at MVP-4-D"): a clean dark-first palette anchored on a deep neutral + a single warm accent (pangolin orange — the logo's existing color). The actual Design Spec values get reconciled in MVP-4-D when Kelvin can see them rendered.
- **No new external crates** beyond `serde_json` (already workspace-pinned via alloy transitive — declare directly under `tools/design-tokens-gen/Cargo.toml`). The generator uses `serde_json::Value` for ingest + hand-rolled emitters for the two outputs (no codegen frameworks). Workspace-pinned `serde_json` lives in `[workspace.dependencies]`; tools crate uses `{ workspace = true }`.
- **Tools crate lives at `tools/design-tokens-gen/` (NOT under `crates/`)** because it is build tooling, not a runtime crate (mirrors `tools/chaincli`'s existing posture).
- **NOT registered in the workspace's library/binary publish surface** — it's `publish = false` (mirror chaincli) so it can't accidentally ship to crates.io.

## 1. Scope

**Built in MVP-4-A:**
- `apps/design-tokens/tokens.json` (NEW) — the canonical source. ~120 lines.
- `apps/design-tokens/dist/tokens.css` (NEW; generated; committed) — CSS custom properties, all under a single `:root { ... }` block plus a `[data-theme="dark"] { ... }` block for the dark overrides.
- `apps/design-tokens/dist/tokens.rs` (NEW; generated; committed) — a Rust module exporting `pub const COLOR_*`, `pub const SPACE_*`, `pub const TYPE_*` etc. So a Rust-side renderer can `use pangolin_design_tokens::*;`.
- `apps/design-tokens/dist/lib.rs` (NEW; tiny `pub use tokens::*;` re-export shell so the crate is includable from other Rust code) — actually, simplest path: make `apps/design-tokens/` itself a tiny Rust crate (`pangolin-design-tokens`) whose `lib.rs` is generated from `tokens.json`. Reconsider in §5 Q-a.
- `tools/design-tokens-gen/src/main.rs` (NEW) — the generator binary. Reads `apps/design-tokens/tokens.json`; writes `apps/design-tokens/dist/tokens.css` + `apps/design-tokens/dist/tokens.rs` (or `lib.rs` depending on Q-a). Hermetic: same input → byte-identical output.
- `tools/design-tokens-gen/Cargo.toml` (NEW) — `publish = false`; deps `serde_json` (workspace).
- `apps/design-tokens/Cargo.toml` (NEW, if Q-a → standalone-crate option) — exposes the generated constants as `pangolin-design-tokens`.
- CI integration: a new job `design-tokens-up-to-date` that runs `cargo run -p design-tokens-gen` and asserts `git diff --exit-status apps/design-tokens/dist/` is clean. Failing CI catches a designer editing JSON without re-generating.
- Hermetic tests: input/output round-trip (parse the generated CSS back; parse the generated `tokens.rs` back; assert key set + values match the JSON); CSS-var-name canonicalization test; Rust-constant-name canonicalization test; unknown-schema_version rejected with a clear error.
- The workspace `Cargo.toml`'s `[workspace.members]` gets `tools/design-tokens-gen` added; if Q-a → standalone-crate, also `apps/design-tokens`.

**Deferred (NOT this slice):**
- Actual Design-Spec-fidelity token values (the first-pass tasteful defaults ship now; refinement comes at MVP-4-D when the component library is built and Kelvin can see them rendered).
- TypeScript output (`tokens.ts`) for the extension popup (CSS vars cover MV3; revisit if React-side typed access becomes painful).
- Per-OS native-shell tokens (Windows / macOS / Linux system colors) — out of scope.
- The Figma export pipeline (Kelvin's parallel design workstream).
- A token-versioning migration tool for downstream consumers (premature until we have downstream consumers).

## 2. Splittable? — no, this is the smallest viable foundational slice

The JSON + the generator + the two outputs are tightly coupled: the JSON shape constrains the generator API constrains the output format. Splitting forces a contract surface between the steps that is wasteful at this size (~500 LoC total). ONE slice → audit → merge.

## 3. Design

### 3.1 JSON schema

```jsonc
{
  "$schema": "https://pangolin.example/schemas/design-tokens-v1.json",
  "schema_version": 1,
  "color": {
    "neutral": {
      "0":   "#0A0A0B",
      "50":  "#141416",
      "100": "#1F1F23",
      ...
      "900": "#FAFAFB"
    },
    "accent": {
      "primary":   "#F2843E",  // pangolin orange (placeholder)
      "primary-hover": "#E0732D",
      "secondary": "#3E8EF2"
    },
    "semantic": {
      "surface":   { "light": "#FFFFFF", "dark": "#141416" },
      "surface-elevated": { "light": "#F7F7F8", "dark": "#1F1F23" },
      "text":      { "light": "#0A0A0B", "dark": "#FAFAFB" },
      "text-muted":{ "light": "#5A5A60", "dark": "#A4A4AC" },
      "border":    { "light": "#E7E7EB", "dark": "#2A2A30" },
      "success":   { "light": "#1F9D55", "dark": "#3BD27F" },
      "warning":   { "light": "#C77A1A", "dark": "#F2A94B" },
      "danger":    { "light": "#C42D2D", "dark": "#F25555" }
    }
  },
  "typography": {
    "font_family": {
      "sans": "'Inter', system-ui, -apple-system, sans-serif",
      "mono": "'JetBrains Mono', ui-monospace, monospace"
    },
    "size": { "xs": "0.75rem", "sm": "0.875rem", "base": "1rem",
              "lg": "1.125rem", "xl": "1.25rem", "2xl": "1.5rem",
              "display": "2.25rem" },
    "weight": { "regular": 400, "medium": 500, "semibold": 600, "bold": 700 },
    "line_height": { "tight": "1.2", "base": "1.5", "loose": "1.75" }
  },
  "spacing": { "0": "0", "1": "0.25rem", "2": "0.5rem", "3": "0.75rem",
               "4": "1rem", "6": "1.5rem", "8": "2rem",
               "12": "3rem", "16": "4rem", "24": "6rem" },
  "radius": { "sm": "4px", "md": "8px", "lg": "12px", "full": "9999px" },
  "elevation": {
    "none": "none",
    "sm":   "0 1px 2px rgba(0,0,0,0.06)",
    "md":   "0 4px 8px rgba(0,0,0,0.10)",
    "lg":   "0 12px 24px rgba(0,0,0,0.14)"
  },
  "motion": {
    "duration": { "fast": "100ms", "base": "180ms", "slow": "280ms" },
    "easing": {
      "standard":   "cubic-bezier(0.2, 0, 0, 1)",
      "decelerate": "cubic-bezier(0, 0, 0.2, 1)",
      "accelerate": "cubic-bezier(0.4, 0, 1, 1)",
      "spring":     "cubic-bezier(0.34, 1.56, 0.64, 1)"
    }
  }
}
```

### 3.2 Output: `tokens.css`

```css
/* GENERATED by tools/design-tokens-gen — DO NOT EDIT BY HAND.
   Source: apps/design-tokens/tokens.json  schema_version=1 */
:root {
  --color-accent-primary: #F2843E;
  --color-accent-primary-hover: #E0732D;
  --color-accent-secondary: #3E8EF2;

  --color-surface: #FFFFFF;
  --color-surface-elevated: #F7F7F8;
  --color-text: #0A0A0B;
  --color-text-muted: #5A5A60;
  --color-border: #E7E7EB;
  --color-success: #1F9D55;
  --color-warning: #C77A1A;
  --color-danger: #C42D2D;

  --font-family-sans: 'Inter', system-ui, -apple-system, sans-serif;
  --font-family-mono: 'JetBrains Mono', ui-monospace, monospace;
  --font-size-xs: 0.75rem;
  ...
  --space-1: 0.25rem;
  ...
  --radius-sm: 4px;
  ...
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.06);
  ...
  --motion-duration-fast: 100ms;
  ...
}

[data-theme="dark"] {
  --color-surface: #141416;
  --color-surface-elevated: #1F1F23;
  --color-text: #FAFAFB;
  --color-text-muted: #A4A4AC;
  --color-border: #2A2A30;
  --color-success: #3BD27F;
  --color-warning: #F2A94B;
  --color-danger: #F25555;
}
```

### 3.3 Output: `tokens.rs` (or `lib.rs` per Q-a)

```rust
// SPDX-License-Identifier: AGPL-3.0-or-later
// GENERATED by tools/design-tokens-gen — DO NOT EDIT BY HAND.
// Source: apps/design-tokens/tokens.json  schema_version=1
#![forbid(unsafe_code)]

pub const SCHEMA_VERSION: u8 = 1;

// --- COLOR (hex strings; theme-pair semantics flagged via the LIGHT/DARK suffix) ---
pub const COLOR_ACCENT_PRIMARY: &str = "#F2843E";
pub const COLOR_ACCENT_PRIMARY_HOVER: &str = "#E0732D";
pub const COLOR_SURFACE_LIGHT: &str = "#FFFFFF";
pub const COLOR_SURFACE_DARK: &str = "#141416";
...

// --- TYPOGRAPHY ---
pub const FONT_FAMILY_SANS: &str = "'Inter', system-ui, -apple-system, sans-serif";
pub const FONT_SIZE_BASE: &str = "1rem";
...

// --- SPACING ---
pub const SPACE_4: &str = "1rem";
...
```

(Identifier canonicalization: dash → underscore; upper-snake for `const` names. Tested.)

## 4. L-invariants

- **L1 zero-secret in tokens** — design tokens are non-secret by definition; the file format gates against ever putting secrets in (the generator rejects values that look like secrets — base64, long random hex, etc. — with a typed error, for paranoia).
- **L2 no new atomic surface.**
- **L3 fail-closed** — unknown `schema_version` rejects fail-closed; missing required categories reject fail-closed; the CI gate ensures the dist files are up-to-date or the build fails.
- **L5 no new external crates beyond `serde_json`** (workspace-transitive).
- **L6 AGPL SPDX + `forbid(unsafe_code)`** on every file.
- **L8 tests** — round-trip (parse JSON → emit → re-parse the emitted CSS / Rust → assert structural equality); identifier canonicalization tests; unknown-schema_version test; secret-shaped-value rejection test; deterministic emit test (run generator twice → byte-identical output).
- **L9 §16 ledger** — DECISIONS + DEVLOG entries on merge.

## 5. Open decisions — pre-locked (one carve-out for the builder)

- **Q-a (`tokens.rs` vs `pangolin-design-tokens` crate): builder's call.** Two paths:
  - (i) Emit `apps/design-tokens/dist/tokens.rs` as a standalone file; downstream crates `include!` it. Simpler; no new crate; cleaner build graph.
  - (ii) Make `apps/design-tokens/` itself a `pangolin-design-tokens` crate whose `lib.rs` is the generated tokens. Downstream crates depend on it via `pangolin-design-tokens = { path = "../design-tokens" }`. More idiomatic Rust; clearer dep arrow.
  Either is fine; pick the one that requires fewer changes to the workspace `Cargo.toml`. Report which.
- All other decisions are locked per §0a.

## 6. Places that need care

- **The generator MUST be deterministic.** Same input → byte-identical output. Use BTreeMap (not HashMap) for any ordered iteration; use the same float-to-string formatter; sort keys.
- **The CI up-to-date check** must run on every PR (gate against drift). Add as a step in the existing `ci.yml`.
- **The identifier canonicalization** (`accent-primary` → `COLOR_ACCENT_PRIMARY`) is the most fragile part — must round-trip through tests on both sides (CSS naming + Rust naming).
- **NO build.rs.** Designers + Kelvin must be able to eyeball the dist files in `git diff`. `build.rs`-generated artifacts would be invisible to PR review.
- **Tasteful default disclaimer** — the JSON tokens.json file MUST have a leading comment (well, JSON doesn't have comments — use a `"_comment"` key) saying "first-pass values; refined at MVP-4-D + closed beta". Sets expectation so a reviewer doesn't bikeshed values that will change.

## 7. Success criteria

- `cargo run -p design-tokens-gen` produces both output files byte-identically on repeat runs.
- `git diff --exit-status apps/design-tokens/dist/` clean immediately after a generator run.
- The new CI job catches a JSON edit without a re-generate.
- A downstream Rust caller can `use pangolin_design_tokens::SPACE_4;` and get `"1rem"`.
- A downstream CSS caller can `var(--space-4)` and get `1rem`.
- All hermetic tests green; `cargo fmt --check` + `cargo clippy -p design-tokens-gen --all-targets -- -D warnings` clean.

## 8. Out of scope (filed for follow-up)

- Actual Design-Spec-fidelity color values (refines at MVP-4-D).
- TypeScript output (when the extension popup needs typed access — defer to MVP-4-G).
- Token-versioning migration (when downstream consumers exist).
- Animation token presets (deferred to MVP-4-D's motion-design pass).
- Dark-mode auto-toggle by OS preference (UX-flow concern; MVP-4-B's shell handles).
