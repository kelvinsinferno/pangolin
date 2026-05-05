# Canonical Specifications

> These four documents are the normative contract that Pangolin implements.
> They live in `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\` (PDF) and `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\` (extracted text).
> When code disagrees with a spec, the spec wins. When specs need to change, that requires Kelvin approval.

## The four specs

### 1. Whitepaper
- PDF: `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\Pangolin Whitepaper.pdf`
- Extracted: `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\whitepaper_text.txt`
- Also contained in `Pangolin.pdf` §1–11

**Covers:** Local-first usage, layered authority (social recovery → ownership → session → operation), append-only revisions, blockchain as durability log only, Object/Commit/Enhanced-Privacy storage modes, threat-model boundaries.

### 2. Unified Session Authority, Hardware & Interaction Specification
- Source: `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\Pangolin.pdf` §4101–4419
- Extracted: `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\pangolin_main_text.txt` lines 4101–4419

**Covers:** Session invariant (start = 2 proofs, maintain = 1), proof types (presence + identity), session states, session rules, hardware classes (NFC primary / platform authenticator mandatory / USB optional), session timing (15 min default idle, 4h absolute max, 30–60s presence freshness, 60s prompt timeout), prompt + interruption behavior, mid-action resume, prompt deduplication, failure handling.

### 3. Browser Extension & Mobile Autofill Integration Specification
- Source: `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\Pangolin.pdf` §4420–4805 + Extension↔Core API Contract §4825–5570
- Extracted: same as above

**Covers:** Ambient-first operation, capture-authority rule, system architecture (web → ext → native messaging → Tauri → Rust core), 16 JSON-RPC message types (`core.status`, `accounts.match`, `credential.fill`, `totp.current`, `session.start`, `session.extend`, `capture.candidate`, `capture.confirmed`, `domain.alias.request`, `event.audit`, `extension.heartbeat`, `capture.authority.register`, plus inverse responses), origin binding, iframe rules, platform priority (Chromium → Android → iOS → Firefox → Safari), TOTP handling, save/update capture flows.

### 4. Unified UI/UX Design System Specification
- Source: `C:\Users\kelvi\Desktop\Kelvinsinferno studio\Pangolin\Design Spec.pdf`
- Extracted: `C:\Users\kelvi\.openclaw\workspace-studio-pangolin\design_spec_text.txt`

**Covers:** Design philosophy (future-natural, ambient-first, security-visibility-without-alarm), brand identity (mascot + logo behavior), color system (warm-armor + graphite + restrained-teal accent), typography (Inter/Geist + JetBrains Mono), layout (4px grid; layered panels), desktop / browser extension / mobile design, session visualization, motion + animation (pangolin-scale unfolding metaphor; 100–350ms ranges), prompt + interruption design, component system, accessibility, copy + tone rules (forbidden terms list).

## Supporting locked documents

- **Pricing & business model** — `Pangolin.pdf` §1043–1278: $0.02/revision, $30 one-time, import tiers, iOS entitlement-state model
- **Hardware compatibility** — `Pangolin.pdf` §1279–1338: NFC-first, platform authenticators, certification program concept
- **Market positioning** — `Pangolin.pdf` §1721–1869: 5 axes, primary beachhead, locked one-liner
- **Commit Mode (Phase 2)** — `Pangolin.pdf` §3923+: IPFS pinning, off-chain durability
- **Auto-capture & TOTP appendix** — `Pangolin.pdf` §4256–4456: capture detection, TOTP integration into session model

## Read order for new contributors

1. Whitepaper (the *why*)
2. Unified Session Authority spec (the daily-access invariant)
3. UI/UX Design System spec (the experience contract)
4. Browser Extension & Autofill spec + API contract (the integration points)
5. Master plan: `../../../.openclaw/workspace-studio-pangolin/PANGOLIN_PLAN.md`
6. CONTRIBUTING.md
