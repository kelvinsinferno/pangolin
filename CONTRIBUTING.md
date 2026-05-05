# Contributing to Pangolin

This document is mandatory reading before any code is written. It encodes the discipline that makes a self-custody password manager safe.

## Read order (day 1)

1. `../../.openclaw/workspace-studio-pangolin/pangolin-workspace.md` — project rules + agent lanes
2. The four canonical specs (links in `docs/specs/`):
   - Whitepaper
   - Unified Session Authority, Hardware & Interaction Specification
   - Browser Extension & Mobile Autofill Integration Specification (+ Extension↔Core API Contract)
   - Unified UI/UX Design System Specification
3. `../../.openclaw/workspace-studio-pangolin/PANGOLIN_PLAN.md` — master execution plan
4. This file (CONTRIBUTING.md)
5. `DECISIONS.md` — locked architectural decisions

## Cardinal principles (non-negotiable)

1. Rust core is the only security-critical component.
2. No plaintext leaves the device — ever, for any reason.
3. Blockchain is a log, never an authority.
4. Append-only state. Never silent merge.
5. Session invariant: start = 2 proofs, maintain = 1 proof, presence escalation for high-risk.
6. Authority is layered: social recovery → ownership → session → operation.
7. Ambient-first UX.
8. Capture-authority rule: one component per context.
9. Forbidden user-facing terms: "gas", "blockchain", "transaction", "decentralized storage", "hashes", "revisions".
10. Hardware accelerates, never anchors.

## Per-Issue Development Protocol (§16 of master plan)

Every issue passes five gates: PLAN → APPROVE → BUILD → TEST → SIGNOFF.

### 1. PLAN

Before writing any code, create `docs/issue-plans/<issue-id>.md` with these mandatory sections:

```markdown
# Issue <id>: <title>

## Spec reference
<which canonical spec section this implements; quote the relevant clause verbatim>

## Goal
<one paragraph: what this issue accomplishes and why it exists>

## Approach
<2-5 bullets: how it will be built. Reference existing modules, crates, patterns.
Call out any new abstractions and justify them.>

## Public surface
<exact API: function signatures, types, contract methods, message schemas.
This is what other issues will depend on.>

## Success criteria (how we'll know it works)
<3-7 specific, observable conditions. Each maps to a test.>

## Test plan
<list specific tests that will be written. Each test maps to a success criterion.
Includes: unit, integration, adversarial/negative.>

## Failure modes considered
<what could go wrong and how the implementation handles it.
For security-critical issues: explicit threat enumeration.>

## Rollback / abort plan
<what to do if mid-build it becomes clear the approach is wrong>

## Out of scope
<what this issue intentionally does NOT do>

## Estimated effort
<hours, not days. If >16 hours: split the issue.>
```

The plan file is committed first, on the issue branch, in its own commit. **No code commits land before the plan commit.**

### 2. APPROVE

A reviewer (peer agent, or Claude Code main, or Kelvin for security-critical) checks the plan for:

- Spec reference accurate; implementation matches spec intent
- Approach sound; no obvious design errors; no unnecessary abstractions
- Public surface consistent with surrounding code
- Success criteria specific, observable, falsifiable
- Test plan covers happy path, error path, adversarial path
- Failure modes section non-empty
- Out-of-scope list reasonable

**Security-critical issues** (any touching crypto, session policy, contracts, recovery, capture authority, native messaging boundaries, device-wallet code, funder service, FFI surface freezes) require **Kelvin approval on the plan**. Label them `security-critical`.

### 3. BUILD

Code on the issue branch:

- Commits reference the issue (e.g., `P3-2: implement Revision struct`)
- Spec refs in code comments at the line implementing each clause
- If the plan turns out to be wrong: stop, return to PLAN gate, revise, re-approve. **Do not silently drift.**
- No commenting out tests, no `#[ignore]`, no `// TODO: fix later` for items in the test plan

### 4. TEST

All tests defined in the issue plan must pass on CI.

- Every success criterion has a test
- Negative tests exist for every failure mode
- Branch coverage >90% on changed lines for security-critical paths
- **Never weaken a test to make it pass.** If a test seems wrong, that's a design conversation — return to PLAN.

If TEST fails:
1. Diagnose: build bug or design bug?
2. Build bug → fix in BUILD, retest.
3. Design bug → return to PLAN, revise, re-approve, rebuild, retest.
4. Loop until green.

### 5. SIGNOFF

Final checks:

- All tests in the issue plan pass on a clean CI run
- Public surface matches what the plan said
- Reviewer approves the PR
- No new TODOs/FIXMEs without follow-up issues tracked
- `E2E_TESTS.md` entry added if sync/conflict/recovery/autofill paths touched
- Spec ref reaffirmed — does the code actually implement the cited clause?
- DEVLOG entry: 1–3 sentences on what shipped, surprises, deferred follow-ups

PR merges. Issue closes. Move on.

## Forbidden in user-facing surfaces

CI rejects any PR that adds these terms in `apps/`, `design/`, or user-visible markdown:

- gas
- blockchain
- transaction (in user-facing copy; internal code may use "tx" / "transaction" freely)
- decentralized storage
- hashes
- revisions (use "saves" or "updates" in user copy)

Internal code, comments, and developer docs may use these terms freely.

## Failure & escalation

| Situation | Response |
|---|---|
| TEST fails repeatedly with same root cause | Hard stop. Spawn a fresh agent with full context. If still stuck, escalate to Kelvin. |
| Plan approved but build reveals the approach is wrong | Return to PLAN gate. Document the lesson in DEVLOG. Do not patch around the wrong design. |
| Issue blocked by another in-flight issue | Document in DEVLOG and pause. Do not stub around an upstream issue still in flight unless the issue plan explicitly says so. |
| Spec ambiguity discovered mid-implementation | Stop. Document. Escalate to Kelvin for clarification. Never interpret silently. |
| Adversarial test scenario not in the plan | Add to the plan, get re-approval, add the test, fix if necessary. |

## Commit message format

```
<issue-id>: <one-line summary>

<optional body>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

## License

By contributing, you agree that your contributions are licensed under Apache-2.0.
