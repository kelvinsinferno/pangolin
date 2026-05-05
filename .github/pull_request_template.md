# Pull Request

## Issue
<!-- e.g., Closes #P0-1 -->
Closes #

## Issue plan
<!-- Link to docs/issue-plans/<id>.md -->
- [ ] Plan committed at `docs/issue-plans/<id>.md` and approved before code

## Spec reference
<!-- Quote the spec clause this PR implements. Master plan §17 maps components to specs. -->
- Spec:
- Section / clause:

## Security-critical?
- [ ] **Yes** — touches crypto, session policy, contracts, recovery, capture authority, native messaging, device wallet, funder service, or FFI surface. Kelvin must approve plan and code.
- [ ] No — peer review sufficient.

## Test summary
<!-- Each item = one test from the issue plan's test plan, with status. -->
- [ ] Happy path:
- [ ] Error path:
- [ ] Adversarial / negative:
- [ ] CI green on a clean run

## Forbidden-term check (user-facing surfaces only)
- [ ] No new occurrences of: gas, blockchain, transaction (in user copy), decentralized storage, hashes, revisions
- [ ] If any present: justified in PR description and added to allowlist

## DEVLOG entry
<!-- 1-3 sentences for DEVLOG.md describing what shipped, surprises, deferred follow-ups -->
```
[YYYY-MM-DD] <issue-id>:
```

## E2E_TESTS.md
- [ ] N/A (does not touch sync/conflict/recovery/autofill)
- [ ] Entry added at `E2E_TESTS.md`
