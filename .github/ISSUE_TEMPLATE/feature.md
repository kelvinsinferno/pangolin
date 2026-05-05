---
name: Feature / Issue
about: New work item that flows through the §16 Per-Issue Development Protocol
title: "<id>: <one-line summary>"
labels: ''
assignees: ''
---

> **Before opening this issue:** the executor must produce `docs/issue-plans/<id>.md` with the structure below. Code commits cannot precede the plan commit on the issue branch.

# Issue <id>: <title>

## Spec reference
<!-- Which canonical spec section this implements; quote the relevant clause verbatim -->

## Goal
<!-- One paragraph: what this issue accomplishes and why it exists -->

## Approach
<!-- 2-5 bullets: how it will be built. Reference existing modules. Justify any new abstractions. -->

## Public surface
<!-- Exact API: function signatures, types, contract methods, message schemas. -->

## Success criteria
<!-- 3-7 specific, observable, falsifiable conditions. Each maps to a test. -->

## Test plan
<!-- List specific tests. Includes: unit, integration, adversarial/negative. -->

## Failure modes considered
<!-- What could go wrong and how the implementation handles it. Threats for security-critical issues. -->

## Rollback / abort plan
<!-- What to do if mid-build the approach is wrong. -->

## Out of scope
<!-- What this issue intentionally does NOT do. -->

## Estimated effort
<!-- Hours, not days. If >16 hours: split. -->

## Security-critical?
<!-- Yes/no. If yes: Kelvin approval required at PLAN gate (§16.3 of master plan). -->
