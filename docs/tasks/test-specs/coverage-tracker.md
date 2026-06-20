# Test Coverage Tracker

**Project:** memory-guard

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | Resolve the `Detector` backend (memory-guard tracer + ADR) | `001-detector-backend-tracer-test-spec.md` | TC-001…TC-006 (planned) | ❌ | Pending — backlog (next). Settles Presidio-sidecar vs. ONNX-in-process vs. Go-native NER + hot-path latency budget, behind the existing `Detector` seam; ADR. Not started. |
| 002 | Adversarial context-poisoning test-suite for the write-gate | `002-adversarial-poisoning-suite-test-spec.md` | TC-001…TC-006 (planned) | ❌ | Pending — backlog. MINJA-/GRAGPoison-/context-window-injection cases + a measured recall/precision bar; depends on task 001's detector decision for the bar. Not started. |
| 003 | Post-deletion verification across every index/copy | `003-post-deletion-residue-verification-test-spec.md` | TC-001…TC-006 (planned) | ❌ | Pending — backlog. Extends `verify_delete` to residue detection across entries/indexes (the documented gap); method (substring/embedding/Bloom) TBD in the tracer. Not started. |
| 004 | PII recognizer coverage hardening (behind the Detector seam) | `004-pii-recognizer-coverage-test-spec.md` | TC-001…TC-005 (planned) | ❌ | Pending — backlog. Broaden recognizers + cut false-negatives behind the `Detector` seam, measured against a PII corpus. Not started. |
| 005 | Publish / remote follow-up (git remote + push) | `005-publish-remote-followup-test-spec.md` | TC-001…TC-003 (planned) | ❌ | Pending — backlog. Create a git remote, confirm visibility, push; SPDX headers on new files (TODO.md). Largely operational; verified by the remote existing + push succeeding. Not started. |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | **Verified** — validation harness exercised the live runtime path, or operator observed the targeted behaviour |
| 🟡 | **Code merged** — feat-commit landed, unit tests + fitness + CI green, but runtime/live behaviour not yet observed |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |

## Verification ladder

A task earns 🟡 at levels 1–4 and ✅ only at level 5 or 6. The `Verified by` column records which level the row reached.

| Level | Evidence | Status this earns |
|-------|----------|-------------------|
| 1 | Code merged | 🟡 |
| 2 | Unit tests pass (paste verbatim final line of `go test ./...`) | 🟡 |
| 3 | `make fitness` passes (verbatim closing line) | 🟡 |
| 4 | CI passes (`gh run watch <id> --exit-status` → success) | 🟡 |
| 5 | **Validation harness** exercises the live runtime path end-to-end — paste the command and the final assertion line | ✅ |
| 6 | **Operator-observed** — operator (or executor via `go run .` / a live `serve`) saw the targeted behaviour in stdout / logs | ✅ |

If the task targets runtime-observable behaviour (CLI args, server endpoints, file outputs, side effects), level 5 or 6 is **required** before flipping to ✅. If the task only adds an internal helper covered by unit tests, level 2 may be sufficient — but in that case the row's `Verified by` should explicitly say "unit-test-only; no runtime surface" so future readers don't mistake silence for verification.

## Rule

**The task-executor commits at 🟡 by default.** Only the main session (after spec-verifier APPROVE + the appropriate level-5/6 evidence) updates the row to ✅, in a separate commit titled `verify: confirm task NNN — <level-5/6 evidence>`. This keeps the verification step visible in git history and prevents "merged ≠ done" drift.
</content>
