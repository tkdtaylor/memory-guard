# Test Coverage Tracker

**Project:** memory-guard

## Rules

- Test specs are written **before** implementation begins — no exceptions
- A task is **not** "complete" because the feat commit landed and tests passed. See the verification ladder below.
- Each row maps a task ID to its spec file, current test status, and the verification level achieved

## Coverage

| Task ID | Feature | Spec file | Tests written | Status | Verified by |
|---------|---------|-----------|---------------|--------|-------------|
| 001 | Resolve the `Detector` backend (memory-guard tracer + ADR) | `001-detector-backend-tracer-test-spec.md` | TC-001…TC-006 | ✅ | spec-verifier APPROVE (all 6 TCs ✓, seam/contract/stdlib invariants hold). L6: `go run . write` with `NativeDetector` (ADR-002, Go-native in-process) → PII `pii:EMAIL`-redacted, injection `allow:false`/`stored_id:null`, benign clean. L2: `go test -count=1 ./...` → `ok …memory-guard 0.294s`. Detection cost ~5.6 µs/op (budget <1 ms). TC-004 (dep-scan): no new dep, `go.mod`/`go.sum` unchanged → trivially clear. `guard.go`/`ipc.go`/`CONTRACT.md` untouched. |
| 002 | Adversarial context-poisoning test-suite for the write-gate | `002-adversarial-poisoning-suite-test-spec.md` | TC-001…TC-006 (planned) | ❌ | Pending — backlog. MINJA-/GRAGPoison-/context-window-injection cases + a measured recall/precision bar; depends on task 001's detector decision for the bar. Not started. |
| 003 | Post-deletion verification across every index/copy | `003-post-deletion-residue-verification-test-spec.md` | TC-001…TC-006 | 🟡 | L6 + L2. Method = ADR-003 tiered normalized substring/phrase/token-overlap, **zero new deps** (stdlib `crypto/sha256` only). `verify_delete` now returns `{confirmed, residue_detected, residue_summary?, deletion_hash}`; residue logic in `residue.go` (guard-side, NOT behind the `Detector` seam — `detector.go` untouched). TC-003 corpus (`TestResidueCorpusDetectionRate`): verbatim 5/5=100%, normalized-numeric 7/7=100%, paraphrase 0/2=0% (documented known-miss), **OVERALL 12/14=85.7% (>80% bar ✓), precision 100% (0 FP / 4 clean controls)**. TC-006: `go.mod`/`go.sum` unchanged → trivially clear. L6: live `serve` over Unix socket — `verify_delete` returned `residue_detected:true` + summary on a `$5000→$5k` residue, and `residue_detected:false` (no summary) on a clean store. L2: `go test -count=1 ./...` → `ok github.com/tkdtaylor/memory-guard 0.569s`. v0 `TestVerifyDeleteConfirmsAbsence` still green (TC-005). Pending spec-verifier before ✅. |
| 004 | PII recognizer coverage hardening (behind the Detector seam) | `004-pii-recognizer-coverage-test-spec.md` | TC-001…TC-005 | ✅ | spec-verifier APPROVE (all 5 TCs ✓; seam invariant held — only detector.go + tests + data-model.md changed). L5: `go test -v -run TestCorpusSummary ./...` → 9 categories, recall=1.00/category, precision=1.00 (0 FP / 9 hard negatives) for both RegexDetector and NativeDetector. L2: `go test -count=1 ./...` → `ok github.com/tkdtaylor/memory-guard 0.570s`. guard.go/ipc.go/main.go/CONTRACT.md untouched. Note: spec's `1.2.3.4` hard-negative is itself a valid IP; substituted `v1.2.3` and documented in data-model.md. |
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
