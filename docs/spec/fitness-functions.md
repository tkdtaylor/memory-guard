# Fitness functions

**Project:** memory-guard
**Last updated:** 2026-06-19

## What this file is

Fitness functions are **executable architectural invariants** — automated checks that verify the code
still obeys the rules memory-guard commits to. This file is the declarative spec for those checks; the
implementation lives in the runner the rules point to.

## Status

There is **no `make fitness` / `go fitness` target wired yet** — `go build ./... && go test ./...`
(plus dep-scan / code-scanner for the supply chain once a Presidio-backed detector lands) is the
verification gate today. The rows below are **proposed** (the security invariants the codebase
implies). Promoting one to `active` means adding its check command and wiring it into a `fitness`
umbrella target, in the same commit as the rule change.

## How to run (once wired)

```bash
make fitness          # run all fitness functions
make fitness-<rule>   # run one rule by name
```

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Status | Why this rule earns its row |
|----|------|----------|---------|-----------|---------------|----------|--------|----------------------------|
| F-001 | Write-gate is fail-closed on suspected poisoning | security | No `validate_write` path stores content flagged `injection_suspected`; a flagged write returns `{allow:false, stored_id:null}` and mutates no store | 0 poisoned writes persisted | `make fitness-write-gate-fail-closed` (TODO) | block | proposed | The write-gate is *the* value-add of the block — storing suspected context poisoning is the exact ASI06 failure memory-guard exists to prevent (ADR-001 §1; test `TestWriteGateRejectsSuspectedInjection`). |
| F-002 | PII is never stored or returned raw | security | No stored `entry.content` and no `validate_write`/`validate_read` response contains raw PII; PII is `<LABEL>`-replaced before storage and again on read | 0 raw-PII leaks (store or response) | `make fitness-pii-redacted` (TODO) | block | proposed | Cross-session PII leakage is one of the five ASI06 scenarios; raw PII in the store or a response defeats the redaction the block promises (ADR-001 §1; test `TestWriteRedactsPIIAndStores`). |
| F-003 | Deletion is verified, not assumed | security | `verify_delete` computes `confirmed` from a fresh post-delete presence check, never from the `delete()` return; (v1: across every index/copy) | `confirmed` always reflects a re-check | `make fitness-delete-verified` (TODO) | block | proposed | Post-deletion verification is the documented industry blind spot the block was built to close; a bare `delete()` that assumes success is the gap, not the fix (ADR-001 §5; test `TestVerifyDeleteConfirmsAbsence`). |
| F-004 | Detection backend isolated behind the `Detector` seam | structural | No PII/injection-detection logic or backend-specific type (e.g. Presidio) appears in `guard.go` / `ipc.go` / `main.go` — all of it is behind the `Detector` interface in `detector.go` | 0 detection logic outside the seam | `make fitness-detector-seam` (TODO) | block | proposed | The seam is what keeps the substrate (Go) independent of the detection tool (Presidio) and the backend choice cheap to defer to the tracer; leaking detection into the guard collapses that boundary (ADR-001 §3; the `Detector` interface). |
| F-005 | Fail-closed on malformed/unknown requests | security | Every non-result path (unparseable JSON, unknown op) returns the structured error shape and mutates no store; no path stores on error | 0 store-on-error paths | `make fitness-fail-closed` (TODO) | block | proposed | Store-on-error is the classic gate regression; the safe terminal state must always be a structured error with nothing stored (ADR-001 §7, behaviors B-005; `ipc.go::errShape`). |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.

Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Adversarial-poisoning recall threshold (MINJA/GRAGPoison) | The v0 injection detector is a few regex patterns, by design (scoping). A recall-threshold rule would fail until the adversarial suite + a real detector exist — track it as a v1 limitation, not a red fitness row, until then. |
| Hot-path latency budget on `validate_*` | The latency budget is one of the **open** decisions the memory-guard tracer must settle (detector deployment shape drives it). Premature as a rule before the backend is chosen. |
| Identity-scoped read isolation | v0 reads match by substring across the whole store; tenant isolation is unbuilt. A rule asserting it would fail by design — track as a limitation until the identity model lands. |

## Source-of-truth links

- F-001 ← [SPEC.md](SPEC.md) top-level invariants, ADR-001 §1, [behaviors.md](behaviors.md) B-001
- F-002 ← ADR-001 §1, [behaviors.md](behaviors.md) B-001/B-002, [data-model.md](data-model.md) `entry`
- F-003 ← ADR-001 §5, [behaviors.md](behaviors.md) B-003
- F-004 ← ADR-001 §3, [architecture.md](architecture.md) §4, [interfaces.md](interfaces.md) `Detector`
- F-005 ← ADR-001 §7, [behaviors.md](behaviors.md) B-005, [data-model.md](data-model.md) error shape

## Notes

- These rules are memory-guard's commitments, not generic best practice. Each guards a stated invariant
  in the spec; a violation breaks a security promise, not just style.
- They are `proposed` until the operator confirms and the check command exists. Don't claim a rule is
  enforced until its check command runs.
- F-001…F-003 and F-005 are each covered by an existing unit test today (the `Asserts` column); the row
  stays `proposed` only because the automated fitness runner is not yet wired. F-004 (seam isolation)
  has no unit test — it is a structural check a runner would grep for.
</content>
