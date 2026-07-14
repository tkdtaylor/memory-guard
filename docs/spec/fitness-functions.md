# Fitness functions

**Project:** memory-guard
**Last updated:** 2026-07-14

## What this file is

Fitness functions are **executable architectural invariants** — automated checks that verify the code
still obeys the rules memory-guard commits to. This file is the declarative spec for those checks; the
implementation lives in the runner the rules point to.

## Status

**`make fitness` is wired (task 012).** `make check` runs build + test + all enforced fitness
functions and exits non-zero on any `block`-severity breach. The verification gate is:

```bash
go build ./... && go test ./...   # compilation + unit tests (unchanged from v0)
make fitness                      # all enforced fitness functions
make check                        # build + test + fitness (the full gate)
```

F-001–F-003 and F-005 are **proposed** — each backed by an existing unit test but not yet
independently wired to a `make fitness-<rule>` target; wiring them is follow-on work. **F-004,
F-006, and F-007 are `active`** — each has a real check command and runs as part of `make fitness`.
Promoting another rule to `active` means giving it a runnable check command and a `fitness-<rule>`
target, in the same commit as the rule change.

## How to run

```bash
make fitness                    # run all enforced fitness functions (exits non-zero on block breach)
make fitness-latency            # F-007: hot-path latency budget
make fitness-recall-precision   # F-006: write-gate + PII recall/precision floors
make fitness-seam               # F-004: detector + store seam-isolation grep
make check                      # full gate: build + test + fitness
```

## Rules

| ID | Rule | Category | Asserts | Threshold | Check command | Severity | Status | Why this rule earns its row |
|----|------|----------|---------|-----------|---------------|----------|--------|----------------------------|
| F-001 | Write-gate is fail-closed on suspected poisoning | security | No `validate_write` path stores content flagged `injection_suspected`; a flagged write returns `{allow:false, stored_id:null}` and mutates no store | 0 poisoned writes persisted | `make fitness-write-gate-fail-closed` (TODO) | block | proposed | The write-gate is *the* value-add of the block — storing suspected context poisoning is the exact ASI06 failure memory-guard exists to prevent (ADR-001 §1; test `TestWriteGateRejectsSuspectedInjection`). |
| F-002 | PII is never stored or returned raw | security | No stored `entry.content` and no `validate_write`/`validate_read` response contains raw PII; PII is `<LABEL>`-replaced before storage and again on read | 0 raw-PII leaks (store or response) | `make fitness-pii-redacted` (TODO) | block | proposed | Cross-session PII leakage is one of the five ASI06 scenarios; raw PII in the store or a response defeats the redaction the block promises (ADR-001 §1; test `TestWriteRedactsPIIAndStores`). |
| F-003 | Deletion is verified, not assumed | security | `verify_delete` computes `confirmed` from a fresh post-delete presence check, never from the `delete()` return; (v1: across every index/copy) | `confirmed` always reflects a re-check | `make fitness-delete-verified` (TODO) | block | proposed | Post-deletion verification is the documented industry blind spot the block was built to close; a bare `delete()` that assumes success is the gap, not the fix (ADR-001 §5; test `TestVerifyDeleteConfirmsAbsence`). |
| F-004 | Detection and store backends isolated behind their seams | structural | No detector-backend-specific implementation symbol (e.g. Presidio import path, `PresidioClient` type) and no store-backend-internal type (`TwoIndexStore`, `byContent`) appears in non-comment code in `guard.go` / `ipc.go` / `main.go` or in `CONTRACT.md`; all backend specifics live in `detector.go` / `store.go` | 0 backend specifics outside the seam | `make fitness-seam` | block | active | The seam is what keeps the substrate (Go) independent of the detection tool (Presidio) and the storage implementation (TwoIndexStore), and keeps both backend choices cheap to defer or revisit; leaking either into the guard collapses that boundary (ADR-001 §3, ADR-005; the `Detector` and `MemoryStore` interfaces). |
| F-005 | Fail-closed on malformed/unknown requests | security | Every non-result path (unparseable JSON, unknown op) returns the structured error shape and mutates no store; no path stores on error | 0 store-on-error paths | `make fitness-fail-closed` (TODO) | block | proposed | Store-on-error is the classic gate regression; the safe terminal state must always be a structured error with nothing stored (ADR-001 §7, behaviors B-005; `ipc.go::errShape`). |
| F-006 | Write-gate adversarial recall ≥ threshold AND PII corpus recall/precision = 1.00 | security | `TestFitnessRecallPrecision` (fitness runner, task 012) runs the write-gate poisoning suite (32 labelled cases: MINJA / GRAGPoison / context-window injection) and the PII corpus (9 categories, 36 positive samples) through `ValidateWrite` / `RedactPII` and asserts: poisoning recall ≥ 0.80 and precision ≥ 0.85 per backend; PII per-category recall ≥ 0.80; PII overall precision = 1.00. Task 023 adds a SEPARATE, non-enforced held-out check (`TestPoisoningOWASP...` in `owasp_benchmark_corpus_test.go`) over the combined `adversarialCorpus` ++ `owaspCorpus`; it does NOT change what `make fitness-recall-precision` enforces. | **Enforced (unchanged by task 023):** poisoning recall ≥ 0.80, precision ≥ 0.85 over task 002's `adversarialCorpus` alone (floor from 26/32 = 0.8125, 26/30 = 0.867 measured 2026-06-25, task 014 Phase A); PII recall/precision = 1.00 per category. **Held-out (task 023, not enforced):** combined-corpus recall = 0.5256 (41/78), precision = 0.9111 (4 FP / 30 benign) per backend; OWASP-subset recall = 0.3261 (15/46). | `make fitness-recall-precision` | block | active | Turns "passes its own examples" into a measured adversarial bar locked to the documented baselines (task 002). Enforced poisoning baseline (task 014 Phase A, UNCHANGED by task 023): recall=0.81 (26/32), precision=0.87 (26/30) over `adversarialCorpus` only; Phase A recovered 4 no-collision miss classes ([INJECT:] bracket prefix, AI-anchored jailbreak phrasing, base64/URL decode-then-rescan) over the byte-for-byte-UNCHANGED corpus; the 6 remaining misses are the framing classes (remember:/from now on/whenever/any AI) deferred to Phase B (ADR-010). PII: all 9 categories recall=1.00, precision=1.00 (task 004). **Task 023 held-out addition** (`owasp_benchmark_corpus_test.go`, measured 2026-07-14, NOT part of the enforced gate): a `derived` OWASP Agent Memory Guard corpus (46 poisoning across self-reinforcement, size-anomaly, source-spoofing, protected-key-bypass, plus 16 benign incl. 4 hard-benign) concatenated with `adversarialCorpus` gives combined recall=0.5256 (41/78), precision=0.9111 (4 FP / 30 benign) per backend; OWASP-subset recall=0.3261 (15/46). The combined number is lower by design, not a regression: memory-guard has no self-reinforcement, size-anomaly, source-class, or protected-key detector today, so 31 of the 46 OWASP cases are documented genuine misses (each `MISS:`-noted in the corpus, REQ-006). Its own thresholds live in `owaspBackendThresholds` (recall 0.30, precision 0.65), set 22 to 26 pp below measured per the honest-floor convention (10 to 30 pp below measured, never above measured, so a genuine miss cannot be papered over). A future detector task (013/014-style) may recover the four gap classes; the enforced floor here is unchanged and still measures task 002's corpus only. A future stronger backend raises the enforced threshold constants in `fitness_test.go` without touching either corpus. |
| F-007 | Hot-path latency budget `< 1 ms` per `validate_*` op | performance | `TestFitnessLatency` measures average per-op detection cost of `ValidateWrite` over 500 iterations (after 50-op warmup) using the live `NativeDetector` and fails if the average exceeds `1 ms` | `< 1 ms` per `validate_*` op; current tree ~5.6–22 µs | `make fitness-latency` | block | active | The per-call latency budget is the stated constraint that drove the Go-native in-process backend choice (ADR-002). The runner locks in that decision by asserting the budget against the hot path — a detector backend that costs ≥ 1 ms per op violates the latency premise the stack was designed around. |

Categories: `structural`, `hygiene`, `performance`, `complexity`, `security`, `coverage`.

Severity: `block` (fails the runner) / `warn` (surfaces only).

## Rules considered but rejected

| Proposed rule | Why rejected |
|---------------|--------------|
| Adversarial-poisoning recall threshold (MINJA/GRAGPoison) | ~~The v0 injection detector is a few regex patterns, by design (scoping). A recall-threshold rule would fail until the adversarial suite + a real detector exist — track it as a v1 limitation, not a red fitness row, until then.~~ **Promoted to F-006 (task 002)** — the adversarial suite exists; the enforced floor is recall=0.81, precision=0.87 (task 014 Phase A; was recall=0.69, precision=0.85 on the v0 4-pattern regex). |
| Hot-path latency budget on `validate_*` | ~~The latency budget is one of the **open** decisions the memory-guard tracer must settle (detector deployment shape drives it). Premature as a rule before the backend is chosen.~~ **Promoted to F-007 (task 012)** — the backend is chosen (ADR-002: Go-native in-process `NativeDetector`, measured ~5.6 µs/op). The budget (`< 1 ms`) is now enforced by `make fitness-latency`. |
| Identity-scoped read isolation | v0 reads match by substring across the whole store; tenant isolation is unbuilt. A rule asserting it would fail by design — track as a limitation until the identity model lands. |

## Source-of-truth links

- F-001 ← [SPEC.md](SPEC.md) top-level invariants, ADR-001 §1, [behaviors.md](behaviors.md) B-001
- F-002 ← ADR-001 §1, [behaviors.md](behaviors.md) B-001/B-002, [data-model.md](data-model.md) `entry`
- F-003 ← ADR-001 §5, [behaviors.md](behaviors.md) B-003
- F-004 ← ADR-001 §3, ADR-005, [architecture.md](architecture.md) §4, [interfaces.md](interfaces.md) `Detector`/`MemoryStore`, `fitness_test.go::TestFitnessSeam`
- F-005 ← ADR-001 §7, [behaviors.md](behaviors.md) B-005, [data-model.md](data-model.md) error shape
- F-006 ← ADR-002, `poisoning_suite_test.go`, `detector_corpus_test.go`, `fitness_test.go::TestFitnessRecallPrecision` (enforced floor); `owasp_benchmark_corpus_test.go::TestPoisoningOWASP...` (task 023 held-out combined-corpus measurement, not enforced)
- F-007 ← ADR-002, [AGENTS.md](../../AGENTS.md) latency invariant, `fitness_test.go::TestFitnessLatency`

## Notes

- These rules are memory-guard's commitments, not generic best practice. Each guards a stated invariant
  in the spec; a violation breaks a security promise, not just style.
- They are `proposed` until the operator confirms and the check command exists. Don't claim a rule is
  enforced until its check command runs.
- F-001…F-003 and F-005 are each covered by an existing unit test today (the `Asserts` column); the row
  stays `proposed` only because each lacks an independent `make fitness-<rule>` target — wiring them is
  follow-on work. F-004, F-006, and F-007 are `active` and run via `make fitness`.
- Source-of-truth links: F-006 ← `poisoning_suite_test.go` / `detector_corpus_test.go`;
  F-007 ← ADR-002; F-004 ← ADR-001 §3, ADR-005, `fitness_test.go::TestFitnessSeam`.
</content>
