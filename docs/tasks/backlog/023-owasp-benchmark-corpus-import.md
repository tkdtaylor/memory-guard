# Task 023: Import the OWASP Agent Memory Guard benchmark corpus as held-out regression fixtures

**Project:** memory-guard
**Created:** 2026-07-14
**Status:** ❌ Not started

> Part of the OWASP-comparison adopt-task set (tasks 018–023, [`docs/plans/roadmap.md`](../../plans/roadmap.md), the "R3, snapshot / rollback" note). This is a **measurement + fixtures** task, not a detector-behavior change: it does not modify `detector.go`, does not chase 100% recall, and does not recover new miss-classes (that is a separate task-013/014-style follow-on, started only if this task's honest miss record justifies it).

## Goal

Import the [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/) project's published payload benchmark (`agent-memory-guard` package, reported ~55 payloads, 92.5% recall / 100% precision on their own suite) as an additional, clearly-provenanced, held-out fixture set, distinct from and never mutating task 002's `adversarialCorpus`, and use it to honestly measure memory-guard's own write-gate recall/precision on threat classes the existing corpus does not exercise. Then update the **F-006** fitness floor in place to the new honest baseline.

The task 002 corpus already covers MINJA, GRAGPoison, and context-window-injection framing. This task's value-add is the OWASP-distinctive classes memory-guard has no fixture for today: self-reinforcement/repetition-bias poisoning, size/length-anomaly injection, source-class spoofing (tool-output impersonating a trusted origin), and protected/immutable-key bypass attempts. These are the same four capability gaps [`docs/comparison-owasp-agent-memory-guard.md`](../../comparison-owasp-agent-memory-guard.md) already names under "What theirs does that we do not."

## Context

- Source project: OWASP Incubator **Agent Memory Guard** (`github.com/OWASP/www-project-agent-memory-guard`, the `agent-memory-guard` Python package). Already referenced in this repo: [`docs/comparison-owasp-agent-memory-guard.md`](../../comparison-owasp-agent-memory-guard.md) (full feature comparison, Apache-2.0, v0.3.0 June 2026) and [`docs/architecture/decisions/001-foundational-stack.md`](../../architecture/decisions/001-foundational-stack.md) (cited as one input to the foundational-stack decision).
- The fixture this task extends: task 002's `adversarialCorpus` in [`poisoning_suite_test.go`](../../../poisoning_suite_test.go) ([completed/002](../completed/002-adversarial-poisoning-suite.md) plus [its test spec](../test-specs/002-adversarial-poisoning-suite-test-spec.md)): 32 poisoning / 14 benign cases across MINJA/GRAGPoison/context-window classes, `backendThresholds` keyed by Detector type-name, `poisoningSample`/`poisoningClass` types.
- How floors get raised honestly in this repo: [task 013](../completed/013-injection-recall-lift.md) (rejected method, ADR-010) and [task 014](../completed/014-injection-recall-lift-phased.md) (Phase A shipped, ADR-011) both establish the pattern this task follows: measure on an unchanged corpus, raise the threshold constant, record the honest number in F-006, never trade recall for precision or vice versa, and record misses instead of hiding them. Task 023 reuses that discipline but does not touch the detector, only fixtures and the floor.
- Fitness floor: [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md) **F-006**. The enforced `make fitness-recall-precision` check (`fitness_test.go::TestFitnessRecallPrecision`) currently asserts recall ≥ 0.80 and precision ≥ 0.85 over task 002's `adversarialCorpus` alone (floor from the task-014 Phase A baseline, 26/32 = 0.8125 recall, 26/30 = 0.867 precision).
- `backendThresholds` map plus `Detector` type-name keying is the mechanism task 002's TC-006 built precisely so a stronger backend, or here a wider corpus, raises the bar without rewriting existing fixtures. This task reuses that mechanism rather than reinventing it.

## Hard constraints (non-negotiable)

- **Task 002's `adversarialCorpus` in `poisoning_suite_test.go` stays byte-for-byte unchanged.** No edits to that file at all. The imported/derived corpus lives in a new file, `owasp_benchmark_corpus_test.go`, as a separately-named variable (e.g. `owaspCorpus`), reusing the existing `poisoningSample` / `poisoningClass` types (same package, no new types needed for the shared shape).
- **No detector-behavior change.** `detector.go`, `guard.go`, `ipc.go`, and `docs/CONTRACT.md` are byte-for-byte untouched. If the new corpus reveals miss-classes the current detector does not catch, they are recorded honestly (see Requirements) and not fixed here. Recovering them is a separate, explicitly out-of-scope follow-on task (013/014-style).
- **`fitness_test.go` and `Makefile` are not touched by this task.** The enforced `make fitness-recall-precision` gate keeps measuring task 002's `adversarialCorpus` exactly as it does today (unaffected, still green). This task's combined-corpus measurement runs as its own `go test -run TestPoisoningOWASP...` target with its own threshold constants in the new file: a new, additional held-out regression check, not a change to what the existing blocking gate enforces. Wiring the combined corpus into `make fitness-recall-precision` itself is explicitly a candidate follow-on task, not part of this one.
- **Stdlib-only.** `go.mod` stays require-free. The corpus is Go literals baked into the test file, with no network fetch at test time (no `http.Get` of the OWASP repo during `go test`). If payloads are imported, they are copied into the source file with attribution, not pulled live.
- License: OWASP Agent Memory Guard is Apache-2.0. Any imported content carries an attribution header in the new file (project name, URL, license, date accessed, imported-vs-derived statement per case set).

## Readiness-gate blocker: confirm before starting

This task is not startable until the following is resolved.

- [ ] **OWASP AMG's raw payload set is confirmed obtainable**: the actual labelled cases (content, poisoning/benign label, class), not merely the aggregate headline numbers (~55 payloads, 92.5% recall, 100% precision). Check the project repo (`github.com/OWASP/www-project-agent-memory-guard`) and the `agent-memory-guard` package's own test/eval fixtures for a checked-in benchmark file.
  - **If obtainable:** import the real payloads (translated into `poisoningSample` literals, each tagged `imported` in its note, with a per-case citation of the source file/commit if the upstream repo has stable references).
  - **If not obtainable** (only the aggregate 92.5%/100% figures are published, for example in a README, blog post, or conference talk, with no raw corpus checked in anywhere): fall back to hand-deriving a representative fixture set from the documented threat-class taxonomy in [`docs/comparison-owasp-agent-memory-guard.md`](../../comparison-owasp-agent-memory-guard.md): self-reinforcement/repetition-bias, size/length-anomaly, source-class spoofing, and protected/immutable-key bypass. Each case is clearly labeled `derived` (not `imported`) in its note field, with a rationale comment explaining it approximates the class rather than reproduces a specific upstream payload. This is the expected path unless the executor finds a genuine raw corpus.
- [ ] Whichever path is taken, the provenance decision is recorded (a doc comment at the top of `owasp_benchmark_corpus_test.go` stating which path was taken and why). This is REQ-001 below, not an optional nicety.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | The corpus's provenance is explicit and machine-checkable: a package-level constant or doc-comment in the new file states whether the corpus is `imported` (from a confirmed raw OWASP payload set, with source citation) or `derived` (hand-built from the documented threat-class taxonomy, per the readiness-gate fallback), and every individual case's note carries the same `imported:`/`derived:` prefix. A corpus that mixes provenance without per-case labeling is not acceptable. | must have |
| REQ-002 | A new, separately-named fixture set (`owaspCorpus` in `owasp_benchmark_corpus_test.go`) is added, reusing `poisoningSample`/`poisoningClass`, covering the OWASP-distinctive classes not in task 002's taxonomy: self-reinforcement/repetition-bias, size/length-anomaly, source-class spoofing, protected/immutable-key bypass, plus a benign counterpart set including hard-benign look-alikes. Target at least 40 poisoning cases (aiming toward OWASP's reported ~55) and at least 15 benign. The file carries an Apache-2.0 attribution header naming the OWASP Agent Memory Guard project and URL. | must have |
| REQ-003 | Task 002's `adversarialCorpus` and `poisoning_suite_test.go` are byte-for-byte unchanged, verified by `git diff` on that path showing zero changes. | must have |
| REQ-004 | A combined-corpus harness (task 002's `adversarialCorpus` plus the new `owaspCorpus`, concatenated without mutating either) runs every case through `ValidateWrite` for both `RegexDetector` and `NativeDetector`, computes recall and precision, and asserts them against a new threshold map (e.g. `owaspBackendThresholds`, keyed by Detector type-name, the same mechanism as task 002's `backendThresholds`). Every case the gate rejects is asserted fail-closed per-case (`allow:false`, `stored_id:null`, no store entry for that content): the same per-case invariant task 002's TC-003 established, applied to the OWASP-derived cases. | must have |
| REQ-005 | `docs/spec/fitness-functions.md` F-006 is rewritten in place (not appended) to record the new honest combined-corpus baseline as an additional held-out measurement alongside the existing enforced task-002-only floor: the new number, the honest-floor convention (10 to 30 percentage points below measured), and an explicit statement that the existing enforced `make fitness-recall-precision` floor is unchanged by this task (it still measures task 002's corpus only). The combined-corpus number is recorded for visibility, not silently substituted as the enforced gate. The existing floor value is never lowered. | must have |
| REQ-006 | Any case in `owaspCorpus` that the write-gate does not catch (a genuine miss on the new corpus) is recorded honestly with a `MISS:` note (matching task 002's convention) and surfaced in the F-006 update as a documented gap: explicitly not fixed in this task, and explicitly not used to justify lowering any threshold below what is actually measured. A future detector task may pick these up (013/014-style), out of scope here. | must have |
| REQ-007 | The new suite is `go.mod`-require-free (stdlib literals only, no network fetch at test time), deterministic across `-count=3` (no map-ordering flakiness, the same sorted-output discipline as `poisoning_suite_test.go`), and touches no file outside `{owasp_benchmark_corpus_test.go, docs/spec/fitness-functions.md}`. `detector.go`/`guard.go`/`ipc.go`/`docs/CONTRACT.md`/`fitness_test.go`/`Makefile` are all byte-for-byte unchanged. | must have |

## Readiness gate

- [ ] Test spec `023-owasp-benchmark-corpus-import-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Readiness-gate blocker above resolved: obtainability of OWASP AMG's raw payload set confirmed one way or the other, and the corresponding provenance path (`imported` or `derived`) decided before any fixture is written
- [ ] Task 002's `adversarialCorpus` confirmed as the unmodified continuity baseline (it is, `poisoning_suite_test.go`)
- [ ] F-006's current enforced floor confirmed: recall ≥ 0.80, precision ≥ 0.85 over the task-002-only corpus (`docs/spec/fitness-functions.md`, task 014 Phase A baseline)
- [ ] Verification plan below filled in before any code (per `AGENTS.md` "Always")

## Acceptance criteria

- [ ] [REQ-001] Provenance (`imported`/`derived`) is explicit at the file level and per-case; no unlabeled mixed-provenance case exists (TC-001).
- [ ] [REQ-002] `owaspCorpus` exists in `owasp_benchmark_corpus_test.go` with at least 40 poisoning cases across the 4 OWASP-distinctive classes plus at least 15 benign (incl. hard-benign), Apache-2.0 attribution header present (TC-002).
- [ ] [REQ-003] `git diff -- poisoning_suite_test.go` against the pre-task tree is empty (TC-003).
- [ ] [REQ-004] Combined-corpus recall/precision computed and asserted per backend via a new, independent threshold map; every rejected case is fail-closed-asserted per-case (TC-004, TC-005).
- [ ] [REQ-005] F-006 rewritten in place with the new combined baseline, honest-floor convention restated, and an explicit note that the existing enforced floor is unchanged by this task (TC-006).
- [ ] [REQ-006] Every OWASP-corpus miss is `MISS:`-noted and shows up in the F-006 update as a documented, not silently absorbed, gap (TC-007).
- [ ] [REQ-007] `go.mod` require-free; no network fetch in the test; deterministic across `-count=3`; only `owasp_benchmark_corpus_test.go` and `docs/spec/fitness-functions.md` differ from `main` (TC-008).
- [ ] `go build ./... && go test ./...` green; task 002's suite, PII corpus floors, v0/v1 suites, and `make fitness` (unchanged scope) all stay green.

## Verification plan

- **Highest level achievable:** L5. The new combined-corpus suite is the validation harness: `go test -run TestPoisoningOWASP -count=3 ./...` runs the write-gate over `adversarialCorpus` plus `owaspCorpus` and the final summary line reports recall/precision per backend against the new threshold map, deterministic across `-count=3`. This is the recorded evidence that earns ✅. No L6 is needed: this is a test-harness/fixtures task with no new runtime-observable behavior (it mirrors task 002's own verification plan, which also stopped at L5 for the same reason).
- **Level 2, unit:** `go build ./... && go test -count=1 ./...` → `ok`, including the provenance assertion (TC-001), the corpus-existence/class-coverage assertion (TC-002), the per-case fail-closed assertion on the OWASP subset (TC-005), and the require-free / no-touch-outside-scope checks (TC-008).
- **Level 3, fitness gate (unaffected):** `make fitness` → `All fitness checks passed.` Unchanged in scope by this task (F-006's enforced check still runs over task 002's corpus only, per the hard constraint); confirms no regression was introduced elsewhere.
- **Level 5, harness:** the combined-corpus summary line (recall, precision, fail-closed count, miss list) is the recorded evidence; record the new numbers in `docs/spec/fitness-functions.md` F-006 (rewritten in place, existing enforced floor untouched) and cross-reference from `docs/comparison-owasp-agent-memory-guard.md` if that file needs a pointer to the new fixture (optional, not required for ✅).
</content>
