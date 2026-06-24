# Test Spec 012: Fitness-function runner wired as a gate

**Linked task:** [`docs/tasks/backlog/012-fitness-function-runner.md`](../backlog/012-fitness-function-runner.md)
**Written:** 2026-06-24

> Authored ahead of execution. Every case asserts a **real pass/fail**, not just "the target runs":
> each fitness function must pass green on the current tree **and** go red (non-zero, with the
> measured-vs-threshold delta) when fed a synthetic breach. A target that always exits 0 fails this
> spec. The runner stays stdlib + shell + `go test` — no new dependency.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ | ✅ |
| REQ-003 | TC-003 | ✅ | ✅ |
| REQ-004 | TC-004 | ✅ | ✅ |
| REQ-005 | TC-005 | ✅ | ✅ |
| REQ-006 | TC-006 | ✅ | ✅ |
| REQ-007 | TC-007 | ✅ | ✅ |
| REQ-008 | TC-008 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Each synthetic-breach fixture is reverted/isolated so it never weakens the real tree

## Test fixtures

- **Over-budget latency op** — a synthetic `Detector` (or a wrapped `validate_*` call) that sleeps past
  the `< 1 ms` budget, used only to drive the breach path; never registered on the live path.
- **Below-floor corpus stub** — a labelled poisoning/PII run rigged to score under the documented floor
  (recall 0.69 / precision 0.85 for poisoning; 1.00 for PII), to prove the floor function goes red.
- **Seeded seam leak** — a temporary backend-specific token (e.g. a `presidio`/store-internal symbol)
  inserted into a copy of `guard.go` / `ipc.go` / `CONTRACT.md`, to prove the grep function goes red.

## Test cases

### TC-001: `make fitness` / `make check` run all functions and gate the build
- **Requirement:** REQ-001
- **Input:** `make fitness` (and `make check`) on the current tree; then with one block-severity
  function forced to breach.
- **Expected:** clean tree → all enforced functions run, exit **0**. With any block function breached →
  the umbrella target exits **non-zero** (the breach is not swallowed).
- **Edge cases:** a `warn`-severity function surfaces its message but does **not** flip the exit code;
  only `block` rules fail the umbrella.

### TC-002: each function is independently runnable
- **Requirement:** REQ-002
- **Input:** invoke each rule alone (`make fitness-latency`, `make fitness-recall-precision`,
  `make fitness-seam`, or the equivalent single-rule command).
- **Expected:** each runs in isolation and reports only its own rule's result + exit code — no
  dependency on the others having run first.
- **Edge cases:** an unknown `fitness-<rule>` name fails clearly rather than silently passing.

### TC-003: latency-budget function — passes now, fails over budget
- **Requirement:** REQ-003, REQ-006
- **Input:** (a) the current `validate_*` hot path; (b) the over-budget latency fixture.
- **Expected:** (a) measured per-op cost (~5.6 µs today) is `< 1 ms` → exit **0**; (b) the over-budget
  op breaches → exit **non-zero** with a `measured <X> vs threshold 1ms` line naming the latency rule.
- **Edge cases:** measurement is averaged over enough ops that GC/scheduler jitter doesn't false-fail
  the clean tree; the budget is the assertion, not the current number.

### TC-004: recall/precision floor — passes at baseline, fails below floor
- **Requirement:** REQ-004, REQ-006
- **Input:** (a) the live poisoning suite + PII corpus; (b) the below-floor corpus stub.
- **Expected:** (a) poisoning recall ≥ 0.69 / precision ≥ 0.85 and PII recall/precision = 1.00 → exit
  **0**, printing measured-vs-threshold **per backend** (RegexDetector / NativeDetector); (b) a seeded
  drop below any floor → exit **non-zero** with the offending metric's measured-vs-threshold delta.
- **Edge cases:** the floor is read from the documented baselines, so task 007 raising recall raises the
  floor without editing the corpus; a backend that scores *above* floor never false-fails.

### TC-005: seam-isolation function — passes clean, fails on a seeded leak
- **Requirement:** REQ-005, REQ-006
- **Input:** (a) the current `guard.go` / `ipc.go` / `main.go` / `CONTRACT.md`; (b) the same files with
  a seeded backend-specific token.
- **Expected:** (a) no backend specifics found → exit **0**; (b) the seeded leak → exit **non-zero**
  with the offending `file:line` and the matched token.
- **Edge cases:** the grep does not false-positive on the legitimate `Detector` interface name or on
  comments that *describe* the seam; it targets backend implementation symbols, not the seam itself.

### TC-006: every breach fails loudly with a measured-vs-threshold delta
- **Requirement:** REQ-006
- **Input:** trigger each of the three breach fixtures (TC-003b / TC-004b / TC-005b) in turn.
- **Expected:** each produces a **non-zero exit** *and* a single line of the form
  `FAIL <rule>: measured <X> vs threshold <Y>` (or `file:line` for the seam grep) — never a silent pass,
  a bare `exit 1` with no message, or an uncaught panic.
- **Edge cases:** a function that cannot run its check (e.g. corpus missing) reports an error and exits
  non-zero — it does **not** count a non-runnable check as a pass.

### TC-007: spec rows flip `proposed` → `active` in the same commit
- **Requirement:** REQ-007
- **Input:** inspect `docs/spec/fitness-functions.md` after the task.
- **Expected:** the latency, recall/precision, and seam-isolation rows read `active` (not `proposed`),
  each `Check command` column holds the **real** runnable command (no `(TODO)` placeholder), and the
  **Status** preamble no longer says the umbrella target is unwired. The flip lands in the same commit
  as the runner code.
- **Edge cases:** rows the runner does **not** yet enforce stay honestly `proposed` — no row is flipped
  to `active` without a backing check command.

### TC-008: no new dependency
- **Requirement:** REQ-008
- **Input:** `go.mod` after the task; the runner's invocation surface.
- **Expected:** `go.mod` has no `require` block (stdlib-only preserved); the runner uses only
  `make` / shell / `grep` / `go test` — no benchmark or assertion framework pulled in.
- **Edge cases:** if a check genuinely needs a tool not present, it is a shell builtin or already-listed
  command (e.g. `grep`), not a new Go module.
