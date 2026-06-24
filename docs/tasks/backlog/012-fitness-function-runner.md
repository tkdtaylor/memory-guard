# Task 012: Fitness-function runner wired as a gate

**Project:** memory-guard
**Created:** 2026-06-24
**Status:** backlog

> The fitness functions in [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md) are
> **declared but not enforced** — F-001…F-005 are `proposed` and only F-006 has a runnable check.
> AGENTS.md says there is "no `make check` / `make fitness` target yet — `go build ./... && go test
> ./...` is the verification gate today." That makes the **L3 `make fitness` rung of the verification
> ladder unreachable**. This task builds the runner that closes that gap, turning the spec's invariants
> into executable gates that exit non-zero on breach.

## Goal

Promote the fitness functions from a declarative spec into **executable, independently-runnable gates**
behind a `make check` / `make fitness` target (neither exists today; the Makefile is build/test/fmt/clean
only). The runner enforces at least three classes of invariant — the **per-op hot-path latency budget**,
a **recall/precision floor** for the poisoning suite and the PII corpus, and a **seam-isolation check** —
each exiting non-zero with a measured-vs-threshold delta on breach so it can wire into CI and flip the
L3 rung of the verification ladder from unreachable to green. The matching `docs/spec/fitness-functions.md`
rows flip from `proposed` to `active`/enforced in the same commit.

## Context

- Source: roadmap [T7](../../plans/roadmap.md) ("Fitness-function runner wired as a gate"), and the
  **Status** + **Rules considered but rejected** sections of [`docs/spec/fitness-functions.md`](../../spec/fitness-functions.md).
- **Today:** `Makefile` has `build` / `test` / `fmt` / `clean` and no umbrella fitness target. F-006 is
  the only `active` rule, run directly via `go test -run TestPoisoning ./...` (not the `make
  fitness-<rule>` form the rows document). F-001…F-005 are `proposed`, each backed by an existing unit
  test (F-004 is a structural grep with no unit test).
- **Baselines this runner must lock in** (so a backend swap can't silently regress below them):
  - **Latency budget** — `< 1 ms` detection cost per `validate_*` op; measured **~5.6 µs** today
    (ADR-002). The runner asserts the budget, not the current measurement.
  - **Write-gate poisoning floor** — recall **0.69** / precision **0.85** measured 2026-06-19 over
    32 poisoning / 14 benign cases; F-006 enforces a conservative `≥ 0.55` floor today. This runner
    surfaces the **documented baselines** as the floor (to rise with task 007).
  - **PII corpus floor** — recall/precision **1.00** over 9 categories (task 004).
  - **Seam isolation** — no detector/store backend specifics in `guard.go` / `ipc.go` / `main.go` /
    `CONTRACT.md` (F-004).
- **No new dependency** — the runner is Go stdlib + shell/grep + `go test`, consistent with the
  stdlib-only v0. It must **not** introduce a benchmark/assertion framework dependency.
- The runner **wraps existing checks where they exist** (F-006's poisoning suite, the PII corpus tests)
  rather than duplicating their corpora — it orchestrates and thresholds, it does not re-author the data.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-001 | A `make fitness` (and `make check`) target exists and runs **all** enforced fitness functions; it exits non-zero if any `block`-severity function breaches. | must have |
| REQ-002 | Each fitness function is **independently runnable** (a `make fitness-<rule>` target or an equivalent single-rule invocation) so one rule can be exercised in isolation. | must have |
| REQ-003 | **Latency budget** function: measures per-op detection cost on the `validate_*` hot path and **fails non-zero** if it exceeds the `< 1 ms` budget, printing the measured-vs-threshold delta. | must have |
| REQ-004 | **Recall/precision floor** function: runs the write-gate poisoning suite and the PII corpus and **fails non-zero** if recall or precision drops below the documented baseline floors, printing measured-vs-threshold per backend. | must have |
| REQ-005 | **Seam-isolation** function: greps `guard.go` / `ipc.go` / `main.go` / `CONTRACT.md` for detector/store backend specifics and **fails non-zero** with the offending file:line if any leak past the `Detector` seam. | must have |
| REQ-006 | Every breach **fails loudly**: a non-zero exit **and** a one-line `measured X vs threshold Y` message naming the rule — not a silent pass or a bare panic. | must have |
| REQ-007 | The matching `docs/spec/fitness-functions.md` rows (latency, recall/precision, seam-isolation) flip from `proposed` to `active`/enforced in the **same commit**, with their real check command replacing the `(TODO)` placeholder. | must have |
| REQ-008 | The runner adds **no third-party dependency** (stdlib + shell + `go test` only); `go.mod` stays `require`-free. | must have |

## Readiness gate

- [x] Test spec `012-fitness-function-runner-test-spec.md` exists in `docs/tasks/test-specs/`
- [ ] Decide the runner shape (Makefile recipes calling `go test`-tagged checks + a grep script, vs. a
      small `cmd/fitness` Go entrypoint) — keep it stdlib-only and document the choice in the task PR
- [ ] Confirm the documented baseline floors to encode (latency `< 1 ms`; poisoning recall 0.69 /
      precision 0.85; PII 1.00) against the current spec before locking thresholds

## Acceptance criteria

- [ ] [REQ-001] `make fitness` and `make check` run all enforced functions; non-zero on any block breach (TC-001).
- [ ] [REQ-002] Each function runs independently via its own target/invocation (TC-002).
- [ ] [REQ-003] Latency function passes on the current tree and fails on a synthetic over-budget op,
      printing the delta (TC-003).
- [ ] [REQ-004] Recall/precision function passes at the current baselines and fails on a seeded
      below-floor regression, printing measured-vs-threshold per backend (TC-004).
- [ ] [REQ-005] Seam-isolation function passes on the current tree and fails on a seeded backend leak,
      naming the file:line (TC-005).
- [ ] [REQ-006] Each breach exits non-zero with a `measured vs threshold` message (TC-006).
- [ ] [REQ-007] `docs/spec/fitness-functions.md` rows flip `proposed` → `active` with real check
      commands, same commit (TC-007).
- [ ] [REQ-008] No new dependency; `go.mod` stays `require`-free (TC-008).
- [ ] `go build ./... && go test ./...` green; `make fitness` green on the current tree.

## Verification plan

- **Highest level achievable:** **L3** — the runner *is* the `make fitness` gate; running it on the
  current tree (all functions green) and on each synthetic breach (each function red, non-zero) is the
  L3 evidence. The runner itself is unit-and-gate verifiable end to end.
- **Level 2 — unit:** `go test ./...` → `ok`, including any helper that the synthetic-breach cases
  drive (the over-budget op, the seeded below-floor corpus, the seeded seam leak).
- **Level 3 — gate:** `make fitness` exits 0 on the current tree; each `make fitness-<rule>` exits 0;
  each synthetic-breach fixture makes its rule exit non-zero with the measured-vs-threshold delta quoted.
  Record the quoted output in the verify commit.
- **Level 4 (out of scope, note only):** wiring `make fitness` into CI is **L4** and belongs to a
  follow-on CI task — this task makes the rung *reachable*, it does not claim the CI run.
