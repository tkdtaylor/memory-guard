# Test Spec 023: Import the OWASP Agent Memory Guard benchmark corpus as held-out regression fixtures

**Linked task:** [`docs/tasks/backlog/023-owasp-benchmark-corpus-import.md`](../backlog/023-owasp-benchmark-corpus-import.md)
**Written:** 2026-07-14

> Authored ahead of execution. The whole task is fixtures plus a measurement harness, so it is fully locally verifiable via `go test`, the same shape as [002's test spec](002-adversarial-poisoning-suite-test-spec.md). The corpus content depends on the readiness-gate blocker in the task file (`imported` vs `derived` path); the test cases below hold under either path since they assert on provenance labeling and measured numbers, not on specific case text.

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | Yes | Yes |
| REQ-002 | TC-002 | Yes | Yes |
| REQ-003 | TC-003 | Yes | Yes |
| REQ-004 | TC-004, TC-005 | Yes | Yes |
| REQ-005 | TC-006 | Yes | Yes |
| REQ-006 | TC-007 | Yes | Yes |
| REQ-007 | TC-008 | Yes | Yes |

## Pre-implementation checklist

- [ ] The readiness-gate blocker in the task file is resolved before any fixture is written (obtainability of the raw OWASP payload set confirmed, provenance path decided)
- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] No test case depends on the exact wording of an `imported` vs `derived` case; assertions target structure (labels, classes, counts, provenance tags) and measured behavior, not literal case text

## Test fixtures

- **`owaspCorpus`** (new, in `owasp_benchmark_corpus_test.go`): a `[]poisoningSample` (reusing task 002's type) covering four OWASP-distinctive classes not represented in task 002's `adversarialCorpus`:
  - `classSelfReinforcement`: repeated/reinforcing instruction fragments designed to bias agent behavior cumulatively across multiple writes (e.g. a case that alone looks benign but is one of a repeated series).
  - `classSizeAnomaly`: abnormally large single writes designed to bury a directive in padding, or a payload sized to dominate/crowd out other memory.
  - `classSourceSpoofing`: tool-output-shaped content that claims a trusted origin (e.g. `"[VERIFIED SYSTEM SOURCE]"`, `"origin: internal-admin-tool"`) without matching the existing MINJA/GRAGPoison framing markers.
  - `classProtectedKeyBypass`: writes that attempt to name or overwrite a reserved/protected/immutable key (e.g. `"key: system.policy.locked, value: ..."`). Memory-guard has no protected-key concept today, so these are expected genuine misses unless coincidentally caught by the existing injection regex.
  - Each poisoning case's `note` field is prefixed `imported:` or `derived:` per the task's provenance decision, plus (for `derived` cases) a one-line rationale.
  - A benign counterpart set, including hard-benign look-alikes per class (e.g. a legitimate size-heavy log dump; a legitimate `"source: verified-partner-api"` tag; a legitimate settings write that happens to touch a key named `policy_locked_reason` without attempting to overwrite protection).
- **`adversarialCorpus`** (existing, untouched): task 002's 32 poisoning / 14 benign corpus in `poisoning_suite_test.go`, used only as a read-only input to the combined-corpus measurement, never modified.
- **Pre-task snapshot**: a `git diff` baseline captured before any edit, used by TC-003 and TC-008 to assert on the exact set of changed files.

## Test cases

### TC-001: corpus provenance is explicit and machine-checkable
- **Requirement:** REQ-001
- **Input:** inspect the package-level provenance constant/doc-comment in `owasp_benchmark_corpus_test.go`, and every `note` field across `owaspCorpus`.
- **Expected:** the file-level constant/comment states `imported` or `derived` (exactly one, matching the readiness-gate decision recorded in the task); every case's `note` field starts with the matching `imported:` or `derived:` prefix (a Go test iterates `owaspCorpus` and fails on any case whose note lacks that prefix, or whose prefix disagrees with the file-level declaration).
- **Edge cases:** a corpus that mixes `imported:` and `derived:` notes without the file-level constant reflecting "mixed" explicitly fails; an empty note fails.

### TC-002: `owaspCorpus` exists with the required class coverage and license header
- **Requirement:** REQ-002
- **Input:** load `owaspCorpus`; inspect the top-of-file header comment.
- **Expected:** at least 40 poisoning cases total, with at least 6 cases in each of the 4 new classes (`classSelfReinforcement`, `classSizeAnomaly`, `classSourceSpoofing`, `classProtectedKeyBypass`); at least 15 benign cases including at least 3 hard-benign look-alikes; the file header names "OWASP Agent Memory Guard", its URL, and "Apache-2.0".
- **Edge cases:** a class with zero cases fails the minimum-per-class check; a header missing the license string fails.

### TC-003: task 002's corpus and file are byte-for-byte unchanged
- **Requirement:** REQ-003
- **Input:** `git diff -- poisoning_suite_test.go` run against the commit that starts the task.
- **Expected:** empty diff. No test-level Go assertion is required for this (it is a file-identity check); the executor records the `git diff` output (or its absence) as the evidence, and the reviewer/spec-verifier re-runs it independently.
- **Edge cases:** a whitespace-only change to `poisoning_suite_test.go` still fails this check; the check is byte-identity, not semantic-identity.

### TC-004: combined-corpus recall and precision computed and asserted per backend
- **Requirement:** REQ-004
- **Input:** concatenate `adversarialCorpus` and `owaspCorpus` (without mutating either); run every case through `ValidateWrite` for `RegexDetector` and `NativeDetector`.
- **Expected:** recall = (poisoning cases rejected) / (total poisoning cases across both corpora); precision = (true-poisoning rejections) / (all rejections); both are computed and logged per backend, and asserted against a new `owaspBackendThresholds` map (or equivalently named) keyed by `fmt.Sprintf("%T", det)`, mirroring `thresholdsFor` in `poisoning_suite_test.go`. A backend missing from the map falls back to a conservative default (mirrors `defaultThresholds`) rather than passing by default.
- **Edge cases:** if recall or precision on the combined set is below the new threshold, the test fails with a `measured X vs threshold Y` style message (same convention as `fitness_test.go`'s breach output); a backend that regresses recall on the OWASP subset alone (even if the combined number still clears threshold) is logged, not silently absorbed.

### TC-005: fail-closed holds per-case on the OWASP subset
- **Requirement:** REQ-004
- **Input:** for every `owaspCorpus` poisoning case the gate rejects, inspect the result and the store (same probe-key technique as task 002's `TestPoisoningFailClosedPerCase`).
- **Expected:** `allow:false`, `stored_id:nil`, and no store entry is retrievable for that content, for every rejected case, under both backends.
- **Edge cases:** a `classProtectedKeyBypass` case that also resembles benign settings text (a case designed to be borderline) is still checked: if rejected, it must be fully absent from the store; if not rejected, it is logged as a REQ-006 miss, not treated as a TC-005 failure (TC-005 only binds the invariant for cases the gate did reject).

### TC-006: F-006 rewritten in place with the new combined baseline
- **Requirement:** REQ-005
- **Input:** inspect `docs/spec/fitness-functions.md` after the change.
- **Expected:** the F-006 row (or its accompanying prose) records the new combined-corpus recall/precision numbers as measured, states the honest-floor convention (10 to 30 percentage points below measured) applied to any new threshold constant introduced in `owasp_benchmark_corpus_test.go`, and explicitly states that the existing enforced `make fitness-recall-precision` floor (recall ≥ 0.80, precision ≥ 0.85 over task 002's corpus alone) is unchanged by this task. The pre-existing floor values are present unchanged (not lowered).
- **Edge cases:** this is verified by inspection, not a Go test; the reviewer confirms the row was rewritten in place (not appended as a duplicate row) and that the old floor value still appears, unlowered, in the enforced-check description.

### TC-007: OWASP-corpus misses are recorded honestly, not silently absorbed
- **Requirement:** REQ-006
- **Input:** run the combined-corpus suite; collect every `owaspCorpus` poisoning case where `allow:true` (a miss).
- **Expected:** every miss has a `MISS:`-prefixed note (or equivalent) logged via `t.Logf`, matching task 002's convention (`TestPoisoningRecallPrecision`'s `RECALL MISS` logging); the set of missed classes is reflected in the F-006 update from TC-006 as a documented gap (e.g. "protected-key bypass is a known miss, no protected-key concept exists today"). The threshold asserted in TC-004 is set at or below the actually-measured recall, never above it, so a genuine miss cannot be papered over by an inflated threshold.
- **Edge cases:** if the detector happens to catch a `classProtectedKeyBypass` case incidentally (e.g. it also matches an existing `<instructions>` pattern), that is a genuine catch, not a miss, and is not required to be flagged; the test only requires misses (not catches) to be noted.

### TC-008: stdlib-only, deterministic, and scoped to the two allowed files
- **Requirement:** REQ-007
- **Input:** `go.mod`/`go.sum` diff; `go test -run TestPoisoningOWASP -count=3 ./...` run twice; `git diff --stat` against the pre-task commit.
- **Expected:** `go.mod` has no new `require` line (still require-free); the combined-corpus summary line is byte-identical across the two `-count=3` runs (no map-ordering flakiness, matching `TestPoisoningCorpusSummary`'s sorted-class-key discipline); `git diff --stat` shows only `owasp_benchmark_corpus_test.go` (new file) and `docs/spec/fitness-functions.md` as changed, with `detector.go`, `guard.go`, `ipc.go`, `docs/CONTRACT.md`, `fitness_test.go`, and `Makefile` absent from the diff.
- **Edge cases:** a test that fetches anything over the network (even a cached OWASP repo clone) at `go test` time fails this check; the corpus must be literal Go data checked into the file, not fetched at test time.
</content>
