# Test Spec 007: Presidio-backed `Detector` (un-defer ADR-002's Presidio path)

**Linked task:** [`docs/tasks/backlog/007-presidio-detector-backend.md`](../backlog/007-presidio-detector-backend.md)
**Written:** 2026-06-24

> Authored ahead of execution. The seam-isolation (TC-006), seam-swap (TC-007), and interface-parity
> (TC-001) cases are **unit-verifiable locally** against the unchanged `Detector` interface. The
> **recall-lift** bar (TC-002) runs against task 002's **unchanged** `adversarialCorpus` and asserts
> **recall > 0.69**. The **latency** re-validation (TC-003) and the **dep-scan/code-scanner** gate
> (TC-005) depend on the real Presidio backend being wired (sidecar or ONNX); the ADR-decision (TC-004)
> is a doc check. The corpus must **not** be modified — a stronger backend raises its `backendThresholds`
> entry, not the corpus (task 002's TC-006 contract).

## Requirements coverage

| Req ID | Test cases | Locally verifiable? | Covered? |
|--------|-----------|---------------------|----------|
| REQ-001 | TC-001 | ✅ | ✅ |
| REQ-002 | TC-002 | ✅ (needs Presidio backend wired; corpus unchanged) | ✅ |
| REQ-003 | TC-003 | ⚠️ needs Presidio backend wired (L6 latency) | ✅ |
| REQ-004 | TC-004 | ✅ (doc check) | ✅ |
| REQ-005 | TC-005 | ⚠️ needs the first dependency added (dep-scan/code-scanner) | ✅ |
| REQ-006 | TC-006 | ✅ (grep guard/ipc/contract clean of Presidio types) | ✅ |
| REQ-007 | TC-007 | ✅ | ✅ |

## Pre-implementation checklist

- [ ] All test cases below are defined
- [ ] Expected inputs and outputs are specified for each case
- [ ] Edge cases and error paths are covered
- [ ] Every REQ-ID from the task has at least one test case
- [ ] Task 002's `adversarialCorpus` is used **unchanged** as the recall-lift bar
- [ ] The v0/v1 detector tests (`TestNativeDetectorHotPathLatency`, parity tests) remain green

## Test fixtures

- **Unchanged poisoning corpus** — task 002's `adversarialCorpus` in `poisoning_suite_test.go`
  (32 poisoning / 14 benign, three classes: MINJA / GRAGPoison / context-window-injection, plus
  hard-benign). Used **as-is** — the recall lift is proven on the same held-out cases the 0.69 baseline
  was measured on, including the 10 documented miss-classes the regex backend missed.
- **Presidio backend handle** — the new Presidio-backed `Detector` (sidecar or ONNX, per the ADR),
  constructed via the config-driven selection path; for unit cases it may run against a pinned local
  Presidio sidecar / loaded ONNX model, or skip-with-reason if the backend is unavailable in the CI
  environment (recorded, not silently passed).
- **PII probe inputs** — representative PII-bearing strings (`"contact alice@example.com ssn 123-45-6789"`,
  a name/DOB/phone case) for redaction + latency measurement, mirroring `TestNativeDetectorHotPathLatency`.

## Test cases

### TC-001: Presidio backend satisfies the unchanged `Detector` interface; guard/IPC/contract untouched
- **Requirement:** REQ-001
- **Input:** construct the Presidio-backed `Detector`; assign it to a `var d Detector`; call
  `RedactPII` and `DetectInjection` through the interface.
- **Expected:** it compiles and satisfies `Detector` with **no** signature change; `RedactPII` returns
  `<LABEL>`-redacted text + `pii:<LABEL>` flags, `DetectInjection` returns `["injection_suspected"]` or
  `nil`. `MemoryGuard`, `ipc.go`, and `docs/CONTRACT.md` are **byte-for-byte unchanged** by this task
  (diff check).
- **Edge cases:** empty input → no redaction, no flags, no panic; backend-unavailable → a fail-closed
  error surfaced as the stable `{error:{code,message,retryable}}` shape, never a Presidio-typed error.

### TC-002: recall lifts above the 0.69 / 0.85 regex baseline on the unchanged corpus
- **Requirement:** REQ-002
- **Input:** run task 002's **unchanged** `adversarialCorpus` (32 poisoning / 14 benign) through the
  write-gate backed by the Presidio `Detector`; compute recall (poisoning rejected / total poisoning)
  and precision (true poisoning / all rejected) exactly as the existing harness does.
- **Expected:** **recall strictly `> 0.69`** (a real lift over the regex/Go-native baseline), asserted
  via a Presidio entry in `backendThresholds` whose `recall` floor is set above 0.69; **precision** at
  or above the baseline floor (no precision regression to buy recall). The corpus is **not** modified —
  the lift is measured on the same cases, including the 10 documented misses.
- **Edge cases:** if the backend recovers some-but-not-all of the 10 documented miss-classes, the
  measured recall is recorded per class; the floor is set from the **honest measured** value (10–30 pp
  guard below measured, per the suite's convention), never aspirationally. A precision drop below the
  baseline floor **fails** this case — recall must not be bought with false positives.

### TC-003: `< 1 ms` per-op hot-path latency re-validated with Presidio wired
- **Requirement:** REQ-003
- **Input:** with the Presidio backend selected, measure detection cost (`RedactPII` + `DetectInjection`)
  per `validate_*` op on a representative PII-bearing input, averaged over many iterations
  (mirroring `TestNativeDetectorHotPathLatency`).
- **Expected:** measured per-op detection cost **`< 1 ms`** (the ADR-002 budget), asserted in a
  Presidio latency test. The measured figure is recorded in the new ADR. If a naive sidecar round-trip
  exceeds the budget, the ADR records the mitigation (warm process / batching / ONNX in-process) **or**
  a revised budget with explicit rationale — a silently-blown budget **fails** this case.
- **Edge cases:** sidecar cold-start / first-call warmup is excluded from the steady-state measurement
  but **noted** in the ADR (it is a real operational cost the deployment-shape decision must own).

### TC-004: sidecar-vs-ONNX decided and recorded in a new ADR referencing ADR-002
- **Requirement:** REQ-004
- **Input:** inspect `docs/architecture/decisions/` for the new ADR produced by this task.
- **Expected:** a new ADR exists that (a) **decides** sidecar/subprocess vs. ONNX-in-process, (b)
  weighs it against the single-binary / hot-path-latency / minimal-dependency-surface invariants, (c)
  **references ADR-002** as the deferral this task acts on (un-defers, does **not** supersede), and (d)
  records the measured latency (TC-003) and pinned dependency versions (TC-005).
- **Edge cases:** the ADR must not claim the deferral is "foreclosed" in the other direction — the
  unchosen path (sidecar or ONNX) stays a documented future option behind the seam.

### TC-005: dep-scan + code-scanner clear the first dependency; versions pinned
- **Requirement:** REQ-005
- **Input:** run `gods` (dep-scan) **and** `code-scanner` on the new module tree (Presidio SDK / ONNX
  runtime + recognizer model) once it is added to `go.mod`.
- **Expected:** both **pass, exit 0**, with the dependency **version-pinned** (`go.mod` + `go.sum`
  pinned; model blob checksummed); the pinned versions are recorded in the new ADR **and**
  `docs/spec/configuration.md`. This gate is **blocking** — it must pass before the dependency merges.
  This is the repo's **first** `require` block, so the prior "trivially clears (nothing added)" note no
  longer applies.
- **Edge cases:** a flagged transitive module (CVE / malware finding) **blocks** that backend path —
  fall back to the other deployment shape (sidecar↔ONNX) or a pinned-and-patched version, and record
  the decision in the ADR. No `--allow`/override without an explicit, justified suppression.

### TC-006: RegexDetector/NativeDetector still selectable, config-driven; no Presidio leak past the seam
- **Requirement:** REQ-006
- **Input:** (a) select each of `RegexDetector`, `NativeDetector`, and the Presidio backend via the
  config-driven construction path; (b) grep `guard.go`, `ipc.go`, and `docs/CONTRACT.md` for any
  Presidio/ONNX type, import, or symbol.
- **Expected:** (a) all three backends construct and run behind the seam, selected by config — the
  prior backends are **not** removed or made unselectable; (b) the grep is **clean** — **zero**
  Presidio/ONNX-specific types or imports appear in `guard.go`, `ipc.go`, or `docs/CONTRACT.md`. All
  backend specifics live **only** behind `detector.go`'s `Detector` seam.
- **Edge cases:** an unknown/invalid backend name in config → a clear construction error (fail-closed),
  not a silent fallback that hides a misconfiguration; the error is generic, not Presidio-typed.

### TC-007: Presidio backend swaps in/out behind the seam with no caller change
- **Requirement:** REQ-007
- **Input:** construct `MemoryGuard` with `NewRegexDetector()`, then with `NewNativeDetector()`, then
  with the Presidio backend — same `MemoryGuard` / IPC call sites, no contract change — and exercise
  `validate_write` / `validate_read` / `verify_delete` through each.
- **Expected:** every backend drops in behind the unchanged seam with **no** change to `guard.go`,
  `ipc.go`, or the contract; the write-gate stays fail-closed, PII stays redacted before storage and on
  read across all three. This is the seam proof — the same property task 001's TC-006 established,
  extended to the Presidio backend.
- **Edge cases:** swapping mid-process (two guards, two backends, one corpus) yields each backend's own
  measured recall/precision — no shared mutable state leaks between detector instances.
