# memory-guard

The agent **memory-I/O gate** for the secure-agent ecosystem (OWASP **ASI06** — Memory & Context
Poisoning). It sits in front of any agent memory store and answers a single question on every read
and write: *is this safe to store / return?* PII never lands in stored context unredacted; poisoned
writes are flagged and rejected at ingestion (the **write-gate**); and deletions are **verified** —
the industry blind-spot most memory stores skip. The one Python-leaning dependency (Microsoft
Presidio, for PII) is isolated behind the `Detector` seam so the substrate stays Go. memory-guard
coordinates with `audit-trail` (it emits detections as events) in the ecosystem; `validate_read` /
`validate_write` / `verify_delete` are its contract.

## Invariants

These are load-bearing — violating one breaks the security model, not just style:

- **The write-gate is fail-closed on suspected poisoning.** `validate_write` runs injection
  detection **before** storage; a write flagged `injection_suspected` is **rejected** (`allow:false`,
  `stored_id:null`) and never persists. The write-gate is the value-add, not the PII redaction.
  *(Enforced in `guard.go::ValidateWrite`; test `TestWriteGateRejectsSuspectedInjection`.)*
- **PII is redacted before it lands in the store.** `validate_write` redacts via the `Detector`
  before persisting; `validate_read` redacts again on the way out (defense in depth). The raw PII is
  never stored and never returned. *(Enforced in `guard.go::ValidateWrite` / `ValidateRead`; test
  `TestWriteRedactsPIIAndStores`.)*
- **Deletion is verified, not assumed.** `verify_delete` must **prove** the entry is gone, not just
  call `delete()`. v0 confirms absence from the in-memory store; v1 extends the proof to every
  index/copy (residue detection — the documented gap). *(Enforced in `guard.go::VerifyDelete`; test
  `TestVerifyDeleteConfirmsAbsence`.)*
- **The `Detector` seam isolates the detection backend.** PII + injection detection lives **only**
  behind the `Detector` interface (`detector.go`). No Presidio (or any backend) specific detail leaks
  past that seam into the guard, the contract, or the IPC. Swapping the v0 `RegexDetector` for a
  Presidio-backed detector must be a one-implementation change with **no contract, guard, or IPC
  impact**. *(Enforced by the `Detector` interface in `detector.go`.)*
- **Stable error shape.** IPC errors are `{error:{code,message,retryable}}` (`ipc.go::errShape`).
- **Single static binary, low per-call overhead.** memory-guard is Go because it gates *every*
  memory op — per-call latency on the hot path matters, and the value-add (write-gate +
  delete-verification) is orchestration, not NLP. *(Enforced by the language / single-binary layout.)*

## Contract (v0 shape — not yet tracer-validated)

```
validate_read(query, identity)  -> { allow, content_redacted, flags }
validate_write(entry, identity) -> { allow, stored_id, flags }    # write-gate: fail-closed on poisoning
verify_delete(id)               -> { confirmed }                  # post-deletion verification (the industry gap)
```

Mirrors `interface-contracts.md §2` and the scoping doc
`memory-guard.md`. memory-guard was **out of the first tracer-bullet's
scope** (the slice is stateless, tracer-bullet.md §6) — its contract gets **its own tracer** once
memory is in play, which may refine these shapes. This v0 is a skeleton against the v0 contract
shape, not yet tracer-validated. The full as-built record is
[ADR-001](docs/architecture/decisions/001-foundational-stack.md).

## Resolved — the `Detector` backend (memory-guard tracer, [ADR-002](docs/architecture/decisions/002-detector-backend.md))

The **`Detector` backend** decision is **resolved (see [ADR-002](docs/architecture/decisions/002-detector-backend.md))**:
a **Go-native, in-process** backend (`NativeDetector` in `detector.go`), **zero new third-party
dependencies** (stays inside the Go stdlib — the v0 stdlib-only property holds), measured **~5.6 µs
detection cost per `validate_*` op** (the budget is `< 1 ms`). Presidio-as-sidecar and
Presidio-via-ONNX are **deferred, not foreclosed** — they still slot in additively behind the unchanged
`Detector` seam if a future requirement demands Presidio-grade NER recall. Keep everything backend-
specific behind the `Detector` seam, exactly as before: the seam is what made this choice cheap to make
and keeps it cheap to revisit. The remaining open tracer items (the adversarial-poisoning test-suite and
the v1 residue-detection method) are tracked as their own tasks/ADRs.

## Project structure

```
detector.go    ← the Detector seam: PII + injection detection; v0 RegexDetector (Presidio stand-in)
guard.go       ← MemoryGuard core: ValidateWrite (write-gate) / ValidateRead / VerifyDelete + the in-memory store
ipc.go         ← JSON-over-Unix-socket IPC server (validate_write / validate_read / verify_delete / ping); error shape
main.go        ← CLI entrypoint: serve / write / read subcommands
guard_test.go  ← unit tests for the write-gate, PII redaction, delete-verification, and the detector
go.mod         ← module github.com/tkdtaylor/memory-guard (go 1.26)
Makefile       ← build / test / fmt / clean
docs/          ← spec + planning + history (the source-of-truth side)
  spec/           authoritative current-state snapshot — SPEC.md, behaviors, architecture, data-model, interfaces, configuration, fitness-functions
  architecture/   overview, diagrams.md, ADRs (decisions/)
  CONTRACT.md     the v0 interface contract (mirrors the ecosystem's v1 interface contract §2)
  plans/          roadmap
  tasks/          active, backlog, completed task files
    test-specs/   TDD specs — always written before implementation
```

This repo is a **single Go `package main`** — a flat set of `*.go` files at the repo root, not a
multi-package tree. The layout is established; new work documents and extends it, it does not
restructure it. `docs/` is the input side (read before you act, the artifact that survives a rewrite);
the `*.go` files are the output side.

`docs/spec/` is **dual-natured** — output of every task that changes externally-visible behavior, the
data model, an interface, or configuration; and input to onboarding, drift audits, and (in the limit)
regenerating the codebase. The code is one realization of the spec. Spec and code that disagree means
one of them is wrong; fix it in the same change.

## Tech stack

Go (`go 1.26`, module `github.com/tkdtaylor/memory-guard`). **Single static binary.** The v0 has
**no third-party dependencies** — the standard library only (`net`, `encoding/json`, `crypto/rand`,
`regexp`, `bufio`, `sync`). The v1 Presidio-backed `Detector` (sidecar/ONNX) is the first external
dependency and a future ADR — it must clear `dep-scan` / `code-scanner` as a blocking gate. License:
**Apache-2.0** (SPDX header on every first-party `.go` file).

## Commands

```bash
go build ./...                                    # compile
go test ./...                                     # run tests
go fmt ./...                                       # format
golangci-lint run                                 # lint (when installed)

# run it
go run . write "contact alice@example.com"        # redacts PII, stores; prints the WriteResult JSON
go run . read  "contact"                           # seeds then reads; prints the redacted ReadResult JSON
go run . serve --socket /run/memguard.sock        # IPC daemon (newline-delimited JSON)
make build && make test                            # via the Makefile
```

There is no `make check` / `make fitness` target yet — `go build ./... && go test ./...` (plus
dep-scan / code-scanner for the supply chain once a Presidio-backed detector lands) is the
verification gate today. Fitness functions are seeded as `proposed` in
`docs/spec/fitness-functions.md`; wiring a runner is future work.

## Conventions

- Task files are named `NNN-short-name.md` (zero-padded, sequential across all task states)
- Every task has a paired test spec; no implementation starts without one
- Tasks follow Unix philosophy — one task, one responsibility; break things smaller when in doubt
- ADRs live in `docs/architecture/decisions/` — add one whenever a significant design decision is made
- Go: standard `gofmt` layout; tests live beside source as `*_test.go` in `package main`. Keep
  dependencies minimal (v0 is stdlib-only; a Presidio-backed detector is an ask-first ADR, not a
  casual add). Every first-party `.go` file carries `// SPDX-License-Identifier: Apache-2.0`.
- **Never leak a detector backend's specifics past the `Detector` seam.** Error shape is
  `{error:{code,message,retryable}}`.
- **Spec is updated in the same commit as the code change.** A task that changes externally-visible
  behavior, the data model, an interface, or configuration is not done until the matching `docs/spec/`
  file reflects the new state. Stale spec entries are rewritten in place — never appended to. The ADR
  carries the history; the spec carries the truth.
- **Diagrams update with the code.** When a component boundary moves or a runtime flow changes, update
  `docs/architecture/diagrams.md` in the same commit.

## Design principles

This project follows **Unix philosophy** as its default — composability over monolithic design.
Complex behavior emerges from combining small, independent components communicating through
standardized interfaces.

Four structural properties to design for:

- **Modularity** — independent units that can be built, understood, and changed on their own (the
  detector, the guard core, the IPC server are separable concerns)
- **Interface standardization** — stable, well-defined contracts (the `Detector` interface + the
  `validate_*` verbs are the seams that let a backend or a memory store swap behind them)
- **Maintainability** — changes in one module should not cascade across unrelated ones
- **Reusability** — components should be liftable into another project without entanglement

Derived working rules:

- **One thing, well** — each module and function has a single clear responsibility
- **Small, composable pieces** over large configurable ones
- **Plain text** for configs, intermediate artifacts, and data interchange (JSON over the socket)
- **Explicit over implicit** — surface assumptions in code and types, not in comments
- **Fail fast, crash loudly** on unexpected state — and **fail closed** on the write-gate
- **Test in isolation** — every component runnable without the whole stack
- **Defer premature decisions** — no abstractions until the second or third concrete use demands them
  (the `Detector` seam exists precisely so the backend choice can be deferred to the tracer)

**Monolithic is a legitimate choice when deliberate** — a hot-path gate or a detection primitive can
be cohesive for good reasons (per-call latency, correctness). The principle is "prefer composability at
user-facing or cross-module boundaries, and document any deviation with an ADR." The `Detector` seam is
exactly the kind of cross-module boundary that stays composable; the write-gate orchestration inside
`MemoryGuard` is deliberately cohesive.

## Working in this project

Every task lives on its own branch (or worktree under concurrent sessions). Working directly on the
default branch (`master`) is blocked by the `no-commit-on-main.py` hook — `scripts/start-task.sh` is
how you pick the right isolation.

1. Start each session by reading the relevant task file (including its **Verification plan**) and its test spec
2. Check `docs/architecture/overview.md` for system context
3. Write the test spec before any implementation code
4. Use the **task-executor** agent to implement. Its Step 0 runs `scripts/start-task.sh <NNN> <slug>` to set up either:
   - `BRANCH task/NNN-<slug>` (solo session — the common case), or
   - `WORKTREE .claude/worktrees/NNN-<slug>/` (concurrent session detected; the executor `cd`s in)

   The executor commits at status **🟡 (code merged)** on the task branch.
5. After the executor returns, use **spec-verifier** on the task — it returns APPROVE or BLOCK based on per-assertion evidence
6. If spec-verifier APPROVEs **and** the verification plan's L5/L6 evidence is recorded, promote the row to **✅ (verified)** in `coverage-tracker.md` in a **separate commit** titled `verify: confirm task NNN — <evidence>` (still on the task branch)
7. **Merge to master** when ready: `git checkout master && git merge task/NNN-<slug>`. The cleanup hook then deletes the task branch and removes the worktree (if any).
8. **Commit after each milestone** — never start the next task without committing the current one first

The separation between the task branch and `master` is the load-bearing rule for multi-session
safety. The separation between 🟡 (feat commit) and ✅ (verify commit) is the load-bearing rule for
verification honesty: **never** mark ✅ in the same commit as the feature work.

## Commit rules

**Commit after every milestone.** Do not batch multiple tasks into one commit. Do not continue to the
next task until the current one is committed.

All commits below land on the **task branch** (`task/NNN-<slug>`), never on `master` directly.

| Milestone | What to stage | Message |
|-----------|--------------|---------|
| ADR written | `docs/architecture/decisions/NNN-*.md`, any superseded spec entries | `docs: add ADR NNN — <decision title>` |
| Test spec written | `docs/tasks/test-specs/NNN-*-test-spec.md`, updated `coverage-tracker.md` | `test: add spec for task NNN — <name>` |
| Task code merged (🟡) | source changes, moved task file, `coverage-tracker.md` row set to 🟡, affected `docs/spec/` files | `feat: complete task NNN — <name>` |
| Task verified (✅) | `coverage-tracker.md` row promoted 🟡 → ✅ with `Verified by` filled | `verify: confirm task NNN — <evidence>` |
| Diagram updated | `docs/architecture/diagrams.md` (with date bump) | `docs: refresh diagrams — <what changed>` |
| Merged into master | (after `git merge task/NNN-<slug>` on `master`) | (default `Merge branch …` message) |

This repo is **public** (Apache-2.0); there is **no git remote yet** (TODO.md) — push after each
milestone once a remote is configured. For a genuine master-only doc fix, include `[allow-main]` in
the message.

## Plan mode

When you exit plan mode, a hook restructures the plan: each step becomes a task file in
`docs/tasks/backlog/`, test-spec stubs are created, and the full plan is backed up to `docs/plans/`.
Use the **task-executor** agent to work through tasks one at a time.

```
use task-executor — task: docs/tasks/backlog/NNN-name.md, spec: docs/tasks/test-specs/NNN-name-test-spec.md
```

### End handoffs with a resume command

When a response completes a milestone that leaves follow-on work, end with a **fenced code block**
containing the exact resume command. Verify the path exists before writing it (glob
`docs/tasks/backlog/NNN-*.md` and the matching test-spec). Skip the block when there is genuinely
nothing to resume.

## Hook profiles

```bash
export CLAUDE_HOOK_PROFILE=minimal    # Safety hooks only
export CLAUDE_HOOK_PROFILE=standard   # + workflow hooks — default
export CLAUDE_HOOK_PROFILE=strict     # + formatting, notifications
export CLAUDE_DISABLED_HOOKS=desktop-notify,batch-format-typecheck
```

## Boundaries

### Always
- Write the test spec before any implementation code
- Fill in the **Verification plan** of the task file *before* writing code
- Commit after every milestone (task completed, spec written, ADR written)
- Read the task file (including its Verification plan) and test spec before starting
- Create an ADR for significant design decisions
- **Update `docs/spec/` in the same commit** as any code change altering behavior, data model, interfaces, or configuration
- **Update `docs/architecture/diagrams.md` in the same commit** as any change moving a component boundary or diagrammed flow
- **Default new task status to 🟡 on the feat commit; ✅ only after spec-verifier APPROVE + recorded L5/L6 evidence**, in a separate `verify:` commit
- **Run `spec-verifier` on every task** before promoting to ✅
- **Start every task on its own branch via `scripts/start-task.sh <NNN> <slug>`**
- **Keep all detector specifics behind the `Detector` seam** — every change keeps the guard, contract, and IPC backend-agnostic
- **Keep the write-gate fail-closed** — a write flagged for poisoning must never persist

### Ask first
- Modifying files in `docs/plans/`, `docs/tasks/`, or `docs/architecture/decisions/`
- Deleting or renaming existing source files (`detector.go`, `guard.go`, `ipc.go`, `main.go`)
- Adding dependencies not already in the tech stack (v0 is **stdlib-only** — a Presidio-backed detector,
  an ONNX runtime, or any NLP/NER dependency is a future ADR + a `dep-scan`/`code-scanner` blocking gate,
  not a casual add)
- Changing the project structure beyond what a task requires
- Reorganizing `docs/spec/` (splitting files, renaming sections)

### Never
- Combine unrelated changes in one task or commit
- Skip the test spec — even for "small" changes
- Force push or rewrite published git history
- Add a `Co-Authored-By` line to commits unless explicitly asked
- Run `git checkout -- <path>` over a dirty working tree — it silently overwrites uncommitted work. `git stash` first, or use `git diff`/`git show` to compare.
- **Append to spec entries instead of rewriting them.** The ADR keeps history — the spec is a snapshot.
- **Add future-tense statements to the spec.** Planned work goes in `docs/plans/` and `docs/tasks/`.
- **Mark a task ✅ on the same commit as the feature work.**
- **Claim a verification level you did not actually reach.**
- **Commit directly to `master`.** Use `[allow-main]` in the message for genuine master-only doc fixes.
- **Leak a detector backend's specifics past the `Detector` seam** — it collapses the one seam that keeps the substrate (Go) independent of the detection tool (Presidio).
- **Let the write-gate regress into a thin PII-redaction wrapper** — the fail-closed poisoning gate is the built delta, not an optional layer.
- **Reduce `verify_delete` to a bare `delete()`** — it must prove absence; in v1, across every index/copy.

## Common rationalizations

These are the excuses that precede a broken invariant. Catch them in yourself:

- *"It's just a quick Presidio call inlined in the guard to ship faster."* — No. Every detector call
  goes through the `Detector` seam. Inlining Presidio into `guard.go` is exactly the leak the seam
  exists to prevent — it makes the backend choice expensive to revisit in the tracer.
- *"The content only *looks* like injection; storing it is probably fine."* — No. The write-gate is
  fail-closed: a `injection_suspected` flag rejects the write. "Probably fine" is how context
  poisoning lands in the store.
- *"`delete()` returned, so the entry is gone — `verify_delete` can just confirm the call."* — No.
  Verification means *proving* absence (v0: re-checking the store; v1: scanning every index/copy for
  residue). A bare `delete()` is the industry gap memory-guard exists to close.
- *"Tests pass, so it's verified."* — No. Tests passing earns 🟡. ✅ needs L5/L6 runtime evidence.

## Agent rules and retros

Process-level rules, common rationalizations, and project-specific retros live in
`docs/architecture/agent-rules.md` (when present). The `inject-retros.py` SessionStart hook surfaces
relevant entries at session start — adding an entry there is how a one-time mistake becomes a
permanent guard.

When dispatching parallel agents in one message, run
`scripts/verify-worktree-isolation.sh <agent-id> …` afterward to confirm none bypassed the worktree flag.

## Recommended tooling

This is a **Go security block on the agent's memory hot path** — it gates every read/write and will
soon pull an NLP detection backend. Wire the supply-chain and security gates before adopting anything
new:

- **dep-scan** — supply-chain CVE scan of Go modules. Critical the moment the Presidio-backed
  `Detector` (or an ONNX runtime / NER model) pulls its first dependency tree. Use `gods` for Go.
  Install: `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh | bash`
- **code-scanner** — scan any new module (and the repo itself) for malware / backdoors / credential
  harvesting before adoption — doubly important for a block on the path that sees PII and tool output.
  Trigger: "scan this repo for malware".
- **code-review** — review diffs before merge, especially anything touching the `Detector` seam, the
  write-gate, or `verify_delete`. Trigger: `/code-review`.
- **security-auditor agent** — run a security pass on any change to the write-gate or the detector
  before ship. Invoke: "use the security-auditor on the write-gate". It checks for poisoning that
  bypasses the gate, PII that reaches the store, and detector specifics leaking past the seam.

### Hooks

Wired via `.claude/settings.json` (standard profile): `no-commit-on-main`, `protect-secrets`,
`block-no-verify`, plan→tasks restructuring, compaction guards, spec-coverage-check. Control with
`CLAUDE_HOOK_PROFILE` (minimal/standard/strict).
</content>
