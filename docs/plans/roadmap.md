# Roadmap — memory-guard

The agent **memory-I/O gate** for the secure-agent ecosystem (OWASP **ASI06** — Memory & Context
Poisoning). It sits in front of any agent memory store and gates every read and write: poisoned writes
are **rejected at ingestion** (the write-gate, fail-closed), PII is **redacted before storage** and
again on read, and deletions are **verified** — proven gone, not merely `delete()`d. The `Detector`
interface + the `validate_*` verbs are the adapter seams, so a Presidio-backed detection backend and a
real MemoryStore can be swapped without touching callers.

Authoritative design: the project's internal design notes
+ `interface-contracts.md §2`. As-built foundational stack:
[ADR-001](../architecture/decisions/001-foundational-stack.md).

## v0 — write-gate + PII redaction + delete-verification skeleton — ✅ shipped

Working today (`detector.go` / `guard.go` / `ipc.go` / `main.go`): the `validate_write` write-gate
(injection detection **before** storage, fail-closed on `injection_suspected`, redact PII, mint an
opaque `stored_id`, store the redacted content); `validate_read` (substring scan + PII redaction on
the way out); `verify_delete` (delete + re-check absence — post-deletion verification); a `0600`
Unix-socket JSON IPC server (`serve --socket`) dispatching the three verbs + `ping`; and in-process
`write` / `read` demos. The detection lives behind the `Detector` seam (v0 `RegexDetector`, a Presidio
stand-in). Pure Go, **stdlib only**. The `Detector` interface + the `validate_*` verbs are the adapter
seams — a real detection backend and a real MemoryStore slot in behind them without changing the
contract.

> **Contract tracer-validated (T6 / ADR-008).** memory-guard ran its own tracer-bullet: an
> end-to-end slice drives `validate_write → validate_read → verify_delete` over the live `serve`
> socket against the real `MemoryStore` seam, asserting each verb's response field-by-field on the
> JSON decoded off the socket. The shapes validated **unchanged**. The detector dimension was
> validated against the v0 `NativeDetector` (Presidio, T2, still pending) — a noted follow-up.

## v0-hardening increment (within-repo) — ✅ shipped (tasks 001–005)

> **Naming note — read this if you think memory-guard is "at v1."** These five were historically
> labelled "v1 tasks," but they **harden the v0 substrate; they do not deliver a true v1.** After
> all five, detection is still regex/Go-native (no Presidio/NER), the store is still an in-memory
> map stand-in, identity is carried-but-not-enforced, and the contract is **not yet
> tracer-validated**. What a genuine v1 requires is tracked under
> [Toward a true v1](#toward-a-true-v1-substrate-not-just-tasks) below.

Each was a self-contained task behind the contract (`validate_read`/`validate_write`/`verify_delete`)
and the `Detector` interface — the swap points stayed fixed so hardening slotted in **without
changing the contract or any caller**. The load-bearing invariants (write-gate fail-closed, PII never
stored/returned raw, delete-verified, detector-seam isolation, fail-closed errors) held across every
task.

| # | Work | Status |
|---|------|--------|
| 1 | **Resolve the `Detector` backend** — settled Presidio-as-sidecar vs. Presidio-via-ONNX in-process vs. Go-native behind the existing `Detector` seam; recorded as [ADR-002](../architecture/decisions/002-detector-backend.md) (Go-native, in-process, zero new deps; ~5.6 µs/op). Presidio is **deferred, not foreclosed**. | ✅ verified (L6) |
| 2 | **Adversarial context-poisoning test-suite** — MINJA-/GRAGPoison-/context-window-injection suite; measured baseline recall **0.69** / precision **0.85** on the v0 backends, with 10 documented miss-classes. | ✅ verified (L5) |
| 3 | **Post-deletion residue verification** — extended `verify_delete` from "absent in the in-memory map" to a tiered residue scan over surviving entries + a deletion-hash ([ADR-003](../architecture/decisions/003-residue-verification.md)); residue 85.7% / precision 100% over the one store. | ✅ verified (L6) |
| 4 | **PII recognizer coverage hardening** — broadened the recognizer set (phone, IBAN, IP, DOB, more credential shapes) behind the `Detector` seam; recall/precision 1.00 over 9 categories on the corpus. | ✅ verified (L5) |
| 5 | **Publish / remote follow-up** — created the private GitHub remote and pushed; SPDX headers on new files. | ✅ verified (L6) |

The working v0 source was **not rewritten** — these extended it behind the contract + `Detector` seam.

## Toward a true v1 (substrate, not just tasks)

The five tasks above hardened the **skeleton**; they did not replace the **stand-ins**. The repo flips
from "v0 substrate" to a defensible **v1** when the load-bearing stand-ins become real and the
contract is tracer-validated. The gating item — the **contract tracer** (T6) — has now **run**: the
contract shapes are tracer-validated over the live socket against the real store (ADR-008), so the
"not yet tracer-validated" caveat is removed. The one remaining open v1 dimension is the real
detection backend (T2 / Presidio). Ordered by dependency:

| # | Work | Unblocks / depends on | Status |
|---|------|-----------------------|--------|
| T1 | **MemoryStore seam + one real adapter** — extract a `MemoryStore` interface and back it with a real store (vector/LangChain/LlamaIndex memory) instead of the in-memory map. The single map is *why* delete-proof and identity can't be real yet. | foundational — unblocks T3, T4 | 🔜 proposed |
| T2 | **Presidio-backed `Detector`** (sidecar or ONNX, behind the unchanged seam) — un-defer ADR-002's Presidio path; first third-party dep, so a `dep-scan`/`code-scanner` **blocking gate** + a new ADR; must lift recall above the 0.69 regex baseline and re-validate the `< 1 ms` latency budget. | behind the `Detector` seam | 🔜 proposed |
| T3 | **Residue proof across every index/copy** — extend the residue scan from "survivors in one map" to every backing index of the real store, plus the documented semantic-paraphrase miss-class. | **depends on T1** | 🔜 proposed |
| T4 | **Identity-scoped read isolation (R1)** — enforce `identity` on `validate_read` so a writer's entries are readable only under a matching identity. | **depends on T1 + the identity-propagation contract** (agent-mesh already ships the verifiable SPIFFE principal; vault is not the source) | 🔜 startable — one interface decision (see R1) |
| T5 | **audit-trail OCSF emission (R2)** — emit detections as OCSF events to `audit-trail` (soft runtime dep). | consume audit-trail's emit contract | 🔜 proposed |
| T6 | **memory-guard's own tracer-bullet** — end-to-end slice over the live `serve` socket with a real store + a real consumer that **validated the contract shapes** field-by-field on the decoded socket response; shapes validated **unchanged** (no refinement forced). Detector dimension covered against the v0 `NativeDetector` (real-Presidio re-validation is a noted follow-up). Task 011 / [ADR-008](../architecture/decisions/008-contract-tracer-validation.md). **This is the task that earns the v1 label.** | **depends on T1, ideally T2** | ✅ tracer-validated (L6) |
| T7 | **Fitness-function runner wired as a gate** — promote `docs/spec/fitness-functions.md` from `proposed` to enforced (latency budget, recall/precision floor, seam-isolation check) behind a `make check`/`make fitness` target. | — | 🔜 proposed |

## Remaining work — blocked / decisions needed

### R1 — Identity-scoped read isolation — the issuer exists; the propagation contract does not
**Re-scoped 2026-06-24 after auditing the siblings.** Today `validate_read` matches by substring across
the whole store and `identity` is carried but not enforced. The earlier blocker ("needs a
workload-identity model from agent-mesh / vault") is **partly stale**:

- **agent-mesh already ships the verifiable principal** — X.509-SVID issuance (SPIFFE ID as a URI SAN,
  Ed25519-bound), a signed-envelope wire carrier (`Envelope.From`), and a fail-closed verification path
  (chain → trust-bundle, signature, replay), tracer-validated. Only the *live* SPIRE/Vault issuer is
  deferred — a mock issuer stands in behind agent-mesh's `SvidProvider` seam, which is exactly what our
  own tracer would use.
- **vault is not an identity source** — it is a secrets broker, and its own SPIFFE binding is itself
  blocked on agent-mesh. It is a *co-consumer* of the same principal, not a supplier. **Dropped as a
  dependency for this task.**

So the real remaining gap is **the identity-propagation contract**: the shape of the verified SPIFFE
claim memory-guard receives on each `validate_*`, and who verifies it. That is one interface decision,
not an upstream build.

**Recommended resolution ([ADR-004](../architecture/decisions/004-identity-propagation.md), *Proposed*;
ratified when task 009 implements): memory-guard receives a *pre-verified* SPIFFE principal — the
normalized SPIFFE ID plus a `trust_tier` (e.g. `attested`) — and does NOT re-verify the SVID itself.** Verification (SVID chain, Ed25519 signature, replay) stays agent-mesh's
job; the hosting agent's mesh receiver hands the trusted principal across memory-guard's `0600`
UID-gated socket. memory-guard binds/matches on the SPIFFE ID and enforces isolation only when
`trust_tier` is attested; an unverified/absent principal hits the documented no-identity fallback (009
REQ-005). Rationale: **(1)** keeps the `< 1 ms` hot-path budget — per-call X.509 chain verification
would blow it; **(2)** honors the seam discipline — no SPIFFE/X.509 specifics leak into the guard, the
same reason the `Detector` seam exists; **(3)** the trust boundary is already the local UID-gated
socket — a caller that could forge the principal could equally lie about the content/query, so in-guard
re-verification buys little there. In-process SVID verification stays available behind the same
`Principal` seam as a **deferred zero-trust config**, not the v1 default.

With this, **009 is startable now** against agent-mesh's mock SVID; live SPIRE swaps in later behind
agent-mesh's `SvidProvider` seam with no memory-guard change. Until 009 lands, the un-scoped substrate
read remains the v0/v1 behavior.

### R2 — audit-trail emission — soft-dependency, plannable
Detections are returned as `flags` today; emitting them as **OCSF events to `audit-trail`** is a
plannable task once the audit-trail emit contract is consumed here (a soft runtime dep, not a
build-time blocker). Sequence after the `Detector` backend is settled.

## Notes for the orchestrator

This repo is built out one task at a time by **agent-builder** (and drivable via `/autopilot` /
`/backlog-autopilot`): it reads this roadmap + `docs/tasks/backlog/NNN-*.md`, builds the next ready
task, runs the verification gate (`go build ./... && go test ./...`, plus dep-scan/code-scanner on any
new module), and integrates it. The working v0 source (`detector.go`, `guard.go`, `ipc.go`, `main.go`)
is **not rewritten** — v1 work extends it behind the contract + `Detector` seam. Adding a dependency
(e.g. a Presidio SDK / ONNX runtime for task 001) is an "ask-first" event: it must clear dep-scan and be
recorded in the task's ADR, because memory-guard's whole point is a minimal, auditable gate on the
memory hot path.
</content>
