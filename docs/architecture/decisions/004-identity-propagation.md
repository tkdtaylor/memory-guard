# ADR-004 — Identity propagation: a pre-verified SPIFFE principal, not in-guard SVID verification

**Status:** Proposed (recommended direction; ratified when [task 009](../../tasks/backlog/009-identity-scoped-read-isolation.md) implements)
**Date:** 2026-06-24
**Refines:** the identity model left open in [ADR-001](001-foundational-stack.md) — `identity` is carried on `validate_*` today but **not enforced**.
**Task:** [009 — Identity-scoped read isolation (R1 / roadmap T4)](../../tasks/backlog/009-identity-scoped-read-isolation.md) (REQ-007 — this ADR is its deliverable).

## Context

`validate_read` / `validate_write` already carry an `identity` argument, but it is an inert free-form
`map[string]any`: `ValidateRead` matches by substring across the **whole** store and never reads
`identity`. Task 009 makes identity **load-bearing** — a writer's entries readable only under a matching
identity (tenant isolation on the memory hot path).

An audit of the sibling projects (2026-06-24) re-scoped the blocker this ADR resolves:

- **agent-mesh already issues and verifies a workload identity.** It mints an **X.509-SVID** (SPIFFE ID
  as a URI SAN, binding an Ed25519 key), carries the principal on the wire in a **signed envelope**
  (`Envelope.From`, Ed25519-signed over a canonical body), and exposes a **fail-closed verification
  path** — SVID chain → trust-bundle, URI-SAN match, signature, replay/freshness — emitting a
  `trust_tier` (`attested`) on success. This is tracer-validated. Only the *live* SPIRE/Vault issuer is
  deferred; a **mock issuer** stands in behind agent-mesh's `SvidProvider` seam, which is what our own
  tracer would use.
- **vault is not an identity source.** It is a secrets broker; its own SPIFFE binding is itself blocked
  on agent-mesh. It is a *co-consumer* of the same principal, not a supplier — **removed** as a 009
  dependency.

So the open question is **not** "who builds the identity" (agent-mesh did) but **the
identity-propagation contract**: what verified claim memory-guard receives on each `validate_*`, and
**who runs the verification**. Two candidates:

1. **Pre-verified principal** — memory-guard receives an already-verified principal (normalized SPIFFE
   ID + `trust_tier`); the SVID/signature/replay checks happen **upstream** (the hosting agent's
   agent-mesh receiver). memory-guard does **not** parse certs.
2. **In-guard SVID verification** — memory-guard receives the full SVID (X.509-SVID PEM + trust bundle)
   and runs the chain + signature verification **itself, per call**.

The decision is weighed against memory-guard's **load-bearing invariants**: low per-call latency on the
memory hot path (the gate runs on *every* read and write, budget `< 1 ms`, ~5.6 µs detection today —
ADR-002), the `Detector`-style **seam discipline** (no backend specifics leak into the guard), the
`0600` UID-gated Unix-socket trust boundary, and **fail-closed** on the security-critical path.

## Decision

**Adopt option 1 — memory-guard receives a *pre-verified* SPIFFE principal and trusts it; agent-mesh
owns verification.** Keep in-guard SVID verification (option 2) available behind the same seam as a
**deferred zero-trust config**, not the v1 default.

- **Wire shape on `validate_*`.** `identity` becomes a typed principal, not a free-form map:

  ```jsonc
  "identity": {
    "spiffe_id":  "spiffe://<trust-domain>/agent/<id>",  // the normalized match key
    "trust_tier": "attested"                              // from agent-mesh; "" / "unattested" otherwise
  }
  ```

- **`Principal` seam.** A small guard-side interface isolates "how identity is obtained/verified" from
  "how it is bound and matched":

  ```go
  type Principal interface {
      Subject() string   // normalized identity key (the SPIFFE ID); "" if none
      Attested() bool    // trust_tier == "attested"
  }
  ```

  The **v1 default** impl (`PreVerifiedPrincipal`) trusts the caller-supplied `spiffe_id` + `trust_tier`.
  A **deferred** impl (`SvidVerifyingPrincipal`) parses and verifies an SVID + bundle in-process for a
  zero-trust deployment — same seam, no guard change.

- **Binding & matching.** `validate_write` records `Subject()` as the entry's bound identity key;
  `validate_read` returns an entry only when the reader's `Subject()` **exactly** matches the entry's
  bound key (no substring/fuzzy on the identity). Matching is guard-side orchestration — **not** a
  `Detector` concern; no detector specifics enter the identity path.

- **Enforcement gate.** Isolation is enforced **only when `Attested()` is true**. An unverified or
  absent principal does **not** silently return-everything — it hits the documented no-identity fallback
  (009 **REQ-005**: deny, or unbound-only). This keeps the posture **fail-closed**.

- **memory-guard does not parse certificates.** No X.509 / SPIFFE-PEM / Ed25519 verification code in
  `guard.go` or `ipc.go` in the v1 default path. That logic lives upstream (agent-mesh) or, for
  zero-trust, behind the `Principal` seam.

## Rationale

| Criterion (invariant) | Option 2: in-guard SVID verification | **Option 1: pre-verified principal (chosen)** |
|---|---|---|
| Hot-path latency (every memory op, `< 1 ms`) | ✗ per-call X.509 chain + Ed25519 verify — ms-scale, or forces a verification cache | ✓ string compare on a normalized key |
| Seam discipline (no backend specifics in the guard) | ✗ X.509/SPIFFE parsing baked into `guard.go`; issuer swap = guard change | ✓ guard sees only a normalized principal; issuer swaps upstream behind agent-mesh's `SvidProvider` |
| Single responsibility (no duplicated verification) | ✗ a second verification path that can disagree with agent-mesh's | ✓ agent-mesh remains the one verifier (already tracer-validated) |
| Trust boundary already drawn | — re-verifies a caller already across the `0600` UID-gated socket | ✓ trusts the local UID-gated caller that *also* supplies content/query |
| Fail-closed | ✓ (if implemented correctly) | ✓ enforce only when `attested`; else REQ-005 fallback |
| Zero-trust deployments | ✓ native | ✓ available behind the `Principal` seam as a deferred config |

The decisive factor is the **threat model at memory-guard's boundary**. The caller is a trusted local
component across a `0600` UID-gated socket; a caller able to forge `spiffe_id` could equally lie about
the `content` and `query` it is gating — so in-guard re-verification of *only* the identity buys little
against that adversary while costing real hot-path latency and dragging X.509 specifics into the
substrate. "Don't trust the caller" belongs in a verifying gateway **in front of** the hot-path gate,
not inside it — and when a deployment genuinely needs it, the `Principal` seam turns it on without a
re-architecture.

## Consequences

- **009 is startable now** against agent-mesh's mock SVID (exactly what a v1 tracer uses); live SPIRE
  swaps in later behind agent-mesh's `SvidProvider` seam with **no memory-guard change**.
- The `Detector`-seam discipline gains a sibling: a **`Principal` seam** that keeps identity
  verification out of the guard. The contract verbs stay backend-agnostic — `identity` is now typed but
  carries no SPIFFE/X.509 machinery.
- **PII redaction on read is unchanged** (defense in depth still runs on whatever the scoped set
  returns); the write-gate stays fail-closed; the IPC error shape `{error:{code,message,retryable}}` is
  unchanged.
- **vault is not in the identity path.** It remains a peer consumer of the same principal; this ADR
  records that removal so a future reader does not re-introduce it as a dependency.
- A zero-trust posture (in-guard SVID verification) is a **deferred, additive** option behind the
  `Principal` seam — this ADR defers it, it does not foreclose it (mirroring ADR-002's treatment of
  Presidio).

## To confirm at implementation (task 009)

> This ADR is **Proposed**; task 009 ratifies it and fills these in, then flips the status to Accepted.

- **No-identity / unattested fallback policy** — REQ-005: **deny** vs. **unbound-only**. Pin one and
  record it here and in `behaviors.md`.
- **`trust_tier` vocabulary** — confirm the exact set agent-mesh emits (`attested` / `unattested` / …)
  and the precise predicate `Attested()` uses, against agent-mesh's published contract.
- **Durable index** — with task 006's real `MemoryStore`, prefer a **per-identity index/partition** for
  the scoped lookup over a linear identity filter; 009 may ship the linear filter over the v0 map first
  and note the index as the durable form.
- **Spec propagation** — update `docs/spec/interfaces.md` (the typed `identity` shape) and
  `docs/spec/data-model.md` (the entry's bound-identity key) in the same commit as the 009 code.
