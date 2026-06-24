# ADR-004 — Identity propagation: a pre-verified SPIFFE principal, not in-guard SVID verification

**Status:** Accepted (ratified 2026-06-24 by [task 009](../../tasks/completed/009-identity-scoped-read-isolation.md), which implements it — `Principal` seam in `principal.go`, binding/matching in `guard.go`)
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

## Confirmed at implementation (task 009 — ratified 2026-06-24)

> Ratified: status flipped Proposed → **Accepted**. The open items are resolved as follows.

- **No-identity / unattested fallback policy — UNBOUND-ONLY (REQ-005).** An unattested or absent
  principal returns **only** entries that were themselves written with **no bound identity**
  (public/system entries — bound to the `unboundKey` marker); it **never** returns an identity-bound
  entry and **never** returns-everything. This is **fail-closed w.r.t. bound entries** (the security
  property: a forged/unverified caller reaches no isolated tenant data) while keeping the v0 demo
  (`go run . write/read`, which carries no identity) working — identity-less writes are readable by
  identity-less reads. Recorded in `behaviors.md` (B-002, B-008) and `data-model.md` (the entry's
  `boundIdentity`). *(Considered and rejected: hard **deny**. Unbound-only is strictly safer than
  "return everything" and, unlike deny, preserves the public/system-memory use case and the v0 demo
  without weakening tenant isolation — bound entries stay invisible either way.)*

- **`trust_tier` predicate — `Attested()` ⇔ `trust_tier == "attested"`.** The guard treats the single
  literal value `"attested"` (the tier agent-mesh emits on a successful SVID chain → trust-bundle →
  URI-SAN → signature → replay verification) as attested; **every** other value (`""`, `"unattested"`,
  any unknown string) is **not** attested and routes to the unbound-only fallback. The literal lives in
  one place behind the seam (`attestedTier` in `principal.go`); broadening the accepted vocabulary, if
  agent-mesh adds tiers, is a one-constant change there with no guard/IPC impact. **Matching of the
  identity itself is EXACT** on the normalized `Subject()` (the trimmed SPIFFE ID) — no substring/fuzzy,
  so `tenant-1` never matches `tenant-12`.

- **Durable index — per-identity index/partition is the durable form; 009 ships the linear filter.**
  Task 009 ships a **linear identity filter** over the task-006 `MemoryStore` seam: `validate_read`
  calls `Scan(query)` and keeps only entries whose `boundIdentity` exactly equals the reader's
  visibility key. This is correct and behind the seam, but O(store) per read. The **durable form** is a
  **per-identity index/partition** (`identity → entries`) exposed through the `MemoryStore` seam so the
  scoped lookup is O(matches), not O(store) — a store-internal change behind the **unchanged**
  `validate_*` verbs and `Principal` seam, deferred to a future task. Recorded here so a future reader
  knows the linear filter is the v0 mechanics, not the intended steady state.

- **Spec propagation — done in the 009 feat commit.** `docs/spec/interfaces.md` (the typed `identity`
  `{spiffe_id, trust_tier}` shape + the `Principal` seam), `docs/spec/data-model.md` (the entry's
  `boundIdentity` key, replacing the inert `identity map`), and `docs/spec/behaviors.md` (B-001/B-002
  rewritten + B-008 the isolation behavior) were updated in the same commit as the code.

- **Deferred behind the seam (recorded, not built here):** `SvidVerifyingPrincipal` — the zero-trust
  variant that parses + verifies an X.509-SVID + trust bundle in-process — is **not** implemented in
  009. It is a future, additive `Principal` impl with no guard/IPC change. No X.509 / SPIFFE-PEM /
  Ed25519 parsing was added to `guard.go` or `ipc.go`; `go.mod` stays require-free.
