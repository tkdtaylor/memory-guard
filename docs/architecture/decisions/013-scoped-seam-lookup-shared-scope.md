# ADR-013: Scoped `MemoryStore` lookup + explicit shared scope (durable identity isolation)

**Status:** Accepted
**Date:** 2026-07-12
**Task:** [016 (Durable identity isolation)](../../tasks/completed/016-durable-identity-isolation.md)
**Relates to:** ADR-004 (identity propagation, the `Principal` seam, ratified by task 009: this ADR realizes its deferred "durable per-identity index" item at seam level), ADR-005 (the `MemoryStore` seam this extends), ADR-012 (the `FileStore` whose persistence makes the restart proof possible).

## Context

Task 009 shipped exact-string identity isolation: `ValidateWrite` binds `entry.boundIdentity`, and `ValidateRead` filtered `store.Scan(query)` by exact key equality. Three gaps remained from roadmap T4, all now addressable because task 015 gave the seam a persistent backing:

1. **The scoped lookup was a guard-side linear filter over `Scan`.** ADR-004 explicitly recorded this as "the v0 mechanics, not the intended steady state", deferring a store-side scoped lookup so the store, not the guard, owns the scoping.
2. **Isolation only existed inside one process lifetime.** Every adapter was in-memory until `FileStore` (ADR-012). Durability was untestable.
3. **There was no shared scope.** Under 009, an attested reader sees *only* entries bound to its exact subject, and unbound entries are visible only to unattested/absent readers. An attested tenant had no way to publish a memory readable by other identities.

ADR-004 already resolved the trust model: memory-guard receives a **pre-verified** principal across the `0600` socket; cryptographic verification (SVID chain, signature, replay) stays upstream in agent-mesh. Nothing here parses certificates; string-exact matching stays the enforcement primitive.

## Decision

**Push the identity-scoped lookup into the `MemoryStore` seam as a new `ScanScoped` verb, add an explicit attested-only shared scope keyed by a reserved forge-proof marker, and prove the whole visibility matrix survives a restart over `FileStore`.**

### 1. `ScanScoped` on the `MemoryStore` seam

```go
// ScanScoped returns every entry whose content contains query AND whose
// boundIdentity is an exact member of visibleKeys. Exact string membership,
// no substring/fuzzy on keys. Empty visibleKeys returns no entries.
ScanScoped(query string, visibleKeys []string) []entry
```

Implemented by all three adapters (`InMemoryStore`, `TwoIndexStore`, `FileStore`) as a linear filter over the primary index. `ValidateRead` computes the reader's visible-key set once and calls `ScanScoped` exactly once; the guard-side filter loop over `Scan` is removed from the read path. Per-identity physical partitioning *inside* an adapter (an O(matches) lookup) stays an internal optimization behind this verb, deferred until a store's scale demands it: the seam is now scoped store-side, which is what ADR-004 deferred.

### 2. Shared scope: attested-writer-only publish, readable by all

The typed `identity` argument gains one **optional** field, meaningful on `validate_write` only:

```jsonc
"identity": { "spiffe_id": "…", "trust_tier": "attested", "scope": "shared" }
```

- `ValidateWrite` binds the reserved `sharedScopeKey` **iff** the writer is attested **and** `scope == "shared"`. An unattested writer requesting shared binds **unbound** instead (no privilege escalation: an unverified caller can never inject content into attested tenants' reads). An unknown scope value is ignored (binds normally).
- Guard-side visible-key derivation (the only policy site): an attested reader's visible keys are `{Subject(), sharedScopeKey}`; an unattested/absent reader's are `{unboundKey, sharedScopeKey}`. So shared entries are readable under every identity class, and attested readers still do **not** see unbound entries (the shipped 009 behavior); shared is the one cross-tenant channel.
- `scope` on a `validate_read` identity is ignored entirely.

### 3. Reserved marker, forge-proof

The shared binding is a reserved `boundIdentity` marker constant `sharedScopeKey = "shared://"` (chosen because it is not a valid `spiffe://` URI). `boundKeyFor` maps any principal whose `Subject()` equals the marker to the unbound key, so **no caller can reach the shared binding by forging `spiffe_id`**. The only path to a shared-bound entry is an explicit attested `scope:"shared"`.

### Scope carriage mechanics (the readiness-gate decision)

Scope is carried by **adding `SharedScope() bool` to the `Principal` interface**, decoded by `principalFromMap` from the optional `scope` string into `PreVerifiedPrincipal`. Rationale: it keeps `boundKeyFor` free of type assertions (it already takes a `Principal`), and the deferred zero-trust `SvidVerifyingPrincipal` implements it naturally. The alternative (threading a separate `scope` argument through `ValidateWrite` only) was rejected because it splits the identity claim across two parameters and re-introduces the free-form carriage the `Principal` seam exists to replace. Scope is honored **only at write and only when attested**; the read path never consults it.

## Consequences

- `ValidateRead` goes through `ScanScoped`, not a guard-side filter (spy-store test proves exactly one `ScanScoped` call, zero `Scan` calls). All pre-shared cases are behavior-preserving; the task-009 `identity_isolation_test.go` suite passes unmodified.
- Isolation is now a property of the stored data: over `FileStore`, an independently constructed guard on the same path re-enforces the full matrix (A sees A+shared; B sees B+shared; unattested sees unbound+shared), proven across a simulated restart.
- PII redaction on the scoped result set is unchanged for every scope class; raw PII never appears in any reader's `content_redacted` nor in the store file.
- Substrate constraints hold: stdlib-only (`go.mod` require-free), no store/identity backend specifics past their seams, IPC error shape and the three response shapes unchanged.
- **Not in scope, deferred:** cryptographic principal verification (stays in agent-mesh, `SvidVerifyingPrincipal` deferred behind the `Principal` seam); per-identity physical partitioning inside an adapter; fine-grained ACLs / groups / multi-tenant scopes beyond the single shared scope (a future contract decision needing its own ADR). The stale roadmap T4/R1 rows are flagged to the operator, not edited (`docs/plans/` is ask-first).
