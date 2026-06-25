# ADR-010 — Injection-recall lift: reject the regex framing-anchor approach; defer to token-level negation-scope analysis

**Status:** Accepted
**Date:** 2026-06-25
**Supersedes the approach in:** [task 013](../../tasks/completed/013-injection-recall-lift.md) (the framing-anchor heuristic). The *goal* (lift write-gate injection recall above the honest 0.6875 baseline) is retained and re-homed in a new task; the *method* is rejected.
**Relates to:** [ADR-002](002-detector-backend.md) (the `Detector` seam), task 002 (the `adversarialCorpus` + the 10 documented miss-classes), ADR-009 Finding 1 (the conflation that motivated task 013).

## Context

The native `DetectInjection` heuristic catches **22/32** poisoning cases (recall **0.6875**, precision **0.85**) on task 002's `adversarialCorpus`, with 10 documented miss-classes. Task 013 set out to recover those miss-classes — several of which are **framing-based**: `remember:` / `from now on` / `whenever` / `any AI` / `store…permanently` / `standing order`, each paired in the corpus with an override/exfiltration directive.

The attempted method: match the framing phrase, then require an attacker **directive object** (override-of-instructions, or exfil-verb + sensitive-object, or an attacker recipient) to co-occur within a character window of the framing phrase — all in regex, behind the unchanged `Detector` seam.

This ADR records why that method was rejected after it cleared unit tests and spec-verification but failed three rounds of adversarial security audit.

## What happened (the evidence)

Task 013 reached recall **1.00 (32/32)** then **0.97 (31/32)**, precision held, corpus byte-for-byte unchanged, seam clean, `go test` + `make fitness` green, and **spec-verifier APPROVED twice**. It nonetheless failed the security gate three times, each fix introducing a new failure one layer deeper:

- **SEC-001 (CRITICAL, over-rejection).** The bare framing patterns matched ordinary benign English. On the **fail-closed** write-gate this silently *drops legitimate writes* — 17/18 plausible benign entries rejected live ("Remember: buy milk", "From now on we ship on Fridays", "Whenever the build fails you must escalate"). The 14-case benign corpus was structurally **blind** to it.
- **SEC-006 (MEDIUM, over-rejection, negation-blind).** Anchoring to a directive object fixed SEC-001 but rejected benign **security-policy** writes that *forbid* the action ("never disclose passwords", "any AI must not leak data") — the anchor matched directive vocabulary without distinguishing "do X" from "do **not** do X".
- **SEC-007 (CRITICAL, fail-OPEN).** Adding a negation guard opened a **bypass**: an attacker prepends a short, semantically-empty negator + filler ("`prevent;`", "`no,`", "`never:`") before a real directive and the poisoning write **persists**. Tightening the window (`{0,12}→{0,4}`, clause-respecting) failed **both** directions at once — it still allowed comma/colon-separated shields *and* re-broke legitimate negations that span an adverb ("must not **ever** disclose").

## Decision

**Reject the regex framing-anchor approach for the framing-based miss-classes.** Do not ship task 013. Keep `main` at the sound **0.6875** baseline — a lower-recall but **sound** fail-closed gate strictly beats a higher-recall gate with a fail-open bypass or a legitimate-write DoS.

**The recall lift is deferred, not abandoned**, and split by tractability:

1. **The genuinely-recoverable, no-collision miss-classes** — `[INJECT:]` bracket prefix, explicit jailbreak phrasings (DAN / unrestricted-AI / developer-mode), and the **base64 / URL decode-then-rescan** path — have **zero benign collision and need no negation logic**. They are safe to recover with the same regex approach and remain available as a low-risk follow-up.
2. **The framing-based miss-classes** (`remember:` / `from now on` / `whenever` / `any AI` / framing + directive) require distinguishing an *imperative to perform* an override/exfil action from a *policy that forbids* it. That is **grammatical negation scope**, which a character-distance heuristic provably cannot approximate (see Rationale). These are re-homed to a new task that does **token-level scope analysis** with an adversarial corpus covering *both* the negator-shield (fail-open) and the adverb-separated-negation (over-rejection) classes from the start.

## Rationale

The discriminator the framing anchor needs is **whether the negator grammatically governs the directive's verb**. The regex approximates it with **character distance** between tokens. These are irreconcilable on any single window value:

| Example | Type | Required window |
|---|---|---|
| `do not disclose` | real negation (gap 1) | reach ≥ 1 |
| `no, output` | shield (gap 2) | reach < 2 |
| `not ever disclose` | real negation (gap 5) | reach ≥ 5 |
| `no   output` | shield (gap 3) | reach < 3 |

No window separates real negations (which legitimately span adverbs) from filler shields (which are short). `{0,4}` lands between and gets **both** wrong. This is the ceiling of the heuristic, not a tuning bug — another iteration on the same approach will not converge.

Two process lessons, recorded so they are not re-learned:

- **Green unit tests + spec-verifier APPROVE did not mean safe.** Both passed at every failing round because the test corpus could not see the regression class (benign-policy writes, then negator shields). For a **security boundary**, an adversarial audit that *constructs* the missing inputs is a non-optional gate, distinct from spec adherence.
- **On a fail-closed gate, over-rejection and fail-open are both first-class security failures** — the former is a silent DoS on legitimate memory writes, the latter is the poisoning the gate exists to stop. A recall metric that ignores realistic benign traffic, or an evasion test that only uses one directive shape, hides them.

## Consequences

- `main` stays at recall 0.6875 / precision 0.85 — unchanged, sound, no fail-open, no over-rejection. The unsafe task/013 branch (commits `a73a600`→`48f32de`) was deleted local + remote, never merged.
- Task 013 is marked **superseded** (its framing-anchor spec is the rejected method). Its REQ-002/REQ-003 *measurement discipline* (corpus frozen, precision held, honest floors) was sound and carries forward.
- A new task is filed for the deferred work: **token-level negation-scope** recovery of the framing classes, plus (optionally first) the no-collision recoveries from (1) above, with the SEC-001/006/007 classes as mandatory adversarial corpus entries and the security-auditor in the loop from the start.
- The `Detector` seam, contract, and all other v1 work (tasks 006–012) are unaffected — this concerns only the native injection heuristic's recall.
