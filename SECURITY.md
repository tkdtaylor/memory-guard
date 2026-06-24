# Security Policy

## Supported versions

memory-guard has not yet cut a tagged release. Until a `v1.0.0` ships, only the
current `main` branch receives security fixes. This table will be filled in once
releases begin.

| Version | Security fixes |
|---------|---------------|
| `main` (pre-release) | ✅ Yes |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/memory-guard/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (the input text / memory payload that slipped through)
- The commit or `main` state you observed it on
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

Encrypt with PGP if you prefer — open an issue requesting a public key and
we will publish one.

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

**In scope:**

- A write-gate bypass: PII or secrets reaching the underlying MemoryStore that the
  detector/redactor should have caught or blocked
- A redaction bypass: input crafted so a known PII/secret category is not redacted
  (regex evasion, encoding tricks, unicode confusables)
- Post-deletion verification returning a false "deleted" when data persists
- Memory-poisoning paths the adversarial suite is meant to catch (injection of
  attacker-controlled content that survives the gate)

**Out of scope:**

- False positives (over-redaction) that are not an information-disclosure issue —
  file a regular issue
- The example/test detection fixtures under the test suite (e.g.
  `AKIAIOSFODNN7EXAMPLE`) — these are deliberately non-secret test vectors
- Vulnerabilities in upstream detectors (e.g. Microsoft Presidio) or third-party
  libraries with no exploitable path through memory-guard
- Findings that require an already-compromised host or operator-supplied
  malicious configuration

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.
