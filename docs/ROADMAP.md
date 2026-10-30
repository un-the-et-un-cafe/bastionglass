# Capability roadmap and evidence gates

Status: proposed development direction, 2026-10-30. This document changes no runtime permissions or behavior. The current executable remains v0.1.0. There is no promised delivery date, funded deployment, certification or guaranteed detection rate.

## Implemented versus intended

| Capability | Implemented in v0.1.0 | Intended development |
|---|---|---|
| Malware and vulnerability detection | Six source heuristics and two curated runtime patch-review rules | Broader evidence-backed detection, advisory coverage and safe integration with maintained scanners |
| Endpoint detection and response (EDR) | No event collector or response engine | Supported, scoped endpoint telemetry, correlated findings and reversible response |
| Firewall and policy enforcement | No network or host setting changes | Provider-supported egress policies and least-privilege enforcement |
| Sandbox integration | Read-only path controls within the existing environment | Validate and integrate supported isolation controls; never bypass the host boundary |
| Network visibility and deep inspection | Synthetic metadata counters only | Authorized metadata first; separately reviewed, narrowly scoped deep inspection where lawful, supported and justified |
| Service/account integration | No account access or credential handling | Owner-approved integrations using least-privilege scoped access and supported secret isolation |
| Incident reporting | Private template and evidence criteria only | Approved redacted reports to verified recipients with receipts and an owner stop |
| Remediation and recovery | No mutation or quarantine | Bounded, reversible actions with tested rollback and durable owner-controlled recovery |
| Independent assurance | Local tests and limited independent code review | Independent assessment and penetration testing in explicitly authorized test environments; external certification only if applicable and actually obtained |

## Phased delivery

### 1. Strengthen the observation foundation

Expand benign regression fixtures, dated advisory coverage and platform compatibility. Maintain an explicit supported-version matrix and known coverage gaps. Additions must preserve source minimization and bounded execution. Gate: all existing tests pass; each new rule has positive, negative, malformed and resource-bound tests; reviewers approve the threat-model delta.

### 2. Add supported telemetry and detection integrations

Design an opt-in adapter interface for provider-authorized event sources and maintained scanners. Begin with local or aggregate metadata, not private message bodies or session state. Exercise fixtures in an isolated test environment before connecting real telemetry. Gate: document exact permissions, fields, retention and deletion; test forbidden-field rejection; measure dropped events, false positives and false negatives on a versioned labeled evaluation corpus. Publish corpus limits rather than treating a synthetic score as production efficacy.

### 3. Introduce prevention and enforcement

Integrate approved firewall/egress and sandbox policies through supported mechanisms. Capability detection must fail closed for enforcement requests it cannot safely satisfy, while clearly reporting unobserved areas. No denied host access or privilege workaround. Gate: dry-run policy diffs, authorization checks, regression and interruption tests, measured overhead and tested rollback in a disposable authorized environment. Never change a managed host as an incidental rule update.

### 4. Evaluate deep network inspection separately

Metadata visibility precedes packet/content inspection. Document who owns each traffic flow, which interfaces are accessible, the privacy/security implications and whether encrypted content can or should be inspected. A packet capture does not imply visibility into TLS plaintext. Prefer designs that never retain credentials or user content. Gate: explicit authorization and supported capture facilities; independent threat/privacy review; tests for content exclusion, retention limits, access controls, redaction and failure modes. No TLS interception, certificates, VPN or persistent collector is enabled by this plan. Reject an integration if its collection risks cannot be bounded.

### 5. Add controlled incident response

Start with reviewable dry-run actions and minimal incident drafts. Later, specifically approved standing policies may permit bounded reports or reversible containment; unknown cases remain review-required. Reporting requires verified secure destinations, evidence thresholds, deduplication, rate limits and delivery receipts. Remediation requires precise target/action allowlists, a preview, rollback and stop/pause handling. Gate: benign incident simulations, false-alarm tests, interrupted/repeated-action tests and restoration verification. Never send full reports, private source or secrets by default.

### 6. Independent assurance and sustained maintenance

Commission independent assessment when resources and authorization exist; separate any certification scheme's scope from general safety claims. Retest after material model, tool, runtime or provider-interface changes. Changes enter through review, reproducible tests and versioned releases, not autonomous privilege growth. A failed gate blocks that feature's adoption, not honest reporting of the limitation.

## Measurable release gates

Before each capability is enabled, its release proposal must specify and measure:

- Detection precision/recall or false-positive/false-negative counts on a disclosed labeled corpus, including uncertainty and untested threats.
- Maximum memory, CPU time, event rate, storage and network overhead on declared hardware; explicit pass/fail budgets chosen before evaluation.
- Zero forbidden fields emitted in the privacy regression corpus; this is a test result, not proof against every leak.
- Permission-denial, malformed-input, race, retry, interruption and owner stop tests.
- Rollback success and recovery time in the declared test environment; no uninterrupted-service promise.
- Independent review of new trust boundaries and, where applicable, authorized penetration testing before production adoption.

No universal efficacy percentage or resource SLA is invented here. Phase-specific thresholds must be justified and approved before testing, and results must identify failures and coverage gaps. Public releases contain safe source and synthetic fixtures; real telemetry, credentials, customer data, private baselines and incident evidence stay out of the repository.
