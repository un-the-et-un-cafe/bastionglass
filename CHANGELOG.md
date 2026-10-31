# Changelog

## Unreleased linked OpenSSL advisory review — 2026-10-31

- Add a bounded, dated CVE-2026-35189 upstream 3.5 review, with explicit unknown exposure/backports and uncovered versions.
- Normalize Python-linked OpenSSL version output; never echo raw vendor/private suffixes or substitute a CLI observation.
- Add eight synthetic regression tests. No runtime upgrade, network access, dependency or automatic report.

## Unreleased read-completeness hardening — 2026-10-30

- Reject unexpected early EOF instead of reporting a truncated prefix as a complete file observation.
- Preserve the read budget for rejected partial reads; do not return their hashes or findings.
- Add four regression tests for immediate/partial EOF, normal short chunks and empty files.
- No new file scope, permissions, network access or automatic response.

## 0.1.0 candidate — 2026-10-30

Initial bounded source observation suite, explicit path and resource boundaries, redacted heuristic findings, dated runtime patch-review observations, manifest-bound hash comparison and synthetic traffic-metadata validation. No live traffic monitoring, autonomous updates, automatic reports, remediation or security guarantee.

## Unreleased documentation clarification

- Distinguish current prototype limits from intended comprehensive defense capabilities.
- Add phased detection, enforcement, network visibility and response roadmap with privacy, permission and measurable validation gates.
- No executable changes or newly enabled capabilities.
