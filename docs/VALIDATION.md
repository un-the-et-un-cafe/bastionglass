# Validation record

Candidate date: 2026-10-30. This file records reproducible local checks, not certification.

## Private linked OpenSSL advisory increment — 2026-10-31

- 54 local unit tests passed, including eight new tests: older upstream 3.5 versions, fixed boundary, uncovered series, invalid/vendor/prerelease/oversized input, standard-date normalization, linked-library provenance, private-suffix non-echoing and CLI review-flag behavior.
- Compilation and patch whitespace checks passed. Inputs are synthetic; no malicious certificate or exploit was executed.
- Official advisory independently read before implementation. This rule does not establish application exposure or vendor backport status and deliberately does not cover every affected upstream series.
- Pending independent review and hosted CI for this exact increment; earlier hosted results do not apply to this change. Actual runtime observations remain private.

## GitHub checks

The pull-request workflow runs unit tests, Python compilation and patch whitespace checks on standard Ubuntu 24.04 runners with Python 3.12 and 3.14. This samples the documented Python 3.12+ range; it is not an exhaustive platform matrix. Python patch versions are resolved from the latest available patch within each selected minor and printed in the run log.

Official checkout/setup actions are pinned to complete commit IDs. The workflow grants only `contents: read`, does not persist checkout credentials, installs no project dependencies, and does not use secrets, deployment, packet capture or `pull_request_target`. PR-only triggers avoid duplicate branch-push runs; superseded PR runs are cancelled. Hosted success must be verified for the exact current PR head; the presence of this workflow is not a passing result.

Action pins verified against the maintainers' release tags and action definitions on 2026-10-30:

- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1): `3d3c42e5aac5ba805825da76410c181273ba90b1`.
- [actions/setup-python v7.1.0](https://github.com/actions/setup-python/releases/tag/v7.1.0): `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0`.

## Current private read-completeness increment

- `python3 -m unittest discover -s tests -v`: **46 tests passed** on Python 3.12.14.
- Four added tests exercise unexpected EOF without a metadata change, partial-read accounting without a returned hash, legitimate short chunks and empty files.
- `python3 -m py_compile bastionglass.py tests/test_bastionglass.py` and `git diff --check`: passed.
- The unchanged 42-test suite below remains historical evidence for the earlier candidate. This increment requires independent review before publication.
- Runtime patch-review flags remain unresolved; these trusted synthetic tests do not establish that the interpreter or host is fully patched.

## Earlier candidate checks

- `python3 -m unittest discover -s tests -v`: **42 tests passed**.
- `python3 -m py_compile bastionglass.py tests/test_bastionglass.py`: passed.
- Explicit self-scan of 11 selected first-party source, test, fixture and documentation files: all observed; zero heuristic candidate categories for that manifest.
- Runtime version observation: executed and produced patch-status review flags. The private report is intentionally excluded from the repository; those flags are not evidence of infection.
- Synthetic traffic fixture: two events; aggregate accounting and explicit `live_traffic_observed: false`, `payloads_inspected: false` verified.
- Tests demonstrate traversal/symlink/hardlink exclusions, special-file handling, bounded reads, mutation observations, strict synthetic-event parsing and non-echoing output in the listed cases.

The self-scan is not independent review and cannot detect every issue in its own implementation. Documentation and any later changes require a fresh check. No line/branch coverage percentage was measured.

## Independent local review

A separate review identified a mismatch between the strict UTF-8 contract and Python JSON byte decoding, which also accepted UTF-16/32. The parser now decodes strict UTF-8 before JSON parsing; a six-encoding regression test passes. A second reviewer reran all 42 tests. This is local source review, not external certification.

## Not executed or established

- No live network, packet, TLS, host, kernel or container-runtime audit.
- No malware execution, escape test, penetration test or external security certification.
- No Windows support, other Python/platform matrix or production-scale testing.
- No external report, OpenAI receipt, remediation, continuous monitor or automatic update.
- No guarantee that a pattern-free source file contains no credentials or vulnerabilities.
- No authenticated/signed release or hosted CI result is claimed by this local record.

## Repeat

Use a reviewed, patched runtime and rerun the README commands in an authorized workspace. Repeat the negative tests after filesystem/runtime changes. Review the explicit manifest and private report destination before each real scan. Independent reviewers should use `AUDIT.md`, inspect code and document their actual findings before publication/adoption.
