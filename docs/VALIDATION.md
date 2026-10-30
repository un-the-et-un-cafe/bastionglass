# Validation record

Candidate date: 2026-10-30. This file records reproducible local checks, not certification.

## Executed

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
