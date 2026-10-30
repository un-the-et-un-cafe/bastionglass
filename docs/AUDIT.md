# Auditor's guide

## Shortest useful audit

1. Read `THREAT_MODEL.md` and confirm the deployment uses only an authorized project allowlist.
2. Review the sole runtime module, `bastionglass.py`, from imports through CLI. No third-party dependencies or plugin loading exists.
3. Inspect all path opens: `open_workspace`, `open_project`, `read_source`. Check descriptor lifetime, `O_NOFOLLOW`, regular-file/single-link rules, size accounting and metadata comparisons.
4. Review each `RULES` pattern. They are candidate heuristics, not malware verdicts; confirm matches never leave memory as plaintext.
5. Review report construction and `RedactedParser.error`. Confirm no path, source excerpt, environment value or raw exception enters reports.
6. Review `analyze_synthetic_traffic`. Exact-key validation is intentional; there is no network collector.
7. Run the test suite and inspect negative tests. Review the explicit false-positive and false-negative examples.
8. Inspect publication files individually. Do not commit scan reports, real traffic, baselines or private source even if `.gitignore` would allow them.

## Rule-to-test map

All named tests are in `tests/test_bastionglass.py`.

| Runtime rule or contract | Direct evidence |
|---|---|
| `secret.private_key_marker` | `test_private_key_marker_candidate` |
| `secret.literal_credential_candidate` | `test_secret_candidates_never_echo_value` |
| `code.dynamic_execution_candidate` | `test_code_heuristics_are_candidates_not_malware`, `test_comments_can_be_false_positives` |
| `code.shell_execution_candidate` | `test_code_heuristics_are_candidates_not_malware` |
| `code.unsafe_deserialization_candidate` | `test_code_heuristics_are_candidates_not_malware` |
| `code.tls_verification_disabled_candidate` | `test_code_heuristics_are_candidates_not_malware` |
| No complete-detection claim | `test_obfuscated_example_is_explicit_detection_limit`, `test_no_live_visibility_claim` |
| Sensitive path exclusion | `test_sensitive_names_rejected`, `test_workspace_broad_and_sensitive_roots_rejected` |
| Traversal/symlink/hardlink exclusion | `test_path_traversal_and_dotpaths_rejected`, all symlink tests, `test_hardlink_rejected` |
| Nonblocking special-file rejection | `test_fifo_does_not_block`, `test_directory_is_not_source` |
| File and total read limits | `test_file_size_cap`, `test_total_cap_marks_incomplete`, `test_failed_read_bytes_still_count_against_total_budget` |
| Complete-read accounting | `test_early_eof_is_not_a_complete_observation`, `test_partial_read_then_eof_retains_accounting_without_hash`, `test_short_chunks_that_reach_expected_size_are_accepted`, `test_empty_file_is_a_complete_zero_byte_observation` |
| Race observations | `test_opened_descriptor_survives_path_replacement_without_following_link`, `test_content_mutation_during_read_is_rejected`, `test_symlink_swap_before_open_is_rejected` |
| Redacted reports/errors | `test_safe_scan_has_no_contents_or_paths`, `test_missing_file_error_is_fixed_and_redacted`, `test_invalid_cli_arguments_are_redacted` |
| Explicit baseline binding | `test_hash_baseline_is_read_only_and_explicit`, `test_baseline_scope_or_incomplete_cannot_match` |
| Runtime evidence limits | `test_runtime_observation_labels_backports_and_coverage_unknown` |
| No network/subprocess imports | `test_no_subprocess_or_network_imports` (structural check only, not a sandbox) |
| Synthetic-only traffic | `test_live_input_rejected`, `test_aggregate_only` |
| No private network fields | `test_payload_and_destination_fields_rejected`, `test_unknown_enums_rejected` |
| Traffic parser bounds | `test_size_event_and_number_limits`, `test_duplicate_nonfinite_nested_and_malformed_rejected`, `test_utf16_and_utf32_are_rejected_even_with_valid_json` |

## Review gates

- Unit tests must pass. A failed security-negative test blocks adoption.
- Source read/write/network behavior must match documentation and permission design.
- Every new finding class must declare evidence strength, likely false positives and detection gaps.
- Verify archive and commit hashes independently before distribution. Signing/authentication is separate from hashing.
- At least one independent code review is required before treating a release candidate as reviewed. Independent review is not an external penetration test or certification.
- Do not claim a percentage of security coverage from test counts. Tests demonstrate only their stated cases.

## Publication checklist

Publish only the reviewed source, synthetic fixtures, tests, documentation and license. Keep runtime observations and local reports private. Check staged files, all committed history and generated archives for accidental data. A clean heuristic secret scan cannot prove that all sensitive data was excluded; manual file review remains necessary.
