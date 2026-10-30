# Formats and extension contract

## Source observation API

`scan(workspace: str, project: str, files: list[str]) -> dict` accepts an explicitly authorized absolute workspace and relative project/file paths. Invalid manifests/boundaries raise `BoundaryError` with a fixed code. Per-file exclusions or read failures make `complete` false; processing can continue within the remaining read budget. No file contents or names are returned. API callers must catch `BoundaryError` and retain only its fixed code; do not forward diagnostic stack traces or argument values.

`bastionglass.scan.v1` contains: suite version, UTC observation time, scope, coverage declarations, runtime observations, manifest fingerprint, per-file records, total bytes read, completeness, candidate finding count and the constant `security_verdict: not_provided`.

A file record contains its **manifest index**, status, and either a fixed rejection reason or SHA-256/byte count/findings. Indices can be mapped locally to the caller's ordered manifest; do not publish that mapping without review. The fingerprint binds project-relative identity and the ordered file list, not a machine identity or absolute workspace. Identical project names/content on different machines can have matching fingerprints.

`complete` covers requested file observations, not complete vulnerability coverage. `candidate_findings` counts matching rule categories across files, not proven vulnerabilities or affected lines. Each category's `matches` caps at 1,000; `matches_capped` declares truncation. File hashing uses SHA-256; this is integrity comparison, not authentication.

## Baseline comparison

`compare_baseline(report, approved_baseline)` requires a baseline object with exactly `manifest_sha256` and `hashes` (ordered SHA-256 strings, one per manifest file). This is an in-memory API, not a loader or trust store. Only pass a report produced by the suite and a separately reviewed baseline. Mismatched/incomplete scopes return `not_comparable`; altered content returns changed indices. The function never writes, signs, approves, creates or updates a baseline.

## Synthetic traffic schema

Top-level exact keys:

```json
{"schema":"bastionglass.traffic.v1","source":"synthetic","events":[]}
```

Each event has exactly:

- `direction`: `in` or `out`
- `transport`: `tls`, `plaintext` or `unknown`
- `destination_policy`: `approved`, `unapproved` or `unknown`
- `bytes`: integer 0..1,073,741,824, not a boolean

No endpoint strings or content fields are accepted. All events are explicitly synthetic. The summary returns aggregate byte/event counts and sets `live_traffic_observed` and `payloads_inspected` to false. A synthetic TLS label does not demonstrate a real handshake, certificate validation or encryption.

Malformed UTF-8/JSON, duplicate keys, nonfinite constants, oversized/deep inputs, extra fields, wrong enums and wrong numeric types are rejected with `invalid_traffic_fixture`. Rejected values are never echoed. There is no XML, archive or packet parser.

## Extension rules

- Keep changes versioned. Incompatible input/output changes require a new schema identifier and migration tests.
- New rules must be deterministic, bounded, reviewable and have benign positive/negative fixtures. Never add a rule that executes the content it inspects.
- Each new data source requires an explicit permission/data-retention design. Do not silently turn the synthetic adapter into a live collector.
- Never place arbitrary input, source text, credential values, URLs, headers or OS error strings into reports.
- An inventory method must not import inspected project code, execute package hooks or shell out to arbitrary commands.
- Changing a default from read-only to mutation, network capture or reporting is a new capability requiring separate owner authorization and a new threat review.
