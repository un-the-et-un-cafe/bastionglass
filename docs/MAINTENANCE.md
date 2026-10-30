# Reviewed maintenance and compatibility

## Change process

1. Identify a concrete Dot/runtime capability change or official advisory, recording source, date, affected versions, known mitigations and unknowns.
2. Reassess data access, privileges and trust boundaries before designing a check.
3. Add bounded benign fixtures and regression tests; never run a container escape or real malicious payload merely to test this suite.
4. Implement the smallest change. Keep dependencies at zero where practical. Any future dependency needs official provenance, pinning, license review and its own patch process.
5. Conduct independent review and run all existing tests. Recheck redaction and failure paths.
6. Save a verified owner-controlled checkpoint. Adopt only after applicable approvals; rollback to the prior reviewed version if needed.
7. Retire stale advisory assumptions explicitly. Never silently mark a component patched because a version string is newer or a command is absent.

No unattended rule download, generated-code execution, model-driven patching, automatic baseline acceptance or automatic privilege escalation is implemented. Daily research can propose changes; it does not authorize deploying them. Owner pause/stop takes precedence over recovery or scheduled checks.

## Compatibility matrix

| Surface | v0 evidence | Required future check |
|---|---|---|
| POSIX descriptor-relative filesystem | Tested in the current workspace | Repeat boundary/race tests after runtime changes |
| Python 3.12+ standard library | Current tests run on Python 3.12.14 | Confirm provider backports or a patched environment before untrusted processing |
| Windows filesystem | Not supported by this implementation | Separate handle/reparse-point design and tests; do not weaken checks for compatibility |
| Host kernel/container runtime | Unknown; not inspected | Provider confirmation, not absence of a CLI binary |
| Dot tool/connector requests | Not observed | Provider-supported, authorized telemetry contract |
| Live network payloads | Not observed or captured | Separate privacy/security/legal review and supported capture mechanism |
| Browser TLS/session state | Not inspected | Do not extract cookies or install interception certificates |
| Remote API billing/credits | Not inspected | Separate authorized accounting source |

## Advisory snapshot

The initial curated rules reference Python's official 3.12.16 security release, checked 2026-10-30:
https://www.python.org/downloads/release/python-31216/

That release discusses compromised-CA distrust, archive-filter fixes and Expat 2.9.0. The scanner flags an older observed Python 3.12 or Expat 2.x version for **patch-status review**. It does not establish exploitability, absence of vendor backports, or compromise. Other Python series and dependencies are outside this two-rule snapshot. Runtime source dates are emitted in each advisory record. The snapshot does not update itself; maintainers must review official releases before relying on it later.

A version update can break project compatibility. Prefer a provider-patched runtime or a reviewed isolated project environment. Never overwrite a managed platform interpreter as an incidental scanner action. Rebuild pinned environments and rerun project tests plus a clean restore before adoption; required downtime is unknown until measured.
