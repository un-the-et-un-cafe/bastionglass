# Threat model and data flow

Status: v0.1.0 prototype. Reviewed documentation date: 2026-10-30.

## Assets

Credentials, private source/data, customer content, integrity of reviewed work, accurate security findings and the owner's authority to stop or pause work. A scan must not create a second leak through logs, stack traces, generated reports or publication artifacts.

## Boundaries

| Boundary | Implemented behavior | Limit |
|---|---|---|
| Invocation → filesystem | Explicit absolute workspace, relative project and explicit file list | The owner/caller must authorize that workspace; this is not an OS permission boundary |
| Path → opened object | Reject dot/traversal components, follow no symlinks, use directory descriptors, reject hardlinks/non-regular files | Does not defeat hostile kernel/root, mount replacement or all same-user mutation scenarios |
| Source → findings | Strict UTF-8, bounded content, fixed rule IDs/counts, no matching values or filenames | Selected heuristics miss obfuscated, encoded, contextual and novel threats; comments can match |
| Opened object → digest | Compare size, inode/device and modification/change metadata before/after reading | Not an atomic filesystem snapshot; same-user adversarial races are not comprehensively defeated |
| Baseline → comparison | Explicitly supplied ordered manifest/hash binding; no auto-approval or writes | A compromised or unreviewed baseline cannot establish trust |
| Runtime → advisory status | Public version observations plus two fixed, dated comparisons | No complete CVE database; backports, trust stores, host runtime and kernel remain unknown |
| Synthetic events → traffic summary | Exact keys/enums, no raw endpoints/payload, aggregate counts only | No live traffic or TLS plaintext is observed |
| Findings → outside parties | No transport or submission implementation | Human/private review and applicable approval required before any future disclosure |

## Data flow

The CLI parses workspace/project/file arguments. `open_workspace` opens the explicit workspace component by component; `open_project` opens the project relative to that descriptor. `read_source` opens each allowlisted file without following links, checks its metadata and reads within limits. `inspect_source` produces hashes, byte counts and candidate rule counts. `scan` assembles a report, adds public runtime version observations and prints it through `main`.

Selected source bytes temporarily enter process memory so that patterns and hashes can be computed. Python memory is not securely zeroized; this suite is not a secret vault or a defense against a compromised interpreter/kernel. Paths are used internally for reading but are not emitted in normal reports. Invalid paths and OS errors become fixed reason codes. CLI errors do not echo rejected arguments. No environment variables, credentials, process environment, browser storage, user home, system logs or provider connector content are inspected. No source is executed by scanning; the scanner and tests themselves must be reviewed before execution.

The synthetic traffic API accepts bytes directly, validates a fixed JSON schema and returns counters. No input event is retained in the output. This is a separate function, not an automatic input collector.

## Resource ceilings

128 files; 256 KiB per file; 4 MiB total source bytes read, including failed/raced reads; 512 UTF-8 bytes per relative path and at most 12 components. Source reports contain at most six rule entries per observed file. Traffic fixtures: 64 KiB, at most 256 events, maximum 2^30 bytes as a numeric measurement per event. These are **input limits**, not CPU/RAM quotas enforced by an external sandbox.

## Current scope and enduring boundaries

v0.1.0 does not implement exploit execution, kernel probing, live packet inspection, TLS interception, eBPF, VPN integration, host firewall changes, malware detonation or automatic deletion/quarantine. This describes today's implementation, not a permanent exclusion of defensive capabilities. The [roadmap](ROADMAP.md) defines future detection, enforcement, network visibility and response work with separate permission and validation gates. No future capability is authorized merely by appearing on that roadmap.

Enduring constraints: no perfect security or uptime guarantee, anti-forensics, bypassing platform shutdown/oversight, unauthorized persistence, or acquisition of accounts, credentials or compute by the suite. Owner-authorized service integration may use scoped credentials through supported secret storage; it must not harvest login sessions or bypass provider restrictions. No version can prove that a container cannot escape or that an unobserved host is patched. Recovery and remediation must honor the owner's stop/pause and platform controls.

An empty finding list means only that the selected patterns did not match the selected readable files. It must never be rewritten as “no malware,” “vulnerability-free,” or “all traffic secure.”
