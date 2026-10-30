# BastionGlass

**Small, inspectable security observations for owner-controlled AI workspaces.**

BastionGlass is an early, dependency-free defensive prototype. It helps review explicitly selected source files, notice selected runtime patch gaps, compare reviewed file hashes and test privacy-preserving traffic-metadata rules against synthetic events.

It is **not** an antivirus, EDR, firewall, sandbox, network monitor, security certification or proof that a workspace is safe. It cannot guarantee freedom from present or future vulnerabilities. No live packet capture, TLS interception, account access, automatic incident submission or automatic remediation is implemented.

## What works in v0.1.0

- Explicit workspace, project and file manifest. No recursive discovery of a home directory, credentials, Git history or unrelated projects.
- Component-by-component directory opens with `O_NOFOLLOW`; regular single-link files only. Symlinks, hardlinks, special files and dot paths are rejected.
- Bounded UTF-8 source scanning with six small, auditable heuristic rules. Findings contain rule identifiers and counts, not matching text or paths.
- Python, Expat and OpenSSL version observations, with two dated, curated patch-review rules. Vendor backports and host configuration remain unknown.
- Read-only comparison against a separately reviewed, manifest-bound hash baseline. Hash matches never establish safety.
- Strict **synthetic-only** traffic-event analysis. It rejects payload, URL, hostname, IP, cookie and credential fields instead of attempting unreliable redaction.
- No application network calls, subprocess execution, package installation, privilege changes, file modification, self-update or external reporting.

## Run without installing

Requires Python 3.12+ on a POSIX platform supporting descriptor-relative opens, `O_NOFOLLOW` and `O_DIRECTORY`. Platform security maintenance remains the environment provider's responsibility. Review the source before running.

From a checkout called `bastionglass` inside an authorized workspace:

```sh
python3 -m unittest discover -s tests -v
python3 bastionglass.py \
  --workspace /absolute/authorized/workspace \
  --project bastionglass \
  --file bastionglass.py \
  --file tests/test_bastionglass.py
```

Run the second command from the repository directory. `--workspace` is an explicit absolute directory; `--project` and each `--file` are relative paths. Shell expansion is not supported by the scanner. Do not pass tokens or secrets as arguments.

JSON goes to standard output. Save it **outside the source/publication tree** only if needed, using a destination already protected by the environment. Reports disclose runtime versions, file lengths and hashes; treat them as private even though source text and filenames are omitted. The suite neither configures storage permissions nor encrypts reports. `.gitignore` is defense in depth, not a sharing boundary.

Exit codes: `0` means every requested source file was observed with no heuristic candidates and no curated runtime patch-review flag; `1` means review is needed or a file was not scanned; `2` means the invocation or workspace boundary was rejected. None is a comprehensive security verdict.

For synthetic traffic tests, use `analyze_synthetic_traffic` with `fixtures/traffic-synthetic.json` through the documented Python API. There is deliberately no live-capture CLI.

## Audit and extend

1. [Audit guide and rule/test map](docs/AUDIT.md)
2. [Threat model, boundaries and data flow](docs/THREAT_MODEL.md)
3. [Formats and extension contract](docs/CONTRACTS.md)
4. [Evidence and validation limits](docs/VALIDATION.md)
5. [Reviewed update and compatibility process](docs/MAINTENANCE.md)
6. [Network visibility and incident escalation](docs/NETWORK_AND_REPORTING.md)
7. [Security reporting policy](SECURITY.md)

The intended improvement loop is **reviewed rules → tests → evidence → owner-authorized adoption**. It is not autonomous self-modification or expansion of access. Any future Dot capability must be separately checked against the compatibility matrix and threat model.

## License

Apache-2.0. See [LICENSE](LICENSE). This project is independent and is not endorsed by OpenAI or any other provider. Product names identify compatibility or disclosure destinations, not sponsorship.
