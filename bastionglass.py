# SPDX-License-Identifier: Apache-2.0
"""BastionGlass: bounded local observations, never a security verdict."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
import sys
import ssl
from xml.parsers import expat

VERSION = "0.1.0"
MAX_FILES = 128
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_TRAFFIC_BYTES = 64 * 1024
MAX_EVENTS = 256
ALLOWED_SUFFIXES = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".c", ".h", ".java", ".kt", ".swift", ".md", ".txt", ".json", ".toml", ".yml", ".yaml", ".css", ".html"}
BLOCKED_NAMES = {"credentials", "secrets", "passwords", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts", "config.json", "token.json", "tokens.json", "credentials.json", "secrets.json", "package-lock.json"}
RULES = (
    ("secret.private_key_marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("secret.literal_credential_candidate", re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|client[_-]?secret)\s*[=:]\s*['\"][^'\"\r\n]{12,256}['\"]")),
    ("code.dynamic_execution_candidate", re.compile(r"\b(?:eval|exec)\s*\(")),
    ("code.shell_execution_candidate", re.compile(r"\bshell\s*=\s*True\b|\bos\.system\s*\(")),
    ("code.unsafe_deserialization_candidate", re.compile(r"\bpickle\.(?:load|loads)\s*\(")),
    ("code.tls_verification_disabled_candidate", re.compile(r"\bverify\s*=\s*False\b|_create_unverified_context\s*\(")),
)
COVERAGE = {
    "live_network_capture": "not_implemented",
    "tls_payload_inspection": "not_implemented",
    "host_runtime_and_kernel": "unknown",
    "provider_connector_traffic": "not_observed",
    "malware_execution_detection": "not_established_by_static_scan",
    "advisory_feed": "curated_snapshot_not_complete_or_live",
    "external_reporting": "disabled",
}


class BoundaryError(Exception):
    """Fixed-code failure. Never include untrusted values or OS error text."""


def reject(code: str) -> None:
    raise BoundaryError(code) from None


def relative_parts(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        reject("invalid_path")
    try:
        if len(value.encode("utf-8")) > MAX_PATH_BYTES:
            reject("invalid_path")
    except UnicodeEncodeError:
        reject("invalid_path")
    parts = value.split("/")
    if len(parts) > 12 or any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,100}", p) for p in parts):
        reject("invalid_path")
    if any(p.lower() in BLOCKED_NAMES or p.lower().startswith(("secret", "credential", "password")) for p in parts):
        reject("excluded_path")
    return tuple(parts)


def _directory_flags() -> int:
    if not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC")) or os.open not in os.supports_dir_fd:
        reject("unsupported_platform")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@contextmanager
def open_workspace(path: str):
    """Open an explicit absolute workspace component-by-component without links."""
    if not isinstance(path, str) or not path.startswith("/") or path in ("/", "/home", "/tmp", "/workspace"):
        reject("invalid_workspace")
    parts = relative_parts(path[1:])
    if len(parts) < 2 or parts[0] in {"proc", "sys", "dev", "etc", "root", "home"}:
        reject("invalid_workspace")
    fd = None
    try:
        fd = os.open("/", _directory_flags())
        for part in parts:
            child = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError:
        reject("workspace_unavailable")
    finally:
        if fd is not None:
            os.close(fd)


@contextmanager
def open_project(workspace_fd: int, project: str):
    parts = relative_parts(project)
    fd = os.dup(workspace_fd)
    try:
        for part in parts:
            child = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    except OSError:
        reject("project_unavailable")
    finally:
        os.close(fd)


def read_source(project_fd: int, relative: str, limit: int = MAX_FILE_BYTES, *, accounting: list[int] | None = None) -> bytes:
    parts = relative_parts(relative)
    if PurePosixPath(parts[-1]).suffix.lower() not in ALLOWED_SUFFIXES:
        reject("unsupported_file_type")
    if type(limit) is not int or not 0 <= limit <= MAX_FILE_BYTES:
        reject("invalid_read_limit")
    directory = os.dup(project_fd)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, _directory_flags(), dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            reject("non_regular_or_linked_file")
        if before.st_size > limit:
            reject("file_limit")
        chunks = []
        count = 0
        while count < limit:
            chunk = os.read(fd, min(65536, limit - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if accounting is not None:
                accounting[0] += len(chunk)
            if count > limit:
                reject("file_limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            reject("file_changed_during_read")
        if count != before.st_size:
            reject("incomplete_file_read")
        return b"".join(chunks)
    except OSError:
        reject("file_unavailable")
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def inspect_source(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE_BYTES:
        reject("file_limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        reject("unsupported_encoding")
    if "\x00" in text:
        reject("unsupported_encoding")
    findings = []
    for rule_id, pattern in RULES:
        count = sum(1 for _ in pattern.finditer(text))
        if count:
            findings.append({"rule_id": rule_id, "matches": min(count, 1000), "matches_capped": count > 1000, "classification": "candidate_requires_review"})
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "findings": findings}


def runtime_observation() -> dict:
    python = tuple(sys.version_info[:3])
    expat_version = tuple(expat.version_info)
    advisories = []
    for component, observed, known_series, fixed, url in (
        ("python", python, (3, 12), (3, 12, 16), "https://www.python.org/downloads/release/python-31216/"),
        ("expat", expat_version, (2,), (2, 9, 0), "https://www.python.org/downloads/release/python-31216/"),
    ):
        status = "patch_status_review_required" if observed[:len(known_series)] == known_series and observed < fixed else "no_older_version_flag_for_this_rule"
        advisories.append({"component": component, "status": status, "source": url, "evidence_checked_on": "2026-10-30", "vendor_backports": "unknown", "not_a_comprehensive_vulnerability_assessment": True})
    return {"python": ".".join(map(str, python)), "expat": ".".join(map(str, expat_version)), "openssl": ssl.OPENSSL_VERSION, "advisories": advisories}


def scan(workspace: str, project: str, files: list[str]) -> dict:
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES or any(not isinstance(name, str) for name in files) or len(set(files)) != len(files):
        reject("invalid_manifest")
    for name in files:
        relative_parts(name)
    report = {"schema": "bastionglass.scan.v1", "version": VERSION, "observed_at": datetime.now(timezone.utc).isoformat(), "scope": "explicit_project_file_manifest", "coverage": dict(COVERAGE), "runtime": runtime_observation(), "files": [], "complete": True, "security_verdict": "not_provided"}
    report["manifest_sha256"] = hashlib.sha256(json.dumps([project, files], separators=(",", ":")).encode()).hexdigest()
    accounting = [0]
    with open_workspace(workspace) as workspace_fd, open_project(workspace_fd, project) as project_fd:
        for index, name in enumerate(files):
            try:
                raw = read_source(project_fd, name, min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - accounting[0]), accounting=accounting)
                result = inspect_source(raw)
                result.update({"file_index": index, "status": "observed"})
            except BoundaryError as error:
                result = {"file_index": index, "status": "not_scanned", "reason": str(error)}
                report["complete"] = False
            report["files"].append(result)
    report["bytes_read"] = accounting[0]
    report["candidate_findings"] = sum(len(item.get("findings", [])) for item in report["files"])
    return report


def compare_baseline(report: dict, approved_baseline: dict) -> dict:
    """Caller supplies separately reviewed manifest/hash binding; never auto-approved."""
    if not isinstance(approved_baseline, dict) or set(approved_baseline) != {"manifest_sha256", "hashes"}:
        reject("invalid_baseline")
    approved_hashes = approved_baseline["hashes"]
    digest = approved_baseline["manifest_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(approved_hashes, list) or not 1 <= len(approved_hashes) <= MAX_FILES or any(not isinstance(x, str) or not re.fullmatch(r"[0-9a-f]{64}", x) for x in approved_hashes):
        reject("invalid_baseline")
    observed = report.get("files", [])
    if not report.get("complete") or report.get("manifest_sha256") != digest or len(observed) != len(approved_hashes):
        return {"status": "not_comparable", "trust": "not_established"}
    changed = [index for index, (item, digest) in enumerate(zip(observed, approved_hashes)) if item.get("sha256") != digest]
    return {"status": "changed" if changed else "hashes_match", "changed_file_indices": changed, "trust": "matching_hashes_do_not_establish_safety"}


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("invalid_traffic_fixture")
        result[key] = value
    return result


def analyze_synthetic_traffic(raw: bytes) -> dict:
    """Strict aggregate-only synthetic events. Not a packet decoder or live monitor."""
    if not isinstance(raw, bytes) or len(raw) > MAX_TRAFFIC_BYTES:
        reject("invalid_traffic_fixture")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_no_duplicates, parse_constant=lambda _: reject("invalid_traffic_fixture"))
    except (ValueError, UnicodeError, RecursionError):
        reject("invalid_traffic_fixture")
    if not isinstance(value, dict) or set(value) != {"schema", "source", "events"} or value["schema"] != "bastionglass.traffic.v1" or value["source"] != "synthetic":
        reject("invalid_traffic_fixture")
    events = value["events"]
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        reject("invalid_traffic_fixture")
    totals = {"events": len(events), "bytes_in": 0, "bytes_out": 0, "plaintext_events": 0, "unapproved_destination_events": 0, "unknown_transport_events": 0}
    for event in events:
        if not isinstance(event, dict) or set(event) != {"direction", "transport", "destination_policy", "bytes"}:
            reject("invalid_traffic_fixture")
        if event["direction"] not in ("in", "out") or event["transport"] not in ("tls", "plaintext", "unknown") or event["destination_policy"] not in ("approved", "unapproved", "unknown") or type(event["bytes"]) is not int or not 0 <= event["bytes"] <= 2**30:
            reject("invalid_traffic_fixture")
        totals["bytes_" + event["direction"]] += event["bytes"]
        totals["plaintext_events"] += event["transport"] == "plaintext"
        totals["unknown_transport_events"] += event["transport"] == "unknown"
        totals["unapproved_destination_events"] += event["destination_policy"] == "unapproved"
    return {"schema": "bastionglass.traffic-summary.v1", "source": "synthetic", "totals": totals, "live_traffic_observed": False, "payloads_inspected": False, "security_verdict": "not_provided"}


class RedactedParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments, which could contain secrets.
        print(json.dumps({"schema": "bastionglass.error.v1", "status": "not_scanned", "reason": "invalid_cli_arguments"}), file=sys.stderr)
        raise SystemExit(2)


def main(argv=None) -> int:
    parser = RedactedParser(description="Read-only bounded source observations; no live traffic or automatic reports.")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--file", action="append", required=True, dest="files")
    args = parser.parse_args(argv)
    try:
        report = scan(args.workspace, args.project, args.files)
    except BoundaryError as error:
        print(json.dumps({"schema": "bastionglass.error.v1", "status": "not_scanned", "reason": str(error)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    runtime_review = any(item["status"] == "patch_status_review_required" for item in report["runtime"]["advisories"])
    return 0 if report["complete"] and not report["candidate_findings"] and not runtime_review else 1


if __name__ == "__main__":
    raise SystemExit(main())
