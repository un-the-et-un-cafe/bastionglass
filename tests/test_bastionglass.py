# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import bastionglass as bg


class Suite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bastionglass-test-")
        self.workspace = Path(self.tmp.name)
        self.project = self.workspace / "project"
        self.project.mkdir()
        (self.project / "safe.py").write_text("print('synthetic')\n")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, files=None):
        return bg.scan(str(self.workspace), "project", files or ["safe.py"])

    def read(self, name, limit=bg.MAX_FILE_BYTES):
        with bg.open_workspace(str(self.workspace)) as w, bg.open_project(w, "project") as p:
            return bg.read_source(p, name, limit)

    def test_safe_scan_has_no_contents_or_paths(self):
        report = self.scan()
        data = json.dumps(report)
        self.assertTrue(report["complete"])
        self.assertEqual(report["candidate_findings"], 0)
        self.assertNotIn(str(self.workspace), data)
        self.assertNotIn("safe.py", data)
        self.assertNotIn("print('synthetic')", data)
        self.assertEqual(report["security_verdict"], "not_provided")

    def test_no_live_visibility_claim(self):
        coverage = self.scan()["coverage"]
        self.assertEqual(coverage["live_network_capture"], "not_implemented")
        self.assertEqual(coverage["provider_connector_traffic"], "not_observed")
        self.assertEqual(coverage["external_reporting"], "disabled")

    def test_early_eof_is_not_a_complete_observation(self):
        with patch.object(bg.os, "read", return_value=b""):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["bytes_read"], 0)
        self.assertEqual(report["files"], [{"file_index": 0, "status": "not_scanned", "reason": "incomplete_file_read"}])

    def test_partial_read_then_eof_retains_accounting_without_hash(self):
        with patch.object(bg.os, "read", side_effect=[b"pri", b""]):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertEqual(report["bytes_read"], 3)
        self.assertEqual(report["files"][0]["reason"], "incomplete_file_read")
        self.assertNotIn("sha256", report["files"][0])
        self.assertNotIn("pri", json.dumps(report))

    def test_short_chunks_that_reach_expected_size_are_accepted(self):
        original_read = os.read
        with patch.object(bg.os, "read", side_effect=lambda fd, count: original_read(fd, min(count, 3))):
            report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual(report["bytes_read"], len(b"print('synthetic')\n"))

    def test_empty_file_is_a_complete_zero_byte_observation(self):
        (self.project / "safe.py").write_bytes(b"")
        report = self.scan()
        self.assertTrue(report["complete"])
        self.assertEqual(report["bytes_read"], 0)
        self.assertEqual(report["files"][0]["sha256"], bg.hashlib.sha256(b"").hexdigest())

    def test_path_traversal_and_dotpaths_rejected(self):
        for name in ("../outside.py", "./safe.py", "/etc/passwd", ".git/config", "a//b.py", "a/../b.py", "a/./b.py", "a\\b.py", ".env", "a/", "\x00.py"):
            with self.subTest(name=name), self.assertRaises(bg.BoundaryError):
                bg.relative_parts(name)

    def test_sensitive_names_rejected(self):
        for name in ("credentials.json", "tokens.json", "secrets.py", "passwords/source.py", "id_rsa", "config.json"):
            with self.subTest(name=name), self.assertRaises(bg.BoundaryError):
                self.read(name)

    def test_unicode_and_long_paths_rejected(self):
        for name in ("x" * 513, "秘密.py", "\ud800.py", "a/" * 13 + "b.py"):
            with self.assertRaises(bg.BoundaryError):
                bg.relative_parts(name)

    def test_workspace_broad_and_sensitive_roots_rejected(self):
        for root in ("/", "/home", "/tmp", "/workspace", "/home/agent", "/proc/1", "/etc/security", "relative", "/workspace/../home"):
            with self.subTest(root=root), self.assertRaises(bg.BoundaryError):
                with bg.open_workspace(root):
                    pass

    def test_workspace_symlink_is_not_followed(self):
        alias = self.workspace / "alias"
        alias.symlink_to(self.project, target_is_directory=True)
        with self.assertRaises(bg.BoundaryError):
            with bg.open_workspace(str(alias)):
                pass

    def test_project_symlink_is_not_followed(self):
        (self.workspace / "alias").symlink_to(self.project, target_is_directory=True)
        with self.assertRaises(bg.BoundaryError):
            bg.scan(str(self.workspace), "alias", ["safe.py"])

    def test_file_symlink_is_not_followed(self):
        (self.project / "alias.py").symlink_to(self.project / "safe.py")
        report = self.scan(["alias.py"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["files"][0]["reason"], "file_unavailable")

    def test_intermediate_symlink_is_not_followed(self):
        (self.project / "alias").symlink_to(self.project, target_is_directory=True)
        self.assertFalse(self.scan(["alias/safe.py"])["complete"])

    def test_hardlink_rejected(self):
        os.link(self.project / "safe.py", self.project / "linked.py")
        self.assertEqual(self.scan(["linked.py"])["files"][0]["reason"], "non_regular_or_linked_file")

    def test_fifo_does_not_block(self):
        os.mkfifo(self.project / "fifo.py")
        self.assertEqual(self.scan(["fifo.py"])["files"][0]["reason"], "non_regular_or_linked_file")

    def test_directory_is_not_source(self):
        (self.project / "directory.py").mkdir()
        self.assertFalse(self.scan(["directory.py"])["complete"])

    def test_unknown_extension_is_not_read(self):
        (self.project / "data.bin").write_bytes(b"synthetic")
        self.assertEqual(self.scan(["data.bin"])["files"][0]["reason"], "unsupported_file_type")

    def test_missing_file_error_is_fixed_and_redacted(self):
        report = self.scan(["private-name.py"])
        self.assertFalse(report["complete"])
        self.assertNotIn("private-name", json.dumps(report))
        self.assertEqual(report["files"][0]["reason"], "file_unavailable")

    def test_manifest_bounds_and_types(self):
        for files in ([], ["safe.py"] * 129, ["safe.py", "safe.py"], [None], [[]], "safe.py"):
            with self.assertRaises(bg.BoundaryError):
                bg.scan(str(self.workspace), "project", files)

    def test_file_size_cap(self):
        (self.project / "large.py").write_bytes(b"a" * (bg.MAX_FILE_BYTES + 1))
        self.assertEqual(self.scan(["large.py"])["files"][0]["reason"], "file_limit")

    def test_read_limit_checks(self):
        for value in (-1, True, bg.MAX_FILE_BYTES + 1):
            with self.assertRaises(bg.BoundaryError):
                self.read("safe.py", value)

    def test_total_cap_marks_incomplete(self):
        files = []
        for index in range(17):
            name = f"source{index}.py"
            (self.project / name).write_bytes(b"a" * bg.MAX_FILE_BYTES)
            files.append(name)
        report = self.scan(files)
        self.assertFalse(report["complete"])
        self.assertEqual(report["bytes_read"], bg.MAX_TOTAL_BYTES)
        self.assertEqual(report["files"][-1]["reason"], "file_limit")

    def test_invalid_utf8_and_nul_are_not_processed(self):
        for raw in (b"\xff", b"a\x00b"):
            with self.assertRaises(bg.BoundaryError):
                bg.inspect_source(raw)

    def test_secret_candidates_never_echo_value(self):
        secret = "synthetic_" + "X" * 32
        raw = ("api_key = '" + secret + "'\n").encode()
        report = bg.inspect_source(raw)
        self.assertEqual(report["findings"][0]["rule_id"], "secret.literal_credential_candidate")
        self.assertNotIn(secret, json.dumps(report))

    def test_private_key_marker_candidate(self):
        raw = ("-----BEGIN " + "PRIVATE KEY-----\nsynthetic only").encode()
        self.assertEqual(bg.inspect_source(raw)["findings"][0]["rule_id"], "secret.private_key_marker")

    def test_code_heuristics_are_candidates_not_malware(self):
        snippets = ["eval" + "('1')", "subprocess.run('x', shell=" + "True)", "pickle." + "loads(b'x')", "get('x', verify=" + "False)"]
        for snippet in snippets:
            report = bg.inspect_source(snippet.encode())
            self.assertTrue(report["findings"])
            self.assertTrue(all(x["classification"] == "candidate_requires_review" for x in report["findings"]))

    def test_comments_can_be_false_positives(self):
        report = bg.inspect_source(("# documentation: " + "eval" + "('x')").encode())
        self.assertTrue(report["findings"])

    def test_obfuscated_example_is_explicit_detection_limit(self):
        report = bg.inspect_source(b"operation = 'e' + 'val'\n")
        self.assertEqual(report["findings"], [])

    def test_opened_descriptor_survives_path_replacement_without_following_link(self):
        original_read = os.read
        changed = False
        def replace_then_read(fd, count):
            nonlocal changed
            if not changed:
                changed = True
                (self.project / "safe.py").rename(self.project / "old.py")
                (self.project / "safe.py").symlink_to("/nonexistent/outside.py")
            return original_read(fd, count)
        with patch.object(bg.os, "read", replace_then_read):
            # Rename may update ctime and trigger conservative race rejection.
            try:
                content = self.read("safe.py")
            except bg.BoundaryError as exc:
                self.assertEqual(str(exc), "file_changed_during_read")
            else:
                self.assertEqual(content, b"print('synthetic')\n")

    def test_content_mutation_during_read_is_rejected(self):
        original_read = os.read
        changed = False
        def mutate_then_read(fd, count):
            nonlocal changed
            if not changed:
                changed = True
                (self.project / "safe.py").write_text("changed and longer content\n")
            return original_read(fd, count)
        with patch.object(bg.os, "read", mutate_then_read), self.assertRaisesRegex(bg.BoundaryError, "file_changed_during_read"):
            self.read("safe.py")

    def test_symlink_swap_before_open_is_rejected(self):
        original_open = os.open
        def swap(path, flags, *args, **kwargs):
            if path == "safe.py":
                (self.project / "safe.py").unlink()
                (self.project / "safe.py").symlink_to("/nonexistent/private.py")
            return original_open(path, flags, *args, **kwargs)
        # Open the directory first; platform capability checks must see original os.open.
        with bg.open_workspace(str(self.workspace)) as w, bg.open_project(w, "project") as p:
            with patch.object(bg.os, "open", swap), self.assertRaisesRegex(bg.BoundaryError, "file_unavailable"):
                bg.read_source(p, "safe.py")

    def test_hash_baseline_is_read_only_and_explicit(self):
        report = self.scan()
        baseline = {"manifest_sha256": report["manifest_sha256"], "hashes": [report["files"][0]["sha256"]]}
        self.assertEqual(bg.compare_baseline(report, baseline)["status"], "hashes_match")
        (self.project / "safe.py").write_text("changed\n")
        result = bg.compare_baseline(self.scan(), baseline)
        self.assertEqual(result["changed_file_indices"], [0])
        self.assertEqual(result["trust"], "matching_hashes_do_not_establish_safety")

    def test_baseline_scope_or_incomplete_cannot_match(self):
        report = self.scan()
        baseline = {"manifest_sha256": "0" * 64, "hashes": [report["files"][0]["sha256"]]}
        self.assertEqual(bg.compare_baseline(report, baseline)["status"], "not_comparable")
        for invalid in ({}, [], {"manifest_sha256": "x", "hashes": []}):
            with self.assertRaises(bg.BoundaryError):
                bg.compare_baseline(report, invalid)

    def test_failed_read_bytes_still_count_against_total_budget(self):
        original_read = os.read
        changed = False
        def mutate_after_read(fd, count):
            nonlocal changed
            content = original_read(fd, count)
            if not changed:
                changed = True
                (self.project / "safe.py").write_text("mutated source during scan\n")
            return content
        with patch.object(bg.os, "read", mutate_after_read):
            report = self.scan()
        self.assertFalse(report["complete"])
        self.assertGreater(report["bytes_read"], 0)
        self.assertLessEqual(report["bytes_read"], bg.MAX_TOTAL_BYTES)

    def test_invalid_cli_arguments_are_redacted(self):
        import io
        from contextlib import redirect_stderr
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit):
            bg.main(["--unknown", "synthetic-sensitive-marker"])
        self.assertNotIn("synthetic-sensitive-marker", output.getvalue())
        self.assertIn("invalid_cli_arguments", output.getvalue())

    def test_runtime_observation_labels_backports_and_coverage_unknown(self):
        observation = bg.runtime_observation()
        self.assertRegex(observation["python"], r"^\d+\.\d+\.\d+$")
        for advisory in observation["advisories"]:
            self.assertEqual(advisory["vendor_backports"], "unknown")
            self.assertTrue(advisory["not_a_comprehensive_vulnerability_assessment"])
            self.assertEqual(advisory["evidence_checked_on"], "2026-10-31" if advisory["component"] == "openssl" else "2026-10-30")

    def test_openssl_35_older_versions_require_review(self):
        for version in ("3.5.0", "3.5.7", "3.5.8"):
            with self.subTest(version=version):
                result = bg.openssl_advisory_observation("OpenSSL " + version)
                self.assertEqual(result["status"], "patch_status_review_required")
                self.assertEqual(result["observed_version"], version)

    def test_openssl_fixed_boundary_only_clears_version_flag(self):
        for version in ("3.5.9", "3.5.10"):
            result = bg.openssl_advisory_observation("OpenSSL " + version)
            self.assertEqual(result["status"], "no_older_version_flag_for_this_rule")
            self.assertEqual(result["vendor_backports"], "unknown")
            self.assertEqual(result["application_exposure"], "unknown")
            self.assertNotIn("safe", json.dumps(result))

    def test_openssl_other_series_remain_unknown(self):
        for version in ("3.0.23", "3.4.8", "3.6.5", "4.0.3", "9.0.0"):
            result = bg.openssl_advisory_observation("OpenSSL " + version)
            self.assertEqual(result["status"], "unknown_series_not_covered")

    def test_openssl_unparseable_and_vendor_strings_not_echoed(self):
        for value in (None, 35, "", "LibreSSL 3.5.9", "OpenSSL 3.5.9-dev",
                      "OpenSSL 3.5.8-vendor-backport", "OpenSSL 3.5.9 /private/synthetic-marker",
                      "OpenSSL 3.5.9\n", "OpenSSL " + "9" * 5000):
            result = bg.openssl_advisory_observation(value)
            self.assertEqual(result["status"], "unknown_unparseable_version")
            self.assertEqual(result["observed_version"], "unknown")
            self.assertNotIn("synthetic-marker", json.dumps(result))

    def test_openssl_standard_date_is_not_echoed(self):
        result = bg.openssl_advisory_observation("OpenSSL 3.5.9 29 Sep 2026")
        self.assertEqual(result["observed_version"], "3.5.9")
        self.assertNotIn("29 Sep", json.dumps(result))

    def test_openssl_runtime_uses_linked_library_not_cli(self):
        with patch.object(bg.ssl, "OPENSSL_VERSION", "OpenSSL 3.5.8 29 Sep 2026"):
            report = bg.runtime_observation()
        result = report["advisories"][-1]
        self.assertEqual(report["openssl"], "3.5.8")
        self.assertEqual(result["observation_source"], "python_ssl_linked_library")
        self.assertEqual(result["status"], "patch_status_review_required")

    def test_openssl_runtime_never_echoes_private_version_suffix(self):
        with patch.object(bg.ssl, "OPENSSL_VERSION", "OpenSSL 3.5.8 /private/synthetic-marker"):
            report = bg.runtime_observation()
        self.assertEqual(report["openssl"], "unknown")
        self.assertNotIn("synthetic-marker", json.dumps(report))

    def test_openssl_review_flag_affects_cli_exit_without_vulnerability_verdict(self):
        import io
        from contextlib import redirect_stdout
        with patch.object(bg.sys, "version_info", (3, 12, 16)), \
             patch.object(bg.expat, "version_info", (2, 9, 0)):
            for version, expected in (("OpenSSL 3.5.8", 1), ("OpenSSL 3.5.9", 0)):
                output = io.StringIO()
                with patch.object(bg.ssl, "OPENSSL_VERSION", version), redirect_stdout(output):
                    code = bg.main(["--workspace", str(self.workspace), "--project", "project", "--file", "safe.py"])
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(output.getvalue())["security_verdict"], "not_provided")

    def test_no_subprocess_or_network_imports(self):
        source = Path(bg.__file__).read_text()
        import ast
        tree = ast.parse(source)
        imported = {node.names[0].name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)}
        self.assertTrue(imported.isdisjoint({"socket", "subprocess", "urllib", "requests", "http"}))


class Traffic(unittest.TestCase):
    def fixture(self):
        return {"schema": "bastionglass.traffic.v1", "source": "synthetic", "events": [{"direction": "out", "transport": "tls", "destination_policy": "approved", "bytes": 128}]}

    def run_fixture(self, value):
        return bg.analyze_synthetic_traffic(json.dumps(value).encode())

    def test_aggregate_only(self):
        report = self.run_fixture(self.fixture())
        self.assertEqual(report["totals"]["bytes_out"], 128)
        self.assertFalse(report["payloads_inspected"])
        self.assertFalse(report["live_traffic_observed"])

    def test_live_input_rejected(self):
        value = self.fixture()
        value["source"] = "live"
        with self.assertRaises(bg.BoundaryError):
            self.run_fixture(value)

    def test_payload_and_destination_fields_rejected(self):
        for key in ("payload", "url", "hostname", "ip", "cookie", "authorization", "token"):
            value = self.fixture()
            value["events"][0][key] = "synthetic private content"
            with self.assertRaises(bg.BoundaryError) as raised:
                self.run_fixture(value)
            self.assertEqual(str(raised.exception), "invalid_traffic_fixture")

    def test_unknown_and_plaintext_counts(self):
        value = self.fixture()
        value["events"] += [{"direction": "in", "transport": "plaintext", "destination_policy": "unapproved", "bytes": 10}, {"direction": "in", "transport": "unknown", "destination_policy": "unknown", "bytes": 1}]
        totals = self.run_fixture(value)["totals"]
        self.assertEqual(totals["plaintext_events"], 1)
        self.assertEqual(totals["unknown_transport_events"], 1)
        self.assertEqual(totals["unapproved_destination_events"], 1)

    def test_size_event_and_number_limits(self):
        for number in (True, -1, 2**30 + 1, 0.5, None):
            value = self.fixture()
            value["events"][0]["bytes"] = number
            with self.assertRaises(bg.BoundaryError):
                self.run_fixture(value)
        value = self.fixture()
        value["events"] *= 257
        with self.assertRaises(bg.BoundaryError):
            self.run_fixture(value)
        with self.assertRaises(bg.BoundaryError):
            bg.analyze_synthetic_traffic(b" " * (bg.MAX_TRAFFIC_BYTES + 1))

    def test_duplicate_nonfinite_nested_and_malformed_rejected(self):
        for raw in (b'{"source":"synthetic","source":"synthetic"}', b'{"x":NaN}', b'[' * 2000, b'\xff', b'null', b'[]'):
            with self.assertRaises(bg.BoundaryError):
                bg.analyze_synthetic_traffic(raw)

    def test_utf16_and_utf32_are_rejected_even_with_valid_json(self):
        text = json.dumps(self.fixture())
        for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
            with self.subTest(encoding=encoding), self.assertRaises(bg.BoundaryError) as raised:
                bg.analyze_synthetic_traffic(text.encode(encoding))
            self.assertEqual(str(raised.exception), "invalid_traffic_fixture")

    def test_unknown_enums_rejected(self):
        for key in ("direction", "transport", "destination_policy"):
            value = self.fixture()
            value["events"][0][key] = "private.example"
            with self.assertRaises(bg.BoundaryError) as raised:
                self.run_fixture(value)
            self.assertNotIn("private.example", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
