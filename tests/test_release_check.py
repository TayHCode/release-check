from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.denylist = self.root / "terms.json"
        self.denylist.write_text(json.dumps({"categories": {"family": {"placeholder": "private", "terms": ["HiddenPerson"]}}}))
        self.terms = rc.load_terms(self.denylist)
        self.git("init", "-q", "-b", "main")
        # Match the auditor's isolated Git settings, including on Windows.
        self.git("config", "core.autocrlf", "false")
        self.git("config", "user.name", "Fixture contributors")
        self.git("config", "user.email", "fixture")
        shutil.copyfile(Path(rc.__file__).with_name("LICENSE"), self.repo / "LICENSE")
        (self.repo / "README.md").write_text("# Fixture\n## Honest limitations\nSynthetic only.\npython -c 'print(1)'\n")
        (self.repo / "CONTRIBUTING.md").write_text("Run tests.")
        (self.repo / "SECURITY.md").write_text("Private reporting.")
        (self.repo / ".github/ISSUE_TEMPLATE").mkdir(parents=True)
        (self.repo / ".github/ISSUE_TEMPLATE/bug.yml").write_text("name: bug\n")
        (self.repo / "tests").mkdir()
        (self.repo / "tests/test_fixture.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertEqual(2 + 2, 4)\n")
        self.manifest = {"exclude": [], "approvals": [], "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", "print(1)"]}], "checks": [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}]}
        (self.repo / "release-check.json").write_text(json.dumps(self.manifest))
        self.commit("Initial fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True).stdout

    def commit(self, message):
        files = [str(p.relative_to(self.repo)) for p in self.repo.rglob("*") if p.is_file() and ".git" not in p.relative_to(self.repo).parts]
        self.git("add", "--", *files)
        self.git("commit", "-q", "-m", message)

    def scan(self):
        scanner = rc.Scanner(self.terms)
        scanner.tree(self.repo)
        scanner.history(self.repo)
        return scanner

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main([str(self.repo), "--denylist", str(self.denylist), "--reports", str(self.root / "reports"), *args])
        return code, out.getvalue(), err.getvalue()

    def latest_report(self):
        return json.loads(sorted((self.root / "reports").rglob("report.json"))[-1].read_text())

    def save_manifest(self):
        (self.repo / "release-check.json").write_text(json.dumps(self.manifest))

    def private_history(self):
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Add old example")
        self.git("rm", "--", "old.txt")
        self.git("commit", "-q", "-m", "Remove old example")

    def test_text_verdict_fix_these_lists_blocking_with_fixes(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "KlMnOpQrStUvWxYz"
        (self.repo / "sample.txt").write_text(token)
        self.commit("Add token fixture")
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        self.assertTrue(out.startswith("release-check " + rc.VERSION))
        for text in ("VERDICT: FIX-THESE", "BLOCKING", "WARNINGS", "PLAN", "TEST BEFORE PUBLISHING", "REPORT:", "Fix:"):
            self.assertIn(text, out)
        for text in (out, err, *(p.read_text() for p in (self.root / "reports").rglob("report.*"))):
            self.assertNotIn(token, text)
            self.assertNotIn(str(self.root), text)
        self.assertTrue(out.isascii())
        report = self.latest_report()
        fixes = {(rc.group_of(f), rc.fix_for(f)) for f in report["findings"]}
        self.assertEqual(out.count("   Fix: "), len(fixes))
        hit = next(f for f in report["findings"] if f["kind"] == "github-token")
        report["findings"] = [dict(hit, path="sample.txt", line=n) for n in range(1, 13)]
        text = rc.format_text(report)
        self.assertIn("... and 2 more in report.md", text)
        self.assertNotIn("sample.txt:11 ", text)
        self.assertIn("| sample.txt | 12 |", rc.format_markdown(report))

    def test_commit_author_email_gets_export_guidance_not_example_approval(self):
        address = "author@" + "example.com"
        self.git("-c", "user.name=Sample Author", "-c", "user.email=" + address,
                 "commit", "--allow-empty", "-qm", "Author fixture")
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        finding = next(f for f in self.latest_report()["findings"]
                       if f["kind"] == "email" and f["path"].startswith("@commit/"))
        fix = rc.fix_for(finding)
        for text in ("author or committer email", "--export", "generic authorship", "original history private"):
            self.assertIn(text, fix)
        self.assertNotIn("deliberate public example", fix)
        self.assertNotIn(address, out)

    def test_missing_documents_have_their_own_fix_instructions(self):
        for name in ("CONTRIBUTING.md", "SECURITY.md"):
            (self.repo / name).unlink()
        shutil.rmtree(self.repo / ".github/ISSUE_TEMPLATE")
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        self.assertIn("Create CONTRIBUTING.md with instructions", out)
        self.assertIn("Create SECURITY.md with supported versions", out)
        self.assertIn("Markdown issue template (.md) or YAML issue form (.yml or .yaml)", out)
        self.assertNotIn("A README says", out)

    def test_blocked_export_warns_that_copied_content_is_still_private(self):
        token = "gh" + "p_" + "A" * 30
        (self.repo / "config.py").write_text(token)
        self.git("add", "--", "config.py")
        target = self.root / "blocked-export"
        code, out, err = self.run_cli("--export", str(target))
        self.assertEqual(code, 1, err)
        self.assertFalse(target.exists())
        self.assertEqual((target.with_name(target.name + ".BLOCKED") / "config.py").read_text(), token)
        self.assertNotIn("VERDICT: PASS", out)
        self.assertIn("WARNING: " + rc.BLOCKED_EXPORT_WARNING, out)
        self.assertIn(rc.BLOCKED_EXPORT_WARNING, (next((self.root / "reports").rglob("report.md"))).read_text())
        self.assertNotIn(token, out)
        code, out, err = self.run_cli("--json", "--export", str(self.root / "json-export"))
        self.assertEqual(code, 1, err)
        self.assertFalse(json.loads(out)["export_ready"])
        self.assertEqual(json.loads(out)["export_warning"], rc.BLOCKED_EXPORT_WARNING)

    def test_passing_export_has_no_blocked_export_warning(self):
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "passing-export"))
        self.assertEqual(code, 0, out + err)
        self.assertNotIn(rc.BLOCKED_EXPORT_WARNING, out)
        code, out, err = self.run_cli("--json", "--verify", "--export", str(self.root / "passing-json-export"))
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("export_warning", json.loads(out))

    def test_digest_failure_explains_file_times_even_when_bytes_match(self):
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, self.scan())
        digest = rc.export_digest(target)
        readme = target / "README.md"
        before = readme.stat()
        os.utime(readme, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
        out = io.StringIO()
        with redirect_stdout(out):
            code = rc.main([str(target), "--check-digest", digest])
        self.assertEqual(code, 1)
        for text in ("modification times", "Restoring bytes alone", "new folder"):
            self.assertIn(text, out.getvalue())
        os.utime(readme, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(rc.export_digest(target), digest)

    def test_text_verdict_pass_for_clean_export(self):
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 0, out + err)
        self.assertIn("VERDICT: PASS", out)
        self.assertIn("This is not a complete secret scanner.", out)
        self.assertIn("Run a dedicated secret scanner too and read the export yourself", out)
        self.assertEqual(self.latest_report()["verdict"], "PASS")
        self.assertEqual(self.latest_report()["summary"]["blocking"], 0)

    def test_json_flag_prints_legacy_summary(self):
        code, out, err = self.run_cli("--json")
        self.assertEqual(code, 1, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertEqual(set(json.loads(out)), {"ready", "counts", "report"})
        code, out, err = self.run_cli("--json", "--scrub-plan")
        first, remainder = out.split("\n", 1)
        self.assertEqual(set(json.loads(first)), {"ready", "counts", "report"})
        self.assertIn("drop_files", json.loads(remainder))
        code, out, err = self.run_cli("--json", "--export", str(self.root / "export"))
        self.assertEqual(set(json.loads(out)), {"ready", "counts", "report", "export_ready", "export_counts", "export_warning"})

    def test_history_findings_are_warnings_when_exporting(self):
        self.private_history()
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 0, out + err)
        report = self.latest_report()
        self.assertEqual(report["summary"]["blocking"], 0)
        self.assertTrue(any(f.get("severity") == "warning" and f.get("why") == "source-only" for f in report["findings"]))

    def test_history_findings_block_without_export(self):
        self.private_history()
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        finding = next(f for f in self.latest_report()["findings"] if f["kind"] == "denylist")
        self.assertEqual(finding["severity"], "blocking")
        self.assertEqual(rc.fix_for(finding), rc.HISTORY_FIX)
        self.assertIn(rc.HISTORY_FIX, out)

    def test_acknowledged_findings_are_warnings(self):
        raw = ("demo@" + "example.org").encode()
        scanner = rc.Scanner([])
        scanner.file(raw, "tree", "example.txt")
        self.manifest["approvals"] = [dict(scanner.findings[0], reason="Synthetic example address")]
        self.save_manifest()
        (self.repo / "example.txt").write_bytes(raw)
        code, out, err = self.run_cli()
        finding = next(f for f in self.latest_report()["findings"] if f["kind"] == "email")
        self.assertEqual((finding["severity"], finding["why"]), ("warning", "acknowledged"))
        self.assertIn("acknowledged", out)

    def test_verdict_always_matches_exit_code(self):
        code, out, err = self.run_cli("--verify")
        self.assertEqual(code, 0, out + err)
        self.assertIn("VERDICT: PASS", out)
        code, out, err = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("VERDICT: FIX-THESE", out)
        with patch.object(rc.Scanner, "tree", side_effect=OSError("SyntheticFailure")):
            code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("VERDICT: INCOMPLETE", err)
        self.assertEqual(self.latest_report()["verdict"], "INCOMPLETE")

    def test_every_finding_kind_has_a_fix(self):
        import re
        kinds = set(rc.PATTERNS) | set(rc.SECRET_PATTERNS) | {"denylist", "ipv4", "ipv6", "tailnet-ip", "audit-incomplete"}
        kinds.update(re.findall(r'\.add\("[^"\n]+", "[^"\n]+", "([^"\n]+)"', Path(rc.__file__).read_text()))
        self.assertEqual(kinds - rc.FIXES.keys(), set())
        self.assertTrue(all(rc.FIXES[kind] for kind in kinds))

    def test_scrub_classes_are_the_six_named(self):
        labels = ["private terms", "emails", "IP addresses", "internal host names", "home paths", "credentials"]
        self.assertEqual([label for label, _ in rc.GROUPS[:6]], labels)
        raw = "HiddenPerson\ndemo@" + "example.org\n192.0." + "2.1\nnode." + "internal\n/home/" + "fakeuser/data\ngh" + "p_" + "A" * 30
        (self.repo / "example.txt").write_text(raw)
        self.run_cli()
        classes = self.latest_report()["scrub_plan"]["by_class"]
        self.assertEqual(list(classes), labels)
        self.assertTrue(all(counts["files"] >= 1 for counts in classes.values()))

    def test_plan_steps_and_actors(self):
        (self.repo / "example.txt").write_text("HiddenPerson")
        self.run_cli()
        report = self.latest_report()
        steps = report["plan"]
        self.assertEqual((steps[0]["id"], steps[-1]["id"]), ("read", "publish"))
        self.assertTrue(all(s["actor"] in {"tool", "you"} for s in steps))
        self.assertIn("fix-content", {s["id"] for s in steps})
        self.assertTrue(all(s["status"] == "planned" for s in steps if s["actor"] == "tool" and s["id"] != "read"))
        (self.repo / "example.txt").unlink()
        self.run_cli("--export", str(self.root / "export"))
        steps = self.latest_report()["plan"]
        self.assertNotIn("fix-content", {s["id"] for s in steps})
        self.assertTrue(all(s["status"] == "done" for s in steps if s["actor"] == "tool"))

    def test_test_list_automatic_items_follow_verification(self):
        self.run_cli()
        statuses = {i["id"]: i["status"] for i in self.latest_report()["pre_publish_tests"]}
        self.assertEqual((statuses["quickstart-1"], statuses["check-1"]), ("not run", "not run"))
        self.run_cli("--verify")
        statuses = {i["id"]: i["status"] for i in self.latest_report()["pre_publish_tests"]}
        self.assertEqual((statuses["quickstart-1"], statuses["check-1"]), ("passed", "passed"))
        self.assertEqual(next(s["status"] for s in self.latest_report()["plan"] if s["id"] == "verify"), "done")
        self.manifest["checks"][0]["argv"] = ["python", "-c", "raise SystemExit(3)"]
        self.save_manifest()
        self.run_cli("--verify")
        statuses = {i["id"]: i["status"] for i in self.latest_report()["pre_publish_tests"]}
        self.assertEqual(statuses["check-1"], "failed")
        self.assertEqual(next(s["status"] for s in self.latest_report()["plan"] if s["id"] == "verify"), "planned")

    def test_test_list_conditional_manual_items(self):
        self.run_cli()
        report = self.latest_report()
        items = {i["id"] for i in report["pre_publish_tests"]}
        always = {"fresh-clone", "publish-export-not-original", "license-holder", "hosting-side", "after-publish"}
        self.assertTrue(always <= items)
        self.assertTrue({"rotate-credentials", "review-media", "inspect-commit", "confirm-digest"}.isdisjoint(items))
        scanner = rc.Scanner([])
        scanner.file(("gh" + "p_" + "A" * 30).encode(), "history", "example.txt")
        scanner.file(b"image example", "tree", "picture.png")
        report["findings"].extend(scanner.findings)
        report["export"] = {**report, "digest": "a" * 64}
        items = {i["id"]: i for i in rc.test_list(report, self.manifest, scanner)}
        self.assertTrue({"rotate-credentials", "review-media", "inspect-commit", "confirm-digest", "unreadable-content"} <= items.keys())
        self.assertIn(report["export"]["digest"], items["confirm-digest"]["text"])
        self.assertTrue(all(i["status"] == "to do" for i in items.values() if i["kind"] == "manual"))

    def test_untrusted_manifest_text_never_reaches_test_list(self):
        self.manifest["checks"][0]["role"] = "SyntheticPrivateLabel"
        self.manifest["quickstart"][0].update(file="HiddenPerson.md", line="SyntheticPrivateLine")
        self.save_manifest()
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        for text in (out, err, *(p.read_text() for p in (self.root / "reports").rglob("report.*"))):
            for private in ("SyntheticPrivateLabel", "HiddenPerson", "SyntheticPrivateLine"):
                self.assertNotIn(private, text)
        self.assertIn("other check", out)
        self.assertIn("line 0", out)

    def test_missing_readme_is_a_finding_with_a_fix(self):
        (self.repo / "README.md").unlink()
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, err)
        kinds = {f["kind"] for f in self.latest_report()["findings"]}
        self.assertTrue({"missing-document", "missing-limitations"} <= kinds)
        self.assertIn("README.md", out)
        self.assertIn(rc.FIXES["missing-document"], out)
        code, out, err = self.run_cli("--export", str(self.root / "export"))
        self.assertEqual(code, 1, err)
        self.assertFalse((self.root / "export/README.md").exists())
        self.assertFalse((self.repo / "README.md").exists())

    def test_missing_readme_with_verify_keeps_the_audit(self):
        (self.repo / "sample.txt").write_text("gh" + "p_" + "A" * 30)
        self.commit("Add sample")
        (self.repo / "README.md").unlink()
        with patch.object(rc, "command") as command:
            code, out, err = self.run_cli("--verify")
        command.assert_not_called()
        self.assertEqual(code, 1, out + err)
        kinds = {f["kind"] for f in self.latest_report()["findings"]}
        self.assertTrue({"missing-document", "quickstart-document-missing", "github-token"} <= kinds)
        self.assertEqual(self.latest_report()["verification"]["commands"], [])

    def test_undecodable_readme_does_not_abort(self):
        (self.repo / "README.md").write_bytes(b"\xff\xfe Invalid text\n")
        for args in ((), ("--verify",)):
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 1, out + err)
            self.assertIn("VERDICT: FIX-THESE", out)
        original = Path.read_text
        def unreadable(path, *args, **kwargs):
            if path == self.repo / "README.md":
                raise PermissionError("SyntheticPrivateDetail")
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_text", unreadable):
            code, out, err = self.run_cli("--verify")
        self.assertEqual(code, 1, out + err)
        self.assertNotIn("SyntheticPrivateDetail", out + err)

    def test_error_codes_are_specific_and_private(self):
        existing = self.root / "existing"
        existing.mkdir()
        inner = self.repo / "inner"
        inner.mkdir()
        plain = self.root / "plain"
        plain.mkdir()
        cases = [
            ([str(self.repo)], {"denylist-required"}),
            ([str(self.repo), "--denylist", str(self.root / "absent")], {"denylist-not-found"}),
            ([str(self.repo), "--denylist", str(self.denylist), "--export", str(existing)], {"export-destination-exists"}),
            ([str(inner), "--denylist", str(self.denylist)], {"not-repository-root"}),
            ([str(plain), "--denylist", str(self.denylist)], {"not-a-git-repository", "not-repository-root"}),
            ([str(self.root / "missing"), "--denylist", str(self.denylist)], {"repo-not-found"}),
        ]
        for argv, expected in cases:
            for json_mode in (False, True):
                with self.subTest(argv=argv, json=json_mode):
                    out, err = io.StringIO(), io.StringIO()
                    with patch.dict(os.environ, {"RELEASE_CHECK_DENYLIST": ""}), redirect_stdout(out), redirect_stderr(err):
                        code = rc.main(argv + ["--reports", str(self.root / "reports")] + (["--json"] if json_mode else []))
                    self.assertEqual(code, 2)
                    if json_mode:
                        value = json.loads(err.getvalue())
                        self.assertEqual(set(value), {"ready", "error", "code", "message"} if value["code"] == "export-destination-exists" else {"ready", "error", "code"})
                        self.assertIn(value["code"], expected)
                    else:
                        self.assertIn("VERDICT: INCOMPLETE", err.getvalue())
                        self.assertTrue(any(f"Reason: {key} - {rc.ERRORS[key]}" in err.getvalue() for key in expected))
                    if "export-destination-exists" not in expected:
                        self.assertNotIn(str(self.root), out.getvalue() + err.getvalue())
        (self.repo / "release-check.json").write_text("{")
        code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("manifest-schema", err)

    def test_shallow_source_blocks_export(self):
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth=1", self.repo.as_uri(), str(shallow)],
                       check=True, capture_output=True)
        self.repo = shallow
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 1, out + err)
        report = self.latest_report()
        self.assertEqual(report["verdict"], "FIX-THESE")
        self.assertFalse(report["export"]["ready"])
        self.assertTrue(any(f["kind"] == "shallow-history" and f["scope"] == "export"
                            and f["severity"] == "blocking" for f in report["export"]["findings"]))
        self.assertEqual(report["export"]["verification"]["status"], "pass")

    def test_dirty_tracked_bytes_have_a_notice_without_a_new_gate(self):
        code, out, err = self.run_cli()
        self.assertNotIn("NOTICE:", out)
        self.assertFalse(self.latest_report()["scrub_plan"]["working_changes"])
        for change in ("unstaged", "staged", "new-file"):
            with self.subTest(change=change):
                if change == "new-file":
                    path = self.repo / "new.txt"
                    path.write_text("New example")
                else:
                    path = self.repo / "README.md"
                    path.write_text(path.read_text() + "\nEdited example\n")
                if change != "unstaged":
                    self.git("add", "--", path.name)
                target = self.root / ("export-" + change)
                code, out, err = self.run_cli("--verify", "--export", str(target))
                self.assertEqual(code, 0, out + err)
                self.assertIn("NOTICE: Tracked files have uncommitted or staged changes.", out)
                self.assertTrue(self.latest_report()["scrub_plan"]["working_changes"])
                self.assertEqual(self.latest_report()["summary"]["blocking"], 0)
                self.assertEqual((target / path.name).read_bytes(), path.read_bytes())
                markdown = sorted((self.root / "reports").rglob("report.md"))[-1].read_text()
                self.assertIn("NOTICE:", markdown)
                self.git("add", "--", path.name)
                self.git("commit", "-q", "-m", "Save example")

    def test_invalid_project_type_cli_has_no_traceback_or_paths(self):
        (self.repo / "pyproject.toml").write_text('project = "x"\n')
        for mode in ([], ["--json"]):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, rc.__file__, str(self.repo),
                                         "--denylist", str(self.denylist), "--reports", str(self.root / "reports"), *mode],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                if mode:
                    self.assertEqual(json.loads(result.stderr)["code"], "audit-incomplete")
                else:
                    self.assertIn("VERDICT: INCOMPLETE", result.stderr)
                report = self.latest_report()
                self.assertEqual(report["verdict"], "INCOMPLETE")
                for text in (result.stdout, result.stderr,
                             *(p.read_text() for p in (self.root / "reports").rglob("report.*"))):
                    for private in ("Traceback", "AttributeError", str(Path(rc.__file__).parent), str(self.root)):
                        self.assertNotIn(private, text)

    def test_unexpected_exception_and_report_failure_stay_private(self):
        for failure in (AttributeError, RuntimeError):
            for report_fails in (False, True):
                with self.subTest(failure=failure.__name__, report_fails=report_fails):
                    original = rc.write_reports
                    def write(directory, report):
                        if report_fails:
                            raise OSError(str(Path(rc.__file__).parent))
                        return original(directory, report)
                    with patch.object(rc.Scanner, "tree", side_effect=failure("SyntheticPrivateDetail")), patch.object(rc, "write_reports", write):
                        code, out, err = self.run_cli()
                    self.assertEqual(code, 2)
                    self.assertIn("VERDICT: INCOMPLETE", err)
                    for private in ("Traceback", "SyntheticPrivateDetail", str(Path(rc.__file__).parent)):
                        self.assertNotIn(private, out + err)

    def test_fix_text_is_distinct_with_separate_history_guidance(self):
        self.run_cli()
        report = self.latest_report()
        scanner = rc.Scanner([])
        for scope in ("tree", "history"):
            for kind in ("ipv4", "ipv6", "tailnet-ip"):
                scanner.add(scope, "personal", kind, "example.txt", 1)
        report["findings"] = scanner.findings
        text = rc.format_text(report)
        fixes = [line for line in text.splitlines() if line.startswith("   Fix: ")]
        self.assertEqual(fixes, ["   Fix: " + rc.fix_for(scanner.findings[0]), "   Fix: " + rc.fix_for(scanner.findings[3])])
        self.assertNotIn("credential", " ".join(fixes))
        scanner.add("history", "secrets", "github-token", "example.txt", 1)
        self.assertIn("Revoke the credential", rc.fix_for(scanner.findings[-1]))

    def test_unknown_error_detail_is_never_printed(self):
        with patch.object(rc.Scanner, "tree", side_effect=rc.AuditError("SyntheticPrivateDetail")):
            code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("audit-incomplete", err)
        for text in (out, err, *(p.read_text() for p in (self.root / "reports").rglob("report.*"))):
            self.assertNotIn("SyntheticPrivateDetail", text)

    def test_export_contains_tracked_files_only(self):
        (self.repo / ".gitignore").write_text("notes/\n")
        self.commit("Ignore local notes")
        (self.repo / "draft.txt").write_text("Untracked draft")
        (self.repo / "notes").mkdir()
        (self.repo / "notes/local.txt").write_text("Ignored draft")
        target = self.root / "export"
        code, out, err = self.run_cli("--verify", "--export", str(target))
        self.assertEqual(code, 0, out + err)
        self.assertFalse((target / "draft.txt").exists())
        self.assertFalse((target / "notes/local.txt").exists())
        report = self.latest_report()
        self.assertEqual(report["export"]["not_exported"], {"count": 2, "paths": ["draft.txt", "notes/local.txt"]})
        self.assertEqual(report["scrub_plan"]["not_exported_count"], 2)
        self.assertEqual(report["export"]["file_count"], len([p for p in rc.git(target, "ls-files", "-z").split(b"\0") if p]))
        self.assertEqual(report["summary"]["blocking"], 0)

    def test_export_keeps_directory_exclusions(self):
        (self.repo / "credentials-old").mkdir()
        (self.repo / "credentials-old/notes.txt").write_text("Synthetic notes")
        self.commit("Add excluded folder")
        target = self.root / "export"
        scanner = rc.Scanner(self.terms)
        copied = rc.copy_tree(self.repo, target, self.manifest, scanner)
        self.assertFalse((target / "credentials-old").exists())
        self.assertNotIn("credentials-old/notes.txt", copied["files"])
        report = {"findings": [], "stats": {}}
        self.assertIn("credentials-old/notes.txt", rc.scrub_plan(report, self.repo, self.manifest, scanner)["drop_files"])

    def test_submodules_block_source_audit_and_export(self):
        for state in ("initialized", "uninitialized", "staged", "excluded"):
            with self.subTest(state=state):
                self.manifest["exclude"] = ["component"] if state == "excluded" else []
                self.save_manifest()
                (self.repo / ".gitmodules").write_text(
                    '[submodule "component"]\n\tpath = component\n\turl = https://example.org/component.git\n')
                oid = self.git("rev-parse", "HEAD").strip().decode()
                self.git("add", "--", ".gitmodules", "release-check.json")
                self.git("update-index", "--add", "--cacheinfo", f"160000,{oid},component")
                if state != "staged":
                    self.git("commit", "-q", "-m", "Add component")
                if state == "initialized":
                    (self.repo / "component").mkdir()
                    (self.repo / "component/inside.txt").write_text("HiddenPerson")
                code, out, err = self.run_cli()
                self.assertEqual(code, 1, out + err)
                source = self.latest_report()
                self.assertTrue(any(f["kind"] == "submodule" and f["scope"] == "tree"
                                    and f["severity"] == "blocking" for f in source["findings"]))
                self.assertFalse(any(f["path"].startswith("component/") for f in source["findings"]))
                target = self.root / ("export-" + state)
                code, out, err = self.run_cli("--verify", "--export", str(target))
                self.assertEqual(code, 1, out + err)
                report = self.latest_report()
                self.assertEqual(report["verdict"], "FIX-THESE")
                self.assertFalse(report["export"]["ready"])
                self.assertTrue(any(f["kind"] == "submodule" and f["scope"] == "export"
                                    and f["severity"] == "blocking" for f in report["export"]["findings"]))
                self.assertFalse((target / "component").exists())
                self.assertEqual(report["export"]["verification"]["status"], "pass")
                self.git("update-index", "--force-remove", "component")
                self.git("commit", "-q", "--allow-empty", "-m", "Remove component")
                if (self.repo / "component").exists():
                    shutil.rmtree(self.repo / "component")

    def test_export_commit_is_generic_and_utc(self):
        target = self.root / "export"
        with patch.dict(os.environ, {"TZ": "EST5EDT"}):
            rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        identity = rc.git(target, "log", "-1", "--format=%an%n%ae%n%cn%n%ce%n%ai%n%ci").decode().splitlines()
        self.assertEqual(identity[:4], ["Release Export", "release-export", "Release Export", "release-export"])
        self.assertTrue(all(date.endswith("+0000") for date in identity[4:]))
        self.assertEqual(rc.git(target, "rev-list", "--count", "--all").strip(), b"1")
        self.assertEqual(rc.git(target, "remote"), b"")

    def test_export_digest_matches_documented_algorithm(self):
        import hashlib
        (self.repo / "run.sh").write_bytes(b"echo example\n")
        (self.repo / "run.sh").chmod(0o755)
        (self.repo / "accent-\u00e9.txt").write_bytes(b"Example\r\n")
        self.commit("Add byte and mode examples")
        target = self.root / "export"
        code, out, err = self.run_cli("--verify", "--export", str(target))
        self.assertEqual(code, 0, out + err)
        export = self.latest_report()["export"]
        h = hashlib.sha256()
        for raw in sorted(filter(None, rc.git(target, "ls-files", "-z").split(b"\0"))):
            file = target / os.fsdecode(raw)
            h.update(raw + b"\0" + str(file.stat().st_mode & 0o111).encode() + b"\0" + str(file.stat().st_mtime_ns).encode() + b"\0")
            h.update(file.read_bytes() + b"\0")
        for file in sorted((target / ".git").rglob("*"), key=lambda p: p.relative_to(target / ".git").as_posix()):
            rel = file.relative_to(target / ".git").as_posix()
            h.update(rel.encode() + b"\0" + (b"directory" if file.is_dir() else file.read_bytes()) + b"\0")
        digest = hashlib.sha256(rc.git(target, "rev-parse", "HEAD").strip() + b"\0" + h.hexdigest().encode()).hexdigest()
        self.assertEqual(export["digest"], digest)
        self.assertEqual(rc.export_digest(target), digest)
        self.assertEqual(export["commit"], rc.git(target, "rev-parse", "HEAD").strip().decode())
        self.assertIn(digest, out)
        self.assertIn(digest, next(i["text"] for i in self.latest_report()["pre_publish_tests"] if i["id"] == "confirm-digest"))

    def test_check_digest_detects_changes(self):
        def check(target, digest, expected):
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = rc.main([str(target), "--check-digest", digest])
            self.assertEqual(code, expected, out.getvalue() + err.getvalue())
            self.assertIn("VERDICT: " + {0: "PASS", 1: "FIX-THESE", 2: "INCOMPLETE"}[expected], out.getvalue() + err.getvalue())
            self.assertNotIn(str(target), out.getvalue() + err.getvalue())
        for mutation in ("edit", "untracked", "second-commit", "ignored", "branch", "remote", "tag-only", "mode", "symlink", "config", "hook"):
            with self.subTest(mutation=mutation):
                target = self.root / mutation
                rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
                digest = rc.export_digest(target)
                check(target, digest, 1)  # A raw copy has no recorded audit and cannot pass.
                check(target, "0" * 64, 1)
                check(target, "invalid", 2)
                if mutation == "edit":
                    (target / "README.md").write_text("Changed")
                elif mutation == "untracked":
                    (target / "new.txt").write_text("New")
                elif mutation == "second-commit":
                    rc.git(target, "-c", "user.name=Example", "-c", "user.email=example", "commit", "-q", "--allow-empty", "-m", "Second")
                elif mutation == "ignored":
                    (target / ".git/info/exclude").write_text("ignored.txt\n")
                    (target / "ignored.txt").write_text("Ignored")
                elif mutation == "branch":
                    rc.git(target, "branch", "extra")
                elif mutation == "remote":
                    rc.git(target, "remote", "add", "example", str(self.repo))
                elif mutation == "tag-only":
                    tree = rc.git(target, "rev-parse", "HEAD^{tree}").strip().decode()
                    commit = rc.git(target, "-c", "user.name=Example", "-c", "user.email=example", "commit-tree", tree, "-m", "Separate").strip().decode()
                    rc.git(target, "tag", "extra", commit)
                elif mutation == "mode":
                    before = (target / "README.md").stat().st_mode & 0o111
                    (target / "README.md").chmod(0o700)
                    if (target / "README.md").stat().st_mode & 0o111 == before:
                        self.skipTest("This filesystem does not support changing Unix execute bits")
                elif mutation == "config":
                    rc.git(target, "config", "user.name", "Example")
                elif mutation == "hook":
                    (target / ".git/hooks/pre-commit").write_text("#!/bin/sh\nexit 0\n")
                else:
                    (target / "README.md").unlink()
                    (target / "README.md").symlink_to("LICENSE")
                check(target, digest, 1)
        self.assertFalse((self.root / "reports").exists())

    def test_check_digest_rejects_every_added_ref(self):
        token = "gh" + "p_" + "A" * 30
        for kind in ("lightweight", "annotated", "blob-tag", "tree-tag", "custom-ref"):
            with self.subTest(kind=kind):
                target = self.root / kind
                rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
                digest = rc.export_digest(target)
                if kind == "lightweight":
                    rc.git(target, "tag", "extra", "HEAD")
                elif kind == "annotated":
                    rc.git(target, "-c", "user.name=Example", "-c", "user.email=example",
                           "-c", "tag.gpgsign=false", "tag", "-a", "extra", "-m", "HiddenPerson", "HEAD")
                else:
                    blob = subprocess.run(["git", "-C", str(target), "hash-object", "-w", "--stdin"],
                                          input=token.encode(), capture_output=True, check=True).stdout.strip().decode()
                    if kind == "tree-tag":
                        entry = f"100644 blob {blob}\tsecret.txt\n".encode()
                        oid = subprocess.run(["git", "-C", str(target), "mktree"], input=entry,
                                             capture_output=True, check=True).stdout.strip().decode()
                    else:
                        oid = blob
                    if kind == "custom-ref":
                        rc.git(target, "update-ref", "refs/leak/example", oid)
                    else:
                        rc.git(target, "tag", "extra", oid)
                # Ref checks include loose and packed refs, regardless of object type.
                for packed in (False, True):
                    with self.subTest(packed=packed):
                        if packed:
                            rc.git(target, "pack-refs", "--all")
                        out, err = io.StringIO(), io.StringIO()
                        with redirect_stdout(out), redirect_stderr(err):
                            code = rc.main([str(target), "--check-digest", digest])
                        self.assertEqual(code, 1, out.getvalue() + err.getvalue())
                        self.assertIn("VERDICT: FIX-THESE", out.getvalue())
                        for private in (token, "HiddenPerson", str(target)):
                            self.assertNotIn(private, out.getvalue() + err.getvalue())
                self.assertEqual(rc.git(target, "rev-list", "--count", "--all").strip(), b"1")
        self.assertFalse((self.root / "reports").exists())

    def test_replaced_git_function_controls_export_identity(self):
        original = rc.git
        commits = []
        def replacement(repo, *args):
            if "commit" in args:
                args = tuple("user.name=Example Export" if arg.startswith("user.name=") else "user.email=example-export" if arg.startswith("user.email=") else arg for arg in args)
                args = (*args[:-1], "Example export message")
                commits.append(args)
            return original(repo, *args)
        target = self.root / "export"
        with patch.object(rc, "git", replacement):
            rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        self.assertEqual(len(commits), 1)
        self.assertEqual(rc.git(target, "log", "-1", "--format=%an%n%ae%n%B").decode().strip().splitlines(), ["Example Export", "example-export", "Example export message"])
        def changing_copy(repo, *args):
            result = original(repo, *args)
            if "commit" in args:
                (repo / "README.md").write_text("Changed during export")
            return result
        scanner = rc.Scanner(self.terms)
        with patch.object(rc, "git", changing_copy):
            rc.copy_tree(self.repo, self.root / "changed-export", self.manifest, scanner)
        self.assertTrue(any(f["kind"] == "export-content-mismatch" and not f["reviewed"] for f in scanner.findings))

    def test_versions_agree(self):
        import re
        import tomllib
        root = Path(rc.__file__).parent
        project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
        heading = re.search(r"^## (\d+\.\d+\.\d+)", (root / "CHANGELOG.md").read_text(), re.M)
        self.assertIsNotNone(heading)
        self.assertEqual(rc.VERSION, project["version"])
        self.assertEqual(rc.VERSION, heading.group(1))

    def test_own_manifest_matches_own_readme(self):
        import shlex
        root = Path(rc.__file__).parent
        manifest = json.loads((root / "release-check.json").read_text())
        for entry in manifest["quickstart"]:
            lines = (root / entry["file"]).read_text().splitlines()
            self.assertEqual(shlex.split(lines[entry["line"] - 1]), entry["argv"])

    def test_example_denylist_is_generic_and_requires_replacement(self):
        path = Path(rc.__file__).parent / "examples/denylist.example.json"
        with self.assertRaisesRegex(rc.AuditError, 'denylist-example'):
            rc.load_terms(path)
        scanner = rc.Scanner([])
        scanner.file(path.read_bytes(), "tree", "examples/denylist.example.json")
        self.assertEqual(scanner.findings, [])

    def test_library_signatures_are_stable(self):
        import inspect
        expected = {
            rc.Scanner.__init__: ["self", "terms", "private_repos", "approvals"],
            rc.Scanner.text: ["self", "raw", "scope", "path", "object_id"],
            rc.Scanner.add: ["self", "scope", "category", "kind", "path", "line", "value", "term_index", "object_id"],
            rc.load_terms: ["path"], rc.manifest_for: ["repo", "path"],
            rc.verify: ["repo", "report_dir", "scanner", "manifest", "timeout"],
            rc.audit: ["repo", "terms", "manifest", "private_repos", "verify_commands", "report_dir", "timeout"],
            rc.copy_tree: ["repo", "target", "manifest", "scanner"],
            rc.license_audit: ["repo", "scanner", "manifest"],
            rc.protected: ["path"], rc.git: ["repo", "args"],
        }
        for function, names in expected.items():
            self.assertEqual(list(inspect.signature(function).parameters), names)
        self.assertEqual(rc.Scanner([]).findings, [])
        report = rc.audit(self.repo, self.terms, self.manifest, [], False, self.root, 30)
        self.assertEqual(set(report), {"version", "ready", "counts", "reviewed_count", "stats", "license", "verification", "findings"})

    def test_tool_is_one_stdlib_file_with_no_network_or_publish(self):
        import ast
        import tomllib
        root = Path(rc.__file__).parent
        tree = ast.parse(Path(rc.__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0)
                imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertNotIn(node.value, {"push", "fetch", "pull", "ls-remote"})
        self.assertTrue(imports <= sys.stdlib_module_names)
        self.assertTrue(imports.isdisjoint({"socket", "urllib", "http", "ftplib", "smtplib", "ssl"}))
        project = tomllib.loads((root / "pyproject.toml").read_text())
        self.assertEqual(project["project"]["dependencies"], [])
        self.assertEqual(project["tool"]["setuptools"]["py-modules"], ["release_check"])
        self.assertEqual(sorted(p.name for p in root.glob("*.py")), ["release_check.py"])

    def test_own_tracked_files_pass_builtin_detectors(self):
        root = Path(rc.__file__).parent
        try:
            tracked = rc.git(root, "ls-files", "-z")
        except rc.AuditError:
            self.skipTest("Tracked-file list is unavailable")
        manifest = json.loads((root / "release-check.json").read_text())
        scanner = rc.Scanner([], approvals=manifest["approvals"])
        for raw in filter(None, tracked.split(b"\0")):
            rel = os.fsdecode(raw)
            scanner.file((root / rel).read_bytes(), "tree", rel)
        self.assertEqual([f for f in scanner.findings if not f["reviewed"]], [])
        self.assertTrue(all(isinstance(a.get("reason"), str) and a["reason"].strip() for a in manifest["approvals"]))

    def test_default_exclusions_are_generic(self):
        self.assertEqual(rc.DEFAULT_EXCLUDES, [
            ".git", ".env", ".env.*", "*.env", ".npmrc", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "*.pem", "*.key", "*.p12", "*.pfx",
            "credentials*", "*token.json", ".git-credentials", ".netrc", ".pgpass", ".htpasswd", "kubeconfig", ".pypirc",
            "*.jks", "*.keystore", "terraform.tfstate", "*.tfstate", ".docker/config.json", "keystore.properties", ".kube/config",
        ])

    def test_short_aliases_detect_words_and_filenames_not_digest_substrings(self):
        scanner=rc.Scanner(['z07'])
        scanner.text(b'sha256:abcz07def https://files.pythonhosted.org/abz07cd/wheel.whl', 'tree', 'uv.lock')
        self.assertEqual(scanner.findings, [])
        scanner.text(b'z07\nZ07.example.invalid\n/units/tool-z07-demo.service', 'tree', 'config')
        self.assertEqual(len(scanner.findings), 3)
        scanner.file(b'', 'tree', 'tool-z07.service')
        self.assertTrue(any(f['kind']=='denylist' and f['path'].startswith('[path-') for f in scanner.findings))

    def test_full_history_names_metadata_and_case_insensitive_terms(self):
        (self.repo / "HIDDENPERSON.txt").write_text("hiddenperson\n")
        self.git("config", "user.name", "HiddenPerson")
        self.commit("Decided with hiddenperson")
        self.git("rm", "--", "HIDDENPERSON.txt")
        self.git("commit", "-q", "-m", "Remove file")
        scanner = self.scan()
        findings = [f for f in scanner.findings if f["kind"] == "denylist"]
        self.assertTrue(any(f["scope"] == "metadata" for f in findings))
        self.assertTrue(any(f["scope"] == "history" for f in findings))
        self.assertFalse(any(f["scope"] == "tree" for f in findings))
        raw = json.dumps(scanner.findings)
        self.assertNotIn("hiddenperson", raw.lower())
        self.assertTrue(all(f["term_index"] == 0 for f in findings))
        self.assertTrue(any(f["path"].startswith("[path-") for f in findings))

    def test_other_branch_and_deleted_blob(self):
        self.git("checkout", "-q", "-b", "old")
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Old")
        self.git("checkout", "-q", "main")
        self.assertTrue(any(f["kind"] == "denylist" and f["scope"] == "history" for f in self.scan().findings))

    def test_builtin_network_and_personal_detectors(self):
        raw = ("\n".join([
            "demo@" + "example.org", "+1 " + "555-" + "123-" + "4567",
            "192.0." + "2.1", "2001:" + "db8:" + ":1", "100.64." + "3.4",
            "node." + "ts.net", "/home/" + "fakeuser/data",
            "C:\\" + "Users\\" + "fakeuser\\data", "node." + "internal",
            "buildbox-" + "07", "https://github.com/" + "fake/private-repo",
        ]) + "\n").encode()
        scanner = rc.Scanner(self.terms, ["fake/private-repo"])
        scanner.file(raw, "tree", "text.txt")
        kinds = {f["kind"] for f in scanner.findings}
        self.assertTrue({"email", "phone", "ipv4", "ipv6", "tailnet-ip", "tailnet-host", "home-path", "internal-host", "private-repo-url"} <= kinds)
        self.assertNotIn("fakeuser", json.dumps(scanner.findings))

    def test_secrets_values_never_reach_output_or_reports(self):
        secret = "gh" + "p_" + "Ab2C3d4E5f6G7h8I9j0K" + "lmNOPqRsTuvWxYz"
        (self.repo / "secret.txt").write_text("key=" + secret)
        self.commit("Test")
        code, out, err = self.run_cli("--scrub-plan")
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out + err)
        reports = list((self.root / "reports").rglob("report.*"))
        self.assertEqual(len(reports), 2)
        for p in reports:
            if os.name != "nt":
                self.assertEqual(p.stat().st_mode & 0o777, 0o600)
                self.assertEqual(p.parent.stat().st_mode & 0o777, 0o700)
            self.assertNotIn(secret, p.read_text())
        report = json.loads(next(p for p in reports if p.suffix == ".json").read_text())
        self.assertGreater(report["counts"]["secrets"], 0)
        self.assertTrue(any(f["line"] == 1 and f["kind"] == "github-token" for f in report["findings"]))

    def test_utf16_terms_are_not_skipped(self):
        scanner = rc.Scanner(self.terms)
        scanner.file("HiddenPerson".encode("utf_16"), "tree", "wide.txt")
        self.assertTrue(any(f["kind"] == "denylist" for f in scanner.findings))

    def test_specific_review_cannot_waive_denylist_or_secret(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"HiddenPerson", "tree", "data.txt")
        finding = scanner.findings[0]
        approve = {k: finding[k] for k in ("scope", "kind", "path", "fingerprint")}
        repeat = rc.Scanner(self.terms, approvals=[approve])
        repeat.file(b"HiddenPerson", "tree", "data.txt")
        self.assertFalse(repeat.findings[0]["reviewed"])
        repeat = rc.Scanner(self.terms)
        repeat.file((b"demo@" + b"example.org"), "tree", "text.txt")
        hit = next(f for f in repeat.findings if f["kind"] == "email")
        repeat = rc.Scanner(self.terms, approvals=[hit])
        repeat.file((b"demo@" + b"example.org"), "tree", "text.txt")
        repeat.file((b"demo@" + b"example.org"), "tree", "other.txt")
        self.assertEqual(sum(f["reviewed"] for f in repeat.findings), 1)

    def test_private_filename_and_ipv6_filename_are_fingerprinted(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"fixture", "tree", "HiddenPerson.txt")
        self.assertTrue(all(f["path"].startswith("[path-") for f in scanner.findings))
        self.assertTrue(scanner.safe_path("2001:" + "db8:" + ":1.txt").startswith("[path-"))

    def test_opaque_secret_filename_never_reaches_reports(self):
        value = "Ab3D4e5F6g7H8i9J0kL1m" + "N2oP3qR4sT5uV6wX7yZ8"
        (self.repo / (value + ".txt")).write_text("fixture")
        code, out, err = self.run_cli("--scrub-plan")
        self.assertEqual(code, 1)
        self.assertNotIn(value, out + err)
        for report in (self.root / "reports").rglob("report.*"):
            self.assertNotIn(value, report.read_text())

    def test_untrusted_check_label_cannot_leak_into_reports(self):
        secret = "Synthetic" + "PrivateLabel"
        scanner = rc.Scanner(self.terms)
        manifest = {**self.manifest, "checks": [{"role": secret, "argv": ["python", "-c", "print(1)"]}]}
        with patch.object(rc, "command") as call:
            with self.assertRaises(rc.AuditError):
                rc.verify(self.repo, self.root, scanner, manifest, 10)
        call.assert_not_called()
        self.assertNotIn(secret, json.dumps(scanner.findings))

    def test_malformed_manifest_is_a_safe_incomplete_audit(self):
        (self.repo / "release-check.json").write_text(json.dumps({"checks": ["SyntheticPrivateManifestContent"]}))
        code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertNotIn("SyntheticPrivateManifestContent", out + err)

    def test_invalid_cli_argument_is_not_printed(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as caught:
                rc.main([str(self.repo), "--timeout", "SyntheticPrivateArgument"])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("SyntheticPrivateArgument", out.getvalue() + err.getvalue())

    def test_lfs_pointer_blocks_unscanned_content(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(("version https://git-lfs.github.com/" + "spec/v1\noid sha256:" + "a" * 64 + "\nsize 42\n").encode(), "tree", "pointer.txt")
        self.assertTrue(any(f["kind"] == "lfs-content-not-scanned" for f in scanner.findings))

    def test_public_commit_signature_is_not_treated_as_a_secret(self):
        raw = b"tree " + b"a" * 40 + b"\nauthor Fixture <fixture> 1 +0000\ncommitter Fixture <fixture> 1 +0000\ngpgsig BEGIN SIGNATURE\n random-public-signature\n\nMessage HiddenPerson\n"
        filtered = rc.commit_text(raw)
        self.assertIn(b"author Fixture", filtered)
        self.assertIn(b"Message HiddenPerson", filtered)
        self.assertNotIn(b"random-public-signature", filtered)

    def test_versions_and_classifier_punctuation_are_not_network_addresses(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b'attrs-26.1.0\n2026-03-19T14:22:25Z\n"License :: OSI Approved :: MIT License"\nPath.home()\n', "tree", "metadata.txt")
        self.assertEqual(scanner.findings, [])

    def test_entropy_and_key_formats_cannot_be_approved(self):
        value = "Ab3D4e5F6g7H8i9J0kL1m" + "N2oP3qR4sT5uV6wX7yZ8"
        scanner = rc.Scanner(self.terms)
        scanner.file(value.encode(), "tree", "random.txt")
        self.assertTrue(any(f["kind"] == "entropy" for f in scanner.findings))
        repeat = rc.Scanner(self.terms, approvals=scanner.findings)
        repeat.file(value.encode(), "tree", "random.txt")
        self.assertTrue(all(not f["reviewed"] for f in repeat.findings))

    def test_compressed_and_binary_files_require_review(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"binary\0bytes", "tree", "archive.zip")
        self.assertTrue(any(f["kind"] == "binary-review" for f in scanner.findings))

    def test_export_flattens_history_and_excludes_config_without_source_write(self):
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Private history")
        self.git("rm", "--", "old.txt")
        self.git("commit", "-q", "-m", "Remove")
        (self.repo / ".env").write_text("fixture config")
        before = self.git("status", "--porcelain")
        scanner = rc.Scanner(self.terms)
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, scanner)
        self.assertFalse((target / ".env").exists())
        self.assertEqual(before, self.git("status", "--porcelain"))
        self.assertEqual(rc.git(target, "rev-list", "--count", "HEAD").strip(), b"1")
        self.assertEqual(rc.git(target, "remote").strip(), b"")
        clean = rc.Scanner(self.terms)
        clean.tree(target)
        clean.history(target)
        self.assertEqual(clean.findings, [])

    def test_export_refuses_existing_destination(self):
        target = self.root / "export"
        target.mkdir()
        (target / "keep").write_text("preserve")
        with self.assertRaises(rc.AuditError):
            rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        self.assertEqual((target / "keep").read_text(), "preserve")

    def test_symlink_is_not_followed_or_copied(self):
        outside = self.root / "outside"
        outside.write_text("HiddenPerson")
        (self.repo / "linked").symlink_to(outside)
        scanner = self.scan()
        self.assertTrue(any(f["kind"] == "symlink" for f in scanner.findings))
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, scanner)
        self.assertFalse((target / "linked").exists())

    def test_media_is_reviewed_by_exact_fingerprint(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"image fixture", "tree", "image.png")
        self.assertTrue(any(f["category"] == "media" for f in scanner.findings))

    def test_license_text_and_protected_attribution(self):
        scanner = rc.Scanner(self.terms)
        self.assertEqual(rc.license_audit(self.repo, scanner, self.manifest)["status"], "pass")
        manifest = {**self.manifest, "exclude": ["LICENSE"]}
        rc.license_audit(self.repo, scanner, manifest)
        self.assertTrue(any(f["kind"] == "excluded-attribution" for f in scanner.findings))
        (self.repo / "LICENSE").write_text("MIT License\nPermission is hereby granted to do something else.")
        self.assertEqual(rc.license_audit(self.repo, scanner, self.manifest)["status"], "blocked")

    def test_historical_notice_cannot_be_removed_from_export(self):
        (self.repo / "NOTICE").write_text("Upstream attribution fixture.")
        self.commit("Add attribution")
        self.git("rm", "--", "NOTICE")
        self.git("commit", "-q", "-m", "Remove notice")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 1, out + err)
        report = json.loads(next((self.root / "reports").rglob("report.json")).read_text())
        self.assertFalse(report["export"]["ready"])
        self.assertTrue(any(f["kind"] == "historical-attribution-missing" for f in report["export"]["findings"]))

    def test_changed_notice_blocks_but_added_notice_context_preserves_attribution(self):
        (self.repo / "NOTICE").write_text("Upstream attribution fixture.\n")
        self.commit("Add attribution")
        (self.repo / "NOTICE").write_text("New context.\nUpstream attribution fixture.\n")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "good-export"))
        self.assertEqual(code, 0, out + err)
        (self.repo / "NOTICE").write_text("Different attribution.\n")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "bad-export"))
        self.assertEqual(code, 1, out + err)
        report = json.loads(sorted((self.root / "reports").rglob("report.json"))[-1].read_text())
        self.assertTrue(any(f["kind"] == "historical-attribution-changed" for f in report["export"]["findings"]))

    def test_shallow_history_blocks_coverage(self):
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth=1", self.repo.as_uri(), str(shallow)], check=True, capture_output=True)
        scanner = rc.Scanner(self.terms)
        scanner.history(shallow)
        self.assertTrue(any(f["kind"] == "shallow-history" for f in scanner.findings))

    def test_denylist_inside_source_is_refused_with_no_content(self):
        path = self.repo / "list.json"
        path.write_text('["HiddenPerson"]')
        code, out, err = self.run_cli("--denylist", str(path))
        self.assertEqual(code, 2)
        self.assertNotIn("HiddenPerson", out + err)

    def test_dependency_unknown_and_incompatible_licenses_block(self):
        package = {"name": "fixture", "version": "1", "expression": "GPL-3.0-only", "license": None, "classifiers": [], "license_files": [{"path": "LICENSE", "hash": "f" * 64}]}
        scanner = rc.Scanner(self.terms)
        result = rc.dependency_audit(json.dumps([package]).encode(), self.repo, scanner, self.manifest)
        self.assertEqual(result["blocked"], 1)
        package["expression"] = "MIT"
        result = rc.dependency_audit(json.dumps([package]).encode(), self.repo, rc.Scanner(self.terms), self.manifest)
        self.assertEqual(result["blocked"], 0)

    def test_quickstart_mismatch_never_runs(self):
        scanner = rc.Scanner(self.terms)
        with patch.object(rc, "command") as call:
            result = rc.verify(self.repo, self.root, scanner, {**self.manifest, "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", "print(2)"]}]}, 10)
        self.assertEqual(result["status"], "blocked")
        call.assert_not_called()

    def test_clean_clone_quickstart_and_tests_run_without_inherited_credentials(self):
        scanner = rc.Scanner(self.terms)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "never-inherit-" + "fixture"}):
            result = rc.verify(self.repo, self.root, scanner, self.manifest, 30)
        self.assertEqual(result["status"], "pass", scanner.findings)
        self.assertEqual([r["exit_code"] for r in result["commands"]], [0, 0])
        self.assertNotIn("GITHUB_TOKEN", rc.safe_environment(self.root / "home", self.root / "bin"))

    def test_command_failure_output_is_only_fingerprinted(self):
        scanner = rc.Scanner(self.terms)
        secret = "Synthetic" + "PrivateFailureText"
        manifest = {**self.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", f"import sys;print('{secret}');sys.exit(3)"]}]}
        result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["commands"][-1]["exit_code"], 3)
        self.assertNotIn(secret, json.dumps(result) + json.dumps(scanner.findings))

    def test_missing_venv_support_explains_remedy_and_runs_no_steps(self):
        scanner = rc.Scanner(self.terms)
        with patch.object(rc, "command", return_value=(1, b"ensurepip unavailable")):
            result = rc.verify(self.repo, self.root, scanner, self.manifest, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["commands"], [])
        finding = next(f for f in scanner.findings if f["kind"] == "venv-creation-failed")
        for text in ("python3-venv", "uv", "did not execute the quickstart or tests"):
            self.assertIn(text, rc.fix_for(finding))

    def test_missing_declared_executable_is_a_blocker_with_plain_guidance(self):
        scanner = rc.Scanner(self.terms)
        manifest = {**self.manifest, "checks": [{"role": "tests", "argv": ["missing-fixture-program"]}]}
        result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual([step["exit_code"] for step in result["commands"]], [0, 127])
        finding = next(f for f in scanner.findings if f["kind"] == "command-not-found")
        self.assertIn("earlier quickstart step", rc.fix_for(finding))

    def test_command_exit_127_is_not_misreported_as_missing_executable(self):
        scanner = rc.Scanner(self.terms)
        manifest = {**self.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", "raise SystemExit(127)"]}]}
        result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["commands"][-1]["exit_code"], 127)
        self.assertIn("command-failed", {f["kind"] for f in scanner.findings})
        self.assertNotIn("command-not-found", {f["kind"] for f in scanner.findings})

    def test_verification_uses_fresh_python_and_profile_not_parent_environment(self):
        import shlex
        script = "import os,sys; assert sys.prefix != sys.base_prefix; assert os.environ['HOME'] == os.environ['TEMP']; assert 'SAMPLE_PRIVATE_VALUE' not in os.environ"
        (self.repo / "README.md").write_text("# Sample\n## Limitations\nSynthetic only.\npython -c " + shlex.quote(script) + "\n")
        manifest = {**self.manifest, "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", script]}]}
        scanner = rc.Scanner(self.terms)
        with patch.dict(os.environ, {"SAMPLE_PRIVATE_VALUE": "never-inherit"}):
            result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "pass", scanner.findings)
        self.assertEqual([step["exit_code"] for step in result["commands"]], [0, 0])

    def test_command_timeout_kills_process_and_blocks(self):
        code, output = rc.command([sys.executable, "-c", "import time;time.sleep(30)"], self.repo, rc.safe_environment(self.root / "home", Path(sys.executable).parent), 1)
        self.assertEqual(code, 124)

    def test_incomplete_scan_still_saves_safe_failure_report(self):
        with patch.object(rc.Scanner, "tree", side_effect=OSError("private-exception-detail")):
            code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        report = next((self.root / "reports").rglob("report.json")).read_text()
        self.assertNotIn("private-exception-detail", report + out + err)
        self.assertEqual(json.loads(report)["counts"], {"coverage": 1})

    def test_cli_export_ready_with_private_history_and_zero_export_findings(self):
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Private history")
        self.git("rm", "--", "old.txt")
        self.git("commit", "-q", "-m", "Remove")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 0, out + err)
        report = json.loads(next((self.root / "reports").rglob("report.json")).read_text())
        self.assertFalse(report["ready"])
        self.assertTrue(report["export"]["ready"])
        self.assertEqual(report["export"]["counts"], {})

    def test_dogfood_labelled_literals_block_without_disclosing_values(self):
        literal = "Sup3r" + "S3cretPw1"
        lines = [
            "DB_PASSWORD" + "=" + literal, "db_password" + ' = "' + literal + '"',
            "MYSQL_PASSWORD" + ": " + literal, "export DB_PASSWORD" + "=" + literal,
            *(label + "=" + literal for label in ("SECRET", "client_secret", "API_TOKEN", "token", "pwd")),
            json.dumps(dict([("password", literal)])), '"api_key"' + ': "' + literal + '"',
            "'password'" + ": '" + literal + "'", "'api_key'" + ": '" + literal + "'",
            "aws_secret_access_key" + " = " + "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY",
            "pwd" + "=" + "a7",
        ]
        for line in lines:
            with self.subTest(line=lines.index(line)):
                scanner = rc.Scanner([], approvals=[])
                scanner.text(line.encode(), "tree", "settings.txt")
                self.assertTrue(any(f["kind"] == "assigned-secret" for f in scanner.findings))
                self.assertTrue(all(not f["reviewed"] for f in scanner.findings))
        (self.repo / "settings.txt").write_text("\n".join(lines))
        self.git("add", "--", "settings.txt")
        code, out, err = self.run_cli("--export", str(self.root / "tracked-export"))
        self.assertEqual(code, 1, out + err)
        report = self.latest_report()
        self.assertEqual({f["line"] for f in report["export"]["findings"] if f["kind"] == "assigned-secret"}, set(range(1, len(lines) + 1)))
        for text in (out, err, *(p.read_text() for p in (self.root / "reports").rglob("report.*"))):
            self.assertNotIn(literal, text)

    def test_dogfood_placeholders_and_environment_references_pass(self):
        values = [
            "changeme", "change_me", "your_key_here", "<token>", "xxx", "example", "...",
            '""', "''", 'os.environ["SVC"]', 'os.environ.get("SVC")',
            'os.getenv("SVC")', "${VAR}", '"${VAR}"', "process.env.X", 'env("X")',
        ]
        lines = ["API_KEY = " + value for value in values]
        lines += ["DB_PASSWORD=" + value for value in values]
        scanner = rc.Scanner([])
        scanner.text("\n".join(lines).encode(), "tree", "settings.txt")
        self.assertEqual(scanner.findings, [])
        (self.repo / "settings.txt").write_text("\n".join(lines))
        self.git("add", "--", "settings.txt")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 0, out + err)

    def test_python_names_and_annotations_are_references(self):
        lines = [
            "def load(" + "token" + ": str):", "token" + ": str | None = None",
            "self.token" + " = token", "API_KEY" + " = injected_value",
        ]
        scanner = rc.Scanner([])
        scanner.text("\n".join(lines).encode(), "tree", "settings.py")
        self.assertEqual(scanner.findings, [])
        scanner.text(("DB_PASSWORD" + ' = "' + "Sup3r" + "S3cretPw1" + '"').encode(), "tree", "settings.py")
        self.assertEqual([f["kind"] for f in scanner.findings], ["assigned-secret"])

    def test_dogfood_webhook_urls_cannot_be_approved(self):
        urls = [
            "https://hooks." + "slack.com/services/T000/B000/" + "FixtureWebhookValue9",
            "https://discord." + "com/api/webhooks/123456789/" + "FixtureWebhookValue9",
            "https://discordapp." + "com/api/v10/webhooks/123456789/" + "FixtureWebhookValue9",
        ]
        for url in urls:
            scanner = rc.Scanner([])
            scanner.text(url.encode(), "tree", "settings.txt")
            self.assertEqual([f["kind"] for f in scanner.findings], ["webhook-url"])
            repeat = rc.Scanner([], approvals=scanner.findings)
            repeat.text(url.encode(), "tree", "settings.txt")
            self.assertFalse(repeat.findings[0]["reviewed"])
            self.assertNotIn(url, json.dumps(repeat.findings))

    def test_dogfood_credential_files_are_scanned_and_excluded(self):
        paths = [
            "prod.env", ".env.local", ".env.production", "config/service.env", ".npmrc",
            "config/.npmrc", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "backup_id_rsa",
            "tokens.txt", "credentials.json", "server.pem", "config/.ENV.LOCAL",
        ]
        for rel in paths:
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("DB_PASSWORD" + "=" + "Sup3r" + "S3cretPw1")
        self.git("add", "--", *paths)
        scanner = self.scan()
        for rel in paths:
            self.assertTrue(any(f["kind"] == "credential-file" and f["path"] == rel for f in scanner.findings), rel)
        target = self.root / "export"
        code, out, err = self.run_cli("--verify", "--export", str(target))
        self.assertEqual(code, 0, out + err)
        self.assertTrue(all(not (target / rel).exists() for rel in paths))
        self.assertEqual(set(self.latest_report()["scrub_plan"]["drop_files"]), set(paths))

    def test_dogfood_named_home_paths_are_redacted(self):
        raw = "~" + "jdoe/notes"
        for scope in ("tree", "history"):
            scanner = rc.Scanner([])
            scanner.text(raw.encode(), scope, "notes.txt")
            self.assertEqual([f["kind"] for f in scanner.findings], ["home-path"])
            self.assertNotIn("jdoe", json.dumps(scanner.findings))
            self.assertTrue(scanner.safe_path(raw).startswith("[path-"))
        scanner = rc.Scanner([])
        scanner.text(b"~/.cache ./relative README.md", "tree", "notes.txt")
        self.assertEqual(scanner.findings, [])

    def test_dogfood_approvals_require_each_scope(self):
        (self.repo / "example.txt").write_text("security@" + "example.com")
        self.commit("Add deliberate example")
        findings = [f for f in self.scan().findings if f["kind"] == "email"]
        self.assertEqual({f["scope"] for f in findings}, {"tree", "history"})
        for scope, missing in (("tree", "history"), ("history", "tree")):
            self.manifest["approvals"] = [f for f in findings if f["scope"] == scope]
            self.save_manifest()
            code, out, err = self.run_cli("--export", str(self.root / (scope + "-export")))
            self.assertEqual(code, 1, out + err)
            blocked = [f for f in self.latest_report()["export"]["findings"] if f["kind"] == "email" and not f["reviewed"]]
            self.assertEqual({f["scope"] for f in blocked}, {missing})
            self.assertIn('still lacks approval in scope "' + missing + '"', out)
            self.assertNotIn("Publish a one-commit copy", out)
        self.manifest["approvals"] = findings
        self.save_manifest()
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "both-export"))
        self.assertEqual(code, 0, out + err)

    def test_dogfood_missing_or_malformed_manifests_are_incomplete(self):
        external = self.root / "SyntheticPrivateManifest.json"
        for content, error in ((None, "manifest-not-found"), ("{", "manifest-schema"), ("[]", "manifest-schema"), ('{"checks": [1]}', "manifest-schema"), ('{"checks": [{"argv": 7}]}', "command-schema")):
            if content is not None:
                external.write_text(content)
            for extra in ((), ("--verify",), ("--export", str(self.root / "export"))):
                for json_mode in (False, True):
                    code, out, err = self.run_cli("--manifest", str(external), *extra, *(("--json",) if json_mode else ()))
                    self.assertEqual(code, 2, out + err)
                    self.assertIn(error, err)
                    self.assertNotIn("SyntheticPrivateManifest", out + err)
                    self.assertFalse((self.root / "export").exists())
        (self.repo / "release-check.json").write_text("{")
        code, out, err = self.run_cli("--verify")
        self.assertEqual(code, 2, out + err)
        self.assertIn("manifest-schema", err)
        self.assertIn("invalid JSON/schema", err)

    def test_invalid_commands_are_incomplete_before_missing_verification_steps(self):
        self.manifest["quickstart"] = []
        self.manifest["checks"] = [dict(role="tests", argv=7)]
        self.save_manifest()
        code, out, err = self.run_cli("--verify")
        self.assertEqual(code, 2, out + err)
        self.assertIn("command-schema", err)

    def test_dogfood_external_manifest_is_not_copied(self):
        external = self.root / "manifest.json"
        external.write_text(json.dumps(self.manifest))
        self.git("rm", "--", "release-check.json")
        target = self.root / "export"
        code, out, err = self.run_cli("--manifest", str(external), "--verify", "--export", str(target))
        self.assertEqual(code, 0, out + err)
        self.assertFalse((target / "release-check.json").exists())

    def test_dogfood_digest_missing_or_non_git_target_is_incomplete(self):
        plain = self.root / "plain"
        plain.mkdir()
        for target, error in ((self.root / "missing", "repo-not-found"), (plain, "not-a-git-repository")):
            for json_mode in (False, True):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = rc.main([str(target), "--check-digest", "0" * 64, *(("--json",) if json_mode else ())])
                self.assertEqual(code, 2)
                self.assertIn(error, err.getvalue())
                self.assertNotIn(str(target), out.getvalue() + err.getvalue())

    def test_dogfood_digest_rejects_sample_hooks_and_requires_exact_config(self):
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner([]))
        digest = rc.export_digest(target)
        hooks = target / ".git/hooks"
        sample = hooks / "fixture.sample"
        sample.write_text("#!/bin/sh\nexit 0\n")
        sample.chmod(0o700)
        with self.assertRaisesRegex(rc.AuditError, "export-not-clean"):
            rc.export_digest(target)
        hook = hooks / "pre-commit"
        hook.write_bytes(sample.read_bytes())
        for mode in (0o600, 0o700):
            hook.chmod(mode)
            with self.assertRaisesRegex(rc.AuditError, "export-not-clean"):
                rc.export_digest(target)
        hook.unlink()
        sample.unlink()
        config = target / ".git/config"
        original = config.read_bytes()
        config.write_bytes(original + b"\n")
        with self.assertRaisesRegex(rc.AuditError, "export-not-clean"):
            rc.export_digest(target)
        config.write_bytes(original)
        self.assertEqual(rc.export_digest(target), digest)


if __name__ == "__main__":
    unittest.main()
