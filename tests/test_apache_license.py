"""Apache recognition and retained derivative attribution, using synthetic history."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import release_check as rc

COAUTHOR = "Co-Authored-By: Claude Sonnet 5.5 <noreply@" + "anthropic.com>"

CANONICAL = (Path(__file__).parent / "fixtures/Apache-2.0.txt").read_text()
BODY, APPENDIX = CANONICAL.split("END OF TERMS AND CONDITIONS", 1)
BODY += "END OF TERMS AND CONDITIONS"
NOTICE = APPENDIX[APPENDIX.index("Copyright "):].replace(
    "[yyyy] [name of copyright owner]", "2026 Example Contributors")


class ApacheLicenseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.manifest = {"exclude": []}
        self.write_license(CANONICAL)

    def write_license(self, text):
        (self.repo / "LICENSE").write_text(text)

    def audit(self):
        scanner = rc.Scanner([])
        result = rc.license_audit(self.repo, scanner, self.manifest)
        return result, {f["kind"] for f in scanner.findings}

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="Release Export", GIT_AUTHOR_EMAIL="release-export",
                   GIT_COMMITTER_NAME="Release Export", GIT_COMMITTER_EMAIL="release-export")
        return subprocess.run(["git", "-C", str(self.repo), *args], env=env,
                              check=True, capture_output=True).stdout

    def commit(self):
        if not (self.repo / ".git").exists():
            self.git("init", "-q", "-b", "main")
        paths = [p.name for p in self.repo.iterdir() if p.is_file()]
        self.git("add", "--", *paths)
        self.git("commit", "-q", "-m", "Synthetic upstream\n\n" + COAUTHOR)

    def test_canonical_and_standard_appendix_variants_pass(self):
        for text in (CANONICAL, BODY, BODY + "\n" + NOTICE,
                     CANONICAL.replace("[yyyy] [name of copyright owner]", "2026 Example Contributors"),
                     re.sub(r"\s+", " ", CANONICAL), CANONICAL.replace("\n", "\r\n")):
            with self.subTest(text=text[-60:]):
                self.write_license(text)
                result, kinds = self.audit()
                self.assertEqual(result["identifier"], "Apache-2.0")
                self.assertEqual(result["status"], "pass")
                self.assertEqual(kinds, set())

    def test_modified_truncated_and_extra_terms_fail(self):
        for text in (CANONICAL.replace("royalty-free", "royalty-bearing"),
                     CANONICAL.replace("excluding those notices", "excluding any notices"),
                     CANONICAL.replace("submitted to Licensor", "submitted to the Licensor"),
                     BODY[:BODY.index("3. Grant")], BODY + "\nNo commercial use.",
                     CANONICAL.replace("limitations under the License.", "No commercial use."),
                     BODY + "\n" + NOTICE.replace("Copyright 2026 Example Contributors", "Copyright"),
                     CANONICAL.replace("January 2004", "January 2026")):
            with self.subTest(text=text[-60:]):
                self.write_license(text)
                result, kinds = self.audit()
                self.assertEqual(result["status"], "blocked")
                self.assertIn("unrecognized-or-modified-license", kinds)

    def test_missing_license_fails_even_with_metadata(self):
        (self.repo / "LICENSE").unlink()
        (self.repo / "pyproject.toml").write_text('[project]\nlicense = "Apache-2.0"\n')
        result, kinds = self.audit()
        self.assertEqual(result["status"], "blocked")
        self.assertIn("missing-license", kinds)

    def test_pyproject_string_and_legacy_text_metadata(self):
        for label in ('"Apache-2.0"', '{text = "Apache-2.0"}', '"MIT"', '{text = "MIT"}'):
            with self.subTest(label=label):
                (self.repo / "pyproject.toml").write_text('[project]\nlicense = ' + label + '\n')
                _, kinds = self.audit()
                self.assertEqual("license-metadata-mismatch" in kinds, '"MIT"' in label)

    def test_package_metadata_relicensing_both_directions(self):
        for text, declared in ((CANONICAL, "MIT"),
                               (Path(rc.__file__).with_name("LICENSE").read_text(), "Apache-2.0")):
            self.write_license(text)
            (self.repo / "package.json").write_text(json.dumps({"license": declared}))
            _, kinds = self.audit()
            self.assertIn("license-metadata-mismatch", kinds)
            self.assertIn("dependency-ecosystem-manual-review", kinds)

    def test_matching_package_license_keeps_manual_ecosystem_review(self):
        (self.repo / "package.json").write_text(json.dumps({"license": "Apache-2.0"}))
        _, kinds = self.audit()
        self.assertNotIn("license-metadata-mismatch", kinds)
        self.assertIn("dependency-ecosystem-manual-review", kinds)

    def test_notice_is_optional_without_upstream_notice(self):
        self.commit()
        self.assertEqual(self.audit()[1], set())
        (self.repo / "NOTICE").write_text("Example upstream attribution.\n")
        self.assertEqual(self.audit()[1], set())

    def test_upstream_notice_must_survive_and_may_be_extended(self):
        (self.repo / "NOTICE").write_text("Example upstream attribution.\n")
        self.commit()
        (self.repo / "NOTICE").write_text("Example upstream attribution.\nAdditional context.\n")
        self.assertEqual(self.audit()[1], set())
        (self.repo / "NOTICE").write_text("Replacement attribution.\n")
        self.assertIn("historical-attribution-changed", self.audit()[1])
        (self.repo / "NOTICE").unlink()
        self.assertIn("historical-attribution-missing", self.audit()[1])

    def test_historical_copyright_is_preserved(self):
        self.write_license(BODY + "\n" + NOTICE)
        self.commit()
        self.assertEqual(self.audit()[1], set())
        self.write_license(BODY + "\n" + NOTICE.replace("Example Contributors", "Replacement Contributors"))
        self.assertIn("historical-attribution-changed", self.audit()[1])

    def test_source_file_copyright_is_preserved(self):
        (self.repo / "core.py").write_text('# Copyright 2026 Example Contributors\nprint("example")\n')
        self.commit()
        (self.repo / "core.py").write_text('print("example")\n')
        self.assertIn("historical-attribution-changed", self.audit()[1])

    def test_license_relabel_cannot_erase_apache_history(self):
        self.write_license(BODY + "\n" + NOTICE)
        self.commit()
        self.write_license(Path(rc.__file__).with_name("LICENSE").read_text())
        self.assertIn("historical-attribution-changed", self.audit()[1])

    def test_relabel_with_same_copyright_is_still_blocked(self):
        self.write_license(BODY + "\n" + NOTICE)
        self.commit()
        mit = Path(rc.__file__).with_name("LICENSE").read_text()
        mit = re.sub(r"Copyright[^\n]+", "Copyright 2026 Example Contributors", mit)
        self.write_license(mit)
        self.assertIn("historical-attribution-changed", self.audit()[1])

    def test_pyproject_metadata_relicensing_reverse_direction(self):
        self.write_license(Path(rc.__file__).with_name("LICENSE").read_text())
        for declared in ('"Apache-2.0"', '{text = "Apache-2.0"}'):
            (self.repo / "pyproject.toml").write_text('[project]\nlicense = ' + declared + '\n')
            self.assertIn("license-metadata-mismatch", self.audit()[1])

    def test_copyright_owner_substring_cannot_replace_original(self):
        self.write_license(BODY + "\n" + NOTICE)
        self.commit()
        self.write_license(BODY + "\n" + NOTICE.replace("Example Contributors", "Example ContributorsX"))
        self.assertIn("historical-attribution-changed", self.audit()[1])

    def test_verified_export_pass_and_missing_copyright_block(self):
        auxiliary = tempfile.TemporaryDirectory()
        self.addCleanup(auxiliary.cleanup)
        root = Path(auxiliary.name)
        terms = root / "terms.json"
        terms.write_text(json.dumps({"categories": {"synthetic": {"placeholder": "private", "terms": ["HiddenPerson"]}}}))
        (self.repo / "README.md").write_text("# Example\n## Limitations\nSynthetic only.\npython -c 'print(1)'\n")
        (self.repo / "CONTRIBUTING.md").write_text("Run tests.\n")
        (self.repo / "SECURITY.md").write_text("Private reporting.\n")
        (self.repo / ".github/ISSUE_TEMPLATE").mkdir(parents=True)
        (self.repo / ".github/ISSUE_TEMPLATE/bug.yml").write_text("name: bug\n")
        (self.repo / "tests").mkdir()
        (self.repo / "tests/test_example.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertEqual(2 + 2, 4)\n")
        (self.repo / "core.py").write_text('# Copyright 2026 Example Contributors\nprint("example")\n')
        manifest = {"exclude": [], "approvals": [], "stdlib_only": True,
                    "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", "print(1)"]}],
                    "checks": [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.commit()
        self.git("add", "--", "README.md", "CONTRIBUTING.md", "SECURITY.md", ".github/ISSUE_TEMPLATE/bug.yml", "tests/test_example.py")
        self.git("commit", "-q", "-m", "Synthetic quality files\n\n" + COAUTHOR)
        for changed in (False, True):
            if changed:
                (self.repo / "core.py").write_text('print("example")\n')
            destination = root / ("blocked" if changed else "clean")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = rc.main([str(self.repo), "--denylist", str(terms), "--reports", str(root / "reports"),
                                "--verify-no-venv", "--export", str(destination)])
            self.assertEqual(code, 1 if changed else 0, out.getvalue() + err.getvalue())
            report = json.loads(sorted((root / "reports").rglob("report.json"))[-1].read_text())
            if changed:
                self.assertFalse(destination.exists())
                self.assertIn("historical-attribution-changed", {f["kind"] for f in report["export"]["findings"]})
            else:
                self.assertEqual(report["verdict"], "PASS")
                self.assertEqual(report["export"]["license"]["identifier"], "Apache-2.0")
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(rc.main([str(destination), "--check-digest", report["export"]["digest"]]), 0)

    def test_notice_and_license_exclusions_remain_blocked(self):
        (self.repo / "NOTICE").write_text("Example upstream attribution.\n")
        for path in ("LICENSE", "NOTICE"):
            with self.subTest(path=path):
                self.manifest["exclude"] = [path]
                self.assertIn("excluded-attribution", self.audit()[1])

    def test_existing_mit_recognition_is_unchanged(self):
        text = Path(rc.__file__).with_name("LICENSE").read_text()
        self.write_license(text)
        result, kinds = self.audit()
        self.assertEqual(result["identifier"], "MIT")
        self.assertEqual(kinds, set())
        self.write_license(text.replace("free of charge", "for a fee"))
        self.assertIn("unrecognized-or-modified-license", self.audit()[1])
