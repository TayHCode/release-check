"""Synthetic whole-word and real-CLI privacy regressions."""
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest

import release_check as rc
import test_release_check as fixtures


class BoundaryTests(unittest.TestCase):
    def hits(self, term, text, encoding="utf-8"):
        scanner = rc.Scanner([term])
        scanner.text(text.encode(encoding), "tree", "sample.txt")
        return [f for f in scanner.findings if f["kind"] == "denylist"]

    def test_alphabetic_terms_match_whole_tokens_only(self):
        for text in ("cat", "CAT", "Cat", "(cat)", "cat's", "cat’s", "cat-file",
                     "cat.txt", "/cat/", "https://cat.example.org", "cat@example.org"):
            with self.subTest(text=text):
                self.assertTrue(self.hits("cat", text))
        for text in ("cats", "bobcat", "scatter", "SCATTER", "écaté", "猫cat犬",
                     "cat_file", "cat2", "2cat", "catFood", "getCat", "HTTPcat", "sCATter"):
            with self.subTest(text=text):
                self.assertEqual(self.hits("cat", text), [])

    def test_unicode_whole_words_are_case_insensitive(self):
        self.assertTrue(self.hits("élan", "ÉLAN"))
        self.assertEqual(self.hits("élan", "mélange"), [])
        self.assertTrue(self.hits("猫", "猫"))
        self.assertEqual(self.hits("猫", "猫咪"), [])

    def test_utf16_preserves_boundaries_and_line_numbers(self):
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                hits = self.hits("larch", "blank\noverlarch\nlarch", encoding)
                self.assertTrue(hits)
                self.assertTrue(all(f["line"] == 3 for f in hits))

    def test_nonalphabetic_terms_are_literal_strings(self):
        for term in ("z07", "a1", "1", "foo-bar", "dot.name", "foo_bar", "élan1",
                     "a+b", "owner@example.org", "/home/fakeuser", "@fakehandle"):
            for text in (term, "x" + term + "y", "_" + term + "_", term.upper()):
                with self.subTest(term=term, text=text):
                    hits = self.hits(term, text)
                    self.assertEqual(bool(hits), bool(re.search(re.escape(term), text, re.I)))

    def test_placeholders_constants_and_coauthor_are_not_findings(self):
        scanner = rc.Scanner(["larch"])
        scanner.file(("192.0.2.0/24\n198.51.100.42\n203.0.113.255\n2001:db8::1\n"
                      "example.com\n/workspace/sample-project\nhttps://api.github.com/repos/example/sample-project\n"
                      "UTF-16\nHTTP/1.1\nwindows-01\n" + "/" + "home/user/data\n"
                      "Co-Authored-By: Fixture <bot@example.org>\n").encode(), "tree", "README.md")
        self.assertEqual(scanner.findings, [])

    def test_protocol_values_and_token_modules_are_not_secrets(self):
        scanner = rc.Scanner(["larch"])
        value = "Ab3D4e5F6g7H8i9J0kL1mN2oP3qR4sT5uV6wX7yZ8"
        for path in ("token.py", "constants.py", "certificate.pem"):
            scanner.file(value.encode(), "tree", path)
        self.assertEqual(scanner.findings, [])

    def test_secret_formats_still_block_without_approvals(self):
        values = {"github-token": "gh" + "p_" + "A" * 30,
                  "aws-key": "AKIA" + "A" * 16,
                  "api-key": "sk-" + "A" * 30,
                  "google-key": "AIza" + "A" * 35,
                  "slack-key": "xoxb-" + "A" * 20,
                  "jwt": "eyJ" + "A" * 18 + "." + "B" * 18 + "." + "C" * 18,
                  "private-key": "-----BEGIN " + "PRIVATE KEY-----",
                  "assigned-secret": "api_key=" + "Ab3D4e5F6g7H8i9J0kL",
                  "bearer": "Bearer " + "A" * 20,
                  "credential-url": "https://" + "owner:" + "password123" + "@example.com"}
        for kind, value in values.items():
            with self.subTest(kind=kind):
                scanner = rc.Scanner(["larch"])
                scanner.file(value.encode(), "tree", "sample.txt")
                expected = "api-key" if kind in {"google-key", "slack-key"} else kind
                self.assertTrue(any(f["kind"] == expected and not f["reviewed"] for f in scanner.findings))

        scanner = rc.Scanner(["larch"])
        scanner.file(("github_pat_" + "A" * 25 + "_" + "B" * 25).encode(), "tree", "sample.txt")
        self.assertTrue(any(f["kind"] == "github-token" for f in scanner.findings))

    def test_anthropic_key_format_is_blocked(self):
        scanner = rc.Scanner(["larch"])
        scanner.file(("sk-" + "ant-api03-" + "A" * 35).encode(), "tree", "sample.txt")
        self.assertTrue(any(f["kind"] == "api-key" and not f["reviewed"] for f in scanner.findings))

    def test_nonplaceholder_emails_block_and_documented_placeholders_pass(self):
        address = "person" + "@" + "samplemail" + ".invalid"
        scanner = rc.Scanner(["larch"])
        scanner.file(("Contact " + address + "\n").encode(), "tree", "sample.txt")
        self.assertTrue(any(f["kind"] == "email-address" for f in scanner.findings))

        placeholders = ["user@example" + suffix for suffix in (".com", ".org", ".net")]
        placeholders += ["123+fixture@users.noreply.github.com"]
        trailer = "Co-Authored-By: Fixture <noreply@" + "anthropic.com>"
        scanner = rc.Scanner(["larch"])
        scanner.file(("\n".join(placeholders) + "\n" + trailer + "\n").encode(), "tree", "sample.txt")
        self.assertEqual(scanner.findings, [])

    def test_transport_and_noreply_addresses_pass_but_personal_addresses_block(self):
        for local, domain in (("git", "github.com"), ("GIT", "host.invalid"),
                              ("noreply", "anthropic.com"), ("NO-REPLY", "host.invalid"),
                              ("123+fixture", "users.noreply.github.com")):
            with self.subTest(local=local, domain=domain):
                scanner = rc.Scanner(["larch"])
                scanner.file((local + "@" + domain).encode(), "tree", "sample.txt")
                self.assertEqual(scanner.findings, [])
        for local in ("person", "git.person", "my-noreply", "no-reply-person"):
            with self.subTest(local=local):
                scanner = rc.Scanner(["larch"])
                scanner.file((local + "@" + "mail.invalid").encode(), "tree", "sample.txt")
                self.assertEqual([f["kind"] for f in scanner.findings], ["email-address"])

    def test_nonplaceholder_home_paths_block_and_documented_placeholders_pass(self):
        home = "/" + "home/" + "alex/" + "projects/sample"
        home_root = "/" + "home/" + "casey"
        mac = "/" + "Users/" + "jordan/" + "work/sample"
        scanner = rc.Scanner(["larch"])
        scanner.file((home + "\n" + home_root + "\n" + mac + "\n").encode(), "tree", "sample.txt")
        self.assertEqual(sum(f["kind"] == "home-path" for f in scanner.findings), 3)

        scanner = rc.Scanner(["larch"])
        scanner.file(("/" + "home/user/work\n/" + "home/you/work\n/" + "Users/name/work\n").encode(), "tree", "sample.txt")
        self.assertEqual(scanner.findings, [])

    def test_package_versions_are_not_emails_but_numbered_domains_still_block(self):
        scanner = rc.Scanner(["larch"])
        scanner.file(b"brew install python@3.11\npackage@1.2.3\n", "tree", "README.md")
        self.assertEqual(scanner.findings, [])

        for domain in ("host2.invalid", "3.invalid", "xn--fixture.invalid"):
            with self.subTest(domain=domain):
                scanner = rc.Scanner(["larch"])
                scanner.file(("person@" + domain + ".\n").encode(), "tree", "sample.txt")
                self.assertEqual([f["kind"] for f in scanner.findings], ["email-address"])

    def test_owner_identifiers_only_match_when_denied(self):
        for term in ("Person", "Family", "Agent", "owner@example.org", "windows-01",
                     "node.internal", "/" + "home/" + "fakeuser", "@fakehandle"):
            with self.subTest(term=term):
                scanner = rc.Scanner([term])
                scanner.text(term.upper().encode(), "tree", "README.md")
                self.assertEqual(len(scanner.findings), 1)
                self.assertEqual(scanner.findings[0]["kind"], "denylist")

    def test_unicode_filename_matches_stay_redacted(self):
        scanner = rc.Scanner(["i"])
        scanner.file(b"i", "tree", "mıx.txt")
        self.assertTrue(all(f["path"].startswith("[path-") for f in scanner.findings))
        self.assertNotIn("mıx", json.dumps(scanner.findings, ensure_ascii=False))


class PrivacyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.denylist.write_text(json.dumps(["larch"]))

    def cli(self, *args):
        fixture = self.fixture
        result = subprocess.run([sys.executable, rc.__file__, str(fixture.repo),
                                 "--denylist", str(fixture.denylist), "--reports",
                                 str(fixture.root / "reports"), *args], capture_output=True, text=True, timeout=60)
        self.assertNotIn("larch", (result.stdout + result.stderr).lower())
        locator = json.loads(result.stdout.splitlines()[0])["report"]
        report_path = fixture.root / "reports" / locator
        raw_json, markdown = report_path.read_text(), report_path.with_suffix(".md").read_text()
        self.assertNotIn("larch", (raw_json + markdown).lower())
        return result.returncode, json.loads(raw_json), markdown

    def test_inside_word_hits_produce_no_findings_or_review_class(self):
        fixture = self.fixture
        (fixture.repo / "overlarch.txt").write_text("overlarch\ngetLarchValue\n")
        fixture.commit("Review overlarch")
        code, report, markdown = self.cli("--verify", "--scrub-plan", "--export", str(fixture.root / "export"))
        self.assertEqual(code, 0)
        for target in (report, report["export"]):
            self.assertTrue(target["ready"])
            self.assertEqual(target["counts"], {})
            self.assertEqual(target["findings"], [])
            self.assertNotIn("reviewable_findings", target)
            self.assertNotIn("reviewable_count", target)
        self.assertNotIn("Reviewable private-term", markdown)
        self.assertEqual(report["scrub_plan"]["replace_or_remove"], [])

    def test_whole_word_hits_block_and_only_they_need_scrubbing(self):
        fixture = self.fixture
        (fixture.repo / "data.txt").write_text("overlarch\nlarch\ngetLarchValue\n")
        fixture.commit("Fixture")
        code, report, _ = self.cli("--verify", "--scrub-plan")
        self.assertEqual(code, 1)
        self.assertFalse(report["ready"])
        self.assertTrue(report["scrub_plan"]["replace_or_remove"])
        self.assertTrue(all(f["line"] == 2 for f in report["scrub_plan"]["replace_or_remove"]))

    def test_denylist_cannot_be_waived_even_with_reason(self):
        scanner = rc.Scanner(["larch"], approvals=[{"scope": "tree", "kind": "denylist",
                            "path": "data.txt", "fingerprint": rc.fingerprint("larch"), "reason": "Reviewed."}])
        scanner.file(b"larch", "tree", "data.txt")
        self.assertFalse(scanner.findings[0]["reviewed"])
        self.assertEqual(scanner.matched_approvals, set())

    def test_owner_email_in_history_blocks_but_coauthor_does_not(self):
        fixture = self.fixture
        fixture.git("config", "user.email", "bot@example.org")
        fixture.git("commit", "-q", "--allow-empty", "-m", "Fixture\n\nCo-Authored-By: Fixture <bot@example.org>")
        code, report, markdown = self.cli("--verify")
        self.assertEqual(code, 0)
        fixture.denylist.write_text(json.dumps(["owner@example.org"]))
        fixture.git("config", "user.email", "owner@example.org")
        fixture.git("commit", "-q", "--allow-empty", "-m", "Fixture")
        code, report, markdown = self.cli("--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any(f["scope"] == "metadata" and f["kind"] == "denylist" for f in report["findings"]))

    def test_unlisted_email_in_file_and_git_identity_blocks(self):
        fixture = self.fixture
        address = "fixture.person" + "@" + "samplemail" + ".invalid"
        (fixture.repo / "contact.txt").write_text("Contact: " + address + "\n")
        fixture.git("config", "user.email", address)
        fixture.commit("Synthetic fixture")
        code, report, markdown = self.cli("--verify")
        self.assertEqual(code, 1)
        hits = [f for f in report["findings"] if f["kind"] == "email-address"]
        self.assertTrue(any(f["scope"] == "tree" for f in hits))
        self.assertTrue(any(f["scope"] == "metadata" for f in hits))
        self.assertNotIn(address, json.dumps(report) + markdown)

    def test_deleted_history_and_commit_identity_still_block(self):
        fixture = self.fixture
        (fixture.repo / "larch.txt").write_text("larch\n")
        fixture.git("config", "user.name", "Larch")
        fixture.commit("larch")
        fixture.git("rm", "--", "larch.txt")
        fixture.git("config", "user.name", "Fixture")
        fixture.git("commit", "-q", "-m", "Remove")
        code, report, _ = self.cli("--verify")
        self.assertEqual(code, 1)
        self.assertTrue(any(f["scope"] == "history" and f["kind"] == "denylist" for f in report["findings"]))
        self.assertTrue(any(f["scope"] == "metadata" and f["kind"] == "denylist" for f in report["findings"]))

    def test_missing_configuration_explains_both_flags_and_environment(self):
        environment = {k: v for k, v in os.environ.items() if k not in {"RELEASE_CHECK_DENYLIST", "RELEASE_CHECK_REPORTS"}}
        result = subprocess.run([sys.executable, rc.__file__, str(self.fixture.repo)], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        message = json.loads(result.stderr)["message"]
        for value in ("--denylist /private/terms.json", "--reports /private/reports", "RELEASE_CHECK_DENYLIST", "RELEASE_CHECK_REPORTS"):
            self.assertIn(value, message)

    def test_environment_defaults_and_explicit_flags_win(self):
        fixture = self.fixture
        environment = {**os.environ, "RELEASE_CHECK_DENYLIST": str(fixture.denylist), "RELEASE_CHECK_REPORTS": str(fixture.root / "env-reports")}
        result = subprocess.run([sys.executable, rc.__file__, str(fixture.repo)], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(list((fixture.root / "env-reports").rglob("report.json")))
        environment.update(RELEASE_CHECK_DENYLIST=str(fixture.root / "missing.json"), RELEASE_CHECK_REPORTS=str(fixture.repo / "forbidden-reports"))
        result = subprocess.run([sys.executable, rc.__file__, str(fixture.repo), "--denylist", str(fixture.denylist), "--reports", str(fixture.root / "explicit-reports")], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(list((fixture.root / "explicit-reports").rglob("report.json")))
        self.assertFalse((fixture.repo / "forbidden-reports").exists())

    def test_empty_report_default_has_actionable_error(self):
        environment = {**os.environ, "RELEASE_CHECK_DENYLIST": str(self.fixture.denylist), "RELEASE_CHECK_REPORTS": ""}
        result = subprocess.run([sys.executable, rc.__file__, str(self.fixture.repo)], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--reports /private/reports", json.loads(result.stderr)["message"])

    def test_invalid_argument_never_prints_private_argument(self):
        result = subprocess.run([sys.executable, rc.__file__, "--invalid-larch=private-value"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr), {"ready": False, "error": "invalid-arguments"})

    def test_declared_project_quickstart_lines_remain_exact(self):
        root = Path(rc.__file__).parent
        manifest = json.loads((root / "release-check.json").read_text())
        for command in manifest["quickstart"]:
            line = (root / command["file"]).read_text().splitlines()[command["line"] - 1]
            self.assertEqual(shlex.split(line), command["argv"])


if __name__ == "__main__":
    unittest.main()
