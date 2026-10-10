"""Blocked artifacts and targeted fourth-pass diagnostics."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures


class Round4Tests(unittest.TestCase):
    setUp = fixtures.AuditTests.setUp
    git = fixtures.AuditTests.git
    commit = fixtures.AuditTests.commit
    run_cli = fixtures.AuditTests.run_cli
    latest_report = fixtures.AuditTests.latest_report
    save_manifest = fixtures.AuditTests.save_manifest
    private_history = fixtures.AuditTests.private_history

    def digest_check(self, target, digest):
        out = io.StringIO()
        with redirect_stdout(out):
            code = rc.main([str(target), '--check-digest', digest])
        return code, out.getvalue()

    def blocked_export(self):
        token = 'gh' + 'p_' + 'A' * 30
        (self.repo / 'local_settings.py').write_text(token)
        self.commit('Synthetic credential')
        target = self.root / 'flagged'
        code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 1, out + err)
        self.assertFalse(target.exists())
        return target.with_name('flagged.BLOCKED'), self.latest_report()['export'], token, out

    def test_blocked_output_has_no_git_objects_or_usable_repository(self):
        blocked, export, token, out = self.blocked_export()
        self.assertFalse((blocked / '.git').exists())
        result = subprocess.run(['git', '-C', str(blocked), 'rev-parse', '--git-dir'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Do not publish', (blocked / rc.BLOCKED_README).read_text())
        self.assertIn('run git init', out)
        self.assertEqual((blocked / 'local_settings.py').read_text(), token)
        self.assertEqual(json.loads((blocked / rc.AUDIT_RECORD).read_text()), export['audit_record'])
        code, text = self.digest_check(blocked, export['digest'])
        self.assertEqual(code, 1, text)
        self.assertIn('DIGEST MATCHES BUT THE EXPORT WAS NOT CLEAN', text)

    def test_blocked_digest_checks_bytes_times_and_record(self):
        blocked, export, _, _ = self.blocked_export()
        for name in ('local_settings.py', rc.AUDIT_RECORD, rc.BLOCKED_README):
            with self.subTest(name=name):
                path = blocked / name
                raw, info = path.read_bytes(), path.stat()
                path.write_bytes(raw + b'changed')
                self.assertNotEqual(rc.export_digest(blocked), export['digest'])
                self.assertEqual(self.digest_check(blocked, export['digest'])[0], 1)
                path.write_bytes(raw)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1000000000))
                self.assertNotEqual(rc.export_digest(blocked), export['digest'])
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                self.assertEqual(rc.export_digest(blocked), export['digest'])

    def test_plain_artifact_cannot_be_clean_even_with_forged_pass_record(self):
        blocked, export, _, _ = self.blocked_export()
        record = dict(export['audit_record'], verdict='PASS', blocking_count=0, verified=True, isolation='venv')
        (blocked / rc.AUDIT_RECORD).write_text(json.dumps(record))
        code, text = self.digest_check(blocked, rc.export_digest(blocked))
        self.assertEqual(code, 1, text)
        self.assertIn('NOT CLEAN', text)

    def test_interrupted_export_removes_git_and_keeps_warning(self):
        original = rc.audit
        calls = []
        def fail_export(*args):
            calls.append(args[0])
            if len(calls) == 2:
                raise OSError('synthetic interruption')
            return original(*args)
        target = self.root / 'interrupted'
        with patch.object(rc, 'audit', side_effect=fail_export):
            code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 2, out + err)
        blocked = target.with_name('interrupted.BLOCKED')
        self.assertFalse(target.exists())
        self.assertFalse((blocked / '.git').exists())
        self.assertTrue((blocked / rc.BLOCKED_README).is_file())
        code, text = self.digest_check(blocked, rc.export_digest(blocked))
        self.assertEqual(code, 1, text)
        self.assertIn('NOT CLEAN', text)

    def test_export_snapshot_fixes_do_not_request_another_export(self):
        _, export, _, out = self.blocked_export()
        for finding in export['findings']:
            if finding['scope'] == 'history':
                self.assertNotIn('one-commit copy', rc.fix_for(finding))
                self.assertEqual(finding['origin'], 'export')
        self.assertIn('export snapshot (approval scope history)', out)
        self.assertIn('SOURCE history', out)
        self.assertIn('Informational:', out)
        self.assertNotIn('Make a one-commit copy', out)
        report = self.latest_report()
        self.assertTrue(all(f['severity'] == 'warning' and f['why'] == 'source-only'
                            for f in report['findings'] if f['scope'] == 'history'))
        markdown = rc.format_markdown(report)
        self.assertIn('| export snapshot: history |', markdown)
        self.assertIn('| SOURCE: history |', markdown)

    def test_keyboard_interrupt_leaves_no_usable_blocked_git_repository(self):
        original = rc.audit
        calls = []
        def interrupt_export(*args):
            calls.append(args[0])
            if len(calls) == 2:
                raise KeyboardInterrupt()
            return original(*args)
        target = self.root / 'cancelled'
        with patch.object(rc, 'audit', side_effect=interrupt_export):
            code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 2, out + err)
        blocked = target.with_name('cancelled.BLOCKED')
        self.assertFalse((blocked / '.git').exists())
        self.assertTrue((blocked / rc.BLOCKED_README).is_file())
        self.assertNotIn('Traceback', err)

    def test_source_history_warning_for_clean_export_is_informational(self):
        self.private_history()
        code, out, err = self.run_cli('--verify', '--export', str(self.root / 'clean'))
        self.assertEqual(code, 0, out + err)
        self.assertIn('the export (one commit, no history)', out)
        self.assertIn('SOURCE history', out)
        self.assertNotIn('Make a one-commit copy', out)

    def test_shipped_terms_are_incomplete_in_text_and_json(self):
        self.denylist.write_bytes(Path(rc.__file__).with_name('examples').joinpath('denylist.example.json').read_bytes())
        for args in ((), ('--json',)):
            code, out, err = self.run_cli(*args)
            self.assertEqual(code, 2, out + err)
            self.assertIn('INCOMPLETE', err)
            self.assertIn('denylist-example', err)
            self.assertIn('no real private terms', err)
            self.assertNotIn('Replace With Your Full Name', err)

    def test_partial_placeholder_list_is_incomplete(self):
        self.denylist.write_text(json.dumps(['HiddenPerson', 'replace-with-machine-name']))
        with self.assertRaisesRegex(rc.AuditError, 'denylist-example'):
            rc.load_terms(self.denylist)

    def test_empty_and_all_example_lists_explain_missing_coverage(self):
        for terms in ([], ['example', 'placeholder'], ['your-name', 'your-username']):
            self.denylist.write_text(json.dumps(terms))
            code, out, err = self.run_cli()
            self.assertEqual(code, 2, out + err)
            self.assertIn('Private-term coverage is INCOMPLETE', err)
            self.assertIn('no real private terms', err)

    def test_first_audit_names_single_verification_reason(self):
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, out + err)
        self.assertIn('No content or repository problems found.', out)
        self.assertIn('verification-not-run: run with --verify', out)
        self.assertEqual(self.latest_report()['summary']['blocking'], 1)
        self.assertIn('1 commit\n', out)
        self.assertNotIn('1 commits', out)

    def test_venv_failure_short_recovery_precedes_details(self):
        with patch.object(rc, 'verification_venv', return_value=(None, b'synthetic failure', 'venv')):
            code, out, err = self.run_cli('--verify')
        self.assertEqual(code, 1, out + err)
        self.assertLess(out.index('Verification could not create a venv'), out.index('BLOCKING -'))
        self.assertLess(out.index('No-admin fix:'), out.index('Details: Linux/macOS:'))
        self.assertIn('official script', out)
        self.assertIn('--verify-no-venv', out)
        self.assertEqual(self.latest_report()['verification']['commands'], [])

    def test_bare_private_key_header_is_detected(self):
        header = '-' * 5 + 'BEGIN OPENSSH ' + 'PRIVATE KEY' + '-' * 5
        scanner = rc.Scanner([])
        scanner.file(header.encode(), 'tree', 'README.md')
        self.assertIn('private-key', {f['kind'] for f in scanner.findings})
