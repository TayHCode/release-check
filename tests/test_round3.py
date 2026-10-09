"""Windows launcher and round-three diagnostic regressions."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures


class LauncherTests(unittest.TestCase):
    def test_python_launchers_use_selected_interpreter_without_mutating_manifest(self):
        python = Path('verification') / 'Scripts' / 'python.exe'
        for prefix in (['python'], ['python3'], ['py'], ['py', '-3']):
            with self.subTest(prefix=prefix):
                argv = prefix + ['-m', 'unittest']
                original = list(argv)
                self.assertEqual(rc.verification_argv(argv, python), [str(python), '-m', 'unittest'])
                self.assertEqual(argv, original)

    def test_unrelated_executables_and_explicit_paths_are_preserved(self):
        for name in ('pytest', 'python2', '/custom/python', 'python3.99'):
            self.assertEqual(rc.verification_argv([name, '--help'], Path(sys.executable)), [name, '--help'])


class Round3Tests(unittest.TestCase):
    setUp = fixtures.AuditTests.setUp
    git = fixtures.AuditTests.git
    commit = fixtures.AuditTests.commit
    run_cli = fixtures.AuditTests.run_cli
    latest_report = fixtures.AuditTests.latest_report
    save_manifest = fixtures.AuditTests.save_manifest

    def test_no_venv_label_names_actual_route_and_lower_isolation(self):
        self.manifest['stdlib_only'] = True
        self.save_manifest()
        code, out, err = self.run_cli('--verify-no-venv')
        self.assertEqual(code, 0, out + err)
        self.assertIn('verified (no-venv; current-interpreter (less isolated))', out)

    def test_py_launcher_verifies_both_quickstart_and_checks(self):
        (self.repo / 'README.md').write_text('# Fixture\n## Honest limitations\nSynthetic only.\npy -3 -m unittest discover -s tests -q\n')
        argv = ['py', '-3', '-m', 'unittest', 'discover', '-s', 'tests', '-q']
        self.manifest['quickstart'][0]['argv'] = argv
        self.manifest['checks'][0]['argv'] = argv
        self.save_manifest()
        code, out, err = self.run_cli('--verify', '--export', str(self.root / 'launcher-export'))
        self.assertEqual(code, 0, out + err)
        self.assertEqual([c['exit_code'] for c in self.latest_report()['export']['verification']['commands']], [0, 0])

    def test_noreply_exact_domain_is_public_but_real_and_lookalike_addresses_block(self):
        domain = 'users.' + 'noreply.github.com'
        for local in ('sample-user', '12345+sample-user'):
            scanner = rc.Scanner([])
            scanner.text((local + '@' + domain).encode(), 'metadata', '@commit/fixture')
            self.assertNotIn('email', {f['kind'] for f in scanner.findings})
        for address in ('person@' + 'mail.example.org', 'user@' + domain + '.example.org', 'user@other.' + domain, 'user@' + 'github.com'):
            scanner = rc.Scanner([])
            scanner.text(address.encode(), 'tree', 'README.md')
            self.assertIn('email', {f['kind'] for f in scanner.findings})

    def test_noreply_does_not_exempt_private_terms(self):
        scanner = rc.Scanner(['invented-person'])
        scanner.text(('invented-person@users.' + 'noreply.github.com').encode(), 'tree', 'README.md')
        self.assertIn('denylist', {f['kind'] for f in scanner.findings})

    def test_source_noreply_author_and_committer_do_not_block(self):
        self.git('config', 'user.email', '12345+sample-user@users.' + 'noreply.github.com')
        self.git('commit', '-q', '--allow-empty', '-m', 'Public noreply fixture')
        code, out, err = self.run_cli('--verify')
        self.assertEqual(code, 0, out + err)

    def test_existing_export_and_blocked_paths_are_named_in_text_and_json(self):
        for existing in ('target', 'blocked', 'both'):
            target = self.root / existing
            blocked = target.with_name(target.name + '.BLOCKED')
            paths = [target] if existing == 'target' else [blocked] if existing == 'blocked' else [target, blocked]
            for path in paths:
                path.mkdir()
            for mode in ((), ('--json',)):
                code, out, err = self.run_cli('--export', str(target), *mode)
                self.assertEqual(code, 2, out + err)
                message = json.loads(err)['message'] if mode else err
                for path in paths:
                    self.assertIn(str(path), message)
                    self.assertTrue(path.is_dir())
                self.assertIn('--export NEW_DIR', message)

    def test_malformed_terms_json_names_location_without_leaking_content(self):
        self.denylist.write_text('{\n"private-value": invalid\n}')
        for mode in ((), ('--json',)):
            code, out, err = self.run_cli(*mode)
            self.assertEqual(code, 2)
            self.assertIn('denylist-json', err)
            self.assertIn('line 2, column 18', err)
            self.assertNotIn('private-value', out + err)

    def test_valid_but_unsupported_terms_shape_retains_schema_code(self):
        self.denylist.write_text('{"unsupported": []}')
        code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn('denylist-schema', err)

    def test_actual_uv_route_is_displayed_and_accepted_by_digest(self):
        original = rc.verification_venv
        def fixture_builder(workspace, timeout):
            python, output, _ = original(workspace, timeout)
            return python, output, 'uv'
        target = self.root / 'uv-export'
        with patch.object(rc, 'verification_venv', side_effect=fixture_builder):
            code, out, err = self.run_cli('--verify', '--export', str(target))
        self.assertEqual(code, 0, out + err)
        self.assertIn('verified (uv)', out)
        report = self.latest_report()['export']
        record = rc.read_export_audit(target)
        self.assertEqual(record['isolation'], 'uv')
        self.assertTrue(report['ready'])

    def test_plan_describes_history_and_metadata_without_claiming_content_is_removed(self):
        code, out, err = self.run_cli()
        self.assertIn('findings from history and commit metadata', out)
        self.assertIn('matching working-file content still needs fixing', out)
        self.assertNotIn('exist only in old commits', out)
