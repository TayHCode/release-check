"""Export verdict, encoding and no-admin verification regressions."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures


class Round2Tests(unittest.TestCase):
    setUp = fixtures.AuditTests.setUp
    git = fixtures.AuditTests.git
    commit = fixtures.AuditTests.commit
    run_cli = fixtures.AuditTests.run_cli
    latest_report = fixtures.AuditTests.latest_report
    save_manifest = fixtures.AuditTests.save_manifest

    def digest_check(self, target, digest):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main([str(target), '--check-digest', digest])
        return code, out.getvalue() + err.getvalue()

    def test_verified_clean_export_digest_pass_and_file_tamper(self):
        target = self.root / 'clean'
        code, out, err = self.run_cli('--verify', '--export', str(target))
        self.assertEqual(code, 0, out + err)
        self.assertFalse(target.with_name('clean.BLOCKED').exists())
        report = self.latest_report()['export']
        self.assertEqual(report['audit_record']['blocking_count'], 0)
        self.assertEqual(report['audit_record']['verdict'], 'PASS')
        self.assertTrue(report['audit_record']['verified'])
        code, out = self.digest_check(target, report['digest'])
        self.assertEqual(code, 0, out)
        self.assertIn('DIGEST MATCHES AND THE EXPORT IS CLEAN', out)
        self.assertIn('verified (--verify; fresh venv)', out)
        (target / 'README.md').write_text('Changed content')
        code, out = self.digest_check(target, report['digest'])
        self.assertEqual(code, 1, out)
        self.assertNotIn('VERDICT: PASS', out)
        self.assertIn('not established', out)

    def test_matching_digest_of_credential_export_stays_blocked(self):
        planted = 'gh' + 'p_' + 'B' * 30
        (self.repo / 'config.py').write_text(planted)
        self.git('add', '--', 'config.py')
        target = self.root / 'flagged'
        code, out, err = self.run_cli('--verify', '--export', str(target))
        self.assertEqual(code, 1, out + err)
        self.assertFalse(target.exists())
        blocked = target.with_name('flagged.BLOCKED')
        self.assertEqual((blocked / 'config.py').read_text(), planted)
        self.assertIn('EXPORT BLOCKED', out)
        self.assertNotIn(planted, out + err)
        export = self.latest_report()['export']
        record = export['audit_record']
        self.assertGreater(record['blocking_count'], 0)
        code, out = self.digest_check(blocked, export['digest'])
        self.assertEqual(code, 1, out)
        self.assertIn(f"DIGEST MATCHES BUT THE EXPORT WAS NOT CLEAN: {record['blocking_count']} blocking findings (FIX-THESE)", out)
        self.assertIn('verified (--verify; fresh venv)', out)
        self.assertNotIn('VERDICT: PASS', out)

    def test_unverified_export_cannot_pass_matching_digest(self):
        target = self.root / 'unverified'
        code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 1, out + err)
        self.assertFalse(target.exists())
        export = self.latest_report()['export']
        self.assertEqual(export['audit_record']['blocking_count'], 1)
        code, out = self.digest_check(target.with_name('unverified.BLOCKED'), export['digest'])
        self.assertEqual(code, 1, out)
        self.assertIn('1 blocking findings (FIX-THESE)', out)
        self.assertIn('not verified', out)

    def test_audit_record_tamper_changes_digest(self):
        target = self.root / 'clean'
        code, out, err = self.run_cli('--verify', '--export', str(target))
        self.assertEqual(code, 0, out + err)
        digest = self.latest_report()['export']['digest']
        record = target / '.git' / rc.AUDIT_RECORD
        record.write_text(record.read_text() + ' ')
        self.assertEqual(self.digest_check(target, digest)[0], 1)

    def test_missing_record_never_passes_even_matching_digest(self):
        target = self.root / 'legacy'
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        code, out = self.digest_check(target, rc.export_digest(target))
        self.assertEqual(code, 1, out)
        self.assertIn('No valid recorded audit', out)
        self.assertIn('not verified', out)

    def test_invalid_or_inconsistent_record_is_not_a_clean_verdict(self):
        target = self.root / 'record'
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        base = dict(format=1, verdict='PASS', blocking_count=0, verified=True,
                    isolation='venv', commit=rc.git(target, 'rev-parse', 'HEAD').strip().decode())
        for change in ({'blocking_count': 1}, {'blocking_count': True}, {'verified': False}, {'verified': 'true'}, {'commit': 'invalid'}, {'isolation': 'invalid'}, {'format': 2}):
            with self.subTest(change=change):
                (target / '.git' / rc.AUDIT_RECORD).write_text(json.dumps({**base, **change}))
                self.assertEqual(self.digest_check(target, rc.export_digest(target))[0], 1)

    def test_interrupted_audit_leaves_only_blocked_destination(self):
        original = rc.audit
        calls = []
        def failing(*args, **kwargs):
            calls.append(args[0])
            if len(calls) == 2:
                raise OSError('synthetic failure')
            return original(*args, **kwargs)
        target = self.root / 'interrupted'
        with patch.object(rc, 'audit', side_effect=failing):
            code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 2, out + err)
        self.assertFalse(target.exists())
        self.assertTrue(target.with_name('interrupted.BLOCKED').is_dir())

    def test_existing_blocked_destination_is_preserved(self):
        target = self.root / 'destination'
        blocked = target.with_name('destination.BLOCKED')
        blocked.mkdir()
        (blocked / 'keep').write_text('existing')
        code, out, err = self.run_cli('--export', str(target))
        self.assertEqual(code, 2, out + err)
        self.assertIn('export-destination-exists', err)
        self.assertEqual((blocked / 'keep').read_text(), 'existing')
        self.assertFalse(target.exists())

    def test_plan_and_manual_publication_step_require_clean_verdict(self):
        code, out, err = self.run_cli('--export', str(self.root / 'blocked-plan'))
        self.assertEqual(code, 1, out + err)
        report = self.latest_report()
        publish = next(step for step in report['plan'] if step['id'] == 'publish')
        manual = next(step for step in report['pre_publish_tests'] if step['id'] == 'publish-export-not-original')
        for step in (publish, manual):
            self.assertIn('clean export verdict', step['text'])
            self.assertIn('PASS from --check-digest', step['text'])
            self.assertIn('owner approval', step['text'])

    def test_utf8_bom_manifest_and_terms_are_accepted_silently(self):
        (self.repo / 'release-check.json').write_text(json.dumps(self.manifest), encoding='utf-8-sig')
        for filename, content in (('terms.json', '["HiddenPerson"]'), ('terms.txt', '# ignored\nHiddenPerson\n')):
            terms = self.root / filename
            terms.write_text(content, encoding='utf-8-sig')
            self.assertEqual(rc.load_terms(terms), ['HiddenPerson'])
        code, out, err = self.run_cli('--verify')
        self.assertEqual(code, 0, out + err)
        self.assertNotIn('BOM', out + err)

    def test_other_encodings_get_specific_private_errors(self):
        for filename, code, content in (('manifest', 'manifest-encoding', json.dumps(self.manifest)), ('terms', 'denylist-encoding', '["HiddenPerson"]')):
            with self.subTest(filename=filename):
                if filename == 'manifest':
                    (self.repo / 'release-check.json').write_text(content, encoding='utf-16')
                else:
                    self.denylist.write_text(content, encoding='utf-16')
                status, out, err = self.run_cli()
                self.assertEqual(status, 2, out + err)
                self.assertIn(code, err)
                self.assertIn('UTF-8', err)
                self.assertNotIn('HiddenPerson', out + err)
                (self.repo / 'release-check.json').write_text(json.dumps(self.manifest))

    def test_git_identity_findings_share_one_fix_and_real_locations(self):
        address = 'sample@' + 'example.org'
        self.git('config', 'user.email', address)
        self.git('commit', '--allow-empty', '-qm', 'Metadata fixture')
        oid = self.git('rev-parse', 'HEAD').strip().decode()
        code, out, err = self.run_cli()
        self.assertEqual(code, 1, out + err)
        self.assertIn('Blocking: 4', out)
        self.assertIn('commit ' + oid + ' author metadata', out)
        self.assertIn('commit ' + oid + ' committer metadata', out)
        self.assertIn('.git/config (local Git configuration, entry ', out)
        emails = out.split('1. emails (3)')[1].split('2. verification')[0]
        self.assertEqual(emails.count('   Fix:'), 1)
        self.assertIn('--verify --export', emails)
        self.assertNotIn('lacks approval', emails)
        self.assertNotIn('@config:', out)
        self.assertNotIn(address, out + err)

    def test_stdlib_no_venv_executes_in_fresh_clone_and_clean_home(self):
        import shlex
        script = "import os,sys; assert sys.version_info[:2] == " + repr(sys.version_info[:2]) + "; assert os.environ['HOME'] == os.environ['TEMP']; assert 'SAMPLE_PRIVATE_VALUE' not in os.environ; assert not os.path.exists('untracked-local.txt')"
        (self.repo / 'README.md').write_text('# Fixture\n## Limitations\nSynthetic only.\npython3 -c ' + shlex.quote(script) + '\n')
        (self.repo / 'untracked-local.txt').write_text('Private local fixture')
        self.manifest['stdlib_only'] = True
        self.manifest['quickstart'][0]['argv'] = ['python3', '-c', script]
        self.save_manifest()
        target = self.root / 'stdlib'
        with patch.object(rc, 'verification_venv', side_effect=AssertionError('must not create a venv')), patch.dict(os.environ, {'SAMPLE_PRIVATE_VALUE': 'never-inherit'}):
            code, out, err = self.run_cli('--verify-no-venv', '--export', str(target))
        self.assertEqual(code, 0, out + err)
        self.assertIn('current-interpreter (less isolated)', out)
        code, out = self.digest_check(target, self.latest_report()['export']['digest'])
        self.assertEqual(code, 0, out)
        self.assertIn('verified (--verify-no-venv; current interpreter, less isolated)', out)

    def test_no_venv_requires_explicit_stdlib_declaration(self):
        code, out, err = self.run_cli('--verify-no-venv')
        self.assertEqual(code, 1, out + err)
        self.assertIn('no-venv-not-stdlib', out)
        self.assertEqual(self.latest_report()['verification']['commands'], [])

    def test_no_venv_rejects_declared_dependencies(self):
        self.manifest['stdlib_only'] = True
        self.save_manifest()
        (self.repo / 'pyproject.toml').write_text('[project]\nname="fixture"\ndependencies=["third-party"]\n')
        code, out, err = self.run_cli('--verify-no-venv')
        self.assertEqual(code, 1, out + err)
        self.assertIn('no-venv-not-stdlib', out)

    def test_venv_fallback_order_and_partial_cleanup(self):
        git = shutil.which('git')
        for successful in ('stdlib', 'uv', 'virtualenv', None):
            with self.subTest(successful=successful):
                workspace = self.root / ('attempt-' + str(successful))
                workspace.mkdir()
                calls = []
                def attempt(argv, cwd, environment, timeout):
                    tool = 'stdlib' if argv[0] == sys.executable else Path(argv[0]).name
                    calls.append(tool)
                    envdir = workspace / 'venv'
                    self.assertFalse(envdir.exists())
                    self.assertNotIn('SAMPLE_PRIVATE_VALUE', environment)
                    envdir.mkdir()
                    if tool == successful:
                        executable = envdir / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
                        executable.parent.mkdir()
                        executable.write_text('fixture executable')
                        return 0, b''
                    (envdir / 'partial').write_text('failed attempt')
                    return 1, b'creation failed'
                binaries = {'git': git, 'uv': str(self.root / 'uv'), 'virtualenv': str(self.root / 'virtualenv')}
                with patch.object(rc.shutil, 'which', side_effect=lambda name: binaries.get(name)), patch.object(rc, 'command', side_effect=attempt):
                    python, _, route = rc.verification_venv(workspace, 30)
                expected = ['stdlib', 'uv', 'virtualenv']
                self.assertEqual(calls, expected[:expected.index(successful) + 1] if successful else expected)
                self.assertEqual(python is not None, successful is not None)
                self.assertEqual(route, "venv" if successful == "stdlib" else successful or "not-run")

    def test_absent_fallbacks_are_not_invoked(self):
        git = shutil.which('git')
        workspace = self.root / 'absent'
        workspace.mkdir()
        with patch.object(rc.shutil, 'which', side_effect=lambda name: git if name == 'git' else None), patch.object(rc, 'command', return_value=(1, b'no ensurepip')) as run:
            python, _, route = rc.verification_venv(workspace, 30)
        self.assertIsNone(python)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1:3], ['-m', 'venv'])
