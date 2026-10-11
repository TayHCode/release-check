"""Exact upstream evidence can authorize only the three known wording variants."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import release_check as rc

CANONICAL = (Path(__file__).parent / 'fixtures/Apache-2.0.txt').read_text()
DIFFERENCES = [
    {'canonical': 'submitted to Licensor', 'upstream': 'submitted to the Licensor'},
    {'canonical': 'received by Licensor', 'upstream': 'received by the Licensor'},
    {'canonical': 'within such NOTICE file, excluding those notices',
     'upstream': 'within such NOTICE file, excluding any notices'},
]
UPSTREAM = (Path(__file__).parent / 'fixtures/engineering-notebook-LICENSE.txt').read_text()


class UpstreamLicenseDispositionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.path = self.repo / 'LICENSE'
        self.path.write_text(UPSTREAM)
        self.disposition = dict(
            reviewed=True, spdx='Apache-2.0', path='LICENSE',
            source_url='https://github.com/prime-radiant-inc/engineering-notebook',
            upstream_commit='b0a34caa4b59e466652572310fd043a9548027c2',
            sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
            differences=copy.deepcopy(DIFFERENCES))
        self.manifest = {'exclude': [], 'license_owner_disposition': self.disposition}

    def audit(self):
        scanner = rc.Scanner([])
        result = rc.license_audit(self.repo, scanner, self.manifest)
        return result, {f['kind'] for f in scanner.findings}

    def test_exact_variants_accepted_and_reported(self):
        (self.repo / 'release-check.json').write_text(json.dumps(self.manifest))
        self.manifest = rc.manifest_for(self.repo, None)
        result, kinds = self.audit()
        self.assertEqual(kinds, set())
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['identifier'], 'Apache-2.0')
        self.assertEqual(result['owner_disposition'], self.disposition)
        report = dict(version=rc.VERSION, ready=True, findings=[], counts={},
                      verification={}, license=result)
        for output in (rc.format_text(report), rc.format_markdown(report)):
            self.assertIn('OWNER UPSTREAM LICENSE DISPOSITION', output)
            for value in (self.disposition['source_url'], self.disposition['upstream_commit'],
                          self.disposition['sha256'], 'submitted to the Licensor'):
                self.assertIn(value, output)
        self.assertFalse(rc.apache_license(UPSTREAM))

    def test_absent_or_malformed_disposition_blocked(self):
        for value in (None, {}, [], True):
            self.manifest['license_owner_disposition'] = value
            with self.subTest(value=value):
                self.assertIn('unrecognized-or-modified-license', self.audit()[1])

    def test_wrong_hash_or_evidence_blocked(self):
        for field, value in (
            ('sha256', 'f' * 64), ('source_url', 'https://example.org'),
            ('upstream_commit', 'b0a34caa'), ('path', 'COPYING'),
            ('reviewed', 1), ('reviewed', False), ('spdx', 'MIT'),
            ('differences', DIFFERENCES[:2]), ('differences', list(reversed(DIFFERENCES)))):
            with self.subTest(field=field, value=value):
                self.manifest['license_owner_disposition'] = dict(self.disposition, **{field: value})
                self.assertIn('unrecognized-or-modified-license', self.audit()[1])

    def test_disposition_cannot_be_ignored_by_replacing_with_canonical(self):
        self.path.write_text(CANONICAL)
        self.assertIn('invalid-license-owner-disposition', self.audit()[1])
        self.disposition['sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertIn('invalid-license-owner-disposition', self.audit()[1])

    def test_unknown_evidence_fields_cannot_leak_into_report(self):
        self.disposition['note'] = 'Unreviewed arbitrary data'
        result, kinds = self.audit()
        self.assertIn('invalid-license-owner-disposition', kinds)
        self.assertNotIn('owner_disposition', result)

    def test_observed_variant_license_must_remain_verbatim(self):
        env = dict(os.environ, GIT_AUTHOR_NAME='Release Export', GIT_AUTHOR_EMAIL='release-export',
                   GIT_COMMITTER_NAME='Release Export', GIT_COMMITTER_EMAIL='release-export')
        def git(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], env=env,
                           check=True, capture_output=True)
        git('init', '-q', '-b', 'main')
        git('add', '--', 'LICENSE')
        git('commit', '-q', '-m', 'Synthetic upstream\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@' + 'anthropic.com>')
        self.assertEqual(self.audit()[1], set())
        self.path.write_text(CANONICAL)
        self.manifest.pop('license_owner_disposition')
        self.assertIn('historical-attribution-changed', self.audit()[1])
        self.path.write_text(UPSTREAM + '\n')
        self.manifest['license_owner_disposition'] = self.disposition
        self.disposition['sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.assertIn('historical-attribution-changed', self.audit()[1])

    def test_other_edits_rejected_even_with_updated_hash(self):
        for text in (UPSTREAM.replace('royalty-free', 'royalty-bearing'),
                     UPSTREAM.replace('January 2004', 'January 2026'),
                     UPSTREAM + '\nNo commercial use.\n',
                     UPSTREAM.replace('submitted to the Licensor', 'submitted to Licensor'),
                     UPSTREAM.replace('excluding any notices', 'excluding those notices'),
                     UPSTREAM.replace('Prime Radiant Inc.', 'Replacement Corporation'),
                     UPSTREAM + '\n'):
            with self.subTest(text=text[-40:]):
                self.path.write_text(text)
                self.disposition['sha256'] = hashlib.sha256(self.path.read_bytes()).hexdigest()
                self.assertIn('unrecognized-or-modified-license', self.audit()[1])

    def test_metadata_and_attribution_stay_enforced(self):
        (self.repo / 'pyproject.toml').write_text('[project]\nlicense = "MIT"\n')
        self.assertIn('license-metadata-mismatch', self.audit()[1])
        self.manifest['exclude'] = ['LICENSE']
        self.assertIn('excluded-attribution', self.audit()[1])

    def test_missing_license_stays_blocked(self):
        self.path.unlink()
        self.assertIn('missing-license', self.audit()[1])

    def test_canonical_still_needs_no_disposition(self):
        self.path.write_text(CANONICAL)
        self.manifest.pop('license_owner_disposition')
        self.assertEqual(self.audit()[1], set())
