"""Invented regression data is assembled at runtime, never copied from user files."""
import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import random
import shutil
import string
import unittest

import release_check as rc
import test_release_check as fixtures


def value(length=40, alphabet=string.ascii_letters + string.digits):
    return ''.join(random.Random(500 + length).choices(alphabet, k=length))


def findings(text, path="notes.txt", terms=()):
    scan = rc.Scanner(terms)
    scan.text(text.encode(), "tree", path)
    return scan.findings


class DetectorRegressions(unittest.TestCase):
    def assert_kind(self, text, kind, path="notes.txt", terms=()):
        hits = findings(text, path, terms)
        self.assertIn(kind, {f['kind'] for f in hits})
        self.assertTrue(all(not f['reviewed'] for f in hits if f['category'] == 'secrets'))
        return hits

    def test_provider_prefixes(self):
        hexdigits = string.hexdigits[:16]
        prefixes = [("glpat-", 20, None), ("shpat_", 32, hexdigits),
                    ("shpca_", 32, hexdigits), ("sq0atp-", 22, None),
                    ("sq0csp-", 22, None), ("dop_v1_", 64, hexdigits),
                    ("key-", 32, hexdigits), ("SK", 32, hexdigits), ("AC", 32, hexdigits)]
        for prefix, length, alphabet in prefixes:
            with self.subTest(prefix=prefix):
                self.assert_kind(prefix + value(length, alphabet or string.ascii_letters + string.digits), 'provider-token')
        self.assert_kind('glpat-' + value(19) + '-', 'provider-token')
        self.assert_kind(str(123 * 1000000) + ':AA' + value(33), 'provider-token')
        self.assert_kind(value(32, hexdigits) + '-us' + str(21), 'provider-token')
        url = 'https://' + 'fixture.webhook.office.com' + '/webhookb2/' + value(32) + '/IncomingWebhook/' + value()
        self.assert_kind(url, 'webhook-url')

    def test_context_hex_and_lowercase_tokens(self):
        for size, alphabet in [(32, string.hexdigits[:16]), (40, string.hexdigits[:16]),
                               (64, string.hexdigits[:16]), (40, string.ascii_lowercase),
                               (24, string.ascii_letters + string.digits)]:
            with self.subTest(size=size, alphabet=alphabet):
                self.assertTrue(any(f['category'] == 'secrets' for f in findings('token ' + value(size, alphabet))))
        self.assertEqual(findings('digest ' + value(64, string.hexdigits[:16])), [])
        self.assert_kind('API_KEY' + '\n' + value(64, string.hexdigits[:16]), 'entropy')

    def test_base64_slashes_and_connection_keys(self):
        secret = value(43)[:20] + '/' + value(43)[21:] + '='
        self.assert_kind(secret, 'entropy')
        for label in ['AccountKey', 'SharedAccessKey', 'client-key-data', 'certificate-key-data', 'private_key_id']:
            with self.subTest(label=label):
                self.assert_kind(label + ': ' + secret, 'assigned-secret')
        self.assert_kind('CONN = "DefaultEndpointsProtocol=https;AccountKey' + '=' + secret + ';EndpointSuffix=core.windows.net"', 'assigned-secret', 'config.py')

    def test_label_spellings_and_contexts(self):
        secret = value(14)
        labels = ['pass', 'passwd', 'pwd', 'password', 'secret', 'token', 'credential',
                  'auth', 'private_key', 'access_key', 'api_key', 'key', 'githubToken',
                  'clientSecret', 'refreshToken', 'smtpPassword', 'secretAccessKey',
                  'storePassword', 'keyPassword', 'trustPassword']
        for label in labels:
            with self.subTest(label=label):
                self.assert_kind(json.dumps({label: secret}), 'assigned-secret')
        for text, kind in [('--password' + ' ' + secret, 'cli-secret'), ('sshpass' + ' -p' + ' ' + secret, 'cli-secret'),
                           ('tool ' + '-p' + secret, 'cli-secret'),
                           ('mysql' + ' -u fixture ' + '-p' + secret, 'cli-secret'),
                           ('<' + 'password' + '>' + secret + '</' + 'password' + '>', 'xml-secret'),
                           ('password' + ' is ' + secret, 'prose-secret')]:
            with self.subTest(kind=kind, text=text[:15]):
                self.assert_kind(text, kind)
        for prefix in ['# ', '"""', "'''"]:
            self.assert_kind(prefix + 'password' + ': ' + secret + prefix, 'assigned-secret', 'config.py')
        self.assert_kind('password' + ' is ' + value(4), 'prose-secret')
        self.assert_kind('password' + '=' + 'ex' + 'ample' + value(12), 'assigned-secret')
        self.assert_kind('password' + '=' + value(8) + '(' + value(8), 'assigned-secret', 'config.py')

    def test_references_and_placeholders_remain_clear(self):
        for v in ['os.environ["VAR"]', '${VAR}', 'changeme', '<placeholder>']:
            self.assertEqual(findings('password' + '=' + v, 'config.py'), [])
            self.assertEqual(findings('password' + '=' + v), [])
        for code in ['key' + ' = (left, right)', 'token' + ' = injected', 'key == "public"']:
            self.assertEqual(findings(code, 'config.py'), [])

    def test_credential_content_in_renamed_files(self):
        secret = value(14)
        self.assert_kind('machine example.org login fixture ' + 'password' + ' ' + secret, 'netrc-password')
        self.assert_kind('machine example.org\nlogin fixture\n' + 'password' + ' ' + value(4), 'netrc-password')
        self.assert_kind(':'.join(['db.example.org', str(5432), 'db', 'fixture', secret]), 'pgpass')
        for prefix in ['apr1', '2a', '2b', '2y', '6']:
            self.assert_kind('fixture:$' + prefix + '$' + value(8) + '$' + value(), 'password-hash')
        self.assert_kind(json.dumps({'auths': {'example.org': {'auth': base64.b64encode(('fixture:' + secret).encode()).decode()}}}), 'assigned-secret')

    def test_basic_and_curl_auth(self):
        b64 = base64.b64encode(('fixture:' + value(12)).encode()).decode()
        self.assert_kind('Authorization: Basic ' + b64, 'basic-auth')
        self.assert_kind(json.dumps({'Authorization': 'Basic ' + b64}), 'basic-auth')
        self.assert_kind('curl -u fixture:' + value(12) + ' https://example.org', 'curl-auth')

    def test_extended_credential_url_schemes(self):
        for scheme in ['ftp', 'mongodb', 'mongodb+srv', 'amqps', 'mssql', 'mssql+pyodbc', 'redis']:
            self.assert_kind(scheme + '://fixture:' + value(12) + '@example.org/db', 'credential-url')
        self.assert_kind('redis://:' + value(12) + '@example.org', 'credential-url')
        self.assert_kind('https://' + value() + '@example.org', 'credential-url')

    def test_phone_shapes(self):
        for parts in [['+44', '7700', '900123'], ['+49', '151', '23456789'], ['+61', '412', '345', '678'],
                      ['+91', '98765', '43210'], ['+55', '11', '91234-5678'], ['07700', '900123'],
                      ['0044', '7700', '900123'], ['512', '867', '5309']]:
            self.assert_kind(('' if parts[0] == '512' else ' ').join(parts), 'phone')
        self.assertEqual(findings('timestamp ' + str(1700000000)), [])

    def test_internal_host_positions_and_unc(self):
        for suffix in ['corp', 'internal', 'intranet', 'home.arpa', 'private', 'lan', 'local', 'test']:
            self.assert_kind('.'.join(['build', suffix]), 'internal-host')
            self.assert_kind('https://' + '.'.join(['build', suffix, 'example.org']), 'internal-host')
        self.assert_kind('\\' * 2 + 'FILES' + '\\share', 'internal-host')

    def test_internal_domains_schema_and_report_redaction(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'terms.json'
            domain = '.'.join(['invented', 'invalid'])
            path.write_text(json.dumps({'terms': ['fictional'], 'internal_domains': [domain]}))
            terms = rc.load_terms(path)
            hits = self.assert_kind('https://build.' + domain, 'internal-host', terms=terms)
            self.assertNotIn(domain, json.dumps(hits))
            self.assertTrue(rc.Scanner(terms).safe_path('build.' + domain).startswith('[path-'))
            path.write_text(json.dumps({'terms': ['fictional'], 'internal_domains': ['*']}))
            with self.assertRaises(rc.AuditError):
                rc.load_terms(path)

    def test_private_term_normalization_and_safe_paths(self):
        parts = ['marma' + 'duke', 'voss']
        term = '-'.join(parts)
        for sep in ['', ' ', '_', '-', '\u2011', '-\n', ' - ']:
            text = sep.join(parts)
            self.assert_kind(text, 'denylist', terms=[term])
            self.assertTrue(rc.Scanner([term]).safe_path(text + '.md').startswith('[path-'))
        word = 'fictional'
        for text in [word[:3] + '\u200b' + word[3:], word[:3] + '\u2063' + word[3:], ''.join(chr(ord(c) + 0xfee0) for c in word)]:
            self.assert_kind(text, 'denylist', terms=[word])
            self.assertTrue(rc.Scanner([word]).safe_path(text).startswith('[path-'))
        secret = 'glpat-' + value(20)
        self.assert_kind(secret[:3] + '\u200b' + secret[3:], 'provider-token')

    def test_email_normalization(self):
        for at in ['&#64;', '%40', '\uff20', ' [at] ', '(at)']:
            self.assert_kind('fixture' + at + 'example' + ' [dot] org', 'email')
        self.assert_kind('"fixture person"' + '@' + 'example.org', 'email')

    def test_mac_and_ipv4_dot_obfuscation(self):
        pairs = [format(n, '02x') for n in [0, 26, 43, 60, 77, 94]]
        for sep in [':', '-']:
            self.assert_kind(sep.join(pairs), 'mac-address')
        self.assert_kind('.'.join(''.join(pairs)[i:i+4] for i in range(0, 12, 4)), 'mac-address')
        self.assert_kind('NIC ' + ''.join(pairs), 'mac-address')
        for sep in ['[.]', ' . ']:
            self.assert_kind(sep.join(str(n) for n in [192, 168, 1, 42]), 'ipv4')

    def test_home_path_variants(self):
        for text in ['\\' * 2 + 'fileserver\\home\\fictional', '%2F' + 'home' + '%2F' + 'fictional' + '%2Fproject',
                     '/'.join(['', 'Volumes', 'fictional']), '/'.join(['', 'mnt', 'home', 'fictional'])]:
            self.assert_kind(text, 'home-path')

    def test_integrity_exemption_does_not_hide_explicit_tokens(self):
        for algorithm in [256, 384, 512]:
            integrity = 'sha' + str(algorithm) + '-' + value(86) + '=='
            self.assertEqual(findings(json.dumps({'integrity': integrity}), 'package-lock.json'), [])
        digest = value(64, string.hexdigits[:16])
        self.assertEqual(findings('hash = "' + digest + '"', 'poetry.lock'), [])
        self.assert_kind(json.dumps({'integrity': 'glpat-' + value(20)}), 'provider-token', 'package-lock.json')

    def test_cheap_false_positives(self):
        function = '_'.join(['test', 'specific', 'review', 'cannot', 'waive', 'denylist', 'or', 'secret'])
        self.assertEqual(findings('def ' + function + '(self):', 'code.py'), [])
        for name in ['macos', 'node', 'utf', 'sha', 'base', 'iso']:
            self.assertEqual(findings(name + '-' + str(14)), [])
        for receiver in ['self', 'ctx', 'this', 'config', 'request']:
            for attr in ['local', 'internal', 'home']:
                self.assertEqual(findings(receiver + '.' + attr, 'code.py'), [])
        self.assertEqual(findings('https://docs.example.org/guides/private-networking-overview'), [])
        self.assertEqual(findings('export API_KEY' + '=' + '${API_KEY}'), [])
        self.assertEqual(findings('password' + ': <your password>'), [])
        self.assertEqual(findings('password' + ' is os.environ["VAR"]'), [])
        self.assertEqual(findings('copy ' + '.'.join(['settings', 'local', 'json'])), [])
        payload = base64.b64encode(bytes(random.Random(3).choices(range(256), k=300))).decode()
        self.assertEqual(findings('data:image/png;' + 'base64,' + payload, 'index.html'), [])
        self.assertEqual(findings('https://example.org/' + '/'.join(['SomePathWithCaps9'] * 4)), [])
        for license_id in ['mit', 'Apache-2.0', 'BSD-3-Clause']:
            self.assertEqual(findings(json.dumps({'key': license_id})), [])


class ExportRegressions(unittest.TestCase):
    setUp = fixtures.AuditTests.setUp
    git = fixtures.AuditTests.git
    commit = fixtures.AuditTests.commit

    def test_credential_files_are_detected_and_excluded(self):
        names = ['.netrc', '.pgpass', '.htpasswd', 'kubeconfig', '.pypirc',
                 'fixture.jks', 'fixture.keystore', 'terraform.tfstate',
                 '.docker/config.json', 'keystore.properties', '.kube/config',
                 'nested/.docker/config.json', 'nested/.kube/config']
        for name in names:
            p = self.repo / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('invented')
            scan = rc.Scanner([])
            scan.file(p.read_bytes(), 'tree', name)
            self.assertIn('credential-file', {f['kind'] for f in scan.findings})
        self.commit('Add invented credential files')
        target = self.root / 'export'
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner([]))
        self.assertTrue(all(not (target / name).exists() for name in names))
        rc.export_digest(target)

    def test_digest_metadata_and_unreachable_tampering(self):
        base = self.root / 'base'
        rc.copy_tree(self.repo, base, self.manifest, rc.Scanner([]))
        digest = rc.export_digest(base)
        paths = ['hooks/fixture.sample', 'info/attributes', 'objects/info/alternates', 'shallow',
                 'info/grafts', 'EXTRA', 'FETCH_HEAD', 'ORIG_HEAD', 'modules/x/config',
                 'worktrees/x/gitdir', 'lfs/x', 'info/sparse-checkout', 'objects/pack/extra']
        for name in paths + ['reflog', 'detached', 'loose', 'pack', 'empty-dir', 'index', 'touch', 'hook-symlink']:
            with self.subTest(name=name):
                target = self.root / 'mutation'
                shutil.copytree(base, target)
                try:
                    if name in paths:
                        p = target / '.git' / name
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_text('invented')
                    elif name == 'reflog':
                        p = target / '.git/logs/HEAD'
                        p.write_bytes(p.read_bytes() + b'invented\n')
                    elif name == 'detached':
                        rc.git(target, 'checkout', '-q', '--detach')
                    elif name in {'loose', 'pack'}:
                        p = target / 'blob.txt'
                        p.write_text('invented')
                        rc.git(target, 'hash-object', '-w', 'blob.txt')
                        p.unlink()
                        if name == 'pack':
                            rc.git(target, 'gc', '-q', '--prune=never')
                    elif name == 'empty-dir':
                        (target / 'empty').mkdir()
                    elif name == 'index':
                        p = target / '.git/index'
                        p.write_bytes(p.read_bytes() + b'invented')
                    elif name == 'hook-symlink':
                        (target / '.git/hooks/fixture.sample').symlink_to(self.root / 'missing')
                    else:
                        p = target / 'README.md'
                        import os
                        st = p.stat()
                        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1000000))
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(rc.main([str(target), '--check-digest', digest]), 1)
                finally:
                    shutil.rmtree(target)
        self.assertEqual(rc.export_digest(base), digest)

    def test_ref_tagger_and_remote_metadata(self):
        term = 'fictional' + 'identity'
        self.git('branch', 'branch-' + term)
        self.git('-c', 'user.name=' + term, 'tag', '-a', 'tag-' + term, '-m', term)
        self.git('remote', 'add', 'origin', 'https://fixture:' + 'glpat-' + value(20) + '@example.org/' + term)
        scan = rc.Scanner([term])
        scan.history(self.repo)
        self.assertTrue(any(f['path'] == '@refs' and f['kind'] == 'denylist' for f in scan.findings))
        self.assertTrue(any(f['path'] == '@config' and f['category'] == 'secrets' for f in scan.findings))
        self.assertNotIn(term, json.dumps(scan.findings))


if __name__ == '__main__':
    unittest.main()
