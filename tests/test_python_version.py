import json
from pathlib import Path
import subprocess
import sys
import unittest


class PythonVersionTests(unittest.TestCase):
    def run_old_python(self, *args):
        source = Path(__file__).resolve().parents[1] / 'release_check.py'
        code = "import sys; sys.version_info=(3,9,6); exec(compile(open(sys.argv[1]).read(),sys.argv[1],'exec'))"
        return subprocess.run([sys.executable, '-c', code, str(source), *args], capture_output=True, text=True)

    def test_old_python_help_explains_minimum_before_tomllib_import(self):
        result = self.run_old_python('--help')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertTrue(result.stderr.startswith('release-check needs Python 3.11 or newer; you have 3.9.6.'))
        self.assertIn('README Quickstart', result.stderr)
        self.assertIn('no-admin uv/Python 3.12 route', result.stderr)

    def test_old_python_json_keeps_structured_error_with_version(self):
        result = self.run_old_python('--json')
        self.assertEqual(result.returncode, 2)
        error = json.loads(result.stderr)
        self.assertEqual(error['code'], 'python-version')
        self.assertEqual(error['verdict'], 'INCOMPLETE')
        self.assertFalse(error['ready'])
        self.assertIn('you have 3.9.6', error['message'])
        self.assertNotIn('Traceback', result.stderr)
