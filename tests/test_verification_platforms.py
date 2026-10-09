import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc


class VerificationPlatformTests(unittest.TestCase):
    def test_windows_environment_keeps_os_paths_and_isolates_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / 'home'
            bindir = Path(tmp) / 'Scripts'
            with patch.object(sys, 'platform', 'win32'), patch.object(rc.shutil, 'which', return_value=str(Path(tmp) / 'git')), patch.dict(os.environ, {'SystemRoot': 'SystemFixture', 'SAMPLE_PRIVATE_VALUE': 'never-inherit'}):
                env = rc.safe_environment(home, bindir)
            self.assertEqual(env['USERPROFILE'], str(home))
            self.assertEqual(env['APPDATA'], str(home / 'AppData/Roaming'))
            self.assertEqual(env['LOCALAPPDATA'], str(home / 'AppData/Local'))
            self.assertEqual(env['SystemRoot'], 'SystemFixture')
            self.assertEqual(env['TEMP'], str(home))
            self.assertEqual(env['TMP'], str(home))
            self.assertEqual(env['PATH'].split(os.pathsep)[0], str(bindir))
            self.assertIn(str(Path('SystemFixture') / 'System32'), env['PATH'])
            self.assertNotIn('SAMPLE_PRIVATE_VALUE', env)
            self.assertEqual(env['GIT_CONFIG_GLOBAL'], os.devnull)

    def test_command_does_not_resolve_from_parent_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = rc.safe_environment(Path(tmp) / 'home', Path(tmp) / 'empty')
            env['PATH'] = str(Path(tmp) / 'empty')
            code, output = rc.command(['python', '-c', 'raise SystemExit(99)'], Path(tmp), env, 1)
            self.assertEqual(code, 127)
            self.assertIn(b'not found', output)

    def test_windows_timeout_kills_only_its_process_tree(self):
        # Exercise the Windows branch without starting a real process on Unix.
        with tempfile.TemporaryDirectory() as tmp:
            env = {'PATH': tmp, 'SystemRoot': tmp}
            with patch.object(sys, 'platform', 'win32'), patch.object(rc.shutil, 'which', return_value='fixture.exe'), patch.object(rc.subprocess, 'Popen') as start, patch.object(rc.subprocess, 'run') as kill:
                process = start.return_value
                process.pid = 123
                process.wait.side_effect = [subprocess.TimeoutExpired('fixture', 1), 0]
                process.poll.return_value = None
                code, _ = rc.command(['fixture'], Path(tmp), env, 1)
            self.assertEqual(code, 124)
            self.assertEqual(kill.call_args.args[0], [str(Path(tmp) / 'System32/taskkill.exe'), '/PID', '123', '/T', '/F'])
            process.kill.assert_called_once()
