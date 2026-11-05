import importlib.util
import pathlib
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('restart_mac', pathlib.Path(__file__).resolve().parents[1] / 'scripts/restart-mac.py')
restart_mac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restart_mac)
ORIGIN = 'https://relay.example.com'


class MacRestartTests(unittest.TestCase):
    def test_explicit_routes_override_stale_parent_environment(self):
        def run(command, **kwargs):
            output = ORIGIN if command[0] == '/bin/launchctl' else 'false'
            return subprocess.CompletedProcess(command, 0, output, '')

        with patch.object(restart_mac.subprocess, 'run', side_effect=run) as calls:
            restart_mac.restart(ORIGIN)
        command = calls.call_args_list[-1].args[0]
        self.assertEqual(command[:3], ['/usr/bin/open', '-a', 'Orca'])
        self.assertEqual(command[3:], [part for name in restart_mac.VARIABLES for part in ['--env', name + '=' + ORIGIN]])
        self.assertTrue(any('to quit' in ' '.join(call.args[0]) for call in calls.call_args_list))

    def test_unconfigured_mac_is_not_quit(self):
        with patch.object(restart_mac.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')) as calls:
            with self.assertRaises(ValueError):
                restart_mac.restart(ORIGIN)
        self.assertEqual(calls.call_count, 1)

    def test_invalid_origin_does_not_start_any_process(self):
        with patch.object(restart_mac.subprocess, 'run') as calls:
            with self.assertRaises(ValueError):
                restart_mac.restart('https://relay.example.com/path')
        calls.assert_not_called()
