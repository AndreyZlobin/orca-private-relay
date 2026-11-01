import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('relay_client', ROOT / 'scripts/relay.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
ORIGIN = 'https://relay.example.com'
KEY = 'k' * 43


class ClientSetupTests(unittest.TestCase):
    def test_profile_is_private_and_a_secret_cannot_be_sent_to_another_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            profile = client.save_profile(root / 'connection.json', ORIGIN, KEY)
            self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
            self.assertEqual(client.load_connection(profile, root=root), (ORIGIN, KEY))
            with self.assertRaises(ValueError):
                client.load_connection(profile, 'https://another.example.com', root=root)
            link = root / 'link.json'
            link.symlink_to(profile)
            with self.assertRaises(ValueError):
                client.save_profile(link, ORIGIN, KEY)

    def test_wrong_owner_key_stops_before_settings_restart_or_clipboard(self):
        with patch.object(client.platform, 'system', return_value='Darwin'), \
             patch.object(client.pathlib.Path, 'is_dir', return_value=True), \
             patch.object(client, 'load_connection', return_value=(ORIGIN, KEY)), \
             patch.object(client, 'health'), \
             patch.object(client, 'request_json', side_effect=ValueError('invalid key')), \
             patch.object(client.subprocess, 'run') as run, \
             patch.object(client, 'restart_orca') as restart, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'invalid key'):
                client.connect()
        run.assert_not_called()
        restart.assert_not_called()

    def test_connect_is_independent_of_ssh_and_does_not_print_the_owner_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = io.StringIO()
            with patch.object(client, 'ROOT', root), \
                 patch.object(client.platform, 'system', return_value='Darwin'), \
                 patch.object(client.pathlib.Path, 'is_dir', return_value=True), \
                 patch.object(client, 'load_connection', return_value=(ORIGIN, KEY)), \
                 patch.object(client, 'health', return_value={'ok': True}), \
                 patch.object(client, 'request_json') as request, \
                 patch.object(client.subprocess, 'run') as run, \
                 patch.object(client, 'restart_orca') as restart, contextlib.redirect_stdout(output):
                client.connect()
            request.assert_called_once_with(ORIGIN, '/admin/status', KEY)
            restart.assert_called_once()
            self.assertEqual(len(run.call_args_list), 2)
            self.assertEqual(run.call_args_list[-1].args[0], ['pbcopy'])
            self.assertEqual(run.call_args_list[-1].kwargs['input'], KEY.encode())
            self.assertTrue(all('ssh' not in call.args[0] for call in run.call_args_list))
            self.assertNotIn(KEY, output.getvalue())
            self.assertEqual(json.loads((root / '.private/connection.json').read_text())['origin'], ORIGIN)


if __name__ == '__main__':
    unittest.main()
