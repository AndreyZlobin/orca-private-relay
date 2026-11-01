import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import desired


class DesiredStateTests(unittest.TestCase):
    def test_one_field_resolves_all_defaults_and_repeated_resolution_is_stable(self):
        data = {'server': '1.1.1.1'}
        state = desired.resolve(data)
        self.assertEqual(state, desired.resolve(data))
        self.assertEqual(state['host'], 'root@1.1.1.1')
        self.assertEqual(state['origin'], 'https://orca-relay.1-1-1-1.sslip.io')
        self.assertEqual(state['auth'], 'password')
        self.assertEqual(state['port'], 22)
        self.assertTrue(state['configure_mac'])
        self.assertEqual(data, {'server': '1.1.1.1'})

    def test_secrets_unknown_fields_and_invalid_types_are_rejected(self):
        for key in ['password', 'owner_key', 'code', 'private_key']:
            with self.assertRaises(ValueError):
                desired.resolve({'server': '1.1.1.1', key: 'not-configuration'})
        for values in [{'server': 'root@@host'}, {'server': '-oProxyCommand=bad'},
                       {'server': '1.1.1.1', 'ssh_port': True}, {'server': '1.1.1.1', 'configure_mac': 'false'},
                       {'relay': None}, {'relay': 'https://relay.example.com', 'server': '1.1.1.1'}]:
            with self.assertRaises(ValueError):
                desired.resolve(values)

    def test_plan_reads_legacy_configuration_without_prompting_or_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / '.private').mkdir()
            legacy = {'ssh_host': 'deploy@1.1.1.1', 'origin': 'https://relay.example.com', 'ssh_auth': 'key', 'ssh_port': 2222}
            (root / '.private/deploy.json').write_text(json.dumps(legacy))
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with patch('builtins.input', side_effect=AssertionError('must not prompt')):
                state = desired.load(root)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(before, after)
            self.assertEqual(state['host'], 'deploy@1.1.1.1')
            self.assertEqual(state['auth'], 'key')
            self.assertEqual(state['port'], 2222)
            self.assertIn('2222', desired.install_arguments(state))

    def test_first_run_asks_once_and_saves_only_desired_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with patch('builtins.input', return_value='1.1.1.1') as prompt:
                first = desired.load(root, interactive=True)
            prompt.assert_called_once()
            path = root / '.private/desired.json'
            self.assertEqual(json.loads(path.read_text()), {'server': '1.1.1.1'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch('builtins.input', side_effect=AssertionError('repeat must not prompt')):
                self.assertEqual(desired.load(root, interactive=True), first)

    def test_existing_relay_client_has_no_server_or_ssh_configuration(self):
        self.assertEqual(desired.resolve({'relay': 'https://relay.example.com'}), {'kind': 'client', 'origin': 'https://relay.example.com'})
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / '.private').mkdir()
            (root / '.private/client.json').write_text(json.dumps({'origin': 'https://relay.example.com'}))
            with patch('builtins.input', side_effect=AssertionError('do not ask a client for VPS credentials')):
                self.assertEqual(desired.load(root, interactive=True)['kind'], 'client')


if __name__ == '__main__':
    unittest.main()
