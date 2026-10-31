import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


deploy = module('relay_deploy', ROOT / 'scripts/deploy.py')
install = module('relay_install', ROOT / 'deploy/install.py')


class DeploymentTests(unittest.TestCase):
    def test_origin_can_be_derived_without_a_domain_account(self):
        self.assertEqual(deploy.resolve_origin({'ssh_host': 'root@1.1.1.1'}), 'https://orca-relay.1-1-1-1.sslip.io')
        self.assertEqual(deploy.resolve_origin({'ssh_host': 'alias', 'public_ipv4': '8.8.8.8'}), 'https://orca-relay.8-8-8-8.sslip.io')
        self.assertEqual(deploy.resolve_origin({'ssh_host': 'root@10.0.0.1', 'origin': 'https://relay.example.com'}), 'https://relay.example.com')
        with self.assertRaises(ValueError):
            deploy.resolve_origin({'ssh_host': 'root@10.0.0.1'})

    def test_configuration_cannot_inject_remote_commands(self):
        for host in ['-oProxyCommand=evil', 'user@host;reboot', 'host\nreboot', 'user@host $(id)']:
            with self.assertRaises(ValueError):
                deploy.ssh_args({'ssh_host': host})
        for origin in ['http://relay.example.com', 'https://relay.example.com/', 'https://x;reboot', 'https://user@relay.example.com', 'https://relay.example.com\n']:
            with self.assertRaises(ValueError):
                deploy.resolve_origin({'origin': origin})
        with self.assertRaises(ValueError):
            deploy.ssh_args({'ssh_host': 'root@host', 'ssh_port': True})

    def test_plan_cannot_install_upload_or_fetch_credentials(self):
        calls = []
        def remote(_ssh, command, **kwargs):
            calls.append((command, kwargs))
            return '0' if command == 'id -u' else 'build' if 'installed-source' in command else ''
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'deploy.json'
            original = json.dumps({'ssh_host': 'root@host', 'origin': 'https://relay.example.com'})
            config.write_text(original)
            with patch.object(deploy, 'remote', side_effect=remote), patch.object(deploy, 'source_hash', return_value='a' * 64), contextlib.redirect_stdout(io.StringIO()):
                deploy.main(['--config', str(config), '--plan'])
            self.assertEqual(config.read_text(), original)
        self.assertTrue(calls[-1][0].endswith('sh -s -- --plan'))
        self.assertFalse(any('tar -x' in command or 'docker run' in command or 'OWNER_SECRET' in command for command, _ in calls))

    def test_only_build_inputs_change_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'src').mkdir()
            for name in ['Cargo.toml', 'Cargo.lock', 'src/main.rs']:
                (root / name).write_text(name)
            first = deploy.source_hash(root)
            (root / 'README.md').write_text('new instructions')
            self.assertEqual(first, deploy.source_hash(root))
            (root / 'src/main.rs').write_text('changed code')
            self.assertNotEqual(first, deploy.source_hash(root))

    def test_new_host_does_not_reuse_previous_origin(self):
        destinations = []
        def remote(ssh, command, **kwargs):
            destinations.append(ssh[-1])
            return '0' if command == 'id -u' else 'build' if 'installed-source' in command else ''
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'deploy.json'
            config.write_text(json.dumps({'ssh_host': 'root@old-host', 'origin': 'https://old.example.com', 'public_ipv4': '8.8.8.8'}))
            output = io.StringIO()
            with patch.object(deploy, 'remote', side_effect=remote), patch.object(deploy, 'source_hash', return_value='a' * 64), contextlib.redirect_stdout(output):
                deploy.main(['--config', str(config), '--host', 'root@1.1.1.1', '--plan'])
            self.assertIn('https://orca-relay.1-1-1-1.sslip.io', output.getvalue())
            self.assertNotIn('old.example.com', output.getvalue())
            self.assertTrue(all(host == 'root@1.1.1.1' for host in destinations))

    def test_installation_is_repeatable_and_restores_previous_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            existing = root / 'existing'
            created = root / 'new'
            existing.write_bytes(b'old')
            existing.chmod(0o600)
            changes = install.Changes(root / 'backups')
            self.assertFalse(changes.write(existing, b'old', 0o600))
            self.assertFalse((root / 'backups').exists())
            self.assertTrue(changes.write(existing, b'new', 0o644))
            self.assertFalse(changes.write(existing, b'new', 0o644))
            changes.write(created, b'created')
            changes.restore()
            self.assertEqual(existing.read_bytes(), b'old')
            self.assertEqual(existing.stat().st_mode & 0o777, 0o600)
            self.assertFalse(created.exists())

    def test_existing_caddy_site_must_match_both_domain_and_upstream(self):
        config = {'routes': [{'match': [{'host': ['other.example.com']}], 'handle': [{'upstreams': [{'dial': '127.0.0.1:6770'}]}]}]}
        self.assertFalse(install.has_managed_upstream(config, 'relay.example.com'))
        config['routes'].append({'match': [{'host': ['relay.example.com']}], 'handle': [{'upstreams': [{'dial': '127.0.0.1:8000'}]}]})
        self.assertFalse(install.has_managed_upstream(config, 'relay.example.com'))
        config['routes'][1]['handle'][0]['upstreams'][0]['dial'] = '127.0.0.1:6770'
        self.assertTrue(install.has_managed_upstream(config, 'relay.example.com'))


if __name__ == '__main__':
    unittest.main()
