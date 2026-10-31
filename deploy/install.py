"""Apply only changed files and recover the previous runtime/configuration on failure."""
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request

ROOT = pathlib.Path('/opt/orca-private-relay')
BINARY = pathlib.Path('/usr/local/bin/orca-private-relay')
ENVIRONMENT = pathlib.Path('/etc/orca-private-relay.env')
CADDYFILE = pathlib.Path('/etc/caddy/Caddyfile')
SITE = pathlib.Path('/etc/caddy/conf.d/orca-private-relay.caddy')
UNIT = pathlib.Path('/etc/systemd/system/orca-private-relay.service')
FIREWALL = pathlib.Path('/usr/local/lib/orca-private-relay/firewall.sh')
FIREWALL_UNIT = pathlib.Path('/etc/systemd/system/orca-private-relay-firewall.service')


def run(*argv, capture=False, required=True):
    result = subprocess.run(argv, capture_output=capture, text=True)
    if result.returncode and required:
        raise RuntimeError(f'{argv[0]} failed ({result.returncode})')
    return result


def active(service):
    return run('systemctl', 'is-active', '--quiet', service, required=False).returncode == 0


class Changes:
    def __init__(self, backup_root):
        self.root = backup_root
        self.previous = {}

    def write(self, path, content, mode=0o644):
        path = pathlib.Path(path)
        if path.is_symlink():
            raise RuntimeError(f'Refusing to replace a symlink: {path}')
        if path.exists() and path.read_bytes() == content and stat.S_IMODE(path.stat().st_mode) == mode:
            return False
        if path not in self.previous:
            backup = self.root / path.relative_to('/')
            if path.exists():
                backup.parent.mkdir(parents=True, exist_ok=True)
                self.root.chmod(0o700)
                shutil.copy2(path, backup)
                self.previous[path] = backup
            else:
                self.previous[path] = None
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temp = pathlib.Path(handle.name)
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        return True

    def restore(self):
        for path, backup in reversed(list(self.previous.items())):
            if backup is None:
                path.unlink(missing_ok=True)
            else:
                shutil.copy2(backup, path)


def site_content(domain):
    return (domain + ''' {
    header {
        Cache-Control "no-store"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
    }
    reverse_proxy 127.0.0.1:6770
}
''').encode()


def has_managed_upstream(node, domain, matched=False):
    if isinstance(node, list):
        return any(has_managed_upstream(item, domain, matched) for item in node)
    if not isinstance(node, dict):
        return False
    matched = matched or any(domain in rule.get('host', []) for rule in node.get('match', []) if isinstance(rule, dict))
    if matched and any(up.get('dial') == '127.0.0.1:6770' for up in node.get('upstreams', [])):
        return True
    return any(has_managed_upstream(value, domain, matched) for value in node.values() if isinstance(value, (dict, list)))


def local_health():
    for attempt in range(10):
        try:
            with urllib.request.urlopen('http://127.0.0.1:6770/healthz', timeout=2) as response:
                value = json.load(response)
            if value.get('ok') is True and value.get('service') == 'orca-private-relay':
                return
        except (OSError, ValueError):
            pass
        if attempt < 9:
            time.sleep(1)
    raise RuntimeError('Native relay health check failed')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Run installer as root')
    os.umask(0o077)
    lock = open('/run/lock/orca-private-relay-install.lock', 'a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError('Another relay installation is already applying changes') from None
    origin = os.environ.get('RELAY_DEPLOY_ORIGIN', '')
    if not re.fullmatch(r'https://[a-z0-9][a-z0-9.-]*[a-z0-9]', origin):
        raise RuntimeError('Expected canonical HTTPS domain without port/path')
    domain = origin.removeprefix('https://')
    source_digest = os.environ.get('RELAY_SOURCE_SHA256', '')
    if source_digest and not re.fullmatch('[0-9a-f]{64}', source_digest):
        raise RuntimeError('Invalid source digest')
    environment = None
    if ENVIRONMENT.exists():
        values = dict(line.split('=', 1) for line in ENVIRONMENT.read_text().splitlines() if '=' in line)
        if values.get('RELAY_ORIGIN') != origin:
            raise RuntimeError('Existing origin differs; migrate domain/paired clients explicitly')
    else:
        environment = (
            f'RELAY_ORIGIN={origin}\nRELAY_LISTEN=127.0.0.1:6770\n'
            'RELAY_DATABASE=/var/lib/orca-private-relay/relay.sqlite\n'
            f'RELAY_OWNER_SECRET={secrets.token_urlsafe(32)}\n'
            f'RELAY_SIGNING_KEY={secrets.token_urlsafe(48)}\n'
        ).encode()
    candidate = BINARY if os.environ.get('RELAY_REUSE_BINARY') == '1' else ROOT / 'target/release/orca-private-relay'
    binary_data = candidate.read_bytes()
    previous_relay = active('orca-private-relay')
    previous_caddy = active('caddy')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    changes = Changes(ROOT / 'backups' / stamp)
    runtime_changed = False
    caddy_changed = False
    firewall_was_installed = FIREWALL_UNIT.exists()
    try:
        if run('getent', 'passwd', 'orca-relay', capture=True, required=False).returncode:
            run('useradd', '--system', '--home-dir', '/var/lib/orca-private-relay', '--shell', '/usr/sbin/nologin', 'orca-relay')
        run('install', '-d', '-m', '700', '-o', 'orca-relay', '-g', 'orca-relay', '/var/lib/orca-private-relay')
        if environment is not None:
            changes.write(ENVIRONMENT, environment, 0o600)
        elif stat.S_IMODE(ENVIRONMENT.stat().st_mode) != 0o600:
            changes.write(ENVIRONMENT, ENVIRONMENT.read_bytes(), 0o600)
        current = CADDYFILE.read_text() if CADDYFILE.exists() else '{\n    admin 127.0.0.1:2019\n}\n'
        inline_domain = bool(re.search(r'(?m)^\s*(?:https://)?' + re.escape(domain) + r'\s*\{', current))
        if inline_domain:
            adapted = run('caddy', 'adapt', '--config', str(CADDYFILE), capture=True)
            if not has_managed_upstream(json.loads(adapted.stdout), domain):
                raise RuntimeError('This domain already belongs to another Caddy site; refusing replacement')
        else:
            # The installer uses umask 077; Caddy must still be able to read imports.
            run('install', '-d', '-m', '755', str(SITE.parent))
            caddy_changed = changes.write(SITE, site_content(domain))
            if 'import /etc/caddy/conf.d/*.caddy' not in current:
                caddy_changed = changes.write(CADDYFILE, (current.rstrip() + '\n\nimport /etc/caddy/conf.d/*.caddy\n').encode()) or caddy_changed
        run('caddy', 'validate', '--config', str(CADDYFILE), capture=True)
        runtime_changed = changes.write(BINARY, binary_data, 0o755)
        unit_changed = changes.write(UNIT, (ROOT / 'deploy/orca-private-relay.service').read_bytes())
        runtime_changed = runtime_changed or unit_changed or environment is not None
        changes.write(FIREWALL, (ROOT / 'deploy/firewall.sh').read_bytes(), 0o755)
        firewall_unit_changed = changes.write(FIREWALL_UNIT, (ROOT / 'deploy/orca-private-relay-firewall.service').read_bytes())
        if unit_changed or firewall_unit_changed:
            run('systemctl', 'daemon-reload')
        run('sh', str(FIREWALL))
        run('systemctl', 'enable', '--now', 'orca-private-relay-firewall')
        run('systemctl', 'enable', 'orca-private-relay')
        if previous_relay and runtime_changed:
            run('systemctl', 'restart', 'orca-private-relay')
        elif not previous_relay:
            run('systemctl', 'start', 'orca-private-relay')
        local_health()
        run('systemctl', 'enable', 'caddy')
        if not previous_caddy:
            run('systemctl', 'start', 'caddy')
        elif caddy_changed:
            run('systemctl', 'reload', 'caddy')
        if source_digest:
            changes.write(ROOT / '.installed-source.sha256', (source_digest + '\n').encode(), 0o600)
            changes.write(ROOT / '.installed-binary.sha256', (hashlib.sha256(binary_data).hexdigest() + '\n').encode(), 0o600)
        print('Relay runtime:', 'updated' if runtime_changed else 'unchanged; connection preserved')
        print('HTTPS configuration:', 'updated' if caddy_changed else 'unchanged')
        print('Keys and database: preserved' if environment is None else 'Private owner/signing keys generated')
    except Exception:
        if not previous_relay:
            run('systemctl', 'stop', 'orca-private-relay', required=False)
        if not firewall_was_installed:
            run('systemctl', 'disable', '--now', 'orca-private-relay-firewall', required=False)
        changes.restore()
        run('systemctl', 'daemon-reload', required=False)
        if previous_relay and runtime_changed:
            run('systemctl', 'restart', 'orca-private-relay', required=False)
        if previous_caddy and caddy_changed:
            run('systemctl', 'reload', 'caddy', required=False)
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(f'Install failed; previous files restored: {error}') from None
