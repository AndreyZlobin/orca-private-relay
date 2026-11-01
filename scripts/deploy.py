"""Prepare a bare VPS, build the relay, configure HTTPS and verify public readiness."""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import pathlib
import re
import shlex
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGE = 'rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3'


def resolve_origin(config):
    origin = config.get('origin')
    if not origin:
        host = config.get('public_ipv4') or config['ssh_host'].rsplit('@', 1)[-1]
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addresses = [ipaddress.ip_address(r[4][0]) for r in socket.getaddrinfo(host, None, socket.AF_INET)]
            except OSError as e:
                raise ValueError('Cannot derive a public IP from SSH alias; set origin or public_ipv4') from e
        public = next((ip for ip in addresses if ip.version == 4 and ip.is_global), None)
        if not public:
            raise ValueError('Automatic HTTPS requires a public IPv4; set origin explicitly')
        origin = f'https://orca-relay.{str(public).replace(".", "-")}.sslip.io'
    if not isinstance(origin, str) or not re.fullmatch(r'https://[a-z0-9][a-z0-9.-]*[a-z0-9]', origin):
        raise ValueError('origin must be an HTTPS hostname without a port, path or trailing slash')
    parsed = urllib.parse.urlparse(origin)
    if origin != 'https://' + (parsed.hostname or ''):
        raise ValueError('Invalid HTTPS origin')
    return origin


def ssh_args(config, *, password_login=False):
    host = config.get('ssh_host', '')
    if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]*', host):
        raise ValueError('Invalid SSH destination')
    port = config.get('ssh_port', 22)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('ssh_port must be between 1 and 65535')
    args = ['ssh', '-o', 'BatchMode=' + ('no' if password_login else 'yes'), '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=accept-new', '-p', str(port)]
    if password_login:
        args += ['-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no', '-o', 'KbdInteractiveAuthentication=no']
    elif config.get('ssh_key'):
        key = pathlib.Path(config['ssh_key']).expanduser()
        if not key.is_file():
            raise ValueError('SSH private key does not exist')
        args += ['-i', str(key)]
    return args + [host]


@contextlib.contextmanager
def ssh_connection(config, ask_pass=False):
    if not ask_pass:
        yield ssh_args(config)
        return
    args = ssh_args(config, password_login=True)
    # A short, private socket path also fits macOS's Unix-socket path limit.
    with tempfile.TemporaryDirectory(prefix='orca-ssh-', dir='/tmp') as directory:
        control = ['-o', 'ControlPath=' + str(pathlib.Path(directory) / 'control')]
        master = [*args[:-1], *control, '-M', '-N', '-f', '-o', 'ControlPersist=300', args[-1]]
        print('Enter the VPS login password at the SSH prompt (not saved).', flush=True)
        result = subprocess.run(master, check=False)
        if result.returncode:
            raise RuntimeError('Password SSH login failed; the VPS must already permit password login for this user')
        try:
            # BatchMode prevents an interrupted master from consuming uploaded data
            # as interactive input. All commands share the authenticated connection.
            yield ['ssh', '-o', 'BatchMode=yes', '-o', 'ControlMaster=no', *control, *args[1:]]
        finally:
            try:
                subprocess.run([*args[:-1], *control, '-O', 'exit', args[-1]],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass  # ControlPersist also expires an idle master after five minutes.


def source_hash(root=ROOT):
    digest = hashlib.sha256(IMAGE.encode())
    paths = [root / 'Cargo.toml', root / 'Cargo.lock', *sorted((root / 'src').rglob('*.rs'))]
    for path in paths:
        digest.update(str(path.relative_to(root)).encode() + b'\0')
        content = path.read_bytes()
        digest.update(len(content).to_bytes(8, 'big') + content)
    return digest.hexdigest()


def remote(ssh, command, *, data=None, capture=False):
    result = subprocess.run([*ssh, command], input=data, capture_output=capture, check=False)
    if result.returncode:
        detail = result.stderr.decode(errors='replace').strip() if capture and result.stderr else ''
        raise RuntimeError(f'Remote command failed ({result.returncode}): {detail}')
    return result.stdout.decode().strip() if capture else ''


def verify_health(origin, timeout=120):
    deadline = time.monotonic() + timeout
    error = 'not ready'
    while True:
        try:
            with urllib.request.urlopen(origin + '/healthz', timeout=8) as response:
                result = json.load(response)
            if result.get('ok') is True and result.get('service') == 'orca-private-relay':
                return result
            error = 'unexpected health response'
        except (OSError, ValueError) as e:
            error = str(e)
        if time.monotonic() >= deadline:
            raise RuntimeError('Public HTTPS is not ready. Check DNS and provider-level TCP 80/443 rules. ' + error)
        time.sleep(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', help='SSH destination; root or passwordless sudo required')
    parser.add_argument('--port', type=int, help='SSH port; overrides the saved port')
    parser.add_argument('--origin', help='HTTPS hostname; omit to derive an sslip.io name from the VPS IPv4')
    parser.add_argument('--config', type=pathlib.Path, default=ROOT / '.private/deploy.json')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true', help='Read-only dependency and build plan')
    modes.add_argument('--status', action='store_true', help='Read current service and public HTTPS status')
    parser.add_argument('--rebuild', action='store_true', help='Force rebuilding the native binary')
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument('--ask-pass', action='store_true', help='Prompt once for the VPS SSH password; remember this login method')
    auth.add_argument('--key-auth', action='store_true', help='Use SSH keys even if password login was previously selected')
    args = parser.parse_args(argv)
    try:
        config = json.loads(args.config.read_text()) if args.config.exists() else {}
        if not isinstance(config, dict):
            parser.error('Configuration must be a JSON object')
    except (OSError, ValueError) as error:
        parser.error(f'Cannot read configuration: {error}')
    if args.host:
        if args.host != config.get('ssh_host') and not args.origin:
            # A new VPS must not accidentally take the previous server's hostname.
            config.pop('origin', None)
            config.pop('public_ipv4', None)
        config['ssh_host'] = args.host
    if args.origin:
        config['origin'] = args.origin
    if args.port is not None:
        config['ssh_port'] = args.port
    connections = contextlib.ExitStack()
    try:
        if config.get('ssh_auth') not in [None, 'key', 'password']:
            raise ValueError('ssh_auth must be key or password')
        password_login = args.ask_pass or (not args.key_auth and config.get('ssh_auth') == 'password')
        ssh = connections.enter_context(ssh_connection(config, password_login))
        origin = resolve_origin(config)
        user_id = remote(ssh, 'id -u', capture=True)
        elevate = '' if user_id == '0' else 'sudo -n '
        remote(ssh, elevate + 'true')
        print('Relay endpoint:', origin, flush=True)
        if args.status:
            remote(ssh, elevate + 'systemctl show orca-private-relay -p ActiveState -p MainPID -p NRestarts -p MemoryCurrent')
            print('Public HTTPS:', verify_health(origin, timeout=0))
            return
        digest = source_hash()
        reuse_check = (
            'test -x /usr/local/bin/orca-private-relay && '
            f'test "$(cat /opt/orca-private-relay/.installed-source.sha256 2>/dev/null)" = {digest} && '
            'test "$(sha256sum /usr/local/bin/orca-private-relay | cut -d " " -f1)" = '
            '"$(cat /opt/orca-private-relay/.installed-binary.sha256 2>/dev/null)" && echo reuse || echo build'
        )
        reuse = remote(ssh, elevate + 'sh -c ' + shlex.quote(reuse_check), capture=True) == 'reuse' and not args.rebuild
        print('Binary:', 'reuse unchanged release' if reuse else 'build release on VPS', flush=True)
        mode = '--plan' if args.plan else 'apply'
        command = elevate + 'env RELAY_NEED_BUILD=' + ('0' if reuse else '1') + ' sh -s -- ' + mode
        remote(ssh, command, data=(ROOT / 'deploy/bootstrap.sh').read_bytes())
        if args.plan:
            return
        remote(ssh, elevate + 'install -d -m 755 /opt/orca-private-relay')
        process = subprocess.Popen([*ssh, elevate + 'tar -xzf - -C /opt/orca-private-relay'], stdin=subprocess.PIPE)
        assert process.stdin is not None
        try:
            with tarfile.open(fileobj=process.stdin, mode='w|gz') as archive:
                for name in ['Cargo.toml', 'Cargo.lock', 'src', 'deploy', 'THIRD_PARTY_NOTICES.md', 'LICENSE', 'README.md']:
                    archive.add(ROOT / name, arcname=name, filter=lambda info: None if '__pycache__' in info.name else info)
        finally:
            process.stdin.close()
        if process.wait():
            raise RuntimeError('Source upload failed')
        if not reuse:
            build = (
                'docker run --rm --name orca-relay-build --cpus=0.75 --memory=1100m --memory-swap=1300m '
                '-e CARGO_BUILD_JOBS=1 -e CARGO_HOME=/build/.cargo-cache '
                '-v /opt/orca-private-relay:/build -w /build ' + shlex.quote(IMAGE) + ' cargo build --release --locked'
            )
            remote(ssh, elevate + build)
        install = elevate + 'env RELAY_DEPLOY_ORIGIN=' + shlex.quote(origin) + ' RELAY_SOURCE_SHA256=' + digest + ' RELAY_REUSE_BINARY=' + ('1' if reuse else '0') + ' sh /opt/orca-private-relay/deploy/install.sh'
        remote(ssh, install)
        print('Waiting for trusted public HTTPS...', flush=True)
        verify_health(origin)
        private = ROOT / '.private'
        private.mkdir(mode=0o700, exist_ok=True)
        private.chmod(0o700)
        secret = remote(ssh, elevate + 'python3 -c ' + shlex.quote("from pathlib import Path; d=dict(l.split('=',1) for l in Path('/etc/orca-private-relay.env').read_text().splitlines() if '=' in l); print(d['RELAY_OWNER_SECRET'])"), capture=True)
        key = private / 'owner.key'
        key.write_text(secret)
        key.chmod(0o600)
        config['origin'] = origin
        config['ssh_auth'] = 'password' if password_login else 'key'
        args.config.parent.mkdir(parents=True, exist_ok=True)
        args.config.write_text(json.dumps(config, indent=2) + '\n')
        args.config.chmod(0o600)
        print('Ready. Owner key saved privately to .private/owner.key (not printed).')
        print('Next on Mac: python3 scripts/configure-mac.py')
        return config
    except (ValueError, RuntimeError, OSError) as e:
        parser.exit(1, f'Error: {e}\n')
    finally:
        connections.close()


if __name__ == '__main__':
    main()
