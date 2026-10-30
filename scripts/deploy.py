"""Build on your VPS in a disposable container and install the native service."""
import argparse
import json
import pathlib
import shlex
import subprocess
import tarfile
import urllib.parse

root = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--host', help='SSH destination, e.g. deploy@203.0.113.10')
parser.add_argument('--origin', help='HTTPS origin, e.g. https://relay.example.com')
args = parser.parse_args()
config_path = root / '.private/deploy.json'
config = json.loads(config_path.read_text()) if config_path.exists() else {}
host = args.host or config.get('ssh_host')
origin = args.origin or config.get('origin')
if not host or not origin:
    parser.error('set --host and --origin, or create .private/deploy.json')
if host.startswith('-') or any(c.isspace() for c in host):
    parser.error('invalid SSH destination')
url = urllib.parse.urlparse(origin)
if url.scheme != 'https' or not url.hostname or origin != 'https://' + url.hostname:
    parser.error('origin must be an HTTPS hostname without a path or trailing slash')

image = 'rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3'
command = (
    'sudo -n install -d -m 755 /opt/orca-private-relay && '
    'sudo -n tar -xzf - -C /opt/orca-private-relay && '
    'sudo -n docker run --rm --name orca-relay-build --cpus=0.75 '
    '--memory=1100m --memory-swap=1300m -e CARGO_BUILD_JOBS=1 '
    '-e CARGO_HOME=/build/.cargo-cache -v /opt/orca-private-relay:/build '
    '-w /build ' + shlex.quote(image) + ' cargo build --release --locked && '
    'sudo -n env RELAY_DEPLOY_ORIGIN=' + shlex.quote(origin) +
    ' sh /opt/orca-private-relay/deploy/install.sh'
)
process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host, command], stdin=subprocess.PIPE)
assert process.stdin is not None
try:
    with tarfile.open(fileobj=process.stdin, mode='w|gz') as archive:
        for name in ['Cargo.toml', 'Cargo.lock', 'src', 'deploy', 'THIRD_PARTY_NOTICES.md', 'LICENSE', 'README.md']:
            archive.add(root / name, arcname=name, filter=lambda info: None if '__pycache__' in info.name else info)
finally:
    process.stdin.close()
code = process.wait()
if code:
    raise SystemExit(code)
