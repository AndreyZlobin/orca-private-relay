"""Configure the stock app's launch environment; no app files or helpers are installed."""
import pathlib
import plistlib
import subprocess
import argparse
import json
import os
import urllib.parse

root = pathlib.Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--origin', help='HTTPS origin of your private relay')
args = parser.parse_args()
config_path = root / '.private/deploy.json'
config = json.loads(config_path.read_text()) if config_path.exists() else {}
origin = args.origin or config.get('origin')
if not origin:
    parser.error('pass --origin https://relay.example.com or create .private/deploy.json')
parsed = urllib.parse.urlparse(origin)
if parsed.scheme != 'https' or not parsed.hostname or origin != 'https://' + parsed.hostname:
    parser.error('origin must be an HTTPS hostname without a path or trailing slash')
settings = {name: origin for name in [
    'ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL'
]}
private = root / '.private'
private.mkdir(mode=0o700, exist_ok=True)
baseline = private / 'mac-baseline.json'
if not baseline.exists():
    before = {}
    for name in settings:
        result = subprocess.run(['/bin/launchctl', 'getenv', name], capture_output=True, text=True)
        before[name] = result.stdout.strip() if result.returncode == 0 else None
    baseline.write_text(json.dumps(before, indent=2))
    os.chmod(baseline, 0o600)
# A login-time macOS configuration job sets environment variables and exits.
# It does not run a tunnel, connector, proxy or background service on the Mac.
path = pathlib.Path.home() / 'Library/LaunchAgents/local.orca.private-relay-env.plist'
path.parent.mkdir(parents=True, exist_ok=True)
payload = {
    'Label': 'local.orca.private-relay-env',
    'ProgramArguments': ['/bin/sh', '-c', '; '.join(
        '/bin/launchctl setenv ' + name + ' ' + value for name, value in settings.items()
    )],
    'RunAtLoad': True,
}
path.write_bytes(plistlib.dumps(payload))
path.chmod(0o600)
for name, value in settings.items():
    subprocess.run(['/bin/launchctl', 'setenv', name, value], check=True)
print('Configured stock Orca launch environment; restart Orca to apply.')
