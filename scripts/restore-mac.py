"""Restore launch settings saved before the private relay was configured."""
import json
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
before = json.loads((root / '.private/mac-baseline.json').read_text())
label = 'local.orca.private-relay-env'
subprocess.run(['/bin/launchctl', 'bootout', f'gui/{os.getuid()}/{label}'], capture_output=True)
for name in ['ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL']:
    value = before.get(name)
    command = ['setenv', name, value] if value else ['unsetenv', name]
    subprocess.run(['/bin/launchctl', *command], check=True)
(pathlib.Path.home() / f'Library/LaunchAgents/{label}.plist').unlink(missing_ok=True)
print('Original launch settings restored; restart Orca and select local network mode.')
