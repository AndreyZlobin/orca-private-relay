"""Read-only Mac/Relay connectivity report; output omits passwords and session tokens."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import platform
import plistlib
import re
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request

VARIABLES = ['ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL']


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
    return result.stdout.strip() if result.returncode == 0 else ''


def public_origin(value):
    if not value:
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ['http', 'https', 'ws', 'wss'] or not parsed.hostname:
            return '<invalid URL>'
        host = parsed.hostname
        if ':' in host:
            host = '[' + host + ']'
        return parsed.scheme + '://' + host + (':' + str(parsed.port) if parsed.port else '')
    except ValueError:
        return '<invalid URL>'


def process_routes(text):
    result = {}
    for name in VARIABLES:
        values = re.findall(r'(?:^|\s)' + re.escape(name) + r'=([^\s]+)', text)
        result[name] = public_origin(values[-1]) if values else None
    return result


def websocket_probe(origin, host_id):
    parsed = urllib.parse.urlsplit(origin)
    nonce = base64.b64encode(os.urandom(16)).decode()
    path = '/v1/connect/' + host_id
    context = ssl.create_default_context()
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname=parsed.hostname) as connection:
            request = (f'GET {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nUpgrade: websocket\r\n'
                       f'Connection: Upgrade\r\nSec-WebSocket-Key: {nonce}\r\nSec-WebSocket-Version: 13\r\n\r\n')
            connection.sendall(request.encode())
            response = b''
            while b'\r\n\r\n' not in response and len(response) < 16384:
                part = connection.recv(4096)
                if not part:
                    break
                response += part
            headers = response.decode(errors='replace').split('\r\n')
            expected = base64.b64encode(hashlib.sha1((nonce + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            accept = next((line.split(':', 1)[1].strip() for line in headers if line.lower().startswith('sec-websocket-accept:')), '')
            if headers[0].startswith('HTTP/1.1 101') and accept == expected:
                # Anonymous probe only: it does not authenticate a phone or replace a host.
                mask = os.urandom(4)
                payload = (1000).to_bytes(2, 'big')
                connection.sendall(bytes([0x88, 0x82]) + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))
                return 'OK (101 Switching Protocols)'
            return headers[0] or 'No HTTP response'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    origin = public_origin(args.origin)
    if not origin or origin != args.origin or not origin.startswith('https://'):
        parser.error('Expected an HTTPS origin without credentials, path or query')
    if platform.system() != 'Darwin':
        parser.error('Run this report on the affected Mac')
    report = {'expected_relay': origin}
    app = pathlib.Path('/Applications/Orca.app/Contents/Info.plist')
    if app.exists():
        report['orca_version'] = plistlib.loads(app.read_bytes()).get('CFBundleShortVersionString')
    pids = [pid for pid in run('/usr/bin/pgrep', '-u', str(os.getuid()), '-x', 'Orca').splitlines() if pid.isdigit()]
    report['orca_running'] = bool(pids)
    report['launch_environment'] = {name: public_origin(run('/bin/launchctl', 'getenv', name)) for name in VARIABLES}
    report['running_orca_environment'] = [process_routes(run('/bin/ps', 'eww', '-p', pid, '-o', 'command=')) for pid in pids]
    data = pathlib.Path.home() / 'Library/Application Support/Orca'
    host_id = 'connectivity-probe'
    identity = data / 'orca-e2ee-keypair.json'
    if identity.exists():
        public = json.loads(identity.read_text()).get('publicKeyB64', '')
        raw = base64.b64decode(public, validate=True)
        if len(raw) == 32:
            host_id = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')[:16]
            report['relay_host_id'] = host_id
    profiles = data / 'orca-profile-index.json'
    if profiles.exists():
        index = json.loads(profiles.read_text())
        profile = next((p for p in index.get('profiles', []) if p.get('id') == index.get('activeProfileId')), {})
        report['profile_linked_to_relay_account'] = bool(profile.get('cloud'))
    try:
        with urllib.request.urlopen(origin + '/healthz', timeout=8) as response:
            health = json.loads(response.read(16384))
        report['https_health'] = health.get('ok') is True and health.get('service') == 'orca-private-relay'
    except Exception as error:
        report['https_health'] = type(error).__name__ + ': ' + str(error)
    try:
        report['direct_websocket'] = websocket_probe(origin, host_id)
    except Exception as error:
        report['direct_websocket'] = type(error).__name__ + ': ' + str(error)
    report['proxy_configured'] = bool(urllib.request.getproxies())
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
