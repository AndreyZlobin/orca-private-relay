"""Install a Relay once, or connect another Mac without accessing the VPS over SSH."""
import argparse
import getpass
import json
import os
import pathlib
import platform
import plistlib
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import deploy

ROOT = pathlib.Path(__file__).resolve().parent.parent
VARIABLES = ['ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(origin, path, key=None):
    headers = {'Accept': 'application/json'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    request = urllib.request.Request(origin + path, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=8) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('Relay returned an oversized response')
        result = json.loads(data)
        if not isinstance(result, dict):
            raise ValueError('Relay returned an invalid response')
        return result
    except urllib.error.HTTPError as error:
        if error.code in [401, 403]:
            raise ValueError('Ключ подключения не принят этим Relay. Настройки Mac не изменены.') from None
        raise ValueError(f'Relay HTTP error {error.code}; настройки Mac не изменены') from None


def load_connection(profile=None, origin=None, root=ROOT, deployment=False):
    if profile is None and not deployment and (root / '.private/connection.json').exists():
        profile = root / '.private/connection.json'
    if profile:
        data = json.loads(pathlib.Path(profile).expanduser().read_text())
        if not isinstance(data, dict) or data.get('version') != 1 or set(data) != {'version', 'origin', 'owner_key'}:
            raise ValueError('Ожидался файл подключения, созданный командой ./relay export')
    else:
        config = root / '.private/deploy.json'
        data = json.loads(config.read_text()) if config.exists() else {}
        if not isinstance(data, dict):
            raise ValueError('Invalid local Relay configuration')
        key = root / '.private/owner.key'
        data = {'origin': data.get('origin'), 'owner_key': key.read_text().strip() if key.exists() else None}
    if origin and data.get('origin') and origin != data['origin']:
        # Never send an imported profile's secret to an overridden server.
        raise ValueError('Адрес отличается от файла подключения; экспортируйте профиль нужного Relay')
    address = origin or data.get('origin')
    if not address:
        raise ValueError('Укажите --origin https://relay.example.com или --profile /path/connection.json')
    address = deploy.resolve_origin({'origin': address})
    key = data.get('owner_key')
    if key is not None and (not isinstance(key, str) or not 32 <= len(key) <= 1024 or any(c in key for c in '\r\n\0')):
        raise ValueError('Invalid connection key')
    return address, key


def save_profile(path, origin, key):
    if not key:
        raise ValueError('Нет локального ключа. Экспортируйте профиль на компьютере, с которого устанавливали Relay.')
    path = pathlib.Path(path).expanduser()
    if path.is_symlink():
        raise ValueError('Refusing to overwrite a symlink')
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({'version': 1, 'origin': origin, 'owner_key': key}, indent=2) + '\n'
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as handle:
        temporary = pathlib.Path(handle.name)
        os.fchmod(handle.fileno(), 0o600)
        handle.write(payload)
    os.replace(temporary, path)
    return path


def health(origin):
    result = request_json(origin, '/healthz')
    if result.get('ok') is not True or result.get('service') != 'orca-private-relay':
        raise ValueError('По этому адресу нет совместимого Orca Private Relay')
    return result


def restart_orca():
    subprocess.run(['osascript', '-e', 'tell application id "com.stablyai.orca" to quit'], check=True, capture_output=True)
    for _ in range(30):
        state = subprocess.run(['osascript', '-e', 'application id "com.stablyai.orca" is running'],
                               check=True, capture_output=True, text=True)
        if state.stdout.strip() == 'false':
            subprocess.run(['open', '-a', 'Orca'], check=True)
            return
        time.sleep(0.5)
    raise ValueError('Orca ожидает завершения или диалога сохранения. Закройте её и откройте снова.')


def connect(profile=None, origin=None, restart=True):
    if platform.system() != 'Darwin':
        raise ValueError('Подключение этой командой пока поддерживается на macOS')
    if not pathlib.Path('/Applications/Orca.app').is_dir():
        raise ValueError('Сначала установите штатную Orca в /Applications/Orca.app')
    address, key = load_connection(profile, origin)
    print('Проверяю HTTPS и Relay:', address, flush=True)
    result = health(address)
    if not key:
        key = getpass.getpass('Ключ владельца Relay (ввод скрыт; SSH-пароль не нужен): ').strip()
        if not 32 <= len(key) <= 1024 or any(c in key for c in '\r\n\0'):
            raise ValueError('Invalid connection key')
    request_json(address, '/admin/status', key)
    print('Relay доступен, ключ принят. Настраиваю Mac...', flush=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/configure-mac.py'), '--origin', address], check=True)
    private = ROOT / '.private'
    private.mkdir(mode=0o700, exist_ok=True)
    private.chmod(0o700)
    save_profile(private / 'connection.json', address, key)
    if restart:
        restart_orca()
    # Clipboard is filled only after all checks; the key is never printed or put in argv.
    subprocess.run(['pbcopy'], input=key.encode(), check=True)
    print('Техническая настройка выполнена. Ключ подключения уже в буфере обмена.')
    print('В Orca: Orca Mobile → Orca Relay → Войти для Relay; вставьте ключ через Cmd+V.')
    print('Затем отсканируйте телефоном новый QR. Эти действия штатная Orca пока требует в интерфейсе.')
    print('SSH, root и повторная установка сервера для этого Mac не требуются.')
    if not restart:
        print('Перезапуск пропущен (--no-restart): полностью закройте и снова откройте Orca.')
    return result


def doctor(origin=None):
    address, _ = load_connection(origin=origin)
    result = health(address)
    print('Relay HTTPS: OK; protocol:', result.get('protocol', 'unknown'))
    if platform.system() != 'Darwin':
        return
    mismatch = []
    for name in VARIABLES:
        current = subprocess.run(['/bin/launchctl', 'getenv', name], capture_output=True, text=True, check=False)
        if current.stdout.strip() != address:
            mismatch.append(name)
    job = pathlib.Path.home() / 'Library/LaunchAgents/local.orca.private-relay-env.plist'
    if not job.exists():
        mismatch.append('LaunchAgent missing')
    else:
        plist = plistlib.loads(job.read_bytes())
        script = plist.get('ProgramArguments', [])
        if len(script) != 3 or any(f'/bin/launchctl setenv {name} {address}' not in script[-1].split('; ') for name in VARIABLES):
            mismatch.append('LaunchAgent settings differ')
    if mismatch:
        raise ValueError('Требуется ./relay connect: ' + ', '.join(mismatch))
    print('Mac launch environment and login-time configuration: OK')
    print('Вход Orca и сопряжение телефона этой проверкой не подтверждаются.')


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == 'install':
        result = deploy.main(argv[1:])
        if result is not None:
            key = (ROOT / '.private/owner.key').read_text().strip()
            path = save_profile(ROOT / '.private/connection.json', result['origin'], key)
            print('Файл для подключения других Mac:', path)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('install', help='Install/update the VPS and create a private connection file')
    client = commands.add_parser('connect', help='Configure another Mac; no VPS SSH connection')
    client.add_argument('--profile', type=pathlib.Path)
    client.add_argument('--origin')
    client.add_argument('--no-restart', action='store_true')
    export = commands.add_parser('export', help='Export a private connection file on the trusted setup Mac')
    export.add_argument('--output', type=pathlib.Path, default=ROOT / '.private/connection.json')
    check = commands.add_parser('doctor', help='Check Relay and Mac settings without SSH or changing them')
    check.add_argument('--origin')
    commands.add_parser('disconnect', help='Restore the previous Mac launch settings')
    args = parser.parse_args(argv)
    if args.command == 'connect':
        connect(args.profile, args.origin, not args.no_restart)
    elif args.command == 'export':
        origin, key = load_connection(deployment=True)
        print('Файл подключения:', save_profile(args.output, origin, key))
        print('Содержит ключ владельца. Передайте только на свой Mac; не добавляйте в Git.')
    elif args.command == 'doctor':
        doctor(args.origin)
    else:
        subprocess.run([sys.executable, str(ROOT / 'scripts/restore-mac.py')], check=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f'Ошибка: {error}') from None
