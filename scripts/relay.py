"""Install a Relay once, or connect another Mac without accessing the VPS over SSH."""
import argparse
import getpass
import json
import os
import pathlib
import platform
import plistlib
import re
import shlex
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

import deploy
import desired

ROOT = pathlib.Path(__file__).resolve().parent.parent
VARIABLES = ['ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(origin, path, key=None, data=None):
    headers = {'Accept': 'application/json'}
    if key:
        headers['Authorization'] = 'Bearer ' + key
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(origin + path, headers=headers, data=body)
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
            if path == '/v1/setup/check':
                raise ValueError('Код неверен, истёк или уже использован. Получите новый: ./relay code на установочном Mac.') from None
            raise ValueError('Ключ подключения не принят этим Relay. Настройки Mac не изменены.') from None
        if error.code == 404 and path in ['/v1/setup/check', '/admin/setup-codes']:
            raise ValueError('На сервере ещё старая версия без кодов подключения. Требуется обновление Relay через ./relay install.') from None
        raise ValueError(f'Relay HTTP error {error.code}; настройки Mac не изменены') from None


def load_connection(profile=None, origin=None, root=ROOT, deployment=False):
    client = root / '.private/client.json'
    if profile is None and not deployment and client.exists():
        saved = json.loads(client.read_text())
        if not isinstance(saved, dict) or not isinstance(saved.get('origin'), str):
            raise ValueError('Invalid local client configuration')
        return deploy.resolve_origin({'origin': origin or saved['origin']}), None
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


def print_setup_code(origin, key):
    if not key:
        raise ValueError('Получайте новый код на компьютере, с которого устанавливали Relay.')
    result = request_json(origin, '/admin/setup-codes', key, data={})
    code = result.get('code', '')
    if not isinstance(code, str) or not re.fullmatch(r'[A-HJ-NP-Z2-9]{4}(?:-[A-HJ-NP-Z2-9]{4}){2}', code) or result.get('origin') != origin:
        raise ValueError('Relay вернул некорректный код подключения')
    print('\nRelay готов:', origin)
    print('КОД ПОДКЛЮЧЕНИЯ:', code)
    print('Действует 10 минут, подходит для одного входа. Новый код: ./relay code')
    print('На подключаемом Mac выполните:')
    print('./relay connect ' + shlex.quote(origin) + ' --code ' + shlex.quote(code))
    return result


def restart_orca(origin):
    subprocess.run([sys.executable, str(ROOT / 'scripts/restart-mac.py'), '--origin', origin], check=True)


def mac_configured(origin):
    if not (pathlib.Path.home() / 'Library/LaunchAgents/local.orca.private-relay-env.plist').exists():
        return False
    for name in VARIABLES:
        current = subprocess.run(['/bin/launchctl', 'getenv', name], capture_output=True, text=True, check=False)
        if current.returncode or current.stdout.strip() != origin:
            return False
    return True


def connect(profile=None, origin=None, restart=True, code=None):
    if platform.system() != 'Darwin':
        raise ValueError('Подключение этой командой пока поддерживается на macOS')
    if not pathlib.Path('/Applications/Orca.app').is_dir():
        raise ValueError('Сначала установите штатную Orca в /Applications/Orca.app')
    if profile and code:
        raise ValueError('Используйте код подключения или файл профиля, а не оба одновременно')
    if origin and not profile:
        address, key = deploy.resolve_origin({'origin': origin}), None
    else:
        address, key = load_connection(profile, origin)
    print('Проверяю HTTPS и Relay:', address, flush=True)
    result = health(address)
    if code or not key:
        code = code or getpass.getpass('Код подключения, который выдал установщик: ').strip()
        result_code = request_json(address, '/v1/setup/check', data={'code': code})
        if result_code.get('ok') is not True or result_code.get('origin') != address:
            raise ValueError('Relay не подтвердил код подключения')
        credential = code
    else:
        if not 32 <= len(key) <= 1024 or any(c in key for c in '\r\n\0'):
            raise ValueError('Invalid connection key')
        request_json(address, '/admin/status', key)
        credential = key
    print('Relay доступен, данные подключения приняты. Настраиваю Mac...', flush=True)
    subprocess.run([sys.executable, str(ROOT / 'scripts/configure-mac.py'), '--origin', address], check=True)
    private = ROOT / '.private'
    private.mkdir(mode=0o700, exist_ok=True)
    private.chmod(0o700)
    if key:
        save_profile(private / 'connection.json', address, key)
    client = private / 'client.json'
    descriptor = os.open(client, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as handle:
        os.fchmod(handle.fileno(), 0o600)
        json.dump({'origin': address}, handle)
    if restart:
        restart_orca(address)
    # Clipboard is filled only after all checks; the key is never printed or put in argv.
    subprocess.run(['pbcopy'], input=credential.encode(), check=True)
    print('Техническая настройка выполнена. Данные для входа уже в буфере обмена.')
    print('В Orca: Orca Mobile → Orca Relay → Войти для Relay; вставьте код через Cmd+V.')
    print('Затем отсканируйте телефоном новый QR. Эти действия штатная Orca пока требует в интерфейсе.')
    print('SSH, root и повторная установка сервера для этого Mac не требуются.')
    if not restart:
        print('Перезапуск пропущен (--no-restart): полностью закройте и снова откройте Orca.')
    return result


def doctor(origin=None):
    address, _ = load_connection(origin=origin)
    result = health(address)
    print('Relay HTTPS: OK; protocol:', result.get('protocol', 'unknown'))
    print('Одноразовые коды:', 'доступны' if 'setup-codes-v1' in result.get('features', []) else 'нужно обновить сервер')
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
    if not argv:
        argv = ['apply']
    if argv and argv[0] == 'install':
        server_only = '--server-only' in argv
        arguments = [value for value in argv[1:] if value != '--server-only']
        if not arguments and not (ROOT / '.private/deploy.json').exists():
            address = input('IP-адрес VPS: ').strip()
            user = input('Пользователь VPS [root]: ').strip() or 'root'
            arguments = ['--host', user + '@' + address, '--ask-pass']
        result = deploy.main(arguments)
        if result is not None:
            key = (ROOT / '.private/owner.key').read_text().strip()
            issued = print_setup_code(result['origin'], key)
            if not server_only and platform.system() == 'Darwin' and pathlib.Path('/Applications/Orca.app').is_dir():
                if mac_configured(result['origin']):
                    print('Этот Mac уже настроен на Relay; повторный перезапуск не требуется.')
                else:
                    connect(origin=result['origin'], code=issued['code'])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, help_text in [('apply', 'Apply relay.json; ask only for required credentials'),
                            ('plan', 'Show resolved desired state without accessing the VPS')]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument('--config', type=pathlib.Path)
    server = commands.add_parser('install', help='Install/update the VPS, print a code and configure this Mac')
    server.add_argument('--server-only', action='store_true', help='Skip configuring this Mac')
    client = commands.add_parser('connect', help='Configure another Mac; no VPS SSH connection')
    client.add_argument('--profile', type=pathlib.Path)
    client.add_argument('--origin')
    client.add_argument('address', nargs='?', help='Relay HTTPS address printed by the installer')
    client.add_argument('--code', help='One-time connection code printed by the installer')
    client.add_argument('--no-restart', action='store_true')
    export = commands.add_parser('export', help='Export a private connection file on the trusted setup Mac')
    export.add_argument('--output', type=pathlib.Path, default=ROOT / '.private/connection.json')
    check = commands.add_parser('doctor', help='Check Relay and Mac settings without SSH or changing them')
    check.add_argument('--origin')
    commands.add_parser('disconnect', help='Restore the previous Mac launch settings')
    commands.add_parser('code', help='Print a fresh one-time connection code; no SSH connection')
    args = parser.parse_args(argv)
    if args.command in ['apply', 'plan']:
        state = desired.load(ROOT, args.config, interactive=args.command == 'apply')
        if args.command == 'plan':
            print(json.dumps(state, indent=2, ensure_ascii=False))
            print('Желаемое состояние; подключения к VPS и изменений нет.')
        elif state['kind'] == 'client':
            health(state['origin'])
            if platform.system() == 'Darwin' and mac_configured(state['origin']):
                print('Этот Mac уже настроен. Для нового входа используйте ./relay connect ' + state['origin'])
            else:
                connect(origin=state['origin'])
        else:
            main(desired.install_arguments(state))
    elif args.command == 'connect':
        if args.address and args.origin and args.address != args.origin:
            parser.error('Specify one Relay address')
        connect(args.profile, args.origin or args.address, not args.no_restart, args.code)
    elif args.command == 'code':
        origin, key = load_connection(deployment=True)
        print_setup_code(origin, key)
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
