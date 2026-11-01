"""Minimal desired state. No passwords, owner keys or setup codes in configuration."""
import json
import os
import pathlib
import tempfile

import deploy


def resolve(data, previous=None):
    previous = previous or {}
    if not isinstance(data, dict):
        raise ValueError('Конфигурация должна быть JSON-объектом')
    if 'relay' in data:
        if set(data) != {'relay'}:
            raise ValueError('Для подключения к готовому Relay нужен только параметр relay')
        if not isinstance(data['relay'], str) or not data['relay']:
            raise ValueError('relay должен быть HTTPS-адресом')
        return {'kind': 'client', 'origin': deploy.resolve_origin({'origin': data['relay']})}
    allowed = {'server', 'origin', 'ssh_port', 'auth', 'configure_mac'}
    if set(data) - allowed:
        raise ValueError('Неизвестные параметры: ' + ', '.join(sorted(set(data) - allowed)) + '. Пароли и коды в конфиге не допускаются.')
    host = data.get('server')
    if not isinstance(host, str) or not host or host.count('@') > 1:
        raise ValueError('Укажите server: IP-адрес или user@IP')
    if '@' not in host:
        host = 'root@' + host
    port = data.get('ssh_port', 22)
    deploy.ssh_args({'ssh_host': host, 'ssh_port': port})
    auth = data.get('auth', 'auto')
    if auth not in ['auto', 'key', 'password']:
        raise ValueError('auth: auto, key или password')
    if auth == 'auto':
        auth = previous.get('ssh_auth', 'key') if previous.get('ssh_host') == host else 'password'
    if auth not in ['key', 'password']:
        raise ValueError('Invalid saved authentication method')
    mac = data.get('configure_mac', True)
    if not isinstance(mac, bool):
        raise ValueError('configure_mac должен быть true или false')
    if 'origin' in data and (not isinstance(data['origin'], str) or not data['origin']):
        raise ValueError('origin должен быть HTTPS-адресом')
    origin = deploy.resolve_origin({'ssh_host': host, 'origin': data.get('origin')})
    return {'kind': 'server', 'host': host, 'port': port, 'origin': origin, 'auth': auth, 'configure_mac': mac}


def load(root, path=None, interactive=False):
    root = pathlib.Path(root)
    previous_file = root / '.private/deploy.json'
    previous = json.loads(previous_file.read_text()) if previous_file.exists() else {}
    if not isinstance(previous, dict):
        raise ValueError('Invalid previous deployment configuration')
    if path is not None:
        source = pathlib.Path(path).expanduser().resolve()
        if not source.is_file():
            raise ValueError('Файл конфигурации не найден: ' + str(source))
    else:
        public = root / 'relay.json'
        source = public if public.exists() else root / '.private/desired.json'
    save = False
    if source.exists():
        data = json.loads(source.read_text())
    elif previous.get('ssh_host'):
        data = {'server': previous['ssh_host']}
        if previous.get('origin'):
            data['origin'] = previous['origin']
        if previous.get('ssh_port', 22) != 22:
            data['ssh_port'] = previous['ssh_port']
        save = interactive
    elif (root / '.private/client.json').exists():
        client = json.loads((root / '.private/client.json').read_text())
        if not isinstance(client, dict):
            raise ValueError('Invalid saved client configuration')
        data = {'relay': client.get('origin')}
        save = interactive
    elif interactive:
        data = {'server': input('Адрес VPS (IP или user@IP; пользователь по умолчанию root): ').strip()}
        save = True
    else:
        raise ValueError('Создайте relay.json с адресом server или запустите ./relay для первоначальной настройки')
    result = resolve(data, previous)
    if save:
        source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', dir=source.parent, delete=False) as handle:
            temporary = pathlib.Path(handle.name)
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, indent=2)
            handle.write('\n')
        os.replace(temporary, source)
    return result


def install_arguments(state):
    arguments = ['install', '--host', state['host'], '--origin', state['origin'], '--port', str(state['port']),
                 '--ask-pass' if state['auth'] == 'password' else '--key-auth']
    if not state['configure_mac']:
        arguments.append('--server-only')
    return arguments
