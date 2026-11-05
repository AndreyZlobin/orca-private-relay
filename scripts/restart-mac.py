"""Gracefully reopen stock Orca with explicit Relay routing; preserve account and pairing data."""
import argparse
import platform
import subprocess
import time
import urllib.parse

VARIABLES = ['ORCA_RELAY_URL', 'ORCA_CLOUD_API_URL', 'ORCA_CLOUD_AUTH_URL', 'ORCA_PUSH_GATEWAY_URL']


def restart(origin):
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != 'https' or not parsed.hostname or origin != 'https://' + parsed.hostname:
        raise ValueError('Expected an HTTPS hostname without a path or credentials')
    # Confirm persistent configuration before interrupting the GUI. Never reset credentials.
    for name in VARIABLES:
        value = subprocess.run(['/bin/launchctl', 'getenv', name], capture_output=True, text=True, check=False)
        if value.returncode or value.stdout.strip() != origin:
            raise ValueError('Сначала настройте Relay через configure-mac.py --origin ' + origin)
    subprocess.run(['/usr/bin/osascript', '-e', 'tell application id "com.stablyai.orca" to quit'],
                   check=True, capture_output=True, timeout=45)
    for _ in range(60):
        state = subprocess.run(['/usr/bin/osascript', '-e', 'application id "com.stablyai.orca" is running'],
                               check=True, capture_output=True, text=True, timeout=8)
        if state.stdout.strip() == 'false':
            command = ['/usr/bin/open', '-a', 'Orca']
            for name in VARIABLES:
                command.extend(['--env', name + '=' + origin])
            # An old terminal or CLI may have stale inherited variables. LaunchServices
            # must receive these overrides explicitly, rather than inheriting its caller.
            subprocess.run(command, check=True, timeout=15)
            return
        time.sleep(0.5)
    raise ValueError('Orca не завершилась: проверьте диалог сохранения. Принудительное завершение не выполнялось.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('Run this command on the affected Mac')
    try:
        restart(args.origin)
    except (ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')
    print('Orca запущена с явным адресом Relay: ' + args.origin)
    print('Теперь проверьте доступ с телефона через мобильный интернет. Сопряжения и аккаунт не сбрасывались.')


if __name__ == '__main__':
    main()
