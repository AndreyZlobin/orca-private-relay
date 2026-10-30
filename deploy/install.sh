#!/bin/sh
# Run on the VPS as root, after the Linux release binary has been built.
set -eu
: "${RELAY_DEPLOY_ORIGIN:?Set RELAY_DEPLOY_ORIGIN=https://relay.example.com}"
export RELAY_DEPLOY_ORIGIN
RELAY_DOMAIN=$(python3 - <<'PY'
import os,re,urllib.parse
origin=os.environ['RELAY_DEPLOY_ORIGIN']
url=urllib.parse.urlparse(origin)
if not re.fullmatch(r'https://[a-z0-9][a-z0-9.-]*[a-z0-9]',origin) or origin != 'https://' + (url.hostname or ''):
    raise SystemExit('Expected canonical HTTPS domain without a port/path')
print(url.hostname)
PY
)
cd /opt/orca-private-relay
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 700 backups
cp /etc/caddy/Caddyfile "backups/Caddyfile.$STAMP"
if [ -f /usr/local/bin/orca-private-relay ]; then
  cp /usr/local/bin/orca-private-relay "backups/orca-private-relay.$STAMP"
fi
getent passwd orca-relay >/dev/null || useradd --system --home-dir /var/lib/orca-private-relay --shell /usr/sbin/nologin orca-relay
install -d -m 700 -o orca-relay -g orca-relay /var/lib/orca-private-relay
if [ ! -f /etc/orca-private-relay.env ]; then
  python3 - <<'PY'
import os,secrets
p='/etc/orca-private-relay.env'
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:
    f.write('RELAY_ORIGIN='+os.environ['RELAY_DEPLOY_ORIGIN']+'\nRELAY_LISTEN=127.0.0.1:6770\nRELAY_DATABASE=/var/lib/orca-private-relay/relay.sqlite\n')
    f.write('RELAY_OWNER_SECRET='+secrets.token_urlsafe(32)+'\n')
    f.write('RELAY_SIGNING_KEY='+secrets.token_urlsafe(48)+'\n')
PY
fi
python3 - <<'PY'
import os
with open('/etc/orca-private-relay.env') as f:
    values=dict(line.strip().split('=',1) for line in f if '=' in line)
if values.get('RELAY_ORIGIN') != os.environ['RELAY_DEPLOY_ORIGIN']:
    raise SystemExit('Existing origin differs: migrate domain and paired clients explicitly before redeploying')
PY
install -m 755 target/release/orca-private-relay /usr/local/bin/orca-private-relay.next
mv /usr/local/bin/orca-private-relay.next /usr/local/bin/orca-private-relay
install -m 644 deploy/orca-private-relay.service /etc/systemd/system/orca-private-relay.service
systemctl daemon-reload
systemctl enable --now orca-private-relay
systemctl restart orca-private-relay
sleep 1
curl --fail --silent http://127.0.0.1:6770/healthz
install -d -m 755 /etc/caddy/conf.d
{ printf '%s {\n' "$RELAY_DOMAIN"; cat <<'CADDY'
    header {
        Cache-Control "no-store"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
    }
    reverse_proxy 127.0.0.1:6770
}
CADDY
} > /etc/caddy/conf.d/orca-private-relay.caddy
if ! grep -q '^import /etc/caddy/conf.d/\*.caddy$' /etc/caddy/Caddyfile && ! grep -Fq "$RELAY_DOMAIN" /etc/caddy/Caddyfile; then
    printf '\nimport /etc/caddy/conf.d/*.caddy\n' >> /etc/caddy/Caddyfile
fi
if caddy validate --config /etc/caddy/Caddyfile; then
    systemctl reload caddy
else
    cp "backups/Caddyfile.$STAMP" /etc/caddy/Caddyfile
    exit 1
fi
printf '\nRelay installed; Caddy configuration backup: %s\n' "$STAMP"
