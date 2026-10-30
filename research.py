"""Download only protocol references from the installed Orca release (not a checkout)."""
import concurrent.futures
import json
import pathlib
import urllib.request

BASE = 'https://raw.githubusercontent.com/stablyai/orca/v1.4.245/'
ROOT = pathlib.Path(__file__).parent / '.research'
tree = json.load(urllib.request.urlopen('https://api.github.com/repos/stablyai/orca/git/trees/v1.4.245?recursive=1'))
paths = []
for item in tree['tree']:
    p = item['path']
    if item['type'] != 'blob' or '.test.' in p:
        continue
    if (p.startswith('src/main/runtime/mobile-cloud-relay/') or
        p.startswith('src/shared/orca-cloud') or
        p.startswith('src/shared/mobile-relay') or
        p.startswith('cloud/packages/protocol/') or
        p.startswith('cloud/packages/contracts/') or
        p.startswith('src/main/orca-profiles/profile-cloud-') or
        p in ['cloud/apps/relay/src/relay-server.ts', 'cloud/apps/relay/src/app.ts',
              'cloud/apps/relay/src/splice-forwarder.ts', 'cloud/apps/relay/src/relay-token-verifier.ts',
              'cloud/apps/relay/src/test-fixtures/host-control-proof.ts', 'LICENSE']):
        paths.append(p)
def get(p):
    out = ROOT / p
    if not out.exists():
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(urllib.request.urlopen(BASE + p, timeout=30).read())
    return p
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    result = list(pool.map(get, paths))
print(f'{len(result)} protocol reference files in {ROOT}')
print('\n'.join(p for p in result if p.startswith('cloud/packages/')))
