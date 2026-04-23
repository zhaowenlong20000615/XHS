"""List all unique xhs API endpoints from all capture files."""
from mitmproxy import http
import os

endpoints = {}  # url_base -> {methods, count, hosts}

def request(flow: http.HTTPFlow):
    req = flow.request
    # xhs 相关域名 + IP
    host_ok = any(h in req.host for h in ['xiaohongshu', 'rnote', 'xhscdn', 'rednotecdn']) \
           or req.host.startswith(('1.71.', '1.13.', '114.55.', '119.45.'))
    if not host_ok:
        return
    base = req.path.split('?')[0]
    key = f'{base}'
    if key not in endpoints:
        endpoints[key] = {'methods': set(), 'count': 0, 'hosts': set(), 'with_sig': 0}
    endpoints[key]['methods'].add(req.method)
    endpoints[key]['count'] += 1
    endpoints[key]['hosts'].add(req.host)
    if 'x-mini-sig' in req.headers:
        endpoints[key]['with_sig'] += 1

def done():
    api_endpoints = sorted([k for k in endpoints if k.startswith('/api/')])
    other_endpoints = sorted([k for k in endpoints if not k.startswith('/api/')])
    print(f'\n=== /api/ endpoints ({len(api_endpoints)}) ===')
    for path in api_endpoints:
        e = endpoints[path]
        methods = '/'.join(sorted(e['methods']))
        sig = f' [sig×{e["with_sig"]}]' if e['with_sig'] else ''
        print(f'  {methods:10} x{e["count"]:<3} {path}{sig}')
    if other_endpoints:
        print(f'\n=== other endpoints ({len(other_endpoints)}) ===')
        for path in other_endpoints[:20]:
            e = endpoints[path]
            methods = '/'.join(sorted(e['methods']))
            print(f'  {methods:10} x{e["count"]:<3} {path}')
    print(f'\nTotal unique paths: {len(endpoints)}')
