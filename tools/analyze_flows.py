#!/usr/bin/env python3
"""
Extract xhs signature headers and bodies from a mitmproxy flow file.
Focuses on authentication / signing headers that xhs uses.
"""
import sys, os, json
from mitmproxy import io, http
from mitmproxy.exceptions import FlowReadException

SIGNATURE_HEADERS = {
    'x-sign', 'x-s', 'x-s-common', 'x-t', 'x-mns', 'x-legacy-sign',
    'shield', 'x-xs', 'x-b3-traceid', 'authorization',
    'xy-common-params', 'xy-direction', 'x-b3-spanid',
    'shumei-id', 'x-trace-id', 'x-app-id', 'x-smd', 'x-cronet-ts',
}

def main(path):
    interesting = []
    all_sns = []
    with open(path, 'rb') as f:
        reader = io.FlowReader(f)
        try:
            for flow in reader.stream():
                if not isinstance(flow, http.HTTPFlow):
                    continue
                req = flow.request
                # xhs core API paths
                if '/api/sns/' not in req.path and '/api/im/' not in req.path:
                    continue
                all_sns.append(flow)
                # find signature headers
                sig = {k: v for k, v in req.headers.items() if k.lower() in SIGNATURE_HEADERS}
                if sig:
                    interesting.append((flow, sig))
        except FlowReadException as e:
            print(f'[!] flow read error: {e}', file=sys.stderr)

    print(f'[*] Total /api/sns or /api/im flows: {len(all_sns)}')
    print(f'[*] Flows with signature headers: {len(interesting)}')

    # show all unique header names across the sns flows (to discover custom ones)
    all_headers = set()
    for f in all_sns:
        for k in f.request.headers.keys():
            all_headers.add(k.lower())
    print(f'\n[*] All unique header names across sns/im flows:')
    custom = sorted(h for h in all_headers if h.startswith('x-') or 'shield' in h or 'sign' in h or 'trace' in h)
    for h in custom:
        print(f'    {h}')

    # show one representative flow in detail
    if all_sns:
        print(f'\n{"="*70}')
        print('[*] Sample flow (first homefeed or signed request):')
        # prefer homefeed if present
        sample = next((f for f in all_sns if 'homefeed' in f.request.path), all_sns[0])
        req = sample.request
        print(f'{req.method} {req.url}')
        print(f'Pretty path: {req.pretty_url}')
        print()
        print('--- Request headers ---')
        for k, v in req.headers.items():
            print(f'{k}: {v}')
        print()
        if req.content:
            body = req.content
            print('--- Request body (first 500 bytes) ---')
            try:
                print(body.decode('utf-8')[:500])
            except UnicodeDecodeError:
                print(repr(body[:500]))
        resp = sample.response
        if resp:
            print()
            print(f'--- Response: {resp.status_code} {resp.reason} ---')
            for k, v in list(resp.headers.items())[:10]:
                print(f'{k}: {v}')
            if resp.content:
                try:
                    preview = resp.content.decode('utf-8')[:300]
                except UnicodeDecodeError:
                    preview = repr(resp.content[:300])
                print(f'\nResponse body preview:\n{preview}')


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else sorted(
        [os.path.join('capture', f) for f in os.listdir('capture') if f.endswith('.mitm')],
        key=lambda p: os.path.getsize(p), reverse=True
    )[0]
    print(f'[*] Analyzing: {path}\n')
    main(path)
