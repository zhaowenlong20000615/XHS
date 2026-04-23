"""
mitmproxy addon to extract xhs signature headers from a flow file.

Usage:
    mitmdump -n -r capture.mitm -s tools/extract_signatures.py -q
"""
from mitmproxy import http

XHS_PATTERNS = ('/api/sns/', '/api/im/', '/api/capa/', '/api/push/', '/api/nike/')

SIG_HEADER_NAMES = {
    'x-sign', 'x-s', 'x-s-common', 'x-t', 'x-mns', 'x-legacy-sign',
    'shield', 'x-xs', 'x-xt',
    'xy-common-params', 'xy-direction', 'xy-platform-info',
    'shumei-id', 'x-trace-id', 'x-app-id', 'x-smd',
    'x-cronet-ts', 'authorization',
}

seen_urls = set()
sig_samples = []
all_headers_seen = set()


def request(flow: http.HTTPFlow):
    req = flow.request
    if not any(p in req.path for p in XHS_PATTERNS):
        return

    # track unique path (strip query)
    url_base = req.url.split('?')[0]
    seen_urls.add(url_base)

    # record every header name we've ever seen on xhs API flows
    for k in req.headers.keys():
        all_headers_seen.add(k.lower())

    # find signature-ish headers
    found_sigs = {}
    for k, v in req.headers.items():
        lk = k.lower()
        if lk in SIG_HEADER_NAMES or lk.startswith('x-') or 'shield' in lk or 'sign' in lk:
            found_sigs[k] = v

    if found_sigs and len(sig_samples) < 6:
        sig_samples.append({
            'url': req.url,
            'method': req.method,
            'headers': dict(req.headers),
            'body_preview': (req.content[:300].decode('utf-8', errors='replace') if req.content else None),
        })


def done():
    import json
    print('=' * 70)
    print(f'Total unique xhs API endpoints captured: {len(seen_urls)}')
    print()
    print('All unique header names on xhs API flows:')
    print('-' * 70)
    interesting = sorted(
        h for h in all_headers_seen
        if h.startswith('x-') or 'shield' in h or 'sign' in h or 'trace' in h or 'smd' in h or 'xy-' in h
    )
    for h in interesting:
        print(f'  {h}')
    print()
    print('=' * 70)
    print(f'Sample signed requests ({len(sig_samples)}):')
    print('=' * 70)
    for i, s in enumerate(sig_samples):
        print(f'\n--- Sample {i+1}: {s["method"]} {s["url"]}')
        for k, v in s['headers'].items():
            if len(v) > 200:
                v = v[:200] + f'... ({len(v)} bytes)'
            print(f'  {k}: {v}')
        if s['body_preview']:
            print(f'  [body] {s["body_preview"][:200]}')
