/*
 * xhs signing dumper
 *
 * Hooks the Tiny SDK signing entry point to capture every signed request:
 *   ega.f.j(method, url, body) → Map<String,String> of signed headers
 *
 * Also hooks r76.a.intercept to see the final applied header set and
 * the x-legacy-* values, so you get the complete picture.
 *
 * Usage:
 *   python3 inject.py   (with XHS_SCRIPT=dump_signing.js)
 */

'use strict';

function hexShort(bytes) {
    if (!bytes || bytes.length === 0) return '(empty)';
    const bs = new Uint8Array(bytes);
    let s = '';
    for (let i = 0; i < Math.min(bs.length, 32); i++) {
        s += ('0' + bs[i].toString(16)).slice(-2);
    }
    if (bs.length > 32) s += '...';
    return s;
}

function tryUtf8(bytes) {
    if (!bytes || bytes.length === 0) return '(empty)';
    try {
        // Use Java's String constructor to decode reliably
        const String = Java.use('java.lang.String');
        return String.$new(bytes, 'UTF-8').toString();
    } catch (e) {
        return '(non-utf8) ' + hexShort(bytes);
    }
}

Java.perform(function () {
    console.log('[dump_signing] attached to pid ' + Process.id);
    console.log('[dump_signing] android version: ' + Java.androidVersion);

    // --- Hook #1: ega.f.j(method, url, body) — the Tiny signing bridge ---
    try {
        const EgaF = Java.use('ega.f');
        // Overload: (String, String, byte[])
        EgaF.j.overload('java.lang.String', 'java.lang.String', '[B').implementation = function (method, url, body) {
            console.log('\n======== ega.f.j CALLED ========');
            console.log('  method: ' + method);
            console.log('  url:    ' + url);
            console.log('  body:   ' + (body ? body.length + ' bytes' : 'null'));
            if (body && body.length > 0 && body.length < 4096) {
                console.log('  body utf8: ' + tryUtf8(body));
            }

            const result = this.j(method, url, body);

            console.log('---- signed headers returned ----');
            if (result === null) {
                console.log('  (null)');
            } else {
                const it = result.entrySet().iterator();
                while (it.hasNext()) {
                    const entry = it.next();
                    const k = entry.getKey().toString();
                    const v = entry.getValue() ? entry.getValue().toString() : 'null';
                    // Truncate huge values
                    const vDisplay = v.length > 200 ? v.substring(0, 200) + '... [' + v.length + 'B]' : v;
                    console.log('  ' + k + ': ' + vDisplay);
                }
            }
            console.log('================================\n');
            return result;
        };
        console.log('[dump_signing] hooked ega.f.j');
    } catch (e) {
        console.log('[dump_signing] ega.f.j hook failed: ' + e);
    }

    // --- Hook #2: r76.a.intercept — the Tiny OkHttp interceptor ---
    try {
        const R76A = Java.use('r76.a');
        R76A.intercept.implementation = function (chain) {
            const req = chain.request();
            console.log('\n======== r76.a (TinyInterceptor) ========');
            console.log('  request: ' + req.method() + ' ' + req.url().toString().substring(0, 120));

            const response = this.intercept(chain);

            // Log all headers of the *final* request that was proceeded
            // (we cannot easily capture the modified builder; but the request
            // we see here is the original. To see the final modified one we
            // need to hook chain.proceed().)
            return response;
        };
        console.log('[dump_signing] hooked r76.a.intercept');
    } catch (e) {
        console.log('[dump_signing] r76.a.intercept hook failed: ' + e);
    }

    // --- Hook #3: Request.Builder.header (best view of final headers) ---
    // Hooking this for ALL requests would be too noisy, so we tag via URL substring
    try {
        const Builder = Java.use('okhttp3.Request$Builder');
        const origHeader = Builder.header.overload('java.lang.String', 'java.lang.String');
        origHeader.implementation = function (name, value) {
            // Only log signing-related headers
            const ln = name.toLowerCase();
            if (ln.indexOf('mini') >= 0
                || ln.indexOf('shield') >= 0
                || ln.indexOf('xy-') >= 0
                || ln.indexOf('legacy') >= 0) {
                const vs = value ? value.toString() : 'null';
                const display = vs.length > 120 ? vs.substring(0, 120) + '...' : vs;
                console.log('  [header] ' + name + ': ' + display);
            }
            return origHeader.call(this, name, value);
        };
        console.log('[dump_signing] hooked Request.Builder.header');
    } catch (e) {
        console.log('[dump_signing] Builder.header hook failed: ' + e);
    }

    // --- Hook #4: w3.a(alias, data) — x-mini-mua RSA signer (optional) ---
    try {
        const W3 = Java.use('com.xingin.tiny.internal.w3');
        W3.a.overload('java.lang.String', 'java.lang.String').implementation = function (alias, data) {
            console.log('\n[w3.a RSA sign] alias=' + alias);
            console.log('[w3.a RSA sign] data=' + (data.length > 200 ? data.substring(0, 200) + '...' : data));
            const r = this.a(alias, data);
            console.log('[w3.a RSA sign] result=' + (r ? r.substring(0, 120) : 'null') + '...');
            return r;
        };
        console.log('[dump_signing] hooked w3.a (RSA)');
    } catch (e) {
        console.log('[dump_signing] w3.a hook failed: ' + e);
    }

    console.log('[dump_signing] ALL HOOKS INSTALLED. Triggering an xhs network call will now show signatures.');
});
