/*
 * xhs Request/Response full-capture via OkHttp Interceptor hook.
 *
 * Philosophy: we don't bypass SSL pinning. Instead, xhs connects to the
 * real edith.rnote.com with the real certificate (pinning passes), and we
 * hook the OkHttp Interceptor chain which sits ABOVE the TLS layer. We
 * see the Request object (URL, headers, body) before encryption and the
 * Response object (code, headers, body) after decryption.
 *
 * This is the most elegant path for capturing all xhs business traffic.
 *
 * Prerequisites: Java.available === true.
 */

// Also keep libxyass JNI_OnLoad bypass from previous script (anti-debug).
var _logFile = null;
var _logPath = '/data/data/com.xingin.xhs/files/xhs_capture.log';
function log() {
    var args = Array.prototype.slice.call(arguments);
    var line = '[' + new Date().toISOString() + '] ' + args.join(' ');
    try {
        if (!_logFile) _logFile = new File(_logPath, 'a');
        _logFile.write(line + '\n');
        _logFile.flush();
    } catch (e) {}
}

log('=== xhs_capture_all.js boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java);
if (typeof Java !== 'undefined') {
    log('Java.available:', Java.available);
}

// ------------------------------------------------------------------
// Anti-debug: neutralize libxyass JNI_OnLoad (same as before)
// ------------------------------------------------------------------
function hookXyass() {
    var libc = Process.getModuleByName('libc.so');
    var dlopen_ext = libc.findExportByName('android_dlopen_ext');
    if (!dlopen_ext) return;
    Interceptor.attach(dlopen_ext, {
        onEnter: function (args) {
            try { this.path = args[0].readCString(); } catch (e) {}
        },
        onLeave: function (retval) {
            if (!this.path) return;
            if (this.path.indexOf('libxyass.so') !== -1) {
                try {
                    var mod = Process.getModuleByName('libxyass.so');
                    var exps = mod.enumerateExports();
                    var hit = exps.find(function (e) { return e.name === 'JNI_OnLoad'; });
                    if (hit) {
                        Interceptor.replace(hit.address, new NativeCallback(function () {
                            return 0x10006;
                        }, 'int', ['pointer', 'pointer']));
                        log('[xyass] JNI_OnLoad bypassed');
                    }
                } catch (e) {}
            }
        },
    });
    log('[xyass] watching dlopen');
}

try { hookXyass(); } catch (e) { log('[xyass] setup failed:', e); }

// ------------------------------------------------------------------
// OkHttp Interceptor hook via Java bridge
// ------------------------------------------------------------------
function installOkHttpHook() {
    if (typeof Java === 'undefined' || !Java.available) {
        log('[java] Java bridge NOT available - cannot install OkHttp hook');
        return;
    }

    Java.perform(function () {
        log('[java] inside Java.perform');

        // Hook okhttp3.Interceptor.Chain.proceed(Request) - this is where
        // every interceptor in the chain sees the final request before
        // it's sent, and the response after it comes back.
        //
        // Actually we hook okhttp3.RealCall.execute or .enqueue? No,
        // simpler: hook the Request/Response classes directly to read
        // fields, and use the Chain.proceed interception.

        // Try multiple OkHttp versions: okhttp3 (common) + internal shaded
        var candidates = [
            'okhttp3.internal.http.RealInterceptorChain',
            'okhttp3.internal.connection.RealCall',
            'okhttp3.RealCall',
        ];

        candidates.forEach(function (cls) {
            try {
                var C = Java.use(cls);
                log('[java] found class:', cls);
            } catch (e) {
                log('[java] not found:', cls);
            }
        });

        // Universal approach: hook okhttp3.OkHttpClient$Builder.addInterceptor
        // so we can see when xhs installs interceptors. But easier is to
        // directly hook Request/Response construction.

        // Best bet: hook okhttp3.Response constructor (or build()) to log
        // every response that returns from the network.
        try {
            var Response = Java.use('okhttp3.Response');
            log('[java] Response class:', Response.class.getName());
            // Enumerate methods to find good hook points
            var methods = Response.class.getDeclaredMethods();
            log('[java] Response has', methods.length, 'methods');
        } catch (e) {
            log('[java] okhttp3.Response not found:', e);
        }

        // Hook RealInterceptorChain.proceed(Request): invoked once per
        // interceptor; the LAST one in the chain goes to the network layer.
        try {
            var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
            RIC.proceed.overload('okhttp3.Request').implementation = function (request) {
                var url = request.url().toString();
                var method = request.method();
                log('[req] ' + method + ' ' + url);
                try {
                    var headers = request.headers();
                    var hSize = headers.size();
                    for (var i = 0; i < hSize; i++) {
                        log('  > ' + headers.name(i) + ': ' + headers.value(i));
                    }
                    var body = request.body();
                    if (body) {
                        var Buffer = Java.use('okio.Buffer');
                        var buf = Buffer.$new();
                        body.writeTo(buf);
                        var bodyStr = buf.readUtf8();
                        if (bodyStr.length > 500) bodyStr = bodyStr.substring(0, 500) + '...';
                        log('  > body: ' + bodyStr);
                    }
                } catch (e) {
                    log('  > [req parse err] ' + e);
                }

                var response = this.proceed(request);
                try {
                    log('[resp] ' + response.code() + ' ' + url);
                    var rHeaders = response.headers();
                    var rSize = rHeaders.size();
                    for (var j = 0; j < rSize; j++) {
                        log('  < ' + rHeaders.name(j) + ': ' + rHeaders.value(j));
                    }
                    // Clone body to read it without consuming
                    var peekBody = response.peekBody(8192);
                    var rBody = peekBody.string();
                    if (rBody.length > 800) rBody = rBody.substring(0, 800) + '...';
                    log('  < body: ' + rBody);
                } catch (e) {
                    log('  < [resp parse err] ' + e);
                }
                return response;
            };
            log('[java] hooked RealInterceptorChain.proceed');
        } catch (e) {
            log('[java] proceed hook failed: ' + e);
        }
    });
}

// Delay Java hook - OkHttp classes may not be loaded yet at gadget start.
setTimeout(function () {
    try { installOkHttpHook(); } catch (e) { log('[main] okhttp: ' + e); }
}, 3000);

// Also retry periodically in case classes load later
var retries = 0;
var retryTimer = setInterval(function () {
    retries++;
    try { installOkHttpHook(); } catch (e) {}
    if (retries >= 10) {
        clearInterval(retryTimer);
    }
}, 2000);

log('[boot] ready - waiting for OkHttp to load');
