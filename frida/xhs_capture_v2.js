/*
 * xhs Request/Response full-capture v2
 *
 * Key change from v1:
 *   - DO NOT bypass libxyass JNI_OnLoad. That function registers the native
 *     methods for com.xingin.shield.http.Native, which xhs needs for its
 *     HTTP interceptor. Bypassing it causes UnsatisfiedLinkError and the
 *     app calls System.exit(0).
 *
 *   - INSTEAD: let JNI_OnLoad run fully, but intercept libc raise()/tgkill()
 *     and filter SIGABRT (signal 6). The anti-debug code inside xyass
 *     calls raise(SIGABRT) to self-terminate; we return 0 for that case
 *     while letting all other signals through (pthread_cond/kill/etc).
 *
 *   - Then hook okhttp3.internal.http.RealInterceptorChain.proceed to
 *     capture every Request/Response pair with full headers + body.
 */

var SIGABRT = 6;
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

log('=== xhs_capture_v2 boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java, 'available:', (typeof Java !== 'undefined' && Java.available));

// ------------------------------------------------------------------
// Layer 1: Selective signal blocking - only SIGABRT
// ------------------------------------------------------------------
// Strategy: Interceptor.replace with a NativeCallback that checks the
// signal argument. If sig === 6 (SIGABRT), return 0. Otherwise call the
// original function. This preserves pthread_kill/raise for normal use
// while blocking the anti-debug self-kill.
function installSignalFilter() {
    var libc = Process.getModuleByName('libc.so');

    // raise(int sig)
    try {
        var raiseAddr = libc.findExportByName('raise');
        if (raiseAddr) {
            var origRaise = new NativeFunction(raiseAddr, 'int', ['int']);
            Interceptor.replace(raiseAddr, new NativeCallback(function (sig) {
                if (sig === SIGABRT) {
                    log('[sig] BLOCKED raise(SIGABRT)');
                    return 0;
                }
                return origRaise(sig);
            }, 'int', ['int']));
            log('[sig] filter raise() for SIGABRT');
        }
    } catch (e) { log('[sig] raise hook failed: ' + e); }

    // tgkill(int tgid, int tid, int sig) - common on Android
    try {
        var tgkillAddr = libc.findExportByName('tgkill');
        if (tgkillAddr) {
            var origTgkill = new NativeFunction(tgkillAddr, 'int', ['int', 'int', 'int']);
            Interceptor.replace(tgkillAddr, new NativeCallback(function (tgid, tid, sig) {
                if (sig === SIGABRT) {
                    log('[sig] BLOCKED tgkill(tgid=' + tgid + ', tid=' + tid + ', SIGABRT)');
                    return 0;
                }
                return origTgkill(tgid, tid, sig);
            }, 'int', ['int', 'int', 'int']));
            log('[sig] filter tgkill() for SIGABRT');
        }
    } catch (e) { log('[sig] tgkill hook failed: ' + e); }

    // pthread_kill(pthread_t, sig) - may be used by some anti-debug
    try {
        var pkAddr = libc.findExportByName('pthread_kill');
        if (pkAddr) {
            var origPk = new NativeFunction(pkAddr, 'int', ['pointer', 'int']);
            Interceptor.replace(pkAddr, new NativeCallback(function (thread, sig) {
                if (sig === SIGABRT) {
                    log('[sig] BLOCKED pthread_kill(SIGABRT)');
                    return 0;
                }
                return origPk(thread, sig);
            }, 'int', ['pointer', 'int']));
            log('[sig] filter pthread_kill() for SIGABRT');
        }
    } catch (e) { log('[sig] pthread_kill hook failed: ' + e); }

    // abort() - absolute process termination
    try {
        var abortAddr = libc.findExportByName('abort');
        if (abortAddr) {
            Interceptor.replace(abortAddr, new NativeCallback(function () {
                log('[sig] BLOCKED libc.abort()');
                // return quietly; caller may already have unstable state
            }, 'void', []));
            log('[sig] filter abort()');
        }
    } catch (e) { log('[sig] abort hook failed: ' + e); }

    // _exit() and exit() - less common for anti-debug but possible
    ['_exit', 'exit'].forEach(function (name) {
        try {
            var addr = libc.findExportByName(name);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    log('[sig] observed libc.' + name + '(' + args[0].toInt32() + ')');
                    // Don't actually block these unless exit code is 0 from anti-debug path
                    // System.exit(0) from Java also lands here - we let it through for now
                    // but log so we can see it.
                },
            });
            log('[sig] watching ' + name + '()');
        } catch (e) {}
    });
}

// ------------------------------------------------------------------
// Layer 2: OkHttp Interceptor hook (Java)
// ------------------------------------------------------------------
function installOkHttpCapture() {
    if (typeof Java === 'undefined' || !Java.available) {
        log('[java] Java bridge NOT available');
        return false;
    }

    var installed = false;
    Java.perform(function () {
        try {
            var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
            var Buffer = Java.use('okio.Buffer');

            RIC.proceed.overload('okhttp3.Request').implementation = function (request) {
                // Capture request
                try {
                    var url = request.url().toString();
                    var method = request.method();
                    log('[REQ] ' + method + ' ' + url);
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        log('  > ' + headers.name(i) + ': ' + headers.value(i));
                    }
                    var body = request.body();
                    if (body !== null) {
                        try {
                            var buf = Buffer.$new();
                            body.writeTo(buf);
                            var bodyStr = buf.readUtf8();
                            if (bodyStr.length > 2000) bodyStr = bodyStr.substring(0, 2000) + '...[trunc]';
                            log('  > BODY: ' + bodyStr);
                        } catch (be) {
                            log('  > [body not readable: ' + be + ']');
                        }
                    }
                } catch (e) { log('[REQ parse err] ' + e); }

                // Call original proceed to get response
                var response;
                try {
                    response = this.proceed(request);
                } catch (e) {
                    log('[ERR] proceed threw: ' + e);
                    throw e;
                }

                // Capture response
                try {
                    log('[RESP] ' + response.code() + ' ' + response.request().url().toString());
                    var rh = response.headers();
                    for (var j = 0; j < rh.size(); j++) {
                        log('  < ' + rh.name(j) + ': ' + rh.value(j));
                    }
                    // peekBody copies up to N bytes without consuming the underlying source
                    var peek = response.peekBody(16384);
                    var rBody = peek.string();
                    if (rBody.length > 3000) rBody = rBody.substring(0, 3000) + '...[trunc]';
                    log('  < BODY: ' + rBody);
                } catch (e) { log('[RESP parse err] ' + e); }

                return response;
            };

            log('[java] hooked RealInterceptorChain.proceed — all HTTP flows will be captured');
            installed = true;
        } catch (e) {
            log('[java] hook failed: ' + e);
        }
    });
    return installed;
}

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------
try { installSignalFilter(); } catch (e) { log('[main] sig: ' + e); }

// Install OkHttp hook with retry - classes may not be loaded at boot
var okHookInstalled = false;
function tryInstallOkHttp() {
    if (okHookInstalled) return;
    try {
        if (installOkHttpCapture()) {
            okHookInstalled = true;
        }
    } catch (e) {
        log('[retry] ' + e);
    }
}

// Retry schedule: right away, after 1s, 3s, 6s, 10s, then every 5s up to 1 min
[0, 1000, 3000, 6000, 10000].forEach(function (delay) {
    setTimeout(tryInstallOkHttp, delay);
});
var retryCount = 0;
var retryTimer = setInterval(function () {
    retryCount++;
    if (okHookInstalled || retryCount > 12) {
        clearInterval(retryTimer);
        return;
    }
    tryInstallOkHttp();
}, 5000);

log('[boot] ready');
