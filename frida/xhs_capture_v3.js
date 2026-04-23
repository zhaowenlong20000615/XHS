/*
 * xhs Request/Response full-capture v3
 *
 * v3 key change: use Interceptor.attach + onEnter arg rewrite instead of
 * Interceptor.replace for libc signal functions. On ARM32 .replace has
 * Thumb bit handling issues with high-frequency libc symbols like
 * raise/tgkill/pthread_kill (called dozens of times during pthread init).
 *
 * Strategy: when sig === SIGABRT (6), rewrite args to sig=0 (POSIX null
 * signal). The original function runs normally but with harmless args.
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

log('=== xhs_capture_v3 boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java, 'available:', (typeof Java !== 'undefined' && Java.available));

// ------------------------------------------------------------------
// Layer 1: Arg-rewrite signal filter (attach-only, NO replace)
// ------------------------------------------------------------------
function installSignalFilter() {
    var libc = Process.getModuleByName('libc.so');

    // raise(int sig) — arg0 is the sig
    try {
        var raiseAddr = libc.findExportByName('raise');
        if (raiseAddr) {
            Interceptor.attach(raiseAddr, {
                onEnter: function (args) {
                    var sig = args[0].toInt32();
                    if (sig === SIGABRT) {
                        log('[sig] neutralized raise(SIGABRT) -> raise(0)');
                        args[0] = ptr(0);
                    }
                },
            });
            log('[sig] attached raise()');
        }
    } catch (e) { log('[sig] raise failed: ' + e); }

    // tgkill(int tgid, int tid, int sig) — arg2 is the sig
    try {
        var tgkillAddr = libc.findExportByName('tgkill');
        if (tgkillAddr) {
            Interceptor.attach(tgkillAddr, {
                onEnter: function (args) {
                    var sig = args[2].toInt32();
                    if (sig === SIGABRT) {
                        log('[sig] neutralized tgkill(tgid=' + args[0].toInt32()
                            + ', tid=' + args[1].toInt32() + ', SIGABRT) -> sig=0');
                        args[2] = ptr(0);
                    }
                },
            });
            log('[sig] attached tgkill()');
        }
    } catch (e) { log('[sig] tgkill failed: ' + e); }

    // pthread_kill(pthread_t, int sig) — arg1 is the sig
    try {
        var pkAddr = libc.findExportByName('pthread_kill');
        if (pkAddr) {
            Interceptor.attach(pkAddr, {
                onEnter: function (args) {
                    var sig = args[1].toInt32();
                    if (sig === SIGABRT) {
                        log('[sig] neutralized pthread_kill(SIGABRT) -> sig=0');
                        args[1] = ptr(0);
                    }
                },
            });
            log('[sig] attached pthread_kill()');
        }
    } catch (e) { log('[sig] pthread_kill failed: ' + e); }

    // For abort() we can't rewrite args (takes none). But abort is almost
    // never called directly — the usual anti-debug path is raise(SIGABRT).
    // Only hook abort if we see it being called. Leave it alone for now
    // to avoid ARM32 Thumb issues with Interceptor.replace.

    // syscall() wrapper used with __NR_tgkill (131 on ARM)
    try {
        var syscallAddr = libc.findExportByName('syscall');
        if (syscallAddr) {
            Interceptor.attach(syscallAddr, {
                onEnter: function (args) {
                    var nr = args[0].toInt32();
                    // __NR_tgkill is 270 on ARM, __NR_kill is 37, __NR_rt_sigqueueinfo is 178
                    if (nr === 270 || nr === 131) {  // tgkill variants
                        var sig = args[3].toInt32();
                        if (sig === SIGABRT) {
                            log('[sig] neutralized syscall(tgkill, ..., SIGABRT)');
                            args[3] = ptr(0);
                        }
                    }
                },
            });
            log('[sig] attached syscall() for tgkill/kill');
        }
    } catch (e) { log('[sig] syscall failed: ' + e); }
}

// ------------------------------------------------------------------
// Layer 2: OkHttp Interceptor hook via Java
// ------------------------------------------------------------------
var okHookInstalled = false;

function installOkHttpCapture() {
    if (okHookInstalled) return true;
    if (typeof Java === 'undefined' || !Java.available) {
        return false;
    }

    var ok = false;
    Java.perform(function () {
        try {
            var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
            var Buffer = Java.use('okio.Buffer');

            RIC.proceed.overload('okhttp3.Request').implementation = function (request) {
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

                var response;
                try {
                    response = this.proceed(request);
                } catch (e) {
                    log('[ERR] proceed threw: ' + e);
                    throw e;
                }

                try {
                    log('[RESP] ' + response.code() + ' ' + response.request().url().toString());
                    var rh = response.headers();
                    for (var j = 0; j < rh.size(); j++) {
                        log('  < ' + rh.name(j) + ': ' + rh.value(j));
                    }
                    var peek = response.peekBody(16384);
                    var rBody = peek.string();
                    if (rBody.length > 3000) rBody = rBody.substring(0, 3000) + '...[trunc]';
                    log('  < BODY: ' + rBody);
                } catch (e) { log('[RESP parse err] ' + e); }

                return response;
            };

            log('[java] hooked RealInterceptorChain.proceed');
            ok = true;
        } catch (e) {
            log('[java] hook failed: ' + e);
        }
    });
    if (ok) okHookInstalled = true;
    return ok;
}

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------
try { installSignalFilter(); } catch (e) { log('[main] sig: ' + e); }

// Retry OkHttp hook - classes load lazily
[100, 500, 1500, 3000, 6000, 10000, 20000].forEach(function (delay) {
    setTimeout(function () {
        try { installOkHttpCapture(); } catch (e) {}
    }, delay);
});

log('[boot] ready');
