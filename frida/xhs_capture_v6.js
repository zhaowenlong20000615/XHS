/*
 * xhs Request/Response full-capture v6
 *
 * v6 fixes timing: installSignatureHook() called at top-level was async-queuing
 * Java.perform callback and blocking further synchronous execution. In v6 we
 * ONLY use the dlopen-watcher path to install the signature hook — that runs
 * on the main Java thread's stack (inside System.loadLibrary's dlopen call),
 * so Java.perform there executes SYNCHRONOUSLY and completes before
 * libxyass's JNI_OnLoad runs.
 *
 * Order of top-level operations (all synchronous, no Java.perform):
 *   1. Exception handler (safety net for NULL-deref tripwires)
 *   2. Signal filters (SIGABRT via raise/tgkill/pthread_kill/syscall)
 *   3. dlopen watcher (installs Signature hook when libxyass loads)
 *   4. OkHttp hook retry timers (Java.perform — queued, OK because async)
 */

var SIGABRT = 6;
var XHS_EXPECTED_SIGNATURE_HASH = 0x4cdc059d;

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

log('=== xhs_capture_v6 boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java, 'available:', (typeof Java !== 'undefined' && Java.available));

// ------------------------------------------------------------------
// Step 1: Exception handler (safety net)
// ------------------------------------------------------------------
var segvCount = 0;
Process.setExceptionHandler(function (details) {
    if (details.type !== 'access-violation') return false;
    var faultAddr;
    try { faultAddr = details.memory.address; } catch (e) { return false; }
    if (!faultAddr) return false;
    var addrInt = faultAddr.toInt32();
    if (addrInt < 0 || addrInt > 0x10000) return false;

    segvCount++;
    var pc = details.context.pc;
    var pcInt = pc.toInt32();
    var cpsr = 0;
    try { cpsr = details.context.cpsr; } catch (e) {}
    if (typeof cpsr === 'object' && cpsr !== null && cpsr.toInt32) cpsr = cpsr.toInt32();
    var isThumb = (cpsr & 0x20) !== 0;

    var advance = 4;
    if (isThumb) {
        try {
            var hw1 = pc.readU16();
            var prefix5 = (hw1 >> 11) & 0x1f;
            advance = prefix5 >= 0x1d ? 4 : 2;
        } catch (e) { advance = 2; }
    }

    details.context.pc = ptr(pcInt + advance);
    if (segvCount <= 20) {
        log('[segv] #' + segvCount + ' fault=' + faultAddr + ' pc=' + pc + ' advance=' + advance);
    }
    return true;
});
log('[step1] exception handler installed');

// ------------------------------------------------------------------
// Step 2: Signal filters (SIGABRT via all paths)
// ------------------------------------------------------------------
var libc = Process.getModuleByName('libc.so');
log('[step2] libc module: ' + libc);

['raise', 'tgkill', 'pthread_kill'].forEach(function (name) {
    try {
        var addr = libc.findExportByName(name);
        if (!addr) return;
        var sigArgIdx = name === 'raise' ? 0 : (name === 'tgkill' ? 2 : 1);
        Interceptor.attach(addr, {
            onEnter: function (args) {
                if (args[sigArgIdx].toInt32() === SIGABRT) {
                    log('[sig] ' + name + '(SIGABRT) -> 0');
                    args[sigArgIdx] = ptr(0);
                }
            },
        });
        log('[step2] hooked ' + name);
    } catch (e) { log('[step2] ' + name + ' failed: ' + e); }
});

// syscall() catches rt_sigqueueinfo / rt_tgsigqueueinfo / tgkill / kill paths
try {
    var syscallAddr = libc.findExportByName('syscall');
    if (syscallAddr) {
        Interceptor.attach(syscallAddr, {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                // ARM syscall numbers:
                // __NR_kill = 37, __NR_tgkill = 270, __NR_rt_sigqueueinfo = 178,
                // __NR_rt_tgsigqueueinfo = 363
                var sigIdx = -1;
                if (nr === 37) sigIdx = 2;                          // kill(pid, sig)
                else if (nr === 270 || nr === 363) sigIdx = 3;      // tgkill/tgsigqueueinfo
                else if (nr === 178) sigIdx = 2;                    // rt_sigqueueinfo(pid, sig, info)
                if (sigIdx < 0) return;
                if (args[sigIdx].toInt32() === SIGABRT) {
                    log('[sig] syscall(nr=' + nr + ') SIGABRT -> 0');
                    args[sigIdx] = ptr(0);
                }
            },
        });
        log('[step2] hooked syscall for sigqueue variants');
    }
} catch (e) { log('[step2] syscall hook failed: ' + e); }

// ------------------------------------------------------------------
// Step 3: dlopen watcher — install Signature hook when libxyass loads
// ------------------------------------------------------------------
function installSignatureHookSync() {
    // Must only be called from main Java thread stack (e.g., dlopen onLeave).
    try {
        Java.perform(function () {
            try {
                var Signature = Java.use('android.content.pm.Signature');
                Signature.hashCode.implementation = function () {
                    var orig = this.hashCode();
                    log('[sigspoof] Signature.hashCode() orig=0x' + (orig >>> 0).toString(16)
                        + ' -> 0x' + XHS_EXPECTED_SIGNATURE_HASH.toString(16));
                    return XHS_EXPECTED_SIGNATURE_HASH;
                };
                log('[sigspoof] Signature.hashCode spoof ACTIVE');
            } catch (je) {
                log('[sigspoof] Java.use failed: ' + je);
            }
        });
    } catch (e) {
        log('[sigspoof] Java.perform failed: ' + e);
    }
}

// Fast poll for libxyass.so loading. setInterval runs on agent thread.
// When module appears, install Signature hook via Java.perform (which may be
// sync or async — we keep polling installOkHttpCapture too).
var libxyassFound = false;
var libxyassPollCount = 0;
var libxyassPollTimer = setInterval(function () {
    libxyassPollCount++;
    if (!libxyassFound) {
        try {
            var mod = Process.findModuleByName('libxyass.so');
            if (mod) {
                libxyassFound = true;
                log('[poll] libxyass.so found at ' + mod.base + ' after ' + libxyassPollCount + ' polls ('
                    + (libxyassPollCount * 10) + 'ms)');
                installSignatureHookSync();
            }
        } catch (e) {}
    }
    if (libxyassPollCount >= 500) {
        clearInterval(libxyassPollTimer);
        log('[poll] gave up after 500 polls (5s)');
    }
}, 10);
log('[step3] libxyass poll timer started (10ms interval)');

// Skip top-level Java.perform — it blocks agent thread waiting for JVM init
// on first call. Rely on poll timer which runs later.

// ------------------------------------------------------------------
// Step 4: OkHttp RealInterceptorChain.proceed capture (async retry)
// ------------------------------------------------------------------
var okHookInstalled = false;
function installOkHttpCapture() {
    if (okHookInstalled) return true;
    if (typeof Java === 'undefined' || !Java.available) return false;
    var ok = false;
    try {
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
                            } catch (be) {}
                        }
                    } catch (e) {}

                    var response = this.proceed(request);

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
                    } catch (e) {}

                    return response;
                };
                log('[java] hooked RealInterceptorChain.proceed');
                ok = true;
            } catch (e) { log('[java] RIC hook failed: ' + e); }
        });
    } catch (e) { log('[java] perform failed: ' + e); }
    if (ok) okHookInstalled = true;
    return ok;
}

// Schedule async OkHttp retries (main thread will execute when idle)
[500, 1500, 3000, 6000, 10000, 20000].forEach(function (delay) {
    setTimeout(function () {
        try { installOkHttpCapture(); } catch (e) {}
    }, delay);
});

log('[step4] OkHttp retry timers scheduled');
log('[boot] READY');
