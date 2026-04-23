/*
 * xhs Request/Response full-capture v5
 *
 * Root cause fix: libxyass JNI_OnLoad reads signatures[0].hashCode() and
 * uses it as the XOR seed for in-place string decryption. Since we
 * installed a re-signed APK (xhs.manual.apk), the hash is wrong, the
 * decrypted strings are garbage, subsequent jmethodID lookups return
 * pointers into .dynstr instead of real methods, and CallObjectMethodV
 * dereferences NULL fields inside libart.
 *
 * Static RE (docs/09 line 188-191) established the expected value:
 *   Arrays.hashCode(XINGIN.RSA) = 0x4cdc059d (signed: +1289487773)
 *
 * Strategy:
 *   1. Hook android.content.pm.Signature.hashCode() → 0x4cdc059d (global spoof)
 *   2. Set it up BEFORE libxyass.so loads (gadget runs before Application.onCreate)
 *   3. Keep the signal/exception safety nets as fallbacks
 *   4. Hook okhttp3 RealInterceptorChain.proceed to capture all HTTP
 *   5. (Optional) Hook libart RegisterNatives to dump libxyass native method table
 *
 * Log goes to /data/data/com.xingin.xhs/files/xhs_capture.log
 */

var SIGABRT = 6;
var XHS_EXPECTED_SIGNATURE_HASH = 0x4cdc059d;  // +1289487773 (docs/09 line 191)

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

log('=== xhs_capture_v5 boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java, 'available:', (typeof Java !== 'undefined' && Java.available));
log('XHS_EXPECTED_SIGNATURE_HASH = 0x' + XHS_EXPECTED_SIGNATURE_HASH.toString(16));

// ------------------------------------------------------------------
// Layer 0: Exception handler safety net (with proper Thumb advance)
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

    if (segvCount <= 10) {
        log('[segv] #' + segvCount + ' fault=' + faultAddr + ' pc=' + pc
            + ' thumb=' + isThumb + ' advance=' + advance);
    }
    return true;
});
log('[segv] exception handler installed (safety net)');

// ------------------------------------------------------------------
// Layer 1: SIGABRT arg filter safety net
// ------------------------------------------------------------------
function installSignalFilter() {
    var libc = Process.getModuleByName('libc.so');
    var targets = [
        { name: 'raise', sigArg: 0 },
        { name: 'tgkill', sigArg: 2 },
        { name: 'pthread_kill', sigArg: 1 },
    ];
    targets.forEach(function (t) {
        try {
            var addr = libc.findExportByName(t.name);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    if (args[t.sigArg].toInt32() === SIGABRT) {
                        log('[sig] ' + t.name + '(SIGABRT) -> 0');
                        args[t.sigArg] = ptr(0);
                    }
                },
            });
            log('[sig] attached ' + t.name);
        } catch (e) { log('[sig] ' + t.name + ' failed: ' + e); }
    });
}
try { installSignalFilter(); } catch (e) { log('[sig] setup: ' + e); }

// ------------------------------------------------------------------
// Layer 2: THE FIX — spoof Signature.hashCode() globally
// ------------------------------------------------------------------
var sigHookInstalled = false;
function installSignatureHook() {
    if (sigHookInstalled) return true;
    if (typeof Java === 'undefined' || !Java.available) return false;

    var ok = false;
    Java.perform(function () {
        try {
            var Signature = Java.use('android.content.pm.Signature');
            Signature.hashCode.implementation = function () {
                var orig = this.hashCode();
                // Only spoof if looks like APK-check call (from libxyass).
                // Cheapest heuristic: always spoof. xhs process rarely
                // calls Signature.hashCode for anything else.
                log('[sigspoof] Signature.hashCode() orig=0x' + orig.toString(16)
                    + ' -> 0x' + XHS_EXPECTED_SIGNATURE_HASH.toString(16));
                return XHS_EXPECTED_SIGNATURE_HASH;
            };
            log('[sigspoof] hooked Signature.hashCode globally -> 0x'
                + XHS_EXPECTED_SIGNATURE_HASH.toString(16));
            ok = true;
        } catch (e) {
            log('[sigspoof] hook failed: ' + e);
        }
    });
    if (ok) sigHookInstalled = true;
    return ok;
}

// Install IMMEDIATELY (queued async)
try { installSignatureHook(); } catch (e) { log('[sigspoof] early: ' + e); }

// CRITICAL: Also hook dlopen to install synchronously on the main thread
// right before libxyass JNI_OnLoad runs.
try {
    log('[dlopen] attempting to install watcher...');
    var libc_for_dlopen = Process.getModuleByName('libc.so');
    log('[dlopen] libc module: ' + libc_for_dlopen);
    var dlopen_ext_addr = libc_for_dlopen.findExportByName('android_dlopen_ext');
    log('[dlopen] android_dlopen_ext addr: ' + dlopen_ext_addr);
    if (dlopen_ext_addr) {
        Interceptor.attach(dlopen_ext_addr, {
            onEnter: function (args) {
                try { this.path = args[0].readCString(); } catch (e) {}
            },
            onLeave: function (retval) {
                if (!this.path) return;
                if (this.path.indexOf('libxyass.so') !== -1) {
                    log('[dlopen] libxyass.so loaded — installing Signature spoof SYNC');
                    installSignatureHook();
                    installOkHttpCapture();
                }
            },
        });
        log('[dlopen] watcher INSTALLED on ' + dlopen_ext_addr);
    }
} catch (e) {
    log('[dlopen] install failed: ' + e + ' stack: ' + (e.stack || 'n/a'));
}

// Also add a syscall hook for rt_sigqueueinfo (SIGABRT via sigqueue bypasses raise/tgkill)
try {
    var libc_for_sc = Process.getModuleByName('libc.so');
    var syscall_addr = libc_for_sc.findExportByName('syscall');
    if (syscall_addr) {
        Interceptor.attach(syscall_addr, {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                // __NR_rt_sigqueueinfo = 178, __NR_rt_tgsigqueueinfo = 363 on ARM
                // __NR_tgkill = 270, __NR_kill = 37
                if (nr === 178 || nr === 363 || nr === 270 || nr === 37) {
                    // sig position varies:
                    // kill(pid, sig) -> nr 37, args: pid=1, sig=2
                    // tgkill(tgid, tid, sig) -> nr 270, args: tgid=1, tid=2, sig=3
                    // rt_sigqueueinfo(pid, sig, uinfo) -> nr 178, args: pid=1, sig=2, ui=3
                    // rt_tgsigqueueinfo(tgid, tid, sig, uinfo) -> nr 363, args: tgid=1, tid=2, sig=3
                    var sigIdx = (nr === 270 || nr === 363) ? 3 : 2;
                    if (args[sigIdx].toInt32() === SIGABRT) {
                        log('[sig] syscall(' + nr + ', ..., SIGABRT) -> 0');
                        args[sigIdx] = ptr(0);
                    }
                }
            },
        });
        log('[sig] attached syscall() for sigqueue variants');
    }
} catch (e) { log('[sig] syscall hook failed: ' + e); }

// ------------------------------------------------------------------
// Layer 3: OkHttp RealInterceptorChain.proceed capture
// ------------------------------------------------------------------
var okHookInstalled = false;
function installOkHttpCapture() {
    if (okHookInstalled) return true;
    if (typeof Java === 'undefined' || !Java.available) return false;

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
                        } catch (be) { log('  > [body err: ' + be + ']'); }
                    }
                } catch (e) { log('[REQ parse] ' + e); }

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
                } catch (e) { log('[RESP parse] ' + e); }

                return response;
            };

            log('[java] hooked RealInterceptorChain.proceed');
            ok = true;
        } catch (e) { log('[java] RIC hook failed: ' + e); }
    });
    if (ok) okHookInstalled = true;
    return ok;
}

// OkHttp classes may load later than Signature; retry
[100, 500, 1500, 3000, 6000, 10000, 20000].forEach(function (delay) {
    setTimeout(function () {
        try {
            installSignatureHook();  // re-try in case Java wasn't ready at script boot
            installOkHttpCapture();
        } catch (e) {}
    }, delay);
});

log('[boot] ready');
