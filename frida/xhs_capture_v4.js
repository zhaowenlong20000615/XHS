/*
 * xhs Request/Response full-capture v4
 *
 * v4 strategy: handle xhs's intentional NULL-deref tripwire via
 * Process.setExceptionHandler. The anti-debug thread deliberately reads
 * NULL->field_at_0x10d to test if a debugger intercepts SIGSEGV. We
 * install a Frida exception handler that:
 *   1. Detects the fault (access-violation at a tiny addr like 0x10d)
 *   2. Advances PC past the faulty instruction (2 bytes Thumb, 4 ARM)
 *   3. Returns true (handled) so the thread continues without crashing
 *
 * Combined with:
 *   - Signal filter for raise/tgkill SIGABRT (attach-only)
 *   - OkHttp Interceptor capture via Java bridge
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

log('=== xhs_capture_v4 boot pid=' + Process.id + ' arch=' + Process.arch);
log('Frida:', Frida.version, 'Runtime:', Script.runtime);
log('Java typeof:', typeof Java, 'available:', (typeof Java !== 'undefined' && Java.available));

// ------------------------------------------------------------------
// Layer 0: Exception handler - absorb NULL-deref tripwires
// ------------------------------------------------------------------
var segvCount = 0;
Process.setExceptionHandler(function (details) {
    if (details.type !== 'access-violation') return false;

    var faultAddr;
    try { faultAddr = details.memory.address; } catch (e) { return false; }
    if (!faultAddr) return false;

    var addrInt = faultAddr.toInt32();
    // Only absorb small addresses (NULL deref tripwires). Don't eat
    // real crashes at legitimate mapped addresses.
    if (addrInt < 0 || addrInt > 0x10000) return false;

    segvCount++;
    var pc = details.context.pc;
    var pcInt = pc.toInt32();

    // Check Thumb mode via CPSR T-bit (bit 5)
    var cpsr = 0;
    try { cpsr = details.context.cpsr; } catch (e) {}
    if (typeof cpsr === 'object' && cpsr !== null && cpsr.toInt32) {
        cpsr = cpsr.toInt32();
    }
    var isThumb = (cpsr & 0x20) !== 0;

    // Determine instruction length by reading first halfword (Thumb) or
    // assuming 4 bytes (ARM)
    var advance = 4;
    if (isThumb) {
        try {
            var hw1 = pc.readU16();
            // Thumb-32 prefix: first 5 bits in {0b11101, 0b11110, 0b11111}
            var prefix5 = (hw1 >> 11) & 0x1f;
            var isThumb32 = prefix5 >= 0x1d;
            advance = isThumb32 ? 4 : 2;
        } catch (e) { advance = 2; }
    }

    details.context.pc = ptr(pcInt + advance);

    if (segvCount <= 20) {
        log('[segv] #' + segvCount + ' fault=' + faultAddr + ' pc=' + pc
            + ' cpsr=0x' + cpsr.toString(16) + ' thumb=' + isThumb
            + ' advance=' + advance);
    }
    return true;
});
log('[segv] exception handler installed');

// ------------------------------------------------------------------
// Layer 1: SIGABRT arg-rewrite (attach-only, no Thumb issues)
// ------------------------------------------------------------------
function installSignalFilter() {
    var libc = Process.getModuleByName('libc.so');

    var targets = [
        { name: 'raise', sigArg: 0, sig: 1 },   // raise(sig), arg 0 is sig
        { name: 'tgkill', sigArg: 2, sig: 3 },  // tgkill(tgid, tid, sig), arg 2
        { name: 'pthread_kill', sigArg: 1, sig: 2 },  // pthread_kill(thread, sig), arg 1
    ];

    targets.forEach(function (t) {
        try {
            var addr = libc.findExportByName(t.name);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    var sig = args[t.sigArg].toInt32();
                    if (sig === SIGABRT) {
                        log('[sig] ' + t.name + '(SIGABRT) -> sig=0');
                        args[t.sigArg] = ptr(0);
                    }
                },
            });
            log('[sig] attached ' + t.name);
        } catch (e) { log('[sig] ' + t.name + ' failed: ' + e); }
    });
}

// ------------------------------------------------------------------
// Layer 2: OkHttp Interceptor hook via Java
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
        } catch (e) { log('[java] hook failed: ' + e); }
    });
    if (ok) okHookInstalled = true;
    return ok;
}

// ------------------------------------------------------------------
// Run
// ------------------------------------------------------------------
try { installSignalFilter(); } catch (e) { log('[main] sig: ' + e); }

[100, 500, 1500, 3000, 6000, 10000, 20000].forEach(function (delay) {
    setTimeout(function () {
        try { installOkHttpCapture(); } catch (e) {}
    }, delay);
});

log('[boot] ready');
