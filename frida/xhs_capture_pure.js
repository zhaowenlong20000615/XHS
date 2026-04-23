/*
 * xhs pure OkHttp capture — designed for use with frida-server against
 * ORIGINAL xhs.apk (not re-signed). Since the APK signature matches what
 * libxyass expects (Arrays.hashCode(XINGIN.RSA) = 0x4cdc059d), libxyass's
 * integrity check passes naturally and no signature spoof is needed.
 *
 * Layer strategy:
 *   1. Java hook on okhttp3.internal.http.RealInterceptorChain.proceed
 *      — captures every Request/Response pair (URL, headers, body)
 *   2. Writes to /data/data/com.xingin.xhs/files/xhs_capture.log
 *      (xhs owns this file, writes from frida-attached context succeed)
 *
 * Usage with frida-server 17.8.2 on port 47042:
 *   frida -H 127.0.0.1:47042 -f com.xingin.xhs -l xhs_capture_pure.js
 */

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
    // Also send to Frida console for live monitoring
    send(line);
}

log('=== xhs_capture_pure boot pid=' + Process.id + ' arch=' + Process.arch);

if (!Java.available) {
    log('[FATAL] Java bridge not available');
} else {
    Java.perform(function () {
        log('[java] Java.perform active');

        try {
            var RIC = Java.use('okhttp3.internal.http.RealInterceptorChain');
            var Buffer = Java.use('okio.Buffer');

            RIC.proceed.overload('okhttp3.Request').implementation = function (request) {
                // ---- capture REQUEST ----
                var reqLog = [];
                try {
                    var url = request.url().toString();
                    var method = request.method();
                    reqLog.push('[REQ] ' + method + ' ' + url);

                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        reqLog.push('  > ' + headers.name(i) + ': ' + headers.value(i));
                    }

                    var body = request.body();
                    if (body !== null) {
                        try {
                            var buf = Buffer.$new();
                            body.writeTo(buf);
                            var bodyStr = buf.readUtf8();
                            if (bodyStr.length > 4000) bodyStr = bodyStr.substring(0, 4000) + '...[trunc]';
                            reqLog.push('  > BODY: ' + bodyStr);
                        } catch (be) {
                            reqLog.push('  > [body unreadable: ' + be + ']');
                        }
                    }
                } catch (e) { reqLog.push('[REQ parse err: ' + e + ']'); }

                reqLog.forEach(function (l) { log(l); });

                // ---- run original proceed ----
                var response;
                try {
                    response = this.proceed(request);
                } catch (e) {
                    log('[ERR] proceed threw: ' + e);
                    throw e;
                }

                // ---- capture RESPONSE ----
                var respLog = [];
                try {
                    respLog.push('[RESP] ' + response.code() + ' ' + response.request().url().toString());
                    var rh = response.headers();
                    for (var j = 0; j < rh.size(); j++) {
                        respLog.push('  < ' + rh.name(j) + ': ' + rh.value(j));
                    }
                    // peekBody makes a copy of up to N bytes without consuming the source
                    var peek = response.peekBody(32768);
                    var rBody = peek.string();
                    if (rBody.length > 8000) rBody = rBody.substring(0, 8000) + '...[trunc]';
                    respLog.push('  < BODY: ' + rBody);
                } catch (e) { respLog.push('[RESP parse err: ' + e + ']'); }

                respLog.forEach(function (l) { log(l); });

                return response;
            };

            log('[java] hooked okhttp3.internal.http.RealInterceptorChain.proceed');
        } catch (e) {
            log('[java] RIC hook failed: ' + e);
            log('  trying fallback: RealCall.execute');
            try {
                var RC = Java.use('okhttp3.RealCall');
                // backup hook point
                log('[java] RealCall found');
            } catch (e2) { log('[java] fallback failed: ' + e2); }
        }

        log('[java] ready — waiting for xhs to make HTTP requests');
    });
}
