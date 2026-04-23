/*
 * xhs anti-debug bypass via libxyass.so JNI_OnLoad neutralization.
 *
 * libxyass.so is xhs's anti-debug entry point. It's loaded ~5s into App
 * startup and its JNI_OnLoad calls a raise(SIGABRT) trigger that crashes
 * the process. Since it's the only exported symbol, nuke it.
 *
 * Strategy:
 *   1. Hook android_dlopen_ext / dlopen to watch for libxyass.so load
 *   2. The moment it loads, Interceptor.replace JNI_OnLoad to return JNI_VERSION_1_6
 *   3. JVM calls the replaced stub → xyass init runs zero code → no raise(SIGABRT)
 *
 * Also does minimal SSL bypass via Interceptor.attach (no .replace of code
 * segments to avoid GWP-ASan page-fault tripwires).
 */

// File-based logging: gadget stdout doesn't reach logcat in script mode.
// Write to xhs own files dir (we run as untrusted_app in xhs process).
var _logFile = null;
var _logPath = '/data/data/com.xingin.xhs/files/xhs_bypass.log';
function logToFile() {
    var args = Array.prototype.slice.call(arguments);
    var line = args.join(' ');
    try {
        if (!_logFile) _logFile = new File(_logPath, 'a');
        _logFile.write(line + '\n');
        _logFile.flush();
    } catch (e) {
        // last resort - drop
    }
}

logToFile('[bypass] boot, arch:', Process.arch, 'pid:', Process.id);

var JNI_VERSION_1_6 = 0x00010006;

// -------------------------------------------------------------------
// Kill libxyass JNI_OnLoad on load
// -------------------------------------------------------------------
function hookLibxyass() {
    // If it's already loaded (rare early-case), patch immediately
    try {
        var mod = Process.getModuleByName('libxyass.so');
        patchXyass(mod);
        return;
    } catch (e) { /* not loaded yet, set up dlopen watcher */ }

    var libc = Process.getModuleByName('libc.so');
    var dlopen_ext = libc.findExportByName('android_dlopen_ext');
    if (!dlopen_ext) {
        logToFile('[xyass] android_dlopen_ext not found!');
        return;
    }

    Interceptor.attach(dlopen_ext, {
        onEnter: function (args) {
            try {
                this.path = args[0].readCString();
            } catch (e) {}
        },
        onLeave: function (retval) {
            if (!this.path) return;
            if (this.path.indexOf('libxyass.so') !== -1) {
                logToFile('[xyass] libxyass.so just loaded, patching JNI_OnLoad');
                try {
                    var mod = Process.getModuleByName('libxyass.so');
                    patchXyass(mod);
                } catch (e) {
                    logToFile('[xyass] getModule failed: ' + e.message);
                }
            } else if (this.path.indexOf('libssl') !== -1 || this.path.indexOf('libcronet') !== -1) {
                logToFile('[defer] late SSL lib load: ' + this.path);
                installSslHooksPassive();
            }
        },
    });
    logToFile('[xyass] watching dlopen for libxyass.so');
}

function patchXyass(mod) {
    var exps = mod.enumerateExports();
    var hit = exps.find(function (e) { return e.name === 'JNI_OnLoad'; });
    if (!hit) {
        logToFile('[xyass] JNI_OnLoad export not found!');
        return;
    }
    Interceptor.replace(hit.address, new NativeCallback(function (vm, reserved) {
        logToFile('[xyass] JNI_OnLoad BYPASSED, returning JNI_VERSION_1_6');
        return JNI_VERSION_1_6;
    }, 'int', ['pointer', 'pointer']));
    logToFile('[xyass] JNI_OnLoad patched @', hit.address);
}

// -------------------------------------------------------------------
// Minimal passive SSL hooks - only Interceptor.attach, no .replace
// on actual SSL code. We only rewrite the verify callback arg.
// -------------------------------------------------------------------
var sslHooked = {};

function installSslHooksPassive() {
    var alwaysOk = new NativeCallback(function (ssl, outAlert) {
        return 0; // ssl_verify_ok
    }, 'int', ['pointer', 'pointer']);

    Process.enumerateModules().forEach(function (mod) {
        var n = mod.name.toLowerCase();
        if (n.indexOf('ssl') === -1 && n.indexOf('cronet') === -1) return;
        if (sslHooked[mod.name]) return;
        try {
            var exps = mod.enumerateExports();
            ['SSL_CTX_set_custom_verify', 'SSL_set_custom_verify'].forEach(function (fn) {
                var e = exps.find(function (x) { return x.name === fn; });
                if (e) {
                    try {
                        Interceptor.attach(e.address, {
                            onEnter: function (args) {
                                args[2] = alwaysOk;
                            },
                        });
                        logToFile('[ssl] hooked ' + mod.name + '!' + fn);
                    } catch (err) {}
                }
            });
            sslHooked[mod.name] = true;
        } catch (e) {}
    });
}

// -------------------------------------------------------------------
// Run
// -------------------------------------------------------------------
try { hookLibxyass(); } catch (e) { logToFile('[main] xyass: ' + e); }
try { installSslHooksPassive(); } catch (e) { logToFile('[main] ssl: ' + e); }

// Periodic re-scan: if new SSL/Cronet modules load via linker namespace
// (bypassing android_dlopen_ext), the defer hook won't fire. Brute-force
// poll every 500ms and install hooks on any newly-present module.
var sslPollCount = 0;
var sslPollTimer = setInterval(function () {
    sslPollCount++;
    try { installSslHooksPassive(); } catch (e) {}
    // After 60 polls (30s), slow down to every 5s
    if (sslPollCount === 60) {
        clearInterval(sslPollTimer);
        sslPollTimer = setInterval(function () {
            try { installSslHooksPassive(); } catch (e) {}
        }, 5000);
    }
}, 500);

logToFile('[bypass] ready - polling for SSL modules every 500ms');
