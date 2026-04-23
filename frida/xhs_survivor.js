/*
 * xhs Survivor Bypass - 配合 gadget script mode 使用
 *
 * 核心策略：
 *   1. 立刻 hook libc abort/exit/kill/raise，防止任何反调试代码结束进程
 *   2. Hook BoringSSL SSL 函数（对已加载的 libssl）
 *   3. 用 dlopen hook 延迟 hook 后加载的 libcronet (xhs 主网络栈)
 */

console.log('[xhs-survivor] boot');

// -------------------------------------------------------------------
// Layer 0: Block any form of process termination
// -------------------------------------------------------------------
function blockTermination() {
    // ONLY hook process-level termination. NEVER hook kill/raise/pthread_kill -
    // those are used by pthread internals for cond variables and thread synchronization.
    // Hooking them causes futex_wait deadlocks.
    var libc = Process.getModuleByName('libc.so');
    var targets = ['abort', '_exit', 'exit', '__assert2', '__assert'];
    targets.forEach(function (name) {
        try {
            var addr = libc.findExportByName(name);
            if (!addr) return;
            // Interceptor.attach (not replace) - let the original still get called
            // but we log and optionally bail. For true block we need replace though.
            // Use attach with onEnter that never calls original by returning early
            // is not possible; use replace but only on abort/exit family.
            Interceptor.replace(addr, new NativeCallback(function () {
                console.log('[xhs-survivor] BLOCKED libc.' + name);
                // return quietly; caller's return-on-failure path will continue
            }, 'void', ['int']));
            console.log('[xhs-survivor] hooked libc.' + name);
        } catch (e) {
            console.log('[xhs-survivor] skip ' + name + ': ' + e.message);
        }
    });
}

// -------------------------------------------------------------------
// Layer 1: Native SSL bypass for currently-loaded SSL libs
// -------------------------------------------------------------------
function installSslHooks() {
    var alwaysOk = new NativeCallback(function (ssl, outAlert) {
        return 0;
    }, 'int', ['pointer', 'pointer']);

    var hookCount = 0;
    Process.enumerateModules().forEach(function (mod) {
        var n = mod.name.toLowerCase();
        if (n.indexOf('ssl') === -1 && n.indexOf('cronet') === -1) return;
        try {
            var exps = mod.enumerateExports();
            exps.forEach(function (exp) {
                if (exp.name === 'SSL_CTX_set_custom_verify' || exp.name === 'SSL_set_custom_verify') {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function (args) {
                                args[2] = alwaysOk;
                            },
                        });
                        console.log('[ssl] hooked ' + mod.name + '!' + exp.name);
                        hookCount++;
                    } catch (e) {}
                } else if (exp.name === 'SSL_get_verify_result') {
                    try {
                        Interceptor.replace(exp.address, new NativeCallback(function () {
                            return 0;
                        }, 'long', ['pointer']));
                        console.log('[ssl] replaced ' + mod.name + '!' + exp.name);
                        hookCount++;
                    } catch (e) {}
                }
            });
        } catch (e) {
            console.log('[ssl] enum ' + mod.name + ' failed: ' + e.message);
        }
    });
    console.log('[ssl] installed ' + hookCount + ' hooks');
}

// -------------------------------------------------------------------
// Layer 2: Defer-hook SSL libs loaded later (e.g. xhs own libcronet)
// -------------------------------------------------------------------
function installDeferredHooks() {
    var libc = Process.getModuleByName('libc.so');
    var dlopen_ext = libc.findExportByName('android_dlopen_ext');
    if (!dlopen_ext) {
        console.log('[defer] android_dlopen_ext not found');
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
            var p = this.path.toLowerCase();
            if (p.indexOf('libssl') !== -1 || p.indexOf('libcronet') !== -1) {
                console.log('[defer] late load: ' + this.path);
                // re-run SSL hooks (idempotent thanks to Interceptor)
                installSslHooks();
            }
        },
    });
    console.log('[defer] watching android_dlopen_ext');
}

// -------------------------------------------------------------------
// Layer 4: Neutralize xhs libsentry crash handler (GWP-ASan trip-wire)
// -------------------------------------------------------------------
// libsentry is xhs's self-built crash reporter that also acts as an
// anti-debug tripwire. xhs deliberately triggers GWP-ASan page faults;
// the sentry signal handler records them and the app's main thread
// then freezes once any crash record exists.
//
// Strategy: no-op all libsentry functions that record crashes or install
// signal handlers. If sentry never records, the "have crash" gate stays false.
function neutralizeSentry() {
    var libs = [
        'libsentry.so',
        'libsentry-hook.so',
        'libsentry-record.so',
        'libsentry-gwp-asan.so',
    ];
    libs.forEach(function (libName) {
        var mod;
        try {
            mod = Process.getModuleByName(libName);
        } catch (e) {
            console.log('[sentry] ' + libName + ' not loaded, skip');
            return;
        }
        try {
            var exps = mod.enumerateExports();
            var patched = 0;
            exps.forEach(function (exp) {
                var n = exp.name.toLowerCase();
                if (n.indexOf('crash_record') !== -1
                    || n.indexOf('crashrecord') !== -1
                    || n.indexOf('signal_handler') !== -1
                    || n.indexOf('invoke_signal') !== -1
                    || n.indexOf('store_file') !== -1
                    || n.indexOf('register_signal') !== -1
                    || n.indexOf('nativeinit') !== -1
                    || n.indexOf('gwp_asan') !== -1) {
                    try {
                        Interceptor.replace(
                            exp.address,
                            new NativeCallback(function () { return 0; }, 'int', [])
                        );
                        console.log('[sentry] no-op ' + libName + '!' + exp.name);
                        patched++;
                    } catch (e) {}
                }
            });
            console.log('[sentry] ' + libName + ': ' + patched + ' funcs patched');
        } catch (e) {
            console.log('[sentry] enum failed for ' + libName + ': ' + e.message);
        }
    });
}

// -------------------------------------------------------------------
// Run
// -------------------------------------------------------------------
try {
    blockTermination();
} catch (e) {
    console.log('[survivor] blockTermination failed: ' + e);
}

try {
    neutralizeSentry();
} catch (e) {
    console.log('[survivor] neutralizeSentry failed: ' + e);
}

try {
    installSslHooks();
} catch (e) {
    console.log('[survivor] installSslHooks failed: ' + e);
}

try {
    installDeferredHooks();
} catch (e) {
    console.log('[survivor] installDeferredHooks failed: ' + e);
}

console.log('[xhs-survivor] ready');
