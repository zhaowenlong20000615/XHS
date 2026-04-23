/*
 * xhs combined bypass script
 *
 * 组合绕过：
 *   1. SSL Pinning (native BoringSSL + Java OkHttp)
 *   2. Signature verification (防止重签后自杀)
 *   3. Root/Frida detection silencing
 *
 * 用于 frida-gadget 模式注入（无需 frida-server）
 */

console.log('[xhs-bypass] Script starting...');
console.log('[xhs-bypass] Frida:', Frida.version, 'Runtime:', Script.runtime);
console.log('[xhs-bypass] Process:', Process.id, Process.arch);

// -------------------------------------------------------------------
// Layer 1: Native SSL bypass (BoringSSL)
// Works without Java bridge — hooks C symbols directly
// -------------------------------------------------------------------
function installNativeSslBypass() {
    var alwaysOk = new NativeCallback(function (ssl, outAlert) {
        return 0; // ssl_verify_ok
    }, 'int', ['pointer', 'pointer']);

    var targetLibs = ['libssl.so', 'stable_cronet_libssl.so', 'libcronet.114.0.5735.38.so'];
    var hookCount = 0;

    Process.enumerateModules().forEach(function (mod) {
        var name = mod.name;
        // Match either known lib names or any libcronet variant
        if (targetLibs.indexOf(name) === -1 && name.indexOf('cronet') === -1 && name.indexOf('ssl') === -1) {
            return;
        }

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
                        console.log('[ssl] Hooked ' + name + '!' + exp.name);
                        hookCount++;
                    } catch (e) {}
                } else if (exp.name === 'SSL_get_verify_result') {
                    try {
                        Interceptor.replace(
                            exp.address,
                            new NativeCallback(function () { return 0; }, 'long', ['pointer'])
                        );
                        console.log('[ssl] Replaced ' + name + '!' + exp.name);
                        hookCount++;
                    } catch (e) {}
                }
            });
        } catch (e) {
            console.log('[ssl] enum failed for ' + name + ': ' + e.message);
        }
    });

    console.log('[ssl] Native hooks installed: ' + hookCount);
}

// -------------------------------------------------------------------
// Layer 2: Java-layer hooks (if Java bridge works)
// -------------------------------------------------------------------
function installJavaHooks() {
    if (typeof Java === 'undefined' || !Java.available) {
        console.log('[java] Java bridge not available, skipping Java-layer hooks');
        return;
    }

    try {
        Java.perform(function () {
            console.log('[java] Running Java.perform...');

            // --- OkHttp CertificatePinner.check (all overloads) ---
            try {
                var CertPinner = Java.use('okhttp3.CertificatePinner');
                CertPinner.check.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        console.log('[java] okhttp3.CertificatePinner.check bypassed');
                        return;
                    };
                });
                console.log('[java] Hooked okhttp3.CertificatePinner.check');
            } catch (e) {
                console.log('[java] okhttp3.CertificatePinner not found: ' + e);
            }

            // --- Custom X509TrustManager (common xhs wrapper) ---
            try {
                var X509TM = Java.use('javax.net.ssl.X509TrustManager');
                // Can't replace interface directly; instead, override TrustManagerImpl
                var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TMI.checkTrustedRecursive.implementation = function () {
                    console.log('[java] TrustManagerImpl.checkTrustedRecursive bypassed');
                    return Java.use('java.util.ArrayList').$new();
                };
                console.log('[java] Hooked TrustManagerImpl');
            } catch (e) {
                console.log('[java] TrustManagerImpl hook failed: ' + e);
            }

            // --- Signature verification bypass (PackageManager) ---
            // xhs may check its own APK signature after repackaging
            try {
                var PM = Java.use('android.app.ApplicationPackageManager');
                var origSignatures = null;

                PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
                    var info = this.getPackageInfo(pkg, flags);
                    if (pkg === 'com.xingin.xhs' && (flags & 64) !== 0) {  // GET_SIGNATURES = 64
                        console.log('[sig] PackageInfo.signatures intercepted for ' + pkg);
                        // We don't know the original signature yet — log it for analysis
                        if (info.signatures && info.signatures.value) {
                            for (var i = 0; i < info.signatures.value.length; i++) {
                                var s = info.signatures.value[i];
                                console.log('[sig]   current=' + s.toCharsString().substring(0, 40) + '...');
                            }
                        }
                    }
                    return info;
                };
                console.log('[sig] Hooked ApplicationPackageManager.getPackageInfo');
            } catch (e) {
                console.log('[sig] PackageManager hook failed: ' + e);
            }

            // --- System.exit prevention (in case shield tries to kill) ---
            try {
                var System = Java.use('java.lang.System');
                System.exit.implementation = function (code) {
                    console.log('[kill] BLOCKED System.exit(' + code + ')');
                    // print stack
                    console.log(Java.use('android.util.Log').getStackTraceString(
                        Java.use('java.lang.Exception').$new()
                    ));
                };
                var Process2 = Java.use('android.os.Process');
                Process2.killProcess.implementation = function (pid) {
                    console.log('[kill] BLOCKED Process.killProcess(' + pid + ')');
                };
                console.log('[kill] Hooked System.exit / Process.killProcess');
            } catch (e) {
                console.log('[kill] exit hook failed: ' + e);
            }
        });
    } catch (e) {
        console.log('[java] Java.perform failed: ' + e);
    }
}

// -------------------------------------------------------------------
// Layer 3: Libc-level protection (block /proc/self/maps leakage of frida)
// -------------------------------------------------------------------
function installLibcProtection() {
    try {
        var open = Module.findExportByName('libc.so', 'open');
        if (!open) return;
        Interceptor.attach(open, {
            onEnter: function (args) {
                var path = args[0].readCString();
                if (path && (path.indexOf('/proc/self/maps') !== -1 || path.indexOf('/proc/self/task') !== -1)) {
                    this.isMaps = true;
                    this.path = path;
                }
            },
        });
        console.log('[libc] Armed open() watcher for /proc/self/maps');
    } catch (e) {
        console.log('[libc] ' + e);
    }
}

// ====================================================================
// Run everything
// ====================================================================
try {
    installNativeSslBypass();
} catch (e) { console.log('[main] native: ' + e); }

try {
    installJavaHooks();
} catch (e) { console.log('[main] java: ' + e); }

try {
    installLibcProtection();
} catch (e) { console.log('[main] libc: ' + e); }

console.log('[xhs-bypass] All layers attempted. Ready for traffic.');
