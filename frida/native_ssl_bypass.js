// Native SSL bypass for xhs / Douyin
// Bypasses BoringSSL cert verification without Java bridge
// Targets Conscrypt + Cronet SSL libraries

console.log('[*] Loading native SSL bypass (BoringSSL)...');

// Always-OK custom verify callback
// Signature: enum ssl_verify_result_t (*)(SSL *ssl, uint8_t *out_alert)
// Returns 0 = ssl_verify_ok
var alwaysOk = new NativeCallback(function (ssl, outAlert) {
    return 0;
}, 'int', ['pointer', 'pointer']);

var sslLibs = Process.enumerateModules().filter(function (m) {
    var n = m.name.toLowerCase();
    return n === 'libssl.so' || n === 'stable_cronet_libssl.so';
});

var hookCount = 0;

sslLibs.forEach(function (lib) {
    console.log('\n[mod]', lib.name, '@', lib.base);

    // --- 1. Hook SSL_CTX_set_custom_verify ---
    // BoringSSL API: void SSL_CTX_set_custom_verify(SSL_CTX*, int mode, verify_cb)
    try {
        var exp = lib.enumerateExports().find(function (e) {
            return e.name === 'SSL_CTX_set_custom_verify';
        });
        if (exp) {
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    // args[0] = SSL_CTX*
                    // args[1] = mode (SSL_VERIFY_PEER=1)
                    // args[2] = callback
                    args[2] = alwaysOk;
                },
            });
            console.log('  [+] Hooked SSL_CTX_set_custom_verify @', exp.address);
            hookCount++;
        }
    } catch (e) {
        console.log('  [-] SSL_CTX_set_custom_verify:', e.message);
    }

    // --- 2. Hook SSL_set_custom_verify (per-connection variant) ---
    try {
        var exp = lib.enumerateExports().find(function (e) {
            return e.name === 'SSL_set_custom_verify';
        });
        if (exp) {
            Interceptor.attach(exp.address, {
                onEnter: function (args) {
                    args[2] = alwaysOk;
                },
            });
            console.log('  [+] Hooked SSL_set_custom_verify @', exp.address);
            hookCount++;
        }
    } catch (e) {
        console.log('  [-] SSL_set_custom_verify:', e.message);
    }

    // --- 3. Replace SSL_get_verify_result to always return X509_V_OK (0) ---
    try {
        var exp = lib.enumerateExports().find(function (e) {
            return e.name === 'SSL_get_verify_result';
        });
        if (exp) {
            Interceptor.replace(
                exp.address,
                new NativeCallback(
                    function (ssl) {
                        return 0; // X509_V_OK
                    },
                    'long',
                    ['pointer']
                )
            );
            console.log('  [+] Replaced SSL_get_verify_result @', exp.address);
            hookCount++;
        }
    } catch (e) {
        console.log('  [-] SSL_get_verify_result:', e.message);
    }
});

console.log('\n[✓] Total hooks installed:', hookCount);
console.log('[✓] Native SSL bypass active — all new TLS connections will skip peer verification');
