/*
 * 通用 SSL Unpinning for xhs / 抖音
 * 覆盖：OkHttp3 CertificatePinner、TrustManager、Conscrypt、WebView
 * 目标：让所有 HTTPS 在运行时跳过证书校验
 */
Java.perform(function() {
    var count = 0;
    var hook = function(clazz, method, impl) {
        try {
            var cls = Java.use(clazz);
            cls[method].overloads.forEach(function(overload) {
                overload.implementation = impl;
                count++;
            });
            console.log('[+] Hooked: ' + clazz + '.' + method);
        } catch (e) {}
    };

    // --- OkHttp3 CertificatePinner (xhs 用这个最多) ---
    hook('okhttp3.CertificatePinner', 'check', function() { return; });
    hook('okhttp3.CertificatePinner', 'check$okhttp', function() { return; });

    // --- 抖音/xhs 混淆后的 CertificatePinner (字节跳动常见)  ---
    try {
        Java.enumerateLoadedClasses({
            onMatch: function(name) {
                if (name.indexOf('CertificatePinner') !== -1 && name.indexOf('okhttp') === -1) {
                    try {
                        var c = Java.use(name);
                        if (c.check) {
                            c.check.overloads.forEach(function(ov) {
                                ov.implementation = function() { return; };
                            });
                            console.log('[+] Hooked obfuscated: ' + name + '.check');
                        }
                    } catch (e) {}
                }
            },
            onComplete: function() {}
        });
    } catch (e) {}

    // --- TrustManager (整个证书链校验) ---
    var TrustManager = Java.registerClass({
        name: 'com.mitm.TrustMgr',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
            console.log('[+] SSLContext.init bypassed');
            this.init(km, [TrustManager.$new()], sr);
        };

    // --- Conscrypt (Android 默认 TLS 栈) ---
    hook('com.android.org.conscrypt.TrustManagerImpl', 'checkTrustedRecursive', function() { return Java.use('java.util.ArrayList').$new(); });
    hook('com.android.org.conscrypt.TrustManagerImpl', 'verifyChain', function(untrustedChain) { return untrustedChain; });

    // --- WebView ---
    hook('android.webkit.WebViewClient', 'onReceivedSslError', function(view, handler, error) { handler.proceed(); });

    console.log('[✓] SSL Unpinning loaded. ' + count + ' methods hooked.');
});
