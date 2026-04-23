// 枚举 xhs SSL 相关模块和 verify 符号 (Frida 17.x API)
console.log('[*] Process arch:', Process.arch);

var sslMods = Process.enumerateModules().filter(function(m) {
    var n = m.name.toLowerCase();
    return n.indexOf('ssl') !== -1 || n.indexOf('crypto') !== -1 || n.indexOf('boring') !== -1;
});

sslMods.forEach(function(m) {
    console.log('\n[mod]', m.name, 'base:', m.base);
    try {
        var exps = m.enumerateExports();
        var verifies = exps.filter(function(e) {
            return e.name.indexOf('verify') !== -1
                || e.name.indexOf('Verify') !== -1
                || e.name.indexOf('SSL_CTX_set_verify') !== -1
                || e.name.indexOf('SSL_get_verify_result') !== -1
                || e.name.indexOf('SSL_set_custom_verify') !== -1;
        });
        console.log('  [' + exps.length + ' exports, ' + verifies.length + ' verify-related]');
        verifies.slice(0, 15).forEach(function(e) {
            console.log('  ', e.name, '@', e.address);
        });
    } catch (e) {
        console.log('  [!] enumerate failed:', e.message);
    }
});
