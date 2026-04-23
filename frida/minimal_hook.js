/*
 * Minimal diagnostic hook - only block process termination.
 * Used to isolate which hook in xhs_survivor.js breaks xhs startup.
 */
console.log('[minimal] boot');
console.log('[minimal] Frida:', Frida.version, 'Runtime:', Script.runtime);
console.log('[minimal] Process arch:', Process.arch, 'pid:', Process.id);

try {
    var libc = Process.getModuleByName('libc.so');
    ['abort', '_exit'].forEach(function (name) {
        try {
            var addr = libc.findExportByName(name);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        console.log('[minimal] caught libc.' + name + ' from:');
                        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).slice(0, 8).join('\n'));
                    },
                });
                console.log('[minimal] watching libc.' + name);
            }
        } catch (e) {
            console.log('[minimal] skip ' + name + ': ' + e.message);
        }
    });
} catch (e) {
    console.log('[minimal] init failed: ' + e);
}

console.log('[minimal] ready - xhs should run normally');
