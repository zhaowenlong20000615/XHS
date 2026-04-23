// 诊断 Frida runtime 环境
console.log('[+] Script loaded');
console.log('[+] Frida version:', Frida.version);
console.log('[+] Script runtime:', Script.runtime);
console.log('[+] Process arch:', Process.arch);
console.log('[+] Process pointerSize:', Process.pointerSize);
console.log('[+] Process id:', Process.id);
console.log('[+] Java typeof:', typeof Java);
console.log('[+] ObjC typeof:', typeof ObjC);

if (typeof Java !== 'undefined') {
    console.log('[+] Java.available:', Java.available);
    if (Java.available) {
        Java.perform(function() {
            console.log('[+] Java.androidVersion:', Java.androidVersion);
        });
    }
}

// 列出所有 loaded modules 看有没有 libart
var libs = Process.enumerateModules().filter(function(m) {
    return m.name.indexOf('art') !== -1 || m.name.indexOf('dalvik') !== -1 || m.name.indexOf('frida') !== -1;
});
console.log('[+] Relevant modules:', JSON.stringify(libs.map(function(m) { return m.name; })));
