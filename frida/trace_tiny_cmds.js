// Usage: frida -U -f com.xingin.xhs -l trace_tiny_cmds.js --no-pause
// 抓 libtiny cmd 分发序列, 找到激活 tracker 子模块 (t 字段) 的 cmd
// 输出每行一条: {seq, ts_ms, cmd, arg_count, arg_types}

(function () {
    var seq = 0;
    var startTs = Date.now();

    function waitLib() {
        var base = Module.findBaseAddress('libtiny.so');
        if (!base) { setTimeout(waitLib, 100); return; }
        install(base);
    }

    function install(base) {
        // Java_com_xingin_tiny_internal_t_a exported; fallback to offset 0x90795 (thumb)
        var sym = Module.findExportByName('libtiny.so', 'Java_com_xingin_tiny_internal_t_a');
        if (!sym) sym = base.add(0x90795);
        console.log('[trace_tiny_cmds] hooking', sym);

        Interceptor.attach(sym, {
            onEnter: function (args) {
                // ARM32 calling conv: r0=JNIEnv*, r1=jclass, r2=cmd (int), r3=jobjectArray
                var env = args[0];
                var cmd = args[2].toInt32();
                var argArrPtr = args[3];

                // Use JNI GetArrayLength + GetObjectArrayElement + GetObjectClass to describe types
                // Shorter: just log cmd + arrPtr (non-null?)
                var info = {
                    seq: seq++,
                    ts_ms: Date.now() - startTs,
                    cmd: cmd,
                    arg_arr_ptr: argArrPtr.toString(),
                };

                // Pull array length via JNIEnv vtable (arm 32bit: env[0] = funcs table)
                // funcs[171] = GetArrayLength in typical Android JNI layout — unreliable to hard-code
                // Simpler: log first StringObject arg if present
                try {
                    var JNIEnv = Java.vm.getEnv();
                    var jarr = argArrPtr;
                    if (!jarr.isNull()) {
                        // JNI returns jsize
                        var len = JNIEnv.handle.readPointer().add(171*4).readPointer();
                        // Too fragile — just send cmd + ptr for now
                    }
                } catch (e) {}

                send({type: 'tiny_cmd', info: info});
            }
        });

        console.log('[trace_tiny_cmds] installed, listening for cmd calls...');
    }

    setTimeout(waitLib, 50);
})();
