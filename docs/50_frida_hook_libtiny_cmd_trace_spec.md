# 需求: Frida hook 真机 libtiny cmd 分发序列

**受众**: 负责跑真机 Frida 的窗口
**产出**: `lsposed/xhs-capture/captures/tiny_cmds_<timestamp>.jsonl`
**目的**: 让这边 unidbg 黑盒模拟对齐真机的 libtiny 初始化序列

---

## 1. 背景 (为什么要这个 trace)

### 我们 unidbg 现状
unidbg 黑盒模拟 xhs 签名,能产 6 个 header (mua/s1/sig/shield/xy-platform-info/xy-common-params)。live server 实测 **2/5 endpoint PASS**。

### 新发现 (今天,2026-04-18)
实测 `captures/xhs_fresh_install_20260418_105925.log` 真机 x-mini-mua **1548B**(之前 memory 记的 1058B 是错的)。

我们 mua **1165B**, 比真机**短 383B**:
- JSON 部分: 我们 296B, 真机 343B, 缺 **`"t"` 字段 47B**
- tail 部分: 我们 576B (decoded), 真机 816B, 缺 **240B**

### 缺的 `t` 对象
真机 JSON 里有:
```json
"t":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]}
```
我们 JSON 里**完全没这个字段**。说明 libtiny 内部"tracker 子模块"在我们 unidbg init 时**未激活**。一旦激活,mua JSON 会自动包含 `t` 对象(+47B), 同时预计 tail accumulator 也会跟着增长补齐 240B。

### 为啥需要真机 trace
libtiny 是 OLLVM 混淆的 native 库,`Java_com_xingin_tiny_internal_t_a(env, class, cmd, args)` 是总入口,按 `cmd` (32-bit int) 分发到不同子函数。**哪个 cmd 激活 tracker 模块我们不知道**,穷举 2^32 空间不可能。

我们当前 unidbg 里 init 阶段调了 15 个 cmd,真机可能调了更多/不同的。**diff 真机 cmd 序列 vs 我们 unidbg 的,就能精确找到哪几个 cmd 缺**。

---

## 2. Hook 目标

### 函数
```
库:        libtiny.so
符号:      Java_com_xingin_tiny_internal_t_a
ARM 地址:  libtiny.so + 0x90795 (thumb 模式, 最低位 = 1)
签名:      JNIEXPORT jobject JNICALL
           Java_com_xingin_tiny_internal_t_a(JNIEnv* env, jclass clazz, jint cmd, jobjectArray args)
```

### 调用点
Java 侧 `com.xingin.tiny.internal.t.a(int cmd, Object[] args)` → native。
xhs 启动期间会连续调用此函数几十~几百次来初始化 libtiny 各模块 (config / register / onActivityStarted / getChannel / 等)。

### ARM32 调用约定
- r0 = JNIEnv*
- r1 = jclass
- **r2 = cmd (int)** ← **核心要 log**
- **r3 = jobjectArray args** ← 也要 log (arg 数量和类型)

---

## 3. 要抓的数据 (每次调用)

对每次 `Java_com_xingin_tiny_internal_t_a` 调用,记录一条 JSON Lines:

```json
{
  "seq": 0,                         // 自增序号, 从 0 开始
  "ts_ms": 42,                      // 相对 Frida attach 的毫秒
  "cmd": 1027279761,                // int 值 (可能负数, 有符号)
  "cmd_hex": "0x3d3a2d11",          // 原始 32-bit 表示 (便于查表)
  "arg_count": 16,                  // args.length, 如果 args 为 null 则 -1
  "arg_types": [                    // 每个 arg 的运行时类型
    "java.lang.String",
    "java.lang.String",
    "java.lang.Integer",
    "java.lang.Boolean",
    "java.lang.Float",
    "java.lang.Application",        // 如果是 Application/Activity 等 Android 对象
    "java.util.ArrayList",
    "byte[]",                       // 原生数组
    null                            // 代表 args[i]==null
  ],
  "arg_summary": [                  // 每个 arg 的简短值 (最多 80 字符)
    "ECFAAF01",
    "a5b8432c4477b553",
    "0",
    "true",
    "false",
    "android.app.Application@a3b4c5d",
    "[]",
    "<byte[0]>",
    null
  ],
  "tid": 12345,                     // 线程 id (辨别是否异步)
  "caller": "com.xingin.tiny.A.b+0x18"  // 可选: Java 栈顶 (用 Thread.currentThread().getStackTrace())
}
```

**关键字段**: `cmd` 最重要,`arg_count` + `arg_types` 次之。`arg_summary` 用于调试。

---

## 4. Frida 脚本

我已经写了骨架 `frida/trace_tiny_cmds.js`,但**功能不全**。你需要完善成上面数据格式。参考下面伪代码:

```javascript
// frida/trace_tiny_cmds.js (需要你完善)
Java.perform(function () {
    var seq = 0;
    var startTs = Date.now();

    function install() {
        var base = Module.findBaseAddress('libtiny.so');
        if (!base) { setTimeout(install, 100); return; }

        var sym = base.add(0x90795);  // thumb, 但 Interceptor.attach 会自动处理

        Interceptor.attach(sym, {
            onEnter: function (args) {
                // r0=JNIEnv*, r1=jclass, r2=cmd, r3=jobjectArray
                var cmd = args[2].toInt32();
                var argArrNative = args[3];  // NativePointer to jobjectArray

                // 用 Java.vm 转成 Java 可操作的 jobject
                var env = Java.vm.getEnv();

                // GetArrayLength
                var arrLen = -1;
                var argTypes = [];
                var argSummary = [];
                try {
                    if (!argArrNative.isNull()) {
                        arrLen = env.getArrayLength(argArrNative);
                        for (var i = 0; i < arrLen; i++) {
                            var elem = env.getObjectArrayElement(argArrNative, i);
                            if (elem.isNull()) {
                                argTypes.push(null);
                                argSummary.push(null);
                            } else {
                                // GetObjectClass + getName via reflection
                                var cls = env.getObjectClass(elem);
                                // 这里最简的做法: wrap 成 Java.cast 或直接 toString
                                var typeName = getClassName(env, cls);
                                argTypes.push(typeName);
                                argSummary.push(briefValue(env, elem, typeName));
                                env.deleteLocalRef(cls);
                            }
                            env.deleteLocalRef(elem);
                        }
                    }
                } catch (e) {
                    argSummary.push('[err: ' + e + ']');
                }

                // 线程 id
                var tid = Process.getCurrentThreadId();

                send({
                    seq: seq++,
                    ts_ms: Date.now() - startTs,
                    cmd: cmd,
                    cmd_hex: '0x' + (cmd >>> 0).toString(16).padStart(8, '0'),
                    arg_count: arrLen,
                    arg_types: argTypes,
                    arg_summary: argSummary,
                    tid: tid
                });
            }
        });

        console.log('[trace_tiny_cmds] installed at', sym);
    }

    setTimeout(install, 50);

    function getClassName(env, clsRef) {
        // 用 Class.getName() via CallObjectMethod
        // 或用 Java.cast 方式
        try {
            var Cls = Java.use('java.lang.Class');
            var cObj = Java.cast(clsRef, Cls);
            return cObj.getName();
        } catch (e) {
            return '<unknown>';
        }
    }

    function briefValue(env, elem, typeName) {
        // 根据 type 抽 80 字符摘要
        try {
            if (typeName === 'java.lang.String') {
                var S = Java.use('java.lang.String');
                var s = Java.cast(elem, S).toString();
                return s.length > 80 ? s.substring(0, 80) + '...' : s;
            }
            if (typeName === 'java.lang.Integer' || typeName === 'java.lang.Long'
                || typeName === 'java.lang.Float' || typeName === 'java.lang.Double'
                || typeName === 'java.lang.Boolean') {
                var Obj = Java.use(typeName);
                return Java.cast(elem, Obj).toString();
            }
            if (typeName === '[B') return '<byte[]>';
            if (typeName.indexOf('[') === 0) return '<array>';
            return '@' + elem.toString();
        } catch (e) {
            return '[err]';
        }
    }
});
```

> 注: Frida 的 `env.getArrayLength` / `env.getObjectArrayElement` 调法依 Frida 版本不同,可能要用 `env.callFunction` 或直接读 JNIEnv vtable。如果该 API 不行,退化到 **只 log cmd + arg_count(不抓 types)** 也可接受。

---

## 5. 运行步骤

```bash
cd /Users/zhao/Desktop/test/xhs/frida

# 方案 A (推荐): 冷启动抓完整 init
adb shell am force-stop com.xingin.xhs
python3 trace_tiny_runner.py --spawn

# 方案 B (备用): attach 已跑的 xhs
python3 trace_tiny_runner.py
```

### 停止时机
让 xhs 启动到**首页完全加载、能滑动** (大约 20-30 秒)。期间应至少看到 1 次网络请求 (`/cfg/android` POST 是第一条)。然后 **Ctrl-C** 停 runner。

### 输出位置
```
lsposed/xhs-capture/captures/tiny_cmds_<epoch_timestamp>.jsonl
```
一行一条 JSON。

### 预期数量
估 **50-300 条**。如果 < 20 条: hook 没上 (检查 Frida 是否连上, 符号是否找到)。如果 > 1000 条: 你等太久了, 早点 Ctrl-C。

---

## 6. 我们 unidbg 的对照 (已知的 15 个 cmd)

```
cmd             十六进制        调用点 / 语义猜测
1027279761      0x3d3a2d11      config init (SDK config)
2099694886      0x7d260ca6      register Application
1932492929      0x73310f01      onActivityStarted (×5)
-1752783575     0x97864fa9      ready signal
-378830707      0xe961e28d      getChannel
1268781800      0x4ba7b428      (×2, 参数 1, 0)
378947270       0x1693ef06      userGranted
1140071423      0x43f7d37f      d7.a (?)
-130547861      0xf83b432b      session id
-1750991364     0x978176fc      sign (核心 cmd)
```

这 10 个 cmd id 算 15 个调用 (1932492929 × 5 + 1268781800 × 2)。

真机如果有**其他 cmd id**,那就是我们缺的。

---

## 7. 我拿到 trace 后做的事

1. 解析 jsonl, 提取所有 unique cmd id (排序)
2. diff 真机 cmd 集合 vs 我们 15 个
3. 对每个"真机有我们没"的 cmd,研究它的 args 类型,在 unidbg init 里补调
4. 补完重跑 `MuaTailProbeTest` 看 mua JSON 是否出现 `"t":{...}` 字段
5. 出现 → 我们 mua 长度应从 1165B → ~1548B → 可能突破 2/5 live test

---

## 8. 常见坑

| 问题 | 解决 |
|---|---|
| Frida 连不上 (`frida.ProcessNotFoundError`) | 手机开 `frida-server` (root 后 `/data/local/tmp/frida-server`) |
| symbol `Java_com_xingin_tiny_internal_t_a` 找不到 | 直接用 `base.add(0x90795)` |
| `env.getArrayLength is not a function` | Frida API 版本问题, 退回 "只 log cmd + arg_arr_ptr" |
| 捕获 0 条 | xhs app 已 attach 但没触发 init? 强制 force-stop 后 --spawn |
| 捕获几千条 | Ctrl-C 早点,我们只要到首条 mua 为止 |

## 9. 结果回收

生成 jsonl 后告诉我文件路径,我这边立刻开始 diff 分析。

或者最简反馈格式:
```
# 贴 tail -n 50 就行
cat lsposed/xhs-capture/captures/tiny_cmds_<ts>.jsonl | head -200
```

我从前 200 条能提取 unique cmd 集合。

---

## 10. 为什么这没偏离大方向

**大方向 = unidbg 黑盒模拟** = 不改 app,只补环境让 app 代码自己在 unidbg 里正常跑。

Frida trace 真机 = **只观测不修改**,和 SYSCALL_TRACE / LSPosed xhs-capture 一样性质。拿到观测结果 → 补 unidbg 环境 (多调几个 init cmd) → libtiny 自己生成完整 mua。

app 代码一行都没改,签名由 libtiny 自己产出。**完全符合黑盒模拟定义**。
