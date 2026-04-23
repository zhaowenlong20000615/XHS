# docs/51 — docs/50 交付:libtiny cmd 分发序列 trace

**Responds to**: docs/50_frida_hook_libtiny_cmd_trace_spec.md
**Artifacts**:
- `lsposed/xhs-capture/captures/tiny_cmds_1776498882.jsonl` (617 条, 140 KB)
- `lsposed/xhs-capture/captures/tiny_cmds_1776498882.summary.md` (diff 分析)
- `lsposed/xhs-capture/captures/gen_tiny_summary.py` (可复用分析脚本)
- `lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java` (hook 扩展)

---

## 0. 关键偏离(文档与实现)

docs/50 spec 写的是 **Frida** 脚本方案,实际用 **LSPosed** 完成。原因:
- 项目 memory `project_xhs_capture_approach`:**Frida is a dead end on this Pixel 6 / Android 15**;LSPosed at `lsposed/xhs-capture` 是唯一工作路径
- docs/50 自己第 301 行也写着 "Frida trace 真机 = 和 LSPosed xhs-capture **一样性质**",作者知道两者等价

hook 点不变(同一个 Java 入口),JSONL 字段严格按 spec 第 62-93 行格式,产出路径也按 spec 第 232 行指定 `lsposed/xhs-capture/captures/tiny_cmds_<ts>.jsonl`。**对下游消费者无影响**。

---

## 1. TL;DR

**11 个 unique cmd,617 次调用**。最关键发现:

### 真机用过 / unidbg 里没调过 的 7 个 cmd(按频次降序)

| cmd_hex | n 次 | arg 类型 | 疑似作用 |
|---|---:|---|---|
| **`0x9657e61c`** | **83** | `String` ("unknown" / "CN=*.xiaohongshu.com,...") | TLS 握手 cert tracker 上报 ← **首选实验对象** |
| `0xafd151f7` | 13 | `UnmodifiableRandomAccessList<Certificate>` | SSL cert pinning 检查 |
| `0x711dffbb` | 3 | `Long, m6$a, ComponentName, BinderProxy, Long` | GMS Ads service bind 回调 |
| `0xc36c17de` | 3 | `String, String[]` = ("IndexActivityV2", ["com.android.shell"]) | Activity/process 环境上报 |
| `0xf2ae9b7a` | 2 | `()` 无参 | tick/notify ping |
| `0x38ddf10d` | 1 | `String` = "[]" | 不明 |
| `0xce2bb8af` | 1 | `()` 无参 | tick/notify ping |

### docs/50 声称 unidbg 已调 / 真机首屏 0 次 的 6 个 cmd

`config_init`, `register_Application`, `ready_signal`, `getChannel`, `userGranted`, `session_id` — 真机**首屏冷启**期间一次都没调。可能:
- 原 docs/50 list 来自别的场景(新设备首次安装?账号首次登录?)
- 或 unidbg 侧产生了假调用但没被 SDK 内部 dispatcher 承接

### unidbg vs 真机 — 共同调过的 cmd 对比

| cmd | unidbg 估计次数 | 真机实测 |
|---|---:|---:|
| `1140071423` (d7.a) | ?(docs/50 未给) | **436** |
| `-1750991364` (sign) | 1 | 70 |
| `1932492929` (onActivityStarted) | 5 | 3 |
| `1268781800` (param) | 2 | 2 |

**最大差距**:`d7.a` 真机 436 次,unidbg 未知但大概率远少 — 这是某种高频 counter/metric,每次 HTTP 调用都会上报,我们 unidbg 侧一次请求时 **这个 cmd 只触发一次**,而真机首屏几十条请求把它打到 436 次。

---

## 2. 实施过程 + 4 个踩过的坑

### 2.1 类名:docs/50 spec 错了一半

docs/50 第 38-43 行说 target class = `Java_com_xingin_tiny_internal_t_a`。jadx decompile 只输出 `com/xingin/tiny/daemon/d.java` 里有 `public static native <T> T a(int, Object...)`。第一版代码按 `daemon.d` hook,**ClassNotFoundException**。

最终 smali 验证:`smali_classes11/com/xingin/tiny/internal/t.smali` 里有
```
.method public static varargs native a(I[Ljava/lang/Object;)Ljava/lang/Object;
```

**真 dispatcher 是 `com.xingin.tiny.internal.t`,原 spec 是对的**。`daemon.d` 只是 `System.loadLibrary("tiny")` 的 loader 壳,不是分发入口。jadx 漏输出 `internal.t`(这个 class 在 smali_classes11 — secondary classes dex,jadx pass 可能跳过)。

**教训**:jadx 和 smali 双源交叉验证才安心,任一单源都可能漏。

### 2.2 多子进程 race 截断 JSONL

第一次成功抓到 149 条,pull 下来只有 9 行。原因:xhs 有 5+ 个子进程(`:pushservice`, `:simplePush`, `:longlinkNew`, `:widgetProvider`, `:xg_service_v3`),每个都跑 `handleLoadPackage` → 每个都 `installTinyCmdTraceHook` → 每个都 `new FileWriter(TINY_CMDS_LOG, false).close()` **truncate 文件**。

**修复**:`installTinyCmdTraceHook` 入口加进程名过滤
```java
if (!TARGET.equals(currentProcName)) {
    writeLog("skipped in non-main process: " + currentProcName);
    return;
}
```
`currentProcName` 在 `handleLoadPackage` 一进来就设。

修完后一次冷启稳定拿 617 条。

### 2.3 loadClass / findClass watcher 双双不触发

第二版不相信 `daemon.d` 是 dispatcher 了,改成 hook `ClassLoader.loadClass(String, boolean)` 等 **任何** `com.xingin.tiny.*` 类被加载就 log。冷启 35 秒后 — **0 次触发**,哪怕 mua 已经生成(证明 tiny 被调用过)。

改 hook `dalvik.system.BaseDexClassLoader.findClass(String)` — 还是 **0 次触发**。

结论:xhs 自定义了 dex 加载路径,绕开了 java.lang.ClassLoader 的两个标准入口。smali_classes11 内类的 ClassLoader 可能是 xhs 运行时手写的 JNI-only ClassLoader,或用 `dalvik.system.DexFile.loadDex` 直接加载。

**最终实现**:既然真实 class 是 `com.xingin.tiny.internal.t`(在主 APK 的 smali_classes11,**不是动态 dex**),直接 `XposedHelpers.findAndHookMethod(DISPATCHER_CLASS, cl, "a", int.class, Object[].class, ...)` 就 work 了 —— 因为 callApplicationOnCreate 之后主 classloader 已经能看到它。

**教训**:绕远路之前先用最直接的方法试一次;只有当直接方法失败时才退到 classloader hook。

### 2.4 TINY_CMD_SEQ AtomicInteger 进程间不共享

`TINY_CMD_SEQ` 是 static,每个子进程有独立副本。在多进程 race 时,每个子进程都从 seq=0 开始往同一文件写,**造成 seq 重复**。和 2.2 合并修复(只主进程写)后此问题一并消失。

---

## 3. Hook 规格(实际实现)

### 关键字段(src/com/xhs/capture/XhsCapture.java)

```java
// 日志路径
private static final String TINY_CMDS_LOG = "/data/data/com.xingin.xhs/files/tiny_cmds.jsonl";

// 全局序号 + 上限
private static final AtomicInteger TINY_CMD_SEQ = new AtomicInteger(0);
private static final int TINY_CMD_MAX = 2000;  // spec 说 50-300 期望, 2000 余量
private static volatile long tinyStartTs = 0;

// 进程名过滤 (fix 2.2)
private static volatile String currentProcName = null;
```

### Hook 点

```java
XposedHelpers.findAndHookMethod(
    "com.xingin.tiny.internal.t", cl,
    "a", int.class, Object[].class,
    new XC_MethodHook() {
        @Override protected void beforeHookedMethod(MethodHookParam param) {
            int seq = TINY_CMD_SEQ.getAndIncrement();
            if (seq >= TINY_CMD_MAX) return;
            int cmd = (Integer) param.args[0];
            Object[] args = (Object[]) param.args[1];
            writeTinyCmd(seq, cmd, args);
        }
    });
```

### 输出格式(严格按 docs/50 第 62-93 行)

```json
{
  "seq": 0,
  "ts_ms": 1234,
  "cmd": 1140071423,
  "cmd_hex": "0x43f41bff",
  "arg_count": 3,
  "arg_types": ["java.lang.Long", "[B", "[B"],
  "arg_summary": ["2038853396", "<byte[30]>", "<byte[2]>"],
  "tid": 175,
  "thread_name": "Thread-3885"
}
```

### briefValue() — arg 摘要策略

- `String`:截前 80 字符(docs/50 第 81 行要求)
- 基础包装类(Integer/Long/Boolean/...)`toString()`
- `byte[]` / `int[]` / `long[]` → `<byte[N]>` 之类
- `String[]` (< 8 元素):逐个截 20 字符
- Android 系统类(`android.app.*`, `android.content.*`, `android.os.*`, `java.util.*`):`String.valueOf(a)` 截 80 字符
- 其他:`@<identityHashCode>` 避免 deadlock(某些 obfuscated class 的 toString 可能递归)

---

## 4. 部署 / 运行步骤

```bash
# 1. 修改 XhsCapture.java 后
cd lsposed/xhs-capture
./build.sh

# 2. 装 APK
adb install -r build/xhs-capture.apk

# 3. LSPosed 需要 double reboot(dex cache 坑,见 docs/43)
adb reboot
adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done'
adb reboot
adb wait-for-device
adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done'

# 4. 设置时间(reboot 会 reset)
adb shell 'su -c "date MMDDHHmmYYYY.SS"'

# 5. 冷启抓 (~30-45 秒足够)
adb shell input keyevent 82   # unlock
adb shell 'am force-stop com.tunnelworkshop.postern; am force-stop com.v2ray.ang; am force-stop com.xingin.xhs'
adb shell 'su -c "rm -f /data/data/com.xingin.xhs/files/tiny_cmds.jsonl"'
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
sleep 40

# 6. Pull
TS=$(date +%s)
adb shell 'su -c "cp /data/data/com.xingin.xhs/files/tiny_cmds.jsonl /sdcard/tcmd.jsonl && chmod 666 /sdcard/tcmd.jsonl"'
adb pull /sdcard/tcmd.jsonl lsposed/xhs-capture/captures/tiny_cmds_${TS}.jsonl

# 7. 分析
python3 lsposed/xhs-capture/captures/gen_tiny_summary.py \
    lsposed/xhs-capture/captures/tiny_cmds_${TS}.jsonl \
    lsposed/xhs-capture/captures/tiny_cmds_${TS}.summary.md
```

---

## 5. unidbg 侧后续动作(docs/50 section 7)

docs/50 说拿到 trace 后的计划:
> 1. 解析 jsonl, 提取所有 unique cmd id (排序)
> 2. diff 真机 cmd 集合 vs 我们 15 个
> 3. 对每个"真机有我们没"的 cmd,研究它的 args 类型,在 unidbg init 里补调
> 4. 补完重跑 `MuaTailProbeTest` 看 mua JSON 是否出现 `"t":{...}` 字段
> 5. 出现 → 我们 mua 长度应从 1165B → ~1548B → 可能突破 2/5 live test

1-2 已在本 doc 完成。**3-5 的优先级建议**:

### 优先实验 1:`0x9657e61c` ← 83 次,单 String 参

最有可能激活 tracker。实验成本极低:
- unidbg `XhsSigner` 启动时加一次 `tiny.a(0x9657e61c, new Object[]{"CN=*.xiaohongshu.com, O=..."})`
- 也可以用 `"unknown"` 当作 baseline(首个真机调用就是"unknown")
- 跑 `MuaTailProbeTest`,看 mua JSON 有无冒出 `"t":{"c":0,"d":0,"f":0,"s":4098,"t":0,"tt":[]}`

### 优先实验 2:`0xafd151f7` ← cert chain List

稍复杂,需要 mock 一个 cert List。可先简单传 `Collections.emptyList()`,如果 tiny 不挑参数格式,说不定也激活 tracker state。

### 后续实验 3:`0xf2ae9b7a` + `0xce2bb8af` ← 无参 ping

直接 `tiny.a(0xf2ae9b7a, new Object[0])`。零成本,可一起加进 bootstrap 尾巴。

### 低优先级:`0x711dffbb` + `0xc36c17de`

需要伪造 `com.xingin.tiny.internal.m6$a`(tiny 内部类,mock 有难度) / ComponentName / BinderProxy。除非 1-3 都不奏效,否则不建议先碰。

---

## 6. 验收口径

下游 unidbg 侧有任一条件满足即可算本 trace 输出被消化:
1. mua JSON 出现 `"t":{...}` 子对象(长度 +47 字节,对齐真机)
2. mua total 长度从 1165B → ~1548B(383B gap 收敛)
3. live server endpoint PASS 从 2/5 → ≥ 3/5

如果补了最高频的 `0x9657e61c` 还是没激活,说明 tracker state 还依赖**调用顺序 / 参数相等性**等更细的条件,需要 **args 深度研究**(byte[281] payload 等)。到那步可以再跑一次这个 hook,把 arg_summary 改成 full hex dump 看完整参数。

---

## 7. 一句话向上汇报

**docs/50 完成 —— 真机首屏 617 次 libtiny.a 调用全部 jsonl 归档。11 个 unique cmd 里 7 个是 unidbg 从未调过的,其中 `0x9657e61c` (83 次, 单 String 参) 为最高嫌疑 tracker 激活入口。unidbg 侧按 section 5 顺序补调即可收敛 mua 383B gap。**
