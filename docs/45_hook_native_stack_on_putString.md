# docs/45 — 真机 putString main_hmac 时的 native stack 抓取

**Responds to**: 主项目 unidbg 侧干线 1 卡点,docs/43/44 信息不够
**先决条件**: docs/42 `main_hmac_writer.log` 已经拿到 Java stack; docs/44 cPtr dump 已拿
**目标**: 拿到**native 侧**调 `SharedPreferences$Editor.putString("main_hmac", ...)` 时的**完整 native stack 的 PC 列表**,帮 unidbg 侧反汇编精确定位 derive 分支入口(不是整条 intercept 全域)

---

## TL;DR

目前已知 `Native.intercept` 内部某处做 derive + putString,但 unidbg 反汇编定位太大(几千条指令,OLLVM 混淆)。
拿到 **native PC 栈** 后反汇编范围从 "几千条" 降到 "几十条",精准找 derive 的 if 分支判断。

一条 JNI helper + 扩展 docs/42 已有的 Java hook,产出 `scratch/persistent_survey/main_hmac_native_stack.log`(~2 KB)。

---

## 1. 背景

### 1.1 干线 1 已穷尽的分析

- 真机 `Native.intercept` 调用栈: `LSPHooker_.putString ← Native.intercept(Native) ← XhsHttpInterceptor.intercept`
- **Java stack 里 Native.intercept 是"Native Method" 没 line number** → 无法定位 native 内部哪个 PC 调了 putString
- docs/44 cPtr dump 证实 +0x018 不是 derive gate,derive 分支藏在 intercept 内部更深处

### 1.2 为什么要 native stack

Unidbg 侧要反汇编 `libxyass` 找 derive 分支。不知道 PC 就得扫整条 intercept (~几千条 Thumb 指令, OLLVM 后控制流打散)。
拿到 native PC 栈后:
```
PC[0] libart.so+0x???            ← NativeHelper 自己
PC[1] libart.so+0x???            ← _Unwind_Backtrace
PC[2] libart.so+0x???            ← CallObjectMethodV implementation
PC[3] libxyass.so+0x26123        ← ★ libxyass 里调 CallObjectMethodV 的地方 ★
PC[4] libxyass.so+0x25ab0        ← 上一个函数的调用点
...
```

只要反汇编 `libxyass+0x26123` 周围 50 条指令就能看到 **"是否 derive" 的 if 判断**,补对应 JNI stub。

---

## 2. 实施步骤

### Step 1 — 写 JNI helper (C 代码)

在 `lsposed/xhs-capture/jni/` 新建文件 `native_stack.c`:

```c
#include <jni.h>
#include <unwind.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_FRAMES 30

typedef struct {
    size_t count;
    uintptr_t pcs[MAX_FRAMES];
} UnwindState;

static _Unwind_Reason_Code unwind_cb(struct _Unwind_Context *ctx, void *arg) {
    UnwindState *st = (UnwindState *)arg;
    if (st->count >= MAX_FRAMES) return _URC_END_OF_STACK;
    uintptr_t pc = _Unwind_GetIP(ctx);
    if (pc == 0) return _URC_END_OF_STACK;
    st->pcs[st->count++] = pc;
    return _URC_NO_REASON;
}

JNIEXPORT jlongArray JNICALL
Java_com_xhs_capture_NativeStack_capture(JNIEnv *env, jclass cls) {
    UnwindState st = { .count = 0 };
    _Unwind_Backtrace(unwind_cb, &st);
    jlongArray arr = (*env)->NewLongArray(env, (jsize)st.count);
    if (arr == NULL) return NULL;
    jlong *buf = (jlong *)malloc(sizeof(jlong) * st.count);
    for (size_t i = 0; i < st.count; i++) buf[i] = (jlong)(uintptr_t)st.pcs[i];
    (*env)->SetLongArrayRegion(env, arr, 0, (jsize)st.count, buf);
    free(buf);
    return arr;
}
```

### Step 2 — 写 Android.mk / CMakeLists

参考 `lsposed/xhs-capture/` 里现有的 `jni/Android.mk`(已存在),加一行:
```
LOCAL_SRC_FILES += native_stack.c
LOCAL_LDLIBS += -ldl
```

或在 CMakeLists 里:
```
add_library(native_stack SHARED native_stack.c)
target_link_libraries(native_stack log)
```

(按实际构建系统决定)

NDK 编译产物为 `libnative_stack.so`,和 `libxhscap.so`(现有)一起打进 apk 的 `lib/armeabi-v7a/`。

### Step 3 — Java 侧加 loader + 辅助类

在 `lsposed/xhs-capture/src/com/xhs/capture/NativeStack.java`:

```java
package com.xhs.capture;

public class NativeStack {
    static {
        try { System.loadLibrary("native_stack"); }
        catch (Throwable t) { /* fallback: log error */ }
    }
    public static native long[] capture();
}
```

### Step 4 — 扩展 docs/42 已有的 putString hook

在 `XhsCapture.java` 里,找到已有的 main_hmac writer hook (filter key=="main_hmac"),增加:

```java
// 在 beforeHookedMethod 里 (docs/42 已有):
if ("main_hmac".equals(key)) {
    StringBuilder sb = new StringBuilder();
    sb.append("[HOOK main_hmac_writer] ts=").append(System.currentTimeMillis()).append('\n');
    // ... 原 docs/42 的字段 ...

    // 新增: native stack
    try {
        long[] nativePCs = NativeStack.capture();
        sb.append("  native_stack=\n");
        // 读 /proc/self/maps 解析 PC 落在哪个 library
        java.util.Map<String,long[]> libRanges = loadLibRanges();  // 见下
        for (long pc : nativePCs) {
            String lib = resolveLib(pc, libRanges);
            sb.append(String.format("    pc=0x%x  %s%n", pc, lib));
        }
    } catch (Throwable t) {
        sb.append("  native_stack_err=").append(t).append('\n');
    }

    writeLog(sb.toString());
}

// Helper: 解析 /proc/self/maps 得 library base/end
private static java.util.Map<String,long[]> loadLibRanges() throws Exception {
    java.util.Map<String,long[]> out = new java.util.LinkedHashMap<>();
    java.io.BufferedReader br = new java.io.BufferedReader(
        new java.io.FileReader("/proc/self/maps"));
    String line;
    while ((line = br.readLine()) != null) {
        // 格式: "76f41000-76fbc000 r-xp 00000000 fd:00 12345  /data/app/.../lib/armeabi-v7a/libxyass.so"
        int dash = line.indexOf('-');
        int sp1 = line.indexOf(' ', dash);
        if (dash < 0 || sp1 < 0) continue;
        long lo = Long.parseLong(line.substring(0, dash), 16);
        long hi = Long.parseLong(line.substring(dash+1, sp1), 16);
        // 只看含 "r-x" 的行(可执行段), 且 path 指向 .so
        if (!line.contains("r-xp")) continue;
        int slash = line.lastIndexOf('/');
        if (slash < 0 || !line.endsWith(".so")) continue;
        String name = line.substring(slash+1);
        // 取最早的 base
        if (!out.containsKey(name) || out.get(name)[0] > lo)
            out.put(name, new long[]{lo, hi});
    }
    br.close();
    return out;
}

private static String resolveLib(long pc, java.util.Map<String,long[]> ranges) {
    for (java.util.Map.Entry<String,long[]> e : ranges.entrySet()) {
        long[] r = e.getValue();
        if (pc >= r[0] && pc < r[1]) {
            return e.getKey() + "+0x" + Long.toHexString(pc - r[0]);
        }
    }
    return "?";
}
```

### Step 5 — Deploy + 抓一次

```bash
cd lsposed/xhs-capture
./build.sh              # 编译 Java + NDK 一起
adb install -r build/xhs-capture.apk
# 更新 LSPosed db 指向新 apk_path, 2x reboot (参考 docs/43 已有流程)

# 确保 s.xml 没 main_hmac (强制 derive)
adb shell "su -c 'rm -f /data/data/com.xingin.xhs/shared_prefs/s.xml'"
adb shell 'am force-stop com.xingin.xhs'
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
sleep 60   # 等 app 做完首启 bootstrap 触发 derive

# pull
adb shell 'su -c "cp /data/data/com.xingin.xhs/files/main_hmac_writer.log /sdcard/mhw2.log"'
adb pull /sdcard/mhw2.log scratch/persistent_survey/main_hmac_native_stack.log
```

---

## 3. 期望产出样本

`scratch/persistent_survey/main_hmac_native_stack.log`:

```
[HOOK main_hmac_writer] ts=1776500001234
  thread=sky7
  value_prefix=9sQx+OUeOG4/W1OtYjlyPRNG6jZZ
  value_len=128
  stack=
    dalvik.system.VMStack.getThreadStackTrace(Native Method)
    ... (Java stack 同 docs/42)
    com.xingin.shield.http.Native.intercept(Native Method)
    com.xingin.shield.http.XhsHttpInterceptor.intercept(SourceFile:8)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:10)
  native_stack=
    pc=0x76f41000  libnative_stack.so+0x1234   ← 我们自己的 helper
    pc=0x76e01000  libc.so+0x5678              ← _Unwind_Backtrace
    pc=0x76d00000  libart.so+0x9abc            ← CallObjectMethodV
    pc=0x76f41abc  libxyass.so+0x26af0         ← ★ libxyass 调 putString 的 PC
    pc=0x76f41a00  libxyass.so+0x25abc         ← ★ 其上一级函数
    pc=0x76f41900  libxyass.so+0x23f80         ← intercept 内部
    pc=0x76f41e55  libxyass.so+0x23e55         ← intercept 入口
    ...
  sp_file=/data/user/0/com.xingin.xhs/shared_prefs/s.xml
```

对 unidbg 侧最有价值的是 **带 "libxyass.so+0x..." 的行**。

---

## 4. 失败保护

### 4.1 _Unwind_Backtrace 不可用

Android 15 默认带 `libunwind`,但某些压 libc 可能缺。若 `_Unwind_Backtrace` 返空,回退用 frame pointer walk:
```c
// 32-bit ARM: fp 是 r11 (或 r7 if Thumb)
uintptr_t *fp;
__asm__("mov %0, fp" : "=r" (fp));
while (fp && count < MAX_FRAMES) {
    uintptr_t pc = fp[14/4];   // lr 位置, 编译器相关, Android ABI 一般是 fp[-1]
    uintptr_t next = fp[0];
    if (next <= (uintptr_t)fp) break;
    st.pcs[count++] = pc;
    fp = (uintptr_t*)next;
}
```

### 4.2 /proc/self/maps 读不到

如果 hook 进程没权限读自己 maps (罕见),可以在启动时一次性解析 maps 存到 static 字段。

### 4.3 NDK 编译环境

`lsposed/xhs-capture/build.sh` 已经配好 NDK 路径 (`NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/r27c`),沿用。

---

## 5. 我拿到数据后的动作

1. **反汇编 libxyass+0x<PC>**(stack 里第一个 libxyass 行),找 50 条指令范围内的 `cmp`/`bne`/`beq` 分支
2. **追溯分支条件** → 某个变量来源 → 某个 `blx` 调用 → 对应 `env->CallXxxMethodV` 参数
3. **补 JNI stub**(比如发现是 Settings.Secure 返空、或某个 ClassLoader 返 null)
4. **rerun** signer,看 derive 有没进去
5. **理论上 derive 进入后**:
   - 调 MediaDrm → 我们已有 stub 返 aa293284-...
   - 调 `SP.Editor.putString("main_hmac", <derived>)` → 我们 spMap hook 捕获
   - spMap 里 main_hmac 有值 → 删 `MAIN_HMAC_VALUE` 硬编码 → 干线 1 closed

---

## 6. 时间预算

- 写 C helper + Android.mk 调整: **10 分钟**
- NDK 编译 + apk 打包: **5 分钟**
- Java hook 扩展: **10 分钟**
- Deploy + 2x reboot: **5 分钟**
- 抓 + pull: **2 分钟**
- 总计: **~30-40 分钟**

比我盲反 Native.intercept 全域(2-4 小时)快 5-10x。

---

## 7. 交付清单

```
lsposed/xhs-capture/jni/native_stack.c                  (+~30 行)
lsposed/xhs-capture/jni/Android.mk                      (+1 行: LOCAL_SRC_FILES)
lsposed/xhs-capture/src/com/xhs/capture/NativeStack.java (+~10 行)
lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java (+~40 行: resolveLib + hook 扩展)
lsposed/xhs-capture/build/xhs-capture.apk                (包含新 native_stack.so)
scratch/persistent_survey/main_hmac_native_stack.log     (核心交付, ~2 KB)
```

---

## 8. 一句话向上汇报

**已有 Java stack 定位到 `Native.intercept`,但缺 native PC 无法精确反汇编。写个 JNI helper 用 `_Unwind_Backtrace` 拿 native stack,在 putString 命中 "main_hmac" 时一起 log。unidbg 侧拿到 `libxyass+0x???` 的 PC 后只需反汇编 50 条指令就能找到 derive 分支,补 JNI stub 让 Native.intercept 自己 derive,删掉最后一个硬编码。**
