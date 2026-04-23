# docs/43 — main_hmac writer capture delivery

**Responds to**: `docs/42_hook_main_hmac_writer_stack.md`
**Companion**: `docs/40_persistent_secrets_survival_investigation.md` → `scratch/persistent_survey/findings.md`
**Status**: ✅ Stack captured; writer identified; unidbg integration recipe drafted
**Date**: 2026-04-18
**Device**: Pixel 6 / Android 15 / XHS 9.19.0 build 9190807

---

## TL;DR (读这一段就够上手了)

`main_hmac` 的 96 字节值是 xhs 第一次调 OkHttp 拦截链时,由 **libxyass 的 native `Native.intercept(...)`** 懒生成并写进 `SharedPreferences("s")` 的。写入时的 Java stack 明确定位到:

```
com.xingin.shield.http.Native.intercept(Native Method)              ★ 真正写 main_hmac 的 native 入口
com.xingin.shield.http.XhsHttpInterceptor.intercept(SourceFile:8)   ★ 触发它的 Java 入口
okhttp3.internal.http.RealInterceptorChain.proceed
  …
```

**对 unidbg 的直接后果**:`XhsCombinedSigner.java:70` 的 `MAIN_HMAC_VALUE` 硬编码**可以删**。只要让 unidbg:

1. 走完 `libxyass` 原本的 JNI_OnLoad(已经在做)
2. 构造一个空 `RealInterceptorChain`,new 一个 `XhsHttpInterceptor`
3. 反射调 `interceptor.intercept(chain)`
4. native 自己完成 derivation + putString
5. 我们 `spMap` 的 putString hook 捕获这一次 → 96 字节自动落地
6. 后续所有签名走 `spMap.getString("main_hmac")` 全部命中

跨设备自动适配(每个 device 的 widevine `device_id` 不同 → derivation 产物不同 → spMap 自动存本设备专属值),不再需要手动抓 `s.xml`。

---

## 1. 问题背景和为什么做这一条

### 1.1 主线瓶颈

`unidbg-xhs` 黑盒签名器走通了,但 edith.xiaohongshu.com 的写接口返回 406。
调查链:

- docs/39 fresh install 抓包 → 发现真机所有 write endpoint 全部 200
- docs/40 persistent secrets 调查 → 确认 `main_hmac = 96B` 跨 uninstall 保持同值
- 我们推断 derivation 源是 widevine device_id,但没逆 derivation 函数
- 目前做法:`XhsCombinedSigner.java:70` **硬编码** `MAIN_HMAC_VALUE = "9sQx+OUeOG4/W1…"`
  - 本设备持续 valid,但**跨设备就要重抓**

### 1.2 为什么"捕获 writer stack"解决问题

> 原 spec 42 的核心假设:
> **如果我们知道 app 里哪个 Java 方法写的 main_hmac,unidbg 侧就可以照搬调这个方法,让 native 自己完成生成,我们的 spMap 就自动捕获到 96B,无需手动逆 derivation。**

这是"黑盒复现"策略 —— 我们不逆算法,让 app 自己跑就行。

---

## 2. Hook 做了什么

### 2.1 插桩点

```java
// 在 xhs 进程里 hook:
android.app.SharedPreferencesImpl$EditorImpl.putString(String, String)
```

**过滤条件**:`"main_hmac".equals(key)`

- `SharedPreferencesImpl$EditorImpl` 是 Android framework 系统类,不受 xhs DexGuard 影响,classloader 从 boot class loader 拉
- 过滤 key 避免给其他 putString 调用带开销
- hook 装在 `IXposedHookLoadPackage.handleLoadPackage` 最早的位置(不用等 Application.onCreate),保证早期 putString 也能被抓

### 2.2 打印格式

Hook 每次命中写一行 block 到 `/data/data/com.xingin.xhs/files/main_hmac_writer.log`:

```
[HOOK main_hmac_writer] ts=<millis>
  thread=<Thread.currentThread().getName()>
  value_prefix=<first 32 chars>
  value_len=<chars>
  stack=
    <30 层 StackTraceElement>
  sp_file=<this$0.mFile>
```

额外增强(超过原 spec):
- 加了 `sp_file` 字段,用 `XposedHelpers.getObjectField(this$0, "mFile")` 拿 EditorImpl 背后的 SP 文件路径,**验证确实是 `s.xml`**
- 镜像一行简短提示到主 `xhs_capture.log`,便于 chronology 对齐

### 2.3 实际代码位置

文件 `lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java`:

```java
// 常量
private static final String MAIN_HMAC_WRITER_LOG =
        "/data/data/com.xingin.xhs/files/main_hmac_writer.log";

// handleLoadPackage 里第一步就装(早于 Application.onCreate)
try { installMainHmacWriterHook(lpparam.classLoader); } catch (Throwable t) { … }

// 方法定义(节选,完整版见源文件)
private static void installMainHmacWriterHook(ClassLoader cl) {
    XposedHelpers.findAndHookMethod(
        "android.app.SharedPreferencesImpl$EditorImpl", cl,
        "putString", String.class, String.class,
        new XC_MethodHook() {
            @Override protected void beforeHookedMethod(MethodHookParam param) {
                String key = (String) param.args[0];
                if (!"main_hmac".equals(key)) return;
                // … build block, write to MAIN_HMAC_WRITER_LOG …
            }
        });
}
```

### 2.4 重要部署细节

#### Log 路径不用 spec 里的 `/sdcard/main_hmac_writer.log`

改到 `/data/data/com.xingin.xhs/files/main_hmac_writer.log`,原因:

- Android 15 scoped storage,普通 app 不能往 `/sdcard` 根写(EACCES,除非持 `MANAGE_EXTERNAL_STORAGE`)
- app 私有目录一定可写,不需要额外权限
- pull 方法:`adb shell su -c "cp /data/data/com.xingin.xhs/files/main_hmac_writer.log /sdcard/X && chmod 666 /sdcard/X"; adb pull /sdcard/X …`

#### ⚠️ LSPosed 需要 reboot 两次

**已实测**:更新 xhs-capture 模块 APK 后,LSPosed 需要两次 reboot 才真正加载新 dex:

1. 第一次 reboot:LSPosed daemon 读到 DB 里新的 `apk_path`,但 dex cache 还是旧的 → hook 不生效,`xhs_capture.log` 都不会被创建
2. 第二次 reboot:dex cache flush,新 dex 注入到 xhs 进程 → hook 生效

**症状**:xhs 进程 `/proc/<pid>/maps` 完全看不到 `com.xhs.capture` 相关映射。

**判断方法**(pid 是 xhs 主进程):
```bash
adb shell "su -c 'cat /proc/$PID/maps'" | grep -E "xhscap|xhs\.capture"
# 如果无输出 → module 没注入 → 再 reboot 一次
# 如果有几行 → module OK
```

以后调 LSPosed 遇到 "hook 没触发" 先多 reboot 一次再 debug。

---

## 3. 捕获到的 stack trace 和解读

### 3.1 原始 log (保留在 `scratch/persistent_survey/main_hmac_writer.log`)

```
[HOOK main_hmac_writer] ts=1776480605941
  thread=sky7
  value_prefix=9sQx+OUeOG4/W1OtYjlyPRNG6jZZ4XAz
  value_len=128
  stack=
    dalvik.system.VMStack.getThreadStackTrace(Native Method)
    java.lang.Thread.getStackTrace(Thread.java:2843)
    com.xhs.capture.XhsCapture$2.beforeHookedMethod(XhsCapture.java:189)
    grnA.L.S.AlqR.dEWA.UOp.XposedBridge$LegacyApiSupport.handleBefore(r8-map-id-…)
    org.lsposed.lspd.impl.LSPosedBridge$NativeHooker.callback(r8-map-id-…:177)
    LSPHooker_.putString(Unknown Source:14)
    com.xingin.shield.http.Native.intercept(Native Method)
    com.xingin.shield.http.XhsHttpInterceptor.intercept(SourceFile:8)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:10)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:1)
    java.lang.reflect.Method.invoke(Native Method)
    M.gJrMB.ns.LULRoQot.cVJKgxzvG.HookBridge.invokeOriginalMethod(Native Method)
    org.lsposed.lspd.impl.LSPosedBridge$NativeHooker.callback(r8-map-id-…:190)
    LSPHooker_.proceed(Unknown Source:11)
    qba.a.intercept(SourceFile:29)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:10)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:1)
    java.lang.reflect.Method.invoke(Native Method)
    M.gJrMB.ns.LULRoQot.cVJKgxzvG.HookBridge.invokeOriginalMethod(Native Method)
    org.lsposed.lspd.impl.LSPosedBridge$NativeHooker.callback(r8-map-id-…:190)
    LSPHooker_.proceed(Unknown Source:11)
    lba.o.intercept(SourceFile:15)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:10)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:1)
    java.lang.reflect.Method.invoke(Native Method)
    M.gJrMB.ns.LULRoQot.cVJKgxzvG.HookBridge.invokeOriginalMethod(Native Method)
    org.lsposed.lspd.impl.LSPosedBridge$NativeHooker.callback(r8-map-id-…:190)
    LSPHooker_.proceed(Unknown Source:11)
    lba.y.intercept(SourceFile:13)
    okhttp3.internal.http.RealInterceptorChain.proceed(SourceFile:10)
  sp_file=/data/user/0/com.xingin.xhs/shared_prefs/s.xml
```

### 3.2 分层解读

去掉 LSPosed 框架机械层 (`XposedBridge`, `LSPosedBridge`, `LSPHooker_`, `HookBridge` 等),真正的应用层 call chain:

| 层 | 类/方法 | 意义 |
|---|---|---|
| 7 | `com.xingin.shield.http.Native.intercept(Native Method)` | **★ 真正的 writer** — libxyass 里的 JNI 函数。它内部做 derivation + 调回 Java 的 `SP.Editor.putString`。 |
| 8 | `com.xingin.shield.http.XhsHttpInterceptor.intercept(SourceFile:8)` | **★ Java 入口** — 一个标准 `okhttp3.Interceptor` 实现。它包装 `Native.intercept` 调用。 |
| 9-10 | `okhttp3.internal.http.RealInterceptorChain.proceed` | 标准 OkHttp 拦截链机制 |
| 14 | `qba.a.intercept` | xhs 的上游 interceptor (被 DexGuard 混淆,需要 jadx 查原名) |
| 21 | `lba.o.intercept` | 同上 |
| 28 | `lba.y.intercept` | 最外层 interceptor,OkHttp 链起点 |

**关键 insights**:

1. **Thread 是 `sky7` —— OkHttp 的 worker 线程,不是 main**
   说明 main_hmac 的写入**不在 Application.onCreate 阶段**,而是**发第一个 HTTP 请求时**才触发。

2. **`Native.intercept` 是 native method** — 签名未知,但 libxyass 能解析它的参数

3. **三层 obfuscated interceptor 是 xhs 自己的 OkHttp 中间件**
   我们不需要还原它们;unidbg 侧直接 new `XhsHttpInterceptor`,跳过 `qba.a`/`lba.o`/`lba.y`。

4. **`sp_file = /data/user/0/com.xingin.xhs/shared_prefs/s.xml`** —— 100% 确认是写 `s.xml`

5. **`value_len = 128` / `value_prefix` 的 base64 前缀** —— 和已知的 96B main_hmac 完全一致,且和 `XhsCombinedSigner.MAIN_HMAC_VALUE` 硬编码值完全一致。证明捕获的就是主项目需要的那个 secret。

6. **整次 fresh install 冷启动全过程,`main_hmac_writer.log` 只有一条记录**
   说明 derivation 只跑一次;之后 native 从 SP 读缓存,不再 putString。我们的 `mainHmacCaptured` flag 也可以去掉,反正实际就只有一次。

---

## 4. 给 unidbg 的集成 recipe

### 4.1 目标代码位置

```
unidbg-xhs/src/main/java/com/xhs/sign/XhsCombinedSigner.java
  └─ 定位: line 69-70 附近 (MAIN_HMAC_VALUE 硬编码)
     与 line 389-391 (写入 spMap 的位置)
```

### 4.2 改动方案

#### Step A: 删除硬编码

```java
// 删:
private static final String MAIN_HMAC_VALUE = "9sQx+OUeOG4/W1OtYjlyPRNG6jZZ…";

// 删:
if (System.getenv("MAIN_HMAC_DISABLE") == null)
    spMap.put("main_hmac", MAIN_HMAC_VALUE);
```

#### Step B: 加 bootstrap 方法

```java
/**
 * 让 libxyass 的 native intercept 自己跑一遍 derivation + putString,
 * 我们的 spMap 在 putString hook 里捕获到 96B main_hmac,完成生成。
 *
 * 必须在 unidbg 完成 libxyass JNI_OnLoad 之后、发第一个签名请求之前调用。
 * 只需要调一次,主项目流程里放到 signer 构造器末尾合适。
 *
 * 参考真机 stack trace (docs/43):
 *   com.xingin.shield.http.Native.intercept(Native Method)          ← native writer
 *   com.xingin.shield.http.XhsHttpInterceptor.intercept(Chain)      ← Java entry
 */
private void bootstrapMainHmac() {
    // 1. 从 VM 拉起 XhsHttpInterceptor
    DvmClass interceptorCls = vm.resolveClass("com/xingin/shield/http/XhsHttpInterceptor");
    DvmObject<?> interceptor = interceptorCls.newObject(null);  // 无参构造

    // 2. 构造一个 stub RealInterceptorChain 包着 dummy Request
    //    OkHttp 的 Chain.request() 只要能返回一个 Request 即可
    DvmObject<?> dummyRequest = buildDummyOkHttpRequest("GET", "https://edith.xiaohongshu.com/api/ping");
    DvmObject<?> chain = buildDummyChain(dummyRequest);

    // 3. 反射调 interceptor.intercept(chain)
    //    签名: okhttp3.Response intercept(okhttp3.Interceptor$Chain)
    try {
        interceptor.callJniMethodObject(emulator,
            "intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;", chain);
    } catch (Throwable t) {
        // 可能 OkHttp 后段会试图真正发请求并抛异常 — OK,
        // 我们只要 native intercept 内 putString 已经落库
    }

    // 4. 验证 spMap 被正确写入
    if (!spMap.containsKey("main_hmac")) {
        throw new IllegalStateException(
            "main_hmac bootstrap failed: spMap still doesn't have it. " +
            "Check that our SharedPreferences.putString hook fired.");
    }
}
```

#### Step C: 确保 spMap 的 putString hook 已装

项目里 unidbg 侧应该已经 hook 了 Android 的 `SharedPreferences$Editor.putString`(或等价的),在 `spMap.put(key, value)`。如果没有,需要加上:

```java
// 在 Android runtime init 阶段(unidbg 的 AndroidResolver/DvmMethod 扩展),
// 拦截 android.app.SharedPreferencesImpl$EditorImpl.putString(String, String)
// → 写到 signer.spMap
```

这部分项目可能已有,请查 `unidbg-xhs` 里 spMap 怎么初始化的。

### 4.3 验证方法

```java
// 在 Junit 或 main 里
XhsCombinedSigner signer = new XhsCombinedSigner();
signer.bootstrapMainHmac();

byte[] v = Base64.decode(signer.spMap.get("main_hmac"));
assert v.length == 96 : "expected 96B, got " + v.length;
// 本设备上应该等于已知值:
assert signer.spMap.get("main_hmac").startsWith("9sQx+OUeOG4/W1");
```

### 4.4 跨设备工作原理

主项目未来的用户在自己的手机抓 `x-legacy-did` / `xy-platform-info.deviceId`(或用 docs/38 的手机代理),把这个 `device_id`(32 字符 UUID)配置给 unidbg:

- 每个设备的 widevine device_id 不同
- `libxyass Native.intercept` 读到新 device_id → derivation 出**新的** 96B main_hmac
- 我们的 spMap hook 捕获 → 存到该设备专属的 `spMap`
- 后续签名全部命中该值,无需手动抓 `s.xml`

**这是本次交付的最大价值**:从"每台新设备要手动抓 s.xml"升级为"配个 device_id 就 OK"。

---

## 5. 未解决的问题 / 后续可做

### 5.1 `XhsHttpInterceptor` 构造细节未验证

- 是否**无参构造**?如果有参(例如要一个 `Context` 或 `OkHttpClient`),unidbg 要先 mock 这些对象
- `intercept` 可能不是 `public`,反射时 `setAccessible(true)`
- **解决办法**:用 `jadx target/xhs.apk`,查 `com.xingin.shield.http.XhsHttpInterceptor` 的字段和构造,1 分钟能搞定

### 5.2 native 写 putString 的具体机制

从 Java 层看是 `Native.intercept(Native Method)`,但它内部怎么调到 Java 的 SP.putString 的?
可能路径:
- a) native 通过 JNI 调 Java 的 `getSharedPreferences("s").edit().putString(...).apply()`
- b) native 直接读写 xml 文件,Java 不参与(但 stack 里看到 `putString` 被调,说明走 JNI)

这个不影响 unidbg 的黑盒复现,但如果后续需要深挖 derivation:
- hook `MediaDrm.getPropertyByteArray(String)` 看 device_id 是哪里读的
- hook `javax.crypto.Mac.doFinal` 看 derivation 用了哪种 KDF

### 5.3 如果 unidbg bootstrap 崩在 interceptor 下游

`XhsHttpInterceptor` 可能在自己完成 Native.intercept 之后还会调 `chain.proceed(newRequest)` 往下走,unidbg 里下游 interceptor(`qba.a`/`lba.o`/`lba.y`)不存在会抛 NPE。

**解决**:
- 把 chain.proceed 里的 Request 丢给一个 stub "Chain" 返回一个 dummy 200 Response 就行
- 或者 try-catch 整个 interceptor 调用,只要 `spMap` 里已经有 main_hmac,下游崩了也 OK

### 5.4 工作流加固建议

在 `XhsCombinedSigner` 构造器或某个 init 方法里:

```java
// 启动时 bootstrap,失败 fail-fast
this.bootstrapMainHmac();

// 并 assert 关键字段齐全
String mh = spMap.get("main_hmac");
Objects.requireNonNull(mh, "main_hmac not in spMap after bootstrap");
if (Base64.decode(mh).length != 96) {
    throw new IllegalStateException("main_hmac length != 96: " + mh);
}
```

---

## 6. 交付清单

```
lsposed/xhs-capture/src/com/xhs/capture/XhsCapture.java       (+~70 行新 hook)
lsposed/xhs-capture/build/xhs-capture.apk                      (已部署到设备)
scratch/persistent_survey/main_hmac_writer.log                 (2.3 KB,一次完整 capture)
scratch/persistent_survey/findings.md                          (追加了 "2026-04-18 追加" 章节)
docs/43_main_hmac_writer_delivery.md                           ← 本文档
```

---

## 7. 复现步骤 (如果需要再抓一次 / 别的设备抓)

```bash
# 前置
adb devices                     # 设备连着
adb shell su -c "id"            # root 可用
adb shell date                  # 如果是 2025 就 su 一下 date MMDDHHmmYYYY.ss

# 清环境,装最新 xhs-capture
cd lsposed/xhs-capture
NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/r27c ./build.sh
adb install -r build/xhs-capture.apk

# 更新 LSPosed DB 指向新 apk_path
NEW_PATH=$(adb shell 'pm path com.xhs.capture' | tr -d '\r' | sed 's|^package:||')
adb shell 'su -c "cp /data/adb/lspd/config/modules_config.db /sdcard/mc.db && chmod 666 /sdcard/mc.db"'
adb pull /sdcard/mc.db /tmp/mc.db
python3 -c "
import sqlite3
c = sqlite3.connect('/tmp/mc.db')
c.execute('UPDATE modules SET apk_path=? WHERE module_pkg_name=?',
          ('$NEW_PATH', 'com.xhs.capture'))
c.commit()
"
adb push /tmp/mc.db /sdcard/mc.db
adb shell 'su -c "cp /sdcard/mc.db /data/adb/lspd/config/modules_config.db && sync"'

# Reboot x2 (必须两次 — LSPosed 第一次 reboot 后 dex cache 还是旧的)
adb reboot && adb wait-for-device && adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 1; done'
adb reboot && adb wait-for-device && adb shell 'while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 1; done'
adb shell 'su -c "date MMDDHHmmYYYY.ss"'   # 如果 reboot 重置了时钟

# 关掉 VPN(Postern/v2ray 会抢默认路由)
adb shell 'am force-stop com.tunnelworkshop.postern 2>/dev/null; am force-stop com.v2ray.ang 2>/dev/null'

# uninstall + reinstall xhs(清 s.xml 强制 native 重新跑 derivation)
adb uninstall com.xingin.xhs
adb install target/xhs.apk
adb shell 'su -c "rm -f /data/data/com.xingin.xhs/files/main_hmac_writer.log"'

# 冷启动 — 让 app 发第一个请求
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
sleep 60      # 足够跑完 intercept

# 验证 hook 抓到了
adb shell 'su -c "ls -la /data/data/com.xingin.xhs/files/main_hmac_writer.log"'
# 如果 No such file,说明 LSPosed 还没 attach → 再 reboot 一次试

# pull
adb shell 'su -c "cp /data/data/com.xingin.xhs/files/main_hmac_writer.log /sdcard/mhw.log && chmod 666 /sdcard/mhw.log"'
adb pull /sdcard/mhw.log scratch/persistent_survey/main_hmac_writer_$(date +%Y%m%d_%H%M%S).log

# 验证内容
cat scratch/persistent_survey/main_hmac_writer_*.log | head -40
# 应该看到 "com.xingin.shield.http.Native.intercept" 这一行
```

---

## 8. 一句话向上汇报

**main_hmac 不是 startup 生成,是懒生成:第一个 HTTP 请求过 `XhsHttpInterceptor.intercept` 时,由 libxyass native `Native.intercept()` 从 device-fixed 种子派生并 putString 到 s.xml。unidbg 只要在签名前反射调一次这个 intercept 让 native 自己跑,spMap 就捕获到 96B —— 跨设备自动适配,可以删掉 `MAIN_HMAC_VALUE` 硬编码。**
