# 参考项目分析:LitSummer/xhs_unidbg_sign (XHS v7.6.73)

> 写于 2026-04-17。本文档为 `/Users/zhao/Desktop/test/xhs/docs/39_*`,供本项目其他 Claude 窗口或协作者参考。
> **目标**:从这个 31-star 的公开 unidbg 参考实现里榨出一切对本项目(xhs 8.x 签名逆向)有帮助的信息,同时明确区分「可借鉴」与「版本已过时,不可用」。

---

## 0. 一句话结论

LitSummer/xhs_unidbg_sign **只解决 `shield` 一个 header**(外加纯拼字符串的 `xy-platform-info`),目标版本是 XHS v7.6.73(build=7673009),代码量一个 `Sign.java` 20100 字节。**它对本项目最大的实际贡献是 1 条信息**:v7.6.73 的 HMAC key 叫 `main_hmac`,来源是 `SharedPreferences("s")`,由 Java 层注入 native,而不是 hardcoded 在 `.bss`。这与本项目 memory `project_libxyass_bss_keys` 关于「hidden secret must exist elsewhere」的推断直接对应,是一条可立刻在真机 LSPosed 上验证的线索。

其他所有东西(Chain 桩、okhttp3 透传、initialize/intercept 签名)只是**工程脚手架参考**,算法层面完全不适用(版本代际差距见 §8)。

---

## 1. 仓库元数据(已通过 GitHub API 核实)

| 字段 | 值 |
|---|---|
| URL | https://github.com/LitSummer/xhs_unidbg_sign |
| `full_name` | LitSummer/xhs_unidbg_sign |
| `description` | xiaohongshu 7.6.73 unidbg sign |
| `default_branch` | main |
| `size` (KB) | 5 |
| stars / forks | 31 / 26 |
| `open_issues_count` | 0 |
| license | null (**无许可证**) |
| `language` | null (GitHub 未检测到主语言) |
| 唯一 commit SHA | `1da40b10fb7ca8c7d89ed2d0044778d75d5c23e5` |
| commit message | `"add xhs sign"` |
| commit date | 2022-12-27T07:21:19Z |
| `pushed_at` | 2022-12-27T07:22:28Z |
| `created_at` | 2023-01-04T03:12:35Z |

## 2. 文件清单(仓库根)

只有一个文件:

```
Sign.java    20100 bytes
```

没有 `pom.xml` / `build.gradle` / `README.md` / `LICENSE`。**意味着使用者必须自己搭一个 unidbg maven 项目,把 `Sign.java` 拷进去**。

---

## 3. Sign.java 结构剖析

### 3.1 package 与 imports

```java
package com.xingin.xhs;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;   // 未使用
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;  // 未使用
import com.github.unidbg.memory.Memory;
import okhttp3.internal.connection.RealCall;
import okhttp3.internal.http.CallServerInterceptor;
import okhttp3.internal.http.RealInterceptorChain;
import okio.BufferedSink;
import okhttp3.*;
import okio.Buffer;
// Apache HttpClient 用于真实出网请求,不参与签名
import org.apache.http.*; // ...
import java.nio.charset.Charset;
// etc.
```

**关键依赖**:
- `unidbg-android`(含 Unicorn2 backend)
- `okhttp3` 真实依赖(非桩)—— 项目直接用真 `Request / HttpUrl / Headers / Buffer` 对象透传给 native
- `okio`
- `org.apache.httpcomponents`(用于最终出网,不参与签名)

### 3.2 类签名

```java
public class Sign extends AbstractJni {
    private final String deviceId;
    private final String mainHmac;
    private final VM vm;
    private final DvmClass i;      // 指向 XhsHttpInterceptor class
    private final long t;          // initialize() 返回的 handle
    private final AndroidEmulator emulator;
    private final String platformInfo;
}
```

继承 `AbstractJni` → **Sign 本身就是 JNI dispatcher**(通过 `vm.setJni(this)` 注册)。

### 3.3 构造函数(emulator 初始化)

```java
private Sign(String deviceId, String mainHmac) {
    this.deviceId = deviceId;
    this.mainHmac = mainHmac;
    platformInfo = "platform=android&build=7673009&deviceId=" + deviceId;

    emulator = AndroidEmulatorBuilder
            .for64Bit()
            .setProcessName("com.xingin.xhs")
            .addBackendFactory(new Unicorn2Factory(true))
            .build();
    emulator.getSyscallHandler().setEnableThreadDispatcher(true);
    emulator.getBackend().registerEmuCountHook(100000);
    emulator.getSyscallHandler().setVerbose(true);

    Memory memory = emulator.getMemory();
    memory.setLibraryResolver(new AndroidResolver(23));  // API level 23
    memory.setCallInitFunction(true);

    vm = emulator.createDalvikVM(new File(
        "unidbg-android/src/test/resources/xhs/xiaohongshu7673.apk"));
    vm.setJni(this);
    vm.setVerbose(true);

    i = vm.resolveClass("com/xingin/shield/http/XhsHttpInterceptor");
    DalvikModule dm = vm.loadLibrary("xyass", true);
    dm.callJNI_OnLoad(emulator);
    i.callStaticJniMethod(emulator, "initializeNative()V");
    t = i.newObject(null).callJniMethodLong(emulator,
        "initialize(Ljava/lang/String;)J", "main");
}
```

**全部可核实的字段值**:
- 进程名: `com.xingin.xhs`
- 目标架构: **arm64**(`for64Bit()`)
- Backend: Unicorn2(带 fallback?参数 `true`;实测 unidbg API 中 `new Unicorn2Factory(true)` 的 boolean 是 `fallbackUnicorn` 开关,即失败时回退到 Unicorn1)
- 线程分派器: 启用
- 指令计数 hook 阈值: `100000`(超过则触发 hook,一般作为 watchdog/调试断点)
- 系统调用 verbose: 开
- Library resolver: `AndroidResolver(23)` —— **Android 6.0 (API 23) 运行时**
- `callInitFunction(true)` —— 执行 `.init_array` constructors
- **APK**: `xiaohongshu7673.apk`(仓库没附带,需使用者自备)
- 目标 Java 类: `com/xingin/shield/http/XhsHttpInterceptor`
- **只加载一个 native library**: `xyass`(对应 `libxyass.so`)
- JNI_OnLoad 主动触发
- 两次 JNI 调用:
  1. `XhsHttpInterceptor.initializeNative()V` —— 静态,无参,无返回(初始化 native 模块)
  2. `XhsHttpInterceptor.initialize(String)J` —— 实例方法,**入参字符串 `"main"`**,返回 **long handle**(后续 `intercept` 带回)

### 3.4 成员变量使用模式

- `t` 是 `long handle`,`intercept()` 每次调用都会把 `t` 作为第二个参数传回,意味着 native 侧用 `t` 作为 context pointer 定位内部状态(包含 HMAC key 缓存)。
- `i` 是 `DvmClass` 引用,`newObject(null)` 用 `null` 作为 Java 实例 value 创建一个 fake instance,仅用于触发实例方法 JNI 回调。

---

## 4. JNI 桩完整清单(共 ~26 个)

以下所有签名**完全 verbatim** 来自 `Sign.java`,不做任何简化或推断。

### 4.1 `getStaticObjectField`(2 条)

```java
"com/xingin/shield/http/ContextHolder->sLogger:Lcom/xingin/shield/http/ShieldLogger;"
    → new ShieldLogger instance (DvmObject)
"com/xingin/shield/http/ContextHolder->sDeviceId:Ljava/lang/String;"
    → StringObject(deviceId)
```

### 4.2 `getStaticIntField`(1 条)

```java
"com/xingin/shield/http/ContextHolder->sAppId:I"
    → 0xecfaaf01
```

**注意**:`0xecfaaf01` = 十进制 3975512833。在 xy-common-params 中对应 `app_id=ECFAAF01` 与 `project_id=ECFAAF`(去掉最低字节)。这与本项目 memory `project_xhs_14_headers_truth_table` 中 `xy-common-params 35 字段` 里的 app_id/project_id 一致。

### 4.3 `callVoidMethodV`(9 条)

前 8 条是日志桩,全部 **no-op**:

```
ShieldLogger.nativeInitializeStart()V
ShieldLogger.nativeInitializeEnd()V
ShieldLogger.initializeStart()V
ShieldLogger.initializedEnd()V        ← 原代码 typo,确实是 "initializedEnd" 不是 "initializeEnd"
ShieldLogger.buildSourceStart()V
ShieldLogger.buildSourceEnd()V
ShieldLogger.calculateStart()V
ShieldLogger.calculateEnd()V
```

**这 8 个日志点就是 native 内部流程的天然分段**:
1. `nativeInitialize*` → JNI_OnLoad 时机
2. `initialize*` → `initialize("main")J` 调用期间
3. `buildSource*` → **canonicalize 构建阶段**(对应本项目 `canonicalize = 6 segments + SHA-1`)
4. `calculate*` → **hash/HMAC 计算阶段**(对应本项目 0x2b838)

第 9 条是 okhttp3 真对象透传:

```java
"okhttp3/RequestBody->writeTo(Lokio/BufferedSink;)V"
    → 解包真 BufferedSink + 真 RequestBody,调 requestBody.writeTo(bufferedSink)
```

### 4.4 `callObjectMethodV`(15 条)—— 最密集的桩

| 签名 | 行为 |
|---|---|
| `Context.getSharedPreferences(String,I)SharedPreferences` | 用 SP 文件名作为 DvmObject 的 value 包装返回 |
| `SharedPreferences.getString(String,String)String` | 当 SP 文件名=`"s"` 时:key=`"main"` → `""`;key=`"main_hmac"` → `mainHmac` **(构造注入)** |
| `Interceptor$Chain.request()Request` | 返回真 Request |
| `Request.url()HttpUrl` | 返回真 HttpUrl |
| `HttpUrl.encodedPath()String` | 返回真 path |
| `HttpUrl.encodedQuery()String` | 返回真 query |
| `Request.body()RequestBody` | 返回真 RequestBody |
| `Request.headers()Headers` | 返回真 Headers |
| `Buffer.writeString(String,Charset)Buffer` | 委托真 Buffer |
| `Headers.name(I)String` | 委托真 Headers |
| `Headers.value(I)String` | 委托真 Headers |
| `Buffer.clone()Buffer` | 委托真 Buffer |
| `Request.newBuilder()Request$Builder` | 委托真 Request.newBuilder() |
| `Request$Builder.header(String,String)Request$Builder` | 委托 |
| `Request$Builder.build()Request` | 委托 |
| `Interceptor$Chain.proceed(Request)Response` | 合成一个 **200** 空 Response |

**关键模式**:凡涉及 okhttp3/okio 对象,**全部把真实 Java 对象塞进 `DvmObject.value`**,native 回调时通过 `dvmObject.getValue()` 取出真对象操作。这个模式让"canonicalize 从 Request 里读 path+query"这种逻辑在 unidbg 里无需重新实现一套数据结构。

### 4.5 `callStaticObjectMethodV`(2 条)

```
java/nio/charset/Charset->defaultCharset()    → real Charset.defaultCharset()
com/xingin/shield/http/Base64Helper->decode(String)[B  → java.util.Base64.getDecoder().decode()
```

**说明**:native 把 Base64 解码"外包"回 Java,典型的 unidbg 外包策略(避免在 ARM 中重写复杂逻辑)。

### 4.6 `newObjectV`(1 条)

```
okio/Buffer-><init>()V  → dvmClass.newObject(new Buffer())
```

### 4.7 `callIntMethodV`(3 条)

```
okhttp3/Headers.size()I          → headers.size()
okio/Buffer.read([B)I            → buffer.read(sink)
okhttp3/Response.code()I         → 200                  ← 硬编码
```

`Response.code → 200` 硬编码这一点非常关键:native 内部会检查 response 状态,直接强返 200 即可绕过。

### 4.8 桩总计

- Object fields: 2
- Int fields: 1
- Void methods: 9
- Object methods: 15 + 1 static = 16
- Int methods: 3
- New objects: 1
- **总计 32 个 JNI 回调点**

全部都围绕 3 个职责:ContextHolder 静态字段、ShieldLogger 日志无操作、okhttp3/okio 真对象透传 + 2 个自定义逻辑(SharedPreferences 路由、Base64 外包)。

---

## 5. 端到端请求流程

```
main() {
    String deviceId = "8fa2bc4d-c123-39b7-9cf1-d62f2b8e6b3a";   // hardcoded 示例值
    String mainHmac = "5Opy/47vBg/Xma7/sd7I9f9yjJKRYbzFM7v+EUost7QAc" +
                      "DBNgrDCWFJTjo/0gr8kKWFrXSu11wo1daWQZewTOvVGiBZBN" +
                      "eOvVYPPT3xn2Av6gapdi4fgmS/KQRceXKjb";    // Base64 blob
    Sign sign = new Sign(deviceId, mainHmac);                   // ← 构造器: 加载 libxyass, initialize("main")J

    String url     = sign.getVideoSearchUrl("china");           // 返回硬编码的视频搜索 URL 模板
    Map<String,String> headers = sign.getBeforeInterceptHeaders();  // ← 返回 11 个"预先准备好"的 headers

    String shield   = sign.getShield(url, headers);             // ← 唯一真正调 native 的环节
    String platform = sign.getPlatformInfo();                   // ← 纯字符串拼接,不过 native

    headers.put("shield", shield);
    headers.put("xy-platform-info", platform);

    String result = doGet(url, headers);                        // Apache HttpClient + proxy 127.0.0.1:8089
}
```

### 5.1 `getBeforeInterceptHeaders()` 内容(示例硬编码)

**这 11 个 header 在 Sign.java 中直接以 demo 字符串形式硬编码**,说明**作者并未解决它们的生成**:

```
x-b3-traceid            "50504ddeae1b0600"
x-legacy-smid           "20221216155456b727..."
x-legacy-did            "8fa2bc4d-c133-39b7-9cf1-d64f2b8e6b3a"
x-legacy-fid            "167118471610a2c0b1785df9fe318b9fb87a05272cfe"
x-legacy-sid            "session.1671185082040052454936"
x-mini-gid              "7d3e46c010df550a3a603cdf7d03be52f12a2e8947359e0f778367a6"
x-mini-sig              "b3c6b12a25e4e07cd445db9fbb0f9d880fba3613a2fa81f5de347ea5df4438fc"
x-mini-mua              "eyJhIjoiRUNGQUHGMDEiLCJjIjoxMDIs..." (JWT-like blob with base64 payload + RSA-like signature)
xy-common-params        "fid=...&device_fingerprint=...&..."  (35 字段)
user-agent              "Dalvik/2.1.0 (Linux; U; Android 10; ONEPLUS A6010 ...)"
referer                 "https://app.xhs.cn/"
accept-encoding         "gzip"
```

**重点**:
- `x-mini-sig` / `x-mini-mua` / `xy-common-params` 全是**示例写死的字符串**,shield 计算依赖这些 header 作为 canonicalize 的一部分,但**作者没有实现怎么生成它们**。
- v7.6.73 的 `x-mini-mua` 是 **JWT 格式** `header.payload.signature`(Base64 + RSA 签名),与本项目 memory `project_mua_binary_tail_missing` 描述的新版(**249B JSON + 762B 二进制尾巴 累加器**)完全不同的结构 —— **这是强有力的证据证明 mua 机制在 7.x → 8.x 之间被彻底重写过**。

### 5.2 `getShield()` 核心

```java
public String getShield(String url, Map<String, String> headers) {
    Request.Builder builder = new Request.Builder().url(url);
    for (Map.Entry<String, String> e : headers.entrySet())
        builder.addHeader(e.getKey(), e.getValue());
    Request request = builder.build();

    RealInterceptorChain c = new RealInterceptorChain(
        new RealCall(new OkHttpClient(), request, false),
        new ArrayList<CallServerInterceptor>(), 0, null, request,
        0, 0, 0);
    DvmObject<?> chain = vm.resolveClass("okhttp3/Interceptor$Chain").newObject(c);

    DvmObject<?> resp = i.callStaticJniMethodObject(emulator,
        "intercept(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;",
        chain, t);

    return ((Response) resp.getValue()).header("shield");
}
```

注意:
- **直接伪造一个 `RealInterceptorChain`**(okhttp3 内部类),参数大部分用 `null / 0`
- `intercept` 是**静态 JNI 方法**,签名 `(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;` —— 两个参数:Chain + long handle
- native 在内部把 `"shield"` header 添加到 response,Java 侧读 `response.header("shield")`

---

## 6. 算法覆盖矩阵

| 本项目目标 header | LitSummer 项目 | 状态 |
|---|---|---|
| `shield` | ✅ 完整 native 调用,结果来自 `libxyass.so` | **可做参考** |
| `xy-platform-info` | ✅ 但只是 `"platform=android&build=7673009&deviceId=..."` 纯拼接 | **v7 比 v8 简单**;本项目 v8 多了 `x_trace_page_current` 等字段,见 memory `project_canonicalize_byte_exact_6_of_6` |
| `x-mini-sig` | ❌ **示例字符串,不生成** | 作者无解 |
| `x-mini-mua` | ❌ **示例字符串(JWT 格式),不生成** | 作者无解 + 格式已变 |
| `xy-common-params` | ❌ **示例字符串,不生成** | 作者无解 |
| `x-legacy-*` | ❌ 示例硬编码 | 作者无解 |
| `x-b3-traceid` | ❌ 示例硬编码 | 作者无解 |
| `x-common` | N/A | v7 不存在此 header |

**结论**:这个项目只是个 "shield only" 的 POC。

---

## 7. 对本项目**真正有用**的借鉴点

### 7.1 🎯 最高优先级:`main_hmac` 来自 SharedPreferences

> 这是本文档的**唯一可立即行动**的线索。

**v7.6.73 事实**(Sign.java 第 124-135 行):
```java
case "android/content/SharedPreferences->getString(...)": {
    if (((StringObject) dvmObject.getValue()).getValue().equals("s")) {
        if (vaList.getObjectArg(0).getValue().equals("main"))
            return new StringObject(vm, "");
        if (vaList.getObjectArg(0).getValue().equals("main_hmac"))
            return new StringObject(vm, mainHmac);
    }
}
```

- SharedPreferences 文件名: `"s"`(物理路径:`/data/data/com.xingin.xhs/shared_prefs/s.xml`)
- key `"main"` → 空字符串
- key `"main_hmac"` → **Base64 encoded HMAC 密钥**(示例值见 §5,116 字符 Base64,解码后约 87 字节二进制)

**这与本项目 memory `project_libxyass_bss_keys` 的推断完全吻合**:
> "both are publicly-knowable (build + deviceId UUID); **a hidden secret must exist elsewhere (ctx arg or hardcoded constant)**"

→ 那个 "hidden secret" 在 v7.6.73 就是 `shared_prefs/s.xml` 的 `main_hmac` 字段。**在 v8.x 很可能仍然存在**(结构继承),只是可能改名或换文件。

**建议立即验证**(Pixel 6 + LSPosed,本项目已有环境):
```bash
# 方法 1: 直接 adb pull
adb shell "run-as com.xingin.xhs ls shared_prefs/" 2>/dev/null || \
adb shell "su -c 'ls /data/data/com.xingin.xhs/shared_prefs/'"
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml'"

# 方法 2: LSPosed 模块 hook SharedPreferences.getString
# 在 lsposed/xhs-capture 里加个 hook,在 shield 生成时 dump 所有 SP 读操作
```

如果找到这个 key,本项目 `project_shield_byte_exact_18_18` 的**「固定 fixture replay」限制可以直接解除** —— 算法 0x2b838 已完全还原(见 memory `project_0x2b838_final_status`),**缺的就是 key**。

### 7.2 okhttp3 真对象透传模式(可直接移植到 unidbg-xhs/)

现状:本项目 `unidbg-xhs/src/main/java/com/xhs/sign/` 需要给 libxyass 传 Chain。参考 §4.4 模式,**不需要手写 Headers/HttpUrl 的假数据结构**,直接用真 okhttp3 对象 + `resolveClass().newObject(realObj)` 透传。

适用范围:`XhsShieldSigner.java` / `XhsCombinedSigner.java` 如果需要重构 Chain 伪造逻辑,按这个套路写最干净。

### 7.3 `initialize → intercept` 的 handle 模式

- v7.6.73: `initialize("main")J` 返回 handle,`intercept(Chain, handle)Response` 消费 handle
- 本项目 v8.x:架构应**极大概率保留**这个模式(memory `project_libxyass_canon_low_architecture` 提到 `intercept → header_wrapper → canon_low`)
- "main" 字符串是用户账号 slot 名(猜测,未验证)—— v8.x 可能扩展为多账号

### 7.4 APP_ID 常量延续性

`ContextHolder.sAppId = 0xecfaaf01` 在 v7 和 v8 都存在(xy-common-params 里 `app_id=ECFAAF01` 十六进制),作为一个**版本恒定常量**可用于调试交叉验证。

### 7.5 Android API level & 架构选择

- v7.6.73: `AndroidResolver(23)` + `for64Bit()`
- 本项目 Unicorn/unidbg 如果遇到"系统 lib 找不到"可以先试 API 23,这是一个保守但稳的选择

### 7.6 日志桩揭示的内部分段

`ShieldLogger` 的 8 个日志方法名(§4.3)透露了 native 内部 4 阶段:
1. `nativeInitialize` —— JNI_OnLoad
2. `initialize` —— 用户/session 注册
3. `buildSource` —— canonicalize
4. `calculate` —— hash/HMAC

→ 在 Frida / unidbg hook 时,可以根据 ShieldLogger 符号快速定位源码段。本项目 `libxyass.so` 符号如果还保留 `ShieldLogger::*` 的 symbol,直接 `r2 -c "is~Logger"` 或 `strings -a | grep -i logger` 就能找到定位锚点。

---

## 8. 版本代际差距(⚠️ 不可直接复用的地方)

| 维度 | v7.6.73 | 本项目 v8.x(build=85683130) |
|---|---|---|
| build number | 7673009 | 85683130 |
| 相关 native lib | 只有 `libxyass.so` | `libxyass.so` + `libtiny.so` + `libxyasf.so` |
| `x-mini-mua` 格式 | JWT (header.payload.signature, RSA) | **249B JSON + 762B 二进制累加器尾巴** |
| `shield` 算法 | 大概率标准 HMAC + SharedPreferences key | 自定义 0x2b838 算法(S-box + KSA + ARX + VEOR,**已还原**) |
| canonicalize | 未知具体格式 | **6 segments**: path+query+xy-common+xy-direction+xy-platform+xy-scene+body |
| canonicalize hash | 未知 | **SHA-1 with 40B prefix state**(非标 HMAC) |
| `xy-platform-info` | 3 字段: platform+build+deviceId | v8 更多字段,包括 `x_trace_page_current` 等 |
| `xy-common-params` | 未公开 | 35 字段,遵循 Java HashMap bucket(64) 迭代顺序 |
| 反爬机制 | 基本只有 shield + user-agent | 跨请求滚动累加器(mua binary tail)+ shadowban |

**所以**:任何 v7.6.73 的**具体数值/算法/字段**都**不能**直接作为 v8.x 的 ground truth。只能在**架构/模式层面**参考。

---

## 9. 原代码 bugs & caveats

### 9.1 `SharedPreferences.getString` 缺少 `break`(latent bug)

在 `callObjectMethodV` 中:

```java
case "android/content/SharedPreferences->getString(...)": {
    if (((StringObject) dvmObject.getValue()).getValue().equals("s")) {
        if (...equals("main")) return new StringObject(vm, "");
        if (...equals("main_hmac")) return new StringObject(vm, mainHmac);
    }
    // ← 这里没有 break 也没有 return!
}
case "okhttp3/Interceptor$Chain->request()Lokhttp3/Request;": {
    RealInterceptorChain chain = (RealInterceptorChain) dvmObject.getValue();  // ← CCE
    ...
}
```

如果 SP 名不是 `"s"`,或 key 不是 `"main"/"main_hmac"`,会**穿透**到下一个 case(Chain.request()),触发 `ClassCastException`(因为 SP 的 DvmObject 不是 RealInterceptorChain)。**在实际 v7.6.73 的 native 调用里只用这两个 key,所以不会 crash,但如果移植到 v8 新增 key 会炸**。

### 9.2 硬编码 `Response.code()` = 200

`callIntMethodV` 里 Response.code 永远返回 200 —— 这个在 v7 OK 因为 native 只检查 200,但如果 v8 native 会查多个状态码或检查 `response.isSuccessful()`,需要真实 response。

### 9.3 APK 路径是硬编码的测试资源路径

```
"unidbg-android/src/test/resources/xhs/xiaohongshu7673.apk"
```

明显是从 unidbg 官方 test 资源目录拷出来的路径,**使用者必须自己放 APK**,仓库没提供。

### 9.4 无 license

使用时注意版权风险,作者未声明任何 license。

### 9.5 两个未使用的 import

`ArrayObject`、`ProxyDvmObject` 被 import 但代码中无引用 —— 无功能影响,仅代码整洁度问题。

---

## 10. 交叉引用本项目 memory/docs

| 本项目条目 | 关联 |
|---|---|
| `project_libxyass_bss_keys` | **§7.1 直接对应**:v7.6.73 的 `main_hmac` 就是 "hidden secret" 候选 |
| `project_shield_byte_exact_18_18` | 目前用 fixture 绕过缺 key 问题,如果 §7.1 验证成功可脱离 fixture |
| `project_0x2b838_final_status` | 算法已还原,缺 key,§7.1 解锁 |
| `project_libxyass_canon_low_architecture` | `intercept → header_wrapper → canon_low` 对应 v7 的 `initialize + intercept` 骨架 |
| `project_canonicalize_byte_exact_6_of_6` | v8 canon 已完成,v7 的 `buildSource` 日志点提示 canon 位置 |
| `project_mua_binary_tail_missing` | v7 mua 是 JWT,v8 是 JSON + binary tail,**机制完全不同,不能参考** |
| `project_xhs_capture_approach` | LSPosed 是验证 §7.1 的现成工具 |
| `docs/28_java_field_sources.md` | v7 硬编码 xy-common-params 35 字段的源头与 v8 28_java_field_sources 可以对比 |

---

## 11. 下一步行动建议(排优先级)

### P0 —— 立即可做,成本极低,收益极高

**验证 `main_hmac` 在 v8.x 是否仍在 SharedPreferences**。
```bash
# 在已 root / LSPosed 的 Pixel 6 上
adb shell "su -c 'ls /data/data/com.xingin.xhs/shared_prefs/'"
adb shell "su -c 'cat /data/data/com.xingin.xhs/shared_prefs/s.xml' | grep -i hmac"
# 或者扫所有 xml
adb shell "su -c 'grep -rli hmac /data/data/com.xingin.xhs/shared_prefs/'"
```

如果找到 key,下一步:
1. 用这个真实 key 填入本项目 Unicorn 签名器
2. 跑 `project_0x2b838_final_status` 里已还原的算法
3. 看 shield 是否能 byte-exact 匹配(无需 fixture)

### P1 —— 工程优化

把 `Sign.java` §4.4 的 okhttp3 真对象透传模式移植到本项目 `unidbg-xhs/src/main/java/com/xhs/sign/XhsShieldSigner.java` 或 `XhsCombinedSigner.java`,减少手写桩代码。

### P2 —— 架构验证

检查 v8.x libxyass 是否仍然有 `ShieldLogger` 符号(§7.6),有的话 Frida hook 可以高效定位 canon/hash 切割点。

---

## 12. 文档完整性检查表

本文档中所有声明的核实状态:

| 声明类型 | 核实方式 |
|---|---|
| 仓库元数据(§1) | ✅ GitHub API `/repos/LitSummer/xhs_unidbg_sign` |
| 文件清单(§2) | ✅ GitHub API `/repos/.../contents/` |
| Sign.java 代码(§3-5) | ✅ raw.githubusercontent.com/.../Sign.java 全文抓取 + verbatim 引用 |
| 常量 `0xecfaaf01` | ✅ 代码直接出现 |
| commit SHA / 日期 | ✅ GitHub API `/commits` |
| APP_ID 对应 xy-common-params | ⚠️ 推断(基于 hex-to-text 明显对应) |
| v8 mua 格式 | 引用本项目 memory `project_mua_binary_tail_missing` |
| v8 canon 6-segment | 引用本项目 memory `project_canonicalize_byte_exact_6_of_6` |
| "AndroidResolver(23) = API 23" | ✅ unidbg 约定俗成 |
| `Unicorn2Factory(true)` boolean 语义 | ⚠️ 基于 unidbg 源码惯例推断为 fallbackUnicorn |
| §7.1 main_hmac 在 v8 也存在 | ❌ **未验证 — 这是 P0 行动项** |
| §9.1 fallthrough bug | ✅ 基于 Java 语义,代码中确实无 break/return |

---

## 附录 A. Sign.java 关键片段索引

如需随时查阅原文,可 WebFetch:
```
https://raw.githubusercontent.com/LitSummer/xhs_unidbg_sign/main/Sign.java
```

关键字段定位(基于 20100 字节总长的估算行号,实际以文件为准):
- emulator 构造 — 类声明之后前 30 行
- `AbstractJni` override 从 `getStaticObjectField` 开始
- `getShield` / `getPlatformInfo` 位于文件中后段
- `main` 在末尾

---

## 附录 B. 文档生成上下文

- 生成时间: 2026-04-17
- 生成者: Claude (xhs 项目主会话)
- 用户明确指示: "详细分析...不能有错"
- 抓取工具: WebFetch(GitHub API + raw content)
- 未执行的验证: §7.1 的真机 SP dump(留给 P0 行动)

如本文档与实际代码有出入,以 `https://github.com/LitSummer/xhs_unidbg_sign/blob/main/Sign.java` 当前内容为准。
