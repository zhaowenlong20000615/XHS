# 小红书 9.19.0 请求头算法逆向完整报告 (v2)

**目标**: com.xingin.xhs v9.19.0 (build 9190807)
**日期**: 2026-04-11
**工具**: Jadx 1.5.5 静态反编译 + mitmproxy 抓包分析 + nm 符号分析
**状态**: 🟢 Java 层已完整映射 | 🟡 native 层需 Frida 动态跟踪

---

## ⚠️ 先修正一个之前的误判

**v1 报告的错误结论**: "小红书绝大多数接口不验证签名"。

**实际情况**:
- 我们之前做的"删签名测试"只针对**`/api/sns/v6/homefeed` 等只读公共接口**，它们确实不验证签名
- **写接口**（发评论、点赞、关注、发笔记、登录等）**大概率会验证**，我们还没测
- 签名是**真实存在且必要的**，上面只是因为某些只读接口服务器放水才"看起来没用"

---

## 🧩 小红书完整的 HTTP 签名架构

小红书的主 API 请求头分三类：

### 类 1: **静态参数**（Java 层纯文本构造）
- `user-agent`, `referer`, `accept-encoding` 等标准 HTTP 头
- `xy-common-params` — 身份信息载体（含 id_token）

### 类 2: **轻签名**（Java 层可见）
- `x-legacy-did` — device id
- `x-legacy-sid` — session id  
- `x-legacy-fid` — foreign id
- `x-b3-traceid` — 客户端生成的 trace id
- `x-xray-traceid` — 客户端生成的 xray id

### 类 3: **重签名**（纯 native，Java 层看不到字符串常量）
- `x-mini-sig` — 请求签名 (SHA256 hex)
- `x-mini-s1` — 会话凭证 (base64)
- `x-mini-gid` — 设备全局 ID
- `x-mini-mua` — 设备指纹 JWT (RSA 签名)
- `shield` — 旧版签名（过渡兼容）
- `xy-direction`, `xy-scene` — 动态运营参数

---

## 🏗️ 完整拦截器链

```
OkHttpClient:
  ┌────────────────────────────────────┐
  │  1. xy-common-params 拦截器        │  ← lba.a0 (paa.a=zlb.j0)
  │     - GET: URL query               │  
  │     - POST: body 字段               │
  │     - 所有: header                  │
  │     - 拼接: k=v&k=v (URL encoded)  │
  └────────────────────────────────────┘
  ┌────────────────────────────────────┐
  │  2. shield 签名拦截器               │  ← com.xingin.shield.http.XhsHttpInterceptor  
  │     - predicate.test(req) 过滤      │
  │     - Native.intercept(chain, ptr)  │  ⚠️ 100% native, 连 chain.proceed 都在 C++
  │     - 添加 `shield: <sig>` header   │
  └────────────────────────────────────┘
  ┌────────────────────────────────────┐
  │  3. Tiny 签名拦截器 (r76.a)         │  ← r76.a "TinyInterceptor"
  │     - 加 x-legacy-did (明文)        │
  │     - 加 x-legacy-sid (明文)        │
  │     - 调 ega.f.j(method, url, body) │  → d3.b(-1750991364) → libtiny.so
  │     - native 返回 Map 含:           │
  │       {x-mini-sig, x-mini-s1,      │
  │        x-mini-gid, x-mini-mua,      │
  │        xy-direction, xy-scene}      │
  │     - 全部注入 request header        │
  └────────────────────────────────────┘
  ┌────────────────────────────────────┐
  │  4. trace-id 拦截器 (zlb.n0)        │
  │     - 若缺 X-B3-TraceId: 生成        │
  │     - 若缺 x-xray-traceid: 生成      │
  └────────────────────────────────────┘
  ... (失败容灾 lba.g / 限流 lba.x / 重试 qba.b / ...)
  ┌────────────────────────────────────┐
  │  N. headers 清除拦截器 (ux8.a0)     │
  │     - 若目标域名不是小红书自家:      │
  │       removeHeader 所有敏感 header  │
  │     (防止 token 泄露到 CDN)         │
  └────────────────────────────────────┘
```

---

## 📋 每个 Header 逐一分析

### `xy-common-params` — **身份认证载体**

**构造位置**: [lba/a0.java](../target/jadx_out/sources/lba/a0.java) → [sba/a.java](../target/jadx_out/sources/sba/a.java) `sba.a.b()` 方法

**Provider**: [zlb/j0.java](../target/jadx_out/sources/zlb/j0.java) (35 字段, `HashMap<String, Function0<String>>`)

**拼接公式**:
```java
StringBuffer sb = new StringBuffer();
for (Map.Entry<String, Function0<String>> e : provider.c(req).entrySet()) {
    sb.append(e.getKey() + '=' + URLEncoder.encode(e.getValue().invoke()) + '&');
}
return sb.toString().trim('&');
```

**Python**:
```python
import urllib.parse
"&".join(f"{k}={urllib.parse.quote_plus(v())}" for k, v in fields.items())
```

**35 个字段完整清单**: 见 `zlb/j0.java` 或附录 1。核心字段：
- **`id_token`** — `UserServiceImpl.getIdToken()` → `ar.d6.A().idToken` → MMKV `login_user_info_kv`
- **`sid`** — `v4b.a.a.a()` → `IUserService.sessionId`
- **`gid`** — `ega.f.d()` → Tiny native 调用
- `deviceId`, `did`, `fid`, `t`, `launch_id`, ...（详见 [附录](#附录-xy-common-params-字段表)）

**放置位置**:
- **GET/DELETE**: URL query string（每字段独立）+ header
- **POST FormBody**: form body 字段 + header
- **POST MultipartBody**: multipart part + header
- **POST JSON**: 只 header

---

### `x-legacy-*` — **明文身份**

**添加位置**: [r76/a.java](../target/jadx_out/sources/r76/a.java) line 32-33

```java
builderNewBuilder.header("x-legacy-did", kka.r.e());          // deviceId
builderNewBuilder.header("x-legacy-sid", z76.q0.f479254a.b()); // sessionId
```

**`x-legacy-fid`** 可能在其他拦截器里添加，或者空字段。

**Python**:
```python
x_legacy_did = str(uuid.UUID(bytes=md5(android_id).digest_for_uuidv3()))
x_legacy_sid = user_info.session_id  # "session.1774780073824545783425"
```

---

### `x-mini-sig`, `x-mini-s1`, `x-mini-gid`, `x-mini-mua`, `shield`, `xy-direction`, `xy-scene` — **Tiny 原生签名**

**🏆 核心发现**: 这 7 个 header **全部由同一个 native 调用生成**，入口是 `ega.f.j()`。

**完整调用链**:

```
1. r76.a.intercept(chain)                                     ← OkHttp 拦截器 (Java)
        │
2.      ▼ 读 request body 为 byte[]
        │
3. ega.f.j(method, url, body)                                 ← Java 入口 (ega/f.java:225)
        │  参数: method, host, path, query, body
        │
4.      ▼
        │
5. d3.b(-1750991364, method, host, path, query, body)        ← Tiny 命令路由 (d3.java:54)
        │
6.      ▼
        │
7. com.xingin.tiny.internal.t.b(-1750991364, args)            ← JNI bridge
        │
8.      ▼
        │
9. libtiny.so — 动态 RegisterNatives 注册的函数               ← Native (不可静态分析)
        │  算法: 内部加密 (非标准 crypto), 输入包含请求元信息 + 设备指纹
        │
10.     ▼
        │
11. 返回 Map<String, String>:
      {
        "x-mini-sig":     "cdab52dd21816a...",  // SHA256 hex (64 chars)
        "x-mini-s1":      "AAsAAAABOZy6...",    // base64 (62 bytes decoded)
        "x-mini-gid":     "7cbc529e2e3e...",    // 56 hex chars = 28 bytes
        "x-mini-mua":     "eyJhIjoiRUNGQU...",  // base64 JWT-like (1 KB)
        "shield":         "<...>",              // 旧版签名 (兼容)
        "xy-direction":   "76",
        "xy-scene":       "fs=1&point=0",
        ...
      }
        │
12.     ▼
        │
13. for (entry : result.entrySet()) {
      builder.header(entry.getKey(), entry.getValue());
    }
```

**关键证据**: [r76/a.java:40-44](../target/jadx_out/sources/r76/a.java)
```java
Map<String, String> map = ega.f.j(request.method(), request.url().toString(), buffer.readByteArray());
if (map != null) {
    for (Map.Entry<String, String> entry : map.entrySet()) {
        builderNewBuilder.header(entry.getKey(), entry.getValue());
    }
}
```

**为什么 Jadx 找不到这些 header 名字**: 因为它们**从来没作为 Java 字符串字面量出现过**！name 和 value 都是在 native 层的 C++ 代码里用 `NewStringUTF` 动态创建的 Map 返回给 Java。

**Tiny 命令 ID `-1750991364`** = `0x97BEA13C`（有符号 32 位 int）
- 这是 Tiny SDK 内部的**函数路由 ID**，每个 native 功能都有一个这样的 int
- 其他已知 ID:
  - `-378830707` = gid 获取 (`d3.b()`)
  - `1140071423` = 字符串加密/解密
  - `617278119` = bytes 加密
  - `-872198405` = bytes 解密
  - `-715706235` = base64 字符串合法性检查

---

### `x-mini-mua` 的 RSA 签名细节

除了 native Tiny 签名外，`x-mini-mua` 的**最后一段**是一个 RSA 签名，这部分**Java 层可见**：

**类**: [com/xingin/tiny/internal/w3.java](../target/jadx_out/sources/com/xingin/tiny/internal/w3.java)

**签名方法 `w3.a(String alias, String data)`**:
```java
// 伪代码（已去除字符串加密）
public static String sign(String alias, String data) {
    PrivateKey key = keystore.getKey(alias, null);   // Android KeyStore
    Signature sig = Signature.getInstance("SHA256withRSA", keystoreProvider);
    sig.initSign(key);
    sig.update(data.getBytes(UTF_8));
    return Base64.encodeToString(sig.sign(), Base64.NO_WRAP);
}
```

**关键细节**:
1. 使用 **Android Keystore System**（硬件级 TEE 保护）
2. **私钥永不出设备**, 即使 Root 也不能 dump 出明文
3. 算法: `SHA256withRSA` (备用 fallback `SHA256withRSA/PSS`)
4. Keystore 实例: 优先 `f141247b`（私有 keystore，可能从 APK 资源加载），否则 `f141249d` (默认 `AndroidKeyStore`)
5. 所有 crypto API 调用经过 `v3/q6` method cache，字符串常量 XOR 加密

**`x-mini-mua` 构造**:
```
1. 构造 JSON payload: {"a":"ECFAAF01","c":N,"k":<pubkey_sha256>,"p":"a","s":<secret>,"u":<uuid>,"v":"2.9.55"}
2. b1 = base64(json_payload)
3. b2 = base64_nowrap(w3.a("<alias>", b1))     ← Android KeyStore RSA
4. x-mini-mua = b1 + "." + b2
```

---

### `shield` 签名

**拦截器**: [com/xingin/shield/http/XhsHttpInterceptor.java](../target/jadx_out/sources/com/xingin/shield/http/XhsHttpInterceptor.java)

**Native 层**: [com/xingin/shield/http/Native.java](../target/jadx_out/sources/com/xingin/shield/http/Native.java)

```java
public class Native {
    static native long initialize(String configPath);
    static native void initializeNative();
    static native Response intercept(Chain chain, long ptr) throws IOException;  // ⚠️ 整个拦截都在 native！
    static native void destroy(long ptr);
}
```

**调用方式**: `XhsHttpInterceptor.intercept(chain)` → `Native.intercept(chain, cPtr)`
- Native 函数直接接收 OkHttp 的 `Chain` 对象
- 在 C++ 里通过 JNI 读 request / 加 header / 调 `chain.proceed()` 发请求
- 返回 `Response` 给 Java

**这是最凶残的设计**: Java 层几乎没有任何业务代码，完全黑盒。

**shield so 文件**: 搜索 `Java_com_xingin_shield_http_Native_*` 符号在所有 .so 里都**没找到** —— 说明和 Tiny 一样用 **动态 `RegisterNatives`**，隐藏静态分析。
- 候选库: `libsecurebase.so`, `libshadowhook.so`, `libSystemHealer.so`（需 Frida 动态验证）

**Shield 初始化阶段**（来自 [ContextHolder.writeLog](../target/jadx_out/sources/com/xingin/shield/http/ContextHolder.java)）:
```
1. nativeInitializeStart
2. nativeInitializeEnd
3. initializeStart
4. initializedEnd
5. buildSourceStart   ← 构造签名输入
6. buildSourceEnd
7. calculateStart     ← 真正计算签名
8. calculateEnd
```

---

### `x-b3-traceid`, `x-xray-traceid` — **客户端 trace id**

**拦截器**: [zlb/n0.java](../target/jadx_out/sources/zlb/n0.java)

**`X-B3-TraceId`** (16 字符 hex):
```java
// 时间戳和随机数按位交错
long ts = System.currentTimeMillis();
long rnd = Random.nextLong();
StringBuffer sb = new StringBuffer();
for (int i = 0; i < 8; i++) {
    sb.append(HEX_CHARS[(int)(ts & 15)]);
    sb.append(HEX_CHARS[(int)(rnd & 15)]);
    ts >>= i * 4;
    rnd >>= i * 4;
}
return sb.toString();
```

**`x-xray-traceid`** (32 字符 hex):
```java
// 格式: %016x%016x
// 第一部分: (ts << 23) | (counter.getAndIncrement() & 0x7FFFFF)
// 第二部分: Random.nextLong()
String.format("%016x%016x", 
    (System.currentTimeMillis() << 23) | (counter & 0x7FFFFF),
    Random.nextLong());
```

Python:
```python
import random, time
def gen_xray_traceid():
    ts = int(time.time() * 1000)
    counter = random.randint(0, 0x7FFFFF)
    rnd = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    return f"{(ts << 23) | counter:016x}{rnd:016x}"
```

---

## 🎯 `gid` (设备 ID) 详细

**调用链**: `zlb.j0` → `ega.f.d()` → `com.xingin.tiny.internal.d3.b()` → `t.b(-378830707, [])` → native

**算法**: 在 `libtiny.so` 里
- 基于硬件特征 (Build.*, android_id, cpu 指纹)
- 首次启动时需**向小红书服务器注册**（tiny SDK 内部有 activate endpoint）
- 结果缓存到本地（MMKV 或 SharedPreferences）
- 实测字符串: `7cbc529e2e3e5495c7fef55d674f81d13df3052947359ec877568100` (56 hex = 28 字节 = SHA224?)

---

## 🎯 `deviceId` (UUID 格式) 算法还原

**文件**: [kka/r.java](../target/jadx_out/sources/kka/r.java) `kka.r.f()`

**算法**:
```python
def xhs_device_id(android_id: str) -> str:
    """UUID v3 (MD5-based), Java UUID.nameUUIDFromBytes(android_id.encode('utf-8'))"""
    md5 = bytearray(hashlib.md5(android_id.encode('utf-8')).digest())
    md5[6] = (md5[6] & 0x0f) | 0x30   # UUID version 3
    md5[8] = (md5[8] & 0x3f) | 0x80   # variant
    return str(uuid.UUID(bytes=bytes(md5)))
```

**验证**: 实抓的 `aa293284-0e77-319d-9710-5b6b0a03bd9c` 第 13 位是 `3` ✅ (UUIDv3 标记)

**伪造性**: ⭐⭐⭐⭐⭐ 极易 (本地生成 + SharedPreferences 缓存)

---

## 🎯 `did` (migo-did) 算法还原

**文件**: [l22/b.java](../target/jadx_out/sources/l22/b.java) `l22.b.b()`

**算法**: 按优先级选一个 ID + 类型后缀 + MD5
```python
def build_local_did(oaid, imei, gid, device_id, android_id) -> str:
    if oaid:
        raw = oaid.replace('-','').replace('_','').lower() + 'oaid'
    elif imei:
        raw = imei.replace('-','').replace('_','').lower() + 'imei'
    elif gid:
        raw = gid.replace('-','').replace('_','').lower() + 'gid'
    elif device_id:
        raw = device_id.replace('-','').replace('_','').lower() + 'deviceid'
    elif android_id:
        raw = android_id.replace('-','').replace('_','').lower() + 'androidid'
    else:
        return str(uuid.uuid4())
    return hashlib.md5(raw.encode('utf-8')).hexdigest()
```

**Source**: 3 种
- `ACTIVATE_SERVER` — 服务器 activate 接口下发
- `DEVICE_PARAMS_SDK` — Tiny SDK 提供
- `LOCAL_GEN` — 上面算法本地生成

**持久化**: MMKV `did_value_manager`

---

## 🎯 登录态存储

**`id_token` 完整链路**:
```
xy-common-params.id_token
  ← UserServiceImpl.getIdToken()
  ← ar.d6.f11924a.A().getIdToken()       [全局单例 d6, A()=当前 UserInfo]
  ← com.xingin.account.entities.UserInfo.idToken  [@td.c("id_token") POJO 字段]
```

**存储位置**: MMKV 实例 `login_user_info_kv`
- 物理路径: `/data/data/com.xingin.xhs/files/mmkv/login_user_info_kv`
- Root 后可直接 pull 并用 [MMKV](https://github.com/Tencent/MMKV) 解析读出 `idToken`

**刷新方式**: App 启动时加载；登录/刷新 token 接口返回后调用 `UserInfo.setIdToken()` 覆写。

---

## 🏴 主 API 网络栈三层结构

小红书不只有一个 OkHttpClient，至少有 **3 套独立的**:

### 栈 1: 主 API (`edith.rnote.com`, `rec.rnote.com`)
- 装配器: 主 App 内部（我们的抓包里最多的请求）
- 拦截器: `lba.a0` (xy-common-params) + `r76.a` (Tiny 签名) + `XhsHttpInterceptor` (shield)
- 用于: 所有核心业务接口

### 栈 2: Hera (`rec.xiaohongshu.com`)
- 装配器: [HeraAbilityImpl](../target/jadx_out/sources/com/xingin/hera/spi/HeraAbilityImpl.java) line 28-68
- 拦截器: 匿名 xy-common-params + `XhsHttpInterceptor.newInstance("hera", ...)` + `r76.a`
- 用于: 独立数据 SDK

### 栈 3: 小程序/Mini App (`xhsminiapp/*`)
- 装配器: [ux8/k.java](../target/jadx_out/sources/ux8/k.java)
- Header: `mp-common-params`（不是 xy-common-params）
- 用于: 小红书内嵌小程序

### 栈 4: Push 子系统 (`com.xhs.push`)
- 装配器: [gqb/p.java](../target/jadx_out/sources/gqb/p.java)
- Provider: `gqb.n`（13 字段，简化版 commonParams）

---

## 🛠️ Frida 动态分析脚本

**位置**: [frida/dump_signing.js](../frida/dump_signing.js)

**捕获的函数**:
1. **`ega.f.j(method, url, body)`** — 所有 Tiny 签名的输入输出
2. **`r76.a.intercept(chain)`** — 拦截器本身
3. **`okhttp3.Request$Builder.header(k, v)`** — 所有 header 添加
4. **`com.xingin.tiny.internal.w3.a(alias, data)`** — RSA 签名

**使用方法**:
```bash
cd /Users/zhao/Desktop/test/xhs/frida
XHS_SCRIPT=dump_signing.js python3 inject.py
# 然后在手机上操作小红书，每个请求都会输出 input/output
```

**输出示例**:
```
======== ega.f.j CALLED ========
  method: GET
  url:    https://edith.rnote.com/api/sns/v6/homefeed?oid=...
  body:   0 bytes
---- signed headers returned ----
  x-mini-sig: cdab52dd21816a74981585c7b5d87ea388c732f11edc5ffa4c83c58e956f825c
  x-mini-s1: AAsAAAABOZy6i/uXAfeHV65TIA+tBsQj0kmJgGI3hna9itmdj8UGDBO0WjEEdbH6OGRUpfBeTornL70CAZI=
  x-mini-gid: 7cbc529e2e3e5495c7fef55d674f81d13df3052947359ec877568100
  x-mini-mua: eyJhIjoiRUNGQU... [1074 chars]
  xy-direction: 76
  xy-scene: fs=1&point=0
================================
```

---

## 🎯 实用路线图

### 路线 A: Sign-as-a-Service（推荐）

**原理**: 让真实运行的 App 当你的签名机，你通过 Frida RPC 把 Python 构造的 (method, url, body) 送进 `ega.f.j`，取回签名 map。

**步骤**:
1. 启动 xhs 并用 Frida 注入 `dump_signing.js` 的变种（暴露 RPC API）
2. Python 脚本通过 `frida.rpc` 调用 `signRequest(method, url, body)`
3. App 在内部计算签名返回 Map
4. Python 把 Map 填进 headers 并发出请求

**优点**: 无需逆向任何 native 算法
**缺点**: 需要一部真机 + Frida + 网络

### 路线 B: 纯本地 Python（需进一步逆向）

**步骤**:
1. 用 Ghidra 打开 `libtiny.so`，找 `JNI_OnLoad` 里的 `RegisterNatives` 调用
2. 定位命令 ID `-1750991364` 对应的函数地址
3. 反编译 ARM 代码，还原签名算法
4. Python 重实现

**优点**: 完全脱离设备
**缺点**: 数天到数周工作量（取决于算法复杂度）

### 路线 C: 混合模式（折中）

- `xy-common-params` 用 Python 构造（35 字段都能本地生成或复用）
- `x-legacy-*` 用 Python 构造
- `x-mini-*`, `shield`, `xy-direction`, `xy-scene` 走 Frida Sign-as-a-Service

---

## 📚 参考源文件（Jadx 产出）

### 主要文件
- [r76/a.java](../target/jadx_out/sources/r76/a.java) ⭐ **主签名拦截器 "TinyInterceptor"**
- [ega/f.java](../target/jadx_out/sources/ega/f.java) ⭐ **Tiny SDK 签名 Java 入口**
- [com/xingin/tiny/internal/d3.java](../target/jadx_out/sources/com/xingin/tiny/internal/d3.java) — Tiny 命令路由
- [com/xingin/tiny/internal/w3.java](../target/jadx_out/sources/com/xingin/tiny/internal/w3.java) ⭐ **RSA 签名器 (x-mini-mua 后半段)**
- [com/xingin/shield/http/XhsHttpInterceptor.java](../target/jadx_out/sources/com/xingin/shield/http/XhsHttpInterceptor.java) ⭐ **Shield 拦截器**
- [com/xingin/shield/http/Native.java](../target/jadx_out/sources/com/xingin/shield/http/Native.java) — Shield native 接口

### xy-common-params 相关
- [zlb/j0.java](../target/jadx_out/sources/zlb/j0.java) — 35 字段 commonParams provider (主栈)
- [gqb/p.java](../target/jadx_out/sources/gqb/p.java) — push 栈 (13 字段)
- [q76/t.java](../target/jadx_out/sources/q76/t.java) — Hera 栈 (匿名 provider)
- [lba/a0.java](../target/jadx_out/sources/lba/a0.java) — 主拦截器 addHeader
- [sba/a.java](../target/jadx_out/sources/sba/a.java) — 字符串拼接工具

### 设备标识
- [kka/r.java](../target/jadx_out/sources/kka/r.java) — deviceId 生成 (UUIDv3)
- [l22/b.java](../target/jadx_out/sources/l22/b.java) — did (migo-did) 生成
- [com/xingin/a/a/f/FingerPrintJni.java](../target/jadx_out/sources/com/xingin/a/a/f/FingerPrintJni.java) — fid (libxyasf.so)

### 账号
- [com/xingin/account/impl/UserServiceImpl.java](../target/jadx_out/sources/com/xingin/account/impl/UserServiceImpl.java)
- [com/xingin/account/entities/UserInfo.java](../target/jadx_out/sources/com/xingin/account/entities/UserInfo.java)

### 其他
- [zlb/n0.java](../target/jadx_out/sources/zlb/n0.java) — trace id 拦截器
- [ux8/a0.java](../target/jadx_out/sources/ux8/a0.java) — 第三方域名 header 清除器
- [ux8/k.java](../target/jadx_out/sources/ux8/k.java) — 小程序网络栈 (mp-common-params)
- [taa/f.java](../target/jadx_out/sources/taa/f.java) — OkHttpClient builder，拦截器链装配

---

## 附录: xy-common-params 字段表

来自 [zlb/j0.java](../target/jadx_out/sources/zlb/j0.java) 的 35 字段（完整）：

| 字段 | 实现 | 值示例 | 备注 |
|---|---|---|---|
| `platform` | 常量 | `android` | |
| `project_id` | 常量 | `ECFAAF` | |
| `app_id` | 常量 | `ECFAAF01` | |
| `versionName` | `un5.c.f415118h` | `9.19.0` | |
| `build` | `kka.e.k(ctx)` | `9190807` | |
| `channel` | `kka.i.a(ctx)` | `YingYongBao` | |
| `origin_channel` | `kka.o1.a(ctx)` | - | |
| `overseas_channel` | `un5.e.e()` | `0` | |
| `lang` | Locale | `zh-Hans` | |
| `mlanguage` | `h87.c.a.b(...)` | `zh_cn` | |
| `dlang` | `o.D()` | `zh` | |
| `deviceId` | `kka.r.e()` | UUID v3 | |
| `did` | `l22.b.a.f()` | MD5 hex | |
| `fid` | `ylb.d6.a.c()` | (空) | |
| **`gid`** | `ega.f.d()` | 56 hex | native |
| **`sid`** | `v4b.a.a.a()` | `session.*` | 登录时下发 |
| **`id_token`** | `UserService.getIdToken()` | 长字符串 | **登录时下发** |
| `t` | `fs5.r.a.e()` | 时间戳 | |
| `launch_id` | `n29.a.b` | 时间戳 | |
| `tz` | `TimeZone.getID()` | `Asia/Shanghai` | |
| `device_model` | `DeviceInfoContainer` | `phone` | |
| `folder_type` | `DeviceInfoContainer` | `none` | |
| `cpu_name` | `kka.o.b.a()` | `oriole` | |
| `cpu_abi` | `z12.h.a.a(ctx)` | - | |
| `device_level` | `lka.e.c(ctx).f266970h` | - | |
| `nqe_score` | `r49.e.a.b()` | - | |
| `teenager` | `d47.u.a.d()` | `0`/`1` | |
| `auto_trans` | `i42.k.a.e()` | `0`/`1` | |
| `uis` | `qvb.c.i(ctx)` | `light`/`dark` | |
| `holder_ctry` | `x69.a.j.d()` | `US` | |
| `active_ctry` | `sr.a.a.g()` | - | |
| `data_ctry` | `x69.a.j.c()` | `SG` | |
| `SUE` | 常量 | `1` | |
| `identifier_flag` | `sr.a.a.i().length > 0 ? "4":"0"` | `4` | |
| `x_trace_page_current` | `n5b.p.b` | `explore_feed` | |
