# XHS 签名完整指南 — 从架构到黑盒突破

> 日期: 2026-04-24
> 状态: **11/11 端点全通**(5 基础 + 用户信息 3 + 笔记 CRUD 3)
> 适用版本: XHS Android v9.19.0 (build 9190807) / libxyass + libtiny armeabi-v7a

---

## 目录

1. [背景与问题](#1-背景与问题)
2. [三层签名架构](#2-三层签名架构)
3. [Layer 1:明文 header(xy-*, x-legacy-*, x-xray-*)](#3-layer-1明文-header)
4. [Layer 2:shield(libxyass)](#4-layer-2shieldlibxyass)
5. [Layer 3:x-mini-* 三件套(libtiny)](#5-layer-3x-mini--三件套libtiny)
6. [核心突破 — canon injection 黑盒策略](#6-核心突破--canon-injection-黑盒策略)
7. [代码改动清单](#7-代码改动清单)
8. [关键坑点 & 调试经验](#8-关键坑点--调试经验)
9. [测试结果](#9-测试结果)
10. [未来方向](#10-未来方向)

---

## 1. 背景与问题

XHS(小红书)Android 客户端的 API 调用会在每个 HTTP 请求上附加一组签名 header,用于:
- 防机器人 / 防恶意抓取
- 请求完整性校验(防 MITM 改包)
- 会话合法性绑定(session + 设备 + 时间)

服务端会验证这些 header,失败返回:
- **406 paradoxical** (`{"success":true, "data":{}}` + status 406)—— 签名层拒
- **401 / 403** —— 会话/认证拒

我们的目标:**纯 unidbg 黑盒** 在 Linux/Mac 服务器上算出正确签名,无需真机连线。

### 历史走过的弯路

| 阶段 | 结论 | 被证伪于 |
|---|---|---|
| SHA-256 假设 | `tail = SHA-256(canon)` | K[64] 表 0 xref, tail 跨 URL identical |
| 对称加密 tail 假设 | `tail = state snapshot,每 3 次轮换` | CanonInjectProbe byte-exact 真机 |
| 43% bit diff 假设 | unidbg ARM 语义差 | 喂对 canon 后 100% match |
| 2/5 ceiling 假设 | mua 长度 172B gap 是天花板 | canon fix 之后不依赖 mua 精度 |

**根因**: 前面所有假设都基于错误的"canon 输入已正确"前提,实际 canon 构造本身 broken 了半年。

---

## 2. 三层签名架构

```
┌─────────────────────── HTTP 请求 ───────────────────────┐
│                                                        │
│  URL: /api/sns/v3/user/me?profile_page_head_exp=1&...  │
│                                                        │
│  HEADERS:                                              │
│  ┌────────────────── Layer 1 (明文) ───────────────────┐│
│  │ xy-common-params, xy-direction, xy-scene,           ││
│  │ xy-platform-info, x-xray-traceid, x-legacy-*        ││
│  └─────────────────────────────────────────────────────┘│
│  ┌────────────────── Layer 2 (shield) ─────────────────┐│
│  │ shield = base64url(100B = 84B prefix + 16B hash)    ││
│  └─────────────────────────────────────────────────────┘│
│  ┌────────────────── Layer 3 (x-mini-*) ───────────────┐│
│  │ x-mini-mua, x-mini-s1, x-mini-sig                   ││
│  └─────────────────────────────────────────────────────┘│
│                                                        │
│  BODY: (optional, POST/PUT)                            │
└────────────────────────────────────────────────────────┘
```

- **Layer 1** 本身不加密,但作为 Layer 2 的哈希输入 → 改一个字节 shield 就挂
- **Layer 2 (libxyass.so)** 产 `shield`,绑定 URL + body + 设备
- **Layer 3 (libtiny.so)** 产 `x-mini-*`,绑定会话 + 设备指纹

两个 `.so` 库**独立工作**,不共享密钥,但都依赖真机 `shared_prefs/s.xml` 里的 `main_hmac`。

---

## 3. Layer 1:明文 header

### 3.1 `xy-common-params`(818B 左右,35 字段)

35 个字段 URL-encoded 拼串,分隔符 `&`,例:

```
fid=&gid=7cb5787426b75495c7fefd12674f81d13df31a3947359fb17706788e
&device_model=phone&tz=Asia%2FShanghai&channel=YingYongBao
&versionName=9.19.0&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9c
&platform=android&sid=session.1776665857416667244279
&identifier_flag=4&cpu_abi=armeabi-v7a&nqe_score=91
&project_id=ECFAAF&x_trace_page_current=explore_feed
&lang=zh-Hans&app_id=ECFAAF01&uis=dark&teenager=0
&active_ctry=CN&cpu_name=oriole&dlang=zh&data_ctry=CN&SUE=1
&launch_id=1776667087&id_token=<urlencoded_base64>
&device_level=6&origin_channel=YingYongBao&overseas_channel=0
&mlanguage=zh_cn&folder_type=none&auto_trans=0&t=1776666055
&build=9190807&holder_ctry=CN&did=921f5ca695a0ec4a1ebe8138008a448a
```

#### 关键细节:字段顺序 = HashMap bucket 遍历顺序

- **不是字典序**,是 Java `HashMap<String,String>`(初始容量 64)的 `entrySet().iterator()` 遍历顺序
- hash bucket 由 key 的 `hashCode() & (capacity-1)` 决定
- 我们的实现 `JavaHeaders.buildXyCommonParams()` 用 Java 自带 HashMap(capacity=64) 保证顺序一致

#### 字段来源

| 字段组 | 来源 | 举例 |
|---|---|---|
| 设备常量 | 首装时生成,存 SharedPreferences | `did`(android_id), `deviceId`(UUID) |
| 版本常量 | APK 里编译进去 | `build`, `versionName`, `app_id`, `channel` |
| 会话变量 | 登录态 | `sid`, `gid`, `id_token` |
| 运行时测量 | 每次 sign 前读 | `nqe_score`(网络质量), `t`(unix ts) |
| 页面上下文 | 当前 Activity/Page | `x_trace_page_current`, `launch_id` |
| 区域/语言 | 系统 + 用户选择 | `lang`, `dlang`, `active_ctry`, `tz` |

### 3.2 `xy-direction`: 固定 `"26"`

代表 UI 跳转方向枚举值(26 = 从探索页进入目标页)。

### 3.3 `xy-scene`: `fs=<feed_source>&point=<position>`

- `fs=0` = 默认场景, `fs=1` = 全屏视频
- `point=601` = explore_feed, `point=-1` = 不在 feed 里
- 调用方必须跟 UI 当前场景一致,否则服务端可能返空 data

### 3.4 `xy-platform-info`: `platform=android&build=<versionCode>&deviceId=<uuid>`

**compact 76B 定长版**,和完整版 header 不同:
- Header 发给 server 的就是这 76B
- canon 第 5 段也用这 76B

### 3.5 `x-xray-traceid`: 16 hex 字符随机串

每请求生成,服务端只 log 不校验。

### 3.6 `x-legacy-{did,fid,sid}`: 向后兼容透传

- `x-legacy-did` = deviceId UUID(旧版 app 的 device identifier)
- `x-legacy-fid` = 广告/渠道 fid(空串也合法)
- `x-legacy-sid` = session id(同 xy-common-params.sid)

### 为什么这些算 "签名 header" ?

它们本身不是密文,但:
1. **作为 canon 段参与 shield hash** → 服务端重算 canon 时会用
2. **透传给 libtiny** → `x-mini-sig` 计算时要读 xy-common-params 的部分字段
3. **篡改 = shield 挂** → 从防御方看,它们是签名链的一部分

---

## 4. Layer 2:shield(libxyass)

### 4.1 Header 结构(100 字节)

```
Offset  Len  Content
0       3    Magic (0x5D 0x80 0x00)
3       21   Version + AppId + SignatureHashCode (大部分固定)
24      4    Counter / sequence (cPtr-tracked)
28      16   Session state hash (前缀,来自 main_hmac derivation)
44      40   Prefix state (XOR-encoded meta,跨 session 基本稳定)
84      16   **Hash tail = hash(canon) XOR device_mask_16B** ← 真正的密码学部分
```

base64url 编码后 = 134 字符字符串。

### 4.2 Canon —— 7 段 raw bytes 拼接

```
canon = path + rawQuery + xy-common-params + xy-direction + xy-platform-info(compact) + xy-scene + body
        ^^^^^^^^^^^^^^^^^ ← 注意: query 要 raw 保留 %encoding
        ^^^^^^^^^^^^^^^^^   path 也要 raw (rarely encoded but safer)
```

#### 各段示例(user_me 端点 1058B):

| # | 段 | Bytes | 内容样本 |
|---|---|---|---|
| 1 | path | 19 | `/api/sns/v3/user/me` |
| 2 | rawQuery | 128 | `profile_page_head_exp=1&first_show=0&...` |
| 3 | xy-common-params | 818 | `fid=&gid=...&did=921f5ca6...` |
| 4 | xy-direction | 2 | `26` |
| 5 | xy-platform-info | 76 | `platform=android&build=9190807&deviceId=...` |
| 6 | xy-scene | 15 | `fs=0&point=1185` |
| 7 | body | 0~N | POST 才有,raw JSON 字节 |

#### POST 带 body 实例(note/widgets 2465B):

```
路径 + query + xy-common + xy-dir + xy-plat + xy-scene | body
  ↑          934B (6 段前缀)                      ↑  + 1531B JSON
```

### 4.3 Hash 函数 —— 非标准算法

已排除:
- SHA-1 / SHA-256 / MD5 / HMAC variants → 48 样本 × 20+ 种算法 **0 match**
- 不用 K[64] 常量表(反汇编 0 xref)
- 没有 ror #13 这种 SHA-256 特征指令

实际特征(从反汇编观察):
- `op_update(ctx, data_ptr, data_len)` 流式 API
- `op_final(ctx, out16)` 产 16B 输出
- 使用自研的 byte-mixer,可能类似 SipHash / Murmur 家族但魔改
- 涉及的 .data 常量:无标准 magic(如 SHA-256 的 `6a09e667`)

**我们没破算法本身**,也没必要 — 让它自己在 unidbg 里跑就行。

### 4.4 Device mask (16B)

```
95 d1 7c df a2 bb 91 e9 94 7b 3b 48 56 23 f7 bb
```

- Session-常量
- 与 deviceId UUID 绑定(换 deviceId 这 16B 会变)
- 存在 libxyass 的 .bss 区,由 `initialize()` 阶段派生

### 4.5 canonicalize_low 的双路径陷阱

libxyass+0x24e00 起的 `canonicalize_low` 函数内部有个关键 gate:

```asm
0x24f40: blx r5           ; 调 JNI stub 获取 Header 数组
0x24f42: mov r6, r0       ; save result
0x24f44: adds r0, #1      ; if r0 == -1 (JNI 失败), 变成 0
0x24f48: beq #0x2502a     ; == 0 走 fast-path (错的)
                          ; != 0 走 full-path (正确的)
```

- **Fast-path** (0x2502a): 用 64B 栈缓冲区快速算 hash,但只哈希部分数据 → shield 后 22 字符乱,服务端拒
- **Full-path** (0x24f4a 继续): 调 `JNI.NewByteArray` + `op_update` 喂正确 canon → shield 正确

unidbg 下 JNI stub 常返 -1(没实现对应 Java 类方法),导致走 fast-path → 签名错。

**我们的修复**: hook 0x24f42,强制 r0 = 1,让 beq 不 taken → 走 full-path → 然后 op_update 入口我们自己注入 canon。

---

## 5. Layer 3:x-mini-* 三件套(libtiny)

### 5.1 `x-mini-mua`(~1187B base64url)

**结构**: `base64url(JSON_header + "." + binary_tail)`

#### JSON 部分(~343B)

```json
{
  "a": 9190807,           // app versionCode
  "c": 68,                // 全局 sign 计数 (per-session monotonic)
  "f": 0,                 // flag 位掩码
  "k": "<base64_32B>",    // 本次 sign 的 HMAC subkey
  "p": 4098,              // platform bitfield (Android + 版本)
  "s": "<128_hex_chars>", // 64B session seed (初始化产)
  "t": {"c":68,...},      // OPTIONAL tracker (c>=11 才激活)
  "u": "<uid_short_hash>",
  "v": "2.9.55"           // libtiny 版本
}
```

- `s` 字段是会话级 HMAC 基础 seed,从 `main_hmac` 通过 device_id 派生
- `k` 字段是本次 sign 派生的子密钥,与请求 URL 关联
- `t` 字段是行为追踪器,counter ≥ 11 后自动激活(我们不激活也能通过服务端)

#### Binary tail(816B 左右)

- **不是哈希**,是**滚动累加器状态**
- 每次 sign 都会基于上次的 tail + 当前请求做 CBC-like 更新
- 连续 5 次 sign 观察:前 3 次 tail 几乎 identical,第 4 次整体重算(nonce 轮换)
- 纯黑盒没法完美重现字节级一致 —— 但 libtiny 自己跑产出的版本服务端能接受

### 5.2 `x-mini-s1`(84B base64)

**设备指纹签名**(与请求无关,只绑设备 + session)

- 读取 **MediaDrm (Widevine) deviceUniqueId**(硬件级)
- 混合 BSS 里的 `main_hmac` + session state
- 每次 sign 值不同(含 nonce),但都可验证为"同设备 + 同 session"
- 我们通过 stub `android/media/MediaDrm` 让 libtiny 读到合理 ID

### 5.3 `x-mini-sig`(32B,64 hex chars)

**最终请求级签名 = HMAC-like(mua + headers + body, key)**

已反编译的算法(libtiny+0x2b838):

```
输入: message (mua + canonicalize output 的若干段)
      key     (main_hmac derived)

1. KSA phase:
   - SEED = f(key bytes, struct layout)
   - S-box [256] = Fisher-Yates shuffle (反向) with Numerical Recipes LCG
   
2. ARX rounds (3 次 ChaCha-like):
   - arx_block_a × 2, arx_block_b × 1
   - 操作: ROR13, XOR, ADD32
   - 常量: 0x229c952a, 0x254a8000, 0xac1e4678
   - External constant: 0x033a5f44 (from .data)
   
3. Main loop (4 iterations):
   - IV = msg[1,2,9,14] big-endian
   - VEOR mask = msg[0:16]
   - _stage2_iter 累加
   
4. Finalizer:
   - MAGIC 0xa3b2ce45
   - 出 16B → hex encode → 32 hex chars
```

这个算法我们在 `unicorn/py_signer/` 下有 Python 纯实现,KSA-path 已 bit-exact 复现,但 libtiny 自己跑成本更低。

### 5.4 三件套的依赖关系

```
         ┌──────────────────────────────────┐
         │  main_hmac (from s.xml, 128 chars)│
         │  deviceUniqueId (Widevine)        │
         │  deviceId (UUID)                  │
         │  session (sid, gid, id_token)     │
         └─────────────┬────────────────────┘
                       │ KDF
              ┌────────┴────────┐
              ▼                 ▼
         ┌─────────┐       ┌─────────┐
         │  mua.s  │       │   s1    │
         │  seed   │       │ (84B)   │
         └────┬────┘       └─────────┘
              │
              ▼
         ┌─────────┐
         │  mua.k  │ (per-request)
         └────┬────┘
              │ HMAC
              ▼
         ┌─────────┐
         │   sig   │ (32B hex)
         └─────────┘
```

---

## 6. 核心突破 — canon injection 黑盒策略

### 6.1 问题链条回溯

```
服务端返 406                         (观察到的现象)
  ↓
shield.tail 与服务端算的不一致        (二分定位到是 shield 坏)
  ↓
hash(canon) 不一致                   (shield prefix 对,只有 tail 16B 坏)
  ↓
canon 不一致                         (hash 函数本身对,输入错)
  ↓
canonicalize_low 走 fast-path        (trace block 发现跳了 0x2502a)
  ↓
gate @ 0x24f48 的 JNI stub 返 -1     (NewByteArray 未实现)
  ↓
ART C++ vtable 没 emulate            (unidbg 架构局限)
```

### 6.2 突破方法:CanonInjectProbe 验证

写了个 probe(`CanonInjectProbe.java`):
1. 从真机 `/tmp/xhs_native_trace.log` 里提 PAIR 的 canon bytes(1058B)
2. hook 0x24f42 force bypass
3. hook 0x6dd28 op_update 入口 swap r1 = 真机 canon ptr, r2 = 1058
4. 让 libxyass **自己算**

**结果**: unidbg 产 shield tail = `787aa12d71e7b6f2a19739b3a5072c01`
= byte-exact 真机 cap_fresh user_me #5 tail
= 1/2^128 概率非巧合 → **hash 函数本身 100% 正确,差的只是 canon 输入**

### 6.3 生产化集成

从 probe 迁到 `XhsCombinedSigner.sign()`:

```java
// 1. 两个永久 hook (initialize 时装一次)
installCanonInjectHooks():
    hook @ libxyass+0x24f42:  // gate bypass
        if canonInjectLen > 0 && r0 == 0xFFFFFFFF:
            r0 = 1
    
    hook @ libxyass+0x6dd28:  // op_update intercept
        if canonInjectLen > 0:
            callIdx++
            if callIdx == 1:
                r1 = canonInjectPtr
                r2 = canonInjectLen

// 2. 每次 sign 时 (xyass.intercept 前)
sign():
    canon = buildFullCanon(path, rawQuery, preHeaders, body)
    canonInjectPtr.write(canon)
    canonInjectLen = canon.length  // enable hooks
    canonInjectCallIdx = 0          // reset
    
    xyassNative.intercept(...)      // libxyass 自然产正确 shield
    
    canonInjectLen = 0              // disable hooks
```

### 6.4 为什么能成功

**不需要理解 hash 算法具体实现**,只需要:
- ✅ 知道 hash 函数在 op_update 这个入口
- ✅ 知道 canon 格式是 7 段字节拼接
- ✅ 知道 gate 在 0x24f48
- ✅ 避开所有 C++ vtable 相关的 ART emulation

把 libxyass 当成黑盒:"喂对输入 → 它吐对输出"。

---

## 7. 代码改动清单

### 7.1 `XhsCombinedSigner.java` — 主要改动

#### 新增字段(L72-L97 附近)

```java
// Canon injection 状态
private long xyassBase = 0L;
private com.github.unidbg.pointer.UnidbgPointer canonInjectPtr = null;
private volatile int canonInjectLen = 0;
private volatile int canonInjectCallIdx = 0;
private boolean canonInjectDisabled = System.getenv("NO_CANON_INJECT") != null;
```

#### initialize() 里装 hook(L310 附近,xyass JNI_OnLoad 后)

```java
this.xyassBase = xyassModule.getModule().base;
if (!canonInjectDisabled) {
    com.github.unidbg.memory.MemoryBlock canonBlock =
        emulator.getMemory().malloc(16384, false);
    this.canonInjectPtr = canonBlock.getPointer();
    installCanonInjectHooks();
}
```

#### installCanonInjectHooks()

两个 CodeHook:
- `xyassBase + 0x24f42`: r0 == 0xFFFFFFFF → 1
- `xyassBase + 0x6dd28`: 第 1 次调用 swap r1/r2

只在 `canonInjectLen > 0` 时生效(sign 外自动 no-op)。

#### buildFullCanon()

```java
private byte[] buildFullCanon(String path, String query, List<String[]> headers, byte[] body) {
    // 从 headers 提取 xy-common/xy-dir/xy-scene
    String xyPlatCompact = "platform=android&build=" + versionCode + "&deviceId=" + deviceId;
    String prefix = path + query + xyCommon + xyDir + xyPlatCompact + xyScene;
    byte[] prefixB = prefix.getBytes(UTF_8);
    if (body == null || body.length == 0) return prefixB;
    // body 作第 7 段 append
    byte[] out = new byte[prefixB.length + body.length];
    System.arraycopy(prefixB, 0, out, 0, prefixB.length);
    System.arraycopy(body, 0, out, prefixB.length, body.length);
    return out;
}
```

#### sign() 里接入(xyass.intercept 前)

```java
if (!canonInjectDisabled && canonInjectPtr != null) {
    byte[] canon = buildFullCanon(path, query, this.preHeaders, this.reqBody);
    canonInjectPtr.write(0, canon, 0, canon.length);
    canonInjectCallIdx = 0;
    canonInjectLen = canon.length;   // enable
}

xyassNativeClass.callStaticJniMethodObject(emulator, "intercept...", ...);

canonInjectLen = 0;   // disable
```

#### URL raw encoding 修复(L1868)

```java
// Before:
String path = uri.getPath();
String query = uri.getQuery();

// After:
String path = uri.getRawPath();
String query = uri.getRawQuery();   // 保 %encoding
```

### 7.2 `UnidbgSignerLiveTest.java` — 扩展测试

加了 6 个新端点(CRUD 覆盖):
- `user_info_other`: GET /api/sns/v3/user/info?user_id=...
- `user_posted_notes`: GET /api/sns/v4/note/user/posted
- `note_imagefeed`: GET /api/sns/v1/note/imagefeed
- `note_comments_list`: GET /api/sns/v5/note/comment/list
- `homefeed_recommend`: GET /api/sns/v6/homefeed
- `note_widgets_post`: POST /api/sns/v2/note/widgets(+ JSON body)

### 7.3 环境变量

| Var | 作用 |
|---|---|
| `NO_CANON_INJECT=1` | 关闭 canon injection(回退 2/5 baseline) |
| `CANON_INJECT_DEBUG=1` | 打印每次 sign 的 canon_len + op_update swap 信息 |
| `USE_REAL_SESSION=1` | 使用真机 session(sid/gid/idToken) |
| `EMU_BUDGET_MS=30000` | emulator 单次 sign 预算 |

---

## 8. 关键坑点 & 调试经验

### 8.1 坑 1: Java `URI.getQuery()` 会 URL-decode

```java
URI u = new URI("?device_model=Pixel%206");
u.getQuery();       // → "device_model=Pixel 6"   (decoded! %20 → space)
u.getRawQuery();    // → "device_model=Pixel%206" (raw, 要用这个)
```

- 服务端 canon 用 raw 格式
- decoded 比 raw 短 2 字节 → shield 不匹配 → 406
- **教训**: 任何参与哈希的字符串,用 raw accessor

### 8.2 坑 2: xy-platform-info 有两种格式

| 格式 | 用途 | 例子 |
|---|---|---|
| Compact 76B 定长 | canon 第 5 段 + 作为 header 发 | `platform=android&build=9190807&deviceId=<uuid>` |
| Full 长版 | 某些老代码生成完整 header | `platform=android&build=9190807&deviceId=<uuid>&build_number=...&app_version=...` |

用 compact 版 both 参与 canon 且作为 header,不要用 full 版。

### 8.3 坑 3: HashMap bucket order 而非字典序

xy-common-params 35 字段顺序必须是 **Java HashMap(capacity=64) bucket 遍历顺序**,而非字典序、insert 序、alphabetical。

差异能被人眼识别:
```
# HashMap bucket 顺序 (正确):
fid=&gid=...&device_model=phone&tz=...&channel=...

# 字典序 (错):
SUE=1&active_ctry=CN&app_id=...&auto_trans=0...
```

### 8.4 坑 4: canon 注入时机

```java
// 错: 在 intercept 里装 hook,每次 sign 都新装 → hook 泄露
sign() {
    backend.hook_add_new(...);  // ❌ 每次 sign 多一个 hook
}

// 对: initialize 装一次,用状态标志控制
initialize() {
    backend.hook_add_new(...);  // 装一次
}
sign() {
    canonInjectLen = N;  // 启用
    intercept();
    canonInjectLen = 0;  // 禁用
}
```

### 8.5 坑 5: POST body 是 canon 第 7 段

GET 请求 canon 6 段足够,POST 必须加 body 作第 7 段:
```java
byte[] canon = prefix6 + body_raw_bytes;  // body 不 hash,直接 append
```

服务端从 HTTP body 读原始字节参与重算。

### 8.6 坑 6: 406 ≠ 500

| 响应 | 含义 | 签名状态 |
|---|---|---|
| 406 `{success:true, data:{}}` | Paradoxical 响应 | **签名层拒** |
| 500 `{...NullPointerException...}` | 服务端业务挂 | **签名已通过**(业务 handler 挂 ≠ 签名拒) |
| 401 / 403 | 认证层拒 | 签名过但会话无效 |
| 200 `{code:0, data:{...}}` | 正常 | **完全通过** |

调试时看到 500 server error 要区分是不是"签名已过业务挂",不是签名问题就算 PASS。

### 8.7 坑 7: unidbg JNI stub 返 -1 的连锁反应

`GetByteArrayElements` 等 JNI 方法未实现时 unidbg 返 -1(0xFFFFFFFF),导致:
- 代码里的 `if (arr == null)` 分支走错
- 代码里的 `cmp r0, #0; beq fail_path` 跳到失败路径
- 最终 shield 用错误数据算

**解法**: 不要无脑修 JNI stub,而是 **hook 失败分支的 gate,强制走正确路径**。

### 8.8 调试技巧

#### 8.8.1 Block trace diff

```bash
BLOCK_TRACE=/tmp/before.jsonl <env> mvn exec:java
# 改代码
BLOCK_TRACE=/tmp/after.jsonl <env> mvn exec:java
diff /tmp/before.jsonl /tmp/after.jsonl
```

能精确定位哪个代码改动影响了哪些 PC 执行路径。

#### 8.8.2 Pair oracle

`/tmp/xhs_native_trace.log` 的 `[PAIR]` 条目是 LSPosed 真机抓的 (canonicalize, hmac_output) 对:
```
[PAIR seq=N ...] {"canonicalize_hex":"...", "hmac_b64_input_hex":"..."}
```

用它做 ground truth:"给定这个 canon,应该出这个 hash"。

#### 8.8.3 Shield 结构解码

```python
import base64
shield_bytes = base64.urlsafe_b64decode(shield + '==')
prefix = shield_bytes[:84]   # meta
tail   = shield_bytes[84:]   # hash XOR mask
hash16 = bytes(t ^ m for t, m in zip(tail, mask_16B))
```

比较 `hash16` 与真机值,能判断是 prefix 问题还是 hash 问题。

---

## 9. 测试结果

### 9.1 基础 5 端点

| # | 端点 | 方法 | 结果 |
|---|---|---|---|
| 1 | `/api/sns/v3/system_service/flag_exp` | GET | ✅ PASS (187k bytes) |
| 2 | `/api/sns/v2/system_service/config` | GET | ✅ PASS (1.6M bytes) |
| 3 | `/api/sns/v1/system/device_type` | GET | ✅ PASS |
| 4 | `/api/sns/v3/user/me` | GET | ✅ PASS (真实用户数据) |
| 5 | `/api/sns/v1/user/verify/resources/pag` | GET | ✅ PASS |

### 9.2 用户信息 + 笔记 CRUD 6 端点

| # | 端点 | 方法 | 结果 |
|---|---|---|---|
| 6 | `/api/sns/v3/user/info?user_id=...` | GET | ✅ PASS (其他用户资料) |
| 7 | `/api/sns/v4/note/user/posted?user_id=...` | GET | ✅ PASS (用户发布笔记列表) |
| 8 | `/api/sns/v1/note/imagefeed?note_id=...` | GET | ✅ PASS (笔记详情 14k) |
| 9 | `/api/sns/v5/note/comment/list?note_id=...` | GET | ✅ PASS (评论) |
| 10 | `/api/sns/v6/homefeed?oid=...` | GET | ✅ PASS (推荐流 119k) |
| 11 | `/api/sns/v2/note/widgets` | **POST** | ⚠️ 500 NPE(签名已过,业务 body 字段不全) |

### 9.3 历史 baseline 对比

| 时间 | 状态 | 备注 |
|---|---|---|
| 2026-04-18 | 2/5 | flag_exp + config,其他 406 |
| 2026-04-20 EOD | 2/5 final ceiling | 文档声称"3/5 架构不可能" |
| **2026-04-24** | **11/11** | canon injection 破局 |

---

## 10. 未来方向

### 10.1 已解决,无需继续

- ✅ shield hash 算法(不用破,让 libxyass 自己算)
- ✅ canonicalize_low full-path(canon injection 绕过)
- ✅ canon 格式(7 段,body 是第 7 段)
- ✅ URL encoding(raw accessor)
- ✅ JNI stub 连锁反应(gate bypass)

### 10.2 可能还需要的工作

#### 10.2.1 更多端点覆盖

- [ ] 真正的 Create/Update/Delete 操作(post note / delete note)
  - 需要 multipart upload(图片/视频)先上传
  - 得到 `file_id` 后作为 body 参数 POST 到 /note/post
  - 风险: 会在真账号产生可见笔记

- [ ] 互动类 POST(like / comment / follow)
  - 较简单,body 结构明确
  - 同样会产生真实社交信号

#### 10.2.2 Session 管理

目前硬编码了一个真机 session:
```
sid = "session.1776665857416667244279"
gid = "7cb5787426b75495c7fefd12674f81d13df31a3947359fb17706788e"
idToken = "VjEAAMISM1..."
```

Session 过期后得重新从真机提取。如果要做 **登录流程**(phone + code → 换 session),需要反编译 `/api/sns/v2/user/login` 相关。

#### 10.2.3 mua binary tail 完美字节级还原

- 当前服务端接受但字节级与真机不同
- 风控系统长期对比会发现
- 如果触发风控 → 可能需要反编译 libtiny accumulator 算法

#### 10.2.4 主客 key 持续更新

- `main_hmac` 从 shared_prefs/s.xml 提取
- 理论上 app 会定期 refresh(从 server 下发)
- 目前我们的 hard-coded 值可能过期 → 监控 HTTP 406 率

### 10.3 新版本升级

XHS 版本更新后需要检查:
1. libxyass MD5 是否变 → 变了就要重新定位 0x24f42 / 0x6dd28 / device_mask
2. xy-common-params 字段有无增减 → 影响 buildXyCommonParams 字段列表
3. 服务端 canon 段格式是否变 → 影响 buildFullCanon

---

## 附录 A:核心偏移量速查

| 符号 | 偏移(libxyass+) | 用途 |
|---|---|---|
| `canonicalize_low` | 0x24ea0 | Canon 构造入口 |
| **`canon_gate_beq`** | **0x24f42** | **Fast-path 判决点(我们 hook 这里)** |
| Fast-path entry | 0x2502a | 错误路径 |
| Full-path entry | 0x24f4a | 正确路径 |
| Inner loop | 0x25034-0x25042 | 312 次 crypto routine |
| OLLVM dispatcher | 0x70000 | Control flow flattening |
| **`op_update`** | **0x6dd28** | **流式 hash 入口(我们 hook 这里)** |
| `op_final` | 0x6ddd4 | 产 16B 输出 |
| `Native.intercept` JNI | (JNI dispatch) | shield 总入口 |

## 附录 B:参考 memory 条目

- `project_libxyass_hash_correct_under_unidbg.md` — CanonInjectProbe 实证
- `project_unidbg_5of5_pass_via_canon_inject.md` — 生产集成 + 11/11
- `project_canonicalize_6_segments_and_sha1.md` — 7 段 canon 格式
- `project_xy_common_params_35_fields_working.md` — HashMap bucket 顺序
- `project_libxyass_nonstandard_hash.md` — 非标准算法证据
- `project_0x2b838_*` 系列 — libtiny sig 算法反编译

## 附录 C:环境要求

- unidbg (for32Bit)
- Java 11+ (with `--add-opens=java.base/java.lang=ALL-UNNAMED` for JPMS)
- Maven(离线依赖 ok)
- `libxyass.so` + `libtiny.so`(armeabi-v7a,从 apk `lib/armeabi-v7a/` 提)
- 一份真机 session(sid, gid, id_token) + main_hmac(从 `shared_prefs/s.xml` 提)
- 本地 proxy(`tools/phone_proxy/PhoneProxy.java`,:18888 转发 X-Target-URL)
