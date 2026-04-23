# 笔记 CRUD 请求 — 所有字段来源分析 (ground truth)

**目的**: 先把笔记 CRUD 请求里**每一个字段**的来源搞清楚,再规划黑盒模拟。
**样本源**: [`lsposed/xhs-capture/captures/xhs_capture_20260413_162400.log`](../lsposed/xhs-capture/captures/xhs_capture_20260413_162400.log)
**日期**: 2026-04-15

---

## 0. 笔记 CRUD 涉及的所有 endpoints

从 capture 里 grep 出所有 note-related 请求 (去掉 CDN):

| 操作 | 方法 | URL | 用途 |
|---|---|---|---|
| 读 | GET | `/api/sns/v5/note/comment/list` | 评论列表 |
| 读 | GET | `/api/sns/v1/note/imagefeed` | 图片 feed |
| 读 | GET | `/api/sns/v11/search/images/entrance/show` | 笔记图搜索入口 |
| 读 | GET | `/api/im/smiles/note/add` | 表情包 |
| 读 | GET | `/api/sns/v4/note/user/posted` | 某用户发的笔记列表 |
| 读 | GET | `/api/sns/v1/interaction/note/like_collect/list` | 点赞/收藏人列表 |
| 读 | POST | `/api/sns/v1/note/detailfeed/preload` | 详情 feed 预加载 |
| 读 | POST | `/api/sns/v2/note/widgets` | 笔记挂件 |
| 读 | POST | `/api/sns/v1/note/metrics_report` | 指标上报 |
| 写 | POST | `/api/sns/v1/note/like?oid=...` | 点赞 |
| 写 | POST | `/api/sns/v1/note/collect` | 收藏 |
| 写 | POST | `/api/sns/capa/postgw/note/delete` | 删笔记 |

**结论**: 读/写两条路的 header **结构完全一致**,只有 body 内容变。验证签名逻辑只需要跑一个能成功返回的读请求(comment/list)+ 一个写请求(note/like)。

---

## 1. 规范样本 — POST /api/sns/v1/note/like

取 `[08:22:14.139]` 的点赞请求作为规范样本。所有 21 个观测到的头:

```http
POST /api/sns/v1/note/like?oid=discovery.69d640d600000000230209b5 HTTP/1.1
Host: edith.xiaohongshu.com
User-Agent: Dalvik/2.1.0 (Linux; U; Android 15; Pixel 6 Build/BP1A.250305.019) Resolution/1080*2400 Version/9.19.0 Build/9190807 Device/(Google;Pixel 6) discover/9.19.0 NetType/Unknown
Referer: https://app.xhs.cn/
Accept: ...
Content-Type: ...
Connection: ...

xy-direction: 26
xy-scene: fs=0&point=2565
xy-common-params: fid=&gid=7cb7be21...&device_model=phone&...&t=1776068534&build=9190807&holder_ctry=CN&did=921f5ca6...
xy-platform-info: platform=android&build=9190807&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9c

x-legacy-did: aa293284-0e77-319d-9710-5b6b0a03bd9c
x-legacy-sid: session.1776067598905471817912
x-legacy-fid: (empty)

X-B3-TraceId: c0c0aa1158170f0f
x-xray-traceid: cec2f78f56596e6a34a85b551ab11080

shield: XYAAQABAAAAAEAAABTAAAAUzUWEe0xG1IbD9/c+qCLOlKGmTtFa+lG438PdeFeRKoTlIa5nbRvSJ34qudYz8Mr1Zl+2KUzEAxLQ2PaZOr033k0j7fR2vAwtJmdQLa97ZKIQakZ

x-mini-sig: 5472019dde8281fca9d38d3c9087938339fcdc78744f19213dc347c566447261
x-mini-s1:  AJMAAAABFHLKxGXKM6Quzm2dmoajZDOxUSxQcpgu1QmKUa6Zmbg+aLVokWvDYoUr4Sp3dEQrP3lmZE4Im3k=
x-mini-gid: 7cb7be2194d15495c7fef2b0674f81d13df318a947359aaf7789359f
x-mini-mua: eyJhIjoiRUNGQUFGMDEiLCJjIjoxNDcsImsiOiJjYWU3NTkxNjQyZjY1NWNiZGRlN2MxNDI5YmZmMmRjNWFjZmExOGU3ZDY3MjAyZDhlODViNzNkN2NmNTQ1OTEzIiwicCI6ImEiLCJzIjoiMzRiNDkyNTA4ZThkYmZhZTJhZTZlODRmYjhlMmM4NTcwOGY5NTYyODIxYmQ3MmJhMTM4YzcyOWZhYzY3Y2JmOTUxODE2MzM1NmYxMjg2MDFmZDM3MDdlYmUwMmZiNDczNWJiZTVjYTM2MzY0OWZjMGI3NmFkMTM5ZWEyMWIyODIiLCJ0Ijp7ImMiOjc3MiwiZCI6NCwiZiI6MCwicyI6NDA5OCwidCI6OTQ0MTksInR0IjpbMV19LCJ1IjoiMDAwMDAwMDAyNTA3MTQ0NmJiYjBjMGZjYTg4YjAzNzEwYWIwYWMxZiIsInYiOiIyLjkuNTUifQ.4U5csPF_ZHW74qlDgTC...(RSA 512字节)...

X-XHS-Ext-Failover: 128
X-XHS-Ext-DNSIsolateTag: 0
X-XHS-Ext-CustomIPList: 117.88.123.99;119.45.249.52;...

(BODY: empty — like 操作 oid 在 query 上)
```

---

## 2. 总表 — 21 个头的来源分类

每行是一个 header,按"黑盒难度"从易到难排序:

| # | Header | 值示例 | 是否参与 shield 签名 | 来源(Java类 / Native / 系统) | 状态 |
|---|---|---|---|---|---|
| 1 | `Host` | `edith.xiaohongshu.com` | 否 | OkHttp 从 URL 自动填 | ✅ free |
| 2 | `Connection`, `Accept`, `Content-Type` | 标准 | 否 | OkHttp 默认值 | ✅ free |
| 3 | `User-Agent` | `Dalvik/2.1.0 ... Version/9.19.0 Build/9190807 Device/(Google;Pixel 6) discover/9.19.0 NetType/Unknown` | 否 | `tqb.c0` 同 `xy-platform-info` 同一个类拼装 | ✅ f-string |
| 4 | `Referer` | `https://app.xhs.cn/` | 否 | 常量 | ✅ 硬编码 |
| 5 | `X-B3-TraceId` | 16 hex | 否 | OkHttp 追踪拦截器,每请求随机 | ✅ random16 |
| 6 | `x-xray-traceid` | 32 hex | 否 | 同上,分布式链路追踪 | ✅ random32 |
| 7 | `x-legacy-did` | `aa293284-0e77-319d-9710-5b6b0a03bd9c` | 否 | [`r76/a.java:34`](../target/jadx_out/sources/r76/a.java) `kka.r.e()` = UUIDv3(MD5(android_id)) | ✅ Py 一行 |
| 8 | `x-legacy-sid` | `session.1776067598905471817912` | 否 | [`r76/a.java:35`](../target/jadx_out/sources/r76/a.java) `z76.q0.f479254a.b()` = 登录态 session | 🟡 需要外部 login |
| 9 | `x-legacy-fid` | (空) | 否 | [`ylb/d6.java`](../target/jadx_out/sources/ylb/d6.java) FingerPrintJni.getFingerPrint(),默认空字符串 | ✅ 空 |
| 10 | `xy-direction` | `26` | **否** | `zlb.t0` (classes14.dex 未反编译) `magic_num + hash(user_id)%100`,实测固定 26 | ✅ 常量 26 |
| 11 | `xy-scene` | `fs=0&point=2565` | **是** | `zlb.w0` (classes14.dex 未反编译) `HashMap{fs, point}` 按 bucket(16) 顺序,`fs` 在前 `point` 在后 | ⚠️ point 需要从页面状态来 |
| 12 | `xy-platform-info` | `platform=android&build=9190807&deviceId=aa293284-...` | **是** | [`tqb/c0.java:229`](../target/jadx_out/sources/tqb/c0.java) `"platform=android&build="+versionCode+"&deviceId="+UUID` | ✅ f-string |
| 13 | `xy-common-params` | 35 字段 urlencoded | **是** | [`zlb/j0.java:54-323`](../target/jadx_out/sources/zlb/j0.java) + [`sba/a.java:23-33`](../target/jadx_out/sources/sba/a.java) `HashMap{35 fields}` 按 bucket(64) 顺序拼 | 🟡 35 字段各自源(见 §3) |
| 14 | `shield` | `XY...` 136 字符 base64 | 自证 | [`com/xingin/shield/http/Native.java`](../target/jadx_out/sources/com/xingin/shield/http/Native.java) → `libxyass.XhsHttpInterceptor.intercept(Chain, long)` | ❌ native blocked |
| 15 | `x-mini-sig` | 64 hex | 自证 | [`r76/a.java:43`](../target/jadx_out/sources/r76/a.java) `ega.f.j(m,u,b)` → `d3.b(-1750991364,...)` → libtiny | ❌ native blocked |
| 16 | `x-mini-s1` | `AJ...=` base64 | 自证 | 同上,同一次 native 调用返回的 Map | ❌ native blocked |
| 17 | `x-mini-gid` | 56 hex | 否 | **同上,同一次调用返回** (memory 验证:header 名字 `x-mini-*` **不**出现在 dex 字符串表,由 libtiny 构造) | ❌ native blocked |
| 18 | `x-mini-mua` | JWT `eyJ...RSA` | 自证 | 同上,**payload 里 c/s/t 是计数器**,签名尾是 **TEE RSA-4096** | ⛔ 物理不可 |
| 19 | `X-XHS-Ext-Failover` | `128` | 否 | [`lba/g.java:127`](../target/jadx_out/sources/lba/g.java) FailoverCronetInterceptor | ✅ 常量/位图 |
| 20 | `X-XHS-Ext-DNSIsolateTag` | `0` | 否 | 未在 jadx 找到字符串 literal (可能在 classes 不反编译的地方或 native),snapshot 为 `0` | ✅ snapshot 0 |
| 21 | `X-XHS-Ext-CustomIPList` | `117.88.123.99;...` | 否 | [`ymb/k.java:176`](../target/jadx_out/sources/ymb/k.java) `cob.h.a(...)` 从 HTTPDNS 拿 | 🟡 DNS cache,snapshot 即可 |

### 关键观察

1. **真正参与 shield 签名 (canonicalize) 的只有 4 段**: `path + xy-common-params + xy-platform-info + xy-scene + (query|body)`。其余 17 个头(含 `xy-direction` !)都不进哈希,签错都无所谓。
2. **x-mini-gid/sig/s1/mua 是同一次 libtiny 调用返回的 Map**,[r76/a.java:43-46](../target/jadx_out/sources/r76/a.java) 遍历 Map 塞进 builder。doc 28 说 x-mini-gid 是另一个 cmd `-378830707` 是错的——`-378830707` 只是 install-time seed 生成,运行期塞 header 的是 `-1750991364` 这一个 cmd。
3. **xy-direction 值在真实设备上永远是 26**,不是服务端下发——`magic_num=26` 来自 region config,bucket=hash(user_id)%100=0(空 user_id 时)。
4. **User-Agent 要精确**(见 §4)——抓包里每一段 `Resolution/1080*2400`, `Version/9.19.0`, `Build/9190807`, `Device/(Google;Pixel 6)`, `discover/9.19.0`, `NetType/Unknown` 都是 `tqb.c0` 拼的,不能瞎填。

---

## 3. xy-common-params 的 35 个子字段

⚠️ **这 35 个字段**每一个都要按真值算出来,因为 xy-common-params 整串进 shield canonicalize。一字之差 shield 就错。

字段在 Java 侧按**插入顺序**定义 ([`zlb/j0.java`](../target/jadx_out/sources/zlb/j0.java)),但拼串时按 HashMap(capacity=64) 的 bucket 顺序遍历。Bucket index = `(java_hash(key) ^ (java_hash(key)>>16)) & 63`。

拼串顺序(从规范样本提取,已验证 bucket 公式):

```
fid→gid→device_model→tz→channel→versionName→deviceId→platform→sid→identifier_flag
→cpu_abi→nqe_score→project_id→x_trace_page_current→lang→app_id→uis→teenager
→active_ctry→cpu_name→dlang→data_ctry→SUE→launch_id→id_token→device_level
→origin_channel→overseas_channel→mlanguage→folder_type→auto_trans→t→build→holder_ctry→did
```

| # | 字段 | 观测值 | Java 源 | 性质 | Py 策略 |
|---|---|---|---|---|---|
| 1 | `fid` | `` (空) | `ylb.d6.c()` = FingerPrintJni,默认空 | install | 空串 |
| 2 | `gid` | `7cb7be2194d15495c7fef2b0...` | `ega.f.d()` = libtiny cmd `-378830707` | install-pinned | ❌ 需要激活期快照或 libtiny 黑盒 |
| 3 | `device_model` | `phone` | `DeviceInfoContainer.savedDeviceType` | device | 常量 `phone` |
| 4 | `tz` | `Asia/Shanghai` (url→ `Asia%2FShanghai`) | `TimeZone.getDefault().getID()` | runtime | 常量 |
| 5 | `channel` | `YingYongBao` | META-INF/CHANNEL 文件 (`kka.i.a()`) | install | 常量 |
| 6 | `versionName` | `9.19.0` | `un5.c.f415118h` 硬编码 (`c3b/j2.java:33`) | const | 常量 |
| 7 | `deviceId` | `aa293284-0e77-319d-9710-5b6b0a03bd9c` | `kka.r.f()` = UUIDv3(MD5(android_id)) | install | ✅ Py 派生 |
| 8 | `platform` | `android` | 字面量 | const | 常量 |
| 9 | `sid` | `session.1776067598905471817912` | `v4b.a.a()` = `IUserService.getSessionId()` | session | 🟡 外部 login |
| 10 | `identifier_flag` | `4` | `Function0` 返回 `"4"` | const-ish | 常量 |
| 11 | `cpu_abi` | `armeabi-v7a` | `z12.h.a(ctx)` | device | 常量 (32bit so) |
| 12 | `nqe_score` | `93` / `88` / `60`... | `r49.e.a.b()` 网络质量分 | runtime | 🟡 随便填 0-100 |
| 13 | `project_id` | `ECFAAF` | 字面量 | const | 常量 |
| 14 | `x_trace_page_current` | `explore_feed` / `note_detail_r10` / ... | `n5b.p.f288607b` 页面 tag | runtime | 🟡 影响 shield? 需要测 |
| 15 | `lang` | `zh-Hans` | locale 派生 | runtime | 常量 |
| 16 | `app_id` | `ECFAAF01` | 字面量 (Android: ECFAAF01, iOS: ECFAAF02) | const | 常量 |
| 17 | `uis` | `dark` | `qvb.c.i(ctx)` 深浅色 | runtime | snapshot |
| 18 | `teenager` | `0` | `d47.u.d()` | account | 常量 0 |
| 19 | `active_ctry` | `CN` | `sr.a.f390439a.g()` | runtime | 常量 |
| 20 | `cpu_name` | `oriole` (= Pixel 6 SoC) | `kka.o.b().a()` SharedPrefs | device | snapshot |
| 21 | `dlang` | `zh` | locale primary | runtime | 常量 |
| 22 | `data_ctry` | `CN` | `x69.a.f449270j.c()` | account | 常量 |
| 23 | `SUE` | `1` | 字面量 | const | 常量 |
| 24 | `launch_id` | `1776068454` | `n29.a.f287700b` = 进程启动时间戳 | per-launch | 🟡 signer init 时 `int(time.time())` |
| 25 | `id_token` | `VjEAANAffN...` (urlencoded) | `IUserService.getIdToken()` | session | 🟡 login 返回 |
| 26 | `device_level` | `6` | `lka.e.c(ctx).h` | device | 常量 6 |
| 27 | `origin_channel` | `YingYongBao` | `kka.o1.a()` | install | 常量 |
| 28 | `overseas_channel` | `0` | `un5.e` flag | install | 常量 |
| 29 | `mlanguage` | `zh_cn` | `h87.c.b(...)` | runtime | 常量 |
| 30 | `folder_type` | `none` | `DeviceInfoContainer.getFolderType()` | device | 常量 |
| 31 | `auto_trans` | `0` | `i42.k.e()` | account | 常量 |
| 32 | `t` | `1776068534` | `fs5.r.e()` = `(now_ms + serverOffset)/1000` | per-request | ✅ `int(time.time())` |
| 33 | `build` | `9190807` | `PackageManager.versionCode` | const | 常量 |
| 34 | `holder_ctry` | `CN` | `x69.a.f449270j.d()` | account | 常量 |
| 35 | `did` | `921f5ca695a0ec4a1ebe8138008a448a` | `l22.b.f()` = 登录账号内部 did (**与 x-legacy-did 不同**!) | session | 🟡 login 返回 |

**注意** `did` (field 35) ≠ `deviceId` (field 7) ≠ `x-legacy-did` header:
- `deviceId` = UUIDv3 设备 id,**设备级**,android_id 派生
- `did` = 账号绑定 did,**账号级**,login response 返回
- `x-legacy-did` = 等于 `deviceId`

---

## 4. User-Agent 拆解

```
Dalvik/2.1.0 (Linux; U; Android 15; Pixel 6 Build/BP1A.250305.019)
  Resolution/1080*2400
  Version/9.19.0
  Build/9190807
  Device/(Google;Pixel 6)
  discover/9.19.0
  NetType/Unknown
```

| 段 | 值 | 源 |
|---|---|---|
| `Dalvik/2.1.0` | 固定 | Dalvik VM 版本 |
| `Linux; U; Android 15` | 固定 | Android 15 |
| `Pixel 6 Build/BP1A.250305.019` | 设备相关 | `Build.MODEL` + `Build.ID` |
| `Resolution/1080*2400` | 设备相关 | `DisplayMetrics` |
| `Version/9.19.0` | const | versionName |
| `Build/9190807` | const | versionCode |
| `Device/(Google;Pixel 6)` | 设备相关 | `Build.MANUFACTURER + MODEL` |
| `discover/9.19.0` | const | 产品线名 + versionName |
| `NetType/Unknown` | runtime | 网络类型 (cell/wifi/unknown) |

User-Agent **不参与 shield canonicalize**(只有 path/xy-common/xy-platform/xy-scene 进哈希),所以错了也不会引起 406。但服务端可能有单独的 UA 黑名单,保守起见完全复制真机。

---

## 5. x-mini-mua JWT payload 结构

每次请求都变的计数器:

```json
{
  "a": "ECFAAF01",           // app_id 常量
  "c": 147,                  // ← 进程级计数器,每次 sign 自增 1
  "k": "cae75916...54591"    // 32 字节设备 key (hex),install-pinned
  "p": "a",                  // platform android
  "s": "34b49250...b282",    // 64 字节 HMAC seed (hex),install-pinned
  "t": {
    "c": 772,                // 各 counter (total / success / fail ...)
    "d": 4,
    "f": 0,
    "s": 4098,
    "t": 94419,              // 毫秒级 uptime?
    "tt": [1]
  },
  "u": "00000000250714...",  // 32 字节常量
  "v": "2.9.55"              // 内部库版本
}
```

**RSA 尾段** = `RSA-SHA256(header.payload, device_private_key)`,私钥存在 Android **硬件 KeyStore (TEE)** 里,任何软件层都**不可能**导出。离线生成 mua 只有两条路:
(a) 运行一个真机(或 Android 模拟器含 TEE)让它自己签;
(b) 复用当前进程 session 内的 RSA 输出——不行,每个请求 payload 不一样,签名会变。

**但**:服务端是否真的验证 RSA 尾段?尚未证实——可能只检查 payload 是不是合法 JWT。需要做一个"把真 mua 的 RSA 段用 base64 垃圾替换"的对比测试。

---

## 6. shield 字段拆解

规范样本的 shield:

```
XYAAQABAAAAAEAAABTAAAAUzUWEe0xG1IbD9/c+qCLOlKGmTtFa+lG438PdeFeRKoTl
Ia5nbRvSJ34qudYz8Mr1Zl+2KUzEAxLQ2PaZOr033k0j7fR2vAwtJmdQLa97ZKIQakZ
```

= `"XY"` 前缀 + base64(100 字节 raw):

```
raw[0..4]   = 00 04 00 00     magic/flags
raw[4..8]   = 01 00 00 00     version?
raw[8..11]  = 14 00 00        length_hi?
raw[11..16] = 00 53 35 16 11  ← device prefix 开头
raw[16..84] = ... 68 字节 ← device prefix (跨请求稳定)
raw[84..100] = 16 字节 shield_tail (per-request)
```

**已知**:`raw[0..84]` 在同一 session/device 所有请求里字节级相同,`raw[84..100]` 每请求变化。
**已知公式** (memory 2731 + 42 对样本验证):
```
shield_tail = inner_hash(canonicalize) XOR DEVICE_MASK_16B
canonicalize = path + xy-common-params + xy-platform-info + xy-scene + (query|body)
DEVICE_MASK_16B ← 从 device 信息派生 (已解)
inner_hash ← ??? (libxyass 重度混淆,未解)
```

---

## 7. 黑盒模拟路线 (针对每个字段)

把上面所有字段按"黑盒该怎么处理"分类:

### A. 可以纯 Python 硬编码/派生 (15 个)

```
platform versionName channel origin_channel lang project_id app_id build identifier_flag
tz cpu_abi device_level overseas_channel mlanguage folder_type auto_trans teenager
active_ctry data_ctry holder_ctry SUE device_model cpu_name uis dlang
deviceId (UUIDv3 of android_id)
x-legacy-did (=deviceId)
xy-platform-info (f-string)
x-legacy-fid (空)
X-B3-TraceId (random16)
x-xray-traceid (random32)
User-Agent (模板填 model/build)
Referer (常量)
X-XHS-Ext-Failover (常量 128)
X-XHS-Ext-DNSIsolateTag (常量 0)
```

### B. 需要 session/account 级外部输入 (4 个)

```
sid / x-legacy-sid / id_token / did
```
→ 来自 login response,每会话一次,不变。当前通过 `XhsIdentity` 传入。

### C. 需要 per-request 运行时计算 (3 个)

```
t = int(time.time())          ✅ 简单
launch_id = int(time.time())  ✅ signer init 时一次
nqe_score = 随便 0-100         ⚠️ 服务端可能不校验,测试
x_trace_page_current = ?       ⚠️ 影响 shield?需要验证
xy-scene point = ?             ⚠️ 影响 shield (进 canon)
```

### D. 需要一次性"激活期"快照 (2 个)

```
x-mini-gid = libtiny install 时生成,本地缓存,跨请求不变
X-XHS-Ext-CustomIPList = HTTPDNS 结果,可缓存
```
→ 用真机首次激活时抓到的值即可。

### E. native 算法卡点 (3 个)

```
shield      — libxyass inner_hash 未破,canonicalize 输入在当前模拟器里被污染 (memory 2768)
x-mini-sig  — libtiny cmd -1750991364 byte-mixer 未破
x-mini-s1   — 同上 (同一次调用返回)
```

### F. 物理卡点 (1 个)

```
x-mini-mua RSA 尾段 — TEE KeyStore,软件层不可生成
```

---

## 8. 还需要用 Ghidra 确认的问题

为了把 E 类卡点推进,需要在 libxyass 和 libtiny 里回答以下具体问题:

### 8.1 libxyass.so (`target/apk_libs/lib/armeabi-v7a/libxyass.so`)

1. **RegisterNatives 偏移**:4 个 native 方法的 `fn_ptr` 是哪 4 个绝对地址?(已知,模拟器里已 capture,需要 Ghidra 交叉验证)
2. **XhsHttpInterceptor.intercept 入口**:参数解包——`Chain`, `jlong ctx` 分别对应哪个 JNI 调用读哪个字段?
3. **canonicalize 构造位置**:哪个 C 函数拼 `path + xy-common + xy-platform + xy-scene`?具体通过哪几个 `CallObjectMethod` 从 `Request.Headers` 取出 header?目前模拟器里 canonicalize 被污染(memory 2768/2770)——是因为 JNI 返回值不对,还是 Java Map 实现不对?
4. **inner_hash 入口 + 签名**:接受什么参数 (const char*, size_t)?返回 16 字节到哪个 buffer?是独立函数还是 inline?
5. **DEVICE_MASK_16B**:是常量表?还是从 deviceId UUID 派生?哪个函数计算它?
6. **.bss 里的 key1/key2**:memory `project_libxyass_bss_keys.md` 里记录的两个 HMAC 密钥是从哪读的?什么时候写入?

### 8.2 libtiny.so (`target/apk_libs/lib/armeabi-v7a/libtiny.so`)

1. **cmd dispatch 表地址**:`-1750991364` 对应的 ARM 函数在哪?(已知大致地址,需要 Ghidra 符号定位)
2. **该函数返回的 Map 有几个 key**:是 3 个 (sig/s1/mua) 还是 4 个 (+gid)?通过数该函数里的 `CallObjectMethod(map, put, ...)` 调用就知道。
3. **byte-mixer buffer 输入源**:memory 2758 说外部输入只有 `x-mini-mua` 字符串 + 2 个 .bss 字节。Ghidra 能否证实?具体哪几条 `LDRB` 指令读外部数据?
4. **48 个常量表**(memory 2726):这张表用于干什么?SHA? HMAC? 自研?
5. **SHA-256 IV 三个地址**(memory 2727):是标准 SHA 还是魔改?
6. **19 字节 .bss init flag**(memory 2726/libtiny_signer SEED_BYTES):这个 buffer 是谁写入的?什么时候?为什么我们的模拟器必须手动 patch?
7. **cmd `-378830707`**:是否真的生成 x-mini-gid?还是只生成某种 seed?

---

## 9. 下一步执行顺序

1. ✅ **本文**(你正在读的):把 21 个头 + 35 个 xy-common 字段全部追到源。
2. **Ghidra headless 跑两个 .so**,回答 §8 的 13 个问题,产出 `docs/34_native_interface_contract.md`。
3. 基于 §8 的答案,**修复 Unicorn 模拟器的 canonicalize 污染**(memory 2768):很可能是 JNI `Headers.value(i)` 返回的字符串错。
4. 修好 canonicalize 后,**跑一次 shield 生成**对比真值。如果 tail 16 字节仍错,说明 `inner_hash` 函数本身在模拟器里没有正确执行完(缺全局状态 / cPtr snapshot),继续查。
5. libtiny 同样步骤:用 Ghidra 定位 cmd 函数 → 定位 byte-mixer 输入 → 修模拟器对应的 JNI stub 或 .bss patch。
6. 最终落点:**12 个头全黑盒生成** (§7 的 A+B+C+D+E),mua RSA 尾段 replay。
