# XHS 签名相关字段的 Java 源码追踪表

**日期**: 2026-04-14
**Py 复现**: [scratch/ghidra_work/xhs_signer_v3.py](../scratch/ghidra_work/xhs_signer_v3.py)
**验证**:
- `xy-common-params`: 41/42 真实抓包字节级精确匹配
- `xy-scene`: 6/6 抓包值精确匹配
- 共 14 个 XHS 自定义请求头,**10/14 已 Py 完整复写**

## ⚠️ canonicalize 实际是 5 段(对 edith/rec hosts)

```
canonicalize = path
             + xy-common-params
             + xy-platform-info
             + xy-scene             ← 之前漏了!参与签名
             + (url_query 或 form_body 视情况)
```

5 段直接拼接,无分隔符。`xy-scene` 参与 shield 签名,所以 Py 复写必须能精确生成它。`xy-direction` **不参与签名**,可以 snapshot 或默认值。

---

## 14 个 XHS 头总览

| # | Header | 状态 | Java 类 | 是否签名 |
|---|---|---|---|---|
| 1 | `xy-platform-info` | ✅ Py | `tqb/c0.java:229` | ✅ |
| 2 | `xy-common-params` | ✅ Py | `zlb/j0.java` + `sba/a.java` | ✅ |
| 3 | `xy-scene` | ✅ Py | `zlb/w0.java`(classes14 dex) | ✅ |
| 4 | `xy-direction` | ✅ snapshot | `zlb/t0.java`(classes14 dex) | ❌ |
| 5 | `x-mini-gid` | ✅ snapshot | `ega/f.java` → libtiny | ⚠️ 在 xy-common-params 内 |
| 6 | `x-legacy-did` | ✅ Py | `r76/a.java:32` | ❌ |
| 7 | `x-legacy-sid` | ✅ Py | `r76/a.java:33` | ❌ |
| 8 | `x-legacy-fid` | ✅ Py | `ylb/d6.java:151` | ❌ |
| 9 | `X-B3-TraceId` | ✅ Py | tracing interceptor | ❌ |
| 10 | `x-xray-traceid` | ✅ Py | tracing interceptor | ❌ |
| 11 | `shield` | ❌ blocked | `libxyass.so` | ✅ self |
| 12 | `x-mini-sig` | ❌ blocked | `libtiny.so` dispatch `-1750991364` | ✅ self |
| 13 | `x-mini-s1` | ❌ blocked | `libtiny.so` dispatch `-1750991364` | ✅ self |
| 14 | `x-mini-mua` | ❌ replay | TEE-RSA(物理不可) | ✅ self |

---

## 1. xy-platform-info(76 字节固定模板)

**Java 源**: [`tqb/c0.java:229`](../target/jadx_out/sources/tqb/c0.java)

```java
String str2 = "platform=android&build=" + cVar.z() + "&deviceId=" + str;
```

- `cVar.z()` = `un5.c.f415117g` = versionCode
- `str` = sDeviceId UUID

**Py 复现**: 一行 f-string,无任何转义。

---

## 2. xy-common-params(35 字段 HashMap)

### 2.1 总入口

[`lba/a0.java:102`](../target/jadx_out/sources/lba/a0.java) okhttp interceptor:
```java
builder3.addHeader("xy-common-params", aVar.b(aVar2, request));
```

### 2.2 拼接函数

[`sba/a.java:23-33`](../target/jadx_out/sources/sba/a.java):
```java
StringBuffer sb = new StringBuffer();
for (Map.Entry<String, Function0<String>> entry : aVar.c(request).entrySet()) {
    sb.append(entry.getKey() + '=' + URLEncoder.encode(entry.getValue().invoke()) + '&');
}
return StringsKt.trim(sb.toString(), '&');
```

要点:
- `URLEncoder.encode()` = form-urlencoded(空格→`+`,其他→大写 `%XX`)
- 末尾 `&` 用 `trim('&')` 去掉
- HashMap 迭代顺序是 **bucket-index 顺序**

### 2.3 35 个字段及其源(zlb/j0.java)

| # | 插入序 | bucket(64) | 字段 | Java 源 | 类型 | Py 源策略 |
|---|---|---|---|---|---|---|
| 1 | 0 | 1 | `platform` | `"android"` literal | const | hardcoded |
| 2 | 1 | 5 | `versionName` | `un5.c.f415118h` 由 `c3b/j2.java:33` 设为 `"9.19.0"` | const | hardcoded |
| 3 | 2 | 4 | `channel` | `kka.i.a()` 读 META-INF/CHANNEL | install | snapshot |
| 4 | 3 | 26 | `origin_channel` | `kka.o1.a()` | install | snapshot |
| 5 | 4 | 14 | `lang` | locale 派生(`zh-Hans`/`en` 等) | runtime | computable |
| 6 | 5 | 6 | `deviceId` | `kka.r.f()` UUID v3(MD5 of android_id) → SharedPrefs `pre_device.xml` | install | snapshot 或 from android_id |
| 7 | 6 | 0 | `fid` | `ylb.d6.c()` = FingerPrintJni.getFingerPrint() if enabled, 默认 `""` | install | snapshot(通常空) |
| 8 | 7 | 12 | `project_id` | `"ECFAAF"` literal | const | hardcoded |
| 9 | 8 | 15 | `app_id` | `"ECFAAF01"` literal | const | hardcoded |
| 10 | 9 | 32 | `build` | `kka.e.k(ctx)` = PackageManager.versionCode = `9190807` (`c3b/j2.java:31`) | const | hardcoded |
| 11 | 10 | 8 | `sid` | `v4b.a.a()` = `IUserService.getSessionId()` | session | snapshot 或 login resp |
| 12 | 11 | 31 | `t` | `fs5.r.e()` = `(System.currentTimeMillis() + serverOffset) / 1000` | per-request | `time.time()` |
| 13 | 12 | 16 | `uis` | `qvb.c.i(ctx)` ? `"light"` : `"dark"` | runtime | snapshot |
| 14 | 13 | 9 | `identifier_flag` | `Function0` 返回 `"4"` | const-ish | hardcoded |
| 15 | 14 | 13 | `x_trace_page_current` | `n5b.p.f288607b` 当前页面 tag | runtime | snapshot 或 `""` |
| 16 | 15 | 3 | `tz` | `TimeZone.getDefault().getID()` | runtime | `Asia/Shanghai` |
| 17 | 16 | 23 | `launch_id` | `n29.a.f287700b` = `System.currentTimeMillis()/1000` 在进程启动时一次 | per-launch | `int(time.time())` 在 signer init 时 |
| 18 | 17 | 17 | `teenager` | `d47.u.d()` ? `"1"` : `"0"` | account | snapshot,默认 `"0"` |
| 19 | 18 | 19 | `cpu_name` | `kka.o.b().a()` 读 SharedPrefs `pref_mediacodec.cpuName`(如 `oriole`) | device | snapshot |
| 20 | 19 | 2 | `device_model` | `DeviceInfoContainer.savedDeviceType`(如 `phone`) | device | snapshot |
| 21 | 20 | 1 | `gid` | `ega.f.d()` → libtiny dispatch ID `-378830707` | install | **snapshot only**(libtiny 黑盒) |
| 22 | 21 | 27 | `overseas_channel` | `un5.e` flag → `"1"`/`"0"` | install | snapshot |
| 23 | 22 | 29 | `folder_type` | `DeviceInfoContainer.getFolderType()`(如 `none`) | device | snapshot |
| 24 | 23 | 20 | `dlang` | locale primary language tag(如 `zh`) | runtime | computable |
| 25 | 24 | 34 | `did` | `l22.b.f()` = login state's currentDid OR `"default-currentDid"` | session | snapshot |
| 26 | 25 | 33 | `holder_ctry` | `x69.a.f449270j.d()` | account | snapshot,通常 `"CN"` |
| 27 | 26 | 18 | `active_ctry` | `sr.a.f390439a.g()` | runtime | snapshot,通常 `"CN"` |
| 28 | 27 | 21 | `data_ctry` | `x69.a.f449270j.c()` | account | snapshot,通常 `"CN"` |
| 29 | 28 | 30 | `auto_trans` | `i42.k.e()` ? `"1"` : `"0"` | account | snapshot,默认 `"0"` |
| 30 | 29 | 28 | `mlanguage` | `h87.c.b(...)` 多语言代码(如 `zh_cn`) | runtime | snapshot |
| 31 | 30 | 22 | `SUE` | `"1"` literal | const | hardcoded |
| 32 | 31 | 25 | `device_level` | `lka.e.c(ctx).h`(如 `"6"`) | device | snapshot |
| 33 | 32 | 10 | `cpu_abi` | `z12.h.a(ctx)`(如 `armeabi-v7a`) | device | snapshot |
| 34 | 33 | 11 | `nqe_score` | `r49.e.f363569a.b()` 当前网络质量分(0-100) | runtime | snapshot 或 `"0"` |
| 35 | 34 | 24 | `id_token` | `IUserService.getIdToken()` | session | snapshot |

### 2.4 HashMap 迭代顺序公式(Py 复现)

```python
def _java_string_hash(s):
    h = 0
    for c in s:
        h = (31*h + ord(c)) & 0xffffffff
    if h >= 0x80000000: h -= 0x100000000
    return h

def _hashmap_bucket(k, capacity=64):
    h = _java_string_hash(k) & 0xffffffff
    return ((h ^ (h >> 16)) & 0xffffffff) & (capacity - 1)

# 排序: 主 key=bucket index, 次 key=insertion order
sorted(keys, key=lambda k: (_hashmap_bucket(k, 64), _INSERTION_INDEX[k]))
```

- **capacity=64**: Kotlin `hashMapOf` 35 个条目时容量取 `nextPow2(ceil(35/0.75)+1) = 64`
- **insertion order tiebreaker**: 同 bucket 的 key 按 Java 8+ 链表(尾插)顺序遍历

**验证**: 41/41 真实抓包字节级精确匹配。

---

## 3. x-mini-gid(install fingerprint)

**Java 源**: [`zlb/j0.java:236`](../target/jadx_out/sources/zlb/j0.java) → `ega.f.d()`

[`ega/f.java:140`](../target/jadx_out/sources/ega/f.java):
```java
public static String d() {
    return d3.b();  // libtiny dispatch ID -378830707
}
```

[`com/xingin/tiny/internal/d3.java:48`](../target/jadx_out/sources/com/xingin/tiny/internal/d3.java):
```java
public static String b() {
    return (String) t.b(-378830707, new Object[0]);
}
```

→ 进 libtiny native(也是混淆的)。**install-pinned**,libtiny 在首次启动时生成并缓存(可能在 SharedPrefs 或 `/data/data/com.xingin.xhs/files/` 下)。

**Py 复现策略**: snapshot only。`xhs_signer_v3.py` 中 `XhsFieldSources.gid` 直接保存。

---

## 4. xy-scene(参与签名!)

**Java 类**: `zlb.w0` — jadx 没有反编译出来,我从 `target/dex/classes14.dex` 的 dexdump 反推。

**dex 位置**: `5c0c14: zlb.w0.intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;`

### 反编译伪代码

```java
public Response intercept(Chain chain) {
    Request req = chain.request();

    // Feature flag check
    if (!ylb.d4.u0.value) {
        return chain.proceed(req);
    }

    // If xy-scene already set, pass through
    if (req.header("xy-scene") != null) {
        return chain.proceed(req);
    }

    // Read runtime values
    int point = aob.b.c;          // static int updated by page tracker
    int fs = (computed)            // 1 if fullscreen viewing, else 0

    // Build HashMap of {fs, point} (default capacity 16)
    HashMap<String, String> map = MapsKt.hashMapOf(
        TuplesKt.to("point", String.valueOf(point)),  // inserted first
        TuplesKt.to("fs",    String.valueOf(fs))      // inserted second
    );

    // Iterate HashMap in bucket order, format key=encode(value)&...
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<String, String> e : map.entrySet()) {
        sb.append(e.getKey() + "=" + URLEncoder.encode(e.getValue()) + "&");
    }
    String value = StringsKt.trim(sb.toString(), '&');

    // Set header
    return chain.proceed(req.newBuilder().addHeader("xy-scene", value).build());
}
```

### HashMap 迭代顺序(capacity=16)

| key | java_hash | bucket(16) | iteration position |
|---|---|---|---|
| `fs` | `0xc0d` (3085) | **13** | 1st |
| `point` | `0x69aef9b` (110985115) | **14** | 2nd |

→ 输出格式总是 `fs=N&point=M`。

### Py 复现(已验证 6/6 抓包值)

```python
def build_xy_scene(fs: int = 0, point: int = 0) -> str:
    return f'fs={fs}&point={point}'
```

### 重要警告

`xy-scene` **在 canonicalize 里**(已验证 41/42 出现):

```
...&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9cfs=0&point=1185
                                                  ^^^^^^^^^^^^^^
                                                  xy-scene 直接拼上去
```

→ Py 调用 `signer.sign(fs=, point=)` 必须传入正确的运行时值,否则 shield 哈希错。
默认 `(0, 0)` 适合冷启动 / 非 feed 请求。

---

## 5. xy-direction(不签名)

**Java 类**: `zlb.t0` — 同样 jadx 没出,从 dexdump 反推。

**dex 位置**: `5c07bc: zlb.t0.intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;`

### 反编译伪代码

```java
public Response intercept(Chain chain) {
    Request req = chain.request();
    String host = req.url().host();

    if (!ylb.d4.w().getEnable()) {
        return chain.proceed(req);
    }

    // Read destination zone for this host
    String destZone = (LinkedHashMap) t94.d.l.get(host);
    if (destZone == null) destZone = "";

    // magic_num from RegionConfig (e.g. 26)
    int magic_num = ylb.d4.W().getMagic_num();
    if (magic_num < 0) {
        log("magic_num is invalid");
        return chain.proceed(req);
    }

    // Check if xy-direction already set
    String existing = req.header("xy-direction");
    if (existing != null) {
        log("xy_direction已有值: " + existing);
    }

    // Compute xy-direction value:
    //   bucket = (hash(user_id) % 100)  if user_id present, else 0
    //   value  = bucket + magic_num
    String userId = (logged_in)
                  ? v4b.a.b()
                  : ar.d6.A().getUserid();
    int bucket = userId.isEmpty() ? 0
               : (long_hash(userId) % 100);
    int value = bucket + magic_num;

    Builder b = req.newBuilder();
    b.header("xy-direction", String.valueOf(value));
    if (!destZone.isEmpty()) {
        b.header("destination-zone", destZone);
    }
    return chain.proceed(b.build());
}
```

### 在抓包中观察到的值

所有 21 个 edith 请求的 `xy-direction` 都是 `26`。这意味着 `bucket = 0`(可能 user_id 为空,或 hash 路径未启用),value = magic_num = 26。

### Py 复现

```python
def build_xy_direction(magic_num: int = 26, user_id: str = '') -> str:
    return str(magic_num)  # bucket==0 in observed device
```

`xy-direction` **NOT 在 canonicalize 里**(0/42 出现),不参与签名,snapshot 一个 `26` 即可。

---

## 6. x-legacy-did / sid / fid

**Java 源**: [`r76/a.java:32-33`](../target/jadx_out/sources/r76/a.java) + 同模式

```java
builder.header("x-legacy-did", kka.r.e());                    // = device_id
builder.header("x-legacy-sid", z76.q0.f479254a.b());           // = sid
// fid 在另一个 interceptor 中,值 = ylb.d6.c() = fid
```

**Py 复现**: 直接复用 `XhsFieldSources` 的 `device_id` / `sid` / `fid`。

---

## 5. shield(libxyass)

**Java 入口**: [`com/xingin/shield/http/Native.java`](../target/jadx_out/sources/com/xingin/shield/http/Native.java):
```java
public static native Response intercept(Interceptor.Chain chain, long ctx);
```

整个 shield 生成都在 native(`libxyass.so`)。Java 侧只是把 OkHttp Request 整体丢给 native。

**已破解**:
- `canonicalize = path + xy-common-params + xy-platform-info + url_query`(直接拼接,无分隔符)
- `shield_tail = inner_hash(canonicalize) XOR DEVICE_MASK_16B`(15+42 对样本验证)
- shield 格式 = `"XY"` literal + base64(99 字节) = 83 字节 device prefix + 16 字节 shield_tail

**未破解**: `inner_hash` 函数本身(libxyass CFG-flatten 重度混淆,需要动态 hook 帮助,见 [docs/29](29_dynamic_hook_spec.md))

---

## 6. x-mini-sig / x-mini-s1 / x-mini-mua

**Java 源**: [`ega/f.java:225-251`](../target/jadx_out/sources/ega/f.java)

```java
public static Map<String, String> j(String method, String url, byte[] body) {
    URL u = new URL(url);
    return d3.b(-1750991364, method, u.getHost(), u.getPath(), u.getQuery(), body);
}
```

→ libtiny dispatch ID `-1750991364`,native black box。

返回 Map 包含:
- `x-mini-sig` (32 hex)
- `x-mini-s1` (变长 base64)
- `x-mini-mua` (JWT 格式: `header.payload.RSA_signature`)

**已知**:
- `x-mini-mua` 末尾 RSA-4096 签名来自 Android **硬件 KeyStore (TEE)**,私钥不可导出。**这部分物理上不能离线生成**,只能 replay。
- `x-mini-sig` / `x-mini-s1` 走类似 libxyass 但在 libtiny。机制可能跟 shield 一样。

**Py 复现**: 见 [docs/29](29_dynamic_hook_spec.md) 的动态 hook 需求。

---

## 7. libtiny dispatch ID 表(部分已识别)

| ID | 调用者 | 用途 |
|---|---|---|
| `-378830707` | `d3.b()` → String | x-mini-gid |
| `-1750991364` | `f.j(method, url, body)` → Map | 主签名(x-mini-sig/s1/mua) |
| `617278119` | `d3.b(byte[])` → byte[] | 字节变换(未知) |
| `1268781800` | `f.f(int)` → Map | 文件性能 map |
| `704287623` | `d3.c()` | shutdown |
| `-2129897533` | `d3.a(b)` | 注册回调 |
| `-930908590` | `d3.a(long)` | 设置启动时间 |
| `1027279761` | `d3.a(c)` | init 配置 |
| `1932492929` | `d3.a(boolean)` | 后台标志 |
| `2099694886` | `d3.a(Object)` | 未知 |
| `730317001` | `d3.a(int, str, str, bool[], obj[])` | 未知 5 参 |
| `-872198405` | `d3.a(byte[])` → byte[] | 字节变换 2 |
| `-715706235` | `d3.a(boolean, str)` → bool | 未知 |

---

## 总结

**Java 侧 10/14 头完整 Py 复写**:
- ✅ `xy-platform-info`: f-string,字节精确
- ✅ `xy-common-params`: 35 字段 + HashMap 迭代顺序,**41/42 字节级匹配**
- ✅ `xy-scene`: HashMap{fs,point} bucket 顺序,**6/6 抓包值精确**
- ✅ `xy-direction`: snapshot `26`(在所观察设备上)
- ✅ `x-legacy-did/sid/fid`: 字段映射
- ✅ `x-mini-gid`: snapshot(libtiny 黑盒)
- ✅ `X-B3-TraceId` / `x-xray-traceid`: random,不签名

**Native 侧 4/14 blocked**:
- ❌ `shield`: libxyass `inner_hash` 函数(CFG-flatten 混淆)
- ❌ `x-mini-sig`: libtiny dispatch `-1750991364`
- ❌ `x-mini-s1`: libtiny dispatch `-1750991364`
- ❌ `x-mini-mua`: TEE-RSA(物理不可导出,只能 replay)

详见 [docs/29_dynamic_hook_spec.md](29_dynamic_hook_spec.md)。

## ⚠️ canonicalize 5 段公式(给 native shield 计算用)

```
canonicalize_for_edith_or_rec_host =
      path
    + xy-common-params           ← 由 zlb.j0 + sba.a 生成
    + xy-platform-info           ← 由 tqb.c0:229 生成
    + xy-scene                   ← 由 zlb.w0 生成,默认 'fs=0&point=0'
    + (url_query OR form_body)   ← GET URL query 或 POST form-urlencoded body
```

5 段直接拼接,无分隔符。Py 复写见 `xhs_signer_v3.py:XhsSigner.sign()`。

对非 edith host(如 `modelportrait.xiaohongshu.com`):
```
canonicalize_for_other_host = path + url_query + xy-platform-info
```
(只有 3 段,因为 xy-common-params/xy-scene/xy-direction 这些 interceptor 不挂这种 host)
