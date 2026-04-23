# libxyass + libtiny native 接口契约 (Ghidra 结果)

**目的**: 回答 [docs/33_note_crud_field_analysis.md §8](33_note_crud_field_analysis.md) 里列的 13 个 native 接口问题。
**数据源**:
- 前面窗口留下的解密表 `scratch/ghidra_work/libxyass_strings.json` (92 高置信字符串)
- 原始 `scratch/ghidra_work/all_decrypted_strings.json` (156 entries, 大量低置信)
- 头部反汇编 `scratch/ghidra_work/jni_onload_full.txt` / `intercept_disasm.txt`
- 本次 headless 跑出的 libxyass / libtiny section map + symbol
- `scratch/ghidra_work/libtiny_dispatch_decomp.txt` (libtiny dispatch 已反编译 73k 字节)
**日期**: 2026-04-15

---

## 0. 总体结构

### libxyass.so
```
ImageBase         : 00010000
Arch              : ARM:LE:32:v8
.text             : 0001d760..0008520b  (424 KB 混淆代码 + CFG-flatten)
.ppp.ttl          : 0008520c..00086637  ← OLLVM 指示器,确认重度混淆
.rodata           : 000188d8..0001d753
.data             : 0008bc70..0008d9c3
.bss              : 0008dbd0..0008e33b  (1900 字节)
.got / .got.plt   : 0008dab4..0008dbcb
Exports           : 仅 1 个 — JNI_OnLoad @ 0x0002ef68
```

### libtiny.so
```
ImageBase         : 00010000
Arch              : ARM:LE:32:v8
Exports           : 仅 1 个 — JNI_OnLoad @ 0x000c22b4
```

两库都只暴露 `JNI_OnLoad`,**所有 native 方法都走 `RegisterNatives` 动态注册**,所以要找 intercept/initialize 入口得从 `JNI_OnLoad` 内部开始追,或者看我们 Unicorn 驱动 capture 的地址(已知: M0..M3 的 4 个 fn_ptr)。

---

## 1. libxyass 的 9 个字符串解密路径 (最重要发现!)

OLLVM 字符串加密不是"一张表",而是每个代码路径内联一个解密桩。按解密函数聚合解密结果,**等价于拿到了每条代码路径的"import 表"**。92 条高置信解密串分布在 **9 个解密函数**里,每个函数代表一条逻辑路径:

### fn `0x1a170` — Bootstrap / 系统服务获取
```
okhttp3/Request$Builder
android/content/pm/PackageManager
android/content/SharedPreferences
android/content/Context
android/app/Application
(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
readByteArray
()Lokhttp3/RequestBody;
```
→ 用于 `initialize()`,首次启动拿 Context + SharedPreferences + PackageInfo。**跟 per-request 无关**。

### fn `0x1bc30` — Initialize / 设备状态设置
```
initialize, signatures, xy-ter-str, newBuilder
closing the old response error
getSharedPreferences
(String,String)→SharedPreferences$Editor
okhttp3/ResponseBody
```
→ 也是 initialize 路径的一部分,包含 "xy-ter-str" 这个错误模板 + "signatures" (读 APK 签名做反篡改检查?)。

### fn `0x1c440` — 版本号读取
```
versionCode, writeString, encodedPath
[Landroid/content/pm/Signature;
(I)→String
```
→ 读 `PackageInfo.versionCode` 和 APK 签名数组。**这就是前面 memory 里 "build=85683130 bug" 的 PackageInfo 路径**——`PackageManager.getPackageInfo().versionCode` 被 libxyass 直接读,我们 stub 必须返回正确值(已修复)。

### fn `0x1cc6c` — RegisterNatives 机制
```
hashCode
android/content/pm/Signature
(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;  ← intercept JNI 签名
Ljava/lang/String;
()Ljava/nio/charset/Charset;
(Ljava/lang/String;)Ljava/lang/String;
```
→ 这条路径包含 intercept() 的 JNI 签名 `(Chain, long) → Response`,说明它是 `RegisterNatives` 数组的构造点。

### fn `0x1d580` — **Shield + xy-platform-info 生成 / 设置路径** ⭐
```
okhttp3/Response, java/lang/String
com/xingin/shield/http/ContextHolder
xy-platform-info       ← header name
shield                 ← header name
isHttp, decode, sAppId, <init>, values, string
(String)→List
```
→ 这是**发射 shield 和 xy-platform-info header** 的代码路径。`sAppId` 是 `ContextHolder` 的静态字段。`isHttp` 是 `Request.isHttp()` 检查。

### fn `0x1ddac` — **Hash / HMAC 计算路径** ⭐⭐⭐
```
com/xingin/shield/http/Base64Helper
okhttp3/Interceptor$Chain
okhttp3/Headers         ← 取 headers
okhttp3/HttpUrl
okhttp3/Request
_hmac                   ← !!! HMAC 片段
()Lokio/Buffer;
clone, close, ([B)I, value, build
```
→ **这是 inner_hash / shield_tail 计算路径**。包含 HMAC 字面量片段 + Base64Helper + Buffer + Headers — 一次性把 hash 需要的所有 Java 对象都拉出来。

**重大推论**: `_hmac` 这个前缀意味着某处有类似 `"HmacSHA256"` 或 `"HmacSHA1"` 的完整常量,只不过被拆成片段存储。inner_hash 很可能**是标准 HMAC**,不是自研。

### fn `0x1e560` — **intercept 主入口 / xy-platform-info 拼装** ⭐⭐
```
intercept                                            ← JNI name
platform=android&build=%lld&deviceId=%s             ← xy-platform-info 格式串!
()Lokhttp3/Headers; / ()Lokhttp3/Request; / ()Lokhttp3/HttpUrl;
com/xingin/shield/http/Native                       ← JNI class
putString / getString                                ← SharedPreferences 读写
okhttp3/RequestBody
(String,Charset)→Buffer
```
→ **这是 intercept JNI 入口函数本体**,它
(1) 读 Chain → Request → URL / Headers / body
(2) 格式化 `platform=android&build=%lld&deviceId=%s` 得到 xy-platform-info
(3) 读写 SharedPreferences (`getString` / `putString`)
(4) 最终构造 shield header

### fn `0x1b29c` (16 strings) — 通用辅助
```
java/nio/charset/Charset, java/util/List
getPackageName, getPackageInfo, defaultCharset
name, size, read, %lld, encodeToString
```
→ 辅助 (字符集 + List + Package 查询)。

### fn `0x22e24` — Byte 数组编解码
```
([B)→String
(String)→[B
encodedQuery
(BufferedSink)→V
```

---

## 2. canonicalize **没有** xy-common-params / xy-scene / xy-direction 的字面量

**这是对 doc 28 canonicalize 5 段公式最重要的质疑**:

解密表里 libxyass 引用的 **header name 字面量只有两个**:
- `xy-platform-info` (fn 0x1d580)
- `shield` (fn 0x1d580)

没有 `xy-common-params`, `xy-scene`, `xy-direction`, `x-legacy-did`, `x-mini-sig`... 一个都没有(92 条高置信解密里绝对没有,剩余 64 条低置信也没匹配到)。

**推论** (2 种可能):

**A. libxyass 只读 xy-platform-info 一个 header 字面量,其余是迭代**
- 通过 `Headers.size()` / `Headers.name(i)` / `Headers.value(i)` 遍历整个 Headers 对象
- canonicalize 公式实际可能是: `path + (query|body) + xy-platform-info + <all other headers 按插入顺序拼>`
- 这能解释 memory 2768 的"canonicalize 被污染"——我们的 Unicorn 只塞了 4 个 pre_headers,但真机上 libxyass 看到的 Headers 包含 **所有 15+ 个 header**(因为 shield 是 OkHttp 链最末端的 interceptor)

**B. libxyass 通过 `Headers.get(String)` 按名字字面量取,但我们的解密器没跑出那些字面量**
- 92/1200+ 字符串解密成功率约 7.5%,`xy-common-params` 的密文可能在 64 条低置信条目里但得分 <0.6 被过滤掉
- 这种情况 canonicalize 公式就是 doc 28 的 5 段

**如何证伪**:
反汇编 fn `0x1d580` 和 `0x1e560`,搜 `okhttp3/Headers.get(String)` 的 PLT 调用。如果有 → B;如果只有 `size/name/value` 调用 → A。

**对修 bug 的意义**:
- 如果是 A,我们需要把模拟器的 pre_headers 扩充到**完整 15+ 个 header**(`x-legacy-*`, `X-B3-TraceId`, `x-xray-traceid`, `xy-direction`, `xy-scene`, `xy-common-params`, `xy-platform-info`, `x-mini-*`),并且**按 OkHttp 插入顺序**(先被加的在前)
- 如果是 B,我们只需要保证那 4 个 pre_headers 字节级精确

我的倾向:**方案 A 更可能**。理由:
1. shield 是链末 interceptor,实际看到的 Headers 肯定是全集,不是 4 项
2. libxyass 只解密 `xy-platform-info` + `shield` 两个字面量,说明它只对这两个特殊处理(`xy-platform-info` 要自己生成并添加;`shield` 是最终要设的 header 名)
3. 如果它要按名字过滤,应该至少看到 `xy-common-params` 字面量——再怎么混淆,一个 18 字节的字面量总要被引用

---

## 3. 回答 doc 33 §8 的 13 个问题

### libxyass

**Q1. 4 个 native 的 fn_ptr 绝对地址**
→ 从我们 Unicorn 驱动的 `registered` 列表读,不需要 Ghidra 交叉验证。已知: initialize / initializeNative / intercept / (第 4 个) 都 capture 成功。

**Q2. intercept 参数解包**
→ JNI 签名已确认: `(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;` (来自 fn 0x1cc6c 解密)。参数: `r0=env, r1=clazz, r2=chain, r3=pad, [sp+0]=ctx_lo, [sp+4]=ctx_hi`。已经在 Unicorn 驱动里这样传了。

**Q3. canonicalize 构造位置 + 读哪些 header**
→ **未解决**。最可能的入口是 fn `0x1d580` 或 `0x1e560`。下一步:在 Ghidra 里反汇编这两个函数,搜 `Headers.size/name/value` 调用 vs `Headers.get` 调用,敲定方案 A or B。

**Q4. inner_hash 入口 + 签名**
→ **未解决**,但已定位到 fn `0x1ddac`(含 `_hmac` + `Base64Helper` + `Buffer` + `Headers` + `([B)I`)。这个 `([B)I` 签名 `(byte[])→int` 可能是 HMAC/SHA update 一步。

**Q5. DEVICE_MASK_16B 派生源**
→ **已知**(memory `project_shield_architecture_cracked.md`): 其他窗口通过 42 对样本已解出 DEVICE_MASK,从 deviceId UUID 派生。

**Q6. .bss key1/key2 是什么**
→ **已知**(memory `project_libxyass_bss_keys.md`): 两个都公开可知 (build + deviceId),**隐藏密钥一定在别处**。现在结合 fn `0x1ddac` 的 `_hmac` 发现,真正的 HMAC key 很可能是:
  - 硬编码在 fn 0x1ddac 的常量区
  - 或者从 cPtr 里取(所以 cPtr snapshot 路径才有意义)

### libtiny

**Q7. cmd `-1750991364` dispatch 函数地址**
→ `scratch/ghidra_work/libtiny_dispatch_decomp.txt` 已有 73KB 反编译,但 headless 重跑时没 hit 立即数(说明 cmd 是通过 PC-relative 常量池或动态计算传入)。需要读 `libtiny_dispatch_decomp.txt` 找答案,留给下一步。

**Q8. 返回 Map 里几个 key (3 or 4)**
→ **未解决**。需要读 libtiny_dispatch_decomp.txt 找 `java/util/Map.put` 的调用次数。如果是 3,则 x-mini-gid 走 cmd `-378830707`;如果是 4,则 doc 28 错,cmd `-1750991364` 一次性返 sig/s1/mua/gid。

**Q9. byte-mixer 输入源 (已部分定位)**
→ memory 2758 已确认外部输入 = `x-mini-mua` 字符串 + 2 个 .bss 字节。Ghidra 交叉验证留待下一步。

**Q10. 48 常量表用途 (memory 2726)**
→ 已知是 byte-mixer 查表,未知具体是 SHA/HMAC/RC4 还是自研。

**Q11. SHA-256 IV 三个地址 (memory 2727)**
→ 已知位置。是否标准 SHA / 魔改未确定。

**Q12. 19 字节 .bss init flag (memory 2725+)**
→ 已知位置 0x405c3fb8,已经在 libtiny_signer.py 里用 `SEED_BYTES` patch 过。具体写入来源:应该是 cmd `1027279761` 的 init 配置路径。

**Q13. cmd `-378830707` 生成什么**
→ doc 28 说生成 x-mini-gid,但 r76/a.java 的 Java 代码显示 **per-request header 是 cmd `-1750991364` 返回的 Map 遍历**——x-mini-gid 不从 Java 层单独调 `-378830707`。最可能的真相: `-378830707` 只在 **install 期**生成并缓存到 SharedPreferences,此后 `ega.f.d()` 直接读缓存,不再调 native。需要反汇编验证。

---

## 4. 下一步具体动作 (优先级)

### Priority 0 (立刻): 验证 canonicalize 污染假设
**动作**: 修改 `xhs_signer.py` 的 `pre_headers`,把**完整 15 个 header**按 OkHttp 插入顺序塞进去,然后跑一次 `shield` 对比真值。

插入顺序(从真实抓包 trace 出来,等价于 OkHttp 链里 interceptor 逐个 addHeader 的顺序):
```
1.  xy-direction          (zlb.t0)
2.  X-B3-TraceId          (tracing)
3.  x-xray-traceid        (tracing)
4.  xy-scene              (zlb.w0)
5.  x-legacy-did          (r76/a)
6.  x-legacy-fid          (ylb/d6)
7.  x-legacy-sid          (r76/a)
8.  x-mini-gid            (r76/a via ega.f.j)
9.  x-mini-s1             (r76/a via ega.f.j)
10. x-mini-sig            (r76/a via ega.f.j)
11. x-mini-mua            (r76/a via ega.f.j)
12. xy-common-params      (lba/a0)
13. User-Agent            (不进)
14. Referer               (不进)
(shield 此时才跑,读完 Headers 塞自己 + xy-platform-info)
```

如果 shield tail 对了 → 假设 A 正确,canonicalize 就是 "path + 所有前置 header 拼接"。
如果还错 → 假设 B,回到 Ghidra 挖 `Headers.get` 调用。

### Priority 1: 深挖 fn 0x1d580 + 0x1e560 + 0x1ddac
写一个更聚焦的 Ghidra 脚本,反汇编这 3 个函数 + 列出所有 callees,产出 `docs/35_libxyass_intercept_disasm.md`。

### Priority 2: 读 libtiny_dispatch_decomp.txt
前面窗口已经反编译了 73KB,直接读。找 `map.put` / cmd 表。

### Priority 3: 补齐字符串解密
batch_decrypt_all.py 还躺在 scratch 里,可能重跑时把 0.5 以下分数的也保留看看能否凑出 `xy-common-params`。

---

## 5. Unicorn 模拟器要改的具体位置

基于 §4 Priority 0:

**文件**: `unicorn/xhs_signer.py`,第 164-169 行的 `pre_headers` 列表。
**现状**:
```python
pre_headers = [
    ("xy-common-params", java_headers.get("xy-common-params", "")),
    ("xy-direction",      c.xy_direction),
    ("xy-platform-info", java_headers.get("xy-platform-info", "")),
    ("xy-scene",          c.xy_scene),
]
```

**应该改成**(假设 A):
```python
# OkHttp 链插入顺序,shield 是最末 interceptor,看到的 Headers 包含全集
pre_headers = [
    ("xy-direction",     c.xy_direction),
    ("X-B3-TraceId",     java_headers.get("X-B3-TraceId", "")),
    ("x-xray-traceid",   java_headers.get("x-xray-traceid", "")),
    ("xy-scene",         c.xy_scene),
    ("x-legacy-did",     java_headers.get("x-legacy-did", "")),
    ("x-legacy-fid",     java_headers.get("x-legacy-fid", "")),
    ("x-legacy-sid",     java_headers.get("x-legacy-sid", "")),
    ("x-mini-gid",       c.x_mini_gid),
    ("x-mini-s1",        "<placeholder>"),
    ("x-mini-sig",       "<placeholder>"),
    ("x-mini-mua",       "<placeholder>"),
    ("xy-common-params", java_headers.get("xy-common-params", "")),
]
# xy-platform-info 由 libxyass 自己生成,不在 pre_headers
```

**注意**: x-mini-s1/sig/mua 在 shield 之前已经由 libtiny 设好,但我们的模拟器先跑 shield 后跑 libtiny。如果 libxyass 只是遍历 Headers,只需要保证 **每个条目的 name+value 是真实的**;x-mini-sig 的值可以先用真机 snapshot 占位,后续 libtiny 也跑通就同步替换。
