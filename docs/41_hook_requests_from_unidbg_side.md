# unidbg 侧向 LSPosed 窗口提的 hook 请求

## 背景

主项目目标是 unidbg 黑盒产 16 个 header 打过 XHS edith CRUD endpoint 的 mua+shield gate。

2026-04-18 已确认 `main_hmac` 是签名 gate,真机取自 `/data/data/com.xingin.xhs/shared_prefs/s.xml`。注入到 unidbg 后:

- ✅ libtiny 能产 mua,head4 因 main_hmac 改变(说明 main_hmac 被用到 HMAC 里)
- ❌ tail 仍是 **576B stateless** (vs 真机 768~1088B accumulator)
- ❌ libxyass `intercept()` 在注入 main_hmac 后进入 `canon_low` 的极长循环(PC `0x24f9a↔0x24fd6`, r11=0xfff=4095 inner, outer 次数极大),30s 跑 57M blocks 未退出

## 本文档目的

下面几个 hook 拿到数据后可直接喂 unidbg 侧比对,定位 **为什么 main_hmac 注入让 xyass 挂** 以及 **为什么 tail 长度锁在 576B**。

真机 LSPosed 每个 hook 都请输出到 `scratch/hook_requests/<hook_name>.log`,这样我 pull 下来对比。

---

## Hook 请求 #1 — libxyass.intercept 进入时的 cPtr 内存 dump (最高优先级)

**动机**: libxyass 的 cPtr 是 `initialize("main")` 返回的 handle,里面有 context。`intercept(chain, cPtr)` 读这个 cPtr 跑 canon_low,outer loop 次数可能由 cPtr 里某个 int32/size_t 字段控制。unidbg 侧 cPtr 目前 = `0x402520f0`,**对应的是 libxyass 内部分配的一个结构体**,我们不知道真机里它的字段长啥样。

**hook 点**: `libxyass.so` export 的 JNI 方法 `intercept(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;`

**要做**: 在 intercept 进入瞬间,读 `arg1` (Java long 的 cPtr),然后从这个 cPtr 地址读 **0x200 字节** hex dump。重复 3 次(3 次不同 request)以观察哪些字节稳定、哪些变化。

**实现伪码** (xposed/LSPosed):
```java
// intercept 的 native 入口地址从 so symbol 找
// 或者 hook DexGuard 后的 Java wrapper: 找 com.xingin.utils.core.XYInterceptor$intercept (或类似)
// 更方便: shadowhook intercept libxyass symbol Java_..._intercept
// 然后在 enter 时:
long cPtr = argJ;  // Java long -> native ptr
byte[] mem = readMem(cPtr, 0x200);
log("intercept cPtr=0x" + Long.toHexString(cPtr) + " dump=" + hex(mem));
// 请求 URL + method 也 log 一下便于对应
```

**输出 → `scratch/hook_requests/intercept_cptr_dump.log`**,每行:
```
seq=0 url=https://edith.xiaohongshu.com/api/sns/v3/user/me?profile_page_head_exp=1 cPtr=0x... dump=<0x200 bytes hex>
seq=1 url=... cPtr=0x... dump=...
```

---

## Hook 请求 #2 — libxyass canon_low outer loop 实际 iteration 次数

**动机**: 我 unidbg 侧观察 inner loop `0x24f9a↔0x24fd6` 的 r0 recursive 达到 0xfff 后退出,然后**外层再次进入**。30s 跑 2700 outer × 4095 inner。真机必须在很少 outer 就出来。需要确认真机实际 outer 次数。

**hook 点**: `libxyass+0x24fd8` (inner loop 刚退出的 PC,每次到这说明完成了一个 outer iter)

**实现**: shadowhook code hook 在 `libxyass_base + 0x24fd8` (Thumb,记得 |1),counter++。intercept 入口时 counter=0,intercept 退出时 log counter。

**输出 → `scratch/hook_requests/outer_loop_count.log`**:
```
intercept seq=0 url=... outer_iterations=3
intercept seq=1 url=... outer_iterations=5
...
```

**我的预期**: 真机 outer 应该是 3~10 次左右。如果不是这个量级,说明 unidbg 的某个 state 让 outer 膨胀。

---

## Hook 请求 #3 — main_hmac 读 vs 写的 call site

**动机**: 我要确认真机是 **app 本地生成并 putString** 还是 **从别处 getString 后 putString**。

**hook 点**:
- Java: `android.app.SharedPreferencesImpl` 的 `getString(String, String)` 和 `SharedPreferencesImpl$EditorImpl.putString(String, String)`

**只 log**: 当 `fileName endsWith "s.xml"` 或 `key.equals("main_hmac")` 时,打印:
```
[SP] method=putString file=s.xml key=main_hmac val=<first 32 chars>
     stack=<top 8 Java stack frames>
```

**输出 → `scratch/hook_requests/main_hmac_io.log`**

**关键看**:
- 冷启动第一次 `getString("main_hmac", default)` 返回是 default 还是已有值?
- 如果是 default,紧接着有没有 `putString("main_hmac", ...)`? stack 是谁调的?
- 如果不是 default,说明**启动前 s.xml 就有值**——那就一定是跨 install 继承(和用户的假设一致)

---

## Hook 请求 #4 — libtiny 第一次计算 mua tail 时 AES-CBC plaintext 长度

**动机**: 真机 mua tail 768B = AES-CBC(~752B plaintext);我们 unidbg tail 576B = AES-CBC(~560B plaintext)。差 192B plaintext。真机 plaintext 里多出来的那 192B 是什么?

**hook 点**: libtiny 内部的 `EVP_EncryptUpdate` 或 `AES_cbc_encrypt` (通常 PLT,从 `libtiny.so` 的 import 表找)

**退而求其次**: hook `libtiny+0x5xxxxx` 某个已知会调 AES 加密的位置 (你们应该比我清楚 libtiny 结构)

**log**: 每次 AES-CBC 入口时,log 入参的 plaintext_len 和 plaintext 的前 64 字节 + 后 64 字节 hex。

**输出 → `scratch/hook_requests/mua_aes_plaintext.log`**:
```
seq=0 url=... plaintext_len=752
  first_64=<hex>
  last_64=<hex>
```

**我的预期**: plaintext 里一定有 device fingerprint 字符串(deviceId/android_id/model 等),那些是已知的。但如果有 **uninitialized buffer** 或 **sensor 读数**,我们 unidbg 就要补。

---

## Hook 请求 #5 — 真机和 unidbg 的 xy-platform-info 字节级 diff

**动机**: memory 里记 xy-platform-info 已经 byte-exact,但那是**没注入 main_hmac** 的状态。注入 main_hmac 后 xyass 挂根本产不出 xy-platform-info,**我怀疑 main_hmac 影响了 xy-platform-info 的生成**。

**hook 点**: `okhttp3.Request$Builder.header(key, value)` (Java 层,libxyass 设 header 最后都走这个)

**log 条件**: 当 key 是 `x-shield`、`xy-platform-info`、`x-mini-s1` 之一时:
```
[header-set] url=... key=xy-platform-info val=<完整 value>
```

**输出 → `scratch/hook_requests/headers_set.log`** 30 个不同 endpoint 就够。

---

## Hook 请求 #6 (nice to have) — cPtr 里 offset 0x40~0x80 的写时机

**动机**: 如果 intercept 读 cPtr 做判断,那 cPtr 的字段 **在 initialize("main") 或某个 setter 里被写入**。找到 writer 就能对应到 "unidbg 缺什么"。

**hook 点**: 用 Backend write hook 在 cPtr 地址范围 `cPtr ~ cPtr+0x200` 上监控写,每次写记录: PC (调用者),写入 offset,写入 value。

**输出 → `scratch/hook_requests/cptr_writes.log`**:
```
[cptr-write] pc=libxyass+0x23f0a offset=0x48 val=0x12345678
```

---

## 交付格式小结

所有 log 文件请放 `scratch/hook_requests/`,我 pull 下来(或你 git add 推上来)就能直接喂给 unidbg 比对。

每个 hook 的 log 头先写一行说明:
```
# hook_name: intercept_cptr_dump
# generated: 2026-04-18 xx:xx
# app version: 9.19.0, build 9190807
# device: Pixel 6 Android 15
# note: 3 iter, 同 endpoint
```

---

## 优先级

如果时间紧,只做 #1 + #2 我就能推进:
- #1 给我真机 cPtr 的 ground truth,让我对比 unidbg 的 cPtr
- #2 告诉我真机外层 loop 多少次,让我判断是否 unidbg 某个 field 设错

其他可以后补。

---

## 我这边当前的 signer 入口

```bash
cd unidbg-xhs
export MAVEN_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED"
# 带 main_hmac: xyass 挂,libtiny 能出 576B tail
SKIP_SHIELD=1 EMU_BUDGET_MS=120000 mvn -q exec:java -Dexec.mainClass=com.xhs.sign.MuaTailProbeTest -Dexec.args="5"
```

关键代码:
- `unidbg-xhs/src/main/java/com/xhs/sign/XhsCombinedSigner.java` (signer 本体)
- `unidbg-xhs/src/main/java/com/xhs/sign/UnidbgPatcher.java` (JNI stub patches)
- `unidbg-xhs/src/main/java/com/xhs/sign/MuaTailProbeTest.java` (测试/诊断)

拿到你的 hook 数据后,我去: 找 canon_low 的 outer loop 控制变量 → patch cPtr 里对应字段 → 让 xyass 跑完 → 再测 tail 是否长大。
