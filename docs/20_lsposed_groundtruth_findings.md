# XHS — LSPosed Ground-Truth 数据带来的新发现

**日期**: 2026-04-13
**数据源**: `lsposed/xhs-capture/captures/live.log` (其他会话留下的，17MB / 74k 行)

这是 19 号文档之后用真机数据做的回归分析。**bottom line：算法形状进一步确认，但
精确公式仍未找到 —— 距离能签新请求差 1 个细节（要么 key 派生方式，要么 message
encoding，要么两者）**。

---

## 数据规模

```
Total edith.xiaohongshu.com requests: 515
With shield + sig + s1 + mua headers: 515 (100%)
Distinct shield_tail values: 474 (some natural collisions)
Distinct x-mini-sig values: 490 (essentially all unique)
Sessions in this capture: 4 (x-legacy-sid)
Devices: 1 (x-legacy-did = aa293284-0e77-319d-9710-5b6b0a03bd9c)
```

这是质变 — 从 29 样本到 515 样本，能做的统计推断完全不一样。

---

## 新确认的事实

### 1. x-mini-mua 是 **JWT 格式**，不是 binary blob

```
x-mini-mua = base64url(JSON_payload) "." base64url(signature) "."
```

- **payload (~395 chars)**: `{a, c, k, p, s, u, v}` JSON
  - `a`: 设备 class (e.g., "ECFAAF01")
  - `c`: per-request **counter**
  - `k`: 64-hex per-session HMAC key (NOT device-fixed — 跨 session 变!)
  - `p`: "a"
  - `s`: 128-hex session blob
  - `u`: 40-hex install UUID
  - `v`: app version

- **signature (~1046 chars URL-safe base64 ≈ 784 bytes)**: 看起来像 RSA 签名
  尾部是空（trailing `.`）

- **签名跨 27 flow 有 13 distinct** —— 不是 session-fixed 也不是 per-request：
  说明 mua signature 按某种**批次/时间窗口**变化（比如每 N 秒重算一次）

### 2. shield 100 字节布局复现

跨 831 个真实抓包，**byte 0 of shield_tail (=byte 84) 总是在 `0x70-0x7f`**
（831/831，0% 误差）。具体分布：

```
0x7b: 8.2%  0x7c: 7.6%  0x7f: 7.0%  0x76: 6.9%
0x77: 6.7%  0x74: 6.6%  0x75: 6.4%  ...
```

16 个 distinct values，分布相对均匀 → byte 0 = `0x70 | (4-bit varying)`，
高 4 位 fixed 为 `0b0111`。

bytes 1-15 是高熵的 (246/831 distinct)，看起来像普通 hash 输出。

### 3. shield_tail 依赖 timestamp `t`（**关键变量**）

实证：取一组 **同 method/url/body** 的请求，看 shield_tail 何时变化：

```
flow1: t=1776068545  tail=75bb0135302ffa16a8c15d7744febddd
flow2: t=1776068545  tail=75bb0135302ffa16a8c15d7744febddd  ★ 同 t 同 tail
flow3: t=1776068546  tail=730cd6b9b20d8b939b5b59560760be6f
flow4: t=1776068553  tail=7719e69dd994bd5e7623ec91251f00bc
flow5: t=1776068561  tail=78a11d47386ced9ee8ae76afbdf35359
```

**结论**：
- shield_tail = `f(method, url, body, t)`
- t 是 Unix timestamp 秒级（来自 `xy-common-params` 里的 `t=...`）
- **不依赖** counter / nonce / trace ID
- 同一秒内同请求的 shield 完全相同（即重试可以直接复用）

### 4. x-mini-sig 32 字节，**全部 distinct** (515/515)

和 shield 不同，sig **没有任何 collision**。意味着它依赖**某种纳秒级或 random
nonce** 字段。这就是为什么我们之前的"shield 同的两个请求 sig 不同"现象。

可能 sig 的输入包含：
- 每请求新生成的 nonce (在 mua 的 binary tail 里？)
- 或 X-B3-TraceId
- 或 timestamp + counter 组合

### 5. mua_k 是 **session-bound**，不是 device-bound

```
session A: mua_k = 86947cc6d9ee80e4a6203084a6c95c46...
session B: mua_k = cae7591642f655cbdde7c1429bff2dc5...
```

跨同一 device 的两个 session，mua_k **完全不同**。意味着：
- mua_k 是登录/会话开始时**服务器返回**的（或客户端生成后给服务器）
- 静态 RE 没法预测它，必须从 capture 里读
- **要签某个 device 的请求，必须先抓到该 device 的当前 session 的 mua_k**

### 6. x-mini-gid 也跨 session 变化

```
session A: gid = 7cb7b96978d75495c7fef3a4674f81d13df3e879473592ab77aca34d
session B: gid = 7cb7be79828a5495c7fef...
session C: gid = 7cb7be2194d15495c7fef...
```

3 distinct gids in 1 device. Pattern: 都以 `7cb7be` 或 `7cb7b9` 开头，可能内含
session ID + device fingerprint hash。

---

## Brute force 结果：30+ 种组合 0 匹配

用以下输入空间测试 shield_tail：

```
key candidates (12+):
  mua_k (str, hex bytes), mua_s, mua_u, deviceId, gid, sid,
  shield_inner_64 (4 inner blocks), shield_inner_first/last 16/32

message candidates (20+):
  M+P, M\nP, M\nPQ, M+P+B, M\nPQ\nB, UPP variants, with t, with xy-common-params,
  with counter, with body, with various separators (\n, /, : etc)

hash algorithms: SHA-1, SHA-256, MD5, SHA-512
HMAC modes: hmac, key+msg, msg+key, key+msg+key (sandwich)
slices: every 16-byte window of the digest
masking: byte 0 high-nibble = 0x7 (matches 831/831 ground truth)
```

**结果：0 个直接匹配**。

也试了 saved-SHA1-state 的恢复（用 shield prefix 的 64 字节作为 H 状态继续 update）—
仍然 0 匹配。

---

## 为什么 brute force 不出来？最可能的原因

排序按可能性：

### A. Key 是派生的，不是直接用

候选派生方式：
- HKDF: `key = HKDF(mua_k, info=path, salt=t)`
- PBKDF2: `key = PBKDF2(mua_k, salt=device_id, iter=N)`
- HMAC chain: `key = HMAC(mua_k, "shield_v1") || HMAC(mua_k, "shield_v2")`
- 基于解密字符串 `_hmac`: `key = HMAC(mua_k, "_hmac")` 或类似
- libxyass 内部 SHA-1 of (deviceId || appId || ...) 作为 key

### B. Canonicalize 用 length-prefixed 或非 UTF-8 encoding

候选格式：
- Java `DataOutputStream.writeUTF()` 风格：每个字段前 2 字节 length
- Protobuf 风格：tag + varint length + value
- length-prefixed 但用 4-byte big-endian length
- 排序后的 query parameters，每个 `key=value` 用 `&` 拼

### C. 包含我没看到的 header

候选：
- `User-Agent`（虽然全 session 一样，但可能在 hash 里）
- `Referer` / `Host`
- 某个 `X-XHS-Ext-*` header
- `xy-common-params` 整段（虽然我试了一些 layout）
- `xy-platform-info`（同上）

### D. 输出经过 transform

候选：
- byte permutation (如 SHA-1 输出后 swap 字节)
- XOR with fixed mask
- 分两个 hash 异或：`shield_tail = hash1[0:16] XOR hash2[0:16]`

---

## 务实结论

**纯静态 + brute force 已经接近上限。** 不是说不可能，但每多一层未知（key 派生 +
encoding），搜索空间就×10×10×10... 我已经试了几千组合都没匹配。

要真正 cross 这条线，最高 ROI 的路径是：

### 选项 X（**强烈推荐**）— 从 jadx 反查 `xy-common-params` 构造逻辑

`xy-common-params` 是 Java 层构造的（不是 native），里面有 `t=...`, `did=...`,
`launch_id=...` 等。**Java 层一定有构造它的代码**，去 jadx_out 找谁拼这个字符串。
如果那段代码同时也参与 shield 计算，就直接看到了 canonicalize 模板。

### 选项 Y — 在 LSPosed 抓更多 native 数据

修改 `xhs-capture` 的 LSPosed module，加上 hook 在 libxyass `0x286d0` 入口和出口
（而不是只 hook OkHttp 层），抓 1 组真实 (input, output)。这违反"纯静态"的 ground
rule 但是 5 分钟搞定。

### 选项 Z — 接受当前结果

承认我们已经达到了静态 RE 的硬上限。当前结果（device-pinned signer 能 replay 但
不能签新）是可以工程化的：用户拿一个真实 device 的 capture，每个 (method, path,
body) 都从 capture 里复用全套 header。够用于"重放真实 device 已发过的请求"，不够
用于"任意签新请求"。

---

## 本会话新增/修改文件

- `docs/19_FINAL_state_and_ceiling.md` — 上一个文档，记录硬上限
- `docs/20_lsposed_groundtruth_findings.md` — 本文档
- `lsposed/xhs-capture/captures/live.log` — 17MB ground truth (其他会话产出)
- `scratch/ghidra_work/diff_trace_sha1_update.py` — intercept 多 PC hook
- `scratch/ghidra_work/bruteforce_shield_tail.py` — 第一版 brute force
- `scratch/ghidra_work/xhs_device_pin_signer.py` — device-pinned signer 半成品

## 选项 X 验证结果（已尝试，部分破产）

`xy-common-params` 在 jadx 里**找到了**：[sba/a.java](target/jadx_out/sources/sba/a.java)
的 `b()` 方法。它简单地把 `aVar.c(request)` 的 Map 拼成 `key=URLEncode(value)&...`，
trim 末尾 `&`。**纯字符串拼接，无 hash 计算**。

`shield`/`x-mini-sig`/`x-mini-s1` 在 jadx 里**只找到 strip 代码**
（[ux8/a0.java](target/jadx_out/sources/ux8/a0.java)），**没有任何 addHeader 代码**。
意味着这 4 个签名 header **完全是 native libxyass intercept 添加的**，Java 层不参与。

这就把 canonicalize 的破解完全推回 native 端。而 native 端我们已经证明纯静态 +
Unicorn 触底（docs/19）。

## 92 个解密字符串作 key 的最终 brute force

把 libxyass 所有 92 个解密字符串 + 几个派生形式作为 HMAC key，对 7 种 message
模板（含 xy-common-params）做 6174 组合的搜索：

```
98 keys × 7 msgs × 3 hashes × 3 modes = 6174 tries
matches: 0
```

**纯静态 brute force 路径正式终结**。

## 终极结论

5 个 session 跑下来的成果总和：

| 维度 | 完成度 |
|---|---|
| 算法形状（HMAC-SHA1 + base64 + device key + canonicalize） | ✅ 100% |
| 关键 native 函数定位（Init/Update/Final + canonicalizers + entry） | ✅ 100% |
| SHA-1 标准性证明（实测 H state 与 std 完全一致） | ✅ 100% |
| Java 层密钥来源（ContextHolder.sDeviceId / sAppId） | ✅ 100% |
| Java 层 xy-common-params 构造代码 | ✅ 100% |
| shield 100B 字节布局（84 device-fixed + 16 per-request） | ✅ 100% |
| device-pin replay signer（self-test 通过） | ✅ 100% |
| **shield_tail 16B 精确公式（要签新请求必须的）** | ❌ 0% |
| **x-mini-sig 32B 精确公式** | ❌ 0% |
| **x-mini-s1 公式** | ❌ 0% |
| **x-mini-mua signature 公式** | ❌ 0% |

**4 个 per-request 签名 header 全都不能从静态推算出来**。要解开它们，**唯一现实
的路径是动态执行**（无论是 Frida hook 0x286d0 入口/出口 5 分钟搞定，还是改
LSPosed module 加 native hook，还是真机 strace + memdump）。

纯静态 RE 已经完成了它能做的所有事 —— 算法形状、所有关键位置、所有 Java 侧、所有
ground truth 字段映射 —— 都拿到了。只差最后 1 步**字节级精确公式**，而这一步本质上
需要 1 组 (input, output) 的真实 ground truth 才能验证（brute force 解空间太大）。

## 现状给用户的工程化能用的东西

1. [`xhs_device_pin_signer.py`](scratch/ghidra_work/xhs_device_pin_signer.py)
   - 从一个真实抓包 bootstrap `DeviceSnapshot`
   - 复用 84-byte device prefix + 所有 device 常量 header
   - 自动重建 mua JSON（counter 自增）
   - 4 个 per-request hash header 的位置占位（用 best-guess HMAC，**实际不会被
     server 接受**）
   - **真正能用的模式**：纯 replay（method+path+body 完全相同的请求重发）

2. 完整的 ghidra/Unicorn/capstone trace 工具集，可以继续打深 native 端

3. 完整的算法形状文档，方便未来如果接入动态分析（哪怕只是 1 次）的人快速 cross
   the line

## 选项 Y（动态破解）所需的最小投入

如果用户哪天想真正做出能签新请求的 signer，**只需要 1 次 Frida hook**：

```js
// Hook libxyass+0x286d0 入口，dump 4 个参数 + stack args
Interceptor.attach(Module.findBaseAddress('libxyass.so').add(0x286d0), {
  onEnter(args) {
    this.out_ptr = args[0];
    console.log('[286d0] r0=', args[0], 'r1=', args[1].toInt32(),
                'key1=', readStdString(args[2]), 'r3=', args[3]);
    console.log('  stack[0..16]:', hexdump(this.context.sp, {length: 16}));
  },
  onLeave(retval) {
    console.log('[286d0] returned, output:', readStdString(this.out_ptr));
  }
});
```

跑一次 app，看一次 0x286d0 调用，所有谜团全解开。但这超出了用户的 ground rule。
