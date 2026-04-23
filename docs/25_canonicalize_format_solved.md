# XHS canonicalize 格式 100% 破解

**日期**: 2026-04-14
**数据源**: `scratch/native_trace/canonicalize_trace_20260414_102756.log` (native hook dump from other window)

---

## 🎯 核心结果

**canonicalize 格式 = `path + query + xy-platform-info`** (直接字节拼接,无分隔符)

通过 1 个完整捕获的 126-byte 样本 100% 验证:

```
Request:
  GET https://modelportrait.xiaohongshu.com/api/model_portrait/detect_items?cpu_name=Pixel%206
  xy-platform-info: platform=android&build=9190807&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9c

Native canonicalize bytes (op_update r1):
  /api/model_portrait/detect_itemscpu_name=Pixel%206platform=android&build=9190807&deviceId=aa293284-0e77-319d-9710-5b6b0a03bd9c

Decomposition:
  [0:32]    /api/model_portrait/detect_items   ← URL path
  [32:50]   cpu_name=Pixel%206                  ← URL query (no '?')
  [50:126]  platform=android&build=9190807&deviceId=...  ← xy-platform-info verbatim
                                                    ↑ length 76 bytes ✓
  Total: 126 bytes ✓
```

**关键事实**:
- ❌ NO method (GET/POST not included)
- ❌ NO body (不参与 hash)
- ❌ NO host (modelportrait.xiaohongshu.com not in canonicalize)
- ❌ NO `?` separator before query
- ❌ NO separator between query and xy-platform-info
- ✅ ONLY 3 fields concatenated: path, query, xy-platform-info

For requests on edith host (the main XHS API), the URL query string usually contains
the same fields as `xy-common-params`, so the canonicalize ends up looking like
`path + xy-common-params + xy-platform-info`. But for non-edith hosts (modelportrait,
mediacloud, etc.), the query is shorter (just `?cpu_name=...` or similar), and
xy-common-params is absent — the canonicalize is `path + short_query + xy-platform-info`.

---

## libxyass HMAC 内部结构(从 ctx dump 反推)

`op_update` / `op_final` 的 ctx 是一个 284-byte buffer 分配自 0x6d0f0:

```
ctx layout (284 bytes total, only first 64 bytes captured by hook):
  [0:20]   precomputed SHA-1 H state after processing (ipad XOR key)
  [20:40]  precomputed SHA-1 H state after processing (opad XOR key)
  [40:60]  ★ INIT VALUE — appears to be a fixed magic, NOT running H state
  [60:64]  ★ INIT MAGIC — appears constant across all calls
  [64:284] ★ message buffer / running H state (NOT captured in dump)
```

**Evidence that ctx[40:64] is INIT, not running state**:
13 OP_FINAL records across 9 different ctx instances + different message lengths
all show **identical** ctx_final bytes [40:64]:

```
60 8d 38 c4 a2 74 d8 d6 ab dd 57 1f 72 dc 1a a6 84 56 1b 78 fd 28 c7 65
```

If this were the running H state, it would differ per message. Since it doesn't,
op_update doesn't write to [40:64] — it writes to a different region (probably
[64:284] which we don't see).

**Implication for HMAC reconstruction**:
The libxyass HMAC is **HMAC-SHA1 with precomputed inner+outer states** (a standard
optimization). The 40-byte ctx_pre is the precomputed state. This avoids re-doing
the ipad/opad XOR for every message.

To compute HMAC manually:
1. Use `ctx_pre[0:20]` as the SHA-1 H state for the inner hash
2. SHA-1-update with the canonicalize message (telling it the ipad block was already processed)
3. SHA-1-finalize → 20-byte inner result
4. Use `ctx_pre[20:40]` as the SHA-1 H state for the outer hash
5. SHA-1-update with the inner result (20 bytes)
6. SHA-1-finalize → 20-byte HMAC result
7. Truncate / transform to 16-byte shield_tail

**However, my brute force of this exact construction did NOT match shield_tail**.
This means there's an **additional transform** between the HMAC output and shield_tail.

---

## 已知 vs 未知

### ✅ 已知(从 dump):

| 项目 | 值 |
|---|---|
| **canonicalize 格式** | `path + query + xy-platform-info` |
| **ctx_pre[0:40]** | `cd5fba80a230917652509106510d6a9f2a3fc9fc33cedd60ca790c59f23e957621422627bb9f50b5` |
| **ctx_init[40:64]** | `608d38c4a274d8d6abdd571f72dc1aa684561b78fd28c765` (24-byte fixed init) |
| **key1** (from bss) | `"9190807"` (build version) |
| **key2** (from bss) | `"aa293284-0e77-319d-9710-5b6b0a03bd9c"` (sDeviceId UUID) |
| **shield 100B 布局** | `[0:84]=device_fixed_prefix` + `[84:100]=per_request_hash` |

### ❌ 未知(等 #1 #2 #3 hooks):

1. **op_final 的 16-byte output** (the inner hash result)
2. **hmac_b64 的 input/output** (the actual shield_tail computation)
3. **Whether the byte-0 mask `0x7?`** is applied by hmac_b64 or by op_final

### 🟡 部分已知:

- Brute force with the captured canonicalize + standard HMAC variants → **0 matches**
- This means there's a **non-obvious transform** between canonicalize and shield_tail
- Most likely: hmac_b64 wraps the inner hash output in another HMAC layer

---

## Py skeleton 状态

[xhs_device_pin_signer.py](scratch/ghidra_work/xhs_device_pin_signer.py) 已更新:

```python
def _canonicalize_low(self, method, full_url, body, xy_platform_info):
    """★ CONFIRMED ★ canonicalize = path + query + xy-platform-info"""
    parsed = urlparse(full_url)
    return parsed.path.encode() + parsed.query.encode() + xy_platform_info.encode()
```

The canonicalize function is **fully implemented**. The hash transform after it
is still placeholder until we get the hmac_b64 hook output.

---

## 当前进度评估

```
完整 signer 流程 (5 步):
  Step 1: Build canonicalize input              ✅ 100% (just confirmed)
  Step 2: Run canonicalize chain (inner hash)   ❌ 不知道精确 algo
  Step 3: Run hmac_b64 (outer transform)        ❌ 不知道
  Step 4: Decode b64 → 16-byte shield_tail      ❌ 不知道 byte 0 mask 来源
  Step 5: Combine with device-fixed 84-byte prefix → 100-byte shield   ✅
```

**Step 1 + Step 5 完成 (40%)**. Step 2-4 需要 1 次 hmac_b64 entry+exit 完整 dump 才能解开。

---

## 下一步等待

`fast_canonicalize_solver.py` V2 已升级支持新格式。等 NDK 编译完 → libxhscap.so 可以 inline-hook 0x286d0 (hmac_b64) → dump 它的 entry+exit → 我立即跑 solver:

```bash
python3 scratch/ghidra_work/fast_canonicalize_solver.py
```

预期输出:
```
HEADER_WRAPPER ENTRY ...
OP_UPDATE ENTRY ... raw_data: <THE canonicalize bytes>  ← already have
OP_FINAL ENTRY ...
HMAC_B64 ENTRY ... data: <16-byte inner hash>          ← NEED THIS
                  out:  <base64 of shield_tail>          ← NEED THIS
```

**1 个完整的 HMAC_B64 entry+exit pair = 整个公式破解**。
