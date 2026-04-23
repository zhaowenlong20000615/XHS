# XHS — Brute Force Exhaustion + Cross-Session Findings

**日期**: 2026-04-13 (session continuation)
**目的**: 记录 docs/21 之后做的所有静态 brute force 尝试 + 跨 session 的新发现

---

## 这一轮的实质性新发现

### 1. mua_k 是 **per-request 旋转的** token

这是之前误解的关键修正：

| Capture 文件 | 总样本 | distinct mua_k |
|---|---|---|
| `live.log` | 303 flows | **1** |
| `session1_first_capture_80apis.mitm` | 29 flows | **1** |
| `session2_full_usage_20260411_123810.mitm` | 149 flows | **11** |

**session2 的 11 个 distinct mua_k 给了我们重要的约束求解机会** —— 跨多个 key 同时
满足同一公式的 (key, msg) 组合极少。

### 2. shield_prefix[16:80] **跨所有 mua_k 不变** = 真正的 device-fixed 64-byte 指纹

这彻底澄清了 shield 的结构语义：

```
shield (100 bytes total, base64-encoded as header value)
├── [0:16]  magic + length fields           ── DEVICE-FIXED
├── [16:80] 64-byte device install fingerprint ── DEVICE-FIXED (NOT KDF-derived from mua_k!)
├── [80:84] separator `f79348fb`             ── DEVICE-FIXED
└── [84:100] 16-byte per-request hash        ── PER-REQUEST (★ THE unknown)
```

**关键确认**：64 字节 device fingerprint **不是从 mua_k 派生的**（我测了 MD5/SHA1/HMAC-MD5
of mua_k + counter 都不匹配），所以它是从某个我们看不见的 device-only secret 计算的
（例如 ANDROID_ID 派生 + APK signature hash + 某个 native-only 常量）。

### 3. mua_k 旋转模式确认

session2 里 11 个 mua_k 在 149 个请求中的分布表明：mua_k **每 N 请求轮换一次**
（N ≈ 13）。这跟之前的猜测"per-batch signature"一致。可能的轮换触发：
- 每 N 秒
- 每 N 请求
- 每个新的 navigation context

### 4. shield_tail 跨 mua_k 的强约束 brute force：**0 matches**

用 **149 个 session2 样本 × 11 个 mua_k × 18 msg 模板 × 5 hash × 4 mode = 11520
组合**做约束求解。要求公式同时满足 ALL 149 samples。

```
Total combinations checked: ~11520
Matches: 0
```

测过的所有组合：
- key_form: `mua_k_str` (hex 字符串编码), `mua_k_bytes` (32 字节解码)
- hash: MD5, MD4, SHA-1, SHA-256, RIPEMD-160
- mode: HMAC, prefix-keyed (`H(k+m)`), suffix-keyed (`H(m+k)`), sandwich (`H(k+m+k)`)
- message templates:
  - `M+P`, `M+PQ`, `M\nP\nB`, `M\nPQ\nB`
  - `M\nPQ\nT\nB` (with timestamp)
  - `M\nPQ\nXY\nB` (with xy_common_params)
  - `XY\nM\nPQ\nB`
  - `M_PQ_C_B` (with mua counter)
  - 等等
- match modes: strict (16 bytes equal), loose (bytes 1-15 equal), masked (low nibble + bytes 1-15)
- slice offsets: 0..15 of digest

### 5. AES-128 假设也排除

测试 `AES-128-ECB(key=mua_k[:16/16:32/8:24/shield_prefix[16:32]], ciphertext=shield_tail)`
解密 — 所有候选 key 解出的 plaintext 都是随机字节，无任何可识别的结构（不是 ASCII，
不是已知 magic, 不像 length-prefixed 数据）。

AES 不是答案 —— 至少不是直接 mode + 简单 key。

---

## 完整测试矩阵汇总

| 假设 | 测试方法 | 组合数 | 结果 |
|---|---|---|---|
| HMAC-SHA1 truncated to 16 | 旧版 brute force | 6174 | 0 matches |
| MD5 family + simple keys | `test_md5_hypothesis.py` | 4536 | 0 matches |
| Single-field hash (H1) | `test_focused_hypotheses.py` | ~70 | 0 |
| HASH XOR mask (H2) | `test_focused_hypotheses.py` | ~830 | 0 |
| HASH(prefix\|\|canon) (H3) | `test_focused_hypotheses.py` | ~1080 | 0 |
| Loose match bytes 1-15 (H4) | `test_focused_hypotheses.py` | ~50 | 0 |
| Cross-session 11-key constraint | `test_session2_brute.py` | 11520 | 0 |
| AES-128 ECB decrypt | `test_aes_*.py` | ~16 | 0 |
| **TOTAL** | | **~24276** | **0** |

**每一个我能想到的 plausible 公式都不匹配真实 shield_tail**。

---

## 这意味着什么

剩下的可能性：

### A. canonicalize 包含我没见过的字段（最可能）

可能的隐藏输入：
- **设备硬件 fingerprint**（IMEI, MAC, 序列号 — 这些可能存在 native 端某个 .bss
  缓存里，不在 OkHttp header 中）
- **APK signature hash**（已知 libxyass 调 `getPackageInfo` + `signatures` + `hashCode`,
  这个 32-bit hash 可能参与了 hash 输入）
- **某个 native-internal 计数器或 timestamp**（更细粒度）
- **某个 .bss 全局状态**（在 JNI_OnLoad 时 init 的 64 byte 数组）

### B. 输入序列化不是简单字符串

可能格式：
- **Java DataOutputStream**: `writeUTF` = 2-byte length + UTF-8 bytes
- **protobuf-style**: tag + varint length + value
- **Length-prefixed binary**: 4-byte BE length + raw bytes
- **某种 XHS 自定义二进制格式**

### C. Hash key 是派生的（HKDF / PBKDF2）

Key 不是 mua_k 直接，而是 `KDF(mua_k, salt=device_fingerprint)`。
`_hmac` 解密字符串可能是 KDF 的 info 参数。

### D. 完全自定义 hash with non-standard IV

虽然 ROR 扫描显示 libxyass 只有标准 SHA-1，但 `0x6d1d4 / 0x6dd28 / 0x6ddd4`
内部可能有 CFG-flatten 编码的常量，使得它是个**改了 IV / K table 的 SHA-1 变种**。

每个都需要 native dump 才能验证。

---

## 我能用静态拿到的最后一项 useful info

**`shield_prefix[16:80]` 是绝对的 device fingerprint** — 跨多个 session、多个 mua_k
都不变。

这意味着 **device-pin signer 的 shortcut 仍然 100% 可用**：
1. 从一个真实抓包提取 84 字节 prefix
2. 同一 device 上**所有未来请求**都能用这个 prefix
3. 只需要算最后 16 字节的 per-request hash

如果有一天能 dump 出 hash 公式，**整个 signer 就 ready 了** —— 因为 `xhs_device_pin_signer.py`
已经有了所有 supporting infrastructure。

---

## 待 dump 来时的 1-行 verification

`scratch/ghidra_work/fast_canonicalize_solver.py` 已经写好。一旦
`xhs_native_trace*.log` 文件 land，跑：

```bash
python3 scratch/ghidra_work/fast_canonicalize_solver.py
```

这会自动：
1. 解析 native trace 拿到 (key1, key2, data, output) 真实四元组
2. 对每个真实记录测 ~120 种 hash 构造
3. 第一个全匹配的就是答案
4. 然后跟 OkHttp 层关联，反推 canonicalize 模板

**整个流程 5 分钟**，无需我做任何额外编码。

---

## 本会话新增/修改的文件

| 文件 | 作用 |
|---|---|
| `scratch/ghidra_work/test_md5_hypothesis.py` | 4536 combo MD5 family brute force |
| `scratch/ghidra_work/test_focused_hypotheses.py` | H1-H4 focused hypothesis tests |
| `scratch/ghidra_work/test_session2_brute.py` | 11-key constraint solver |
| `scratch/ghidra_work/fast_canonicalize_solver.py` | (已存在) 等 dump 用的 1-pass solver |
| `scratch/ghidra_work/xhs_device_pin_signer.py` | 更新了 MD5 hypothesis 进 _shield_hash16 |
| `docs/21_canonicalize_low_architecture.md` | (已写) 架构 deep dive |
| `docs/22_brute_force_exhaustion.md` | 本文档 |

## 结论

**纯静态分析已经触达天花板**。所有可枚举的 hash 公式都不匹配。剩下的未知数
（隐藏 input 字段 / 序列化格式 / 派生 key）都是 **non-enumerable** 的，必须通过
**1 次 native function dump** 才能解开。

现在等待另一个窗口的 LSPosed module 修复 + 部署完成。
