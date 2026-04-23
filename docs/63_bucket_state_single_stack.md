# 2026-04-20 EOD7 libtiny bucket state 单栈化 — 真根因又前进一层

**⚠️ 后续 round 2-4 反证更新**: 栈/sl 假设已被 FORCE_C/JNI_TRACE/多尺度 COUNTER_PROBE 推翻。见下文 "Round 2-4 反证" 节。

## 今日关键进展 (接 docs/62)

用 BlockHook + COUNTER_PROBE + 反汇编组合, 把 172B gap 的根因从"bucket hash 函数"追到"state 指针来源"。

## 工具链 (全部 unidbg 黑盒)

1. **BlockHook with sign marker** (XhsCombinedSigner.java blockTraceWriter)
   - sign() 入/出注入 `{"marker":"sign_start","sseq":N}` 到 block_trace.jsonl
   - BlockHook 只在 `blockTraceInSign=true` 时记录, per-sign 50k 上限
   - → 4 次 sign × 40k blocks = 160k 可 diff 数据

2. **diff_blocks.py / diff_blocks_v2.py** (scratch/2026-04-20_bucket_hash)
   - v1: set diff 找 URL-only PCs
   - v2: multiset 找 URL-depdendent 的 count 差异热点

3. **COUNTER_PROBE WriteHook** — 过滤 sign 内 size=4, value∈[1,100] 的所有写入, per-sign 50k 上限
   - 分析找 "每 sseq 最后一次写入 == sseq+1" 的 slot
   - 结果: **栈 0xbfffc500 / 0xbfffc254 是 c 写入点**

4. **TARGETED_WRITE hook** 追这两个栈写入的 PC
   - PC=libtiny+0xf6f06 (r1=c value str to 0xbfffc500)
   - PC=libtiny+0x570d78 (r0=c value str to 0xbfffc254)

5. **SL_PROBE** at libtiny+0xf6f0a
   - sl = 0xbfffc0c8 **恒定**, r7 = 0xbfffc5c8 恒定
   - 但 sl+0xf4/0xfc 每次 sign 持久变化 → 栈 frame 复用

## 诊断

libtiny sign 函数大致结构:
```
state_ptr = bucket_lookup(url)   // 真机返不同指针, unidbg 固定
state_ptr->c += 1                // write 0xbfffc500/0xbfffc254
...JSON encode with c...
```

**真机**: `state_ptr` 来自 heap 上 per-URL HashMap<URL,State> 查找, 每 URL 独立 struct → c 独立递增
**unidbg**: `state_ptr` 都指向 fixed stack addr (sl+0xf4 一带) → 所有 URL 共用同一 c

## 为什么 sl 固定?

- ARM Thumb 里 sl (r10) 被 libtiny 用作本地 frame 基址指针 (不是 TLS)
- sign cmd 入口函数的 stack 初始化是 "sl = sp - N", sp 在 unidbg 每次调用一样
- 真机 sign 可能在不同 thread 里被调 (pthread 分发), sl 不同
- 或真机 sign 入口查 bucket, 把 state heap ptr 存给 sl, 我们 bucket 查找退化为 fallback

## pthread_create 被 hook 的影响 (猜测未证实)

`XhsCombinedSigner:256-276` 把 pthread_create 拦成 "捕获参数但不创建线程", 之后在主线程顺序跑线程函数。真机 libtiny 若依赖多线程各自 TLS/state, 这里会被塌陷。

## 今日反汇编洞察

1. **libtiny+0x8ef44** 周围是 HashMap<hash,X> bucket lookup (Murmur 风 fmix + popcount + `hash & (cap-1)` / `hash % 47`), cap=47. URL_A/B 算出不同 hash (0x6c423c07 / 0x5d6281e9 / 0x9301e511) 落不同 bucket, **不是**单桶根源。
2. **libtiny+0x16efbe** 是 `std::map::find` (红黑树 + 字符串 SSO memcmp 循环), URL_A 走次数是 URL_B 10 倍以上, 但也不是 counter 存储。
3. **c counter 写入 PC** = 0xf6f06 / 0x570d78, 值从 sl+0xf4 读出 +1 写回.

## 下次攻击点

1. 追 sl 的**来源** — 在 sign cmd 入口加 hook 记录 `state_ptr = ?` 被赋给 sl 的那一条指令 (ldr/mov/str to r10)
2. 如果 sl 来自某个 `ldr r10, [..., #offset]`, 反汇编看 offset 是不是 HashMap value
3. 真机做的 pthread_create 捕获的线程函数当前在主线程串跑 (pendingThreads), 看能否让每次 sign 分配独立栈 (手动 fork emulator state)

## 今日前进清单

- ✅ sign() 加 BlockHook marker, diff 出 URL-dependent PC
- ✅ 反汇编 3 候选 PC, 排除 0x8ef44 (HashMap 多桶) / 0x16efbe (std::map find)
- ✅ COUNTER_PROBE 定位 c 写入栈地址 (0xbfffc500, 0xbfffc254)
- ✅ TARGETED_WRITE 定位 c 写入 PC (0xf6f06, 0x570d78)
- ✅ SL_PROBE 证实 sl 每次 sign 恒定 → 单桶根因是 state ptr 源

## Why / How to apply

**Why**: 这是把 docs/62 "bucket hash 单桶" 假设进一步细化为 "state ptr 指向固定栈地址" — 假设从"哈希层面"降到"指针来源层面"。黑盒 WriteHook + CodeHook 组合让我们定位到 c 的精确写入点和栈地址, 不用改 libtiny 一条指令。

**How to apply**:
- 默认 unidbg 继续带 FIX_D7_EOR + D7_REPS=46 (cptr 有价值)
- 追 sl 源头时用 CodeHook hook `sign cmd entry PC`, 记录 sl 被赋值 PC
- 如果确认 sl 来自 bucket lookup, 那真正破 172B gap = 让 bucket lookup 返不同指针, 即 per-URL state 初始化
- docs/62 的 HashMap URL-hash 不是天花板, 真正天花板在 state 分配 (per-URL malloc)

---

## Round 2-4 反证更新 (同日 EOD)

### Round 2 (FORCE_C 实验) — 推翻 "栈是 c 源"

加 `FORCE_C=N` CodeHook at lib+0xf6f06: 每次 hook 执行都把 0xbfffc500/0xbfffc254 覆写成 N=11. 实测 mua JSON 里 c 仍正常递增 2,3,4,5 — **栈 0xbfffc500 不是 c state**, 只是某局部 buffer 的 write 目标。

### Round 3 (JNI_TRACE + MUA_PUT_TRACE) — JSON 全 native 内生成

- `JNI_TRACE=1` 覆写 getStaticIntField/getStaticObjectField/getIntField: 只读 3 个 Java field (versionCode, sAppId, sDeviceId), init 时各 1 次. c 不走 Java field.
- `MUA_PUT_TRACE=1` 在 HashMap.put capture 打 PC/LR: key='x-mini-mua', value=`base64(JSON).base64(sig)` 完整串, PC=lib+0xbfd60284 (Java 层), LR=lib+0xb536f. **native 端完整产出 JSON + base64**, c 在 native 内部算然后直接编码进 JSON buffer。

### Round 4 (多尺度 COUNTER_PROBE) — per-URL bucket 存在但 c 非其字段

扩 COUNTER_PROBE 支持 size=1/2/4/8, 排除栈, per-sign 1M cap. 结果:

- **HEAP(0x4027f1a0) sz=8**: 仅 URL_B (sseq=2,4,6,8) 写入, value=145 恒定
- **HEAP(0x4027f1b0) sz=8**: 仅 URL_A (sseq=1,3,5,7) 写入, value=145 恒定
- **libtiny+0xb42000** (URL_B) / **libtiny+0xb421c0** (URL_A): per-URL base64 JSON buffer, 固定地址
- **libtiny+0x5ceb18 / +0x5ceb1c** sz=4: 全局 bump counter, 每 sign 增 168 / 176 (byte 计数)

**关键**: per-URL heap bucket 实在 (0x4027f1a0/1b0 不同 URL 写到不同 slot), 但 value 是 flag 不是 counter. libtiny 里没找到任何 "每 sseq last-value == sseq+1" 的 4B 对齐 slot → **c counter 不是简单 u32**。

### 结论

- 从 docs/62 "bucket hash collide" → docs/63 初版 "sl 单栈" → 现在 "per-URL bucket 存在但 c 非其字段"
- c 可能: bit-packed / OLLVM 加密间接访问 / ldr+1+str 但写不落 4B 对齐地址
- 真机 per-URL c 独立 vs 我们 global c 单调 的差异根源仍未找到

### 下次攻击点 (优先级)

1. 反汇编 libtiny+0xb5350 JNI wrapper caller (需扫 bl/blx/indirect jump), 追 base64 完成到 put 的上一层
2. 在 sign cmd 入口 (-1750991364 dispatch) 装 hook, 记录第一条 malloc 或 state-alloc 返回的指针
3. 用 instruction-level CodeHook 在 lib+0xf6ef0..0xf6f20 窗口, 捕获 c 相关的 ldr/add/str 序列
4. Dump libtiny.bss 0x5ceb00 周围 64 字节, 看邻接 struct field

### 当日文件

- `scratch/2026-04-20_bucket_hash/diff_blocks.py` / `diff_blocks_v2.py` / `disasm.py` / `disasm2.py` / `disasm3.py` / `disasm4.py`
- `find_counter.py` / `find_counter_v2/v3/v4/v5.py` / `find_perurl.py` / `find_c_byte.py`
- `block_trace_2url.jsonl` (40k blocks per sign × 4)
- `counter_probe_v5.jsonl` (size 1/2/4/8 全写入, non-stack)

### Probe env vars 汇总 (XhsCombinedSigner.java 新增)

| env var | 作用 |
|---------|------|
| `BLOCK_TRACE=path` | BlockHook 写 per-sign block 入口到 jsonl |
| `BLOCK_TRACE_IN_SIGN=1` | 只在 sign() 边界内记录 |
| `BLOCK_TRACE_PER_SIGN=N` | per-sign block 上限 |
| `COUNTER_PROBE=path` | WriteHook 写 size 1/2/4/8 到 jsonl |
| `COUNTER_PROBE_NOSTACK=1` | 排除栈地址 |
| `TARGETED_WRITE=addr1,addr2` | 精确地址 WriteHook 带 PC |
| `BUCKET_PROBE=1` | hook 0x8ef44 (HashMap bucket lookup) |
| `SL_PROBE=1` | hook 0xf6f0a 读 sl |
| `SL_TRACE=1` | 每 block 入口 sl 变化 |
| `FORCE_C=N` | hook 0xf6f06 覆写 c=N 到栈 |
| `MUA_PUT_TRACE=1` | 在 HashMap.put capture 打 native caller |
| `JNI_TRACE=1` | trace 所有 JNI field 访问 |
| `MULTI_URL=2` | 仅 2 URL 轮换 (减少 diff 噪声) |

