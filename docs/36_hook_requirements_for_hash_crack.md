# Frida/LSPosed Hook 需求文档 — libxyass shield hash 数据采集

**目的**: 我 (Unicorn 黑盒 signer 窗口) 已经把 shield canonicalize **字节级构造完美** (6/6 Frida 样本 byte-exact regression),但 shield 最后那 16 字节 hash 算法没破解。这个 hash 在 libxyass 里被 OLLVM CFG-flattened + C++ vtable 分派包装,我静态逆向 + Unicorn 动态暴力都走不下去了。

需要你在**真机 LSPosed 环境**(不需要 Frida,LSPosed 足够)下 hook libxyass 的几个关键点,把数据 dump 出来给我。

---

## 背景简述 (可跳过)

1. shield 格式 = `"XY" + base64(84B device_prefix + 16B tail)`
2. `shield_tail = hmac_b64_input XOR DEVICE_MASK_16B`,DEVICE_MASK 已知
3. `hmac_b64_input` 是 canonicalize 经 hash 后的 16 字节输出,**这就是要 hook 的目标**
4. hash 函数入口在 libxyass `op_update @0x6dd28`,但它是个 C++ virtual dispatcher (156 字节):
   ```
   struct_ptr = r0 + 0x44 → inner_obj
   if (*inner_obj == 0) return 0;              ← 我们 emu 这里永远短路
   r0 = inner_obj[+4] → data_buffer_struct
   r3 = data_buffer_struct[+0xc] → real_compress_fn
   blx r3                                        ← 真正的 hash 在这里调用
   ```
5. `data_buffer_struct[+0xc]` 的 `real_compress_fn` 地址我们不知道。只要知道这个地址 + 它的 calling convention,Unicorn 就能把它当子函数调。

---

## 具体 Hook 需求 (按优先级)

### 🔴 P0 — 必须 (没这个下一轮彻底过不去)

**Hook A**: `libxyass + 0x6dd8e` (op_update 内部的 `blx r3` 指令)

这条指令**就在 cbz 之后、blx 之前**。hook 时 `r3` 的值就是**真实的 hash compress 函数地址**。同时 dump 参数 `r0/r1/r2`。

**Dump 格式** (JSON,每次调用一条):
```json
{
  "event": "op_update_dispatch",
  "libxyass_base": "0x7bdc0000",     // 真机地址,用于我这边算 offset
  "pc": "0x7bde3d8e",                // 绝对地址 (lib_base + 0x6dd8e)
  "r0_struct_ptr": "0xf5148010",     // 第 1 个参数 (C++ this — data buffer 结构体指针)
  "r1_data_ptr": "0xf5148020",       // 第 2 个参数 (要哈希的 raw 字节)
  "r2_length": "0x2e4",              // 第 3 个参数 (字节数)
  "r3_target_fn": "0x7bdbc510",      // ★★★ 真实 hash 函数的绝对地址 ★★★
  "r3_offset_from_lib": "0xbc510",   // r3 - lib_base → 我可以直接用这个 offset
  "struct_ptr_content": "hex",       // 可选: r0 指向的前 0x40 字节,用于还原 struct 布局
  "data_ptr_content": "hex"          // r1 指向的 r2 字节 (canonicalize bytes)
}
```

**为什么需要**: 只要知道 `r3_offset_from_lib`,我就能在 Unicorn 里用 `signer._call(uc, lib_base + r3_offset, (r0_struct, r1_data, r2_len))` 直接调用真 hash 函数,完全绕过 OLLVM CFG 和 C++ vtable 分派。

### 🔴 P0 — 必须

**Hook B**: 同一次 `blx r3` **返回后** (即下一条指令 `libxyass + 0x6dd90`)

dump 返回值 + **struct_ptr 内容变化**(前 0x40 字节),这告诉我 hash 函数把结果写到哪里了 (state 内部? 独立 out_buf? ctx 里某个 offset?)

```json
{
  "event": "op_update_return",
  "pc": "0x7bde3d90",
  "r0_return": "0x...",              // blx r3 的返回值
  "struct_ptr_content_after": "hex"  // 同一个 r0_struct_ptr 的前 0x40 字节
}
```

**关键**: 对比 Hook A 的 `struct_ptr_content` 和 Hook B 的 `struct_ptr_content_after`,看 hash 函数改了哪些字节。如果某 16 字节区域从 `[MD5 IV]` 变成 `[新 state]`,就是 MD5 的 h[0..3]。

### 🟡 P1 — 强烈建议 (能省我几个小时)

**Hook C**: `libxyass + 0x286d0` (hmac_b64 wrapper 入口)

dump 栈上第 2、3 个参数 `[sp+8]`, `[sp+c]` (就是 16 字节 data_in 和 data_len),加上 `r3` (app_id)。

```json
{
  "event": "hmac_b64_entry",
  "pc": "0x7bd9e6d0",
  "r0_out_ptr": "0x...",
  "r1_alg": 1,
  "r2_key1_str": "...",               // std::string 指针,dump 字符串
  "r3_app_id": "0xecfaaf01",
  "sp_8_data_ptr": "0x...",           // [sp+8] = 16B data_in 指针
  "sp_8_data_content": "hex",         // 16 字节 hash 输出 ← 这就是 hmac_b64_input!
  "sp_c_data_len": 16
}
```

**为什么需要**: 给我第二份 (canonicalize, digest) pair, 和 op_update 的 dispatch 点做 **cross-reference 确认**。

### 🟡 P1 — 能有最好

**Hook D**: 对每个请求,同时 dump:
- 该请求的完整 canonicalize bytes (从 op_update 的 r1/r2 读)
- 该请求最终产出的 shield header (从 JNI `Request.Builder.header("shield", ...)` 或直接抓 HTTP)

我已经有 48 对历史样本,但那些 session state 不同不好复现。新的样本最好**同一 session 连续捕 20-30 个**,保证 session-level invariants (key1/key2/DEVICE_MASK) 恒定,方便做差分分析。

### 🟢 P2 — 可选

**Hook E**: `libxyass + 0x6d0f0` (alt_hash_init 入口) 和 `libxyass + 0x6d176` (init 里那个 `bl 0x6ec38` 构造器调用点)

dump 两个 malloc 的返回值 (284B ctx + 148B inner),以及**构造器返回后 inner 的前 0x20 字节**。

**为什么**: 我想看 inner object 的 [+0] flag (我们 emu 里永远是 0) 在真机上被谁何时置成非零。这是整个死锁的根因。

---

## Hook 怎么装 (LSPosed 真机)

lsposed/xhs-capture 模块已经有成熟的 libxyass hook 框架 (scratch/native_trace/full_trace_*.log 就是它的输出)。加几个 offset 就行:

```java
// 伪代码,参考 xhs-capture 现有 module
libxyass_base = findBase("libxyass.so");

installHook(libxyass_base + 0x6dd8e, onDispatchBeforeBlx);   // Hook A
installHook(libxyass_base + 0x6dd90, onDispatchAfterBlx);    // Hook B
installHook(libxyass_base + 0x286d0, onHmacB64Entry);        // Hook C (可能已经有)
// Hook D 复用 xhs-capture 现有的 HTTP capture 模块
```

**P0 A+B 最重要** — 只要给我 A 的 `r3_offset_from_lib` 和 B 的 `struct_ptr_content_after`,我就能继续推 Unicorn 黑盒路径。

---

## 输出格式约定

把每一条 event 以 JSON line 写到一个日志文件,例:

```
scratch/native_trace/hash_probe_YYYYMMDD_HHMMSS.jsonl
```

每行是一个完整 JSON 对象。运行 3-10 个真实 HTTP 请求 (任何 xhs app 操作,哪怕划 feed) 就够了。

---

## 我这边能用上这些数据做什么

1. **P0 A+B → 直接用**: 拿到 `r3_offset_from_lib`,在 Unicorn 里加一个新 hook:
   ```python
   # unicorn/sign.py 的第 5 个 hook
   def _real_hash_compress(uc, pc, size, _ud):
       # 在 op_update 的 blx r3 位置,绕过 cbz
       # 直接调用 signer._call(uc, lib_base + r3_offset, (r0, r1, r2))
       ...
   ```
   这样 `op_update` 内部就会**自然地**跑真 hash 函数,无需破解算法本身。

2. **P1 C → 验证闭环**: 拿 Hook C 的 `sp_8_data_content` 和我 emu 产出的对比,byte-exact 通过 → 直接过 server 验签。

3. **P1 D → 新 regression set**: 20-30 对样本比我手头的 48 老样本质量高一个数量级。

4. **P2 E → 根因补丁**: 知道 flag 被谁设了后,我能在 Unicorn 里加个 mem patch 让 cbz 自然过,不用 force r0=1 这种 hack。

---

## 交付后我这边的工作量

拿到 P0 A+B 数据后,预计 **1-2 小时**能产出:
- 更新 `unicorn/sign.py` 的第 5 个 hook,直接用真机地址调 hash
- 跑 `scratch/test_canonicalize_byte_exact.py` 验证不退化
- 写一个 `test_shield_hash_byte_exact.py` 对比 Frida pair 的 digest → 目标 48/48
- 整合到 note CRUD 实测脚本 (`scratch/test_note_crud.py`)
- 把 memory / todo 清理干净,提交 checkpoint

## 如果拿不到数据 (备选)

那只有走**更底层的 Ghidra 手工逆向 alt_hash_update OLLVM CFG**,预计 5-10 小时,不保证成功。或者等我能拿到能 overlay 进 Unicorn 的新版 cPtr snapshot (需要修 xhs-capture 的 heap_object dumper bug —— 它把 ASCII 字符串数据误当成了指针地址,0x6e6f6973 "nois" 这类)。

---

## 附录: 当前 signer 状态快照

- `unicorn/sign.py` — 4 hook pipeline (gate/capture/force_eof/inject SHA1 fallback)
- `unicorn/java_headers.py` — 35 字段 xy-common-params byte-exact
- `unicorn/xhs_signer.py` — `XhsIdentity` 完整 override 面
- `scratch/test_canonicalize_byte_exact.py` — 6/6 regression 守卫
- `scratch/native_trace/canonicalize_pairs*.jsonl` — 48 个旧样本 (input+digest)
- `scratch/ghidra_work/full_proj` — libxyass 已做过 full auto-analysis 的 Ghidra 工程

Unicorn 端我测了能产出**结构完美但 hash 数值错**的 shield,注入 Python SHA1 作 fallback 的版本每次能产出 per-request-varying output。canonicalize 6/6 matches real device byte-for-byte。唯一缺的就是那 16 字节 hash。
