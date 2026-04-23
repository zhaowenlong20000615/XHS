# XHS libxyass — 完整静态分析最终版

**日期**: 2026-04-13 (session continuation)
**状态**: 静态分析的所有 productive 角度都挖完了。剩下的细节需要 native dump。

这是 docs/22 之后通过 **完整反汇编 0x24bcc + 0x26c6c 重新 probe + intercept 完整 trace** 得到的最终架构理解。

---

## 这一轮新发现的 6 个事实

### 1. **`0x26c6c` 是 `std::string` 拷贝构造函数**(不是 canonicalize)

之前误判:从 probe 输出看 `out = in[0:4] + in[16:end]`,以为是 string parser/canonicalizer。

**真相**:它是 **libc++ `std::string::string(const std::string&)`**。当我用 std::string 结构(SSO 或 LONG 模式)作 input 重新 probe 时,output 完全是 input struct 的 byte-by-byte copy:

| Input(std::string) | Output(64-byte buf) |
|---|---|
| SSO `b'abc'` | `06 61 62 63 00...` (size=3<<1, "abc") |
| LONG 21 字节 | `25 00 00 00 ...` (cap=37,LSB=1) |

之前的"奇怪截断"是因为我用 C string 当 std::string struct,函数读到的"data ptr"是垃圾。

### 2. **intercept 调 `0x24a1c` (header_wrapper) 只 1 次**

不是之前以为的"per-header 6-12 次"。整个 intercept 函数体只有一处 `bl 0x24a1c` at 0x2474c。

### 3. **intercept 调 `0x1ee70` (add_header) **4 次**, enum = 5, 6, 7, 8**

```
0x23eba: add_header(..., r3=5)   ← shield?
0x2466e: add_header(..., r3=6)   ← x-mini-mua?
0x2471a: add_header(..., r3=7)   ← x-mini-sig?
0x247a4: add_header(..., r3=8)   ← x-mini-s1?
```

每个 call 之前都做 SIMD 4x vst1.32 zero-init 一个独立的 std::string output,然后:
```
ldr r1, [r0, #0x40]   ; r1 = name_ptr (or similar)
ldr r2, [r0, #0x4c]   ; r2 = value_ptr
mov r0, r5            ; r0 = different per call
movs r3, <enum>
bl 0x1ee70
```

这表明 add_header 的真实签名是 `add_header(headers_obj, name_ptr, value_ptr, enum)`,
**name 和 value 来自一个预构建的 struct 在 r0 处**,不是计算出来的。

### 4. **`cmp r0, #6` 在 0x24a1c 比较的是 `*r3` = std::string cap field**

0x24a1c 的 r3 = sp+0x98 = 一个 64-byte buffer that contains a std::string at offset 0
(populated by 0x26c6c) plus other state. `*r3 = first 4 bytes of std::string struct`:
- LONG mode: cap field (e.g., 0x21 for 16-byte string)
- SSO mode: byte 0 = size << 1 (e.g., 0x06 for 3-byte string)

`cmp r0, #6` → `cap < 6` 意味着 std::string is empty / very short → low path (0x24ea0)。
否则 → high path (0x24bcc)。

**这是 dispatch by string length, NOT by header enum**。

### 5. **canonicalize_high (0x24bcc) 完整流程**(via full disasm)

```
0x24c40: SHA1_Init(sp+0x34)        ← initialize hash ctx

LOOP body (0x24c72-0x24d42):
  vtable[0xb62ec14] iter           ← CFG-flatten dispatcher (next iter object)
  vtable[0x300] virtual call       ← get next byte ptr + length
  alloc 8208 bytes (op_new)
  __aeabi_memset(buf, 0x2000, 0x20)  ← fill 8KB with spaces (DECORATIVE)
  HEX-encode loop using `0123456789abcdef`  ← decorative hex output
  free 8KB                          ← op_delete
  bl 0x2ad80: SHA1_Update(ctx, RAW_bytes, length)   ← ★ THE actual hash input ★
  ...continue loop until iter returns -1...

0x24d54: SHA1_Final(sp+0x34, sp+0xc0)   ← 20-byte digest at sp+0xc0

SWITCH on ctx_int (the std::string cap field):
  case 6:
    bl 0x2b838(r6+4, 0x40, sp+0xc0, 0x14, sp+0x90)
        ↓
        HMAC-SHA1 outer pass:
          key = caller-provided state at r6+4
          key_size = 0x40 (block size)
          inner = sp+0xc0 (first SHA-1 result, 20 bytes)
          inner_len = 0x14 (= 20)
          output = sp+0x90
  case 7:
    different branch at 0x24db4
  default:
    yet another branch at 0x24e08

bl 0x2696c   ← base64 encode the final hash
```

**关键观察**:
- The hex-encoding loop at 0x24cb2-0x24cf2 is **DECORATIVE** — it allocates 8KB,
  fills with hex, but the SHA1_Update is fed the RAW bytes (sb), not the hex buffer.
  The hex encoding might be for log output or std::string display.
- The loop iterates over an ABSTRACT iterator (vtable-driven), so the input
  fields are determined dynamically. We can't statically know which fields.

### 6. **`0x2b838` 是 HMAC outer pass**(virtual confirmation)

940-byte stack frame, 0 ROR ops in 2KB scan(全部 CFG-flatten 编码),0 SHA constants visible. 但调用约定与 HMAC outer pass 完美匹配:
```
bl 0x2b838(r0=r6+4_key_state, r1=0x40_block_size, r2=inner_hash, r3=20_inner_len, sp[0]=output_buf)
```

This is `H(K_outer || H_inner_result)` where:
- K_outer = `r6+4` = something the caller (intercept or 0x24a1c) provided
- H_inner_result = `sp+0xc0` (first SHA-1 output, 20 bytes)
- output → `sp+0x90`

---

## 真正阻塞静态分析的 3 个未知数

### A. **vtable iterator 在 canonicalize_high 中遍历的是什么对象**?

`vtable[0x300]` 和 `vtable[0xb62ec14]` 是 CFG-flatten 编码的 function pointer indices。
真实的 dispatch target 需要 emulate 时 inspect runtime memory state,静态推不出来。

但我 KNOW:
- 它返回 `(byte_ptr, length)` 对
- 每次 iteration 提供一组字节 → SHA1_Update
- 直到 iter 返回 -1 (`adds r0, #1; bne loop`)

最可能的来源(基于 intercept 的上下文):**Request 对象的 fields list iterator** — 遍历 (method, host, path, body, headers...) 中的每一个 field。

### B. **`r6+4` 处的 outer key 是什么**?

`r6 = ctx_struct_ptr`(intercept 传入的 sp+0x98 buffer)。
`r6+4` = 64-byte buffer 的第 5 个字节起。

在 intercept 里,sp+0x98 是用 4x vst1.64 SIMD 零初始化的,然后 `bl 0x26c6c` 拷贝一个
std::string 进去。**std::string copy 的 12 字节 cap/size/dptr 占据 sp+0x98..sp+0xa4**。
`sp+0x9c (= sp+0x98 + 4) = std::string 的 size 字段`。

If LONG mode: `r6+4 = size field` (a 32-bit integer).
But that doesn't make sense as a HMAC outer key.

More plausible: **the buffer is a struct, and after the 12-byte std::string at offset 0,
there's additional state at offset 12+**. The "outer key" might be at sp+0xa4 onwards,
populated by some other code I haven't traced.

OR: `r6+4` might be misread by me. The actual access could be `r6` (not `r6+4`). Let me re-verify.

### C. **add_header(r0, ?, ?, enum)` 中 `r0` 指向的 struct 长什么样?**

每个 add_header call 用不同的 r0(r5 / r4 / [sp+0x5c]),且都做了 SIMD init。这 4 个
struct 是 4 个独立的 header value 容器。它们的内容(name + value bytes)从某个**早期
计算的结果**抽取。

哪个早期计算?这是关键 — 如果能找到,就找到了 hash。

---

## 修正的整体架构

```
intercept(env, this, chain, cPtr) {
  // Phase 1: extract request fields
  url     = chain.request().url()
  method  = chain.request().method()
  body    = chain.request().body().toBytes()
  
  // Phase 2: compose canonical input (multi-step, multi-buffer)
  setup_at_sp_plus_98()       // 64-byte buffer
  std::string_copy(sp+0x98, sl[0x18])   // 0x26c6c — copy one field
  
  // Phase 3: build header value containers (4 of them, one per signature)
  // Each is initialized by SIMD vst1.32 zero
  // Each gets a name + value populated somewhere
  
  // Phase 4: compute hashes (THIS IS WHERE we don't know exactly what happens)
  header_wrapper(out=sp+0x68, env, ?, ctx=sp+0x98)  // 0x24a1c
    → dispatches to canonicalize_low or canonicalize_high
    → produces hash output(s) into sp+0x68 (or somewhere)
  
  // Phase 5: add 4 headers
  add_header(struct1, name='shield',     value=hash1, enum=5)
  add_header(struct2, name='x-mini-mua', value=hash2, enum=6)
  add_header(struct3, name='x-mini-sig', value=hash3, enum=7)
  add_header(struct4, name='x-mini-s1',  value=hash4, enum=8)
  
  // Phase 6: proceed
  return chain.proceed(modified_request)
}
```

The **gap is between Phase 4 and Phase 5**:How does header_wrapper produce 4 different hash values from 1 call? Possibilities:
1. **Internal dispatch** — header_wrapper has its own loop that calls hash 4 times
2. **Output struct with 4 fields** — header_wrapper writes to (out+0x10), (out+0x20), (out+0x30), (out+0x40)
3. **Each add_header internally re-computes** — header_wrapper just primes state, each add_header triggers its own hash
4. **All 4 use the same hash** — different `enum` values result in different add_header behavior but same hash bytes

---

## 下一步如果继续静态

**最高 ROI 的 3 个未尝试的角度**:

### α. 反汇编 `add_header (0x1ee70)` 完整函数体
This function decides what to do with each `enum` value. If it computes the hash internally, we'll see a switch on enum + 4 different hash code paths. If it just appends, we'll see addHeader-style code.

### β. 反汇编 `header_wrapper (0x24a1c)` 内部完整流程
Specifically what it writes to its output buffer (`r0` = sp+0x68 in caller). If we see 4 writes at offsets 0x10, 0x20, etc., we know it produces 4 hash outputs.

### γ. 静态识别 `r6+4` 的真实内容
通过反汇编 intercept 在 sp+0x98 写入 phase,确定该 64-byte buffer 的字节 layout。
特别是 sp+0x9c (= r6+4) 是什么。

---

## 实际可执行的下一步

我可以做 **α + β + γ 三个全部**(纯静态,不需要 NDK 或 native dump)。

每个大概 30 分钟工作量。完成后我们会知道:
- **add_header 是否 internally compute hash** (大概率是,因为只有 1 次 header_wrapper call 但 4 次 add_header)
- **header_wrapper 输出 layout**
- **outer key 的真实位置**

如果发现 add_header 内部 compute hash,**我们能直接看到完整的 hash 链,无需 native dump**。

要做 α/β/γ 吗?还是先等 NDK + native dump?
