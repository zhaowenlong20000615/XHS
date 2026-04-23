# XHS canonicalize_low 完整架构（静态反汇编后）

**日期**: 2026-04-13
**方法**: 完整反汇编 0x24ea0 (canonicalize_low) 0x300 字节函数体

这是 19/20 文档之后的进一步静态突破。**通过完整反汇编 canonicalize_low 整个函数
体，我已经搞清楚 enum 0..5 路径的整体处理流程**。距离能签新请求只差 1 个未知数：
**0x6d1d4/0x6dd28/0x6ddd4 chain 内部用的是哪种 hash 原语**。

---

## canonicalize_low 完整流程（从反汇编反推）

```c
// 0x24ea0: canonicalize_low(out_str*, sl, arg2, ctx_int*)
std::string canonicalize_low(std::string* out, void* sl, void* arg2, int* ctx_int) {
    // ---- Phase 1: virtual call to get some object/data ----
    auto vtable_ptr_1 = vtable_call_via_cfg_flatten(sl, arg2);  // → r6
    auto inner_ptr   = sl->vtbl[0x2c0](sl, 0x1000);             // → sb
    
    // ---- Phase 2: alloc 284-byte ctx + init ----
    void* ctx = operator_new(284);          // 0x6d0f0
    memset(ctx, 0, 284);
    int first_int = ctx_int[0];             // ctx_int += 4
    int ret = op_init(ctx, first_int, ctx_int+1, /*block_size=*/0x40);  // 0x6d1d4
    if (ret == 0) goto error_path;          // returns 16 bytes of 0x01
    
    // ---- Phase 3: loop (CALL #3 in inner loop) ----
    while (true) {
        auto next = sl->vtbl[?](sl, vtable_ptr_1);  // 0x24f40 blx r5
        if (next == -1) break;              // end of iteration
        
        // ---- Phase 4: get input bytes via virtual call ----
        auto input_bytes = sl->vtbl[0x2e0](r5, sb);  // → r8 (= raw byte ptr)
        
        // ---- Phase 5: HEX-ENCODE input bytes to a 8208-byte buffer ----
        // Allocates an 8208-byte heap buffer, marks it as a libc++ LONG std::string
        // (cap=0x2011, size=0x2000=8192), then loops:
        //   for (i = 0; i <= 4095; i++):
        //     hex_buf[i*2]   = HEX_TABLE[(input[i] >> 4) & 0xf]
        //     hex_buf[i*2+1] = HEX_TABLE[input[i] & 0xf]
        //
        // HEX_TABLE = "0123456789abcdef" (the decrypted string we found at .rodata 0xaa58)
        char* hex_buf = operator_new[](0x2010);
        // ... hex encode loop ...
        
        // ---- Phase 6: feed RAW bytes (not hex) to ctx ----
        op_update(ctx, r8 /*raw bytes*/, length);  // 0x6dd28
        
        // Inner loop releases hex_buf — used only for some side channel?
        sl->vtbl[0x300](sl, ...);  // another virtual call
    }
    
    // ---- Phase 7: finalize, get 16-byte output at sp+0x30 ----
    op_final(ctx, /*out=*/sp+0x30, /*len_var=*/sp+0x2c);  // 0x6ddd4
    
    // ---- Phase 8: cleanup + write 16-byte std::string into output ----
    cleanup(ctx[0x44]);   // 0x6ecae
    libcpp_string_destruct(ctx);  // 0x76690 PLT
    
    char* out_data = operator_new[](32);  // for 16-byte content + slack
    out->cap  = 0x21;     // libc++ LONG mode, 32 byte cap | 1
    out->size = 0x10;     // 16 bytes
    out->data = out_data;
    memcpy(out_data, sp+0x30, 16);   // copy the 16-byte hash result
    
    return *out;
}
```

**关键事实**：

1. **canonicalize_low 总是产 16 字节** — `cap=0x21, size=0x10`。这正好等于
   shield_tail 的 size！
2. **错误路径产 16 字节 `0x01010101` 重复** — 当 op_init 返回 0 时
3. HEX_TABLE `0123456789abcdef` 用在内部一个 hex-encoding loop（不是输出，是某种
   side processing）
4. `op_init(ctx, first_int, ctx_int+1, 0x40)` —— **0x40 = 64 = block size**，
   这是经典 hash init signature
5. `op_update(ctx, raw_bytes, len)` 用 raw 字节（不是 hex）feed ctx

## 16 字节输出的可能 primitive

block_size=64 + 16-byte output 匹配以下 hash:
- **MD5** (block 64, output 16) ✅
- **MD4** (block 64, output 16) ✅
- **HMAC-MD5** (block 64, output 16) ✅
- **CRC + counter** ❌ (不需要 ctx)
- **CityHash / FarmHash / xxHash128** (256-bit but truncated)
- **SipHash-2-4** (block 8, output 8 — wrong block size)

最可能：**MD5 或 HMAC-MD5**

但我们前面 search 了 MD5 T-table 常量，0 hits。这意味着 MD5 T 常量也被
**CFG-flatten 编码** 了，跟 SHA-1 K 常量一样。

## 0x286d0 的角色

之前以为 0x286d0 是 HMAC + base64 wrapper，**现在重新理解**：

- canonicalize_low 已经产出了 hashed 的 16 字节
- 0x286d0 接受这 16 字节 + key1 + key2 + alg=1
- **0x286d0 大量 ldrb/strb/uxtb/lsls/add 但 0 ROR ops** → 是纯 base64 encoder
- 输出 84 字符 base64 std::string

那 0x286d0 可能就是 **`base64(canonical_16B || other_metadata)`**。
比如：`base64(prefix(48B) || canonical_16B)` 输出 ~84 chars.

48 + 16 = 64 byte raw → 88 b64 chars ❌
48 + 12 = 60 raw → 80 b64
50 + 12 = 62 raw → 84 b64 ✅ (with `=` padding)

所以可能：**out = base64(50B device prefix || 12B per-request payload)**
其中 12B per-request payload 由 16B canonical_16B 截断/转换而来。

**byte 0 高 nibble fixed `0b0111`** 现在有了新解释：可能是 50B prefix 的最后一个
byte 的固定位 + 12B 数据中第一个字节的高 nibble 总是被某种类型 tag 占用。

## 仍未解的 1 个未知数

**op_init (0x6d1d4) / op_update (0x6dd28) / op_final (0x6ddd4) 内部用的是哪种
hash 原语**？最可能是 MD5（block 64 + output 16 + ROL by 7,12,17,22 等），但
常量被 CFG-flatten 编码了。

## 数据请求（给 native hook 那边）

最低限度需要 **1 组**：

```
[libxyass+0x6d1d4 (op_init) 入口]
  r0 = ctx ptr (284 bytes, our scope)
  r1 = first_int (4 bytes from caller)
  r2 = ctx_int+1 (subsequent ints from caller)  
  r3 = 0x40

[libxyass+0x6d1d4 出口]
  r0 = return value (1 = success, 0 = error)
  ctx[0..40] dump (post-init state — should contain hash IV)

[libxyass+0x6dd28 (op_update) 入口]
  r0 = ctx ptr
  r1 = data ptr (raw bytes ★ this is what we hash)
  r2 = data length
  + dump data[0..length] hex

[libxyass+0x6ddd4 (op_final) 入口]
  r0 = ctx ptr (post-update)
  r1 = output ptr (sp+0x30, 16 bytes)
  r2 = ?

[libxyass+0x6ddd4 出口]
  *r1[0..16] dump = the 16-byte hash result
```

**1 个 sample 就能告诉我们**：
- ctx 内部 layout 是不是 MD5 (64 + 16 + 16 + 16 + 16 + 16 + 16 + 16 = 144 bytes
  state, 余下是 buffer)
- update fed 的 data 是什么 canonical 格式
- final 输出的 16 字节是不是真的等于 standard MD5(那段 data)

**5 分钟解开剩下的所有谜题**。

## 当前 Py skeleton 状态

`canonicalize_low()` 已知会输出 16 字节。我可以预先在 skeleton 里把它写成：

```python
def canonicalize_low(method, url, body, request_metadata, header_enum) -> bytes:
    """Returns 16 bytes — the per-request hash for shield/x-mini-* headers."""
    # Step 1: build canonical bytes from request fields
    # (exact format unknown — needs native dump of 0x6dd28 input)
    canonical = build_canonical_message(method, url, body, ...)
    
    # Step 2: hash with 64-byte block primitive returning 16 bytes
    # Most likely candidates:
    return hashlib.md5(canonical).digest()                  # 64-block, 16-byte
    # OR:
    return hmac.new(KEY, canonical, hashlib.md5).digest()   # HMAC-MD5
    # OR:
    return hashlib.new('md4', canonical).digest()           # MD4
```

一旦 native dump 来，我就能 **3 行 Python** 完成 `canonicalize_low` 的实现。
