# XHS libxyass — 完整静态架构(最终版)

**日期**: 2026-04-13 (continuation, after re-probing 0x26c6c + full disasm of 0x24a1c/0x1ee70/0xdbee)
**状态**: 静态分析所有可挖角度全部完成。剩余未知 **必须** 通过动态执行(LSPosed native hook)解开。

---

## 完整 intercept 数据流(static-recovered)

```
intercept(env, this, chain, cPtr) {
    // ─── Phase 1: extract Request fields ───────────────────────
    url      = chain.request().url()
    method   = chain.request().method()
    body     = chain.request().body().toBytes()

    // ─── Phase 2: build the canonicalize-input ctx struct ─────
    sp+0x98 ← vmov.i32 q8, #0; vst1.64 ×4    // 64-byte zero buffer
    bl 0x76890                                // pthread_mutex_lock
    bl 0x26c6c(out=sp+0x98, in=sl[0x18])     // libc++ std::string COPY ctor
    bl 0x768a0                                // pthread_mutex_unlock
    // sp+0x98 now contains: [12 bytes std::string copy] + [52 bytes other state]

    // ─── Phase 3: header_wrapper (the single hash computation) ──
    bl 0x24a1c(
        r0 = sp+0x68,            // output container (sb)
        r1 = JNIEnv*,
        r2 = some_object,
        r3 = sp+0x98             // ctx struct (cap field becomes "header type")
    )
    // → produces 1 std::string at sp+0x68 (the hash value of THIS header)

    // ─── Phase 4: extract & add 1st header (using header_wrapper result) ─
    ldr r3, [chain.vtable + 0x29c]
    blx r3                       // chain->vtable[0x29c](data_ptr)
                                 // adds the hash-computed value to request

    // ─── Phase 5: 4 more headers via add_header virtual dispatch ──
    add_header_vcall(struct1, ..., enum=5)   // 0x23eba
    add_header_vcall(struct2, ..., enum=6)   // 0x2466e
    add_header_vcall(struct3, ..., enum=7)   // 0x2471a
    // ← header_wrapper called HERE (out of order!) at 0x2474c
    add_header_vcall(struct4, ..., enum=8)   // 0x247a4

    // ─── Phase 6: proceed ──
    return chain.proceed(modified_request)
}
```

**5 个 header total: 1 from header_wrapper + 4 from add_header virtual dispatch**.

Or possibly **4 total**: header_wrapper produces 1, add_header_vcalls produce 3 (one of the 4 add_header sites might be for a non-signature header).

---

## 完整 0x24a1c (header_wrapper) 解析

```c
std::string header_wrapper(env, jobject, ctx_64byte_buffer*) {
    int cap_field = ctx_64byte_buffer[0];   // first 4 bytes (= cap of std::string at offset 0)
    
    // Branch on string cap (NOT a header enum — I was wrong about this earlier)
    if (cap_field < 6) {
        // SSO mode short string OR very small std::string → low path
        canon_fn = canonicalize_low (0x24ea0)
    } else {
        // LONG mode or longer SSO → high path
        canon_fn = canonicalize_high (0x24bcc)
    }
    
    // Apply CFG-flatten obfuscation: real_addr = canon_fn + 0xb9dd6454
    real_canon_fn = canon_fn + 0xb9dd6454
    
    std::string canon_result;
    real_canon_fn(out=&canon_result, env, ctx_struct, ctx_struct);  // blx r4
    // canon_result is a std::string holding the hash input (16 or 20 bytes)
    
    // Build 2 std::string keys from .bss
    std::string key1 = std::string(/* .bss[0x7df20] = "9190807" */);  // → sp+0x20
    std::string key2 = std::string(/* .bss[0x7df10] = devid    */);  // → sp+0x14
    
    std::string hmac_out;
    hmac_b64(
        out      = &hmac_out,         // sp+0x2c
        alg      = 1,
        key1_str = &key1,             // sp+0x20 = "9190807" (build)
        ctx      = some_value,        // r5 (reloaded from .bss)
        stack[0] = ctx_struct[0],     // cap field of input struct
        stack[4] = &key2,             // sp+0x14 = devid
        stack[8] = canon_result.data, // canonicalize result bytes
        stack[12] = canon_result.size // canonicalize result length
    )
    
    // Append hmac result to output container via 0xdbee (string append)
    bl 0xdbee(out=sb, name?, hmac_out)
    
    // Cleanup intermediate std::strings
    if (key1.is_long_mode) delete key1.data
    if (key2.is_long_mode) delete key2.data
    if (canon_result.is_long_mode) delete canon_result.data
    if (hmac_out.is_long_mode) delete hmac_out.data
    
    return sb;
}
```

**0x24a1c 只产 1 个 hash 输出**。这进一步证实了 4 个签名 header 不是 1 次调用产 4 个,而是各自独立计算。

---

## 完整 0x1ee70 (add_header virtual dispatcher) 解析

```c
void add_header_vcall(obj, ..., int enum) {
    // 50 bytes total — just a virtual call wrapper
    save_stack_canary()
    void (*fn)() = obj->vtable[0x238]
    fn(obj, ..., enum)              // ★ virtual dispatch ★
    check_stack_canary()
}
```

**0x1ee70 没任何实际逻辑**,全部 dispatch 到 `obj->vtable[0x238]` — 一个**运行时确定**的虚函数。这意味着:

1. 4 个 add_header 调用每个用 **不同的 obj**,各自的 vtable[0x238] 可能指向**不同的实现**
2. 每个实现可能 internally 计算自己 hash + 添加 header
3. 这些 vtable 指针在 RegisterNatives / 静态初始化时设置,**静态读不到**

---

## 完整 0xdbee (string append helper) 解析

```c
void string_append_helper(out_container, ?, std::string* src) {
    bl 0xdc74(...)                 // some prep
    int len_a = strlen(arg1)       // PLT call to strlen-like
    int len_b = src.size           // SSO/LONG-aware size read
    int total = len_a + len_b
    bl 0xd954(out, arg1)           // some op
    char* src_data = src.is_long ? src.dptr : &src+1
    bl 0xda9c(out, src_data, len_b)  // append src_data to out
}
```

**这 confirms: 0xdbee 是 std::string append**。0x24a1c 用它把 hmac 结果 append 到 output container。

---

## 8 个本 session 新确认的事实

1. **`0x26c6c` = libc++ std::string copy ctor** (not canonicalize)
2. **intercept calls `header_wrapper` 1× only** (at 0x2474c)
3. **intercept calls `add_header_vcall` 4× with enum=5,6,7,8** (at 0x23eba, 0x2466e, 0x2471a, 0x247a4)
4. **`add_header_vcall` is a 50-byte vtable wrapper** dispatching to `obj->vtable[0x238]`
5. **`cmp r0, #6` in 0x24a1c reads std::string cap field, NOT a header enum**
6. **`header_wrapper` produces exactly 1 hash output** via the chain `canonicalize → hmac_b64 → 0xdbee append`
7. **`canonicalize_high` (0x24bcc)** does: SHA1_Init → loop[vtable_iter + SHA1_Update] → SHA1_Final → switch → 0x2b838 (HMAC outer pass) → base64
8. **`0xdbee` is a std::string append helper** (writes hash result to output container)

---

## 静态分析的根本上限

**为什么不能再深入静态**:

- `canonicalize_high` 的内层 vtable iterator (`vtable[0x300]`, `vtable[0xb62ec14]`) 通过 CFG-flatten 偏移调用,**真实目标函数在运行时计算**
- `0x2b838` 内有 940 字节栈帧 + 完全 CFG-flatten,**0 个 ROR / 0 个 SHA 常量**直接可见
- `0x1ee70 → vtable[0x238]` 的 4 个虚函数指针在 **JNI_OnLoad 运行时**填充
- `0x6d0f0 / 0x6d1d4 / 0x6dd28 / 0x6ddd4` 系列同样是 CFG-flatten dispatcher

**libxyass 是为防静态分析专门设计的**。CFG-flatten + virtual dispatch + 字符串 lazy decryption 让 call graph 在静态层完全不可见。

---

## Py skeleton 当前可填的部分

基于 8 个新确认的事实,我可以更新 Py skeleton 让它的架构**架构正确**(虽然无法 produce 正确字节,因为缺最后的 vtable resolution + iterator content):

```python
class XhsSigner:
    def sign(self, method, url, body):
        # Phase 1: build per-request data
        canon_input = self._build_canonicalize_input(method, url, body)
        # ↑ from vtable iterator — currently a placeholder
        
        # Phase 2: compute the 1 hash via header_wrapper architecture
        canon_result = self._canonicalize(canon_input)
        # Uses inner SHA-1 + outer pass via 0x2b838 (HMAC-style)
        
        # Phase 3: HMAC-wrap with build/devid keys
        hash_result = self._hmac_b64(
            alg=1,
            key1=b'9190807',                              # build version
            key2=self.device.devid.encode(),              # device UUID
            data=canon_result,
        )
        
        # Phase 4: build all 4 header values
        # (Requires 4 separate code paths, only 1 (shield?) traceable statically)
        return {
            'shield': self._build_shield(hash_result),
            'x-mini-mua': self._build_mua(...),       # vtable[0x238] black box
            'x-mini-sig': self._build_sig(...),       # vtable[0x238] black box
            'x-mini-s1': self._build_s1(...),         # vtable[0x238] black box
        }
```

**only 1 of 4 hashes is statically traceable**(the one through header_wrapper). The other 3 are vtable-dispatched and will need dynamic data to resolve.

---

## 给另一窗口的精确请求

只要 **1 次 native hook** dump 到下面任一组数据,我就能完成 Py 端复写:

### 选项 A (最理想): hook libxyass+0x286d0 (hmac_b64) entry+exit
```
key1: <bytes>
key2: <bytes>  
data: <16 raw bytes — the canonicalize result>
out:  <bytes — the hmac_b64 output>
```
→ 直接验证 hash 公式 + 反推 inner hash

### 选项 B: hook libxyass+0x6dd28 (canonicalize_low op_update) entry
```
ctx_ptr: <addr>
data_ptr: <bytes — the RAW canonicalize bytes>
data_len: <int>
```
→ 直接看到 canonicalize 输出的字节流,反推模板

### 选项 C: hook the 4 vtable[0x238] dispatched functions
```
For each of (shield, mua, sig, s1), dump the function's input/output
```
→ 完整解开 4 个 hash header 的算法

### 选项 D (lowest effort): just dump the .bss table at JNI_OnLoad end
```
.bss[0x7df00..0x7e100] full hex
```
→ 看到所有 lazy-decrypted strings 的实际值,可能反推哪些字符串是 inner key

---

## 总结

**纯静态分析的 productive 工作已经做完**。所有可读的反汇编都读了。剩下的所有未知数都需要 1 次 native hook dump,5 分钟解开。

`fast_canonicalize_solver.py` V2 已经支持新格式,等 dump 来直接 1 个命令出结果。

如果需要继续推进,**只能等 NDK + native hook**。我现在 idle,Py skeleton 准备好接收数据。
