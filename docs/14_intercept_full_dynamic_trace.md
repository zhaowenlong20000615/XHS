# libxyass.so — intercept() Full Dynamic Trace (Updated)

**Major corrections to docs/13:**

1. **`0x174c8` is `memcpy`, NOT a crypto function.** Confirmed by hooking the BL site at `0x23fce` and inspecting args:
   - `r0` = output buffer (stack or malloc'd)
   - `r1` = source buffer (e.g. `0x50001000`, holding `/api/tes...` from `GetStringUTFChars`)
   - `r2` = length (e.g. `8`)
   - Followed by `strb r0, [r5, r6]` to write a null terminator
   - All 3 calls to `0x174c8` in intercept have the **identical** `(dst, src, len) → memcpy + null` pattern
   - This is the `__memcpy_chk` or similar inlined memcpy from libc, reused 3× for 3 string copies (with small-string optimization: `< 11 bytes` lives on stack, else `malloc(round_up_16(len))`)

2. **NEON-accelerated `toupper` loops** are at `0x243aa-0x243fc` and `0x24490-0x244fe`. The signature pattern:
   ```
   vmvn.i32 q8, #0x60        ; constant for "subtract 0x60"
   vmov.i32 q9, #0x1a         ; constant for "less than 26"
   vld1.8  {d22, d23}, [r0]   ; load 16 bytes
   vmovl.u8 ...                ; widen to 16-bit
   vaddw.u16 ...               ; subtract 0x60 (per byte)
   vcgt.u32 ...                ; compare > 0x1a
   veor                        ; mask with 0x20
   vbit                        ; conditionally toggle bit
   vst1.8 ...                  ; store back
   ```
   This is the SIMD vectorization of `if (c-'a' < 26) c ^= 0x20` — i.e. `toupper` for ASCII letters. The scalar fallback for tail bytes is at `0x24404`.

3. **The MD5 T-table at `0x79418` is unused.** I scanned every instruction in libxyass for any reference to it (via MOVW/MOVT pairs OR pc-relative loads). **Zero references.** It's leftover constant data from libc++ (or similar), not an active MD5 implementation.

4. **`0x26714` is the `CallVoidMethodV` wrapper.** Same pattern as 0x1edf8 (CallObjectMethodV) and 0x1ee70 (GetStaticObjectField):
   ```
   ldr r3, [r0]                  ; r0 = JNIEnv*
   ldr.w r4, [r3, #0xf8]         ; r4 = iface[#0xf8/4 = 62] = CallVoidMethodV
   blx r4
   ```

5. **The actual canonicalization + crypto path** (now confirmed from trace):
   ```
   intercept:
       # 1. Walk request: chain.request() → request → url → path/query/method/body
       # 2. For each string field:
       #      a. GetStringUTFLength to get the length
       #      b. malloc or stack-alloc a buffer
       #      c. memcpy via 0x174c8 (3× total = 3 string fields copied)
       #      d. NEON-accelerated toupper to normalize
       # 3. strncmp uppercase strings against known header allow-list
       # 4. Build a Java byte[] of size 0x1000 (4KB working buffer)
       # 5. Call 0x26c6c with (state, output=sp+0x98, scratch=sp+0x8c)
       #      ← THIS IS THE LIKELY HASH/SIGN FUNCTION
       # 6. malloc(0x50) twice more — fresh hash state structs
       # 7. ... more JNI calls to assemble the final shield header
   ```

## Critical: 0x26c6c is the most likely real crypto function

Evidence:
- Called exactly **once** from intercept at `0x246d4`
- 728 bytes of code, **340-byte stack frame** (`sub sp, #0x154`) — large enough for hash state + scratch
- Reads ~42 different constants via pc-rel loads (CFG-flattened dispatcher pattern)
- Called with 3 args: `r0 = data ptr`, `r1 = output buffer (sp+0x98)`, `r2 = scratch (sp+0x8c)`
- Called AFTER all canonicalization (memcpy, toupper, strncmp) is done
- Followed immediately by `malloc(0x50)` × 2 — likely allocating fresh hash-state structs

Negative evidence:
- It's CFG-flattened (computed branches via accumulator), so static reading is hard
- Constants don't match standard SHA/MD5 round constants
- May call helpers like `0x250f4` and `0x024a1c` internally

## Updated 7 .bss slot mappings (from previous trace)

| Slot | Method | Class |
|---|---|---|
| `0x7dfc4` | `request()` | `Interceptor.Chain` |
| `0x7dfc8` | `url()` | `Request` |
| `0x7dfcc` | `encodedPath()` | `HttpUrl` |
| `0x7dfd0` | `encodedQuery()` | `HttpUrl` |
| `0x7dfa8` | `method()` | `Request` |
| `0x7dfd4` | `body()` | `Request` |
| `0x7dfd6` | `<init>()` | `okio.Buffer` |
| `0x7dfdc` | (Buffer accessor — likely `writeTo`/`readByteArray`) | `okio.Buffer` |
| `0x7dfa0` | (Buffer accessor) | `okio.Buffer` |

## What is now known about the canonical string

**Confirmed**: intercept extracts these fields, normalizes them to UPPERCASE, then feeds them to `0x26c6c`:
- HTTP method (e.g. `GET`, `POST`)
- URL encoded path
- URL encoded query (or empty)
- Body bytes (via `okio.Buffer.readByteArray`)

The exact concatenation order + separator chars are still unknown from static analysis (would need to inspect `0x26c6c`'s state buffer post-call), but the **inputs** are now fully known.

## Next steps to fully recover the algorithm

The remaining ~10% is `0x26c6c`'s internal logic. Three options:

1. **Hook `0x26c6c` under Unicorn** with realistic mock inputs and observe the output bytes for known plaintexts. If the algorithm is HMAC-MD5, fixed-key + known-plaintext gives a verifiable digest.

2. **Statically deobfuscate `0x26c6c`** by tracing its CFG dispatcher (the `add r0, sb; mov pc, r0` pattern using accumulator). Manually unrolling 42 dispatcher states is ~6-10 hours.

3. **Frida hook** on `libxyass.so + 0x246d4` to capture the exact arguments and return value at runtime — 5 minutes if you have a device.

For a complete Python port, option 3 is strongly recommended.
