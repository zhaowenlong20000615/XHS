# libxyass.so — intercept() Algorithm (RECOVERED via Unicorn JNI Trace)

**Method:** Run intercept() under Unicorn with a fake `okhttp3.Chain`, seed
`.bss[0x7df08]` with the obfuscated CallObjectMethodV wrapper pointer, log
every JNI vtable trampoline hit. The trace reveals the **exact sequence** of
JNI calls intercept makes — i.e. the canonical-string-builder algorithm.

**Source data:**
- `scratch/ghidra_work/run_intercept.py` — the dynamic Unicorn driver
- `scratch/ghidra_work/run_intercept.log` — the captured trace
- `scratch/ghidra_work/libxyass_strings.json` — 92 decrypted strings
- `docs/11_intercept_asm_annotated.md` — 1037-line annotated disassembly

---

## 1. The .bss state struct

`intercept()` reads from a small struct whose pointer is cached at
`.bss[0x7df08]`. The struct contains:

- A **base value** — adding `0x10589130` (the obfuscation constant `fp`)
  to any field gives a real function pointer in libxyass `.text`. This is
  the same XOR/offset obfuscation we saw in `JNI_OnLoad` (with constant
  `0x666e4b10` there).

When intercept does:
```asm
ldr r1, [r6]              ; r6 = .bss[0x7df08], r1 = state struct value
add.w r3, r1, fp          ; r3 = state + 0x10589130
blx r3                    ; jumps to libxyass+0x1edf8 = CallObjectMethodV wrapper
```

it's **always invoking the same wrapper** (the CallObjectMethodV wrapper at
`0x1edf8`) — the DIFFERENT methods being called are differentiated entirely
by `r2 = jmethodID` loaded from a different `.bss` slot per call.

The jmethodID slots that intercept reads are at:

| Slot | First used | Inferred meaning |
|---|---|---|
| `0x7dfc4` | call 3 — on Chain | `okhttp3.Interceptor$Chain.request()` → Request |
| `0x7dfc8` | call 4 — on Request | `okhttp3.Request.url()` → HttpUrl |
| `0x7dfcc` | call 5 — on HttpUrl | `okhttp3.HttpUrl.encodedPath()` → String |
| `0x7dfd0` | call 6 — on HttpUrl | `okhttp3.HttpUrl.encodedQuery()` → String |
| `0x7dfa8` | call 7 — on Request | `okhttp3.Request.method()` → String |
| `0x7dfd4` | call 8 — on Request | `okhttp3.Request.body()` → RequestBody |
| `0x7dfd6` | call 9 — NewObject | `okio.Buffer.<init>()` |
| `0x7dfdc` | calls 12,13,15 — on Buffer | likely `Buffer.size()` / `readByteArray()` / `writeTo` |
| `0x7dfa0` | call 21 — on Buffer | another Buffer accessor |
| `0x7df94` | (later) | another method |

Each of these slot addresses is populated by `JNI_OnLoad` during its
deferred-init helpers (`0xdff0` / `0xd7f0` / `0xe0c8`).

---

## 2. The captured JNI call sequence

Output of running `scratch/ghidra_work/run_intercept.py`:

```
[  1] GetStaticObjectField              # ContextHolder.sAppId or similar
[  2] ExceptionCheck                    # standard post-call check
[  3] CallObjectMethodV(chain, mid=slot[0x7dfc4]) → A   ; chain.request()
[  4] CallObjectMethodV(A, mid=slot[0x7dfc8])     → B   ; request.url()
[  5] CallObjectMethodV(B, mid=slot[0x7dfcc])     → C   ; httpUrl.encodedPath()
[  6] CallObjectMethodV(B, mid=slot[0x7dfd0])     → D   ; httpUrl.encodedQuery()
[  7] CallObjectMethodV(A, mid=slot[0x7dfa8])     → E   ; request.method()
[  8] CallObjectMethodV(A, mid=slot[0x7dfd4])     → F   ; request.body()
[  9] NewObjectV(?, mid=slot[0x7dfd6])            → G   ; new okio.Buffer()
[ 10] GetStringUTFChars(C)                          ; UTF-8 bytes of encodedPath
[ 11] ExceptionCheck
[ 12] CallObjectMethodV(G, slot[0x7dfdc])           ; buffer.???()
[ 13] CallObjectMethodV(G, slot[0x7dfdc])           ; buffer.???()  (same method, second call)
[ 14] CallIntMethodV(?, slot[0x7dfe4])              ; some_int_returning_method()
[ 15] CallObjectMethodV(G, slot[0x7dfdc])           ; buffer.???()  (third call)
[ 16] CallVoidMethodV(E, slot[0x7dfe8])             ; method_string.???()
[ 17] GetStaticObjectField                          ; another static field
[ 18] ExceptionCheck
[ 19] GetStaticObjectField                          ; another static field
[ 20] ExceptionCheck
[ 21] CallObjectMethodV(G, slot[0x7dfa0])           ; buffer.???() (different method)
[ 22] NewByteArray(0x1000)                          ; 4096-byte working buffer
```

(Trace cut at this point because my fake byte-buffer didn't have realistic
data for the next step — easy to extend.)

---

## 3. Reconstructed algorithm

From the call sequence + the 92 decrypted strings + the 19 unique BL targets
in intercept (most importantly: **3× calls to `0x174c8`** = the crypto block
function and **8× calls to `0xd7a4`** = the internal allocator), the
algorithm is:

```python
def intercept(chain):
    # Phase 1: integrity-gated init (one-time per process)
    if state == NULL:
        state = malloc(0x50)              # 80-byte state struct
        zero(state)
        # ... APK signature verification chain (already documented in §3 of doc 09)
        # ... loads each jmethodID via decrypt → GetMethodID → cache to .bss
    
    # Phase 2: load static config
    sAppId = ContextHolder.sAppId          # static String, the app secret
    
    # Phase 3: extract the request fields (canonical components)
    request      = chain.request()
    url          = request.url()           # HttpUrl
    encoded_path = url.encodedPath()       # String, e.g. "/api/sns/v1/..."
    encoded_query= url.encodedQuery()      # String, e.g. "k=v&k2=v2" or null
    method       = request.method()        # String, e.g. "GET" / "POST"
    body         = request.body()          # RequestBody, may be null
    
    # Phase 4: buffer the body bytes
    buffer = new okio.Buffer()
    if body is not null:
        body.writeTo(buffer)
    body_bytes = buffer.readByteArray()
    
    # Phase 5: convert strings to UTF-8 byte arrays via GetStringUTFChars
    path_bytes   = GetStringUTFChars(encoded_path)
    query_bytes  = GetStringUTFChars(encoded_query) if encoded_query else b""
    method_bytes = GetStringUTFChars(method)
    
    # Phase 6: build the canonical string and hash it
    work_buf = malloc(0x1000)              # 4 KB scratch space
    
    # Construction (inferred from 3× calls to 0x174c8 + MD5 T-table presence):
    # 0x174c8(state_ptr, init_data, init_len)   ← initialize crypto state
    # 0x174c8(state_ptr, msg_data,  msg_len)    ← absorb canonical bytes
    # 0x174c8(state_ptr, output,    32)         ← finalize, produce 32 bytes
    canonical = (
        method_bytes + b"\n" +
        path_bytes   + b"\n" +
        query_bytes  + b"\n" +
        body_bytes
    )                                       # exact separator unknown — see §5
    digest = md5_based_kdf(sAppId, canonical, 32)   # 32-byte digest
    
    # Phase 7: pack the shield blob (100 bytes total)
    # Layout from captured shield bytes:
    #   magic[4]=5d 80 00 40 + flags[4]=00 40 00 00 + reserved[4]=00 10 00 00
    #   counter[4]=body_len  + counter[4]=time_or_seq
    #   digest[32]           + nonce[48]
    shield_blob = (
        b"\x5d\x80\x00\x40" + b"\x00\x40\x00\x00" + b"\x00\x10\x00\x00" +
        struct.pack("<I", len(body_bytes)) +
        struct.pack(">I", int(time.time())) +
        digest +
        os.urandom(48)
    )
    shield_b64 = Base64Helper.encodeToString(shield_blob)
    
    # Phase 8: produce the other two libxyass headers
    # xy-platform-info uses the format string "platform=android&build=%lld&deviceId=%s"
    platform_info = "platform=android&build=%d&deviceId=%s" % (build_number, device_id)
    # xy-ter-str: still unknown format
    
    # Phase 9: build new Request with the 3 added headers
    builder = request.newBuilder()
    builder.header("shield",            shield_b64)
    builder.header("xy-platform-info",  platform_info)
    builder.header("xy-ter-str",        ter_str)
    new_request = builder.build()
    
    # Phase 10: continue the chain
    return chain.proceed(new_request)
```

---

## 4. What the trace **proves** vs. what is **inferred**

### Proved by the Unicorn trace (high confidence)

| Fact | Evidence |
|---|---|
| intercept reads `ContextHolder.sAppId` (or another static) first | call [1] = GetStaticObjectField |
| intercept calls `chain.request()` first (slot 0x7dfc4) | call [3] |
| Then `request.url()` → HttpUrl (slot 0x7dfc8) | call [4] |
| Then `httpUrl.encodedPath()` → String (slot 0x7dfcc) | call [5], confirmed by call [10] GetStringUTFChars on the result |
| Then `httpUrl.encodedQuery()` → String (slot 0x7dfd0) | call [6] |
| Then `request.method()` → String (slot 0x7dfa8) | call [7] |
| Then `request.body()` → RequestBody (slot 0x7dfd4) | call [8] |
| Then `new okio.Buffer()` is allocated | call [9] = NewObjectV |
| Then UTF-8 strings are extracted from one of the URL components | call [10] = GetStringUTFChars |
| A 4 KB working buffer is allocated for canonical + hash | call [22] = NewByteArray(0x1000) |

### Inferred from decrypted strings (medium confidence)

| Fact | Evidence |
|---|---|
| Body is buffered via `body.writeTo(buffer)` | string `writeTo` decrypted; `Buffer` class decrypted |
| Body bytes obtained via `buffer.readByteArray()` | string `readByteArray` decrypted; signature `()[B` decrypted |
| Strings converted via `Charset.defaultCharset()` | strings `defaultCharset`, `forName` decrypted |
| Output is base64 via `Base64Helper.encodeToString([B)` | string `encodeToString` decrypted; class `Base64Helper` decrypted |
| Headers added via `Request.Builder.header(String, String)` | strings `newBuilder`, `header`, `build` decrypted |
| Three headers produced: `shield`, `xy-platform-info`, `xy-ter-str` | all 3 strings decrypted |
| HMAC is involved | string `_hmac` decrypted |
| MD5 is the hash family | T-table at `0x79418`, no SHA-256/SM3/BLAKE2 constants |

### Still **NOT** known statically (requires Frida)

| Unknown | Why it blocks the Python port |
|---|---|
| Exact byte layout of the canonical string | separator chars + field order — could be `method\npath\n...` or any other format |
| Exact algorithm of `0x174c8` (crypto primitive) | CFG-flattened; only known to be MD5-based with HMAC pattern |
| The secret seed value (sAppId) hardcoded inside libxyass | stored as `ContextHolder.sAppId` static, set via Java side |
| Exact 100-byte shield blob field order (counter offsets, nonce semantics) | captured layout is consistent across requests but inferred |
| Format of `xy-ter-str` | string is decrypted but its derivation is not statically traced |

---

## 5. The remaining static work to fully recover the algorithm

I have **structure** (call sequence) and **strings** (method names). The
gap is the **byte layout** of the canonical string and the **exact
crypto** inside `0x174c8`. To close those gaps purely statically, you
would need to:

1. Trace the 3 `bl 0x174c8` call sites in intercept and capture the
   `(r0, r1, r2)` arguments at each — these are the (state, data, len)
   triples for the crypto operations. Knowing `len` for the second call
   would tell you the canonical string length, which constrains the
   format.
   - The 3 calls are at intercept offsets `0x23fce`, `0x24134`, `0x24370`
     (visible in `docs/11_intercept_asm_annotated.md`).

2. For each call, walk backward through the asm and identify what got
   written into the buffer that becomes `r1`. The buffer is allocated by
   one of the 8 `bl 0xd7a4` calls (the internal malloc).
   - This is hand-readable from the annotated asm — about 2-4 hours of
     careful reading.

3. Statically deobfuscate `0x174c8`. It is CFG-flattened (every basic
   block ends with `mov pc, rN` where `rN` is computed from an
   accumulator). To trace it, you would either:
   - Write a small Unicorn driver that runs `0x174c8` with controlled
     inputs and observes the output bytes for known plaintexts (e.g., the
     all-zero buffer)
   - Or interpret the dispatcher table by hand — ~6-10 hours

The total effort to close the remaining gap statically is roughly
**1-2 more days** of focused work. For comparison, a single Frida hook
on `0x174c8` would close it in **5 minutes**.

---

## 6. The 100-byte shield blob (recap)

From captured network traffic:

```
offset  size  content
  0     4     5d 80 00 40   ← magic ("v5 shield" version)
  4     4     00 40 00 00   ← flags
  8     4     00 10 00 00   ← reserved
 12     4     <body len>     ← LE counter — body length seen by signer
 16     4     <counter2>     ← BE u32, varies between requests (timestamp or seq)
 20    32     <hash>         ← 32-byte digest output
 52    48     <nonce>        ← random / pad
```

After the digest, base64-encode → string → header value. This layout is
**consistent across all captured shield headers** (verified by reading
20+ samples from `capture/session2_full_usage_20260411_123810.mitm`).

---

## 7. Files

```
docs/13_intercept_algorithm_recovered.md         ← this file
scratch/ghidra_work/run_intercept.py             ← Unicorn driver, captures the trace
scratch/ghidra_work/run_intercept.log            ← raw trace output
scratch/ghidra_work/extract_intercept_calls.py   ← .bss slot extractor
```

The Python port skeleton is updated in [scratch/ghidra_work/xhs_sign_skeleton.py](../scratch/ghidra_work/xhs_sign_skeleton.py)
to reflect the recovered structure.
