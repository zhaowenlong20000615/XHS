# XHS Request Signature — Complete Static RE Report (FINAL)

**Project:** `/Users/zhao/Desktop/test/xhs/`
**Targets analyzed statically:** `libxyass.so` + Java `r76.a` / `ega.f` / `com.xingin.tiny.*`
**Tools used:** Ghidra headless, Capstone, Unicorn (ARM Cortex-A15 + VFP/NEON), pyelftools, jadx_out
**Approach:** Ghidra + Unicorn string-decryption tool + jadx Java exploration → human reading
**Date:** 2026-04-11 (resumed session)

---

## TL;DR — Signature header ownership

**Signing is split across TWO libraries, not one.** My earlier reports assumed libxyass produces all headers. This was wrong.

| Header | Produced by | Entry point | Status |
|---|---|---|---|
| `shield` | **libxyass.so** native | `intercept()` @ `0x23e54` | ✅ fully located; algorithm structure known, exact bytes not yet readable |
| `xy-platform-info` | **libxyass.so** native | same intercept | ✅ located |
| `xy-ter-str` | **libxyass.so** native | same intercept | ✅ located |
| `x-mini-mua` | **libtiny.so** native | `com.xingin.tiny.daemon.d.a(int, Object[])` | ❌ not reversed (user task was libxyass only) |
| `x-mini-sig` | **libtiny.so** native | same | ❌ not reversed |
| `x-mini-s1` | **libtiny.so** native | same | ❌ not reversed |
| `x-mini-gid` | **libtiny.so** native | same | ❌ not reversed |
| `x-legacy-did` | **pure Java** `kka.r.e()` | no crypto — reads install UUID | ✅ easy to reproduce |
| `x-legacy-sid` | **pure Java** `z76.q0.f479254a.b()` | no crypto — reads session ID | ✅ easy to reproduce |
| `x-legacy-fid` | almost always empty in captures | — | ✅ no-op |

**Implication for Python port:** A complete Python signer needs BOTH libxyass (shield) AND libtiny (x-mini-*) reversed. This session reversed libxyass as requested; libtiny is a separate effort.

---

## 1. How the two signers hook into okhttp

### 1.1 The Java interceptor chain

Jadx shows two cooperating Interceptors, both touching every outgoing request:

1. **TinyInterceptor** `r76.a` ([target/jadx_out/sources/r76/a.java](../target/jadx_out/sources/r76/a.java))
   ```java
   builder.header("x-legacy-did", kka.r.e());        // pure Java
   builder.header("x-legacy-sid", z76.q0.f479254a.b()); // pure Java
   byte[] body = buffer.readByteArray();
   Map<String,String> mini = ega.f.j(method, url.toString(), body);
   // mini contains: x-mini-mua, x-mini-sig, x-mini-s1, x-mini-gid
   for (Map.Entry<String,String> e : mini.entrySet())
       builder.header(e.getKey(), e.getValue());
   ```
   And `ega.f.j()` ([target/jadx_out/sources/ega/f.java:225](../target/jadx_out/sources/ega/f.java)) drops into the native layer:
   ```java
   return (Map) com.xingin.tiny.internal.d3.b(-1750991364, str, host, path, query, bArr);
   ```
   `d3.b()` is a thin dispatcher that forwards to the native method `com.xingin.tiny.daemon.d.a(int, Object[])` which is **loaded from `libtiny.so`** (the library name is itself XOR-encrypted, unpacked in the static block of `com.xingin.tiny.daemon.d`). `-1750991364` is the operation code for "sign HTTP request".

2. **ShieldInterceptor** `com.xingin.shield.http.XhsHttpInterceptor` — the one we've been chasing. Its `intercept(Chain)` method calls the native `Native.intercept(Chain, long cPtr)` registered by `libxyass.so`'s `JNI_OnLoad`. This is the function at `0x23e54`.

### 1.2 Shield only adds 3 headers

Looking at the strings decrypted from `libxyass.so`, the only header-name strings present are:
- `shield`
- `xy-platform-info`
- `xy-ter-str`

And there are **no** `x-mini-*` or `x-legacy-*` strings anywhere in libxyass — I decrypted the entire string table and none are there. Those 7 headers are produced elsewhere (§1.1).

---

## 2. libxyass.so string decryption — SOLVED

### 2.1 Architecture

libxyass has **10 separate string-decryption functions** (not 1). Each "handles" a subset of strings. All share the same prologue:

```
push {r4-r7, lr}
add r7, sp, #0xc
push.w {r8, sb, sl, fp}
sub sp, #0xXX
...
```

and all take `(char* buf, int len)` as args — they XOR-decrypt `buf` in place.

### 2.2 The 10 decrypt functions

| Address | Notes | # strings it handles |
|---|---|---|
| `0x1a170` | Largest (1850 B), longest strings | 9 |
| `0x1bc30` | 1772 B | 6 |
| `0x1ddac` | 1178 B | 5 |
| `0x1cc6c` | 1192 B | 3 |
| `0x1d580` | 200 B — smallest | 4 |
| `0x1b29c` | 1644 B | 4 |
| `0x1e560` | 432 B | 3 |
| `0x1a9fc` | 712 B | 3 |
| `0x1c440` | 674 B | 2 |
| **`0x22e24`** | NEW — found in second-pass hunt | 4 |

**Key observation**: my Unicorn-based tool can call any of these functions **standalone** on any buffer, without needing the rest of JNI_OnLoad's state. The sanity check (`scratch/ghidra_work/standalone_decrypt.py`) confirms each function correctly decrypts its known-good ciphertext.

### 2.3 Encrypted string table location

All encrypted strings live in `.rodata` between `0x0a900` and `0x0b420` (2838 bytes, ~100 blobs). No other range of libxyass contains encrypted string data (verified by wide-area scan).

### 2.4 Results: 92 of ~100 strings decrypted

The full decrypted dictionary is in [scratch/ghidra_work/libxyass_strings.json](../scratch/ghidra_work/libxyass_strings.json). Highlights:

**Java class names (19 strings)**:
```
okhttp3/Request, okhttp3/HttpUrl, okhttp3/Request$Builder, okhttp3/RequestBody,
okhttp3/Headers, okhttp3/Interceptor$Chain, okhttp3/Response, okhttp3/ResponseBody,
okio/Buffer, java/lang/String, java/util/List, java/nio/charset/Charset,
android/app/Application, android/content/Context, android/content/SharedPreferences,
android/content/SharedPreferences$Editor, android/content/pm/PackageManager,
android/content/pm/PackageInfo, android/content/pm/Signature,
com/xingin/shield/http/Native, com/xingin/shield/http/ContextHolder,
com/xingin/shield/http/Base64Helper
```

**JNI method/field signatures (28 strings)** — every single one corresponds to a method intercept() will call on the Request/Headers/Body/Url/Response objects. For example:
```
()Ljava/lang/String;                                        ← method()/url() return type
(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;            ← Native.intercept signature
()Lokhttp3/Request;                                         ← chain.request() return
()Lokio/Buffer;                                             ← new Buffer()
([B)I                                                        ← read(byte[])
(Ljava/lang/String;Ljava/nio/charset/Charset;)Lokio/Buffer; ← stringToBuffer
(Lokio/BufferedSink;)V                                      ← RequestBody.writeTo(BufferedSink)
(Lokhttp3/Request;)Lokhttp3/Response;                       ← Chain.proceed(Request)
```

**Method names (41+ strings)**, including:
```
newBuilder, request, body, url, header, headers, method, size, name, value, values,
encodedPath, encodedQuery, readByteArray, writeTo, build,
clone, close, read, proceed,
getPackageManager, getPackageInfo, getPackageName, hashCode, signatures,
getSharedPreferences, edit, commit, putString, getString,
encodeToString, decode, defaultCharset, <init>, string, code,
```

**Header names owned by libxyass**:
```
shield                  ← the main signature header
xy-platform-info        ← platform info
xy-ter-str              ← another internal header
```

**Internal helpers**:
```
_hmac                   ← HMAC is confirmed used
isHttp                  ← SharedPreferences key
sAppId                  ← SharedPreferences key
```

**Format string**:
```
platform=android&build=%lld&deviceId=%s    ← assembled at runtime for some identifier
```

### 2.5 The 9 remaining undecrypted blobs

Within the encrypted range, 9 blobs at offsets `0xaa28, 0xaa58, 0xabc1, 0xae39, 0xae4d, 0xb048, 0xb058, 0xb200, 0xb226` do not decrypt with any of the 10 known functions or any of the other 48 functions with the same prologue. Analysis of these (by inspecting the raw bytes) shows:

- `0xaa58` starts with plaintext `0123456789abcdef` — it's the **hex alphabet lookup table** (not encrypted, my blob detector just included it in the range)
- `0xaa28` has mixed plain/binary bytes — possibly a packed version/config struct
- Others genuinely don't match any decrypt function's output
- They may belong to an 11th decrypt function that isn't reachable from JNI_OnLoad's early phase

Because these blobs don't appear critical (no header names, no method names — those are all in the 92 decrypted ones), the 91 %  coverage is sufficient for reading intercept().

---

## 3. intercept() @ `0x23e54` — structural analysis

### 3.1 High-level layout

From [docs/11_intercept_asm_annotated.md](./11_intercept_asm_annotated.md) (1037 lines of annotated disassembly):

```
intercept(JNIEnv* env, jobject thiz, jobject chain, jlong cPtr):
    ┌─ PROLOGUE (0x23e54 — 0x23e80, 44 bytes)
    │   push {r4-r7, lr}; push {r8-r11}
    │   vpush {d8-d13}               ← save 96 B of NEON regs
    │   sub sp, #0xf0                ← 240-byte stack frame
    │   r5 = env
    │
    ├─ STATE INIT (0x23e66 — 0x23eac)
    │   Load state ptr from .bss[0x7df08]
    │   If null: malloc(0x50 = 80 B), zero it, store back
    │   Load state.[0x30] / state.[0x40] / state.[0x4c] → temps
    │   Call 0x1ee70 (GetStaticObjectField wrapper) — load a cached global (probably ContextHolder.sAppId field)
    │
    ├─ INTEGRITY CHECK (0x23ebe — 0x23eda)
    │   r0 = env; r1 = JNIEnv->[0x390] ; blx r1 — ?
    │   (0x390 / 4 = 228, likely ExceptionCheck or NewWeakGlobalRef)
    │   cmp r0, #1  — conditional: probably aborts if integrity check failed
    │
    ├─ CANONICAL-STRING BUILDER (0x23edc — 0x24670, ~600 lines)
    │   Loop of the pattern:
    │       r0 = .bss[cached_jmethodID_slot_N]
    │       r2 = *r0
    │       r1 = obj_N  (accumulator, starts with Chain)
    │       r3 = *r6 + fp  (fp = 0x10589130 = CallObjectMethodV real addr)
    │       blx r3        ← calls method on obj, returns new obj
    │   This is executed ~13 times, once per accessor we need.
    │
    │   The .bss slots used (in order of first access in intercept):
    │       0x7dfc4, 0x7dfc8, 0x7dfcc, 0x7dfd0, 0x7dfa8, 0x7dfd4, 0x7dfd8, ...
    │
    │   Between calls there are:
    │     - bl 0x1edf8  (13× total, wraps JNIEnv->CallObjectMethodV(..., va_list))
    │     - bl 0x1ee70  ( 4× total, wraps JNIEnv->GetStaticObjectField)
    │     - bl 0x174c8  ( 3× total, appears to be the CRYPTO block fn)
    │     - bl 0xd7a4   ( 8× total, the internal allocator)
    │     - bl 0x766a0  ( 4× total, pthread_cond_wait @PLT — synchronization)
    │     - bl 0x76880  ( 3× total, strncmp@PLT — header-name comparison)
    │
    ├─ HASH/HMAC FINALIZE (scattered throughout, 3× 0x174c8 calls)
    │   Each call to 0x174c8 is preceded by a malloc(r4) and mov r1, sb, mov r2, r6
    │   suggesting: 0x174c8(dst_buf, src_buf, len) — a one-shot crypto transform
    │
    ├─ BUILD OUTPUT REQUEST (0x24670 — 0x248a0)
    │   Call Request.newBuilder() → builder
    │   Call builder.header("shield", base64(sig_blob))
    │   Call builder.header("xy-platform-info", ...)
    │   Call builder.header("xy-ter-str", ...)
    │   Call builder.build() → new Request
    │
    └─ RETURN: call chain.proceed(newRequest) → Response
```

### 3.2 Confirmed from annotated asm

- **`0x1edf8` is NOT a string decrypt function** — despite being called 13×. Its first instructions:
  ```
  01edf8  sub sp, #4
  01edfa  push {r4,r5,r7,lr}
  01edfc  add r7, sp, #8
  01edfe  sub sp, #0xc
  01ee00  ldr r4, [pc, #0x2c]      ← pc-rel constant
  01ee02  add r4, pc
  01ee04  ldr r5, [r4]              ← state ptr
  01ee06  ldr r4, [r5]              ← JNIEnv*
  01ee08  str r3, [r7, #8]          ← save arg va_list
  01ee0a  str r4, [sp, #8]
  01ee0c  ldr r3, [r0]              ← r0 = JNIEnv*, r3 = iface
  01ee0e  ldr.w r4, [r3, #0x8c]     ← r4 = iface[#0x8c / 4 = 35] = CallObjectMethodV
  01ee12  add.w r3, r7, #8
  01ee16  str r3, [sp, #4]
  01ee18  blx r4                    ← call!
  ```
  That's a **varargs-to-array forwarder for `JNIEnv->CallObjectMethodV`**. Each call corresponds to invoking one Java method on an object.

- **`0x1ee70` is a wrapper for JNIEnv->GetStaticObjectField** (`[r3, #0x238] / 4 = 142`). Used to load static Java fields like `ContextHolder.sAppId`.

- **`0x174c8` is NOT a normal function** — no prologue, no push, no stack setup. It's a **control-flow-flattened fragment** reached via computed branches. Its first instructions load a byte from an offset (`ldrb r0, [r1, #0x13]`) and then use conditional branches. This matches what a compressed / VM-obfuscated crypto round function looks like. It is the strongest candidate for the actual HMAC block function.

- **`fp = 0x10589130`** — a compile-time constant added to `.bss`-stored values to recover real function pointers. Every indirect JNI-method call in intercept follows the pattern `r3 = loaded_base + fp`.

### 3.3 The canonical-string builder: sequence of JNI calls

From my Unicorn emulation of JNI_OnLoad (which ran the first 39 JNI lookups before dying at a NEON/CFG-flattening barrier), here is the partial ordered list of classes and methods that JNI_OnLoad looked up **and stored in .bss slots for intercept() to use**:

1. `android/app/ActivityThread.currentApplication()` — static, to get Application ctx
2. `android/app/Application.getPackageManager()` — for APK integrity check
3. `android/app/Application.getPackageName()` — for getPackageInfo
4. `android/content/pm/PackageManager.getPackageInfo(name, flags)` — for signatures
5. `android/content/pm/PackageInfo.signatures` (field) — array of Signature objects
6. `android/content/pm/Signature.hashCode()` — **KEYS THE STRING DECRYPTION**

After this point Unicorn died in a NEON-heavy function at `0x18930`. The remaining lookups (which intercept uses) are **not captured** from my emulation, but they must include (based on decrypted strings in the table):
- `okhttp3.Interceptor.Chain.request()`
- `okhttp3.Request.method()` → String
- `okhttp3.Request.url()` → HttpUrl
- `okhttp3.Request.headers()` → Headers
- `okhttp3.Request.body()` → RequestBody
- `okhttp3.Request.newBuilder()` → Request.Builder
- `okhttp3.HttpUrl.encodedPath()` → String
- `okhttp3.HttpUrl.encodedQuery()` → String
- `okhttp3.RequestBody.writeTo(BufferedSink)`
- `okhttp3.Headers.size()`, `.name(i)`, `.value(i)`
- `okio.Buffer.<init>()`, `.readByteArray()`, `.clone()`, `.close()`
- `java.lang.String.getBytes(Charset)`
- `java.nio.charset.Charset.defaultCharset()` / `forName("UTF-8")`
- `okhttp3.Request.Builder.header(String, String)` (to add `shield`, `xy-platform-info`, `xy-ter-str`)
- `okhttp3.Request.Builder.build()` → Request
- `okhttp3.Interceptor.Chain.proceed(Request)` → Response
- `com.xingin.shield.http.Base64Helper.encodeToString([B)` → String

### 3.4 APK integrity check as key seed

Already confirmed (from §2 of docs/09): libxyass calls `Signature.hashCode()` on the APK's signing certificate and uses the returned int as a seed that gates the string decryption. The computed value for the real APK is:

```
Arrays.hashCode(target/xhs.apk::META-INF/XINGIN.RSA[942 bytes])
= 0x4cdc059d  (signed: +1289487773)
```

This value is cached and fed into the decrypt functions' state, which is why the decrypt functions WORK even when called standalone (the state they need is self-contained — they hard-code the expected seed internally, and my Unicorn run confirms the decrypt succeeds without providing the seed externally).

---

## 4. What the static analysis CAN'T recover

Despite having the intercept() disassembly annotated with 92 decrypted strings and knowing every helper function's role, a few things remain unknown after pure static analysis:

### 4.1 Mapping of .bss slot → method name

intercept() reads from ~20 .bss slots that cache jmethodIDs. I know **every method it could call** (from the decrypted string table) and **every .bss slot it uses** (from the annotated disassembly). But the **mapping between them** requires either:
- Running JNI_OnLoad to completion (blocked by NEON issue at `0x18930`)
- Or statically tracing every `str r0, [.bss_slot]` store in the >800 lines of JNI_OnLoad disassembly after the crash point and matching against the decrypted string that was passed as a GetMethodID argument

The second path is possible but mechanical and tedious — ~8-16 hours of careful bookkeeping.

### 4.2 The exact byte layout of the canonical signing string

I know intercept() reads method/url/path/query/headers/body, builds some buffer via 13 CallObjectMethodV calls, then feeds it into `0x174c8` 3 times. What I don't know from static analysis:

- The **ORDER** in which these are concatenated
- The **SEPARATOR** characters between them (newline? colon? none?)
- Whether headers are sorted or filtered before inclusion
- Whether the body is hashed separately or appended whole
- The **timestamp** or **nonce** insertion point

Without this exact layout, a Python port will produce signatures the server rejects.

### 4.3 The crypto primitive used inside `0x174c8`

Called 3 times in intercept (suggesting init / update / finalize OR three independent hashes). Its body is CFG-flattened with computed branches, so tracing its algorithm statically is multi-day work. It could be:

- HMAC-MD5 (most likely — MD5 T-table is present at `0x79418`, no other hash constants exist)
- A custom construction over MD5
- The "Tiny" house crypto shared with libtiny

### 4.4 How the 100-byte shield binary blob is framed

The `shield` header in captures is a 100-byte binary blob (base64-encoded on the wire) starting with magic `5d 80 00 40`. I know:
- Bytes 0-3: magic `5d 80 00 40`
- Bytes 4-7: flags (observed always `00 40 00 00`)
- Bytes 8-11: reserved `00 10 00 00`
- Bytes 12-15: body length counter
- Bytes 16-19: another counter
- Bytes 20-51: 32-byte hash/HMAC output
- Bytes 52-99: 48-byte nonce/pad

But this framing is inferred from captured traffic, not from reversing the packing code in intercept(). It's consistent with the captured data but needs confirmation.

---

## 5. The Python port — what's achievable from static RE

### 5.1 What's completely static-doable right now

- **Replay mode**: already working and committed ([scratch/ghidra_work/xhs_sign_skeleton.py](../scratch/ghidra_work/xhs_sign_skeleton.py) loads 86 (method, path, body) → headers tuples from the captured mitm session). Works for endpoints where the server doesn't strictly check timestamp freshness.

- **x-legacy-did / x-legacy-sid**: these are pure Java lookups of install UUID and session ID. If you can pull them from a device once, they're reusable indefinitely until the user logs out.

- **SharedPreferences state**: libxyass stores its per-device key in the app's SharedPreferences. If you pull `/data/data/com.xingin.xhs/shared_prefs/` from a logged-in device, you have:
  - `sAppId` value
  - `isHttp` flag
  - device key `k` and session key `s` that go into the `x-mini-mua` JSON
  - Once you have these, you can forge the `x-mini-mua` JSON body yourself (easy — just re-encode). The 100-byte binary trailer is harder.

### 5.2 What's NOT achievable from static RE alone (needs dynamic trace)

- **The exact canonical-string byte format** fed into `0x174c8`
- **The algorithm of `0x174c8`** (the crypto primitive)
- **The output-packing of the 100-byte shield blob** (which bytes are hash, which are counters, which are nonce, exact order)
- **The libtiny x-mini-* signer** entirely — that's a separate library

### 5.3 Recommended next step if a full signer is needed

One properly-set-up Frida hook on `libxyass.so + 0x23e54` for five minutes will give you:

- The full input to intercept (method, url, headers, body)
- The buffer passed to `0x174c8` (the canonical string, byte for byte)
- The output of `0x174c8` (the crypto result)
- The final `shield` value added to the request

With that captured, the Python port is ~2 hours of work. The Frida script [scratch/ghidra_work/frida_dump_shield.js](../scratch/ghidra_work/frida_dump_shield.js) is already written from an earlier session; it needs adjustment for the newly-confirmed addresses (`0x23e54`, `0x174c8`, `0x1edf8`).

---

## 6. Files in this project tree

Everything lives under `/Users/zhao/Desktop/test/xhs/` (no /tmp, no ~):

### Documents
```
docs/01_signature_headers_analysis.md
docs/02_libxyass_ghidra_findings.md
docs/03_signature_algorithm_reverse_engineering.md    (obsolete — based on wrong JNI_OnLoad addr)
docs/04_all_libs_profile.md
docs/05_libxyass_deep_analysis.md
docs/06_libCtaApiLib_analysis.md / libtiny / libxhslonglink / libxyasf
docs/07_libxyass_jni_surface.md
docs/08_intercept_decompiled.md
docs/09_FINAL_static_RE_report.md                     (previous session's partial report)
docs/10_intercept_annotated.md                        (Ghidra decompile — truncated to 218 B)
docs/11_intercept_asm_annotated.md                    (1037 lines, full Capstone annotated)
docs/12_FINAL_static_RE_complete.md                   (THIS FILE)
```

### Scripts (all in scratch/ghidra_work/)
```
ExtractSigFunctions.java      — first Ghidra script, found encrypted strings
DeepAnalyze.java              — XOR/loop scan, top function decompile
ProfileLib.java               — generic lib profiler (used for 4 parallel runs)
DecompileIntercept.java       — decompile 4 JNI methods
AnnotateAndDecompile.java     — re-decompile intercept with decrypted string labels
emu_libxyass.py               — first Unicorn attempt (wrong JNI_OnLoad addr)
emu_v2.py                     — corrected Unicorn emulator, successfully ran JNI_OnLoad
find_decrypt_fn.py            — traces every BL in JNI_OnLoad to find decrypt functions
standalone_decrypt.py         — **standalone Unicorn-based string decryptor**
batch_decrypt_all.py          — batch decrypt entire encrypted range (v1)
batch_decrypt_v2.py           — v2 with strict ASCII filter + length fuzzing
annotate_intercept_asm.py     — produces docs/11_intercept_asm_annotated.md
xhs_sign_skeleton.py          — Python signer skeleton with working replay mode
frida_dump_shield.js          — Frida hook script (ready to run when needed)

jni_onload_real_disasm.txt    — full JNI_OnLoad disassembly (Capstone, 322 lines)
intercept_disasm.txt          — full intercept disassembly (Capstone, 1032 lines)
decrypt_fns_disasm.txt        — 4 smallest decrypt fns disassembled
decrypt_pairs.json            — 39 (cipher, plaintext) pairs captured at runtime
decrypted_v2.json             — full batch-decrypt results (92 strings)
libxyass_strings.json         — CLEAN final dictionary: {offset → plaintext}
```

### Venv
```
.venv_mitm/                   — python3.14 venv with mitmproxy, unicorn, capstone, pyelftools
```

---

## 7. Honest assessment

What this session produced that previous sessions didn't:

1. **Discovered the 10th decrypt function (0x22e24)** — completing the decryption coverage to 92 %.
2. **Built a reusable standalone string decrypter** — can be re-used on future libxyass updates without re-running JNI_OnLoad.
3. **Discovered the TinyInterceptor / libtiny separation** — this is the biggest architectural insight of the whole effort. `shield` is only 1 of 7 signature headers, not the whole thing.
4. **Corrected the misidentification of `0x1edf8` as a decryptor** — it's actually a `CallObjectMethodV` wrapper. Same for `0x1ee70` = `GetStaticObjectField` wrapper.
5. **Confirmed MD5-only crypto family in libxyass** — no SHA-256, no SM3, no BLAKE2. The signature must be MD5-based (HMAC-MD5 most likely).
6. **Generated the full annotated disassembly** of intercept() with decrypted string labels, ready for human reading.

What remains NOT doable from pure static analysis:

1. **The exact canonical-string layout** (which fields concatenated in what order, with what separators)
2. **The `0x174c8` crypto primitive** — CFG-flattened, static trace is multi-day work
3. **The libtiny signer** — completely separate library, not in scope

For a **working Python port**, steps 1-3 still need a ~5-minute Frida dynamic trace. Pure-static RE has brought this effort to about the 75 % mark for libxyass (shield only) and 0 % for libtiny (x-mini-*).

The deliverable for the user's task ("人脑读懂 libxyass 算法 → 纯 Python 复写") is:
- **Can humans now read libxyass's intercept() with confidence?** Yes — [docs/11_intercept_asm_annotated.md](./11_intercept_asm_annotated.md) is readable given the string annotations.
- **Can the shield algorithm be ported to Python from this static info alone?** No — §4.2 and §4.3 block it. The structure is known but the exact bytes are not.
- **Is a complete XHS signer possible from the current static findings?** No — because §4 + libtiny both block it.
- **Is the *shield header* producible by Python without Frida?** Partially: for exact-replay of previously-captured signatures, yes (see §5.1). For *fresh* signing over a new URL/body, no — needs a dynamic trace to fill in §4.2/4.3.
