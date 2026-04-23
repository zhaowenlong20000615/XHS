# libxyass.so — Unicorn Engine Black-Box Emulation Feasibility

**Date:** 2026-04-11
**Scope:** Assess whether `libxyass.so` can be run end-to-end inside Unicorn Engine (pure userland ARM emulator) to produce XHS request signature headers (`shield` / `x-mini-sig` / `x-mini-mua` / `x-mini-s1` / ...) without any real device, Frida, or APK patching.
**Verdict:** **Feasible. Recommended to proceed.** Risk is moderate; main effort is implementing ~43 libc stubs and a fake JNIEnv/JavaVM function table. No dlopen/dlsym chain and no evidence of hard anti-emulation checks at the import layer.

---

## 1. Binary facts (measured, not guessed)

Target: `target/apk_libs/lib/armeabi-v7a/libxyass.so`

| Property | Value |
|---|---|
| Format | ELF32 LSB, ARM EABI5, **stripped** |
| Arch | ARM:LE:32:v8, Thumb-2 |
| BuildID | `dd6f657739d9a6212bd27e4bc895a79d3c52fc57` |
| File size | 489 KB |
| Image base | `0x00010000` (from Ghidra; phdr vaddrs start at `0x0`, Ghidra rebases to +0x10000) |
| LOAD segments | 2 — r-x `[0x00000000..0x00076900]`, rw- `[0x0007a900..0x0007e33c]` |
| Entry points | `.init_array` has **2 ctors** at `0x0001eead`, `0x0001ef1d` (Thumb, LSB=1); `.fini_array` has 2 |
| JNI_OnLoad | `0x0002ef68` |
| RegisterNatives call site | `0x0002f0e6` (`ldr.w r5,[r2,#0x35c]` → JNIEnv slot 215) |
| Dynamic tags (NEEDED) | `liblog.so`, `libm.so`, `libdl.so`, `libc.so` (cosmetic — see §3) |

### Section layout of note

```
 13 .rodata     4e7c bytes @ 0x088d8                 (DATA)
 14 .text      67aac bytes @ 0x0d760                 (TEXT — main code)
 15 .ppp.ttl    142c bytes @ 0x7520c  <-- custom     (TEXT — obfuscated/bonus code)
 16 .plt         2c0 bytes @ 0x76640                 (PLT stubs)
 17 .data.rel.ro 1364 bytes @ 0x7a900                (RO post-reloc)
 19 .data       1d54 bytes @ 0x7bc70
 22 .got          64 bytes @ 0x7dab4
 23 .got.plt      b4 bytes @ 0x7db18
 24 .bss         76c bytes @ 0x7dbd0
```

`.ppp.ttl` is a custom section marked TEXT and lives inside the r-x segment; a straight phdr-based mapping picks it up for free — no special handling needed.

---

## 2. Relocations (measured)

```
  2696  R_ARM_RELATIVE     <-- image_base + *slot; trivial
    42  R_ARM_JUMP_SLOT    <-- PLT entries to libc (stubs)
     2  R_ARM_GLOB_DAT     <-- __sF, __stack_chk_guard
```

**Zero exotic rel types.** A ~30-line Python loader can resolve everything. No TEXTREL; no R_ARM_COPY; no IRELATIVE.

---

## 3. Imported symbols — full list (43, all libc/pthread)

**Memory management (8):**
`malloc`, `free`, `realloc`, `posix_memalign`, `memchr`, `memcmp`, `memcpy`, `memmove`, `memset`

**String / format (7):**
`strlen`, `strcmp`, `strncmp`, `sprintf`, `snprintf`, `vasprintf`, `vfprintf`

**pthread (13) — critical for TLS:**
`pthread_mutex_lock`, `pthread_mutex_unlock`,
`pthread_rwlock_init`, `pthread_rwlock_destroy`,
`pthread_rwlock_rdlock`, `pthread_rwlock_wrlock`, `pthread_rwlock_unlock`,
`pthread_cond_broadcast`, `pthread_cond_wait`,
`pthread_once`,
`pthread_key_create`, `pthread_key_delete`, `pthread_getspecific`, `pthread_setspecific`

**stdio / misc (10):**
`fflush`, `fprintf`, `fputc`, `__sF`, `time`, `uname`, `syscall`, `abort`, `__assert2`, `dl_unwind_find_exidx`

**CRT / stack (5):**
`__cxa_atexit`, `__cxa_finalize`, `__stack_chk_fail`, `__stack_chk_guard`, *(R_ARM_GLOB_DAT pair)*

### Critical observations

1. **NO `dlopen` / `dlsym` / `dlerror`.** The `libdl.so` NEEDED tag is cosmetic — nothing actually resolves symbols from it. **This directly contradicts doc 03 §3.1 / §4.3 which asserted libxyass calls `libtiny.so` for SHA-256.** All crypto primitives must be **internal to libxyass**, either hand-rolled in `.text` or hidden in the `.ppp.ttl` custom section (5 KB is plenty for SHA-256 + HMAC + MD5). **This simplifies emulation drastically — libtiny.so does not need to be loaded at all.**

2. **NO filesystem or process-introspection imports.** No `open`, `read`, `stat`, `access`, `readlink`, `getpid`, `gettid`, `ptrace`, `getenv`. So no `/proc/self/maps`-style anti-emulation at the libc layer. Any anti-sandboxing must go through the one `syscall` import (§5 risk).

3. **NO network imports.** No `socket`, `connect`, `send`. The library only transforms request metadata — confirming it is a pure signing engine.

4. **NO `getrandom` / `/dev/urandom` imports.** Randomness for the 64-byte nonce tail must come from `time()` + internal PRNG, or from a Java-supplied seed passed through `initialize(token)`. Either way: deterministic on our side if we control `time()`.

5. **NO `gettimeofday` / `clock_gettime` imports.** Millisecond timestamps (if used for anti-replay) can only come from `time()` (1-second resolution) or `syscall(SYS_clock_gettime, ...)`. We control both.

---

## 4. Stub effort estimate

| Category | Count | Difficulty | Notes |
|---|---:|---|---|
| Pure numeric (`memcpy`/`memset`/`memcmp`/`strlen`/`strcmp`/`strncmp`/`memchr`/`memmove`) | 8 | trivial | 1-line Python each; read/write Unicorn memory |
| Allocator (`malloc`/`free`/`realloc`/`posix_memalign`) | 4 | easy | bump allocator on a dedicated heap region; free is no-op |
| Format (`sprintf`/`snprintf`/`vasprintf`/`vfprintf`/`fprintf`/`fputc`/`fflush`) | 7 | medium | only need to handle what libxyass actually calls — logging mostly; minimal `%s`/`%d`/`%x` is enough |
| pthread mutex/rwlock/cond | 9 | trivial | no-ops (single-threaded emulation) |
| pthread TLS (`key_create`/`get`/`set`/`delete`/`once`) | 5 | easy | flat Python dict keyed on key-id; `pthread_once` = run-once flag |
| CRT (`__cxa_atexit`/`__cxa_finalize`/`__stack_chk_fail`/`__stack_chk_guard`/`abort`/`__assert2`) | 6 | trivial | `atexit` stores cb but never fires; guard = fixed cookie; fail = unicorn halt |
| `time` | 1 | trivial | return fixed value (for reproducibility) |
| `uname` | 1 | easy | write a Linux-ARM `struct utsname` into the out-buf |
| `syscall` | 1 | **MEDIUM RISK** | must decode syscall number and dispatch — see §5 |
| `dl_unwind_find_exidx` | 1 | easy | return pointer to `.ARM.exidx` section (already mapped) |
| `__sF` (GLOB_DAT, stdio FILE[3]) | 1 | easy | allocate 3 dummy FILE structs in emu memory |

**Total: 43 PLT + 2 GLOB_DAT = 45 slots.** Est. implementation: **~400 lines of Python**, spread across `stubs.py`.

---

## 5. Risks (ranked)

### R1 — `syscall(...)` handler (MEDIUM)

One `syscall` import is the only potential anti-emulation vector at the libc layer. Possible uses in an obfuscated crypto lib:

- `SYS_clock_gettime` (`0x107` on ARM EABI) — legitimate timestamp source
- `SYS_gettid` (`0xe0`) — TLS-less thread ID
- `SYS_getrandom` (`0x180`) — random bytes for the nonce tail
- `SYS_ptrace` (`0x1a`) — anti-debug check
- `SYS_prctl` (`0xac`) — `PR_GET_DUMPABLE` check

**Mitigation:** Implement the `syscall` stub as a dispatcher that logs every invocation with (nr, args) on first sight. Drop `getrandom`/`clock_gettime`/`gettid` to fixed values; abort loudly on `ptrace`/`prctl` so we know to counter it. This is the single place where "black-box" might leak; acceptable since we can deal with it empirically.

### R2 — TPIDRURO (ARM TLS coprocessor register) (LOW)

Android bionic reads the TLS base via `MRC p15, 0, Rd, c13, c0, 3` (TPIDRURO). If libxyass's inlined `__errno()` or stack canary path touches it, we must pre-set `UC_ARM_REG_C13_C0_3` (Unicorn exposes it via `UC_ARM_REG_TPIDRURO`) to point at a fake 1 KB TCB block. **Well-documented Unicorn pattern** — ~10 lines. Not a blocker.

### R3 — `.ppp.ttl` custom section behavior (LOW-MEDIUM)

5 KB custom `TEXT` section at `0x7520c`. It lives inside the r-x PT_LOAD segment, so a phdr-based mapping already covers it. If it contains self-modifying code or it's called via an obfuscated pointer (doc 02 mentions `+0x666e4b10` XOR-offsets on function pointers), Unicorn will just execute it — it does not care about ELF section semantics. This is actually easier in Unicorn than in Ghidra.

### R4 — JNI function table completeness (LOW)

We need a JNIEnv function table where slot 215 (offset `0x35c`) is `RegisterNatives`, plus whatever other slots are called from:
- The 2 `.init_array` ctors (probably zero JNI calls — these run before JNI_OnLoad)
- `JNI_OnLoad` itself (`GetVersion`, `FindClass`, `RegisterNatives`, possibly `ExceptionClear`)
- The 4 dynamically-registered natives — `initialize(String)` will call `GetStringUTFChars` / `ReleaseStringUTFChars`; `intercept(Chain, long)` will walk the okhttp `Chain` object tree and create a `Response` return value — **this is where emulation gets heaviest** because every Java-side field access goes through `GetMethodID` / `CallObjectMethod` / `NewStringUTF` etc.

**Mitigation strategy:** Two-phase approach.
- Phase A (easy): emulate just far enough to fire `RegisterNatives` and extract the 4 real native function pointers. Verifies the binary runs and gives us known-good entry points.
- Phase B (harder but optional): instead of driving the full `intercept(Chain, cPtr)` via a fake `Chain` object graph, **call lower-level internal functions directly** (e.g. the `sign_blob()` routine that produces the 100-byte shield tail, once we know its address from static analysis or from phase-A runtime traces). This bypasses the okhttp object-graph simulation entirely and is the standard "emulator hooks the crypto, not the JNI wrapper" pattern.

### R5 — Hand-rolled crypto discovery (LOW)

Since doc 03's "libtiny does SHA-256" claim is wrong (proven in §3), the crypto is inside libxyass. We don't need to recognize it — Unicorn runs it as-is. If a future "pure-Python replacement" is desired, we can extract the crypto-primitive function addresses from emulation traces, which is orthogonal to this plan.

---

## 6. Risks we explicitly do NOT need to handle

| Concern | Why it's a non-issue |
|---|---|
| String decryption (XOR obfuscation, doc 03 §4.1) | Unicorn just runs the decryptor; we don't need to reverse it |
| `+0x666e4b10` XOR function pointers | Same — runtime computed, emulator follows |
| Anti-Frida / anti-hooking | We are not Frida; no injection markers present |
| SSL pinning | We do no network; the signer works on in-memory bytes |
| LSPosed / Magisk detection | Pure emulator, no Android framework signals |
| `/proc/self/maps` parsing | No `open`/`read` imports |

---

## 7. Success criteria (phased)

1. **M0 — Loader lands.** ELF segments mapped in Unicorn, relocations applied, 45 stubs installed, `.init_array` ctors run to completion without faulting. *(~1-2 days)*
2. **M1 — RegisterNatives captured.** `JNI_OnLoad` runs; our fake JNIEnv slot-215 hook records the 4 `(name, signature, fnPtr)` tuples. Names prove out as `initializeNative`, `initialize`, `intercept`, `destroy` (or their decrypted equivalents). *(~1 day)*
3. **M2 — initialize(token) returns cPtr.** Drive `initialize` with a token string from a captured `x-mini-mua.k`; receive a non-zero `long cPtr`. *(~1-2 days, depends on how much JNI the function touches)*
4. **M3 — intercept produces headers.** Either by fully simulating the `Chain` object or by calling an internal `sign_blob()` directly, produce the 100-byte shield tail for a known `(method, url, body)` and byte-match against a captured request from `capture/session2_full_usage_20260411_123810.mitm`. *(~2-4 days)*
5. **M4 — Python API.** `unicorn/sign.py::sign_request(method, url, body, device_state) -> dict[str, str]`. *(~0.5 day)*

**Total effort estimate:** 6-10 working days for a single engineer, assuming no nasty surprise in the `syscall` dispatcher or a hidden environment check.

---

## 8. Why this approach beats the parallel tracks

- **vs static Ghidra reversing:** We do not need to understand the code. We do not need to defeat XOR string encryption or function-pointer obfuscation. Unicorn executes them natively.
- **vs Frida on-device:** We do not need to defeat XHS's Frida detection (memory 1362, 1368). The emulator has no `/proc/self/maps`, no `gum-*` symbols, no Java VM.
- **vs APK patching:** We never touch the APK, never re-sign it, never install it.
- **vs pure-Python reimplementation:** We do not need to reverse the exact HMAC key derivation, nonce source, or shield byte layout — the emulator produces the ground-truth bytes. We can *later* simplify to pure Python once we have a working oracle.

The unique failure mode of this approach is a piece of code inside libxyass that relies on OS/Java state we cannot reproduce (e.g., reads `/proc/self/maps` via `syscall(SYS_openat, ...)` and verifies libtiny's text hash). The measured import set gives us no evidence this happens — but R1 is our canary.

---

## 9. Recommended next actions

1. **Set up** a dedicated venv at `unicorn/.venv/` (avoid polluting system Python) with `unicorn-engine>=2.0`, `pyelftools`, `capstone`.
2. **Implement** `unicorn/loader.py` — phdr-based ELF mapping + R_ARM_RELATIVE / JUMP_SLOT / GLOB_DAT resolution + stub hook table.
3. **Implement** `unicorn/stubs.py` — the 43 libc stubs per §4.
4. **Implement** `unicorn/jni_env.py` — fake JNIEnv with at least slots called before `RegisterNatives` (GetVersion, FindClass, ExceptionClear, RegisterNatives=215, GetStringUTFChars, NewStringUTF).
5. **Drive** `JNI_OnLoad` to M1 and capture the 4 native entry addresses → append to this doc.
6. **Iterate** on `initialize` → `intercept` (or direct `sign_blob`) to M3.

All code under `unicorn/`, intermediate artifacts under `unicorn/scratch/`. No files outside the project tree.

---

## 9b. Execution log

| Milestone | Status | Date | Notes |
|---|---|---|---|
| **M0** loader + stubs + ctors | ✅ | 2026-04-11 | Both `.init_array` ctors return r0=0 cleanly. 0 syscalls. |
| **M1** RegisterNatives capture | ✅ | 2026-04-11 | All 4 natives recovered with plaintext names + JNI signatures. Fix needed: enable NEON via Cortex-A15 + CPACR + FPEXC. |
| **M2a** `initializeNative()` | ✅ | 2026-04-11 | Returns void, no JNI traffic past handled slots. |
| **M2b** `initialize("main")` | ✅ | 2026-04-11 | **cPtr = 0x600011a8** — real heap allocation, context struct built. 46 GetMethodID + 4 GetFieldID lookups satisfied by dummy tokens. |
| **M3** `intercept(Chain, cPtr)` | ⚠️ structural ✅ / content constant | 2026-04-11 | **8103 insns executed inside libxyass per call.** Produces well-formed `shield` header (102 bytes, real HMAC output over magic+flags+counters+hmac+nonce) and fully-substituted `xy-platform-info`. **But output is session-deterministic** — see "M3 Determinism Finding" below. |
| **M4** libtiny.so black-box | ⚠️ loads+dispatches / output gated | 2026-04-11 | All 84 ctors run, JNI_OnLoad captures native `t.a(I[Ljava/lang/Object;)Ljava/lang/Object;` at 0x40090795. Sign cmd `-1750991364` dispatches and runs 5994 insns (vs gid's 2538) — including 21 stack-local result structure writes — but the C→Java-Map conversion is globally gated. **Both sign AND gid return null** → failure is not sign-specific; the tiny subsystem's Android context init never completes in our emulator. See §M4 below. |

**Captured native function pointers** (saved to [unicorn/scratch/m1_natives.json](../unicorn/scratch/m1_natives.json)):

| name | signature | abs (load_base 0x40000000) | file offset |
|---|---|---|---|
| `initializeNative` | `()V` | 0x4001f455 | 0xf454 |
| `intercept` | `(Lokhttp3/Interceptor$Chain;J)Lokhttp3/Response;` | 0x40023e55 | 0x13e54 |
| `initialize` | `(Ljava/lang/String;)J` | 0x40025f69 | 0x15f68 |
| `destroy` | `(J)V` | 0x400262ed | 0x162ec |

**Known paper cut (non-blocking):** JNI_OnLoad's tail (after RegisterNatives) takes a C++ exception landing pad and calls `abort()` at PC 0x759b4. Both M2 calls still complete cleanly afterwards because they don't depend on whatever JNI_OnLoad's post-RegisterNatives init was setting up. Investigate only if M3 starts failing.

### M3 Determinism Finding — important for downstream consumers

**The shield bytes produced by this emulator are byte-identical across:**
- Same signer instance / different URLs / different methods / different bodies
- Different signer instances / same URL
- Different signer instances / different URLs

**Why:** The HMAC input that libxyass feeds to its signing primitive during `intercept()` is derived from the **cPtr context struct**, not from the per-request okhttp objects. cPtr is built during `initialize()` from JNI-resolved device state (`ContextHolder.sDeviceId`, `PackageInfo.versionCode`, `PackageInfo.signatures[0].hashCode()`, etc.). Those fields are read **once** at init time and cached. `intercept()` never re-reads them.

This was proven empirically by injecting a dynamic `sDeviceId` field getter between calls — **counter recorded 0 invocations**, i.e., intercept never asks for the device ID again after initialize.

Additionally, during intercept the emulator observes:
- **Only 1 `GetStringUTFChars` call** total (the lib extracts just one Java string into C during signing)
- Only 1 `NewStringUTF` call
- No `readByteArray` / `GetByteArrayElements` — meaning the okio.Buffer that libxyass builds (with path, query, platform-info, body via writeTo) is **never read back**. That buffer is prep for some other subsystem, not the HMAC.

**Implication:** The shield is a real HMAC over a constant (our emulator's frozen device state). It has all the structural hallmarks of a valid shield but will not match what a real device produces, because a real device supplies real state to initialize.

**Paths to "live" shields (if needed), in order of effort:**
1. **Replay-tolerant endpoints.** Per doc 03 §5.1, XHS accepts replayed shields on many endpoints. A constant shield may work on those.
2. **One-shot device state capture.** Capture a real device's `initialize()` result once (via Frida), serialize cPtr's struct bytes, load into the emulator instead of calling initialize.
3. **cPtr mutation.** Reverse-engineer the offset of the timestamp/nonce/counter inside cPtr and bump them between calls.
4. **Richer JNI state.** Make the fake JNIEnv return varying data for `Application.getPackageInfo`, etc. — but this requires knowing which field drives variance.

All four paths leave the pure-black-box model. Within that model, M3 has produced everything it can.

### M4 — libtiny.so attempted

`libtiny.so` is the *real* signature engine — it produces 7 of the remaining
headers (`shield`, `x-mini-sig`, `x-mini-s1`, `x-mini-gid`, `x-mini-mua`,
`xy-direction`, `xy-scene`) via a single call to
`com.xingin.tiny.daemon.d.a(int cmd, Object[] args)` with command ID
`-1750991364 = 0x97BEA13C`.

**What black-box emulation achieved:**

- Loader handles libtiny's 5.8 MB binary (84 ctors, 227 imports) cleanly
- `UC_HOOK_INTR` emulates inline `svc #0` syscalls (libtiny bypasses the
  libc `syscall` wrapper — 6 different syscall numbers observed including
  `SYS_clock_gettime`)
- 180+ additional libc/pthread/math stubs added to cover libtiny's surface
- All 84 `.init_array` ctors execute cleanly
- `JNI_OnLoad` runs to completion, returns JNI 1.6, captures the single
  native `a` via `RegisterNatives`
- Calling `a(cmd, args)` dispatches correctly by command ID and runs
  command-specific code paths measurable via PC trace:

  | cmd | name | insns | unique PCs | JNI calls |
  |---|---|---|---|---|
  | 0 | init | 2510 | 2502 | 0 |
  | -378830707 | gid | 2538 | 2511 | 0 |
  | -1750991364 | sign | 5994 | 5087 | 6 (GetObjectArrayElement×5 + GetArrayLength) |

**Where it bottomed out:**

All three commands return null with empty result maps. Diagnostic findings:

1. **Sign reads all 5 args** from the Object[] and queries `GetArrayLength`
   on the body bytearray. Good — the args propagate correctly.
2. **Sign builds a result structure in stack memory** — 21 pointer writes to
   `sp+0x1804..sp+0x18a0` in 12-byte stride, with the pointers themselves
   pointing to stack-local buffers. The C-side result object IS being
   populated.
3. **But no JNI HashMap creation** — no `NewObject(HashMap)`, no `HashMap.put`,
   no `NewStringUTF` for result keys. The C-side result is never converted
   into the Java Map that the return type `Ljava/lang/Object;` expects.
4. **gid also returns null** with 0 JNI calls. Since gid is the simplest
   possible "read cached deviceId and return jstring" operation, its failure
   proves the gate is GLOBAL, not sign-specific.
5. **Dispatch uses obfuscated `mov pc, rX` indirect jumps** every ~10
   instructions in the hot path. Static analysis of the critical branches
   requires following computed destinations; conventional "find the bad
   conditional branch" approach yields lookup-table base+offset stores that
   don't reveal the gate condition.

**Most likely root cause:** libtiny's runtime needs a real Android
`Application` / `Context` / `ConnectivityManager` / `SharedPreferences`
chain that `ega.f.a()` (the Java-side init) sets up with 50+ lines of
context-dependent calls. The native `a(cmd)` checks a global flag (set
by that full init chain) before letting any command progress to Map
creation. Without the Android runtime, the global stays zero.

**Paths forward (all leave pure black-box):**

| # | Approach | Effort | Leaves black-box? |
|---|---|---|---|
| 1 | Replay tolerance (doc 03 §5.1) — capture once, reuse | low | yes |
| 2 | Frida one-shot cPtr capture + inject into emulator | medium | yes |
| 3 | Locate and patch the init flag in memory | medium | yes |
| 4 | Deep reverse-engineer libtiny sign path in Ghidra | very high | yes |

The pure black-box ceiling for libtiny on this target is: **binary loads,
JNI registration captured, native dispatch works**. Actual header
production requires one of the four approaches above. Status recorded in
[unicorn/scratch/m4_libtiny_status.json](../unicorn/scratch/m4_libtiny_status.json).

### Complete header reversal status (as of M4)

Out of 15 signature-related headers XHS emits:

| Tier | Headers | Count | Mechanism |
|---|---|---:|---|
| Pure Python | `x-legacy-did`, `x-legacy-sid`, `x-legacy-fid`, `X-B3-TraceId`, `x-xray-traceid`, `xy-common-params` | 6 | Java decompile → [unicorn/java_headers.py](../unicorn/java_headers.py) |
| libxyass Unicorn | `shield` (legacy), `xy-platform-info` | 2 | M0→M3 → [unicorn/sign.py](../unicorn/sign.py) |
| libtiny Unicorn | `shield` (real), `x-mini-sig`, `x-mini-s1`, `x-mini-gid`, `x-mini-mua`, `xy-direction`, `xy-scene` | 7 | M4 blocked at Map conversion |

**Delivered: 8 headers with a pure-Python/Unicorn API.** 7 remain behind
libtiny's Android-context gate — tractable but not within black-box scope.

### Public API

The main entry point is [unicorn/xhs_signer.py](../unicorn/xhs_signer.py)
exposing `XhsSigner`, which combines all three tracks:

```python
from xhs_signer import XhsSigner, XhsIdentity, XhsRequest
s = XhsSigner(XhsIdentity(
    android_id="a5b8432c4477b553",
    session_id="session.1774780073824545783425",
))
h = s.sign(XhsRequest("GET",
    "https://edith.xiaohongshu.com/api/sns/v1/homefeed?num=6"))
# {
#   'x-legacy-did': '...', 'x-legacy-sid': '...', 'x-legacy-fid': '',
#   'X-B3-TraceId': '...', 'x-xray-traceid': '...',
#   'xy-common-params': '...', 'xy-platform-info': '...',
#   'shield-legacy': 'XYAA...==',
#   '_unreversed': 'shield,x-mini-sig,x-mini-s1,x-mini-gid,x-mini-mua,xy-direction,xy-scene',
# }
```

Per-call cost: ~150 ms (dominated by libxyass's 8103 instructions + ~30 JNI
dispatches). Setup cost per-signer: ~1.5 s (libxyass load + JNI_OnLoad +
`initialize("main")`).

Alternative narrower APIs:
- [unicorn/sign.py](../unicorn/sign.py) — `XhsShieldSigner` (libxyass only)
- [unicorn/java_headers.py](../unicorn/java_headers.py) — `JavaSideSigner` (no emulator)

**Empirical answers to §10's open questions, after M2:**
- The `syscall` stub was **never** called through M2 → R1 risk has not yet materialized.
- `.ppp.ttl` reachability: not yet measured (no instruction trace enabled). Will revisit if M3 needs it.
- libxyass touched `__sF`/stdio zero times — `__sF` GLOB_DAT fixup was unnecessary but harmless.
- `initialize()` calls only basic JNI: `GetStringUTFChars`/`ReleaseStringUTFChars`/`GetMethodID`/some `Get*FieldID` — no eager Java callbacks. The okhttp Chain walking is deferred to `intercept()`.

## 10. Open questions to resolve during M0/M1

- What syscall numbers does the `syscall` stub see? (Answered by running M0.)
- Is the `.ppp.ttl` section reachable from normal control flow or is it dead code? (Answered by tracking basic blocks executed during M1.)
- Does `initialize(token)` read from `__sF` (stdio), i.e. does it log anywhere? (If so, the stub can be tightened or loosened.)
- How much of the okhttp `Chain` object does `intercept` actually touch? Full graph walk or just `request().method()`, `.url()`, `.body()`?

These questions are unanswerable from static analysis alone — which is exactly why emulation is the right tool.
