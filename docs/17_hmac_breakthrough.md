# XHS libxyass — HMAC Breakthrough (continuation of 16_FINAL)

**Status**: Pure-static reverse engineering using Ghidra + Unicorn + decrypted strings.
**Date**: 2026-04-13

This doc captures the breakthroughs in the current session that go beyond
`16_FINAL_static_RE_definitive.md`.

## Headline findings

1. **HMAC is confirmed.** The decrypted string `_hmac` exists in libxyass at
   .rodata blob `0xacc0`. This is the smoking gun proving the request signing
   is HMAC-based, not a custom hash.

2. **Hex alphabet confirmed.** `0123456789abcdef` is decrypted at .rodata blob
   `0xaa58`. This is the hex digit table used somewhere in the pipeline (the
   final hex encoding of an HMAC-SHA1 digest is the natural use).

3. **Base64 encoder confirmed.** Function `0x286d0` produces output whose
   structure is **a libc++ `std::string` in LONG mode (`cap=80`) containing
   only base64 characters**. Probing it with all-zero internal state yields
   `'AAAA...AAA='` which is base64('\\0' * N) — proving the function emits
   base64 of an internal byte buffer.

4. **Caller of 0x286d0 found.** The only direct caller is `0x24a1c`, which is
   a header-builder helper called from `intercept` at `0x247xx`. The caller is
   invoked once per missing header (`r3 = 6, 7, 8, ...` enum values).

5. **0x286d0 signature decoded.** Reading the disassembly of `0x24a90-0x24aa0`
   (the call site setup):

   ```
   r0 = output buffer (sp+0x2c, 80 bytes pre-zeroed by NEON)
   r1 = 1                          ; algorithm selector / mode
   r2 = std::string* (sp+0x20)     ; KEY1 — copied from .bss[0x7df20]
   r3 = ctx_ptr (caller_r5)        ; pointer to int the caller passed
   sp[0]  = *ctx_ptr               ; an int (header enum)
   sp[4]  = std::string* (sp+0x14) ; KEY2 — copied from .bss[0x7df10]
   sp[8]  = raw data pointer       ; the *message bytes* of the SECOND
                                   ;   std::string built via blx r4 (sp+0x38)
   sp[12] = raw data length        ; the *length* of those message bytes
   ```

   So `0x286d0(out, alg, key1_str, ctx, [int, key2_str, data_ptr, data_len])`.
   It produces a base64-encoded HMAC, returned as `std::string` written into
   `*out`.

6. **The two HMAC keys live at .bss `0x7df10` and `0x7df20`** as global
   `std::string` instances, lazily populated by an init routine in function
   `0x1f454` (a 3.6 KB static initializer). The decryption pattern at
   `0x201bc` / `0x20286` is:
   `operator new[](alloc) → memcpy from .rodata via 0x174c8 → write
   (data_ptr, size) into .bss[0x7df1?]`.

7. **0x286d0 contains zero external crypto calls.** Of the 5 unique `bl`
   targets inside the first 0x800 bytes:
   `0xd7a4`=`operator new[]`, `0xda9c`=?, `0xdb18`=?, `0x174c8`=memcpy,
   `0x174e0`=memset. **No PLT entries, no openssl, no boringssl.** All hash
   primitive code is inlined in libxyass itself.

## Reference map of relevant addresses

| Address    | Role                                                   |
|------------|--------------------------------------------------------|
| `0x1f454`  | Static init function — populates .bss std::strings    |
| `0x1eec6`  | Static-init zeroing of `0x7df10`                       |
| `0x1eee0`  | Static-init zeroing of `0x7df20`                       |
| `0x201c6`  | Populator: writes decrypted bytes to `0x7df10`         |
| `0x20292`  | Populator: writes decrypted bytes to `0x7df20`         |
| `0x174c8`  | memcpy (NEON, vectorised)                              |
| `0x174e0`  | memset                                                 |
| `0x23e54`  | `intercept` — the okhttp3 interceptor entry            |
| `0x24a1c`  | Header builder (per-header wrapper around `0x286d0`)   |
| `0x24a64`  | `bl 0xd9a8` — std::string copy from `0x7df20` to local |
| `0x24a74`  | `bl 0xd9a8` — std::string copy from `0x7df10` to local |
| `0x24a5a`  | `blx r4` — third std::string built (the *data*)        |
| `0x24aa0`  | `bl 0x286d0` — the HMAC call                           |
| `0x286d0`  | HMAC + base64 wrapper (returns `std::string`)          |
| `0x7df10`  | `.bss` global std::string — HMAC key2                  |
| `0x7df20`  | `.bss` global std::string — HMAC key1                  |
| `0xa900..` | `.rodata` encrypted-string blobs                       |
| `0xacc0`   | encrypted blob for `_hmac`                             |
| `0xaa58`   | encrypted blob for `0123456789abcdef`                  |
| `0xad58`   | encrypted blob for `shield` (the missing header name)  |

## What still blocks a working Python port

To finish the algorithm we need:

- **The two HMAC keys** at `0x7df10` and `0x7df20`. They are populated by
  `0x1f454`, which is too large/fragile to emulate cleanly with our
  Unicorn+stub setup (it crashes after ~388 instructions). Options:
  - Patch the populator paths at `0x201c6` and `0x20292` so we only run the
    necessary chunks.
  - Manually trace which encrypted blob in `decrypt_pairs.json` corresponds
    to each slot by following the `bl 0x174c8` source pointer at the
    populator call site.
- **The exact hash primitive** (MD5? SHA-1? SHA-256?) used inside `0x286d0`.
  It cannot be inferred from the call graph alone since 0x286d0 is heavily
  CFG-flattened (the same `mov pc, rN` pattern as the rest of libxyass).
  The base64 output size scales with input length in a way that does not
  match any single standard hash:
  - `data="abc" k1="" k2=""` → 60 b64 = 45 raw bytes
  - `data="abc" k1=k2=non-empty` → 72 b64 = 54 raw bytes
  - `data="hello world" k1=k2=non-empty` → 84 b64 = 63 raw bytes
  This linear growth strongly suggests the function **does not hash at all**
  in our test setup — it copies (`key1 || data || key2 || padding`) into a
  buffer and base64-encodes it. The hash step is being silently skipped
  because some internal flag/state is uninitialised.
- **The canonicalisation** that produces the message string. The message
  comes from the third std::string built via `blx r4` (an indirect call)
  at `0x24a5a`. `r4` is loaded from a vtable-like table at `0x24a52`, so
  the canonicalisation function differs **per header type** — there are 6+
  different ones, one per header enum (`shield`, `xy-ter-str`,
  `xy-platform-info`, etc.).

## Updated mental model of intercept signing

```
For each header enum h ∈ {6, 7, 8, 9, 10, 11, ...}:
    canon_str = canonicalize_for_header_h(request)        ; via blx r4 table
    digest    = HMAC( key1=.bss[0x7df20], key2=.bss[0x7df10],
                      msg=canon_str, alg=1 )              ; 0x286d0 internal
    encoded   = base64(digest)                            ; 0x286d0 internal
    request.addHeader(name_for(h), encoded)               ; via 0x1ee70
```

Where `name_for(h)` for each enum maps to one of: `shield`, `xy-ter-str`,
`xy-platform-info`, `x-mini-gid`, `xy-direction`, `xy-scene`, etc.

## Files added in this session

- `scratch/ghidra_work/probe_26c6c_v2.py` — disproved 0x26c6c as a hash
- `scratch/ghidra_work/probe_286d0_hmac.py` — calls 0x286d0 with the corrected
  arg layout and dumps the libc++ std::string output.
- `scratch/ghidra_work/dump_bss_strings.py` — attempts (but fails) to run the
  full static initializer to populate the .bss strings.

## Conclusion

Pure static RE has now identified the **shape** of the signing algorithm
end-to-end:

`HMAC( static_keys, canonicalize_per_header( request ) )` → base64 → header value.

The two remaining unknowns (the static keys and the hash primitive) are both
**recoverable in principle from libxyass alone**, but require either:
(a) a more careful Unicorn harness that runs the static init plus the
    obfuscated `0x286d0` to completion, or
(b) tracing the encrypted .rodata blob → .bss slot mapping from the
    populator code.

Both are within scope of the user's "static RE only" rule. The current
`xhs_sign_skeleton.py` replay path remains the only working signing surface
until those last two pieces are recovered.
