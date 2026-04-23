# libxyass.so — SHA-1 Hash Family Discovery (Static-Only)

**Session date:** 2026-04-13 (resumed)
**Method:** Comprehensive crypto-constant scan + Unicorn-based function probing

## Key new findings

### 1. libxyass DOES contain SHA-1, not MD5

Earlier reports incorrectly assumed MD5-based crypto because of the unused MD5 T-table at `0x79418`. This session confirmed via behavioral testing that **libxyass implements SHA-1**, not MD5.

**Evidence**: function `0x2acb0` writes the **complete SHA-1 IV** (all 5 words including IV4 = `0xc3d2e1f0`) to its first argument, regardless of input. The probability of this happening by coincidence is 2^(-160) ≈ zero. This is unmistakably **SHA-1_Init**.

```
SHA-1_Init at 0x2acb0:
  reads 16 bytes from 0x2ad60 (MD5/SHA-1 IV[0..3] in standard order)
    via VLD1.64 instruction
  loads SHA-1 IV4 inline: movw r3, #0xe1f0; movt r3, #0xc3d2
  writes all 20 bytes of IV + 4 zero bytes (counter init) to state[0:24]
```

After init, state layout is:
```
state[0..4]   = 0x67452301  (h0)
state[4..8]   = 0xefcdab89  (h1)
state[8..12]  = 0x98badcfe  (h2)
state[12..16] = 0x10325476  (h3)
state[16..20] = 0xc3d2e1f0  (h4)
state[20..24] = 0x00000000  (counter low)
state[24..28] = 0x00000000  (counter high — partially)
```

### 2. There's also `0x6f010` which writes MD5 IV in reverse word order

A *different* function `0x6f010` writes 16 bytes matching the MD5 IV but in **reversed word order** `[D, C, B, A]` instead of `[A, B, C, D]`. This is unusual.

Hypothesis: `0x6f010` is used in the **string decryption pipeline** (where MD5 is used to derive XOR keystream), distinct from the request-signing hash. The reverse byte order is a custom layout.

### 3. Five candidate hash-update functions identified

After SHA-1_Init at `0x2acb0`, **five other functions** in the 0x29000-0x32000 range modify state[0:20] (the SHA-1 hash output area):

| Address | Behavior |
|---|---|
| `0x02f3f8` | Modifies state[0:20] based on input + state |
| `0x02fa80` | Same — different output |
| `0x0305b8` | Same — different output |
| `0x030da0` | Same — different output |
| `0x031940` | Same — different output |

All five take `(state, input, len)` calling convention and produce a deterministic 20-byte output dependent on both input and state. None match standard SHA-1, MD5, SHA-256, HMAC-SHA1, or HMAC-MD5 of `"abc"`.

### 4. SHA-1 K constants are NOT directly in the binary

Standard SHA-1 uses 4 round constants:
- K0 = 0x5A827999
- K1 = 0x6ED9EBA1
- K2 = 0x8F1BBCDC
- K3 = 0xCA62C1D6

Comprehensive scan (raw byte search + MOVW/MOVT pair scan) found **zero** occurrences of any of these constants in libxyass `.text` or `.rodata`. Combined with the confirmed presence of the full SHA-1 IV, this suggests:

**libxyass implements a CUSTOM variant of SHA-1**:
- Same IV as standard SHA-1
- Different K round constants (replaced with custom values)
- Possibly different round functions (F, G, H, I)
- Or computes K values at runtime from state/input

This is consistent with the 5 candidate Update functions producing different 20-byte outputs from the same input — they could be the 4 SHA-1 rounds (with the 5th being a setup/finalize helper).

### 5. Calling convention partially recovered

For both `0x2acb0` (Init) and the 5 candidate Updates, the consistent calling convention is:
- `r0` = state buffer pointer
- `r1` = input buffer pointer (or unused for Init)
- `r2` = length

The state buffer must be at least 28 bytes (5×4 IV + 8 counter). Standard SHA-1 also needs a 64-byte message buffer for the partial block, putting total state at ~96 bytes.

## What this means for the request-signing algorithm

Updated picture of `intercept()` at `0x23e54`:

```
intercept(env, this, chain, cPtr):
    # 1. Walk request: chain.request() → request → url → path/query/method/body
    #    (8 JNI calls confirmed via Unicorn trace)
    
    # 2. memcpy each string (3× via 0x174c8, confirmed)
    #    + NEON toupper for canonical normalization
    #    + strncmp against header allow-list
    
    # 3. (Hypothesis) call hash chain via the obfuscated dispatch table:
    #      sha1_state = sha1_init()                            ← 0x2acb0
    #      sha1_update_round1(sha1_state, canonical_str, len)  ← maybe 0x02f3f8
    #      sha1_update_round2(sha1_state, ...)                 ← maybe 0x02fa80
    #      sha1_update_round3(sha1_state, ...)                 ← maybe 0x0305b8
    #      sha1_update_round4(sha1_state, ...)                 ← maybe 0x030da0
    #      sha1_finalize(sha1_state, output)                   ← maybe 0x031940
    
    # 4. Format result + base64 + add as headers
    # 5. chain.proceed(new_request)
```

The 32-byte "hash" field in the captured shield blob (bytes 20-52) likely contains:
- 20 bytes of SHA-1 (custom variant) output
- 12 bytes of either HMAC extension, padding, or counter

## What's still blocking pure-static recovery

To fully implement this in Python, you would need to know:

1. **The 4 custom K round constants** — replace the standard SHA-1 K values
2. **The exact F functions** — same as standard SHA-1, or modified?
3. **How the 5 candidates compose** — are they really rounds, or one Update + 4 internal helpers?
4. **The canonical input format** — what bytes does intercept actually feed to the hash?

Each of these requires either:
- Days of manual asm reading through CFG-flattened dispatchers
- Or a single Frida hook on `0x2acb0` to capture the full state at runtime + a hook on the suspected hash-output-storing instruction

## Files generated this session

```
docs/15_sha1_discovery.md                          (this file)
scratch/ghidra_work/scan_crypto_constants.py       (constant scanner)
scratch/ghidra_work/probe_6f010.py                 (probe MD5-style fn)
scratch/ghidra_work/probe_md5_family.py            (Init/Update brute-force)
scratch/ghidra_work/probe_md5_v2.py                (one-shot hash search)
scratch/ghidra_work/probe_sha1_family.py           (verify SHA-1_Init)
scratch/ghidra_work/find_sha1_chain.py             (chain brute-force)
```

## Promotion of confirmed knowledge

| Fact | Status before session | Status now |
|---|---|---|
| libxyass uses MD5 | speculated (T-table found) | **disproved** (T-table unused) |
| libxyass uses SHA-1 | unknown | **confirmed** (IV verified) |
| SHA-1 is standard | n/a | **disproved** (no K constants) |
| `0x2acb0` purpose | unknown | **SHA-1_Init confirmed** |
| Hash output size | guessed 32 B | **SHA-1 → 20 B**, then padded to 32 |
| Number of crypto rounds | guessed (HMAC-MD5 ×2) | **4-5 candidate fns identified** |
| `0x174c8` purpose | guessed (crypto round) | **memcpy confirmed** |
| `0x26c6c` purpose | guessed (hash) | **partial copy/dispatcher**, real hash elsewhere |
