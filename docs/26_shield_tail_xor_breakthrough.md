# shield_tail = data_in XOR DEVICE_MASK_16B

**Date**: 2026-04-14
**Data**: `scratch/native_trace/shield_pairs.jsonl` (15 clean pairs from other window)

---

## TL;DR

```
shield_tail (16B) = hmac_b64_input (16B) XOR DEVICE_MASK (16B)
```

The `hmac_b64` function at `libxyass!0x286d0` is **misnamed**. It is not HMAC,
not base64 wrapper — it is a plain 16-byte XOR with a device-pinned constant.
Verified across 15/15 distinct captures.

For the captured device:

```
DEVICE_MASK = 95d17cdfa2bb91e9947b3b485623f7bb
```

This mask is **not** a literal in `libxyass.so` (grep confirmed) and is **not**
derived from `key1`/`key2`/`ctx_pre` via any standard hash. It is a per-install
secret loaded at runtime — likely from SharedPrefs/KeyStore by an init
constructor.

Operationally this doesn't matter: any single `(hmac_b64_input, shield_tail)`
pair on a target device recovers the mask via XOR.

---

## Evidence

15 pairs from `shield_pairs.jsonl`. For each: `data_in_hex XOR shield_tail_hex`:

```
95d17cdfa2bb91e9947b3b485623f7bb
95d17cdfa2bb91e9947b3b485623f7bb
95d17cdfa2bb91e9947b3b485623f7bb
... (all 15 identical)
```

15/15 produce the same constant. This is mathematically conclusive:

```
shield_tail = data_in XOR k    where k is fixed per-device
```

Brute force coverage that came up empty (~200 constructions tested in
`crack_shield_tail.py`):
- All MD5/SHA1/SHA224/SHA256/SHA512 over `data`, `key||data`, `data||key`,
  `key1||data||key2`, etc.
- All HMAC variants with key candidates: `key1`, `key2`, `key2_no_dash`,
  `key2_bytes`, `key1+key2`, `key2+key1`, etc.
- Nested HMAC (e.g., `HMAC(k1, HMAC(k2, data))`)
- AES-128/256-ECB encrypt/decrypt with hash-derived keys
- Precomputed HMAC-SHA1 continuation from `ctx_pre[0:20]`/`ctx_pre[20:40]`
  (the `cd5fba80...` from canonicalize trace)

XOR with constant matched on the FIRST diagnostic check. None of the hash
variants ever could — XOR is the only function that produces this kind of
fixed-difference fingerprint.

---

## Pipeline status

```
Step 1: build canonicalize        \u2705 path + query + xy-platform-info
Step 2: inner_hash(canonicalize)  \u274c \u2192 16B data_in    \u2190 STILL OPEN
Step 3: shield_tail = data_in XOR DEVICE_MASK_16B  \u2705 SOLVED
Step 4: shield = device_prefix || shield_tail      \u2705 (already had)
```

Only **Step 2** remains. To solve it we need ONE matched pair where the SAME
captured request gives us both:

- `canonicalize` bytes (from `op_update raw_data`)
- `data_in` (from `hmac_b64` entry hook on the SAME ctx in the SAME ms window)

Then we test `inner_hash` candidates against that pair until one matches:
- `MD5(canonicalize)`
- `SHA1(canonicalize)[:16]`
- `HMAC-MD5(key, canonicalize)` with key in {key1, key2, ctx_pre[?]}
- Precomputed HMAC continuation from `ctx_pre`

Once we know `inner_hash`, the entire signer is one function:

```python
def shield_tail(canonicalize_bytes, device_mask):
    return bytes(a ^ b for a, b in zip(inner_hash(canonicalize_bytes), device_mask))
```

---

## What the other window can do next

The simplest possible capture: in **one** request, log both:

1. `op_update` `raw_data` chunks for one `ctx` instance \u2192 reassemble \u2192 canonicalize bytes
2. The very next `hmac_b64` ENTRY on the same tid within ~5ms \u2192 16-byte `data_in`

Output as one JSON line:

```json
{"canonicalize_hex": "...", "hmac_b64_input_hex": "..."}
```

A single such pair fully determines `inner_hash`. Even better: 2-3 pairs to
disambiguate between MD5 and SHA1[:16].

---

## Update to Py signer

[xhs_device_pin_signer.py](../scratch/ghidra_work/xhs_device_pin_signer.py)
now has a `shield_mask: bytes` field on `DeviceSnapshot` and `_shield_hash16`
implemented as `MD5(canonicalize) XOR shield_mask` (placeholder inner hash
until verified).
