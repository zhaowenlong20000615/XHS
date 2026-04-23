# docs/37 — Hash Probe Delivery Report

**Responds to**: `docs/36_hook_requirements_for_hash_crack.md`
**Status**: ✅ P0 A + P0 B delivered, P1 C + P1 D delivered via pre-existing framework
**Session date**: 2026-04-15
**libxyass build**: xhs 9.19.0 (build 9190807)

---

## TL;DR

The Unicorn signer's blocker was: the shield hash function is reached inside
`op_update @ 0x6dd28` through a C++ virtual dispatch whose target is loaded
from `data_buffer_struct[+0xc]` into `r3` and then `blx r3`. The docs/36 spec
asked the xhs-capture LSPosed window to hook that dispatch site on a real
device and dump the resolved target address + struct state.

**The answer: the real compression function is at `libxyass + 0x6ee64`**,
invariant across 61 consecutive calls in one session. Drop that offset into
`unicorn/sign.py`'s dispatch hook and the signer can call it directly,
bypassing both the OLLVM CFG flattening and the vtable chain that blocked
static reversal.

In addition we produced a **26-entry byte-exact regression fixture**
(unique `canonicalize_hex` → `hmac_b64_input_hex` pairs) ready for
`test_hash_byte_exact.py`.

---

## Deliverables

| Path | Size | Purpose |
|---|---|---|
| `scratch/native_trace/hash_probe_20260415_160508.jsonl` | 197 KB | Raw hook output — 61 `op_update_dispatch` + 61 `op_update_return` events |
| `scratch/native_trace/xhs_native_trace_20260415_160508.log` | 411 KB | Full native trace during the same session (INTERCEPT, CANON_LOW, OP_UPDATE, HMAC_B64_WRAP, [PAIR]…) |
| `scratch/native_trace/hash_fixture_20260415_160508.jsonl` | 58 KB | **Regression fixture** — 1 header line + 26 `(canonicalize_hex, hmac_b64_input_hex)` pairs |
| `lsposed/xhs-capture/jni/src/xhscap_hook.cpp` | +~200 LOC | New hooks: `dispatch_blx_pre`, `dispatch_after_pre`, dedicated JSONL writer |

---

## Hook implementation

### Offsets

```cpp
static constexpr uintptr_t LIBXYASS_DISPATCH_BLX_OFF    = 0x6dd8e;   // blx r3
static constexpr uintptr_t LIBXYASS_DISPATCH_AFTER_OFF  = 0x6dd98;   // str r0, [sp, #0xc]
```

### Why 0x6dd98 instead of the 0x6dd90 the spec asked for

The spec proposed hooking `0x6dd90 ldr r1, [r6]` immediately after the `blx`.
In practice that instantly crashed xhs with a `SIGSEGV SEGV_ACCERR` once the
probe fired — shadowhook's BKPT-trap emulator for this specific 2-byte
Thumb-1 load interacts badly with the adjacent Hook A at `0x6dd8e` (they're
only 2 bytes apart, so the trampolines can touch one another), and the
original `[r6]` load fault path ends up with a corrupt r3.

Moved Hook B to **`0x6dd98 str r0, [sp, #0xc]`**:
- **4 bytes past Hook A** → no trampoline overlap
- **On the merge path** — both the `blx`-taken branch and the
  `cbz`-short-circuit branch converge at `0x6dd96` / `0x6dd98`, so B fires
  on every dispatch path
- **`str r0, [sp+0xc]` is trivially emulatable** — stack is always mapped
  writable, no PC-relative arithmetic, nothing to go wrong
- `r0` at this point still holds the blx return value (AAPCS caller-saved
  but nothing has clobbered it between `blx` return at 0x6dd90 and the
  store at 0x6dd98), or `0` when the cbz short-circuit fired

### Callback pairing

The two hooks correlate via thread-local storage. Hook A stashes
`r0_struct_ptr`, `r1_data_ptr`, `r2_length`, and `seq` into TLS; Hook B
reads them back when it fires post-blx and emits `op_update_return` with
the same `paired_seq`. When the event cap is hit, A clears TLS so B skips
silently.

```cpp
static __thread uint32_t t_probe_struct_ptr = 0;
static __thread uint32_t t_probe_data_ptr   = 0;
static __thread uint32_t t_probe_data_len   = 0;
static __thread uint64_t t_probe_seq_in_A   = 0;

#define HASH_PROBE_MAX_EVENTS 300    // ~150 dispatches worth of A+B pairs
```

### Output file

Separate `hash_probe.jsonl` file, separate mutex (`g_probe_mu`), separate fd
(`g_probe_log_fd`) — does not contaminate the main `xhs_native_trace.log`
which is used by other tooling.

```
/data/data/com.xingin.xhs/files/hash_probe.jsonl
```

### Enable via selection

```bash
adb shell 'su -c "echo \"intercept canon_low canon_high update final hmac probe_blx probe_after\" > /data/local/tmp/xhscap_hooks"'
adb shell 'am force-stop com.xingin.xhs'
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'
```

---

## JSONL schema

### `op_update_dispatch` (Hook A — pre-blx)

```json
{
  "event": "op_update_dispatch",
  "seq": 0,
  "tid": 7339,
  "ms": 1776239975606,
  "libxyass_base":        "0x7d3c0000",
  "pc":                   "0x7d42dd8e",
  "r0_struct_ptr":        "0x4c31b130",   // C++ "this" for the virtual call (data_buffer_struct)
  "r1_data_ptr":          "0x480c40d0",   // raw canonicalize bytes to be hashed
  "r2_length":            965,             // length in bytes
  "r3_target_fn":         "0x7d42ee65",   // Thumb-tagged (bit 0 = 1)
  "r3_target_fn_masked":  "0x7d42ee64",   // bit 0 cleared
  "r3_offset_from_lib":   "0x6ee64",      // ★ canonical invariant ★
  "r3_is_thumb":          true,
  "struct_ptr_content":   "hex (0x40 bytes at r0_struct_ptr)",
  "data_ptr_content":     "hex (up to 2048 bytes at r1_data_ptr)",
  "data_truncated":       false,
  "data_full_length":     965
}
```

### `op_update_return` (Hook B — post-blx)

```json
{
  "event": "op_update_return",
  "paired_seq": 0,
  "tid": 7339,
  "ms": 1776239975606,
  "libxyass_base": "0x7d3c0000",
  "pc":            "0x7d42dd98",
  "r0_return":     "0x00000001",          // blx return value
  "r0_struct_ptr": "0x4c31b130",          // same struct as paired A
  "struct_ptr_content_after": "hex (0x40 bytes)"
}
```

---

## Findings

### 1. `r3_offset_from_lib = 0x6ee64` is invariant

```python
{d["r3_offset_from_lib"] for d in dispatches}  # -> {'0x6ee64'}
```

All 61 dispatches in the session resolved to the same compression function
offset. It's safe to hardcode.

### 2. `r0_return` is always `0x1` (success flag)

```python
{int(r["r0_return"], 16) for r in returns}  # -> {1}
```

The real hash function returns a boolean success flag, not the hash state.
The actual hash state mutates **in place** through the struct pointer chain,
not via the return value.

### 3. `struct_ptr_content[0..0x40]` is mostly stable

58 / 61 pairs have **identical** `struct_ptr_content` before and after the
blx. The 3 that change differ only at byte offsets `0x31`, `0x36`, `0x37` —
those look like internal block-fill counters / input-byte-counter bytes
mutating as data streams into the MD-family buffer.

The implication: **the compressed hash state is not stored in the first 0x40
bytes of `r0_struct_ptr`**. The struct is a wrapper object (vtable +
pointers + small counters); the actual 96-byte MD state lives through
`mid[+8]` → `state` which the existing `op_update_pre` hook already dumps
as `hash_state_pre`.

For a "was this the right compression" sanity check in Unicorn, compare the
full 96-byte state at `mid[+8]` before/after the `blx`, not `struct_ptr`.

### 4. Per-request data volume

Canonicalize input sizes ranged from **97 bytes** (`/api/httpdns/prefetch`)
to **2784 bytes** (`/api/sns/v6/homefeed` with large common_params blob).
The hash at `0x6ee64` handled all sizes successfully (`r0_return = 1`
across the board).

### 5. The "vtable" label in `op_update_pre` is off by one deref

The existing `op_update_pre` hook dumps a field called `vtable[3] =
0x7d96ee65`. On inspection that value is **not** `*(*mid + 0xc)` (a true
vtable lookup) — it's **`*(mid + 0xc)`**, i.e., a plain function pointer
stored as a data field in the struct. Decoding the `mid_obj` base64:

```
mid[0..4]   = vtable ptr  (0x7d97bc1c — genuine vtable)
mid[4..8]   = 0
mid[8..12]  = state ptr   (0xf06812c0 — points at 96-byte MD buffer)
mid[12..16] = method ptr  (0x7d96ee65 — ★ the compress fn we want ★)
```

So `op_update_pre` was technically already capturing the answer via its
`vtable[3]` printout — it just wasn't flagged as the target. The new
`dispatch_blx_pre` hook captures it as a structured JSONL field with the
proper semantic label.

---

## Cross-reference: dispatch → PAIR → fixture

The three files form a chain that the Unicorn signer can consume:

```
hash_probe.jsonl            xhs_native_trace.log               hash_fixture.jsonl
(61 hook events)            (27 [PAIR] entries)                (26 regression pairs)
    │                               │                                  │
    │ extracts                      │ emits via TLS flush:              │
    │ r3_offset_from_lib            │ op_update_pre → op_final_pre →    │
    │ r1_data_ptr contents          │ my_hmac_b64 → buffered canon +    │
    │                               │ 16B data_in from hmac_b64 arg     │
    │                               │                                   │
    │                               ▼                                   │
    └──────────────┐   {canonicalize_hex, hmac_b64_input_hex,            │
                   │    key1, key2, header_enum}                         │
                   │                                                    │
                   └────── pair extraction + dedup ────────────────────► │
                                                                        ▼
                                                              hash_fixture.jsonl
                                                              (1 header + 26 pairs)
```

The PAIR lines were emitted by pre-existing xhs-capture framework code that
I didn't touch — `op_update_pre` accumulates canonicalize bytes into a TLS
buffer, `op_final_pre` marks it ready, and `my_hmac_b64` flushes the buffer
plus the 16-byte `data_in` hmac arg into a single `[PAIR seq=…]` JSON line.

The **61 hash_probe events** are more granular than the **27 PAIR lines**
because a single signing request often calls `op_update` more than once
(incremental streaming), but the PAIR collapses all of that into one final
input-output sample per request. 61 ÷ 27 ≈ 2.26 dispatches per request, as
expected.

---

## Regression fixture (for `test_hash_byte_exact.py`)

### Header line

```json
{
  "__type__": "fixture_header",
  "hash_fn_offset_from_libxyass": "0x6ee64",
  "dispatch_blx_offset":          "0x6dd8e",
  "libxyass_base_at_capture":     "0x7e080000",
  "captured_ms_range":            [1776240621631, 1776240637585],
  "r0_return_observed":           [1]
}
```

### Pair line schema

```json
{
  "__type__": "regression_pair",
  "pair_seq": 0,
  "tid": 7339,
  "ms": 1776240621632,
  "key1":        "9190807",
  "key2":        "aa293284-0e77-319d-9710-5b6b0a03bd9c",
  "header_enum": 4,
  "canonicalize_hex":   "2f6170692f...",
  "hmac_b64_input_hex": "91a4f3ccf201650292ea5ae12585b614",
  "canonicalize_len": 965,
  "digest_len":       16
}
```

### Coverage

| # | len | digest[:8] | endpoint |
|---|---|---|---|
| 0  | 965  | `91a4f3cc` | `/api/sns/v2/user/teenager/status` |
| 1  | 984  | `0c991f7b` | `/api/sns/badge/update_badge` |
| 2  | 2485 | `b4d773a4` | `/api/sns/v6/homefeed` (large variant) |
| 3  | 935  | `81eecea3` | `/api/sns/v1/tag/reobpage` |
| 4  | 927  | `fb843119` | `/api/sns/v6/message/detect` |
| 5  | 942  | `d841d96a` | `/api/sns/v1/system_service/config` |
| 6  | 974  | `6dedba85` | `/api/push/get_gesture_guidance_config` |
| 7  | 938  | `11fb1188` | `/api/sns/v1/paddles/pull_shanks` |
| 8  | 946  | `20ec1de2` | `/api/sns/v2/user/account_info/anomalies` |
| 9  | 931  | `2da9589c` | `/api/sns/reach/msg/query` |
| 10 | 1068 | `52462186` | `/api/sns/v2/system_service/splash_async_optimization` |
| 11 | 1124 | `b0435522` | `/api/sns/v2/system_service/splash_async_optimization` |
| 12 | 380  | `20f8afa4` | `/api/model_portrait/model_score` |
| 13 | 126  | `ebbbe839` | `/api/model_portrait/detect_items` |
| 14 | 97   | `a0237848` | `/api/httpdns/prefetch` (smallest) |
| 15 | 382  | `16099224` | `/api/model_portrait/model_score` |
| 16 | 969  | `dfef094a` | `/api/im/v2/messages/offline` |
| 17 | 941  | `fa13c2e5` | `/api/sns/v6/message/detect` |
| 18 | 978  | `da606c2e` | `/api/sns/v1/ads/resource` |
| 19 | 984  | `f6571754` | `/api/sns/v2/system_service/splash_config` |
| 20 | 2784 | `249b45b7` | `/api/sns/v6/homefeed` (largest) |
| 21 | 947  | `aba15fc8` | `/api/sns/v1/system_service/launch` |
| 23 | 1061 | `454347a1` | `/api/sns/v3/user/me` |
| 24 | 982  | `b126bce1` | `/api/redcity/ip/v1/chats/pet` |
| 25 | 950  | `2c423f03` | `/api/sns/v1/system_service/launch` |
| 26 | 1060 | `6a1802f1` | `/api/im/private/query_online_status` |

- **26 unique canonicalize inputs** (no duplicates)
- **26 unique 16-byte digests** (confirms non-degenerate hash)
- **97 → 2784 byte range** — exercises small/medium/large compression paths
- **All session invariants constant**: `key1=9190807`, `key2=<deviceId UUID>`,
  `header_enum=4`, `app_id=0xECFAAF01`

---

## Integration path for `unicorn/sign.py`

### Minimal change — hardcoded offset

```python
# unicorn/sign.py

HASH_COMPRESS_OFFSET = 0x6ee64   # from docs/37 hash probe (2026-04-15)

def _hash_dispatch_hook(uc, pc, size, _ud):
    """
    Called at op_update's `blx r3` site (libxyass + 0x6dd8e) to redirect the
    dispatch to the real compression function at libxyass + 0x6ee64. This
    bypasses the OLLVM-flattened CFG + C++ vtable indirection that we can't
    emulate in Unicorn.
    """
    r0 = uc.reg_read(UC_ARM_REG_R0)   # data_buffer_struct pointer (C++ this)
    r1 = uc.reg_read(UC_ARM_REG_R1)   # raw canonicalize bytes
    r2 = uc.reg_read(UC_ARM_REG_R2)   # length in bytes
    # Call the hash function the real device resolves dynamically, now
    # directly by offset. r0 must stay as the C++ this pointer.
    signer._call(uc, lib_base + HASH_COMPRESS_OFFSET, (r0, r1, r2))
```

### Regression test driver

```python
# scratch/test_hash_byte_exact.py
import json

def load_fixture():
    lines = [json.loads(l) for l in open("scratch/native_trace/hash_fixture_20260415_160508.jsonl")]
    return lines[0], lines[1:]   # (header, pairs)

def test_hash_byte_exact():
    header, pairs = load_fixture()
    assert header["hash_fn_offset_from_libxyass"] == "0x6ee64"
    ok = 0
    mismatches = []
    for p in pairs:
        canon    = bytes.fromhex(p["canonicalize_hex"])
        expected = bytes.fromhex(p["hmac_b64_input_hex"])
        got      = run_emu_hash(canon)   # signer.hash(canon) in unicorn/sign.py
        if got == expected:
            ok += 1
        else:
            mismatches.append((p["pair_seq"], expected.hex(), got.hex()))
    print(f"{ok}/{len(pairs)} byte-exact")
    for seq, exp, got in mismatches[:5]:
        print(f"  seq={seq}")
        print(f"    expected: {exp}")
        print(f"    got:      {got}")
    assert ok == len(pairs), f"{len(mismatches)} hash mismatches"
```

### Expected cascade once hash is byte-exact

Once `test_hash_byte_exact.py` passes 26/26, the downstream hasher chain
should auto-align:

```
canonicalize → [hash @ 0x6ee64] → 16B data_in → hmac_b64_input
                                                     ↓
                                  XOR with DEVICE_MASK_16B (already known)
                                                     ↓
                                                shield_tail (16B)
                                                     ↓
                                  device_prefix (84B, already byte-exact)
                                                     ↓
                                                shield header (100B byte-exact)
```

At that point `scratch/test_note_crud.py` can be re-run against
`/api/sns/v4/note/user/posted` and should return `200 OK` with real note
payload instead of `406`.

---

## Issues encountered & fixes

### Issue 1 — Hook B at 0x6dd90 crashed xhs

**Symptom**: `F libc: Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault
addr 0x7dd75da2 in tid 7947 (sky4), pid 7752 (com.xingin.xhs)` on the first
probe event.

**Diagnosis**: shadowhook installs BKPT-based traps on 2-byte Thumb-1
instructions. Hooking two adjacent 2-byte instructions (`0x6dd8e` and
`0x6dd90`) causes the trap emulator for the second instruction
(`ldr r1, [r6]`) to mis-handle control flow, leaving a corrupt register
that gets used in a subsequent computed branch — which then jumps to an
unmapped address.

**Fix**: moved Hook B to `0x6dd98 str r0, [sp, #0xc]` (see "Why 0x6dd98"
section above). Verified by:

1. With Hook B at 0x6dd90 → xhs crashes instantly (1st probe event).
2. With Hook B removed (only Hook A) → xhs stable, 64 events captured.
3. With Hook B at 0x6dd98 → xhs stable, **61 A + 61 B paired events**
   captured cleanly, no tombstones attributable to xhs pid.

### Issue 2 — device network appears dead after reboot

**Symptom**: xhs shows "no network" error, ping 8.8.8.8 fails, but wifi
shows `VALIDATED` in dumpsys.

**Root cause 1**: `adb reboot` resets the clock to factory default
(`Feb 2025`) which makes TLS cert validation fail system-wide. Visible in
logcat as Google auth `NETWORK_ERROR` for all apps, not just xhs.

**Root cause 2**: `com.tunnelworkshop.postern` VPN auto-starts on boot and
installs a default route `default via tun1 (1.1.1.1/0)` that covers all
uids 0-99999 — but tun1 is a dead tunnel, so all user traffic gets
blackholed. `ip route show table all | grep default` will show the
blackhole route before the real wlan0 route.

**Fix** (both must be applied after every reboot):
```bash
adb shell 'su -c "date 041517002026.00"'               # clock
adb shell 'am force-stop com.tunnelworkshop.postern'   # VPN
```

Consider adding a `preflight_check()` to `deploy_and_dump.sh` that:
1. Checks `getprop ro.build.date` drift against `date +%s` on host
2. Checks `dumpsys connectivity | grep Postern` for active VPN

### Issue 3 — `_rc4_store_pre` hook from earlier session destabilized xhs

(Recorded here for future reference, not re-triggered in this session.)

The previous RC4 plaintext capture hook at `0x28a08` fires on every byte of
every RC4 encryption — with 83-byte plaintexts and ~10 iterations per
shield sign, that's ~1000+ SIGTRAP signals per second which disrupted
xhs's `LongLinkService` native worker timing and caused a `Bad JNI
version passed to GetEnv: 1879114240` symptom plus service crash loops.

For docs/37 I deliberately **omitted** `rc4` from the selection tokens.
The probe_blx/probe_after tokens fire at most 2× per request (~10/sec
under heavy load), well below the RC4 flood rate, and xhs stayed stable
throughout the session.

If docs/32 RC4 data needs to be re-captured, I recommend moving the hook
to after the full 83-byte RC4 is done (single trap per shield instead of
per-byte), or using `shadowhook_unhook` inside the handler to self-remove
after the first capture.

---

## Acceptance checklist (from docs/36 §"验收")

| Item | Status | Evidence |
|---|---|---|
| P0 A — `r3_target_fn` captured | ✅ | `hash_probe_*.jsonl` dispatches all have `r3_target_fn = 0x7e0eee65` and `r3_offset_from_lib = 0x6ee64` |
| P0 A — `struct_ptr_content` | ✅ | 64 bytes per dispatch event |
| P0 A — `data_ptr_content` | ✅ | Up to 2048 bytes per dispatch, 126-2048 observed |
| P0 A — `r0/r1/r2` args | ✅ | All three fields populated |
| P0 B — `r0_return` | ✅ | Always `0x1` across all 61 returns |
| P0 B — `struct_ptr_content_after` | ✅ | 64 bytes per return event; shows 58/61 unchanged + 3/61 mutating at offsets 0x31/0x36/0x37 |
| P1 C — `hmac_b64_entry` | ✅ (pre-existing) | `my_hmac_b64` trampoline wrap already captures entry/exit, 27 events in same session |
| P1 D — per-request (canonicalize, shield-ish digest) pairs | ✅ | `hash_fixture_*.jsonl` has 26 unique pairs, same session, session-invariant keys |
| P2 E — `alt_hash_init` ctx dump | ⚪ skipped | Non-blocking; can be re-enabled via `alt_init` token if needed |

---

## Files touched

### Modified
- `lsposed/xhs-capture/jni/src/xhscap_hook.cpp`
  - +2 offset constants
  - +~200 LOC: `t_probe_*` TLS vars, `g_probe_mu`/`g_probe_log_fd`,
    `probe_ensure_open`/`probe_write`, `dispatch_blx_pre`,
    `dispatch_after_pre`, 2 new targets[] entries
  - No changes to existing callbacks

### Created
- `scratch/native_trace/hash_probe_20260415_160508.jsonl`
- `scratch/native_trace/xhs_native_trace_20260415_160508.log`
- `scratch/native_trace/hash_fixture_20260415_160508.jsonl`
- `docs/37_hash_probe_delivery.md` (this document)

### No changes needed
- `unicorn/sign.py` — integration is the next session's work, this doc
  just provides the data + example code
- `lsposed/xhs-capture/src/...` Java — no Java hook changes needed for this
  task
- `AndroidManifest.xml` / build — no new permissions/dependencies

---

## Next session's work (not in scope for docs/37)

1. Wire `HASH_COMPRESS_OFFSET = 0x6ee64` into `unicorn/sign.py` as the 5th
   hook (at `0x6dd8e blx r3` dispatch point).
2. Write `scratch/test_hash_byte_exact.py` consuming
   `hash_fixture_20260415_160508.jsonl`, target 26/26 byte-exact.
3. Re-run `scratch/test_canonicalize_byte_exact.py` to ensure the
   canonicalize regression still holds (6/6 previous guard).
4. Re-run `scratch/test_note_crud.py` against
   `/api/sns/v4/note/user/posted` — expect 200 OK + real note payload.
5. Clean up LSPosed kill-switch (`/data/local/tmp/xhscap_disable`) if
   left over from debugging, and reset selection to a minimal set if
   docs/37 is considered complete.

---

## Contact points for re-capture

If xhs APK is upgraded or the install data is wiped, re-run this same
capture:

```bash
# 1. pre-flight
adb shell 'date'                              # check clock!
adb shell 'ip route show table all | grep default'  # check for tun1 VPN!

# 2. build + install
cd /Users/zhao/Desktop/test/xhs/lsposed/xhs-capture
NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/r27c ./build.sh
adb install -r build/xhs-capture.apk
# (LSPosed DB path update: see history for `pm path com.xhs.capture` +
#  UPDATE modules SET apk_path=...)

# 3. enable probe hooks
adb shell 'su -c "echo \"intercept canon_low canon_high update final hmac probe_blx probe_after\" > /data/local/tmp/xhscap_hooks"'

# 4. trigger
adb shell 'am force-stop com.xingin.xhs'
adb shell 'monkey -p com.xingin.xhs -c android.intent.category.LAUNCHER 1'

# 5. wait + pull
sleep 20
adb shell 'su -c "cp /data/data/com.xingin.xhs/files/hash_probe.jsonl /sdcard/; cp /data/data/com.xingin.xhs/files/xhs_native_trace.log /sdcard/"'
TS=$(date +%Y%m%d_%H%M%S)
adb pull /sdcard/hash_probe.jsonl      scratch/native_trace/hash_probe_${TS}.jsonl
adb pull /sdcard/xhs_native_trace.log  scratch/native_trace/xhs_native_trace_${TS}.log

# 6. build fixture (see the python snippet in "Cross-reference" section above)
```

The `r3_offset_from_lib` is expected to remain `0x6ee64` for the same APK
build; if it changes across captures, the APK was updated and
`unicorn/sign.py`'s `HASH_COMPRESS_OFFSET` constant needs to be updated
from the new fixture header.
