#!/usr/bin/env python3
"""
Deeply binary-patch libfrida-gadget.so to remove all shield-detectable strings.

Strategy:
  - Same-length replacement only (no ELF offset changes)
  - Preserve 'frida:rpc' protocol keyword (used in internal if-strcmp)
  - Replace all other 'frida'/'gum-'/'gadget' occurrences with neutral tokens
"""
import sys
from pathlib import Path

SRC = Path('/Users/zhao/.objection/android/armeabi-v7a/libfrida-gadget.so')
DST = Path('/Users/zhao/Desktop/test/xhs/build/stage/lib/armeabi-v7a/libxhsdlsupport.so')


def count_matches(data: bytes, needle: bytes) -> int:
    n = i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            return n
        n += 1
        i += len(needle)


def patch_preserve(data: bytearray, old: bytes, new: bytes, preserve_suffixes=()) -> int:
    """Replace `old` with `new` (same length), but skip if followed by any suffix in preserve_suffixes."""
    assert len(old) == len(new), f'length mismatch: {old}={len(old)} vs {new}={len(new)}'
    count = 0
    i = 0
    while True:
        i = data.find(old, i)
        if i < 0:
            break
        # check preserve
        skip = False
        for suf in preserve_suffixes:
            if data[i + len(old):i + len(old) + len(suf)] == suf:
                skip = True
                break
        if skip:
            i += len(old)
            continue
        data[i:i + len(old)] = new
        count += 1
        i += len(old)
    return count


def main():
    print(f'[*] Loading {SRC}')
    data = bytearray(SRC.read_bytes())
    print(f'[*] Size: {len(data):,} bytes')

    # --- Pre-patch counts ---
    print('\n--- Before ---')
    for needle in [b'frida', b'gum-', b'gadget', b'frida:rpc', b'gum-js-loop', b'frida-gadget']:
        print(f'  {needle!s}: {count_matches(bytes(data), needle)}')

    # --- Replacements (all same length) ---
    replacements = [
        # (old, new, preserve_suffixes)
        # frida (5) -> xycap (5), but keep 'frida:rpc'
        (b'frida', b'xycap', (b':rpc',)),
        # gum- (4) -> xyc- (4). 覆盖 gum-js-loop/gum-error-quark 等
        (b'gum-', b'xyc-', ()),
        # gadget (6) -> xyport (6)
        (b'gadget', b'xyport', ()),
    ]

    total = 0
    print('\n--- Patching ---')
    for old, new, preserve in replacements:
        n = patch_preserve(data, old, new, preserve)
        print(f'  {old!s} -> {new!s}: {n} replacements')
        total += n
    print(f'\nTotal replacements: {total}')

    # --- Post-patch verification ---
    print('\n--- After ---')
    for needle in [b'frida', b'xycap', b'gum-', b'xyc-', b'gadget', b'xyport', b'frida:rpc']:
        print(f'  {needle!s}: {count_matches(bytes(data), needle)}')

    # --- Sanity: ELF magic still intact? ---
    assert data[:4] == b'\x7fELF', 'ELF header corrupted!'
    print('\n[+] ELF magic intact')

    # --- Write output ---
    DST.parent.mkdir(parents=True, exist_ok=True)
    DST.write_bytes(bytes(data))
    print(f'[+] Wrote {DST} ({DST.stat().st_size:,} bytes)')


if __name__ == '__main__':
    main()
