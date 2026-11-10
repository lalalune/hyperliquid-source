#!/usr/bin/env python3
"""Bind the node #115 Locus `cls` clearinghouse lookup and the `ctr` counter flag (stage 97).

Continues #6164 (tce handler) and #6206 (per-key action 0x5582180). This tool binds:

1. the two Location records naming l1/src/dex_registry/clearinghouses.rs (11:29 and
   17:33) and the perp_meta.rs 163:38 record, with the census of RIP-relative loads
   of each record in .text;
2. the clearinghouse lookup in the tce handler 0x57c9f60: the asset id at [arg+0x38]
   is divided by 10000 (multiply by 0x346dc5d63886594b, shift right 11); the
   quotient must be below Locus cls length (box +0x7d0), else a Result::unwrap panic
   with error tag 0x156 at clearinghouses.rs:11:29; the 0x510-byte element's +0x50
   word must equal the quotient and the remainder (id - q*10000) must be below the
   element's +0x10 length, else an Option panic at perp_meta.rs:163:38; the element's
   +0x8 pointer is then indexed in 0x20-byte steps (byte +0x1d read);
3. the 0x5582180 flag [rsp+0x28]: cleared at 0x5582cb4 and 0x5583230, set to 1 only
   after the call to 0x55817e0 at 0x5583117, which is skipped while [rsp+0x23] or
   the flag is set; Locus ctr (+0xab0) is incremented (saturating) only when the flag
   is set and [rsp+0x58] is non-zero;
4. the direct callers of 0x5582180, 0x55817e0, 0x558b730 and 0x5588d90.

The captured binary is not executed. objdump and readelf are not started.
"""
import argparse
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from fde_extents import fde_extents
from freeze_snapshot_115 import direct_calls, read_va, relative_relocations, text

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-clearinghouse-list-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

LOCATIONS = {
    0x648b990: (b'l1/src/dex_registry/clearinghouses.rs', 11, 29),
    0x648b9a8: (b'l1/src/dex_registry/clearinghouses.rs', 17, 33),
    0x64768a8: (b'l1/src/perp_meta.rs', 163, 38),
}
UNWRAP_MSG = (0x7d3212, b'called `Result::unwrap()` on an `Err` value')

FIXED = {
    # tce handler 0x57c9f60: asset id -> clearinghouse index and local index
    0x57c9fb0: '488b5e38',                  # mov rbx, [rsi+0x38]          (asset id)
    0x57c9fb4: '48ba4b598638d6c56d34',      # movabs rdx, 0x346dc5d63886594b
    0x57c9fc1: '48f7e2',                    # mul rdx
    0x57c9fc7: '49c1ec0b',                  # shr r12, 11                  (id / 10000)
    0x57c9fcb: '4c3ba1d0070000',            # cmp r12, [rcx+0x7d0]         (cls len)
    0x57c9fd2: '0f83da040000',              # jae 0x57ca4b2                (unwrap panic)
    0x57c9ff9: '4c8bb9c8070000',            # mov r15, [rcx+0x7c8]         (cls ptr)
    0x57ca000: '4d69f410050000',            # imul r14, r12, 0x510
    0x57ca018: '4f3b643750',                # cmp r12, [r15+r14+0x50]      (element id)
    0x57ca01d: '0f8582040000',              # jne 0x57ca4a5
    0x57ca023: '4969c410270000',            # imul rax, r12, 10000
    0x57ca02d: '4929c5',                    # sub r13, rax                 (local index)
    0x57ca033: '4d3b6f10',                  # cmp r13, [r15+0x10]          (element list len)
    0x57ca037: '0f8368040000',              # jae 0x57ca4a5
    0x57ca03d: '498b4708',                  # mov rax, [r15+0x8]
    0x57ca044: '48c1e105',                  # shl rcx, 5                   (0x20-byte entries)
    0x57ca048: '0fb654081d',                # movzx edx, byte [rax+rcx+0x1d]
    0x57ca4b2: '66c74424305601',            # mov word [rsp+0x30], 0x156
    0x57ca4d3: 'be2b000000',                # mov esi, 0x2b
    # 0x5582180: flag [rsp+0x28] and the Locus ctr increment
    0x5582cb4: 'c744242800000000',          # mov dword [rsp+0x28], 0
    0x5583230: 'c744242800000000',          # mov dword [rsp+0x28], 0
    0x55830d8: '0fb6442423',                # movzx eax, byte [rsp+0x23]
    0x55830dd: '0a442428',                  # or al, [rsp+0x28]
    0x55830e1: 'a801',                      # test al, 1
    0x55830e3: '7541',                      # jne 0x5583126                (skip the call)
    0x5583120: 'b001',                      # mov al, 1
    0x5583122: '89442428',                  # mov [rsp+0x28], eax          (flag = 1)
    0x5583256: '48837c245800',              # cmp qword [rsp+0x58], 0
    0x558325c: '0f95c0',                    # setne al
    0x558325f: '84442428',                  # test [rsp+0x28], al
    0x5583273: '498b85b00a0000',            # mov rax, [r13+0xab0]         (Locus ctr)
    0x558327a: '48ffc0',                    # inc rax
    0x5583284: '480f44c1',                  # cmove rax, rcx               (saturate)
    0x5583288: '498985b00a0000',            # mov [r13+0xab0], rax
}
REFERENCES = (
    # (instruction va, prefix, length, target)
    (0x57ca4a5, b'\x48\x8d\x3d', 7, 0x64768a8),
    (0x57ca4ac, b'\xff\x15', 6, 0x64df830),
    (0x57ca4b9, b'\x48\x8d\x3d', 7, UNWRAP_MSG[0]),
    (0x57ca4c7, b'\x4c\x8d\x05', 7, 0x648b990),
    (0x57ca4d8, b'\xff\x15', 6, 0x64df6a0),
    (0x5583117, b'\xe8', 5, 0x55817e0),
)
CALLEES = (0x5582180, 0x55817e0, 0x558b730, 0x5588d90)


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def rip_target(data, va, prefix, length):
    raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def location(data, rel, va):
    ptr = rel.get(va)
    if ptr is None:
        raise ValueError(f'Location {va:#x} has no relocation')
    n = struct.unpack('<Q', read_va(data, va + 8, 8))[0]
    line, col = struct.unpack('<II', read_va(data, va + 16, 8))
    return read_va(data, ptr, n), line, col


def lea_census(data, target):
    base, code = text(data)
    count = 0
    for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = m.start()
        if i + 7 <= len(code) and base + i + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            count += 1
    return count


def bind(data, fdes):
    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, target in REFERENCES:
        if rip_target(data, va, prefix, length) != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, UNWRAP_MSG[0], len(UNWRAP_MSG[1])) != UNWRAP_MSG[1]:
        raise ValueError('unwrap message changed')
    rel = relative_relocations(data)
    locs = {}
    for va, want in LOCATIONS.items():
        got = location(data, rel, va)
        if got != want:
            raise ValueError(f'Location {va:#x} changed')
        locs[hex(va)] = {'file': got[0].decode(), 'line': got[1], 'col': got[2], 'lea_refs': lea_census(data, va)}
    # magic divisor: ceil(2^75 / 10000) shifted form used by mul+shr 11 (high half, then >> 11)
    if (0x346dc5d63886594b * 123456789) >> 75 != 123456789 // 10000:
        raise ValueError('divisor constant changed')
    for sample in (0, 9999, 10000, 19999, 2**40 + 7):
        if (0x346dc5d63886594b * sample) >> 75 != sample // 10000:
            raise ValueError('divisor check failed')

    def frame(va):
        hits = [f for f in fdes if f['start'] <= va < f['end']]
        if len(hits) != 1:
            raise ValueError(f'{va:#x} is not in one FDE')
        return hits[0]['start']

    callers = {hex(t): sorted({(hex(c), hex(frame(c))) for c in direct_calls(data, t)}) for t in CALLEES}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'locations': locs,
        'clearinghouse_lookup': {
            'function': hex(0x57c9f60),
            'index': 'clearinghouse = asset_id / 10000 (mul 0x346dc5d63886594b, shr 11); '
                     'local = asset_id - clearinghouse * 10000',
            'bounds': 'clearinghouse < Locus cls len (box +0x7d0) else Result::unwrap panic, error tag 0x156, '
                      'clearinghouses.rs:11:29',
            'element': '0x510 bytes at box +0x7c8; +0x50 must equal the clearinghouse index, '
                       'local must be < +0x10 (list at +0x8, 0x20-byte entries, byte +0x1d read), '
                       'else panic via slot 0x64df830 at perp_meta.rs:163:38',
        },
        'ctr_flag': {
            'function': hex(0x5582180),
            'cleared': [hex(0x5582cb4), hex(0x5583230)],
            'set': hex(0x5583122) + ' after the only call to 0x55817e0 in this block (0x5583117)',
            'skip_call_when': '[rsp+0x23] | flag has bit 0 set',
            'increment': 'Locus ctr +0xab0 saturating inc at 0x5583273 when flag set and [rsp+0x58] != 0',
        },
        'callers': callers,
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    locs = result['locations']
    print('refs', {k: v['lea_refs'] for k, v in locs.items()})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
