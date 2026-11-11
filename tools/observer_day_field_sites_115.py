#!/usr/bin/env python3
"""Classify the node #115 [reg+0x208] / [reg+0x218] census sites left open by #5952.

#5952 listed 30 disp32 operands at +0x208 or +0x218 (non-rsp base) inside the
77 functions that call the observer record slot 0x64e1010 or the observer
constructor slot 0x64e1020. It named 7 of them (the record entry, the
constructor and two spot checks). This tool pins the other 23 and sorts them
into five shapes:

A. 0x2f19520 (2 sites): a wrapper that builds one observer named
   "handle_request_rate_limiter" through the constructor slot, moves it to
   rbx+0x8 behind a zero tag byte, and stores 6000 at rbx+0x200 (observer
   +0x1f8) and 1 at rbx+0x268. The two operands are 16-byte stores of the
   moved observer's +0x200..+0x21f.
B. 0x2bdf8f0, 0x54a9c70, 0x54b66b0 (5 sites): `mov rdx, [rax+0x208]` where rax
   is loaded through `add rax, 0x110` / `mov rax, [rax]`, or the lazy-init
   slot 0x64e4e70; rdx is then raised to at least (r13 == -1).
C. 0x2bdf8f0, 0x54a9c70, 0x54b66b0 (3 sites): `mov rax, [r14+0x218]` with r14
   = [rsp+0x18], compared with 0x8000000000000000; the same base holds fields
   at +0x9d8 or +0x1548.
D. 0x2cc1120 (6 sites): the function's state (fields at +0xfb0..+0xfbc) keeps
   a begin/end pair of u32 items at +0x208/+0x210 and a pointer at +0x218.
E. 0x422abf0 (7 sites): a 32-byte field at +0x208 is read whole and reset to
   (0, 8, 0, 0) in three places.

Only A has an observer base; its operands are part of a whole-object move.
B to E do not match the observer layout (#5946, #5952: +0x208 a u64 count,
+0x210 an f64 sum, +0x218 an f64 constant). The census shape is unchanged
from #5952.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import bisect
import json
import re
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-observer-day-field-sites-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

RECORD, RECORD_SLOT = 0x1547530, 0x64e1010
CONSTRUCTOR, CONSTRUCTOR_SLOT = 0x1548bb0, 0x64e1020
LAZY_SLOT = 0x64e4e70
NAME = (0x644408, b'handle_request_rate_limiter')

# #5952 already named these 7 (record entry, constructor, two spot checks).
NAMED_BY_5952 = {0x1547732, 0x1547740, 0x1548dd6, 0x15ed69e, 0x422acd2, 0x422ace0, 0x422acee}

# ModRM address -> (shape, instruction address)
SITES = {
    0x2f195a9: ('A', 0x2f195a7), 0x2f195b0: ('A', 0x2f195ae),
    0x2be19dd: ('B', 0x2be19db), 0x2be1a3c: ('B', 0x2be1a3a), 0x2be43ac: ('B', 0x2be43aa),
    0x54abe52: ('B', 0x54abe50), 0x54b87c9: ('B', 0x54b87c7),
    0x2be5ec8: ('C', 0x2be5ec6), 0x54b07f8: ('C', 0x54b07f6), 0x54bce47: ('C', 0x54bce45),
    0x2cc3a70: ('D', 0x2cc3a6e), 0x2cc80fd: ('D', 0x2cc80fb), 0x2cc811c: ('D', 0x2cc811a),
    0x2cc82c7: ('D', 0x2cc82c5), 0x2cc82d3: ('D', 0x2cc82d1), 0x2cc8b73: ('D', 0x2cc8b71),
    0x422ad09: ('E', 0x422ad06), 0x422ad48: ('E', 0x422ad46), 0x422ad64: ('E', 0x422ad62),
    0x422bddc: ('E', 0x422bdda), 0x422bdf7: ('E', 0x422bdf4), 0x422c27e: ('E', 0x422c27c),
    0x422c297: ('E', 0x422c295),
}

FIXED = {
    # A: 0x2f19520 builds one observer and moves it to rbx+0x8
    0x2f1952e: '4889fb',                      # mov rbx, rdi             (output)
    0x2f19543: 'b91b000000',                  # mov ecx, 27              (name length)
    0x2f19553: '48c7042401000000',            # mov qword [rsp], 1       (observer +0x0)
    0x2f1955b: '48b80000000000000040',        # movabs rax, 2.0
    0x2f19565: '4889442408',                  # mov [rsp+8], rax         (observer +0x8)
    0x2f19579: 'baf8010000',                  # mov edx, 0x1f8           (save observer +0x0..+0x1f8)
    0x2f195a7: '0f118308020000',              # movups [rbx+0x208], xmm0 (observer +0x200)
    0x2f195ae: '0f118b18020000',              # movups [rbx+0x218], xmm1 (observer +0x210)
    0x2f195e6: 'baf8010000',                  # mov edx, 0x1f8           (restore at rsp+7)
    0x2f195f1: 'c60300',                      # mov byte [rbx], 0        (tag)
    0x2f195f4: '488d7b01',                    # lea rdi, [rbx+1]
    0x2f195fb: 'baff010000',                  # mov edx, 0x1ff           (rbx+0x8 = observer +0x0)
    0x2f19603: '48c78300020000' + '70170000',  # mov qword [rbx+0x200], 6000 (observer +0x1f8)
    0x2f1960e: '48c78368020000' + '01000000',  # mov qword [rbx+0x268], 1
    # B: rax from the lazy path, then [rax+0x208]
    0x2be19a7: '480510010000', 0x2be1a20: '480510010000', 0x2be4399: '480510010000',
    0x54abe1c: '480510010000', 0x54b8793: '480510010000',   # add rax, 0x110
    0x2be19db: '488b9008020000', 0x2be1a3a: '488b9008020000', 0x2be43aa: '488b9008020000',
    0x54abe50: '488b9008020000', 0x54b87c7: '488b9008020000',  # mov rdx, [rax+0x208]
    # C: r14 = [rsp+0x18]; [r14+0x218] vs 0x8000000000000000
    0x2be5e95: '4c8b742418', 0x54b07c5: '4c8b742418', 0x54bce14: '4c8b742418',
    0x2be5ea9: '49899ed8090000', 0x54b07d9: '49899e48150000', 0x54bce28: '49899ed8090000',
    0x2be5ec6: '498b8618020000', 0x54b07f6: '498b8618020000', 0x54bce45: '498b8618020000',
    0x2be5ecd: '48b90000000000000080', 0x54b07fd: '48b90000000000000080',
    0x54bce4c: '48b90000000000000080',
    # D: 0x2cc1120 state
    0x2cc3a66: '410fb687b00f0000',            # movzx eax, byte [r15+0xfb0]
    0x2cc3a6e: '498d9718020000',              # lea rdx, [r15+0x218]
    0x2cc80f7: '488d0c88',                    # lea rcx, [rax+rcx*4]   (end of u32 items)
    0x2cc80fb: '49898708020000',              # mov [r15+0x208], rax
    0x2cc8102: '49898f10020000',              # mov [r15+0x210], rcx
    0x2cc8116: '488b1c24',                    # mov rbx, [rsp]
    0x2cc811a: '48898b08020000',              # mov [rbx+0x208], rcx   (begin + 4)
    0x2cc8123: '8983b80f0000',                # mov [rbx+0xfb8], eax
    0x2cc82ae: '488b3424',                    # mov rsi, [rsp]
    0x2cc82b8: '488d86bc0f0000',              # lea rax, [rsi+0xfbc]
    0x2cc82c5: '488d8e18020000',              # lea rcx, [rsi+0x218]
    0x2cc82d1: '48898618020000',              # mov [rsi+0x218], rax   (pointer)
    0x2cc8b6d: '488b0c24',                    # mov rcx, [rsp]
    0x2cc8b71: '488b8108020000',              # mov rax, [rcx+0x208]
    0x2cc8b78: '488b8910020000',              # mov rcx, [rcx+0x210]
    # E: 0x422abf0 32-byte field reset to (0, 8, 0, 0)
    0x422accc: '488b0424', 0x422bdd6: '488b0424', 0x422c278: '488b0424',   # mov rax, [rsp]
    0x422acec: '48c78008020000' + '00000000', 0x422bdda: '48c78008020000' + '00000000',
    0x422c27c: '48c78008020000' + '00000000',                                # +0x208 = 0
    0x422acf7: '48c78010020000' + '08000000', 0x422bde5: '48c78010020000' + '08000000',
    0x422c287: '48c78010020000' + '08000000',                                # +0x210 = 8
    0x422ad06: '660f118018020000', 0x422bdf4: '660f118018020000',            # movupd [rax+0x218]
    0x422c295: '0f118018020000',                                             # movups [rax+0x218]
    0x422ad46: '488bb308020000', 0x422ad52: '488b8b10020000', 0x422ad62: '488b9318020000',
}
RIP_REFS = (
    # (instruction va, prefix length, length, target)
    (0x2f19531, 3, 7, NAME[0]),
    (0x2f1954d, 2, 6, CONSTRUCTOR_SLOT),
    (0x2be19cd, 2, 6, LAZY_SLOT), (0x2be1a28, 2, 6, LAZY_SLOT), (0x2be43a1, 2, 6, LAZY_SLOT),
    (0x54abe42, 2, 6, LAZY_SLOT), (0x54b87b9, 2, 6, LAZY_SLOT),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def text(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    return sec['address'], data[sec['offset']:sec['offset'] + sec['size']]


def slot_calls(data, slot):
    base, code = text(data)
    return [base + m.start() for m in re.finditer(rb'\xff\x15', code)
            if base + m.start() + 6 + struct.unpack_from('<i', code, m.start() + 2)[0] == slot]


def framer(fdes):
    ordered = sorted(fdes, key=lambda f: f['start'])
    starts = [f['start'] for f in ordered]

    def frame(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or not ordered[i]['start'] <= va < ordered[i]['end']:
            raise ValueError(f'{va:#x} has no FDE')
        return ordered[i]['start']
    return frame


def disp32_operands(data, disp):
    """[reg+disp32] ModRM operands (mod=10) whose base is not rsp; returns ModRM addresses (as #5952)."""
    base, code = text(data)
    out = []
    for m in re.finditer(re.escape(struct.pack('<i', disp)), code):
        i = m.start()
        if i >= 1 and code[i - 1] >> 6 == 2 and code[i - 1] & 7 != 4:
            out.append(base + i - 1)
        elif i >= 2 and code[i - 2] >> 6 == 2 and code[i - 2] & 7 == 4 and code[i - 1] & 7 != 4:
            out.append(base + i - 2)
    return out

SHAPES = {
    'A': 'observer base: 0x2f19520 builds observer %r via the constructor slot and moves it to rbx+0x8 '
         'behind tag byte 0; [rbx+0x208]/[rbx+0x218] are 16-byte stores of observer +0x200..+0x21f in '
         'that move; then observer +0x1f8 = 6000 and rbx+0x268 = 1',
    'B': 'not an observer: rax comes from the lazy path (add rax, 0x110 / mov rax, [rax], or slot '
         '0x64e4e70), then rdx = [rax+0x208] is raised to at least (r13 == -1)',
    'C': 'not an observer: r14 = [rsp+0x18] also holds +0x9d8 or +0x1548; [r14+0x218] is compared with '
         '0x8000000000000000 (observer +0x218 is an f64)',
    'D': 'not an observer: the 0x2cc1120 state (byte +0xfb0, dwords +0xfb8/+0xfbc) keeps a begin/end '
         'pair of u32 items at +0x208/+0x210 and stores a pointer at +0x218',
    'E': 'not an observer: the 0x422abf0 field at +0x208..+0x227 is read whole and reset to (0, 8, 0, 0) '
         'in three places (observer +0x210 is an f64 sum)',
}


def bind(data, fdes):
    for va, expect in FIXED.items():
        if read_va(data, va, len(expect) // 2) != bytes.fromhex(expect):
            raise ValueError(f'instruction at {va:#x} changed')
    for va, prefix_len, length, target in RIP_REFS:
        raw = read_va(data, va, length)
        if va + length + struct.unpack_from('<i', raw, prefix_len)[0] != target:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, NAME[0], len(NAME[1])) != NAME[1]:
        raise ValueError('observer name changed')
    for modrm, (_, insn) in SITES.items():
        if not insn < modrm < insn + 8 or modrm not in range(insn, insn + len(FIXED[insn]) // 2):
            raise ValueError(f'site {modrm:#x} is not inside its pinned instruction')

    frame = framer(fdes)
    owners = {frame(v) for v in slot_calls(data, RECORD_SLOT) + slot_calls(data, CONSTRUCTOR_SLOT)}
    owners |= {RECORD, CONSTRUCTOR}
    census = {}
    for disp in (0x208, 0x218):
        census[disp] = [v for v in disp32_operands(data, disp) if frame(v) in owners]
    found = set(census[0x208]) | set(census[0x218])
    if found != NAMED_BY_5952 | set(SITES):
        raise ValueError('census changed: %s' % sorted(hex(v) for v in found ^ (NAMED_BY_5952 | set(SITES))))

    table = []
    for modrm in sorted(SITES):
        shape, insn = SITES[modrm]
        disp = 0x208 if modrm in census[0x208] else 0x218
        table.append([hex(modrm), hex(frame(modrm)), hex(disp), shape, hex(insn)])
    counts = {s: sum(1 for v in SITES.values() if v[0] == s) for s in sorted(SHAPES)}
    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'census': {
            'owner_functions': len(owners),
            'plus_0x208': len(census[0x208]),
            'plus_0x218': len(census[0x218]),
            'named_by_5952': sorted(hex(v) for v in NAMED_BY_5952),
            'classified_here': len(SITES),
        },
        'shapes': {s: (SHAPES[s] % NAME[1].decode() if s == 'A' else SHAPES[s]) for s in sorted(SHAPES)},
        'shape_counts': counts,
        'sites': table,
        'observer_semantic_reads_outside_record': 0,
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
    print('sites=%d shapes=%s' % (result['census']['classified_here'], result['shape_counts']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
