#!/usr/bin/env python3
"""RE-005 decode side: pin the bincode-fork varint u64 *decode* fast path in node #94.

Static, offline, read-only; reuses the ELF/FDE helpers of tools/bincode_varint.py.
Evidence re-derived from the pinned bytes: FDE extents, exact anchor bytes, the
four-entry tag jump table (tag - 0xfb) resolved to its arms, and a closure scan
of the `add r32,-0xfb; cmp r32,3` tag dispatch over all of .text.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bincode_varint as bv  # noqa: E402

# (name, fde_start, fde_end, anchors, jump table va, expected table targets)
DECODERS = (
    ('varint_decode_u64_slice', 0x466bd10, 0x466bdf5, (
        (0x466bd3d, '4883f808', 'cmp rax,8: fast path needs > 8 bytes remaining'),
        (0x466bd47, '0fb611', 'movzx edx,byte [rcx]: read tag byte'),
        (0x466bd4a, '4881fafb000000', 'cmp rdx,0xfb: tag < 251 is the value (1 byte)'),
        (0x466bd53, '41b801000000', 'mov r8d,1: consumed 1'),
        (0x466bd5b, '81c205ffffff', 'add edx,-0xfb: tag index'),
        (0x466bd61, '83fa03', 'cmp edx,3: indexes 0..3 (0xfb..0xfe) dispatch'),
        (0x466bd66, '4c8d053bb108fc', 'lea r8,[jump table]'),
        (0x466bd76, '0fb75101', 'movzx edx,word [rcx+1]: 0xfb arm reads u16'),
        (0x466bd7a, '41b803000000', 'mov r8d,3: consumed 3'),
        (0x466bd8e, '8b5101', 'mov edx,dword [rcx+1]: 0xfc arm reads u32'),
        (0x466bd91, '41b805000000', 'mov r8d,5: consumed 5'),
        (0x466bd82, '488b5101', 'mov rdx,qword [rcx+1]: 0xfd arm reads u64'),
        (0x466bd86, '41b809000000', 'mov r8d,9: consumed 9'),
        (0x466bda9, 'c60712', 'mov byte [rdi],0x12: Ok tag of the result'),
    ), 0x6f6ea8, (0x466bd76, 0x466bd8e, 0x466bd82, 0x466bdc5)),
    ('varint_decode_u64_inlined_a', 0x2558ee0, 0x2559404, (
        (0x2558f2a, '4883fa08', 'cmp rdx,8: fast path needs > 8 bytes remaining'),
        (0x2558f38, '410fb618', 'movzx ebx,byte [r8]: read tag byte'),
        (0x2558f3c, '4881fbfb000000', 'cmp rbx,0xfb: tag < 251 is the value (1 byte)'),
        (0x2558f4d, '81c305ffffff', 'add ebx,-0xfb: tag index'),
        (0x2558f53, '83fb03', 'cmp ebx,3: indexes 0..3 (0xfb..0xfe) dispatch'),
        (0x2558f5c, '4c8d0d21cae8fd', 'lea r9,[jump table]'),
        (0x2558f6d, '410fb75801', 'movzx ebx,word [r8+1]: 0xfb arm reads u16'),
        (0x2558f86, '418b5801', 'mov ebx,dword [r8+1]: 0xfc arm reads u32'),
        (0x2558f7a, '498b5801', 'mov rbx,qword [r8+1]: 0xfd arm reads u64'),
        (0x25591af, 'be02000000', 'mov esi,2: 0xfe arm builds an error (kind arg 2)'),
        (0x25591b4, 'ba04000000', 'mov edx,4: 0xfe arm error detail 4'),
        (0x25591ce, 'ba0c000000', 'mov edx,0xc: tag 0xff arm error detail 0xc'),
        (0x25593ea, '488d3d871e1603', 'lea rdi,[de/decoder.rs:93:13 Location]'),
        (0x25593f7, '488d3dd21d1603', 'lea rdi,[de/impls.rs:499:20 Location]'),
    ), 0x3e5984, (0x2558f6d, 0x2558f86, 0x2558f7a, 0x25591a1)),
)
# `add r32,-0xfb` (81 /0) then `cmp r32,3` (83 /7) on the same register. A byte 0x40-0x4f before
# 0x81 is taken as the add's REX prefix only when both it and the cmp carry REX.B, so the
# recorded VA is the instruction start (as objdump prints it), never a stray preceding byte.
DISPATCH = re.compile(rb'\x81([\xc0-\xc7])\x05\xff\xff\xff([\x40-\x4f])?\x83([\xf8-\xff])\x03', re.S)
CMP_FB = re.compile(rb'\x81[\xf8-\xff]\xfb\x00\x00\x00', re.S)
DISPATCH_SITES = 21
DISPATCH_FUNCTIONS = 16
LOCATION_LEAS = (0x25593ea, 0x25593f7)


def rel32_table(data, secs, table, count=4):
    """Absolute targets of `count` rel32s that lie entirely in one section."""
    need = 4 * count
    for section in secs.values():
        if not section['addr']:
            continue
        if section['addr'] <= table and table + need <= section['addr'] + section['size']:
            off = section['offset'] + table - section['addr']
            if off < 0 or off + need > len(data):
                raise bv.EvidenceError(f'jump table {table:#x} leaves the file')
            return tuple(table + struct.unpack_from('<i', data, off + 4 * i)[0] for i in range(count))
    raise bv.EvidenceError(f'jump table {table:#x}+{need} leaves its section')


def scan(data, expected_sha256=bv.SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise bv.EvidenceError(f'input SHA-256 {digest} is not node #94 {bv.SHA256}')
    secs = bv.sections(data)
    text = secs['.text']
    tb = data[text['offset']:text['offset'] + text['size']]
    fdes = bv.fde_extents(data, secs)
    relocs = bv.relative_relocs(data, secs)
    out = []
    for name, start, end, anchors, table, targets in DECODERS:
        if fdes.get(start) != end:
            raise bv.EvidenceError(f'{name}: FDE extent is not {start:#x}..{end:#x}')
        rows = []
        for va, hexbytes, meaning in anchors:
            want = bytes.fromhex(hexbytes)
            o = bv.va_to_off(secs, va)
            if not start <= va < end or data[o:o + len(want)] != want:
                raise bv.EvidenceError(f'{name}: bytes at {va:#x} are not {hexbytes}')
            rows.append({'va': f'{va:#x}', 'file_offset': f'{o:#x}', 'bytes': hexbytes, 'meaning': meaning})
        got = rel32_table(data, secs, table)
        if got != targets:
            raise bv.EvidenceError(f'{name}: jump table {table:#x} targets changed')
        out.append({'name': name, 'fde_start': f'{start:#x}', 'fde_end': f'{end:#x}', 'anchors': rows,
                    'jump_table': f'{table:#x}',
                    'jump_targets_by_tag': {f'{0xfb + i:#x}': f'{t:#x}' for i, t in enumerate(got)}})
    starts = sorted(fdes)
    sites = []
    for m in DISPATCH.finditer(tb):
        add_reg, cmp_reg = m.group(1)[0] & 7, m.group(3)[0] & 7
        cmp_b = (m.group(2)[0] & 1) if m.group(2) else 0
        if add_reg != cmp_reg:
            continue
        pos = m.start()
        if cmp_b and pos and 0x40 <= tb[pos - 1] <= 0x4f and tb[pos - 1] & 1:
            pos -= 1  # REX.B of the add (the cmp names r8d-r15d, so the add must too)
        elif cmp_b:
            raise bv.EvidenceError(f'dispatch at {text["addr"] + pos:#x}: cmp uses REX.B but add has no prefix')
        va = text['addr'] + pos
        i = bisect.bisect_right(starts, va) - 1
        if i < 0 or va >= fdes[starts[i]]:
            raise bv.EvidenceError(f'dispatch at {va:#x} outside every FDE')
        if not CMP_FB.search(tb, starts[i] - text['addr'], pos):
            raise bv.EvidenceError(f'dispatch at {va:#x} has no earlier cmp reg,0xfb in its function')
        sites.append({'va': f'{va:#x}', 'fde_start': f'{starts[i]:#x}'})
    nfn = len({s['fde_start'] for s in sites})
    if len(sites) != DISPATCH_SITES or nfn != DISPATCH_FUNCTIONS:
        raise bv.EvidenceError(f'dispatch closure {len(sites)} sites/{nfn} functions, expected '
                               f'{DISPATCH_SITES}/{DISPATCH_FUNCTIONS}')
    return {
        'schema': 're005-bincode-varint-decode/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'decoders': out,
        'panic_locations': [bv.panic_location(data, secs, relocs, va) for va in LOCATION_LEAS],
        'tag_dispatch_sites': sites,
        'tag_dispatch_function_count': nfn,
        'wire_rule_observed': {'lt_0xfb': 'tag byte is the value, 1 consumed', '0xfb': 'u16 LE at +1, 3 consumed',
                               '0xfc': 'u32 LE at +1, 5 consumed', '0xfd': 'u64 LE at +1, 9 consumed',
                               '0xfe': 'error arm (no u128 read)', '0xff': 'error arm'},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, default=bv.TARGET)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args(argv)
    try:
        text = bv.render(scan(a.input.read_bytes()))
    except (bv.EvidenceError, OSError, struct.error, ValueError) as e:
        print(f'bincode_varint_decode: {e}', file=sys.stderr)
        return 1
    if a.output:
        a.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
