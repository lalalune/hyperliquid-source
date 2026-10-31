#!/usr/bin/env python3
"""RE-005: pin the bincode-fork varint integer-encoding sites in node #94.

Static, offline, read-only. Never executes the captured binary. Every claim
is re-derived from the pinned artifact bytes: SHA-256, ELF section headers,
.eh_frame FDE extents, exact instruction bytes at each anchor, direct call
counts in .text, and the panic Location record reached through .rela.dyn.
Output is canonical JSON (sorted keys, fixed separators, trailing newline).
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
R_X86_64_RELATIVE = 8


class EvidenceError(Exception):
    """Raised when the input does not carry the pinned evidence exactly."""


# Each function: (name, fde_start, fde_end, anchors, expected direct calls).
# Anchors are (virtual address, exact instruction bytes, meaning).
FUNCTIONS = (
    ('varint_encode_u32_vec', 0x27ab0a0, 0x27ab27c, (
        (0x27ab0aa, '81f9fb000000', 'cmp ecx,0xfb: values < 251 take the single-byte arm'),
        (0x27ab0c3, '42880c0a', 'mov [rdx+r9],cl: single byte is the value itself'),
        (0x27ab0cf, '81f900000100', 'cmp ecx,0x10000: values < 65536 take the u16 arm'),
        (0x27ab0e8, '42c6040ffb', 'mov byte [rdi+r9],0xfb: u16 marker 251'),
        (0x27ab0f8, '66c1c108', 'rol cx,8: u16 payload byte-swapped when dl != 0'),
        (0x27ab102, '4883fa01', 'cmp rdx,1: grow unless 2 bytes of capacity remain'),
        (0x27ab128, '42c6040ffc', 'mov byte [rdi+r9],0xfc: u32 marker 252'),
        (0x27ab138, '0fc9', 'bswap ecx: u32 payload byte-swapped when dl != 0'),
        (0x27ab140, '4883fa03', 'cmp rdx,3: grow unless 4 bytes of capacity remain'),
        (0x27ab156, '48c70008000000', 'mov qword [rax],8: result discriminant 8 on success'),
    ), 3),
    ('varint_size_u32', 0x27ab280, 0x27ab2f5, (
        (0x27ab281, '81f9fb000000', 'cmp ecx,0xfb: values < 251 count 1 byte'),
        (0x27ab292, '48ffc0', 'inc rax: +1 byte'),
        (0x27ab297, '81f900000100', 'cmp ecx,0x10000: values < 65536 count 3 bytes'),
        (0x27ab2af, '488d4103', 'lea rax,[rcx+3]: +3 bytes (marker + u16)'),
        (0x27ab2cd, '488d4105', 'lea rax,[rcx+5]: +5 bytes (marker + u32)'),
        (0x27ab2dc, '48c70708000000', 'mov qword [rdi],8: result discriminant 8 on success'),
        (0x27ab2e8, '488d3d897bf102', 'lea rdi,[panic Location]: counter overflow panic'),
    ), 2),
    ('varint_encode_u64_vec', 0x27ab300, 0x27ab5a8, (
        (0x27ab30b, '4881f9fb000000', 'cmp rcx,0xfb: values < 251 take the single-byte arm'),
        (0x27ab325, '42880c0a', 'mov [rdx+r9],cl: single byte is the value itself'),
        (0x27ab331, '4881f900000100', 'cmp rcx,0x10000: values < 65536 take the u16 arm'),
        (0x27ab34b, '42c6040ffb', 'mov byte [rdi+r9],0xfb: u16 marker 251'),
        (0x27ab35b, '66c1c108', 'rol cx,8: u16 payload byte-swapped when dl != 0'),
        (0x27ab380, '48c1ef20', 'shr rdi,32: high half zero selects the u32 arm'),
        (0x27ab397, '42c6040ffc', 'mov byte [rdi+r9],0xfc: u32 marker 252'),
        (0x27ab3a7, '0fc9', 'bswap ecx: u32 payload byte-swapped when dl != 0'),
        (0x27ab3d4, '42c6040ffd', 'mov byte [rdi+r9],0xfd: u64 marker 253'),
        (0x27ab3e4, '480fc9', 'bswap rcx: u64 payload byte-swapped when dl != 0'),
        (0x27ab3ed, '4883fa07', 'cmp rdx,7: grow unless 8 bytes of capacity remain'),
        (0x27ab403, '48c70008000000', 'mov qword [rax],8: result discriminant 8 on success'),
    ), 25),
    ('varint_size_u64', 0x27ab5b0, 0x27ab64b, (
        (0x27ab5b1, '4881f9fb000000', 'cmp rcx,0xfb: values < 251 count 1 byte'),
        (0x27ab5c3, '48ffc0', 'inc rax: +1 byte'),
        (0x27ab5c8, '4881f900000100', 'cmp rcx,0x10000: values < 65536 count 3 bytes'),
        (0x27ab5e1, '488d4103', 'lea rax,[rcx+3]: +3 bytes (marker + u16)'),
        (0x27ab5ef, '48c1e920', 'shr rcx,32: high half zero selects the 5-byte count'),
        (0x27ab605, '488d4105', 'lea rax,[rcx+5]: +5 bytes (marker + u32)'),
        (0x27ab623, '488d4109', 'lea rax,[rcx+9]: +9 bytes (marker + u64)'),
        (0x27ab632, '48c70708000000', 'mov qword [rdi],8: result discriminant 8 on success'),
        (0x27ab63e, '488d3d3378f102', 'lea rdi,[panic Location]: counter overflow panic'),
    ), 25),
    ('varint_encode_u32_le_ptr', 0x4aa9ae0, 0x4aa9c86, (
        (0x4aa9ae8, '8b1e', 'mov ebx,[rsi]: value passed by reference'),
        (0x4aa9aea, '81fbfb000000', 'cmp ebx,0xfb: values < 251 take the single-byte arm'),
        (0x4aa9b04, '881c31', 'mov [rcx+rsi],bl: single byte is the value itself'),
        (0x4aa9b0c, '81fb00000100', 'cmp ebx,0x10000: values < 65536 take the u16 arm'),
        (0x4aa9b29, 'c60437fb', 'mov byte [rdi+rsi],0xfb: u16 marker 251'),
        (0x4aa9b41, '66891c37', 'mov [rdi+rsi],bx: u16 stored little-endian, no swap arm'),
        (0x4aa9b60, 'c60437fc', 'mov byte [rdi+rsi],0xfc: u32 marker 252'),
        (0x4aa9b78, '891c37', 'mov [rdi+rsi],ebx: u32 stored little-endian, no swap arm'),
        (0x4aa9b83, '48c70008000000', 'mov qword [rax],8: result discriminant 8 on success'),
    ), 75),
    ('varint_encode_u64_vec_b', 0x4aa9f80, 0x4aaa228, (
        (0x4aa9f8b, '4881f9fb000000', 'cmp rcx,0xfb: values < 251 take the single-byte arm'),
        (0x4aa9fb1, '4881f900000100', 'cmp rcx,0x10000: values < 65536 take the u16 arm'),
        (0x4aa9fcb, '42c6040ffb', 'mov byte [rdi+r9],0xfb: u16 marker 251'),
        (0x4aa9fdb, '66c1c108', 'rol cx,8: u16 payload byte-swapped when dl != 0'),
        (0x4aaa000, '48c1ef20', 'shr rdi,32: high half zero selects the u32 arm'),
        (0x4aaa017, '42c6040ffc', 'mov byte [rdi+r9],0xfc: u32 marker 252'),
        (0x4aaa027, '0fc9', 'bswap ecx: u32 payload byte-swapped when dl != 0'),
        (0x4aaa054, '42c6040ffd', 'mov byte [rdi+r9],0xfd: u64 marker 253'),
        (0x4aaa064, '480fc9', 'bswap rcx: u64 payload byte-swapped when dl != 0'),
        (0x4aaa083, '48c70008000000', 'mov qword [rax],8: result discriminant 8 on success'),
    ), 86),
    ('varint_size_u64_b', 0x4aaa230, 0x4aaa2cb, (
        (0x4aaa231, '4881f9fb000000', 'cmp rcx,0xfb: values < 251 count 1 byte'),
        (0x4aaa248, '4881f900000100', 'cmp rcx,0x10000: values < 65536 count 3 bytes'),
        (0x4aaa261, '488d4103', 'lea rax,[rcx+3]: +3 bytes (marker + u16)'),
        (0x4aaa26f, '48c1e920', 'shr rcx,32: high half zero selects the 5-byte count'),
        (0x4aaa285, '488d4105', 'lea rax,[rcx+5]: +5 bytes (marker + u32)'),
        (0x4aaa2a3, '488d4109', 'lea rax,[rcx+9]: +9 bytes (marker + u64)'),
        (0x4aaa2b2, '48c70708000000', 'mov qword [rdi],8: result discriminant 8 on success'),
        (0x4aaa2be, '488d3d23dac800', 'lea rdi,[panic Location]: counter overflow panic'),
    ), 87),
)
PANIC_LEAS = (0x27ab2e8, 0x27ab63e, 0x4aaa2be)
# Byte idioms counted across all of .text to bound uniqueness.
IDIOMS = {
    'cmp_r32_0xfb_then_cmp_0x10000': re.compile(
        rb'\x81[\xf8-\xff]\xfb\x00\x00\x00\x73.[\x00-\xff]{0,48}?\x81[\xf8-\xff]\x00\x00\x01\x00', re.S),
    'cmp_r64_0xfb_then_cmp_0x10000': re.compile(
        rb'[\x48\x49]\x81[\xf8-\xff]\xfb\x00\x00\x00\x73.[\x00-\xff]{0,48}?[\x48\x49]\x81[\xf8-\xff]\x00\x00\x01\x00', re.S),
    'store_marker_0xfd_imm8': re.compile(rb'\x42\xc6\x04\x0f\xfd'),
}


def sections(data):
    if data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not a little-endian ELF64 file')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 58)
    if shentsize != 64 or shoff + shnum * 64 > len(data):
        raise EvidenceError('section header table is truncated or malformed')
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * 64) for i in range(shnum)]
    stro = raw[shstrndx][4]
    out = {}
    for h in raw:
        end = data.index(b'\0', stro + h[0])
        out[data[stro + h[0]:end].decode()] = {'addr': h[3], 'offset': h[4], 'size': h[5]}
    for name in ('.text', '.eh_frame', '.eh_frame_hdr', '.rela.dyn', '.data.rel.ro', '.rodata'):
        if name not in out:
            raise EvidenceError(f'missing section {name}')
        s = out[name]
        if s['offset'] + s['size'] > len(data):
            raise EvidenceError(f'section {name} extends past end of file')
    return out


def va_to_off(secs, va):
    for s in secs.values():
        if s['addr'] and s['addr'] <= va < s['addr'] + s['size']:
            return s['offset'] + va - s['addr']
    raise EvidenceError(f'address {va:#x} is outside every section')


def fde_extents(data, secs):
    """Return {pc_begin: pc_end} from .eh_frame_hdr's table and each FDE body."""
    hdr = secs['.eh_frame_hdr']
    h = hdr['offset']
    version, eh_ptr_enc, count_enc, table_enc = data[h:h + 4]
    if (version, eh_ptr_enc, count_enc, table_enc) != (1, 0x1b, 0x03, 0x3b):
        raise EvidenceError('unexpected .eh_frame_hdr encodings')
    count = struct.unpack_from('<I', data, h + 8)[0]
    ef = secs['.eh_frame']
    out = {}
    for i in range(count):
        start_rel, fde_rel = struct.unpack_from('<ii', data, h + 12 + i * 8)
        start = hdr['addr'] + start_rel
        fde_va = hdr['addr'] + fde_rel
        fo = ef['offset'] + fde_va - ef['addr']
        length, cie_ptr = struct.unpack_from('<II', data, fo)
        if length in (0, 0xffffffff) or cie_ptr == 0:
            raise EvidenceError(f'FDE at {fde_va:#x} is malformed')
        begin_rel, pc_range = struct.unpack_from('<iI', data, fo + 8)
        begin = fde_va + 8 + begin_rel
        if begin != start:
            raise EvidenceError(f'FDE at {fde_va:#x} disagrees with its index entry')
        out[begin] = begin + pc_range
    return out


def direct_calls(text, base, target):
    """Byte-pattern hits of E8 rel32 landing on target (not a CFG proof)."""
    sites = []
    for m in re.finditer(rb'\xe8', text):
        p = m.start()
        if p + 5 <= len(text) and base + p + 5 + struct.unpack_from('<i', text, p + 1)[0] == target:
            sites.append(base + p)
    return sites


def relative_relocs(data, secs):
    r = secs['.rela.dyn']
    out = {}
    for o in range(r['offset'], r['offset'] + r['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, o)
        if info & 0xffffffff == R_X86_64_RELATIVE:
            out[where] = addend
    return out


def bytes_in_section(data, secs, va, size):
    """Return `size` bytes at `va` from the section `va_to_off` would select.

    A declared length must not continue into the next section or past EOF.
    `va_to_off` only checks that the first byte is mapped, and a Python slice
    silently shortens a read that runs off the end of the file.
    """
    if size <= 0:
        raise EvidenceError(f'range {va:#x} has non-positive length {size}')
    for name, s in secs.items():
        if s['addr'] and s['addr'] <= va < s['addr'] + s['size']:
            if va + size > s['addr'] + s['size']:
                raise EvidenceError(f'range {va:#x}+{size} leaves section {name}')
            off = s['offset'] + va - s['addr']
            blob = data[off:off + size]
            if len(blob) != size:
                raise EvidenceError(f'range {va:#x}+{size} leaves the file')
            return blob
    raise EvidenceError(f'address {va:#x} is outside every section')


def panic_location(data, secs, relocs, lea_va):
    insn = bytes_in_section(data, secs, lea_va, 7)
    if insn[:3] != b'\x48\x8d\x3d':
        raise EvidenceError(f'no lea rdi,[rip+disp] at {lea_va:#x}')
    loc = lea_va + 7 + struct.unpack_from('<i', insn, 3)[0]
    if loc not in relocs:
        raise EvidenceError(f'Location {loc:#x} has no RELATIVE relocation')
    path_va = relocs[loc]
    length, line, col = struct.unpack_from('<QII', bytes_in_section(data, secs, loc + 8, 16))
    if length <= 0:
        raise EvidenceError(f'panic path at {path_va:#x} has empty length')
    try:
        path = bytes_in_section(data, secs, path_va, length).decode()
    except UnicodeDecodeError:
        raise EvidenceError(f'panic path at {path_va:#x} is not UTF-8') from None
    return {'location': f'{loc:#x}', 'path_va': f'{path_va:#x}',
            'path': path, 'line': line, 'column': col}


def scan(data, expected_sha256=SHA256):
    """expected_sha256 exists only so tests can feed mutated copies past the digest gate."""
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_sha256:
        raise EvidenceError(f'input SHA-256 {digest} is not node #94 {SHA256}')
    secs = sections(data)
    text = secs['.text']
    tbytes = data[text['offset']:text['offset'] + text['size']]
    fdes = fde_extents(data, secs)
    relocs = relative_relocs(data, secs)
    functions = []
    for name, start, end, anchors, calls in FUNCTIONS:
        if fdes.get(start) != end:
            raise EvidenceError(f'{name}: FDE extent is not {start:#x}..{end:#x}')
        rows = []
        for va, hexbytes, meaning in anchors:
            if not start <= va < end:
                raise EvidenceError(f'{name}: anchor {va:#x} outside its FDE')
            want = bytes.fromhex(hexbytes)
            o = va_to_off(secs, va)
            if data[o:o + len(want)] != want:
                raise EvidenceError(f'{name}: bytes at {va:#x} are not {hexbytes}')
            rows.append({'va': f'{va:#x}', 'file_offset': f'{o:#x}', 'bytes': hexbytes, 'meaning': meaning})
        sites = direct_calls(tbytes, text['addr'], start)
        got = len(sites)
        if got != calls:
            raise EvidenceError(f'{name}: {got} direct calls, expected {calls}')
        functions.append({'name': name, 'fde_start': f'{start:#x}', 'fde_end': f'{end:#x}',
                          'size': end - start, 'direct_calls': got,
                          'call_sites': [f'{x:#x}' for x in sorted(sites)], 'anchors': rows})
    starts = sorted(fdes)
    pinned = {start for _, start, _, _, _ in FUNCTIONS}
    idioms = {}
    for k, p in sorted(IDIOMS.items()):
        hits = []
        for m in p.finditer(tbytes):
            pos = m.start()
            if k.startswith('cmp_r32'):
                # A REX.W byte before 0x81 makes this the r64 form, which has its own row.
                if pos and 0x48 <= tbytes[pos - 1] <= 0x4f:
                    continue
                if pos and 0x40 <= tbytes[pos - 1] <= 0x47:
                    pos -= 1  # REX without W belongs to the instruction: record its start
            va = text['addr'] + pos
            i = bisect.bisect_right(starts, va) - 1
            owner = starts[i] if i >= 0 and va < fdes[starts[i]] else None
            if owner not in pinned:
                raise EvidenceError(f'idiom {k} at {va:#x} lies outside every pinned function')
            hits.append(f'{va:#x}')
        idioms[k] = hits
    return {
        'schema': 're005-bincode-varint/1',
        'target': {'release': 94, 'sha256': digest, 'size': len(data)},
        'coordinates': 'virtual addresses; file_offset = va - 0x1000 inside .text',
        'sections': {k: {f: f'{v:#x}' for f, v in secs[k].items()}
                     for k in ('.text', '.eh_frame_hdr', '.rodata', '.data.rel.ro')},
        'fde_count': len(fdes),
        'functions': functions,
        'panic_locations': [panic_location(data, secs, relocs, va) for va in PANIC_LEAS],
        'text_idiom_sites': idioms,
        'wire_rule_observed': {
            'lt_251': '1 byte, the value',
            'lt_65536': '0xfb then u16',
            'u32_high_half_zero': '0xfc then u32',
            'otherwise_u64': '0xfd then u64',
            'byte_order': 'little-endian store; the *_vec encoders byte-swap when the dl flag argument is non-zero; varint_encode_u32_le_ptr has no swap arm',
        },
    }


def render(result):
    return json.dumps(result, indent=2, sort_keys=True, separators=(',', ': ')) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--input', type=Path, default=TARGET)
    ap.add_argument('--output', type=Path)
    a = ap.parse_args(argv)
    try:
        text = render(scan(a.input.read_bytes()))
    except (EvidenceError, OSError, struct.error, ValueError) as e:
        print(f'bincode_varint: {e}', file=sys.stderr)
        return 1
    if a.output:
        a.output.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
