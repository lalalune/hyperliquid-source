#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 generic dealloc-size evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The tail-call target is out of scope: this packet claims only the caller window.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x140e430, 0x140e486
PAD_END = 0x140e490
BODY = bytes.fromhex(
    '488b77204885f6744c488b4710488d4e01480faf4f08488d140848ffca4889c148f7d9'
    '4821d14801ce4883c6117426488b7f184829cfb940000000f3480fbcc831d24839f00f'
    '47d14883f8110f43d1ff258bfb3504c3')
PAD = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('1000000064820000b04c72005600000000000000')
TAIL_SLOT, TAIL_TARGET = 0x576e010, 0x54c8cb0
# Direct e8 call sites, each confirmed as a `call 140e430` instruction start
# by linear disassembly, with its exact 5-byte sequence.
CALL_SITES = {
    0x141cee2: bytes.fromhex('e84915ffff'),
    0x141d9f6: bytes.fromhex('e8350affff'),
    0x141e0e2: bytes.fromhex('e84903ffff'),
    0x141e81c: bytes.fromhex('e80ffcfeff'),
    0x141ef12: bytes.fromhex('e819f5feff'),
    0x141f663: bytes.fromhex('e8c8edfeff'),
    0x141fdb7: bytes.fromhex('e874e6feff'),
    0x1420513: bytes.fromhex('e818dffeff'),
}
MASK = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def tzcnt(value):
    return 64 if value == 0 else (value & -value).bit_length() - 1


def padded(count, elem_size):
    return ((count + 1) * elem_size) & MASK


def pad_of(align, padded_value):
    return ((-align) & (align + padded_value - 1)) & MASK


def compute(count, align, elem_size):
    """Decoded formula; returns None for either early-return path."""
    if count == 0:
        return None
    pad = pad_of(align, padded(count, elem_size))
    size = (count + pad + 0x11) & MASK
    if size == 0:
        return None
    flag = tzcnt(align) if (align > size or align >= 0x11) else 0
    return dict(padded=hex(padded(count, elem_size)), pad=hex(pad),
                size=hex(size), flag=flag)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Dealloc-size instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    record = read(eh['address'] + 0x8260, len(FDE))
    require(record == FDE, 'FDE record changed')
    pc = eh['address'] + 0x8260 + 8 + struct.unpack_from('<i', record, 8)[0]
    extent = struct.unpack_from('<I', record, 12)[0]
    require((pc, pc + extent) == (START, END), 'FDE PC/range changed')
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    require(rels.get(TAIL_SLOT) == (8, TAIL_TARGET), 'Tail-call slot relocation changed')
    window_slots = [a for a, (info, addend) in rels.items() if info == 8 and addend == START]
    require(window_slots == [], 'Unexpected slot maps to window')
    # Tail jump: jmp *slot at 0x140e47f, RIP-relative to 0x576e010.
    tail = read(0x140e47f, 6)
    require(tail == bytes.fromhex('ff258bfb3504'), 'Tail-jump bytes changed')
    require(0x140e485 + struct.unpack_from('<i', tail, 2)[0] == TAIL_SLOT, 'Tail-jump slot changed')
    # Incoming calls: exactly the eight direct e8 sites, no indirect slot calls.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    indirect, direct = [], []
    for opcode in (b'\xff\x15', b'\xff\x25', b'\xe8'):
        pos = 0
        while (pos := code.find(opcode, pos)) >= 0:
            length = len(opcode) + 4
            if pos + length <= len(code):
                destination = text['address'] + pos + length + struct.unpack_from('<i', code, pos + len(opcode))[0]
                if destination == START and opcode == b'\xe8':
                    direct.append(text['address'] + pos)
                elif opcode != b'\xe8' and destination in window_slots:
                    indirect.append(text['address'] + pos)
            pos += 1
    require(sorted(direct) == sorted(CALL_SITES) and indirect == [], 'Call-pattern candidate set changed')
    for site, raw_call in CALL_SITES.items():
        require(read(site, 5) == raw_call, 'Caller call bytes changed')
    # Field offsets and constants decoded from the retained instruction bytes.
    require(body[3] == 0x20, 'Count field offset changed')
    require(body[12] == 0x10, 'Align field offset changed')
    require(body[21] == 0x08, 'Element-size field offset changed')
    require(body[50] == 0x18, 'Base field offset changed')
    require(body[44] == 0x11, 'Trailer constant changed')
    require(body[75] == 0x11, 'Flag threshold constant changed')
    require(struct.unpack_from('<I', body, 55)[0] == 0x40, 'tzcnt fallback constant changed')
    # Edges computed from the decoded formula, not assumed.
    edges = {
        'count=1,align=16,elem=8': compute(1, 16, 8),
        'count=1,align=32,elem=8': compute(1, 32, 8),
        'count=3,align=8,elem=24': compute(3, 8, 24),
        'count=2,align=24,elem=16': compute(2, 24, 16),
        'count=5,align=17,elem=4': compute(5, 17, 4),
        'count=1,align=64,elem=1': compute(1, 64, 1),
    }
    require(edges['count=1,align=16,elem=8'] == dict(padded='0x10', pad='0x10', size='0x22', flag=0),
            'Edge count=1,align=16,elem=8 changed')
    require(edges['count=1,align=32,elem=8'] == dict(padded='0x10', pad='0x20', size='0x32', flag=5),
            'Edge count=1,align=32,elem=8 changed')
    require(edges['count=3,align=8,elem=24'] == dict(padded='0x60', pad='0x60', size='0x74', flag=0),
            'Edge count=3,align=8,elem=24 changed')
    require(edges['count=2,align=24,elem=16'] == dict(padded='0x30', pad='0x40', size='0x53', flag=3),
            'Edge count=2,align=24,elem=16 changed')
    require(edges['count=5,align=17,elem=4'] == dict(padded='0x18', pad='0x28', size='0x3e', flag=0),
            'Edge count=5,align=17,elem=4 changed')
    require(edges['count=1,align=64,elem=1'] == dict(padded='0x2', pad='0x40', size='0x52', flag=6),
            'Edge count=1,align=64,elem=1 changed')
    require(compute(0, 16, 8) is None, 'Zero-count early return changed')
    # Non-wrapping grid: size is at least 0x12, so the align>size gate never
    # fires below the 0x11 threshold; the flag is tzcnt(align) iff align >= 0x11.
    grid = 0
    for count in range(1, 51):
        for align in (1, 2, 3, 4, 7, 8, 15, 16, 17, 24, 31, 32, 33, 64, 128, 256):
            for elem_size in (1, 2, 8, 16, 24, 88):
                out = compute(count, align, elem_size)
                require(out is not None and int(out['size'], 16) >= 0x12, 'Grid size bound failed')
                require(out['flag'] == (tzcnt(align) if align >= 0x11 else 0), 'Grid flag rule failed')
                grid += 1
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x8260',
                              padding_bytes=10, padding_stride_end=hex(PAD_END),
                              inferred_label='generic dealloc-size helper'),
                arithmetic=dict(input_loads='u64 count at rdi+0x20, align at rdi+0x10, elem_size at rdi+0x08, base at rdi+0x18',
                                padded_formula='(count + 1) * elem_size (mod 2^64)',
                                pad_formula='(-align) & (align + padded - 1) (mod 2^64)',
                                size_formula='count + pad + 0x11 (mod 2^64)',
                                pointer_formula='base - pad (mod 2^64)',
                                flag_formula='tzcnt(align) if (align > size or align >= 0x11) else 0; tzcnt(0) = 64',
                                early_return_on=['count == 0', 'size == 0 (64-bit wrap only)'],
                                edges=edges,
                                nonwrapping_grid_cases=grid,
                                nonwrapping_flag_rule='tzcnt(align) if align >= 0x11 else 0'),
                tail_call=dict(slot=hex(TAIL_SLOT), target=hex(TAIL_TARGET),
                               registers='rdi = base - pad, rsi = size, rdx = flag, rcx = tzcnt(align), rax = align',
                               target_claimed_here=False),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, sorted(CALL_SITES))),
                                           ff15_ff25_candidates=indirect,
                                           complete_xref_census=False),
                captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256, 'Expected exact node #94 size/SHA-256')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation generic dealloc-size evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
