#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 fixed-88 dealloc-size evidence packet.

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
START, END = 0x1417c40, 0x1417c77
PAD_END = 0x1417c80
BODY = bytes.fromhex(
    '488b77084885f6742d486bc6584883c0674883e0f04801c64883c6117418488b3f4829c7'
    '31d24883fe100f92c2c1e202ff259a633504c3')
PAD = b'\xcc' * 9
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000e88800003cde72003700000000000000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
CALLER_FDE = bytes.fromhex(
    '380000004c130100a40547005001000004f76c95ff420e10420e18410e20440e8001830'
    '48e038f0202f90e20410e18420e10420e08410e8001000000')
CALLER_START, CALLER_END = 0x143f520, 0x143f670
CALL_SITE = 0x143f645
TAIL_SLOT, TAIL_TARGET = 0x576e010, 0x54c8cb0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def aligned(count):
    return (count * 0x58 + 0x67) & ~0xF


def size_of(count):
    return (count + aligned(count) + 0x11) % (1 << 64)


def flag_of(count):
    return 4 if size_of(count) < 0x10 else 0


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
    require(read(eh['address'] + 0x2dc714, len(CALLER_CIE)) == CALLER_CIE, 'Caller CIE changed')
    for offset, raw, start, end in [(0x88e4, FDE, START, END),
                                    (0x2eda5c, CALLER_FDE, CALLER_START, CALLER_END)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')
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
    # Tail jump: jmp *slot at 0x1417c70, RIP-relative to 0x576e010.
    tail = read(0x1417c70, 6)
    require(tail == bytes.fromhex('ff259a633504'), 'Tail-jump bytes changed')
    require(0x1417c76 + struct.unpack_from('<i', tail, 2)[0] == TAIL_SLOT, 'Tail-jump slot changed')
    # Incoming call: exactly one direct e8 to the window, no indirect slot calls.
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
    require(direct == [CALL_SITE] and indirect == [], 'Call-pattern candidate set changed')
    require(read(CALL_SITE, 5) == bytes.fromhex('e8f685fdff'), 'Caller call bytes changed')
    # Arithmetic constants decoded from the retained instruction bytes.
    require(body[12] == 0x58, 'Element size constant changed')
    require(body[16] == 0x67, 'Header constant changed')
    require(body[27] == 0x11, 'Trailer constant changed')
    require(body[41] == 0x10, 'Flag threshold changed')
    require(body[47] == 2, 'Flag shift changed')
    # Edges computed from the decoded formula, not assumed.
    edges = {count: dict(aligned=aligned(count), size=size_of(count), flag=flag_of(count))
             for count in (1, 15, 16, 255, 4096)}
    require(edges[1] == dict(aligned=0xb0, size=0xc2, flag=0), 'Edge count=1 changed')
    require(edges[15] == dict(aligned=0x580, size=0x5a0, flag=0), 'Edge count=15 changed')
    require(edges[16] == dict(aligned=0x5e0, size=0x601, flag=0), 'Edge count=16 changed')
    require(edges[255] == dict(aligned=0x5800, size=0x5910, flag=0), 'Edge count=255 changed')
    require(edges[4096] == dict(aligned=0x58060, size=0x59071, flag=0), 'Edge count=4096 changed')
    # Non-wrapping fall-through inputs always clear the flag: count >= 1 gives
    # aligned >= 0xb0, so size >= 0xc2 > 0x10; flag 4 needs a wrap into 1..15.
    require(all(size_of(n) >= 0xc2 and flag_of(n) == 0 for n in range(1, 10001)),
            'Flag-always-zero bound failed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x88e4',
                              padding_bytes=9, padding_stride_end=hex(PAD_END),
                              inferred_label='fixed-88 dealloc-size helper'),
                arithmetic=dict(input_load='u64 count at rdi+8, base pointer at rdi',
                                element_size='0x58', header='0x67', trailer='0x11',
                                aligned_formula='(count*0x58 + 0x67) with low 4 bits cleared (floor to 16)',
                                size_formula='count + floored(count*0x58 + 0x67) + 0x11 (mod 2^64)',
                                pointer_formula='field - floored(count*0x58 + 0x67)',
                                flag_formula='(size < 0x10) ? 4 : 0',
                                flag_always_zero_nonwrapping=True,
                                early_return_on=['count == 0', 'size == 0 (64-bit wrap only)'],
                                edges={str(k): {kk: hex(vv) for kk, vv in v.items()} for k, v in edges.items()},
                                checked_nonwrapping_counts=10000),
                tail_call=dict(slot=hex(TAIL_SLOT), target=hex(TAIL_TARGET),
                               registers='rdi = field - aligned, rsi = size, rdx = flag, rcx = entry value',
                               target_claimed_here=False),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, direct)),
                                           ff15_ff25_candidates=indirect,
                                           validated_caller_fde=['0x143f520', '0x143f670'],
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
        print('Foundation dealloc-size evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
