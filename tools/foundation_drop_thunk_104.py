#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 drop-thunk evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The per-element call target, the resume target, and the tail-call target are
out of scope: this packet claims only the caller window, its observable
behavior, and its register handoff.
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
START, END = 0x14522b0, 0x1452306
PAD_END = 0x1452310
BODY = bytes.fromhex(
    '415653504889fbe8a4d2f9ff488b034885c07417488b7b08486bf06831d24883c4085b415e'
    'ff2535bd31044883c4085b415ec34989c6488b034885c07410488b7b08486bf06831d2ff15'
    '12bd31044c89f7e80ade2004')
PAD = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
FDE = bytes.fromhex(
    '3800000008260100782048005600000004136895ff420e10410e18410e2083038e025e0e184'
    '10e10420e08460e20440e18410e10420e08410e200000')
CALLER_A_FDE = bytes.fromhex(
    '64000000cc2c0100e42f48009101000004536495ff410e10420e18420e20420e28420e30410'
    'e38410e4083078c068d058e048f0386026a0e38410e30420e28420e20420e18420e10410e084'
    '10e4002bb0e38410e30420e28420e20420e18420e10410e08460e4000')
CALLER_B_FDE = bytes.fromhex(
    '3800000004300100ec394800b700000004bb6295ff420e10410e18410e2083038e02025d0e184'
    '10e10420e08460e20440e18410e10420e08410e2000')
CALLER_A_START, CALLER_A_END = 0x14538e0, 0x1453a71
CALLER_B_START, CALLER_B_END = 0x1454620, 0x14546d7
CALL_SITES = (0x1453a00, 0x14546a7)
ELEMENT_CALL = 0x13ef560
RESUME_CALL = 0x5660110
ELEMENT_SIZE = 0x68
TAIL_SLOT, TAIL_TARGET = 0x576e010, 0x54c8cb0


def require(condition, message):
    if not condition:
        raise ValueError(message)


def size_of(length):
    return (length * ELEMENT_SIZE) % (1 << 64)


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
    require(body == BODY, 'Drop-thunk instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'] + 0x2dc714, len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x2eed18, FDE, START, END),
                                    (0x2ef3dc, CALLER_A_FDE, CALLER_A_START, CALLER_A_END),
                                    (0x2ef714, CALLER_B_FDE, CALLER_B_START, CALLER_B_END)]:
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
    # Per-element call: call 0x13ef560 at 0x14522b7, before the null guard.
    elem = read(0x14522b7, 5)
    require(elem == bytes.fromhex('e8a4d2f9ff'), 'Per-element call bytes changed')
    require(0x14522bc + struct.unpack_from('<i', elem, 1)[0] == ELEMENT_CALL,
            'Per-element call target changed')
    # Tail jump: jmp *slot at 0x14522d5, RIP-relative to 0x576e010.
    tail = read(0x14522d5, 6)
    require(tail == bytes.fromhex('ff2535bd3104'), 'Tail-jump bytes changed')
    require(0x14522db + struct.unpack_from('<i', tail, 2)[0] == TAIL_SLOT, 'Tail-jump slot changed')
    # Landing pad inside the FDE: same tail-slot call, then _Unwind_Resume call.
    land_call = read(0x14522f8, 6)
    require(land_call == bytes.fromhex('ff1512bd3104'), 'Landing-pad tail-slot call bytes changed')
    require(0x14522fe + struct.unpack_from('<i', land_call, 2)[0] == TAIL_SLOT,
            'Landing-pad tail-slot changed')
    resume = read(0x1452301, 5)
    require(resume == bytes.fromhex('e80ade2004'), 'Resume call bytes changed')
    require(0x1452306 + struct.unpack_from('<i', resume, 1)[0] == RESUME_CALL,
            'Resume call target changed')
    # Incoming calls: exactly two direct e8 calls to the window, no indirect slot calls.
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
    require(direct == list(CALL_SITES) and indirect == [], 'Call-pattern candidate set changed')
    require(read(0x1453a00, 5) == bytes.fromhex('e8abe8ffff'), 'Caller A call bytes changed')
    require(read(0x14546a7, 5) == bytes.fromhex('e804dcffff'), 'Caller B call bytes changed')
    # Caller argument setup: mov %rax,%r14; mov %rbx,%rdi immediately before each call.
    for site in CALL_SITES:
        require(read(site - 6, 6) == bytes.fromhex('4989c64889df'), 'Caller argument setup changed')
    # Decoded constants from the retained instruction bytes.
    require(body[19] == 0x17, 'Main null-guard jump displacement changed')
    require(body[61] == 0x10, 'Landing-pad null-guard jump displacement changed')
    require(body[27] == ELEMENT_SIZE, 'Element size constant changed')
    require(body[69] == ELEMENT_SIZE, 'Landing-pad element size constant changed')
    require(body[28:30] == bytes.fromhex('31d2'), 'Flag-clear opcode changed')
    require(body[70:72] == bytes.fromhex('31d2'), 'Landing-pad flag-clear opcode changed')
    # Edges computed from the decoded formula, not assumed.
    edges = {length: size_of(length) for length in (1, 2, 16, 255, 4096)}
    require(edges[1] == 0x68, 'Edge length=1 changed')
    require(edges[2] == 0xd0, 'Edge length=2 changed')
    require(edges[16] == 0x680, 'Edge length=16 changed')
    require(edges[255] == 0x6798, 'Edge length=255 changed')
    require(edges[4096] == 0x68000, 'Edge length=4096 changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x2eed18',
                              padding_bytes=10, padding_stride_end=hex(PAD_END),
                              inferred_label='drop thunk, 104-byte elements'),
                behavior=dict(call_order='per-element call 0x13ef560 first, then null guard',
                              length_load='u64 length at rdi+0, base pointer at rdi+8 on fall-through',
                              element_size='0x68', size_formula='length * 0x68 (mod 2^64)',
                              early_return_on=['length == 0'],
                              flag_at_tail_jump='rdx = 0 (xor edx,edx, never set otherwise)',
                              edges={str(k): hex(v) for k, v in edges.items()},
                              per_element_call_target=hex(ELEMENT_CALL),
                              per_element_call_claimed_here=False,
                              landing_pad='inside FDE 0x14522e3..0x1452306: reload length, null guard, '
                                          'same multiply, tail-slot call, then _Unwind_Resume call 0x5660110'),
                tail_call=dict(slot=hex(TAIL_SLOT), target=hex(TAIL_TARGET),
                               registers='rdi = field+8, rsi = length * 0x68, rdx = 0',
                               target_claimed_here=False),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, direct)),
                                           ff15_ff25_candidates=indirect,
                                           validated_caller_fdes=['0x14538e0', '0x1453a71', '0x1454620', '0x14546d7'],
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
        print('Foundation drop-thunk-104 evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
