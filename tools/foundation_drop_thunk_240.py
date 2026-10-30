#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 drop-thunk evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The per-element call target, the landing-pad resume target, and the tail-call
target are out of scope: this packet claims only the caller window, its
observable behavior, and its register handoffs.
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
START, END = 0x152f710, 0x152f76c
PAD_END = 0x152f770
BODY = bytes.fromhex(
    '415653504889fbe8844c0100488b034885c0741a488b7b084869f0f000000031d24883c4085b415eff25d2e823044883c4085b415ec34989c6488b034885c07413488b7b084869f0f000000031d2ff15ace823044c89f7e8a4091304')
PAD = b'\xcc' * 4
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
FDE = bytes.fromhex('38000000185a0200c8c054005c00000004b72595ff420e10410e18410e2083038e02610e18410e10420e08460e20440e18410e10420e08410e200000')
CALLER_FDE = bytes.fromhex(
    '50000000a8550200d87854009015000004fb2695ff410e10420e18420e20420e28420e30410e38470ea01183078c068d058e048f0386020302130e38410e30420e28420e20420e18420e10410e08410ea0110000')
CALLER_START, CALLER_END = 0x152aab0, 0x152c040
CALL_SITE = 0x152bffc
ELEMENT_CALL = 0x15443a0
RESUME_CALL = 0x5660110
ELEMENT_SIZE = 0xf0
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
    for offset, raw, start, end in [(0x302128, FDE, START, END),
                                    (0x301cb8, CALLER_FDE, CALLER_START, CALLER_END)]:
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
    # Per-element call: call 0x15443a0 at 0x152f717, before the null guard.
    elem = read(0x152f717, 5)
    require(elem == bytes.fromhex('e8844c0100'), 'Per-element call bytes changed')
    require(0x152f71c + struct.unpack_from('<i', elem, 1)[0] == ELEMENT_CALL,
            'Per-element call target changed')
    # Tail jump: jmp *slot at 0x152f738, RIP-relative to 0x576e010.
    tail = read(0x152f738, 6)
    require(tail == bytes.fromhex('ff25d2e82304'), 'Tail-jump bytes changed')
    require(0x152f73e + struct.unpack_from('<i', tail, 2)[0] == TAIL_SLOT, 'Tail-jump slot changed')
    # Landing pad at 0x152f746: reload, null guard, same multiply, same tail slot,
    # then restore the saved exception pointer and call the resume PLT entry.
    require(body[64] == 0x13, 'Landing-pad null-guard jump displacement changed')
    require(body[72] == ELEMENT_SIZE, 'Landing-pad element size constant changed')
    land_call = read(0x152f75e, 6)
    require(land_call == bytes.fromhex('ff15ace82304'), 'Landing-pad tail-slot call bytes changed')
    require(0x152f764 + struct.unpack_from('<i', land_call, 2)[0] == TAIL_SLOT,
            'Landing-pad tail-call slot changed')
    resume = read(0x152f767, 5)
    require(resume == bytes.fromhex('e8a4091304'), 'Resume call bytes changed')
    require(0x152f76c + struct.unpack_from('<i', resume, 1)[0] == RESUME_CALL,
            'Resume call target changed')
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
    require(read(CALL_SITE, 5) == bytes.fromhex('e80f370000'), 'Caller call bytes changed')
    # Caller argument setup: lea 0x2f8(%rsp),%rdi immediately before the call.
    require(read(0x152bff4, 8) == bytes.fromhex('488dbc24f8020000'), 'Caller argument setup changed')
    # Decoded constants from the retained instruction bytes.
    require(body[19] == 0x1a, 'Null-guard jump displacement changed')
    require(body[27] == ELEMENT_SIZE, 'Element size constant changed')
    require(body[31:33] == bytes.fromhex('31d2'), 'Flag-clear opcode changed')
    require(body[76:78] == bytes.fromhex('31d2'), 'Landing-pad flag-clear opcode changed')
    # Edges computed from the decoded formula, not assumed.
    edges = {length: size_of(length) for length in (1, 2, 16, 255, 4096)}
    require(edges[1] == 0xf0, 'Edge length=1 changed')
    require(edges[2] == 0x1e0, 'Edge length=2 changed')
    require(edges[16] == 0xf00, 'Edge length=16 changed')
    require(edges[255] == 0xef10, 'Edge length=255 changed')
    require(edges[4096] == 0xf0000, 'Edge length=4096 changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(), fde_section_offset='0x302128',
                              padding_bytes=4, padding_stride_end=hex(PAD_END),
                              inferred_label='drop thunk, 240-byte elements'),
                behavior=dict(call_order='per-element call 0x15443a0 first, then null guard',
                              length_load='u64 length at rdi+0, base pointer at rdi+8 on fall-through',
                              element_size='0xf0', size_formula='length * 0xf0 (mod 2^64)',
                              early_return_on=['length == 0'],
                              flag_at_tail_jump='rdx = 0 (xor edx,edx, never set otherwise)',
                              edges={str(k): hex(v) for k, v in edges.items()},
                              per_element_call_target=hex(ELEMENT_CALL),
                              per_element_call_claimed_here=False,
                              landing_pad='reload length, null guard, same multiply and tail slot, '
                                          'else restore saved pointer and call resume PLT entry 0x5660110',
                              resume_call_target=hex(RESUME_CALL),
                              resume_call_claimed_here=False),
                tail_call=dict(slot=hex(TAIL_SLOT), target=hex(TAIL_TARGET),
                               registers='rdi = field+8, rsi = length * 0xf0, rdx = 0',
                               target_claimed_here=False),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, direct)),
                                           ff15_ff25_candidates=indirect,
                                           validated_caller_fde=['0x152aab0', '0x152c040'],
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
        print('Foundation drop-thunk-240 evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
