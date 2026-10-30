#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 days-to-seconds evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.

The window's FDE covers [0x1518ca0, 0x1518ce6) (70 bytes). The unwind index
stride to the next entry, 0x1518cf0, is 80 bytes only because ten int3
padding bytes follow the FDE end; the stride is not the FDE extent.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, FDE_END, INDEX_END = 0x1518ca0, 0x1518ce6, 0x1518cf0
BODY = bytes.fromhex(
    '5553504889d389f5e833f7ffff89ef4889c6e879f5ffff4869c080510100700c4801d87014'
    '4883c4085b5dc3488d3db58c1504ff15d7542504488d3da88c1504ff1532542504')
PADDING = b'\xcc' * 10
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex(
    '28000000ec480100982e82004600000000410e10410e18410e2083038602660e18410e10410e'
    '08410e200000')
CALLER_FDE = bytes.fromhex(
    '48000000b0470100a41d82009004000000410e10420e18420e20420e28420e30410e38440e608'
    '3078c068d058e048f03860203cd020e38410e30420e28420e20420e18420e10410e08410e60')


def require(condition, message):
    if not condition:
        raise ValueError(message)


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

    body = read(START, FDE_END - START)
    require(body == BODY, 'Days-to-seconds instruction window changed')
    require(read(FDE_END, INDEX_END - FDE_END) == PADDING, 'FDE padding changed')
    eh = by_name['.eh_frame']
    require(read(eh['address'], len(CIE)) == CIE, 'CIE changed')
    for offset, raw, start, end in [(0x148e8, FDE, START, FDE_END),
                                    (0x147ac, CALLER_FDE, 0x1517a70, 0x1517f00)]:
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # Both retained records use the CIE-confirmed pcrel/sdata4 initial PC.
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

    def relative(address, expected):
        require(rels.get(address) == (8, expected), 'Relative relocation changed')
        require(read(address, 8) == b'\0' * 8, 'Unexpected pre-relocation pointer')

    relative(0x576e1b0, 0x157b4a0)
    relative(0x576e118, 0x157b480)
    # Call edges inside the window, with RIP-relative targets recomputed.
    require(read(0x1518ca8, 5) == bytes.fromhex('e833f7ffff'), 'First callee call changed')
    require(0x1518ca8 + 5 + struct.unpack_from('<i', body, 9)[0] == 0x15183e0,
            'First callee call target changed')
    require(read(0x1518cb2, 5) == bytes.fromhex('e879f5ffff'), 'Second callee call changed')
    require(0x1518cb2 + 5 + struct.unpack_from('<i', body, 19)[0] == 0x1518230,
            'Second callee call target changed')
    require(read(0x1518cd3, 6) == bytes.fromhex('ff15d7542504'), 'Imul-arm call changed')
    require(0x1518cd3 + 6 + struct.unpack_from('<i', body, 53)[0] == 0x576e1b0,
            'Imul-arm call slot changed')
    require(read(0x1518ce0, 6) == bytes.fromhex('ff1532542504'), 'Add-arm call changed')
    require(0x1518ce0 + 6 + struct.unpack_from('<i', body, 66)[0] == 0x576e118,
            'Add-arm call slot changed')
    require(read(0x1518ccc, 7) == bytes.fromhex('488d3db58c1504'), 'Imul-arm argument changed')
    require(0x1518ccc + 7 + struct.unpack_from('<i', body, 47)[0] == 0x5671988,
            'Imul-arm argument target changed')
    require(read(0x1518cd9, 7) == bytes.fromhex('488d3da88c1504'), 'Add-arm argument changed')
    require(0x1518cd9 + 7 + struct.unpack_from('<i', body, 60)[0] == 0x5671988,
            'Add-arm argument target changed')
    # Signed-overflow branches: jo after imul goes to the imul arm, jo after
    # add goes to the add arm. The two arms are distinct call targets.
    require(body[30] == 0x70 and body[31] == 0x0c, 'Imul overflow branch changed')
    require(START + 32 + body[31] == 0x1518ccc, 'Imul overflow branch target changed')
    require(body[35] == 0x70 and body[36] == 0x14, 'Add overflow branch changed')
    require(START + 37 + body[36] == 0x1518cd9, 'Add overflow branch target changed')
    # Incoming direct calls, validated as bytes.
    require(read(0x1517e43, 5) == bytes.fromhex('e8580e0000'), 'Incoming call 1 changed')
    require(read(0x1517eb5, 5) == bytes.fromhex('e8e60d0000'), 'Incoming call 2 changed')
    require(0x1517e43 + 5 + struct.unpack_from('<i', read(0x1517e43, 5), 1)[0] == START,
            'Incoming call 1 target changed')
    require(0x1517eb5 + 5 + struct.unpack_from('<i', read(0x1517eb5, 5), 1)[0] == START,
            'Incoming call 2 target changed')

    # This byte-pattern scan is explicitly NOT a complete xref census. GNU
    # disassembly from the caller FDE start validates the two retained
    # candidates as instruction starts.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            destination = text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination == START:
                direct.append(text['address'] + pos)
        pos += 1
    require(direct == [0x1517e43, 0x1517eb5], 'Call-pattern candidate set changed')
    # Arithmetic constants parsed from the retained instruction bytes.
    multiplier = struct.unpack_from('<I', body, 26)[0]
    require(multiplier == 86400, 'Arithmetic constant changed')
    return dict(target_release='94', target_sha256=SHA256, coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), fde_end_va_exclusive=hex(FDE_END),
                              index_stride_end_va_exclusive=hex(INDEX_END),
                              fde_bytes=len(body), index_stride_bytes=INDEX_END - START,
                              fde_body_sha256=hashlib.sha256(body).hexdigest(),
                              index_stride_sha256=hashlib.sha256(body + PADDING).hexdigest(),
                              fde_section_offset='0x148e8',
                              inferred_label='checked arithmetic helper: second callee result x 86400 plus saved input, both operations overflow-checked'),
                arithmetic=dict(first_callee='0x15183e0', second_callee='0x1518230',
                                seconds_per_day=multiplier,
                                imul_overflow_arm='0x1518ccc', imul_overflow_target='0x157b4a0',
                                imul_overflow_slot='0x576e1b0',
                                add_overflow_arm='0x1518cd9', add_overflow_target='0x157b480',
                                add_overflow_slot='0x576e118',
                                shared_arm_argument='0x5671988',
                                branch='signed overflow: jo after imul goes to imul arm, jo after add goes to add arm',
                                result='rax returned unchanged when neither operation overflows'),
                call_edges=dict(first_callee_fde=['0x15183e0', '0x151877c'],
                                second_callee_fde=['0x1518230', '0x15183d2'],
                                incoming_sites=['0x1517e43', '0x1517eb5'],
                                incoming_caller_fde=['0x1517a70', '0x1517f00']),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, direct)),
                                           validated_caller_fde=['0x1517a70', '0x1517f00'],
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
        print('Foundation days-to-seconds evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
