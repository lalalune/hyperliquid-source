#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 pointer-select evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls: one landing pad, one lea, one add, one
compare, one conditional move, one field load, then ret. The selected base is
rdi + 0xe518 when esi == 1, otherwise rdi + 0xec10; the returned value is the
8-byte field at base + 0x78. The return value is fully determined (rax is
loaded, not a setcc byte), and no global, table, or constant meaning is
claimed anywhere.

This window is bound ALONE. No census of similar windows is claimed.
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
START, END = 0x552cac0, 0x552cade
PAD_END = 0x552cae0
BODY = bytes.fromhex(
    'f30f1efa488d8718e500004881c710ec000083fe01480f44f8488b4778c3')
PAD = b'\xcc' * 2
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('10000000b4ae2c00f00658041e00000000000000')
NEXT_FDE = bytes.fromhex(
    '38000000c8ae2c00fc0658046500000000460e108d02420e188c03440e208604'
    '410e2883054e0e3002430e28410e20410e18420e10420e0800000000')
CALLER_FDES = (
    (0x2c04b8,
     bytes.fromhex(
         '6c000000bc042c0078a352049d02000000460e108f02420e188e03450e208d0'
         '4420e288c05440e308606430e388307470e6002f30e68530e705c0e68410e60'
         '440a0e38410e30410e28420e20420e18420e10420e08420b02ac0a0e38410e30'
         '410e28420e20420e18420e10420e084a0b'),
     0x54cbd50, 0x54cbfed),
    (0x2c0528,
     bytes.fromhex(
         '540000002c052c00a8a552043601000000460e108f02420e188e03490e208d0'
         '4490e288c05480e308606470e388307470e5002910e58550e60580e58410e50'
         '440a0e384b0e30410e28420e20420e18420e10420e08490b00'),
     0x54cbff0, 0x54cc126),
    (0x2c89c4,
     bytes.fromhex(
         '60000000c8892c006c4857042102000000460e108f02450e188e03460e208d0'
         '4450e288c05440e308606470e388307470e6002fb0a0e38440e30410e28420e'
         '20420e18420e10420e08480b02d90a0e38410e30410e28420e20420e18420e10'
         '420e08410b'),
     0x551e750, 0x551e971),
)
CALL_SITES = (
    (0x54cbfc2, bytes.fromhex('e8f90a0600')),
    (0x54cc11a, bytes.fromhex('e8a1090600')),
    (0x551e8d0, bytes.fromhex('e8ebe10000')),
    (0x551e8e7, bytes.fromhex('e8d4e10000')),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def select_offset(selector):
    """Base offset of the window, for edge checks only.

    This is a Python restatement of the retained instruction sequence, not a
    run or emulation of the captured binary. The compare is the full 32-bit
    esi against 1; cmove fires only on equality.
    """
    return 0xe518 if selector == 1 else 0xec10


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
    require(body == BODY, 'Pointer-select instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'CIE changed')
    check_fde(0x2caeb0, FDE, START, END)
    check_fde(0x2caec4, NEXT_FDE, PAD_END, 0x552cb45)
    for offset, raw, start, end in CALLER_FDES:
        check_fde(offset, raw, start, end)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x552cac0.
    require(body[0:4] == bytes.fromhex('f30f1efa'), 'Endbr64 changed')
    require(body[4:11] == bytes.fromhex('488d8718e50000'), 'Select lea changed')
    require(struct.unpack_from('<i', body, 7)[0] == 0xe518,
            'Select displacement changed')
    require(body[11:18] == bytes.fromhex('4881c710ec0000'), 'Default add changed')
    require(struct.unpack_from('<i', body, 14)[0] == 0xec10,
            'Default displacement changed')
    require(body[18:21] == bytes.fromhex('83fe01'), 'Selector compare changed')
    require(body[21:25] == bytes.fromhex('480f44f8'), 'Conditional move changed')
    require(body[25:29] == bytes.fromhex('488b4778'), 'Field load changed')
    require(body[28] == 0x78, 'Field offset changed')
    require(body[29:30] == bytes.fromhex('c3'), 'Return changed')
    # Caller call bytes and targets come before the incoming scan, so a
    # mutated call site reports its own check rather than the scan's.
    for site, raw in CALL_SITES:
        call = read(site, 5)
        require(call == raw, 'Caller call bytes changed')
        require(site + 5 + struct.unpack_from('<i', call, 1)[0] == START,
                'Caller call target changed')
    # Incoming calls: exactly four direct e8 calls, no indirect slot calls.
    # No relocation of any type maps a slot to this window.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    window_slots = [a for a, (info, addend) in rels.items() if addend == START]
    require(window_slots == [], 'Unexpected slot maps to window')
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [site for site, _ in CALL_SITES],
            'Incoming direct call set changed')
    return {
        'behavior': {
            'arguments': 'rdi = base pointer, esi = selector (32-bit compare)',
            'calls_inside_window': 0,
            'field_offset': '0x78',
            'meaning_of_base_and_field': 'unknown, not claimed',
            'return_shape': 'rax = 8-byte load at selected base + 0x78, fully determined',
            'select_rule': 'esi == 1 -> base = rdi + 0xe518, else base = rdi + 0xec10',
            'edges': {
                'selector_0': '0xec88',
                'selector_1': '0xe590',
                'selector_2': '0xec88',
            },
        },
        'captured_binary_executed': False,
        'coordinate_system': 'ELF virtual addresses, no runtime rebase',
        'function': {
            'bytes': 30,
            'end_va_exclusive': '0x552cade',
            'fde_section_offset': '0x2caeb0',
            'inferred_label': 'pointer-select plus field load, bound alone',
            'next_fde_section_offset': '0x2caec4',
            'padding_bytes': 2,
            'padding_stride_end': '0x552cae0',
            'sha256': hashlib.sha256(body).hexdigest(),
            'start_va': '0x552cac0',
        },
        'incoming_pattern_scan': {
            'byte_count': len(code),
            'caller_fdes': ['0x54cbd50', '0x54cbff0', '0x551e750'],
            'complete_xref_census': False,
            'e8_candidates': ['0x54cbfc2', '0x54cc11a', '0x551e8d0', '0x551e8e7'],
            'section': '.text',
            'validated_caller_fdes': ['0x54cbd50', '0x54cbff0', '0x551e750'],
        },
        'progress_gate_requested': False,
        'target_release': '94',
        'target_sha256': SHA256,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', required=True)
    args = parser.parse_args()
    data = Path(args.binary).read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    evidence = json.loads(Path(args.check).read_text())
    require(analyze(data) == evidence, 'Evidence does not reproduce')
    print('Foundation pointer-select evidence reproduces exactly.')


if __name__ == '__main__':
    main()
