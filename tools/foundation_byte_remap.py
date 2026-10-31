#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-remap evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
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
START, END, PAD_END = 0x25acc20, 0x25acc6e, 0x25acc70
BODY = bytes.fromhex(
    '89f80fb6c88d9140ffffff83fa207301c381f98f0000007e1b81f990000000742281f9a000'
    '000075084080e61f4080cea089f0c385c974f94080e60f4080ce8089f0c34080e60f4080ce'
    '9089f0c3')
PAD = b'\xcc' * 2
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next and both sampled callers use CIE at offset 0 (zR, pcrel
# sdata4); the pc/range decode below is the same arithmetic for every record.
FDE_WINDOW = bytes.fromhex('1000000084400900807683014e00000000000000')
FDE_NEXT = bytes.fromhex(
    '4800000098400900bc7683018a00000000410e10420e18420e20420e28420e30410e38410'
    'e4083078c068d058e048f03860202670e38410e30420e28420e20420e18420e10410e08410e4000')
FDE_CALLER_1 = bytes.fromhex(
    '3c00000048740300ec5c0e014801000000410e10420e18420e20420e28410e3083068c058e'
    '048f03860202e90e28420e20420e18420e10410e08410e30000000')
FDE_CALLER_2 = bytes.fromhex(
    '480000007c7c030058760e01d601000000410e10420e18420e20420e28420e30410e38440e5'
    '083078c068d058e048f0386020304010e38410e30420e28420e20420e18420e10410e08410e50')
CALLERS = [
    dict(site_va='0x1dfe6d5', call_bytes='e846e57a00', fde_start='0x1dfe650',
         fde_end='0x1dfe798', fde_section_offset='0x37444', fde_raw=FDE_CALLER_1.hex()),
    dict(site_va='0x1dfe713', call_bytes='e808e57a00', fde_start='0x1dfe650',
         fde_end='0x1dfe798', fde_section_offset='0x37444', fde_raw=FDE_CALLER_1.hex()),
    dict(site_va='0x1e00885', call_bytes='e896c37a00', fde_start='0x1e007f0',
         fde_end='0x1e009c6', fde_section_offset='0x37c78', fde_raw=FDE_CALLER_2.hex()),
]
SCAN_HIT_COUNT = 124


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rule(edi, esi):
    """Byte-level semantics of the window, as a zero-extended 32-bit result.

    edi/esi are 32-bit inputs; every return path moves a full 32-bit register
    into eax, so the result is fully determined (no low-byte-only caveat).
    b is the low byte of edi.
    """
    b = edi & 0xff
    if 0xc0 <= b < 0xe0:
        return edi & 0xffffffff
    if b <= 0x8f:
        if b == 0:
            return esi & 0xffffffff
        return ((esi & 0xf) | 0x80) & 0xffffffff
    if b == 0x90:
        return ((esi & 0xf) | 0x90) & 0xffffffff
    if b == 0xa0:
        return ((esi & 0x1f) | 0xa0) & 0xffffffff
    return esi & 0xffffffff


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

    require(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == SHA256,
            'Expected exact node #94 size/SHA-256')
    body = read(START, END - START)
    require(body == BODY, 'Byte-remap instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks, from the disassembly:
    # mov edi,eax 0-1; movzbl al,ecx 2-4; lea -0xc0 5-10 (imm32 at 7);
    # cmp $0x20 11-13 (imm8 at 13); jae 14-15 (rel8 at 15); ret 16;
    # cmp $0x8f 17-22 (imm32 at 19); jle 23-24 (rel8 at 24);
    # cmp $0x90 25-30 (imm32 at 27); je 31-32 (rel8 at 32);
    # cmp $0xa0 33-38 (imm32 at 35); jne 39-40 (rel8 at 40);
    # and $0x1f 41-44 (imm8 at 44); or $0xa0 45-48 (imm8 at 48);
    # mov esi,eax 49-50; ret 51; test 52-53; je 54-55 (rel8 at 55);
    # and $0xf 56-59 (imm8 at 59); or $0x80 60-63 (imm8 at 63);
    # mov 64-65; ret 66; and $0xf 67-70 (imm8 at 70);
    # or $0x90 71-74 (imm8 at 74); mov 75-76; ret 77.
    require(body[0:2] == b'\x89\xf8', 'Entry move changed')
    require(body[2:5] == b'\x0f\xb6\xc8', 'Byte load changed')
    require(struct.unpack_from('<i', body, 7)[0] == -0xc0, 'Range base changed')
    require(body[13] == 0x20, 'Range width changed')
    require(body[14] == 0x73 and body[15] == 0x01, 'Range branch changed')
    require(body[16] == 0xc3, 'Early return changed')
    require(struct.unpack_from('<I', body, 19)[0] == 0x8f, 'Low-range limit changed')
    require(body[23] == 0x7e and body[24] == 0x1b, 'Low-range branch changed')
    require(struct.unpack_from('<I', body, 27)[0] == 0x90, 'First tag constant changed')
    require(body[31] == 0x74 and body[32] == 0x22, 'First tag branch changed')
    require(struct.unpack_from('<I', body, 35)[0] == 0xa0, 'Second tag constant changed')
    require(body[39] == 0x75 and body[40] == 0x08, 'Second tag branch changed')
    require(body[44] == 0x1f, 'Second tag mask changed')
    require(body[48] == 0xa0, 'Second tag or changed')
    require(body[51] == 0xc3, 'Shared return changed')
    require(body[52:54] == b'\x85\xc9', 'Zero test changed')
    require(body[54] == 0x74 and body[55] == 0xf9, 'Zero branch changed')
    require(body[59] == 0x0f, 'Low-range mask changed')
    require(body[63] == 0x80, 'Low-range or changed')
    require(body[66] == 0xc3, 'Low-range return changed')
    require(body[70] == 0x0f, 'First tag mask changed')
    require(body[74] == 0x90, 'First tag or changed')
    require(body[77] == 0xc3, 'First tag return changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x94080, FDE_WINDOW, START, END)
    check_fde(0x94094, FDE_NEXT, PAD_END, 0x25accfa)
    seen_fde = set()
    for caller in CALLERS:
        key = caller['fde_section_offset']
        if key not in seen_fde:
            check_fde(int(key, 16), bytes.fromhex(caller['fde_raw']),
                      int(caller['fde_start'], 16), int(caller['fde_end'], 16))
            seen_fde.add(key)
        site = int(caller['site_va'], 16)
        require(read(site, 5) == bytes.fromhex(caller['call_bytes']), 'Caller call bytes changed')
    for name in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[name]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            _address, _info, addend = struct.unpack_from('<QQq', raw, off)
            require(addend != START, 'Unexpected naming relocation')
    # This byte-pattern scan is explicitly NOT a complete xref census: it
    # counts direct e8 sites only, and only a 3-site sample is validated.
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
    require(len(direct) == SCAN_HIT_COUNT, 'Call-pattern candidate count changed')
    for caller in CALLERS:
        require(int(caller['site_va'], 16) in direct, 'Sampled caller missing from scan')
    edges = {
        'c0-early': rule(0x123456c0, 0xdeadbeef),
        'df-early': rule(0x123456df, 0xdeadbeef),
        'e0-fallthrough': rule(0xe0, 0xdeadbeef),
        'bf-fallthrough': rule(0xbf, 0xdeadbeef),
        'zero': rule(0x00, 0xabcdef12),
        'one': rule(0x01, 0xabcdef12),
        '8f': rule(0x8f, 0x123456ff),
        '90': rule(0x90, 0x12345678),
        '91': rule(0x91, 0x12345678),
        'a0': rule(0xa0, 0x12345678),
        'a1': rule(0xa1, 0x12345678),
    }
    require(edges == {'c0-early': 0x123456c0, 'df-early': 0x123456df,
                      'e0-fallthrough': 0xdeadbeef, 'bf-fallthrough': 0xdeadbeef,
                      'zero': 0xabcdef12, 'one': 0x82, '8f': 0x8f, '90': 0x98,
                      '91': 0x12345678, 'a0': 0xb8, 'a1': 0x12345678},
            'Rule edges changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x94080', stride_padding_bytes=2,
                              next_fde_start_va='0x25acc70',
                              inferred_label='byte remap'),
                rule=dict(early_range='[0xc0, 0xe0)', low_range='<= 0x8f',
                          tags={'0x90': '(sil & 0xf) | 0x90', '0xa0': '(sil & 0x1f) | 0xa0'},
                          low_mask=15, low_or=128, otherwise='esi unchanged',
                          edges={k: hex(v) for k, v in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidate_count=len(direct),
                                           sampled_caller_fdes=['0x1dfe650..0x1dfe798',
                                                                '0x1e007f0..0x1e009c6'],
                                           complete_xref_census=False),
                naming_relocation=None,
                captured_binary_executed=False, progress_gate_requested=False)


def inspect(path):
    data = Path(path).read_bytes()
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--check', type=Path, help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        require(result == json.loads(args.check.read_text()), 'Retained evidence differs')
        print('Foundation byte-remap evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
