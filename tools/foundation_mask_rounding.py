#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 mask/rounding evidence packet.

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
START, END, PAD_END = 0x555e610, 0x555e65b, 0x555e660
MASK = 0xff00ff00ff00feff
SENTINEL = -72
SMALL_LIMIT = 0x1ffff
SMALL_BASE = 0x20000
BODY = bytes.fromhex(
    'f30f1efa48bafffe00ff00ff00ff48c7c0b8ffffff4839fa72304889f848c1e8084801f8'
    '4881ffffff0100770fba000002004829fa48c1ea0b4801d04885c048c7c2b8ffffff480f44c2c3')
PAD = b'\xcc' * 5
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next use CIE at offset 0 (zR, pcrel sdata4); caller 1 uses the zPLR
# CIE at 0x6205d0; callers 2/3 use CIE at offset 0. The pc/range decode below
# is the same pcrel sdata4 arithmetic for every record.
FDE_WINDOW = bytes.fromhex('10000000a0fd2c0054d35a044b00000000000000')
FDE_NEXT = bytes.fromhex('10000000b4fd2c0090d35a040c00000000000000')
FDE_CALLER_1 = bytes.fromhex(
    '3c00000034b80000b041d703150b0000041a4e8cff450e108602430d06498f038e048d058c'
    '06830702640a0c07084b0b03be042e10662e000348042e105d2e00')
FDE_CALLER_2 = bytes.fromhex(
    '6c000000b4102b00e0143b044806000000420e108f02420e188e03420e208d04450e288c05'
    '440e308606440e3883074a0ee00102630a0e38430e30410e28420e20420e18420e10420e08'
    '440b02c80ee801490ef0014c0ee801410ee00102c20ee801460ef001460ee801410ee0010000')
FDE_CALLER_3 = bytes.fromhex(
    '48000000145a2d00b03664040802000000460e108f02470e188e03450e208d04450e288c05'
    '410e308606410e388307440e700371010a0e38440e30410e28420e20420e18420e10420e08'
    '450b')
CALLERS = [
    dict(site_va='0x5081df3', call_bytes='e818c84d00', fde_start='0x50814d0',
         fde_end='0x5081fe5', fde_section_offset='0x62be00', fde_raw=FDE_CALLER_1.hex()),
    dict(site_va='0x5343b8a', call_bytes='e881aa2100', fde_start='0x5343ab0',
         fde_end='0x53440f8', fde_section_offset='0x2b10b0', fde_raw=FDE_CALLER_2.hex()),
    dict(site_va='0x55fa67b', call_bytes='e8903ff6ff', fde_start='0x55fa5e0',
         fde_end='0x55fa7e8', fde_section_offset='0x2d5a10', fde_raw=FDE_CALLER_3.hex()),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rule(rdi):
    """Byte-level semantics of the window, mod 2**64, as an unsigned rax value.

    The -72 sentinel is the unsigned value 0xffffffffffffffb8. The v == 0
    branch is unreachable on the stated inputs (see the README): the small
    path yields at least 64 and the large path yields a positive sum, so the
    cmove never fires for any input that reaches it.
    """
    if rdi > MASK:
        return (1 << 64) + SENTINEL
    value = (rdi + (rdi >> 8)
             + (((SMALL_BASE - rdi) >> 11) if rdi <= SMALL_LIMIT else 0)) % (1 << 64)
    return (1 << 64) + SENTINEL if value == 0 else value


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
    require(body == BODY, 'Mask/rounding instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks: mask, sentinel, thresholds, shifts.
    # Layout (offsets from the disassembly): endbr64 0-3; movabs mask 4-13
    # (imm64 at 6); mov sentinel 14-20 (imm32 at 17); cmp 21-23; jb 24-25;
    # mov/shr/add 26-35; cmp limit 36-42 (imm32 at 39); ja 43-44; mov base
    # 45-49 (imm32 at 46); sub 50-52; shr 53-56 (shift at 56); add 57-59;
    # test 60-62; mov sentinel 63-69 (imm32 at 66); cmove 70-73; ret 74.
    require(struct.unpack_from('<Q', body, 6)[0] == MASK, 'Mask constant changed')
    require(struct.unpack_from('<i', body, 17)[0] == SENTINEL, 'Sentinel changed')
    require(body[24] == 0x72 and body[25] == 0x30, 'Unsigned-above branch changed')
    require(struct.unpack_from('<I', body, 39)[0] == SMALL_LIMIT, 'Small-path limit changed')
    require(body[43] == 0x77 and body[44] == 0x0f, 'Unsigned-above branch changed')
    require(struct.unpack_from('<I', body, 46)[0] == SMALL_BASE, 'Small-path base changed')
    require(body[56] == 0x0b, 'Small-path shift changed')
    require(struct.unpack_from('<i', body, 66)[0] == SENTINEL, 'Second sentinel changed')
    require(body[74] == 0xc3, 'Return opcode changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2cfd9c, FDE_WINDOW, START, END)
    check_fde(0x2cfdb0, FDE_NEXT, PAD_END, 0x555e66c)
    for caller in CALLERS:
        check_fde(int(caller['fde_section_offset'], 16), bytes.fromhex(caller['fde_raw']),
                  int(caller['fde_start'], 16), int(caller['fde_end'], 16))
        site = int(caller['site_va'], 16)
        require(read(site, 5) == bytes.fromhex(caller['call_bytes']), 'Caller call bytes changed')
    for name in ('.rela.dyn', '.rela.plt'):
        relsec = by_name[name]
        require(relsec['size'] % 24 == 0, 'Truncated RELA section')
        raw = read(relsec['address'], relsec['size'])
        for off in range(0, len(raw), 24):
            _address, _info, addend = struct.unpack_from('<QQq', raw, off)
            require(addend != START, 'Unexpected naming relocation')
    # This byte-pattern scan is explicitly NOT a complete xref census.
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
    require(direct == [int(c['site_va'], 16) for c in CALLERS], 'Call-pattern candidate set changed')
    edges = {
        '0x0': rule(0), '0x1': rule(1), '0x1ffff': rule(0x1ffff),
        '0x20000': rule(0x20000), 'mask': rule(MASK), 'mask+1': rule(MASK + 1),
        'max-u64': rule((1 << 64) - 1),
    }
    require(edges == {'0x0': 64, '0x1': 64, '0x1ffff': 131582, '0x20000': 131584,
                      'mask': 0xfffffffffffffffd, 'mask+1': 0xffffffffffffffb8,
                      'max-u64': 0xffffffffffffffb8}, 'Rule edges changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x2cfd9c', stride_padding_bytes=5,
                              next_fde_start_va='0x555e660',
                              inferred_label='mask/rounding arithmetic'),
                rule=dict(mask=hex(MASK), sentinel=SENTINEL, small_limit=hex(SMALL_LIMIT),
                          small_base=hex(SMALL_BASE), small_shift=11, large_shift=8,
                          unreachable_zero_branch=True, edges={k: hex(v) for k, v in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidates=list(map(hex, direct)),
                                           validated_caller_fdes=[c['fde_start'] + '..' + c['fde_end']
                                                                  for c in CALLERS],
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
        print('Foundation mask-rounding evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
