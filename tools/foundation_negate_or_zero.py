#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 negate-or-zero evidence packet.

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
START, END, PAD_END = 0x555ac00, 0x555ac12, 0x555ac20
BODY = bytes.fromhex('f30f1efa89f831d2f7d84883ff880f46c2c3')
PAD = b'\xcc' * 14
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next and the caller FDE use CIE at offset 0 (zR, pcrel sdata4);
# the pc/range decode below is the same arithmetic for every record.
FDE_WINDOW = bytes.fromhex('1000000008fa2c00dc9c5a041200000000000000')
FDE_NEXT = bytes.fromhex('100000001cfa2c00e89c5a047700000000000000')
FDE_CALLER = bytes.fromhex(
    '8000000058472d00ec4062041c10000000420e108f02450e188e03420e208d04450e288c05440e308606440e3883074a0ee001032e030a0e38440e30410e28420e20420e18420e10420e08450b0369080ee801500ef0015e0ee801410ee00102e10ee801500ef0015e0ee801410ee00102410ee801500ef0015f0ee801420ee001000000')
CALLERS = [
    dict(site_va='0x55da082', call_bytes='e8790bf8ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
    dict(site_va='0x55da0c7', call_bytes='e8340bf8ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
    dict(site_va='0x55da276', call_bytes='e88509f8ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
    dict(site_va='0x55da68e', call_bytes='e86d05f8ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
    dict(site_va='0x55dad00', call_bytes='e8fbfef7ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
    dict(site_va='0x55dad37', call_bytes='e8c4fef7ff', fde_start='0x55d9d60',
         fde_end='0x55dad7c', fde_section_offset='0x2d4754', fde_raw=FDE_CALLER.hex()),
]
SCAN_HIT_COUNT = 6
# Unsigned threshold: 0xffffffffffffff88 is -0x78 sign-extended to 64 bits.
MASK = 0xffffffffffffff88


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rule(rdi):
    """Gate semantics of the window, as a zero-extended 32-bit result.

    rdi is a 64-bit input. The bytes compare the full 64-bit rdi against
    the mask with an unsigned below-or-equal move: rdi unsigned <= mask
    returns 0, otherwise the 32-bit negation of the low word of rdi is
    returned (zero-extended). For sign-extended inputs this is exactly
    the signed range [-119, -1] -> -edi, else 0; the unsigned form is
    the literal rule and is what the checker locks.
    """
    rdi &= 0xffffffffffffffff
    if rdi <= MASK:
        return 0
    return (-(rdi & 0xffffffff)) & 0xffffffff


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
    require(body == BODY, 'Negate-or-zero instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks, from the disassembly:
    # endbr64 0-3; mov edi,eax 4-5; xor edx,edx 6-7; neg eax 8-9;
    # cmp $mask,rdi 10-13 (imm8 0x88 at 13, sign-extended by 83 /7);
    # cmovbe edx,eax 14-16; ret 17.
    require(body[0:4] == b'\xf3\x0f\x1e\xfa', 'Entry endbr64 changed')
    require(body[4:6] == b'\x89\xf8', 'Entry move changed')
    require(body[6:8] == b'\x31\xd2', 'Zero register changed')
    require(body[8:10] == b'\xf7\xd8', 'Negation changed')
    require(body[10:13] == b'\x48\x83\xff', 'Compare opcode changed')
    require(body[13] == 0x88, 'Compare constant changed')
    require(body[14:17] == b'\x0f\x46\xc2', 'Conditional move changed')
    require(body[17] == 0xc3, 'Return changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2cfa04, FDE_WINDOW, START, END)
    check_fde(0x2cfa18, FDE_NEXT, PAD_END, 0x555ac97)
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
    # counts direct e8 sites only, and all 6 are boundary-confirmed.
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
        require(int(caller['site_va'], 16) in direct, 'Caller missing from scan')
    edges = {
        'minus-1': rule(0xffffffffffffffff),
        'minus-119': rule(0xffffffffffffff89),
        'minus-120': rule(0xffffffffffffff88),
        'zero': rule(0),
        'one': rule(1),
        'plus-119': rule(119),
        'mask-plus-1': rule(MASK + 1),
        # 0x1ffffff89 has low word 0xffffff89 but its full 64-bit value is
        # below the mask, so it returns 0: the comparison is on all of rdi,
        # not on the low word alone.
        'high-bits-small': rule(0x1ffffff89),
    }
    require(edges == {'minus-1': 1, 'minus-119': 119, 'minus-120': 0, 'zero': 0,
                      'one': 0, 'plus-119': 0, 'mask-plus-1': 119, 'high-bits-small': 0},
            'Rule edges changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x2cfa04', stride_padding_bytes=14,
                              next_fde_start_va='0x555ac20',
                              inferred_label='negate-or-zero gate'),
                rule=dict(mask='0xffffffffffffff88',
                          unsigned_form='rdi <= mask -> 0, else (-low32(rdi)) & 0xffffffff',
                          signed_form='sign-extended rdi in [-119, -1] -> -edi, else 0',
                          edges={k: hex(v) for k, v in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidate_count=len(direct),
                                           caller_fdes=['0x55d9d60..0x55dad7c'],
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
        print('Foundation negate-or-zero evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
