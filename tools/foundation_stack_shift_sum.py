#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 stack-arg shift-sum evidence packet.

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
START, END, PAD_END = 0x55c6c40, 0x55c6c77, 0x55c6c80
BODY = bytes.fromhex(
    'f30f1efa31c0837c2408017403c366908b54240c8b442410be0800000039c289d1'
    '0f46c229c1b80100000048d3e089d148d3e64801f0c3')
PAD = b'\xcc' * 9
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next and the caller FDE use CIE at offset 0 (zR, pcrel sdata4);
# the pc/range decode below is the same arithmetic for every record.
FDE_WINDOW = bytes.fromhex('10000000083b2d001c1c61043700000000000000')
FDE_NEXT = bytes.fromhex('100000001c3b2d00481c61041d00000000000000')
FDE_CALLER = bytes.fromhex(
    '5000000044fb2c00d0a85a04c802000000420e108f02480e188e03450e208d04420e288c05410e308606410e3883074c0e70030a010e90017d0e7002850a0e38470e30410e28450e20420e18450e10420e084f0b')
CALLERS = [
    dict(site_va='0x555ba70', call_bytes='e8cbb10600', fde_start='0x555b930',
         fde_end='0x555bbf8', fde_section_offset='0x2cfb40', fde_raw=FDE_CALLER.hex()),
]
SCAN_HIT_COUNT = 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rule(flag, arg1, arg2):
    """Gate semantics of the window, as a 64-bit wrapping result.

    flag is the 32-bit word at [rsp+8], arg1 the 32-bit word at [rsp+0xc],
    arg2 the 32-bit word at [rsp+0x10], all read in the window's own frame
    (rsp points at the return address on entry, so these are the caller's
    stack-passed words). The min is unsigned (cmovbe); both shifts take
    their counts mod 64 (x86 shl %cl semantics), and the sum wraps mod 2^64.
    """
    flag &= 0xffffffff
    arg1 &= 0xffffffff
    arg2 &= 0xffffffff
    if flag != 1:
        return 0
    lo = arg1 if arg1 <= arg2 else arg2
    return ((1 << ((arg1 - lo) % 64)) + (8 << (arg1 % 64))) % (1 << 64)


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
    require(body == BODY, 'Stack-arg shift-sum instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks, from the disassembly:
    # endbr64 0-3; xor %eax,%eax 4-5; cmpl $1,0x8(%rsp) 6-10;
    # je +3 11-12 (target is the compute path at 16); ret 13;
    # 2-byte nop 14-15; mov 0xc(%rsp),%edx 16-19; mov 0x10(%rsp),%eax 20-23;
    # mov $8,%esi 24-28; cmp %eax,%edx 29-30; mov %edx,%ecx 31-32;
    # cmovbe %edx,%eax 33-35; sub %eax,%ecx 36-37; mov $1,%eax 38-42;
    # shl %cl,%rax 43-45; mov %edx,%ecx 46-47; shl %cl,%rsi 48-50;
    # add %rsi,%rax 51-53; ret 54.
    require(body[0:4] == b'\xf3\x0f\x1e\xfa', 'Entry endbr64 changed')
    require(body[4:6] == b'\x31\xc0', 'Zero register changed')
    require(body[6:11] == b'\x83\x7c\x24\x08\x01', 'Flag compare changed')
    require(body[11:13] == b'\x74\x03', 'Flag branch changed')
    require(body[13] == 0xc3, 'Early return changed')
    require(body[14:16] == b'\x66\x90', 'Inter-path nop changed')
    require(body[16:20] == b'\x8b\x54\x24\x0c', 'Arg1 load changed')
    require(body[20:24] == b'\x8b\x44\x24\x10', 'Arg2 load changed')
    require(body[24:29] == b'\xbe\x08\x00\x00\x00', 'Base constant changed')
    require(body[29:31] == b'\x39\xc2', 'Min compare changed')
    require(body[31:33] == b'\x89\xd1', 'Difference setup changed')
    require(body[33:36] == b'\x0f\x46\xc2', 'Unsigned min select changed')
    require(body[36:38] == b'\x29\xc1', 'Difference changed')
    require(body[38:43] == b'\xb8\x01\x00\x00\x00', 'Shift base changed')
    require(body[43:46] == b'\x48\xd3\xe0', 'First shift changed')
    require(body[46:48] == b'\x89\xd1', 'Second shift setup changed')
    require(body[48:51] == b'\x48\xd3\xe6', 'Second shift changed')
    require(body[51:54] == b'\x48\x01\xf0', 'Sum changed')
    require(body[54] == 0xc3, 'Return changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2d3b04, FDE_WINDOW, START, END)
    check_fde(0x2d3b18, FDE_NEXT, PAD_END, 0x55c6c9d)
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
    # counts direct e8 sites only, and the single site is boundary-confirmed.
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
        # Flag not 1 -> 0, regardless of the arguments.
        'flag-zero': rule(0, 5, 3),
        'flag-two': rule(2, 5, 3),
        # Flag 1, arg1 == arg2 == 0 -> (1 << 0) + (8 << 0) = 9.
        'both-zero': rule(1, 0, 0),
        # Flag 1, arg1 above arg2 -> (1 << 2) + (8 << 5) = 260.
        'arg1-above': rule(1, 5, 3),
        # Flag 1, arg1 below arg2 -> diff 0 -> 1 + (8 << 3) = 65.
        'arg1-below': rule(1, 3, 5),
        # Flag 1, arg1 == 64: shift counts mod 64 -> 1 + (8 << 0) = 9.
        'arg1-64': rule(1, 64, 0),
        # Flag 1, arg1 == 65, arg2 == 65 -> 1 + (8 << 1) = 17.
        'arg1-65': rule(1, 65, 65),
        # Flag 1, arg1 == 70, arg2 == 0 -> (1 << 6) + (8 << 6) = 576.
        'arg1-70': rule(1, 70, 0),
        # Flag 1, arg1 == 0xffffffff, arg2 == 0 -> diff mod 64 == 63,
        # 8 << 63 wraps to 0 mod 2^64 -> 2^63.
        'arg1-max': rule(1, 0xffffffff, 0),
    }
    require(edges == {'flag-zero': 0, 'flag-two': 0, 'both-zero': 9,
                      'arg1-above': 260, 'arg1-below': 65, 'arg1-64': 9,
                      'arg1-65': 17, 'arg1-70': 576, 'arg1-max': 1 << 63},
            'Rule edges changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x2d3b04', stride_padding_bytes=9,
                              next_fde_start_va='0x55c6c80',
                              inferred_label='stack-arg shift sum'),
                rule=dict(unsigned_form='flag at [rsp+8] != 1 -> 0, else '
                          '(1 << ((arg1 - min(arg1, arg2)) mod 64)) + '
                          '(8 << (arg1 mod 64)) mod 2^64, arg1 at [rsp+0xc], '
                          'arg2 at [rsp+0x10], unsigned 32-bit min',
                          edges={k: hex(v) for k, v in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidate_count=len(direct),
                                           caller_fdes=['0x555b930..0x555bbf8'],
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
        print('Foundation stack-shift-sum evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
