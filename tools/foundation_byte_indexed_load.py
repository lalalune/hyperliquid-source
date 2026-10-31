#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 byte-indexed-load evidence packet.

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
START, END, PAD_END = 0x556bfe0, 0x556bff6, 0x556c000
BODY = bytes.fromhex('f30f1efa0fb6570131c039f2720789f60fb644f708c3')
PAD = b'\xcc' * 10
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next and the caller FDE use CIE at offset 0 (zR, pcrel sdata4);
# the pc/range decode below is the same arithmetic for every record.
FDE_WINDOW = bytes.fromhex('100000007c0d2d00489d5b041600000000000000')
FDE_NEXT = bytes.fromhex(
    '4c000000900d2d00549d5b04060b000000460e108f02450e188e03420e208d04420e288c05410e308606410e388307470ef00103eb080a0e38440e30410e28420e20420e18420e10420e0848')
FDE_CALLER = bytes.fromhex(
    '38000000a03c2d00b43b6104e409000000420e108d02420e188c03410e208604430e288305470e400341010a0e28460e20410e18420e1042')
CALLERS = [
    dict(site_va='0x55c8f0b', call_bytes='e8d030faff', fde_start='0x55c8d70',
         fde_end='0x55c9754', fde_section_offset='0x2d3c9c', fde_raw=FDE_CALLER.hex()),
]
SCAN_HIT_COUNT = 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rule(count_byte, index, indexed_byte):
    """Gate semantics of the window, as a zero-extended byte result.

    count_byte is the byte at [rdi+1] (0..255); index is the full 32-bit
    esi, compared unsigned against the zero-extended count byte (the jb
    after cmp %esi,%edx); indexed_byte is the byte at [rdi + 8*esi + 8],
    reached only when the count byte is not below the index. The mov
    %esi,%esi zero-extends the index, so the scaled load uses the full
    32-bit index, and every return is a full-register move into eax, so
    the result is always 0..255 with no low-byte-only caveat.
    """
    count_byte &= 0xff
    index &= 0xffffffff
    if count_byte < index:
        return 0
    return indexed_byte & 0xff


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
    require(body == BODY, 'Byte-indexed-load instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks, from the disassembly:
    # endbr64 0-3; movzbl 0x1(%rdi),%edx 4-7; xor %eax,%eax 8-9;
    # cmp %esi,%edx 10-11; jb +7 12-13 (target is the ret at 21);
    # mov %esi,%esi 14-15; movzbl 0x8(%rdi,%rsi,8),%eax 16-20; ret 21.
    require(body[0:4] == b'\xf3\x0f\x1e\xfa', 'Entry endbr64 changed')
    require(body[4:8] == b'\x0f\xb6\x57\x01', 'Count-byte load changed')
    require(body[8:10] == b'\x31\xc0', 'Zero register changed')
    require(body[10:12] == b'\x39\xf2', 'Unsigned compare changed')
    require(body[12:14] == b'\x72\x07', 'Below branch changed')
    require(body[14:16] == b'\x89\xf6', 'Index zero-extension changed')
    require(body[16:21] == b'\x0f\xb6\x44\xf7\x08', 'Indexed load changed')
    require(body[21] == 0xc3, 'Return changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2d0d78, FDE_WINDOW, START, END)
    check_fde(0x2d0d8c, FDE_NEXT, PAD_END, 0x556cb06)
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
        # count < index -> 0, regardless of the indexed byte.
        'below': rule(3, 5, 0x41),
        # count == index -> indexed byte.
        'equal': rule(10, 10, 0x7a),
        # count > index -> indexed byte.
        'above': rule(5, 3, 0x41),
        # Full 32-bit index: a count byte (max 255) is below any index > 255.
        'index-above-255': rule(255, 256, 0x41),
        # Zero count with zero index reaches the load, not the early return.
        'zero-count-zero-index': rule(0, 0, 0x00),
        # Indexed byte is returned zero-extended, never truncated.
        'indexed-byte': rule(200, 7, 0xff),
    }
    require(edges == {'below': 0, 'equal': 0x7a, 'above': 0x41,
                      'index-above-255': 0, 'zero-count-zero-index': 0,
                      'indexed-byte': 0xff},
            'Rule edges changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x2d0d78', stride_padding_bytes=10,
                              next_fde_start_va='0x556c000',
                              inferred_label='byte-indexed byte load'),
                rule=dict(unsigned_form='byte at [rdi+1] < esi (unsigned) -> 0, '
                          'else byte at [rdi + 8*esi + 8]',
                          edges={k: hex(v) for k, v in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidate_count=len(direct),
                                           caller_fdes=['0x55c8d70..0x55c9754'],
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
        print('Foundation byte-indexed-load evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
