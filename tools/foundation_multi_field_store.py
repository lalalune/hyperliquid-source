#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multi-field default/store evidence packet.

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
START, END, PAD_END = 0x55c6be0, 0x55c6c3a, 0x55c6c40
BODY = bytes.fromhex(
    'f30f1efa8b4708ba030000008b3685c08977140f44c28b570c85d27507c7470c'
    '400000008b570485d275108d56f9b90600000039ca0f42d18957048b4f1085c9'
    '750f4189f04129d039d6410f43c8894f1039d00f47c2894708c3')
PAD = b'\xcc' * 6
# Retained .eh_frame records (section offsets, raw bytes incl. length field).
# Window/next and the caller FDE use CIE at offset 0 (zR, pcrel sdata4);
# the pc/range decode below is the same arithmetic for every record.
FDE_WINDOW = bytes.fromhex('10000000f43a2d00d01b61045a00000000000000')
FDE_NEXT = bytes.fromhex('10000000083b2d001c1c61043700000000000000')
FDE_CALLER = bytes.fromhex(
    '6800000034fd2c00a0bf5a041f14000000420e108f02490e188e03490e208d044'
    '50e288c05440e3086064b0e388307440e80010346010ea0016a0e800102490e88'
    '01580e9001440e9801410ea001530e800103ed030a0e38440e30410e28420e204'
    '20e18420e10420e08410b')
CALLERS = [
    dict(site_va='0x555deab', call_bytes='e8308d0600', fde_start='0x555d1f0',
         fde_end='0x555e60f', fde_section_offset='0x2cfd30', fde_raw=FDE_CALLER.hex()),
]
SCAN_HIT_COUNT = 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def apply_model(source, field_08, field_0c, field_04, field_10):
    """Final 32-bit field values after the window runs, plus the return register.

    source is the 32-bit word at [rsi]; field_08/0c/04/10 are the 32-bit
    words at [rdi+0x8]/[rdi+0xc]/[rdi+0x4]/[rdi+0x10] on entry. All
    comparisons are unsigned 32-bit (cmovb/cmovae/cmova); the (source - 7)
    difference wraps mod 2^32, so a source below 7 defaults field_04 to 6
    rather than to a negative value. The store to [rdi+0x14] is
    unconditional; every other field is written only on its default path,
    except [rdi+0x8], which is always rewritten with min(field_08', field_04').
    """
    source &= 0xffffffff
    field_08 &= 0xffffffff
    field_0c &= 0xffffffff
    field_04 &= 0xffffffff
    field_10 &= 0xffffffff
    a_prime = 3 if field_08 == 0 else field_08
    c_final = 0x40 if field_0c == 0 else field_0c
    if field_04 == 0:
        d_final = (source - 7) % (1 << 32)
        if d_final > 6:
            d_final = 6
    else:
        d_final = field_04
    if field_10 == 0:
        e_final = (source - d_final) if source >= d_final else 0
    else:
        e_final = field_10
    a_final = a_prime if a_prime <= d_final else d_final
    return dict(store_14=source, field_08=a_final, field_0c=c_final,
                field_04=d_final, field_10=e_final, return_eax=a_final)


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
    require(body == BODY, 'Multi-field store instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'Stride padding changed')
    # Fixed-offset instruction locks, from the disassembly:
    # endbr64 0-3; mov 0x8(%rdi),%eax 4-6; mov $3,%edx 7-11;
    # mov (%rsi),%esi 12-13; test %eax,%eax 14-15;
    # mov %esi,0x14(%rdi) 16-18; cmove %edx,%eax 19-21;
    # mov 0xc(%rdi),%edx 22-24; test %edx,%edx 25-26;
    # jne +7 27-28 (target 0x55c6c04); movl $0x40,0xc(%rdi) 29-35;
    # mov 0x4(%rdi),%edx 36-38; test %edx,%edx 39-40;
    # jne +16 41-42 (target 0x55c6c1b); lea -0x7(%rsi),%edx 43-45;
    # mov $6,%ecx 46-50; cmp %ecx,%edx 51-52; cmovb %ecx,%edx 53-55;
    # mov %edx,0x4(%rdi) 56-58; mov 0x10(%rdi),%ecx 59-61;
    # test %ecx,%ecx 62-63; jne +15 64-65 (target 0x55c6c31);
    # mov %esi,%r8d 66-68; sub %edx,%r8d 69-71; cmp %edx,%esi 72-73;
    # cmovae %r8d,%ecx 74-77; mov %ecx,0x10(%rdi) 78-80;
    # cmp %edx,%eax 81-82; cmova %edx,%eax 83-85;
    # mov %eax,0x8(%rdi) 86-88; ret 89.
    require(body[0:4] == b'\xf3\x0f\x1e\xfa', 'Entry endbr64 changed')
    require(body[4:7] == b'\x8b\x47\x08', 'Field +0x8 load changed')
    require(body[7:12] == b'\xba\x03\x00\x00\x00', 'Default constant 3 changed')
    require(body[12:14] == b'\x8b\x36', 'Source load changed')
    require(body[14:16] == b'\x85\xc0', 'Default test changed')
    require(body[16:19] == b'\x89\x77\x14', 'Source store changed')
    require(body[19:22] == b'\x0f\x44\xc2', 'Default select changed')
    require(body[22:25] == b'\x8b\x57\x0c', 'Field +0xc load changed')
    require(body[25:27] == b'\x85\xd2', 'Field +0xc test changed')
    require(body[27:29] == b'\x75\x07', 'Field +0xc branch changed')
    require(body[29:36] == b'\xc7\x47\x0c\x40\x00\x00\x00', 'Field +0xc default changed')
    require(body[36:39] == b'\x8b\x57\x04', 'Field +0x4 load changed')
    require(body[39:41] == b'\x85\xd2', 'Field +0x4 test changed')
    require(body[41:43] == b'\x75\x10', 'Field +0x4 branch changed')
    require(body[43:46] == b'\x8d\x56\xf9', 'Source-minus-7 changed')
    require(body[46:51] == b'\xb9\x06\x00\x00\x00', 'Field +0x4 cap constant changed')
    require(body[51:53] == b'\x39\xca', 'Field +0x4 cap compare changed')
    require(body[53:56] == b'\x0f\x42\xd1', 'Field +0x4 cap select changed')
    require(body[56:59] == b'\x89\x57\x04', 'Field +0x4 store changed')
    require(body[59:62] == b'\x8b\x4f\x10', 'Field +0x10 load changed')
    require(body[62:64] == b'\x85\xc9', 'Field +0x10 test changed')
    require(body[64:66] == b'\x75\x0f', 'Field +0x10 branch changed')
    require(body[66:69] == b'\x41\x89\xf0', 'Saturating difference setup changed')
    require(body[69:72] == b'\x41\x29\xd0', 'Saturating difference changed')
    require(body[72:74] == b'\x39\xd6', 'Saturating difference compare changed')
    require(body[74:78] == b'\x41\x0f\x43\xc8', 'Saturating difference select changed')
    require(body[78:81] == b'\x89\x4f\x10', 'Field +0x10 store changed')
    require(body[81:83] == b'\x39\xd0', 'Final min compare changed')
    require(body[83:86] == b'\x0f\x47\xc2', 'Final min select changed')
    require(body[86:89] == b'\x89\x47\x08', 'Field +0x8 store changed')
    require(body[89] == 0xc3, 'Return changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        # pcrel sdata4: pc = field VA + signed displacement at record offset 8.
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    check_fde(0x2d3af0, FDE_WINDOW, START, END)
    check_fde(0x2d3b04, FDE_NEXT, PAD_END, 0x55c6c77)
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
        # All zero: default 3, default 0x40, source-7 wraps so cap is 6,
        # saturating difference floors at 0, final min(3, 6) is 3.
        'all-zero': apply_model(0, 0, 0, 0, 0),
        # Source 10, field_04 defaults to min(3, 6) = 3, difference 7,
        # final min(5, 3) = 3.
        'mid': apply_model(10, 5, 1, 0, 0),
        # Nonzero field_04/field_10 pass through; final min(3, 4) = 3.
        'nonzero-d-e': apply_model(20, 0, 0, 4, 9),
        # Source below 7: source-7 wraps, cap is 6, difference floors at 0,
        # final min(7, 6) = 6.
        'small-source': apply_model(5, 7, 2, 0, 0),
        # Source 14: field_04 defaults to min(7, 6) = 6, difference 8,
        # final min(9, 6) = 6.
        'source-14': apply_model(14, 9, 3, 0, 0),
        # Source 13: field_04 defaults to min(6, 6) = 6, difference 7,
        # final min(2, 6) = 2.
        'source-13': apply_model(13, 2, 0, 0, 0),
        # Source 7: field_04 defaults to min(0, 6) = 0, difference 7,
        # final min(3, 0) = 0.
        'source-7': apply_model(7, 0, 0, 0, 0),
        # Source max: field_04 defaults to 6, difference wraps to
        # 0xfffffff9, final min(1, 6) = 1.
        'source-max': apply_model(0xffffffff, 1, 1, 0, 0),
        # Everything nonzero: only the final min changes anything, to 4.
        'all-nonzero': apply_model(100, 10, 5, 4, 3),
    }
    require(edges['all-zero'] == dict(store_14=0, field_08=3, field_0c=0x40,
                                      field_04=6, field_10=0, return_eax=3),
            'All-zero edge changed')
    require(edges['mid'] == dict(store_14=10, field_08=3, field_0c=1,
                                 field_04=3, field_10=7, return_eax=3),
            'Mid edge changed')
    require(edges['nonzero-d-e'] == dict(store_14=20, field_08=3, field_0c=0x40,
                                         field_04=4, field_10=9, return_eax=3),
            'Nonzero-d-e edge changed')
    require(edges['small-source'] == dict(store_14=5, field_08=6, field_0c=2,
                                          field_04=6, field_10=0, return_eax=6),
            'Small-source edge changed')
    require(edges['source-14'] == dict(store_14=14, field_08=6, field_0c=3,
                                       field_04=6, field_10=8, return_eax=6),
            'Source-14 edge changed')
    require(edges['source-13'] == dict(store_14=13, field_08=2, field_0c=0x40,
                                       field_04=6, field_10=7, return_eax=2),
            'Source-13 edge changed')
    require(edges['source-7'] == dict(store_14=7, field_08=0, field_0c=0x40,
                                      field_04=0, field_10=7, return_eax=0),
            'Source-7 edge changed')
    require(edges['source-max'] == dict(store_14=0xffffffff, field_08=1, field_0c=1,
                                        field_04=6, field_10=0xfffffff9, return_eax=1),
            'Source-max edge changed')
    require(edges['all-nonzero'] == dict(store_14=100, field_08=4, field_0c=5,
                                         field_04=4, field_10=3, return_eax=4),
            'All-nonzero edge changed')
    return dict(target_release='94', target_sha256=SHA256,
                coordinate_system='ELF virtual addresses, no runtime rebase',
                function=dict(start_va=hex(START), end_va_exclusive=hex(END), bytes=len(body),
                              sha256=hashlib.sha256(body).hexdigest(),
                              fde_section_offset='0x2d3af0', stride_padding_bytes=6,
                              next_fde_start_va='0x55c6c40',
                              inferred_label='multi-field default/store'),
                rule=dict(unsigned_form='[rdi+0x14] = source unconditionally; '
                          '[rdi+0x8] = min(source-field default 3 if zero, '
                          '[rdi+0x4] default min((source-7) mod 2^32, 6) if zero); '
                          '[rdi+0xc] = 0x40 if zero; [rdi+0x10] = saturating '
                          '(source - [rdi+0x4]) if zero, all 32-bit unsigned',
                          edges={k: {f: hex(v) for f, v in s.items()}
                                 for k, s in edges.items()}),
                incoming_pattern_scan=dict(section='.text', byte_count=len(code),
                                           e8_candidate_count=len(direct),
                                           caller_fdes=['0x555d1f0..0x555e60f'],
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
        print('Foundation multi-field-store evidence reproduces exactly.')
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
