#!/usr/bin/env python3
"""Recover the node #94 TWAP map size path from ELF bytes, without executing it.

The string-key classifier is symbolically traversed from its machine-code
branches and two relative jump tables.  The map visitor and its caller are
checked at the selected branch, data-flow and error blocks; their other input
representations and helper implementations are outside the observation.
"""

import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

SUBJECTS = {
    'outer': 0x336eab0,
    'map_visitor': 0x3aaedd0,
    'key_cursor': 0x34e14e0,
    'key_classifier': 0x3aebac0,
    'packed_classifier': 0x33186c0,
    'owned_classifier': 0x33caeb0,
    'size_string': 0x3a51070,
}

# Contiguous instruction windows were selected from the FDEs.  A hash guards
# the complete selected block, including intervening instructions; extraction
# of tables, labels, branch destinations and call targets still reads ELF bytes.
WINDOWS = [
    ('outer_entry', 0x336eac4, 0x336eae5, 'd45a79d62f5c01557d1600549b528d643b71b0479f9e1ee5e29434904c25ecc5'),
    ('outer_parse_gate', 0x336eae5, 0x336eafb, '0842e3c00cc3c92b85c53fafe5302fda7dea54ef78a5a3d9da452c3c139cb6cd'),
    ('outer_convert', 0x336eafb, 0x336eb30, 'e278e0be03861d643a64829ae18cb27058a3abd510b1836e7f5ba74e1b5c8684'),
    ('outer_success', 0x336eb30, 0x336eb4c, '2cfdd9b26d1384ff2e9fcf82fe11cba2e56fa8a9ded89309e0bf0e7a49942eca'),
    ('outer_error', 0x336eb61, 0x336ebe4, '3f6c656f3c4d228160feac9c1aed55f50e1bf726e7ebbfef5599939fcfebc3ef'),
    ('visitor_entry', 0x3aaede6, 0x3aaee0e, 'e7d1540b27acc42e783e07974b40d8a3352b2448368095ab14ed46be5c868c08'),
    ('visitor_init', 0x3aaee0e, 0x3aaee90, 'fc3e3f077aa2f64bedcce1c6eeded7ba5db54464a6acb6a983d8c3f0c2a3f5c6'),
    ('visitor_key', 0x3aaee90, 0x3aaeeba, '1270a774b848867a0de7badb57495232200082b4a90cfa245338383d3d7aae34'),
    ('size_case', 0x3aaefce, 0x3aaf071, '5537c18087de2fdf0e4c29064c05eb134cd9f0f7d3dc7a6236153747e2c07721'),
    ('case_a', 0x3aaeeba, 0x3aaef62, '6eb4c12aa0e424a515d4d10cadc42202e557598a6a27b582a282b7df78fe23b1'),
    ('case_b', 0x3aaf0d0, 0x3aaf12b, '95264232ca0700ed28dddf5277f27309b771a4644374f42a090a7ac0c36ec963'),
    ('case_r', 0x3aaf071, 0x3aaf0d0, '4b1b0fafae58eed06047469168565a7fcf826930cb5ebccd71d5252f90faa161'),
    ('case_m', 0x3aaef62, 0x3aaefce, '656894b424c002aa4ab94b340aca3735da93f38f53616764e679e3299f822ffe'),
    ('case_t', 0x3aaf12b, 0x3aaf184, 'a311069593df227b2e08bc6e913d9c80aed980ad32eab95d80fc63e671badf7c'),
    ('case_unknown', 0x3aaf184, 0x3aaf1c7, '1b013570be9b8c71942a6c8e4531d01d43268c8c0621c05d91d8ff4a9989f51d'),
    ('visitor_error_sentinel', 0x3aaf2a3, 0x3aaf2be, 'a18edc9855b484b639f221f8080f8e88980786336baf29abf3385399f0b9dcf3'),
    ('dup_a', 0x3aaeeba, 0x3aaeec3, '517fcaa122ecbe844d6edbcd7e9699c97ec9103e98cae3256592fbbed85ce9ed'),
    ('dup_b', 0x3aaf0d0, 0x3aaf0da, '12c5d5d71a3e7d25ece7fa9fc73b6460ecf2aed4e19f03c8a40183dc438dd535'),
    ('dup_s', 0x3aaefce, 0x3aaefe3, '5199b84738d0e62f800fd46c385ed74b998275d239989af4c8bbd19f108f5def'),
    ('dup_r', 0x3aaf071, 0x3aaf07c, '7c1aa4c26449b54e460e8b4cb456562c51c5a98683d944727221bdb17a628199'),
    ('dup_m', 0x3aaef62, 0x3aaef71, 'a6b7b512aa90dd5fddd5d19ed95b22ddaa6aff692ad48d3bcdcf670a69d68f91'),
    ('dup_t', 0x3aaf12b, 0x3aaf134, 'c7481d85e72f3a310bf3e4df06bc79642a3b349c7e25a57756b7ac199f786f05'),
    ('missing_ab', 0x3aaf3b8, 0x3aaf3cc, 'dca49eda2ac10c1d6b904a23a1ed47261310294157ce2f8e9bfa6b76be8dbb62'),
    ('missing_s', 0x3aaf52f, 0x3aaf547, '00335c96d5ca2bef0ac99c00f09849eae60a7b3f66c3170b46c3bf7f55594b0d'),
    ('missing_size_error', 0x3aaf547, 0x3aaf5a3, '50b9c5ed2d4ec14df1b366cfd3decadc2ff4a8885af428cc7139e3cad3ed3360'),
    ('missing_m', 0x3aaf620, 0x3aaf62e, 'a8776df6f8f0494be58740427e8e0748545bc7a0a45e0cdc19e8f6fd2f7bcbc2'),
    ('missing_minutes_error', 0x3aaf725, 0x3aaf777, '24d2a722ef2a1458ab26b91ecc619f6f2455c24fc82491f426874f857bdbe1ca'),
    ('result_pack', 0x3aaf62e, 0x3aaf676, 'b2911b6e61b2c4d9d0e88974c3cd46d9540f8fa145e9ba3d0748e594d891e934'),
    ('key_cursor', 0x34e14e0, 0x34e166c, '36364e4618aa9fb0ce5956287f75f9f9a04c5f749d06c2c1b5fcaa1ae926eb01'),
    ('key_type', 0x3aebacc, 0x3aebb1e, 'de77638220b6489cd2dcd390330f0654c7c4ec34708c234c32df529e7f13414c'),
    ('key_length', 0x3aebb1e, 0x3aebb43, 'ac0303f6d1947969ba907817aa13d02c659082285bb9b268482c5f6f690e6001'),
    ('key_single', 0x3aebb43, 0x3aebb62, '5ba8e18c094be09cf96dc75dc3c590c3cec13e4a951fdca7075bbbdcde43316c'),
    ('key_byte_tree', 0x3aebb62, 0x3aebd4b, 'a7e36932916eec64e5c24965c31a0b0289d554106fdcd6578935f5faac322989'),
    ('packed_key_classifier', 0x33186c0, 0x33187b7, 'ad217a7063f99080df4d418d94e6856a21aeadcdfcab1576fd2ae4c60a70c3e9'),
    ('owned_key_classifier', 0x33caeb0, 0x33cb074, '380451e23e43aa980efe06f5f4728db752793e61c0ae5a776418e107058a9423'),
    ('size_dispatch', 0x3a51083, 0x3a510a2, '9f662890fed533db76421cda854f950953c10185a902f73df3802dc071f0b326'),
    ('size_move_record', 0x3a510a2, 0x3a510b7, '66dc840588b1fafc5872f90b3e43e1b9bcd84a0c76d567f20e88ad5e26c46626'),
    ('size_delegate', 0x3a510b7, 0x3a510db, '6ef28940cd9e71835558a41d1dc039f6d1f30c040173d27909cd4dbe5acf909c'),
    ('size_validate', 0x3a510db, 0x3a51118, '20185eff31d0a102168d78772c3f2cc8a746678d6981a1befc712d767ec642a2'),
    ('size_borrowed', 0x3a51118, 0x3a51163, 'f14a1bee57d93157a367770f4805dfb2422e87bc34e5b7d8cf4b5d507d60d00e'),
    ('size_type_error', 0x3a5117c, 0x3a511a3, '20e7e8a648328b5039df2aa35d2da9c81ec3c20e278d0f8a6676aa1707083cff'),
    ('size_validation_error', 0x3a511a3, 0x3a511dc, '883e106491bd16fe3f45f1d0705a43b49b839ea83e045d3d7993d91da642f5eb'),
    ('size_alloc_failure', 0x3a511dc, 0x3a511e6, '88c06fa2b91f7f40804c3c1111dea3f1e75c7ac28dc737ed7ee1d9eb403ea953'),
    # A previously documented conversion is a dependency, not a subject body.
    ('known_scale_edge', 0x33304d0, 0x33304e5, 'a50d6b424c273ab138bef02ca5dd6cf389b82b8a51d32912caa082bac554f2c7'),
]


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node #94 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        check_digest(data)
        self.data = bytearray(data)
        self.sections = sections(data)
        _, records = eh_frame_records(data, self.sections)
        self.frames = {}
        for row in records:
            if row['start'] in SUBJECTS.values():
                if row['start'] in self.frames:
                    raise ValueError('duplicate selected FDE start')
                self.frames[row['start']] = row
        if set(self.frames) != set(SUBJECTS.values()):
            raise ValueError('selected FDE missing')
        self.relocs = {}
        rela = next(s for s in self.sections if s['name'] == '.rela.dyn')
        if rela['type'] == 8 or rela['size'] % 24:
            raise ValueError('invalid relocation section')
        for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, off)
            if info & 0xffffffff == 8:
                if where in self.relocs:
                    raise ValueError('duplicate relative relocation')
                self.relocs[where] = addend
        for start, fde in self.frames.items():
            sec, _ = self.mapping(start, fde['end'] - start)
            if not sec['flags'] & 4:
                raise ValueError('selected FDE is not file-backed executable code')

    def mapping(self, va, size):
        if size <= 0 or va < 0:
            raise ValueError('invalid address range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('range is not in one file-backed allocated section')
        sec = hits[0]
        off = sec['offset'] + va - sec['address']
        if off + size > len(self.data):
            raise ValueError('range exceeds file')
        return sec, off

    def read(self, va, size):
        _, off = self.mapping(va, size)
        return bytes(self.data[off:off + size])

    def offset(self, va, size=1):
        return self.mapping(va, size)[1]

    def patch(self, va, replacement):
        off = self.offset(va, len(replacement))
        old = bytes(self.data[off:off + len(replacement)])
        self.data[off:off + len(replacement)] = replacement
        return old

    def rel32(self, va, prefix):
        insn = self.read(va, len(prefix) + 4)
        if not insn.startswith(prefix):
            raise ValueError(f'unexpected relative instruction at {va:#x}')
        return va + len(insn) + struct.unpack_from('<i', insn, len(prefix))[0]

    def lea(self, va, prefix=b'\x48\x8d\x05'):
        return self.rel32(va, prefix)

    def call(self, va):
        return self.rel32(va, b'\xe8')

    def slot_call(self, va):
        slot = self.rel32(va, b'\xff\x15')
        if slot not in self.relocs:
            raise ValueError('call slot lacks a relative relocation')
        return slot, self.relocs[slot]

    def branch(self, va):
        first = self.read(va, 2)
        if first[0] == 0x0f and first[1] in (0x84, 0x85, 0x87):
            return self.rel32(va, first)
        if first[0] in (0x74, 0x75):
            return va + 2 + struct.unpack('<b', first[1:])[0]
        raise ValueError(f'not a supported equality branch at {va:#x}')

    def relative_table(self, base, count):
        raw = self.read(base, count * 4)
        return [base + struct.unpack_from('<i', raw, 4 * i)[0] for i in range(count)]


def window_rows(image):
    rows = []
    for name, start, end, expected in WINDOWS:
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError(f'selected instruction window changed: {name}')
        rows.append((name, hex(start), hex(end), hex(image.offset(start, len(raw))),
                     raw.hex(), digest))
    return rows


def _walk_key(image, pc, domains, label=None, compared=None, input_reg=None, *, owned=False):
    """Explore one byte-comparison tree, splitting exact 256-value domains.

    This is a deliberately small instruction recognizer, not a disassembler.
    Unsupported encodings, loops and unbounded accepted languages fail closed.
    """
    if owned:
        lower, upper, done = 0x33caef8, 0x33cb072, 0x33cb049
        mov_label, zero_reg = 0xb0, b'\x31\xc0'
        load_byte, cmp_reg, cmp_first, cmp_offset = (b'\x0f\xb6\x07', b'\x83\xf8',
                                                    b'\x80\x3f', b'\x80\x7f')
    else:
        lower, upper, done = 0x3aebb43, 0x3aebd49, 0x3aebd20
        mov_label, zero_reg = 0xb1, b'\x31\xc9'
        load_byte, cmp_reg, cmp_first, cmp_offset = (b'\x0f\xb6\x08', b'\x83\xf9',
                                                    b'\x80\x38', b'\x80\x78')
    todo = [(pc, tuple(domains), label, compared, input_reg, 0)]
    accepted = []
    while todo:
        pc, domains, label, compared, input_reg, steps = todo.pop()
        if steps > 150 or not lower <= pc <= upper:
            raise ValueError('unexpected key-classifier control flow')
        if pc == done:
            if label is None:
                raise ValueError('key return without a class')
            if label != 6:
                if not 0 <= label < 6 or any(len(x) != 1 for x in domains):
                    raise ValueError('accepted key is not uniquely determined')
                accepted.append((bytes(next(iter(x)) for x in domains), label))
            continue
        raw = image.read(pc, 7)
        new_pc = None
        if raw[0] == mov_label:
            label, new_pc = raw[1], pc + 2
        elif raw[:2] == zero_reg:
            label, compared, new_pc = 0, None, pc + 2
        elif raw[:3] == load_byte:
            input_reg, new_pc = 0, pc + 3
        elif raw[:2] == cmp_reg and input_reg is not None:
            compared, new_pc = (input_reg, raw[2]), pc + 3
        elif raw[:2] == cmp_first:
            compared, new_pc = (0, raw[2]), pc + 3
        elif raw[:2] == cmp_offset:
            compared, new_pc = (raw[2], raw[3]), pc + 4
        elif raw[0] in (0x74, 0x75) or (raw[0] == 0x0f and raw[1] in (0x84, 0x85)):
            if compared is None:
                raise ValueError('conditional key branch without a comparison')
            pos, val = compared
            if pos >= len(domains):
                raise ValueError('key comparison exceeds declared length')
            target = image.branch(pc)
            n = 2 if raw[0] != 0x0f else 6
            jump_on_equal = raw[0] == 0x74 or raw[:2] == b'\x0f\x84'
            for is_equal in (False, True):
                possible = domains[pos] & frozenset([val]) if is_equal else domains[pos] - frozenset([val])
                if possible:
                    ds = list(domains)
                    ds[pos] = possible
                    dest = target if is_equal == jump_on_equal else pc + n
                    todo.append((dest, tuple(ds), label, None, input_reg, steps + 1))
            continue
        elif raw[0] == 0xe9:
            new_pc = image.rel32(pc, b'\xe9')
        elif raw[0] == 0xeb:
            new_pc = pc + 2 + struct.unpack('<b', raw[1:2])[0]
        else:
            raise ValueError(f'unsupported key classifier bytes at {pc:#x}')
        todo.append((new_pc, domains, label, compared, input_reg, steps + 1))
    return accepted


def key_language(image):
    """Return every key accepted by the tag-15 byte-slice branch."""
    # All instruction bytes in these guards have already been checked by the
    # window proof.  The table addresses and every table entry are read here.
    lengths_base = image.lea(0x3aebb33, b'\x48\x8d\x15')
    chars_base = image.lea(0x3aebb52, b'\x48\x8d\x0d')
    max_length = image.read(0x3aebb28, 1)[0] + 1
    char_count = image.read(0x3aebb4b, 1)[0] + 1
    char_bias = struct.unpack('<b', image.read(0x3aebb48, 1))[0]
    lengths = image.relative_table(lengths_base, max_length)
    chars = image.relative_table(chars_base, char_count)
    all_bytes = frozenset(range(256))
    found = []
    for length, target in enumerate(lengths, 1):
        if length == 1:
            if target != 0x3aebb43:
                raise ValueError('one-byte length dispatch changed')
            for value in range(256):
                index = (value + char_bias) & 0xffffffff
                dest = chars[index] if index < char_count else 0x3aebd1e
                found.extend(_walk_key(image, dest, (frozenset([value]),)))
        else:
            found.extend(_walk_key(image, target, [all_bytes] * length))
    found.sort()
    if len({name for name, _ in found}) != len(found):
        raise ValueError('key classifier accepted duplicate paths')
    return found, lengths_base, lengths, chars_base, chars


def owned_key_language(image):
    """Symbolically traverse the tag-14 helper's byte-comparison tree."""
    lengths_base = image.lea(0x33caec9, b'\x48\x8d\x0d')
    chars_base = image.lea(0x33caee8, b'\x48\x8d\x0d')
    max_length = image.read(0x33caec2, 1)[0] + 1
    char_count = image.read(0x33caee1, 1)[0] + 1
    char_bias = struct.unpack('<b', image.read(0x33caede, 1))[0]
    lengths = image.relative_table(lengths_base, max_length)
    chars = image.relative_table(chars_base, char_count)
    all_bytes = frozenset(range(256))
    found = []
    for length, target in enumerate(lengths, 1):
        if length == 1:
            if target != 0x33caed9:
                raise ValueError('owned one-byte length dispatch changed')
            for value in range(256):
                index = (value + char_bias) & 0xffffffff
                dest = chars[index] if index < char_count else 0x33cb047
                found.extend(_walk_key(image, dest, (frozenset([value]),), owned=True))
        else:
            found.extend(_walk_key(image, target, [all_bytes] * length, owned=True))
    found.sort()
    if len({key for key, _ in found}) != len(found):
        raise ValueError('owned classifier accepted duplicate paths')
    return found, lengths_base, lengths, chars_base, chars


def packed_key_language(image):
    """Derive the tag-12/13 helper's length and packed-XOR comparisons.

    The complete selected FDE byte window is checked before this routine.  The
    six multi-byte predicates are fixed-width equality tests: OR of the XORs
    can be zero only if every compared byte matches.  The two overlapping
    four-byte comparisons must also agree on their shared byte.
    """
    lengths_base = image.lea(0x33186d0, b'\x48\x8d\x0d')
    chars_base = image.lea(0x33186ef, b'\x48\x8d\x15')
    max_length = image.read(0x33186c9, 1)[0] + 1
    char_count = image.read(0x33186e8, 1)[0] + 1
    char_bias = struct.unpack('<b', image.read(0x33186e5, 1))[0]
    lengths = image.relative_table(lengths_base, max_length)
    chars = image.relative_table(chars_base, char_count)
    expected = [0x33186e0, 0x3318756, 0x331879c, 0x331879c, 0x33186ff,
                0x331879c, 0x3318766, 0x331879c, 0x3318782, 0x3318730]
    if lengths != expected:
        raise ValueError('packed classifier length dispatch changed')

    def leaf(va):
        raw = image.read(va, 9)
        if raw[:2] == b'\x31\xc9':
            code = 0
        elif raw[0] == 0xb1:
            code = raw[1]
        else:
            raise ValueError('unsupported packed classifier leaf')
        if raw[2:] != bytes.fromhex('884801c60000c3') or code > 6:
            raise ValueError('packed classifier return changed')
        return code

    found = []
    for value in range(256):
        index = (value + char_bias) & 0xffffffff
        dest = chars[index] if index < char_count else 0x331879c
        code = leaf(dest)
        if code != 6:
            found.append((bytes([value]), code))
    asset = image.read(0x3318700, 4) + image.read(0x331870c, 1)
    buy = image.read(0x3318716, 4) + image.read(0x3318722, 1)
    size = image.read(0x3318759, 2)
    minutes_first = image.read(0x3318767, 4)
    minutes_last = image.read(0x331876e, 4)
    if minutes_first[3:] != minutes_last[:1]:
        raise ValueError('packed comparisons disagree at their overlapping byte')
    minutes = minutes_first[:3] + minutes_last
    randomize = image.read(0x3318784, 8) + image.read(0x3318796, 1)
    tail = image.read(0x3318744, 4)
    if tail[2:] != b'\x00\x00':
        raise ValueError('packed 16-bit comparison has nonzero upper bits')
    reduce_only = image.read(0x3318732, 8) + tail[:2]
    for key, va in [(asset, 0x33187a5), (buy, 0x3318727), (size, 0x331875d),
                    (minutes, 0x3318779), (randomize, 0x33187ae),
                    (reduce_only, 0x331874d)]:
        found.append((key, leaf(va)))
    found.sort()
    if len({key for key, _ in found}) != len(found):
        raise ValueError('packed classifier accepted duplicate paths')
    return found, lengths_base, lengths, chars_base, chars


def descriptor(image, classes):
    type_va = image.lea(0x336eac4, b'\x48\x8d\x15')
    fields_va = image.lea(0x336eacb, b'\x4c\x8d\x05')
    type_len = struct.unpack('<I', image.read(0x336ead6, 4))[0]
    count = struct.unpack('<I', image.read(0x336eadc, 4))[0]
    type_name = image.read(type_va, type_len).decode('ascii')
    if type_name != 'TwapWireSerde' or count != 12:
        raise ValueError('unexpected struct descriptor')
    by_key = dict(classes)
    rows = []
    for index in range(count):
        pointer = fields_va + 16 * index
        if pointer not in image.relocs:
            raise ValueError('field descriptor lacks a relative relocation')
        size = struct.unpack('<Q', image.read(pointer + 8, 8))[0]
        if not 1 <= size <= 32:
            raise ValueError('field descriptor length outside scope')
        word = image.read(image.relocs[pointer], size)
        if word not in by_key:
            raise ValueError('descriptor key is not accepted by the classifier')
        rows.append((index, word.decode('ascii'), by_key[word],
                     hex(pointer), hex(image.relocs[pointer]), size))
    if {r[1] for r in rows} != {key.decode('ascii') for key in by_key}:
        raise ValueError('descriptor and classifier key sets differ')
    if any(rows[2*i][2] != i or rows[2*i+1][2] != i for i in range(6)):
        raise ValueError('descriptor aliases do not join the expected cases')
    return type_va, fields_va, rows


def numeric_key_rows(image, table):
    """Recover the direct byte and u64 key-class clamps for internal tags."""
    if table[0] != 0x3aebaea or table[3] != 0x3aebb8d:
        raise ValueError('numeric key arms changed')
    byte_code = image.read(table[0], 22)
    word_code = image.read(table[3], 17)
    if (byte_code[:5] != bytes.fromhex('0fb646013c') or
            byte_code[6] != 0xb9 or byte_code[11:14] != bytes.fromhex('0f42c8')):
        raise ValueError('byte key clamp pattern changed')
    if (word_code[:7] != bytes.fromhex('488b46084883f8') or
            word_code[8] != 0xb9 or word_code[13:17] != bytes.fromhex('480f42c8')):
        raise ValueError('word key clamp pattern changed')
    byte_bound = byte_code[5]
    word_bound = word_code[7]
    byte_fallback = struct.unpack_from('<I', byte_code, 7)[0]
    word_fallback = struct.unpack_from('<I', word_code, 9)[0]
    if not byte_bound == word_bound == byte_fallback == word_fallback == 6:
        raise ValueError('numeric key clamp bound and fallback differ')
    byte_rows = [(1, value, value if value < byte_bound else byte_fallback, 'complete byte domain')
                 for value in range(256)]
    word_samples = list(range(word_bound + 2)) + [(1 << 32) - 1, MASK64]
    word_rows = [(4, value, value if value < word_bound else word_fallback, 'u64 boundary sample')
                 for value in word_samples]
    return byte_rows + word_rows, byte_bound


def error_block(image, va, expected_template):
    field = image.read(image.lea(va), 1).decode('ascii')
    if image.read(va + 7, 14) != bytes.fromhex('488944243048c744243801000000'):
        raise ValueError('error argument is not the selected one-byte field')
    template = image.lea(va + 0x2b, b'\x48\x8d\x3d')
    length = image.read(template, 1)[0]
    text = image.read(template + 1, length).decode('ascii')
    if text != expected_template:
        raise ValueError('unexpected error template')
    call_site = va + 0x37
    if image.read(call_site, 1) != b'\xe8':
        if image.read(call_site, 5) != bytes.fromhex('48894c2420'):
            raise ValueError('unexpected error formatter setup')
        call_site += 5
    if image.call(call_site) != 0x33ddb30:
        raise ValueError('error formatter call changed')
    return field, template, text


def branch_rows(image, cases):
    # The case starts come from the visitor's ELF jump table.  The branch
    # offsets select complete checked instructions in the verified blocks.
    branches = [0x3aaeebd, 0x3aaf0d4, 0x3aaefdd, 0x3aaf076, 0x3aaef6b, 0x3aaf12e]
    rows = []
    for code, branch in enumerate(branches):
        expected_starts = (0x3aaeeba, 0x3aaf0d0, 0x3aaefce,
                           0x3aaf071, 0x3aaef62, 0x3aaf12b)
        if cases[code] != expected_starts[code]:
            raise ValueError('visitor case table no longer points to its guard')
        target = image.branch(branch)
        field, template, _ = error_block(image, target, 'duplicate field `')
        rows.append((code, hex(cases[code]), hex(branch), hex(target), field, hex(template)))
    return rows


def missing_rows(image):
    # Two equality branches enter the missing block; two jump past it when set.
    controls = [(0x3aaf3bc, True), (0x3aaf3c6, False),
                (0x3aaf541, False), (0x3aaf628, True)]
    rows = []
    for branch, jump_if_missing in controls:
        target = image.branch(branch)
        error = target if jump_if_missing else branch + 6
        field, template, _ = error_block(image, error, 'missing field `')
        rows.append((field, hex(branch), hex(target), hex(error), hex(template)))
    return rows


def error_path_rows(image, duplicate, missing):
    """Read the formatter and return-sentinel path at each selected error."""
    if image.read(0x3aaf2b1, 2) != b'\x48\xb9':
        raise ValueError('common error sentinel instruction changed')
    sentinel = struct.unpack('<Q', image.read(0x3aaf2b3, 8))[0]
    if sentinel != 1 << 63:
        raise ValueError('unexpected visitor error sentinel')
    selected = [('duplicate', row[4], int(row[3], 16)) for row in duplicate]
    selected += [('missing', row[0], int(row[3], 16)) for row in missing]
    rows = []
    for kind, field, va in selected:
        call = va + 0x37
        if image.read(call, 1) != b'\xe8':
            call += 5
        formatter = image.call(call)
        if formatter != 0x33ddb30:
            raise ValueError('error formatter edge changed')
        tail = call + 5
        if image.read(tail, 5) == bytes.fromhex('4889442410'):
            if image.rel32(tail + 5, b'\xe9') != 0x3aaf2a3:
                raise ValueError('error does not reach common sentinel')
            end = tail + 10
            route = 'common sentinel'
        else:
            raw = image.read(tail, 22)
            if (raw[:11] != bytes.fromhex('488b4c24184889410848b8') or
                    struct.unpack_from('<Q', raw, 11)[0] != sentinel or
                    raw[19:] != bytes.fromhex('488901')):
                raise ValueError('error does not write the visitor sentinel')
            end = tail + len(raw)
            route = 'direct sentinel'
        raw = image.read(va, end - va)
        rows.append((kind, field, hex(va), hex(end), hex(image.offset(va, len(raw))),
                     hex(call), route, hex(sentinel), raw.hex()))
    return rows, sentinel


def outer_result_rows(image, sentinel):
    """Resolve the guarded outer failure paths and success stores."""
    guard = image.read(0x336eaeb, 2)
    if guard[0] != 0x71:
        raise ValueError('outer visitor guard is not jno')
    ok_target = 0x336eaed + struct.unpack('<b', guard[1:])[0]
    if ok_target != 0x336eafb:
        raise ValueError('visitor success no longer reaches conversion')
    if image.read(0x336eaf5, 3) != bytes.fromhex('c64316'):
        raise ValueError('visitor error output tag store changed')
    visitor_error_tag = image.read(0x336eaf8, 1)[0]
    if image.read(0x336eb29, 1) != b'\x3d':
        raise ValueError('conversion result compare changed')
    conversion_success = struct.unpack('<I', image.read(0x336eb2a, 4))[0]
    if image.branch(0x336eb2e) != 0x336eb61:
        raise ValueError('conversion failure branch changed')
    if image.read(0x336ebdc, 2) != bytes.fromhex('40b5'):
        raise ValueError('conversion error output tag load changed')
    conversion_error_tag = image.read(0x336ebde, 1)[0]
    if visitor_error_tag != conversion_error_tag:
        raise ValueError('outer error paths have different tags')
    if image.rel32(0x336ebdf, b'\xe9') != 0x336eb45:
        raise ValueError('conversion error does not reach tag store')
    if image.read(0x336eb45, 3) != bytes.fromhex('488903'):
        raise ValueError('conversion result word store changed')
    stores = [('s', 0, 8, 0x336eb45)]
    for field, width, va, prefix in [
            ('m', 8, 0x336eb35, '4c8973'), ('a', 4, 0x336eb39, '44897b'),
            ('b', 1, 0x336eb3d, '448863'), ('r', 1, 0x336eb41, '44886b'),
            ('t_or_error_tag', 1, 0x336eb48, '40886b')]:
        raw = image.read(va, 4)
        if raw[:3] != bytes.fromhex(prefix):
            raise ValueError('outer result field store changed')
        stores.append((field, raw[3], width, va))
    outcomes = [
        ('visitor sentinel', hex(sentinel), 0, visitor_error_tag, 'error payload'),
        ('conversion tag differs', hex(conversion_success), 1, conversion_error_tag, 'error payload'),
        ('conversion tag equals', hex(conversion_success), 1, 'field t', 'converted scalar'),
    ]
    return stores, outcomes, conversion_success, visitor_error_tag


def size_reader_paths(image, sentinel, table, default_error):
    """Check selected value-reader rejection and allocation failure branches."""
    if image.read(0x3a510f4, 4) != bytes.fromhex('837c2410'):
        raise ValueError('value validation result compare changed')
    error_status = image.read(0x3a510f8, 1)[0]
    validation_error = image.branch(0x3a510f9)
    allocator_failure = image.branch(0x3a51140)
    if validation_error != 0x3a511a3 or allocator_failure != 0x3a511dc:
        raise ValueError('value failure target changed')
    if image.read(0x3a511cd, 2) != b'\x48\xb8':
        raise ValueError('validation error sentinel instruction changed')
    if struct.unpack('<Q', image.read(0x3a511cf, 8))[0] != sentinel:
        raise ValueError('validation error sentinel changed')
    if image.read(0x3a51194, 2) != b'\x48\xb8':
        raise ValueError('type error sentinel instruction changed')
    if struct.unpack('<Q', image.read(0x3a51196, 8))[0] != sentinel:
        raise ValueError('type error sentinel changed')
    validate_slot, validate_target = image.slot_call(0x3a510ee)
    alloc_slot, alloc_target = image.slot_call(0x3a51137)
    fail_slot, fail_target = image.slot_call(0x3a51126)
    if image.rel32(0x3a511e1, b'\xe9') != 0x3a51123:
        raise ValueError('allocation failure does not reach failure helper')
    if image.read(0x3a5112c, 2) != b'\x0f\x0b':
        raise ValueError('allocation failure is not followed by ud2')
    rows = [
        ('tag 12', hex(table[0]), 'copy three-word record', ''),
        ('tag 13', hex(table[1]), 'length and allocation branches', ''),
        ('tag 14', hex(table[2]), 'delegate record', ''),
        ('tag 15', hex(table[3]), 'check helper status', ''),
        ('all other byte tags', hex(default_error), 'error sentinel', hex(sentinel)),
        ('tag 15 helper status equals', hex(validation_error), 'error sentinel', error_status),
        ('allocation result equals zero', hex(allocator_failure), 'failure helper then ud2', ''),
    ]
    edges = [
        ('size reader validation helper', 0x3a510ee, validate_target, validate_slot),
        ('size reader allocation helper', 0x3a51137, alloc_target, alloc_slot),
        ('size reader failure helper', 0x3a51126, fail_target, fail_slot),
    ]
    return rows, edges


def size_record_flow(image):
    """Follow the successful reader's three words to the outer call."""
    if image.read(0x336eb1b, 3) != bytes.fromhex('4889e6'):
        raise ValueError('outer conversion argument is no longer the visitor result')

    def byte_disp(va, prefix):
        raw = image.read(va, len(prefix) + 1)
        if raw[:-1] != prefix:
            raise ValueError('unexpected byte-displacement record move')
        return raw[-1]

    def dword_disp(va, prefix):
        raw = image.read(va, len(prefix) + 4)
        if raw[:len(prefix)] != prefix:
            raise ValueError('unexpected dword-displacement record move')
        return struct.unpack_from('<I', raw, len(prefix))[0]

    first_in = byte_disp(0x3aaf035, bytes.fromhex('488b4c24'))
    first_slot = byte_disp(0x3aaf047, bytes.fromhex('48894c24'))
    if byte_disp(0x3aaf52f, bytes.fromhex('4c8b7c24')) != first_slot:
        raise ValueError('first record word does not reach the map result')
    if image.read(0x3aaf63e, 3) != bytes.fromhex('4c8938'):
        raise ValueError('first record word output store changed')
    second_in = byte_disp(0x3aaf03a, bytes.fromhex('488b4424'))
    second_slot = dword_disp(0x3aaf03f, bytes.fromhex('48898424'))
    if dword_disp(0x3aaf641, bytes.fromhex('488b8c24')) != second_slot:
        raise ValueError('second record word does not reach the map result')
    second_out = byte_disp(0x3aaf649, bytes.fromhex('488948'))
    third_in = byte_disp(0x3aaf05f, bytes.fromhex('488b4424'))
    third_slot = dword_disp(0x3aaf064, bytes.fromhex('48898424'))
    if dword_disp(0x3aaf64d, bytes.fromhex('488b8c24')) != third_slot:
        raise ValueError('third record word does not reach the map result')
    third_out = byte_disp(0x3aaf655, bytes.fromhex('488948'))
    return [(0, first_in, first_slot, 0), (1, second_in, second_slot, second_out),
            (2, third_in, third_slot, third_out)]


def run_map(fields, classes, missing, duplicate_names):
    """A branch-level model for well-formed map values and normal returns.

    Values are abstracted: a recognized field's value reader succeeds.  Size
    conversion is an external result; neither its bytes nor a target executes.
    """
    seen = set()
    for key in fields:
        code = classes.get(key, 6)
        if code == 6:
            continue
        if code in seen:
            return ('duplicate', duplicate_names[code], 0)
        seen.add(code)
    for code, name in missing:
        if code not in seen:
            return ('missing', name, 0)
    return ('convert', '', 1)


def _csv_bytes(header, rows):
    import io
    buf = io.StringIO(newline='')
    w = csv.writer(buf, delimiter='\t', lineterminator='\n')
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue().encode('utf-8')


def generate(image):
    windows = window_rows(image)
    keys, lengths_base, lengths, chars_base, chars = key_language(image)
    packed_keys, packed_lengths_base, packed_lengths, packed_chars_base, packed_chars = packed_key_language(image)
    owned_keys, owned_lengths_base, owned_lengths, owned_chars_base, owned_chars = owned_key_language(image)
    if packed_keys != keys or owned_keys != keys:
        raise ValueError('string-key representations classify different byte languages')
    type_va, fields_va, desc = descriptor(image, keys)
    case_base = image.lea(0x3aaee70, b'\x48\x8d\x2d')
    if image.read(0x34e1508, 3) != bytes.fromhex('66c707'):
        raise ValueError('key cursor termination store changed')
    end_case = image.read(0x34e150c, 1)[0]
    cases = image.relative_table(case_base, end_case + 1)
    if end_case != len(set(code for _, code in keys)) + 1 or cases[end_case] != 0x3aaf3b8:
        raise ValueError('map end case does not enter required-field checks')
    dup = branch_rows(image, cases)
    missing = missing_rows(image)
    errors, sentinel = error_path_rows(image, dup, missing)
    stores, outcomes, conversion_success, outer_error_tag = outer_result_rows(image, sentinel)
    record_flow = size_record_flow(image)
    canonical = [row[4] for row in dup]
    if [x[0] for x in missing] != [canonical[x] for x in (0, 1, 2, 4)]:
        raise ValueError('missing and duplicate guards disagree')
    aliases = {key: code for key, code in keys}
    packed_aliases = dict(packed_keys)
    owned_aliases = dict(owned_keys)
    if image.call(0x336eae0) != SUBJECTS['map_visitor']:
        raise ValueError('outer visitor call changed')
    if image.call(0x3aaee9b) != SUBJECTS['key_cursor']:
        raise ValueError('visitor key cursor call changed')
    if image.call(0x34e15e7) != SUBJECTS['key_classifier']:
        raise ValueError('key cursor classifier call changed')
    if (image.call(0x3aebb11) != SUBJECTS['packed_classifier'] or
            image.call(0x3aebbb5) != SUBJECTS['packed_classifier'] or
            image.call(0x3aebb83) != SUBJECTS['owned_classifier']):
        raise ValueError('key representation classifier edge changed')
    if image.call(0x3aaf030) != SUBJECTS['size_string']:
        raise ValueError('size string reader call changed')
    if image.rel32(0x3aaf1c2, b'\xe9') != 0x3aaee90:
        raise ValueError('unknown field does not rejoin the map loop')
    slot, conversion = image.slot_call(0x336eb1e)
    scale_slot, scale_target = image.slot_call(0x33304df)
    scale_code = image.read(0x33304d8, 7)
    if scale_code[:3] != b'\x31\xd2\xb9':
        raise ValueError('known scale mode/exponent setters changed')
    exponent = struct.unpack('<I', scale_code[3:])[0]
    if conversion != 0x3330210 or scale_target != 0x3750350 or exponent != 8:
        raise ValueError('known conversion dependency changed')

    key_type_base = image.lea(0x3aebada, b'\x48\x8d\x0d')
    key_type_table = image.relative_table(key_type_base, image.read(0x3aebad3, 1)[0] + 1)
    size_type_base = image.lea(0x3a51092, b'\x48\x8d\x0d')
    size_type_table = image.relative_table(size_type_base, image.read(0x3a5108b, 1)[0] + 1)
    size_type_bias = struct.unpack('<b', image.read(0x3a51088, 1))[0]
    size_error = image.branch(0x3a5108c)
    if key_type_table[14] != 0x3aebb1e:
        raise ValueError('tag-15 key does not enter the byte classifier')
    if key_type_table[11:14] != [0x3aebba3, 0x3aebb00, 0x3aebb69]:
        raise ValueError('key string representation dispatch changed')
    numeric_keys, numeric_bound = numeric_key_rows(image, key_type_table)
    if any(not SUBJECTS['size_string'] <= dest < image.frames[SUBJECTS['size_string']]['end']
           for dest in size_type_table):
        raise ValueError('string dispatch leaves its FDE')
    if size_type_table != [0x3a510a2, 0x3a51118, 0x3a510b7, 0x3a510db]:
        raise ValueError('string dispatch no longer reaches the selected type arms')
    reader_paths, reader_edges = size_reader_paths(image, sentinel, size_type_table, size_error)

    # Case witnesses are predictions from the extracted class and branch
    # tables, under the stated abstract value-reader contract.
    missing_codes = [(canonical.index(row[0]), row[0]) for row in missing]
    presence = []
    for mask in range(1 << len(canonical)):
        inputs = [desc[2 * i][1].encode() for i in range(6) if mask & (1 << i)]
        outcome = run_map(inputs, aliases, missing_codes, canonical)
        presence.append((f'{mask:06b}', ','.join(s.decode() for s in inputs), *outcome))

    permutations = 0
    order_counts = {}
    for n in range(len(canonical) + 1):
        for subset in itertools.combinations(range(len(canonical)), n):
            first_missing = next((name for code, name in missing_codes if code not in subset), None)
            expected = ('convert', '', 1) if first_missing is None else ('missing', first_missing, 0)
            for choices in itertools.product((0, 1), repeat=n):
                chosen = [desc[2 * code + choice][1].encode() for code, choice in zip(subset, choices)]
                for ordered in itertools.permutations(chosen):
                    if run_map(ordered, aliases, missing_codes, canonical) != expected:
                        raise ValueError('field ordering changed model outcome')
                    group = (n, expected[0], expected[1])
                    order_counts[group] = order_counts.get(group, 0) + 1
                    if n == len(canonical):
                        permutations += 1

    duplicate_cases = []
    for i in range(6):
        left, right = desc[2*i][1], desc[2*i+1][1]
        for a, b in ((left, right), (right, left), (left, left), (right, right)):
            result = run_map([a.encode(), b.encode()], aliases, missing_codes, canonical)
            if result != ('duplicate', canonical[i], 0):
                raise ValueError('duplicate alias model disagrees')
            duplicate_cases.append((a, b, *result))

    frames = []
    for name, start in sorted(SUBJECTS.items()):
        fde = image.frames[start]
        raw = image.read(start, fde['end'] - start)
        frames.append({'name': name, 'start_va': hex(start), 'end_va': hex(fde['end']),
                       'file_offset': hex(image.offset(start, len(raw))), 'fde_va': hex(fde['fde']),
                       'cie_va': hex(fde['cie']), 'size': len(raw),
                       'sha256': hashlib.sha256(raw).hexdigest()})
    edges = [
        ('outer to value visitor', 0x336eae0, SUBJECTS['map_visitor'], None),
        ('visitor to key cursor', 0x3aaee9b, SUBJECTS['key_cursor'], None),
        ('key cursor to classifier', 0x34e15e7, SUBJECTS['key_classifier'], None),
        ('key tag 12 to packed classifier', 0x3aebbb5, SUBJECTS['packed_classifier'], None),
        ('key tag 13 to packed classifier', 0x3aebb11, SUBJECTS['packed_classifier'], None),
        ('key tag 14 to owned classifier', 0x3aebb83, SUBJECTS['owned_classifier'], None),
        ('size case to string reader', 0x3aaf030, SUBJECTS['size_string'], None),
        ('outer to existing conversion', 0x336eb1e, conversion, slot),
        ('existing conversion to scaled integer', 0x33304df, scale_target, scale_slot),
    ]
    edges.extend(reader_edges)
    evidence = {
        'target_sha256': SHA256, 'coordinates': 'ELF virtual addresses before load bias',
        'subject_fdes': frames,
        'type_name_va': hex(type_va), 'type_name': image.read(type_va, 13).decode('ascii'),
        'field_descriptor_va': hex(fields_va), 'descriptor_count': len(desc),
        'field_classes': len(set(code for _, code in keys)), 'accepted_byte_keys': len(keys),
        'key_type_table_va': hex(key_type_base),
        'key_type_table': [{'tag': i + 1, 'target_va': hex(t)} for i, t in enumerate(key_type_table)],
        'numeric_key_bound_and_fallback': numeric_bound,
        'string_key_internal_tags': [12, 13, 14, 15],
        'packed_length_table_va': hex(packed_lengths_base),
        'packed_length_targets': [hex(x) for x in packed_lengths],
        'packed_character_table_va': hex(packed_chars_base),
        'packed_character_targets': [hex(x) for x in packed_chars],
        'owned_length_table_va': hex(owned_lengths_base),
        'owned_length_targets': [hex(x) for x in owned_lengths],
        'owned_character_table_va': hex(owned_chars_base),
        'owned_character_targets': [hex(x) for x in owned_chars],
        'length_table_va': hex(lengths_base), 'length_table_targets': [hex(x) for x in lengths],
        'character_table_va': hex(chars_base), 'character_table_targets': [hex(x) for x in chars],
        'map_case_table_va': hex(case_base), 'map_case_targets': [hex(x) for x in cases],
        'map_visitor_sequence_tag': image.read(0x3aaedeb, 1)[0],
        'map_visitor_map_tag': image.read(0x3aaee07, 1)[0], 'map_end_case': end_case,
        'size_type_table_va': hex(size_type_base), 'size_type_targets': [hex(x) for x in size_type_table],
        'size_type_bias': size_type_bias, 'size_error_target_va': hex(size_error),
        'edges': [{'name': n, 'site_va': hex(a), 'target_va': hex(b),
                   'slot_va': None if s is None else hex(s)} for n, a, b, s in edges],
        'known_conversion_mode': 0, 'known_conversion_exponent': exponent,
        'visitor_error_sentinel': hex(sentinel),
        'conversion_success_tag': hex(conversion_success), 'outer_error_tag': outer_error_tag,
        'presence_cases': len(presence), 'presence_conversion_reached': sum(r[-1] for r in presence),
        'all_fields_alias_permutations': permutations, 'duplicate_cases': len(duplicate_cases),
        'all_subset_alias_orderings': sum(order_counts.values()),
        'subset_orderings_reaching_conversion': sum(count for (_, outcome, _), count in order_counts.items()
                                                     if outcome == 'convert'),
        'limits': ['map values and the existing conversion are abstracted',
                   'key tags other than 1, 4 and 12 through 15 are not fully classified', 'no target execution',
                   'no claim about the complete caller or floating-point environment'],
    }
    rows = {
        'evidence.json': (json.dumps(evidence, indent=2, sort_keys=True) + '\n').encode(),
        'windows.tsv': _csv_bytes(('name', 'start_va', 'end_va', 'file_offset', 'bytes_hex', 'sha256'), windows),
        'keys.tsv': _csv_bytes(('descriptor_index', 'key', 'case', 'relocation_va', 'literal_va', 'length'), desc),
        'key-representations.tsv': _csv_bytes(('key', 'tag12_case', 'tag13_case', 'tag14_case', 'tag15_case'),
            [(key.decode('ascii'), packed_aliases[key], packed_aliases[key], owned_aliases[key], code)
             for key, code in keys]),
        'key-numeric-model.tsv': _csv_bytes(('internal_tag', 'unsigned_value', 'case', 'coverage'), numeric_keys),
        'duplicate-branches.tsv': _csv_bytes(('case', 'case_va', 'branch_va', 'error_va', 'field', 'template_va'), dup),
        'missing-branches.tsv': _csv_bytes(('field', 'branch_va', 'branch_target_va', 'error_va', 'template_va'), missing),
        'error-paths.tsv': _csv_bytes(('kind', 'field', 'start_va', 'end_va', 'file_offset', 'formatter_call_va',
                                       'route', 'sentinel', 'bytes_hex'), errors),
        'outer-layout.tsv': _csv_bytes(('field', 'byte_offset', 'width', 'store_va'),
                                       [(field, offset, width, hex(va)) for field, offset, width, va in stores]),
        'size-record-flow.tsv': _csv_bytes(('word', 'reader_result_stack_offset', 'map_slot_stack_offset',
                                             'visitor_result_offset'), record_flow),
        'outer-outcomes.tsv': _csv_bytes(('condition', 'tested_value', 'conversion_calls', 'output_tag', 'word_0'), outcomes),
        'size-reader-paths.tsv': _csv_bytes(('condition', 'target_va', 'effect', 'detail'), reader_paths),
        'presence-model.tsv': _csv_bytes(('mask_case_5_to_0', 'keys', 'outcome', 'field', 'conversion_calls'), presence),
        'order-model.tsv': _csv_bytes(('field_count', 'outcome', 'first_missing_field', 'ordering_count'),
                                      [(n, outcome, field, count) for (n, outcome, field), count
                                       in sorted(order_counts.items())]),
        'duplicates-model.tsv': _csv_bytes(('first_key', 'second_key', 'outcome', 'field', 'conversion_calls'), duplicate_cases),
        'size-type-dispatch.tsv': _csv_bytes(('tag', 'outcome', 'target_va'),
            [(i, 'selected branch', hex(size_type_table[(i + size_type_bias) & 0xffffffff]))
             if ((i + size_type_bias) & 0xffffffff) < len(size_type_table)
             else (i, 'error branch', hex(size_error)) for i in range(256)]),
    }
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    image = Image(TARGET.read_bytes())
    outputs = generate(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(outputs.items()):
        (args.out / name).write_bytes(data)
    print(json.dumps({'files': len(outputs), 'target_sha256': SHA256}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print(f'twap_size_wire94: {error}', file=sys.stderr)
        raise SystemExit(1)
