#!/usr/bin/env python3
"""Extract selected ExchangeMisc codec evidence from node 94 ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected FDE ranges are bounded by the target's FDE records, not by symbols.
# Descriptive names are working labels for this packet.
FUNCTIONS = {
    0x1bab5b0: (0x1bab6fd, 'f354ae179233de0c351f7d2e2925683f91d6b1dc88593ef052af6c7dc3c22436', 'role string reader'),
    0x221a820: (0x221aa7b, 'b26556b324f324294ade330acc7c45ec76f242f4328688a2c8278edd5f3e500f', 'named text writer'),
    0x221aa80: (0x221ab5e, 'c09afbbbae3d03afbb90b7cd91ec32d029495f7b740392853549f63e08ee5d87', 'generic field writer'),
    0x281d230: (0x281d39a, '895812e922118f8ef7a68aef7502ba8e31c74bd5a9ca0e4c198a1a4c58eafcd6', 'role buffer writer'),
    0x281d3a0: (0x281d5fb, '2ffdc474590ab10abf4df9f7ff1dd7fee8fa7a7f728cb87c57419d60c92cd490', 'role wrapper reader'),
    0x1b81580: (0x1b819a1, '0ed05002045bac1eab20f41695e996bc6fe32cd6aef1197aa712076863c7a863', 'entry sequence reader'),
    0x1baac30: (0x1baaf66, '11809539f9d7f2d6a96d8fbd98192610132f0239fbc2014cd62c2721af0046a5', 'value pair reader'),
    0x1834eb0: (0x1835d3d, '37d2d06ce82aa7e0f7084ef3e457643f5ce2363bc831580da3b7fcfe1f75848f', 'binary entry reader'),
    0x1961a70: (0x1962443, '62266223533daac652e1c0ab4e2ae9cb43b67719c423fd7cfe927dffde3cc54d', 'binary value reader'),
    0x1689950: (0x1689b36, 'd8a8132184973c00372c50678be51ea9ac9ceadb3814439e1f7fc66fb0e60a02', 'binary role wrapper'),
    0x1a38ab0: (0x1a391d0, '3a50783c1ba75fc2a8c044511f734e58c0ea74098506ae122e06778b37ff452c', 'binary role string reader'),
    0x280a770: (0x280a89c, '0e78373e399ff994cdfdda387876b27e0bbb7eadbc4842a7df1379f937ae6cca', 'binary role classifier'),
    0x19f87a0: (0x19f9a47, '8175232acf3e5a27646a6977e1a35beeb7c1379faae66eeaa195c9601a7f7c96', 'binary outer struct reader'),
    0x197ab70: (0x197b309, 'd7b245196cae8b158547325567bf419f904bebd8e77a69effb44ba11f8c30ea4', 'binary collection reader'),
    0x26563e0: (0x2656660, '8e076ad2665ae1f82c88c2c149f3df87427cedc30c9b3900072e4565763a57f1', 'binary map collection reader'),
    0x2680ef0: (0x268109b, '82b9e58d4186e2e7f7712314300a76765ee0407ced34f9b050a144ebea0e7c1d', 'binary sequence collection reader'),
    0x1de7260: (0x1de7cad, '3029ce9d9c08a36137c182484552a27a3d95056b534d7e74f43f78cab129406a', 'entry pair writer'),
    0x1e0e570: (0x1e0e6ac, '31a9273cd6a1234ae5c26220586bc2b10f4e767b07e028f27b4af75ae3b45a36', 'value integer adapter'),
    0x25abd40: (0x25ac0c5, 'a84ad1516884c44ebe0720332b3078543f62644d1b973adc484f40d18d0733b7', 'unsigned integer buffer writer'),
    0x1e35e60: (0x1e360eb, 'de21c765baeb7fb41f1576e18615e90076b46b13c68cb93f9332e92f3bfd724c', 'entry sequence writer'),
    0x256b9c0: (0x256bcb0, 'f9ac69e79f427bfaf3cbb11fdd3420fc4c8963eb022b2141bcc9f2ecc9f928e9', 'ordered tree collector'),
    0x25e84c0: (0x25e8589, '5759413591c347b07f8bc8c100a68f7bca3e47864e7e6393f2f2c4a93e75bc0e', 'collection writer'),
    0x2601410: (0x2601c9b, '43139d0dd746b853714cccd91cb028bcfca6d485b276eba23b2ba9740e396c39', 'collection reader'),
    0x265b560: (0x265b6e1, '5ceb4c1bf26f41bf1548ab37c3b161c18eeae4c25a49f2a00a7375fd8dac4409', 'sequence collection reader'),
    0x284daa0: (0x284dd24, 'a0e935803ae78c3998d54c45713acdd3c397f725e541aaa5e203e5015989cfa2', 'tree insertion and key order'),
}

# Complete fixed windows; the binary hash and each selected full FDE digest are
# verified before interpreting the selected instructions.
WINDOWS = [
    ('builder_capture', 0x2756959, 14),
    ('builder_job_pair', 0x2756f5d, 21),
    ('closure_thunk', 0x21e3210, 14),
    ('hash_config_and_call', 0x2815bd5, 32),
    ('struct_mode_and_arity', 0x221aa9e, 33),
    ('struct_array_arity', 0x221aad0, 26),
    ('struct_field_and_call', 0x221aaea, 53),
    ('struct_result_propagation', 0x221ab19, 54),
    ('json_named_field', 0x221a869, 34),
    ('collection_empty_or_nonempty', 0x25e84cf, 67),
    ('collection_calls', 0x25e851f, 33),
    ('collector_size_overflow', 0x256b9c8, 52),
    ('collector_record_offsets', 0x256ba60, 48),
    ('collector_result', 0x256bc4b, 26),
    ('insert_key_comparison', 0x284db1c, 51),
    ('insert_duplicate_overwrite', 0x284db82, 31),
    ('sequence_length_and_mode', 0x1e35e79, 59),
    ('sequence_header', 0x1e35ebc, 40),
    ('sequence_first_pair', 0x1e35f0e, 55),
    ('sequence_loop', 0x1e36013, 87),
    ('pair_direct_header', 0x1de7408, 34),
    ('pair_key_call', 0x1de7451, 35),
    ('nested_pair_direct_header', 0x1de75b1, 32),
    ('nested_value_and_role_calls', 0x1de7604, 36),
    ('nested_role_call', 0x1de76eb, 38),
    ('integer_adapter', 0x1e0e63f, 28),
    ('integer_small_branches', 0x25abd48, 30),
    ('integer_16_branch', 0x25abd7f, 14),
    ('integer_16_marker', 0x25abd98, 27),
    ('integer_32_branch', 0x25abdd7, 40),
    ('integer_32_marker', 0x25abdf4, 35),
    ('integer_8_marker', 0x25abe40, 37),
    ('integer_64_marker', 0x25abe86, 36),
    ('role_buffer_branch', 0x281d234, 60),
    ('role_buffer_else', 0x281d27c, 67),
    ('binary_reader_key_match', 0x19f8db9, 45),
    ('binary_reader_key_match_short', 0x19f8e2b, 31),
    ('binary_reader_duplicate_check', 0x19f919d, 55),
    ('binary_reader_missing_diagnostic', 0x19f9251, 79),
    ('binary_reader_duplicate_diagnostic', 0x19f9770, 69),
    ('binary_reader_type_descriptor', 0x19f94e8, 27),
    ('binary_reader_sequence', 0x19f938b, 74),
    ('binary_collection_map', 0x197af04, 78),
    ('binary_collection_sequence', 0x197b048, 80),
    ('binary_collection_map_duplicate', 0x26564e4, 91),
    ('binary_collection_sequence_duplicate', 0x2680fa1, 95),
    ('binary_map_value_reader_call', 0x2656480, 36),
    ('binary_sequence_entry_reader_call', 0x2680f4d, 37),
    ('binary_entry_value_call', 0x18355b8, 37),
    ('binary_value_role_call', 0x1961f7b, 41),
    ('binary_role_wrapper_call', 0x1689a80, 29),
    ('binary_role_reader_classifier_call', 0x1a38bc6, 31),
    ('binary_role_classifier', 0x280a77a, 139),
    ('collection_map_value', 0x26016a7, 36),
    ('collection_duplicate_key', 0x2601715, 83),
    ('collection_sequence_duplicate_key', 0x265b602, 85),
    ('entry_reader_value', 0x1b817fd, 24),
    ('value_reader_elements', 0x1baacdc, 40),
    ('value_reader_role', 0x1baadfd, 27),
    ('role_reader_string_calls', 0x281d40e, 37),
    ('role_string_comparisons', 0x1bab66a, 74),
    ('role_string_error', 0x1bab6cc, 36),
]
CALLS = [
    (0x2815bf0, 0x221aa80), (0x221aaaf, 0x25a8f80),
    (0x221aadb, 0x25a9bd0), (0x221ab00, 0x25aa7f0),
    (0x221ab14, 0x25e84c0), (0x221a8c6, 0x25dfe40),
    (0x25e852a, 0x256b9c0), (0x25e8538, 0x1e35e60),
    (0x1e35ec7, 0x25a9bd0), (0x1e35f1f, 0x1de7260),
    (0x1e3604e, 0x1de7260), (0x1de7321, 0x1e0d0a0),
    (0x1de745b, 0x1e0d6c0), (0x1de7614, 0x1e0e570),
    (0x1de76fa, 0x281d230), (0x1de77d4, 0x1e0ee20),
    (0x1e0e645, 0x25abd40),
    (0x1de78ae, 0x25aa7f0), (0x1de7954, 0x25aa7f0),
    (0x19f91ca, 0x197ab70), (0x19f93c7, 0x197ab70),
    (0x197af46, 0x26563e0), (0x197b08a, 0x2680ef0),
    (0x26564e4, 0x284daa0), (0x2680fa1, 0x284daa0),
    (0x265648a, 0x1961a70), (0x2680f55, 0x1834eb0),
    (0x18355c2, 0x1961a70), (0x1961f88, 0x1689950),
    (0x1689a8a, 0x1a38ab0), (0x1a38bcf, 0x280a770),
    (0x1a38d0c, 0x280a770),
    (0x26014eb, 0x265b560), (0x26016af, 0x1baac30),
    (0x2601707, 0x284daa0), (0x265b602, 0x284daa0),
    (0x265b5b6, 0x1b81580), (0x1b81802, 0x1baac30),
    (0x1baace6, 0x1b799a0), (0x1baae02, 0x281d3a0),
    (0x281d417, 0x1bab5b0), (0x281d46b, 0x1bab5b0),
]
BRANCHES = [
    (0x221aaa2, 'je', 0x221aad0), (0x221aabc, 'je', 0x221aaea),
    (0x221aae8, 'jne', 0x221aabe), (0x221aaef, 'jne', 0x221ab0b),
    (0x221ab09, 'jne', 0x221ab28), (0x221ab21, 'jne', 0x221ab36),
    (0x25e84d5, 'je', 0x25e850c), (0x1e35eff, 'je', 0x1e36013),
    (0x1e35f3a, 'je', 0x1e36013), (0x1e3605b, 'jne', 0x1e35f40),
    (0x1e36068, 'jne', 0x1e36040), (0x281d23a, 'jne', 0x281d27c),
    (0x19f91a2, 'jne', 0x19f8e46), (0x19f91b0, 'jne', 0x19f9770),
    (0x19f922e, 'je', 0x19f9251), (0x19f8e40, 'je', 0x19f91a8),
    (0x26564ee, 'je', 0x2656420), (0x2680fab, 'je', 0x2680f40),
    (0x265b60a, 'je', 0x265b5b0),
    (0x1bab673, 'jne', 0x1bab695), (0x1bab68f, 'jne', 0x1bab6cc),
    (0x1bab699, 'jne', 0x1bab6cc), (0x1bab6a7, 'jne', 0x1bab6cc),
]

class Image:
    def __init__(self, data, verify_digest=True):
        if verify_digest and hashlib.sha256(data).hexdigest() != DIGEST:
            raise ValueError('node 94 SHA-256 mismatch')
        self.data = data
        self.sections = sections(data)

    def read(self, va, size, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid address or length')
        rows = [s for s in self.sections if s['type'] != 8 and
                (not executable or s['flags'] & 4) and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(rows) != 1:
            raise ValueError('address is not uniquely file backed')
        s = rows[0]
        off = s['offset'] + va - s['address']
        if off + size > len(self.data):
            raise ValueError('file range truncated')
        return self.data[off:off + size]

    def offset(self, va, size):
        self.read(va, size)
        s = next(s for s in self.sections if s['type'] != 8 and
                 s['address'] <= va and va + size <= s['address'] + s['size'])
        return s['offset'] + va - s['address']


def direct_call(img, va):
    b = img.read(va, 5, True)
    if b[0] != 0xe8:
        raise ValueError('expected direct call')
    return va + 5 + struct.unpack_from('<i', b, 1)[0]


def branch(img, va):
    b = img.read(va, 2, True)
    if b[0] in (0x74, 0x75):
        return ('je' if b[0] == 0x74 else 'jne', va + 2 + struct.unpack('<b', b[1:])[0])
    b = img.read(va, 6, True)
    if b[:2] not in (b'\x0f\x84', b'\x0f\x85'):
        raise ValueError('expected conditional branch')
    return ('je' if b[1] == 0x84 else 'jne', va + 6 + struct.unpack_from('<i', b, 2)[0])


def rip_reference(img, va, prefix):
    raw = img.read(va, len(prefix) + 4, True)
    if not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def role_names(img):
    # Parser uses separate RIP-relative comparison of bytes 0..7 and byte 8.
    technical = rip_reference(img, 0x1bab678, b'\x48\x33\x05')
    tail = rip_reference(img, 0x1bab683, b'\x32\x0d')
    treasury = rip_reference(img, 0x1bab6a0, b'\x48\x3b\x0d')
    if tail != technical + 8:
        raise ValueError('role literal fragments are not adjacent')
    names = [img.read(technical, 9), img.read(treasury, 8)]
    if names != [b'technical', b'treasury']:
        raise ValueError('role literals changed')
    # Literal match arms return 0 via xor eax,eax and 1 via mov al,1.
    if img.read(0x1bab691, 2, True) != b'\x31\xc0':
        raise ValueError('technical tag instruction changed')
    tag_one = img.read(0x1bab69e, 2, True)
    if tag_one[0] != 0xb0:
        raise ValueError('treasury tag instruction changed')
    tag_zero = tag_one[1] ^ tag_one[1]
    # Buffer writer directly embeds the two labels and their short-string tags.
    first = img.read(0x281d268, 10, True)
    second = img.read(0x281d2a8, 10, True)
    tail_byte = img.read(0x281d2b6, 5, True)
    markers = [img.read(0x281d290, 4, True), img.read(0x281d250, 4, True)]
    if (first[:2] != b'\x48\xb9' or second[:2] != b'\x48\xb9' or
            tail_byte[:4] != b'\xc6\x44\x37\x08' or
            any(m[:3] != b'\xc6\x04\x37' for m in markers)):
        raise ValueError('role writer instructions changed')
    labels = [second[2:] + tail_byte[4:], first[2:]]
    if labels != names:
        raise ValueError('role reader and writer literals differ')
    if (img.read(0x281d237, 3, True) != bytes.fromhex('803e01') or
            branch(img, 0x281d23a) != ('jne', 0x281d27c) or
            [m[3] for m in markers] != [0xa0 | len(name) for name in names]):
        raise ValueError('role writer branch or marker changed')
    return [(tag_zero, technical, names[0], markers[0][3]),
            (tag_one[1], treasury, names[1], markers[1][3])]


def field_name(img):
    first = rip_reference(img, 0x19f8dcb, b'\x66\x33\x0d')
    tail = rip_reference(img, 0x19f8dd6, b'\x32\x05')
    if tail != first + 2 or img.read(first, 3) != b'uta':
        raise ValueError('field literal mismatch')
    writer = rip_reference(img, 0x221aaf1, b'\x48\x8d\x35')
    diagnostic = rip_reference(img, 0x19f9251, b'\x48\x8d\x05')
    duplicate = rip_reference(img, 0x19f9770, b'\x48\x8d\x05')
    if img.read(writer, 3) != b'uta' or img.read(diagnostic, 3) != b'uta' or diagnostic != duplicate:
        raise ValueError('field use mismatch')
    return first, img.read(first, 3), writer, diagnostic


def relative_addend(img, slot):
    rel = next(s for s in img.sections if s['name'] == '.rela.dyn')
    raw = img.data[rel['offset']:rel['offset'] + rel['size']]
    if len(raw) != rel['size'] or len(raw) % 24:
        raise ValueError('invalid relocation section')
    rows = [(info, add) for off, info, add in struct.iter_unpack('<QQq', raw) if off == slot]
    if len(rows) != 1 or rows[0][0] != 8:
        raise ValueError('relative relocation mismatch')
    return rows[0][1]


def type_descriptor(img):
    descriptor = rip_reference(img, 0x19f94e8, b'\x48\x8d\x15')
    target = relative_addend(img, descriptor)
    size = struct.unpack('<Q', img.read(descriptor + 8, 8))[0]
    if size > 80:
        raise ValueError('invalid type description length')
    text = img.read(target, size).decode('ascii')
    if text != 'struct ExchangeMisc with 1 element':
        raise ValueError('struct diagnostic changed')
    return {'descriptor_va': hex(descriptor), 'literal_va': hex(target),
            'length': size, 'ascii': text}


def capture_context(img):
    capture = img.read(0x275695c, 11, True)
    if capture[:3] != b'\x48\x8d\x85' or capture[7:] != b'\x49\x89\x45\x00':
        raise ValueError('capture instructions changed')
    field_offset = struct.unpack_from('<I', capture, 3)[0]
    pair = img.read(0x2756f5d, 21, True)
    if pair[:7] != bytes.fromhex('4c89ab50020000') or pair[14:] != bytes.fromhex('48898b58020000'):
        raise ValueError('job pair instructions changed')
    vtable = rip_reference(img, 0x2756f64, b'\x48\x8d\x0d')
    row_offset = struct.unpack_from('<I', pair, 3)[0]
    drop, size, align, method = struct.unpack('<QQQQ', img.read(vtable, 32))
    if (drop, size, align, method) != (0, 8, 8, 0):
        raise ValueError('unexpected job table')
    try:
        thunk = relative_addend(img, vtable + 24)
    except ValueError as error:
        raise ValueError('job table relocation mismatch') from error
    stub = img.read(thunk, 14, True)
    if stub[:4] != bytes.fromhex('534889fb') or stub[9:] != bytes.fromhex('4889d85bc3'):
        raise ValueError('job thunk mismatch')
    body = direct_call(img, thunk + 4)
    config = img.read(0x2815bd5, 13, True)
    if config[:4] != bytes.fromhex('c7442408') or config[8:12] != bytes.fromhex('c644240c'):
        raise ValueError('writer configuration changed')
    if (field_offset, row_offset, thunk, body) != (0x3a70, 0x250, 0x21e3210, 0x2815ba0):
        raise ValueError('job context changed')
    return {'capture_site_va': '0x275695c', 'state_offset': field_offset,
            'job_pointer_offset': row_offset, 'vtable_va': hex(vtable),
            'vtable_size': size, 'vtable_align': align, 'method_thunk_va': hex(thunk),
            'closure_body_va': hex(body), 'writer_config_hex': config[4:8].hex(),
            'writer_flag_byte': config[12]}


def duplicate_key(img, va):
    # movabs rcx, suffix ; store [rax+5] ; movabs rcx, prefix.
    raw = img.read(va, 27, True)
    if raw[:2] != b'\x48\xb9' or raw[10:14] != b'\x48\x89\x48\x05' or raw[14:16] != b'\x48\xb9':
        raise ValueError('unexpected duplicate diagnostic')
    result = raw[16:24] + raw[2:10][3:]
    if result != b'duplicate key':
        raise ValueError('duplicate diagnostic mismatch')
    return result.decode('ascii')


def compare_slot(img):
    """Resolve the insertion comparison slot to its dynamic symbol."""
    ins = img.read(0x284db28, 6, True)
    if ins[:2] != b'\xff\x15':
        raise ValueError('comparison is not an indirect call')
    slot = 0x284db2e + struct.unpack_from('<i', ins, 2)[0]
    def section(name, kind):
        found = [s for s in img.sections if s['name'] == name and s['type'] == kind]
        if len(found) != 1:
            raise ValueError('dynamic section missing or ambiguous')
        return found[0]
    rel, sym, strings = (section('.rela.dyn', 4), section('.dynsym', 11), section('.dynstr', 3))
    shoff = struct.unpack_from('<Q', img.data, 40)[0]
    entsize = struct.unpack_from('<H', img.data, 58)[0]
    ri, si, ti = (img.sections.index(row) for row in (rel, sym, strings))
    if (struct.unpack_from('<I', img.data, shoff + ri * entsize + 40)[0] != si or
            struct.unpack_from('<I', img.data, shoff + si * entsize + 40)[0] != ti or
            struct.unpack_from('<Q', img.data, shoff + ri * entsize + 56)[0] != 24 or
            struct.unpack_from('<Q', img.data, shoff + si * entsize + 56)[0] != 24 or
            rel['size'] % 24 or sym['size'] % 24):
        raise ValueError('dynamic section links or sizes changed')
    matches = []
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', img.data, off)
        if target == slot:
            matches.append((off, info, addend))
    if len(matches) != 1:
        raise ValueError('compare relocation not unique')
    off, info, addend = matches[0]
    index, kind = info >> 32, info & 0xffffffff
    if kind != 6 or addend != 0 or index >= sym['size'] // 24:
        raise ValueError('unexpected compare relocation')
    pos = struct.unpack_from('<I', img.data, sym['offset'] + index * 24)[0]
    if pos >= strings['size']:
        raise ValueError('symbol name outside string table')
    start = strings['offset'] + pos
    end = img.data.find(b'\0', start, strings['offset'] + strings['size'])
    if end < 0:
        raise ValueError('unterminated symbol name')
    name = img.data[start:end].decode('ascii')
    length_ins = img.read(0x284db20, 5, True)
    if length_ins[0] != 0xba or name != 'memcmp':
        raise ValueError('comparison identity changed')
    return {'slot_va': hex(slot), 'relocation_file_offset': hex(off),
            'symbol_index': index, 'symbol': name,
            'key_length': struct.unpack_from('<I', length_ins, 1)[0]}


def integer_rules(img):
    first = img.read(0x25abd48, 18, True)
    second = img.read(0x25abd7f, 9, True)
    high = img.read(0x25abdd7, 7, True)
    if (first[:3] != bytes.fromhex('4881fa') or
            first[7:13] != bytes.fromhex('732e84d20f88') or
            second[:3] != bytes.fromhex('4881fa') or high != bytes.fromhex('4889d148c1e920')):
        raise ValueError('integer threshold instructions changed')
    limits = [128, struct.unpack_from('<I', first, 3)[0],
              struct.unpack_from('<I', second, 3)[0], 1 << high[6]]
    markers = []
    for site, prefix in [(0x25abe44, '42c60409'), (0x25abd9c, '42c6040f'),
                         (0x25abdf8, '42c6040f'), (0x25abe8a, '42c6040f')]:
        raw = img.read(site, 5, True)
        if raw[:4] != bytes.fromhex(prefix):
            raise ValueError('integer marker instruction changed')
        markers.append(raw[4])
    if img.read(0x25abda8, 4, True) != bytes.fromhex('66c1c208') or \
       img.read(0x25abe04, 2, True) != bytes.fromhex('0fca') or \
       img.read(0x25abe96, 3, True) != bytes.fromhex('480fca'):
        raise ValueError('integer byte order instructions changed')
    if limits != [128, 256, 65536, 1 << 32] or markers != [0xcc, 0xcd, 0xce, 0xcf]:
        raise ValueError('integer rules changed')
    return {'exclusive_limits': limits, 'markers': markers, 'payload_byteorder': 'big'}


def integer_model(value, rules):
    """Model the selected writer's ordinary value branches; not node execution."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('value is outside unsigned 64-bit range')
    limits = rules['exclusive_limits']
    if value < limits[0]:
        return bytes([value])
    for limit, marker, width in zip(limits[1:], rules['markers'], (1, 2, 4)):
        if value < limit:
            return bytes([marker]) + value.to_bytes(width, 'big')
    return bytes([rules['markers'][3]]) + value.to_bytes(8, 'big')


def binary_role_checks(img, roles):
    """Read the binary classifier's length, byte comparisons and return tags."""
    decoded = []
    for va, count, tag in [(0x280a780, 9, 0), (0x280a7c8, 8, 1)]:
        cursor = va
        values = []
        for index in range(count):
            if index == 0:
                raw = img.read(cursor, 3, True)
                if raw[:2] != bytes.fromhex('803e'):
                    raise ValueError('role classifier first byte changed')
                values.append(raw[2])
                cursor += 3
            else:
                raw = img.read(cursor, 4, True)
                if raw[:2] != bytes.fromhex('807e') or raw[2] != index:
                    raise ValueError('role classifier indexed byte changed')
                values.append(raw[3])
                cursor += 4
            if branch(img, cursor) != ('jne', 0x280a804):
                raise ValueError('role classifier rejection changed')
            cursor += 2
        result = img.read(cursor, 5, True)
        if result[:4] != bytes.fromhex('66c70009') or result[4] != tag:
            raise ValueError('role classifier tag changed')
        decoded.append({'name': bytes(values).decode('ascii'), 'tag': result[4],
                        'first_cmp_va': hex(va), 'failure_va': '0x280a804'})
    if [(x['tag'], x['name']) for x in decoded] != [(t, n.decode('ascii')) for t, _, n, _ in roles]:
        raise ValueError('binary and text role classifiers differ')
    return decoded


def extract(data, verify_digest=True):
    img = Image(data, verify_digest)
    # Fail on literal changes separately, including in test images whose top-level
    # digest check is intentionally disabled.
    field_va, key, writer_field_va, diagnostic_field_va = field_name(img)
    roles = role_names(img)
    _, records = eh_frame_records(data, img.sections)
    _, index = unwind_index(data)
    by_start = {r['start']: r for r in records}
    starts = {r['start']: r['fde'] for r in index}
    functions = []
    for start in sorted(FUNCTIONS):
        end, expected, label = FUNCTIONS[start]
        if start not in starts or start not in by_start or by_start[start]['end'] != end or starts[start] != by_start[start]['fde']:
            raise ValueError('FDE extent mismatch')
        raw = img.read(start, end - start, True)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError('FDE bytes changed')
        functions.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'size': end - start, 'file_offset': hex(img.offset(start, end-start)),
                          'fde_va': hex(by_start[start]['fde']), 'body_sha256': digest})
    windows = [{'label': name, 'start_va': hex(va), 'file_offset': hex(img.offset(va, size)),
                'size': size, 'bytes_hex': img.read(va, size, True).hex()}
               for name, va, size in WINDOWS]
    calls = []
    for va, target in CALLS:
        actual = direct_call(img, va)
        if actual != target:
            raise ValueError('direct call target changed')
        calls.append({'site_va': hex(va), 'target_va': hex(actual),
                      'instruction_hex': img.read(va, 5, True).hex()})
    branches = []
    for va, op, target in BRANCHES:
        if branch(img, va) != (op, target):
            raise ValueError('branch target changed')
        size = 2 if img.read(va, 1, True)[0] in (0x74, 0x75) else 6
        branches.append({'site_va': hex(va), 'operation': op, 'target_va': hex(target),
                         'instruction_hex': img.read(va, size, True).hex()})
    diag = [duplicate_key(img, va) for va in (0x2656508, 0x2680fc1, 0x2601729, 0x265b620)]
    descriptor = type_descriptor(img)
    int_rules = integer_rules(img)
    small, one_byte, two_bytes, four_bytes = int_rules['exclusive_limits']
    boundaries = [0, small - 1, small, one_byte - 1, one_byte,
                  two_bytes - 1, two_bytes, four_bytes - 1, four_bytes, (1 << 64) - 1]
    int_examples = [{'value': str(n), 'model_hex': integer_model(n, int_rules).hex()} for n in boundaries]
    return {'target_sha256': hashlib.sha256(data).hexdigest(),
            'functions': functions, 'windows': windows, 'direct_calls': calls,
            'conditional_branches': branches,
            'field': {'reader_va': hex(field_va), 'writer_va': hex(writer_field_va),
                      'diagnostic_va': hex(diagnostic_field_va), 'ascii': key.decode('ascii')},
            'hash_capture_context': capture_context(img),
            'tree_key_comparison': compare_slot(img),
            'integer_rules': int_rules, 'integer_boundary_model': int_examples,
            'binary_role_classifier': binary_role_checks(img, roles),
            'struct_diagnostic': descriptor,
            'role_variants': [{'parser_tag': tag, 'literal_va': hex(va), 'name': name.decode('ascii'),
                               'buffer_marker': marker}
                              for tag, va, name, marker in roles],
            'duplicate_key_diagnostics': diag}


def tsv(rows, columns):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    record = extract(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (args.out / 'functions.tsv').write_text(tsv(record['functions'],
        ['label', 'start_va', 'end_va_exclusive', 'size', 'file_offset', 'fde_va', 'body_sha256']), encoding='utf-8')
    (args.out / 'windows.tsv').write_text(tsv(record['windows'],
        ['label', 'start_va', 'file_offset', 'size', 'bytes_hex']), encoding='utf-8')


if __name__ == '__main__':
    main()
