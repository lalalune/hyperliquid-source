#!/usr/bin/env python3
"""Extract node #94 trigger tuple quantity evidence without disassembly or execution."""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SENTINEL = 1 << 63
TOP = (1 << 64) - 1
SUCCESS = 0x186
CONDITIONS = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')

# FDEs are selected ranges, not a function census or source-level boundary claim.
FUNCTIONS = (
    ('order_type_entry_a', 0x1ee0f10, 0x1ee102a, 0x10553f4, '9cd58ffde2f58e39bd2cd0b1c8b77479dd7dc172a6a7d40cca6226b5fb2128f9'),
    ('order_type_entry_b', 0x34f7670, 0x34f778a, 0x117f3e8, '7175b2251322a5bbbb2dff0f6a83ef3a665f6b5dc30bd664e20e7b9f64e2bc2f'),
    ('parent_variant_a', 0x20867e0, 0x2086b73, 0x107b770, '87c78293bb988bb614235aa54e87e8fce215c8d42d965eadb700f6c1326d60fe'),
    ('parent_variant_b', 0x3a3b920, 0x3a3bcb3, 0x11cdb50, '727696ef7c42685fcc0bb993d538d53062ba655348989dc8dc64757ba6293246'),
    ('variant_classifier', 0x21d61c0, 0x21d64ce, 0x108df8c, 'a1055066cdd7b9325984f9d48d35ad410106e6fe1c85571228f51ee2b65382d9'),
    ('tuple_reader_a', 0x20b3c70, 0x20b473b, 0x107e0e8, '89d6433aa9f7d6c13eb410ed4d33b898ca215db262839e71bddddb34c4ea763a'),
    ('tuple_reader_b', 0x3ad6590, 0x3ad705b, 0x11d2a74, '33909d5f3d4c3d7c9113270d96348ee372cd7a89e2ec5bfd0171ae75b00b02f8'),
    ('outer_adapter_a', 0x2198670, 0x21987ba, 0xd30348, '7c186da76e5c062c10d4a2ff283dc89d03f5578252adeffafb7265d01593fdfb'),
    ('outer_adapter_b', 0x3b311d0, 0x3b3131a, 0xe936b4, 'a80253054a76cc3d5c425453daa8f38ad2bae080e6512c276049190569898ed9'),
    ('first_element_reader', 0x1ee4160, 0x1ee4286, 0x1055a68, 'd388307048d0622c2b02acd731dde2cf51c76ac95ed4d3c53f528b40d555163e'),
    ('map_key_iterator', 0x1ec9db0, 0x1ec9f3c, 0x105282c, '8474d69b23d41a76515b90344412220cc1b8574d9b92cad8c2a9eb2028c8175a'),
    ('map_key_classifier', 0x2165dc0, 0x2166066, 0xd2eac4, '385abe0a656f2e5c037f598735a7c5573007db2be029a872dff9ca6369b103a1'),
)

# Exact byte anchors; lengths may stop within the next instruction. No operands are masked.
ANCHORS = (
 ('entry_presence',0x1ee0f15,'48833e00741a488b4608483b46187410488d482048894e080fb60880f916750dc64709034889f84883c4505bc3'),
 ('entry_counter',0x1ee0f57,'488b46204883f8ff0f849d0000004889fb48ffc048894620'),
 ('entry_descriptor_lengths',0x1ee0fbf,'b90d00000041b902000000'),
 ('entry_result',0x1ee0fcf,'807c2429037518488b4424204889df488903c64309044889f84883c4505b'),
 ('entry_success',0x1ee0fee,'0f104424204889df0f1103'),
 ('parent_type_tags',0x20867f5,'0fb62e83fd0c0f844701000083fd0d0f843e01000083fd150f85b5020000'),
 ('parent_result_gate',0x20869af,'0fb6442440488b4c24483c02750948890bc6430903eb7a488b54246048895424180f104424500f1144240848890c24a8017422'),
 ('parent_adapter_result',0x20869ef,'807c2449027542488b442440488903c6430903eb3c4889e64889df'),
 ('variant_dispatch',0x21d61e3,'0fb606ffc883f80e0f871e020000488d0d38a71ffe486304814801c8'),
 ('variant_limit',0x21d6247,'4883fe050f85db0000008b0733052a9d20fe0fb64f04320d249d20fe0fb6c909c10f8481000000'),
 ('variant_output',0x21d63a2,'4983c620807c240801751e410fb606488b4c241048894b08c60302'),
 ('variant_trigger',0x21d632c,'4883fe070f85fc0000008b0733054a9c20fe8b4f03330d449c20fe09c10f85e3000000c644240901'),
 ('representation_gate',0x20b3c84,'0fb60683f8144889742410898424dc0000000f841802000083f8150f857d070000'),
 ('sequence_stride',0x20b3eb4,'4989ef488b4608488b4e10488b561848c1e2054801ca48894c244048894c24484889442450488954245848c744246000000000'),
 ('first_result',0x20b3ef9,'80bc2490000000017542'),
 ('first_missing',0x20b3f45,'0fb69c249100000080fb020f84f7040000'),
 ('second_presence',0x20b3f56,'4c8b6c24404d85ed74264c8b6424484c8b7424584d39f47417498d6c242048896c2448410fb604243c16'),
 ('second_counter',0x20b4151,'488b4424604883f8ff0f8426040000488944240848ffc04889442438'),
 ('second_result',0x20b4197,'48b800000000000000804839c10f85a5000000'),
 ('third_presence',0x20b424f,'4c39f574194c8b742430498d4424404889442448410fb64424203c16754f'),
 ('third_counter',0x20b42df,'48837c2438ff0f84aa020000488b4424084883c00248894424084889442460'),
 ('third_result',0x20b4315,'4c89fd807c2420007423488b442428e9'),
 ('success_stores',0x20b4342,'488d4424480fb64c24214c896500488b1424488955084c897510885d18884d19'),
 ('remaining_count',0x20b4396,'4c29f30f841afdffff48c1eb0548035c24080f82f60100'),
 ('map_first',0x20b3d8b,'80fb020f8566070000'),
 ('map_price',0x20b3ddd,'488b0c244c39e10f857d060000'),
 ('map_third',0x20b3e54,'807c2418020f8551060000'),
 ('adapter_input',0x219867e,'803e160f8410010000'),
 ('adapter_read',0x2198687,'4889e7e8e1b5f1ff31c0483b0424710e488b442408488903c6430902eb53'),
 ('adapter_convert',0x21986c9,'488d7c2420488db42480000000ff15bcb15d030fb74424203d86010000751f'),
 ('adapter_output',0x21986e8,'488b4424284488730848890340886b09'),
 ('first_reader_presence',0x1ee4166,'48833e00741a488b4608483b46187410488d482048894e080fb60880f916'),
 ('first_reader_counter',0x1ee41ab,'488b46204883f8ff0f84a30000004889fb48ffc048894620'),
 ('first_reader_type',0x1ee41fc,'807c243000751f0fb66c2431488d7c2430e8aed22d004889df40886b0131c0'),
 ('key_lengths',0x2165e01,'4883f9040f84880100004883f9090f84250100004883f9080f859b010000488b00483b0567470afe0f858b01000031c9'),
 ('key_bytewise_market',0x2165e5c,'8038690f8555010000807801730f854b0100008078024d0f8541010000807803610f8537010000807804720f852d0100008078056b0f8523010000807806650f8519010000807807747488'),
 ('key_bytewise_price',0x2165f5a,'803874755b80780172755580780269754f80780367754980780467754380780565753d807806727537807807507531b101807808787529'),
 ('key_bytewise_tpsl',0x2165fa1,'803874751480780170750e807802737508b1028078036c7402'),
 ('map_table_dispatch',0x20b3d7b,'488d0d7a3231fe486304814801c8ffe0'),
)
COPY_NAMES = frozenset(('representation_gate','sequence_stride','first_result','first_missing','second_presence',
                        'second_counter','second_result','third_presence','third_counter','third_result',
                        'success_stores','remaining_count','map_first','map_price','map_third'))
# Conditional branch opcodes and destinations are decoded from the file and checked against these anchors.
BRANCHES = (
 ('entry_no_buffer',0x1ee0f19,0x1ee0f35), ('entry_end',0x1ee0f23,0x1ee0f35),
 ('entry_marker_present',0x1ee0f33,0x1ee0f42), ('entry_counter_overflow',0x1ee0f5f,0x1ee1002),
 ('entry_parent_success',0x1ee0fd4,0x1ee0fee),
 ('parent_classification_ok',0x20869bb,0x20869c6),
 ('parent_non_trigger',0x20869e0,0x2086a04),
 ('parent_adapter_ok',0x20869f4,0x2086a38),
 ('sequence_tag',0x20b3c96,0x20b3eb4), ('other_tag',0x20b3c9f,0x20b4422),
 ('first_reader_error',0x20b3f01,0x20b3f45), ('first_missing',0x20b3f50,0x20b444d),
 ('second_buffer_absent',0x20b3f5e,0x20b3f86), ('second_end',0x20b3f6d,0x20b3f86),
 ('second_marker_present',0x20b3f80,0x20b412e), ('second_counter_overflow',0x20b415a,0x20b4586),
 ('second_reader_success',0x20b41a4,0x20b424f), ('third_end',0x20b4252,0x20b426d),
 ('third_marker_present',0x20b426b,0x20b42bc), ('third_counter_overflow',0x20b42e5,0x20b4595),
 ('third_reader_success',0x20b431d,0x20b4342), ('no_remaining',0x20b4399,0x20b40b9),
 ('remaining_count_overflow',0x20b43a8,0x20b45a4),
 ('adapter_absent',0x2198681,0x2198797), ('adapter_reader_success',0x2198695,0x21986a5),
 ('adapter_converter_error',0x21986e6,0x2198707),
 ('first_no_buffer',0x1ee416a,0x1ee4186), ('first_end',0x1ee4174,0x1ee4186),
 ('first_marker_present',0x1ee4184,0x1ee4195), ('first_counter_overflow',0x1ee41b3,0x1ee425c),
 ('first_bad_type',0x1ee4201,0x1ee4222),
)
CALLS = (
 ('entry_parent',0x1ee0fca,0x20867e0),
 ('entry_parent_copy',0x34f772a,0x3a3b920),
 ('parent_classifier',0x20869aa,0x21d61c0),
 ('parent_trigger',0x20869ea,0x2198670),
 ('parent_trigger_copy',0x3a3bb2a,0x3b311d0),
 ('adapter_reader',0x219868a,0x20b3c70),
 ('tuple_first',0x20b3ef4,0x1ee4160),
 ('tuple_second',0x20b417f,0x209d1d0),
 ('tuple_third',0x20b4310,0x2088b40),
 ('map_iterator',0x20b3d26,0x1ec9db0),
 ('key_classifier',0x1ec9eb7,0x2165dc0),
 ('adapter_reader_copy',0x3b311ea,0x3ad6590),
 ('tuple_first_copy',0x3ad6814,0x34f5fc0),
 ('tuple_second_copy',0x3ad6a9f,0x3a51070),
 ('tuple_third_copy',0x3ad6c30,0x3a43ed0),
)


def load_binary(path=BINARY):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('input SHA-256 mismatch')
    return data


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.fdes = {}
        for row in fdes:
            self.fdes.setdefault(row['start'], []).append(row)

    def offset(self, va, size=1, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid address or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size'] and (not executable or s['flags'] & 4)]
        if len(matches) != 1:
            raise ValueError('address does not have one file-backed mapping')
        s = matches[0]
        offset = s['offset'] + va - s['address']
        if offset + size > len(self.data):
            raise ValueError('file range outside input')
        return offset

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return bytes(self.data[off:off + size])

    def relocation(self, address):
        rows = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
        if len(rows) != 1 or rows[0]['size'] % 24:
            raise ValueError('missing or malformed dynamic relocations')
        row = rows[0]
        found = []
        for pos in range(row['offset'], row['offset'] + row['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, pos)
            if where == address:
                found.append((info, addend))
        if len(found) != 1 or found[0][0] != 8:
            raise ValueError('missing, duplicated or non-relative relocation')
        return found[0][1]

    def branch(self, va):
        b = self.read(va, 2, True)
        if 0x70 <= b[0] <= 0x7f:
            return b[0] & 15, va + 2 + struct.unpack('<b', b[1:])[0], b
        if b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
            raw = self.read(va, 6, True)
            return b[1] & 15, va + 6 + struct.unpack_from('<i', raw, 2)[0], raw
        raise ValueError('expected conditional branch')

    def call(self, va):
        raw = self.read(va, 5, True)
        if raw[0] != 0xe8:
            raise ValueError('expected direct rel32 call')
        return va + 5 + struct.unpack_from('<i', raw, 1)[0], raw

    def rip(self, va, prefix):
        raw = self.read(va, len(prefix) + 4, True)
        if raw[:len(prefix)] != prefix:
            raise ValueError('unexpected RIP instruction')
        return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0], raw


def table(image, base, count):
    return [base + struct.unpack('<i', image.read(base + 4 * i, 4))[0] for i in range(count)]


def inspect(image):
    funcs = []
    for role, start, end, fde, expected in FUNCTIONS:
        rows = image.fdes.get(start, [])
        if len(rows) != 1 or rows[0]['end'] != end or rows[0]['fde'] != fde:
            raise ValueError('FDE mismatch for ' + role)
        raw = image.read(start, end - start, True)
        sha = hashlib.sha256(raw).hexdigest()
        if sha != expected:
            raise ValueError('function bytes changed for ' + role)
        funcs.append(dict(role=role, start_va=hex(start), end_va=hex(end), fde_va=hex(fde),
                          file_offset=hex(image.offset(start, len(raw), True)), bytes=len(raw), sha256=sha))
    windows, copies = [], []
    delta = 0x3ad6590 - 0x20b3c70
    for name, va, expected_hex in ANCHORS:
        expected = bytes.fromhex(expected_hex)
        raw = image.read(va, len(expected), True)
        if raw != expected:
            raise ValueError('unexpected bytes at ' + name)
        windows.append(dict(name=name, va=hex(va), file_offset=hex(image.offset(va, len(raw), True)), raw_hex=raw.hex()))
        if name in COPY_NAMES:
            other = image.read(va + delta, len(raw), True)
            if raw != other:
                raise ValueError('corresponding copy differs: ' + name)
            copies.append(dict(name=name, first_va=hex(va), second_va=hex(va + delta), bytes=len(raw), raw_hex=raw.hex()))
    adapter_delta = 0x3b311d0 - 0x2198670
    for name, va, size in (('adapter_absence',0x219867e,9),
                           ('adapter_tag',0x21986dc,12), ('adapter_stores',0x21986e8,16)):
        raw = image.read(va, size, True)
        if raw != image.read(va + adapter_delta, size, True):
            raise ValueError('corresponding adapter differs: ' + name)
        copies.append(dict(name=name, first_va=hex(va), second_va=hex(va + adapter_delta), bytes=size, raw_hex=raw.hex()))
    entry_delta = 0x34f7670 - 0x1ee0f10
    for name, va, size in (('entry_presence',0x1ee0f15,45), ('entry_counter',0x1ee0f57,24),
                           ('entry_descriptor',0x1ee0fbf,11), ('entry_result',0x1ee0fcf,30),
                           ('entry_success',0x1ee0fee,11)):
        raw = image.read(va, size, True)
        if raw != image.read(va + entry_delta, size, True):
            raise ValueError('corresponding entry differs: ' + name)
        copies.append(dict(name=name, first_va=hex(va), second_va=hex(va + entry_delta), bytes=size, raw_hex=raw.hex()))
    parent_delta = 0x3a3b920 - 0x20867e0
    for name, va, size in (('parent_tags',0x20867f5,30), ('parent_gate',0x20869af,51),
                           ('parent_result',0x20869ef,22)):
        raw = image.read(va, size, True)
        if raw != image.read(va + parent_delta, size, True):
            raise ValueError('corresponding parent differs: ' + name)
        copies.append(dict(name=name, first_va=hex(va), second_va=hex(va + parent_delta), bytes=size, raw_hex=raw.hex()))
    branches = []
    for name, va, expected in BRANCHES:
        condition, target, raw = image.branch(va)
        if target != expected:
            raise ValueError('branch target changed: ' + name)
        branches.append(dict(name=name, va=hex(va), condition_code=condition, condition=CONDITIONS[condition], target_va=hex(target), raw_hex=raw.hex()))
        if 0x20b3c70 <= va < 0x20b473b:
            ccond, ctarget, craw = image.branch(va + delta)
            if ccond != condition or ctarget != expected + delta or craw != raw:
                raise ValueError('branch differs in reader copy: ' + name)
            branches.append(dict(name='copy_' + name, va=hex(va + delta), condition_code=ccond, condition=CONDITIONS[ccond],
                                 target_va=hex(ctarget), raw_hex=craw.hex()))
    calls = []
    for name, va, expected in CALLS:
        target, raw = image.call(va)
        if target != expected:
            raise ValueError('call target changed: ' + name)
        calls.append(dict(name=name, va=hex(va), target_va=hex(target), raw_hex=raw.hex()))
    slot, insn = image.rip(0x21986d6, b'\xff\x15')
    if slot != 0x5773898 or image.relocation(slot) != 0x3330210:
        raise ValueError('converter slot changed')
    copy_slot, copy_insn = image.rip(0x3b31236, b'\xff\x15')
    if copy_slot != slot:
        raise ValueError('copy converter slot changed')
    calls.extend((dict(name='converter_a', va=hex(0x21986d6), slot_va=hex(slot), target_va=hex(image.relocation(slot)), raw_hex=insn.hex()),
                  dict(name='converter_b', va=hex(0x3b31236), slot_va=hex(slot), target_va=hex(image.relocation(slot)), raw_hex=copy_insn.hex())))
    # Both type descriptors are relocation-backed {pointer,length} records.
    descriptions = []
    for descriptor in (0x569ae80, 0x57417c0):
        target = image.relocation(descriptor)
        length = struct.unpack('<Q', image.read(descriptor + 8, 8))[0]
        text = image.read(target, length)
        if text != b'struct TriggerWireSerde with 3 elements':
            raise ValueError('unexpected tuple descriptor')
        descriptions.append(dict(record_va=hex(descriptor), text_va=hex(target), length=length, text=text.decode('ascii')))
    dispatch = table(image, 0x3c6ffc, 3)
    if dispatch != [0x20b3d8b, 0x20b3ddd, 0x20b3e54]:
        raise ValueError('unexpected map dispatch')
    name_va, name_insn = image.rip(0x1ee0fa7, b'\x48\x8d\x15')
    fields_va, fields_insn = image.rip(0x1ee0fae, b'\x4c\x8d\x05')
    if (name_va, fields_va) != (0x3e1727, 0x56a1018):
        raise ValueError('order type descriptor references changed')
    enum_binding = [dict(va=hex(0x1ee0fa7), target_va=hex(name_va), raw_hex=name_insn.hex()),
                    dict(va=hex(0x1ee0fae), target_va=hex(fields_va), raw_hex=fields_insn.hex())]
    enum_name = image.read(name_va, 13)
    if enum_name != b'OrderTypeWire':
        raise ValueError('unexpected order type name')
    for record, expected, length in ((0x56a1018,0x3dff83,5), (0x56a1028,0x3dff88,7)):
        if image.relocation(record) != expected or struct.unpack('<Q', image.read(record + 8, 8))[0] != length:
            raise ValueError('unexpected order type descriptor')
    variants = table(image, 0x3d0930, 15)
    if variants[12] != 0x21d623f or image.read(0x3dff83, 12) != b'limittrigger':
        raise ValueError('unexpected variant classifier')
    classifier = table(image, 0x3cc328, 15)
    if classifier[12] != 0x2165df9 or classifier[14] != 0x2165e36:
        raise ValueError('unexpected classifier table')
    # Resolve the four actual optimized string-comparison operands.
    comparison_refs = []
    for va, prefix, expected in ((0x2165e22, b'\x48\x3b\x05', 0x20a590),
                                  (0x2165f3d, b'\x48\x33\x0d', 0x3d6cf2),
                                  (0x2165f48, b'\x32\x05', 0x3d6cfa),
                                  (0x2165f95, b'\x3b\x05', 0x209f78)):
        target, raw = image.rip(va, prefix)
        if target != expected:
            raise ValueError('key comparison target changed')
        comparison_refs.append(dict(va=hex(va), target_va=hex(target), raw_hex=raw.hex()))
    names = [image.read(0x20a590, 8), image.read(0x3d6cf2, 9), image.read(0x209f78, 4)]
    # Decode immediates from the separate byte-by-byte classifier arm. The first
    # comparison is [rax], subsequent ones are [rax+disp8].
    spelled = []
    for addresses in ((0x2165e5c,0x2165e65,0x2165e6f,0x2165e79,0x2165e83,0x2165e8d,0x2165e97,0x2165ea1),
                      (0x2165f5a,0x2165f5f,0x2165f65,0x2165f6b,0x2165f71,0x2165f77,0x2165f7d,0x2165f83,0x2165f8b),
                      (0x2165fa1,0x2165fa6,0x2165fac,0x2165fb4)):
        word = bytearray()
        for index, address in enumerate(addresses):
            raw = image.read(address, 3 if index == 0 else 4, True)
            if (index == 0 and raw[:2] != b'\x80\x38') or (index > 0 and raw[:3] != bytes((0x80, 0x78, index))):
                raise ValueError('unexpected bytewise comparison')
            word.append(raw[-1])
        spelled.append(bytes(word))
    if spelled != names:
        raise ValueError('key classifier copies disagree')
    if names != [b'isMarket', b'triggerPx', b'tpsl']:
        raise ValueError('unexpected field constants')
    if image.read(0x3d26ba, 9) != names[1]:
        raise ValueError('missing price error label')
    return dict(binary_sha256=DIGEST, functions=funcs, windows=windows, paired_windows=copies,
                branches=branches, calls=calls, descriptions=descriptions,
                map_dispatch=[hex(x) for x in dispatch], classifier_table=[hex(x) for x in classifier],
                variant_table=[hex(x) for x in variants], variant_names=['limit','trigger'], order_type_name=enum_name.decode('ascii'), enum_binding=enum_binding,
                comparison_refs=comparison_refs, field_names=[x.decode('ascii') for x in names],
                scope='Selected static paths only. FDEs are unwind extents. External reader and converter bodies are edges.')


def sequence_case(length, markers, first_valid, first_value, price_valid, third_valid, converter_tag):
    """Abstract only the selected tuple control flow; readers supply their indicated result."""
    if not 0 <= length <= 5 or not 0 <= markers < 8 or first_value not in (0, 1, 2):
        raise ValueError('invalid abstract case')
    if any(type(v) is not bool for v in (first_valid, price_valid, third_valid)):
        raise ValueError('reader success flags must be bool')
    if not 0 <= converter_tag <= 0xffff:
        raise ValueError('converter tag outside u16')
    trace = ['first_reader']
    if length == 0 or markers & 1:
        return 'missing_0', trace
    if not first_valid:
        return 'first_error', trace
    if first_value == 2:
        return 'missing_0', trace
    if length < 2 or markers & 2:
        return 'missing_1', trace
    trace.append('price_reader')
    if not price_valid:
        return 'price_error', trace
    if length < 3 or markers & 4:
        return 'missing_2', trace
    trace.append('third_reader')
    if not third_valid:
        return 'third_error', trace
    if length > 3:
        return 'trailing_elements', trace
    trace.append('converter')
    return ('success' if converter_tag == SUCCESS else 'converter_error'), trace


def parent_case(classifier_tag, adapter_tag):
    if not 0 <= classifier_tag <= 255 or not 0 <= adapter_tag <= 255:
        raise ValueError('parent tag outside byte')
    if classifier_tag == 2:
        return 'classifier_error'
    if not classifier_tag & 1:
        return 'other_variant'
    return 'adapter_error' if adapter_tag == 2 else 'adapter_success'


def first_advance(has_buffer, at_end, marker, counter):
    """Model the separately pinned first-element cursor and counter checks."""
    if type(has_buffer) is not bool or type(at_end) is not bool or not 0 <= marker <= 255 or not 0 <= counter <= TOP:
        raise ValueError('invalid cursor case')
    if not has_buffer or at_end:
        return ('absent', 0, counter)
    if marker == 0x16:
        return ('absent', 32, counter)
    if counter == TOP:
        return ('overflow', 32, counter)
    return ('present', 32, counter + 1)


def walk_first_cursor(image, has_buffer, at_end, marker, counter):
    """Interpret the selected first-reader cursor instructions, stopping before value decoding.

    Only the recorded instructions and equal/not-equal branches are accepted.
    A single synthetic, readable 32-byte element supplies the marker byte.
    """
    if type(has_buffer) is not bool or type(at_end) is not bool or not 0 <= marker <= 255 or not 0 <= counter <= TOP:
        raise ValueError('invalid cursor fixture')
    origin = 0x100000
    cursor = origin
    end = origin if at_end else origin + 32
    registers = {'rax': 0, 'rcx': 0}
    zf = None
    ip = 0x1ee4166

    def fixed(address, hex_bytes):
        expected = bytes.fromhex(hex_bytes)
        if image.read(address, len(expected), True) != expected:
            raise ValueError('unsupported cursor instruction')
        return address + len(expected)

    for _ in range(32):
        if ip == 0x1ee4166:
            ip = fixed(ip, '48833e00')
            zf = not has_buffer
        elif ip == 0x1ee416c:
            ip = fixed(ip, '488b4608')
            registers['rax'] = cursor
        elif ip == 0x1ee4170:
            ip = fixed(ip, '483b4618')
            zf = registers['rax'] == end
        elif ip == 0x1ee4176:
            ip = fixed(ip, '488d4820')
            registers['rcx'] = registers['rax'] + 32
        elif ip == 0x1ee417a:
            ip = fixed(ip, '48894e08')
            cursor = registers['rcx']
        elif ip == 0x1ee417e:
            ip = fixed(ip, '0fb608')
            if registers['rax'] != origin or at_end or not has_buffer:
                raise ValueError('unexpected marker read')
            registers['rcx'] = marker
        elif ip == 0x1ee4181:
            raw = image.read(ip, 3, True)
            if raw[:2] != b'\x80\xf9':
                raise ValueError('unsupported marker comparison')
            ip += 3
            zf = registers['rcx'] == raw[2]
        elif ip == 0x1ee4186:
            fixed(ip, '66c7070002')
            return ('absent', cursor - origin, counter)
        elif ip == 0x1ee4195:
            # The actual move-only block copies the element; payload contents are
            # irrelevant to the cursor checks and are not interpreted here.
            ip = fixed(ip, '884c24100f1040010f1048100f114c24200f11442411')
        elif ip == 0x1ee41ab:
            ip = fixed(ip, '488b4620')
            registers['rax'] = counter
        elif ip == 0x1ee41af:
            ip = fixed(ip, '4883f8ff')
            zf = registers['rax'] == TOP
        elif ip == 0x1ee41b9:
            ip = fixed(ip, '4889fb')
        elif ip == 0x1ee41bc:
            ip = fixed(ip, '48ffc0')
            registers['rax'] = (registers['rax'] + 1) & TOP
        elif ip == 0x1ee41bf:
            ip = fixed(ip, '48894620')
            counter = registers['rax']
        elif ip == 0x1ee41c3:
            return ('present', cursor - origin, counter)
        elif ip == 0x1ee425c:
            return ('overflow', cursor - origin, counter)
        elif ip in (0x1ee416a, 0x1ee4174, 0x1ee4184, 0x1ee41b3):
            cc, target, raw = image.branch(ip)
            if zf is None or cc not in (4, 5):
                raise ValueError('unsupported cursor branch')
            ip = target if (zf if cc == 4 else not zf) else ip + len(raw)
        else:
            raise ValueError('unexpected cursor instruction address')
    raise ValueError('cursor walk did not terminate')


def write_tsv(path, fieldnames, rows):
    with path.open('w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, delimiter='\t', lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def generate(data, out):
    # Authenticate before parsing metadata and before making any output directory.
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('input SHA-256 mismatch')
    image = Image(data)
    facts = inspect(image)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    function_rows = []
    for row in facts['functions']:
        start, end = int(row['start_va'], 16), int(row['end_va'], 16)
        function_rows.append(dict(role=row['role'], start_va=row['start_va'], end_va=row['end_va'],
                                  fde_va=row['fde_va'], file_offset=row['file_offset'],
                                  sha256=row['sha256'], raw_hex=image.read(start, end - start, True).hex()))
    write_tsv(out / 'function-bytes.tsv', ('role','start_va','end_va','fde_va','file_offset','sha256','raw_hex'), function_rows)
    call_rows = [dict(name=row['name'], va=row['va'], slot_va=row.get('slot_va', ''),
                      target_va=row['target_va'], raw_hex=row['raw_hex']) for row in facts['calls']]
    write_tsv(out / 'calls.tsv', ('name','va','slot_va','target_va','raw_hex'), call_rows)
    field_rows = [dict(index=i, name=name, name_hex=name.encode('ascii').hex(),
                       map_arm_va=facts['map_dispatch'][i],
                       role=('boolean_reader','price_reader','third_reader')[i])
                  for i, name in enumerate(facts['field_names'])]
    write_tsv(out / 'fields.tsv', ('index','name','name_hex','map_arm_va','role'), field_rows)
    branches = facts['branches']
    write_tsv(out / 'branches.tsv', ('name','va','condition_code','condition','target_va','raw_hex'), branches)
    cursor_rows = []
    for has_buffer, at_end, marker, counter in itertools.product((False, True), (False, True), range(256), (0, TOP - 1, TOP)):
        observed = walk_first_cursor(image, has_buffer, at_end, marker, counter)
        expected = first_advance(has_buffer, at_end, marker, counter)
        if observed != expected:
            raise ValueError('cursor interpretation disagrees with model')
        cursor_rows.append(dict(has_buffer=int(has_buffer), at_end=int(at_end), marker=hex(marker),
                                counter=counter, outcome=observed[0], advance=observed[1], counter_after=observed[2]))
    write_tsv(out / 'cursor-cases.tsv', ('has_buffer','at_end','marker','counter','outcome','advance','counter_after'), cursor_rows)
    names = facts['field_names']
    key_rows = []
    for tag, name in itertools.product((0x0d, 0x0f), (names[0], names[1], names[2], '', 'TriggerPx', 'triggerPx!', 'tps', 'isMarketx')):
        key_rows.append(dict(internal_tag=hex(tag), key=name, key_hex=name.encode('ascii').hex(),
                             index=names.index(name) if name in names else 3))
    write_tsv(out / 'key-cases.tsv', ('internal_tag','key','key_hex','index'), key_rows)
    parent_rows = [dict(classifier_tag=tag, adapter_tag=adapter, outcome=parent_case(tag, adapter))
                   for tag, adapter in itertools.product(range(256), (0, 1, 2, 3))]
    write_tsv(out / 'parent-cases.tsv', ('classifier_tag','adapter_tag','outcome'), parent_rows)
    cases = []
    for n, marker_mask, b, first_ok, price_ok, third_ok, converter_ok in itertools.product(
            range(6), range(8), (0,1,2), (False,True), (False,True), (False,True), (False,True)):
        tag = SUCCESS if converter_ok else 0xa8
        outcome, trace = sequence_case(n, marker_mask, first_ok, b, price_ok, third_ok, tag)
        cases.append(dict(length=n, markers=marker_mask, first_valid=int(first_ok), first_value=b,
                          price_valid=int(price_ok), third_valid=int(third_ok), converter_tag=hex(tag),
                          outcome=outcome, calls=','.join(trace)))
    write_tsv(out / 'sequence-cases.tsv', ('length','markers','first_valid','first_value','price_valid',
                                          'third_valid','converter_tag','outcome','calls'), cases)
    facts['metrics'] = dict(fde_count=len(facts['functions']), anchor_count=len(facts['windows']),
                            paired_anchor_count=len(facts['paired_windows']), branch_count=len(branches),
                            call_count=len(facts['calls']), cursor_case_count=len(cursor_rows), cursor_model_mismatches=0, key_case_count=len(key_rows), parent_case_count=len(parent_rows), sequence_case_count=len(cases))
    (out / 'evidence.json').write_text(json.dumps(facts, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(load_binary(), args.out)


if __name__ == '__main__':
    main()
