#!/usr/bin/env python3
"""Extract the #94 order wire quantity-input path from ELF bytes; never execute it."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE ranges describe unwind coverage, not a complete control-flow proof.
STARTS = (0x1ee0760, 0x20e08a0, 0x1ed8740, 0x2163dc0, 0x330e700,
          0x208b7d0, 0x21272a0, 0x2197ca0, 0x1ec84b0, 0x2152440,
          0x34f51b0, 0x3adcca0)

# Exact instruction windows, identified before extraction. No instruction-text parser.
WINDOWS = (
 ('wrapper_enter', 0x1ee0768, '48833e00741a488b4608483b46187410488d482048894e080fb60880f9167510'),
 ('wrapper_counter', 0x1ee07ad, '488b46204883f8ff0f84c30100004889fb48ffc048894620'),
 ('wrapper_literal', 0x1ee07fd, '488d15826b4ffe4c8d050dd27b03488dbc2448010000488d742460b90e00000041b90e000000e878002000'),
 ('wrapper_gate', 0x1ee0828, '31c0483b842448010000711f0f108424500100000f108c24600100000f294c24300f294424204889dfeb64488dbc2480000000488db42448010000ff154f2a8903'),
 ('wrapper_adapter_tag', 0x1ee0869, '6681bc248000000086010f858e000000'),
 ('wrapper_result', 0x1ee08ad, '807c2456024889df75210f284424200f284c24300f114f100f1107c64736034889f84881c4a00100005bc3488b442450488947300f284424200f284c24300f285424400f1157200f114f100f11074889f84881c4a00100005bc3'),
 ('wrapper_conversion_error', 0x1ee0967, '488d7c2420488db424e0000000e8373982ffe9d0feffff'),
 ('wrapper_counter_overflow', 0x1ee097e, '488d3d0b0b7b03ff158dd788030f0b'),
 ('second_wrapper_literal', 0x34f524d, '488d15cb6409fd4c8d0545471f02488dbc2448010000488d742460b90e00000041b90e000000e8287a5e00'),
 ('second_wrapper_gate', 0x34f5278, '31c0483b842448010000711f0f108424500100000f108c24600100000f294c24300f294424204889dfeb64488dbc2480000000488db42448010000ff15ffdf2702'),
 ('reader_tags', 0x20e08b4, '83f81448897c24184889b42450020000898424cc0100000f849500000083f8150f851b'),
 ('key_call_dispatch', 0x20e0ac0, '4c89ef488db424f0000000e8707cdfff0fb64c24500fb644245180f9090f85420500000fb6c089c0496304864c01f0ffe0'),
 ('price_field', 0x20e0bf7, '488b4424404c39f80f855d1200000fb68424f0000000c68424f0000000163c160f843d130000488d8c24100100000f1041e10f1049f00f114d0f0f114500884424504c897c2440488d7c24204c89eee865c4fbff0fb64424203c090f85a5060000488b4424284889442440488b44243048898424e8000000488b44243848898424480200'),
 ('size_field', 0x20e0c81, '488b4c24104c39f90f855d1000000fb68424f0000000c68424f0000000163c160f8492120000488d8c24100100000f1041e10f1049f00f114d0f0f114500884424504c897c2410488d7c24204c89eee8dbc3fbff0fb64424203c090f85e4050000488b4424284889442410488b44243048898424c0010000488b4424384889842440020000'),
 ('missing_price', 0x20e123f, '4c8b4424404d39f80f8523030000488d0556072ffe48898424b000000048c78424b800000001000000'),
 ('missing_size', 0x20e1570, '31ed488bb424e80000004d39fd0f85c50000004889b424600100004c89c3488d059a032ffe48898424b0000000'),
 ('duplicate_price_error', 0x20e1e62, '4889c3488d053efb2efe48898424b000000048c78424b800000001000000'),
 ('duplicate_size_error', 0x20e1cec, '488d053cfc2efe48898424b000000048c78424b800000001000000'),
 ('output_fields', 0x20e17d4, '4d890649897608488b842448020000498946104d896e1849897e20488b84244002000049894628'),
 ('nested_call', 0x20e0ded, '488d7c24204c89eee8d6a9faff0fb64424203c090f8532050000'),
 ('nested_field_arm', 0x20e0dae, '807c240f030f858f0f00000fb68424f0000000c68424f0000000163c160f84980d0000488d8c24100100000f1041e10f1049f00f114d0f0f11450088442450488d7c24204c89eee8d6a9faff0fb64424203c'),
 ('nested_dispatch', 0x208ba34, 'a80174254889e7488d742420e85bc21000803c24090f85b40000000f104424080f114308c60309eb0d488d7424204889dfe8e6081000'),
 ('nested_key_call', 0x1ec85b3, '488d7c2468488d742420e87e9e2800807c246809'),
 ('nested_classifier_length', 0x21524be, '4883f9040f84590100004883f9090f84080100004883f908'),
 ('nested_classifier_trigger', 0x21525da, '803874755b80780172755580780269754f80780367754980780467754380780565753d807806727537807807507531b101807808787529eb29'),
 ('nested_table_dispatch', 0x212735b, '0fb64c24500fb644245180f9090f85ac0200000fb6c083f803753b0fb68424a8000000c68424a8000000163c160f844c090000410f1045e1410f104df0410f114c240f410f110424884424504c89ffe811a10900eb9f89c0488d0dfe062afe486304814801c8ffe0'),
 ('nested_value_read', 0x2127420, '48b80000000000000080488b0c244839c10f85c80900000fb68424a8000000c68424a8000000163c160f84170a0000410f1045e1410f104df0410f114c240f410f11042488442450488d7c24084c89fee83b5cf7ff0fb64424083c090f85ba070000488b44241048890424488b4424184889442430488b4424204889442448'),
 ('nested_result', 0x21277e1, '89c84d897e0849896e10488b4c244849894e1841885e204188462149c70600000000'),
 ('nested_duplicate_label', 0x2127dff, '488d05b4a82afe488944243848c7442440090000'),
 ('nested_conversion', 0x2197ca0, '5541574156534881ec080100004889fb803e160f84250100004c8d7424684c89f7e8daf5f8ff837c2468017513410f104608410f104e180f114b100f1103eb5d0fb6ac2488000000440fb6bc2489000000410f1046080f298424f0000000498b46184889842400010000488d7c2408488db424f0000000ff157bbb5d030fb74424083d860100007525488b4424104889430840886b1044887b11c60309'),
 ('dual_adapter', 0x330e70e, '4989f44889fb8b464089442404440fb66e444c8b76184c8b7e200fb66e45488d7c2408ff15615146020fb74424083d86010000756d498d7424184c8b742410488d7c2408ff15405146020fb74424083d860100000f85a6000000498d4424304983c446488b4c24100f10000f114308410f1004240f11432c410fb644241088433c4c89731848894b208b44240489432844886b3d40886b3e66c7038601e9a7000000'),
 ('first_error_cleanup', 0x330e7f2, '66890348894b084d85f674594c89ff4c89f631d2ff1504f84502eb49'),
 ('second_error_return', 0x330e850, '66890348894b0848'),
 ('key_size_long', 0x2163f8b, '8038730f85bd000000b1038078017a0f85b1000000e9ae000000'),
 ('key_price_long', 0x2163fa5, '80386c0f85a3000000807801690f85990000008078026d0f858f000000807803690f858500000080780474757f807805507579b102807806787571eb71'),
 ('key_order_type_long', 0x2163fe2, '80386f756a80780172756480780264755e80780365755880780472755280780554754c807806797546807807707540b105807808657538eb38'),
 ('key_order_type_short', 0x2164076, 'b105ebd9'),
 ('key_price_short', 0x216407e, 'b102ebd1'),
 ('key_size_short', 0x216406e, 'b103ebe1'),
)


def verified_bytes(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node #94 SHA-256 mismatch')
    return data


def va_bytes(data, secs, address, size):
    if address < 0 or size < 0:
        raise ValueError('negative address or size')
    hits = [s for s in secs if s['type'] != 8 and s['size'] and
            s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('address is not in exactly one file-backed section')
    s = hits[0]
    pos = s['offset'] + address - s['address']
    if pos + size > len(data):
        raise ValueError('range outside file')
    return data[pos:pos + size], pos, s['name']


def read(data, secs, address, size):
    return va_bytes(data, secs, address, size)[0]


def check_window(data, secs, address, expected):
    raw, offset, section = va_bytes(data, secs, address, len(expected))
    if raw != expected:
        raise ValueError('instruction window mismatch at ' + hex(address))
    return offset, section


def target_rel32(data, secs, site, opcode):
    raw = read(data, secs, site, 5)
    if raw[0] != opcode:
        raise ValueError('unexpected direct branch opcode')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def indirect_slot(data, secs, site):
    raw = read(data, secs, site, 6)
    if raw[:2] != b'\xff\x15':
        raise ValueError('unexpected indirect call opcode')
    return site + 6 + struct.unpack_from('<i', raw, 2)[0]


def lea_rax_target(data, secs, site):
    raw = read(data, secs, site, 7)
    if raw[:3] != b'\x48\x8d\x05':
        raise ValueError('unexpected RIP-relative lea')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def relas(data, secs, wanted):
    rows = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rows) != 1 or rows[0]['size'] % 24:
        raise ValueError('unsupported relocation section')
    s = rows[0]
    out = {}
    for off, info, addend in struct.iter_unpack('<QQq', data[s['offset']:s['offset'] + s['size']]):
        if off in wanted:
            if off in out or info != 8:  # R_X86_64_RELATIVE and symbol index zero
                raise ValueError('unexpected or duplicate relocation')
            out[off] = addend
    if set(out) != set(wanted):
        raise ValueError('missing relocation')
    return out


def table_target(data, secs, table, index, count):
    if not 0 <= index < count:
        raise ValueError('jump table index out of range')
    return table + struct.unpack('<i', read(data, secs, table + 4 * index, 4))[0]


def quantity_key(data, secs, key):
    """Interpret only the two selected, byte-matched string-classifier arms.

    Return 2 or 3 for the selected price/size arms, 7 for their mismatches,
    and None when the input would enter some other classifier arm. This is a
    deliberately small interpreter, not an implementation of the entire parser.
    """
    if not isinstance(key, bytes):
        raise ValueError('key must be bytes')
    if len(key) == 1:
        index = key[0] - ord('a')
        if not 0 <= index < 20:
            return None
        pc = table_target(data, secs, 0x3cbf44, index, 20)
        if pc not in (0x216407e, 0x216406e):
            return None
    elif len(key) in (2, 7):
        pc = table_target(data, secs, 0x3cbf1c, len(key) - 1, 10)
        if pc not in (0x2163f8b, 0x2163fa5):
            raise ValueError('unexpected long-key arm')
    else:
        return None
    cl = None
    equal = None
    for _ in range(32):
        if pc == 0x2164051:
            return 7
        if pc == 0x2164053:
            if cl is None:
                raise ValueError('classifier returned uninitialised value')
            return cl
        if not (0x2163f8b <= pc < 0x2163fe2 or
                0x216406e <= pc < 0x2164072 or
                0x216407e <= pc < 0x2164082):
            raise ValueError('branch leaves selected classifier arms')
        op = read(data, secs, pc, 2)
        if op == b'\x80\x38':
            equal = key[0] == read(data, secs, pc + 2, 1)[0]
            pc += 3
        elif op == b'\x80\x78':
            arg = read(data, secs, pc + 2, 2)
            if arg[0] >= len(key):
                raise ValueError('comparison outside input')
            equal = key[arg[0]] == arg[1]
            pc += 4
        elif op == b'\x0f\x85':
            if equal is None:
                raise ValueError('branch without comparison')
            delta = struct.unpack('<i', read(data, secs, pc + 2, 4))[0]
            pc = pc + 6 + (delta if not equal else 0)
        elif op[0] in (0x74, 0x75):
            if equal is None:
                raise ValueError('branch without comparison')
            delta = struct.unpack('<b', op[1:])[0]
            taken = equal if op[0] == 0x74 else not equal
            pc = pc + 2 + (delta if taken else 0)
        elif op[0] == 0xb1:
            cl = op[1]
            pc += 2
        elif op[0] == 0xe9:
            pc = target_rel32(data, secs, pc, 0xe9)
        elif op[0] == 0xeb:
            pc = pc + 2 + struct.unpack('<b', op[1:])[0]
        else:
            raise ValueError('unsupported instruction in selected classifier arm')
    raise ValueError('classifier step limit exceeded')


def conditional_target(data, secs, site):
    """Decode only the short or near conditional branch forms used here."""
    raw = read(data, secs, site, 2)
    if 0x70 <= raw[0] <= 0x7f:
        return site + 2 + struct.unpack('<b', raw[1:])[0]
    if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return site + 6 + struct.unpack('<i', read(data, secs, site + 2, 4))[0]
    raise ValueError('unexpected conditional branch')


def pair_trace(first, second, second_capacity, success):
    """Abstract only the observed adapter branches; helper results are supplied, not computed."""
    if any(type(v) is not int or not 0 <= v <= 0xffff for v in (first, second, success)):
        raise ValueError('tag outside u16')
    if type(second_capacity) is not int or not 0 <= second_capacity < 1 << 64:
        raise ValueError('capacity outside u64')
    if first != success:
        return ('first_error', 1, int(second_capacity != 0))
    if second != success:
        return ('second_error', 2, 0)
    return ('success', 2, 0)


def wrapper_trace(buffer_present, cursor_at_end, marker, counter):
    """Abstract the wrapper's entry checks; counter overflow is a separate edge."""
    if type(buffer_present) is not bool or type(cursor_at_end) is not bool:
        raise ValueError('presence and end conditions must be bools')
    if type(marker) is not int or not 0 <= marker <= 0xff:
        raise ValueError('marker outside u8')
    if type(counter) is not int or not 0 <= counter < 1 << 64:
        raise ValueError('counter outside u64')
    if not buffer_present or cursor_at_end:
        return ('empty', 0, False)
    if marker == 0x16:
        return ('empty', 0x20, False)
    if counter == (1 << 64) - 1:
        return ('overflow_branch', 0x20, False)
    return ('parse', 0x20, True)


def extract(data):
    verified_bytes(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    extents = []
    for start in STARTS:
        rows = [f for f in fdes if f['start'] == start]
        if len(rows) != 1 or rows[0]['end'] <= start:
            raise ValueError('missing or ambiguous FDE')
        row = rows[0]
        body, offset, sec = va_bytes(data, secs, start, row['end'] - start)
        if not any(s['name'] == sec and s['flags'] & 4 for s in secs):
            raise ValueError('FDE range is not executable')
        extents.append({'start_va': hex(start), 'end_va_exclusive': hex(row['end']),
                        'fde_va': hex(row['fde']), 'file_offset': hex(offset),
                        'section': sec, 'body_sha256': hashlib.sha256(body).hexdigest()})
    windows = []
    for name, address, encoded in WINDOWS:
        expected = bytes.fromhex(encoded)
        offset, sec = check_window(data, secs, address, expected)
        if not any(int(row['start_va'], 16) <= address and
                   address + len(expected) <= int(row['end_va_exclusive'], 16)
                   for row in extents):
            raise ValueError('window outside selected FDE ranges')
        windows.append({'name': name, 'va': hex(address), 'file_offset': hex(offset),
                        'section': sec, 'bytes_hex': expected.hex()})

    descriptor = 0x569da18
    wanted = {descriptor + 16 * i for i in range(14)} | {0x57732b8, 0x5773898}
    reloc = relas(data, secs, wanted)
    keys = []
    for index in range(14):
        slot = descriptor + 16 * index
        length = struct.unpack('<Q', read(data, secs, slot + 8, 8))[0]
        if length > 32:
            raise ValueError('field name too long')
        text = read(data, secs, reloc[slot], length).decode('ascii')
        keys.append({'index': index, 'pointer_slot_va': hex(slot),
                     'literal_va': hex(reloc[slot]), 'length': length, 'name': text})
    if [k['name'] for k in keys] != ['a','asset','b','isBuy','limitPx','p','s','sz','r','reduceOnly','orderType','t','c','cloid']:
        raise ValueError('unexpected field descriptor')
    if read(data, secs, 0x3d7386, 14) != b'OrderWireSerde':
        raise ValueError('unexpected type name')
    if read(data, secs, 0x58b71f, 14) != b'OrderWireSerde':
        raise ValueError('unexpected second type name')
    if read(data, secs, 0x3d26ba, 9) != b'triggerPx':
        raise ValueError('unexpected nested field name')
    error_names = []
    for label, site, word in (('missing_price', 0x20e124d, b'p'),
                              ('missing_size', 0x20e158e, b's'),
                              ('duplicate_price', 0x20e1e65, b'p'),
                              ('duplicate_size', 0x20e1cec, b's'),
                              ('duplicate_trigger', 0x2127dff, b'triggerPx')):
        address = lea_rax_target(data, secs, site)
        if read(data, secs, address, len(word)) != word:
            raise ValueError('unexpected field label')
        error_names.append({'path': label, 'lea_va': hex(site),
                            'literal_va': hex(address), 'name': word.decode('ascii')})
    nested_dispatch = [table_target(data, secs, 0x3c7ab8, i, 3) for i in range(3)]
    if nested_dispatch[1] != 0x2127420:
        raise ValueError('unexpected nested quantity dispatch')
    nested_name = bytes(read(data, secs, p, 1)[0] for p in
                        (0x21525dc, 0x21525e2, 0x21525e8, 0x21525ee,
                         0x21525f4, 0x21525fa, 0x2152600, 0x2152606,
                         0x215260e)).decode('ascii')
    if nested_name != 'triggerPx':
        raise ValueError('nested key compare bytes changed')

    dispatch = [table_target(data, secs, 0x3c7400, i, 9) for i in range(9)]
    if dispatch[2:4] != [0x20e0bf7, 0x20e0c81] or dispatch[5] != 0x20e0dae:
        raise ValueError('quantity field dispatch changed')
    length_table = [table_target(data, secs, 0x3cbf1c, i, 10) for i in range(10)]
    ascii_table = [table_target(data, secs, 0x3cbf44, i, 20) for i in range(20)]
    if (length_table[0], length_table[1], length_table[6]) != (0x2163e43, 0x2163f8b, 0x2163fa5):
        raise ValueError('unexpected key length dispatch')
    if (ascii_table[ord('p')-ord('a')], ascii_table[ord('s')-ord('a')]) != (0x216407e, 0x216406e):
        raise ValueError('unexpected short key dispatch')
    if length_table[8] != 0x2163fe2 or ascii_table[ord('t')-ord('a')] != 0x2164076:
        raise ValueError('unexpected order-type key dispatch')
    # Immediates within checked compare instructions, not names copied from a reference.
    long_price = bytes(read(data, secs, p, 1)[0] for p in
                       (0x2163fa7, 0x2163fb1, 0x2163fbb, 0x2163fc5, 0x2163fcf, 0x2163fd5, 0x2163fdd)).decode('ascii')
    long_size = bytes(read(data, secs, p, 1)[0] for p in (0x2163f8d, 0x2163f99)).decode('ascii')
    if (long_price, long_size) != ('limitPx', 'sz'):
        raise ValueError('quantity key compare constants changed')
    order_type_name = bytes(read(data, secs, p, 1)[0] for p in
                            (0x2163fe4, 0x2163fea, 0x2163ff0, 0x2163ff6,
                             0x2163ffc, 0x2164002, 0x2164008, 0x216400e,
                             0x2164016)).decode('ascii')
    if order_type_name != 'orderType':
        raise ValueError('order-type key compare constants changed')
    for key, expected in ((b'p', 2), (b'limitPx', 2), (b's', 3), (b'sz', 3)):
        if quantity_key(data, secs, key) != expected:
            raise ValueError('quantity key execution disagrees with table')

    calls = []
    direct = [(0x1ee0823, 0x20e08a0), (0x1ee0974, 0x17042b0),
              (0x34f5273, 0x3adcca0),
              (0x20e0acb, 0x1ed8740),
              (0x1ed884d, 0x2163dc0), (0x20e0c46, 0x209d0b0),
              (0x20e0cd0, 0x209d0b0), (0x20e0df5, 0x208b7d0),
              (0x208ba40, 0x2197ca0), (0x2197cc1, 0x21272a0),
              (0x2127356, 0x1ec84b0), (0x1ec85bd, 0x2152440),
              (0x2127470, 0x209d0b0)]
    for site, expected in direct:
        target = target_rel32(data, secs, site, 0xe8)
        if target != expected:
            raise ValueError('direct call target changed')
        calls.append({'site_va': hex(site), 'kind': 'rel32', 'target_va': hex(target)})
    for site in (0x1ee0863, 0x34f52b3, 0x330e731, 0x330e752, 0x2197d17):
        slot = indirect_slot(data, secs, site)
        if slot not in (0x57732b8, 0x5773898):
            raise ValueError('unexpected indirect slot')
        calls.append({'site_va': hex(site), 'kind': 'indirect_rela_relative',
                      'slot_va': hex(slot), 'addend_va': hex(reloc[slot])})
    if (reloc[0x57732b8], reloc[0x5773898]) != (0x330e700, 0x3330210):
        raise ValueError('unexpected relocated target')
    branches = []
    for label, site, target in (
            ('wrapper_counter_overflow', 0x1ee07b5, 0x1ee097e),
            ('wrapper_adapter_error', 0x1ee0873, 0x1ee0907),
            ('duplicate_price', 0x20e0bff, 0x20e1e62),
            ('duplicate_size', 0x20e0c89, 0x20e1cec),
            ('price_present', 0x20e1247, 0x20e1570),
            ('size_present', 0x20e157d, 0x20e1648),
            ('nested_kind_alternative', 0x208ba36, 0x208ba5d),
            ('nested_duplicate_value', 0x2127431, 0x2127dff),
            ('nested_conversion_error', 0x2197d27, 0x2197d4e),
            ('first_conversion_error', 0x330e741, 0x330e7b0),
            ('second_conversion_error', 0x330e762, 0x330e80e),
            ('skip_second_cleanup', 0x330e7fc, 0x330e857)):
        actual = conditional_target(data, secs, site)
        if actual != target:
            raise ValueError('unexpected conditional branch target')
        branches.append({'label': label, 'site_va': hex(site), 'taken_va': hex(actual)})
    first_error = read(data, secs, 0x330e7b0, 0x49)
    second_error = read(data, secs, 0x330e80e, 0x49)
    if first_error != second_error:
        raise ValueError('error-copy sequences differ')
    tag = struct.unpack('<I', read(data, secs, 0x330e73d, 4))[0]
    if tag != 0x186 or read(data, secs, 0x330e75d, 5) != b'\x3d' + struct.pack('<I', tag):
        raise ValueError('adapter success tags disagree')
    cases = []
    for first_ok, second_ok, capacity in ((False, False, 0), (False, True, 1),
                                           (True, False, 0), (True, False, 1), (True, True, 0)):
        result, calls_count, cleanup = pair_trace(tag if first_ok else 0, tag if second_ok else 0, capacity, tag)
        cases.append({'first_tag': hex(tag if first_ok else 0), 'second_tag': hex(tag if second_ok else 0),
                      'second_capacity': capacity, 'path': result, 'helper_calls': calls_count,
                      'cleanup_calls': cleanup})
    wrapper_cases = []
    for present, end, marker, counter in ((False, False, 0, 0), (True, True, 0, 0),
                                           (True, False, 0x16, 0),
                                           (True, False, 0, (1 << 64) - 1),
                                           (True, False, 0, (1 << 64) - 2)):
        path, advance, increment = wrapper_trace(present, end, marker, counter)
        wrapper_cases.append({'buffer_present': present, 'cursor_at_end': end,
                              'marker': hex(marker), 'counter': hex(counter),
                              'path': path, 'cursor_advance': advance,
                              'counter_incremented': increment})
    return {'target_sha256': SHA256, 'coordinate_system': 'ELF virtual addresses before load bias',
            'fdes': extents, 'windows': windows, 'type_literal': 'OrderWireSerde',
            'field_descriptor': keys, 'map_dispatch_va': [hex(v) for v in dispatch],
            'nested_map_dispatch_va': [hex(v) for v in nested_dispatch],
            'key_length_dispatch_va': [hex(v) for v in length_table],
            'key_single_byte_dispatch_va': [hex(v) for v in ascii_table],
            'quantity_aliases': {'price': ['p', long_price], 'size': ['s', long_size]},
            'order_type_aliases': ['t', order_type_name],
            'nested_duplicate_field_literal': 'triggerPx', 'error_names': error_names, 'calls': calls,
            'conditional_branches': branches,
            'identical_error_copy_bytes_hex': first_error.hex(),
            'adapter_success_tag': hex(tag), 'abstract_branch_cases': cases,
            'abstract_wrapper_cases': wrapper_cases,
            'limitations': 'FDE extents are unwind ranges. The nested key classifier and arithmetic helper are external to this extraction. No node code was executed.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    result = extract(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    with (args.out / 'fields.tsv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(('index', 'literal_va', 'length', 'name'))
        for row in result['field_descriptor']:
            writer.writerow((row['index'], row['literal_va'], row['length'], row['name']))
    with (args.out / 'branches.tsv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(('first_tag', 'second_tag', 'second_capacity', 'path', 'helper_calls', 'cleanup_calls'))
        for row in result['abstract_branch_cases']:
            writer.writerow(tuple(row[k] for k in ('first_tag', 'second_tag', 'second_capacity', 'path', 'helper_calls', 'cleanup_calls')))


if __name__ == '__main__':
    main()
