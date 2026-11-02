#!/usr/bin/env python3
"""Collect bounded node 94 chain-field parsing and writing evidence, without execution."""
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
SIZE = 91774280

FUNCTIONS = [
    ('action_reader', 0x2880830),
    ('record_reader', 0x20dc8c0),
    ('key_iterator', 0x1ecdb10),
    ('key_adapter', 0x21540c0),
    ('key_matcher', 0x1e71e80),
    ('key_byte_matcher', 0x1e719c0),
    ('network_value_reader', 0x208d290),
    ('network_wrapper', 0x22e9610),
    ('network_dispatch', 0x21db5f0),
    ('packed_matcher', 0x22edb60),
    ('byte_matcher', 0x22ed9b0),
    ('record_writer', 0x1e89990),
    ('network_writer', 0x22e6160),
]
# These windows were selected by manual instruction inspection. Their hashes
# pin control flow and operand shapes; output bytes are always read from ELF.
ANCHORS = [
    ('action_entry', 0x2880830, 0x2880925, '06cf2cabbd20f19057bb603d59e932a46c2547b4d8443fb23fdc06d42657eb01'),
    ('action_send_asset_arm', 0x2880fb9, 0x2881045, '9091d5081c71bfd4c64a82fb9d9bafa16b0e07212461b66146a2e9a88774e0ff'),
    ('action_error_join', 0x2882b23, 0x2882b3f, '52754b5a857a1e2396f0b91aa0daedd04ffc35a317fa313afbd45f145f403a02'),
    ('action_allocation_and_output', 0x2882e94, 0x2882f6e, '47b63aae2de530f6c31d3c51586cecab036625ea12e6f6669aaabfb35972cc21'),
    ('action_allocation_failure', 0x288300d, 0x288301f, 'b0ee84ba16040c944a5411ac6b249db1b3e5770b547a673f08918cd1edd1db67'),
    ('record_setup', 0x20dc953, 0x20dc96f, 'ff713bd6ee8b7678ff203ab953442289817ee50953fa324a3f1b2cf980a9d8cc'),
    ('record_key_dispatch', 0x20dc9b0, 0x20dc9dc, 'f06bb119dea9c32d390cadc7d7c6ff8a3c76b7bbe7e4aac713ea4400e06196d2'),
    ('chain_duplicate_guard', 0x20dccd6, 0x20dcce1, 'e0ac5405c8d631763533f13ff9e9cec6332e1ae4b62cb1cb3cc2ef23773c7cb7'),
    ('record_chain_value', 0x20dcd17, 0x20dcd3f, '21c082bef14e5727c7faff1ea2b080310e5b96c3045ad48d0a750604960f60aa'),
    ('record_reader_error_sentinel', 0x20dd126, 0x20dd137, '197f0616332043e16633c8d76230abb309fe23b718f5909556338cb72c185dcd'),
    ('missing_value_diagnostic', 0x20de2b4, 0x20de2df, 'f877f48cd1276166f07e8798fd477a870679fe0d2cc34c6951996318bb139558'),
    ('missing_chain', 0x20dd636, 0x20dd6aa, '738fe34212b3f683cdd31b5bff6605ab624d62bb136e3e622f39ea5476a35afd'),
    ('duplicate_chain', 0x20de5bb, 0x20de612, '8d6e314e273c4b7529c86ea70ca83107aecdeea831975392a7c74a7e836d4bff'),
    ('record_chain_store', 0x20de003, 0x20de00e, '1286cb00e7d60371fae53b8953a9fdc6cefbe0d50f5b6411acc3d2ba4f97a6a4'),
    ('field_adapter_empty', 0x1ecdb1a, 0x1ecdb40, '88c4d6beeae54291f5bbd69639e4feaf67507d361029c84930dcfb64e1021968'),
    ('field_adapter_match', 0x1ecdb4e, 0x1ecdc50, '55ee2c202adc738210f13f9261da1053fa4296b6b9f0dc4a4c1630d2a98657c0'),
    ('field_dispatch', 0x21540d1, 0x21542e8, 'f9844e57d4202b0178c5121c5fd5c3211222d72e6699e77abe97230596a22dbb'),
    ('field_matcher', 0x1e71e80, 0x1e72003, '262f07ee848643f5a8670c87fad7de303fc1afebdfe8faf780b5559b286012aa'),
    ('field_byte_matcher', 0x1e719c0, 0x1e71e71, '60ba0ab21ab634641d2856228d1378791285442894dcf565f52d2f003bc241bb'),
    ('value_reader_entry', 0x208d2a5, 0x208d648, '30582a16ec92c53226bfb7b70fcf476a8beb811cc9555e0769912b4117d56eb6'),
    ('value_reader_call', 0x208d444, 0x208d465, '7feca64666d0a9a3fa1e8209a34a46fc68e6f70055aa047a741c7ac65f27cd8f'),
    ('value_wrapper', 0x22e9619, 0x22e9649, '87d6d339eeed14e1e89cae0d45da45e586d08c822fb4816a930adce4f2025cf2'),
    ('network_dispatch', 0x21db619, 0x21db656, 'dea14cbb8f147b2b9db21af19367882c33969235d8744f4bafad2e90d532a5a0'),
    ('network_name_calls', 0x21db656, 0x21db697, 'c8d803b800ca8d14897af5d16faf6ec4c5822cfccdf717577bfe213e007d224f'),
    ('network_numeric_and_names', 0x21db699, 0x21db709, '45032d9be5a6b20f4ad2e19ecc1873c1e5f2f85548a95c84d73b7a816df74298'),
    ('network_packed_matcher', 0x22edb60, 0x22edbf6, '7252d240294a9c1991c173663a84d485d4fcfdc4bf4d058b5491552bbc5dacd4'),
    ('network_byte_error', 0x22edabd, 0x22edb2e, '13c4fa7f1ca8ee6b28e27d0f5c1b38d336b6c25a50569eac006218d5d92ee0d8'),
    ('record_sequence_network', 0x20dd2b0, 0x20dd2da, '950e4a1ced93ebf506e6a53b5b48710d64770799dfef95dac20387ad4480a52f'),
    ('writer_fields', 0x1e89b52, 0x1e89ccc, '7e50c813efef67e510663c1a7ca63a9456e942c827746907f311190efae531ad'),
    ('network_byte_matcher', 0x22ed9ba, 0x22edabd, 'fb01bb700f718255b47342abcb93e07e4fa94e799f2acbbd6cab0432fcddb73f'),
    ('action_writer_setup', 0x1e899a1, 0x1e899e2, '7d794906339cd5abd627dcd93a07c2d3908e3caa51d59f0c34ea5f62bd816f8d'),
    ('action_writer_chain', 0x1e89af0, 0x1e89b52, '9f9f82bc256b4542be289e5fafc339314a8f2592414c0191c06f115d9167e02d'),
    ('action_writer_exit', 0x1e89ccc, 0x1e89d17, 'eefdf3857a966907feef367d76bcac9c5ab56b3cc03ecd5892534f496c83e6ac'),
    ('network_writer_fast', 0x22e6164, 0x22e628d, '4d72956574f3f0a21cce2c9305ae3f915eccecb1a94939501737d7a0d4d30ceb'),
    ('network_writer_grow', 0x22e628d, 0x22e6411, '23eb79ab382f13b47a7ed2d83618b8b403fdbe7fb9e4b931de6b656f4a9a9b18'),
]

CALLS = [
    ('action_reader_to_header_helper', 0x2880885, 0x2056f30),
    ('action_reader_to_record_reader', 0x2880fdd, 0x20dc8c0),
    ('record_to_key_iterator', 0x20dc9b6, 0x1ecdb10),
    ('key_iterator_to_adapter', 0x1ecdc1d, 0x21540c0),
    ('key_adapter_to_packed', 0x2154119, 0x1e71e80),
    ('key_adapter_owned_to_packed', 0x215418a, 0x1e71e80),
    ('key_adapter_to_bytes', 0x215412b, 0x1e719c0),
    ('key_adapter_owned_to_bytes', 0x215414c, 0x1e719c0),
    ('record_to_chain_reader', 0x20dcd1f, 0x208d290),
    ('sequence_to_chain_reader', 0x20dd2c2, 0x208d290),
    ('chain_reader_to_wrapper', 0x208d44c, 0x22e9610),
    ('chain_reader_empty_to_error', 0x208d4d2, 0x1704040),
    ('chain_reader_extra_to_error', 0x208d573, 0x1704040),
    ('chain_reader_bad_tag_detail', 0x208d5d2, 0x21c9ec0),
    ('chain_reader_bad_tag_to_error', 0x208d627, 0x1704040),
    ('wrapper_to_dispatch', 0x22e9621, 0x21db5f0),
    ('dispatch_borrowed_packed', 0x21db661, 0x22edb60),
    ('dispatch_owned_packed', 0x21db6d1, 0x22edb60),
    ('dispatch_borrowed_byte', 0x21db676, 0x22ed9b0),
    ('dispatch_owned_byte', 0x21db692, 0x22ed9b0),
    ('record_writer_to_network_writer', 0x1e89b43, 0x22e6160),
]

BRANCHES = [
    ('action_header_dispatch', 0x2880894, 0x28808f5),
    ('action_record_error_join', 0x2880ff1, 0x2882b23),
    ('action_error_return_join', 0x2882eaf, 0x28808c8),
    ('action_allocation_null', 0x2882f45, 0x288300d),
    ('other_outer_shape', 0x20dc8f7, 0x20de861),
    ('key_result_failure', 0x20dc9c8, 0x20dd111),
    ('duplicate_network_field', 0x20dccdb, 0x20de5bb),
    ('missing_network_value', 0x20dccf3, 0x20de2b4),
    ('network_value_success', 0x20dcd34, 0x20dc9b0),
    ('network_value_error_join', 0x20dd48e, 0x20dd126),
    ('missing_network_field_check', 0x20dd63a, 0x20dd6aa),
    ('missing_helper_non_success', 0x20dd6a4, 0x20ddaee),
    ('key_iterator_empty', 0x1ecdb1f, 0x1ecdb3b),
    ('key_iterator_end_pointer', 0x1ecdb29, 0x1ecdb3b),
    ('key_iterator_not_empty_marker', 0x1ecdb39, 0x1ecdb4e),
    ('key_iterator_count_overflow', 0x1ecdb7e, 0x1ecdc55),
    ('key_matcher_length_outside', 0x1e71e88, 0x1e71fe8),
    ('key_byte_matcher_length_outside', 0x1e719d2, 0x1e71dd9),
    ('key_tag_outside', 0x21540d9, 0x2154201),
    ('key_byte_numeric_outside', 0x21540f8, 0x2154281),
    ('key_word_numeric_outside', 0x215415b, 0x215421a),
    ('network_type_outside', 0x21db621, 0x21db780),
    ('chain_input_tag_12', 0x208d2ab, 0x208d3f8),
    ('chain_input_tag_13', 0x208d2b4, 0x208d3f8),
    ('chain_input_tag_other', 0x208d2bd, 0x208d5c4),
    ('chain_input_empty_sequence', 0x208d2fc, 0x208d472),
    ('chain_input_empty_first', 0x208d315, 0x208d472),
    ('chain_input_extra_element', 0x208d386, 0x208d4f3),
    ('network_small_numeric_outside', 0x21db640, 0x21db803),
    ('network_word_numeric_outside', 0x21db6a1, 0x21db79c),
    ('network_packed_length_seven', 0x22edb64, 0x22edb87),
    ('network_packed_bad_length', 0x22edb6a, 0x22edbdb),
    ('writer_network_failure', 0x1e89b4c, 0x1e89cf2),
    ('local_prefix_grow', 0x22e6184, 0x22e634f),
    ('local_payload_grow', 0x22e61a0, 0x22e637f),
    ('testnet_prefix_grow', 0x22e61c5, 0x22e628d),
    ('testnet_payload_grow', 0x22e61e1, 0x22e62bd),
    ('mainnet_prefix_grow', 0x22e6202, 0x22e62ee),
    ('mainnet_payload_grow', 0x22e621e, 0x22e631e),
    ('sandbox_prefix_grow', 0x22e623f, 0x22e63b0),
    ('sandbox_payload_grow', 0x22e625b, 0x22e63e0),
]

RIP_REFS = [
    ('action_type_key', 0x2880844, '488d05', 0x20a074),
    ('action_type_description', 0x288085f, '488d05', 0x3f4784),
    ('action_dispatch_table', 0x2880915, '488d0d', 0x3f34f0),
    ('action_record_name', 0x2880fb9, '488d15', 0x3c22a9),
    ('action_field_descriptor', 0x2880fc0, '4c8d05', 0x568f248),
    ('field_descriptor_error', 0x1e71fe9, '488d0d', 0x568f248),
    ('field_byte_descriptor_error', 0x1e71def, '488d0d', 0x568f248),
    ('network_descriptor_packed_error', 0x22edbdc, '488d0d', 0x56a0fc0),
    ('network_descriptor_byte_error', 0x22edad3, '488d0d', 0x56a0fc0),
    ('network_field_compare', 0x1e71fb1, '660f7405', 0x208380),
    ('network_field_write', 0x1e89b2a, '0f1005', 0x208380),
    ('network_field_missing', 0x20dd63c, '488d05', 0x208380),
    ('network_field_duplicate', 0x20de5bb, '488d05', 0x208380),
    ('missing_value_text', 0x20de2b4, '488d3d', 0x3c278b),
    ('missing_format', 0x20dd676, '488d35', 0x1df8f3),
    ('duplicate_format', 0x20de5ef, '488d35', 0x1e0fd5),
]

# Piece: (instruction VA, opcode prefix, immediate size, destination offset).
# The cases encode only the instructions admitted in this digest-bound study.
FIELD_PIECES = [
    ('rip', 0x1e71f9a, 0x1e71fdf),
    ('rip', 0x1e71fb1, 0x1e71fc4),
    (11, [(0x1e71f6d, '48b8', 8, 0), (0x1e71f7a, '48b9', 8, 3)], 0x1e71f8d),
    (9, [(0x1e71ed3, '48b8', 8, 0), (0x1e71ee4, '4883f1', 1, 8)], 0x1e71ef1),
    (14, [(0x1e71f1c, '48b8', 8, 0), (0x1e71f29, '48b9', 8, 6)], 0x1e71fd6),
    (5, [(0x1e71e9e, 'b8', 4, 0), (0x1e71ea9, '83f1', 1, 4)], 0x1e71fcd),
    (6, [(0x1e71efa, 'b8', 4, 0), (0x1e71f05, '81f1', 2, 4)], 0x1e71f13),
    (14, [(0x1e71f40, '48b8', 8, 0), (0x1e71f4d, '48b9', 8, 6)], 0x1e71f64),
    (5, [(0x1e71eb4, 'b8', 4, 0), (0x1e71ebf, '83f1', 1, 4)], 0x1e71eca),
]
NAME_PIECES = [
    (5, [(0x22edb6c, 'b8', 4, 0), (0x22edb77, '83f1', 1, 4)], 0x22edb7e),
    (7, [(0x22edb87, 'b8', 4, 0), (0x22edb8e, 'b9', 4, 3)], 0x22edbc9),
    (7, [(0x22edb9a, 'b8', 4, 0), (0x22edba1, 'b9', 4, 3)], 0x22edbd2),
    (7, [(0x22edbad, 'b8', 4, 0), (0x22edbb4, 'b9', 4, 3)], 0x22edbc0),
]
BYTE_MATCHES = [
    ([(0x22ed9c0, '803e'), (0x22ed9c9, '807e01'), (0x22ed9d3, '807e02'),
      (0x22ed9dd, '807e03'), (0x22ed9e7, '807e04')], 0x22ed9f1),
    ([(0x22eda15, '83f9'), (0x22eda1e, '807e01'), (0x22eda28, '807e02'),
      (0x22eda32, '807e03'), (0x22eda3c, '807e04'), (0x22eda42, '807e05'),
      (0x22eda48, '807e06')], 0x22eda4e),
    ([(0x22eda10, '83f9'), (0x22eda5b, '807e01'), (0x22eda61, '807e02'),
      (0x22eda67, '807e03'), (0x22eda6d, '807e04'), (0x22eda73, '807e05'),
      (0x22eda79, '807e06')], 0x22eda7f),
    ([(0x22eda0b, '83f9'), (0x22eda8c, '807e01'), (0x22eda92, '807e02'),
      (0x22eda98, '807e03'), (0x22eda9e, '807e04'), (0x22edaa4, '807e05'),
      (0x22edaaa, '807e06')], 0x22edab0),
]

WRITE_PIECES = [
    (5, [(0x22e61ab, 'c70437', 4, 0), (0x22e61a6, 'c6443704', 1, 4)], 0x22e618e),
    (7, [(0x22e6269, 'c70437', 4, 0), (0x22e6261, 'c7443703', 4, 3)], 0x22e6249),
    (7, [(0x22e61ef, 'c70437', 4, 0), (0x22e61e7, 'c7443703', 4, 3)], 0x22e61cf),
    (7, [(0x22e622c, 'c70437', 4, 0), (0x22e6224, 'c7443703', 4, 3)], 0x22e620c),
]


def verify_identity(data, expected=SHA256):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node 94 size or SHA-256 mismatch')


class Image:
    """ELF byte view with optional per-file-offset mutations for negative controls."""
    def __init__(self, data, patches=None, section_rows=None):
        self.data = data
        self.sections = sections(data) if section_rows is None else section_rows
        self.patches = {} if patches is None else dict(patches)

    def offset(self, va, size=1):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise ValueError('invalid address or length')
        rows = [s for s in self.sections if s['type'] != 8 and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(rows) != 1:
            raise ValueError('address is absent, crosses a section, or is ambiguous')
        row = rows[0]
        off = row['offset'] + va - row['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('file mapping outside input')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        b = bytearray(self.data[off:off + size])
        for pos, byte in self.patches.items():
            if off <= pos < off + size:
                b[pos - off] = byte
        return bytes(b)

    def changed(self, va, value):
        if not 0 <= value <= 255:
            raise ValueError('bad patch byte')
        return Image(self.data, {**self.patches, self.offset(va): value}, self.sections)


def expect(actual, expected, label):
    if actual != expected:
        raise ValueError('unexpected bytes or relation: ' + label)


def rip_target(img, va, prefix):
    prefix = bytes.fromhex(prefix)
    raw = img.read(va, len(prefix) + 4)
    expect(raw[:len(prefix)], prefix, 'RIP opcode')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def transfer(img, va):
    first = img.read(va, 2)
    if first[0] in (0xe8, 0xe9):
        size, disp = 5, 1
    elif first[0] == 0xeb or 0x70 <= first[0] <= 0x7f:
        size, disp = 2, 1
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        size, disp = 6, 2
    else:
        raise ValueError('unsupported transfer encoding')
    raw = img.read(va, size)
    delta = struct.unpack_from('<b' if size == 2 else '<i', raw, disp)[0]
    return va + size + delta, raw


def immediate(img, va, prefix, count):
    prefix = bytes.fromhex(prefix)
    raw = img.read(va, len(prefix) + count)
    expect(raw[:len(prefix)], prefix, 'immediate opcode')
    return raw[len(prefix):]


def join_pieces(img, length, specs):
    out = [None] * length
    for va, prefix, count, at in specs:
        piece = immediate(img, va, prefix, count)
        if at < 0 or at + len(piece) > length:
            raise ValueError('piece outside compared slice')
        for n, byte in enumerate(piece):
            j = at + n
            if out[j] is not None and out[j] != byte:
                raise ValueError('overlapping byte comparisons disagree')
            out[j] = byte
    if any(b is None for b in out):
        raise ValueError('comparison leaves input byte unconstrained')
    return bytes(out)


def stored_tag(img, va):
    b = img.read(va, 5)
    expect(b[:4], bytes.fromhex('66c70709'), 'success tag store')
    return b[4]


def relocation_map(img, wanted):
    rows = [s for s in img.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rows) != 1 or rows[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    s = rows[0]
    raw = img.read(s['address'], s['size'])
    found = {}
    for off in range(0, len(raw), 24):
        slot, info, addend = struct.unpack_from('<QQq', raw, off)
        if slot in wanted:
            if slot in found or info != 8:
                raise ValueError('ambiguous or non-relative descriptor relocation')
            found[slot] = (addend, s['offset'] + off)
    if set(found) != set(wanted):
        raise ValueError('missing descriptor relocation')
    return found


def descriptor(img, rels, slot):
    raw = img.read(slot, 16)
    _, length = struct.unpack('<QQ', raw)
    if not 0 < length <= 64:
        raise ValueError('descriptor length outside study')
    va, rel_off = rels[slot]
    return {'slot': slot, 'slot_offset': img.offset(slot, 16), 'va': va,
            'offset': img.offset(va, length), 'length': length,
            'text': img.read(va, length), 'relocation_offset': rel_off,
            'raw': raw.hex()}


def table(img, name, lea, prefix, count, start, end):
    base = rip_target(img, lea, prefix)
    result = []
    for index in range(count):
        slot = base + 4 * index
        raw = img.read(slot, 4)
        dest = base + struct.unpack('<i', raw)[0]
        if not start <= dest < end:
            raise ValueError('jump table target outside selected extent: ' + name)
        result.append({'table': name, 'index': index, 'base': base,
                       'slot': slot, 'slot_offset': img.offset(slot, 4),
                       'raw': raw.hex(), 'destination': dest})
    return result


def function_records(img):
    _, records = eh_frame_records(img.data, img.sections)
    by_start = {}
    for fde in records:
        if fde['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[fde['start']] = fde
    result = []
    for name, start in FUNCTIONS:
        if start not in by_start:
            raise ValueError('selected FDE missing: ' + name)
        fde = by_start[start]
        if fde['end'] <= start:
            raise ValueError('empty selected FDE')
        body = img.read(start, fde['end'] - start)
        result.append({'role': name, 'start': start, 'end': fde['end'],
                       'file_offset': img.offset(start, len(body)), 'fde': fde['fde'],
                       'cie': fde['cie'], 'lsda': fde['lsda'], 'size': len(body),
                       'sha256': hashlib.sha256(body).hexdigest(), 'bytes': body.hex()})
    return result


def validate_anchors(img):
    rows = []
    for label, start, end, digest in ANCHORS:
        raw = img.read(start, end - start)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('anchor mismatch: ' + label)
        rows.append({'label': label, 'start': start, 'end': end,
                     'file_offset': img.offset(start, len(raw)), 'bytes': raw.hex()})
    return rows


def template(img, va):
    n = img.read(va, 1)[0]
    raw = img.read(va, n + 5)
    expect(raw[n + 1:], bytes.fromhex('c0016000'), 'diagnostic template ending')
    return raw


def extract(img):
    anchors = validate_anchors(img)
    functions = function_records(img)
    byname = {f['role']: f for f in functions}
    key_guard = img.read(0x1e71e84, 4)
    expect(key_guard[:3], bytes.fromhex('4883f8'), 'key length guard')
    key_table_count = key_guard[3] + 1
    tag_guard = img.read(0x21db61e, 3)
    expect(tag_guard[:2], bytes.fromhex('83f8'), 'network tag guard')
    tag_table_count = tag_guard[2] + 1
    name_guard = img.read(0x21db63c, 4)
    expect(name_guard[:3], bytes.fromhex('4883f8'), 'network index guard')
    name_count = name_guard[3] + 1
    key_tag_guard = img.read(0x21540d6, 3)
    expect(key_tag_guard[:2], bytes.fromhex('83f8'), 'field tag guard')
    key_tag_count = key_tag_guard[2] + 1
    key_index_guard = img.read(0x21540f4, 4)
    key_word_guard = img.read(0x2154157, 4)
    expect(key_index_guard[:3], bytes.fromhex('4883f8'), 'field byte guard')
    expect(key_word_guard, key_index_guard, 'field numeric guard equality')
    key_index_count = key_index_guard[3] + 1
    key_byte_length_guard = img.read(0x1e719ce, 4)
    expect(key_byte_length_guard[:3], bytes.fromhex('4883f9'), 'field byte length guard')
    expect(key_byte_length_guard[3] + 1, key_table_count, 'field length table counts')
    field_count = int.from_bytes(immediate(img, 0x1e71ff0, '41b8', 4), 'little')
    end_marker = img.read(0x1ecdb3b, 5)
    expect(end_marker[:4], bytes.fromhex('66c70709'), 'key iteration end tag')
    record_table_count = end_marker[4] + 1
    expect(field_count, len(FIELD_PIECES), 'field descriptor count')
    expect(field_count, key_index_count, 'field numeric domain')
    expect(name_count, len(NAME_PIECES), 'network descriptor count')
    expect(record_table_count, field_count + 1, 'record dispatch count')
    rel_wanted = {0x568f248 + 16 * i for i in range(field_count)} | {0x56a0fc0 + 16 * i for i in range(name_count)}
    rels = relocation_map(img, rel_wanted)
    fields = []
    for index, spec in enumerate(FIELD_PIECES):
        d = descriptor(img, rels, 0x568f248 + 16 * index)
        if spec[0] == 'rip':
            target = rip_target(img, spec[1], '660f7405')
            name = img.read(target, 16)
            ret = spec[2]
        else:
            name = join_pieces(img, spec[0], spec[1])
            ret = spec[2]
        expect(name, d['text'], 'field comparison versus descriptor')
        expect(stored_tag(img, ret), index, 'field success discriminant')
        fields.append({'index': index, 'text': name.decode('ascii'), 'length': len(name),
                       'slot': d['slot'], 'string_va': d['va'], 'file_offset': d['offset'],
                       'relocation_offset': d['relocation_offset'], 'return_va': ret})

    tables = []
    specs = [
        ('field_length', 0x1e71e8e, '488d0d', key_table_count, 'key_matcher'),
        ('field_byte_length', 0x1e719d8, '488d3d', key_table_count, 'key_byte_matcher'),
        ('field_tag', 0x21540df, '488d0d', key_tag_count, 'key_adapter'),
        ('field_numeric_byte', 0x21540fe, '488d0d', key_index_count, 'key_adapter'),
        ('field_numeric_word', 0x2154161, '488d0d', key_index_count, 'key_adapter'),
        ('record_field', 0x20dc968, '4c8d25', record_table_count, 'record_reader'),
        ('network_tag', 0x21db627, '488d0d', tag_table_count, 'network_dispatch'),
        ('network_word', 0x21db6a7, '488d0d', name_count, 'network_dispatch'),
        ('network_byte', 0x21db646, '488d0d', name_count, 'network_dispatch'),
        ('network_writer', 0x22e616a, '488d35', name_count, 'network_writer'),
    ]
    for name, lea, prefix, count, owner in specs:
        f = byname[owner]
        tables.extend(table(img, name, lea, prefix, count, f['start'], f['end']))
    # The action selector is zero-extended from a byte. Search its byte-sized
    # indexable range for the selected arm, without claiming every scanned
    # word is a valid table entry or that all selector values can occur.
    expect(img.read(0x28808f5, 4), bytes.fromhex('410fb6c6'), 'action selector width')
    action_base = rip_target(img, 0x2880915, '488d0d')
    action_slots = []
    for index in range(1 << 8):
        slot = action_base + 4 * index
        raw = img.read(slot, 4)
        destination = action_base + struct.unpack('<i', raw)[0]
        if destination == 0x2880fb9:
            action_slots.append({'table': 'action_selected', 'index': index, 'base': action_base,
                                 'slot': slot, 'slot_offset': img.offset(slot, 4),
                                 'raw': raw.hex(), 'destination': destination})
    expect(len(action_slots), 1, 'selected action slot')
    tables.extend(action_slots)
    bytable = {n: [r for r in tables if r['table'] == n] for n, *_ in specs}
    expect(bytable['record_field'][1]['destination'], 0x20dccd6, 'network field branch')
    key_arms = [0x1e71e9e, 0x1e71efa, 0x1e71fe8, 0x1e71fe8, 0x1e71ed3, 0x1e71fe8,
                0x1e71f6d, 0x1e71fe8, 0x1e71fe8, 0x1e71f1c, 0x1e71fe8, 0x1e71f96]
    expect([r['destination'] for r in bytable['field_length']], key_arms, 'field length dispatch')
    expect(bytable['field_byte_length'][11]['destination'], 0x1e71bb6, '16-byte field dispatch')
    expect(bytable['field_tag'][0]['destination'], 0x21540ef, 'field tag 1')
    expect(bytable['field_tag'][3]['destination'], 0x2154153, 'field tag 4')
    for name in ('field_numeric_byte', 'field_numeric_word'):
        for i, row in enumerate(bytable[name]):
            raw = img.read(row['destination'], 5)
            expect(raw[:4], bytes.fromhex('66c70309'), 'field numeric success store')
            expect(raw[4], i, 'field numeric index')
    for name in ('network_word', 'network_byte'):
        for i, row in enumerate(bytable[name]):
            raw = img.read(row['destination'], 6)
            expect(raw[:5], bytes.fromhex('66c7042409'), 'network numeric store')
            expect(raw[5], i, 'network numeric index')

    names = []
    for index, (n, matcher, ret) in enumerate(NAME_PIECES):
        a = join_pieces(img, n, matcher)
        d = descriptor(img, rels, 0x56a0fc0 + 16 * index)
        expect(a, d['text'], 'network matcher versus descriptor')
        expect(stored_tag(img, ret), index, 'network matcher result')
        byte_specs, byte_ret = BYTE_MATCHES[index]
        byte_name = b''.join(immediate(img, site, prefix, 1) for site, prefix in byte_specs)
        expect(byte_name, a, 'byte and packed network matchers')
        byte_result = img.read(byte_ret, 5)
        expect(byte_result[:4], bytes.fromhex('66c70009'), 'byte matcher success tag')
        expect(byte_result[4], index, 'byte matcher discriminant')
        wn, writer, prefix_site = WRITE_PIECES[index]
        b = join_pieces(img, wn, writer)
        expect(a, b, 'network reader versus writer')
        expect(bytable['network_writer'][index]['destination'], prefix_site - 0x14, 'network writer arm')
        marker = immediate(img, prefix_site, 'c60437', 1)[0]
        expect(marker, 0xa0 | len(b), 'length-prefixed marker')
        names.append({'index': index, 'text': a.decode('ascii'), 'length': len(a),
                      'slot': d['slot'], 'slot_offset': d['slot_offset'],
                      'string_va': d['va'], 'file_offset': d['offset'],
                      'relocation_offset': d['relocation_offset'], 'descriptor_hex': d['raw'],
                      'reader_result_va': ret, 'byte_result_va': byte_ret, 'writer_arm': bytable['network_writer'][index]['destination'],
                      'marker': marker, 'encoded_hex': (bytes([marker]) + b).hex()})
    expect(len({r['text'] for r in names}), len(names), 'distinct network names')

    action_entries = []
    for kind, site, prefix, len_site, len_prefix in [
        ('type_key', 0x2880844, '488d05', 0x2880853, '48c7842418010000'),
        ('type_description', 0x288085f, '488d05', 0x288086e, '48c7842428010000'),
        ('record_name', 0x2880fb9, '488d15', 0x2880fd2, 'b9'),
    ]:
        va = rip_target(img, site, prefix)
        length = int.from_bytes(immediate(img, len_site, len_prefix, 4), 'little')
        if not 0 < length <= 64:
            raise ValueError('action entry length outside study')
        action_entries.append({'kind': kind, 'site': site, 'va': va, 'file_offset': img.offset(va, length),
                               'length': length, 'text': img.read(va, length).decode('ascii')})
    expect([r['text'] for r in action_entries], ['type', 'internally tagged enum Action', 'SendAssetAction'],
           'action literal entries')
    expect(rip_target(img, 0x2880fc0, '4c8d05'), 0x568f248, 'action record descriptor')
    expect(int.from_bytes(immediate(img, 0x2880fd7, '41b9', 4), 'little'), field_count,
           'action record descriptor count')
    action_route = [{'operation': operation, 'site': site, 'file_offset': img.offset(site),
                     'bytes': img.read(site, len(bytes.fromhex(prefix)) + count).hex(),
                     'value': int.from_bytes(immediate(img, site, prefix, count), 'little')}
                    for operation, site, prefix, count in [
                        ('record_copy_length', 0x2881020, 'ba', 4),
                        ('selected_action_variant', 0x2881037, '41bc', 4),
                        ('error_variant', 0x2882b2e, '41bc', 4),
                        ('record_reader_error_sentinel', 0x20dd129, '48b8', 8),
                        ('allocation_length', 0x2882f37, 'bf', 4),
                        ('returned_success_tag', 0x2882f68, 'c603', 1),
                    ]]

    # The byte matcher for the selected 16-byte field shares a first-byte
    # branch with another name; validate that branch and all tail compares.
    first = immediate(img, 0x1e71bb9, '83f9', 1)
    target, branch = transfer(img, 0x1e71bbc)
    expect(target, 0x1e71d72, 'field first-byte branch')
    field_checks = [{'index': 0, 'site': 0x1e71bb9, 'file_offset': img.offset(0x1e71bb9),
                     'bytes': img.read(0x1e71bb9, 3).hex(), 'value_hex': first.hex(),
                     'branch_site': 0x1e71bbc, 'branch_bytes': branch.hex(), 'branch_target': target}]
    for index in range(1, 16):
        site = 0x1e71d72 + 6 * (index - 1)
        prefix = '807e' + format(index, '02x')
        value = immediate(img, site, prefix, 1)
        target, branch = transfer(img, site + 4)
        expect(target, 0x1e71dd9, 'field byte mismatch branch')
        field_checks.append({'index': index, 'site': site, 'file_offset': img.offset(site),
                             'bytes': img.read(site, 4).hex(), 'value_hex': value.hex(),
                             'branch_site': site + 4, 'branch_bytes': branch.hex(), 'branch_target': target})
    expect(bytes.fromhex(''.join(r['value_hex'] for r in field_checks)),
           fields[1]['text'].encode('ascii'), 'field byte comparisons versus descriptor')
    field_byte_result = img.read(0x1e71dcc, 5)
    expect(field_byte_result, bytes.fromhex('66c7000901'), 'field byte matcher success')

    iterator = []
    for operation, site, prefix, size in [
        ('compute_pointer_advance', 0x1ecdb2b, '488d48', 1),
        ('store_pointer_slot', 0x1ecdb2f, '48894e', 1),
        ('compare_counter_sentinel', 0x1ecdb7a, '4883fa', 1),
        ('increment_counter', 0x1ecdb8b, '48ffc2', 0),
        ('store_counter_slot', 0x1ecdb8e, '488956', 1),
    ]:
        value = immediate(img, site, prefix, size)
        raw = img.read(site, len(bytes.fromhex(prefix)) + size)
        iterator.append({'operation': operation, 'site': site, 'file_offset': img.offset(site),
                         'bytes': raw.hex(), 'operand_hex': value.hex()})
    expect([r['operand_hex'] for r in iterator], ['40', '28', 'ff', '', '40'],
           'iterator state operands')

    # The same offset is independently extracted from the reader's store and writer's LEA.
    st = img.read(0x20de008, 6)
    ld = img.read(0x1e89af0, 7)
    expect(st[:2], bytes.fromhex('8885'), 'record byte store')
    expect(ld[:3], bytes.fromhex('498db7'), 'record byte address')
    store_offset = struct.unpack_from('<i', st, 2)[0]
    writer_offset = struct.unpack_from('<i', ld, 3)[0]
    expect(store_offset, writer_offset, 'reader and writer field offset')
    initial = img.read(0x20dc953, 5)
    duplicate = img.read(0x20dccd6, 5)
    missing = img.read(0x20dd636, 4)
    expect(initial[:4], bytes.fromhex('c6442408'), 'field sentinel initialisation')
    expect(duplicate[:4], bytes.fromhex('807c2408'), 'duplicate sentinel opcode')
    expect(missing[:3], bytes.fromhex('4180ff'), 'missing sentinel opcode')
    expect(duplicate[4], initial[4], 'duplicate sentinel')
    expect(missing[3], initial[4], 'missing sentinel')
    expect(initial[4], name_count, 'sentinel follows valid name domain')

    edges = []
    for label, site, target in CALLS:
        dest, raw = transfer(img, site)
        expect(raw[:1], b'\xe8', 'direct call')
        expect(dest, target, label)
        edges.append({'kind': 'call', 'label': label, 'site': site,
                      'file_offset': img.offset(site, len(raw)), 'bytes': raw.hex(), 'target': dest})
    for label, site, target in BRANCHES:
        dest, raw = transfer(img, site)
        expect(dest, target, label)
        edges.append({'kind': 'branch', 'label': label, 'site': site,
                      'file_offset': img.offset(site, len(raw)), 'bytes': raw.hex(), 'target': dest})
    refs = []
    for label, site, prefix, expected in RIP_REFS:
        dest = rip_target(img, site, prefix)
        expect(dest, expected, label)
        raw = img.read(site, len(bytes.fromhex(prefix)) + 4)
        refs.append({'label': label, 'site': site, 'file_offset': img.offset(site, len(raw)),
                     'bytes': raw.hex(), 'target': dest})
    xor = immediate(img, 0x1e899b4, '4180f4', 1)[0]
    shift = immediate(img, 0x1e899b8, '41c0e4', 1)[0]
    marker = immediate(img, 0x1e899bc, '4180cc', 1)[0]
    mode_markers = [{'mode_byte': mode, 'marker_hex': format((((mode ^ xor) << shift) | marker) & 255, '02x')}
                    for mode in (0, 1)]
    diagnostic_va = rip_target(img, 0x20de2b4, '488d3d')
    diagnostic_length = int.from_bytes(immediate(img, 0x20de2c2, 'be', 4), 'little')
    if diagnostic_length > 128:
        raise ValueError('diagnostic outside study')
    diagnostic = {'va': diagnostic_va, 'file_offset': img.offset(diagnostic_va, diagnostic_length),
                  'length': diagnostic_length, 'hex': img.read(diagnostic_va, diagnostic_length).hex()}
    templates = [{'kind': label, 'va': va, 'file_offset': img.offset(va), 'bytes': template(img, va).hex()}
                 for label, va in [('missing', 0x1df8f3), ('duplicate', 0x1e0fd5)]]
    return {'functions': functions, 'anchors': anchors, 'fields': fields, 'names': names, 'field_checks': field_checks, 'iterator': iterator,
            'action_entries': action_entries, 'action_route': action_route, 'action_index': action_slots[0]['index'],
            'tables': tables, 'edges': edges, 'refs': refs, 'mode_markers': mode_markers, 'diagnostic': diagnostic, 'templates': templates,
            'record_chain_offset': store_offset, 'missing_sentinel': initial[4]}


def classify_network(text, names):
    """Abstract exact-slice comparison, not execution of captured code."""
    if not isinstance(text, bytes):
        raise TypeError('expected bytes')
    for row in names:
        if text == row['text'].encode('ascii'):
            return row['index']
    return None


def classify_numeric(internal_tag, value, names):
    """Model two decoded internal numeric representations, not wire markers."""
    if internal_tag not in (1, 4) or type(value) is not int or value < 0:
        raise ValueError('unsupported numeric control')
    if value >= (256 if internal_tag == 1 else 1 << 64):
        raise ValueError('numeric control exceeds representation')
    return value if value < len(names) else None


def growth_trace(spare, length, grown_spare=None, fail=None):
    """Synthetic local buffer-control model; a grow callback is assumed, not executed."""
    if type(spare) is not int or type(length) is not int or spare < 0 or length <= 0:
        raise ValueError('bad synthetic buffer state')
    events = []
    if spare == 0:
        events.append('grow_prefix')
        if fail == 'prefix':
            return events
        if type(grown_spare) is not int or grown_spare < 1:
            raise ValueError('successful prefix grow needs positive spare')
        spare = grown_spare
    events.append('write_prefix')
    spare -= 1
    if spare < length:
        events.append('grow_payload')
        if fail == 'payload':
            return events
    events.append('write_payload')
    return events


def row_values(row, columns):
    out = []
    for key in columns:
        value = row.get(key)
        if value is None:
            out.append('')
        elif isinstance(value, int) and (key.endswith('_va') or key in {'start', 'end', 'fde', 'cie', 'lsda', 'base', 'slot', 'site', 'target', 'destination', 'va', 'file_offset', 'offset', 'slot_offset', 'relocation_offset', 'return_va', 'writer_arm', 'branch_site', 'branch_target'}):
            out.append(hex(value))
        else:
            out.append(value)
    return out


def write_tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(columns)
        for row in rows:
            w.writerow(row_values(row, columns))


def generate(data, output):
    verify_identity(data)
    img = Image(data)
    result = extract(img)
    output.mkdir(parents=True, exist_ok=True)
    write_tsv(output / 'functions.tsv', result['functions'], ['role', 'start', 'end', 'file_offset', 'fde', 'cie', 'lsda', 'size', 'sha256', 'bytes'])
    write_tsv(output / 'windows.tsv', result['anchors'], ['label', 'start', 'end', 'file_offset', 'bytes'])
    write_tsv(output / 'fields.tsv', result['fields'], ['index', 'text', 'length', 'slot', 'string_va', 'file_offset', 'relocation_offset', 'return_va'])
    write_tsv(output / 'field-byte-checks.tsv', result['field_checks'], ['index', 'site', 'file_offset', 'bytes', 'value_hex', 'branch_site', 'branch_bytes', 'branch_target'])
    write_tsv(output / 'iterator-state.tsv', result['iterator'], ['operation', 'site', 'file_offset', 'bytes', 'operand_hex'])
    write_tsv(output / 'action-entries.tsv', result['action_entries'], ['kind', 'site', 'va', 'file_offset', 'length', 'text'])
    write_tsv(output / 'action-route.tsv', result['action_route'], ['operation', 'site', 'file_offset', 'bytes', 'value'])
    write_tsv(output / 'networks.tsv', result['names'], ['index', 'text', 'length', 'slot', 'slot_offset', 'string_va', 'file_offset', 'relocation_offset', 'descriptor_hex', 'reader_result_va', 'byte_result_va', 'writer_arm', 'marker', 'encoded_hex'])
    write_tsv(output / 'tables.tsv', result['tables'], ['table', 'index', 'base', 'slot', 'slot_offset', 'raw', 'destination'])
    write_tsv(output / 'transfers.tsv', result['edges'], ['kind', 'label', 'site', 'file_offset', 'bytes', 'target'])
    write_tsv(output / 'rip-references.tsv', result['refs'], ['label', 'site', 'file_offset', 'bytes', 'target'])
    write_tsv(output / 'mode-markers.tsv', result['mode_markers'], ['mode_byte', 'marker_hex'])
    write_tsv(output / 'diagnostic.tsv', [result['diagnostic']], ['va', 'file_offset', 'length', 'hex'])
    write_tsv(output / 'templates.tsv', result['templates'], ['kind', 'va', 'file_offset', 'bytes'])
    cases = []
    for name in result['names']:
        payload = name['text'].encode('ascii')
        probes = [payload, payload.lower(), payload + b' ', b' ' + payload, payload + b'\x00', payload[:-1]]
        for probe in probes:
            cases.append({'input_hex': probe.hex(), 'result': classify_network(probe, result['names'])})
    for text in [b'', b'NvTestnet', b'\xff', b'TESTNET']:
        cases.append({'input_hex': text.hex(), 'result': classify_network(text, result['names'])})
    write_tsv(output / 'name-cases.tsv', cases, ['input_hex', 'result'])
    numeric_cases = []
    for tag in (1, 4):
        for value in (0, 1, 2, 3, 4, 31, 32, 75, 76, 255):
            numeric_cases.append({'internal_tag': tag, 'value': value,
                                  'result': classify_numeric(tag, value, result['names'])})
    write_tsv(output / 'numeric-cases.tsv', numeric_cases, ['internal_tag', 'value', 'result'])
    key_cases = []
    for tag in (1, 4):
        for value in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 32, 255):
            key_cases.append({'internal_tag': tag, 'value': value,
                              'result': classify_numeric(tag, value, result['fields'])})
    write_tsv(output / 'field-numeric-cases.tsv', key_cases, ['internal_tag', 'value', 'result'])
    grow_cases = []
    for name in result['names']:
        length = name['length']
        for label, spare, grown, failure in [('exact', length + 1, None, None),
                                               ('short_payload', length, None, None),
                                               ('fail_payload', 1, None, 'payload'),
                                               ('fail_prefix', 0, None, 'prefix'),
                                               ('grow_twice', 0, 1, None)]:
            grow_cases.append({'index': name['index'], 'case': label, 'initial_spare': spare,
                               'events': ','.join(growth_trace(spare, length, grown, failure))})
    write_tsv(output / 'growth-cases.tsv', grow_cases, ['index', 'case', 'initial_spare', 'events'])
    summary = {'target_sha256': SHA256, 'target_size': len(data),
               'selected_fdes': len(result['functions']),
               'selected_fde_bytes': sum(f['size'] for f in result['functions']),
               'selected_windows': len(result['anchors']), 'selected_fields': len(result['fields']),
               'network_names': len(result['names']), 'selected_table_slots': len(result['tables']),
               'selected_calls': sum(e['kind'] == 'call' for e in result['edges']),
               'selected_branches': sum(e['kind'] == 'branch' for e in result['edges']),
               'selected_rip_references': len(result['refs']),
               'name_cases': len(cases), 'numeric_cases': len(numeric_cases), 'field_numeric_cases': len(key_cases),
               'field_byte_checks': len(result['field_checks']), 'growth_cases': len(grow_cases),
               'record_chain_offset': result['record_chain_offset'],
               'selected_action_index': result['action_index'],
               'local_missing_sentinel': result['missing_sentinel'],
               'scope': 'Selected byte windows, table slots, and FDE ranges; no complete CFG or target execution.'}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
