# SPDX-License-Identifier: MIT
"""Extract selected node #115 result encoders from authenticated ELF bytes.

The only reconstructed logic here is a deliberately bounded synthetic wire model;
this tool neither executes the captured binary nor invokes external programs.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SENTINEL = 1 << 63

# Selected FDE ranges are pinned separately from their whole-artifact identity.
# Their names describe emitted labels or local roles; they are not source names.
FUNCTIONS = (
    ('result', 0x59229a0, 0x5922bc3, 'fc41aebcdab6b9ed8e2ef0dbdfe16c733e65d0a9f29a0ad62fc50a99b04795b7'),
    ('variants', 0x4d8fcd0, 0x4d907b6, 'c6b9c4888c9799c63006d5c369bf4c52d185dd103bbcf94e6d9c789c68826bee'),
    ('order', 0x4e0d3c0, 0x4e0d41c, '68964a14bbf2634f0d293f319ba4f393333797b039e631a69b3ee7a7c13ff96a'),
    ('cancel', 0x4e0d4c0, 0x4e0d51c, 'c0e36acc46cc4e1bfc6c915fe6fbde109a28a665b62059314bb61ea37dbf2fb0'),
    ('create_vault', 0x4e0dc50, 0x4e0dcf9, '39cc54363e9bad18c1bf272370bdf4a89d84452ccc3b0282313d64ef59125c61'),
    ('liquidation', 0x4e0c0b0, 0x4e0c110, '02a6de365dae9f34cb3c2637265f311e84924e14cefc3380c99a49c9ea484c59'),
    ('twap_order', 0x4e0c240, 0x4e0c29c, 'e0e0a1ca871a9557c9a6e742876ec2adb533e770da30beffdacd7d82bf2fdadb'),
    ('twap_cancel', 0x4e0fb90, 0x4e0fbec, '127de5690d2090c1f79f3aac5382b12eae0968ca14b273a1fc2a94885268352d'),
    ('trailing_stop', 0x4e0c7c0, 0x4e0c81c, '5f8628e37946e4b5aafb8b23a3ed5f00ddb409de46e9cbf03005f2f48fc4c7cd'),
    ('create_subaccount', 0x4e0ef70, 0x4e0f019, '55a44d15e1eb14afe3285912cd14f5161df31c4cefb91f5586fdbd3e8b9fe907'),
    ('token_and_spot', 0x4e0dd90, 0x4e0de21, '7cfacf78f430931f2659b5c6bfbb8ba10e9743bfd6af0cde886f25b4c1c36e72'),
    ('validator_vote', 0x4e0f0d0, 0x4e0f1ed, '87d6ced53a3555b6fcc8e5a1e4d4c7d3e9eca0a8d9ec075fab7d268938b7a520'),
    ('governance_proposal', 0x4e0fc50, 0x4e0fd05, '5ceaf79e9c6ef2cc38513c707bdf2a1e892b1992acc4b2a004733d6e40c070c0'),
    ('set_global', 0x4e0fbf0, 0x4e0fc50, '6d9f5ca6fd53640ff45af62e34bf65c4b1de5ea54d89f46f36e6c6d86ba62793'),
    ('delayed', 0x4e0c110, 0x4e0c23f, '3f61e4d5f204b0ce879c4dbf9da0da88ff79ecf275393d9b75154bceb36826be'),
    ('delayed_id', 0x4e0d7a0, 0x4e0d8d0, 'bcdcb246adcd82d33fae7b328d06526bd8c5c60c8ef556952b9ccf542d1f872a'),
    ('order_status_container', 0x518a280, 0x518a35e, 'eafbed0d6231ec1996cab8a928c6278fac93ba38df6b9dc4feba1e5978c8557e'),
    ('cancel_status_container', 0x518a630, 0x518a70e, '3690f17ca1827a01fd9110d3db965726077afde8cb85b09f50c21ba6cd646ea8'),
    ('order_status_array', 0x52e32a0, 0x52e35ec, '2660ef5b108b371dbf54af55a4e139eee7ff23bbb0b726ae249c56f1c16c2f05'),
    ('cancel_status_array', 0x52a7b90, 0x52a7fbd, 'abb032924d9730afc5a0d05c6f683363e8e53836a3a7ca41674d94136f4d1f48'),
    ('status_error_value', 0x5301c00, 0x5301d45, 'b181d9dffe88830e3b85bdde715895da3552b40eadaf6b6c9fba0702631d3906'),
    ('order_status_value', 0x5188f20, 0x5189312, 'e7fa428402c333f3368e34fe2f5d5350e2b016ad21975615d5debe697b7acb79'),
)

# These are discovery coordinates, not generated values. Each entry, name,
# argument-form pattern and call destination is independently checked below.
CASES = (
    (0x4d8fcf7, b'order', 0x4d90431, 0x4e0d3c0, 'address+8'),
    (0x4d8febb, b'cancel', 0x4d904b3, 0x4e0d4c0, 'address+8'),
    (0x4d8fe1d, b'createVault', 0x4d902ad, 0x4e0dc50, 'address+1'),
    (0x4d8fe55, b'liquidation', 0x4d9032f, 0x4e0c0b0, 'address+8'),
    (0x4d8fd93, b'twapOrder', 0x4d90135, 0x4e0c240, 'address+8'),
    (0x4d8fee9, b'twapCancel', 0x4d90535, 0x4e0fb90, 'address+8'),
    (0x4d8ff45, b'trailingStop', 0x4d90639, 0x4e0c7c0, 'address+8'),
    (0x4d8fe83, b'createSubAccount', 0x4d903a2, 0x4e0ef70, 'address+1'),
    (0x4d8ffa1, b'token', 0x4d90755, 0x4e0dd90, 'word+8'),
    (0x4d8fdef, b'spot', 0x4d90236, 0x4e0dd90, 'word+8'),
    (0x4d8ff73, b'validatorVote', 0x4d906bd, 0x4e0f0d0, 'byte+1'),
    (0x4d8fd65, b'governanceProposal', 0x4d900b3, 0x4e0fc50, 'address+1'),
    (0x4d8fdc1, b'setGlobal', 0x4d901b7, 0x4e0fbf0, 'address+8'),
    (0x4d8ff17, b'delayed', 0x4d905b7, 0x4e0c110, 'address+8'),
    (0x4d8fd25, b'default', None, None, 'none'),
)
# Expected local return blocks. Values are checked against decoded rel8/rel32
# targets before any table is emitted.
ARRAY_FAILURE = (0x4d90769, 0x4d90769, 0x4d903ac, 0x4d90769, 0x4d90769,
                 0x4d90769, 0x4d90769, 0x4d903ac, 0x4d90769, 0x4d90769,
                 0x4d90769, 0x4d90769, 0x4d90769, 0x4d90769, 0x4d8fd58)
STRING_FAILURE = (0x4d906da, 0x4d906da, 0x4d90785, 0x4d906da, 0x4d90785,
                  0x4d90785, 0x4d90785, 0x4d90785, 0x4d90785, 0x4d906da,
                  0x4d906da, 0x4d906da, 0x4d906da, 0x4d90785, 0x4d907b1)
MAP_HEADER = 0x57ce100
ARRAY_HEADER = 0x57ceba0
STRING_WRITER = 0x57cf860
VARIANT_FUNCTION = 0x4d8fcd0
# Additional branches are restricted to the new outer result and delayed path.
# Their targets are recomputed from signed displacements, not disassembler text.
EXTRA_BRANCHES = (
    ('result', 'tag_other', 0x59229c3, 'jne', 0x59229ee),
    ('result', 'err_array', 0x59229ca, 'je', 0x5922a1f),
    ('result', 'err_map_header_ok', 0x59229e7, 'je', 0x5922a40),
    ('result', 'ok_array', 0x59229f3, 'je', 0x5922ad1),
    ('result', 'ok_map_header_ok', 0x5922a14, 'je', 0x5922aee),
    ('result', 'err_array_header_failure', 0x5922a3a, 'jne', 0x5922b6a),
    ('result', 'err_skip_status_key', 0x5922a45, 'jne', 0x5922a65),
    ('result', 'err_status_key_failure', 0x5922a5f, 'jne', 0x5922b7c),
    ('result', 'err_label_failure', 0x5922a7d, 'jne', 0x5922b7c),
    ('result', 'err_skip_response_key', 0x5922a90, 'jne', 0x5922ab0),
    ('result', 'err_response_key_failure', 0x5922aaa, 'jne', 0x5922b7c),
    ('result', 'err_string_failure', 0x5922ac2, 'jne', 0x5922b7c),
    ('result', 'ok_array_header_failure', 0x5922aec, 'jne', 0x5922b6a),
    ('result', 'ok_skip_status_key', 0x5922af3, 'jne', 0x5922b0f),
    ('result', 'ok_status_key_failure', 0x5922b0d, 'jne', 0x5922b7c),
    ('result', 'ok_label_failure', 0x5922b27, 'jne', 0x5922b7c),
    ('result', 'ok_skip_response_key', 0x5922b2e, 'jne', 0x5922b4a),
    ('result', 'ok_response_key_failure', 0x5922b48, 'jne', 0x5922b98),
    ('result', 'ok_child_failure', 0x5922b63, 'jne', 0x5922ba7),
    ('delayed', 'skip_data_key', 0x4e0c134, 'je', 0x4e0c18d),
    ('delayed', 'data_key_failure', 0x4e0c14e, 'jne', 0x4e0c213),
    ('delayed', 'select_array', 0x4e0c159, 'je', 0x4e0c18d),
    ('delayed', 'map_header_ok', 0x4e0c176, 'je', 0x4e0c1aa),
    ('delayed', 'array_header_failure', 0x4e0c1a8, 'jne', 0x4e0c178),
    ('delayed', 'skip_until_key', 0x4e0c1b3, 'jne', 0x4e0c1cf),
    ('delayed', 'until_key_failure', 0x4e0c1cd, 'jne', 0x4e0c213),
    ('delayed', 'until_value_failure', 0x4e0c1e8, 'jne', 0x4e0c20e),
    ('delayed', 'id_result_failure', 0x4e0c207, 'jne', 0x4e0c22c),
    ('delayed_id', 'skip_id_key', 0x4e0d7c7, 'je', 0x4e0d81d),
    ('delayed_id', 'id_key_failure', 0x4e0d7e1, 'jne', 0x4e0d8b7),
    ('delayed_id', 'select_array', 0x4e0d7ec, 'je', 0x4e0d81d),
    ('delayed_id', 'map_header_ok', 0x4e0d806, 'je', 0x4e0d837),
    ('delayed_id', 'array_header_failure', 0x4e0d835, 'jne', 0x4e0d808),
    ('delayed_id', 'skip_height_key', 0x4e0d83c, 'jne', 0x4e0d858),
    ('delayed_id', 'height_key_failure', 0x4e0d856, 'jne', 0x4e0d8b7),
    ('delayed_id', 'height_value_failure', 0x4e0d86e, 'jne', 0x4e0d8b2),
    ('delayed_id', 'skip_index_key', 0x4e0d875, 'jne', 0x4e0d891),
    ('delayed_id', 'index_key_failure', 0x4e0d88f, 'jne', 0x4e0d8b7),
    ('delayed_id', 'index_value_failure', 0x4e0d8a7, 'jne', 0x4e0d8b2),
    ('validator_vote', 'skip_data_key', 0x4e0f0f5, 'je', 0x4e0f10b),
    ('validator_vote', 'data_key_failure', 0x4e0f109, 'jne', 0x4e0f145),
    ('validator_vote', 'capacity_equal', 0x4e0f118, 'je', 0x4e0f15f),
    ('validator_vote', 'rechecked_capacity_equal', 0x4e0f12a, 'je', 0x4e0f1c5),
    ('validator_vote', 'growth_ok', 0x4e0f193, 'je', 0x4e0f1b0),
    ('order_container', 'array', 0x518a2a2, 'je', 0x518a2d0),
    ('order_container', 'map_header_ok', 0x518a2bc, 'je', 0x518a2ea),
    ('order_container', 'array_header_failure', 0x518a2e8, 'jne', 0x518a2be),
    ('order_container', 'skip_statuses_key', 0x518a2ef, 'jne', 0x518a30b),
    ('order_container', 'statuses_key_failure', 0x518a309, 'jne', 0x518a328),
    ('order_container', 'array_result_failure', 0x518a321, 'jne', 0x518a336),
    ('cancel_container', 'array', 0x518a652, 'je', 0x518a680),
    ('cancel_container', 'map_header_ok', 0x518a66c, 'je', 0x518a69a),
    ('cancel_container', 'array_header_failure', 0x518a698, 'jne', 0x518a66e),
    ('cancel_container', 'skip_statuses_key', 0x518a69f, 'jne', 0x518a6bb),
    ('cancel_container', 'statuses_key_failure', 0x518a6b9, 'jne', 0x518a6d8),
    ('cancel_container', 'array_result_failure', 0x518a6d1, 'jne', 0x518a6e6),
    ('order_array', 'direct_candidate_rejected', 0x52e32e1, 'je', 0x52e3304),
    ('order_array', 'array_header_failure', 0x52e3330, 'jne', 0x52e33f0),
    ('order_array', 'direct_flag_absent', 0x52e3350, 'je', 0x52e337e),
    ('order_array', 'first_element_absent', 0x52e335d, 'je', 0x52e33b5),
    ('order_array', 'first_element_failure', 0x52e3378, 'jne', 0x52e3576),
    ('order_array', 'loop_empty', 0x52e3384, 'je', 0x52e33b5),
    ('order_array', 'element_failure', 0x52e33a6, 'jne', 0x52e356f),
    ('order_array', 'loop_continue', 0x52e33b3, 'jne', 0x52e3390),
    ('order_array', 'allocation_null', 0x52e341e, 'je', 0x52e35b6),
    ('order_array', 'buffered_element_failure', 0x52e34aa, 'jne', 0x52e3535),
    ('order_array', 'counter_limit', 0x52e34de, 'je', 0x52e35a7),
    ('cancel_array', 'direct_candidate_rejected', 0x52a7bc6, 'je', 0x52a7be1),
    ('cancel_array', 'array_header_failure', 0x52a7c06, 'jne', 0x52a7c83),
    ('cancel_array', 'direct_flag_absent', 0x52a7c2c, 'je', 0x52a7d0b),
    ('cancel_array', 'first_element_absent', 0x52a7c3f, 'je', 0x52a7db3),
    ('cancel_array', 'first_non_sentinel', 0x52a7c49, 'jne', 0x52a7ee5),
    ('cancel_array', 'success_string_failure', 0x52a7c67, 'jne', 0x52a7f14),
    ('cancel_array', 'loop_empty', 0x52a7d20, 'je', 0x52a7db3),
    ('cancel_array', 'element_non_sentinel', 0x52a7d53, 'jne', 0x52a7d80),
    ('cancel_array', 'success_string_ok', 0x52a7d6c, 'je', 0x52a7da1),
    ('cancel_array', 'element_failure', 0x52a7da4, 'jne', 0x52a7ede),
    ('cancel_array', 'loop_continue', 0x52a7db1, 'jne', 0x52a7d50),
    ('cancel_array', 'counter_limit', 0x52a7e6e, 'je', 0x52a7f78),
    ('status_error', 'capacity_equal', 0x5301c2b, 'je', 0x5301ca3),
    ('status_error', 'capacity_rechecked_equal', 0x5301c35, 'je', 0x5301d15),
    ('status_error', 'key_failure', 0x5301c56, 'jne', 0x5301c79),
    ('status_error', 'value_failure', 0x5301c71, 'jne', 0x5301c86),
    ('status_error', 'growth_ok', 0x5301cd7, 'je', 0x5301cf4),
    ('status_error', 'growth_capacity_unequal', 0x5301d0f, 'jne', 0x5301c3b),
    ('order_status', 'filled_header_failure', 0x5188f74, 'jne', 0x51892f0),
    ('order_status', 'filled_label_failure', 0x5188f92, 'jne', 0x51892f5),
    ('order_status', 'error_header_failure', 0x5188ff0, 'jne', 0x518911e),
    ('order_status', 'error_label_failure', 0x518900e, 'jne', 0x51892f5),
    ('order_status', 'error_value_failure', 0x5189028, 'jne', 0x5189133),
    ('order_status', 'waiting_fill_failure', 0x518905c, 'jne', 0x518908e),
    ('order_status', 'waiting_trigger_ok', 0x518908c, 'je', 0x518905e),
    ('order_status', 'resting_header_failure', 0x51890be, 'jne', 0x5189107),
    ('order_status', 'resting_label_failure', 0x51890d8, 'jne', 0x518910c),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=TARGET_SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'artifact SHA-256 mismatch')


class Image:
    """Map a complete range to exactly one file-backed allocated section."""
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid virtual address or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range is not uniquely file-backed and allocated')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(0 <= off and off + size <= len(self.data), 'range outside file')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])

    def unique_section(self, name):
        rows = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or duplicate file-backed section')
        return rows[0]


def bytes_at(image, va, wanted):
    expected = bytes.fromhex(wanted)
    require(image.read(va, len(expected)) == expected, 'instruction bytes changed')


def rel32(image, va, opcode=b'\xe8'):
    raw = image.read(va, len(opcode) + 4)
    require(raw.startswith(opcode), 'unexpected relative instruction')
    return va + len(raw) + struct.unpack_from('<i', raw, len(opcode))[0]


def branch(image, va, expected_kind=None):
    first = image.read(va, 2)
    if first[0] in (0x74, 0x75):
        raw = first
        kind = 'je' if first[0] == 0x74 else 'jne'
        displacement = struct.unpack_from('<b', first, 1)[0]
    else:
        raw = image.read(va, 6)
        require(raw[:2] in (b'\x0f\x84', b'\x0f\x85'), 'unsupported conditional branch')
        kind = 'je' if raw[1] == 0x84 else 'jne'
        displacement = struct.unpack_from('<i', raw, 2)[0]
    require(expected_kind is None or kind == expected_kind, 'conditional branch inverted')
    return {'va': va, 'file_offset': image.offset(va, len(raw)), 'bytes': raw.hex(),
            'kind': kind, 'target': va + len(raw) + displacement, 'size': len(raw)}


def decode_string_load(image, va):
    raw = image.read(va, 20)
    require(raw[:3] == b'\x48\x8d\x35' and raw[7] == 0xba
            and raw[12:15] in (b'\x4c\x89\xf7', b'\x4c\x89\xff', b'\x4c\x89\xe7'), 'unexpected string load')
    address = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    length = struct.unpack_from('<I', raw, 8)[0]
    require(0 < length <= 64, 'unexpected selected string length')
    require(rel32(image, va + 15) == STRING_WRITER, 'unexpected string writer')
    literal = image.read(address, length)
    require(all(32 <= x < 127 for x in literal), 'selected literal is not printable ASCII')
    return {'load_va': va, 'load_file_offset': image.offset(va, 20),
            'literal_va': address, 'literal_file_offset': image.offset(address, length),
            'length': length, 'bytes': literal.hex(), 'text': literal.decode('ascii'),
            'writer_call_va': va + 15}


def expect_header(image, va, expected_target, expected_size):
    raw = image.read(va, 16)
    require(raw[:7] == b'\x48\x89\xe7\x4c\x89\xf6\xba', 'unexpected header arguments')
    count = struct.unpack_from('<I', raw, 7)[0]
    require(count == expected_size, 'unexpected header element count')
    require(rel32(image, va + 11) == expected_target, 'unexpected header target')
    bytes_at(image, va + 16, '488b04244883f802')
    return va + 24


def map_variants(image):
    # movzbl input tag; lea table(%rip); movslq table[tag*4]; add; indirect jmp.
    bytes_at(image, 0x4d8fce4, '0fb606')
    table = rel32(image, 0x4d8fce7, b'\x48\x8d\x0d')
    bytes_at(image, 0x4d8fcee, '486304814801c8ffe0')
    require(table == 0x914e5c, 'unexpected jump table')
    rows, branches = [], []
    for tag, (expected_entry, expected_name, payload_site, payload_target, form) in enumerate(CASES):
        table_site = table + tag * 4
        table_bytes = image.read(table_site, 4)
        entry = table + struct.unpack('<i', table_bytes)[0]
        require(entry == expected_entry, 'unexpected jump-table entry')
        scan = image.read(entry, 40)
        pattern = b'\x41\x80\x7e\x0b\x00'
        require(scan.count(pattern) == 1, 'missing or ambiguous mode comparison')
        cmp_site = entry + scan.index(pattern)
        zero = branch(image, cmp_site + len(pattern), 'je')
        count = 1 if payload_site is None else 2
        map_start = zero['va'] + zero['size']
        map_status = expect_header(image, map_start, MAP_HEADER, count)
        map_ok = branch(image, map_status, 'je')
        arr_status = expect_header(image, zero['target'], ARRAY_HEADER, count)
        arr_fail = branch(image, arr_status, 'jne')
        require(arr_fail['target'] == ARRAY_FAILURE[tag], 'array failure target changed')
        join = arr_fail['va'] + arr_fail['size']
        require(map_ok['target'] == join, 'map and array arms do not join')
        near = image.read(join, 30)
        mode_one = b'\x41\x80\x7e\x0b\x01'
        require(near.count(mode_one) == 1, 'missing or ambiguous named-mode comparison')
        named_cmp = join + near.index(mode_one)
        named_skip = branch(image, named_cmp + len(mode_one), 'jne')
        label_site = named_skip['target']
        type_site = named_skip['va'] + named_skip['size']
        type_literal = decode_string_load(image, type_site)
        require(type_literal['text'] == 'type', 'unexpected named key')
        bytes_at(image, type_site + 20, '4883f802')
        key_fail = branch(image, type_site + 24, 'jne')
        require(key_fail['target'] == STRING_FAILURE[tag], 'type-key failure target changed')
        require(key_fail['va'] + key_fail['size'] == label_site, 'type key does not join label')
        label = decode_string_load(image, label_site)
        require(label['text'].encode('ascii') == expected_name, 'unexpected variant name')
        bytes_at(image, label_site + 20, '4883f802')
        label_fail = branch(image, label_site + 24, 'jne')
        require(label_fail['target'] == STRING_FAILURE[tag], 'label failure target changed')
        resolved_payload = None
        if payload_site is None:
            require(image.read(label_fail['va'] + label_fail['size'], 4) == b'\x49\x83\xc7\x04',
                    'unexpected default continuation')
            raw_arg = b''
        else:
            resolved_payload = rel32(image, payload_site)
            require(resolved_payload == payload_target, 'unexpected payload target')
            begin = label_fail['va'] + label_fail['size']
            require(begin < payload_site < begin + 80, 'payload call outside selected continuation')
            raw_arg = image.read(begin, payload_site - begin)
            marker = {'address+8': b'\x49\x83\xc7\x08',
                      'address+1': b'\x49\xff\xc7',
                      'word+8': b'\x49\x8b\x57\x08',
                      'byte+1': b'\x45\x0f\xb6\x47\x01'}[form]
            require(marker in raw_arg, 'unexpected payload argument projection')
        rows.append({'tag': tag, 'table_va': table_site, 'table_file_offset': image.offset(table_site, 4),
                     'table_bytes': table_bytes.hex(), 'entry_va': entry,
                     'mode_cmp_va': cmp_site, 'array_entry_va': zero['target'],
                     'map_header_call_va': map_start + 11, 'array_header_call_va': zero['target'] + 11,
                     'container_count': count, 'join_va': join, 'named_cmp_va': named_cmp,
                     'type_load_va': type_site, 'label_load_va': label_site,
                     'label_va': label['literal_va'], 'label_file_offset': label['literal_file_offset'],
                     'label_bytes': label['bytes'], 'label': label['text'],
                     'payload_argument': form, 'payload_argument_bytes': raw_arg.hex(),
                     'payload_call_va': payload_site, 'payload_target_va': resolved_payload})
        for role, item in (('mode_zero', zero), ('map_header_ok', map_ok),
                           ('array_header_failure', arr_fail), ('skip_type_key', named_skip),
                           ('type_key_failure', key_fail), ('label_failure', label_fail)):
            branches.append({'tag': tag, 'role': role, **item})
    return table, rows, branches


def location(image, loc, reference, line, column, compare, compare_bytes):
    section = image.unique_section('.rela.dyn')
    require(section['size'] % 24 == 0, 'truncated relocation table')
    found = []
    for pos in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, pos)
        if slot == loc:
            found.append((info, addend, pos))
    require(len(found) == 1 and found[0][0] == 8, 'missing or ambiguous Location relocation')
    _, pointer, relocation_offset = found[0]
    length, actual_line, actual_column = struct.unpack('<QII', image.read(loc + 8, 16))
    require(0 < length <= 128, 'unexpected Location length')
    source = image.read(pointer, length)
    suffix = b'l1/src/abci/state.rs'
    require(source == suffix or source.endswith(b'/' + suffix), 'unexpected Location source')
    require((actual_line, actual_column) == (line, column), 'unexpected Location line or column')
    raw = image.read(reference, 7)
    require(raw[:2] == b'\x48\x8d' and raw[2] in (0x0d, 0x15), 'unexpected Location LEA')
    require(reference + 7 + struct.unpack_from('<i', raw, 3)[0] == loc,
            'Location LEA target differs')
    bytes_at(image, compare, compare_bytes)
    return {'location_va': loc, 'location_file_offset': image.offset(loc, 24),
            'pointer_addend_va': pointer, 'relocation_file_offset': relocation_offset,
            'path_suffix': suffix.decode('ascii'), 'path_length': length,
            'line': actual_line, 'column': actual_column, 'reference_va': reference,
            'reference_bytes': raw.hex(), 'compare_va': compare,
            'compare_bytes': compare_bytes}


def compare_historical(data):
    verify_digest(data, HISTORICAL_SHA256)
    return location(Image(data), 0x56dfbf8, 0x3273856, 107, 37, 0x3273871, '4983fd02')


def extract_functions(image):
    _, indexed = unwind_index(image.data)
    _, records = eh_frame_records(image.data, image.sections)
    wanted = {start for _, start, _, _ in FUNCTIONS}
    by_start = {start: [] for start in wanted}
    for record in records:
        if record['start'] in wanted:
            by_start[record['start']].append(record)
    index_rows = {row['start']: row for row in indexed if row['start'] in wanted}
    require(len(index_rows) == len(wanted), 'selected FDE missing from unwind index')
    ordered = sorted((start, end) for _, start, end, _ in FUNCTIONS)
    require(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'selected FDEs overlap')
    result = []
    for label, start, end, expected_sha in FUNCTIONS:
        candidates = by_start[start]
        require(len(candidates) == 1, 'missing or ambiguous selected FDE')
        fde = candidates[0]
        require(fde['end'] == end and index_rows[start]['fde'] == fde['fde'],
                'selected unwind extent mismatch')
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_sha, 'selected FDE body changed')
        result.append({'role': label, 'start_va': start, 'end_va_exclusive': end,
                       'file_offset': image.offset(start, len(raw)), 'size': len(raw),
                       'fde_va': fde['fde'], 'cie_va': fde['cie'], 'lsda_va': fde['lsda'],
                       'unwind_index': index_rows[start]['index'], 'sha256': digest,
                       'raw_hex': raw.hex()})
    return result


def extract_core(image):
    # The special 15 branch bypasses the 15-entry indexed jump table.
    bytes_at(image, 0x59229c0, '803e0f')
    tag_branch = branch(image, 0x59229c3, 'jne')
    require(tag_branch['target'] == 0x59229ee, 'unexpected result-tag continuation')
    bytes_at(image, 0x59229b6, '49bd0000000000000080')
    bytes_at(image, 0x5922a83, '4d8b67104d8b7f18')
    require(rel32(image, 0x5922b55) == VARIANT_FUNCTION, 'result variant call changed')
    for va, name in ((0x5922a47, b'status'), (0x5922a65, b'err'),
                     (0x5922a92, b'response'), (0x5922af5, b'status'),
                     (0x5922b0f, b'ok'), (0x5922b30, b'response')):
        require(decode_string_load(image, va)['text'].encode('ascii') == name,
                'unexpected result literal')
    bytes_at(image, 0x5922ac8, '4983c504')
    bytes_at(image, 0x5922b65, '4c892b')
    bytes_at(image, 0x5922b7c, '4c892b4889430848895310')
    # The child result copy and the shared variant return are checked bytewise.
    bytes_at(image, 0x5922ba7, '488b44241848894310488b442408488903488b44241048894308')
    bytes_at(image, 0x4d9075a, '4983c4044c392424752e4c8923')
    bytes_at(image, 0x4e0f11a, '4080cdc2')
    bytes_at(image, 0x4e0c1aa, '4d8b6710')
    bytes_at(image, 0x4e0c1ea, '498b17498b4f08')
    require(rel32(image, 0x4e0c1da) == 0x57d00b0, 'delayed integer writer changed')
    require(rel32(image, 0x4e0c1f9) == 0x4e0d7a0, 'delayed value boundary changed')
    for va, name in ((0x4e0d7c9, 'id'), (0x4e0d83e, 'height'), (0x4e0d877, 'tx_index')):
        require(decode_string_load(image, va)['text'] == name, 'delayed id literal changed')
    require(rel32(image, 0x4e0d861) == 0x57d00b0, 'height writer changed')
    require(rel32(image, 0x4e0d89a) == 0x57d00b0, 'index writer changed')
    bytes_at(image, 0x4e0d858, '4889e74c89fe4c89e2')
    bytes_at(image, 0x4e0d891, '4889e74c89fe4c89f2')
    return tag_branch


def width_facts(image):
    rows = []
    for role, size_site, input_site, indirect_site in (
        ('createVault', 0x4e0dca8, 0x4e0dcad, 0x4e0dcb5),
        ('createSubAccount', 0x4e0efc8, 0x4e0efcd, 0x4e0efd5),
        ('governanceProposal', 0x4e0fcb4, 0x4e0fcb9, 0x4e0fcc1),
    ):
        size_bytes = image.read(size_site, 5)
        input_bytes = image.read(input_site, 5)
        require(size_bytes[0] == 0xbe and input_bytes[0] == 0xb9,
                'unexpected formatter width instruction')
        size = struct.unpack_from('<I', size_bytes, 1)[0]
        count = struct.unpack_from('<I', input_bytes, 1)[0]
        require((count, size) in ((20, 42), (32, 66)), 'unexpected formatter widths')
        slot = rel32(image, indirect_site, b'\xff\x15')
        require(slot == 0x64e4d08, 'unexpected formatter slot')
        rows.append({'role': role, 'buffer_size': size, 'input_size': count,
                     'size_instruction_va': size_site, 'size_instruction_bytes': size_bytes.hex(),
                     'input_instruction_va': input_site, 'input_instruction_bytes': input_bytes.hex(),
                     'call_va': indirect_site, 'call_bytes': image.read(indirect_site, 6).hex(),
                     'slot_va': slot})
    return rows


def delayed_projection(image, variants):
    case = variants[13]
    args = bytes.fromhex(case['payload_argument_bytes'])
    marker = args.index(b'\x49\x83\xc7\x08')
    base = args[marker + 3]
    until_extra = image.read(0x4e0c1ad, 1)[0]
    index_extra = image.read(0x4e0c1f0, 1)[0]
    bytes_at(image, 0x4e0c1aa, '4d8b6710')
    bytes_at(image, 0x4e0c1ea, '498b17498b4f08')
    return {'input_base_adjustment': base, 'delayed_until_offset': base + until_extra,
            'height_offset': base, 'tx_index_offset': base + index_extra,
            'until_load_va': hex(0x4e0c1aa), 'until_load_bytes': image.read(0x4e0c1aa, 4).hex(),
            'id_load_va': hex(0x4e0c1ea), 'id_load_bytes': image.read(0x4e0c1ea, 7).hex(),
            'field_order': [decode_string_load(image, va)['text'] for va in
                            (0x4e0c1b5, 0x4e0d7c9, 0x4e0d83e, 0x4e0d877)]}


def extra_branches(image):
    result = []
    for tag, role, va, kind, expected_target in EXTRA_BRANCHES:
        decoded = branch(image, va, kind)
        require(decoded['target'] == expected_target, 'selected branch target changed')
        result.append({'tag': tag, 'role': role, **decoded})
    return result


def status_paths(image):
    # The two new payload wrappers tail-call different statuses containers.
    require(rel32(image, 0x4e0d3fc, b'\xe9') == 0x518a280, 'order tail call changed')
    require(rel32(image, 0x4e0d4fc, b'\xe9') == 0x518a630, 'cancel tail call changed')
    require(rel32(image, 0x518a314) == 0x52e32a0, 'order statuses call changed')
    require(rel32(image, 0x518a6c4) == 0x52a7b90, 'cancel statuses call changed')
    require(rel32(image, 0x52e3399) == 0x5188f20, 'order element call changed')
    require(rel32(image, 0x52a7d93) == 0x5301c00, 'cancel error call changed')
    bytes_at(image, 0x52e32b9, '4c8b7208488b5210')
    bytes_at(image, 0x52a7ba9, '488b5a084c8b7a10')
    bytes_at(image, 0x52e33ac, '4983c430')
    bytes_at(image, 0x52a7daa, '4983c618')
    bytes_at(image, 0x52a7d50, '4d392e')
    bytes_at(image, 0x52a7c35, '49bd0000000000000080')
    bytes_at(image, 0x52a7d8f, '41566a05')
    bytes_at(image, 0x5301c3f, 'c6043081')
    bytes_at(image, 0x5301c58, '488b442458488b7008488b5010')
    bytes_at(image, 0x52e35b4, '0f0b')
    bytes_at(image, 0x52a7f85, '0f0b')
    error_addr = rel32(image, 0x52a7d88, b'\x4c\x8d\x0d')
    require(image.read(error_addr, 5) == b'error', 'cancel error label changed')
    for va, value in ((0x518a2f1, 'statuses'), (0x518a6a1, 'statuses'),
                      (0x52a7c4f, 'success')):
        require(decode_string_load(image, va)['text'] == value, 'status label changed')
    bytes_at(image, 0x5188f37, '0fb606')
    table = rel32(image, 0x5188f3a, b'\x48\x8d\x0d')
    bytes_at(image, 0x5188f41, '486304814801c8ffe0')
    require(table == 0x91d214, 'order status table changed')
    expected = ((0x5188f4a, 0x5188f7a, 'filled'),
                (0x518909e, 0x51890c0, 'resting'),
                (0x518903a, 0x5189044, 'waitingForFill'),
                (0x518906a, 0x5189074, 'waitingForTrigger'),
                (0x5188fcb, 0x5188ff6, 'error'))
    rows = []
    for tag, (expected_entry, string_site, name) in enumerate(expected):
        slot = table + 4 * tag
        raw = image.read(slot, 4)
        entry = table + struct.unpack('<i', raw)[0]
        literal = decode_string_load(image, string_site)
        require(entry == expected_entry and literal['text'] == name, 'order status arm changed')
        rows.append({'tag': tag, 'table_va': slot, 'table_file_offset': image.offset(slot, 4),
                     'table_bytes': raw.hex(), 'entry_va': entry, **literal})
    facts = {'order_entry_va': hex(0x518a280), 'cancel_entry_va': hex(0x518a630),
             'order_loop_va': hex(0x52e32a0), 'cancel_loop_va': hex(0x52a7b90),
             'order_element_stride': image.read(0x52e33af, 1)[0],
             'cancel_element_stride': image.read(0x52a7dad, 1)[0],
             'status_pointer_offset': image.read(0x52e32bc, 1)[0],
             'status_count_offset': image.read(0x52e32c0, 1)[0],
             'cancel_error_label_va': hex(error_addr),
             'cancel_error_label_bytes': image.read(error_addr, 5).hex(),
             'cancel_error_map_marker': image.read(0x5301c42, 1)[0],
             'cancel_sentinel': hex(struct.unpack_from('<Q', image.read(0x52a7c35, 10), 2)[0]),
             'order_status_table_va': hex(table), 'order_status_entries_inspected': len(rows)}
    return facts, rows


def failure_facts(image):
    # The selected growth-failure arm writes all three output words.
    bytes_at(image, 0x4e0f0e7, '49bd0000000000000080')
    bytes_at(image, 0x4e0f195, '48c7430800000000')
    bytes_at(image, 0x4e0f19d, '48b80300000026000000')
    bytes_at(image, 0x4e0f1a7, '488943104c892b')
    head = struct.unpack_from('<Q', image.read(0x4e0f0e7, 10), 2)[0]
    detail = struct.unpack_from('<Q', image.read(0x4e0f19d, 10), 2)[0]
    return {'head': hex(head), 'second_word': 0, 'third_word': hex(detail),
            'second_word_offset': image.read(0x4e0f198, 1)[0],
            'third_word_offset': image.read(0x4e0f1aa, 1)[0],
            'growth_status_branch_va': hex(0x4e0f193),
            'head_store_va': hex(0x4e0f1ab),
            'detail_immediate_va': hex(0x4e0f19f),
            'raw_stores': image.read(0x4e0f195, 26).hex()}


def hexify(value):
    if value is None:
        return ''
    if isinstance(value, int):
        return hex(value)
    return value


def tsv(rows, columns, hexadecimal=()):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=columns, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({key: hexify(row.get(key)) if key in hexadecimal else row.get(key, '')
                         for key in columns})
    return out.getvalue().encode('utf-8')


def render(data):
    verify_digest(data)
    image = Image(data)
    functions = extract_functions(image)
    special_branch = extract_core(image)
    table, variants, branches = map_variants(image)
    branches.extend(extra_branches(image))
    widths = width_facts(image)
    projection = delayed_projection(image, variants)
    failures = failure_facts(image)
    status_facts, status_rows = status_paths(image)
    loc = location(image, 0x64767a8, 0x3c1352f, 123, 37, 0x3c1353b, '4883f801')
    literals = [decode_string_load(image, va) for va in
                (0x5922a47, 0x5922a65, 0x5922a92, 0x5922af5, 0x5922b0f, 0x5922b30,
                 0x4e0c1b5, 0x4e0d7c9, 0x4e0d83e, 0x4e0d877,
                 0x518a2f1, 0x518a6a1, 0x52a7c4f)]
    literals.extend(decode_string_load(image, row['label_load_va']) for row in variants)
    # The literal written by leaf wrappers has a different register setup.
    data_literal = image.read(0x45a158, 4)
    require(data_literal == b'data', 'data literal changed')
    literals.append({'load_va': None, 'load_file_offset': None, 'literal_va': 0x45a158,
                     'literal_file_offset': image.offset(0x45a158, len(data_literal)), 'length': len(data_literal),
                     'bytes': data_literal.hex(), 'text': data_literal.decode('ascii'), 'writer_call_va': None})
    summary = {'target_sha256': hashlib.sha256(data).hexdigest(),
               'coordinate_system': 'linked ELF virtual addresses before load bias',
               'selected_fde_count': len(functions),
               'selected_fde_bytes': sum(row['size'] for row in functions),
               'jump_table_va': hex(table), 'table_entries_inspected': len(variants),
               'decoded_conditional_transfers': len(branches),
               'special_tag': image.read(0x59229c2, 1)[0],
               'special_tag_other_branch_va': hex(special_branch['target']),
               'sentinel_word': hex(struct.unpack_from('<Q', image.read(0x59229b6, 10), 2)[0]),
               'success_increment': image.read(0x5922acb, 1)[0],
               'location_context': {k: hex(v) if k.endswith(('_va', '_offset')) else v
                                    for k, v in loc.items()},
               'limitations': 'Selected static FDEs and byte patterns only; no runtime, complete schema or component gate.'}
    func_cols = ('role', 'start_va', 'end_va_exclusive', 'file_offset', 'size', 'fde_va',
                 'cie_va', 'lsda_va', 'unwind_index', 'sha256', 'raw_hex')
    var_cols = ('tag', 'table_va', 'table_file_offset', 'table_bytes', 'entry_va', 'mode_cmp_va',
                'array_entry_va', 'map_header_call_va', 'array_header_call_va', 'container_count',
                'join_va', 'named_cmp_va', 'type_load_va', 'label_load_va', 'label_va',
                'label_file_offset', 'label_bytes', 'label', 'payload_argument',
                'payload_argument_bytes', 'payload_call_va', 'payload_target_va')
    branch_cols = ('tag', 'role', 'va', 'file_offset', 'bytes', 'kind', 'target', 'size')
    lit_cols = ('load_va', 'load_file_offset', 'literal_va', 'literal_file_offset', 'length', 'bytes', 'text', 'writer_call_va')
    width_cols = ('role', 'buffer_size', 'input_size', 'size_instruction_va', 'size_instruction_bytes',
                  'input_instruction_va', 'input_instruction_bytes', 'call_va', 'call_bytes', 'slot_va')
    status_cols = ('tag', 'table_va', 'table_file_offset', 'table_bytes', 'entry_va', 'load_va',
                   'load_file_offset', 'literal_va', 'literal_file_offset', 'length', 'bytes', 'text', 'writer_call_va')
    def address_columns(columns):
        return tuple(c for c in columns if c.endswith(('_va', '_offset')) or c in ('va', 'target'))
    return {
        'functions.tsv': tsv(functions, func_cols, address_columns(func_cols)),
        'variants.tsv': tsv(variants, var_cols, address_columns(var_cols)),
        'branches.tsv': tsv(branches, branch_cols, address_columns(branch_cols)),
        'literals.tsv': tsv(literals, lit_cols, address_columns(lit_cols)),
        'format-widths.tsv': tsv(widths, width_cols, address_columns(width_cols)),
        'delayed-projection.json': (json.dumps(projection, sort_keys=True, indent=2) + '\n').encode(),
        'failure.json': (json.dumps(failures, sort_keys=True, indent=2) + '\n').encode(),
        'status-paths.json': (json.dumps(status_facts, sort_keys=True, indent=2) + '\n').encode(),
        'order-statuses.tsv': tsv(status_rows, status_cols, address_columns(status_cols)),
        'summary.json': (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode(),
    }


def encode_subset(mode, tag, value=None):
    """Synthetic model for successful mode 0/1 paths and selected bounded tags.

    It assumes previously studied helper contracts, sufficient buffer capacity,
    normal returns and valid objects. It is not target execution or a full codec.
    """
    require(type(mode) is int and mode in (0, 1), 'unsupported mode')
    require(type(tag) is int and tag in (0, 1, 2, 7, 8, 9, 10, 11, 13, 14, 15), 'unsupported tag')
    def string(raw):
        require(isinstance(raw, bytes) and len(raw) <= 255, 'unsupported string')
        return (bytes([0xa0 | len(raw)]) if len(raw) < 32 else bytes([0xd9, len(raw)])) + raw
    def structure(count):
        return bytes([(0x80 if mode else 0x90) | count])
    def key(raw):
        return string(raw) if mode == 1 else b''
    result = structure(2) + key(b'status')
    if tag == 15:
        require(isinstance(value, bytes), 'error payload must be bytes')
        return result + string(b'err') + key(b'response') + string(value)
    name = CASES[tag][1]
    result += string(b'ok') + key(b'response')
    result += structure(1 if tag == 14 else 2) + key(b'type') + string(name)
    if tag == 14:
        require(value is None, 'default has no payload')
        return result
    result += key(b'data')
    if tag in (0, 1):
        require(isinstance(value, tuple) and len(value) < 16, 'unsupported status list')
        payload = structure(1) + key(b'statuses') + bytes([0x90 | len(value)])
        for item in value:
            if tag == 0:
                require(type(item) is int and item in (2, 3), 'unsupported order status')
                payload += string((b'waitingForFill', b'waitingForTrigger')[item - 2])
            elif item is None:
                payload += string(b'success')
            else:
                require(isinstance(item, bytes), 'unsupported cancel status')
                payload += b'\x81' + string(b'error') + string(item)
        return result + payload
    if tag in (8, 9):
        require(type(value) is int and 0 <= value < 128, 'integer outside modeled range')
        return result + bytes([value])
    if tag == 10:
        require(type(value) is int and value in (0, 1), 'noncanonical boolean')
        return result + bytes([0xc2 | value])
    if tag == 13:
        require(isinstance(value, tuple) and len(value) == 3
                and all(type(x) is int and 0 <= x < 128 for x in value),
                'delayed fields outside modeled range')
        until, height, index = value
        return (result + structure(2) + key(b'delayedUntil') + bytes([until])
                + key(b'id') + structure(2) + key(b'height') + bytes([height])
                + key(b'tx_index') + bytes([index]))
    expected_size = 32 if tag == 11 else 20
    require(isinstance(value, bytes) and len(value) == expected_size, 'incorrect fixed-width payload')
    return result + string(b'0x' + value.hex().encode('ascii'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical-node', type=Path)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    output = render(data)  # authenticate and validate everything before writing
    if args.historical_node is not None:
        compare_historical(args.historical_node.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(output.items()):
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as exc:
        print('abci_res_variants115:', exc, file=sys.stderr)
        raise SystemExit(1)
