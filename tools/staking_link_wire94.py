#!/usr/bin/env python3
"""Recover selected staking-link serialization evidence from node #94 ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected analysis addresses, not a scan or a function census.
# Body hashes are independent corruption controls within the admitted image.
FUNCTIONS = (
    ('outer_writer', 0x231a8c0, 0x231a99e, '5c0e2a5ae50b649e53d8a4b4e581a4228f51461f95a82bf4343ee27087f43ccd'),
    ('tree_to_pairs', 0x25eadf0, 0x25eaeb9, 'd1dce11bdf741411658eb4860b254e1dcd959d9cd9fa66af163f4f61e5328af2'),
    ('tree_collector', 0x25686b0, 0x25689b0, 'cdfc5268e9efba3ebc15d799bf3a30ba21e15c30c7dfec2ff05e3d59c710f6f4'),
    ('pairs_writer', 0x1e231b0, 0x1e2343b, '94829e4d3c0c0ddb00ef6177626d20c44aa547055c52a5d4082b2e59b98d2a16'),
    ('pair_writer', 0x1df2010, 0x1df2565, 'e7ddbaae801bd2c2703ddaa5efbd4c0ea3ae2cd3338e99a6a70384d6bf8b1b48'),
    ('key_writer', 0x1e0d0a0, 0x1e0d205, 'a202a759a0a5e43cfc7b1a4a6733a47b15471f87c5f2da3f3b2822d700289361'),
    ('variant_writer', 0x2319930, 0x2319b96, '74cf8b2158966595380de55b0e1d08f5e336392f94ddc1f035c59d331081d603'),
    ('buffered_variant_writer', 0x2319f00, 0x231a2cc, '35dd82dc0188d868a14c200e21941e4d372e72e1acc95955df39f2a71f347709'),
    ('payload_writer', 0x1e13ab0, 0x1e13b51, 'b6544112157ed34c49538010bbfb49c1f2f09a38e25fd66048472335ad859a7e'),
    ('outer_reader', 0x1866ac0, 0x1867f5e, '73a5da919d3fb5b523472ad4ffdb98029110b95e4213fb309ef4c6a0e07223ee'),
    ('collection_reader', 0x187a310, 0x187aaa9, '1bba435a773d803225a3b312d172f57434b11eee87b5ad1007ce4b499cebca2f'),
    ('map_reader', 0x264d420, 0x264d707, '083e4a76f9010780406a4a93c34c037ad720d12e2ff96a7ce757fab47be15bb9'),
    ('sequence_reader', 0x2689420, 0x2689722, 'de808bb5ee3c980a81d63df683e260193786126c6ea77355b91c4f680c9993a8'),
    ('tree_insert_or_replace', 0x2860dc0, 0x286104c, '44700f2122d0ea1a3e13e422927a7155194f2e89aa4ab4909ceaa233a11863af'),
    ('pair_reader', 0x174cbd0, 0x174dab3, '56166a31f1aafd8dc4bab9b7a3e4c6cc9d8c69ad111022ba4ad992758f649126'),
    ('variant_reader', 0x1686820, 0x1686a50, '00db36693c0c64ac31e66c2a7a172217dd647712d54c8ad392d40093506da478'),
    ('variant_name_reader', 0x17b67c0, 0x17b6ee0, '1cdc49c0eeff09649830e596da45bafbfce43bcf663aea51a17e9e7783f0943c'),
    ('variant_name_classifier', 0x22f9670, 0x22f9837, '09567cf07eae0e5a53fa75d1cc7a4e1a49fe77c930d56996f19992d03000bc97'),
    ('requested_payload_reader', 0x180f8d0, 0x18114a8, '3d306b27428e3ffc1bc424781956954864f1f56cbd763d54af189521ceecf8bd'),
    ('trading_payload_reader', 0x175d550, 0x175f128, '887ab0127983e17d544b91ffc6cb2dcfacab0821484056d4c961d9de2afada36'),
    ('staking_payload_reader', 0x17950b0, 0x1796c88, '9373be861ce347167e748ca599db5f3a5847afde1a5969d1e87d6b6deb2e139b'),
)

# Selected instruction windows, checked before their facts are used. These are
# literal byte patterns, not disassembler output or heuristic x86 decoding.
PINS = (
    ('outer_mode_zero_branch', 0x231a8de, '807a0b00742c'),
    ('outer_named_mode', 0x231a92a, '41807e0b01751a'),
    ('outer_name_length', 0x231a938, 'ba15000000'),
    ('variant_tag_zero', 0x2319944, '0fb60685c00f8483000000'),
    ('variant_tag_one', 0x2319961, 'ba0100000083f801'),
    ('variant_one_mode', 0x23199a1, '41807f0b000f8407010000'),
    ('variant_zero_mode', 0x2319a09, '41807f0b000f84c1000000'),
    ('variant_other_mode', 0x2319a82, '41807f0b000f8484000000'),
    ('variant_payload_offset_a', 0x2319b00, '49ffc6'),
    ('variant_payload_offset_b', 0x2319b2e, '49ffc6'),
    ('variant_payload_name_length', 0x2319b47, 'b90c000000'),
    ('collector_count_times_sixteen', 0x25686b8, '4c8b66404d89e749c1e704'),
    ('collector_wrapper_tree_words', 0x25eadff, '488b0e4885c97435488b5608488b4610'),
    ('collector_wrapper_iterator', 0x25eae40, '48894c241848894c24384889442458'),
    ('collector_iterator_words', 0x2568730, '440fb60e488b56184c8b4610488b760831c04c89e1'),
    ('collector_next_index', 0x2568750, '4c8d42014c89ce48ffc9'),
    ('collector_key_value_offsets', 0x2568757, '48ffc94c8d14924f8d1c914983c3084a8d14924c01ca4881c2e8000000'),
    ('collector_store_and_advance', 0x2568774, '4989c149c1e1044e891c0b4a89540b0848ffc041b1014c89c2'),
    ('collector_node_count_offset', 0x25687ab, '440fb78ee6000000'),
    ('collector_initial_root', 0x25687d0, '4885d274384989d14c89c64983e1077431'),
    ('collector_first_child_walk', 0x25687f0, '488bb6d001000049ffc24d39d175f1'),
    ('collector_leaf_count', 0x256885e, '4531c031d2440fb78ee60000004c39ca'),
    ('collector_parent_index_offset', 0x2568880, '4c8b0e4d85c90f84d900000049ffc00fb796e40000004c89ce66413b91e6000000'),
    ('collector_ascend', 0x256888c, '49ffc00fb796e40000004c89ce66413b91e600000073dd'),
    ('collector_child_offset', 0x25688ac, '4d8d14d14981c2d8010000'),
    ('collector_descend_successor', 0x25688d0, '498b324c8d96d001000049ffc7'),
    ('collector_result_layout', 0x256894b, '4c893748895f084c896710'),
    ('pair_header_length', 0x1df2075, 'ba02000000'),
    ('pair_compact_array_marker', 0x1df21da, 'c6040192'),
    ('pairs_buffer_and_count', 0x1e231c9, '4c8b6a084c8b7210'),
    ('pair_pointer_loads', 0x1e23390, '488b5500488b4d08'),
    ('pair_pointer_stride', 0x1e233b1, '4883c510'),
    ('pair_reader_key_width', 0x174d149, '48c78424c000000014000000'),
    ('pair_reader_two_fields', 0x174d4a6, '83bc242c01000002'),
    ('pair_reader_bad_length_result', 0x174d600, 'c644244804c744244c02000000'),
    ('field_length_test', 0x1867116, '4883bc24a0000000157539'),
    ('field_first_half_load', 0x1867129, 'f30f6f05399ab7fe'),
    ('field_last_half_load', 0x186713e, 'f30f6f15299ab7fe'),
    ('field_equality', 0x1867152, '3dffff00000f95c0'),
    ('outer_unknown_field', 0x186755d, '807c2461007427488d7c24404c89f6ba01000000'),
    ('outer_duplicate_field_test', 0x186758b, '4d85e4488d7c24400f859a060000'),
    ('outer_default_selection', 0x18675ee, '31c041f6c401488b0c24480f44c8488b6c2430480f44e8'),
    ('outer_sequence_one_test', 0x186780b, '83fd017431'),
    ('map_or_sequence_test', 0x187a69b, '80f9df0f879afcffff80f9900f833b01000080e10f0fb6d9'),
    ('sequence_marker_test', 0x187a7e8, '80f9a00f833e01000080e10f0fb6d9'),
    ('map_value_type_and_count', 0x264d4c7, 'b90b00000041b903000000'),
    ('map_insert_result_branch', 0x264d5b1, '803c24030f84b5feffff'),
    ('sequence_insert_result_branch', 0x268956b, '80bc24c0000000030f8407ffffff'),
    ('tree_compare_key_width', 0x2860e3e, 'ba140000004c89e7'),
    ('tree_compare_normalization', 0x2860e4c, '48984885c00f98c10f9fc028c84983c71548ffc34983c614'),
    ('tree_equal_swap_value', 0x2860ea2, '498b4f0d488b4424084889480d410f10070f1100488b1424488b4a0d49894f0d0f1002410f1107'),
    ('tree_new_key_result', 0x2861005, '49ff4610488b442408c60003'),
    ('variant_map_size_small', 0x1686887, '83f8017470e98c010000'),
    ('variant_map_size_large', 0x16868f3, '83f8010f8521010000'),
    ('variant_reader_dispatch', 0x1686927, '85c0745083f801755a'),
    ('key_conversion_lengths', 0x1e0d18b, 'be2a000000b9140000004531c0'),
    ('payload_conversion_lengths', 0x1e13afd, 'be2a000000b9140000004c89fa4531c0'),
    ('payload_name_mode', 0x1e13ace, '41807e0b007414'),
)

# Exact rel32 call sites and expected targets, checked and derived from bytes.
CALLS = (
    ('outer_header_map', 0x231a8ef, 0x25a8f80),
    ('outer_header_sequence', 0x231a91b, 0x25a9bd0),
    ('outer_field_name', 0x231a940, 0x25aa7f0),
    ('outer_tree', 0x231a954, 0x25eadf0),
    ('tree_collect', 0x25eae5a, 0x25686b0),
    ('tree_pairs', 0x25eae68, 0x1e231b0),
    ('pairs_header', 0x1e23217, 0x25a9bd0),
    ('pairs_first_pair', 0x1e2326f, 0x1df2010),
    ('pairs_loop_pair', 0x1e2339e, 0x1df2010),
    ('pair_header', 0x1df207a, 0x25a9bd0),
    ('pair_key', 0x1df20d6, 0x1e0d0a0),
    ('pair_variant', 0x1df21a5, 0x2319930),
    ('pair_buffered_key', 0x1df2217, 0x1e0d6c0),
    ('pair_buffered_variant', 0x1df22f6, 0x2319f00),
    ('key_string', 0x1e0d1a4, 0x25aa7f0),
    ('variant_zero_header', 0x23199df, 0x25a8f80),
    ('variant_zero_name', 0x23199fe, 0x25aa7f0),
    ('variant_zero_named_payload_header', 0x2319a21, 0x25a8f80),
    ('variant_zero_unnamed_payload_header', 0x2319ae2, 0x25a9bd0),
    ('variant_one_header', 0x231996f, 0x25a8f80),
    ('variant_one_name', 0x2319992, 0x25aa7f0),
    ('variant_one_named_payload_header', 0x23199b9, 0x25a8f80),
    ('variant_one_unnamed_payload_header', 0x2319ac0, 0x25a9bd0),
    ('variant_other_header', 0x2319a50, 0x25a8f80),
    ('variant_other_name', 0x2319a73, 0x25aa7f0),
    ('variant_other_named_payload_header', 0x2319a9a, 0x25a8f80),
    ('variant_other_unnamed_payload_header', 0x2319b1e, 0x25a9bd0),
    ('variant_payload', 0x2319b4f, 0x1e13ab0),
    ('payload_field_name', 0x1e13ade, 0x25aa7f0),
    ('payload_address_string', 0x1e13b19, 0x25aa7f0),
    ('outer_reader_unknown', 0x1867571, 0x19682d0),
    ('outer_reader_collection', 0x18675a4, 0x187a310),
    ('outer_reader_sequence_collection', 0x18677e3, 0x187a310),
    ('collection_map', 0x187a6e6, 0x264d420),
    ('collection_sequence', 0x187a82a, 0x2689420),
    ('map_key', 0x264d49a, 0x1699080),
    ('map_variant', 0x264d4e8, 0x1686820),
    ('map_insert', 0x264d5a9, 0x2860dc0),
    ('sequence_pair', 0x2689495, 0x174cbd0),
    ('sequence_insert', 0x2689564, 0x2860dc0),
    ('pair_read_key', 0x174d16d, 0x190f5b0),
    ('pair_read_variant', 0x174d2ca, 0x1686820),
    ('variant_read_name', 0x168690e, 0x17b67c0),
    ('name_classify', 0x17b68df, 0x22f9670),
    ('variant_read_tag_zero', 0x1686983, 0x180f8d0),
    ('variant_read_tag_one', 0x1686938, 0x175d550),
    ('variant_read_tag_other', 0x1686992, 0x17950b0),
)

# A fixed set of conditional edges which distinguishes the main branches.
BRANCHES = (
    ('outer_header_zero', 0x231a8e2, '74', 0x231a910),
    ('outer_skip_name', 0x231a92f, '75', 0x231a94b),
    ('writer_tag_zero', 0x2319949, '0f84', 0x23199d2),
    ('writer_tag_other', 0x2319969, '0f85', 0x2319a50),
    ('writer_zero_unnamed', 0x2319a0e, '0f84', 0x2319ad5),
    ('writer_one_unnamed', 0x23199a6, '0f84', 0x2319ab3),
    ('writer_other_unnamed', 0x2319a87, '0f84', 0x2319b11),
    ('outer_reader_duplicate', 0x1867593, '0f85', 0x1867c33),
    ('map_countdown', 0x264d5b5, '0f84', 0x264d470),
    ('sequence_countdown', 0x2689573, '0f84', 0x2689480),
    ('variant_size_fail', 0x16868f6, '0f85', 0x1686a1d),
    ('variant_tag_zero', 0x1686929, '74', 0x168697b),
    ('variant_tag_other', 0x168692e, '75', 0x168698a),
    ('pair_wrong_length', 0x174d4ae, '0f85', 0x174d600),
    ('tree_equal_key', 0x2860e6d, '74', 0x2860ea2),
    ('collector_first_descend', 0x25687a9, '74', 0x25687d0),
    ('collector_first_child_loop', 0x25687fd, '75', 0x25687f0),
    ('collector_parent_loop', 0x25688a1, '73', 0x2568880),
    ('collector_emit_at_leaf_level', 0x25688a6, '0f84', 0x2568750),
    ('collector_successor_child_loop', 0x25688e0, '75', 0x25688d0),
)

# lea instruction, expected pointer and length are checked against one another.
REFERENCES = (
    ('outer_field', 0x231a931, '488d35', 0x3e0b6a, 21, 'user_to_staking_link2'),
    ('tag_zero', 0x23199ef, '488d35', 0x3e0871, 9, 'Requested'),
    ('tag_one', 0x2319983, '488d35', 0x3e087a, 11, 'TradingUser'),
    ('tag_other', 0x2319a64, '488d35', 0x3e0885, 11, 'StakingUser'),
    ('payload_zero_one', 0x2319b08, '488d15', 0x3e04ae, 12, 'staking_user'),
    ('payload_other', 0x2319b36, '488d15', 0x3e04ba, 12, 'trading_user'),
    ('reader_key_type', 0x264d493, '488d15', 0x20a020, 4, 'User'),
    ('reader_value_type', 0x264d4da, '488d15', 0x3e16ed, 11, 'StakingLink'),
    ('duplicate_field_name', 0x1867c50, '488d05', 0x3b12c0, 21, 'user_to_staking_link2'),
)

# Each character comparison is followed by jne to the common unknown branch.
CLASSIFIER = (
    (0x22f9680, (0x22f9689, 0x22f9693, 0x22f969d, 0x22f96a7, 0x22f96b1, 0x22f96bb, 0x22f96c5, 0x22f96cf), 0x22f96d9),
    (0x22f96f8, (0x22f9701, 0x22f970b, 0x22f9715, 0x22f971f, 0x22f9725, 0x22f972b, 0x22f9731, 0x22f9737, 0x22f973d, 0x22f9743), 0x22f9749),
    (0x22f96f3, (0x22f9756, 0x22f975c, 0x22f9762, 0x22f9768, 0x22f976e, 0x22f9774, 0x22f977a, 0x22f9780, 0x22f9786, 0x22f978c), 0x22f9792),
)

# Three independently bounded readers have the same selected control-flow
# shape. Only the referenced payload literal and rel32 displacements vary.
PAYLOAD_PATHS = (
    ('requested', 0x180f8d0, 0x3e04ae, 0x3b291c, 'staking_user'),
    ('trading', 0x175d550, 0x3e04ae, 0x3b291c, 'staking_user'),
    ('staking', 0x17950b0, 0x3e04ba, 0x3b2910, 'trading_user'),
)
for _name, _base, _field_va, _diagnostic_va, _field in PAYLOAD_PATHS:
    PINS += (
        (_name + '_payload_name_length', _base + 0x685, '48837c24700c'),
        (_name + '_payload_seen_test', _base + 0xac5, '807c2441000f850df9fffff684244801000001'),
        (_name + '_payload_map_width', _base + 0xb00, '48c744241014000000'),
        (_name + '_payload_missing_test', _base + 0xdae, 'f6842448010000017446'),
        (_name + '_payload_empty_sequence', _base + 0x1246, '85ed0f84a8040000'),
        (_name + '_payload_sequence_width', _base + 0x1280, '48c78424b000000014000000'),
        (_name + '_payload_sequence_size', _base + 0x14f9, '83fd010f85c2010000'),
    )
    CALLS += (
        (_name + '_payload_map_address', _base + 0xb19, 0x190f5b0),
        (_name + '_payload_sequence_address', _base + 0x12a1, 0x190f5b0),
    )
    BRANCHES += (
        (_name + '_payload_duplicate', _base + 0xad8, '0f85', _base + 0x1a75),
        (_name + '_payload_missing', _base + 0xdb6, '74', _base + 0xdfe),
        (_name + '_payload_sequence_bad_size', _base + 0x14fc, '0f85', _base + 0x16c4),
    )
    REFERENCES += (
        (_name + '_compare_prefix', _base + 0x698, '48330d', _field_va, 8, _field[:8]),
        (_name + '_compare_suffix', _base + 0x6a2, '3305', _field_va + 8, 4, _field[8:]),
        (_name + '_missing_field', _base + 0xe01, '488d05', _diagnostic_va, 12, _field),
        (_name + '_missing_template', _base + 0xe2b, '488d35', 0x1df8f3, 16, '\x0fmissing field `'),
        (_name + '_duplicate_field', _base + 0x1a78, '488d05', _diagnostic_va, 12, _field),
        (_name + '_duplicate_template', _base + 0x1aa0, '488d35', 0x1e0fd5, 18, '\x11duplicate field `'),
    )


def verify_digest(data):
    got = hashlib.sha256(data).hexdigest()
    if got != SHA256:
        raise ValueError('node #94 input SHA-256 mismatch')
    return got


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, address, size, executable=False):
        if address < 0 or size <= 0:
            raise ValueError('invalid VA or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= address and address + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('VA has no unique file-backed allocated section')
        s = matches[0]
        offset = s['offset'] + address - s['address']
        result = self.data[offset:offset + size]
        if len(result) != size:
            raise ValueError('truncated file-backed range')
        return result


def verify_pin(read, address, expected):
    actual = read(address, len(expected), True)
    if actual != expected:
        raise ValueError('instruction pin mismatch at ' + hex(address))
    return actual


def relative(read, address, prefix, width=4):
    insn = read(address, len(prefix) + width, True)
    if insn[:len(prefix)] != prefix:
        raise ValueError('relative instruction opcode mismatch at ' + hex(address))
    delta = int.from_bytes(insn[len(prefix):], 'little', signed=True)
    return address + len(insn) + delta, insn


def checked_relative(read, address, prefix, target, width=4):
    actual, raw = relative(read, address, prefix, width)
    if actual != target:
        raise ValueError('relative target mismatch at ' + hex(address))
    return raw


def verify_body(body, digest):
    actual = hashlib.sha256(body).hexdigest()
    if actual != digest:
        raise ValueError('selected FDE body mismatch')
    return actual


def function_rows(image):
    _, fdes = eh_frame_records(image.data, image.sections)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    rows = []
    for role, start, end, digest in FUNCTIONS:
        hits = by_start.get(start, [])
        if len(hits) != 1 or hits[0]['end'] != end:
            raise ValueError('missing or ambiguous selected FDE at ' + hex(start))
        body = image.read(start, end - start, True)
        body_hash = verify_body(body, digest)
        rows.append(dict(role=role, start_va=hex(start), end_va_exclusive=hex(end),
                         fde_va=hex(hits[0]['fde']), size=len(body), sha256=body_hash))
    return rows


def classifier_rows(read):
    # The two length tests and dispatch to the S initial are part of the proof.
    verify_pin(read, 0x22f967a, bytes.fromhex('4883fa097566'))
    verify_pin(read, 0x22f96e6, bytes.fromhex('4883fa0b0f85af000000'))
    checked_relative(read, 0x22f96f6, b'\x74', 0x22f9756, 1)
    result = []
    for index, (first, rest, store) in enumerate(CLASSIFIER):
        raw = read(first, 3, True)
        expected_op = b'\x80\x3e' if index == 0 else b'\x83\xf9'
        if raw[:2] != expected_op:
            raise ValueError('classifier first-byte opcode mismatch')
        if index == 0:
            checked_relative(read, first + 3, b'\x0f\x85', 0x22f979f)
        elif index == 1:
            checked_relative(read, first + 3, b'\x0f\x85', 0x22f979f)
        name = bytearray([raw[2]])
        for displacement, address in enumerate(rest, 1):
            op = read(address, 4, True)
            if op[:3] != bytes((0x80, 0x7e, displacement)):
                raise ValueError('classifier comparison mismatch at ' + hex(address))
            name.append(op[3])
            next_op = read(address + 4, 1, True)
            prefix, width = (b'\x0f\x85', 4) if next_op == b'\x0f' else (b'\x75', 1)
            checked_relative(read, address + 4, prefix, 0x22f979f, width)
        out = read(store, 5, True)
        if out[:3] != b'\x66\xc7\x00' or out[3] != 9 or out[4] != index:
            raise ValueError('classifier success store mismatch')
        result.append(dict(name=name.decode('ascii'), tag=out[4], success_status=out[3],
                           initial_compare_va=hex(first), success_store_va=hex(store),
                           comparisons=1 + len(rest), unknown_target_va=hex(0x22f979f)))
    return result


def duplicate_literal(read, high_address, low_address):
    high = read(high_address, 14, True)
    low = read(low_address, 13, True)
    if high[:2] != b'\x48\xb9' or high[10:] != b'\x48\x89\x48\x05':
        raise ValueError('duplicate diagnostic high store mismatch')
    if low[:2] != b'\x48\xb9' or low[10:] != b'\x48\x89\x08':
        raise ValueError('duplicate diagnostic low store mismatch')
    if high[2:5] != low[7:10]:
        raise ValueError('duplicate diagnostic overlapping immediate mismatch')
    value = bytearray(13)
    value[5:13] = high[2:10]
    value[0:8] = low[2:10]
    if bytes(value) != b'duplicate key':
        raise ValueError('duplicate diagnostic mismatch')
    return bytes(value).decode('ascii')


def collector_allocation_guard(read):
    shift = verify_pin(read, 0x25686bf, bytes.fromhex('49c1e704'))[3]
    high_shift = verify_pin(read, 0x25686c6, bytes.fromhex('48c1e83c'))[3]
    limit_instruction = verify_pin(read, 0x25686cd, bytes.fromhex('48b9f8ffffffffffff7f'))
    verify_pin(read, 0x25686d7, bytes.fromhex('4939cf0f97c108c1740b'))
    limit = struct.unpack_from('<Q', limit_instruction, 2)[0]
    return dict(item_size=1 << shift, left_shift=shift, overflow_high_shift=high_shift,
                max_allocation=limit, largest_count=limit >> shift,
                compare_va=hex(0x25686d7))


def collector_count_passes(count, guard):
    """Model only the selected unsigned count/size guard, not allocation."""
    if not isinstance(count, int) or not 0 <= count < 1 << 64:
        raise ValueError('count outside unsigned 64-bit range')
    size = (count << guard['left_shift']) & ((1 << 64) - 1)
    return count >> guard['overflow_high_shift'] == 0 and size <= guard['max_allocation']


def unique_section(image, name):
    matches = [s for s in image.sections if s['name'] == name and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous section: ' + name)
    return matches[0]


def relocation(image, slot):
    rela = unique_section(image, '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('unsupported relocation entry size')
    raw = image.data[rela['offset']:rela['offset'] + rela['size']]
    matches = [(where, info, addend) for where, info, addend in struct.iter_unpack('<QQq', raw)
               if where == slot]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous relocation slot')
    return matches[0]


def imported_symbol(image, slot):
    """Resolve one x86-64 GLOB_DAT slot via file-backed RELA and dynamic symbols."""
    where, info, addend = relocation(image, slot)
    dynsym, dynstr = (unique_section(image, n) for n in ('.dynsym', '.dynstr'))
    if dynsym['size'] % 24:
        raise ValueError('unsupported dynamic symbol entry size')
    kind, symbol_index = info & 0xffffffff, info >> 32
    if kind != 6 or addend != 0 or symbol_index * 24 + 24 > dynsym['size']:
        raise ValueError('unexpected dynamic relocation')
    symbol_offset = dynsym['offset'] + symbol_index * 24
    name_offset = struct.unpack_from('<I', image.data, symbol_offset)[0]
    if name_offset >= dynstr['size']:
        raise ValueError('dynamic symbol name out of range')
    begin, end = dynstr['offset'] + name_offset, dynstr['offset'] + dynstr['size']
    zero = image.data.find(b'\0', begin, end)
    if zero < 0:
        raise ValueError('unterminated dynamic symbol name')
    symbol = image.data[begin:zero].decode('ascii')
    if symbol != 'memcmp':
        raise ValueError('unexpected imported comparator')
    return dict(slot_va=hex(where), relocation_type=kind, symbol_index=symbol_index, symbol=symbol)


def relative_slot(image, slot):
    where, info, addend = relocation(image, slot)
    if info != 8 or addend != 0x29ed380:
        raise ValueError('unexpected relative converter relocation')
    return dict(slot_va=hex(where), relocation_type=info, addend_va=hex(addend))


def check_variant_names(classifier, refs):
    by_role = {row['role']: row for row in refs}
    for row, key in zip(classifier, ('tag_zero', 'tag_one', 'tag_other')):
        if row['name'] != by_role[key]['text']:
            raise ValueError('reader and writer variant names differ')
    if len(classifier) != 3:
        raise ValueError('wrong variant count')


def collect(data):
    digest = verify_digest(data)
    image = Image(data)
    read = image.read
    functions = function_rows(image)
    pins = []
    for role, address, text in PINS:
        expected = bytes.fromhex(text)
        raw = verify_pin(read, address, expected)
        pins.append(dict(role=role, va=hex(address), bytes=raw.hex()))
    calls = []
    for role, address, target in CALLS:
        raw = checked_relative(read, address, b'\xe8', target)
        calls.append(dict(role=role, va=hex(address), target_va=hex(target), bytes=raw.hex()))
    branches = []
    for role, address, prefix, target in BRANCHES:
        prefix = bytes.fromhex(prefix)
        raw = checked_relative(read, address, prefix, target, 1 if len(prefix) == 1 else 4)
        branches.append(dict(role=role, va=hex(address), target_va=hex(target), bytes=raw.hex()))
    refs = []
    for role, address, prefix, target, length, expected in REFERENCES:
        raw = checked_relative(read, address, bytes.fromhex(prefix), target)
        literal = read(target, length).decode('ascii')
        if literal != expected:
            raise ValueError('literal mismatch: ' + role)
        refs.append(dict(role=role, instruction_va=hex(address), instruction_bytes=raw.hex(),
                         literal_va=hex(target), size=len(literal), text=literal))
    classifier = classifier_rows(read)
    by_role = {row['role']: row for row in refs}
    check_variant_names(classifier, refs)
    for row, payload in zip(classifier, ('payload_zero_one', 'payload_zero_one', 'payload_other')):
        row['payload_field'] = by_role[payload]['text']
    messages = [duplicate_literal(read, 0x264d5cf, 0x264d5dd),
                duplicate_literal(read, 0x268958d, 0x268959b)]
    indirect = []
    for role, site in (('key_converter', 0x1e0d198), ('payload_converter', 0x1e13b0d)):
        target, raw = relative(read, site, b'\xff\x15')
        if target != 0x5773120:
            raise ValueError('converter slot mismatch')
        indirect.append(dict(role=role, va=hex(site), slot_va=hex(target), bytes=raw.hex()))
    target, raw = relative(read, 0x2860e46, b'\xff\x15')
    if target != 0x576e488:
        raise ValueError('tree comparator slot mismatch')
    indirect.append(dict(role='tree_key_comparator', va=hex(0x2860e46), slot_va=hex(target), bytes=raw.hex()))
    return dict(artifact_sha256=digest, coordinate_system='linked ELF virtual addresses; end addresses exclusive',
                scope='Selected static paths only; no target execution or full CFG recovery',
                selected_record_counts=dict(functions=len(functions), pins=len(pins), calls=len(calls),
                                            branches=len(branches), references=len(refs),
                                            indirect_calls=len(indirect), variants=len(classifier),
                                            variant_character_comparisons=sum(row['comparisons'] for row in classifier)),
                functions=functions, pins=pins, calls=calls, branches=branches,
                indirect_calls=indirect, references=refs, variants=classifier,
                collector_allocation_guard=collector_allocation_guard(read),
                tree_comparator_import=imported_symbol(image, target),
                converter_relocation=relative_slot(image, 0x5773120), duplicate_key_literals=messages)


def write_outputs(evidence, out):
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(('tag', 'name', 'payload_field', 'initial_compare_va', 'success_store_va', 'unknown_target_va'))
    for row in evidence['variants']:
        writer.writerow((row['tag'], row['name'], row['payload_field'], row['initial_compare_va'],
                         row['success_store_va'], row['unknown_target_va']))
    (out / 'variants.tsv').write_text(stream.getvalue(), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    evidence = collect(BINARY.read_bytes())
    write_outputs(evidence, args.out)


if __name__ == '__main__':
    main()
