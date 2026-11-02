#!/usr/bin/env python3
"""Collect selected node 94 display-name state reader and hash-writer evidence.

No target code is executed. Address interpretation and FDE parsing reuse the
repository's shared ELF helpers; instructions are selected, fixed byte forms.
"""
import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BASE_COMMIT = 'e5c9b6436876b2a4a39daef813171f9879317699'

# Actual FDE ends, not the next unwind-index entry. The full unmasked extent
# hashes bind every selected body even where only a few instructions are read.
FUNCTIONS = [
 ('json_reader', 0x361cc50, 0x361d5df, '21d985dc1d41e571a67b4951e7c8da9040b775f1a0d8d313f3ea84899d6e5284'),
 ('json_sequence', 0x3687600, 0x36878ae, '219f7052041f5c87d5c327a7f4067296d3ff2c42387e94b046d24e48164ccedf'),
 ('json_pair', 0x3029660, 0x3029a27, '374aebd7137983a6b85e10a17111777c69ad58a634bea35745df6200fc16bae3'),
 ('json_value', 0x303f000, 0x303f17f, 'edb3aceaffe995a685af0a9944979c502c9ad83a5bc577ba210f1c2227734c89'),
 ('json_string', 0x3097890, 0x30979e8, '99f732324a2ca4d9ed1eb802c5a3b32b9a686e22314b9797a7dd45fe70ee8a1b'),
 ('mp_reader', 0x2b3fee0, 0x2b40679, 'bac0b0378dc325290d7269695bff8762c8afc7aecbaccf235eddb56cf5620348'),
 ('mp_map', 0x3676290, 0x36766a1, 'da01806501c28b73fb043bc6c81f7dcd9b6852f83e87ca92e91c20b5aac56585'),
 ('mp_sequence', 0x3686e90, 0x368719d, '156628a720b1480a9e69e5a4197f9454c85757929cfc12e36884a2f7bd6c3bea'),
 ('mp_pair', 0x2d62db0, 0x2d63c29, 'f89c36a22845b36eefbcb4d3e28599d8d9417e784728a37c7add4ba9401d525b'),
 ('mp_string', 0x2c632c0, 0x2c63a43, '9092a0e1713366e655c6f58682ffcefc50cef18863b98f21912a1a775f5413c4'),
 ('map_insert', 0x33a8c70, 0x33a8f38, '82a145710992318393eb3e261918090e08ae0bc2ebe879570e081397da9d5be0'),
 ('action_primary', 0x4d9b990, 0x4d9bddc, '03f4ba1606226cbb250f839ea7cb06326ee325c986782b0bfd70059734aa7f49'),
 ('action_insert', 0x493d150, 0x493d418, 'f7773b7a118eb6c30bfe47d5cbd97f7939325cd97af54b8c62ccf4839dd87b5f'),
 ('action_remove', 0x4944b50, 0x4944d45, '9fa16837506fa38ca4739acc65ed55d2a0af8ef7cc49f507cdee0e0600f31fc1'),
 ('field_writer', 0x27b36c0, 0x27b371c, '0af16333fb47dc9a1765d73d16560c06bb7b416db1775dcbbfc079350304260d'),
 ('writer_low', 0x25ea910, 0x25ea9d9, '5439d008c5a5c4893d5fee8d7ad09694f85e956385b8b0bfc95abe2513645dd3'),
 ('writer_shared', 0x45fef60, 0x45ff029, '6078e1cc3aa6e9b8c773a36169cc214549844e222111726f38fd3342884cb0e2'),
 ('seq_low', 0x1e3f470, 0x1e3f6fb, 'f4a041492406e275d33e6354f5889cb9057a5ec8f52078b1ef9ec93122a3ab49'),
 ('seq_shared', 0x440f610, 0x440f89b, 'd4d2e393c3e90436479610be087266eb27cdf518cdb0ee5c8f881043c3097953'),
 ('pair_low', 0x1dd5800, 0x1dd5abb, '6c260b3caa1eceab75cd41a40d3bdcc351668988e6b361654b73c78f0a6176a5'),
 ('pair_shared', 0x43be050, 0x43be30b, '04766f16f8091e2930d13c055dafc048ca2bf7c15188b8d591d9a73389c9bd11'),
 ('value_low', 0x1e0fb80, 0x1e0fcba, '99df5ca67de395ac78b2577475efad9f8ee0dd4ac84f6a86934c16a1f52dff42'),
 ('value_low_direct', 0x1e117a0, 0x1e118da, '4ea044d19d3e36272e382136b7057eab0268657388d0e1e86d8b1de46f990b89'),
 ('value_shared', 0x43f7990, 0x43f7aca, 'a26279c6c0b5d8fa97d72b99a8b6ae8c827da3de4d43cacd930045479132f5d8'),
 ('value_shared_direct', 0x43f6890, 0x43f69ca, '359eef5b64eb851f2af88349f6e178ce536c98c02193c223c807870b18ddf990'),
]

# Each tuple is an independently selected transfer, not a scan for opcodes.
# 'boundary' denotes a previously owned caller, never a newly claimed FDE.
EDGES = [
 ('json_field_to_map', 'boundary', 0x2fe7c37, 'call', 0x361cc50),
 ('json_object_key', 'new', 0x361ce6a, 'call', 0x301d7f0),
 ('json_object_value', 'new', 0x361cefc, 'call', 0x3097890),
 ('json_object_insert', 'new', 0x361cf6e, 'call', 0x33a8c70),
 ('json_sequence', 'new', 0x361cd2b, 'call', 0x3687600),
 ('json_sequence_next', 'new', 0x3687666, 'call', 0x3029660),
 ('json_pair_key', 'new', 0x30297eb, 'call', 0x30485b0),
 ('json_pair_value', 'new', 0x302981e, 'call', 0x303f000),
 ('json_value_string', 'new', 0x303f120, 'call', 0x3097890),
 ('json_sequence_insert', 'new', 0x36876f4, 'call', 0x33a8c70),
 ('mp_field_to_map', 'boundary', 0x2abb2af, 'call', 0x2b3fee0),
 ('mp_map', 'new', 0x2b402b6, 'call', 0x3676290),
 ('mp_sequence', 'new', 0x2b403fa, 'call', 0x3686e90),
 ('mp_map_key', 'new', 0x3676314, 'call', 0x2a72b70),
 ('mp_map_value', 'new', 0x3676362, 'call', 0x2c632c0),
 ('mp_map_insert', 'new', 0x367641b, 'call', 0x33a8c70),
 ('mp_sequence_pair', 'new', 0x3686efc, 'call', 0x2d62db0),
 ('mp_pair_key', 'new', 0x2d63379, 'call', 0x2bd0ea0),
 ('mp_pair_value', 'new', 0x2d634b5, 'call', 0x2c632c0),
 ('mp_sequence_insert', 'new', 0x3686f9d, 'call', 0x33a8c70),
 ('insert_compare_slot', 'new', 0x33a8cf8, 'slot', 0x576e488),
 ('insert_nonempty_helper', 'new', 0x33a8e2f, 'call', 0x2f99820),
 ('prior_action_to_core', 'boundary', 0x4677b80, 'call', 0x4d9b990),
 ('action_compare_name', 'new', 0x4d9bc40, 'slot', 0x576e378),
 ('action_remove_key', 'new', 0x4d9bc91, 'call', 0x4944b50),
 ('action_insert_key', 'new', 0x4d9bd2a, 'call', 0x493d150),
 ('action_insert_compare', 'new', 0x493d1d8, 'slot', 0x576e488),
 ('action_insert_nonempty', 'new', 0x493d30f, 'call', 0x423db50),
 ('action_remove_found', 'new', 0x4944c58, 'call', 0x42b7470),
 ('field_wrapper', 'boundary', 0x275b273, 'call', 0x27b36c0),
 ('field_name', 'new', 0x27b36e3, 'call', 0x25aa7f0),
 ('field_tail', 'new', 0x27b36fc, 'jump', 0x25ea910),
 ('job15_low', 'boundary', 0x2817fd0, 'call', 0x25ea910),
 ('job15_shared', 'boundary', 0x4ae4f10, 'call', 0x45fef60),
 ('low_collect', 'new', 0x25ea97a, 'call', 0x2563060),
 ('low_serialize', 'new', 0x25ea988, 'call', 0x1e3f470),
 ('shared_collect', 'new', 0x45fefca, 'call', 0x486b570),
 ('shared_serialize', 'new', 0x45fefd8, 'call', 0x440f610),
 ('low_first_pair', 'new', 0x1e3f52f, 'call', 0x1dd5800),
 ('low_each_pair', 'new', 0x1e3f65e, 'call', 0x1dd5800),
 ('shared_first_pair', 'new', 0x440f6cf, 'call', 0x43be050),
 ('shared_each_pair', 'new', 0x440f7fe, 'call', 0x43be050),
 ('low_buffered_key', 'new', 0x1dd58b0, 'call', 0x1e0d0a0),
 ('low_buffered_value', 'new', 0x1dd58c9, 'call', 0x1e0fb80),
 ('low_direct_key', 'new', 0x1dd5976, 'call', 0x1e0d6c0),
 ('low_direct_value', 'new', 0x1dd598f, 'call', 0x1e117a0),
 ('shared_buffered_key', 'new', 0x43be100, 'call', 0x43f4bb0),
 ('shared_buffered_value', 'new', 0x43be119, 'call', 0x43f7990),
 ('shared_direct_key', 'new', 0x43be1c6, 'call', 0x43f56b0),
 ('shared_direct_value', 'new', 0x43be1df, 'call', 0x43f6890),
 ('low_value_buffered_string', 'new', 0x1e0fc5a, 'call', 0x25aa7f0),
 ('low_value_direct_string', 'new', 0x1e1187a, 'call', 0x25aacb0),
 ('shared_value_buffered_string', 'new', 0x43f7a6a, 'call', 0x4aeb170),
 ('shared_value_direct_string', 'new', 0x43f696a, 'call', 0x4aeb630),
]

# Fixed observed branches, grouped by bounded decision. A separate table records
# their opcode, actual signed displacement, fallthrough and target from ELF bytes.
BRANCH_SITES = {
 'json_read': [0x361cc72,0x361ccd9,0x361ce74,0x361ce7f,0x361ce98,0x361ceb1,0x361cee4,0x361cf09,0x361cf7a,0x361cfa0,0x361d155,0x361d18b,0x361d194],
 'json_pairs': [0x3687678,0x368769c,0x3687701,0x368772b,0x3687788,0x303f01b,0x303f04a,0x303f094,0x303f12d],
 'json_string': [0x30978ac,0x30978d0,0x309790d,0x309793d,0x309795a,0x3097975],
 'mp_select': [0x2b400cb,0x2b4026e,0x2b40277,0x2b4028a,0x2b40297,0x2b402c2,0x2b402e2,0x2b402e6,0x2b403bb,0x2b403ce,0x2b403db,0x2b40406,0x2b40422,0x2b40426],
 'mp_map': [0x36762cb,0x367633d,0x367636e,0x3676396,0x3676432,0x367643b,0x367657b],
 'mp_sequence': [0x3686ebf,0x3686f1c,0x3686f4a,0x3686faa,0x3687088],
 'mp_string': [0x2c637a4,0x2c637b7,0x2c637c4,0x2c637e6,0x2c637f7,0x2c63885],
 'insert': [0x33a8c98,0x33a8cea,0x33a8d18,0x33a8d1f,0x33a8d3e,0x33a8ddc,0x33a8e57,0x33a8e83],
 'action': [0x4d9b9ab,0x4d9b9b9,0x4d9b9c7,0x4d9bc14,0x4d9bc31,0x4d9bc5b,0x4d9bca1,0x4d9bca3,0x4d9bd3a,0x4d9bd3c],
 'action_insert': [0x493d178,0x493d1ca,0x493d1f8,0x493d1ff,0x493d21e,0x493d2bc,0x493d337,0x493d363],
 'action_remove': [0x4944b71,0x4944bca,0x4944bf1,0x4944bf8,0x4944c0e,0x4944c84,0x4944c90,0x4944c99,0x4944cc7],
 'field_writer': [0x27b36cf,0x27b36ef],
 'low_writer': [0x25ea925,0x25ea994,0x1e3f4a6,0x1e3f4c6,0x1e3f4e5,0x1e3f50f,0x1e3f518,0x1e3f54a,0x1e3f57d,0x1e3f586,0x1e3f5d0,0x1e3f62d,0x1e3f66b,0x1e3f678],
 'low_pair': [0x1dd582f,0x1dd583a,0x1dd5845,0x1dd5871,0x1dd58ba,0x1dd58d3,0x1dd5933,0x1dd5980,0x1dd5999,0x1dd59af,0x1dd59e7],
 'shared_writer': [0x45fef75,0x45fefe4,0x440f646,0x440f666,0x440f685,0x440f6af,0x440f6b8,0x440f6ea,0x440f80b,0x440f818],
 'shared_pair': [0x43be07f,0x43be08a,0x43be095,0x43be0c1,0x43be10a,0x43be123,0x43be183,0x43be1d0,0x43be1e9,0x43be1ff,0x43be237],
 'value_paths': [0x1e0fba7,0x1e0fbd5,0x1e0fbef,0x1e0fc1a,0x1e0fc63,0x1e117c7,0x1e117f5,0x1e1180f,0x1e1183a,0x1e11883,0x43f79b7,0x43f79e5,0x43f79ff,0x43f7a2a,0x43f7a73,0x43f68b7,0x43f68e5,0x43f68ff,0x43f692a,0x43f6973],
}

# Deliberately limited instruction windows; each is inside a selected body,
# except the explicitly marked earlier-owner boundaries. Ends are exclusive.
WINDOWS = [
 ('prior_json_field', 'boundary', 0x2fe7c09,0x2fe7c89),
 ('prior_mp_field', 'boundary', 0x2abb289,0x2abb310),
 ('prior_named_writer', 'boundary', 0x275b266,0x275b278),
 ('prior_job_low', 'boundary', 0x2817fbd,0x2817ff0),
 ('prior_job_shared', 'boundary', 0x4ae4efd,0x4ae4f30),
 ('prior_json_guard', 'boundary', 0x2fe635d,0x2fe63b8),
 ('prior_json_duplicate', 'boundary', 0x2ff02d5,0x2ff02f0),
 ('prior_mp_duplicate', 'boundary', 0x2abe5aa,0x2abe5c5),
 ('prior_action_wrapper', 'boundary', 0x4677b10,0x4677b90),
 ('prior_shared_base', 'boundary', 0x4d7e8fe,0x4d7e901),
 ('prior_shared_capture', 'boundary', 0x4d7ef4b,0x4d7ef5d),
 ('prior_shared_row15', 'boundary', 0x4d7f60f,0x4d7f62c),
 ('json_object_entry', 'new', 0x361ce5d,0x361ce85),
 ('json_object_value_insert', 'new', 0x361cef7,0x361cf80),
 ('json_object_duplicate', 'new', 0x361cf92,0x361cfdf),
 ('json_object_result', 'new', 0x361d125,0x361d142),
 ('json_sequence_loop', 'new', 0x3687660,0x36876fe),
 ('json_sequence_duplicate', 'new', 0x3687707,0x368776d),
 ('json_string_decode', 'new', 0x30978a1,0x30978f0),
 ('json_string_return', 'new', 0x3097909,0x30979aa),
 ('mp_marker_map', 'new', 0x2b40268,0x2b402c8),
 ('mp_marker_sequence', 'new', 0x2b403b8,0x2b40408),
 ('mp_map_children', 'new', 0x36762f0,0x3676367),
 ('mp_map_insert', 'new', 0x367641b,0x3676464),
 ('mp_map_duplicate', 'new', 0x3676556,0x36765bd),
 ('mp_sequence_insert', 'new', 0x3686ef0,0x3686faa),
 ('mp_sequence_duplicate', 'new', 0x3687063,0x36870c7),
 ('mp_pair_children', 'new', 0x2d63360,0x2d634c5),
 ('mp_string_dispatch', 'new', 0x2c637a1,0x2c6388e),
 ('insert_compare', 'new', 0x33a8ce0,0x33a8d21),
 ('insert_replace', 'new', 0x33a8d52,0x33a8d7e),
 ('insert_root', 'new', 0x33a8e3e,0x33a8ec7),
 ('action_gate', 'new', 0x4d9b9a4,0x4d9b9d0),
 ('action_name_compare', 'new', 0x4d9bbf7,0x4d9bc66),
 ('action_delete', 'new', 0x4d9bc82,0x4d9bcb9),
 ('action_set', 'new', 0x4d9bce5,0x4d9bd5a),
 ('action_duplicate', 'new', 0x4d9bd5a,0x4d9bd77),
 ('action_insert_compare', 'new', 0x493d1c0,0x493d201),
 ('action_insert_replace', 'new', 0x493d232,0x493d25e),
 ('action_insert_root', 'new', 0x493d31e,0x493d3a7),
 ('action_remove_lookup', 'new', 0x4944b61,0x4944c26),
 ('action_remove_found', 'new', 0x4944c26,0x4944cd7),
 ('field_named_and_error', 'new', 0x27b36cb,0x27b371c),
 ('low_map', 'new', 0x25ea91f,0x25ea9a7),
 ('shared_map', 'new', 0x45fef6f,0x45feff7),
 ('low_sequence_head', 'new', 0x1e3f489,0x1e3f4eb),
 ('low_sequence_loop', 'new', 0x1e3f62a,0x1e3f67a),
 ('shared_sequence_head', 'new', 0x440f629,0x440f68b),
 ('shared_sequence_loop', 'new', 0x440f7ca,0x440f81a),
 ('low_pair_buffered', 'new', 0x1dd5853,0x1dd58e7),
 ('low_pair_direct', 'new', 0x1dd592c,0x1dd59b3),
 ('shared_pair_buffered', 'new', 0x43be0a3,0x43be137),
 ('shared_pair_direct', 'new', 0x43be17c,0x43be203),
 ('low_value_buffered', 'new', 0x1e0fc4f,0x1e0fc79),
 ('low_value_direct', 'new', 0x1e1186f,0x1e11899),
 ('shared_value_buffered', 'new', 0x43f7a5f,0x43f7a89),
 ('shared_value_direct', 'new', 0x43f695f,0x43f6989),
]

BOUNDARY_HASHES = {
 'prior_json_field':'589e0a3b795c06d37384b36ddb266bc827161d8bdc2dd8a7555ddb17949af924',
 'prior_mp_field':'a8cbae9cd3fa764af6bc516937a7e457b04814639779fa2733a34591cbcb83b2',
 'prior_named_writer':'c0a888e8fc8b27d327cb828eaf8f19c897c250298f03e95ee44fb2cf4fefce51',
 'prior_job_low':'bf1477569d1ca0882bee903059aef9161c7d68978e230eee6a11fb5e187568a7',
 'prior_job_shared':'8dfdb3516c4770f6510e3fbdf9eb697bfbbbc2299bf128aff1a874719a798ecf',
 'prior_json_guard':'4c24bac0f8495e2b7f8c6fbbdd25c598d1c831644356bf53c31d34c6fe94278b',
 'prior_json_duplicate':'7122470d1668d55a753c892b2ab2f3f440b3f681f037f69dc7e16bf934ba5008',
 'prior_mp_duplicate':'837aa3b7278b552eaecfce73615e80162899e87135fbbaef93cbfe0694749a12',
 'prior_action_wrapper':'c2161cbf348854ae279d4190ea4bc49e8a71e29f7845d9787129f3e542cacb27',
 'prior_shared_base':'179eb31831702eaa52282ba5a57e1784d943be36f9f6f0ec6e65a181d5435b8e',
 'prior_shared_capture':'340c31d0e5b650ee6dd929d90797bffc181e38142e49bc1fb7d35e58d5feba95',
 'prior_shared_row15':'347fbfb66b58052c52fe5a75ab6dec39591b86a3e3369a69a12916ba80e645bb',
}

CONDITION_NAMES = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')


def file_offset(sec, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in sec if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address must map to exactly one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def read(data, sec, va, size):
    off = file_offset(sec, va, size)
    if off + size > len(data):
        raise ValueError('address exceeds file')
    return bytes(data[off:off + size])


def verify_digest(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


def decode_branch(data, sec, va):
    first = read(data, sec, va, 2)
    if 0x70 <= first[0] <= 0x7f:
        width, cond = 2, first[0] - 0x70
        raw = first
        disp = struct.unpack('<b', raw[1:2])[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        width, cond = 6, first[1] - 0x80
        raw = read(data, sec, va, width)
        disp = struct.unpack('<i', raw[2:])[0]
    else:
        raise ValueError('unsupported conditional branch')
    return {'bytes': raw.hex(), 'condition': CONDITION_NAMES[cond],
            'fallthrough': va + width, 'target': va + width + disp,
            'displacement': disp}


def decode_edge(data, sec, va, kind):
    if kind in ('call', 'jump'):
        raw = read(data, sec, va, 5)
        if raw[0] != (0xe8 if kind == 'call' else 0xe9):
            raise ValueError('unexpected rel32 opcode')
        disp = struct.unpack('<i', raw[1:])[0]
    elif kind == 'slot':
        raw = read(data, sec, va, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError('unexpected indirect-call opcode')
        disp = struct.unpack('<i', raw[2:])[0]
    else:
        raise ValueError('unknown edge kind')
    return raw, va + len(raw) + disp


def expected_bytes(data, sec, va, expected):
    raw = read(data, sec, va, len(bytes.fromhex(expected)))
    if raw.hex() != expected:
        raise ValueError('fixed-byte anchor mismatch')
    return raw


def one_section(sec, name):
    found = [s for s in sec if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('missing or ambiguous section')
    return found[0]


def comparison_relocation(data, sec, expected_slot, expected_symbol):
    r = one_section(sec, '.rela.dyn')
    if r['size'] % 24:
        raise ValueError('malformed relocation section')
    found = []
    for off in range(r['offset'], r['offset'] + r['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == expected_slot:
            found.append((off, slot, info & 0xffffffff, info >> 32, addend))
    if len(found) != 1:
        raise ValueError('missing or duplicate comparison relocation')
    off, slot, typ, sym, addend = found[0]
    if typ != 6 or sym == 0 or addend != 0:
        raise ValueError('unexpected comparison relocation')
    dynsym, dynstr = one_section(sec, '.dynsym'), one_section(sec, '.dynstr')
    if sym * 24 + 24 > dynsym['size']:
        raise ValueError('comparison symbol outside table')
    symbol_off = dynsym['offset'] + sym * 24
    name_off = struct.unpack_from('<I', data, symbol_off)[0]
    if name_off >= dynstr['size']:
        raise ValueError('symbol name outside string table')
    start = dynstr['offset'] + name_off
    end = data.find(b'\0', start, dynstr['offset'] + dynstr['size'])
    if end < 0 or bytes(data[start:end]) != expected_symbol:
        raise ValueError('comparison symbol mismatch')
    return {'file_offset': hex(off), 'slot': hex(slot), 'type': typ,
            'symbol_index': sym, 'symbol': expected_symbol.decode('ascii'), 'addend': addend,
            'bytes': bytes(data[off:off+24]).hex()}


def memcmp_relocation(data, sec):
    return comparison_relocation(data, sec, 0x576e488, b'memcmp')


def action_anchors(data, sec):
    # Constants are read from selected instructions and their forms are pinned.
    outer = expected_bytes(data, sec, 0x4677b15, '4983ff65')[-1]
    outer_result = struct.unpack('<H', expected_bytes(data,sec,0x4677b1b,'66c743084301')[-2:])[0]
    maximum = expected_bytes(data, sec, 0x4d9b9b5, '4983fc14')[-1]
    minimum = expected_bytes(data, sec, 0x4d9b9c3, '4983fc03')[-1]
    too_long = struct.unpack('<H', expected_bytes(data,sec,0x4d9b9b1,'66b8d300')[-2:])[0]
    too_short = struct.unpack('<H', expected_bytes(data,sec,0x4d9b9bf,'66b8d400')[-2:])[0]
    duplicate = struct.unpack('<H', expected_bytes(data,sec,0x4d9bd5a,'66b8d500')[-2:])[0]
    success = struct.unpack('<H', expected_bytes(data,sec,0x4d9bd50,'66c7038601')[-2:])[0]
    expected_bytes(data,sec,0x4d9bcb2,'66b88601')
    for va, condition, target in ((0x4d9b9ab,'e',0x4d9bc82),
                                   (0x4d9b9b9,'a',0x4d9bcb9),
                                   (0x4d9b9c7,'b',0x4d9bcb9),
                                   (0x4d9bc31,'ne',0x4d9ba30),
                                   (0x4d9bc5b,'ne',0x4d9ba41)):
        branch = decode_branch(data,sec,va)
        if (branch['condition'],branch['target']) != (condition,target):
            raise ValueError('action branch changed')
    # Once equality is established, the fallthrough jumps to duplicate status.
    _,duplicate_target = decode_edge(data,sec,0x4d9bc61,'jump')
    if duplicate_target != 0x4d9bd5a:
        raise ValueError('action duplicate jump changed')
    return {'outer_limit':outer,'minimum_nonempty':minimum,'maximum':maximum,
            'outer_reject':outer_result,'too_long':too_long,'too_short':too_short,
            'duplicate':duplicate,'success':success}


def action_case(length, duplicate, anchors):
    # A deliberately bounded model of the checked branches, not target execution.
    if type(length) is not int or length < 0 or type(duplicate) is not bool:
        raise ValueError('invalid synthetic action input')
    if length >= anchors['outer_limit']:
        return 'outer_reject', anchors['outer_reject']
    if length == 0:
        return 'remove', anchors['success']
    if length > anchors['maximum']:
        return 'too_long', anchors['too_long']
    if length < anchors['minimum_nonempty']:
        return 'too_short', anchors['too_short']
    if duplicate:
        return 'duplicate_value', anchors['duplicate']
    return 'insert_or_replace', anchors['success']


def primary_capture(data, sec):
    base_setup = expected_bytes(data,sec,0x4d7e8fe,'4889f5')
    capture = expected_bytes(data,sec,0x4d7ef4b,'488d8d1044000048898424a0010000488908')
    row = expected_bytes(data,sec,0x4d7f60f,'488b8c24a001000048898bf0000000488d0da3529c0048898bf8000000')
    target = 0x4d7f61e + 7 + struct.unpack('<i',row[18:22])[0]
    if target != 0x57448c8:
        raise ValueError('primary capture vtable changed')
    rela = one_section(sec,'.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('malformed relocation section')
    entries=[]
    for off in range(rela['offset'],rela['offset']+rela['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot == target+24:
            entries.append((off,info,addend))
    if len(entries)!=1 or entries[0][1]!=8 or entries[0][2]!=0x4592a80:
        raise ValueError('primary row call relocation changed')
    off,info,thunk_va=entries[0]
    thunk=expected_bytes(data,sec,thunk_va,'534889fbe8372455004889d85bc3')
    body=thunk_va+9+struct.unpack('<i',thunk[5:9])[0]
    if body != 0x4ae4ec0:
        raise ValueError('primary row thunk target changed')
    return {'base_setup_site':hex(0x4d7e8fe),'base_setup_bytes':base_setup.hex(),
            'capture_site':hex(0x4d7ef4b), 'capture_bytes':capture.hex(),
            'state_offset':hex(struct.unpack('<I',capture[3:7])[0]),
            'stack_spill_offset':hex(struct.unpack('<I',capture[11:15])[0]),
            'row_site':hex(0x4d7f60f),'row_bytes':row.hex(),'vtable':hex(target),
            'closure_array_offset':hex(struct.unpack('<I',row[11:15])[0]),
            'call_relocation_file_offset':hex(off),
            'call_relocation_bytes':bytes(data[off:off+24]).hex(),
            'thunk':hex(thunk_va),'thunk_bytes':thunk.hex(),'closure_body':hex(body)}


def select_functions(data, sec, index, fdes):
    wanted = {start: (name, end, sha) for name,start,end,sha in FUNCTIONS}
    index_by_start = {}
    for item in index:
        if item['start'] in wanted:
            if item['start'] in index_by_start:
                raise ValueError('duplicate selected unwind start')
            index_by_start[item['start']] = item
    selected = {}
    for item in fdes:
        if item['start'] in wanted:
            if item['start'] in selected:
                raise ValueError('duplicate selected FDE start')
            selected[item['start']] = item
    rows = []
    for name, start, end, sha in FUNCTIONS:
        item, ix = selected.get(start), index_by_start.get(start)
        if item is None or ix is None or item['fde'] != ix['fde'] or item['end'] != end:
            raise ValueError('selected FDE/index mismatch')
        raw = read(data, sec, start, end-start)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('selected FDE bytes changed')
        rows.append({'name': name, 'start': hex(start), 'end_exclusive': hex(end),
                     'file_offset': hex(file_offset(sec,start,end-start)),
                     'length': end-start, 'fde': hex(item['fde']), 'cie': hex(item['cie']),
                     'lsda': hex(item['lsda']) if item['lsda'] is not None else '',
                     'sha256': sha, 'raw_hex': raw.hex()})
    return rows


def owner(va, length=1):
    candidates = [name for name,start,end,_ in FUNCTIONS if start <= va and va+length <= end]
    return candidates[0] if len(candidates) == 1 else None


def marker_case(marker, lower, middle, upper, mask):
    if type(marker) is not int or not lower <= marker < upper:
        raise ValueError('marker outside selected fixed-container ranges')
    return ('map' if marker < middle else 'sequence', marker & mask)


def encode_tsv(rows, fields):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fields, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def prior_field_bindings(data, sec):
    # These are connection witnesses inside already owned visitor functions.
    # They do not claim either function or the original RE-017 GOT calls.
    result=[]
    for mode, guard, diagnostic, literal in (
            ('json',0x2fe6366,0x2ff02d5,0x57f504),
            ('messagepack',0x2abb291,0x2abe5aa,0x578c9a)):
        br=decode_branch(data,sec,guard)
        if br['condition'] != 'ne' or br['target'] != diagnostic:
            raise ValueError('field duplicate guard changed')
        lea=read(data,sec,diagnostic,7)
        if lea[:3] != b'\x48\x8d\x05':
            raise ValueError('field diagnostic LEA changed')
        dest=diagnostic+7+struct.unpack('<i',lea[3:])[0]
        if dest != literal or read(data,sec,dest,20) != b'user_to_display_name':
            raise ValueError('field diagnostic label changed')
        # Both selected visitors place the same literal pointer and length in
        # adjacent stack fields; check the complete immediate store.
        setup=read(data,sec,diagnostic+7,20)
        if setup[0:4] != b'\x48\x89\x84\x24' or setup[8:12] != b'\x48\xc7\x84\x24' or setup[-4:] != b'\x14\x00\x00\x00':
            raise ValueError('field diagnostic length setup changed')
        result.append({'mode':mode,'scope':'prior_boundary','guard_va':hex(guard),
                       'guard_bytes':br['bytes'],'duplicate_target':hex(diagnostic),
                       'label_lea':lea.hex(),'label_va':hex(dest),
                       'label_file_offset':hex(file_offset(sec,dest,20)),
                       'label_bytes':read(data,sec,dest,20).hex(),
                       'pointer_length_setup':setup.hex()})
    br=decode_branch(data,sec,0x2fe6399)
    if br['condition'] != 'ae' or br['target'] != 0x2fe7c09:
        raise ValueError('JSON value handoff changed')
    return {'duplicate_guards':result,'json_colon_handoff':{'site':hex(0x2fe6399),
            'bytes':br['bytes'],'target':hex(br['target'])}}


def selected_windows(data, sec):
    windows = []
    for name, scope, lo, hi in WINDOWS:
        if scope == 'new' and owner(lo,hi-lo) is None:
            raise ValueError('window outside selected functions')
        raw = read(data,sec,lo,hi-lo)
        if scope == 'boundary' and hashlib.sha256(raw).hexdigest() != BOUNDARY_HASHES.get(name):
            raise ValueError('boundary bytes changed')
        windows.append({'name':name, 'scope':scope, 'start':hex(lo),
                        'end_exclusive':hex(hi), 'file_offset':hex(file_offset(sec,lo,hi-lo)),
                        'sha256':hashlib.sha256(raw).hexdigest(), 'bytes':raw.hex()})
    return windows


def produce(data):
    digest = verify_digest(data)
    sec, index = unwind_index(data)
    _, fdes = eh_frame_records(data, sec)
    functions = select_functions(data, sec, index, fdes)
    edge_rows = []
    for name, scope, va, kind, wanted in EDGES:
        if scope == 'new' and owner(va, 6 if kind == 'slot' else 5) is None:
            raise ValueError('new edge outside selected functions')
        raw, target = decode_edge(data,sec,va,kind)
        if target != wanted:
            raise ValueError('relative transfer target changed')
        edge_rows.append({'name':name, 'scope':scope, 'site':hex(va),
                          'file_offset':hex(file_offset(sec,va,len(raw))),
                          'kind':kind, 'target_or_slot':hex(target), 'bytes':raw.hex()})
    windows = selected_windows(data,sec)
    branches=[]
    seen=set()
    for group, sites in BRANCH_SITES.items():
        for va in sites:
            if va in seen or owner(va) is None:
                raise ValueError('duplicate or out-of-scope branch site')
            seen.add(va)
            b=decode_branch(data,sec,va)
            if owner(b['target']) != owner(va):
                raise ValueError('selected branch target leaves owner')
            branches.append({'group':group, 'site':hex(va), 'owner':owner(va),
                             'file_offset':hex(file_offset(sec,va,len(bytes.fromhex(b['bytes'])))),
                             'bytes':b['bytes'], 'condition':b['condition'],
                             'displacement':b['displacement'], 'fallthrough':hex(b['fallthrough']),
                             'target':hex(b['target'])})
    # The fixed byte anchors establish the selected marker path, field pointer
    # and labels; they do not claim all input encodings or all CFG edges.
    expected_bytes(data,sec,0x2b400c9,'84c9')
    expected_bytes(data,sec,0x2b40274,'80f990')
    expected_bytes(data,sec,0x2b403b8,'80f9a0')
    expected_bytes(data,sec,0x2b4027d,'80e10f')
    expected_bytes(data,sec,0x27b36d1,'488d35fdbcc3fd')
    expected_bytes(data,sec,0x27b36d8,'ba14000000')
    expected_bytes(data,sec,0x33a8cf0,'ba14000000')
    expected_bytes(data,sec,0x1dd593d,'c6040192')
    expected_bytes(data,sec,0x43be18d,'c6040192')
    field = read(data,sec,0x3ef3d5,20)
    tag = read(data,sec,0x20a020,4)
    if field != b'user_to_display_name' or tag != b'User':
        raise ValueError('field or key label mismatch')
    duplicates=[]
    for role, second, first in [('json_object',0x361cfa6,0x361cfb4),
                                 ('json_pairs',0x3687731,0x368773f),
                                 ('mp_map',0x3676581,0x367658f),
                                 ('mp_pairs',0x368708e,0x368709c)]:
        hi=read(data,sec,second,10);lo=read(data,sec,first,10)
        if hi[:2]!=b'\x48\xb9' or lo[:2]!=b'\x48\xb9':
            raise ValueError('unexpected diagnostic literal instruction')
        store_hi=read(data,sec,second+10,4)
        store_lo=read(data,sec,first+10,3)
        if store_hi != b'\x48\x89\x48\x05' or store_lo != b'\x48\x89\x08':
            raise ValueError('diagnostic stores changed')
        buf=bytearray(13);buf[5:13]=hi[2:];buf[0:8]=lo[2:]
        if buf != b'duplicate key':
            raise ValueError('duplicate diagnostic changed')
        duplicates.append({'path':role,'first_store_source_va':hex(first),
                           'second_store_source_va':hex(second),'first_mov':lo.hex(),
                           'second_mov':hi.hex(),'first_store':store_lo.hex(),
                           'second_store':store_hi.hex(),'text':buf.decode('ascii')})
    lower, middle, upper, mask = 0x80, read(data,sec,0x2b40276,1)[0],read(data,sec,0x2b403ba,1)[0],read(data,sec,0x2b4027f,1)[0]
    marker_rows=[]
    for marker in range(lower,upper):
        kind,count=marker_case(marker,lower,middle,upper,mask)
        marker_rows.append({'marker':hex(marker),'route':kind,'declared_count':count})
    relocation=memcmp_relocation(data,sec)
    name_relocation=comparison_relocation(data,sec,0x576e378,b'bcmp')
    action=action_anchors(data,sec)
    capture=primary_capture(data,sec)
    action_rows=[]
    lengths=sorted({0, action['minimum_nonempty']-2, action['minimum_nonempty']-1,
                    action['minimum_nonempty'], action['maximum']-1, action['maximum'],
                    action['maximum']+1, action['outer_limit']-1, action['outer_limit']})
    for length in lengths:
        applicable=action['minimum_nonempty'] <= length <= action['maximum']
        for duplicate in ((False,True) if applicable else (False,)):
            route,status=action_case(length,duplicate,action)
            action_rows.append({'byte_length':length,
                                'equal_value_precondition':str(duplicate).lower() if applicable else 'not_tested',
                                'route':route,'status_word':hex(status)})
    boundaries=prior_field_bindings(data,sec)
    # Selected JSON dispatch entries, assuming the index is already in range.
    base=0x59035c
    dispatch=[]
    for character in ('[','{'):
        idx=ord(character)-0x5b
        entry=read(data,sec,base+4*idx,4)
        target=base+struct.unpack('<i',entry)[0]
        if target != {'[':0x361ccf0, '{':0x361cdf6}[character]:
            raise ValueError('JSON selected dispatch target changed')
        dispatch.append({'character':character,'index':idx,'table_va':hex(base),
                         'entry_va':hex(base+4*idx),'bytes':entry.hex(),'target':hex(target)})
    summary={'target_sha256':digest,'base_commit':BASE_COMMIT,
             'coordinates':'unrelocated ELF linked virtual addresses; file offsets separately',
             'function_count':len(functions),'selected_function_bytes':sum(x['length'] for x in functions),
             'edge_count':len(edge_rows),'boundary_edge_count':sum(x['scope']=='boundary' for x in edge_rows),
             'window_count':len(windows),'boundary_window_count':sum(x['scope']=='boundary' for x in windows),
             'branch_count':len(branches),'marker_cases':len(marker_rows),
             'synthetic_action_cases':len(action_rows),
             'diagnostic_paths':len(duplicates),'json_dispatch_entries':len(dispatch),
             'field_name':field.decode('ascii'),'key_label':tag.decode('ascii'),
             'comparison_relocation':relocation,
             'name_comparison_relocation':name_relocation,
             'limits':'Selected static byte forms and actual FDE extents; not a complete CFG, target execution, or component coverage.'}
    files={
      'functions.tsv':encode_tsv(functions,['name','start','end_exclusive','file_offset','length','fde','cie','lsda','sha256','raw_hex']),
      'edges.tsv':encode_tsv(edge_rows,['name','scope','site','file_offset','kind','target_or_slot','bytes']),
      'windows.tsv':encode_tsv(windows,['name','scope','start','end_exclusive','file_offset','sha256','bytes']),
      'branches.tsv':encode_tsv(branches,['group','site','owner','file_offset','bytes','condition','displacement','fallthrough','target']),
      'markers.tsv':encode_tsv(marker_rows,['marker','route','declared_count']),
      'action-cases.tsv':encode_tsv(action_rows,['byte_length','equal_value_precondition','route','status_word']),
      'data.json':json_bytes({'comparison_relocation':relocation,'name_comparison_relocation':name_relocation,
                              'action_anchors':action,'primary_capture':capture,
                              'diagnostics':duplicates,'json_dispatch':dispatch,
                              'prior_field_bindings':boundaries,
                              'field':{'va':hex(0x3ef3d5),'file_offset':hex(file_offset(sec,0x3ef3d5,20)),'bytes':field.hex(),'text':field.decode('ascii')},
                              'key_label':{'va':hex(0x20a020),'file_offset':hex(file_offset(sec,0x20a020,4)),'bytes':tag.hex(),'text':tag.decode('ascii')}}),
      'summary.json':json_bytes(summary),
    }
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    with TARGET.open('rb') as f:
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            outputs=produce(data)
    args.out.mkdir(parents=True,exist_ok=True)
    for name, contents in outputs.items():
        (args.out/name).write_bytes(contents)
    print('Generated %d evidence files.' % len(outputs))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('abci_display_name94:', str(exc), file=sys.stderr)
        raise SystemExit(1)
