#!/usr/bin/env python3
"""Extract one node 94 state-field collection's tagged-value evidence from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
NAMES = ('Perp', 'Spot', 'Token', 'Pdi', 'ActivateDexAbstraction',
         'ActivateUnifiedAccount', 'AllBoleTokens')
FUNCTIONS = (
    ('collection_wrapper', 0x25e3840), ('pair_collector', 0x2563060),
    ('collection_writer', 0x1e193a0),
    ('pair_writer', 0x1dd48e0), ('generic_kind_writer', 0x28e50e0),
    ('direct_kind_writer', 0x28e53a0), ('name_classifier', 0x28d13c0),
    ('quoted_name_reader', 0x1ba8190), ('kind_reader', 0x28e59d0),
    ('kind_collection_reader', 0x1bdd930), ('address_collection_reader', 0x25fa800),
    ('unit_null_reader', 0x1bea020), ('unsigned_integer_writer', 0x25abd40), ('generic_key_writer', 0x1e0d0a0),
    ('direct_key_writer', 0x1e0d6c0), ('numeric_value_reader', 0x1b2fae0),
)
TABLES = (
    ('map_reader_lead_5b_through_7b', 0x3e8a84,
     (0x25fa8a0, *([0x25fa96d] * 10), 0x25faf7e, *([0x25fa96d] * 7),
      0x25fb016, *([0x25fa96d] * 5), 0x25faf03, *([0x25fa96d] * 6), 0x25fa9a6)),
    ('name_length_3_through_22', 0x3f53e4,
     (0x28d13e1, 0x28d147d, 0x28d1403, *([0x28d14d1] * 7),
      0x28d1496, *([0x28d14d1] * 8), 0x28d1422)),
    ('generic_writer_tag', 0x3f5998,
     (0x28e5104, 0x28e5254, 0x28e516a, 0x28e51dc, 0x28e5154, 0x28e52e4, 0x28e530e)),
    ('direct_writer_tag', 0x3f59b4,
     (0x28e53bf, 0x28e550d, 0x28e545f, 0x28e54b8, 0x28e540f, 0x28e55ab, 0x28e5601)),
    ('quoted_reader_tag_or_error', 0x3f59d0,
     (0x28e5c34, 0x28e5c34, 0x28e5c34, 0x28e5c34, 0x28e5a7a, 0x28e5b6f, 0x28e5b78, 0x28e5b81)),
    ('object_reader_tag', 0x3f59f0,
     (0x28e5b53, 0x28e5bdc, 0x28e5bac, 0x28e5bc4, 0x28e5b8f, 0x28e5c00, 0x28e5c1a)),
)
# Each pin is an exact x86-64 byte window; these windows, together with the
# relative dispatch tables, are the finite scope of the instruction analysis.
PINS = (
 ('prior_job_capture_deref',0x281a5c2,'488b36'),
 ('prior_job_serializer_config',0x281a5b5,'c744240800040001c644240c00'),
 ('wrapper_collect_call',0x25e38aa,'e8b1f7f7ff'),
 ('wrapper_array_call',0x25e38b8,'e8e35a83ff'),
 ('collector_count_stride',0x2563068,'4c8b66404d89e749c1e7044c89e048'),
 ('collector_allocation_overflow_guard',0x2563076,'48c1e83c0f95c048b9f8ffffffffffff7f4939cf0f97c108c1740b31ff'),
 ('collector_allocation_error_call',0x2563091,'31ff4c89feff151caf2003'),
 ('collector_zero_allocation_branch',0x256309c,'4d85ff742e4889fb'),
 ('collector_key_value_offsets',0x256310a,'4c8d14924f8d14914981c210010000488d1452498d14d14883c208'),
 ('collector_pair_stride_store',0x2563125,'4989c149c1e1044e89140b4a89540b08'),
 ('collector_tree_node_count',0x256315c,'440fb78eee0100004c39ca0f83c3000000'),
 ('collector_tree_left_child',0x25631a0,'488bb6f001000049ffc24d39d175f1'),
 ('collector_tree_parent',0x2563230,'4c8b0e4d85c90f84d900000049ffc00fb796ec0100004c89ce'),
 ('collector_vector_result',0x25632fb,'4c893748895f084c896710'),
 ('outer_header_call',0x1e19407,'e8c4077900'),
 ('outer_header_result_check',0x1e19411,'4883f8020f85b3000000'),
 ('outer_pair_call_1',0x1e1945f,'e87cb4fbff'),
 ('outer_stride_16',0x1e19551,'89ed49c1e6044d01f54c39ed744b4c8d74'),
 ('outer_header_error_result',0x1e194ce,'488b4c2448488b5c240848ba00000000000000804889134889430848894b10'),
 ('outer_pair_error_check',0x1e19593,'488b4424404839d80f85dffeffff'),
 ('outer_pair_call_2',0x1e1958e,'e84db3fbff'),
 ('pair_header_count_two',0x1dd4935,'ba02000000'),
 ('pair_header_call',0x1dd493a,'e891527d00'),
 ('pair_header_error_check',0x1dd4944,'4883f8020f85c4030000'),
 ('pair_key_error_check',0x1dd49b3,'48394c24200f851d030000'),
 ('pair_value_header_error_check',0x1dd4aac,'4883f8020f85e60a0000'),
 ('pair_key_call_1',0x1dd499b,'e800870300'),
 ('generic_key_hex_arguments',0x1e0d18b,'be2a000000b9140000004531c0ff15825f9603'),
 ('direct_key_hex_arguments',0x1e0d7ab,'be2a000000b9140000004531c0ff1562599603'),
 ('pair_value_fields',0x1dd4a6e,'4d8b3424498b5c24084d85f6410f95c5498b6c2410'),
 ('pair_value_header_call',0x1dd4aa2,'e829517d00'),
 ('pair_two_element_fast_header',0x1dd4ad8,'c6040192'),
 ('pair_key_call_2',0x1dd4b32,'e8898b0300'),
 ('value_tree_left_child',0x1dd4e50,'4d8badc000000048ffc14839c875f1'),
 ('value_tree_parent',0x1dd4ee0,'498bb5b00000004885f60f84d00700'),
 ('value_tree_element_stride',0x1dd4fa7,'48c1e0044801c6'),
 ('pair_direct_kind_call_1',0x1dd4fcf,'e8cc03b100'),
 ('pair_direct_kind_call_2',0x1dd4ff8,'e8a303b100'),
 ('pair_generic_kind_call',0x1dd537f,'e85cfdb000'),
 ('pair_direct_kind_call_3',0x1dd53a8,'e8f3ffb000'),
 ('generic_tag_dispatch',0x28e50f1,'488b06488d0d9d08b1fd486304814801c8ff'),
 ('direct_tag_dispatch',0x28e53ac,'488b06488d0dfe05b1fd486304814801c8ff'),
 ('perp_map_prefix',0x28e53d0,'c6040181'),
 ('perp_name_prefix',0x28e53eb,'c60407a4'),
 ('perp_name',0x28e5403,'c7040750657270'),
 ('token_map_prefix',0x28e5470,'c6040181'),
 ('token_name_prefix',0x28e548b,'c60407a5'),
 ('token_name',0x28e54a3,'c64407046ec70407546f6b65'),
 ('pdi_map_prefix',0x28e54c9,'c6040181'),
 ('pdi_name_prefix',0x28e54e4,'c60407a3'),
 ('pdi_name',0x28e54fc,'c64407026966c704075064'),
 ('spot_map_prefix',0x28e551e,'c6040181'),
 ('spot_name_prefix',0x28e5539,'c60407a4'),
 ('spot_name',0x28e5551,'c7040753706f74'),
 ('payload_u64_call',0x28e5560,'488b46084889e74889d64889c2e8ce67ccff'),
 ('payload_error_check',0x28e5572,'488b04244883f802750f48b80400000000000080e9d1000000'),
 ('direct_key_string_error_check',0x1e0d7c9,'4883f80275094983c404'),
 ('dex_unit_prefix',0x28e5423,'c60431b6'),
 ('dex_unit_prefix_data_ref',0x28e5445,'0f10056913b1fd'),
 ('dex_unit_suffix',0x28e5450,'48bf7472616374696f6e'),
 ('unified_unit_prefix',0x28e55bf,'c60431b6'),
 ('unified_unit_prefix_data_ref',0x28e55e1,'0f1005e311b1fd'),
 ('unified_unit_suffix',0x28e55ec,'48bf644163636f756e74'),
 ('bole_unit_prefix',0x28e5615,'c60431ad'),
 ('bole_unit_suffix',0x28e5637,'48bf6c65546f6b656e73'),
 ('bole_unit_lead',0x28e5646,'48bf416c6c426f6c6554'),
 ('uint_small_cutoffs',0x25abd48,'4881fa00010000732e84d20f88d7000000'),
 ('uint_fixpos_store',0x25abd66,'488b4e084288140949ffc1'),
 ('uint_u16_cutoff',0x25abd7f,'4881fa00000100734f'),
 ('uint_u16_marker',0x25abd9c,'42c6040fcd'),
 ('uint_u16_swap',0x25abda8,'66c1c208'),
 ('uint_u32_cutoff',0x25abdd7,'4889d148c1e9200f8592000000'),
 ('uint_u32_marker',0x25abdf8,'42c6040fce'),
 ('uint_u32_swap',0x25abe04,'0fca'),
 ('uint_u8_marker',0x25abe44,'42c60409cc'),
 ('uint_u64_marker',0x25abe8a,'42c6040fcf'),
 ('uint_u64_swap',0x25abe96,'480fca'),
 ('value_array_open',0x1bdd9ad,'83fe5b0f8514030000'),
 ('value_array_comma_branch',0x1bdda60,'4983f82c755a40f6c5017572'),
 ('value_array_trailing_comma_check',0x1bddad5,'83fa5d0f843d020000'),
 ('value_array_close',0x1bddac0,'4183f85d0f8462010000'),
 ('reader_quote_check',0x28e5a40,'4883fe227540'),
 ('reader_quote_name_call',0x28e5a4e,'e83d272cff'),
 ('reader_quote_error_sentinel',0x28e5a5d,'84c0ba070000000f44d10fb6ca'),
 ('reader_object_check',0x28e5a86,'83fe7b0f8550020000'),
 ('reader_object_name_call',0x28e5abd,'e8ce262cff'),
 ('reader_name_error_check',0x28e5ac2,'807c24080175'),
 ('reader_colon_check',0x28e5b2a,'4883ff3a0f85c7010000'),
 ('reader_object_dispatch',0x28e5b41,'89c8488d0da6feb0fd486304814801c8ffe0'),
 ('reader_numeric_case_0',0x28e5b53,'4c89f7e8859f24ffa8010f8585'),
 ('reader_unit_case_4',0x28e5b8f,'4c89f7e8894430ff4885c00f85'),
 ('reader_quoted_payload_rejection',0x28e5c34,'c64424080d488d358051da02488d15'),
 ('reader_numeric_error_check',0x28e5b5b,'a8010f8585000000'),
 ('reader_null_error_check',0x28e5b97,'4885c00f852effffff'),
 ('reader_close_brace_check',0x28e5ccc,'83fe7d75384885c074'),
 ('quoted_to_classifier_call',0x1ba825a,'e86191d200'),
 ('classifier_length_guard',0x28d13c0,'4889f8488d4afd4883f9130f87000100'),
 ('classifier_pdi',0x28d13e1,'0fb70e81f1506400000fb67e0283f7696609cf'),
 ('classifier_token',0x28d1403,'b9546f6b65330e0fb67e0483f76e09cf0f85'),
 ('classifier_dex_vectors',0x28d1422,'f30f6f06f30f6f4e06660f740d2d2593fd660f7405556093fd660fdbc1660fd7c881f9ffff00007474'),
 ('classifier_unified_vectors',0x28d144b,'f30f6f06f30f6f4e06660f740db42193fd660f7405ec4d93fd660fdbc1660fd7c881f9ffff0000755d'),
 ('classifier_four',0x28d147d,'813e506572707443813e53706f747544c640010131c98808c348'),
 ('classifier_bole',0x28d1496,'48b9416c6c426f6c655448330e48bf6c65546f6b656e7348337e054809cf751bc640010631c98808c3'),
 ('classifier_tag_0',0x28d14c8,'c6400100'),
 ('classifier_tag_1',0x28d148d,'c6400101'),
 ('classifier_tag_2',0x28d1419,'c6400102'),
 ('classifier_tag_3',0x28d13fa,'c6400103'),
 ('classifier_tag_4',0x28d14bf,'c6400104'),
 ('classifier_tag_5',0x28d1474,'c6400105'),
 ('classifier_tag_6',0x28d14b6,'c6400106'),
 ('classifier_unknown',0x28d14d1,'534c8d05675ddf02b9070000004889f74889d64c89c2'),
 ('map_reader_lead_range',0x25fa881,'448d47a54183f8200f87b2000000'),
 ('map_reader_lead_dispatch',0x25fa88f,'488d35eee1defd4e6304864901f041ffe0'),
 ('map_reader_quote_lead',0x25fa941,'83ff220f845f030000'),
 ('map_reader_object_depth_guard',0x25fa9a6,'410fb64e4884c90f84bd080000fec941884e480f84'),
 ('map_reader_colon_check',0x25faa98,'4883ff3a0f8574070000'),
 ('map_reader_kind_collection_call',0x25faab4,'e8772e5eff'),
 ('map_reader_value_error_check',0x25faab9,'837c2478010f84fa020000'),
 ('map_reader_key_compare_size',0x25fabb8,'ba14000000'),
 ('number_minus_check',0x1b2fb59,'4883ff2d75374885c00f84f000'),
 ('number_digit_check',0x1b2fb96,'4080c7d04080ff0a736e'),
 ('number_parse_positive',0x1b2fba8,'ba01000000e8ceefffff'),
 ('number_category_checks',0x1b2fbb2,'488b4424204883f80374c9488b54242883f801740a83f80275134885d27864'),
 ('number_negative_result_rejected',0x1b2fbcc,'4885d2786431c0'),
 ('null_reader_n',0x1bea08d,'4183f96e0f8581000000'),
 ('null_reader_u',0x1bea0b7,'4080fe757550'),
 ('null_reader_l1',0x1bea0cf,'4180f86c7538'),
 ('null_reader_l2',0x1bea0e7,'80f96c752131c0'),
 ('reader_unit_case_5',0x28e5c00,'4c89f7e8184430ff4885c0'),
 ('reader_unit_case_6',0x28e5c1a,'4c89f7e8fe4330ff4885c0'),
 ('collection_reader_kind_call',0x1bddae4,'e8e77ed000'),
 ('collection_reader_failure_check',0x1bddae9,'488b7424104883fe070f84c801'),
 ('collection_reader_insert_call',0x1bddb02,'e8c973c700'),
)


CALLS = (
 ('prior_job_to_collection_wrapper', 0x281a5d0, 0x25e3840),
 ('collect', 0x25e38aa, 0x2563060), ('write_collected', 0x25e38b8, 0x1e193a0),
 ('outer_header', 0x1e19407, 0x25a9bd0), ('write_pair_first', 0x1e1945f, 0x1dd48e0),
 ('write_pair_loop', 0x1e1958e, 0x1dd48e0), ('pair_header', 0x1dd493a, 0x25a9bd0),
 ('write_key_generic', 0x1dd499b, 0x1e0d0a0), ('write_key_direct', 0x1dd4b32, 0x1e0d6c0),
 ('value_header', 0x1dd4aa2, 0x25a9bd0), ('write_kind_direct_1', 0x1dd4fcf, 0x28e53a0),
 ('write_kind_direct_2', 0x1dd4ff8, 0x28e53a0), ('write_kind_generic', 0x1dd537f, 0x28e50e0),
 ('write_kind_direct_3', 0x1dd53a8, 0x28e53a0), ('write_integer_payload', 0x28e556d, 0x25abd40),
 ('map_read_values', 0x25faab4, 0x1bdd930), ('read_kind', 0x1bddae4, 0x28e59d0),
 ('insert_kind', 0x1bddb02, 0x2854ed0), ('read_quoted_variant', 0x28e5a4e, 0x1ba8190),
 ('read_object_variant', 0x28e5abd, 0x1ba8190), ('classify_name', 0x1ba825a, 0x28d13c0),
 ('read_numeric_0', 0x28e5b56, 0x1b2fae0), ('read_numeric_1', 0x28e5bdf, 0x1b2fae0),
 ('read_numeric_2', 0x28e5baf, 0x1b2fae0), ('read_numeric_3', 0x28e5bc7, 0x1b2fae0),
 ('read_null_4', 0x28e5b92, 0x1bea020), ('read_null_5', 0x28e5c03, 0x1bea020),
 ('read_null_6', 0x28e5c1d, 0x1bea020),
 ('write_generic_key_string', 0x1e0d1a4, 0x25aa7f0),
 ('write_direct_key_string', 0x1e0d7c4, 0x25aacb0),
)


def extract_calls(image):
    rows = []
    for name, site, expected in CALLS:
        raw = image.read(site, 5)
        if raw[0] != 0xe8:
            raise ValueError('not a direct call: ' + name)
        target = site + 5 + struct.unpack('<i', raw[1:])[0]
        if target != expected:
            raise ValueError('direct call target mismatch: ' + name)
        image.offset(target, 1)
        rows.append((name, hex(site), hex(image.offset(site, 5)), raw.hex(), hex(target)))
    return rows


def checked_digest(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, length):
        if length < 0 or va < 0:
            raise ValueError('negative address or length')
        matches = [s['offset'] + va - s['address'] for s in self.sections
                   if s['type'] != 8 and s['size'] and s['address'] <= va
                   and va + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('VA has no unique file-backed section')
        return matches[0]

    def read(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]


def verify_pins(image):
    rows = []
    for name, va, expected in PINS:
        got = image.read(va, len(expected) // 2).hex()
        if got != expected:
            raise ValueError('instruction window mismatch: ' + name)
        rows.append((name, hex(va), hex(image.offset(va, len(got) // 2)), got))
    return rows


def extract_tables(image):
    result = {}
    for name, base, expected in TABLES:
        raw = image.read(base, len(expected) * 4)
        targets = tuple(base + delta[0] for delta in struct.iter_unpack('<i', raw))
        if targets != expected:
            raise ValueError('dispatch table mismatch: ' + name)
        for target in targets:
            image.offset(target, 1)
        result[name] = (base, targets)
    return result


def extract_hex_slot(image):
    slot = 0x5773120
    for call in (0x1e0d198, 0x1e0d7b8):
        raw = image.read(call, 6)
        if raw[:2] != b'\xff\x15' or call + 6 + struct.unpack('<i', raw[2:])[0] != slot:
            raise ValueError('key formatter slot reference mismatch')
    matches = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('invalid dynamic relocation section')
    sec = matches[0]
    raw = image.data[sec['offset']:sec['offset'] + sec['size']]
    records = [(info, addend) for address, info, addend in struct.iter_unpack('<QQq', raw)
               if address == slot]
    if records != [(8, 0x29ed380)]:
        raise ValueError('unexpected key formatter relocation')
    image.offset(records[0][1], 1)
    return (hex(slot), records[0][0], hex(records[0][1]))


def extract_names(image):
    matches = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(matches) != 1 or matches[0]['size'] % 24:
        raise ValueError('invalid dynamic relocation section')
    sec = matches[0]
    raw = image.data[sec['offset']:sec['offset'] + sec['size']]
    wanted = {0x56c7240 + 16 * i for i in range(len(NAMES))}
    relocations = {}
    for address, info, addend in struct.iter_unpack('<QQq', raw):
        if address in wanted:
            if address in relocations or info != 8:
                raise ValueError('unexpected or duplicate name relocation')
            relocations[address] = addend
    rows = []
    for i, name in enumerate(NAMES):
        slot = 0x56c7240 + 16 * i
        if slot not in relocations:
            raise ValueError('missing name relocation')
        pointer = relocations[slot]
        length = struct.unpack('<Q', image.read(slot + 8, 8))[0]
        if length > 64:
            raise ValueError('name length out of range')
        actual = image.read(pointer, length)
        if actual != name.encode('ascii'):
            raise ValueError('name descriptor mismatch')
        rows.append((i, actual.decode('ascii'), slot, pointer, length))
    # Cross-check the classifier's overlapping 16-byte comparisons with the
    # independently relocated string descriptors, including their overlap.
    for i, first, second in ((4, 0x207490, 0x203960), (5, 0x206250, 0x203610)):
        name = rows[i][1].encode('ascii')
        if image.read(first, 16) != name[:16] or image.read(second, 16) != name[6:22]:
            raise ValueError('classifier vector constants mismatch')
    for i, first, suffix in ((4, 0x3f67b5, 0x28e5452), (5, 0x3f67cb, 0x28e55ee)):
        name = rows[i][1].encode('ascii')
        if image.read(first, 16) != name[:16] or image.read(suffix, 8) != name[14:22]:
            raise ValueError('direct writer constants mismatch')
    return rows


def classify(name, names):
    """Bounded byte-string model of the seven verified classifier comparisons."""
    if not isinstance(name, bytes):
        raise TypeError('classifier input must be bytes')
    for tag, text, _, _, length in names:
        if len(name) == length and name == text.encode('ascii'):
            return tag
    return None


def model_collector_bytes(count):
    """Predict the collector's two allocation size guards; perform no allocation."""
    if type(count) is not int or not 0 <= count < 1 << 64:
        raise ValueError('model expects a 64-bit unsigned count')
    size = (count << 4) & ((1 << 64) - 1)
    if count >> 60 or size > 0x7ffffffffffffff8:
        raise ValueError('collector allocation size rejected')
    return size


def model_key(key):
    """Predict the reused prefixed-hex formatter for the caller's fixed mode."""
    if not isinstance(key, bytes) or len(key) != 20:
        raise ValueError('model expects exactly 20 key bytes')
    return b'0x' + key.hex().encode('ascii')


def model_kind(tag, payload, names):
    """Predict only the direct writer's verified successful path, not errors/allocations."""
    if type(tag) is not int or not 0 <= tag < len(names):
        raise ValueError('invalid kind tag for model')
    text = names[tag][1].encode('ascii')
    prefix = bytes([0xa0 + len(text)]) + text
    if tag >= 4:
        if payload is not None:
            raise ValueError('unit kind has no payload')
        return prefix
    if type(payload) is not int or not 0 <= payload < 1 << 64:
        raise ValueError('model expects a 64-bit unsigned payload')
    if payload < 0x80:
        encoded = bytes([payload])
    elif payload < 0x100:
        encoded = b'\xcc' + payload.to_bytes(1, 'big')
    elif payload < 0x10000:
        encoded = b'\xcd' + payload.to_bytes(2, 'big')
    elif payload < 0x100000000:
        encoded = b'\xce' + payload.to_bytes(4, 'big')
    else:
        encoded = b'\xcf' + payload.to_bytes(8, 'big')
    return b'\x81' + prefix + encoded


def analyze(data):
    digest = checked_digest(data)
    image = Image(data)
    pins = verify_pins(image)
    tables = extract_tables(image)
    names = extract_names(image)
    calls = extract_calls(image)
    hex_slot = extract_hex_slot(image)
    _, fdes = eh_frame_records(data, image.sections)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    funcs = []
    for name, start in FUNCTIONS:
        found = by_start.get(start, [])
        if len(found) != 1 or found[0]['end'] <= start:
            raise ValueError('missing or ambiguous FDE: ' + name)
        fde = found[0]
        size = fde['end'] - start
        exec_sections = [section for section in image.sections
                         if section['type'] != 8 and section['flags'] & 4
                         and section['address'] <= start
                         and fde['end'] <= section['address'] + section['size']]
        if len(exec_sections) != 1:
            raise ValueError('FDE range is outside a unique executable section: ' + name)
        body = image.read(start, size)
        funcs.append({'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                      'fde_va': hex(fde['fde']), 'file_offset': hex(image.offset(start, size)),
                      'length': size, 'sha256': hashlib.sha256(body).hexdigest()})
    table_owners = {'map_reader_lead_5b_through_7b': 'address_collection_reader',
                    'name_length_3_through_22': 'name_classifier',
                    'generic_writer_tag': 'generic_kind_writer',
                    'direct_writer_tag': 'direct_kind_writer',
                    'quoted_reader_tag_or_error': 'kind_reader',
                    'object_reader_tag': 'kind_reader'}
    for table, role in table_owners.items():
        function = next(item for item in funcs if item['role'] == role)
        start = int(function['start_va'], 16)
        end = int(function['end_va_exclusive'], 16)
        if any(not start <= target < end for target in tables[table][1]):
            raise ValueError('dispatch target outside its FDE: ' + table)
    return {'digest': digest, 'pins': pins, 'tables': tables, 'names': names, 'calls': calls, 'hex_slot': hex_slot, 'functions': funcs}


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(out):
    result = analyze(ARTIFACT.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'anchors.tsv', ('role', 'va', 'file_offset', 'bytes_hex'), result['pins'])
    write_tsv(out / 'calls.tsv', ('role', 'site_va', 'file_offset', 'bytes_hex', 'target_va'), result['calls'])
    write_tsv(out / 'indirect.tsv', ('slot_va', 'rela_info', 'addend_va'), [result['hex_slot']])
    table_rows = []
    for name, (base, targets) in result['tables'].items():
        for index, target in enumerate(targets):
            table_rows.append((name, hex(base), index, hex(base + index * 4), hex(target)))
    write_tsv(out / 'dispatch.tsv', ('table', 'base_va', 'index', 'entry_va', 'target_va'), table_rows)
    variants = []
    tables = result['tables']
    for tag, name, slot, ptr, length in result['names']:
        variants.append((tag, name, hex(slot), hex(ptr), length,
                         hex(tables['generic_writer_tag'][1][tag]),
                         hex(tables['direct_writer_tag'][1][tag]),
                         hex(tables['quoted_reader_tag_or_error'][1][tag]),
                         hex(tables['object_reader_tag'][1][tag]),
                         'map-and-u64' if tag < 4 else 'string-unit'))
    write_tsv(out / 'variants.tsv', ('tag', 'name', 'descriptor_va', 'name_va', 'name_bytes',
              'generic_writer_va', 'direct_writer_va', 'quoted_reader_va', 'object_reader_va',
              'direct_writer_shape'), variants)
    report = {'target_sha256': result['digest'], 'coordinate_system': 'linked ELF virtual addresses; file offsets are zero-based',
              'functions': result['functions'], 'window_count': len(result['pins']), 'direct_call_count': len(result['calls']),
              'dispatch_table_count': len(result['tables']),
              'dispatch_entry_count': sum(len(x[1]) for x in result['tables'].values()),
              'variant_count': len(result['names']),
              'limitations': 'FDE ranges are unwind-described ranges, not independently proven complete bodies. No target execution or full serialization equivalence.'}
    (out / 'summary.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    generate(args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('re009_state_kinds94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
