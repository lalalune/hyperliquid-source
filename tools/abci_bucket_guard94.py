#!/usr/bin/env python3
"""Extract digest-pinned node 94 guard-loader evidence without executing it."""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
ARTIFACT = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x325dd60: ('json_guard_wrapper', '570175d591f610ed7b191a66974570558e57acf55f2816cf3c98c984268fca01'),
    0x3143ec0: ('json_guard_visitor', '08e0260836da5f0f703616103a4e7a569078b1a20b2fe3bc854c49b7a7fb7bcd'),
    0x30339a0: ('json_sequence_width_step', '0136d52ef091ab1e28d10fd5b9415c322f002c2272ae186ee86809b9726283f1'),
    0x2a9c3a0: ('msgpack_guard_visitor', '160a57cc9908c16822e762807dcfa097f543fb8a7f46995e64a77c06d0ceb355'),
    0x2aae4c0: ('msgpack_guard_key_classifier', 'f8d44bcf5efa7eed8e31bbdb82e995eca77d2b89c350121062820c78c172b64b'),
    0x2a65dc0: ('msgpack_width_marker_adapter', 'eec86d9289e4aaf866c8d79272dcdaac2538b162edeeca14d940d829d1082f88'),
}
PINS = [
    ('json_wrapper', 0x325dd60, '534883ec104889fb488d15026132fd4c8d05621548024889e7b90b00000041b902000000e83761eeff488b04244885c0488b4c240848894b084889034889d84883c4105bc3'),
    ('json_head', 0x3143ed4, '488b4e20488b46284839c873404d8d6e18498b561848ffc04889ce48f7de48bd00260000010000000fb67c02ff4883ff207735480fa3fd732f49894628488d3c0648ffc748ffc04883ff0175db48c744240805000000488d7424084c89f7e899f3e9ffe90f06000083ff5b0f848503000083ff7b0f85db050000410fb6564884d20f84a9060000feca418856480f848f050000'),
    ('json_last_duplicate', 0x314408b, '4883f90d0f849b0000004883f90b0f85af000000488b0848330d206e44fd488b4003483305186e44fd4809c80f859100000048837c2440010f84f7040000'),
    ('json_width_key', 0x3144130, '488b0848330d9a6d44fd488b4005483305946d44fd4809c80f8492000000'),
    ('json_width_duplicate', 0x31441e0, '48837c2438000f85bd030000'),
    ('json_map_children', 0x314424c, '4883fe3a755c4885c00f849c030000498946284c89f7e8e903eaff4989d7a8010f85c8000000b8010000004889442440e947ffffff4883fe3a75354885c00f8467030000498946284c89f7e8e4fff4ffa8010f853d0200004889542438e91affffff'),
    ('json_map_finish_seq', 0x31442ca, '410fb64e4884c90f843a030000fec941884e480f84130200004885c00f840b030000498946284c89742420c644242801488d7c2408488d742420e8973df0ff488b4424084883f80275544c8b7c24104531e4eb79f6442440010f8435010000488b4424384989c44885c00f843b010000410fb646483cff0f84c6000000fec0418846484c89f7e8db0beaff4d85e40f84d70000004885c0745de9d5010000a8010f84070200004c8b7c2410488d7c2420e821f6eeffa80174084531e44989d7eb0c4885d20f84f50100004989d4'),
    ('json_result', 0x31443c0, '4c89234c897b084889d84883c4485b415c415d415e415f5dc3'),
    ('json_missing', 0x314445e, '488d05c29743fd488944242048c74424280b000000eb15488d05b69743fd488944242048c74424280d000000488d4424204889442408488d0595876a004889442410488d3d4cb409fd488d742408e87f962900'),
    ('json_duplicates', 0x31445a9, '488d05829643fd488944242048c74424280d000000eb15488d05609643fd488944242048c74424280b000000488d4424204889442408488d054a866a004889442410488d3de3c909fde9b0feffff'),
    ('mp_head', 0x2a9c3a0, '554157415641554154534881ec180100004889fb4883f90a751d48b85f457874537472754833020fb74a084881f1637400004809c1745f0fb656200fb67e210fb6cac6462001488d050b5099fd4c6304884901c041ffe0'),
    ('mp_result', 0x2a9c409, '0fb6442460488b4c2468488b7424703c09751048894b0848897310'),
    ('mp_marker', 0x2a9c6c4, '488b46184885c00f8410020000488b4e1048ffc80fb63948ffc148894e10488946184084ff0f886502000031d2e901fdffff'),
    ('mp_array_type', 0x2a9c954, 'b2e04080ffdf0f8797faffff4080ff900f83af0200004080e70f440fb6e70fb746226685c00f846c10000066ffc8668946220f84c00400004585e40f840b010000'),
    ('mp_array_children', 0x2a9cc19, '4080ffa00f83bd0100004080e70f440fb6ff0fb746226685c00f84be04000066ffc8668946220f84070200004585ff0f8415010000458d67ff4889e74989f6e84390fcff0fb604243c09752d4585e40f844d0100004c8b6c24084889e74c89f6e84291fcff0fb60c2480f9097561458d67fe488b442408eb3c'),
    ('mp_array_output', 0x2a9cd2f, '48894424484c896c2450c644244009410fb746226683f8ff0f84b8010000ffc066418946220f104424400f104c2450e95a010000'),
    ('mp_key_call1', 0x2a9d4fd, '488d7c24404989f64889c6e8b30f0100e9dc000000'),
    ('mp_key_call2', 0x2a9d56f, '4889e74c89fe4c89f2e8430f0100803c2409752c'),
    ('mp_map_width', 0x2a9d5ee, '0fb64424403c090f850ffdffff0fb644244183f802744483f8010f85a40000004883bc24c0000000000f855b0300004889e74d89f74c89f6e89587fcff0fb604243c090f85fc010000488b44240848898424c0000000'),
    ('mp_map_last_finish', 0x2a9d6b2, '4883bc24b8000000010f84d10200004889e74d89f74c89f6e8d185fcff0fb604243c090f8558010000488b44240848898424d8000000b80100000048898424b80000004c89fe41ffc54539ec0f8569f8fffff68424b8000000014c8ba424c0000000488b8424d80000000f8481f3ffff4d85e40f846b0100004c89a424e800000048898424f0000000c68424e00000000940b5010fb746226683f8ff0f8412020000ffc0668946220f108424e00000000f108c24f0000000e94ef7ffff'),
    ('mp_missing_width', 0x2a9d896, '4989c74989f6488d050098adfd488944244048c74424480d000000488d4424404889442420488d056ef3d4004889442428488d35252074fd4889e7488d542420e8a5d40400'),
    ('mp_duplicate', 0x2a9d978, '4d89f7488d052197adfd488944242048c74424280d000000eb184d89f7488d05fc96adfd488944242048c74424280b000000488d44242048890424488d0576f2d4004889442408488d350f3674fd488dbc24900000004889e2e8aad30400'),
    ('json_parent_call', 0x2fe71a3, '4883fe3a0f855eae00004885c00f8412b3000049894628488dbc24301400004c89f6e8966b2700488b8c243014000048898c24880000004885c90f84ac560000488b84243814000048898424f0050000e922160000'),
    ('json_parent_output', 0x2ff3e95, '488b842488000000498986d81d0000488b8424f0050000498986e01d0000'),
    ('mp_parent_call', 0x2aba6fa, '4883bc24b0020000000f8543390000488d156197acfd488dbc2470060000b90b0000004889dee87b1cfeff0fb68424700600003c090f858b3300000f108424780600000f29842410050000e9fc180000'),
    ('mp_parent_stage', 0x2abc059, '0f288424100500000f138424b0020000'),
    ('mp_parent_required', 0x2ab74ca, '4883bc24b0020000000f859a000000488d05e118acfd48898424c001000048c78424c801000017000000'),
    ('mp_parent_output', 0x2ab8a5a, '0f28842410050000410f1185d81d0000'),
    ('materializer_load', 0x3752044, '0f1083d81d00000f298424b0000000'),
    ('materializer_store', 0x3752875, '0f288424b0000000410f1186f8380000'),
    ('mp_array16_length', 0x2a9c6f6, '488b4e10488b46184883f802727a4883c0fe0fb71166c1c2084883c10248894e1048894618440fb7fae907050000'),
    ('mp_array32_length', 0x2a9c665, '488b4e10488b46184883f8040f82070100004883c0fc448b394883c104410fcf48894e1048894618e999050000'),
    ('mp_map16_length', 0x2a9c692, '488b4e10488b46184883f8020f82da0000004883c0fe0fb71166c1c2084883c10248894e1048894618440fb7e2e9ae020000'),
    ('mp_map32_length', 0x2a9c638, '488b4e10488b46184883f8040f82340100004883c0fc448b214883c104410fcc48894e1048894618e90d030000'),
    ('mp_container_truncated', 0x2a9c77e, '4801c148894e1048c7461800000000b001488d0dc2c3c302e9b3060000'),
    ('mp_wide_marker_dispatch', 0x2a9cde0, '4080ffc073094080e71fe939f9ffff400fb6d781c240ffffff4c8d05c44999fd4d630c904d01c189fa41ffe1'),
    ('materializer_args', 0x3751eaf, '4989cd4889d54889f34989fe'),
    ('json_sequence_missing_diagnostic', 0x3144577, '488d3582665902488d151b4e590231ffeb13488d3570665902488d15094e5902bf01000000e84f1b28004989c7e970fdffff'),
    ('mp_first_missing_diagnostic', 0x2a9cd63, '4989f6488d15abb1c302488d0d4498c3024531e4488d7c242031f6e86dd70400e932ffffff'),
    ('mp_second_missing_diagnostic', 0x2a9cdbb, '488d1556b1c302488d0def97c302488d7c2420be01000000e818d704004531e4e9dafeffff'),
    ('mp_sequence_excess', 0x2a9ccce, '4585e4745c4529e70f8238020000c64424400444897c2444eb56'),
    ('json_unknown', 0x31441ad, '0f8444040000498946284c89f7e8d1f1e9ff4885c00f85e9020000'),
    ('mp_unknown', 0x2a9d649, '4889e74d89f74c89f6ba01000000e894d53300803c24090f848f000000'),
    ('prior_json_seq_last_value', 0x3048192, '4183f85d743fe8b3c4f9ffa8017414'),
    ('body_30339a0', 0x30339a0, '4883ec184889f8488b3f4c8b4720488b4f284c39c17343488b571848ffc14d89c149f7d948be00260000010000006690440fb6540aff4983fa2c0f87900000004c0fa3d6733148894f284d8d140949ffc248ffc14983fa0175d648c70424020000004889e6e8c6f8faff4889c2b8010000004883c418c34983fa2c75538078080075624885c90f849700000048894f284c39c1733148ffc1b8010000004c29c0440fb6440aff4983f820774a4c0fa3c6734448894f284c8d040849ffc048ffc14983f80275da48c7042405000000eb924183fa5d750931d231c04883c418c3807808007424c6400800e8f207060083e0014883c418c34183f85d741ae8df07060083e0014883c418c348c7042407000000e94cffffff48c7042415000000e93fffffff488d3dd67c6a02ff1548a67302'),
    ('body_2aae4c0', 0x2aae4c0, '83fa0d746383fa0b0f85a9000000803e6c0f85a0000000807e01610f8596000000807e02730f858c000000807e03740f8582000000807e045f757c807e05627576807e06757570807e0763756a807e086b7564807e0965755e807e0a74755831c0884701c60709c3803e62754a807e01757544807e0263753e807e036b7538807e04657532807e0574752c807e065f7526807e076d7520807e0869751a807e096c7514807e0a6c750e807e0b697508b001807e0c737402b002884701c60709c3'),
    ('body_2a65dc0', 0x2a65dc0, '534889fb0fb64e200fb64621c646200180f9017567488b4e184885c9741d488b561048ffc90fb60248ffc24889561048894e1884c0781731c9eb41c60300488d05532dc702488943084889d85bc3b1e03cdf77283c907306240fb180eb1e3ca07306240fb190eb1489c280e21f3cc00fb6c0b9a00000000f43c889d00fb6d10fb6c84889dfff151daed0024889d85bc3'),
]

# Fixed sites were selected by manual instruction inspection. Targets are
# re-derived from signed PC-relative operands, never from disassembler text.
CALLS = [
    ('json_parent_to_guard', 0x2fe71c5, 0x325dd60),
    ('json_guard_to_visitor', 0x325dd84, 0x3143ec0),
    ('json_last_map_value', 0x3144262, 0x2fe4650),
    ('json_unknown_field', 0x31441ba, 0x2fe3390),
    ('json_width_map_value', 0x3144297, 0x3094280),
    ('json_last_sequence_step', 0x3144304, 0x30480a0),
    ('prior_json_seq_last_value', 0x3048198, 0x2fe4650),
    ('json_width_sequence_step', 0x314437a, 0x30339a0),
    ('json_sequence_width_value_1', 0x3033a89, 0x3094280),
    ('json_sequence_width_value_2', 0x3033a9c, 0x3094280),
    ('json_sequence_missing_diagnostic', 0x314459c, 0x33c60f0),
    ('mp_parent_to_guard', 0x2aba720, 0x2a9c3a0),
    ('mp_seq_last', 0x2a9cc58, 0x2a65ca0),
    ('mp_seq_width', 0x2a9cc79, 0x2a65dc0),
    ('mp_seq_first_missing_diagnostic', 0x2a9cd7e, 0x2aea4f0),
    ('mp_seq_second_missing_diagnostic', 0x2a9cdd3, 0x2aea4f0),
    ('mp_map_key_1', 0x2a9d508, 0x2aae4c0),
    ('mp_map_key_2', 0x2a9d578, 0x2aae4c0),
    ('mp_unknown_field', 0x2a9d657, 0x2ddabf0),
    ('mp_map_width', 0x2a9d626, 0x2a65dc0),
    ('mp_map_last', 0x2a9d6ca, 0x2a65ca0),
]
# Sites inside the two established visitors are new boundary observations,
# not claims of ownership of those parent functions or their older call sites.
BRANCHES = [
    ('json_sequence_open', 0x3143f3f, 0x31442ca),
    ('json_not_object', 0x3143f48, 0x3144529),
    ('json_zero_depth', 0x3143f55, 0x3144604),
    ('json_depth_decrement', 0x3143f61, 0x31444f6),
    ('json_duplicate_last', 0x31440c3, 0x31445c0),
    ('json_duplicate_width', 0x31441e6, 0x31445a9),
    ('json_last_child_error', 0x314426c, 0x314433a),
    ('json_unknown_child_error', 0x31441c2, 0x31444b1),
    ('json_width_child_error', 0x314429e, 0x31444e1),
    ('json_seq_last_result', 0x3144312, 0x3144368),
    ('json_missing_last', 0x3144323, 0x314445e),
    ('json_missing_or_zero_width', 0x3144334, 0x3144475),
    ('json_seq_missing_last', 0x314436a, 0x3144577),
    ('json_seq_missing_or_zero_width', 0x314438e, 0x3144589),
    ('json_parent_child_error', 0x2fe71dd, 0x2fec88f),
    ('mp_non_extension', 0x2a9c3b8, 0x2a9c3d7),
    ('mp_extension', 0x2a9c3d5, 0x2a9c436),
    ('mp_input_exhausted', 0x2a9c6cb, 0x2a9c8e1),
    ('mp_high_marker', 0x2a9c6e9, 0x2a9c954),
    ('mp_negative_fixint_or_other', 0x2a9c95a, 0x2a9c3f7),
    ('mp_array_marker', 0x2a9c964, 0x2a9cc19),
    ('mp_array_out_of_class', 0x2a9cc1d, 0x2a9cde0),
    ('mp_array_depth', 0x2a9cc32, 0x2a9d0f6),
    ('mp_array_depth_decrement', 0x2a9cc3f, 0x2a9ce4c),
    ('mp_array_zero_length', 0x2a9cc48, 0x2a9cd63),
    ('mp_array_last_child_error', 0x2a9cc63, 0x2a9cc92),
    ('mp_array_missing_width', 0x2a9cc68, 0x2a9cdbb),
    ('mp_array_width_child_error', 0x2a9cc85, 0x2a9cce8),
    ('mp_array_exactly_two', 0x2a9ccd1, 0x2a9cd2f),
    ('mp_array_count_underflow', 0x2a9ccd6, 0x2a9cf14),
    ('mp_map_zero_depth', 0x2a9c979, 0x2a9d9eb),
    ('mp_map_depth_decrement', 0x2a9c986, 0x2a9ce4c),
    ('mp_empty_map', 0x2a9c98f, 0x2a9caa0),
    ('mp_array16_truncated', 0x2a9c702, 0x2a9c77e),
    ('mp_array32_truncated', 0x2a9c671, 0x2a9c77e),
    ('mp_map16_truncated', 0x2a9c69e, 0x2a9c77e),
    ('mp_map32_truncated', 0x2a9c644, 0x2a9c77e),
    ('mp_wide_marker_table', 0x2a9cde4, 0x2a9cdef),
    ('mp_map_key_error', 0x2a9d5f5, 0x2a9d30a),
    ('mp_map_unknown', 0x2a9d603, 0x2a9d649),
    ('mp_map_last_key', 0x2a9d608, 0x2a9d6b2),
    ('mp_map_duplicate_width', 0x2a9d617, 0x2a9d978),
    ('mp_unknown_child_ok', 0x2a9d660, 0x2a9d6f5),
    ('mp_map_width_child_error', 0x2a9d631, 0x2a9d833),
    ('mp_map_duplicate_last', 0x2a9d6bb, 0x2a9d992),
    ('mp_map_last_child_error', 0x2a9d6d5, 0x2a9d833),
    ('mp_map_missing_last', 0x2a9d71c, 0x2a9caa3),
    ('mp_map_missing_or_zero_width', 0x2a9d725, 0x2a9d896),
    ('mp_parent_duplicate_guard', 0x2aba703, 0x2abe04c),
    ('mp_parent_child_error', 0x2aba72f, 0x2abdac0),
    ('mp_parent_guard_present', 0x2ab74d3, 0x2ab7573),
]

# Displacements for data-flow observations. The prefix also determines the
# instruction form; each displacement is read from the captured instruction.
OFFSETS = [
    ('json_parent_width_result', 0x2ff3e9d, '498986', 0x1dd8),
    ('json_parent_last_result', 0x2ff3eac, '498986', 0x1de0),
    ('mp_parent_guard_pair_result', 0x2ab8a62, '410f1185', 0x1dd8),
    ('materializer_guard_pair_input', 0x3752044, '0f1083', 0x1dd8),
    ('materializer_guard_pair_stage', 0x375204b, '0f298424', 0xb0),
    ('materializer_guard_pair_reload', 0x3752875, '0f288424', 0xb0),
    ('materializer_guard_pair_output', 0x375287d, '410f1186', 0x38f8),
]
LITERALS = [
    ('json_guard_type', 0x583e71, b'BucketGuard'),
    ('json_key_last', 0x58aec9, b'last_bucket'),
    ('json_key_width', 0x58aed4, b'bucket_millis'),
    ('json_error_last', 0x57dc27, b'last_bucket'),
    ('json_error_width', 0x57dc32, b'bucket_millis'),
    ('mp_error_last', 0x577098, b'last_bucket'),
    ('mp_error_width', 0x5770a3, b'bucket_millis'),
    ('mp_guard_field', 0x578dc1, b'begin_block_logic_guard'),
]

# These instruction immediates bind the selected literal pointer lengths to
# their callers and distinguish the two-field visitor from other structures.
IMMEDIATES = [
    ('json_type_length', 0x325dd79, 'b9', 11),
    ('json_type_field_count', 0x325dd7e, '41b9', 2),
    ('mp_type_length', 0x2aba718, 'b9', 11),
    ('mp_duplicate_guard_length', 0x2abe05b, '48c78424d8260000', 23),
    ('mp_missing_guard_length', 0x2ab74e8, '48c78424c8010000', 23),
]

# RIP-relative instructions name selected literal bytes. Data length is the
# checked field-name length or the overlapping qword read by the instruction.
REFERENCES = [
    ('json_type_name', 0x325dd68, '488d15', 0x583e71, b'BucketGuard'),
    ('mp_type_name', 0x2aba709, '488d15', 0x583e71, b'BucketGuard'),
    ('json_last_key_first_qword', 0x31440a2, '48330d', 0x58aec9, b'last_buc'),
    ('json_last_key_last_qword', 0x31440ad, '483305', 0x58aecc, b't_bucket'),
    ('json_width_key_first_qword', 0x3144133, '48330d', 0x58aed4, b'bucket_m'),
    ('json_width_key_last_qword', 0x314413e, '483305', 0x58aed9, b't_millis'),
    ('mp_duplicate_guard_name', 0x2abe04c, '488d05', 0x578dc1, b'begin_block_logic_guard'),
    ('mp_missing_guard_name', 0x2ab74d9, '488d05', 0x578dc1, b'begin_block_logic_guard'),
    ('json_duplicate_last_name', 0x31445c0, '488d05', 0x57dc27, b'last_bucket'),
    ('json_duplicate_width_name', 0x31445a9, '488d05', 0x57dc32, b'bucket_millis'),
    ('mp_duplicate_last_name', 0x2a9d995, '488d05', 0x577098, b'last_bucket'),
    ('mp_duplicate_width_name', 0x2a9d97b, '488d05', 0x5770a3, b'bucket_millis'),
    ('json_missing_last_name', 0x314445e, '488d05', 0x57dc27, b'last_bucket'),
    ('json_missing_width_name', 0x3144475, '488d05', 0x57dc32, b'bucket_millis'),
    ('mp_missing_last_name', 0x2a9caa6, '488d05', 0x577098, b'last_bucket'),
    ('mp_missing_width_name', 0x2a9d89c, '488d05', 0x5770a3, b'bucket_millis'),
]
WIDE_MARKER_TABLE = 0x4317c4
WIDE_MARKER_SHA256 = '1c4f2a158f658cd4ea9a12434f875160d14720d3685d0db94def935eac584303'


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('Input digest mismatch')


def file_offset(data, secs, va, size):
    if va < 0 or size <= 0 or va + size > 1 << 64:
        raise ValueError('Invalid VA range')
    hits = [s for s in secs if s['type'] != 8 and s['flags'] & 2
            and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('VA range is not uniquely file-backed')
    s = hits[0]
    offset = s['offset'] + va - s['address']
    if offset < 0 or offset + size > len(data):
        raise ValueError('VA range exceeds input')
    return offset, s['name']


def read_va(data, secs, va, size):
    off, _ = file_offset(data, secs, va, size)
    return bytes(data[off:off + size])


def check_pin(actual, expected):
    if bytes(actual) != bytes(expected):
        raise ValueError('Selected instruction window differs')


def rel_call(raw, va, expected=None):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('Expected direct relative call')
    target = va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if expected is not None and target != expected:
        raise ValueError('Call target differs')
    return target


def rel_branch(raw, va, expected=None):
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        size, cond, displacement = 2, raw[0] & 15, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, cond, displacement = 6, raw[1] & 15, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('Expected conditional relative branch')
    target = va + size + displacement
    if expected is not None and target != expected:
        raise ValueError('Branch target differs')
    return size, cond, target


def immediate32(raw, prefix, expected):
    if len(raw) != len(prefix) + 4 or not raw.startswith(prefix):
        raise ValueError('Immediate instruction differs')
    value = struct.unpack_from('<I', raw, len(prefix))[0]
    if value != expected:
        raise ValueError('Immediate value differs')
    return value


def rip_reference(raw, va, prefix, expected):
    if len(raw) != len(prefix) + 4 or not raw.startswith(prefix):
        raise ValueError('RIP-relative instruction differs')
    target = va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    if target != expected:
        raise ValueError('RIP-relative target differs')
    return target


def marker_bounds(lower_insn, upper_insn):
    if len(lower_insn) != 4 or lower_insn[:3] != b'\x40\x80\xff':
        raise ValueError('Marker lower comparison differs')
    if len(upper_insn) != 4 or upper_insn[:3] != b'\x40\x80\xff':
        raise ValueError('Marker upper comparison differs')
    lower, upper = lower_insn[3], upper_insn[3]
    if (lower, upper) != (0xc0, 0xdf):
        raise ValueError('Marker bounds differ')
    return lower, upper


def state_selector_entry(raw):
    if len(raw) != 4:
        raise ValueError('Selector entry length differs')
    target = 0x4313f8 + struct.unpack('<i', raw)[0]
    if target != 0x2a9c6c4:
        raise ValueError('Selector entry target differs')
    return target


def wide_marker_entries(raw, lower=0xc0, upper=0xdf):
    if lower > upper or len(raw) != (upper - lower + 1) * 4 or hashlib.sha256(raw).hexdigest() != WIDE_MARKER_SHA256:
        raise ValueError('Marker jump table differs')
    rows = []
    for i in range(upper - lower + 1):
        target = WIDE_MARKER_TABLE + struct.unpack_from('<i', raw, i * 4)[0]
        if not 0x2a9c3a0 <= target < 0x2a9da87:
            raise ValueError('Marker target outside selected FDE')
        rows.append((lower + i, WIDE_MARKER_TABLE + i * 4, raw[i * 4:i * 4 + 4], target))
    return rows


def decode_classifier(body):
    """Read just the two fixed compare chains and validate their exits."""
    if len(body) != 0xc0 or body[:14] != bytes.fromhex('83fa0d746383fa0b0f85a9000000'):
        raise ValueError('Classifier entry differs')
    base = 0x2aae4c0
    rows = []
    words = []
    for start, length, tag in ((14, 11, 0), (0x68, 13, 1)):
        pos = start
        result = bytearray()
        for index in range(length):
            if index == 12 and tag == 1:
                if body[pos:pos + 2] != b'\xb0\x01':
                    raise ValueError('Classifier tag setup differs')
                pos += 2
            if index == 0:
                if body[pos:pos + 2] != b'\x80\x3e':
                    raise ValueError('Classifier first compare differs')
                c, cmp_len = body[pos + 2], 3
            else:
                if body[pos:pos + 3] != bytes((0x80, 0x7e, index)):
                    raise ValueError('Classifier byte position differs')
                c, cmp_len = body[pos + 3], 4
            cmp_va = base + pos
            pos += cmp_len
            last_width = tag == 1 and index == length - 1
            size, cond, target = rel_branch(body[pos:pos + 6], base + pos,
                                           0x2aae579 if last_width else 0x2aae577)
            if cond != (4 if last_width else 5):
                raise ValueError('Classifier comparison condition differs')
            rows.append((tag, index, cmp_va, c, base + pos, target))
            result.append(c)
            pos += size
        words.append(bytes(result))
    if words != [b'last_bucket', b'bucket_millis']:
        raise ValueError('Classifier key bytes differ')
    return rows, words


def classify_key(words, candidate):
    """Small comparison model; this does not execute target instructions."""
    return next((tag for tag, word in enumerate(words) if candidate == word), 2)


def checked_fdes(data, secs, starts):
    _, index = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    by_start = {}
    for item in records:
        by_start.setdefault(item['start'], []).append(item)
    indexed = {item['start']: item for item in index}
    result = []
    for start in starts:
        matches = by_start.get(start, [])
        if len(matches) != 1 or start not in indexed or indexed[start]['fde'] != matches[0]['fde']:
            raise ValueError('Selected FDE is absent or ambiguous')
        fde = matches[0]
        off, section = file_offset(data, secs, start, fde['end'] - start)
        if section != '.text':
            raise ValueError('Selected FDE is not in text')
        raw = read_va(data, secs, start, fde['end'] - start)
        if hashlib.sha256(raw).hexdigest() != FUNCTIONS[start][1]:
            raise ValueError('Selected FDE body differs')
        result.append((FUNCTIONS[start][0], start, fde['end'], off, fde['fde'], fde['cie'],
                       fde['lsda'], hashlib.sha256(raw).hexdigest()))
    return result


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def hx(value):
    return '' if value is None else hex(value)


def generate(data, out):
    check_digest(data)  # Fail before opening any output on a wrong artifact.
    secs = sections(data)
    fdes = checked_fdes(data, secs, FUNCTIONS)
    windows = []
    for name, va, rawhex in PINS:
        expected = bytes.fromhex(rawhex)
        actual = read_va(data, secs, va, len(expected))
        check_pin(actual, expected)
        off, section = file_offset(data, secs, va, len(actual))
        status = 'prior-function-context' if name.startswith(('json_parent_', 'mp_parent_', 'materializer_', 'prior_')) else 'selected-function'
        windows.append((name, status, hx(va), hx(va + len(actual)), hx(off), section,
                        actual.hex(), hashlib.sha256(actual).hexdigest()))
    calls = []
    for name, va, expected in CALLS:
        raw = read_va(data, secs, va, 5)
        target = rel_call(raw, va, expected)
        off, _ = file_offset(data, secs, va, len(raw))
        status = 'prior-function-context' if name.startswith(('json_parent_', 'mp_parent_', 'prior_')) else 'selected-function'
        calls.append((name, status, hx(va), hx(off), raw.hex(), hx(target)))
    branches = []
    for name, va, expected in BRANCHES:
        size, cond, target = rel_branch(read_va(data, secs, va, 6), va, expected)
        raw = read_va(data, secs, va, size)
        off, _ = file_offset(data, secs, va, size)
        branches.append((name, hx(va), hx(off), raw.hex(), hx(cond), hx(target)))
    offsets = []
    for name, va, prefix_hex, expected in OFFSETS:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, secs, va, len(prefix) + 4)
        if not raw.startswith(prefix):
            raise ValueError('Offset instruction form differs')
        displacement = struct.unpack_from('<i', raw, len(prefix))[0]
        if displacement != expected:
            raise ValueError('Offset instruction displacement differs')
        off, _ = file_offset(data, secs, va, len(raw))
        offsets.append((name, hx(va), hx(off), raw.hex(), hx(displacement)))
    literals = []
    for name, va, expected in LITERALS:
        raw = read_va(data, secs, va, len(expected))
        check_pin(raw, expected)
        off, section = file_offset(data, secs, va, len(raw))
        literals.append((name, hx(va), hx(off), section, len(raw), raw.hex(), raw.decode('ascii')))
    immediates = []
    for name, va, prefix_hex, expected in IMMEDIATES:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, secs, va, len(prefix) + 4)
        value = immediate32(raw, prefix, expected)
        off, _ = file_offset(data, secs, va, len(raw))
        immediates.append((name, hx(va), hx(off), raw.hex(), value))
    references = []
    for name, va, prefix_hex, expected, target_bytes in REFERENCES:
        prefix = bytes.fromhex(prefix_hex)
        raw = read_va(data, secs, va, len(prefix) + 4)
        target = rip_reference(raw, va, prefix, expected)
        actual = read_va(data, secs, target, len(target_bytes))
        check_pin(actual, target_bytes)
        off, _ = file_offset(data, secs, va, len(raw))
        target_off, _ = file_offset(data, secs, target, len(actual))
        references.append((name, hx(va), hx(off), raw.hex(), hx(target), hx(target_off), actual.hex(), actual.decode('ascii')))
    rip_reference(read_va(data, secs, 0x2a9c3e6, 7), 0x2a9c3e6,
                  bytes.fromhex('488d05'), 0x4313f8)
    state_raw = read_va(data, secs, 0x4313fc, 4)
    state_target = state_selector_entry(state_raw)
    state_off, _ = file_offset(data, secs, 0x4313fc, 4)
    state_rows = [(1, hx(0x4313fc), hx(state_off), state_raw.hex(), hx(state_target))]
    rip_reference(read_va(data, secs, 0x2a9cdf9, 7), 0x2a9cdf9,
                  bytes.fromhex('4c8d05'), WIDE_MARKER_TABLE)
    lower, upper = marker_bounds(read_va(data, secs, 0x2a9cde0, 4),
                                 read_va(data, secs, 0x2a9c956, 4))
    wide = wide_marker_entries(read_va(data, secs, WIDE_MARKER_TABLE, (upper - lower + 1) * 4), lower, upper)
    marker_rows = [(hex(marker), hx(va), hx(file_offset(data, secs, va, 4)[0]), raw.hex(), hx(target))
                   for marker, va, raw, target in wide]
    classifier = read_va(data, secs, 0x2aae4c0, 0xc0)
    comparison_rows, words = decode_classifier(classifier)
    key_rows = [(tag, index, hx(va), hx(file_offset(data, secs, va, 1)[0]),
                 hex(byte), chr(byte), hx(branch), hx(target))
                for tag, index, va, byte, branch, target in comparison_rows]
    out.mkdir(parents=True, exist_ok=True)
    extents = [(name, hx(start), hx(end),
                read_va(data, secs, start, end - start).hex())
               for name, start, end, _, _, _, _, _ in fdes]
    write_tsv(out / 'extents.tsv', ('name', 'start_va', 'end_va_exclusive', 'bytes_hex'), extents)
    write_tsv(out / 'functions.tsv', ('name', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'body_sha256'),
              ((name, hx(start), hx(end), hx(off), hx(fde), hx(cie), hx(lsda), digest)
               for name, start, end, off, fde, cie, lsda, digest in fdes))
    write_tsv(out / 'windows.tsv', ('name', 'scope', 'start_va', 'end_va_exclusive', 'file_offset', 'section', 'bytes_hex', 'sha256'), windows)
    write_tsv(out / 'calls.tsv', ('name', 'scope', 'call_va', 'file_offset', 'bytes_hex', 'target_va'), calls)
    write_tsv(out / 'branches.tsv', ('name', 'branch_va', 'file_offset', 'bytes_hex', 'condition_code', 'target_va'), branches)
    write_tsv(out / 'offsets.tsv', ('name', 'instruction_va', 'file_offset', 'bytes_hex', 'displacement'), offsets)
    write_tsv(out / 'literals.tsv', ('name', 'va', 'file_offset', 'section', 'length', 'bytes_hex', 'ascii'), literals)
    write_tsv(out / 'immediates.tsv', ('name', 'instruction_va', 'file_offset', 'bytes_hex', 'value'), immediates)
    write_tsv(out / 'references.tsv', ('name', 'instruction_va', 'file_offset', 'bytes_hex', 'target_va', 'target_file_offset', 'target_hex', 'target_ascii'), references)
    write_tsv(out / 'selector-table.tsv', ('index', 'entry_va', 'file_offset', 'entry_hex', 'target_va'), state_rows)
    write_tsv(out / 'marker-table.tsv', ('marker', 'entry_va', 'file_offset', 'entry_hex', 'target_va'), marker_rows)
    write_tsv(out / 'key-comparisons.tsv', ('result_tag', 'index', 'cmp_va', 'file_offset', 'byte_hex', 'ascii', 'branch_va', 'branch_target_va'), key_rows)
    summary = {'binary_sha256': DIGEST, 'selected_fdes': len(fdes),
               'selected_fde_bytes': sum(end - start for _, start, end, _, _, _, _, _ in fdes),
               'fixed_windows': len(windows),
               'direct_calls': len(calls), 'conditional_branches': len(branches),
               'displacement_observations': len(offsets), 'literals': len(literals),
               'key_comparisons': len(key_rows), 'rip_references': len(references),
               'immediate_observations': len(immediates),
               'wide_marker_entries': len(marker_rows), 'selected_state_entries': len(state_rows), 'key_values': [w.decode('ascii') for w in words],
               'scope': 'Static selected paths and boundary windows; no binary execution or full control-flow census.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with ARTIFACT.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        summary = generate(data, args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except OSError:
        print('abci_bucket_guard94: I/O error', file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, struct.error) as e:
        print('abci_bucket_guard94:', str(e), file=sys.stderr)
        raise SystemExit(1)
