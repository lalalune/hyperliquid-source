#!/usr/bin/env python3
"""Extract selected node 94 address-set loader and root-input evidence.

Only fixed byte patterns are decoded. An FDE is an unwind range, not a proven
source boundary. The captured program is read as data and is never executed.
"""
import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

TARGET = ROOT / 'artifacts' / 'node' / '94' / 'hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected new unwind ranges only. Old callers are boundary windows below.
FUNCTIONS = (
    (0x3b453d0, 'action address gate'),
    (0x3b9d9b0, 'gate index iterator'),
    (0x3b45470, 'gate address table'),
    (0x308a550, 'json set reader'),
    (0x3018f10, 'json sequence element adapter'),
    (0x3586f00, 'json value adapter'),
    (0x35c8330, '20-byte text adapter'),
    (0x2bfdab0, 'messagepack set reader'),
    (0x339ed10, 'set insertion'),
    (0x1e2aad0, 'low set writer'),
    (0x4430b20, 'shared set writer'),
    (0x2806b00, 'low direct item writer'),
    (0x2804dd0, 'low buffered item writer'),
)

# Boundary windows have new instruction addresses but are inside earlier
# inventoried extents. They join prior results; they are not new FDE claims.
WINDOW_RANGES = (
    ('json_visitor_arguments', 'prior-boundary', 0x2fe52dd, 0x6),
    ('json_visitor_save_output', 'prior-boundary', 0x2fe9a64, 0x8),
    ('json_visitor_restore_output', 'prior-boundary', 0x2ff36e4, 0x8),
    ('json_field_scan', 'prior-boundary', 0x2fe6720, 0x22),
    ('json_colon_and_child', 'prior-boundary', 0x2fe805e, 0x86),
    ('messagepack_field', 'prior-boundary', 0x2abb7b2, 0x3d),
    ('messagepack_duplicate_label', 'prior-boundary', 0x2ac0cee, 0x1b),
    ('json_present_copy', 'prior-boundary', 0x2ff30ac, 0x32),
    ('json_absent_default', 'prior-boundary', 0x2ff3288, 0x18),
    ('json_result_fields', 'prior-boundary', 0x2ff3a8a, 0x1f),
    ('materializer_arguments', 'prior-boundary', 0x3751eaf, 0xc),
    ('materializer_field_source', 'prior-boundary', 0x37520bc, 0xf),
    ('materializer_field_destination', 'prior-boundary', 0x3752541, 0x1e),
    ('low_closure_input', 'prior-boundary', 0x27f0655, 0x3b),
    ('shared_closure_input', 'prior-boundary', 0x4ae4255, 0x3b),
    ('gate_loop', 'owned', 0x3b453d0, 0x9e),
    ('gate_iterator', 'owned', 0x3b9d9b0, 0x47),
    ('gate_dispatch', 'owned', 0x3b45470, 0x17),
    ('json_array_entry', 'owned', 0x308a56f, 0x80),
    ('json_array_loop', 'owned', 0x308a650, 0x77),
    ('json_array_finish', 'owned', 0x308a6c7, 0x3d),
    ('json_array_failure', 'owned', 0x308a73c, 0x8e),
    ('json_element_delimiters', 'owned', 0x3018f50, 0x8e),
    ('json_element_error', 'owned', 0x3018ff2, 0x92),
    ('json_text_adapter_call', 'owned', 0x35870c8, 0x53),
    ('text_decode_20', 'owned', 0x35c8330, 0x6b),
    ('msgpack_fixed_array', 'owned', 0x2bfe13f, 0x46),
    ('msgpack_child_check', 'owned', 0x2bfe1a0, 0x6d),
    ('msgpack_insert_loop', 'owned', 0x2bfe26c, 0x2f),
    ('msgpack_truncated_input', 'owned', 0x2bfdb45, 0x2a),
    ('set_compare_and_equal', 'owned', 0x339ed70, 0x68),
    ('set_empty_allocate', 'owned', 0x339ee8b, 0x61),
    ('set_increment_or_equal', 'owned', 0x339eee8, 0x18),
    ('low_writer_header', 'owned', 0x1e2aae9, 0xb8),
    ('low_writer_tree', 'owned', 0x1e2acd0, 0x26),
    ('low_writer_element', 'owned', 0x1e2ad81, 0x97),
    ('low_writer_finalize', 'owned', 0x1e2ae32, 0x57),
    ('shared_writer_header', 'owned', 0x4430b39, 0xb8),
    ('shared_writer_tree', 'owned', 0x4430d20, 0x26),
    ('shared_writer_element', 'owned', 0x4430dd1, 0x97),
    ('shared_writer_finalize', 'owned', 0x4430e82, 0x57),
    ('direct_item_mode', 'owned', 0x2806b11, 0x14),
    ('direct_item_bytes', 'owned', 0x2806d98, 0x1a),
    ('buffered_item_mode', 'owned', 0x2804de5, 0x14),
    ('buffered_item_binary', 'owned', 0x2805083, 0x64),
)

# Only selected actual instruction starts, with curated ownership category.
EDGES = (
    (0x2fe808c, 'boundary'), (0x2abb7da, 'boundary'),
    (0x27f0670, 'boundary'), (0x4ae4270, 'boundary'),
    (0x308a656, 'owned'), (0x308a684, 'owned'),
    (0x3019015, 'owned'), (0x358710c, 'owned'),
    (0x2bfdcd2, 'owned'), (0x2bfe1b1, 'owned'), (0x2bfe276, 'owned'),
    (0x1e2ab16, 'owned'), (0x1e2ada1, 'owned'), (0x1e2ade4, 'owned'),
    (0x1e2ae81, 'owned'), (0x4430b66, 'owned'), (0x4430df1, 'owned'),
    (0x4430e34, 'owned'), (0x4430ed1, 'owned'), (0x2806da0, 'owned'),
    (0x2805119, 'owned'),
)
RIP_REFS = ((0x3b453f0, 7), (0x3b453fc, 7), (0x35c8346, 6), (0x339ed3d, 7))
BRANCHES = (
    0x3b4541c, 0x3b45452, 0x3b9d9b4, 0x3b9d9bc, 0x3b9d9c5, 0x3b9d9cb,
    0x2fe673c, 0x2fe8062, 0x2fe806b, 0x2fe80a1, 0x2abb7bb, 0x2abb7e9, 0x2ff30b4,
    0x308a572, 0x308a5d0, 0x308a5dd, 0x308a5e9, 0x308a5f7,
    0x308a660, 0x308a667, 0x308a705, 0x308a70a, 0x308a78a,
    0x3018f5a, 0x3018f64, 0x3018f9c, 0x3018fa2, 0x3018ff6,
    0x3019002, 0x301900e, 0x301901f,
    0x2bfdb51, 0x2bfdc70, 0x2bfdced, 0x2bfe01c, 0x2bfe142,
    0x2bfe155, 0x2bfe162, 0x2bfe17f, 0x2bfe207, 0x2bfe294,
    0x339ed2a, 0x339ed78, 0x339ed9f, 0x339eda6, 0x339ee31,
    0x339ee9c, 0x339eec4,
    0x1e2ab09, 0x1e2ab24, 0x1e2ab46, 0x1e2ab9a, 0x1e2abd3,
    0x1e2abe4, 0x1e2abee, 0x1e2ac04, 0x1e2acd6, 0x1e2ad95,
    0x1e2adb2, 0x1e2add8, 0x1e2adf2, 0x1e2adff, 0x1e2ae16,
    0x4430b59, 0x4430b74, 0x4430b96, 0x4430bea, 0x4430c23,
    0x4430c34, 0x4430c3e, 0x4430c54, 0x4430d26, 0x4430de5,
    0x4430e02, 0x4430e28, 0x4430e42, 0x4430e4f, 0x4430e66,
    0x2806b1f, 0x2806da9, 0x2806df0, 0x2804df3, 0x2805099,
    0x28050b1, 0x28050c9, 0x2805122,
)

# Expected bytes are captured from file-backed ELF sections, once, and checked
# before producing evidence. No objdump text participates in this table.
PINS = {'window_json_field_scan': '498b1748ffc048f7d90fb67402ff4883fe3a0f875ca40000480fa3f50f831c190000',
 'branch_0x2fe673c': '0f831c190000',
 'branch_0x1e2ab09': '752d',
 'branch_0x1e2ab24': '0f855e030000',
 'branch_0x1e2ab46': '0f84cc030000',
 'branch_0x1e2ab9a': '0f8492020000',
 'branch_0x1e2abd3': '0f85d0020000',
 'branch_0x1e2abe4': '0f8448020000',
 'branch_0x1e2abee': '0f8406030000',
 'branch_0x1e2ac04': '0f83c6000000',
 'branch_0x1e2acd6': '0f840f020000',
 'branch_0x1e2ad95': '7543',
 'branch_0x1e2adb2': '0f8421feffff',
 'branch_0x1e2add8': '74bd',
 'branch_0x1e2adf2': '0f85b8fdffff',
 'branch_0x1e2adff': '0f8404010000',
 'branch_0x1e2ae16': '0f85cefdffff',
 'branch_0x2804df3': '0f848a020000',
 'branch_0x2805099': '0f84a4000000',
 'branch_0x28050b1': '0f84b0000000',
 'branch_0x28050c9': '0f86c3000000',
 'branch_0x2805122': '740c',
 'branch_0x2806b1f': '0f8473020000',
 'branch_0x2806da9': '7547',
 'branch_0x2806df0': '74b9',
 'branch_0x2abb7bb': '0f852d550000',
 'branch_0x2abb7e9': '0f8586180000',
 'branch_0x2bfdb51': '0f820d030000',
 'branch_0x2bfdc70': '0f85ff020000',
 'branch_0x2bfdced': '0f851dffffff',
 'branch_0x2bfe01c': '0f831d010000',
 'branch_0x2bfe142': '0f83bc030000',
 'branch_0x2bfe155': '0f84c5040000',
 'branch_0x2bfe162': '0f843e040000',
 'branch_0x2bfe17f': '0f8426010000',
 'branch_0x2bfe207': '0f858b010000',
 'branch_0x2bfe294': '0f8506ffffff',
 'branch_0x2fe8062': '0f852c8b0000',
 'branch_0x2fe806b': '0f84a1ac0000',
 'branch_0x2fe80a1': '0f84b8490000',
 'branch_0x2ff30b4': '0f84ce010000',
 'branch_0x3018f5a': '0f8792000000',
 'branch_0x3018f64': '7332',
 'branch_0x3018f9c': '7554',
 'branch_0x3018fa2': '7560',
 'branch_0x3018ff6': '7506',
 'branch_0x3019002': '7464',
 'branch_0x301900e': '7466',
 'branch_0x301901f': '7413',
 'branch_0x308a572': '7339',
 'branch_0x308a5d0': '0f859d010000',
 'branch_0x308a5dd': '0f84c6010000',
 'branch_0x308a5e9': '0f849d010000',
 'branch_0x308a5f7': '0f84b9010000',
 'branch_0x308a660': '7429',
 'branch_0x308a667': '7441',
 'branch_0x308a705': '7535',
 'branch_0x308a70a': '0f858a000000',
 'branch_0x308a78a': 'ebd5',
 'branch_0x339ed2a': '0f84ab000000',
 'branch_0x339ed78': '7436',
 'branch_0x339ed9f': '74cf',
 'branch_0x339eda6': '742c',
 'branch_0x339ee31': '7458',
 'branch_0x339ee9c': '746c',
 'branch_0x339eec4': '7354',
 'branch_0x4430b59': '752d',
 'branch_0x4430b74': '0f855e030000',
 'branch_0x4430b96': '0f84cc030000',
 'branch_0x4430bea': '0f8492020000',
 'branch_0x4430c23': '0f85d0020000',
 'branch_0x4430c34': '0f8448020000',
 'branch_0x4430c3e': '0f8406030000',
 'branch_0x4430c54': '0f83c6000000',
 'branch_0x4430d26': '0f840f020000',
 'branch_0x4430de5': '7543',
 'branch_0x4430e02': '0f8421feffff',
 'branch_0x4430e28': '74bd',
 'branch_0x4430e42': '0f85b8fdffff',
 'branch_0x4430e4f': '0f8404010000',
 'branch_0x4430e66': '0f85cefdffff',
 'call_0x1e2ab16': 'e8b5f07700',
 'call_0x1e2ada1': 'e85abd9d00',
 'call_0x1e2ade4': 'e8e79f9d00',
 'call_0x1e2ae81': 'e82a6ffaff',
 'call_0x27f0670': 'e85ba463ff',
 'call_0x2805119': 'e8925bdaff',
 'call_0x2806da0': 'e8db35daff',
 'call_0x2abb7da': 'e8d1221400',
 'call_0x2bfdcd2': 'e839107a00',
 'call_0x2bfe1b1': 'e8da2c0a00',
 'call_0x2bfe276': 'e8950a7a00',
 'call_0x2fe808c': 'e8bf240a00',
 'call_0x3019015': 'e8e6de5600',
 'call_0x308a656': 'e8b5e8f8ff',
 'call_0x308a684': 'e887463100',
 'call_0x358710c': 'e81f120400',
 'call_0x4430b66': 'e8b5986b00',
 'call_0x4430df1': 'e88a601600',
 'call_0x4430e34': 'e8d7501600',
 'call_0x4430ed1': 'e85a65f8ff',
 'call_0x4ae4270': 'e8abc894ff',
 'field_literal': '64697361626c65645f707265636f6d70696c6573',
 'hex_alphabet': '30313233343536373839616263646566',
 'window_buffered_item_binary': 'bfc4000000e8937bdaff89c5498b06498b76104839f00f84a4000000498b4e0840882c3148ffc6498976104839f00f84b0000000c604311448ffc6498976104829f04883f8130f86c3000000418b471089443110410f10070f1104314883c61449897610',
 'window_buffered_item_mode': '49bc0400000000000080807a1a000f848a020000',
 'window_direct_item_bytes': 'ba140000004c89f7e8db35daff4883f80275474983c704eb4949',
 'window_direct_item_mode': '49bf0000000000000080807a0a000f8473020000',
 'window_json_absent_default': '48c78424a00300000000000048c78424b003000000000000',
 'window_json_array_entry': '4839c87339498b561848ffc048f7d948be00260000010000000fb67c02ff4883ff20773a480fa3fe733449894628488d3c0148ffc748ffc04883ff0175db48c744241005000000488d7424104c89f7e80d8df5ffb901000000e95301000083ff5b0f859d010000410fb64e4884c90f84c6010000fec941884e480f849d010000',
 'window_json_array_failure': '4c8b7c24184885c0741b4989c44889c7e83f7df7ffbe280000004c89e731d2ff15af386e024c89ff4c89f6e8445d2800b901000000ebad488d1546136502488d74240f4c89f7e8b99bf5ff4989c7ebd548c744241018000000e91cfeffff488d7c24184989c7e8e9923600ebb8488d3db8106502ff159a396e02488d3de30f6502ff1555396e02488d3d9e106502',
 'window_json_array_finish': '410fb646483cff488b5c24780f84ea000000fec0418846484c89f7e809a9f5ff0f104424400f104c24500f294424100f294c24204889442430f6442410',
 'window_json_array_loop': '4c89ff4c89e6e8b5e8f8ff807c2410017429f64424110174418b4310898424a00000000f10030f298424900000004c89ef4889eee887463100ebc5488b442418488944244848c744244001000000488d7c2460e8e8933600eb1d0f104424600f11442448488b442470488944245848c744244000000000',
 'window_json_colon_and_child': '4883fe3a0f852c8b00004885c00f84a1ac00004989462848c784240801000000000000488dbc24800700004c89f6e8bf240a00488b84248807000083bc2480070000010f84b8490000488d8c24900700000f1001488d8c24680700000f11410848c7842460070000010000004889842468070000b8010000004889842408010000e936070000',
 'window_json_element_delimiters': '440fb6540aff4983fa2c0f87920000004c0fa3d7733248894e284d8d140949ffc248ffc14983fa0175d648c744240802000000488d4424084889f74889c6e83da3fcffe98e0000004983fa2c75548078080075604885c90f84d700000048894e284c39c1733148ffc1b8010000004c29c0440fb6440aff4983f820773d4c0fa3c7733748894e284c8d040849ffc0',
 'window_json_element_error': '4183fa5d7506c6430100eb60807808007464c6400800eb064183f85d7466488d7c2408e8e6de5600807c2408007413488b44241048894308b00188034883c4205bc38b4424098b4c240c894b05894302488b4424108b4c24180fb654241cc643010148894309885315894b1131c088034883c4205bc348c744240807000000e90dffffff48c744240815000000e9fffeffff',
 'window_json_present_copy': 'f6842408010000010f84ce010000488d8c2468070000488b411048898424b00300000f10010f298424a0030000e9c2010000',
 'window_json_result_fields': '488b8424b0030000498986201f00000f288424a0030000410f1186101f0000',
 'window_json_text_adapter_call': '49c7461000000000488d7c24084c89f2ff15c27b1e02488b442408488b7424104883f802750948897308c60301eb59488b542418488d7c2428a8017407e816540000eb05e81f120400807c2428010f84020300',
 'window_low_closure_input': 'c744240800040001c644240c00488b16488dbc24080100004889e6e85ba463ff4c8bb4240801000048b804000000000000804939c60f85f6000000',
 'window_low_writer_element': '4531e4488d0c89488d34884883c6084c397424107543488b542438488d7c2470e85abd9d00488b442470498d4e044839c80f8421feffffe9ec0000000f1f004c8d61014989c7488d0c89488d34884883c6084c3974241074bd488d7c2440488d542410e8e79f9d00498d460448394424400f85b8fdffff8b44243083f8ff0f8404010000ffc08944243040b501bb0000000049ffcd0f85',
 'window_low_writer_finalize': '488b442410488b4c2418488b542420488b7424288b7c2430897c24608b7c2434897c2464488b7c243848897c246848895424504889742458488944244048894c2448488d742440488b5c24084889dfe82a6ffaffeb4e48',
 'window_low_writer_header': '488b1a4c8b62084885db400f95c54c8b6a104d89ef4c0f44fb4c89f848c1e820752d488d7c24404c89f64489fae8b5f07700488b4424404883f8020f855e03000048ba000000000000008031c9eb3abf80000000ff15953494034885c00f84cc030000410fb7560a410fb64e0cc1e11009d1410fb7560881e10101ff0048c1e1104809d1ba800000004889542410488944241848c74424200000000048894c2428c7442430000000004c897424384d85ff0f849202000049',
 'window_low_writer_tree': '498b074885c00f840f02000048ffc3410fb78fe40000004989c7663b88e600000073dd4885db',
 'window_materializer_arguments': '4989cd4889d54889f34989fe',
 'window_materializer_field_destination': '488b8c2480000000488b4110498986403a00000f1001410f1186303a0000',
 'window_materializer_field_source': '488d83101f00004889842480000000',
 'window_messagepack_duplicate_label': '488d05a681abfd48898424d026000048c78424d826000014000000',
 'window_messagepack_field': '4883bc24b8000000000f852d55000048c78424b800000000000000488dbc24700600004889de31d2e8d12214000fb68424700600003c090f8586180000',
 'window_msgpack_child_check': '898c24a0000000488d7c2410ba01000000e8da2c0a00440fb6742410440fb66c2411440fb67c24120fb65c2413440fb6642414440fb6542415440fb64c2416440fb64424170fb67c24180fb67424190fb654241a0fb64c241b0fb66c241c488b44241d4180fe090f858b010000',
 'window_msgpack_fixed_array': '80f9a00f83bc03000080e10f0fb6c90fb746226685c00f84c504000066ffc8668946220f843e04000048c74424700000000048c78424800000000000000085c90f8426010000',
 'window_msgpack_insert_loop': '488d7c2470488d742450e8950a7a008b8c24a0000000ffc9488bb424c0000000488bac24980000000f8506fffffff2',
 'window_msgpack_truncated_input': '4c8b5610488b46184883f8020f820d0300004883c0fe410fb70a66c1c1084983c2024c89561048894618',
 'window_set_compare_and_equal': '4a8d04234883f80874364b8d3427ba140000004c89f741ffd548984885c00f98c10f9fc028c848ffc54983c4143c0174cf0fb6c085c0742ceb0b660f1f440000488b6c2420488b04244883e8010f823d010000488904244d8bbcefe8000000e970ffffffb001e913',
 'window_set_empty_allocate': '4889fbbfe8000000ff153ff13c024885c0746c48c7000000000066c780e6000000000048890348c74308000000000fb788e60000004883f90b73544889de8d5101668990e6000000488d0c89418b561089548818410f10060f1144880848ff4610',
 'window_set_increment_or_equal': '48ff461031c04881c4b80000005b415c415d415e415f5dc3',
 'window_shared_closure_input': 'c744240800040001c644240c00488b16488dbc24080100004889e6e8abc894ff4c8bb4240801000048b804000000000000804939c60f85f6000000',
 'window_shared_writer_element': '4531e4488d0c89488d34884883c6084c397424107543488b542438488d7c2470e88a601600488b442470498d4e044839c80f8421feffffe9ec0000000f1f004c8d61014989c7488d0c89488d34884883c6084c3974241074bd488d7c2440488d542410e8d7501600498d460448394424400f85b8fdffff8b44243083f8ff0f8404010000ffc08944243040b501bb0000000049ffcd0f85',
 'window_shared_writer_finalize': '488b442410488b4c2418488b542420488b7424288b7c2430897c24608b7c2434897c2464488b7c243848897c246848895424504889742458488944244048894c2448488d742440488b5c24084889dfe85a65f8ffeb4e48',
 'window_shared_writer_header': '488b1a4c8b62084885db400f95c54c8b6a104d89ef4c0f44fb4c89f848c1e820752d488d7c24404c89f64489fae8b5986b00488b4424404883f8020f855e03000048ba000000000000008031c9eb3abf80000000ff1545d433014885c00f84cc030000410fb7560a410fb64e0cc1e11009d1410fb7560881e10101ff0048c1e1104809d1ba800000004889542410488944241848c74424200000000048894c2428c7442430000000004c897424384d85ff0f849202000049',
 'window_shared_writer_tree': '498b074885c00f840f02000048ffc3410fb78fe40000004989c7663b88e600000073dd4885db',
 'window_text_decode_20': '534883ec504889fb488d7c24204889e141b814000000ff1574821a02837c24200375218b4424100f1004240f290424894424108943110f11430131c088034883c4505bc30f104424200f114424070f29442430488d7c2430e87355e1ff48894308b00188034883c4505bc3'}

PINS.update({'branch_0x3b4541c': '7436',
 'branch_0x3b45452': '75bc',
 'branch_0x3b9d9b4': '7234',
 'branch_0x3b9d9bc': '742c',
 'branch_0x3b9d9c5': '7223',
 'branch_0x3b9d9cb': '760b',
 'gate_code_0': '660f6f05d1e76bfc660f7f4424e8c74424f822222222',
 'gate_code_1': '660f76c0660f7f4424e8c74424f8ffffffffe9810100',
 'gate_code_10': 'f30f6f05a20ea7fc660f7f4424e8c74424f800000802',
 'gate_code_11': 'f30f6f059810a7fc660f7f4424e8c74424f800000803',
 'gate_code_12': 'f30f6f057610a7fc660f7f4424e8c74424f800000804',
 'gate_code_13': 'f30f6f052f0fa7fc660f7f4424e8c74424f800000805',
 'gate_code_14': 'f30f6f05ef10a7fc660f7f4424e8c74424f800000806',
 'gate_code_15': 'f30f6f052b10a7fc660f7f4424e8c74424f800000807',
 'gate_code_16': 'f30f6f053211a7fc660f7f4424e8c74424f800000808',
 'gate_code_17': 'f30f6f05eb0fa7fc660f7f4424e8c74424f800000809',
 'gate_code_18': 'f30f6f055d0fa7fc660f7f4424e8c74424f80000080a',
 'gate_code_19': 'f30f6f05080fa7fc660f7f4424e8c74424f80000080b',
 'gate_code_2': '660f6f0523e76bfc660f7f4424e8c74424f8eeeeeeee',
 'gate_code_20': 'f30f6f050c10a7fc660f7f4424e8c74424f80000080c',
 'gate_code_21': 'f30f6f05ea0fa7fc660f7f4424e8c74424f80000080d',
 'gate_code_22': 'f30f6f055c0fa7fc660f7f4424e8c74424f80000080e',
 'gate_code_23': 'f30f6f05400fa7fc660f7f4424e8c74424f80000080f',
 'gate_code_24': 'f30f6f051511a7fc660f7f4424e8c74424f800000810',
 'gate_code_25': 'f30f6f054411a7fc660f7f4424e8c74424f800000811',
 'gate_code_26': 'f30f6f05340fa7fc660f7f4424e8c74424f800000812',
 'gate_code_27': '660f6f05e60d6cfc660f7f4424e8c74424f833333333',
 'gate_code_28': '660f6f0535e26bfc660f7f4424e8c74424f855555555',
 'gate_code_29': '660f6f05eded6bfc660f7f4424e8c74424f8bbbbbbbb',
 'gate_code_3': 'f30f6f05480fa7fc660f7f4424e8c74424f80000dead',
 'gate_code_4': 'f30f6f051910a7fc660f7f4424e8c74424f800000007',
 'gate_code_5': '660f6f05bae66bfc660f7f4424e8c74424f8dddddddd',
 'gate_code_6': '660f6f0539156cfc660f7f4424e8c74424f8fefefefe',
 'gate_code_7': 'f30f6f05550fa7fc660f7f4424e8c74424f800000800',
 'gate_code_8': 'f30f6f055f0ea7fc660f7f4424e8c74424f800000813',
 'gate_code_9': 'f30f6f051f10a7fc660f7f4424e8c74424f800000801',
 'gate_head_0': '22222222222222222222222222222222',
 'gate_head_10': '00000000000000000000000000000000',
 'gate_head_11': '00000000000000000000000000000000',
 'gate_head_12': '00000000000000000000000000000000',
 'gate_head_13': '00000000000000000000000000000000',
 'gate_head_14': '00000000000000000000000000000000',
 'gate_head_15': '00000000000000000000000000000000',
 'gate_head_16': '00000000000000000000000000000000',
 'gate_head_17': '00000000000000000000000000000000',
 'gate_head_18': '00000000000000000000000000000000',
 'gate_head_19': '00000000000000000000000000000000',
 'gate_head_2': 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
 'gate_head_20': '00000000000000000000000000000000',
 'gate_head_21': '00000000000000000000000000000000',
 'gate_head_22': '00000000000000000000000000000000',
 'gate_head_23': '00000000000000000000000000000000',
 'gate_head_24': '00000000000000000000000000000000',
 'gate_head_25': '00000000000000000000000000000000',
 'gate_head_26': '00000000000000000000000000000000',
 'gate_head_27': '33333333333333333333333333333333',
 'gate_head_28': '55555555555555555555555555555555',
 'gate_head_29': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 'gate_head_3': '00000000000000000000000000000000',
 'gate_head_4': '00000000000000000000000000000000',
 'gate_head_5': 'dddddddddddddddddddddddddddddddd',
 'gate_head_6': 'fefefefefefefefefefefefefefefefe',
 'gate_head_7': '00000000000000000000000000000000',
 'gate_head_8': '00000000000000000000000000000000',
 'gate_head_9': '00000000000000000000000000000000',
 'gate_iterator_limit': '4883f91e',
 'gate_range': '4080c5f94080fd140f92c0',
 'gate_table': '83345903fd35590391355903c73559030a3559034a3659039b365903e2355903ec36590340355903d1365903ef3459032535590380365903d4345903ac355903b934590314365903b63659031f3759032f365903653659030737590337375903763559035b3559037f3759039e3459034f37590367375903',
 'window_gate_dispatch': '4889f8400fb6ce488d1586cba6fc48630c8a4801d1ffe1',
 'window_gate_iterator': '5048033772344889f048ffc0742c488b4f084801c172234883f91e760b48c7071e000000b01e59c34889074883fe1eb81e000000480f42c659c3488d3dff55b701ff152107bd01',
 'window_gate_loop': '554157415641554154534883ec384889fb660fefc0660f7f4424204c8d7424204c8b25890ec3014c8d7c240c4c8b2d850ec301666666662e0f1f8400000000004c89f731f641ffd489c53c1e7436400fb6f54c89ff41ffd5f30f6f44240cf30f6f0b660f74c8660f6e44241c660f6e5310660f74d0660fdbd1660fd7c23dffff000075bc4080c5f94080fd140f92c04883c4385b415c415d415e415f5dc3'})

PINS.update({'rip_0x339ed3d': '4c8b2d44f73c02',
 'rip_0x35c8346': 'ff1574821a02',
 'rip_0x3b453f0': '4c8b25890ec301',
 'rip_0x3b453fc': '4c8b2d850ec301'})

PINS.update({'window_json_visitor_arguments': '4989f64889fb',
 'window_json_visitor_restore_output': '4c8bb424c0000000',
 'window_json_visitor_save_output': '48899c24c0000000'})


def verify_digest(data, expected=TARGET_SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


class View:
    def __init__(self, data, sections=None):
        self.data = data
        self.sections = elf_index.sections(data) if sections is None else sections

    def offset(self, va, length):
        if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length < 0:
            raise ValueError('invalid VA or length')
        matches = [s for s in self.sections if s['type'] != 8 and s['size']
                   and s['address'] <= va and va + length <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file backed')
        s = matches[0]
        start = s['offset'] + va - s['address']
        if start < 0 or start + length > len(self.data):
            raise ValueError('mapping exceeds file')
        return start

    def read(self, va, length):
        start = self.offset(va, length)
        return bytes(self.data[start:start + length])


def checked(view, key, va, length):
    expected = bytes.fromhex(PINS[key])
    observed = view.read(va, length)
    if len(expected) != length or observed != expected:
        raise ValueError('checked bytes differ at ' + hex(va))
    return observed


def rel_call(view, va):
    raw = checked(view, 'call_' + hex(va), va, 5)
    if raw[0] != 0xe8:
        raise ValueError('not a direct call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def rip_reference(view, va, size):
    raw = checked(view, 'rip_' + hex(va), va, size)
    if size == 7 and raw[:3] in (bytes.fromhex('4c8b25'), bytes.fromhex('4c8b2d')):
        pass
    elif size == 6 and raw[:2] == bytes.fromhex('ff15'):
        pass
    else:
        raise ValueError('unsupported RIP reference')
    target = va + size + struct.unpack_from('<i', raw, size - 4)[0]
    return {'va': hex(va), 'bytes': raw.hex(), 'target': hex(target)}


def branch(view, va):
    raw = bytes.fromhex(PINS['branch_' + hex(va)])
    checked(view, 'branch_' + hex(va), va, len(raw))
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        displacement = struct.unpack_from('<b', raw, 1)[0]
        condition = raw[0] & 15
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack_from('<i', raw, 2)[0]
        condition = raw[1] & 15
    elif len(raw) == 5 and raw[0] == 0xe9:
        displacement = struct.unpack_from('<i', raw, 1)[0]
        condition = None
    elif len(raw) == 2 and raw[0] == 0xeb:
        displacement = struct.unpack_from('<b', raw, 1)[0]
        condition = None
    else:
        raise ValueError('unsupported fixed branch form')
    return {'va': hex(va), 'bytes': raw.hex(), 'condition_code': condition,
            'fallthrough': hex(va + len(raw)), 'target': hex(va + len(raw) + displacement)}


def selected_relocations(view, slots=None):
    secs = {s['name']: s for s in view.sections}
    rela, sym, strings = (secs[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if any(x['type'] == 8 for x in (rela, sym, strings)) or rela['size'] % 24 or sym['size'] % 24:
        raise ValueError('invalid relocation or symbol section')
    selected = {slot: [] for slot in (slots if slots is not None else (0x57705c0, 0x576e488, 0x5773df8, 0x5776280, 0x5776288))}
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', view.data, off)
        if slot in selected:
            typ, index = info & 0xffffffff, info >> 32
            name = ''
            if index:
                if index >= sym['size'] // 24:
                    raise ValueError('symbol index outside table')
                nameoff = struct.unpack_from('<I', view.data, sym['offset'] + index * 24)[0]
                if nameoff >= strings['size']:
                    raise ValueError('symbol name outside table')
                start = strings['offset'] + nameoff
                end = view.data.find(b'\0', start, strings['offset'] + strings['size'])
                if end < 0:
                    raise ValueError('unterminated symbol')
                name = view.data[start:end].decode('ascii')
            selected[slot].append({'slot': hex(slot), 'type': typ, 'symbol_index': index,
                                   'symbol_name': name, 'addend': hex(addend),
                                   'record_file_offset': hex(off)})
    for slot, rows in selected.items():
        if len(rows) != 1:
            raise ValueError('missing or duplicate selected relocation')
        row = rows[0]
        if slot == 0x57705c0 and (row['type'], row['symbol_index'], row['addend']) != (8, 0, hex(0x156e650)):
            raise ValueError('different address decoder relocation')
        expected_relative = {0x5773df8: 0x3b453d0, 0x5776280: 0x3b9d9b0, 0x5776288: 0x3b45470}
        if slot in expected_relative and (row['type'], row['symbol_index'], row['addend']) != (8, 0, hex(expected_relative[slot])):
            raise ValueError('different gate relocation')
        if slot == 0x576e488 and (row['type'], row['symbol_name']) != (6, 'memcmp'):
            raise ValueError('different comparison relocation')
    return [selected[k][0] for k in sorted(selected)]


def gate_cases(view):
    # The code calls the iterator with zero and stops at the byte in the CMP.
    count = checked(view, 'gate_iterator_limit', 0x3b9d9c7, 4)[3]
    gate = checked(view, 'gate_range', 0x3b45454, 11)
    first = (-struct.unpack_from('<b', gate, 3)[0]) & 0xff
    width = gate[7]
    dispatch = checked(view, 'gate_table', 0x5b2004, count * 4)
    rows = []
    for index in range(count):
        target = 0x5b2004 + struct.unpack_from('<i', dispatch, index * 4)[0]
        code = checked(view, 'gate_code_' + str(index), target, 22)
        if code[:4] == bytes.fromhex('660f76c0'):
            head = b'\xff' * 16
            tail = code[10:18]
            src = None
        elif code[:4] in (bytes.fromhex('660f6f05'), bytes.fromhex('f30f6f05')):
            src = target + 8 + struct.unpack_from('<i', code, 4)[0]
            head = checked(view, 'gate_head_' + str(index), src, 16)
            tail = code[14:22]
            if code[8:14] != bytes.fromhex('660f7f4424e8'):
                raise ValueError('different gate head store')
        else:
            raise ValueError('unsupported gate address arm')
        if tail[:4] != bytes.fromhex('c74424f8'):
            raise ValueError('different gate suffix store')
        key = head + tail[4:8]
        rows.append({'index': index, 'table_entry': hex(0x5b2004 + 4 * index),
                     'table_bytes': dispatch[4 * index:4 * index + 4].hex(),
                     'arm': hex(target), 'arm_file_offset': hex(view.offset(target, len(code))),
                     'arm_bytes': code.hex(), 'head_data': None if src is None else hex(src),
                     'head_bytes': head.hex(), 'key_hex': key.hex(),
                     'accepted': int(((index - first) & 255) < width)})
    if len({row['key_hex'] for row in rows}) != count:
        raise ValueError('duplicate gate keys change first-match behavior')
    return rows


def write_tsv(path, rows, keys):
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(keys)
        for row in rows:
            writer.writerow([row.get(key, '') if row.get(key) is not None else '' for key in keys])


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def select_fde(by_start, unwind, va):
    group = by_start.get(va, [])
    if len(group) != 1 or group[0]['end'] <= va:
        raise ValueError('selected FDE missing, duplicated or empty')
    fde = group[0]
    index = fde.get('index')
    if index is None or not 0 <= index < len(unwind) or unwind[index]['start'] != va or unwind[index]['fde'] != fde['fde']:
        raise ValueError('selected FDE and unwind index differ')
    return fde


def collect(data):
    digest = verify_digest(data)
    view = View(data)
    _, records, _ = fde_extents.fde_extents(data)
    _, unwind = elf_index.unwind_index(data)
    by_start = {}
    for fde in records:
        by_start.setdefault(fde['start'], []).append(fde)
    functions = []
    for va, label in FUNCTIONS:
        fde = select_fde(by_start, unwind, va)
        length = fde['end'] - va
        body = view.read(va, length)
        functions.append({'label': label, 'start': hex(va), 'end_exclusive': hex(fde['end']),
                          'file_offset': hex(view.offset(va, length)), 'bytes': length,
                          'fde': hex(fde['fde']), 'cie': hex(fde['cie']),
                          'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None,
                          'sha256': hashlib.sha256(body).hexdigest()})
    windows = []
    for label, ownership, va, length in WINDOW_RANGES:
        raw = checked(view, 'window_' + label, va, length)
        windows.append({'label': label, 'scope': ownership, 'va': hex(va),
                        'file_offset': hex(view.offset(va, length)), 'bytes': raw.hex()})
    edges = []
    for va, scope in EDGES:
        edges.append({'va': hex(va), 'file_offset': hex(view.offset(va, 5)),
                      'bytes': view.read(va, 5).hex(), 'target': hex(rel_call(view, va)),
                      'scope': scope})
    branches = [branch(view, va) for va in BRANCHES]
    literal = checked(view, 'field_literal', 0x578e9b, 20)
    alphabet = checked(view, 'hex_alphabet', 0x208620, 16)
    return {'binary_sha256': digest, 'functions': functions, 'windows': windows,
            'relocations': selected_relocations(view),
            'gate_cases': gate_cases(view),
            'rip_references': [rip_reference(view, va, size) for va, size in RIP_REFS],
            'direct_edges': edges, 'branches': branches,
            'data': {'field': {'va': hex(0x578e9b), 'bytes': literal.hex(),
                               'text': literal.decode('ascii')},
                     'hex_alphabet': {'va': hex(0x208620), 'bytes': alphabet.hex(),
                                      'text': alphabet.decode('ascii')}},
            'limitations': ['selected instruction sites only', 'FDEs are unwind extents',
                            'prior boundary windows do not own their containing extents',
                            'no scheduler or live-object identity proof',
                            'no node execution or binary equivalence']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    result = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / 'evidence.json', result)
    for name, keys in (
        ('functions', ('label', 'start', 'end_exclusive', 'bytes', 'file_offset', 'fde', 'cie', 'lsda', 'sha256')),
        ('windows', ('label', 'scope', 'va', 'file_offset', 'bytes')),
        ('direct_edges', ('scope', 'va', 'file_offset', 'bytes', 'target')),
        ('branches', ('va', 'bytes', 'condition_code', 'fallthrough', 'target')),
        ('relocations', ('slot', 'type', 'symbol_index', 'symbol_name', 'addend', 'record_file_offset')),
        ('gate_cases', ('index', 'table_entry', 'table_bytes', 'arm', 'arm_file_offset', 'arm_bytes', 'head_data', 'head_bytes', 'key_hex', 'accepted')),
        ('rip_references', ('va', 'bytes', 'target')),
    ):
        write_tsv(args.out / (name + '.tsv'), result[name], keys)
    write_json(args.out / 'summary.json', {
        'binary_sha256': result['binary_sha256'],
        'functions': len(result['functions']),
        'function_bytes': sum(f['bytes'] for f in result['functions']),
        'windows': len(result['windows']),
        'prior_boundary_windows': sum(w['scope'] == 'prior-boundary' for w in result['windows']),
        'direct_edges': len(result['direct_edges']),
        'branches': len(result['branches']),
        'relocations': len(result['relocations']),
        'literals': len(result['data']),
        'rip_references': len(result['rip_references']),
        'gate_cases': len(result['gate_cases']),
        'gate_accepted_cases': sum(x['accepted'] for x in result['gate_cases']),
    })
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
