#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce selected node 115 ABCI owner and result-flow evidence from ELF bytes."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

# The shared FDE module imports elf_index as a top-level module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
MASK64 = (1 << 64) - 1

# Selected new FDEs only. Caller/constructor context is recorded separately.
FUNCTIONS = [
    ('buffered_sink', 0x14c37f0, 0x14c389b),
    ('callback_adapter', 0x2a92960, 0x2a929e9),
    ('record_serializer', 0x4d6d740, 0x4d6d886),
    ('line_encoder', 0x50e2f80, 0x50e3104),
    ('wrapper_transform_a', 0x567bb70, 0x567bc40),
    ('wrapper_transform_b', 0x567bc40, 0x567bd43),
    ('owner_assembler', 0x567bd50, 0x567c252),
    ('record_sink', 0x595a6b0, 0x595ac25),
    ('callback_cleanup', 0x2aaea40, 0x2aaecd6),
    ('pending_drain', 0x5a8b130, 0x5a8b3d9),
    ('height_read_wrapper', 0x4f0e990, 0x4f0f30a),
    ('height_read_leaf', 0x4fbd410, 0x4fbd914),
]
PINS = [
    ('assemble_second_alloc', 'owned', 0x567bdda, '4c89ffff159d36e6004885c00f84c10300004989c44889c74889ee4c89faff150a37e600eb1e'),
    ('writer_pre_roll', 'owned', 0x595a706, '4989fd0f1047080f118424c00000004c897424584c8d6424084c89e7ff156862b8004c8d7c24684c89ff4c89e631d2ff157d63b8008b44246885c00f8437040000'),
    ('expanded_return', 'context', 0x5a6c0af, '4989c64c8b7828'),
    ('context_build', 'context', 0x5a6c10a, '4c89b42490160000c68424ac160000004c89a424981600004c8db42440120000488db424b0020000ba500400004c89f7ff15c833a700'),
    ('context_handoff', 'context', 0x5a6c1bc, '4c8db424b0020000488db42440120000ba700400004c89f7ff152e33a700'),
    ('assemble_call', 'context', 0x5a6c1f5, '488d15a4579efa488dbc24401200004c8d8424a00000004c8d8c24200e0000b9100000004c89f6e82ffbc0ff'),
    ('wrapper_transform', 'context', 0x5a6c221, '4c8db42440590000488db42440120000ba280b00004c89f741ffd54c8dbc2440120000ba280b00004c89ff4c89f641ffd5488dbc24b00200004c89fee8def9c0ff4c8db42440590000488db424b0020000ba280b00004c89f741ffd54c8dbc2440120000ba280b00004c89ff4c89f641ffd5488dbc24b00200004c89fee8cdf8c0ff4c8db42440590000488db424b0020000ba280b00004c89f741ffd5'),
    ('wrapper_allocate', 'context', 0x5a6c2be, '48c78424401200000100000048c7842448120000010000004c8da42450120000ba280b00004c89e74c89f641ffd5bf380b0000ff158931a7004885c00f84ba0300004989c6488db42440120000ba380b00004889c7ff15ef31a700'),
    ('constructor_return', 'context', 0x5a6c67e, '4c89f04c89fa4881c4686400005b415c415d415e415f5d'),
    ('save_constructor', 'context', 0x2cb7a15, '4989c648898424280100004889942430010000'),
    ('save_owner_register', 'context', 0x2cb7b84, '4d89f4'),
    ('owner_to_staging', 'context', 0x2cb7e1f, '4c89a424d00d0000488b4c243848898c24d80d0000'),
    ('stage_copy_one', 'context', 0x2cb7e6c, '488db424380700004c8dbc2410320000bab80600004c89ffffd5'),
    ('stage_copy_two', 'context', 0x2cb7ffe, '488dbc2440270000baf00700004c89feffd5'),
    ('stage_copy_three', 'context', 0x2cb8039, '488dbc24501f0000488db42440270000baf0070000ff15b4748203'),
    ('stage_copy_four', 'context', 0x2cb8068, '4c89a398010000488dbba0010000488db424501f0000bab8060000ffd5'),
    ('closure_capture', 'context', 0x2cb9799, '4c8bbb38080000f049ff070f8e2e070000488db3980100004c89bc2440270000c683e20a000000c683dc0a000000c683da0a000000488dbc2430070000bac0060000ff15275d8203'),
    ('closure_allocate', 'context', 0x2cb984d, 'bf18070000ff15285c82034885c00f84870500004989c6488db42430070000ba180700004889c7ff158e5c8203488d3da05795fd488d0d18d97803be190000004c89f2ff15ba7e8203'),
    ('assemble_entry', 'owned', 0x567bd50, '554157415641554154534881ec980a00004d89ce4c89c34989cf4889d54989fd48c784242006000000000000488dbc2428060000ba70040000ff157937e600'),
    ('assemble_size_branch', 'owned', 0x567bd8f, '4d85ff791031ff4c89feff15f936e600e917040000745a4c89ffff15d136e6004885c00f84eb030000'),
    ('assemble_context_copy', 'owned', 0x567c0c7, '498dbda8060000488db42420060000488b1d2b34e600ba78040000ffd3807c240f004d897d10488b442418498945184d897d20410f9585200b000049c7450000000000'),
    ('assemble_return', 'owned', 0x567c165, '41c7852801000000ca9a3b4c89e84881c4980a00005b415c415d415e415f5dc3'),
    ('assemble_failure', 'owned', 0x567c185, '488d3d2c7de200ff159e36e600eb27488d3d1d7de200ff158f36e600eb18bf01000000e9e9fbffffbf010000004c89feff15dd32e6000f0b'),
    ('transform_b_entry', 'owned', 0x567bc40, '415741564154534881ec180200004889f34989fe488b7618488b5320488dbc2410010000ff1546f5e600488d7c2408488db42410010000ba08010000ff158638e600'),
    ('transform_b_replace', 'owned', 0x567bc82, '4c8d7b2881bb2801000000ca9a3b7449488bb3e80000004885f674344889f048c1e004488d04404801c64883c6417420488bbbe00000004829c74883c7d031d24883fe100f92c2c1e202ff15ce37e600488d7b30e815a2fbff'),
    ('transform_b_return', 'owned', 0x567bcdb, '488d7424084c8b252138e600ba080100004c89ff41ffd4ba280b00004c89f74889de41ffd44c89f04881c4180200005b415c415e415fc3'),
    ('transform_a', 'owned', 0x567bb70, '415741564154534881ec580500004889f34989fe4c8dbe580100004c8da424b0020000baa80200004c89e74c89feff156439e600488d7c24084c89e6ff150ef6e600488d7424084c8b254a39e600baa80200004c89ff41ffd4ba280b00004c89f74889de41ffd44c89f04881c4580500005b415c415e415fc3'),
    ('callback_bridge', 'owned', 0x2a92960, '4156534883ec584889fb8bb7100700000f1087c00600000f108fd00600000f294c24400f29442430488b870007000048894424200f1087e00600000f108ff00600000f294c24100f2904244c8b8708070000488d5424304889e1ff151048a5034889dfe878c001004883c4585b415ec3'),
    ('callback_cleanup', 'owned', 0x2a929d0, '4989c64889dfe865c001004c89f7e86de09503ff15d7caa403'),
    ('writer_gate', 'owned', 0x595a6b0, '554157415641554154534881ec1801000031c0483b47180f809f04000048899424b0000000488d5f184883fe014883d6ff48b94b598638d6c56d344889f048f7e148c1ea0b4c69f2102700004c3b77680f8621040000'),
    ('writer_roll_store', 'owned', 0x595a7a5, '4d89756841807d70000f850c030000'),
    ('writer_pass_record', 'owned', 0x595ab27, '4c8d7c24084c89ffff155b5eb8004889df4c89fe488b9424b0000000e8388478ff4889dfe8008eb6fb4889c7e82893bdfb4885c0740f4889442408488d7c2408e894a1b6fb4881c4180100005b415c415d415e415f5dc3'),
    ('writer_open_failure', 'owned', 0x595ab7e, '488d3d32afb0fa488d15d415aa00be2b000000ff15d94bb800'),
    ('encode_start', 'owned', 0x50e2f80, '415741564154534883ec284889d34989f44989febf80000000ff15e1c43f014885c00f841c01000048c7042480000000488944240848c7442410000000004889e04889442418488d7424184889dfe86da7c8ff4889c34885c0'),
    ('encode_failure', 'owned', 0x50e2fd9, '7418488b34244885f67420488b7c240831d2ff15afc43f01eb11488b3424488b5c24084889f048f7d8714a488b034883f801741c4885c07520488b73104885f67417488b7b0831d2ff1579c43f01eb09488b7b08e84ed50000be280000004889df31d2ff155ec43f014883c4285b415c415e415fc3'),
    ('encode_success', 'owned', 0x50e304e, '4c8b7c24104889342448895c24084c897c2410418b44240889442420498b042448894424184c89f84c39fe7425c604030a49ffc7488d7424184c89f74889da4c89f9e85b073efc488b34244885f67599eba24889e7ba01000000b90100000041b801000000e8987b3efc488b5c2408488b442410ebb7'),
    ('encode_allocation_failure', 'owned', 0x50e30c4, 'bf01000000be80000000ff15c4c33f01eb0d'),
    ('serializer_entry', 'owned', 0x4d6d740, '41574156534883ec304889fb4c8b36498b46104939060f84e2000000498b4e08c604017b48ffc04989461066c744240800014889742410488d35b391bafb488d7c2408ba0a0000004889d9e860413100'),
    ('serializer_fields', 'owned', 0x4d6d790, '4885c00f859b000000807c240800757c488d4b58488d359091bafb488d7c2408ba05000000e8760a30004885c07575807c24080075564883eb80488d352889bafb488d7c2408ba060000004889d9e82d9a30004885c0754c31c0f6442408017543807c240900743c'),
    ('serializer_close', 'owned', 0x4d6d7f8, '488b442410488b18488b7310483933745f488b4308c604307d48ffc64889731031c0eb1848c74424180a000000488d7c241831f631d2ff15d43277014883c4305b415e415fc3'),
    ('buffer_entry', 'owned', 0x14c37f0, '55415741564155415453504989cf4989d44989f64889fbe8440100004989c5488b00498b6d104829e84939c7735b498b7d084801ef4c89e64c89faff15d7bc01054c01fd49896d10'),
    ('buffer_followup', 'owned', 0x14c3838, '488d7b384c89f6ff15c3c7010584c074214889dfe8ff0000004889c7e8270607004885c0740c488904244889e7e8961400004883c4085b415c415d415e415f5dc34c89ef4c89e64c89faff1588c701054885c0'),
    ('buffer_error', 'owned', 0x14c388b, '74ab488904244889e7e867140000eb9d'),
    ('cleanup_entry', 'owned', 0x2aaea40, '4157415641554154534889fbff154e88a303488b83a0060000f048ff08750d488dbba0060000ff15ac84a303488b83a8060000f048ff08750d488dbba8060000ff15ea87a303'),
    ('cleanup_remainder', 'owned', 0x2aaea86, '488b4330f048ff08750a488d7b30ff158687a303488b83b0060000f048ff08750d488dbbb0060000ff15c487a303488d7b40e8e3a70000488bb3800500004885f6740f488bbb8805000031d2ff15c809a303488dbb98050000e8dcd10000488dbba0020000e830df0000488b83f80500004889c148f7d97074488b8b080600004885c9744c4c8bbb000600004983c74841bc010000004929cc4c8b2daa64a303eb150f1f8400000000004983c72849ffc44983fc017413498b47d8f048ff0875e9498d7fd841ffd5ebe0488b83f80500004885c07417488bbb0006000048c1e003488d348031d2ff152d09a303488dbb50060000e8b180feff4881c3780600004889df5b415c415d415e415fe99980feff'),
    ('drain_take', 'owned', 0x5a8b130, '4157415641554154534881ec1001000049bd0000000000000080488b87f80500004c89aff80500004889c148f7d90f80ec0100004889fb48894424280f1087000600000f108f100600000f1097200600000f109f300600000f114424300f114c24400f115424500f115c24600f1087400600000f11442470'),
    ('drain_owner_helper', 'owned', 0x5a8b1a8, '488bbfa0060000488d7710488d05fa0aebfa488984248800000048c78424900000000c00000048c7842480000000000000004881c7400100004c8d0580e2a200488d94248000000031c9e8993748ff4989c6'),
    ('drain_record_copy', 'owned', 0x5a8b1fa, '488b44247848898424d00000000f104424680f298424c00000000f104424280f104c24380f105424480f105c24580f299c24b00000000f299424a00000000f298c24900000000f29842480000000c68424d8000000024c89b42400010000'),
    ('drain_first_encode', 'owned', 0x5a8b258, 'bf80000000ff151d42a5004885c00f84f500000048c744240880000000488944241048c744241800000000488d4424084889442420488dbc2480000000488d742420e8a1242eff4989c74885c07419488b7424084885f6741e488b7c241031d2ff15e241a500eb0f4c8b6424084c8b7c24104d39ec7547'),
    ('drain_encode_error', 'owned', 0x5a8b2cf, '498b074883f801741c4885c07520498b77104885f67417498b7f0831d2ff15ae41a500eb09498d7f08e8f305fcff4531e4be280000004c89ff31d2ff159041a50041bf01000000'),
    ('drain_sink', 'owned', 0x5a8b316, '4881c380050000488d9424800000004889df4c89f6e880f3ecff4d85e4740e4c89ff4c89e631d2ff155d41a500488dbc2480000000e83055fcff4881c4100100005b415c415d415e415fc3'),
    ('drain_oom', 'owned', 0x5a8b361, 'bf01000000be80000000ff152741a5000f0b'),
    ('read_wrapper_entry', 'owned', 0x4f0e990, '554157415641554154534881ec980100004889bc24e0000000807f200074564989f94d8b384d8b6808418b68104c89bc24300100004c89ac243801000089ac244001000049c7c480eeffff644c8b3425000000004d01e664410fb644242083f801746783f8027529488d3d590e5901ff15a31f5d014889f74889d64881c4980100005b415c415d415e415f5de9efe90a00'),
    ('read_leaf_entry', 'owned', 0x4fbd410, '554157415641554154534883ec784989f74889fb0fb687200b000088442428'),
    ('read_leaf_fast', 'owned', 0x4fbd4c7, '660f2e0541bb49fb757881bb2801000000ca9a3b4c897c2470757e488b83000b00004c8b702848c7c0f0fffffff0480fc183a80600004883e0f24531e4e9b8010000'),
    ('read_leaf_slow_word', 'owned', 0x4fbd5c4, '488b83000b0000488b40284889442450'),
    ('read_leaf_slow_join', 'owned', 0x4fbd6a0, '4c8b742450448b64244448c7c0f0ffffff488d8ba8060000f0480fc1014883e0f24883f8120f845e010000'),
    ('read_leaf_return', 'owned', 0x4fbd817, '4c89f04883c4785b415c415d415e415f5dc3'),
    ('read_wrapper_call', 'owned', 0x4f0f1d3, '488bb424d80000004c89f7e82de20a004889c3488dbc2480000000e85de7fbff4889d8'),
    ('location_reference', 'context', 0x3c1352f, '488d1572328602'),
    ('constructor_input_save', 'context', 0x5a6c01b, '89d54989f64889fb'),
    ('constructor_expand_boundary', 'context', 0x5a6c045, '488dbc2440120000488d9424b00200004889dee8d3dfb7ffbfc8420000ff151834a7004885c00f84250600004989c7488db424401200004c8b2d8534a700bac84200004889c741ffd54c8da42440120000ba700b00004c89e74c89f641ffd54c89ff4c89e6e8810da2ff'),
    ('drain_unwind', 'owned', 0x5a8b373, '4889c3be280000004c89ffeb224889c34d85e474274c89ff4c89e6eb124889c3488b7424084885f67412488b7c241031d2ff15f640a500eb034889c3488dbc2480000000e8c454fcffeb0d4889c3488d7c2428e8454ffcff4889dfe87d569600ff15e740a500'),
    ('read_leaf_lock_acquire', 'owned', 0x4fbd43f, '4c8daba8060000488b83a806000089c183e108c1e9034883f8f00f93c208ca74124c89ef31f6b900ca9a3bff15683b5201eb0c488d4810f0490fb14d0075e2'),
    ('read_leaf_wake', 'owned', 0x4fbd829, '488dbba8060000ff15b2375201e990feffff'),
    ('read_leaf_unwind', 'owned', 0x4fbd8a8, 'eb004889c348c7c0f0ffffff488b4c2448f0480fc1014883e0f24883f8127531488b7c2448ff1515375201eb24ff15e51b520148c7c1f0ffffff488b542448f0480fc10a4889c34883e1f24883f91274084889dfe84f314301488b7c2448ff15dc365201ebebff15ac1b5201'),
]

# The operands are decoded only from the indicated, byte-pinned instruction forms.
# Labels describe selected raw offsets, not recovered Rust types.
OPERANDS = [
    ('context_saved_stack', 0x5a6c10a, '4c89b424', 4),
    ('context_base_stack', 0x5a6c122, '4c8db424', 4),
    ('context_prefix_copy', 0x5a6c132, 'ba', 4),
    ('context_full_copy', 0x5a6c1cc, 'ba', 4),
    ('assemble_length_from_caller', 0x5a6c214, 'b9', 4),
    ('assemble_lock_stack', 0x567bd70, '48c78424', 4),
    ('assemble_input_stack', 0x567bd7c, '488dbc24', 4),
    ('assemble_input_length', 0x567bd84, 'ba', 4),
    ('assemble_output_offset', 0x567c0c7, '498dbd', 4),
    ('assemble_copy_stack', 0x567c0ce, '488db424', 4),
    ('assemble_copy_length', 0x567c0dd, 'ba', 4),
    ('transform_b_output_length', 0x567bcf2, 'ba', 4),
    ('transform_a_output_length', 0x567bbc9, 'ba', 4),
    ('wrapper_body_stack', 0x5a6c2d6, '4c8da424', 4),
    ('wrapper_body_length', 0x5a6c2de, 'ba', 4),
    ('wrapper_allocation_length', 0x5a6c2ec, 'bf', 4),
    ('wrapper_allocation_copy', 0x5a6c30b, 'ba', 4),
    ('staging_owner_stack', 0x2cb7e1f, '4c89a424', 4),
    ('staging_source_stack', 0x2cb7e6c, '488db424', 4),
    ('staging_dest_stack', 0x2cb7e74, '4c8dbc24', 4),
    ('staging_length', 0x2cb7e7c, 'ba', 4),
    ('intermediate_a_dest_stack', 0x2cb7ffe, '488dbc24', 4),
    ('intermediate_a_length', 0x2cb8006, 'ba', 4),
    ('intermediate_b_dest_stack', 0x2cb8039, '488dbc24', 4),
    ('intermediate_b_source_stack', 0x2cb8041, '488db424', 4),
    ('intermediate_b_length', 0x2cb8049, 'ba', 4),
    ('future_copy_dest', 0x2cb806f, '488dbb', 4),
    ('future_copy_source_stack', 0x2cb8076, '488db424', 4),
    ('future_copy_length', 0x2cb807e, 'ba', 4),
    ('future_copy_base', 0x2cb97aa, '488db3', 4),
    ('closure_stack', 0x2cb97ce, '488dbc24', 4),
    ('closure_copy_length', 0x2cb97d6, 'ba', 4),
    ('closure_allocation', 0x2cb984d, 'bf', 4),
    ('closure_allocation_source', 0x2cb9864, '488db424', 4),
    ('closure_allocation_copy', 0x2cb986c, 'ba', 4),
    ('serializer_height_adjust_byte', 0x4d6d7c6, '4883eb', 1),
    ('roll_multiplier', 0x595a6e1, '48b9', 8),
    ('roll_shift', 0x595a6f1, '48c1ea', 1),
    ('roll_multiple', 0x595a6f5, '4c69f2', 4),
    ('field_one_length', 0x4d6d783, 'ba', 4),
    ('field_two_length', 0x4d6d7b0, 'ba', 4),
    ('field_three_length', 0x4d6d7d6, 'ba', 4),
    ('drain_sentinel', 0x5a8b140, '49bd', 8),
    ('drain_pending_offset', 0x5a8b14a, '488b87', 4),
    ('drain_sentinel_store_offset', 0x5a8b151, '4c89af', 4),
    ('drain_owner_slot', 0x5a8b1a8, '488bbf', 4),
    ('drain_body_adjustment', 0x5a8b1af, '488d77', 1),
    ('drain_record_base_stack', 0x5a8b28d, '488dbc24', 4),
    ('drain_tag_stack', 0x5a8b248, 'c68424', 4),
    ('drain_tag_value', 0x5a8b24f, '', 1),
    ('drain_height_stack', 0x5a8b250, '4c89b424', 4),
    ('drain_sink_base', 0x5a8b316, '4881c3', 4),
    ('read_leaf_state_slot_fast', 0x4fbd4e2, '488b83', 4),
    ('read_leaf_state_field_fast', 0x4fbd4e9, '4c8b70', 1),
    ('read_leaf_state_slot_slow', 0x4fbd5c4, '488b83', 4),
    ('read_leaf_state_field_slow', 0x4fbd5cb, '488b40', 1),
    ('serializer_resps_offset', 0x4d6d7a0, '488d4b', 1),
]

# These are selected instruction starts, checked against the containing pin.
# No scan of unaligned instruction candidates is used as a caller census.
BRANCHES = [
    ('assemble_nonnegative_size', 0x567bd92, 0x567bda4),
    ('assemble_empty_size', 0x567bda4, 0x567be00),
    ('assemble_first_alloc_failure', 0x567bdb2, 0x567c1a3),
    ('assemble_second_alloc_failure', 0x567bde6, 0x567c1ad),
    ('transform_b_special', 0x567bc90, 0x567bcdb),
    ('closure_alloc_failure', 0x2cb985b, 0x2cb9de8),
    ('sink_disabled', 0x595a6c7, 0x595ab6c),
    ('sink_no_roll', 0x595a700, 0x595ab27),
    ('sink_failure', 0x595a741, 0x595ab7e),
    ('sink_no_cleanup', 0x595ab5b, 0x595ab6c),
    ('encoder_alloc_failure', 0x50e2fa2, 0x50e30c4),
    ('encoder_serializer_ok', 0x50e2fd9, 0x50e2ff3),
    ('encoder_writer_path', 0x50e3002, 0x50e304e),
    ('encoder_grow', 0x50e3079, 0x50e30a0),
    ('serializer_field_one_error', 0x4d6d793, 0x4d6d834),
    ('serializer_field_two_error', 0x4d6d7bd, 0x4d6d834),
    ('serializer_field_three_error', 0x4d6d7e6, 0x4d6d834),
    ('serializer_close_grow', 0x4d6d807, 0x4d6d868),
    ('buffer_fallback', 0x14c381c, 0x14c3879),
    ('buffer_no_flush', 0x14c3847, 0x14c386a),
    ('buffer_no_error', 0x14c388b, 0x14c3838),
    ('cleanup_owner_shared', 0x2aaea5d, 0x2aaea6c),
    ('cleanup_second_owner_shared', 0x2aaea77, 0x2aaea86),
    ('cleanup_pending_sentinel', 0x2aaeafd, 0x2aaeb73),
    ('drain_absent_sentinel', 0x5a8b15e, 0x5a8b350),
    ('drain_first_alloc_failure', 0x5a8b266, 0x5a8b361),
    ('drain_first_encoding_success', 0x5a8b2a5, 0x5a8b2c0),
    ('drain_first_error_empty', 0x5a8b2af, 0x5a8b2cf),
    ('drain_first_buffer_usable', 0x5a8b2cd, 0x5a8b316),
    ('drain_error_variant', 0x5a8b2d6, 0x5a8b2f4),
    ('drain_error_nonzero', 0x5a8b2db, 0x5a8b2fd),
    ('drain_temporary_empty', 0x5a8b333, 0x5a8b343),
    ('read_wrapper_uninstrumented', 0x4f0e9ad, 0x4f0ea05),
    ('read_leaf_slow_path', 0x4fbd4e0, 0x4fbd560),
    ('read_leaf_lock_wake', 0x4fbd6c5, 0x4fbd829),
    ('read_leaf_try_fast_lock', 0x4fbd45e, 0x4fbd472),
    ('read_leaf_retry_slow_lock', 0x4fbd47c, 0x4fbd460),
    ('read_leaf_unwind_no_wake', 0x4fbd8c6, 0x4fbd8f9),
    ('read_leaf_unwind_wake', 0x4fbd8f7, 0x4fbd901),
    ('drain_unwind_empty_buffer_a', 0x5a8b386, 0x5a8b3af),
    ('drain_unwind_empty_buffer_b', 0x5a8b39b, 0x5a8b3af),
]

# Direct and RIP-slot calls; slots are additionally checked against .rela.dyn.
CALLS = [
    ('assemble_context', 0x5a6c21c, 0x567bd50),
    ('transform_b', 0x5a6c25d, 0x567bc40),
    ('transform_a', 0x5a6c29e, 0x567bb70),
    ('capture_context_copy', 0x2cb97db, 0x64df508),
    ('closure_heap_copy', 0x2cb9874, 0x64df508),
    ('closure_dispatch_boundary', 0x2cb9890, 0x64e1750),
    ('sink_encoder', 0x595ab43, 0x50e2f80),
    ('sink_flush', 0x595ab53, 0x1533e80),
    ('encode_record', 0x50e2fce, 0x4d6d740),
    ('encoded_sink', 0x50e3090, 0x14c37f0),
    ('record_field_one', 0x4d6d78b, 0x50818f0),
    ('record_field_two', 0x4d6d7b5, 0x506e230),
    ('record_field_three', 0x4d6d7de, 0x5077210),
    ('buffer_memcpy', 0x14c382b, 0x64df508),
    ('buffer_fallback_call', 0x14c3882, 0x64e0010),
    ('callback_normal_cleanup', 0x2a929c3, 0x2aaea40),
    ('callback_unwind_cleanup', 0x2a929d6, 0x2aaea40),
    ('callback_unwind_resume', 0x2a929de, 0x63f0a50),
    ('cleanup_drain', 0x2aaea4c, 0x64e72a0),
    ('drain_read_height', 0x5a8b1f2, 0x4f0e990),
    ('height_read_tail', 0x4f0ea1c, 0x4fbd410),
    ('height_read_instrumented', 0x4f0f1de, 0x4fbd410),
    ('drain_first_encode', 0x5a8b29a, 0x4d6d740),
    ('drain_sink', 0x5a8b32b, 0x595a6b0),
    ('drain_record_cleanup', 0x5a8b34b, 0x5a50880),
    ('drain_unwind_record_cleanup', 0x5a8b3b7, 0x5a50880),
    ('drain_unwind_saved_cleanup', 0x5a8b3c6, 0x5a50310),
    ('drain_resume_unwind', 0x5a8b3ce, 0x63f0a50),
    ('read_leaf_resume_unwind', 0x4fbd8fc, 0x63f0a50),
]

RELOCATION_EXPECTATIONS = {
    0x64471a0: (8, 0, 0x2a93c50),
    0x64471b8: (8, 0, 0x2a92960),
    0x64767a8: (8, 0, 0x443168),
    0x64df480: (8, 0, 0x6355830),
    0x64df490: (8, 0, 0x141e251),
    0x64df498: (8, 0, 0x141e264),
    0x64df4a0: (8, 0, 0x635de30),
    0x64df508: (6, 7, 0),
    0x64df770: (8, 0, 0x1680bd0),
    0x64e0008: (8, 0, 0x154ce40),
    0x64e0010: (8, 0, 0x1533d60),
    0x64e0990: (8, 0, 0x1629690),
    0x64e1750: (8, 0, 0x15d63c0),
    0x64e72a0: (8, 0, 0x5a8b130),
}

LITERALS = [
    ('closure_label', 0x60f021, 25, 'node handle client blocks'),
    ('field_one', 0x916931, 10, 'abci_block'),
    ('field_two', 0x91693b, 5, 'resps'),
    ('field_three', 0x9160f9, 6, 'height'),
    ('crash_height_label', 0x93bcb4, 12, 'crash_height'),
]


def check_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target size or SHA-256 mismatch')


def file_mapping(sec_rows, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or length')
    matches = [s for s in sec_rows if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address does not have one file-backed section')
    section = matches[0]
    return section['offset'] + va - section['address'], section['name']


def read_va(data, sec_rows, va, size, executable=False):
    off, _ = file_mapping(sec_rows, va, size, executable)
    if off < 0 or off + size > len(data):
        raise ValueError('file-backed range exceeds input')
    return data[off:off + size]


def instruction_scope(va, length):
    return ('selected' if any(start <= va and va + length <= end
                              for _, start, end in FUNCTIONS) else 'context')


def unique_section(sec_rows, name, typ=None):
    matches = [s for s in sec_rows if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicated, or NOBITS section: ' + name)
    if typ is not None and matches[0]['type'] != typ:
        raise ValueError('unexpected section type: ' + name)
    return matches[0]


def selected_fdes(frame_rows, header_rows, specs=FUNCTIONS):
    found = []
    for label, start, end in specs:
        candidates = [r for r in frame_rows if r['start'] == start]
        headers = [r for r in header_rows if r['start'] == start]
        if len(candidates) != 1 or len(headers) != 1:
            raise ValueError('missing or ambiguous selected FDE: ' + label)
        row, header = candidates[0], headers[0]
        if row['end'] != end or row['fde'] != header['fde']:
            raise ValueError('FDE extent or header mismatch: ' + label)
        if any(other is not row and other['start'] < end and start < other['end']
               for other in frame_rows):
            raise ValueError('overlapping selected FDE: ' + label)
        found.append((label, row, header))
    return found


def validate_window(read, label, va, expected):
    expected_bytes = bytes.fromhex(expected)
    actual = read(va, len(expected_bytes), True)
    if actual != expected_bytes:
        raise ValueError('instruction window mismatch: ' + label)
    return actual


def pinned_read(read, va, size):
    if not any(start <= va and va + size <= start + len(bytes.fromhex(hx))
               for _, _, start, hx in PINS):
        raise ValueError('operand outside pinned windows')
    return read(va, size, True)


def operand_value(read, va, prefix, width):
    marker = bytes.fromhex(prefix)
    if width not in (1, 4, 8):
        raise ValueError('unsupported operand width')
    raw = pinned_read(read, va, len(marker) + width)
    if raw[:len(marker)] != marker:
        raise ValueError('operand opcode mismatch')
    return int.from_bytes(raw[len(marker):], 'little')


def relative_target(read, va, branch=False):
    prefix = pinned_read(read, va, 1)[0]
    if prefix == 0x0f:
        raw = pinned_read(read, va, 6)
        if not branch or not 0x80 <= raw[1] <= 0x8f:
            raise ValueError('unsupported long branch')
        size, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
    elif 0x70 <= prefix <= 0x7f:
        if not branch:
            raise ValueError('unexpected short branch')
        raw = pinned_read(read, va, 2)
        size, displacement = 2, struct.unpack_from('<b', raw, 1)[0]
    elif prefix in (0xe8, 0xe9):
        if branch:
            raise ValueError('unexpected call')
        raw = pinned_read(read, va, 5)
        size, displacement = 5, struct.unpack_from('<i', raw, 1)[0]
    elif prefix == 0xff:
        if branch:
            raise ValueError('unexpected indirect call')
        raw = pinned_read(read, va, 6)
        if raw[:2] != b'\xff\x15':
            raise ValueError('unsupported indirect call')
        size, displacement = 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported transfer form')
    return va + size + displacement, raw


def parse_relocations(data, sec_rows, wanted=RELOCATION_EXPECTATIONS):
    sec = unique_section(sec_rows, '.rela.dyn', 4)
    if sec['size'] % 24:
        raise ValueError('truncated relocation table')
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        if slot in result:
            raise ValueError('duplicate selected relocation')
        result[slot] = {'type': info & 0xffffffff, 'symbol': info >> 32,
                        'addend': addend, 'file_offset': off}
    for slot, (typ, sym, addend) in wanted.items():
        row = result.get(slot)
        if row is None or (row['type'], row['symbol'], row['addend']) != (typ, sym, addend):
            raise ValueError('missing or altered selected relocation')
    return result


def lsda_sites(data, sec_rows, start, end, lsda):
    """Decode the selected ULEB call-site tables, leaving action types unresolved."""
    section = unique_section(sec_rows, '.gcc_except_table')
    off, name = file_mapping(sec_rows, lsda, 1)
    limit = section['offset'] + section['size']
    if name != '.gcc_except_table' or limit > len(data):
        raise ValueError('LSDA is not in the file-backed exception table')
    pos = off
    if data[pos] != 0xff:
        raise ValueError('unsupported explicit LSDA base')
    pos += 1
    if pos >= limit:
        raise ValueError('truncated LSDA header')
    type_encoding = data[pos]
    pos += 1
    type_table = None
    if type_encoding == 0x9b:
        type_offset, pos = uleb(data, pos, limit)
        if type_offset > limit - pos:
            raise ValueError('LSDA type table outside section')
        type_table = pos + type_offset
    elif type_encoding != 0xff:
        raise ValueError('unsupported LSDA type encoding')
    if pos >= limit or data[pos] != 0x01:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, limit)
    if size > limit - pos:
        raise ValueError('LSDA call-site table outside section')
    table_end = pos + size
    if type_table is not None and table_end > type_table:
        raise ValueError('LSDA call-site table overlaps type table')
    sites = []
    prior_end = start
    while pos < table_end:
        entry_off = pos
        begin, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        site_start, site_end = start + begin, start + begin + length
        target = start + landing if landing else None
        if site_start < prior_end or site_end > end or (target is not None and not start <= target < end):
            raise ValueError('invalid or overlapping LSDA call-site range')
        sites.append((entry_off, site_start, site_end, target, action))
        prior_end = site_end
    return sites


def symbol_name(data, sec_rows, index):
    syms = unique_section(sec_rows, '.dynsym', 11)
    names = unique_section(sec_rows, '.dynstr', 3)
    if syms['size'] % 24 or not 0 <= index < syms['size'] // 24:
        raise ValueError('invalid dynamic symbol index')
    name_offset = struct.unpack_from('<I', data, syms['offset'] + index * 24)[0]
    if name_offset >= names['size']:
        raise ValueError('invalid symbol name offset')
    start = names['offset'] + name_offset
    end = data.find(b'\0', start, names['offset'] + names['size'])
    if end < 0:
        raise ValueError('unterminated symbol name')
    return data[start:end].decode('ascii')


def take_pending(word):
    if not 0 <= word <= MASK64:
        raise ValueError('word outside unsigned 64-bit range')
    return 1 << 63, word != 1 << 63


def roll_bucket(word, multiplier, shift, step):
    if not 0 <= word <= MASK64:
        raise ValueError('word outside unsigned 64-bit range')
    previous = word - int(word != 0)
    return ((previous * multiplier) >> (64 + shift)) * step


def sink_admission(flag_word, word, previous_bucket, multiplier, shift, step):
    if not 0 <= flag_word <= MASK64 or not 0 <= previous_bucket <= MASK64:
        raise ValueError('word outside unsigned 64-bit range')
    if flag_word == 1 << 63:
        return 'disabled', None
    bucket = roll_bucket(word, multiplier, shift, step)
    return ('roll' if bucket > previous_bucket else 'append'), bucket


def buffer_route(capacity, used, length):
    if not (0 <= used <= capacity <= MASK64 and 0 <= length <= MASK64):
        raise ValueError('invalid buffered range')
    return 'copy' if length < capacity - used else 'fallback'


def rip_lea(read, va):
    raw = pinned_read(read, va, 7)
    if raw[:3] not in (b'\x48\x8d\x0d', b'\x48\x8d\x15', b'\x48\x8d\x35'):
        raise ValueError('unsupported selected RIP-relative LEA')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def json_text(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def tsv_text(columns, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    writer.writerows(rows)
    return out.getvalue()


def analyze(data):
    check_identity(data)
    sec_rows, headers = unwind_index(data)
    for name in ('.text', '.rela.dyn', '.dynsym', '.dynstr', '.eh_frame', '.eh_frame_hdr'):
        unique_section(sec_rows, name)
    _, frame_rows = eh_frame_records(data, sec_rows)
    chosen = selected_fdes(frame_rows, headers)
    read = lambda va, size, executable=False: read_va(data, sec_rows, va, size, executable)

    functions = []
    for label, row, hdr in chosen:
        start, end = row['start'], row['end']
        off, name = file_mapping(sec_rows, start, end - start, True)
        body = read(start, end - start, True)
        functions.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                          'file_offset': hex(off), 'section': name, 'length': len(body),
                          'fde_va': hex(row['fde']), 'cie_va': hex(row['cie']),
                          'lsda_va': None if row['lsda'] is None else hex(row['lsda']),
                          'unwind_index': hdr['index'], 'body_sha256': hashlib.sha256(body).hexdigest(),
                          'body_hex': body.hex()})

    landing_rows = []
    for label, row, _ in chosen:
        if row['lsda'] is None:
            continue
        for entry_off, begin, end, landing, action in lsda_sites(
                data, sec_rows, row['start'], row['end'], row['lsda']):
            landing_rows.append([label, hex(row['lsda']), hex(entry_off), hex(begin), hex(end),
                                 '' if landing is None else hex(landing), action])
    callback_entries = [r for r in landing_rows if r[0] == 'callback_adapter' and
                        int(r[3], 16) <= 0x2a929ba < int(r[4], 16)]
    if len(callback_entries) != 1 or callback_entries[0][5] != '0x2a929d0':
        raise ValueError('callback cleanup landing mismatch')
    for call_va, expected in ((0x5a8b1f2, 0x5a8b3be), (0x5a8b29a, 0x5a8b390),
                              (0x5a8b32b, 0x5a8b380)):
        matches = [r for r in landing_rows if r[0] == 'pending_drain' and
                   int(r[3], 16) <= call_va < int(r[4], 16)]
        if len(matches) != 1 or matches[0][5] != hex(expected):
            raise ValueError('pending drain cleanup landing mismatch')

    windows = []
    seen_labels = set()
    for label, role, va, hx in PINS:
        if label in seen_labels:
            raise ValueError('duplicate window label')
        seen_labels.add(label)
        raw = validate_window(read, label, va, hx)
        owners = [name for name, start, end in FUNCTIONS if start <= va and va + len(raw) <= end]
        if role == 'owned' and len(owners) != 1:
            raise ValueError('owned window outside its selected FDE')
        if role == 'context' and owners:
            raise ValueError('context window unexpectedly in selected FDE')
        off, section = file_mapping(sec_rows, va, len(raw), True)
        windows.append([label, role, hex(va), hex(off), section, len(raw), raw.hex(),
                        owners[0] if owners else 'prior-boundary-context'])

    operands = {}
    operand_rows = []
    for label, va, prefix, width in OPERANDS:
        value = operand_value(read, va, prefix, width)
        operands[label] = value
        operand_rows.append([label, instruction_scope(va, len(bytes.fromhex(prefix)) + width),
                             hex(va), hex(file_mapping(sec_rows, va, len(bytes.fromhex(prefix)) + width, True)[0]),
                             prefix, width, hex(value)])

    branches = []
    for label, va, wanted in BRANCHES:
        target, raw = relative_target(read, va, branch=True)
        if target != wanted:
            raise ValueError('unexpected selected branch target: ' + label)
        branches.append([label, instruction_scope(va, len(raw)), hex(va), hex(file_mapping(sec_rows, va, len(raw), True)[0]),
                         raw.hex(), hex(target)])

    relocs = parse_relocations(data, sec_rows)
    if symbol_name(data, sec_rows, relocs[0x64df508]['symbol']) != 'memcpy':
        raise ValueError('unexpected imported copy symbol')
    calls = []
    for label, va, wanted in CALLS:
        target, raw = relative_target(read, va)
        if target != wanted:
            raise ValueError('unexpected selected call target: ' + label)
        slot = raw[:2] == b'\xff\x15'
        resolved = ''
        if slot:
            if target not in relocs:
                raise ValueError('unrecorded selected indirect slot')
            relocation = relocs[target]
            resolved = (hex(relocation['addend']) if relocation['type'] == 8 else
                        'dynamic:' + symbol_name(data, sec_rows, relocation['symbol']))
        calls.append([label, instruction_scope(va, len(raw)), hex(va), hex(file_mapping(sec_rows, va, len(raw), True)[0]), raw.hex(),
                      'rip-slot' if slot else ('rel32-jump' if raw[0] == 0xe9 else 'rel32-call'), hex(target), resolved])

    reloc_rows = [['anchor-only', hex(slot), hex(row['file_offset']), row['type'], row['symbol'], hex(row['addend']),
                   symbol_name(data, sec_rows, row['symbol']) if row['type'] == 6 else '']
                  for slot, row in sorted(relocs.items())]

    literal_rows = []
    for label, va, size, expected in LITERALS:
        b = read(va, size)
        if b.decode('ascii') != expected:
            raise ValueError('literal mismatch: ' + label)
        literal_rows.append([label, hex(va), hex(file_mapping(sec_rows, va, size)[0]), size, b.hex(), expected])
    for label, lea, length_label, expected_va in (
            ('field_one', 0x4d6d777, 'field_one_length', 0x916931),
            ('field_two', 0x4d6d7a4, 'field_two_length', 0x91693b),
            ('field_three', 0x4d6d7ca, 'field_three_length', 0x9160f9)):
        if rip_lea(read, lea) != expected_va or operands[length_label] != next(x[2] for x in LITERALS if x[0] == label):
            raise ValueError('literal reference mismatch: ' + label)

    descriptor = 0x64471a0
    descriptor_bytes = read(descriptor, 32)
    null_pointer, size, align, null_callback = struct.unpack('<QQQQ', descriptor_bytes)
    if null_pointer or null_callback or size != operands['closure_allocation'] or align != 8:
        raise ValueError('closure descriptor framing mismatch')
    if rip_lea(read, 0x2cb9881) != descriptor:
        raise ValueError('closure descriptor reference mismatch')
    if relocs[descriptor + 24]['addend'] != 0x2a92960:
        raise ValueError('callback relocation mismatch')

    location = 0x64767a8
    if rip_lea(read, 0x3c1352f) != location:
        raise ValueError('prior source Location reference mismatch')
    file_length, line, column = struct.unpack('<QII', read(location + 8, 16))
    file_va = relocs[location]['addend']
    source_path = read(file_va, file_length).decode('ascii')
    if (source_path, line, column) != ('l1/src/abci/state.rs', 123, 37):
        raise ValueError('prior source Location mismatch')

    o = operands
    context_pointer = o['context_saved_stack'] - o['context_base_stack']
    assemble_delta = o['assemble_input_stack'] - o['assemble_copy_stack']
    owner_context = o['assemble_output_offset'] + assemble_delta
    owner_state = owner_context + context_pointer
    wrapper_header = o['wrapper_body_stack'] - o['context_base_stack']
    relative_owner = o['staging_owner_stack'] - o['staging_source_stack']
    future_owner = o['future_copy_dest'] + relative_owner
    closure_owner = future_owner - o['future_copy_base']
    serializer_height_offset = o['drain_height_stack'] - o['drain_record_base_stack']
    serializer_tag_offset = o['drain_tag_stack'] - o['drain_record_base_stack']
    checks = [
        o['assemble_length_from_caller'] == 16,
        context_pointer == o['context_prefix_copy'],
        o['context_full_copy'] == o['assemble_input_length'],
        o['assemble_lock_stack'] == o['assemble_copy_stack'],
        assemble_delta + o['assemble_input_length'] == o['assemble_copy_length'],
        context_pointer + 8 <= o['assemble_input_length'],
        owner_state + 8 <= o['transform_a_output_length'],
        o['transform_a_output_length'] == o['transform_b_output_length'] == o['wrapper_body_length'],
        wrapper_header + o['wrapper_body_length'] == o['wrapper_allocation_length'] == o['wrapper_allocation_copy'],
        0 <= relative_owner and relative_owner + 8 <= o['staging_length'],
        o['staging_dest_stack'] + relative_owner + 8 <= o['staging_dest_stack'] + o['intermediate_a_length'],
        o['intermediate_a_dest_stack'] == o['intermediate_b_source_stack'],
        o['intermediate_a_length'] == o['intermediate_b_length'],
        o['intermediate_b_dest_stack'] == o['future_copy_source_stack'],
        relative_owner + 8 <= o['future_copy_length'],
        0 <= closure_owner and closure_owner + 8 <= o['closure_copy_length'],
        o['closure_stack'] == o['closure_allocation_source'],
        o['closure_copy_length'] <= o['closure_allocation_copy'] == o['closure_allocation'],
        closure_owner == o['drain_owner_slot'],
        wrapper_header == o['drain_body_adjustment'],
        o['read_leaf_state_slot_fast'] == o['read_leaf_state_slot_slow'] == owner_state,
        o['read_leaf_state_field_fast'] == o['read_leaf_state_field_slow'],
        o['drain_sentinel'] == 1 << 63,
        o['drain_pending_offset'] == o['drain_sentinel_store_offset'],
        serializer_tag_offset == o['serializer_resps_offset'],
        o['drain_tag_value'] == 2,
        serializer_height_offset == 256 - o['serializer_height_adjust_byte'],
    ]
    if not all(checks):
        raise ValueError('selected pointer-flow relation does not hold')

    m, shift, step = o['roll_multiplier'], o['roll_shift'], o['roll_multiple']
    error = m * step - (1 << (64 + shift))
    if step != 10000 or not 0 < error < (1 << shift):
        raise ValueError('unexpected unsigned bucket constants')
    if read(0x4d6d760, 4, True)[-1] != 0x7b or read(0x4d6d80d, 4, True)[-1] != 0x7d:
        raise ValueError('unexpected serializer framing')
    if read(0x50e307b, 4, True)[-1] != 0x0a:
        raise ValueError('unexpected record terminator')

    layout = {
        'assembler_input_length_from_caller': o['assemble_length_from_caller'],
        'context_pointer_offset': hex(context_pointer),
        'assembler_context_offset': hex(owner_context),
        'assembler_state_pointer_offset': hex(owner_state),
        'constructor_header_bytes': wrapper_header,
        'staged_owner_offset': hex(relative_owner),
        'future_owner_offset': hex(future_owner),
        'closure_owner_offset': hex(closure_owner),
        'drain_owner_offset': hex(o['drain_owner_slot']),
        'drain_body_adjustment': o['drain_body_adjustment'],
        'read_state_word_offset': hex(o['read_leaf_state_field_fast']),
        'drain_pending_offset': hex(o['drain_pending_offset']),
        'drain_sink_offset': hex(o['drain_sink_base']),
        'serializer_resps_offset': hex(serializer_tag_offset),
        'serializer_resps_tag': o['drain_tag_value'],
        'serializer_height_offset': hex(serializer_height_offset),
        'callback_descriptor_va': hex(descriptor),
        'callback_slot_va': hex(descriptor + 24),
        'callback_target_va': hex(relocs[descriptor + 24]['addend']),
        'callback_payload_size': size,
        'callback_payload_alignment': align,
        'inference_conditions': ['selected paths and normal helper returns',
                                 'copy import preserves the indicated bytes',
                                 'intervening helper calls and aliases do not modify the indicated pointer slots',
                                 'the runtime dispatcher invokes the selected descriptor callback'],
    }
    arithmetic = {
        'word_bits': 64,
        'drain_empty_sentinel': hex(o['drain_sentinel']),
        'roll_multiplier': hex(m),
        'roll_shift_after_high_half': shift,
        'roll_bucket_step': step,
        'roll_reciprocal_error': error,
        'roll_reciprocal_error_bound': 1 << shift,
        'serializer_open_byte': 0x7b,
        'serializer_close_byte': 0x7d,
        'record_newline_byte': 0x0a,
    }
    location_record = {'role': 'prior-boundary-context', 'location_va': hex(location),
                       'file_offset': hex(file_mapping(sec_rows, location, 24)[0]),
                       'path_va': hex(file_va), 'path_length': file_length,
                       'source_path': source_path, 'line': line, 'column': column}
    summary = {'target': 'node-115', 'target_sha256': SHA256,
               'coordinate_system': 'linked ELF virtual addresses before rebasing',
               'selected_fdes': len(functions), 'selected_windows': len(windows),
               'owned_windows': sum(x[1] == 'owned' for x in windows),
               'context_windows': sum(x[1] == 'context' for x in windows),
               'selected_branches': len(branches), 'selected_calls': len(calls),
               'selected_lsda_call_sites': len(landing_rows),
               'selected_operands': len(operand_rows), 'selected_relocations': len(reloc_rows),
               'selected_literals': len(literal_rows),
               'limitations': 'Curated static records only; not a function census or a runtime trace.'}
    outputs = {
        'functions.json': json_text(functions),
        'windows.tsv': tsv_text(['label', 'ownership', 'va', 'file_offset', 'section', 'length', 'bytes_hex', 'scope'], windows),
        'operands.tsv': tsv_text(['label', 'ownership', 'va', 'file_offset', 'opcode_prefix_hex', 'width', 'value'], operand_rows),
        'branches.tsv': tsv_text(['label', 'ownership', 'va', 'file_offset', 'bytes_hex', 'target_va'], branches),
        'landings.tsv': tsv_text(['function', 'lsda_va', 'entry_file_offset', 'start_va', 'end_va_exclusive', 'landing_va', 'action_raw'], landing_rows),
        'calls.tsv': tsv_text(['label', 'ownership', 'va', 'file_offset', 'bytes_hex', 'form', 'target_or_slot_va', 'relocation_target'], calls),
        'relocations.tsv': tsv_text(['ownership', 'slot_va', 'entry_file_offset', 'type', 'symbol_index', 'addend', 'symbol_name'], reloc_rows),
        'literals.tsv': tsv_text(['label', 'va', 'file_offset', 'length', 'bytes_hex', 'ascii'], literal_rows),
        'layout.json': json_text(layout),
        'arithmetic.json': json_text(arithmetic),
        'location.json': json_text(location_record),
        'summary.json': json_text(summary),
    }
    return outputs


def generate(binary, output):
    # Authenticate and finish all validation before creating an output directory.
    result = analyze(Path(binary).read_bytes())
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(result.items()):
        (out / name).write_text(content, encoding='utf-8', newline='')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    generate(TARGET, args.out)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('abci_context_result115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
