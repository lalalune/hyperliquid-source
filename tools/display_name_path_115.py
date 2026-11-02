#!/usr/bin/env python3
"""Reproduce selected node 115 setDisplayName static evidence from ELF bytes.

This is a bounded verifier, not an x86 disassembler or a target emulator.  It
checks pinned instruction windows and decodes only specified rel32/rel8 branch
forms, RIP-relative operands and ELF records used by this path.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Roles are deliberately descriptive rather than asserted source symbols.
FUNCTIONS = (
    ('action_router', 0x2bda7c0),
    ('direct_display_handler', 0x2c08600),
    ('outer_caller', 0x2c12690),
    ('initial_identity_helper', 0x2a8ab70),
    ('action_classifier', 0x36c30f0),
    ('action_selector', 0x2bdb5b0),
    ('first_gate', 0x2c202b0),
    ('second_gate', 0x2c206b0),
    ('empty_iterator_helper', 0x2443a40),
    ('formatter', 0x2bc95f0),
    ('dispatcher', 0x2bdbaa0),
    ('display_wrapper', 0x2392200),
    ('display_core', 0x2c76380),
    ('tree_value_iterator', 0x23876e0),
    ('erase_helper', 0x2dcd870),
    ('upsert_helper', 0x2dbff30),
    ('key_search_helper', 0x24c9000),
    ('insert_helper_a', 0x24bda40),
    ('insert_helper_b', 0x26df210),
    ('erase_shift_helper', 0x24e4fb0),
    ('tree_erase_helper', 0x26e0c20),
    ('tree_insert_inner', 0x1cab5c0),
    ('tree_erase_inner', 0x1d5e1a0),
)

# Pinned windows make the branch interpretation reviewable and fail closed if
# any opcode or operand differs. Addresses are linked ELF virtual addresses.
WINDOWS = (
    ('router_entry', 0x2bda7c0, 0x2bda84c, '9caa34bef398b8f6e541cd91ab485fe6833959d46565e0a91c8f286f19ac1a48'),
    ('router_direct_arm', 0x2bdaf4c, 0x2bdaf66, 'f33e48a2064a377f22cf29535e90bc8108c258b515670d02a9518f89a2120dd6'),
    ('router_nested_arm', 0x2bdb07a, 0x2bdb094, '5c2de4ba1b554272957b3394f4a89e9ae1387538bde60ce9b396026a5dd6b84b'),
    ('direct_entry', 0x2c08600, 0x2c0866d, '93fe54e057dee2158167672dd68cc4a8d61ed67fe360db504a4fbcc26146bb9b'),
    ('direct_key1', 0x2c08775, 0x2c087ae, 'd28f7f783353dfc6e3b9e971eb16dc042b58841fcd3eb350d300882fd772914a'),
    ('direct_key2', 0x2c087f5, 0x2c0882d, '475027de693327d96db0b28955dc8f8be1f6c3e99fbabb0fd9169856a67b0a54'),
    ('direct_prior_reject', 0x2c0885a, 0x2c0886d, 'cf9ab854f828250f92f80d4588b44ad3b9d970c3d5416f3ac345cfa179ce17f3'),
    ('direct_gates_and_bound', 0x2c0886d, 0x2c08923, '23ec24f59a3c954256dccca7f50ccf5c9ded2dd6638ee23931dd27271be193c2'),
    ('direct_gate_failure', 0x2c08923, 0x2c08977, '7cfb00b6dab5dd979e5be745222eb3c821f723bd9c41ccefa07f7219d94b2345'),
    ('direct_copy_and_core', 0x2c089b7, 0x2c08a20, 'a36eb87b535be4d95f35f032435116728c9a84c705aa43dd808288309f3a1574'),
    ('direct_core_failure', 0x2c08a20, 0x2c08a74, '7cfb00b6dab5dd979e5be745222eb3c821f723bd9c41ccefa07f7219d94b2345'),
    ('direct_return', 0x2c08a71, 0x2c08a86, 'b566fbfceeac965ade560e3ce306cc63483689c7cb985af6dc5e2201d534d786'),
    ('caller_entry', 0x2c12690, 0x2c12705, 'e79d8eb1d7657bcbf7ff1d668c0ebd2f6473ae86df278c9388037f41d0f2504b'),
    ('caller_classification', 0x2c127a3, 0x2c127d1, '263e9653de1fea2eff722e31b62b8bb837b85405a10149367666736ffa806681'),
    ('caller_original_lookup', 0x2c12835, 0x2c1286d, '9dd14ffe088d0e4c4e0b97c316acbaccc5a5433267b88f48d42c00625d560e2b'),
    ('caller_resolved_lookup', 0x2c128c5, 0x2c128ff, '18cc17536d19d25b7c82f0b67664d7fd080fc93b4a2f9e9548109ee5f6a09388'),
    ('caller_blocked_result', 0x2c12a70, 0x2c12a86, 'e16ca4748908b4c8e9d891009ce6a9459b27eb69ad470b99a48fb42bbd660003'),
    ('caller_result_error_a', 0x2c12a01, 0x2c12a70, '8bbb31d233b67d1bafc28a3e5d6495ac472a300971869ae768d04a597ff86603'),
    ('caller_result_error_b', 0x2c12a86, 0x2c12ada, '7cfb00b6dab5dd979e5be745222eb3c821f723bd9c41ccefa07f7219d94b2345'),
    ('caller_result_error_c', 0x2c12b2e, 0x2c12b84, 'bf36e1007eac657148fe1bacf0385b3c9565bcd8885923530dbed14bd6382629'),
    ('caller_selector', 0x2c12944, 0x2c12969, '6d359a340cfa3ff7a17b629c4655ffba89b7c1940767c74a0f26d233465ee90c'),
    ('caller_gates_dispatch', 0x2c12983, 0x2c12a01, '5a2f0ac85e6a50ce57eade37c02680da092daa05ca9b94d44c2da31961d9f4bb'),
    ('classifier_entry', 0x36c30f0, 0x36c3116, '62e1f642d4f618a47efddd839c4c952dc5ef2b219a61d1bf2ac054668d4143fe'),
    ('selector_entry', 0x2bdb5b0, 0x2bdb5d9, 'a6ef0c73016d433fe486d0096a55cc975463bda7b7c19ce25c8e46aaad1caf52'),
    ('selector_empty', 0x2bdb5f5, 0x2bdb613, '9b41975f9856740bb291aa0b9ca0abbb70c55d10790d374a2a2302631614a346'),
    ('gate1_empty', 0x2c202c9, 0x2c202ee, '59897c28d1fa2aa36692cfdd230a4e90766e0a7263c8016cc261b813003680d5'),
    ('gate1_return', 0x2c2066d, 0x2c20687, '45d3f7329e2ac823c9b0aa003f54440c729f3c47f7974a2be83af794888e13da'),
    ('gate2_init', 0x2c206ca, 0x2c20791, '7a68a22c03a918b2523d2bc43a4a59722f1150fe15d028f594b9ec0cc4ec2a7d'),
    ('gate2_advance', 0x2c207b9, 0x2c207d2, 'fb807b597d9842a018a27868e90361fd3f419518f32f44d6dc1874c10e64eb80'),
    ('gate2_end', 0x2c208e0, 0x2c20900, 'f9725fe394f72ca205c05649e21e8305dc83633a8420483b021a2bffc770a50f'),
    ('gate2_success', 0x2c20944, 0x2c2095f, '2dd1f2a4cc5a3cc78e659ecb58fdc40d036c84ef9aeb3a5a43a7bf7cb893fc64'),
    ('iterator_entry', 0x2443a4b, 0x2443a5b, 'd153272775c0b3870913cd916daf7e917e31c8ea3e5265fbb410e6fb7c901421'),
    ('iterator_empty_a', 0x2443ae9, 0x2443b05, '3844850c2f64daba7496126929d6be23a2d14599ffaa5064f04bd5520e225dac'),
    ('iterator_empty_b', 0x2443b72, 0x2443b7f, '7ece1410813e4973e8042c5ed791745c763da7276ee7444ff9a01bad30186ab5'),
    ('dispatcher_args', 0x2bdbab1, 0x2bdbaf6, 'b4b51a5025567b3a6d25c1fb71aa29a5991212b06598c52d35c94cf5958186bf'),
    ('dispatcher_switch', 0x2bdbb0c, 0x2bdbb2f, 'd1bcdc14d339bc7777e9476b23424fdaeca1cda71685a956e45f7c32a65fe88f'),
    ('dispatcher_arm', 0x2bdc64d, 0x2bdc67a, 'b7b4e3ae3a93025d794054c8a7aa0547c9801cb1472b23920b00152c169987f0'),
    ('dispatcher_tail', 0x2bdc94e, 0x2bdca07, '1e91db0d58ee29a31487bd334d5b44b5077dc6f0c870b75925538fa06a8afe0f'),
    ('formatter_switch', 0x2bc95f4, 0x2bc9616, 'd69aad64affd830000480e9cf528caf473877897fa0e376b040bb49e11302582'),
    ('formatter_arm', 0x2bcb2d4, 0x2bcb33d, '3a7518410954be391f7237eaf16d1774d8a9543d9800bc05eab404bf9d85caf4'),
    ('formatter_multi_sig_arm', 0x2bcb7c7, 0x2bcb830, 'b6f1be0e8b38a8a56cf283cb84ab890ad77c94b92c5b35bb32a2e3c6cb3f422b'),
    ('wrapper_guard', 0x2392214, 0x2392232, '57c01241d62363e581d41dfc0ffe6389def59b9a46ed5b8d0d8431bcadfd1a7b'),
    ('wrapper_copy', 0x2392232, 0x239226e, 'd4d6999d3cf830e2456c36b538bc6a9d74031a00334a921590143b729546c204'),
    ('wrapper_call', 0x239226e, 0x23922a0, '3d64df05eafaef40d621965519807dbcdb074bed96e6520743945a1ad9c4431d'),
    ('wrapper_propagation', 0x23922a0, 0x23922fa, '164479ab052ad9b3d20a32ff2b5640527a556e81772462d8b4a057032bd29060'),
    ('wrapper_alloc_failure', 0x23922fa, 0x2392308, '04358c3521c2760613ae22740b3e447d1b7e819d4a19eec34a30728b62674cce'),
    ('core_bounds', 0x2c7639a, 0x2c763bb, '52778f1b56b03047950bb32283f1c6008344d151032d65a76539f5e185a1b069'),
    ('core_empty_remove', 0x2c76406, 0x2c76437, '3424feff9b9e7071ea28fb8102568ed11210c243eddb7655d62c812d49d05d5c'),
    ('core_return', 0x2c76433, 0x2c7644e, '5da2af31fce6f2261aa17e58b7de504690bae92a9156cc4db41a592267c1f393'),
    ('core_scan_a', 0x2c764fd, 0x2c76532, '1630509e225d49b8bf614634d2bbfa07ae325d0e2a66b27fb6bc4b4ae390ef33'),
    ('core_compare_a', 0x2c76572, 0x2c765a9, 'c922f0455111b9d12d0512a0bac5f46bebaf84d682f373b5c3b3cc660c734313'),
    ('core_compare_b', 0x2c76610, 0x2c76638, 'b7a6c29bcb725cfc2365c267f7f0f2553328ff870de70d0f11b018eb7274c055'),
    ('tree_value_iterator_entry', 0x23876e0, 0x2387727, 'ef1f211a03b55dee76a6ab762d82221266cfbf44afd7c4dbb39d23547407cfbf'),
    ('tree_value_iterator_yield', 0x23878a1, 0x23878ca, '460452d9063bcbc829cc34a31cfc3f006469860abf75316e7faa57605fa4e04f'),
    ('core_upsert', 0x2c7663c, 0x2c766b6, 'db59416537fd815d5d7382244a7670a0e3af46463fd6b5ffc895692dca3bdbe3'),
    ('core_unwind', 0x2c766bb, 0x2c766dc, '5323c9e3d084e28e0047df25885ca3a0124ac75a1a939922d1ec2a72538d0b48'),
    ('key_search_compare', 0x24c9000, 0x24c9060, 'b27f90a7b106cf168f1f318150e7095f26d695628b7e73cba0778899f2151742'),
    ('key_search_return', 0x24c9110, 0x24c913f, 'cfb61cecda7c6f230ab41898d33de607cb0b8ff49fb380ec957f533f796d9255'),
    ('remove_search', 0x2dcd966, 0x2dcd989, '01727bf2168dec3cc0d34b330db41a24bce8e6742882ed24e29602e23f71d729'),
    ('remove_tree_call', 0x2dcd989, 0x2dcd9e4, '8c0a03c96890c836770e0a8f875291033a5f9d7f9287a0d1e858e02cd0ad9e23'),
    ('remove_value', 0x2dcd9e4, 0x2dcda28, 'cad654d9daf59f07a5910f9fbb86f96e3f76290c5322bfc5f020a6e8a52c9944'),
    ('remove_shift_count', 0x2dcdc70, 0x2dcdc86, '5e3b91606be11742a83daf8850139d0320ffb0a0c754cafa7bb4c868411f07d4'),
    ('upsert_search', 0x2dc0105, 0x2dc0141, 'cdb4a07235e3868a18c94350978f5a4f391ebf11004a38e94ac32d45c7827b66'),
    ('upsert_select_compact', 0x2dc01dd, 0x2dc024b, 'cd9933e175747560cc0541f42a5cafd3c7f5ef43366449fee98c6173887bf848'),
    ('upsert_compact_replace', 0x2dc0320, 0x2dc036a, 'a223c2297249fb213a893355ee7a5f5f1e4db54b931eddb9e6415e1825fe0341'),
    ('upsert_tree_compare', 0x2dc0414, 0x2dc04b2, '0ec42f86ab020d7f99f2a64f6fd8e99b0fdc2d7d910cccd6a7f8697ea8dd43bb'),
    ('upsert_replace', 0x2dc04ee, 0x2dc0526, '8533d599fa6b2b546c213555aee2b107e8ddf81074192b66ab36628093331476'),
    ('upsert_insert', 0x2dc0526, 0x2dc05b8, 'ac72b7f72a6907e9fe16991e07b8273a2dc658a05774ab8fc6c5bd86619b322f'),
    ('compact_insert_begin', 0x24bda40, 0x24bda82, 'ee3a9cb4654655a51020b94cacf636ba6f69e297c669991542e4e6c18754d9d3'),
    ('compact_insert_shift_a', 0x24bdaaa, 0x24bdacd, '397b47f046be3d0900f170205983583546bd821c8975d015fa681bb79f80b11d'),
    ('compact_insert_shift_b', 0x24bdacd, 0x24bdb02, 'be827e4b7cac4435e7fb7a35632967e27f1e306e9b3b821fd347f437a061df40'),
    ('compact_insert_write', 0x24bdb02, 0x24bdb30, '72cf4ca06f9503a652789e266522327481aa5baadb8569b82ce1a17669d1a2ab'),
    ('tree_insert_existing', 0x26df227, 0x26df28a, 'db7c5db6405a45f6a005bdf2f82804621c417b1d07b2e0de8bd8e8ee1fd32403'),
    ('tree_insert_empty', 0x26df28a, 0x26df326, '2c9ca5688b04b52d766c34f3e1a896cd3dfb1538cb2e12db7836127b2ee0bb77'),
    ('tree_erase_mutation', 0x26e0c20, 0x26e0cb0, '4f7e3ad788765134550d5efe0b68209b9f0389806a7b5dd5ca7507b5b8fb0ede'),
    ('shift_entry', 0x24e4fb0, 0x24e4ff2, 'f4f8570d91c841833e552e388bb1a6a0203f365bc285caeeb4b5971f05d5b675'),
    ('shift_moves', 0x24e5007, 0x24e505c, '26b280e5180e073704674e4e48bbe4369777a38ec9647b79f94149be0b820654'),
)

# Only these specific instructions are decoded. This is not an instruction
# scanner, so a byte equal to 0xe8 in an immediate cannot become an xref.
EDGES = (
    ('action_router', 'direct_display', 0x2bdaf5c, 'call', 0x2c08600),
    ('action_router', 'nested_outer_caller', 0x2bdb08a, 'call', 0x2c12690),
    ('direct_display_handler', 'identity_helper', 0x2c08627, 'call', 0x2a8ab70),
    ('direct_display_handler', 'original_key_differs', 0x2c087a7, 'jne', 0x2c087b8),
    ('direct_display_handler', 'original_key_equal', 0x2c087a9, 'jmp', 0x2c0885a),
    ('direct_display_handler', 'selected_key_equal', 0x2c08829, 'je', 0x2c0885a),
    ('direct_display_handler', 'first_gate', 0x2c0889a, 'call', 0x2c202b0),
    ('direct_display_handler', 'first_gate_failure', 0x2c088a6, 'jne', 0x2c08923),
    ('direct_display_handler', 'second_gate', 0x2c088d1, 'call', 0x2c206b0),
    ('direct_display_handler', 'second_gate_failure', 0x2c088dd, 'jne', 0x2c08a20),
    ('direct_display_handler', 'length_below_limit', 0x2c0890e, 'jb', 0x2c089b7),
    ('direct_display_handler', 'empty_allocation', 0x2c089ba, 'je', 0x2c089e6),
    ('direct_display_handler', 'allocation_failure', 0x2c089cc, 'je', 0x2c08a9c),
    ('direct_display_handler', 'core', 0x2c08a0d, 'call', 0x2c76380),
    ('direct_display_handler', 'core_failure', 0x2c08a19, 'jne', 0x2c08a20),
    ('outer_caller', 'identity_helper', 0x2c126b2, 'call', 0x2a8ab70),
    ('outer_caller', 'original_identity_equal', 0x2c12867, 'je', 0x2c12a70),
    ('outer_caller', 'selected_identity_equal', 0x2c128f9, 'je', 0x2c12a70),
    ('outer_caller', 'selector', 0x2c12954, 'call', 0x2bdb5b0),
    ('outer_caller', 'selector_failure', 0x2c12963, 'jne', 0x2c12a01),
    ('outer_caller', 'first_gate', 0x2c12998, 'call', 0x2c202b0),
    ('outer_caller', 'first_gate_failure', 0x2c129a4, 'jne', 0x2c12a86),
    ('outer_caller', 'second_gate', 0x2c129d9, 'call', 0x2c206b0),
    ('outer_caller', 'second_gate_failure', 0x2c129e5, 'jne', 0x2c12b2e),
    ('outer_caller', 'dispatcher', 0x2c129f7, 'call', 0x2bdbaa0),
    ('first_gate', 'empty_gate_return', 0x2c202e8, 'jne', 0x2c20675),
    ('second_gate', 'zero_collection', 0x2c206de, 'je', 0x2c206e4),
    ('second_gate', 'advance_iterator', 0x2c207bf, 'call', 0x2443a40),
    ('second_gate', 'iterator_exhausted', 0x2c207cc, 'je', 0x2c208e0),
    ('second_gate', 'drain_iterator', 0x2c208ed, 'call', 0x2443a40),
    ('second_gate', 'neutral_result', 0x2c208fe, 'je', 0x2c20944),
    ('empty_iterator_helper', 'no_remaining', 0x2443a55, 'je', 0x2443ae9),
    ('empty_iterator_helper', 'empty_state', 0x2443b03, 'jne', 0x2443b72),
    ('dispatcher', 'display_wrapper', 0x2bdc670, 'call', 0x2392200),
    ('dispatcher', 'shared_result', 0x2bdc675, 'jmp', 0x2bdc94e),
    ('display_wrapper', 'length_below_wire_limit', 0x239221c, 'jb', 0x239222d),
    ('display_wrapper', 'empty_allocation', 0x2392230, 'je', 0x2392268),
    ('display_wrapper', 'allocation_failure', 0x2392248, 'je', 0x23922fa),
    ('display_wrapper', 'core', 0x239228d, 'call', 0x2c76380),
    ('display_wrapper', 'core_failure', 0x2392299, 'jne', 0x23922a0),
    ('display_core', 'empty_name', 0x2c763a1, 'je', 0x2c76406),
    ('display_core', 'too_long', 0x2c763ab, 'ja', 0x2c76437),
    ('display_core', 'too_short', 0x2c763b9, 'jb', 0x2c76437),
    ('display_core', 'erase', 0x2c76413, 'call', 0x2dcd870),
    ('display_core', 'comparison_differs', 0x2c7658a, 'jne', 0x2c76510),
    ('display_core', 'tree_value_iterator', 0x2c76613, 'call', 0x23876e0),
    ('display_core', 'second_comparison_differs', 0x2c76631, 'jne', 0x2c765c0),
    ('display_core', 'second_comparison_equal', 0x2c76633, 'jmp', 0x2c7658c),
    ('display_core', 'upsert', 0x2c76685, 'call', 0x2dbff30),
    ('erase_helper', 'key_search', 0x2dcd96c, 'call', 0x24c9000),
    ('erase_helper', 'tree_erase', 0x2dcd9ba, 'call', 0x26e0c20),
    ('erase_helper', 'shift', 0x2dcdc7a, 'call', 0x24e4fb0),
    ('upsert_helper', 'key_search', 0x2dc0120, 'call', 0x24c9000),
    ('upsert_helper', 'compact_without_conversion', 0x2dc013b, 'je', 0x2dc01dd),
    ('upsert_helper', 'replace_compact', 0x2dc01ec, 'je', 0x2dc0320),
    ('upsert_helper', 'insert_a', 0x2dc023c, 'call', 0x24bda40),
    ('upsert_helper', 'compact_index_failure', 0x2dc032f, 'jae', 0x2dc0639),
    ('upsert_helper', 'replace_value', 0x2dc0365, 'jmp', 0x2dc0502),
    ('upsert_helper', 'insert_empty_tree', 0x2dc041c, 'je', 0x2dc0526),
    ('upsert_helper', 'found_key', 0x2dc04ae, 'je', 0x2dc04ee),
    ('upsert_helper', 'insert_b', 0x2dc0589, 'call', 0x26df210),
    ('upsert_helper', 'returned_index_failure', 0x2dc05b3, 'jae', 0x2dc0620),
    ('insert_helper_a', 'insert_index_failure', 0x24bda52, 'ja', 0x24bdb30),
    ('insert_helper_a', 'shift_right', 0x24bdab1, 'call', 0x24e4fb0),
    ('insert_helper_a', 'shift_left', 0x24bdae6, 'call', 0x24e4fb0),
    ('insert_helper_b', 'tree_node_insert', 0x26df26e, 'call', 0x1cab5c0),
    ('insert_helper_b', 'tree_allocation_failure', 0x26df29b, 'je', 0x26df338),
    ('insert_helper_b', 'tree_node_limit_failure', 0x26df2cf, 'jae', 0x26df34a),
    ('tree_erase_helper', 'tree_node_erase', 0x26e0c42, 'call', 0x1d5e1a0),
    ('tree_erase_helper', 'no_root_adjustment', 0x26e0c78, 'jne', 0x26e0cb0),
    ('tree_value_iterator', 'no_remaining_values', 0x23876e8, 'je', 0x2387723),
    ('tree_value_iterator', 'unexpected_iterator_state', 0x23876f4, 'jne', 0x23878eb),
    ('tree_value_iterator', 'missing_tree_link', 0x23877e6, 'je', 0x23878dc),
)

SWITCHES = (
    ('router', 'action_router', 0x2bda83c, bytes.fromhex('488d05')),
    ('classifier', 'action_classifier', 0x36c3105, bytes.fromhex('488d15')),
    ('selector', 'action_selector', 0x2bdb5c8, bytes.fromhex('488d0d')),
    ('formatter', 'formatter', 0x2bc9606, bytes.fromhex('488d05')),
    ('dispatcher', 'dispatcher', 0x2bdbb1f, bytes.fromhex('488d05')),
)

NAME_TABLES = (0x644cc40, 0x6467f98, 0x649bac8)
SLOTS = (0x64e7a78, 0x64df480, 0x64df498, 0x64df4a0,
         0x64df508, 0x64df568, 0x64df9f8, 0x64dfb50)
INDIRECTS = (
    ('direct_display_handler', 'original_key_compare', 0x2c08781, 'call', bytes.fromhex('ff15'), 0x64dfb50),
    ('direct_display_handler', 'selected_key_compare', 0x2c08803, 'call', bytes.fromhex('ff15'), 0x64dfb50),
    ('direct_display_handler', 'allocate', 0x2c089c3, 'call', bytes.fromhex('ff15'), 0x64df480),
    ('direct_display_handler', 'copy', 0x2c089de, 'call', bytes.fromhex('ff15'), 0x64df508),
    ('direct_display_handler', 'allocation_failure', 0x2c08aa4, 'call', bytes.fromhex('ff15'), 0x64df498),
    ('outer_caller', 'classifier', 0x2c127af, 'call', bytes.fromhex('ff15'), 0x64e7a78),
    ('outer_caller', 'original_key_compare', 0x2c12841, 'call', bytes.fromhex('ff15'), 0x64dfb50),
    ('outer_caller', 'selected_key_compare', 0x2c128d3, 'call', bytes.fromhex('ff15'), 0x64dfb50),
    ('display_wrapper', 'allocate', 0x239223f, 'call', bytes.fromhex('ff15'), 0x64df480),
    ('display_wrapper', 'copy', 0x239225a, 'call', bytes.fromhex('ff15'), 0x64df508),
    ('display_wrapper', 'allocation_failure', 0x2392302, 'call', bytes.fromhex('ff15'), 0x64df498),
    ('display_core', 'release_erased_value', 0x2c7642d, 'call', bytes.fromhex('ff15'), 0x64df4a0),
    ('display_core', 'compare_bytes', 0x2c76582, 'call', bytes.fromhex('ff15'), 0x64df9f8),
    ('display_core', 'load_comparator', 0x2c765a9, 'load', bytes.fromhex('488b1d'), 0x64df9f8),
    ('key_search_helper', 'key_compare', 0x24c9042, 'call', bytes.fromhex('ff15'), 0x64dfb50),
    ('erase_shift_helper', 'move_records', 0x24e5035, 'call', bytes.fromhex('ff15'), 0x64df568),
)


def verify_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 115 SHA-256 mismatch')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, va, size=1, *, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError('invalid address or size')
        matches = [s for s in self.sections
                   if s['type'] != 8 and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file-backed')
        sec = matches[0]
        off = sec['offset'] + va - sec['address']
        if off + size > len(self.data):
            raise ValueError('address maps outside file')
        return off

    def read(self, va, size, *, executable=False):
        off = self.offset(va, size, executable=executable)
        return bytes(self.data[off:off + size])

    def section(self, name):
        found = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        if len(found) != 1:
            raise ValueError('missing or duplicate file-backed section')
        return found[0]

    def u8(self, va):
        return self.read(va, 1)[0]

    def u16(self, va):
        return struct.unpack('<H', self.read(va, 2))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def u64(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]


def verify_windows(image):
    rows = []
    for name, start, end, expected in WINDOWS:
        raw = image.read(start, end - start, executable=True)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != expected:
            raise ValueError('instruction window mismatch: ' + name)
        rows.append((name, hex(start), hex(end), hex(image.offset(start, len(raw))),
                     raw.hex(), actual))
    return rows


def branch(image, va):
    first = image.read(va, 2, executable=True)
    short = {0x72: 'jb', 0x73: 'jae', 0x74: 'je', 0x75: 'jne', 0x77: 'ja', 0xeb: 'jmp'}
    near = {0x82: 'jb', 0x83: 'jae', 0x84: 'je', 0x85: 'jne', 0x87: 'ja'}
    if first[0] in short:
        raw = first
        delta = struct.unpack('<b', raw[1:])[0]
        return short[first[0]], va + 2 + delta, raw
    if first[0] in (0xe8, 0xe9):
        raw = image.read(va, 5, executable=True)
        delta = struct.unpack('<i', raw[1:])[0]
        return ('call' if first[0] == 0xe8 else 'jmp'), va + 5 + delta, raw
    if first[0] == 0x0f and first[1] in near:
        raw = image.read(va, 6, executable=True)
        delta = struct.unpack('<i', raw[2:])[0]
        return near[first[1]], va + 6 + delta, raw
    raise ValueError('unsupported branch opcode')


def rip_target(image, va, prefix):
    raw = image.read(va, len(prefix) + 4, executable=True)
    if not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative opcode')
    return va + len(raw) + struct.unpack('<i', raw[-4:])[0]


def relocations(image):
    section = image.section('.rela.dyn')
    symbols = image.section('.dynsym')
    strings = image.section('.dynstr')
    if section['size'] % 24 or symbols['size'] % 24:
        raise ValueError('malformed relocation or symbol table')
    result = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot in result:
            raise ValueError('duplicate relocation slot')
        typ, symbol_index = info & 0xffffffff, info >> 32
        name = ''
        if symbol_index:
            if symbol_index * 24 >= symbols['size']:
                raise ValueError('symbol index outside .dynsym')
            name_off = struct.unpack_from('<I', image.data, symbols['offset'] + symbol_index * 24)[0]
            if name_off >= strings['size']:
                raise ValueError('symbol name outside .dynstr')
            begin = strings['offset'] + name_off
            end = image.data.find(b'\0', begin, strings['offset'] + strings['size'])
            if end < 0:
                raise ValueError('unterminated symbol name')
            name = bytes(image.data[begin:end]).decode('ascii')
        result[slot] = (typ, symbol_index, addend, name, off)
    return result


def name_at(image, relocs, entry):
    row = relocs.get(entry)
    if row is None or row[0] != 8 or row[1] != 0 or row[2] < 0:
        raise ValueError('name pointer lacks a relative relocation')
    pointer = row[2]
    length = image.u64(entry + 8)
    if not 0 < length <= 128:
        raise ValueError('invalid variant name length')
    return pointer, length, image.read(pointer, length).decode('ascii')


def frames(image):
    secs, index = unwind_index(image.data)
    _, records = eh_frame_records(image.data, secs)
    by_start = {}
    for row in records:
        by_start.setdefault(row['start'], []).append(row)
    by_index = {row['start']: row for row in index}
    result = {}
    for role, va in FUNCTIONS:
        found = by_start.get(va, [])
        if len(found) != 1 or va not in by_index or found[0]['fde'] != by_index[va]['fde']:
            raise ValueError('selected function lacks a unique indexed FDE: ' + role)
        item = found[0]
        if item['end'] <= va:
            raise ValueError('empty FDE')
        raw = image.read(va, item['end'] - va, executable=True)
        result[role] = dict(item, role=role, file_offset=image.offset(va, len(raw)),
                            body_sha256=hashlib.sha256(raw).hexdigest())
    return result


def switch_tables(image, selected_frames, relocs):
    # The record following each names array is a length-qualified sentinel.
    sentinels = [name_at(image, relocs, base + 92 * 16)[2] for base in NAME_TABLES]
    match = re.fullmatch(r'variant index 0 <= i < ([0-9]+)', sentinels[0])
    if not match or len(set(sentinels)) != 1:
        raise ValueError('variant table sentinel mismatch')
    count = int(match.group(1))
    if count != 92:
        raise ValueError('unexpected variant table count')
    names = []
    for i in range(count):
        entries = [name_at(image, relocs, base + i * 16) for base in NAME_TABLES]
        if len({e[2] for e in entries}) != 1:
            raise ValueError('variant names differ across tables')
        names.append(entries)
    selected = [i for i, row in enumerate(names) if row[0][2] == 'setDisplayName']
    if len(selected) != 1:
        raise ValueError('expected one display-name variant')
    ordinal = selected[0]
    nested = [i for i, row in enumerate(names) if row[0][2] == 'multiSig']
    if len(nested) != 1:
        raise ValueError('expected one nested-action variant')
    nested_ordinal = nested[0]

    if image.read(0x2bdbb10, 2, executable=True) != bytes.fromhex('482d'):
        raise ValueError('unexpected dispatcher tag subtraction')
    bias = image.u32(0x2bdbb12)
    bases, tables = {}, {}
    for label, role, site, prefix in SWITCHES:
        base = rip_target(image, site, prefix)
        frame = selected_frames[role]
        destinations = []
        for i in range(count):
            delta = struct.unpack('<i', image.read(base + i * 4, 4))[0]
            dest = base + delta
            if not frame['start'] <= dest < frame['end']:
                raise ValueError('switch entry outside its FDE: ' + label)
            destinations.append(dest)
        bases[label], tables[label] = base, destinations

    # The formatter independently places this exact pointer and length into
    # its output in the selected arm; do not infer other names by ordinal.
    fmt_literal = rip_target(image, 0x2bcb316, bytes.fromhex('488d05'))
    if (ordinal != 19 or tables['formatter'][ordinal] != 0x2bcb2d4
            or fmt_literal != names[ordinal][0][0]
            or image.u8(0x2bcb327) != names[ordinal][0][1]):
        raise ValueError('formatter does not bind the selected name')
    nested_literal = rip_target(image, 0x2bcb809, bytes.fromhex('488d05'))
    if (nested_ordinal != 52 or tables['formatter'][nested_ordinal] != 0x2bcb7c7
            or nested_literal != names[nested_ordinal][0][0]
            or image.u8(0x2bcb81a) != names[nested_ordinal][0][1]
            or tables['router'][nested_ordinal] != 0x2bdb07a):
        raise ValueError('formatter or router does not bind the nested variant')
    if (tables['classifier'][ordinal] != 0x36c3115
            or tables['selector'][ordinal] != 0x2bdb5f5
            or tables['dispatcher'][ordinal] != 0x2bdc64d
            or tables['router'][ordinal] != 0x2bdaf4c):
        raise ValueError('selected action follows an unexpected arm')
    return count, ordinal, bias, names, bases, tables


def verify_edges(image, selected_frames):
    rows = []
    for role, name, site, expected_kind, expected_target in EDGES:
        f = selected_frames[role]
        if not f['start'] <= site < f['end']:
            raise ValueError('edge outside selected owner')
        kind, target, raw = branch(image, site)
        if kind != expected_kind or target != expected_target:
            raise ValueError('branch mismatch: ' + name)
        if kind == 'call':
            if target not in {r['start'] for r in selected_frames.values()}:
                raise ValueError('call does not name a selected FDE start')
        elif not f['start'] <= target < f['end']:
            raise ValueError('branch target outside selected FDE')
        rows.append((role, name, hex(site), hex(image.offset(site, len(raw))),
                     raw.hex(), kind, hex(target)))
    return rows


def verify_indirects(image, selected_frames, relocs):
    rows = []
    for role, name, site, operation, prefix, expected_slot in INDIRECTS:
        owner = selected_frames[role]
        if not owner['start'] <= site < owner['end']:
            raise ValueError('indirect edge outside selected owner')
        slot = rip_target(image, site, prefix)
        if slot != expected_slot or slot not in relocs:
            raise ValueError('indirect slot mismatch: ' + name)
        typ, symidx, addend, symbol, _ = relocs[slot]
        if typ not in (6, 8) or (typ == 8 and symidx != 0):
            raise ValueError('unsupported indirect relocation')
        raw = image.read(site, len(prefix) + 4, executable=True)
        rows.append((role, name, hex(site), hex(image.offset(site, len(raw))), raw.hex(),
                     operation, hex(slot), typ, hex(addend), symbol))
    return rows


def verify_relocation_meanings(relocs, selected_frames):
    if any(slot not in relocs for slot in SLOTS):
        raise ValueError('missing relocation')
    if (relocs[0x64e7a78][:3] != (8, 0, selected_frames['action_classifier']['start'])
            or [relocs[s][3] for s in (0x64df508, 0x64df568, 0x64df9f8, 0x64dfb50)]
            != ['memcpy', 'memmove', 'bcmp', 'memcmp']):
        raise ValueError('unexpected relocation targets')


def facts(image):
    return {
        'tag_bias': image.u32(0x2bdbb12),
        'tag_default_index': image.u32(0x2bdbb17),
        'wrapper_length_limit_exclusive': image.u8(0x239221b),
        'wrapper_length_error_word': image.u16(0x2392222),
        'direct_length_limit_exclusive': image.u8(0x2c0890d),
        'direct_length_error_word': image.u16(0x2c08918),
        'direct_prior_rejection_word': image.u16(0x2c08863),
        'direct_success_outer_tag': image.u8(0x2c08a1d),
        'direct_error_outer_tag': image.u8(0x2c08a73),
        'name_max_inclusive': image.u8(0x2c763aa),
        'name_min_inclusive': image.u8(0x2c763b8),
        'long_error_word': image.u16(0x2c763a5),
        'short_error_word': image.u16(0x2c763b3),
        'duplicate_error_word': image.u16(0x2c7658e),
        'success_word': image.u16(0x2c76435),
        'success_outer_tag': image.u8(0x239229d),
        'error_outer_tag': image.u8(0x23922e4),
        'prior_rejection_word': image.u16(0x2c12a7c),
        'state_field_offset': image.u32(0x2c76409),
        'key_bytes': image.u32(0x2c1283a),
        'compact_entry_stride': image.u8(0x2c7651e),
        'compact_to_tree_threshold': image.u8(0x2dc0133),
        'tree_storage_tag': hex(image.u64(0x2dc0107)),
        'new_tree_node_bytes': image.u32(0x26df28e),
        'tree_node_local_limit': image.u8(0x26df2ce),
    }


def table_index(tag, values, count):
    """Decode supported input tags; refuse to model a high out-of-range tag."""
    if type(tag) is not int or not 0 <= tag < 2 ** 64:
        raise ValueError('tag must be an unsigned 64-bit integer')
    index = tag - values['tag_bias'] if tag >= values['tag_bias'] else values['tag_default_index']
    if not 0 <= index < count:
        raise ValueError('outside the verified switch table')
    return index


def predict(length, duplicate, prior_rejection, values):
    """Evaluate the recorded branch predicates, not the captured executable."""
    if type(length) is not int or not 0 <= length < 2 ** 64:
        raise ValueError('length must be an unsigned 64-bit integer')
    if type(duplicate) is not bool or type(prior_rejection) is not bool:
        raise ValueError('boolean predicates required')
    ok, err = values['success_outer_tag'], values['error_outer_tag']
    if prior_rejection:
        return ('prior_rejection', err, values['prior_rejection_word'], 'none')
    if length >= values['wrapper_length_limit_exclusive']:
        return ('wrapper_limit', err, values['wrapper_length_error_word'], 'none')
    if length == 0:
        return ('empty', ok, values['success_word'], 'erase')
    if length > values['name_max_inclusive']:
        return ('too_long', err, values['long_error_word'], 'none')
    if length < values['name_min_inclusive']:
        return ('too_short', err, values['short_error_word'], 'none')
    if duplicate:
        return ('duplicate', err, values['duplicate_error_word'], 'none')
    return ('unique', ok, values['success_word'], 'upsert')


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def generate(data, out):
    verify_digest(data)
    image = Image(data)
    windows = verify_windows(image)
    frame_map = frames(image)
    relocs = relocations(image)
    count, ordinal, bias, names, bases, tables = switch_tables(image, frame_map, relocs)
    edges = verify_edges(image, frame_map)
    indirect_edges = verify_indirects(image, frame_map, relocs)
    values = facts(image)
    if values['tag_bias'] != bias:
        raise ValueError('inconsistent tag bias')
    for left, right in (('direct_length_limit_exclusive', 'wrapper_length_limit_exclusive'),
                        ('direct_length_error_word', 'wrapper_length_error_word'),
                        ('direct_prior_rejection_word', 'prior_rejection_word'),
                        ('direct_success_outer_tag', 'success_outer_tag'),
                        ('direct_error_outer_tag', 'error_outer_tag')):
        if values[left] != values[right]:
            raise ValueError('direct and nested result constants differ')
    slot_rows = []
    for slot in SLOTS:
        if slot not in relocs:
            raise ValueError('missing relocation')
        typ, symidx, addend, name, record_off = relocs[slot]
        slot_rows.append((hex(slot), hex(image.offset(slot, 8)), typ, symidx,
                          hex(addend), name, hex(record_off),
                          bytes(image.data[record_off:record_off + 24]).hex()))
    verify_relocation_meanings(relocs, frame_map)

    out.mkdir(parents=True, exist_ok=True)
    frame_rows = [(role, hex(v['start']), hex(v['end']), hex(v['file_offset']),
                   hex(v['fde']), hex(v['cie']), '' if v['lsda'] is None else hex(v['lsda']),
                   v['end'] - v['start'], v['body_sha256']) for role, v in frame_map.items()]
    write_tsv(out / 'functions.tsv', ('role', 'start_va', 'end_va_exclusive', 'file_offset',
                                    'fde_va', 'cie_va', 'lsda_va', 'extent_bytes', 'sha256'), frame_rows)
    write_tsv(out / 'windows.tsv', ('name', 'start_va', 'end_va_exclusive', 'file_offset',
                                   'raw_hex', 'sha256'), windows)
    write_tsv(out / 'edges.tsv', ('owner', 'edge', 'site_va', 'file_offset', 'raw_hex',
                                 'operation', 'target_va'), edges)
    write_tsv(out / 'indirect-edges.tsv', ('owner', 'edge', 'site_va', 'file_offset',
                                          'raw_hex', 'operation', 'slot_va',
                                          'relocation_type', 'addend', 'symbol'), indirect_edges)
    write_tsv(out / 'relocations.tsv', ('slot_va', 'slot_file_offset', 'type', 'symbol_index',
                                      'addend', 'symbol', 'record_file_offset', 'record_hex'), slot_rows)
    switch_rows = []
    for i, entries in enumerate(names):
        switch_rows.append((i, hex(bias + i), entries[0][2], hex(entries[0][0]),
                            entries[0][1], *(hex(tables[label][i]) for label, _, _, _ in SWITCHES)))
    write_tsv(out / 'switches.tsv', ('index', 'tag_if_in_range', 'name_table_entry',
                                    'name_va', 'name_length', 'router_target_va', 'classifier_target_va',
                                    'selector_target_va', 'formatter_target_va',
                                    'dispatcher_target_va'), switch_rows)
    table_rows = []
    for label, role, _, _ in SWITCHES:
        for i in range(count):
            entry = bases[label] + i * 4
            raw = image.read(entry, 4)
            delta = struct.unpack('<i', raw)[0]
            table_rows.append((label, i, hex(entry), hex(image.offset(entry, 4)),
                               raw.hex(), delta, hex(tables[label][i]),
                               hex(frame_map[role]['start']), hex(frame_map[role]['end'])))
    write_tsv(out / 'switch-tables.tsv', ('table', 'index', 'entry_va', 'entry_file_offset',
                                        'raw_hex', 'signed_delta', 'target_va',
                                        'owner_fde_start_va', 'owner_fde_end_va'), table_rows)
    name_rows = []
    for i, entries in enumerate(names):
        for table, (pointer, length, name) in enumerate(entries):
            entry = NAME_TABLES[table] + i * 16
            record_off = relocs[entry][4]
            name_rows.append(('variant', table, i, hex(entry), hex(image.offset(entry, 16)),
                              hex(record_off), hex(pointer), hex(image.offset(pointer, length)),
                              length, name))
    for table, base in enumerate(NAME_TABLES):
        entry = base + count * 16
        pointer, length, name = name_at(image, relocs, entry)
        name_rows.append(('count_sentinel', table, count, hex(entry), hex(image.offset(entry, 16)),
                          hex(relocs[entry][4]), hex(pointer), hex(image.offset(pointer, length)),
                          length, name))
    write_tsv(out / 'name-tables.tsv', ('kind', 'table', 'index', 'entry_va', 'entry_file_offset',
                                       'relocation_file_offset', 'name_va', 'name_file_offset',
                                       'name_length', 'name'), name_rows)
    inputs = [(0, False, False), (0, True, False), (1, False, False),
              (2, False, False), (3, False, False), (3, True, False),
              (20, False, False), (20, True, False), (21, False, False),
              (100, False, False), (101, False, False), (2 ** 64 - 1, False, False),
              (3, False, True), (101, True, True)]
    vector_rows = [(length, int(duplicate), int(blocked), *predict(length, duplicate, blocked, values))
                   for length, duplicate, blocked in inputs]
    write_tsv(out / 'branch-vectors.tsv', ('length', 'duplicate', 'prior_rejection',
                                           'predicted_path', 'outer_tag', 'result_word',
                                           'predicted_mutation'), vector_rows)
    summary = {
        'binary_sha256': DIGEST,
        'coordinate_system': 'linked ELF virtual addresses',
        'facts': values,
        'name_table_bases_va': [hex(x) for x in NAME_TABLES],
        'name_table_count': count,
        'name_table_record_count_including_sentinels': len(name_rows),
        'selected_ordinal': ordinal,
        'selected_tag': bias + ordinal,
        'switch_bases_va': {name: hex(base) for name, base in bases.items()},
        'switch_unique_target_counts': {name: len(set(rows)) for name, rows in tables.items()},
        'switch_entry_count': len(table_rows),
        'indexed_fde_count': len(frame_rows),
        'pinned_window_count': len(windows),
        'decoded_edge_count': len(edges),
        'decoded_indirect_edge_count': len(indirect_edges),
        'relocation_count': len(slot_rows),
        'branch_vector_count': len(vector_rows),
        'limits': 'Static byte evidence and a branch model; no captured executable was run.',
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('display_name_path_115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
