#!/usr/bin/env python3
"""Regenerate selected node 115 ABCI greeting path evidence from ELF bytes.

All coordinates are link-time virtual addresses; windows are selected, not a
complete disassembly. Input integrity, exact instruction bytes, and bounds are
checked before reports are written. No captured program is executed.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
INPUT = ROOT / 'artifacts/node/115/hl-node'

# Exact bytes for selected instruction sequences. Overlapping earlier work is
# marked context in the reports; this does not claim ownership of those bodies.
WINDOWS = [
    ('constructor_first_alloc', 0x5a6c2ec, 'bf380b0000ff158931a7004885c00f84ba0300004989c6488db42440120000ba380b00004889c7ff15ef31a7004c89742410498d7610'),
    ('constructor_second_alloc_return', 0x5a6c637, '4c8da42450120000488db424b0020000ba700b00004c89e7ff15b32ea700bf800b0000ff15202ea7004885c074794989c7488db42440120000ba800b00004889c7ff158a2ea7004c89f04c89fa'),
    ('parent_return_registers', 0x2cb7a15, '4989c6488984242801000048899424300100004180bc241a2a0000004889542438'),
    ('parent_stage_ptr', 0x2cb7e27, '488b4c243848898c24d80d0000'),
    ('parent_copy_1', 0x2cb7e6c, '488db424380700004c8dbc2410320000bab80600004c89ffffd5'),
    ('parent_copy_2', 0x2cb7ffe, '488dbc2440270000baf00700004c89feffd5'),
    ('parent_copy_3', 0x2cb8039, '488dbc24501f0000488db42440270000baf0070000ff15b4748203'),
    ('parent_copy_4', 0x2cb806f, '488dbba0010000488db424501f0000bab8060000ffd5'),
    ('parent_arg', 0x2cb8428, '488b8b40080000f048ff010f8e9f1a0000'),
    ('parent_call', 0x2cb855d, '88942430070000488bbb100b00004c8934240fb6d0488db424103200004531c0e87ed0e1ff'),
    ('task_save_arg', 0x2ad5611, '48894c24384c89442470'),
    ('task_retain_arg', 0x2ad5662, '48894c24184889442440'),
    ('task_stage_arg', 0x2ad56fe, '488b4424184889842448010000'),
    ('task_allocate', 0x2ad57eb, 'bf40030000ff158a9ca0034885c0746e4889c3488db42480000000ba400300004889c7ff15f49ca003'),
    ('task_descriptor_call', 0x2ad5828, '4c8d05a92097034c89ff488b742430ba010000004889d9e8ec0eb0fe'),
    ('task_bad_alloc', 0x2ad5869, 'bf08000000be40030000ff15179ca0030f0b'),
    ('poll_entry', 0x2ad59b7, '0fb6873a03000085c0741683f8030f841b040000488d3d261f9703ff1588b9a003'),
    ('poll_capture', 0x2ad5a29, '4c8babc80000004c896c2448'),
    ('poll_capture_xfer', 0x2ad5c14, '4989e94c89ed4c8d73'),
    ('poll_capture_store', 0x2ad5c44, '4531f64989ed4c89cd4c89bb800100004c89ab88010000'),
    ('poll_resume_load', 0x2ad5e6f, '488b8b88010000f048ff010f8e49ffffff'),
    ('poll_resume_stack', 0x2ad5fb8, '48898424e000000048898c24e8000000'),
    ('poll_copy_1', 0x2ad610f, '488dbc2428020000488d7424484c8b25e593a003bab000000041ffd4'),
    ('poll_copy_2', 0x2ad617e, '4c8dac2490330000488db42490010000ba480100004c89efff156c93a003'),
    ('poll_tls_branch', 0x2ad61c4, '644c8b2425000000004901ec640fb6454883f8010f84a700000083f8020f858900000040b5014c89efe84eb4fcff'),
    ('poll_copy_3', 0x2ad62e0, '4983fe020f84900000004c8bbc2470030000488db42490330000488dbc2490930000baf82f0000ff15fb91a003'),
    ('poll_scheduler_branch', 0x2ad6314, '4183fe017515488db424909300004c89e7e8d68f06004889c7eb13488db424909300004c89e7e861a006004889c7'),
    ('poll_pending', 0x2ad6232, 'c6833a03000003b0014881c488c300005b415c415d415e415f5d'),
    ('wrap_a_call', 0x2b3f31b, '498dbea80000004c89f24c89e1e8431d1900'),
    ('wrap_b_call', 0x2b403c9, '4c89e24c89e9e89c151900'),
    ('construct_a_copy_1', 0x2cd110f, '488dbc24583100004c8b25eae38003baf82f000041ffd4'),
    ('construct_a_layout', 0x2cd113e, '488d05bb847703488984249000000048c7842498000000000000004c89bc24a00000004c89b424a8000000c78424b000000000000000488dbc24b4000000488db42454310000bafc2f000041ffd4'),
    ('construct_a_alloc', 0x2cd11b0, 'bf80300000be07000000ff15d0e380034885c0743a4989c6488db42480000000ba803000004889c7ff152ae380034889df4c89f64c89f2e824f7ffff'),
    ('construct_b_copy_1', 0x2cd1a0f, '488dbc24583100004c8b25eada8003baf82f000041ffd4'),
    ('construct_b_layout', 0x2cd1a3e, '488d054b7d7703488984249000000048c7842498000000000000004c89bc24a00000004c89b424a8000000c78424b000000000000000488dbc24b4000000488db42454310000bafc2f000041ffd4'),
    ('construct_b_alloc', 0x2cd1ab0, 'bf80300000be07000000ff15d0da80034885c0743a4989c6488db42480000000ba803000004889c7ff152ada80034889df4c89f64c89f2e8d4ebffff'),
    ('poll_a_call', 0x2b1db7b, '488d7b384c896c2438488d742418e852f3faff'),
    ('poll_b_call', 0x2b26afb, '488d7b384c896c2438488d742418e8d263faff'),
    ('future_initial_load', 0x2ace51e, '488b83380100004889442440'),
    ('future_initial_store', 0x2ace5bd, '488b44244048898348020000'),
    ('future_copy_1', 0x2ace65a, '488db390010000488dbc24501200004c8b2d980ea103ba100f000041ffd5'),
    ('future_copy_2', 0x2ace678, '4c8db424e8500000488db424d0020000bab01e00004c89f741ffd5'),
    ('future_copy_3', 0x2ace693, '488dbba8100000bab01e000048897c24284c89f641ffd5'),
    ('future_copy_4', 0x2ace6e4, '488db328200000488dbc24d8410000ba100f0000ff150a0ea103'),
    ('future_copy_5', 0x2ace82e, '488dbc2440030000488db424d84100004c8b3dc30ca103ba100f000041ffd7'),
    ('future_copy_6', 0x2ace8c5, '4c8db42458320000488db424d0020000ba800f00004c89f741ffd7ba800f0000488b7c24284c89f641ffd7'),
    ('future_dispatch', 0x2ace94c, '0fb6837a120000488d0dde54b3fd486304814801c8ffe0'),
    ('future_snapshot', 0x2ace963, 'c7837c1200000000010080bb78120000000f842b020000488bb3d01100004883c610488d15a88be4fd488d7c2450b921000000e895a0b7024c8b742450e998020000'),
    ('future_followup', 0x2ace9a5, '4c8db390120000488dbc24d00200004c89f64c89e2e8013e01000fb6ac24d00200004080fd457507b104e9481a0000'),
    ('future_no_snapshot', 0x2aceba5, '488bb3d01100004883c610488d159e89e4fd488dbc2448230000b924000000e897a4b702'),
    ('future_alloc', 0x2acebc9, '48c78424d00200000100000048c78424d802000001000000488dbc24e0020000488db42448230000baa0000000ff150c09a103bfb0000000ff157908a1034885c00f84960900004989c6488db424d0020000bab00000004889c7ff15df08a1034c8974245048b800000000000000804889442458'),
    ('future_prepare_send', 0x2acec3d, '4c89b310120000c6837d12000001488b442458488b4c2460660f104424684889831812000048898b20120000660f118328120000'),
    ('future_send_setup', 0x2acec7b, '488d8b10120000488983381200008993401200000fb68378120000488d156e6ab3fd4889938012000048c7838812000012000000488d9318110000488993c015000048898bc8150000c683d0150000008883d11500004c8db3801200004c89f74c89e6e85db40a00b103a8010f852f1700004889d580bbd015000003753080bbb815000003750c488dbbd0120000e81268ffff488bb3901200004885f6740f488bbb9812000031d2ff157707a1034885ed0f84ce010000'),
    ('future_send_error_text', 0x2acee90, '488d058668b3fd48898424d002000048c78424d802000019000000'),
    ('future_send_success_text', 0x2acefe5, '488d054a67b3fd48898424d002000048c78424d80200001c000000'),
    ('future_followup_gate', 0x2acf04a, '80bb78120000000f84070300004c8bab181200004c89e848f7d80f800e020000c6837d12000000c6837f120000014c8bb320120000660f108328120000660f29842470010000'),
    ('send_initial', 0x2b7a148, '0fb68750030000488d0d56aba8fd486304814801c8ffe04989f64c8bbb40030000488bb3480300000fb69351030000488b0b4c8b4308488d7b10e8396bb8ff'),
    ('send_write', 0x2b7a1a9, 'c68338030000004c89f6488d7b28e8d4000000a8017412c6835003000003b8010000005b415e415fc3'),
    ('send_done', 0x2b7a1f0, '488b73104885f67418488b7b184989d631d24989c7ff15955296034c89f84c89f2c68350030000015b415e415fc3'),
    ('send_unwind', 0x2b7a238, '4989c6eb274989c6c68350030000024c89f7e801688703'),
    ('prepare_encode', 0x2700d66, '488d7c24104c89ee31d2e8ebaac2ff'),
    ('prepare_encode_result', 0x2700dbf, '488b4c24104883f9087513488b442428488943100f104424180f1103eb55488b442418488b7c242048c7030000000048c743080100000048c7431000000000488d15632deffd48630c8a4801d1ffe1'),
    ('size_and_alloc', 0x232b889, '4c8b3e4983c710488d7c2408488d5424304c89fee8feb19a00837c240808752c4c8b6c24404d85ed0f88c500000074324c89efff15be3b1b044885c07529bf010000004c89eeff15c33b1b04'),
    ('writer_call', 0x232b90d, '488d7c2430488d5424084c89fee8c1b49a00837c243008751d488d442418488b481048894b180f10000f11430848c70308000000eb28'),
    ('writer_error', 0x232b943, '0f104424300f104c24400f114b100f1103488b7424184885f6740d488b7c242031d2ff15353b1b04'),
    ('size_dispatch', 0x2cd6ab1, '48bdffffffffffffff7f488b06488d0c284883c10248c1f83f4821c8488d0d785393fd486304814801c8ffe0'),
    ('writer_dispatch', 0x2cd6df4, '48bdffffffffffffff7f488b0e488d34294883c60248c1f93f4821f1488d354d5093fd48630c8e4801f1ffe1'),
    ('writer_case_zero', 0x2cd6e20, '48894424084c8d7a10488b7220483972100f8416040000488b4218c604300048ffc64989d6488972204c8b6310488d7c24104c89fe31d24c89e1e8d1efc5ff488b4c24104883f9080f85f6010000488b7308498b4e104d8b6e204c29e94939cc0f87440400004c89f04d85e47413488b78184c01ef4c89e2ff156a8680034c89f04d01e54c896820'),
    ('writer_case_one', 0x2cd6fa3, '4989c74c8d7210488b7220483972100f84bc020000488b4218c604300148ffc648897220488b4b18488d7c24104c89f631d2e856eec5ff837c2410080f859b000000488b4b08488d7c24104c89f631d2e838eec5ff488b4c24104883f9080f8591000000488b4b10488d7c24104c89f631d2e816eec5ff488b4c24104883f90875734c89f849c70708000000eb24'),
    ('write_tag_two', 0x2cd6f6d, '488b7220483972100f8476020000488b4a18c6043102e9bf000000'),
    ('write_tag_three', 0x2cd6f88, '488b7220483972100f8489020000488b4a18c6043103e9a4000000'),
    ('write_tag_four', 0x2cd6f52, '488b7220483972100f8463020000488b4a18c6043104e9da000000'),
    ('write_tag_five', 0x2cd7031, '488b7220483972100f845d020000488b4a18c604310548ffc64889722048c70008000000'),
    ('uint_small', 0x2935e3b, '4881f9fb000000731d'),
    ('uint_16', 0x2935e61, '4881f90000010073434c8b4e104c390e0f8405010000488b7e0842c6040ffb49ffc14c894e1084d2740466c1c108488b164c29ca4883fa010f86170100006642890c0f4983c102'),
    ('uint_32', 0x2935ead, '4889cf48c1ef20753d4c8b4e104c390e0f842d010000488b7e0842c6040ffc49ffc14c894e1084d274020fc9488b164c29ca4883fa030f864101000042890c0f4983c104eb3c'),
    ('uint_64', 0x2935ef3, '4c8b4e104c390e0f8464010000488b7e0842c6040ffd49ffc14c894e1084d27403480fc9488b164c29ca4883fa070f86770100004a890c0f4983c108'),
    ('followup_poll', 0x2ae2fbe, '4c89fae8fa0c0000440fb67c24504180ff450f84d1010000'),
    ('followup_code', 0x2ae2dd4, '4180ff450f84380400004180ff440f85c3040000'),
    ('constructor_argument', 0x5a6c01b, '89d54989f64889fb'),
    ('constructor_state_capture', 0x5a6c39c, '48899c2460160000'),
    ('constructor_helper_capture', 0x5a6c3d6, '4c89a42468160000'),
    ('constructor_bridge_copy', 0x5a6c5c3, '488dbc2408550000488db42440120000ba3804000041ffd54084ed7408c684243959000001488dbc2440120000488db42408550000e883c9f9ff'),
    ('constructor_bridge_finish', 0x5a6c604, '488dbc24b0020000488db42440120000b915000000ff1579f6a700'),
    ('parent_call_constructor', 0x2cb7a09, '4889ef4c89f6ff152bfa8203'),
    ('bridge_repack_load', 0x5a08f8f, '4889fb4c8bb6200400004c8bbe28040000440fb6a6300400000fb6ae310400004c897c2408'),
    ('bridge_repack_fields', 0x5a08fc2, '4c89b424600400004488a4247c0400004c89bc2468040000'),
    ('bridge_repack_call', 0x5a09014, '488dbc24800400004c89f6e89ceeffff'),
    ('bridge_repack_return', 0x5a09063, '488d742410ba700400004889dfff159264ad00'),
    ('bridge_output_capture', 0x5649691, '4889cb4989d54989f44989fe'),
    ('bridge_output_stage', 0x5649810, '4c8dbc2400040000ba700400004c89ff4c89e6ff15df5ce900'),
    ('bridge_output_copy', 0x5649b66, '498dbea8060000488db424f80300004c8b3d8c59e900ba7804000041ffd7'),
    ('bridge_output_initial', 0x5649c75, '49c786500b00000000000049c786580b000060ea000049c786600b00002005080049c786680b000000000000'),
    ('alternate_entry', 0x5649071, '4989f54989fe488954247048894c247848897424104889742418488d4424704889442420488dbc24c8000000488d742410ba01000000e824bf7fff4d8dbd500b0000b10131c0f0410fb08d500b00000f85bc040000'),
    ('alternate_bucket', 0x5649173, '31c04885c9480f4fc1498b8d580b00004889c24809ca48c1ea20741331d248f7f1493b85600b00007716e95303000031d2f7f1493b85600b00000f8642030000498985600b0000'),
    ('alternate_reset', 0x56491f7, '49c785680b000000000000'),
    ('alternate_counter', 0x56494ef, '0f85f8000000498b85680b000048ffc048c7c1ffffffff480f45c849898d680b000031c9b001f0410fb08d500b00007575488db424c8000000baa00000004c89f7ff15d25fe900'),
    ('alternate_failure', 0x56492d3, '488b5c24784885db790d31ff4889deff15b061e9000f0b'),
    ('followup_inner_write', 0x2ae3dd6, '488d7b704c89e6e8ae6409004989c54989d44883f801751bc645000341bd0100000041f6c501743f41c60645b003e99e020000'),
    ('followup_inner_error', 0x2ae3ef6, '488b732040b53f4889f048f7d80f8062010000'),
    ('followup_inner_success', 0x2ae3ff2, '488b732040b5444889f048f7d8706a'),
    ('context_snapshot_owner', 0x4fc2439, '488d93b0060000'),
    ('context_snapshot_state', 0x5444fc6, '488d9e50040000'),
    ('future_state_one_two', 0x2acf79d, '488d3de4809703ff15b61ba103e97c120000488d3dd2809703ff15ac1ba103e96a120000'),
    ('future_state_five', 0x2ad01e3, '488db3b8120000488dbc24900100004c89e2e8e60b210080bc2490010000030f840a020000'),
    ('future_state_six', 0x2ad03a8, '488dbb881200004c89e6e8d99e0a00a801755f4989d680bb9815000003750c488dbbb0120000e84d51ffff4d85f60f8599000000'),
    ('future_state_seven', 0x2ad0273, '4c8dab881200004c8db424d00200004c89f74c89ee4c89e2e8900601000fb6ac24d00200004080fd450f8474010000'),
    ('future_unwind_landing', 0x2acfbb2, '48894424084c89f7e8b1d2fcffe90d110000'),
    ('future_unwind_release', 0x2ad0cd1, '488bb3181200004889f048f7d8701a731880bb7d12000000740f488bbb2012000031d2ff15a6e7a003c6837d12000000488b8310120000f048ff08750d488dbb10120000ff15c54ea103488b83d0110000f048ff08750d488dbbd0110000ff153b65a103'),
    ('send_unwind_release', 0x2b7a24f, '4989c680bb38030000037509488d7b50e8bcb2f4ff488b73104885f6740c488b7b1831d2ff1527529603c68350030000024c89f7e8c8678703'),
    ('future_mode_mask', 0x2ace4f6, '0fb66c24274080e501'),
    ('future_mode_save', 0x2ace609, '4088abf0020000'),
    ('poll_bad_refcount', 0x2ad5dc9, '0f0b'),
    ('alternate_allocation_failure', 0x5649601, 'bf010000004c8bbc24980000004c89f5e9c9fcffff'),
    ('context_preflight_selected', 0x5a07ed1, '4989f64889fb488bb6500400004c8b7e2848b8917efb3a70ce88d2490fafc748c1c80448b9cc10c7bab88d06004839c8722283bee81000000175344c39bef01000000f824a060000400f94c541833e02740beb2340b50141833e02751a48b80000000000000080488903e91106000031ed41833e0274e6'),
    ('context_preflight_return', 0x5a08551, '4881c4b80100005b415c415d415e415f5dc3'),
    ('bridge_repack_sentinel', 0x5a09024, '488bb424800400004889f048f7d8702f'),
    ('context_parent_result', 0x2cb7761, '488dbc24300700004c89f6488b542408e86a44000083bc243007000002750941c60703e994080000488dbc24d01b0000488db42430070000ba80030000ff15647d8203488bac24b00a0000'),
]

FUNCTIONS = [
    ('bridge_repack', 0x5a08f80), ('bridge_owner_builder', 0x5649680),
    ('task_constructor', 0x2ad5600), ('task_poll', 0x2ad5980),
    ('executor_a_adapter', 0x2b3f300), ('executor_a_constructor', 0x2cd1070),
    ('executor_a_poll', 0x2b1d9a0), ('executor_b_adapter', 0x2b403a0),
    ('executor_b_constructor', 0x2cd1970), ('executor_b_poll', 0x2b26920),
    ('greeting_future', 0x2accee0), ('alternate_greeting_boundary', 0x5649060),
    ('greeting_send_future', 0x2b7a140), ('prepare_record', 0x2700cc0),
    ('encode_record', 0x232b860), ('encoded_size', 0x2cd6aa0),
    ('encode_writer', 0x2cd6de0), ('unsigned_writer', 0x2935e30),
    ('followup_future', 0x2ae27c0), ('followup_write_future', 0x2ae3cc0),
]

# Each entry is (label, instruction address, expected direct target). The
# instruction bytes, opcode and relative displacement are read from the ELF.
TRANSFERS = [
    ('context_parent_to_constructor', 0x2cb857d, 0x2ad5600),
    ('context_constructor_repack', 0x5a6c5f8, 0x5a08f80),
    ('repack_existing_preflight_boundary', 0x5a0901f, 0x5a07ec0),
    ('context_preflight_selected', 0x5a07f01, 0x5a07f25),
    ('context_preflight_not_two', 0x5a07f2c, 0x5a07f48),
    ('context_preflight_return', 0x5a07f3b, 0x5a08551),
    ('repack_sentinel_fast_path', 0x5a09032, 0x5a09063),
    ('capture_bad_refcount', 0x2ad562c, 0x2ad5879),
    ('capture_bad_alloc', 0x2ad57f9, 0x2ad5869),
    ('capture_schedule', 0x2ad583f, 0x15d6730),
    ('poll_first', 0x2ad59c0, 0x2ad59d8),
    ('poll_resume', 0x2ad59c5, 0x2ad5de6),
    ('poll_bad_refcount', 0x2ad5e7a, 0x2ad5dc9),
    ('poll_nonterminal', 0x2ad6060, 0x2ad607e),
    ('thread_mode_one', 0x2ad61d8, 0x2ad6285),
    ('thread_mode_other', 0x2ad61e1, 0x2ad6270),
    ('thread_counter_limit', 0x2ad62b2, 0x2ad6368),
    ('executor_unavailable', 0x2ad62e4, 0x2ad637a),
    ('choose_executor_b', 0x2ad6318, 0x2ad632f),
    ('executor_a', 0x2ad6325, 0x2b3f300),
    ('executor_b', 0x2ad633a, 0x2b403a0),
    ('adapter_a_construct', 0x2b3f328, 0x2cd1070),
    ('adapter_b_construct', 0x2b403cf, 0x2cd1970),
    ('constructor_a_schedule', 0x2cd11e7, 0x2cd0910),
    ('constructor_b_schedule', 0x2cd1ae7, 0x2cd06c0),
    ('executor_a_poll_future', 0x2b1db89, 0x2accee0),
    ('executor_b_poll_future', 0x2b26b09, 0x2accee0),
    ('select_no_snapshot', 0x2ace974, 0x2aceba5),
    ('snapshot_boundary', 0x2ace996, 0x5648a30),
    ('alternate_boundary', 0x2acebc4, 0x5649060),
    ('alternate_aggregate_boundary', 0x56490a7, 0x4e44fd0),
    ('alternate_guard_contended', 0x56490c0, 0x5649582),
    ('alternate_small_divide', 0x564918d, 0x56491a2),
    ('alternate_bucket_advanced', 0x564919b, 0x56491b3),
    ('alternate_bucket_unchanged', 0x564919d, 0x56494f5),
    ('alternate_small_bucket_unchanged', 0x56491ad, 0x56494f5),
    ('alternate_allocation_failed', 0x564931c, 0x5649601),
    ('alternate_guard_release_contended', 0x564951e, 0x5649595),
    ('alternate_alloc_failure', 0x2acec0a, 0x2acf5a6),
    ('greeting_send', 0x2acecde, 0x2b7a140),
    ('greeting_send_pending', 0x2acece7, 0x2ad041c),
    ('greeting_send_zero_result', 0x2aced2c, 0x2acef00),
    ('greeting_unwind_cleanup', 0x2acfbba, 0x2a9ce70),
    ('greeting_unwind_release', 0x2acfbbf, 0x2ad0cd1),
    ('followup_disabled', 0x2acf051, 0x2acf35e),
    ('followup_absent', 0x2acf064, 0x2acf278),
    ('followup_poll', 0x2ace9ba, 0x2ae27c0),
    ('followup_not_pending', 0x2ace9cb, 0x2ace9d4),
    ('followup_pending', 0x2ace9cf, 0x2ad041c),
    ('followup_other_result', 0x2acea38, 0x2acf0ec),
    ('state_five_poll_boundary', 0x2ad01f5, 0x2ce0de0),
    ('state_five_pending', 0x2ad0202, 0x2ad0412),
    ('state_six_existing_write_boundary', 0x2ad03b2, 0x2b7a290),
    ('state_six_pending', 0x2ad03b9, 0x2ad041a),
    ('state_six_error', 0x2ad03d6, 0x2ad0475),
    ('state_seven_poll_boundary', 0x2ad028b, 0x2ae0920),
    ('state_seven_pending', 0x2ad029c, 0x2ad0416),
    ('followup_inner', 0x2ae2fc1, 0x2ae3cc0),
    ('followup_existing_write_boundary', 0x2ae3ddd, 0x2b7a290),
    ('prepare_greeting', 0x2b7a182, 0x2700cc0),
    ('send_existing_write_boundary', 0x2b7a1b7, 0x2b7a290),
    ('send_completed', 0x2b7a1be, 0x2b7a1d2),
    ('send_unwind_cleanup', 0x2b7a25f, 0x2ac5520),
    ('send_unwind_resume', 0x2b7a283, 0x63f0a50),
    ('prepare_encode', 0x2700d70, 0x232b860),
    ('prepare_encode_instrumented', 0x2700f18, 0x232b860),
    ('prepare_error_result', 0x2700dc8, 0x2700ddd),
    ('size_pass', 0x232b89d, 0x2cd6aa0),
    ('size_pass_error', 0x232b8a7, 0x232b8d5),
    ('negative_size', 0x232b8b1, 0x232b97c),
    ('zero_size', 0x232b8b7, 0x232b8eb),
    ('allocation_ok', 0x232b8c5, 0x232b8f0),
    ('writer_pass', 0x232b91a, 0x2cd6de0),
    ('writer_pass_error', 0x232b924, 0x232b943),
    ('zero_tag_capacity', 0x2cd6e31, 0x2cd724d),
    ('zero_length_write', 0x2cd6e5a, 0x2935e30),
    ('zero_length_error', 0x2cd6e68, 0x2cd7064),
    ('uint_extended', 0x2935e42, 0x2935e61),
    ('uint_32_or_more', 0x2935e68, 0x2935ead),
    ('uint_64', 0x2935eb4, 0x2935ef3),
    ('uint_16_little_endian', 0x2935e89, 0x2935e8f),
    ('uint_32_little_endian', 0x2935ed5, 0x2935ed9),
    ('uint_64_little_endian', 0x2935f12, 0x2935f17),
]

TABLES = [
    ('future_states', 0x603e38, 8, 0x2accee0),
    ('send_states', 0x604cac, 4, 0x2b7a140),
    ('size_cases', 0x60be4c, 6, 0x2cd6aa0),
    ('writer_cases', 0x60be64, 6, 0x2cd6de0),
]

LITERALS = [
    ('snapshot_label', 0x917534, b'ReplicaCmd::compute_abci_greeting'),
    ('alternate_label', 0x917555, b'ReplicaCmd::compute_no_abci_greeting'),
    ('send_label', 0x60570b, b'send abci greeting'),
    ('error_label', 0x60571d, b'could not send abci_state'),
    ('success_label', 0x605736, b'successfully sent abci_state'),
]

# Descriptor entries are new; the constructor's indirect target is retained
# strictly as context for the newly selected builder, not as owned GOT work.
RELOCS = [
    ('task_poll_descriptor', 0x64478f0, 0x2ad5980, 'selected'),
    ('executor_a_descriptor', 0x6449600, 0x2b1d9a0, 'selected'),
    ('executor_b_descriptor', 0x6449790, 0x2b26920, 'selected'),
    ('location_file_pointer', 0x64767a8, 0x443168, 'context'),
    ('constructor_builder_target', 0x64ebc98, 0x5649680, 'context'),
]


def verify_digest(data):
    if hashlib.sha256(data).hexdigest() != TARGET:
        raise ValueError('node 115 SHA-256 mismatch')


def mapping(secs, addr, length, *, executable=False):
    if not isinstance(addr, int) or not isinstance(length, int) or addr < 0 or length <= 0:
        raise ValueError('invalid address or length')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= addr and addr + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address lacks a unique file-backed section')
    s = matches[0]
    return s, s['offset'] + addr - s['address']


def read_va(data, secs, addr, length, *, executable=False):
    _, off = mapping(secs, addr, length, executable=executable)
    if off + length > len(data):
        raise ValueError('address outside file')
    return data[off:off + length]


def read_windows(read):
    out = {}
    for name, addr, expected_hex in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        observed = read(addr, len(expected))
        if observed != expected:
            raise ValueError('instruction window differs: ' + name)
        if name in out:
            raise ValueError('duplicate window name')
        out[name] = (addr, observed)
    return out


def direct_transfer(read, addr):
    op = read(addr, 1)[0]
    names = {0x70: 'jo', 0x72: 'jb', 0x73: 'jae', 0x74: 'je',
             0x75: 'jne', 0x76: 'jbe', 0x77: 'ja', 0x78: 'js',
             0x79: 'jns', 0x7e: 'jle', 0x7f: 'jg'}
    if op in (0xe8, 0xe9):
        raw = read(addr, 5)
        return ('call' if op == 0xe8 else 'jmp', addr + 5 + struct.unpack_from('<i', raw, 1)[0], raw)
    if op in names:
        raw = read(addr, 2)
        return names[op], addr + 2 + struct.unpack_from('<b', raw, 1)[0], raw
    if op == 0x0f:
        raw = read(addr, 6)
        short = raw[1] - 0x10
        if short in names:
            return names[short], addr + 6 + struct.unpack_from('<i', raw, 2)[0], raw
    raise ValueError('unsupported direct transfer encoding')


def decode_rel_table(read, base, count, lower, upper):
    if not 0 < count <= 256:
        raise ValueError('invalid selected table length')
    raw = read(base, 4 * count)
    if len(raw) != 4 * count:
        raise ValueError('truncated table')
    offsets = [x[0] for x in struct.iter_unpack('<i', raw)]
    targets = [base + delta for delta in offsets]
    if any(not lower <= target < upper for target in targets):
        raise ValueError('table target outside selected FDE')
    return list(zip(offsets, targets))


def relative_relocations(data, secs, wanted):
    candidates = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('unsupported dynamic relocation section')
    s = candidates[0]
    if s['offset'] < 0 or s['offset'] + s['size'] > len(data):
        raise ValueError('dynamic relocation section outside file')
    body = data[s['offset']:s['offset'] + s['size']]
    wanted = set(wanted)
    found = {}
    for off, info, addend in struct.iter_unpack('<QQq', body):
        if off in wanted:
            if off in found or info != 8:
                raise ValueError('ambiguous or non-relative selected relocation')
            found[off] = addend
    if set(found) != wanted:
        raise ValueError('missing selected relocation')
    return found


def find_relocations(data, secs):
    found = relative_relocations(data, secs, (slot for _, slot, _, _ in RELOCS))
    if any(found[slot] != expected for _, slot, expected, _ in RELOCS):
        raise ValueError('unexpected relocation addend')
    return found


def location_reference(read, site, opcode):
    raw = read(site, 7)
    if len(raw) != 7 or raw[:3] != opcode:
        raise ValueError('unexpected Location reference encoding')
    return site + len(raw) + struct.unpack_from('<i', raw, 3)[0], raw


def validate_historical(data):
    """Optional separately authenticated comparison; output files stay identical."""
    if hashlib.sha256(data).hexdigest() != HISTORICAL_TARGET:
        raise ValueError('node 94 SHA-256 mismatch')
    secs = sections(data)
    read = lambda a, n: read_va(data, secs, a, n)
    slot = 0x56dfbf8
    pointer, size, line, column = struct.unpack('<QQII', read(slot, 24))
    if pointer != 0 or size != 49 or (line, column) != (107, 37):
        raise ValueError('node 94 Location record differs')
    name_va = relative_relocations(data, secs, [slot])[slot]
    name = read(name_va, size)
    if not name.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('node 94 Location suffix differs')
    target, _ = location_reference(read, 0x3273856, bytes.fromhex('488d0d'))
    if target != slot or read(0x3273871, 4) != bytes.fromhex('4983fd02'):
        raise ValueError('node 94 Location caller differs')


def parse_lsda(data, secs, fde):
    """Decode selected ULEB call-site rows; leave action tables uninterpreted."""
    if fde['lsda'] is None:
        return []
    candidates = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(candidates) != 1:
        raise ValueError('missing or ambiguous exception section')
    sec = candidates[0]
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    _, pos = mapping(secs, va, 1)
    limit = sec['offset'] + sec['size']
    if sec['offset'] < 0 or limit > len(data):
        raise ValueError('exception section outside file')
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA pointer encoding')
    encoding = data[pos + 1]
    pos += 2
    if encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    else:
        type_base = limit
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    table_size, pos = uleb(data, pos + 1, limit)
    end = pos + table_size
    if end > limit or end > type_base:
        raise ValueError('LSDA call-site table outside bounds')
    rows = []
    while pos < end:
        begin = pos
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        span = fde['end'] - fde['start']
        if start + length > span or (landing and landing >= span):
            raise ValueError('LSDA call-site or landing outside FDE')
        rows.append({'lsda': va, 'file_offset': begin, 'start': fde['start'] + start,
                     'end': fde['start'] + start + length,
                     'landing': fde['start'] + landing if landing else None,
                     'action': action, 'raw': bytes(data[begin:pos])})
    if pos != end:
        raise ValueError('misaligned LSDA table')
    return rows


def callsite_witness(entries, site, length):
    if length <= 0:
        raise ValueError('invalid call instruction length')
    partial = [e for e in entries if site < e['end'] and e['start'] < site + length
               and not (e['start'] <= site and site + length <= e['end'])]
    if partial:
        raise ValueError('call instruction crosses LSDA call-site boundary')
    hits = [e for e in entries if e['start'] <= site and site + length <= e['end']]
    if len(hits) > 1:
        raise ValueError('ambiguous call-site range')
    return hits[0] if hits else None


def map_copy(pos, src, dst, size, width=8):
    if width <= 0 or size < 0 or min(pos, src, dst) < 0 or not src <= pos or pos + width > src + size:
        raise ValueError('tracked value outside copied range')
    return dst + pos - src


def tsv(header, rows):
    f = io.StringIO(newline='')
    writer = csv.writer(f, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return f.getvalue().encode('utf-8')


def emit_json(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def flow_rows(read, windows):
    """Evaluate only the pinned loads, stores and bounded memcpy equations."""
    def field(addr, size=4):
        if not any(start <= addr and addr + size <= start + len(raw)
                   for start, raw in windows.values()):
            raise ValueError('field is outside checked instruction windows')
        raw = read(addr, size)
        return int.from_bytes(raw, 'little', signed=False)

    rows = []
    def move(name, site, src_space, src, dst_space, dst):
        rows.append((name, hex(site), src_space, hex(src), dst_space, hex(dst), '0x8', hex(src), hex(dst), '0x8'))
        return dst

    def cp(name, site, src_space, src, dst_space, dst, size, pos, width=8):
        out = map_copy(pos, src, dst, size, width)
        rows.append((name, hex(site), src_space, hex(src), dst_space, hex(dst), hex(size), hex(pos), hex(out), hex(width)))
        return out

    # The previously studied constructor's first argument is captured in its
    # stack and propagated through two separately selected builder functions.
    p = field(0x5a6c3a0)
    p = cp('bridge_capture_copy', 0x5a6c5d8, 'constructor_stack', field(0x5a6c5cf),
           'constructor_stack', field(0x5a6c5c7), field(0x5a6c5d4), p)
    p -= field(0x5a6c5c7)
    if p != field(0x5a08f95):
        raise ValueError('bridge repack input join failed')
    p = move('bridge_repack_save', 0x5a08fc2, 'repack_input', p,
             'repack_stack', field(0x5a08fc6))
    p = cp('bridge_repack_return', 0x5a09070, 'repack_stack', field(0x5a09067, 1),
           'constructor_stack', field(0x5a6c5ec), field(0x5a09069), p)
    p -= field(0x5a6c5ec)
    p = cp('bridge_builder_stage', 0x5649823, 'builder_input', 0,
           'builder_stack', field(0x5649814), field(0x5649819), p)
    p = cp('bridge_builder_output', 0x5649b81, 'builder_stack', field(0x5649b71),
           'builder_output', field(0x5649b69), field(0x5649b7d), p)
    p += field(0x5a6c643)
    p = cp('bridge_allocation_stage', 0x5a6c64f, 'constructor_stack', field(0x5a6c643),
           'constructor_stack', field(0x5a6c63b), field(0x5a6c648), p)
    p = cp('bridge_allocation_copy', 0x5a6c678, 'constructor_stack', field(0x5a6c66c),
           'owner_allocation', 0, field(0x5a6c671), p)
    p -= field(0x2ace984, 1)
    # Existing snapshot work reaches its owner's body +0xb00. Decode that
    # offset independently as the destination of the second builder copy.
    builder_field = field(0x5649b69) + field(0x5649814) + field(0x5a08fc6) - field(0x5a09067, 1) - field(0x5649b71)
    previous_snapshot_field = field(0x4fc243c) + field(0x5444fc9)
    if p != builder_field or p != previous_snapshot_field:
        raise ValueError('owner body field join failed')
    rows.append(('owner_body', hex(0x2ace981), 'owner_allocation', hex(p + field(0x2ace984, 1)),
                 'owner_body', hex(p), '0x8', hex(p + field(0x2ace984, 1)), hex(p), '0x8'))

    # Constructor return RDX was saved in the parent; RAX comes from a separate
    # allocation request. The two returned pointer values are not equated.
    p = field(0x2cb7e30)
    p = cp('parent_stage_1', 0x2cb7e84, 'parent_stack', field(0x2cb7e70),
           'parent_stack', field(0x2cb7e78), field(0x2cb7e7d), p)
    p = cp('parent_stage_2', 0x2cb800e, 'parent_stack', field(0x2cb7e78),
           'parent_stack', field(0x2cb8002), field(0x2cb8007), p)
    p = cp('parent_stage_3', 0x2cb804e, 'parent_stack', field(0x2cb8045),
           'parent_stack', field(0x2cb803d), field(0x2cb804a), p)
    p = cp('parent_stage_4', 0x2cb8083, 'parent_stack', field(0x2cb807a),
           'parent_object', field(0x2cb8072), field(0x2cb807f), p)
    if p != field(0x2cb842b):
        raise ValueError('parent field join failed')

    # The callee saves RCX in the copied task capture.
    p = cp('task_capture', 0x2ad580e, 'constructor_stack', field(0x2ad5802),
           'task_object', 0, field(0x2ad5807), field(0x2ad5707))
    if p != field(0x2ad5a2c):
        raise ValueError('initial task field join failed')
    p = move('task_state_save', 0x2ad5c54, 'task_object', p,
             'task_object', field(0x2ad5c57))
    if p != field(0x2ad5e72):
        raise ValueError('resumed task field join failed')
    p = move('task_resume', 0x2ad5fc0, 'task_object', p,
             'poll_stack', field(0x2ad5fc4))
    p = cp('poll_copy_1', 0x2ad6128, 'poll_stack', field(0x2ad611b, 1),
           'poll_stack', field(0x2ad6113), field(0x2ad6124), p)
    p = cp('poll_copy_2', 0x2ad6196, 'poll_stack', field(0x2ad618a),
           'poll_stack', field(0x2ad6182), field(0x2ad618f), p)
    p = cp('poll_copy_3', 0x2ad6307, 'poll_stack', field(0x2ad62f6),
           'poll_stack', field(0x2ad62fe), field(0x2ad6303), p)
    child_argument_base = field(0x2ad62fe)
    p = move('child_argument', 0x2ad6325, 'poll_stack', p,
             'child_input', p - child_argument_base)

    # Both constructor variants have the same layout and copy lengths.
    for delta in (0, 0x900):
        prefix = 'executor_a' if delta == 0 else 'executor_b'
        first_dst = field(0x2cd1113 + delta)
        first_size = field(0x2cd111f + delta)
        second_dst = field(0x2cd1178 + delta)
        second_src = field(0x2cd1180 + delta)
        second_size = field(0x2cd1185 + delta)
        base = field(0x2cd11cc + delta)
        q = cp(prefix + '_input_copy', 0x2cd1123 + delta,
               'child_input', 0, 'executor_stack', first_dst, first_size, p)
        q = cp(prefix + '_stack_copy', 0x2cd1189 + delta,
               'executor_stack', second_src, 'executor_stack', second_dst, second_size, q)
        q = cp(prefix + '_allocation_copy', 0x2cd11d8 + delta,
               'executor_stack', base, 'executor_allocation', 0,
               field(0x2cd11d1 + delta), q)
        wrapper_body = field((0x2b1db7e if delta == 0 else 0x2b26afe), 1)
        q = move(prefix + '_body', 0x2b1db7b if delta == 0 else 0x2b26afb,
                 'executor_allocation', q, 'future_object', q - wrapper_body)
        if q != field(0x2ace521):
            raise ValueError('executor future argument join failed')

    p = move('future_save', 0x2ace5c2, 'future_object', field(0x2ace521),
             'future_object', field(0x2ace5c5))
    p = cp('future_copy_1', 0x2ace675, 'future_object', field(0x2ace65d),
           'future_stack', field(0x2ace665), field(0x2ace671), p)
    p = cp('future_copy_2', 0x2ace690, 'future_stack', field(0x2ace684),
           'future_stack', field(0x2ace67c), field(0x2ace689), p)
    p = cp('future_copy_3', 0x2ace6a7, 'future_stack', field(0x2ace67c),
           'future_object', field(0x2ace696), field(0x2ace69b), p)
    p = cp('future_copy_4', 0x2ace6f8, 'future_object', field(0x2ace6e7),
           'future_stack', field(0x2ace6ef), field(0x2ace6f4), p)
    p = cp('future_copy_5', 0x2ace84a, 'future_stack', field(0x2ace83a),
           'future_stack', field(0x2ace832), field(0x2ace846), p)
    p = cp('future_copy_6', 0x2ace8dd, 'future_stack', field(0x2ace8d1),
           'future_stack', field(0x2ace8c9), field(0x2ace8d6), p)
    p = cp('future_copy_7', 0x2ace8ed, 'future_stack', field(0x2ace8c9),
           'future_object', field(0x2ace696), field(0x2ace8e1), p)
    if p != field(0x2ace97d) or p != field(0x2aceba8):
        raise ValueError('snapshot argument join failed')

    # The branch mode is a separate one-byte value, not the pointer above.
    # Its earlier source is only known as a masked byte in the current frame.
    q = field(0x2ace60c)
    q = cp('mode_copy_1', 0x2ace675, 'future_object', field(0x2ace65d),
           'future_stack', field(0x2ace665), field(0x2ace671), q, width=1)
    q = cp('mode_copy_2', 0x2ace690, 'future_stack', field(0x2ace684),
           'future_stack', field(0x2ace67c), field(0x2ace689), q, width=1)
    q = cp('mode_copy_3', 0x2ace6a7, 'future_stack', field(0x2ace67c),
           'future_object', field(0x2ace696), field(0x2ace69b), q, width=1)
    q = cp('mode_copy_4', 0x2ace6f8, 'future_object', field(0x2ace6e7),
           'future_stack', field(0x2ace6ef), field(0x2ace6f4), q, width=1)
    q = cp('mode_copy_5', 0x2ace84a, 'future_stack', field(0x2ace83a),
           'future_stack', field(0x2ace832), field(0x2ace846), q, width=1)
    q = cp('mode_copy_6', 0x2ace8dd, 'future_stack', field(0x2ace8d1),
           'future_stack', field(0x2ace8c9), field(0x2ace8d6), q, width=1)
    q = cp('mode_copy_7', 0x2ace8ed, 'future_stack', field(0x2ace8c9),
           'future_object', field(0x2ace696), field(0x2ace8e1), q, width=1)
    if q != field(0x2ace96f):
        raise ValueError('snapshot mode join failed')
    return rows


def unsigned_model(n, small, wide, shift, tags):
    """A synthetic model for the selected little-endian integer writes."""
    if not isinstance(n, int) or n < 0 or n >= (1 << 64):
        raise ValueError('integer outside unsigned 64-bit domain')
    if small <= 0 or wide <= small or shift <= 0 or shift >= 64 or len(tags) != 3:
        raise ValueError('invalid encoding parameters')
    if n < small:
        return bytes([n])
    if n < wide:
        return bytes([tags[0]]) + n.to_bytes(2, 'little')
    if n < (1 << shift):
        return bytes([tags[1]]) + n.to_bytes(4, 'little')
    return bytes([tags[2]]) + n.to_bytes(8, 'little')


def bucket_model(old_bucket, old_count, quotient, maximum):
    """Model selected bookkeeping after a nonzero-divisor quotient exists."""
    if any(not isinstance(x, int) or x < 0 or x > maximum
           for x in (old_bucket, old_count, quotient)):
        raise ValueError('bucket value outside unsigned word')
    if quotient > old_bucket:
        old_bucket, old_count = quotient, 0
    return old_bucket, min(old_count + 1, maximum)


def preflight_witness(read):
    """Check the selected sentinel write does not overlap the saved pointer."""
    saved = read(0x5a08fc2, 8)
    output = read(0x5a09014, 8)
    tag = read(0x5a07f28, 4)
    sentinel = read(0x5a07f2e, 10)
    if (saved[:4] != bytes.fromhex('4c89b424') or output[:4] != bytes.fromhex('488dbc24')
            or tag[:3] != bytes.fromhex('41833e') or sentinel[:2] != bytes.fromhex('48b8')):
        raise ValueError('unexpected preflight witness instruction')
    saved_offset = struct.unpack_from('<I', saved, 4)[0]
    output_offset = struct.unpack_from('<I', output, 4)[0]
    if not (saved_offset + 8 <= output_offset or output_offset + 8 <= saved_offset):
        raise ValueError('preflight output overlaps tracked slot')
    return {'saved_pointer_stack_offset': saved_offset, 'output_stack_offset': output_offset,
            'selected_input_tag': tag[3], 'sentinel': struct.unpack_from('<Q', sentinel, 2)[0]}


def parent_result_witness(read):
    """Check that the pointer load is just beyond the copied result prefix."""
    result = read(0x2cb7761, 8)
    copy_len = read(0x2cb7799, 5)
    load = read(0x2cb77a4, 8)
    if (result[:4] != bytes.fromhex('488dbc24') or copy_len[:1] != b'\xba'
            or load[:4] != bytes.fromhex('488bac24')):
        raise ValueError('unexpected parent result instruction')
    base = struct.unpack_from('<I', result, 4)[0]
    length = struct.unpack_from('<I', copy_len, 1)[0]
    pointer = struct.unpack_from('<I', load, 4)[0]
    if pointer < base or pointer - base != length:
        raise ValueError('parent result pointer is not just past copied prefix')
    return {'result_stack_offset': base, 'copied_prefix_length': length,
            'pointer_stack_offset': pointer, 'pointer_result_offset': pointer - base}


def derive_constants(read):
    def pattern(addr, expected):
        raw = read(addr, len(expected))
        if raw != expected:
            raise ValueError('constant instruction pattern mismatch')
        return raw
    small = struct.unpack_from('<I', pattern(0x2935e3b, bytes.fromhex('4881f9fb000000')), 3)[0]
    wide = struct.unpack_from('<I', pattern(0x2935e61, bytes.fromhex('4881f900000100')), 3)[0]
    shift = pattern(0x2935eb0, bytes.fromhex('48c1ef20'))[-1]
    tags = [pattern(a, bytes.fromhex(v))[-1] for a, v in (
        (0x2935e7b, '42c6040ffb'), (0x2935ec7, '42c6040ffc'), (0x2935f04, '42c6040ffd'))]
    pattern(0x2cd6e55, bytes.fromhex('31d2'))  # caller selects the no-swap path
    marker_sites = [0x2cd6e3b, 0x2cd6fbc, 0x2cd6f7f, 0x2cd6f9a, 0x2cd6f64, 0x2cd7043]
    markers = []
    for index, addr in enumerate(marker_sites):
        raw = read(addr, 4)
        if raw[:3] not in (bytes.fromhex('c60430'), bytes.fromhex('c60431')):
            raise ValueError('unexpected writer marker instruction')
        if raw[3] != index:
            raise ValueError('writer marker does not match selected case')
        markers.append(raw[3])
    divisor = struct.unpack_from('<I', pattern(0x5649c80, bytes.fromhex('49c786580b000060ea0000')), 7)[0]
    bucket = struct.unpack_from('<I', pattern(0x5649c8b, bytes.fromhex('49c786600b000020050800')), 7)[0]
    maximum = struct.unpack('<q', struct.pack('<q', struct.unpack_from('<i',
        pattern(0x56494ff, bytes.fromhex('48c7c1ffffffff')), 3)[0]))[0] & ((1 << 64) - 1)
    pattern(0x56494fc, bytes.fromhex('48ffc0'))
    pattern(0x5649506, bytes.fromhex('480f45c8'))
    return small, wide, shift, tags, marker_sites, markers, divisor, bucket, maximum


def build_reports(data):
    verify_digest(data)
    secs = sections(data)
    read = lambda a, n: read_va(data, secs, a, n)
    windows = read_windows(read)
    _, fdes = eh_frame_records(data, secs)
    _, index = unwind_index(data)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    idx = {row['start']: row for row in index}
    selected = {}
    function_rows = []
    for label, start in FUNCTIONS:
        records = by_start.get(start, [])
        if len(records) != 1 or start not in idx:
            raise ValueError('missing or ambiguous indexed FDE')
        f = records[0]
        if f['fde'] != idx[start]['fde'] or f['end'] <= start:
            raise ValueError('unwind header and FDE do not agree')
        sec, off = mapping(secs, start, f['end'] - start, executable=True)
        selected[start] = f
        body = data[off:off + f['end'] - start]
        function_rows.append((label, hex(start), hex(f['end']), sec['name'], hex(off),
                              hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                              hashlib.sha256(body).hexdigest()))

    window_rows = []
    for label, start, _ in WINDOWS:
        raw = windows[label][1]
        sec, off = mapping(secs, start, len(raw), executable=True)
        scope = 'context' if label.startswith(('constructor_', 'parent_', 'context_')) else 'selected'
        window_rows.append((label, scope, hex(start), hex(start + len(raw)), sec['name'], hex(off), raw.hex()))

    transfer_rows = []
    direct_calls = []
    for label, site, expected in TRANSFERS:
        kind, target, raw = direct_transfer(read, site)
        if target != expected:
            raise ValueError('direct transfer target differs: ' + label)
        sec, off = mapping(secs, site, len(raw), executable=True)
        scope = 'context' if label.startswith('context_') else 'selected'
        transfer_rows.append((label, scope, hex(site), sec['name'], hex(off), kind, raw.hex(), hex(target)))
        if scope == 'selected' and kind == 'call':
            direct_calls.append((label, site, target, len(raw)))

    unwind_rows = []
    by_function = {}
    for label, start in FUNCTIONS:
        entries = parse_lsda(data, secs, selected[start])
        by_function[start] = entries
        for e in entries:
            unwind_rows.append((label, hex(e['lsda']), hex(e['file_offset']),
                                hex(e['start']), hex(e['end']),
                                '' if e['landing'] is None else hex(e['landing']),
                                e['action'], e['raw'].hex()))
    unwind_links = []
    for label, site, target, length in direct_calls:
        owners = [f for f in selected.values() if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError('selected call is outside a unique FDE')
        owner = owners[0]
        e = callsite_witness(by_function[owner['start']], site, length)
        state = 'covered' if e is not None else ('no_lsda' if owner['lsda'] is None else 'no_row')
        unwind_links.append((label, hex(site), hex(target), hex(owner['start']), state,
                             '' if not e or e['landing'] is None else hex(e['landing']),
                             '' if not e else e['action']))

    table_rows = []
    for label, address, count, start in TABLES:
        f = selected[start]
        values = decode_rel_table(read, address, count, f['start'], f['end'])
        for ordinal, (delta, target) in enumerate(values):
            table_rows.append((label, hex(address), ordinal, hex(address + ordinal * 4),
                               str(delta), hex(target)))

    rels = find_relocations(data, secs)
    rel_rows = [(label, scope, hex(slot), 'R_X86_64_RELATIVE', hex(rels[slot]))
                for label, slot, _, scope in RELOCS]
    raw_indirect = read(0x5a6c619, 6)
    if raw_indirect[:2] != b'\xff\x15' or 0x5a6c61f + struct.unpack_from('<i', raw_indirect, 2)[0] != 0x64ebc98:
        raise ValueError('constructor builder slot does not match contextual relocation')
    loc = read(0x64767a8, 24)
    pointer, name_len, line, column = struct.unpack('<QQII', loc)
    if pointer != 0 or name_len != 20:
        raise ValueError('unexpected Location layout')
    name = read(rels[0x64767a8], name_len)
    if name != b'l1/src/abci/state.rs' or (line, column) != (123, 37):
        raise ValueError('unexpected Location identity')
    loc_target, loc_reference = location_reference(read, 0x3c1352f, bytes.fromhex('488d15'))
    loc_comparison = read(0x3c1353b, 4)
    if loc_target != 0x64767a8 or loc_comparison != bytes.fromhex('4883f801'):
        raise ValueError('node 115 Location caller differs')
    location = {'binary_sha256': TARGET, 'component_id': 'abci',
                'coordinate_system': 'ELF link-time virtual address',
                'location_va': hex(0x64767a8), 'raw_hex': loc.hex(),
                'file_pointer_relocation_va': hex(0x64767a8),
                'file_name_va': hex(rels[0x64767a8]), 'file_name': name.decode('ascii'),
                'line': line, 'column': column,
                'reference_va': hex(0x3c1352f), 'reference_hex': loc_reference.hex(),
                'comparison_va': hex(0x3c1353b), 'comparison_hex': loc_comparison.hex(),
                'interpretation': 'context anchor only; previously owned loader body excluded'}

    literal_rows = []
    for label, addr, expected in LITERALS:
        raw = read(addr, len(expected))
        if raw != expected:
            raise ValueError('literal differs: ' + label)
        sec, off = mapping(secs, addr, len(raw))
        literal_rows.append((label, hex(addr), sec['name'], hex(off), len(raw), raw.hex(), raw.decode('ascii')))

    small, wide, shift, tags, marker_sites, markers, divisor, bucket, maximum = derive_constants(read)
    marker_rows = [(i, hex(marker_sites[i]), markers[i]) for i in range(len(markers))]
    boundary_values = [0, small - 1, small, wide - 1, wide,
                       (1 << shift) - 1, 1 << shift, (1 << 64) - 1]
    vector_rows = [(str(n), unsigned_model(n, small, wide, shift, tags).hex()) for n in boundary_values]
    case_values = [(bucket, 0, bucket), (bucket, maximum - 1, bucket),
                   (bucket, maximum, bucket), (bucket, maximum, bucket + 1)]
    bucket_rows = [(str(old), str(count), str(quotient),
                    *(str(x) for x in bucket_model(old, count, quotient, maximum)))
                   for old, count, quotient in case_values]
    constants = {'binary_sha256': TARGET, 'unsigned_small_exclusive': small,
                 'unsigned_16_exclusive': wide, 'unsigned_32_limit_shift': shift,
                 'unsigned_extension_markers': tags, 'writer_case_markers': markers,
                 'initial_bucket_divisor': divisor, 'initial_bucket': bucket,
                 'counter_saturation_maximum': maximum,
                 'byte_order_on_selected_call': 'little',
                 'preflight_witness': preflight_witness(read),
                 'parent_result_witness': parent_result_witness(read),
                 'model_warning': 'Synthetic arithmetic model; no target execution or full message schema.'}

    reports = {
        'functions.tsv': tsv(['label', 'start_va', 'end_va_exclusive', 'section', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'body_sha256'], function_rows),
        'windows.tsv': tsv(['label', 'scope', 'start_va', 'end_va_exclusive', 'section', 'file_offset', 'raw_hex'], window_rows),
        'transfers.tsv': tsv(['label', 'scope', 'site_va', 'section', 'file_offset', 'opcode', 'raw_hex', 'target_va'], transfer_rows),
        'unwind.tsv': tsv(['function', 'lsda_va', 'file_offset', 'call_start_va', 'call_end_va_exclusive', 'landing_va', 'action', 'raw_hex'], unwind_rows),
        'unwind_links.tsv': tsv(['call', 'site_va', 'target_va', 'fde_start_va', 'status', 'landing_va', 'action'], unwind_links),
        'dispatch.tsv': tsv(['table', 'table_va', 'selected_index', 'entry_va', 'signed_delta', 'target_va'], table_rows),
        'relocations.tsv': tsv(['label', 'scope', 'slot_va', 'type', 'addend_va'], rel_rows),
        'flow.tsv': tsv(['step', 'site_va', 'source_space', 'source_offset', 'destination_space', 'destination_offset', 'copy_size', 'tracked_before', 'tracked_after', 'tracked_width'], flow_rows(read, windows)),
        'literals.tsv': tsv(['label', 'va', 'section', 'file_offset', 'byte_length', 'raw_hex', 'ascii'], literal_rows),
        'writer_markers.tsv': tsv(['case_index', 'instruction_va', 'byte'], marker_rows),
        'uint_model.tsv': tsv(['synthetic_input', 'expected_little_endian_hex'], vector_rows),
        'bucket_model.tsv': tsv(['synthetic_old_bucket', 'synthetic_old_count', 'synthetic_quotient', 'model_bucket', 'model_count'], bucket_rows),
        'location.json': emit_json(location),
        'constants.json': emit_json(constants),
    }
    reports['summary.json'] = emit_json({
        'binary_sha256': TARGET,
        'selected_fde_count': len(function_rows),
        'selected_window_count': sum(row[1] == 'selected' for row in window_rows),
        'context_window_count': sum(row[1] == 'context' for row in window_rows),
        'selected_transfer_count': sum(row[1] == 'selected' for row in transfer_rows),
        'context_transfer_count': sum(row[1] == 'context' for row in transfer_rows),
        'dispatch_entry_count': len(table_rows),
        'tracked_copy_and_move_count': len(flow_rows(read, windows)),
        'lsda_call_site_rows': len(unwind_rows),
        'direct_call_unwind_links': len(unwind_links),
        'covered_direct_calls': sum(row[4] == 'covered' for row in unwind_links),
        'calls_with_no_lsda': sum(row[4] == 'no_lsda' for row in unwind_links),
        'interpretation': 'Selected records only; these counts are not coverage or equivalence metrics.'
    })
    return reports


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical', type=Path, help='optional separately authenticated node 94 capture')
    args = parser.parse_args(argv)
    reports = build_reports(INPUT.read_bytes())
    if args.historical is not None:
        validate_historical(args.historical.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(reports):
        (args.out / name).write_bytes(reports[name])
    print('Wrote {} deterministic evidence files'.format(len(reports)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_greeting_115: {}'.format(error), file=sys.stderr)
        raise SystemExit(1)
