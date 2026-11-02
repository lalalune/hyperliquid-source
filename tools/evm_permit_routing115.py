#!/usr/bin/env python3
"""Produce byte-grounded evidence for the node 115 RPC permit path.

The selected instruction windows are frozen witnesses from a static analysis;
this program is deliberately not a general instruction decoder. Branches,
rel32 calls, RIP displacements, tables and relocations are decoded from ELF
bytes only. It never executes the captured program or calls external tools.
"""
from __future__ import annotations

import argparse
import bisect
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

# (label, linked virtual address, exact observed bytes). Each window starts at
# an instruction boundary and ends immediately before an instruction boundary.
WITNESSES = [
    ('merge_member_comparator_slot', 0x2f1ba41, '4c8b2db03f5c03'),
    ('merge_writer_comparator_slot', 0x2a322af, '4c8b3d42d7aa03'),
    ('merge_check_candidate', 0x2e378ed, 'f3410fbcc648f7d8488d0480498b54c5d8498b4cc5e0488dbc24f80000004c89feff159c0f6b03488bac24f80000004883fd030f85bb010000'),
    ('merge_member_call', 0x2f1bf5e, '4989fe488b3e4883c7104889d64889cae86df9ffff84c074104885db791431ff4889deff1511355c0349c70603000000eb3d'),
    ('merge_member_copy', 0x2f1bf90, '74224889dfff15e5345c034885c0743c4989c44889c74c89fe4889daff1556355c03eb0641bc0100000049c7060000000049895e084d89661049895e18'),
    ('merge_empty_set', 0x2f1b8e0, '48837f18007440'),
    ('merge_member_equal', 0x2f1ba76, 'f30fbcc54c01f84821d048f7d8488d0480493b5cc4e07519498d04c4488b70d84c89f74889da41ffd589c1b00185c97447'),
    ('merge_member_miss', 0x2f1bad0, '660f74da660fd7c385c075104901cf4983c7104883c110e95cffffff31c04883c4385b415c415d415e415f5dc3'),
    ('merge_reject', 0x2e37ae1, '488b84241001000048894424100f108424000100000f290424488dbc2490000000e81964fcff83fd030f8579070000'),
    ('merge_unwrap_error', 0x2e38289, '4889ac24f8000000660f6f0424f30f7f842400010000488b4424104889842410010000488d3d0fec7dfd488d0d869761034c8d0517ab6103488d9424f8000000be2b000000ff15cc736a03e9e4000000'),
    ('merge_insert_source', 0x2e37a6d, '488b54f8d8488b4cf8e0488b74f8e80f1044f8f00f298424800000004883fe04743e4889b424a8000000660f6f842480000000f3410f7f45004c89ff4c89f64d89e0e87ca6bfff'),
    ('merge_write_compare', 0x2a32300, 'f30fbcc34801e84821f848f7d8488d0480488b542420493b54c5e0751d4c8d34c5000000004d01ee498b76d84c89e741ffd785c00f8490000000'),
    ('merge_write_replace', 0x2a323ca, '498b4ef8488b44241848894810410f1046e80f1100488b4c24100f1001410f1146e8488b491049894ef8eb75'),
    ('merge_write_insert', 0x2a3243b, '49f7d84b8d14804d8964d5d8488b4c242049894cd5e0410f1006410f1144d5e8498b4e1049894cd5f848c70004000000'),
    ('registration_map_address', 0x2d02fae, '4983c408488b4c2418488948100f104424080f1100'),
    ('make_mut_unique', 0x2f1bb5d, '4989ff488b0f31d2b801000000f0480fb111488b1f751a488b43084883f8010f859600000048c703010000004989deeb75'),
    ('make_mut_shared_return', 0x2f1bbf1, 'f048ff0b75094c89ffff1590665c034d89374983c6104c89f0'),
    ('make_mut_weak_store', 0x2f1bc2c, '4989c648c7000100000048c74008010000000f1043100f104b200f1140100f114820498907'),
    ('router_merge_make_mut', 0x2e37935, '488d7c2470ff15780f6b034989c6488dbc2490000000ff15670f6b03'),
    ('router_box_callback', 0x2e381c6, '488d0513e9f9ff4889442420'),
    ('router_box_descriptor', 0x2e38201, '4889442408488d057b826103488944241048c7042402000000488db424f80000004889e24889dfe8c32bf1ff'),
    ('router_install_clone', 0x2d4ae27, '498b2e4885ed7422b82800000083fd017405b818000000498b7e08498b4e10ff14014989c44989d5'),
    ('router_box_clone', 0x2cfe815, '4889fb488d7c24084889dee89b7f1000488b43204889442428bf28000000ff15470c7e034885c07427488b4c2428488948200f104424080f104c24180f1148100f1100488d15291c75034883c4305bc3'),
    ('router_state_clone_a', 0x2e067cd, '488b06f048ff000f8e940000004889fb488907488b4608f048ff000f8e800000004c8d73084989064c8b6e104c8b7e18f049ff45007e6a4c896c2408'),
    ('router_state_clone_b', 0x2e06848, '4c896b104c896318'),
    ('router_box_factory', 0x2cfe4c9, '4889fb488b47200f10070f104f100f294c24100f2904244889e7ffd04989c64989d7be280000004889df31d2ff15a50f7e034c89f04c89fa4883c4205b415e415fc3'),
    ('router_state_factory', 0x2dd6ae5, '4889fb0f10070f104f100f294c24100f290424bf20000000ff157d8970034885c0741b0f10030f104b100f1148100f1100488d154ba867034883c4205bc3'),
    ('router_request_wrapper', 0x2cfe6ba, '488b46200f10060f104e100f294c24100f2904244889e7ffd04889c34989d7be280000004c89ef31d2ff15b70d7e034889e7ba100100004c89e6ff150e0e7e034889df41ff57284989c54889d5ba100100004c89f74c89e6ff15f00d7e034d89ae100100004989ae18010000'),
    ('router_state_rebox', 0x2e332e0, '534883ec204889fe4889e7e8d034fdffbf20000000ff1585c16a034885c0741d0f1004240f104c24100f1148100f1100488d1551e061034883c4205bc3'),
    ('request_future_copy', 0x2e4c69a, '4989f64889fe4889e7e818a1fbff0f1004240f104c24100f118c24400100000f11842430010000488d7c2420ba100100004c89f6ff15342e6903c684248802000000'),
    ('request_future_table', 0x2e4c6dc, 'bf58050000ff15992d69034885c0746f4889c3488d742420ba580500004889c7ff15062e690348c74424200000000048895c2428488d05616860034889442430'),
    ('request_future_return', 0x2e4c728, 'bf20000000ff154d2d69034885c074350f104424200f104c24300f1148100f1100488d15f85d60034881c4780500005b415ec3'),
    ('request_map_read', 0x2e3d10d, '0f1083100100000f108b20010000'),
    ('request_map_save', 0x2e3d19c, '0f1183080300000f118b18030000'),
    ('request_map_reference', 0x2e3d41e, '0f1083d8020000488d83180300000f11834004000048898358040000'),
    ('lookup_map_reference', 0x2e3867b, '4c8babe8000000488bbbd0000000488babd8000000'),
    ('router_build_limiter', 0x2e3763f, '488dbc2458080000ff155bac6a03'),
    ('router_build_routes', 0x2e377a8, '488dbc24f8000000488db42460040000e8a3e7bcfff30f6f842400010000660f7f442470488b8424f8000000f048ff08'),
    ('router_save_map', 0x2e38116, '488b8c24a000000048890c244889442408660f6f442470f30f7f442410'),
    ('router_box_map', 0x2e381d2, 'bf28000000ff15a3726a034885c00f848e000000488b4c242048894820f30f6f04240f104c24100f114810f30f7f00'),
    ('table_builder_return', 0x2a064f1, '488b442430488943100f104424200f11034889d84883c4385b415ec3'),
    ('register_call', 0x2a05fab, '488d156636a5fd4889e7488d742420b908000000e89ccf2f00'),
    ('register_estimate', 0x2a06017, '488d15cfc3bffd4889e7488d742420b90f000000e8f0c92f00'),
    ('call_registration_descriptor', 0x2d02fc3, '4889442410488d05c9d97403488944241848c7442408010000004c8d4424084889df4c89e64c89fa4c89f1ff15a4f17d03'),
    ('estimate_registration_descriptor', 0x2d02a83, '4889442410488d05e9dd7403488944241848c7442408010000004c8d4424084889df4c89e64c89fa4c89f1ff15e4f67d03'),
    ('insertion_arguments', 0x2f1bcee, '4d89c64989cf4989d44889fb4889f7ff15b5cb5c034889e74889c64c89e24c89f9e8dcf8ffff488b0c244885c90f84da000000'),
    ('insertion_key_arguments', 0x2f1b5fe, '4989cf4989d44889f54989fb'),
    ('insertion_key_success', 0x2f1b84d, '48837d100074654d89234d897b0849896b104d896b18'),
    ('insertion_record_stores', 0x2f1bd8f, '49f7da4b8d3c924180e10148894cfed8488954fee0488d0cfe4883c1e80f2804240f1144fee8488b542410488954fef8'),
    ('request_to_lookup', 0x2e3d459, '4c8dbb70030000488dbc24e00000004c89fe4889eae8cdb1ffff'),
    ('lookup_input_hash', 0x2e38b95, '4d8b650049837c2428000f8473010000488b73704c8b6b78498d7c24304889b424680100004c89eae84e270e00'),
    ('router_future_poll', 0x2e386ff, '488bb3c0000000488b83c8000000488d7c24204c89faff5018837c242002750e49c70602000000b003e927080000'),
    ('lookup_candidate_compare', 0x2e38c49, 'f30fbcc04801c84821f048f7d8488d04804d3b6cc1e04c89ea75444d8d2cc14d8b65d8488bbc24680100004c89e64c898c24600100004c89c5488994245801000041ffd0488b9424580100004989e84c8b8c246001000085c00f84c4020000'),
    ('lookup_miss_probe', 0x2e38cf5, '660f74da660fd7c385c0488d838000000075104801f94883c1104883c710e9dafeffff'),
    ('lookup_miss_error', 0x2e38d38, 'c74424500300000048b800000000000000804889442438488d059aaf61fd488944244048c74424481000000048c744242002000000488dbc2490000000488d742470488d542420'),
    ('lookup_tag', 0x2e38f95, '498b45e84883f8010f84a90000004885c00f85ad010000'),
    ('lookup_tag_one_target', 0x2e3904c, '498b45f048894424184d8b65f8498b6c2410'),
    ('lookup_callback', 0x2e390bf, '48ffcd4883e5f0488b442418488d3c284883c710'),
    ('lookup_callback_invoke', 0x2e39129, '4c894c2460488d54242041b80000100031c941ff5424284889c64889d04889b3c0000000488983c8000000'),
    ('call_callback_count', 0x2d03208, '488b07f048ff007e7f'),
    ('call_callback_future', 0x2d03241, 'c684248000000000bf88000000ff152cc27d034885c074274889e6ba880000004889c74889c3ff159bc27d03488d15b4d774034889d84881c4900000005bc3'),
    ('gas_callback_future', 0x2d03be1, 'c684248000000000bf88000000ff158cb87d034885c074274889e6ba880000004889c74889c3ff15fbb87d03488d15d4cf74034889d84881c4900000005bc3'),
    ('call_poll_inner', 0x2d09069, 'c68424a00d000000bfb0080000ff1504647d034885c00f84eb0300004989c6488db42400050000bab00800004889c7ff156a647d034c897568488d05bfc77303488945704889eb488b9424b0000000488dbc24000500004c89f6ff5018488bac24000500004883fd04751e'),
    ('gas_poll_inner', 0x2d067cb, 'c68424480c000000bfa0080000ff15a28c7d034885c00f84700300004989c5488db424b0030000baa00800004889c7ff15088d7d034c896b68488d05bded730348894370488b1424488dbc24b00300004c89eeff50184c8bac24b00300004983fd047517'),
    ('eth_call_diagnostic', 0x2a2a1fd, '4c8d3d14f4a2fd4c89bbf003000048c783f803000008000000'),
    ('estimate_diagnostic', 0x2a226bd, '4c8d3529fdbdfd4c89b3f003000048c783f80300000f000000'),
    ('eth_call_selector', 0x2a2a2af, '4983c4784c89a31806000066c7832206000000004c8b6424384c8db330040000488dbc24100500004c89f64c89e2e88e9dfdff'),
    ('estimate_selector', 0x2a22775, '4883c5784889ab1806000066c7832206000000004d89ee4c8b2c244c8da330040000488dbc24c00200004c89e64c89eae8c618feff'),
    ('filter_selector', 0x2a2d4f5, '488b44243049898424800700006641c784248a07000000014d8dbc2498050000488dbc24300200004c89fe488b942400010000e8436bfdff'),
    ('call_pending_branch', 0x2a2a2e2, '0fb6ac24100500004080fd29750cb003488b6c2408e986020000'),
    ('gas_pending_branch', 0x2a227aa, '0fb6ac24c00200004080fd297507b003e973020000'),
    ('filter_pending_branch', 0x2a2d52d, '0fb6ac24300200004080fd297507b003e960140000'),
    ('call_result_branch', 0x2a2a426, '4080fd280f8568010000c6832204000001'),
    ('call_permit_handoff', 0x2a2a437, '4c89a424980100004c89bc24a001000048898c24a8010000488b83180400004c8bb8d8030000f049ff070f8ef310000066c783210400000000488db3300600004c8ba3000400004c8bab08040000ba100200004c89f7ff15d550ab034c89a3400600004c89ab480600004c89bb50060000f30f6f842498010000f30f7f8358060000488b8424a8010000488983680600004c89a3700600004c89ab78060000'),
    ('call_followon_poll', 0x2a2a53f, '4c8dbb90060000488dbc24400200004c89fe4c89e2e8d7064200'),
    ('followon_indirect_poll', 0x2e4acc7, '498b3c24498b17488b4710488d742410ff5018'),
    ('gas_result_branch', 0x2a228ed, '4080fd280f8550010000c6832204000001'),
    ('filter_result_branch', 0x2a2d610, '4080fd280f8535010000'),
    ('filter_count_limits', 0x2a2cfab, '4981bc2410040000e8030000773c4981bc2458040000e8030000772e4981bc24a0040000e803000077204981bc24e8040000e803000077124981bc2430050000e80300000f86ac020000'),
    ('filter_failure_literal', 0x2a2cff5, '488d0504cca2fd4889842430070000488b05bd26ab034889842438070000488d355a6aa0fd488dbc2430020000488d942430070000ff15b826ab03'),
    ('limiter_ctor_first', 0x175cfe0, '4c8ba424f000000049bfffffffffffffff1f4d39fc4d0f43e7bf38000000ff157c24d8044885c00f84e90100004989c64b8d042449c7060100000049c74608010000000f57c0410f114610410f114619498946304c89742438'),
    ('limiter_ctor_second', 0x175d0c6, '4c8bac2400010000bf38000000ff15a723d8044885c00f84260100004d39fd4d0f42fd4b8d0c3f48c7000100000048c74008010000000f57c00f1140100f11401948894830'),
    ('limiter_ctor_exit', 0x175d192, '488d151f26cb04488d7424504889dfe8fa18f9ff4889d84881c4600100005b415c415d415e415fc3'),
    ('selector_enter', 0x175d25e, '89f54889fb488d357e25cb04e83189f8ff84c00f846701000048837b5000747e'),
    ('selector_first_limit', 0x175d2fc, '4c8b6b1849bcffffffffffffff1f4d39e54d0f43ec4c3b6b70745a'),
    ('selector_first_replace', 0x175d317, 'bf38000000ff155e21d8044885c00f846d0100004989c6488d7b684a8d046d0000000049c7060100000049c74608010000000f57c0410f114610410f11461949894630488b07f048ff087506ff158f4ed8044c8973684c896b70'),
    ('selector_second_limit', 0x175d371, '488b43284c39e04c0f42e04c3ba3800000007459'),
    ('selector_second_replace', 0x175d385, 'bf38000000ff15f020d8044885c00f84ff0000004989c6488d7b784b8d042449c7060100000049c74608010000000f57c0410f114610410f11461949894630488b07f048ff087506ff15254ed8044c8973784c89a380000000'),
    ('selector_read', 0x175d3de, '440fb6fd41c1e7044e8b743b68f049ff060f8eb3000000'),
    ('selector_return', 0x175d47f, 'f2420f10443b204c89f04883c4585b415c415d415e415f5dc3'),
    ('selector_allocation_failure', 0x175d498, 'bf08000000be38000000ff15e81fd8040f0b'),
    ('future_state_input', 0x2a04081, '4989d44889f34989fe0fb686f2010000488d0d8cd1bffd486304814801c8ffe0c683f101000000488bbbe8010000488d83f00100000fb68bf3010000888bf0010000488d0dbdb3a4fd48898c24b001000048c78424b801000025000000c78424c0010000390000004889bc24e80000004881c79000000048898424f0000000488d8424b001000048898424f8000000488d0d490da403488db424e800000031d2e8fa7ffcff'),
    ('future_output_saved', 0x2a04126, '4889442418f20f1183e0010000c683f101000000488d0d6be2bffd48890b48c743081d00000048894310c6436000f20f1143684c8dabd8010000c683d801000000b81d000000eb2a'),
    ('future_deadline_construct', 0x2a04279, 'bf010000004c896c241048896c2408e85300280348898380000000899388000000f20f108300010000ff15c8ccad03c683d101000000'),
    ('future_timeout_build', 0x2a04300, '4c8d0521faa303488dbc24e8000000488d8c24900000004889c6e831fb1000'),
    ('future_poll', 0x2a04351, '4c8dab08010000488dbc24e80000004c89ee4c89e2e885571600488bac24e80000004883fd02751741c60703488b442410c6000341c60629b003'),
    ('future_poll_not_pending', 0x2a04390, '4c8ba424f0000000448bbc24f80000004c89efe88800feff83fd010f85b2000000'),
    ('future_timeout_branch', 0x2a043e9, '488d3de0e2a2fd488db424e8000000e873e3ffffc683d101000000c683d201000001c683d801000001488b084889c7ff11e9c6000000'),
    ('future_terminal_states', 0x2a04528, '488d3d4909a403ff152bcead03488d3d3c09a403ff1526cead03488d3d3ff8a303ff1511cead03eb3f488d3d30f8a303ff150acead03eb3048896c24084c896c2410488d3dcff7a303ff15e9cdad03eb1748896c24084c896c2410488d3db6f7a303ff15d8cdad030f0b'),
    ('inner_terminal_states', 0x2b69c93, '488d3d6ef78d03ff15c0769703488d3d61f78d03ff15bb769703'),
    ('future_complete', 0x2a044bf, 'c683d101000000c683d201000001c683d8010000014d85e4740cf20f1083e0010000b028eb02b026c683f1010000004188064d89660845897e10f2410f114618b0018883f2010000'),
    ('gateway_input', 0x29cc131, '4889bc24e0000000807f2000745648897c24104c8b394c8b61088b6910'),
    ('gateway_tail', 0x29cc195, '488b3e488b76084881c4980100005b415c415d415e415f5de91e920600'),
    ('gateway_tracked', 0x29cc920, '488b3b488b7308e8a48a0600f20f114424104889c3488dbc2480000000e8ce5cd1ff4889d8f20f10442410'),
    ('lock_selector_input', 0x2a353de, '4889fb440fb62ebf01000000e8f1ee24034989c64189d4b10131c0f00fb00b0f8597010000'),
    ('lock_invoke_selector', 0x2a3548c, 'f20f115c2450488d7b08410fb6f5ff1510ceaa03f20f114424084989c631c9b001f00fb00b0f85f60000004c89742458f20f10442408f20f11442460'),
    ('lock_wait', 0x2a3559a, '4889dfba00ca9a3bff1550acaa03e956feffff4889df31f6ff1580b9aa03e9fafeffff'),
    ('timeout_setup', 0x2b13e71, 'bf01000000e8650417034989c44d01fc0f90c04d85ff0f98c130c1752089d54401ed81fdffc99a3b762249ffc4700e81c5003665c481fd00ca9a3b750f488d7c241831f6ff157dd59c03eb57'),
    ('poll_acquire', 0x2b69bd1, '4c8da3800000004c89e74c89feff154cdb970389c53c02752f4508eec683c000000003410fb6fe83e7014889de4c89faff155177970384c0744a488b44240848c70002000000eb6b'),
    ('poll_result', 0x2b69c19, '4c89e7ff1506d39703488b83880000004885c0740a488bbb90000000ff5018488d7b7840f6c5017421488b07f048ff087506ff15a785970331c9eb11488b44240848c70001000000eb21488b0fc683c000000001488b44240848c7000000000048894808c7401001000000'),
    ('acquire_ready_or_closed', 0x5ce69bb, '410fb646388844240f3c0175044d8b6e28498b6c2420b00140f6c5010f85d3010000'),
    ('acquire_fast_and_wait', 0x5ce69f0, '4a8d1c6d000000004531ff48c744241000000000eb1f662e0f1f8400000000004889e8f0490fb14c242074594889c540f6c50175444889e94829d973e348837c241000751131c0b101f0410fb00c244c89642410750e4889e8f04d0fb17c242075ca'),
    ('acquire_pending', 0x5ce6af0, '498b3f488d354efb7d00ff15209a7f00b002e9a9000000'),
    ('acquire_ready_return', 0x5ce6ba2, 'b001f6c301750741c646380031c04883c4485b415c415d415e415f5d'),
    ('timer_poll_bridge', 0x5ce952b, '6441c647440066c744240e01004c89f74889d6ff1514737f00'),
    ('timer_disabled', 0x5cf2e6f, '81bc019000000000ca9a3b0f8495000000'),
    ('timer_error', 0x5cf2f15, '488d3d4f9bc5fa488d1535327d00be73000000ff1542c87e00'),
    ('permit_drop', 0x29f5394, '4889fb0fb6475085c0742f83f8037543488d7b10ff157a1baf03488b43184885c07407488b7b20ff5018488b4308f048ff08751f4883c308eb09488b03f048ff0875104889df4883c4085b415eff2511ceae03'),
    ('waiter_unlink', 0x5ce6754, '807f38010f8591000000488b1fb10131c0f00fb00b752d488d4708488b4f184885c97441488b572048895118488d4f184885d27447488b01488942100f57c00f1101eb3e'),
    ('waiter_unlock', 0x5ce67b9, '483943087517488b572048895308488d4f184885d275b9483943107433488b7730488b47284829c67244751231c9b001f00fb00b75264883c4085b415ec3488b3f4889da4883c4085b415ee907ebffff488b0148894310'),
    ('duration_convert', 0x15ed960, '660f57c9660f2ec80f86cb00000050f20f590529c0e6fe'),
    ('duration_output_scale', 0x15eda2a, '69d040420f0029d169d1e8030000c3'),
]

# Conditional transfer sites and their interpretation in the selected path.
# Targets and instruction lengths are decoded from the captured bytes.
BRANCHES = [
    ('merge_precheck_not_empty_result', 0x2e37920, 'membership wrapper result differs from three'),
    ('merge_key_absent', 0x2f1bf75, 'membership poll returned zero'),
    ('merge_no_memory', 0x2f1bf9e, 'key allocation result is zero'),
    ('merge_set_empty', 0x2f1b8e5, 'map count is zero'),
    ('merge_key_equal', 0x2f1baa5, 'comparator returned zero'),
    ('merge_unwrap_failure', 0x2e37b0a, 'membership wrapper result differs from three'),
    ('merge_writer_equal', 0x2a32334, 'comparator returned zero'),
    ('map_not_exclusive', 0x2f1bb72, 'atomic pointer count differs from one'),
    ('map_other_references', 0x2f1bb7c, 'second pointer count differs from one'),
    ('descriptor_is_empty', 0x2d4ae2d, 'descriptor tag equals zero'),
    ('descriptor_is_tag_one', 0x2d4ae37, 'descriptor tag equals one'),
    ('router_clone_no_memory', 0x2cfe83c, 'allocation result is zero'),
    ('request_future_no_memory', 0x2e4c6ea, 'first allocation result is zero'),
    ('request_box_no_memory', 0x2e4c736, 'second allocation result is zero'),
    ('insert_existing_key', 0x2f1bd1b, 'lookup helper returned zero'),
    ('router_empty_map', 0x2e38b9f, 'map count is zero'),
    ('router_length_mismatch', 0x2e38c62, 'candidate and requested lengths differ'),
    ('router_key_equal', 0x2e38ca2, 'comparator returned zero'),
    ('router_probe_miss', 0x2e38d06, 'empty control byte found'),
    ('router_descriptor_one', 0x2e38f9d, 'descriptor tag equals one'),
    ('router_descriptor_other', 0x2e38fa6, 'descriptor tag is nonzero after excluding one'),
    ('router_future_not_pending', 0x2e3871d, 'callback future output differs from two'),
    ('filter_first_above_limit', 0x2a2cfb7, 'first filter count exceeds its unsigned limit'),
    ('filter_second_above_limit', 0x2a2cfc5, 'second filter count exceeds its unsigned limit'),
    ('filter_third_above_limit', 0x2a2cfd3, 'third filter count exceeds its unsigned limit'),
    ('filter_fourth_above_limit', 0x2a2cfe1, 'fourth filter count exceeds its unsigned limit'),
    ('filter_fifth_in_limit', 0x2a2cfef, 'fifth filter count is at most its unsigned limit'),
    ('call_callback_bad_count', 0x2d0320f, 'reference count increment is nonpositive'),
    ('call_callback_no_memory', 0x2d03257, 'allocation result is zero'),
    ('call_inner_no_memory', 0x2d0907f, 'allocation result is zero'),
    ('call_inner_completed', 0x2d090d2, 'inner result word is not four'),
    ('rpc_call_not_pending', 0x2a2a2ee, 'permit tag differs from 0x29'),
    ('rpc_gas_not_pending', 0x2a227b6, 'permit tag differs from 0x29'),
    ('rpc_filter_not_pending', 0x2a2d539, 'permit tag differs from 0x29'),
    ('rpc_call_not_acquired', 0x2a2a42a, 'permit tag differs from 0x28'),
    ('rpc_gas_not_acquired', 0x2a228f1, 'permit tag differs from 0x28'),
    ('rpc_filter_not_acquired', 0x2a2d614, 'permit tag differs from 0x28'),
    ('config_not_refreshed', 0x175d271, 'refresh helper returned zero'),
    ('first_limit_unchanged', 0x175d315, 'first clipped limit equals stored limit'),
    ('second_limit_unchanged', 0x175d383, 'second clipped limit equals stored limit'),
    ('first_alloc_failed', 0x175d325, 'allocation result is zero'),
    ('second_alloc_failed', 0x175d393, 'allocation result is zero'),
    ('selected_refcount_invalid', 0x175d3ef, 'reference count increment is nonpositive'),
    ('gate_poll_not_pending', 0x2a04377, 'poll result differs from two'),
    ('gate_poll_not_timer_ready', 0x2a043ab, 'poll result differs from one'),
    ('gate_no_permit_pointer', 0x2a044d7, 'returned permit pointer is zero'),
    ('inner_not_pending', 0x2b69be8, 'acquire poll byte differs from two'),
    ('timer_ready', 0x2b69c09, 'timer poll byte is zero'),
    ('acquire_nonerror', 0x2b69c40, 'acquire result low bit is zero'),
    ('queue_closed_flag', 0x5ce69d7, 'low bit of queue word is one'),
    ('queue_fast_path', 0x5ce6a2b, 'available encoded count covers requested amount'),
    ('timer_driver_disabled', 0x5cf2e7a, 'timer driver sentinel equals one billion'),
]

# Direct rel32 calls/jumps and RIP-indirect calls; resolved GOT targets are
# recorded only when a symbol-free R_X86_64_RELATIVE relocation proves them.
CALLS = [
    ('merge_precheck', 0x2e3790e), ('merge_membership', 0x2f1bf6e),
    ('merge_writer', 0x2e37aaf),
    ('insert_map_mutator', 0x2f1bcfd), ('merge_map_mutator', 0x2e3793a),
    ('router_install', 0x2e38228), ('box_clone_state', 0x2cfe820),
    ('request_state_clone', 0x2e4c6a3), ('wrapper_state_clone', 0x2e332eb),
    ('router_build_limiter', 0x2e37647), ('router_build_routes', 0x2e377b8),
    ('register_eth_call', 0x2a05fbf), ('register_estimate_gas', 0x2a0602b),
    ('call_descriptor_insert', 0x2d02fee), ('gas_descriptor_insert', 0x2d02aae),
    ('map_lookup_or_insert', 0x2f1bd0f), ('request_lookup', 0x2e3d46e),
    ('request_lookup_resume', 0x2e3e745),
    ('call_permit_future', 0x2a2a2dd), ('call_followon_poll', 0x2a2a554), ('gas_permit_future', 0x2a227a5),
    ('filter_permit_future', 0x2a2d528), ('future_gateway', 0x2a04121),
    ('gateway_plain_tail', 0x29cc1ad), ('gateway_tracked_call', 0x29cc927),
    ('lock_selector', 0x2a3549a), ('selector_refresh', 0x175d26a),
    ('duration_conversion', 0x2a042a2), ('timeout_construct', 0x2a0431a),
    ('timeout_poll', 0x2a04366), ('acquire_poll', 0x2b69bde),
    ('timer_poll', 0x2b69c01), ('timer_poll_delegate', 0x5ce953e),
    ('acquire_cleanup', 0x2b69c1c), ('timeout_cleanup', 0x2a043a3),
    ('future_cleanup', 0x29e443b), ('queued_waiter_cleanup', 0x29f53a8),
]

# Only these four entries in each selected relative jump table are claimed.
# The x86 dispatch has no general bounds check here; out-of-domain values are
# not assigned semantics by this evidence collector.
TABLES = [
    ('permit_outer', 0x601224, 0x2a04070, 4),
    ('permit_middle', 0x601234, 0x2a04070, 4),
    ('permit_inner', 0x601244, 0x2a04070, 4),
    ('acquire_future', 0x604b38, 0x2b69af0, 4),
]

# Selected descriptor slots and used GOT entries below are decoded from
# .rela.dyn; labels describe observed roles, not recovered source symbols.
SLOTS = [
    ('merge_precheck', 0x64e88b0),
    ('map_mutator', 0x64e88b8), ('router_box_clone', 0x64504a0),
    ('router_box_factory', 0x64504a8), ('router_box_wrapper', 0x64504b0),
    ('router_request_factory', 0x6451388), ('router_state_clone', 0x6451390),
    ('request_future_poll', 0x6452f90),
    ('call_method_callback', 0x64509c0), ('call_future_poll', 0x6450a40),
    ('call_inner_poll', 0x6445880), ('gas_method_callback', 0x64508a0),
    ('gas_future_poll', 0x6450c00), ('gas_inner_poll', 0x64455e0),
    ('map_insertion', 0x64e2198), ('limiter_constructor', 0x64e22a8),
    ('limiter_selector', 0x64e22b0), ('duration_conversion', 0x64e0f70),
    ('acquire_poll', 0x64e7730), ('timer_poll', 0x64e1358),
    ('timer_delegate', 0x64e0858), ('waiter_cleanup', 0x64e6f28),
    ('key_comparator', 0x64df9f8),
]

LOCATIONS = [0x640f7b8, 0x640f7d0, 0x640f7e8, 0x6444e60,
             0x6444e78, 0x6452dc0, 0x64455e8, 0x6445888, 0x64458c0]

# For instruction-boundary verification and the corresponding native body
# hashes. These are unwind ranges, not a complete function census.
STARTS = [
    0x2f1bf50, 0x2f1b8e0, 0x2a32130,
    0x2f1bb50, 0x2d4adf0, 0x2cfe810, 0x2e067c0, 0x2cfe4c0,
    0x2dd6ae0, 0x2cfe6a0, 0x2e332e0, 0x2e4c690,
    0x2e375a0, 0x2a05f60, 0x2d02f60, 0x2d02a20, 0x2f1bce0, 0x2f1b5f0,
    0x2e3cb60, 0x2e38640, 0x2d03200, 0x2d03ba0, 0x2d087e0, 0x2d062f0,
    0x2a2a0e0, 0x2a225c0, 0x2a2cb70, 0x175ceb0, 0x175d250, 0x2a04070,
    0x29cc120, 0x2a353d0, 0x2b13e50, 0x2b69af0, 0x5ce6940, 0x5ce6750,
    0x29f5390, 0x29e4430, 0x5ce94c0, 0x5cf2d30, 0x15ed960, 0x2e4ac30,
]

CONDITIONS = {0x2:'below', 0x3:'above or equal', 0x4:'equal',
              0x5:'not equal', 0x6:'below or equal', 0x7:'above',
              0xc:'less', 0xd:'greater or equal', 0xe:'less or equal', 0xf:'greater'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data, expected=TARGET_SHA256):
    if digest(data) != expected:
        raise ValueError('node 115 SHA-256 mismatch')


def va_offset(secs, va, size):
    """Resolve a complete range in exactly one non-NOBITS file section."""
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual address range')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('virtual address range is not uniquely file backed')
    section = matches[0]
    return section['offset'] + va - section['address'], section['name']


def read_va(data, secs, va, size):
    off, _ = va_offset(secs, va, size)
    if off < 0 or off + size > len(data):
        raise ValueError('virtual address range exceeds file')
    return data[off:off + size]


def expect_bytes(actual, expected):
    if actual != expected:
        raise ValueError('fixed instruction witness mismatch')
    return actual


def decode_branch(raw, site):
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        cc, size, displacement = raw[0] & 15, 2, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        cc, size, displacement = raw[1] & 15, 6, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported or truncated conditional branch')
    if cc not in CONDITIONS:
        raise ValueError('unsupported branch condition')
    return {'condition': CONDITIONS[cc], 'size': size, 'fallthrough': site + size,
            'target': site + size + displacement, 'bytes': raw[:size]}


def decode_relative(raw, site):
    if len(raw) >= 5 and raw[0] in (0xe8, 0xe9):
        return {'kind': 'call_rel32' if raw[0] == 0xe8 else 'jump_rel32',
                'target': site + 5 + struct.unpack_from('<i', raw, 1)[0], 'bytes': raw[:5]}
    if len(raw) >= 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return {'kind': 'call_rip_slot' if raw[1] == 0x15 else 'jump_rip_slot',
                'target': site + 6 + struct.unpack_from('<i', raw, 2)[0], 'bytes': raw[:6]}
    raise ValueError('unsupported or truncated relative call')


def lea_target(raw, site):
    if len(raw) < 7 or raw[0] not in (0x48, 0x4c) or raw[1] != 0x8d or raw[2] not in (5, 13, 21, 29, 37, 45, 53, 61):
        raise ValueError('unsupported or truncated RIP-relative LEA')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def decode_table(raw, base, owner_start, owner_end, count):
    if count <= 0 or len(raw) != count * 4 or owner_start >= owner_end:
        raise ValueError('invalid jump-table range')
    destinations = [base + struct.unpack_from('<i', raw, 4*i)[0] for i in range(count)]
    if any(not owner_start <= d < owner_end for d in destinations):
        raise ValueError('jump-table target outside selected FDE')
    return destinations


def parse_relocations(data, secs):
    named = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(named) != 1 or named[0]['size'] % 24:
        raise ValueError('missing or malformed dynamic relocation section')
    sec = named[0]
    out = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in out:
            raise ValueError('duplicate dynamic relocation slot')
        out[slot] = {'slot': slot, 'info': info, 'type': info & 0xffffffff,
                     'symbol': info >> 32, 'addend': addend, 'file_offset': off,
                     'bytes': data[off:off + 24]}
    return out


def relative_target(relocations, slot):
    row = relocations.get(slot)
    if row is None or row['type'] != 8 or row['symbol'] != 0:
        raise ValueError('slot has no symbol-free R_X86_64_RELATIVE relocation')
    return row['addend']


def dynamic_symbol(data, secs, index):
    if index < 0:
        raise ValueError('negative dynamic symbol index')
    syms = [s for s in secs if s['name'] == '.dynsym' and s['type'] != 8]
    strs = [s for s in secs if s['name'] == '.dynstr' and s['type'] != 8]
    if len(syms) != 1 or len(strs) != 1 or (index + 1) * 24 > syms[0]['size']:
        raise ValueError('invalid dynamic symbol table')
    start = syms[0]['offset'] + index * 24
    name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, start)
    if name >= strs[0]['size']:
        raise ValueError('dynamic symbol name outside string table')
    pos = strs[0]['offset'] + name
    end = data.find(b'\0', pos, strs[0]['offset'] + strs[0]['size'])
    if end < 0:
        raise ValueError('unterminated dynamic symbol')
    return {'name': data[pos:end].decode('ascii'), 'index': index, 'info': info,
            'other': other, 'section_index': shndx, 'value': value, 'size': size}


def select_fdes(data, secs):
    _, entries = unwind_index(data)
    _, all_fdes = eh_frame_records(data, secs)
    by_fde = {f['fde']: f for f in all_fdes}
    if len(by_fde) != len(all_fdes):
        raise ValueError('duplicate FDE records')
    indexes = {row['start']: row for row in entries}
    all_starts = {}
    for fde in all_fdes:
        all_starts[fde['start']] = all_starts.get(fde['start'], 0) + 1
    selected = {}
    for start in STARTS:
        entry = indexes.get(start)
        if entry is None or all_starts.get(start) != 1:
            raise ValueError('missing or ambiguous selected FDE start')
        fde = by_fde.get(entry['fde'])
        if fde is None or fde['start'] != start or fde['end'] <= start or fde['end'] > entry['next_index_upper_bound']:
            raise ValueError('invalid selected FDE extent or unwind index')
        selected[start] = (fde, entry)
    return selected


def owner(selected, va, size=1):
    found = [start for start, (fde, _) in selected.items()
             if start <= va and va + size <= fde['end']]
    if len(found) != 1:
        raise ValueError('selected instruction range is outside or ambiguous in selected FDEs')
    return found[0]


def target_owner(selected, va):
    found = [start for start, (fde, _) in selected.items() if start <= va < fde['end']]
    return found[0] if len(found) == 1 else None


def relative_record(data, secs, relocations, label, slot):
    row = relocations.get(slot)
    if row is None:
        raise ValueError('missing selected relocation')
    off, section = va_offset(secs, slot, 8)
    result = {'label': label, 'slot_va': hex(slot), 'slot_file_offset': hex(off),
              'slot_section': section, 'slot_bytes': data[off:off + 8].hex(),
              'record_file_offset': hex(row['file_offset']), 'record_bytes': row['bytes'].hex(),
              'relocation_type': row['type'], 'symbol_index': row['symbol'],
              'addend': hex(row['addend'])}
    if row['symbol']:
        result['symbol'] = dynamic_symbol(data, secs, row['symbol'])
    return result


def location_record(data, secs, relocations, slot):
    address = relative_target(relocations, slot)
    size, line, col = struct.unpack('<QII', read_va(data, secs, slot + 8, 16))
    if not 0 < size < 256 or not line or not col:
        raise ValueError('invalid Location-shaped record')
    raw_path = read_va(data, secs, address, size)
    suffix_at = raw_path.find(b'evm_rpc/src/')
    if suffix_at < 0 or not raw_path.endswith(b'.rs'):
        raise ValueError('Location-shaped record is outside EVM RPC scope')
    off, _ = va_offset(secs, slot, 24)
    path_off, _ = va_offset(secs, address, size)
    return {'slot_va': hex(slot), 'slot_file_offset': hex(off),
            'slot_bytes': data[off:off + 24].hex(), 'path_va': hex(address),
            'path_file_offset': hex(path_off), 'path_size': size,
            'path_sha256': digest(raw_path), 'path_suffix': raw_path[suffix_at:].decode('ascii'),
            'line': line, 'column': col}


def selector_word(data, secs, site, base_lea_site):
    raw = read_va(data, secs, site, 11)
    if raw[:3] == b'\x66\xc7\x83':
        disp, value = struct.unpack_from('<IH', raw, 3)
        length = 9
    elif raw[:5] == b'\x66\x41\xc7\x84\x24':
        disp, value = struct.unpack_from('<IH', raw, 5)
        length = 11
    else:
        raise ValueError('unsupported selector initialisation store')
    base_insn = read_va(data, secs, base_lea_site, 8)
    if base_insn[:3] in (b'\x4c\x8d\xa3', b'\x4c\x8d\xb3'):
        base_offset = struct.unpack_from('<I', base_insn, 3)[0]
        base_len = 7
    elif base_insn[:4] == b'\x4d\x8d\xbc\x24':
        base_offset = struct.unpack_from('<I', base_insn, 4)[0]
        base_len = 8
    else:
        raise ValueError('unsupported embedded future address')
    state_load = read_va(data, secs, 0x2a0408a, 7)
    if state_load[:3] != b'\x0f\xb6\x86':
        raise ValueError('unexpected permit state load')
    state_offset = disp - base_offset
    if state_offset != struct.unpack_from('<I', state_load, 3)[0]:
        raise ValueError('selector store is not in the expected embedded future')
    return {'store_va': hex(site), 'bytes': raw[:length].hex(),
            'future_base_lea_va': hex(base_lea_site), 'future_base_lea_bytes': base_insn[:base_len].hex(),
            'future_base_offset': base_offset, 'state_offset': state_offset,
            'initial_state': value & 255, 'selector': value >> 8}


def indirect_offset(data, secs, site, prefix):
    raw = read_va(data, secs, site, len(prefix) + 1)
    if not raw.startswith(prefix):
        raise ValueError('unexpected indirect callback instruction')
    return raw[-1]


def tsv(columns, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    writer.writerows(rows)
    return buf.getvalue().encode('utf-8')


def data_anchor(data, secs, va, size):
    off, section = va_offset(secs, va, size)
    value = read_va(data, secs, va, size)
    return {'va': hex(va), 'file_offset': hex(off), 'section': section,
            'length': size, 'bytes': value.hex(), 'text': value.decode('ascii')}


def call_at(data, secs, site):
    return decode_relative(read_va(data, secs, site, 6), site)


def route_record(data, secs, relocations, name, lea_site, length_site, register_site,
                 descriptor_lea, callback_lea, poll_lea, selector_site, base_site, inner_call_site,
                 endpoint_lea):
    literal = lea_target(read_va(data, secs, lea_site, 7), lea_site)
    length_raw = read_va(data, secs, length_site, 5)
    if length_raw[0] != 0xb9:
        raise ValueError('method length is not the expected mov ecx immediate')
    length = struct.unpack_from('<I', length_raw, 1)[0]
    literal_bytes = read_va(data, secs, literal, length)
    if literal_bytes != name.encode('ascii'):
        raise ValueError('registered method literal mismatch')
    if lea_target(read_va(data, secs, endpoint_lea, 7), endpoint_lea) != literal:
        raise ValueError('method diagnostic literal does not match registration')
    register = call_at(data, secs, register_site)
    if register['kind'] != 'call_rel32':
        raise ValueError('registration is not a direct call')
    tag_raw = read_va(data, secs, descriptor_lea + 12, 9)
    if tag_raw[:5] != b'\x48\xc7\x44\x24\x08':
        raise ValueError('unexpected method descriptor tag store')
    tag = struct.unpack_from('<I', tag_raw, 5)[0]
    tag_cmp = read_va(data, secs, 0x2e38f99, 4)
    if tag_cmp[:3] != b'\x48\x83\xf8' or tag != tag_cmp[3]:
        raise ValueError('method descriptor tag does not match dispatch arm')
    method_vtable = lea_target(read_va(data, secs, descriptor_lea, 7), descriptor_lea)
    callback_offset = indirect_offset(data, secs, 0x2e3913b, b'\x41\xff\x54\x24')
    callback = relative_target(relocations, method_vtable + callback_offset)
    future_vtable = lea_target(read_va(data, secs, callback_lea, 7), callback_lea)
    future_offset = indirect_offset(data, secs, 0x2e38715, b'\xff\x50')
    poll = relative_target(relocations, future_vtable + future_offset)
    inner_vtable = lea_target(read_va(data, secs, poll_lea, 7), poll_lea)
    inner_offset = indirect_offset(data, secs, inner_call_site, b'\xff\x50')
    inner_poll = relative_target(relocations, inner_vtable + inner_offset)
    result = {'method': name, 'literal_va': hex(literal), 'literal_length': length,
              'literal_bytes': literal_bytes.hex(), 'literal_lea_va': hex(lea_site),
              'length_va': hex(length_site), 'registration_call_va': hex(register_site),
              'registration_target': hex(register['target']), 'descriptor_lea_va': hex(descriptor_lea),
              'descriptor_vtable_va': hex(method_vtable), 'descriptor_tag': tag, 'callback_slot_va': hex(method_vtable + callback_offset),
              'callback_target': hex(callback), 'future_vtable_lea_va': hex(callback_lea),
              'future_vtable_va': hex(future_vtable), 'future_poll_slot_va': hex(future_vtable + future_offset),
              'future_poll_target': hex(poll), 'inner_vtable_lea_va': hex(poll_lea),
              'inner_vtable_va': hex(inner_vtable), 'inner_poll_slot_va': hex(inner_vtable + inner_offset),
              'inner_poll_target': hex(inner_poll), 'endpoint_literal_lea_va': hex(endpoint_lea),
              'initialisation': selector_word(data, secs, selector_site, base_site)}
    return result


def displacement(data, secs, site, opcode, width):
    """Extract the displacement of one specifically identified instruction."""
    if width not in (1, 4):
        raise ValueError('unsupported displacement width')
    raw = read_va(data, secs, site, len(opcode) + width)
    if raw[:len(opcode)] != opcode:
        raise ValueError('transport instruction mismatch')
    return int.from_bytes(raw[len(opcode):], 'little')


def transport_record(data, secs, relocations, selected):
    # The chosen offsets are instruction encodings, not source-level types.
    # The branches carrying a value through these ranges remain conditional.
    box = lea_target(read_va(data, secs, 0x2e38206, 7), 0x2e38206)
    factory = lea_target(read_va(data, secs, 0x2e381c6, 7), 0x2e381c6)
    state = lea_target(read_va(data, secs, 0x2dd6b16, 7), 0x2dd6b16)
    future = lea_target(read_va(data, secs, 0x2e4c710, 7), 0x2e4c710)
    closure_slots = [
        ('router_box_clone', box + 0x18, 0x2cfe820),
        ('router_box_factory', box + 0x20, 0x2cfe4e3),
        ('router_box_wrapper', box + 0x28, 0x2cfe6d1),
        ('router_request_factory', state + 0x20, 0x2e4c6a3),
        ('router_state_clone', state + 0x28, 0x2e332eb),
        ('request_future_poll', future + 0x18, 0x2e3d46e),
    ]
    for _, slot, anchor in closure_slots:
        if relative_target(relocations, slot) != owner(selected, anchor):
            raise ValueError('closure relocation does not reach the anchored FDE')
    if factory != owner(selected, 0x2dd6b16):
        raise ValueError('stored constructor differs from the anchored FDE')
    def d(site, opcode, width):
        return displacement(data, secs, site, bytes.fromhex(opcode), width)
    # The final stack slot may already have changed during the map merge.
    stack_map = d(0x2e38127, '660f6f4424', 1)
    stage_write = d(0x2e3812d, 'f30f7f4424', 1)
    stage_read = d(0x2e381f4, '0f104c24', 1)
    box_field = d(0x2e381f9, '0f1148', 1)
    clone_read = d(0x2e067f5, '4c8b6e', 1)
    clone_write = d(0x2e06848, '4c896b', 1)
    future_context_stack = d(0x2e4c6b1, '0f118c24', 4)
    future_start_stack = d(0x2e4c6ef, '488d7424', 1)
    poll_read = d(0x2e3d114, '0f108b', 4)
    poll_map = d(0x2e3d1a3, '0f118b', 4)
    poll_map_address = d(0x2e3d425, '488d83', 4)
    lookup_ref_store = d(0x2e3d433, '488983', 4)
    lookup_base = d(0x2e3d459, '4c8dbb', 4)
    lookup_ref_read = d(0x2e3867b, '4c8bab', 4)
    if stage_write != stage_read or box_field != clone_read or clone_read != clone_write:
        raise ValueError('boxed map pointer transfer mismatch')
    if future_context_stack - future_start_stack != poll_read:
        raise ValueError('request future context transfer mismatch')
    if poll_map != poll_map_address or lookup_ref_store - lookup_base != lookup_ref_read:
        raise ValueError('request lookup pointer transfer mismatch')
    return {'boxed_vtable_va': hex(box), 'boxed_constructor_va': hex(factory),
            'state_vtable_va': hex(state), 'request_future_vtable_va': hex(future),
            'closure_slots': [{'role': label, 'slot_va': hex(slot),
                               'target_va': hex(relative_target(relocations, slot))}
                              for label, slot, _ in closure_slots],
            'map_pointer_offsets': {'final_router_stack': stack_map,
                                    'router_staging_stack': stage_write,
                                    'box_and_cloned_state': box_field,
                                    'request_future': poll_read,
                                    'request_polled_map': poll_map,
                                    'lookup_future_reference': lookup_ref_read}}


def build(data):
    # Digest admission precedes all parsing and all filesystem writes.
    check_digest(data)
    secs = sections(data)
    selected = select_fdes(data, secs)
    relocations = parse_relocations(data, secs)
    header = next(s for s in secs if s['name'] == '.eh_frame_hdr')
    functions = []
    for start in sorted(selected):
        fde, entry = selected[start]
        body = read_va(data, secs, start, fde['end'] - start)
        offset, section = va_offset(secs, start, len(body))
        fde_size = struct.unpack('<I', read_va(data, secs, fde['fde'], 4))[0] + 4
        cie_size = struct.unpack('<I', read_va(data, secs, fde['cie'], 4))[0] + 4
        fde_off, _ = va_offset(secs, fde['fde'], fde_size)
        cie_off, _ = va_offset(secs, fde['cie'], cie_size)
        index_off = header['offset'] + 12 + 8 * entry['index']
        functions.append({'start_va': hex(start), 'end_va_exclusive': hex(fde['end']),
                          'length': len(body), 'file_offset': hex(offset), 'section': section,
                          'body_sha256': digest(body), 'fde_va': hex(fde['fde']),
                          'fde_file_offset': hex(fde_off),
                          'fde_bytes': data[fde_off:fde_off + fde_size].hex(),
                          'cie_va': hex(fde['cie']), 'cie_file_offset': hex(cie_off),
                          'cie_bytes': data[cie_off:cie_off + cie_size].hex(),
                          'index': entry['index'], 'index_file_offset': hex(index_off),
                          'index_bytes': data[index_off:index_off + 8].hex(),
                          'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else None})
    windows = []
    witness_ranges = []
    for label, site, expected_hex in WITNESSES:
        expected = bytes.fromhex(expected_hex)
        actual = expect_bytes(read_va(data, secs, site, len(expected)), expected)
        start = owner(selected, site, len(actual))
        off, section = va_offset(secs, site, len(actual))
        windows.append({'label': label, 'start_va': hex(site),
                        'end_va_exclusive': hex(site + len(actual)),
                        'fde_start_va': hex(start), 'file_offset': hex(off),
                        'section': section, 'bytes': actual.hex()})
        witness_ranges.append((site, site + len(actual)))
    branches = []
    for name, site, explanation in BRANCHES:
        raw = read_va(data, secs, site, 6)
        branch = decode_branch(raw, site)
        start = owner(selected, site, branch['size'])
        if not any(lo <= site and site + branch['size'] <= hi for lo, hi in witness_ranges):
            raise ValueError('conditional branch not covered by a frozen witness')
        if target_owner(selected, branch['target']) != start:
            raise ValueError('conditional branch leaves its selected FDE')
        off, _ = va_offset(secs, site, branch['size'])
        branches.append([name, hex(site), hex(off), branch['bytes'].hex(), branch['condition'],
                         hex(branch['fallthrough']), hex(branch['target']), explanation])
    calls = []
    for name, site in CALLS:
        edge = call_at(data, secs, site)
        size = len(edge['bytes'])
        start = owner(selected, site, size)
        off, _ = va_offset(secs, site, size)
        actual = edge['target']
        target = actual
        if edge['kind'].endswith('_slot'):
            target = relative_target(relocations, actual)
        calls.append([name, hex(site), hex(off), edge['bytes'].hex(), hex(start), edge['kind'],
                      hex(actual), hex(target), hex(target_owner(selected, target))
                      if target_owner(selected, target) is not None else ''])
    tables = []
    for name, base, start, count in TABLES:
        fde, _ = selected[start]
        raw = read_va(data, secs, base, count * 4)
        dests = decode_table(raw, base, start, fde['end'], count)
        for i, dst in enumerate(dests):
            off, _ = va_offset(secs, base + 4*i, 4)
            tables.append([name, i, hex(base), hex(base + 4*i), hex(off), raw[4*i:4*i + 4].hex(),
                           hex(dst), hex(start)])
    slots = [relative_record(data, secs, relocations, label, slot) for label, slot in SLOTS]
    slot_index = {row['label']: row for row in slots}
    if slot_index['key_comparator']['relocation_type'] != 6 or slot_index['key_comparator']['symbol']['name'] != 'bcmp':
        raise ValueError('router comparator does not resolve to the expected dynamic symbol')
    for label, _ in SLOTS:
        if label != 'key_comparator':
            relative_target(relocations, int(slot_index[label]['slot_va'], 16))
    transport = transport_record(data, secs, relocations, selected)
    routes = [
        route_record(data, secs, relocations, 'eth_call', 0x2a05fab, 0x2a05fba,
                     0x2a05fbf, 0x2d02fc8, 0x2d0326d, 0x2d090a2, 0x2a2a2ba, 0x2a2a2c8, 0x2d090c3, 0x2a2a1fd),
        route_record(data, secs, relocations, 'eth_estimateGas', 0x2a06017, 0x2a06026,
                     0x2a0602b, 0x2d02a88, 0x2d03c0d, 0x2d06804, 0x2a22780, 0x2a22790, 0x2d0681e, 0x2a226bd),
    ]
    # Check that each independently decoded chain ends at the corresponding
    # observed state-machine entry and that both initialise selector zero.
    for route in routes:
        for key in ('registration_target', 'callback_target', 'future_poll_target', 'inner_poll_target'):
            value = int(route[key], 16)
            if value not in selected:
                raise ValueError('method chain target is not an indexed FDE start')
        if owner(selected, int(route['descriptor_lea_va'], 16)) != int(route['registration_target'], 16):
            raise ValueError('descriptor is outside its registration target')
        if owner(selected, int(route['future_vtable_lea_va'], 16)) != int(route['callback_target'], 16):
            raise ValueError('future table is outside its callback target')
        if owner(selected, int(route['inner_vtable_lea_va'], 16)) != int(route['future_poll_target'], 16):
            raise ValueError('inner table is outside its future poll target')
        if owner(selected, int(route['initialisation']['store_va'], 16)) != int(route['inner_poll_target'], 16):
            raise ValueError('selector initialisation is outside its inner poll target')
        if owner(selected, int(route['endpoint_literal_lea_va'], 16)) != int(route['inner_poll_target'], 16):
            raise ValueError('method literal is outside its inner poll target')
        if route['initialisation']['selector'] != 0:
            raise ValueError('unexpected method selector')
    filter_init = selector_word(data, secs, 0x2a2d502, 0x2a2d50d)
    if filter_init['selector'] != 1:
        raise ValueError('unexpected filter-path selector')
    filter_comparisons = []
    for site in (0x2a2cfab, 0x2a2cfb9, 0x2a2cfc7, 0x2a2cfd5, 0x2a2cfe3):
        raw = read_va(data, secs, site, 12)
        if raw[:4] != b'\x49\x81\xbc\x24':
            raise ValueError('unexpected filter comparison')
        displacement, threshold = struct.unpack_from('<II', raw, 4)
        off, _ = va_offset(secs, site, len(raw))
        filter_comparisons.append({'site_va': hex(site), 'file_offset': hex(off),
                                   'bytes': raw.hex(), 'object_offset': displacement,
                                   'unsigned_limit': threshold})
    unwrap_insn = read_va(data, secs, 0x2e382c9, 5)
    if unwrap_insn[:1] != b'\xbe':
        raise ValueError('unexpected merge diagnostic length instruction')
    unwrap_len = struct.unpack_from('<I', unwrap_insn, 1)[0]
    unwrap_va = lea_target(read_va(data, secs, 0x2e382ac, 7), 0x2e382ac)
    anchors = [data_anchor(data, secs, 0x6023ac, len(b'evm_rpc_expensive_call_permit')),
               data_anchor(data, secs, 0x453cf0, len(b'Method not found')),
               data_anchor(data, secs, 0x433a75, read_va(data, secs, 0x433a74, 1)[0]),
               data_anchor(data, secs, unwrap_va, unwrap_len)]
    if anchors[0]['text'] != 'evm_rpc_expensive_call_permit' or anchors[1]['text'] != 'Method not found':
        raise ValueError('diagnostic literal mismatch')
    cap_site = 0x175d300
    cap_bytes = read_va(data, secs, cap_site, 10)
    if cap_bytes[:2] != b'\x49\xbc':
        raise ValueError('unexpected selector capacity instruction')
    cap = {'site_va': hex(cap_site), 'bytes': cap_bytes.hex(),
           'value': hex(struct.unpack_from('<Q', cap_bytes, 2)[0])}
    records = {'schema': 're011-node115-evm-permit-routing-v1',
               'binary': {'release': '115', 'sha256': digest(data), 'size': len(data)},
               'coordinates': 'linked ELF virtual addresses; FDE ends exclusive; file offsets zero based',
               'functions': functions, 'witnesses': windows, 'relocations': slots,
               'routes': routes, 'transport': transport, 'filter_selector': filter_init,
               'filter_comparisons': filter_comparisons, 'selector_capacity_cap': cap,
               'locations': [location_record(data, secs, relocations, slot) for slot in LOCATIONS],
               'literal_anchors': anchors,
               'limitations': ['Selected FDEs are unwind ranges rather than source-function proof.',
                               'Instruction windows are curated, not an instruction census.',
                               'Method association assumes successful insertion, entry preservation through merge, and selected dynamic calls.',
                               'External symbol binding, opaque callees and runtime reachability are unverified.']}
    route_rows = []
    for r in routes:
        route_rows.append([r['method'], r['literal_va'], r['literal_length'], r['registration_call_va'],
                           r['registration_target'], r['descriptor_vtable_va'], r['callback_slot_va'],
                           r['callback_target'], r['future_vtable_va'], r['future_poll_target'],
                           r['inner_vtable_va'], r['inner_poll_target'], r['initialisation']['selector']])
    return {
        'evidence.json': (json.dumps(records, indent=2, sort_keys=True) + '\n').encode('utf-8'),
        'branches.tsv': tsv(['label', 'site_va', 'file_offset', 'bytes', 'condition',
                             'fallthrough_va', 'target_va', 'taken_when'], branches),
        'calls.tsv': tsv(['label', 'site_va', 'file_offset', 'bytes', 'source_fde_va', 'kind',
                          'direct_target_or_slot_va', 'static_target_va', 'selected_target_fde_va'], calls),
        'states.tsv': tsv(['table', 'state', 'base_va', 'entry_va', 'file_offset', 'entry_bytes',
                           'target_va', 'fde_start_va'], tables),
        'methods.tsv': tsv(['method', 'literal_va', 'length', 'registration_call_va',
                            'registration_target', 'descriptor_vtable_va', 'callback_slot_va',
                            'callback_target', 'future_vtable_va', 'future_poll_target',
                            'inner_vtable_va', 'inner_poll_target', 'selector'], route_rows),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = build(args.binary.read_bytes())
        args.out.mkdir(parents=True, exist_ok=True)
        for name, value in result.items():
            (args.out / name).write_bytes(value)
    except (OSError, ValueError, struct.error, UnicodeDecodeError) as exc:
        print(f'evm_permit_routing115: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
