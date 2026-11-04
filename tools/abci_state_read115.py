#!/usr/bin/env python3
"""Recover a selected node-115 state read, outer decode, and failure path."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

# Tests import this as a module; direct execution already adds this directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# Only ranges owned by this question are listed here. The read dispatcher is
# an earlier contribution's boundary, not an additional selected FDE.
FDE_PINS = [
    ('read_unwrap_wrapper', 0x564a680, 0x564a6e5),
    ('exchange_json_map', 0x3efb050, 0x3f0dfaf),
    ('exchange_key_selector', 0x3bda740, 0x3bdb2a7),
    ('locus_json_value', 0x4112920, 0x4116e5e),
    ('locus_key_selector', 0x3bd3ad0, 0x3bd3cfe),
    ('context_json_value', 0x409c990, 0x409e092),
    ('context_key_selector', 0x41fc4a0, 0x41fc6c2),
    ('json_integer_wrapper', 0x3ef2dc0, 0x3ef2f45),
    ('json_integer_lexer', 0x3ef2440, 0x3ef25c6),
    ('invalid_length_error', 0x2f7fe90, 0x2f7feed),
    ('json_input_and_tail', 0x3ef18b0, 0x3ef1a20),
    ('json_outer_state', 0x404c260, 0x404cb22),
    ('json_inner_state_entry', 0x40908e0, 0x4093e93),
    ('binary_outer_state', 0x3266520, 0x3267997),
    ('json_error_position', 0x3ef1a90, 0x3ef1af6),
    ('position_counter', 0x5c56920, 0x5c569d8),
    ('json_state_cleanup', 0x3f22170, 0x3f22f9b),
    ('json_state_box_cleanup', 0x3f3be70, 0x3f3beae),
    ('binary_state_box_cleanup', 0x300e900, 0x300e93e),
    ('binary_sequence_box_cleanup', 0x30291b0, 0x30291ee),
    ('binary_state_cleanup', 0x3007980, 0x30087ab),
    ('binary_parse_error', 0x422eac0, 0x422eb63),
    ('text_read_error', 0x422eb70, 0x422ebe3),
    ('json_parse_error', 0x422ebf0, 0x422ecb5),
    ('binary_read_error', 0x422ecc0, 0x422ed33),
]

# Filled from the authenticated ELF; these exact instruction windows are
# development-time observations, not an implementation or x86 decoder.
WINDOWS = [
    ('locus_return_copies', 0x411450b, '488dbc2490240000488db42410160000baa00b0000ff15e2af3c024c89f7e872efddff4989c4488dbc2438030000488db42490240000baa00b0000ff15bcaf3c02', 'owned'),
    ('locus_return_result_a', 0x41145bc, '4c8bbc2440030000488db42448030000488dbc2418320000ba900b0000ff1529af3c02eb1a', 'owned'),
    ('locus_return_result_b', 0x41145fb, '83fb020f848b060000488d7d10488db42418320000ba900b0000ff15edae3c0248895d004c897d08', 'owned'),
    ('exchange_locus_copy_to_temp', 0x3f0bf23, '4c8bac2490000000498dbdf81d0000488b1dcf355d02bae8000000488db424502b0000ffd3488dbc24f8140000488db424e0340000baa00b0000ffd3', 'owned'),
    ('exchange_locus_copy_to_output', 0x3f0c4f2, 'bae81000004c89ef488db424f8140000ffd3', 'owned'),
    ('nested_state_success_a', 0x4090b3c, '4d85e40f85e30100004c8bbc24280c0000488db42498340000e9f6010000', 'owned'),
    ('nested_state_success_b', 0x4090d50, '488dbc24d0a90000ba98270000ff15a5e74402', 'owned'),
    ('nested_state_success_c', 0x4090d7f, '4183fd020f8431020000488d7b10488db424d0a90000ba98270000ff1568e744024c892b4c897b084889d8', 'owned'),
    ('exchange_selector_head', 0x3bda740, '534889f84883c2fe4883fa310f87010a0000488d0d1f85bdfc486314914801caffe2', 'owned'),
    ('exchange_locus_match', 0x3bdaaa3, 'b96c6f6375330e0fb6560483f27309ca0f859a06000031c9884801c600005bc3', 'owned'),
    ('exchange_locus_initial', 0x3efb0b4, '49bd00000000000000804889b42410050000c68424180500000148c78424d043000002000000', 'owned'),
    ('exchange_locus_dispatch', 0x3efb3a8, '488b942408150000488dbc2440090000e883f3cdff80bc2440090000010f844d3600000fb6842441090000486304834801d8ffe083bc24d0430000020f8585a20000', 'owned'),
    ('exchange_locus_value', 0x3efd84c, '4883fe3a0f85eeb300004885c00f84dbcf000048894528488dbc24f81400004889eee8ad5021004c8bac24f81400004c8ba424001500004983fd020f847f450000488dbc2440090000ba900b0000488db42408150000ff15601c5e0283bc24d043000002740d488dbc24d0430000e8916b04004c89ac24d04300004c89a424d8430000488db42440090000ba900b0000488dbc24e0430000e916090000', 'owned'),
    ('exchange_locus_missing', 0x3efe856, '83bc24d0430000020f8590020000488d05f55a8cfc488984244009000048c784244809000005000000488d84244009000048898424f8140000488d055aef7d004889842400150000b0018944240c488d3d193d53fc488db424f8140000', 'owned'),
    ('exchange_locus_duplicate', 0x3f0566f, '488d05eaec8bfc488984244009000048c784244809000005000000488d84244009000048898424f8140000488d054f817d004889842400150000b00189442470488d3d64de52fc488db424f8140000', 'owned'),
    ('exchange_locus_copy', 0x3efeaf4, '488dbc24e0340000488db424d0430000baa00b0000ff15f9095e02', 'owned'),
    ('locus_ctx_selector', 0x3bd3ad0, '4889f8b1104883fa030f859a0100000fb70e81f1637400000fb6560283f2786609ca0f847f010000', 'owned'),
    ('locus_ctx_selector_success', 0x3bd3c77, '31c9884801c60000c3', 'owned'),
    ('locus_ctx_initial', 0x4112aa2, 'c644242004c644240802c644243803b8020000004889442418', 'owned'),
    ('locus_ctx_dispatch', 0x4112b54, '488b942448030000488dbc24e00e0000e8670facff80bc24e00e0000010f84711000000fb68424e10e0000488d0d3eec6afc486304814801c8ffe048837c2418020f8540290000', 'owned'),
    ('locus_ctx_value', 0x411362f, '4883fe3a0f85fa1f00004885c00f842f2c0000498947284c89ef4c89fee83f93f8ff488b8c2438030000488b84244003000048894c24184883f9020f84e60900004889842460020000488d8424480300000f1040600f298424200300000f1040500f298424100300000f1040400f298424000300000f10000f1048100f1050200f1058300f299c24f00200000f299424e00200000f298c24d00200000f298424c0020000e908f4ffff', 'owned'),
    ('locus_ctx_missing', 0x4113b84, '48837c2418020f85ad000000488d05b6fb6afc48898424e00e000048c78424e80e000003000000488d8424e00e00004889842438030000488d052e9c5c004889842440030000488d3df3e931fc488db42438030000488b6c2410e8ddf65d00e973040000', 'owned'),
    ('locus_ctx_duplicate', 0x41154db, '488d056be26afc48898424e00e000048c78424e80e000003000000488d8424e00e00004889842438030000488d05e3825c004889842440030000488d3dfedf31fc488db42438030000488b6c2410e892dd5d00e928ebffff', 'owned'),
    ('locus_ctx_materialize', 0x4115dc8, '0f108424c00200000f108c24d00200000f109424e00200000f109c24f00200000f119c24501600000f119424401600000f118c24301600000f11842420160000', 'owned'),
    ('context_selector_head', 0x41fc4a0, '4889f84883c2fd4883fa0d0f87d2010000488d0de0ac5cfc486314914801caffe2', 'owned'),
    ('context_height_match', 0x41fc5af, 'b968656967330e0fb7560481f26874000009ca0f85bb000000b102884801c60000c3', 'owned'),
    ('context_map_initial', 0x409cb81, 'c644242f0248c784249000000000000000b80200000048898424d800000048c78424a80000000000000048c74424680000000048c78424e000000000000000', 'owned'),
    ('context_height_dispatch', 0x409cdd0, '488b542420488d7c2430e8c1f61500807c2430010f84ea0900000fb6442431488d0d5a3f72fc486304814801c8ffe04883bc2490000000010f8438100000', 'owned'),
    ('context_height_guard', 0x409d03a, '48837c2468010f84720d0000488b4d20488b45284839c87337498b142448ffc048f7d90fb67402ff4883fe3a0f8722070000490fa3f70f83ae05000048894528488d340148ffc648ffc04883fe0175d348c7442410030000004889ef488d742410e8f049e5ff4889c5b801000000e999050000', 'owned'),
    ('context_height_parse', 0x409d624, '4883fe3a0f85600100004885c00f841c090000488945284889efe87d57e5ff4889d5a8010f8523040000b8010000004889442468e9fef6ffff', 'owned'),
    ('context_height_absent', 0x409d7de, 'f684249000000001488b942408010000660f6f8c24100100000f84c7020000f6442468010f84d6020000', 'owned'),
    ('context_height_missing', 0x409dade, '488d05ce4272fc488944243048c744243806000000e9be000000', 'owned'),
    ('context_missing_format', 0x409dbb6, '488d4424304889442410488d0529fc63004889442418488d3df14939fc488d742410e8e3566500e997eeffff', 'owned'),
    ('context_height_duplicate', 0x409ddb8, '488d05f43f72fc488944243048c744243806000000e9b7000000', 'owned'),
    ('context_duplicate_format', 0x409de89, '488d4424304889442410488d0556f963004889442418488d3d745639fce928fdffff', 'owned'),
    ('context_result_store', 0x409ccb8, '4c892b488b44240848894308488b442470488943100f288424900000000f11431848896b28', 'owned'),
    ('numeric_wrapper_start', 0x3ef2dc0, '534883ec304889fb488b4f20488b47284839c87340488b531848ffc048f7d948be00260000010000000f1f80000000000fb67c02ff4883ff2d777b480fa3fe733848894328488d3c0148ffc748ffc04883ff0175db48c744240805000000488d7424084889dfe865ecffff4889c2b8010000004883c4305bc3', 'owned'),
    ('numeric_wrapper_dispatch', 0x3ef2e39, '4883ff2d75374885c00f84f000000048894328488d7c24204889de31d2e8e5f5ffff488b4424204883f8037537488b542428b8010000004883c4305bc34080c7d04080ff0a736e488d7c24204889deba01000000e8aef5ffff488b4424204883f80374c9', 'owned'),
    ('numeric_wrapper_results', 0x3ef2e9d, '488b54242883f801740a83f80275134885d2786431c0a801754e31c04883c4305bc3', 'owned'),
    ('decimal_lexer_prefix', 0x3ef2440, '534883ec204889fb4c8b5620488b46284c39d00f830f0100004c8d4001488b7e180fb60c074c89462880f93075364d39d00f83db000000420fb6040704d03c0a0f83cc00000048c74424080d000000488d4424084889f74889c6e8f1f5ffffe9dd000000448d41cf4180f8090f83fc000000', 'owned'),
    ('decimal_lexer_threshold', 0x3ef24b2, '49b8989999999999991980c1d00fb6c94883c00241b9010000004d29d14d8d5001eb2666662e0f1f840000000000450fb6db488946284801c9488d0c8948ffc04c01d90f82be0000004d8d1c014983fb027445440fb65c07ff4180c3d04180fb0a73354c39c176c64c39d175064180fb0576bb', 'owned'),
    ('decimal_lexer_fallback', 0x3ef2525, '0fb6d2488d7c2408ff150dee5e02807c240800745b488b44241048894308b803000000eb580fb6d24889dfeb080fb6d24889df31c9e891fbffff', 'owned'),
    ('wrapper_entry', 0x564a680, '534883ec10488d154cc1e200e87f3dbefea80175094889d04883c4105bc34889542408488d3d88002efb488d0daf06e6004c8d058809e600488d542408be2b000000ff15d84fe9000f0b4889c3488b7c2408488b07ff104889dfe87163da00ff15db4de900', 'owned'),
    ('read_path_check', 0x422e410, '415741564154534881ecc80000004889f24889fe4c8d7c24084c89ffff1516252b02488b5c24104c8b7424184889df4c89f6ff1508252b0284c0740d4d85f6747a803b2f0f94c0eb74', 'context'),
    ('read_extension', 0x422e4f7, '807c2468090f859d000000488b442478488b4c24704883f802750b6681392e2e0f84820000004801c148ffc14889c6662e0f1f8400000000004885f6746a48ffce488d79ff8079fe2e4889f975eb4885f6745548f7d64801c6488d1569b059fcb903000000e83f1737fd84c0743a', 'context'),
    ('read_input_and_error', 0x422e565, '488b742410488b542418488d7c2420ff153e242b024c8b6424204c8b7c24284c89e048f7d80f81e4000000488d7c24084c89fee823070000eb34488b742410488b542418488d7c2420ff150c242b024c8b6424204c8b7c24284c89e048f7d87142488d7c24084c89fee89d0500004889c341be01000000488b7424084885f6740d488b7c241031d2ff15ad0e2b024c89f04889da4881c4c80000005b415c415e415fc3', 'context'),
    ('read_decode_and_return', 0x422e608, '488b4424304c897c242048894424280f57c00f114424304c897c24404889442448488d7c2420e87d32ccff4889d34883f801751d488d7c24084889dee8a70500004889c341be010000004d85e4750aeb834d85e474624531f64c89ff4c89e631d2ff15310e2b02e968ffffff488b4424304c897c242048894424284c897c24304889442438c644244400c64424400166c74424422000488d7c2468488d74242031d2e8717e03ff807c2468097512488b5c24704d85e4759e4531f6e914ffffff0f104424680f104c24780f294c24300f29442420488d7c2408488d742420e8d5030000e959ffffff', 'context'),
    ('json_entry_suffix', 0x3ef18b0, '41574156534883ec700f10070f104f100f1057200f115424400f114c24300f1144242048c74424080000000048c74424100100000048c74424180000000066c74424500080488d7c2408e861a91500bb01000000a801755f488b442428488b4c24304839c1734e488b74242048f7d848ffc148bf00260000010000000f1f4000440fb6440eff4983f82077554c0fa3c7734f48894c24304c8d040849ffc048ffc14983f80175d931db488b7424084885f6750eeb1f31db488b7424084885f67413488b7c24104989d631d2ff151fdb5e024c89f24889d84883c4705b415e415fc34989d648c744245816000000488d7c2408488d742458e8e40000004989c74c89f7e8b9070300bea82700004c89f731d2ff15d9da5e024c89fa488b7424084885f6759debae', 'owned'),
    ('json_error_position', 0x3ef1a90, '415653504889f3488b57284883faff742d48ffc2488b4718488b77204839f2480f43d64889c7e8654ed6014889df4889c64883c4085b415eff253af05e02488d3d0b0a5d02ff1545da5e020f0b4989c64889dfe8a8a504004c89f7e860ef4f02ff15cad95e02', 'owned'),
    ('json_tail_unwind', 0x3ef19d6, '4889c3bea82700004c89f731d2ff15b7da5e02eb164889c34c89f7e87aa40400eb09ff15c2da5e024889c3488b7424084885f6740d488b7c241031d2ff1588da5e024889dfe830f04f02', 'owned'),
    ('json_begin', 0x404c260, '554157415641554154534881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ec780f00004889fb488b4f20488b47284839c87339488b531848ffc048f7d949bd00260000010000000fb67402ff4883fe207735490fa3f5732f48894328488d340148ffc648ffc04883fe0175db48c744242805000000488d7424284889dfe88457eaffe91705000083fe5b0f841802000083fe7b0f85b6050000807b480075170fb64b4984c90f847e060000fec9884b490f84b50500004885c00f845d0600004889432848895c2418c64424200148c7442408000000004c8d6424284c89e7488d742418e87eb6efff807c2428010f8406030000807c2429010f856c030000', 'owned'),
    ('json_key', 0x404c3cd, '48837c243808750f48b865786368616e6765493906747c488b4d20488b45284839c80f83a1010000498b1748ffc048f7d90fb67402ff4883fe3a0f87a7040000490fa3f5731d48894528488d340148ffc648ffc04883fe0175d7e96a0100000f1f40004883fe3a0f857a0400004885c00f8454050000488945284889efe8b156eaff4989c64885c00f840affffffe928020000', 'owned'),
    ('json_key_value', 0x404c460, '48837c2408000f85ac040000488b4d20488b45284839c80f83c5030000498b1748ffc048f7d90fb67402ff4883fe3a0f87d0040000490fa3f5731948894528488d340148ffc648ffc04883fe0175d7e98e0300004883fe3a0f85a70400004885c00f842405000048894528488dbc24d02700004889eee80544040083bc24d0270000024c8b3d1e3049020f84df030000baa82700004c89e74c8db424d02700004c89f641ffd7bfa8270000ff156f2f49024885c00f846b040000baa827000048894424084889c74c89f641ffd7e933feffff', 'owned'),
    ('json_sequence_begin', 0x404c532, '807b480075170fb64b4984c90f847c040000fec9884b490f84a60300004885c00f844e0400004889432848895c2418c644242001488d7c2428488d742418e8bb05f0ff807c24280175444c8b64243041be01000000807b48000f84ba000000e9c6000000', 'owned'),
    ('json_sequence_value', 0x404c5c0, '807c2429010f85eb010000488b742418488dbc24d0270000e80343040083bc24d027000002751641be010000004c8ba424d8270000807b48007450eb5f488d7c2428488db424d0270000baa8270000ff15f32e4902bfa8270000ff15602e49024885c00f84da020000488db424d0270000baa82700004989c44889c7ff15c62e49024531f6807b480075110fb643493cff0f8485030000fec08843494889dfe8fc6eeaff4989c74d85f60f85d50000004d85ff0f852001000031c04c89e2e9ad0100004c8b74243048837c240800', 'owned'),
    ('json_existing_field_drop', 0x404c688, '48837c240800741d4c8b7c24084c89ffe8d35aedffbea82700004c89ff31d2ff15f32d490241bf010000004c89742408', 'owned'),
    ('json_missing_guard', 0x404c6e8, '31c0488b542408e93c01000048837c2408000f845f0100004531ffebb3', 'owned'),
    ('json_release', 0x404c782, '4c8b7424084c89f7e8e159edffbea82700004c89f7eb7c4c89e7e8cf59edffbea82700004c89e731d2ff15ef2c49024c89ffeb6a', 'owned'),
    ('json_return_missing', 0x404c820, '4889dee8184a62004889c2b8010000004881c4784f00005b415c415d415e415f5dc348c744242803000000488d7424284889efe83852eaff4889442408eb4a488d0562c740fc48898424d027000048c78424d827000008000000488d8424d02700004889442428488d05620f69004889442430488d3d2a5d3efc488d742428e81c6a6a00488944240841bf01000000e904feffff', 'owned'),
    ('json_code_and_other', 0x404c8b4, '48c744242806000000488d7424284889efe8c651eaffe9ddfcffff488b8424d8270000ebcb488d15e03d4302488d7424174889dfe8c361eaff4889c7e92bffffff48c744242818000000e9fcf9', 'owned'),
    ('json_duplicate', 0x404c918, '488d05a9c640fc48898424d027000048c78424d827000008000000488d8424d02700004889442428488d05a90e69004889442430488d3dc76b3efc488d742428e863696a004989c6e92bfdffff48c744242806000000488d7424284889efe81551eaff4889442408e924ffffff', 'owned'),
    ('json_alloc_and_guards', 0x404c985, 'bf08000000bea8270000ff15fb2a4902eb6a488d3d6a134302ff157c2b4902eb5b488d3d5b134302ff156d2b4902488d3d2e2c4302ff15882e4902488d3d092c4302ff157b2e4902488d3d142c4302ff15462b4902eb25488d3ded2b4302ff15372b4902eb1648c744240800000000488d3d0d134302ff151f2b49020f0b', 'owned'),
    ('json_existing_field_unwind', 0x404ca5a, '4889c3bea82700004c89ff31d2ff15332a49024889dfe8db3f3a02', 'owned'),
    ('nested_json_entry', 0x40908e0, '554157415641554154534989e34981eb00d000004881ec0010000048c70424000000004c39dc75ec4881ec680100004989f64889fb488b4e20488b46284839c87343498b561848ffc048f7d948be0026000001000000662e0f1f8400000000000fb67c02ff4883ff207746480fa3fe734049894628488d3c0148ffc748ffc04883ff0175db48c78424200c000005000000488db424200c00004c89f7e80f11e6ff4889430848c70302000000e91604000083ff5b0f84ef00000083ff7b0f850006000041807e48007519410fb64e4984c90f84040b0000fec941884e490f84070600004885c00f840809000049894628488dbc24883400004c89f6e870a6e6ff41807e48007513410fb646493cff0f84e10a0000fec041884649488dbc2480760000488db42488340000baa8270000ff15f3ea44024c89f7e8832ae6ff4989c4488dbc24200c0000488db42488340000baa8270000ff15cdea44024c89a424c83300004c8bac24200c00004983fd020f85e7000000', 'owned'),
    ('nested_json_sequence', 0x4090a89, '41807e48007519410fb64e4984c90f842b0a0000fec941884e490f84210500004885c00f8422080000498946284c893424c644240801488dbc24200c00004889e6e861c0ebff80bc24200c000001750a4c8bbc24280c0000eb3580bc24210c0000010f85cb020000488b3424488dbc24200c0000e81e1e08004c8ba424200c00004c8bbc24280c00004983fc0275424c89bc249034000048c78424883400000200000041807e48000f8443010000', 'owned'),
    ('binary_entry', 0x3266520, '554157415641554154534881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ecf80f00004989f64889fb0fb646200fb6762141c64620013c017565498b4e184885c9741d498b761048ffc90fb60648ffc64989761049894e1884c0781431ffeb57c60300488d053cbd1f0348894308eb5a40b7e03cdf77403c907309240f89c6e9a30000003ca07309240f89c6e95b08000089c64080e61f3cc00f82be0900000fb6f8488d0d89a249fd4c6304b94901c841ffe089c789f0400fb6d70fb6c84889df4c89f6ff150cdc27034889d84881c4f84f00005b415c415d415e415f5dc3', 'owned'),
    ('binary_marker_table', 0x3266629, 'b10281c739ffffff83ff110f87360b0000488d15bfa549fd48633cba4801d7ffe7498b4e184885c90f84170b0000498b561048ffc90fb60248ffc24989561049894e18', 'owned'),
    ('binary_map_depth', 0x3266671, '400fb6d6410fb746226685c00f846f11000066ffc866418946220f843c0c000085d20f844a0c0000', 'owned'),
    ('binary_map_key', 0x3266a49, '4183fd080f8574fdffff41803c24650f8569fdffff41807c2401780f855dfdffff41807c2402630f8551fdffff41807c2403680f8545fdffff41807c2404610f8539fdffff41807c24056e0f852dfdffff41807c2406670f8521fdffff41807c2407650f8515fdffffeb2a4883bc2460280000080f8504fdffff488b84245828000048b965786368616e67654839080f85e9fcffff4c8b6424384d85e40f853c0c0000', 'owned'),
    ('binary_map_value', 0x3266aec, '48c744243800000000488dbc24a80000004c89f631d2e86944060083bc24a8000000020f85aafbffff', 'owned'),
    ('binary_sequence', 0x3266e36, '400fb6ee410fb746226685c00f84b709000066ffc866418946220f847704000085ed0f844e060000488dbc24a80000004c89f631d2e80041060083bc24a8000000020f851e020000', 'owned'),
    ('binary_two_byte_truncation', 0x3266f14, '498b7610498b4e184883f9020f83bb0200004801ce4989761049c7461800000000c60301e970f6ffff', 'owned'),
    ('binary_map32', 0x3266f6e, '498b4610498b4e184883f9040f82bd0000004883c1fc8b104883c0040fca4989461049894e18e9dcf6ffff', 'owned'),
    ('binary_array16', 0x3266ffe, '498b4610498b4e184883f90272314883c1fe0fb71066c1c2084883c0024989461049894e180fb7eae90ffeffff', 'owned'),
    ('binary_sequence_alloc', 0x32670ac, 'baa8270000ff1551842703bfa8270000ff15be8327034885c00f84050700004989c7488db424a8000000baa82700004889c7ff152484270383fd010f85b8000000', 'owned'),
    ('binary_sequence_remainder', 0x326719d, 'c60301e908f4ffffc684248800000004c784248c000000010000004c89ffe8f01fdcff', 'owned'),
    ('binary_sequence_empty', 0x32674ac, '488d150db41f03488d0d16b01f034889e731f6e8cc89d1ff0fb604244c8b7c24083c090f85fef9ffffe913fcffff', 'owned'),
    ('invalid_length_error', 0x2f7fe90, '534883ec404889fb4889742408488954241048894c2418488d4424084889442420488b0510f855034889442428488d4424104889442430488d0582a15a014889442438488d3525a94cfd488d542420e85c680c004889d84883c4405bc3', 'owned'),
    ('binary_missing_field', 0x32672d5, '488b4424384885c00f8547030000488dbc2458280000488d05d61c1ffd4889042448c7442408080000004889e048898424a8000000488d05df64470148898424b00000004531e4488d35a1b21cfd488d9424a8000000e810f4ddff', 'owned'),
    ('binary_success', 0x3267613, '4180fd097553488b4c24788d41ff39e87575488b4424304889842490000000c684248800000009410fb746226683f8ff0f8485000000ffc066418946220f108424880000000f108c24980000000f114b100f1103e9a8efffff', 'owned'),
    ('binary_duplicate', 0x3267728, '488d0599181ffd4889042448c7442408080000004889e048898424a8000000488d05a260470148898424b0000000488d35bdbd1cfd488dbc2450280000488d9424a8000000e8ceefddff', 'owned'),
    ('json_drop_box', 0x3f3be70, '415653504889fbe8f462feffbea82700004889df31d24883c4085b415eff250d365a024989c6bea82700004889df31d2ff15fa355a024c89f7e8a24b4b02', 'owned'),
    ('binary_drop_box', 0x300e900, '415653504889fbe87490ffffbea82700004889df31d24883c4085b415eff257d0b4d034989c6bea82700004889df31d2ff156a0b4d034c89f7e812213e03', 'owned'),
    ('binary_sequence_drop_box', 0x30291b0, '415653504889fbe8c4e7fdffbea82700004889df31d24883c4085b415eff25cd624b034989c6bea82700004889df31d2ff15ba624b034c89f7e862783c03', 'owned'),
    ('binary_outer_unwind', 0x3267944, '4889c348837c243800743a488b7c2438e8a76fdaffeb2eff155f7b27034889c3488dbc2450280000e89f96a800eb16ff15477b27034889c3488dbc2450280000e88796a8004889dfe8bf901803ff15297b2703', 'owned'),
    ('json_drop_two_vectors', 0x3f22186, '488bbda81f00004c8ba5b01f000049ffc4660f1f8400000000004983fc0174144c8dbf0002000049ffcce89be8e6ff4c89ffebe6488bb5a01f00004885f67413488bbda81f000048c1e60931d2ff15c7d25b02488bbdc01f00004c8ba5c81f000049ffc4660f1f4400004983fc0174144c8dbf2001000049ffcce81b0ee6ff4c89ffebe6488b85b81f00004885c07417488bbdc01f000048c1e005488d34c031d2ff1573d25b02', 'owned'),
    ('binary_drop_two_vectors', 0x3007996, '488bbda81f00004c8ba5b01f000049ffc4660f1f8400000000004983fc0174144c8dbf0002000049ffcce88b90d8004c89ffebe6488bb5a01f00004885f67413488bbda81f000048c1e60931d2ff15b77a4d03488bbdc01f00004c8ba5c81f000049ffc4660f1f4400004983fc0174144c8dbf2001000049ffcce80bb6d7004c89ffebe6488b85b81f00004885c07417488bbdc01f000048c1e005488d34c031d2ff15637a4d03', 'owned'),
    ('json_drop_unwind_a', 0x3f22df0, '4989c649ffcc7414498d9f000200004c89ffe849dce6ff4989dfebe7488bb5a01f00004885f67413488bbda81f000048c1e60931d2ff1575c65b02', 'owned'),
    ('json_drop_unwind_b', 0x3f22da9, '4989c649ffcc7414498d9f200100004c89ffe86002e6ff4989dfebe7488b85b81f00004885c07466488bbdc01f000048c1e005488d34c031d2ff15b8c65b02', 'owned'),
    ('binary_drop_unwind_a', 0x3008600, '4989c649ffcc7414498d9f000200004c89ffe83984d8004989dfebe7488bb5a01f00004885f67413488bbda81f000048c1e60931d2ff15656e4d03', 'owned'),
    ('binary_drop_unwind_b', 0x30085b9, '4989c649ffcc7414498d9f200100004c89ffe850aad7004989dfebe7488b85b81f00004885c07466488bbdc01f000048c1e005488d34c031d2ff15a86e4d03', 'owned'),
    ('rmp_error_adapter', 0x422eac0, '4156534883ec284889f348897c2408488d058a68faff48894424104889742418488b05591f2b024889442420488d3d6e9d20fc488d742408e8f3490d000fb60b4883f906773c488d15ff8c59fc48630c8a4801d1ffe14883c3084889df4889c3e81b390000eb18488b73084885f67412488b7b1031d24889c3ff1561092b024889d84883c4285b415ec34989c64889dfe8cb3b00004c89f7e8f31e1c02ff155d092b02', 'owned'),
    ('text_read_error_adapter', 0x422eb70, '534883ec30488974240848897c2410488d05da67faff4889442418488d4424084889442420488b0514092b024889442428488d3de1be20fc488d742410e83e490d004889c3488d7c2408e8813800004889d84883c4305bc34889c3488d7c2408e86b3800004889dfe8731e1c02ff15dd082b02', 'owned'),
    ('json_error_adapter', 0x422ebf0, '4156534883ec284889342448897c2408488d055967faff48894424104889e04889442418488b058d152b024889442420488d3d2d5920fc488d742408e8bf480d004889c34c8b3424498b064883f801741c4885c07520498b76104885f67417498b7e0831d2ff1545082b02eb09498d7e08e8da370000be280000004c89f731d2ff152a082b024889d84883c4285b415ec34889c3be280000004c89f731d2ff150c082b024889dfe8b41d1c024889c34889e7e8093b00004889dfe8a11d1c02ff150b082b02', 'owned'),
    ('binary_read_error_adapter', 0x422ecc0, '534883ec30488974240848897c2410488d058a66faff4889442418488d4424084889442420488b05c4072b024889442428488d3debee20fc488d742410e8ee470d004889c3488d7c2408e8313700004889d84883c4305bc34889c3488d7c2408e81b3700004889dfe8231d1c02ff158d072b02', 'owned'),
    ('position_helper', 0x5c56920, '41574156415453504889d34989f64839f277764989ff488d141f488b05cf468900488b00bf0a0000004c89feffd04883f80175214c29fa4c8d62014c39f27218488d0d19bb860031ff4c89e64c89f2ff15fb8b88004531e44b8d1427488b0595468900488b00bf0a0000004c89feffd048ffc074294c29e372314889da4883c4085b415c415e415fc3488d0de8ba860031ff4889de4c89f2ff15b28b8800488d3d8bba8600ff15558b8800488d3d96ba8600ff15708e8800', 'owned'),
]
EDGES = [
    ('exchange_key_classify', 0x3efb3b8, 'e8', 0x3bda740),
    ('exchange_locus_duplicate', 0x3efb3e4, '0f85', 0x3f0566f),
    ('exchange_locus_decode', 0x3efd86e, 'e8', 0x4112920),
    ('exchange_locus_child_error', 0x3efd887, '0f84', 0x3f01e0c),
    ('exchange_locus_present', 0x3efe85e, '0f85', 0x3efeaf4),
    ('locus_key_classify', 0x4112b64, 'e8', 0x3bd3ad0),
    ('locus_ctx_duplicate', 0x4112b95, '0f85', 0x41154db),
    ('locus_ctx_decode', 0x411364c, 'e8', 0x409c990),
    ('locus_ctx_child_error', 0x411366a, '0f84', 0x4114056),
    ('locus_ctx_present', 0x4113b8a, '0f85', 0x4113c3d),
    ('context_key_classify', 0x409cdda, 'e8', 0x41fc4a0),
    ('context_height_duplicate', 0x409d040, '0f84', 0x409ddb8),
    ('context_height_colon', 0x409d070, '0f83', 0x409d624),
    ('context_height_number', 0x409d63e, 'e8', 0x3ef2dc0),
    ('context_height_number_error', 0x409d648, '0f85', 0x409da71),
    ('context_height_absent', 0x409d802, '0f84', 0x409dade),
    ('context_duplicate_format', 0x409dea6, 'e9', 0x409dbd3),
    ('context_format_error', 0x409dbd8, 'e8', 0x46f32c0),
    ('number_minus_branch', 0x3ef2e3d, '75', 0x3ef2e76),
    ('number_negative_digits', 0x3ef2e56, 'e8', 0x3ef2440),
    ('number_positive_digits', 0x3ef2e8d, 'e8', 0x3ef2440),
    ('decimal_leading_zero_end', 0x3ef2480, '0f83', 0x3ef2552),
    ('decimal_leading_zero_error', 0x3ef249a, 'e8', 0x3ef1a90),
    ('decimal_carry_guard', 0x3ef24f5, '0f82', 0x3ef25b9),
    ('decimal_below_threshold', 0x3ef2518, '76', 0x3ef24e0),
    ('decimal_at_threshold', 0x3ef2523, '76', 0x3ef24e0),
    ('decimal_post_integer', 0x3ef255a, 'e8', 0x3ef20f0),
    ('nested_state_open_ok', 0x4090b3f, '0f85', 0x4090d28),
    ('nested_state_copy_tail', 0x4090b55, 'e9', 0x4090d50),
    ('nested_state_result_error', 0x4090d83, '0f84', 0x4090fba),
    ('wrapper_read', 0x564a68c, 'e8', 0x422e410),
    ('wrapper_error', 0x564a693, '75', 0x564a69e),
    ('component_fallback', 0x422e4fc, '0f85', 0x422e59f),
    ('dot_position', 0x422e548, '74', 0x422e59f),
    ('extension_compare', 0x422e55c, 'e8', 0x159fca0),
    ('extension_fallback', 0x422e563, '74', 0x422e59f),
    ('binary_read_result', 0x422e58a, '0f81', 0x422e674),
    ('binary_read_error', 0x422e598, 'e8', 0x422ecc0),
    ('text_read_result', 0x422e5c4, '71', 0x422e608),
    ('text_read_error', 0x422e5ce, 'e8', 0x422eb70),
    ('json_decode', 0x422e62e, 'e8', 0x3ef18b0),
    ('json_decode_test', 0x422e63a, '75', 0x422e659),
    ('json_error', 0x422e644, 'e8', 0x422ebf0),
    ('binary_decode', 0x422e6aa, 'e8', 0x3266520),
    ('binary_tag_test', 0x422e6b4, '75', 0x422e6c8),
    ('binary_error', 0x422e6e6, 'e8', 0x422eac0),
    ('json_root', 0x3ef18fa, 'e8', 0x404c260),
    ('json_root_error', 0x3ef1906, '75', 0x3ef1967),
    ('json_suffix_empty', 0x3ef1915, '73', 0x3ef1965),
    ('json_suffix_too_large', 0x3ef193a, '77', 0x3ef1991),
    ('json_suffix_mask_reject', 0x3ef1940, '73', 0x3ef1991),
    ('json_suffix_loop', 0x3ef1955, '75', 0x3ef1930),
    ('json_suffix_error', 0x3ef19a7, 'e8', 0x3ef1a90),
    ('json_suffix_drop', 0x3ef19b2, 'e8', 0x3f22170),
    ('json_suffix_unwind_box', 0x3ef19f1, 'e8', 0x3f3be70),
    ('json_empty', 0x404c2bb, '73', 0x404c2f6),
    ('json_start_array', 0x404c314, '0f84', 0x404c532),
    ('json_start_map', 0x404c31d, '0f85', 0x404c8d9),
    ('json_depth_zero', 0x404c32f, '0f84', 0x404c9b3),
    ('json_depth_exhausted', 0x404c33a, '0f84', 0x404c8f5),
    ('json_key_iter', 0x404c36d, 'e8', 0x3f479f0),
    ('json_key_error', 0x404c377, '0f84', 0x404c683),
    ('json_no_key', 0x404c382, '0f85', 0x404c6f4),
    ('json_match_key', 0x404c3e2, '74', 0x404c460),
    ('json_duplicate_field', 0x404c466, '0f85', 0x404c918),
    ('json_child_map', 0x404c4d6, 'e8', 0x40908e0),
    ('json_child_failure', 0x404c4ea, '0f84', 0x404c8cf),
    ('json_null_alloc', 0x404c514, '0f84', 0x404c985),
    ('json_child_sequence', 0x404c5d8, 'e8', 0x40908e0),
    ('json_existing_field_drop', 0x404c698, 'e8', 0x3f22170),
    ('json_missing', 0x404c6fa, '0f84', 0x404c85f),
    ('json_wrap_error', 0x404c823, 'e8', 0x4671240),
    ('json_missing_error', 0x404c89f, 'e8', 0x46f32c0),
    ('json_duplicate_error', 0x404c958, 'e8', 0x46f32c0),
    ('json_position_error', 0x404c976, 'e8', 0x3ef1a90),
    ('nested_json_array_open', 0x4090994, '0f84', 0x4090a89),
    ('nested_json_other_open', 0x409099d, '0f85', 0x4090fa3),
    ('nested_json_map', 0x40909db, 'e8', 0x3efb050),
    ('nested_json_map_result', 0x4090a4f, '0f85', 0x4090b3c),
    ('nested_json_sequence_iter', 0x4090aca, 'e8', 0x3f4cb30),
    ('nested_json_sequence_child', 0x4090afd, 'e8', 0x4112920),
    ('rmp_flag_dispatch', 0x3266582, '75', 0x32665e9),
    ('rmp_short_marker', 0x326658b, '74', 0x32665aa),
    ('rmp_positive', 0x32665a4, '78', 0x32665ba),
    ('rmp_fixmap', 0x32665c9, 'e9', 0x3266671),
    ('rmp_fixarray', 0x32665d6, 'e9', 0x3266e36),
    ('rmp_fixstr', 0x32665e3, '0f82', 0x3266fa7),
    ('rmp_map_depth', 0x326667d, '0f84', 0x32677f2),
    ('rmp_map_zero', 0x3266693, '0f84', 0x32672e3),
    ('rmp_key_length', 0x3266abd, '0f85', 0x32667c7),
    ('rmp_key_bytes', 0x3266ad8, '0f85', 0x32667c7),
    ('rmp_duplicate', 0x3266ae6, '0f85', 0x3267728),
    ('rmp_child_map', 0x3266b02, 'e8', 0x32caf70),
    ('rmp_child_map_result', 0x3266b0f, '0f85', 0x32666bf),
    ('rmp_seq_depth', 0x3266e42, '0f84', 0x32677ff),
    ('rmp_seq_zero', 0x3266e58, '0f84', 0x32674ac),
    ('rmp_child_sequence', 0x3266e6b, 'e8', 0x32caf70),
    ('rmp_empty_length_error', 0x32674bf, 'e8', 0x2f7fe90),
    ('rmp_seq_count', 0x32670e7, '0f85', 0x32671a5),
    ('rmp_seq_extra_drop', 0x32671bb, 'e8', 0x30291b0),
    ('rmp_missing_return', 0x32672dd, '0f85', 0x326762a),
    ('rmp_success_depth', 0x3267643, '0f84', 0x32676ce),
    ('rmp_duplicate_error', 0x326776d, 'e8', 0x3046740),
    ('json_error_make', 0x422ec2c, 'e8', 0x43034f0),
    ('json_error_inner_drop', 0x422ec61, 'e8', 0x4232440),
    ('rmp_error_make', 0x422eaf8, 'e8', 0x43034f0),
    ('rmp_error_inner_drop', 0x422eb20, 'e8', 0x4232440),
    ('text_error_make', 0x422ebad, 'e8', 0x43034f0),
    ('text_error_inner_drop', 0x422ebba, 'e8', 0x4232440),
    ('read_error_make', 0x422ecfd, 'e8', 0x43034f0),
    ('read_error_inner_drop', 0x422ed0a, 'e8', 0x4232440),
    ('json_box_drop', 0x3f3be77, 'e8', 0x3f22170),
    ('binary_box_drop', 0x300e907, 'e8', 0x3007980),
    ('binary_sequence_box_drop', 0x30291b7, 'e8', 0x3007980),
    ('binary_outer_unwind_box', 0x3267954, 'e8', 0x300e900),
    ('json_vector_a_drop', 0x3f221b0, 'e8', 0x3d90a50),
    ('json_vector_b_drop', 0x3f22200, 'e8', 0x3d83020),
    ('rmp_vector_a_drop', 0x30079c0, 'e8', 0x3d90a50),
    ('rmp_vector_b_drop', 0x3007a10, 'e8', 0x3d83020),
]
TABLES = [
    ('rmp_primary', 0x70087c, 225, 'd5449da19bbb915b102e09c8f0181fe605e0a42882f6f5180dba20710bafca96'),
    ('rmp_primary_sub', 0x700c00, 18, '6f15945bf61ab3579e74d4598f488d832c98c3ac2300606b30c4fcaa6f3e978e'),
    ('rmp_inner', 0x700c48, 225, 'c4c89b359d73789878fdfb9fc390c8db2301cf0ebdd4c219f714cd45001c2d10'),
    ('rmp_inner_sub', 0x700fcc, 18, '5c8012115e5140e404932240c1e2985cb76a7e41ff5d8d03173ceefd7b1020a2'),
    ('rmp_error_cleanup', 0x7c780c, 7, 'ff5bf94f90eda8d4cd44c1e3e9bb739fca1ae42064e92fdde27b6c6ac769aed3'),
]

# Selected entries, not claims that other table entries are reachable.
NESTED_TABLE_ENTRIES = [
    ('exchange_name_length', 0x7b2c78, 3, 0x3bdaaa3),
    ('exchange_field_index', 0x7becd4, 0, 0x3efb3dc),
    ('locus_field_index', 0x7c17c4, 0, 0x4112b8f),
    ('context_name_length', 0x7c7198, 3, 0x41fc5af),
    ('context_field_index', 0x7c0d50, 2, 0x409d03a),
]

# Fixed instruction forms for one selected stack-to-output dataflow. Values
# are decoded from target bytes and checked before any offset arithmetic.
HEIGHT_OPERANDS = [
    ('context_output_word', 0x409ccd9, '48896b', 1, 0x28),
    ('locus_child_buffer', 0x4112abb, '4c8dac24', 4, 0x338),
    ('locus_child_load_base', 0x4113678, '488d8424', 4, 0x348),
    ('locus_child_load_delta', 0x41136a7, '0f1048', 1, 0x10),
    ('locus_local_store', 0x41136c3, '0f298c24', 4, 0x2d0),
    ('locus_local_load', 0x4115dd0, '0f108c24', 4, 0x2d0),
    ('locus_result_store', 0x4115df8, '0f118c24', 4, 0x1630),
    ('locus_copy1_source', 0x4114513, '488db424', 4, 0x1610),
    ('locus_copy1_dest', 0x411450b, '488dbc24', 4, 0x2490),
    ('locus_copy1_size', 0x411451b, 'ba', 4, 0xba0),
    ('locus_copy2_source', 0x4114539, '488db424', 4, 0x2490),
    ('locus_copy2_dest', 0x4114531, '488dbc24', 4, 0x338),
    ('locus_copy2_size', 0x4114541, 'ba', 4, 0xba0),
    ('locus_copy3_source', 0x41145c4, '488db424', 4, 0x348),
    ('locus_copy3_dest', 0x41145cc, '488dbc24', 4, 0x3218),
    ('locus_copy3_size', 0x41145d4, 'ba', 4, 0xb90),
    ('locus_copy4_dest', 0x4114604, '488d7d', 1, 0x10),
    ('locus_copy4_source', 0x4114608, '488db424', 4, 0x3218),
    ('locus_copy4_size', 0x4114610, 'ba', 4, 0xb90),
    ('exchange_child_buffer', 0x3efd863, '488dbc24', 4, 0x14f8),
    ('exchange_copy1_source', 0x3efd89a, '488db424', 4, 0x1508),
    ('exchange_copy1_dest', 0x3efd88d, '488dbc24', 4, 0x940),
    ('exchange_copy1_size', 0x3efd895, 'ba', 4, 0xb90),
    ('exchange_copy2_source', 0x3efd8cf, '488db424', 4, 0x940),
    ('exchange_copy2_dest', 0x3efd8dc, '488dbc24', 4, 0x43e0),
    ('exchange_copy2_size', 0x3efd8d7, 'ba', 4, 0xb90),
    ('exchange_copy3_source', 0x3efeafc, '488db424', 4, 0x43d0),
    ('exchange_copy3_dest', 0x3efeaf4, '488dbc24', 4, 0x34e0),
    ('exchange_copy3_size', 0x3efeb04, 'ba', 4, 0xba0),
    ('exchange_copy4_source', 0x3f0bf50, '488db424', 4, 0x34e0),
    ('exchange_copy4_dest', 0x3f0bf48, '488dbc24', 4, 0x14f8),
    ('exchange_copy4_size', 0x3f0bf58, 'ba', 4, 0xba0),
    ('exchange_copy5_source', 0x3f0c4fa, '488db424', 4, 0x14f8),
    ('exchange_copy5_size', 0x3f0c4f2, 'ba', 4, 0x10e8),
    ('nested_child_buffer', 0x40909d0, '488dbc24', 4, 0x3488),
    ('nested_copy1_source', 0x4090b4d, '488db424', 4, 0x3498),
    ('nested_copy1_dest', 0x4090d50, '488dbc24', 4, 0xa9d0),
    ('nested_copy1_size', 0x4090d58, 'ba', 4, 0x2798),
    ('nested_copy2_dest', 0x4090d89, '488d7b', 1, 0x10),
    ('nested_copy2_source', 0x4090d8d, '488db424', 4, 0xa9d0),
    ('nested_copy2_size', 0x4090d95, 'ba', 4, 0x2798),
    ('outer_child_buffer', 0x404c4cb, '488dbc24', 4, 0x27d0),
    ('outer_copy_size', 0x404c51a, 'ba', 4, 0x27a8),
]


# RIP-relative references are selected instruction-aligned byte patterns.
RIP_REFS = [
    ('memcpy_slot_load_context', 0x3f0bf32, '488b1d', 0x64df508),
    ('exchange_length_table', 0x3bda752, '488d0d', 0x7b2c78),
    ('exchange_field_table', 0x3efb236, '488d1d', 0x7becd4),
    ('exchange_missing_locus', 0x3efe864, '488d05', 0x7c4360),
    ('exchange_duplicate_locus', 0x3f0566f, '488d05', 0x7c4360),
    ('exchange_missing_format', 0x3efe8a4, '488d3d', 0x4325c4),
    ('exchange_duplicate_format', 0x3f056af, '488d3d', 0x43351a),
    ('locus_field_table', 0x4112b7f, '488d0d', 0x7c17c4),
    ('locus_missing_ctx', 0x4113b90, '488d05', 0x7c374d),
    ('locus_duplicate_ctx', 0x41154db, '488d05', 0x7c374d),
    ('context_length_table', 0x41fc4b1, '488d0d', 0x7c7198),
    ('context_field_table', 0x409cdef, '488d0d', 0x7c0d50),
    ('context_missing_height', 0x409dade, '488d05', 0x7c1db3),
    ('context_duplicate_height', 0x409ddb8, '488d05', 0x7c1db3),
    ('context_missing_template', 0x409dbcc, '488d3d', 0x4325c4),
    ('context_duplicate_template', 0x409de9f, '488d3d', 0x43351a),
    ('wrapper_location', 0x564a685, '488d15', 0x64767d8),
    ('wrapper_unwrap_literal', 0x564a6a3, '488d3d', 0x92a732),
    ('wrapper_diagnostic_location', 0x564a6b1, '4c8d05', 0x64ab040),
    ('read_suffix', 0x422e550, '488d15', 0x7c95c0),
    ('binary_dispatch', 0x32665ec, '488d0d', 0x70087c),
    ('binary_subdispatch', 0x326663a, '488d15', 0x700c00),
    ('binary_inner_dispatch', 0x3266786, '488d3d', 0x700c48),
    ('binary_inner_subdispatch', 0x3266813, '488d35', 0x700fcc),
    ('binary_error_table', 0x422eb06, '488d15', 0x7c780c),
    ('json_missing_key', 0x404c85f, '488d05', 0x458fc8),
    ('json_missing_template', 0x404c893, '488d3d', 0x4325c4),
    ('json_duplicate_key', 0x404c918, '488d05', 0x458fc8),
    ('json_duplicate_template', 0x404c94c, '488d3d', 0x43351a),
    ('binary_missing_key', 0x32672eb, '488d05', 0x458fc8),
    ('binary_missing_template', 0x326731c, '488d35', 0x4325c4),
    ('binary_duplicate_key', 0x3267728, '488d05', 0x458fc8),
    ('binary_duplicate_template', 0x3267756, '488d35', 0x43351a),
    ('binary_invalid_length_template', 0x2f7fed3, '488d35', 0x44a7ff),
    ('binary_error_template', 0x422eaec, '488d3d', 0x438861),
    ('text_read_error_template', 0x422eba1, '488d3d', 0x43aa89),
    ('json_error_template', 0x422ec20, '488d3d', 0x434554),
    ('binary_read_error_template', 0x422ecf1, '488d3d', 0x43dbe3),
]


def authenticate(data, expected=TARGET_SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


def one_section(rows, name):
    matches = [row for row in rows if row['name'] == name and row['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing, duplicate, or fileless section: ' + name)
    return matches[0]


def file_mapping(data, rows, va, size, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid byte range')
    matches = [row for row in rows if row['type'] != 8
               and (not executable or row['flags'] & 4)
               and row['address'] <= va
               and va + size <= row['address'] + row['size']]
    if len(matches) != 1:
        raise ValueError('unmapped, fileless or ambiguous virtual address')
    row = matches[0]
    offset = row['offset'] + va - row['address']
    if offset < 0 or offset + size > len(data):
        raise ValueError('byte range outside file')
    return offset, row['name']


def read_va(data, rows, va, size, executable=False):
    off, _ = file_mapping(data, rows, va, size, executable)
    return bytes(data[off:off + size])


def selected_fdes(data, rows):
    index_rows, index = unwind_index(data)
    if index_rows != rows:
        raise ValueError('section disagreement')
    _, records = eh_frame_records(data, rows)
    by_start = {}
    for record in records:
        by_start.setdefault(record['start'], []).append(record)
    by_index = {row['start']: row for row in index}
    selected = []
    for name, start, end in FDE_PINS:
        found = by_start.get(start, [])
        if len(found) != 1 or found[0]['end'] != end:
            raise ValueError('FDE identity or extent mismatch: ' + name)
        rec = found[0]
        hdr = by_index.get(start)
        if hdr is None or hdr['fde'] != rec['fde']:
            raise ValueError('FDE/header disagreement: ' + name)
        if any(other['fde'] != rec['fde'] and other['start'] < end
               and start < other['end'] for other in records):
            raise ValueError('overlapping FDE extent: ' + name)
        off, secname = file_mapping(data, rows, start, end - start, True)
        raw = bytes(data[off:off + end - start])
        selected.append({
            'role': name, 'start_va': hex(start), 'end_va_exclusive': hex(end),
            'file_offset': hex(off), 'section': secname, 'length': len(raw),
            'fde_va': hex(rec['fde']), 'cie_va': hex(rec['cie']),
            'lsda_va': hex(rec['lsda']) if rec['lsda'] is not None else None,
            'sha256': hashlib.sha256(raw).hexdigest(), 'body_hex': raw.hex(),
        })
    return selected, {name: by_start[start][0] for name, start, _ in FDE_PINS}


def pinned_windows(data, rows):
    result = []
    for name, va, expected_hex, ownership in WINDOWS:
        expected = bytes.fromhex(expected_hex)
        actual = read_va(data, rows, va, len(expected), True)
        if actual != expected:
            raise ValueError('instruction window mismatch: ' + name)
        off, _ = file_mapping(data, rows, va, len(expected), True)
        result.append({'role': name, 'ownership': ownership, 'va': hex(va),
                       'file_offset': hex(off), 'length': len(actual),
                       'bytes': actual.hex(), 'sha256': hashlib.sha256(actual).hexdigest()})
    return result


def transfer(data, rows, va, prefix):
    op = bytes.fromhex(prefix)
    if len(op) == 1 and op[0] in (0xe8, 0xe9):
        size, fmt = 5, '<i'
    elif len(op) == 1 and (0x70 <= op[0] <= 0x7f or op[0] == 0xeb):
        size, fmt = 2, '<b'
    elif len(op) == 2 and op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
        size, fmt = 6, '<i'
    else:
        raise ValueError('unsupported selected transfer form')
    raw = read_va(data, rows, va, size, True)
    if not raw.startswith(op):
        raise ValueError('changed transfer opcode')
    delta = struct.unpack_from(fmt, raw, len(op))[0]
    return va + size + delta, raw


def selected_edges(data, rows):
    out = []
    for name, va, op, expected_target in EDGES:
        target, raw = transfer(data, rows, va, op)
        if target != expected_target:
            raise ValueError('changed transfer target: ' + name)
        off, _ = file_mapping(data, rows, va, len(raw), True)
        ownership = 'context' if 0x422e410 <= va < 0x422e72c else 'owned'
        out.append({'role': name, 'ownership': ownership, 'va': hex(va),
                    'file_offset': hex(off), 'bytes': raw.hex(), 'target_va': hex(target)})
    return out


def selected_references(data, rows):
    out = []
    for name, va, prefix, expected in RIP_REFS:
        raw = read_va(data, rows, va, 7, True)
        if raw[:3] != bytes.fromhex(prefix):
            raise ValueError('changed RIP-relative opcode: ' + name)
        target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != expected:
            raise ValueError('changed RIP-relative target: ' + name)
        off, _ = file_mapping(data, rows, va, 7, True)
        context = 0x422e410 <= va < 0x422e72c or name == 'memcpy_slot_load_context'
        out.append({'role': name, 'va': hex(va), 'file_offset': hex(off),
                    'bytes': raw.hex(), 'target_va': hex(target),
                    'ownership': 'context' if context else 'owned'})
    return out


def selected_tables(data, rows):
    out = []
    for name, base, count, expected_hash in TABLES:
        raw = read_va(data, rows, base, count * 4)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError('changed relative table: ' + name)
        lo, hi = ((0x422eac0, 0x422eb63) if name == 'rmp_error_cleanup'
                  else (0x3266520, 0x3267997))
        for index in range(count):
            delta = struct.unpack_from('<i', raw, 4 * index)[0]
            target = base + delta
            if not lo <= target < hi:
                raise ValueError('relative table target outside selected extent')
            off, _ = file_mapping(data, rows, base + 4 * index, 4)
            out.append({'table': name, 'table_va': hex(base), 'index': index,
                        'entry_va': hex(base + 4 * index), 'file_offset': hex(off),
                        'signed_delta': delta, 'target_va': hex(target)})
    for name, base, index, expected_target in NESTED_TABLE_ENTRIES:
        entry = base + 4 * index
        raw = read_va(data, rows, entry, 4)
        delta = struct.unpack('<i', raw)[0]
        target = base + delta
        if target != expected_target:
            raise ValueError('changed selected nested dispatch entry: ' + name)
        file_mapping(data, rows, target, 1, True)
        off, _ = file_mapping(data, rows, entry, 4)
        out.append({'table': name, 'table_va': hex(base), 'index': index,
                    'entry_va': hex(entry), 'file_offset': hex(off),
                    'signed_delta': delta, 'target_va': hex(target)})
    return out


def trace_height_offsets(data, rows):
    """Calculate the selected copy path; calls, aliases, and branches are conditional."""
    values = {}
    instructions = []
    for name, va, prefix, width, expected in HEIGHT_OPERANDS:
        opcode = bytes.fromhex(prefix)
        raw = read_va(data, rows, va, len(opcode) + width, True)
        value = int.from_bytes(raw[len(opcode):], 'little')
        if raw[:len(opcode)] != opcode or value != expected:
            raise ValueError('changed height-flow operand: ' + name)
        off, _ = file_mapping(data, rows, va, len(raw), True)
        values[name] = value
        instructions.append({'role': name, 'va': hex(va), 'file_offset': hex(off),
                             'bytes': raw.hex(), 'operand': hex(value)})

    def copy_word(at, source, destination, size):
        if not source <= at or at + 8 > source + size:
            raise ValueError('height word outside selected copy')
        return destination + at - source

    v = values
    position = v['locus_child_buffer'] + v['context_output_word']
    position = copy_word(position, v['locus_child_load_base'] + v['locus_child_load_delta'],
                         v['locus_local_store'], 16)
    locus_local = position
    position = copy_word(position, v['locus_local_load'], v['locus_result_store'], 16)
    locus_result = position
    for i in range(1, 5):
        position = copy_word(position, v[f'locus_copy{i}_source'],
                             v[f'locus_copy{i}_dest'], v[f'locus_copy{i}_size'])
    locus_output = position
    position += v['exchange_child_buffer']
    for i in range(1, 5):
        position = copy_word(position, v[f'exchange_copy{i}_source'],
                             v[f'exchange_copy{i}_dest'], v[f'exchange_copy{i}_size'])
    position = copy_word(position, v['exchange_copy5_source'], 0, v['exchange_copy5_size'])
    exchange_output = position
    position += v['nested_child_buffer']
    for i in range(1, 3):
        position = copy_word(position, v[f'nested_copy{i}_source'],
                             v[f'nested_copy{i}_dest'], v[f'nested_copy{i}_size'])
    nested_output = position
    position += v['outer_child_buffer']
    position = copy_word(position, v['outer_child_buffer'], 0, v['outer_copy_size'])
    if (locus_output, exchange_output, nested_output, position) != (0x28,) * 4:
        raise ValueError('height-flow output offset changed')
    return {'instructions': instructions, 'word_bytes': 8,
            'offsets': {'context_output': hex(v['context_output_word']),
                        'locus_first_local_stack': hex(locus_local),
                        'locus_result_stack': hex(locus_result),
                        'locus_output': hex(locus_output), 'exchange_output': hex(exchange_output),
                        'nested_output': hex(nested_output), 'allocated_outer_object': hex(position)},
            'limitation': 'selected normal path with ordinary copy binding and no conflicting aliases'}


def one_relocation(data, rows, slot):
    sec = one_section(rows, '.rela.dyn')
    if sec['size'] % 24 or sec['offset'] < 0 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('truncated RELA section')
    found = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        loc, info, addend = struct.unpack_from('<QQq', data, off)
        if loc == slot:
            found.append((info & 0xffffffff, info >> 32, addend))
    if len(found) != 1 or found[0][:2] != (8, 0):
        raise ValueError('missing, duplicate or non-relative Location relocation')
    return found[0][2]


def external_copy_symbol(data, rows, slot=0x64df508):
    """Resolve a contextual import; the runtime binding is still a boundary."""
    rel = one_section(rows, '.rela.dyn')
    symbols = one_section(rows, '.dynsym')
    strings = one_section(rows, '.dynstr')
    if rel['size'] % 24 or symbols['size'] % 24:
        raise ValueError('malformed dynamic tables')
    matches = []
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', data, off)
        if where == slot:
            matches.append((off, info, addend))
    if len(matches) != 1 or matches[0][1] & 0xffffffff != 6 or matches[0][2] != 0:
        raise ValueError('missing, duplicate or non-GLOB_DAT copy slot')
    reloc_off, info, addend = matches[0]
    index = info >> 32
    symbol_off = symbols['offset'] + index * 24
    if index == 0 or symbol_off + 24 > symbols['offset'] + symbols['size']:
        raise ValueError('dynamic symbol index outside table')
    name_off, st_info, st_other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, symbol_off)
    if name_off >= strings['size'] or shndx != 0:
        raise ValueError('invalid undefined dynamic symbol')
    name_start = strings['offset'] + name_off
    name_end = data.find(b'\0', name_start, strings['offset'] + strings['size'])
    if name_end < 0 or bytes(data[name_start:name_end]) != b'memcpy':
        raise ValueError('copy import name mismatch')
    return {'role': 'context_external_dependency', 'slot_va': hex(slot),
            'relocation_va': hex(rel['address'] + reloc_off - rel['offset']),
            'relocation_file_offset': hex(reloc_off), 'relocation_type': info & 0xffffffff,
            'symbol_index': index, 'symbol_va': hex(symbols['address'] + symbol_off - symbols['offset']),
            'name_va': hex(strings['address'] + name_off), 'name': 'memcpy',
            'symbol_info': st_info, 'symbol_other': st_other, 'symbol_section_index': shndx,
            'symbol_value': value, 'symbol_size': size, 'relocation_addend': addend,
            'limitation': 'runtime binding and callee behavior remain external assumptions'}


def selected_constants(data, rows):
    loc = 0x64767d8
    ptr = one_relocation(data, rows, loc)
    length, line, column = struct.unpack('<QII', read_va(data, rows, loc + 8, 16))
    if length > 256:
        raise ValueError('invalid Location length')
    path = read_va(data, rows, ptr, length)
    if (path, line, column) != (b'l1/src/abci/state.rs', 102, 40):
        raise ValueError('changed contextual Location')
    diagnostic_va = 0x64ab040
    diagnostic_ptr = one_relocation(data, rows, diagnostic_va)
    diag_len, diag_line, diag_col = struct.unpack('<QII', read_va(data, rows, diagnostic_va + 8, 16))
    if diag_len > 256:
        raise ValueError('invalid diagnostic Location length')
    diagnostic_path = read_va(data, rows, diagnostic_ptr, diag_len)
    if (diagnostic_path, diag_line, diag_col) != (b'node/src/hl_node.rs', 346, 66):
        raise ValueError('changed wrapper diagnostic Location')
    strings = [('unwrap', 0x92a732, b'called `Result::unwrap()` on an `Err` value'),
               ('exchange', 0x458fc8, b'exchange'),
               ('locus', 0x7c4360, b'locus'),
               ('ctx', 0x7c374d, b'ctx'),
               ('height', 0x7c1db3, b'height'),
               ('suffix', 0x7c95c0, b'rmp')]
    templates = [('missing', 0x4325c4, b'missing field `'),
                 ('invalid_length', 0x44a7ff, b'invalid length '),
                 ('duplicate', 0x43351a, b'duplicate field `'),
                 ('text_read', 0x43aa89, b'read_to_string: '),
                 ('binary_read', 0x43dbe3, b'read: '),
                 ('binary_parse', 0x438861, b'rmp_from_slice: '),
                 ('json_parse', 0x434554, b'serde_json::from_str: ')]
    result = []
    for role, va, expected in strings:
        raw = read_va(data, rows, va, len(expected))
        if raw != expected:
            raise ValueError('changed literal: ' + role)
        off, _ = file_mapping(data, rows, va, len(raw))
        result.append({'role': role, 'va': hex(va), 'file_offset': hex(off),
                       'length': len(raw), 'bytes': raw.hex(), 'ascii': raw.decode('ascii')})
    for role, va, expected in templates:
        length_byte = read_va(data, rows, va, 1)[0]
        raw = read_va(data, rows, va + 1, length_byte)
        if raw != expected:
            raise ValueError('changed format prefix: ' + role)
        off, _ = file_mapping(data, rows, va, 1 + len(raw))
        result.append({'role': role, 'va': hex(va), 'file_offset': hex(off),
                       'length': length_byte, 'bytes': raw.hex(), 'ascii': raw.decode('ascii')})
    # The same eight literal bytes also occur as two instruction immediates.
    for va in (0x404c3d5, 0x3266acb):
        raw = read_va(data, rows, va, 10, True)
        if raw[:2] not in (b'\x48\xb8', b'\x48\xb9') or raw[2:] != b'exchange':
            raise ValueError('changed inline field comparison')
    mask_bytes = read_va(data, rows, 0x3ef1922, 10, True)
    if mask_bytes[:2] != b'\x48\xbf':
        raise ValueError('changed suffix-mask instruction')
    mask = struct.unpack_from('<Q', mask_bytes, 2)[0]
    if mask != 0x100002600:
        raise ValueError('changed suffix mask')
    lead = read_va(data, rows, 0x404c2c7, 10, True)
    if lead[:2] != b'\x49\xbd' or struct.unpack_from('<Q', lead, 2)[0] != mask:
        raise ValueError('leading/trailing masks differ')
    threshold = read_va(data, rows, 0x3ef24b2, 10, True)
    last_digit = read_va(data, rows, 0x3ef251f, 4, True)
    if threshold[:2] != b'\x49\xb8' or last_digit[:3] != b'\x41\x80\xfb':
        raise ValueError('changed decimal threshold instruction')
    quotient = struct.unpack_from('<Q', threshold, 2)[0] + 1
    remainder = last_digit[3]
    if (quotient, remainder) != divmod(MASK64, 10):
        raise ValueError('changed decimal accumulation threshold')
    return {'location': {'role': 'context_anchor_only', 'va': hex(loc),
                         'path_va': hex(ptr), 'path': path.decode('ascii'),
                         'length': length, 'line': line, 'column': column},
            'diagnostic_location': {'role': 'wrapper_error_location', 'va': hex(diagnostic_va),
                                    'path_va': hex(diagnostic_ptr), 'path': diagnostic_path.decode('ascii'),
                                    'length': diag_len, 'line': diag_line, 'column': diag_col},
            'literals': result, 'whitespace_mask': hex(mask),
            'whitespace_bytes': [i for i in range(33) if (mask >> i) & 1],
            'copy_import': external_copy_symbol(data, rows),
            'decimal_threshold': {'quotient': quotient, 'remainder': remainder,
                                  'constant_va': '0x3ef24b2', 'remainder_va': '0x3ef251f',
                                  'meaning': 'selected digit loop; larger values enter a separate fallback'}}


def normalize_pair(data, rows):
    length = 0xa7
    first, second = 0x3f22186, 0x3007996
    a = bytearray(read_va(data, rows, first, length, True))
    b = bytearray(read_va(data, rows, second, length, True))
    raw_differences = [i for i, (left, right) in enumerate(zip(a, b)) if left != right]
    masks = []
    for instr_off, opcode, target in ((0x2a, b'\xe8', 0x3d90a50),
                                       (0x4d, b'\xff\x15', 0x64df4a0),
                                       (0x7a, b'\xe8', 0x3d83020),
                                       (0xa1, b'\xff\x15', 0x64df4a0)):
        size = len(opcode) + 4
        destinations = []
        for base, raw in ((first, a), (second, b)):
            if raw[instr_off:instr_off + len(opcode)] != opcode:
                raise ValueError('normalization opcode mismatch')
            disp = struct.unpack_from('<i', raw, instr_off + len(opcode))[0]
            dest = base + instr_off + size + disp
            if dest != target:
                raise ValueError('normalization target mismatch')
            destinations.append(hex(dest))
        begin = instr_off + len(opcode)
        a[begin:begin + 4] = b'\0' * 4
        b[begin:begin + 4] = b'\0' * 4
        masks.append({'offset': hex(begin), 'length': 4, 'opcode': opcode.hex(),
                      'target_a': destinations[0], 'target_b': destinations[1]})
    if a != b:
        raise ValueError('unmasked vector cleanup bytes differ')
    return {'a_va': hex(first), 'b_va': hex(second), 'length': length,
            'raw_different_offsets': [hex(i) for i in raw_differences],
            'raw_difference_count': len(raw_differences), 'masks': masks,
            'masked_bytes': sum(item['length'] for item in masks),
            'normalized_sha256': hashlib.sha256(a).hexdigest(),
            'limitation': 'selected original windows only; calls and dynamic binding are boundaries'}


def lsda_table(data, rows, fde):
    if fde['lsda'] is None:
        return []
    sec = one_section(rows, '.gcc_except_table')
    off, secname = file_mapping(data, rows, fde['lsda'], 1)
    if secname != sec['name']:
        raise ValueError('LSDA outside exception table')
    limit = sec['offset'] + sec['size']
    if off + 2 > limit or data[off] != 0xff:
        raise ValueError('unsupported LSDA base')
    pos = off + 1
    encoding = data[pos]
    pos += 1
    type_table = None
    if encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_table = pos + delta
        if type_table > limit:
            raise ValueError('type table outside section')
    elif encoding != 0xff:
        raise ValueError('unsupported LSDA type encoding')
    if pos >= limit or data[pos] != 0x01:
        raise ValueError('unsupported call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    if end > limit or (type_table is not None and end > type_table):
        raise ValueError('call-site table outside section')
    out = []
    prior_end = fde['start']
    while pos < end:
        entry_off = pos
        begin, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        first, last = fde['start'] + begin, fde['start'] + begin + length
        dest = fde['start'] + landing if landing else None
        if first < prior_end or last > fde['end'] or (dest is not None and not fde['start'] <= dest < fde['end']):
            raise ValueError('invalid LSDA range')
        out.append({'fde_start': hex(fde['start']), 'entry_offset': hex(entry_off),
                    'start_va': hex(first), 'end_va_exclusive': hex(last),
                    'landing_va': hex(dest) if dest is not None else '', 'action': action})
        prior_end = last
    if pos != end:
        raise ValueError('misaligned LSDA call-site table')
    return out


# These call-site witnesses identify local unwind destinations only. The action
# numbers are retained raw; no personality or thrown-type semantics are inferred.
LSDA_WITNESSES = [
    ('wrapper_diagnostic', 0x564a6c2, 0x564a6ca, 0),
    ('exchange_locus_decode', 0x3efd86e, 0x3f0da13, 0),
    ('locus_ctx_decode', 0x411364c, 0x4116c5c, 0),
    ('context_height_decode', 0x409d63e, None, 0),
    ('json_root_decode', 0x3ef18fa, 0x3ef19fe, 0),
    ('json_tail_error_position', 0x3ef19a7, 0x3ef19eb, 0),
    ('json_tail_state_drop', 0x3ef19b2, 0x3ef19d6, 0),
    ('json_outer_map_child', 0x404c4d6, 0x404ca0d, 0),
    ('json_saved_state_drop', 0x404c698, 0x404ca5a, 0),
    ('json_outer_sequence_child', 0x404c5d8, None, 0),
    ('binary_outer_map_child', 0x3266b02, 0x3267944, 0),
    ('binary_outer_sequence_child', 0x3266e6b, None, 0),
    ('binary_sequence_extra_drop', 0x32671bb, None, 0),
    ('binary_outer_unwind_box', 0x3267954, 0x326795b, 1),
    ('binary_error_format', 0x422eaf8, 0x422eb4a, 0),
    ('json_error_format', 0x422ec2c, 0x422ec9c, 0),
    ('json_box_drop', 0x3f3be77, 0x3f3be93, 0),
    ('binary_box_drop', 0x300e907, 0x300e923, 0),
    ('binary_sequence_box_drop', 0x30291b7, 0x30291d3, 0),
    ('json_vector_a', 0x3f221b0, 0x3f22df0, 0),
    ('json_vector_b', 0x3f22200, 0x3f22da9, 0),
    ('binary_vector_a', 0x30079c0, 0x3008600, 0),
    ('binary_vector_b', 0x3007a10, 0x30085b9, 0),
]


def selected_unwind_witnesses(unwind, pins=LSDA_WITNESSES):
    out = []
    for name, site, landing, action in pins:
        matches = [row for row in unwind if int(row['start_va'], 16) <= site
                   < int(row['end_va_exclusive'], 16)]
        if len(matches) != 1:
            raise ValueError('missing or ambiguous LSDA witness: ' + name)
        row = matches[0]
        target = hex(landing) if landing is not None else ''
        if row['landing_va'] != target or row['action'] != action:
            raise ValueError('changed LSDA witness: ' + name)
        out.append({'witness': name, 'site_va': hex(site), 'fde_role': row['role'],
                    'range_start_va': row['start_va'], 'range_end_va': row['end_va_exclusive'],
                    'landing_va': target, 'action': row['action']})
    return out


def suffix_step(buf, cursor, mask):
    """Synthetic model of the checked suffix branch for a valid span only."""
    if not isinstance(cursor, int) or not 0 <= cursor <= len(buf):
        raise ValueError('invalid synthetic cursor')
    while cursor < len(buf):
        byte = buf[cursor]
        if byte > 32 or not ((mask >> byte) & 1):
            return 'reject', cursor
        cursor += 1
    return 'accept', cursor


def depth_step(bypass, depth):
    """Synthetic one-level model, not an execution of target instructions."""
    if bypass not in (False, True) or not 0 <= depth <= 255:
        raise ValueError('invalid synthetic depth')
    if bypass:
        return 'bypass', depth
    if depth == 0:
        return 'guard', depth
    depth -= 1
    return ('error' if depth == 0 else 'enter'), depth


def map_key_choice(seen, key, expected):
    """Model one selected key decision, stopping at the unknown-key helper."""
    if type(seen) is not bool or type(key) is not bytes or type(expected) is not bytes:
        raise ValueError('invalid synthetic key input')
    if key != expected:
        return 'other-key-helper'
    return 'duplicate' if seen else 'decode-child'


def binary_sequence_choice(count, child_ok):
    """Model the selected count and child-result decisions only."""
    if type(count) is not int or not 0 <= count <= 0xffffffff or type(child_ok) is not bool:
        raise ValueError('invalid synthetic sequence input')
    if count == 0:
        return 'invalid-length-helper'
    if not child_ok:
        return 'child-error'
    return 'single-child' if count == 1 else 'length-error-and-cleanup'


def decimal_accumulator_step(acc, digit, quotient, remainder):
    """Synthetic selected positive digit branch, not a parser execution."""
    if type(acc) is not int or not 0 <= acc <= MASK64 or type(digit) is not int or not 0 <= digit <= 9:
        raise ValueError('invalid synthetic decimal input')
    if (quotient, remainder) != divmod(MASK64, 10):
        raise ValueError('invalid decimal threshold')
    if acc > quotient or (acc == quotient and digit > remainder):
        return 'fallback', None
    return 'accumulate', acc * 10 + digit


def synthetic_models(mask, field, threshold):
    cases = []
    for value in range(256):
        result, cursor = suffix_step(bytes([value]), 0, mask)
        cases.append({'byte': value, 'result': result, 'cursor': cursor})
    depth = []
    for bypass in (False, True):
        for value in (0, 1, 2, 127, 128, 255):
            result, after = depth_step(bypass, value)
            depth.append({'bypass': bypass, 'before': value, 'result': result, 'after': after})
    keys = []
    for seen in (False, True):
        for key in (field, b'', b'Exchange', b'exchanges'):
            keys.append({'seen': seen, 'key_hex': key.hex(),
                         'decision': map_key_choice(seen, key, field)})
    sequences = []
    for count in (0, 1, 2, 15, 65535, 0xffffffff):
        for child_ok in (False, True):
            sequences.append({'count': count, 'child_ok': child_ok,
                              'decision': binary_sequence_choice(count, child_ok)})
    quotient, remainder = threshold['quotient'], threshold['remainder']
    decimal = []
    for acc, digit in ((0, 0), (0, 9), (quotient - 1, 9), (quotient, 4),
                       (quotient, 5), (quotient, 6), (quotient + 1, 0), (MASK64, 9)):
        decision, value = decimal_accumulator_step(acc, digit, quotient, remainder)
        decimal.append({'accumulator': acc, 'digit': digit, 'decision': decision, 'value': value})
    return {'kind': 'synthetic static models, not captured execution',
            'single_suffix_byte': cases, 'depth_examples': depth,
            'map_key_examples': keys, 'binary_sequence_examples': sequences,
            'decimal_accumulation_examples': decimal}


def compare_old(old, current):
    authenticate(old, OLD_SHA256)
    old_rows, now_rows = sections(old), sections(current)
    # Old values are separately checked, never interpreted as node-115 bytes.
    a = read_va(old, old_rows, 0x2fe307d, 10, True)
    b = read_va(current, now_rows, 0x3ef1922, 10, True)
    if a[:2] != b'\x48\xbe' or b[:2] != b'\x48\xbf':
        raise ValueError('changed cross-release suffix mask instruction')
    old_mask, new_mask = struct.unpack_from('<Q', a, 2)[0], struct.unpack_from('<Q', b, 2)[0]
    old_tag = read_va(old, old_rows, 0x2fe3047, 3, True)
    new_tag = read_va(current, now_rows, 0x3ef1904, 2, True)
    old_size = read_va(old, old_rows, 0x2fe3055, 5, True)
    new_size = read_va(current, now_rows, 0x3ef19b7, 5, True)
    if (old_mask, new_mask, old_tag, new_tag, old_size, new_size) != (
            0x100002600, 0x100002600, b'\x83\x3b\x02', b'\xa8\x01',
            b'\xba\xc8\x1f\x00\x00', b'\xbe\xa8\x27\x00\x00'):
        raise ValueError('changed cross-release witness')
    return {'node94_sha256': OLD_SHA256, 'node115_sha256': TARGET_SHA256,
            'node94': {'mask_va': '0x2fe307d', 'mask': hex(old_mask),
                       'tag_test_va': '0x2fe3047', 'tag_test_bytes': old_tag.hex(),
                       'copy_size_va': '0x2fe3055', 'copy_size_bytes': old_size.hex()},
            'node115': {'mask_va': '0x3ef1922', 'mask': hex(new_mask),
                        'tag_test_va': '0x3ef1904', 'tag_test_bytes': new_tag.hex(),
                        'release_size_va': '0x3ef19b7', 'release_size_bytes': new_size.hex()},
            'conclusion': 'same selected mask; result-test instructions and selected copy/release operands differ; no complete layout equivalence implied'}


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def csv_bytes(rows, fields):
    import io
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fields, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def analyse(data):
    authenticate(data)
    rows = sections(data)
    fdes, records = selected_fdes(data, rows)
    windows = pinned_windows(data, rows)
    edges = selected_edges(data, rows)
    references = selected_references(data, rows)
    tables = selected_tables(data, rows)
    height_flow = trace_height_offsets(data, rows)
    constants = selected_constants(data, rows)
    normalized = normalize_pair(data, rows)
    unwind = []
    for name, _, _ in FDE_PINS:
        for item in lsda_table(data, rows, records[name]):
            item['role'] = name
            unwind.append(item)
    witnesses = selected_unwind_witnesses(unwind)
    field = next(item for item in constants['literals'] if item['role'] == 'exchange')
    models = synthetic_models(int(constants['whitespace_mask'], 16), bytes.fromhex(field['bytes']),
                              constants['decimal_threshold'])
    summary = {'target': 'linux-x86_64-node-115', 'target_sha256': TARGET_SHA256,
               'selected_fdes': len(fdes), 'selected_windows': len(windows),
               'context_windows': sum(row['ownership'] == 'context' for row in windows),
               'selected_transfers': len(edges), 'selected_rip_references': len(references),
               'table_entries': len(tables),
               'lsda_call_site_records': len(unwind), 'selected_unwind_witnesses': len(witnesses),
               'suffix_byte_models': len(models['single_suffix_byte']),
               'depth_models': len(models['depth_examples']),
               'key_models': len(models['map_key_examples']),
               'sequence_models': len(models['binary_sequence_examples']),
               'decimal_accumulation_models': len(models['decimal_accumulation_examples']),
               'height_flow_operands': len(height_flow['instructions']),
               'masked_cleanup_bytes': normalized['masked_bytes'],
               'scope': 'selected static instructions and synthetic models; not component coverage or execution'}
    return {'functions.json': json_bytes(fdes),
            'windows.tsv': csv_bytes(windows, ['role', 'ownership', 'va', 'file_offset', 'length', 'bytes', 'sha256']),
            'edges.tsv': csv_bytes(edges, ['role', 'ownership', 'va', 'file_offset', 'bytes', 'target_va']),
            'references.tsv': csv_bytes(references, ['role', 'ownership', 'va', 'file_offset', 'bytes', 'target_va']),
            'dispatch.tsv': csv_bytes(tables, ['table', 'table_va', 'index', 'entry_va', 'file_offset', 'signed_delta', 'target_va']),
            'constants.json': json_bytes(constants),
            'height-flow.json': json_bytes(height_flow),
            'cleanup-pair.json': json_bytes(normalized),
            'unwind.tsv': csv_bytes(unwind, ['role', 'fde_start', 'entry_offset', 'start_va', 'end_va_exclusive', 'landing_va', 'action']),
            'unwind-witnesses.tsv': csv_bytes(witnesses, ['witness', 'site_va', 'fde_role', 'range_start_va', 'range_end_va', 'landing_va', 'action']),
            'synthetic.json': json_bytes(models),
            'summary.json': json_bytes(summary)}


def generate(data, out):
    files = analyse(data)  # No directory is created before all checks pass.
    out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out / name).write_bytes(content)
    return json.loads(files['summary.json'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--old-elf', type=Path, help='optional authenticated historical cross-check')
    args = parser.parse_args(argv)
    data = args.binary.read_bytes()
    authenticate(data)
    comparison = compare_old(args.old_elf.read_bytes(), data) if args.old_elf else None
    summary = generate(data, args.out)
    print(json.dumps({'summary': summary, 'historical_check': comparison}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('abci_state_read115: ' + type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        sys.exit(1)
