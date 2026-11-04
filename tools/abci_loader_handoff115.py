#!/usr/bin/env python3
"""Reproduce selected #115 ABCI loader handoff evidence from ELF bytes.

This is a static evidence extractor, not an x86 decoder or node emulator.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

BINARY = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Each selected FDE is an unwind range; it is not a complete function census.
FUNCTIONS = [
    ('parent_a', 0x2af0660, 0x2af45e1),
    ('outer_b', 0x2cb6500, 0x2cbbbdf),
    ('parent_b', 0x2cbbbe0, 0x2cbfc3f),
    ('middle', 0x2b41b70, 0x2b43283),
    ('loader_boundary', 0x3c12800, 0x3c12af5),
    ('location_boundary', 0x3c13520, 0x3c13609),
    ('materializer_boundary', 0x3c13610, 0x3c136ed),
    ('result_consumer', 0x2cbfd10, 0x2cc00be),
    ('record_lookup', 0x24b7920, 0x24b8a7f),
    ('next_constructor', 0x5a6bfb0, 0x5a6c8ec),
    ('state_clone_selected', 0x55ea030, 0x55f3d4c),
    ('expanded_state_builder', 0x548ce30, 0x548d8bd),
    ('completed_drop_a', 0x2a973a0, 0x2a97731),
    ('completed_drop_b', 0x2c85400, 0x2c859e0),
]

# These are selected byte windows, checked exactly before any interpretation.
WINDOWS = [
    ('outer_b_init_call', 0x2cb774c, '4088ab48170000c68349170000004c8db328170000488dbc24300700004c89f6488b542408e86a44000083bc243007000002750941c60703e994080000488dbc24d01b0000488db42430070000ba80030000ff15647d8203'),
    ('outer_b_pending', 0x2cb801d, 'b0044c8b7c2420488b4c24508801b003418807b001b104e99b370000'),
    ('outer_b_completed_delivery', 0x2cb7789, '488dbc24d01b0000488db42430070000ba80030000ff15647d8203488bac24b00a0000'),
    ('outer_b_construct_next', 0x2cb7959, '0fb6b3192a0000488dbc2478020000488d942418010000ff15c2fa82030f1045280f298424f0020000c6831c2a0000004989dc488b9b18170000488b4530488b4d10488b552848899c2470010000488984247801000048c78424400100000000000048898c24500100004889942458010000f30f6f4518f30f7f84246001000041c684241d2a000000498db424300b00004c8db42430070000ba700b00004c89f7ff15087b8203410fb694241a2a00004889ef4c89f6ff152bfa82034989c648898424280100004889942430010000'),
    ('parent_a_dispatch', 0x2af06a4, '4989ff0fb64621488d0df63bb1fd486304814801c8ffe00fb643208843220fb613488b7310c6432301488b4b1848898c244801000080fa020f8509010000'),
    ('parent_a_resume_dispatch', 0x2af074c, '4c893c24488dab550500000fb683550500004c8d6328488d0d533bb1fd486304814801c8ffe0'),
    ('parent_a_initialize', 0x2af07eb, '4c893c24488b7b014c8b43084c898424d70200004889bc24d0020000488b36f048ff060f8e6b310000c64323004c8d6328885328488b9424d0020000488bbc24d70200004889532948897b304889733848894b40888354050000488dab55050000c683550500000066480f6ec966480f6ec6660f6cc148c7835f0500000000000048c7835905000000000000888356050000410f100c240f298c24a005000066c783570500000101f30f7f4348'),
    ('parent_a_emit', 0x2af07aa, '4c8bb424d8240000498b76180fb67b22ff15a86c9f034885c0488b3c240f8548300000488db42458210000bab8030000ff1528ed9e03c6432300b001e94d1c0000'),
    ('parent_a_terminal_entry', 0x2af32ef, 'c683e8120000014c8b7360'),
    ('parent_a_terminal_output', 0x2af34f7, '4c89bc2458210000c684246024000000488b44242048898424782400004c89a424802400004c89b424d82400004c89ac24002500004889ac2408250000488b7c2408e8b232fdffe96fd2ffff'),
    ('parent_a_emit_failure', 0x2af3815, '4889842490000000488d8424900000004889842450010000488b05f4c39e034889842458010000488d05798494fd48898424c0200000488d84245001000048898424c8200000488d8424c02000004889842410250000488d059ecdb0ff4889842418250000488dbc24f00500004c8db424102500004c89f6e89ea3f6fff30f6f8424f0050000660f7f842410250000488b84240006000048898424202500004c89b424f0050000488d054daaf6ff48898424f8050000488d3d857f94fd488d1527489503488db424f0050000ff15d1bd9e03e993000000'),
    ('parent_a_construct_call', 0x2af09bd, '0fb68b56050000488b4348f048ff000f8ead2f0000488b5350f048ff020f8e9f2f0000888c2410060000660f6f8424a0050000660f7f8424f005000048898424000600004889942408060000c684241106000000bf58110000ff1564ea9e034885c00f847d2b00004989c6488db424f0050000ba581100004889c7ff15caea9e034c89b36805000048896c24204c8db368050000488dbc24f00500004c89f64c89eae80c110500'),
    ('parent_a_result', 0x2af0a64, '48bd0000000000000080488d450148398424f8050000750eb003488b4c24208801e9a1190000488d8424f80500004c8bbc24f0050000f30f6f000f104810660f7f8424300400000f298c2440040000488b402048898424500400004d8b364c89f7e8d668faffbe581100004c89f731d2ff15c6e99e03c68366050000014c897b60660f6f8424300400000f288c2440040000f30f7f43680f114b78488b84245004000048898388000000488db356050000410fb6879a0b0000888424f00500003883560500000f85db2a0000'),
    ('parent_a_consumers', 0x2af0dda, '4c8d7360488dbbb8000000488d9424c02000004c89f6e82b6b9cff4c896c24184c89642408c68361050000014c8dbb700100004c89ff4c89f6e8f8ee1c00c6836005000001'),
    ('parent_a_lookup_pointer', 0x2af10a2, '488dabb80000004c8d7360'),
    ('parent_a_state_to_context', 0x2af142b, '488b4b60488b5130488b7110488b79280f10411848c78368050000000000004889b3780500004889bb800500000f11838805000048898398050000488993a0050000488dbba80500004c8b2d8de09e03ba90000000488db37001000041ffd50f108424b00500000f108c24c00500000f109424d00500000f109c24e00500000f1183380600000f118b480600000f1193580600000f119b68060000488dbb78060000bab80000004889ee41ffd50f288424700500000f1183700700000f288424300500000f288c24400500000f289424500500000f289c24600500000f119b600700000f1193500700000f118b400700000f1183300700000f288424700300000f288c24800300000f118b900700000f1183800700000f288424900300000f288c24a00300000f1183a00700000f118bb00700000f288424b00300000f288c24c00300000f118bd00700000f1183c00700004c89a3e00700004c89b3e80700000f288424300100000f1183f00700000f108424580300000f118300080000488b842468030000488983100800004c89bb18080000488d93e8120000c683e812000000488db3680500004889942430010000488dab20080000bab80200004889ef4889742468ff1512df9e03'),
    ('parent_a_pending_return', 0x2af242b, '488b042448c70002000000b0038843214881c4e83300005b415c415d415e415f5dc3'),
    ('parent_a_alloc_failure', 0x2af35a2, 'bf08000000be58110000ff15debe9e03e9c8030000'),
    ('parent_a_state_mismatch', 0x2af360b, '4c8d0d9e499503488d9424f005000031ff31c9ff15a43e9f03e956030000'),
    ('parent_b_dispatch', 0x2cbbc1e, '4889d54889f34889bc24980000000fb64621488d0dd9ff94fd486304814801c8ffe00fb643208843220fb60b488b5310c64323014c8b7b184c89bc241802000080f9020f8594010000'),
    ('parent_b_resume_dispatch', 0x2cbbcb2, '4c8dab550500000fb683550500004c8d6328488d0d69ff94fd486304814801c8ffe0'),
    ('parent_b_construct_call', 0x2cbc015, 'c68424c106000000bf58110000ff15583482034885c00f84842b00004989c6488db424a0060000ba581100004889c7ff15be3482034c89b3680500004c8db368050000488dbc24a00600004c89f648896c24204889eae8005be8ff'),
    ('parent_b_pending_return', 0x2cbdafb, '41884500488b84249800000048c70002000000b0038843214881c4083400005b415c415d415e415f5dc3'),
    ('parent_b_state_mismatch', 0x2cbece6, '4c8d0d63f67803488d9424a006000031ff31c9ff15c9878203e9fd020000'),
    ('parent_b_alloc_failure', 0x2cbebb5, 'bf08000000be58110000ff15cb088203e937040000'),
    ('parent_b_terminal_entry', 0x2cbe93f, 'c683e8120000014c8b7360'),
    ('parent_b_terminal_output', 0x2cbeb47, '4c89bc24502d0000c684245830000000488b44242048898424703000004c89a424783000004c89b424d03000004c89ac24f83000004889ac2400310000488b7c2408e862a4feffe99ad9ffff'),
    ('parent_b_emit', 0x2cbc525, '4c8bb424d0300000498b76180fb67b22ff152daf82034885c00f852f290000488db424502d0000bab8030000488bbc2498000000ff15a92f8203c6432300b001e9a6150000'),
    ('parent_b_emit_failure', 0x2cbee73, '48898424a0000000488d8424a00000004889842440010000488b05960d82034889842448010000488d051bce77fd4889842408060000488d8424400100004889842410060000488d8424080600004889842470210000488d05401794ff4889842478210000488dbc24a00600004c8db424702100004c89f6e8b0c8ebfff30f6f8424a0060000660f7f842470210000488b8424b006000048898424802100004c89b424a0060000488d05ffcfebff48898424a8060000488d3d27c977fd488d15c1f47803488db424a0060000ff1573078203e9b7000000'),
    ('parent_b_failure_trap', 0x2cbf001, '0f0b'),
    ('parent_a_failure_trap', 0x2af397f, '0f0b'),
    ('parent_b_result', 0x2cbc070, '48bd0000000000000080488d450148398424a80600007507b003e96c1a0000488d8424a80600004c8bbc24a0060000f30f6f000f104810660f7f8424400400000f298c2450040000488b402048898424600400004d8b364c89f7e83193fcffbe581100004c89f731d2ff15c1338203c68366050000014c897b60660f6f8424400400000f288c2450040000f30f7f43680f114b78488b84246004000048898388000000488db356050000410fb6879a0b0000888424a00600003883560500000f85b12b0000'),
    ('parent_b_consumers', 0x2cbc3d7, '4531c0e8e19dd0ff4c8d7360488dbbb8000000488d9424080600004c89f6e826b57fff4c896c24184c89642408c6836105000001488dbb700100004c89f6e8f6380000c683600500'),
    ('parent_b_state_to_context', 0x2cbcb00, '488b4b60488b5130488b7110488b79280f10411848c78368050000000000004889b3780500004889bb800500000f11838805000048898398050000488993a0050000488dbba80500004c8b2db8298203ba90000000488db37001000041ffd50f108424c80500000f108c24d80500000f109424e80500000f109c24f80500000f1183380600000f118b480600000f1193580600000f119b68060000488dbb78060000bab80000004889ee41ffd50f288424800500000f1183700700000f288424400500000f288c24500500000f289424600500000f289c24700500000f119b600700000f1193500700000f118b400700000f1183300700000f288424800300000f288c24900300000f118b900700000f1183800700000f288424a00300000f288c24b00300000f1183a00700000f118bb00700000f288424c00300000f288c24d00300000f118bd00700000f1183c00700004c89bbe00700004c89a3e80700000f288424000200000f1183f00700000f108424680300000f118300080000488b842478030000488983100800004c89b318080000488d93e8120000c683e812000000488db3680500004889942400020000488dab20080000bab80200004889ef4889742468ff153d288203'),
    ('drop_a_dispatch', 0x2a973a0, '415653500fb647214883f8050f870c0200004889fb488d0d18c0b6fd486304814801c8ffe0'),
    ('drop_a_return', 0x2a975be, '4883c4085b415ec3'),
    ('drop_b_dispatch', 0x2c85400, '41574156530fb647214883f8050f876b0300004889fb488d0dc35b98fd486304814801c8ffe0'),
    ('drop_b_return', 0x2c8577e, '5b415e415fc3'),
    ('middle_entry_dispatch', 0x2b41b70, '554157415641554154534881ecd80a00004989d648897c242049bf0000000000000080488b1e0fb64321488d0dfb2dacfd486304814801c8ffe00fb64320440fb66301488b7308488b4b1048894b2866c743220101488b531848895330f603010f8454010000'),
    ('middle_direct_guard', 0x2b41d2a, '4c8d7b38488973384180fc010f8593010000ff15de599a034883f8010f8567010000488b024889d7ff10e976010000'),
    ('middle_loader_call', 0x2b41eb3, '48895424304939170f82460e00008b0511e39a0385c00f85fc0b00004d8b2f488d7c2470e8d40ab5fe4c89ac24480400000f104424700f29842430040000488b8424800000004889842440040000488dbc24f0070000e8a20ab5fe488d7c2470488db424f0070000e8b0ab0600488dbc2430040000488d742470ff15f5579a034889c5488943404584e4741e49bf00000000000000804c8b742420807b22000f855e0a0000e96d0a0000'),
    ('middle_other_start', 0x2b41f5d, '488d7b48488d35685a9003e883b61300498b37488d7c2470ff15b52f9a03488b842480000000488943700f104424700f1143600f108424880000000f114378488b84249800000048898388000000488b7b50488b7358488b5368488b4b70ff15772f9a0349bf00000000000000804885c00f85c80a00004c89f14c8bb3800000004c8bab88000000488dab900000004c89b3900000004c89ab980000004c8da3e8000000c683e8000000004d85ed0f8809fdffff'),
    ('middle_poll_one', 0x2b420ed, '488d7c24704c89ee4c89f2e8b38c3000807c2470007420488b442408c6000341c604240349ffc74c8b7424204d897e08b003e9e8080000'),
    ('middle_poll_one_results', 0x2b42146, '498b7d00b984000000b8cc000000f0480fb10f7407488b4710ff50204d85ff0f85080a0000488b442408c60001488b442418c600014d85f60f85250a0000'),
    ('middle_poll_two', 0x2b4241a, '4c8d6b50488d7c24704c89ee4c89f2e8c221fbff837c247002750db004488b0c248801e9a8020000'),
    ('middle_poll_three', 0x2b4262c, '4c8dbbf0030000488dbc24300400004c89fe4c89f2e89a84300080bc2430040000007413488b442418c60003b00541880424e987000000'),
    ('middle_sentinel', 0x2b426d4, 'c643470148b8000000000000008048ffc04939c7751d48b8000000000000008048ffc04c8b74242049894608b004e905030000'),
    ('middle_poll_four', 0x2b428be, '488d7c24704c89ee4c89f2e8b2893000807c2470007425c645000341c6070348b8000000000000008048ffc04c8b74242049894608b005e912010000'),
    ('middle_normal_return', 0x2b429b0, '807b22007414488b4330f048ff08750a488d7b30ff1586489a03c6432200807b23007414488b4328f048ff08750a488d7b28ff1538489a03c643230049892e4d897e080f284424700f288c2480000000410f114610410f114e20b0018843214c89f04881c4d80a00005b415c415d415e415f5dc3'),
    ('middle_unwrap_a', 0x2b42a9c, '4889442470488d3d9a2aacfd488d0db94890034c8d05a2559003488d542470be2b000000ff15dacb9903e97b020000'),
    ('middle_unwrap_b', 0x2b42b73, '488dbbc80000004c897c24704c897424784889ac2480000000488d742470e87ae2f4ff4989c6488b442408c60001488b442418c600014c89742470488d3d8d29acfd488d0dac4790034c8d05c5549003488d542470be2b000000ff15cdca9903e96e010000'),
    ('middle_unwrap_c', 0x2b42bd8, '488dbbe00300004c89a424300400004889ac24380400004c89ac2440040000488db42430040000e80ce2f4ff488b4c2418c601014889442470488d3d2a29acfd488d0d494790034c8d0592549003488d542470be2b000000ff156aca9903e90b010000'),
    ('loader_result_and_state', 0x3c1283c, '4889e7488d7424204c89fae8d46385004c8b24244c89e048f7d80f8082010000488b6c24080f104424100f29442460488d35f63e8602488d7c2438e80495ccff4c8b6c2440488b7424484c89242448896c24080f284424600f114424104889e24c89ef4c89f1ff15806d8d024989d44883f8010f8438010000488b7424384885f6740b4c89ef31d2ff15d6cb8c02498b44242848894424584c39f80f85390100004d897c2410498b442418498b74243048ffc048c7c1ffffffff480f45c849894c2418498974242049c78424e8100000000000004989b424f00d00004d8dbc24880d00004c89ffe898905f004c89ffff15d7258d02498b7424304989b424f80e0000498dbc24d80e0000e8b58f5f00498dbc24c0400000ff15b7258d026641c78424283e000000006641c78424e03e0000000041c68424b039000002488b7424204885f6740d488b7c242831d2ff1511cb8c024c89e04883c4785b415c415d415e415f5d'),
    ('loader_rejected_results', 0x3c129de, '488d3d6b3d8602ff1545ce8c02eb444c892424488d3d559abafc488d0d195786024c8d05723d86024889e2be2b000000ff158ccc8c02eb1b4c8d0d733d8602488d742458488d54245031ff31c9ff1537f48c020f0b'),
    ('location_boundary', 0x3c13520, '41574156534883ec504989ce4889d3488d1572328602e8d5ae61004883f80175464989d7498b364885f6740c498b7e0831d2ff1548bf8c024983c6184c89f7e8ccecd1ff488b33b8010000004885f67411488b7b0831d2ff1523bf8c02b8010000004c89faeb460f10030f104b100f294c24100f290424410f1006410f104e10410f1056200f295424400f294c24300f294424204889e6488d4424204889d74889c2ff15d83d8d024889c231c04883c4505b415e415fc3'),
    ('materializer_boundary', 0x3c13610, '4156534881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ec0010000048c70424000000004881ecc80200004889d14889f24889fb4889e74889deff15c55f8d02bfc8420000ff150abe8c024885c074324889e6bac84200004889c74989c6ff1579be8c02bea82700004889df31d2ff1501be8c024c89f04881c4c84200005b415ec3bf08000000bec8420000ff15d3bd8c020f0b'),
    ('next_constructor_prefix', 0x5a6c01b, '89d54989f64889fb488dbc2440120000e88068c2fb488dbc24b0020000488db42440120000e88b82d5ff488dbc2440120000488d9424b00200004889dee8d3dfb7ffbfc8420000ff151834a7004885c00f84250600004989c7488db424401200004c8b2d8534a700bac84200004889c741ffd54c8da42440120000ba700b00004c89e74c89f641ffd54c89ff4c89e6e8810da2ff4989c64c8b7828'),
    ('next_constructor_return', 0x5a6c620, 'c78424401200000100000048c7842448120000010000004c8da42450120000488db424b0020000ba700b00004c89e7ff15b32ea700bf800b0000ff15202ea7004885c074794989c7488db42440120000ba800b00004889c7ff158a2ea7004c89f04c89fa4881c4686400005b415c415d415e415f5dc3'),
    ('next_constructor_failure', 0x5a6c696, 'bf08000000bec8420000ff15ea2da700eb46bf08000000be18000000ff15d82da700eb34bf08000000be380b0000ff15c62da700eb22bf08000000be18000000ff15b42da700eb10bf08000000be800b0000ff15a22da7000f0b'),
    ('clone_arguments', 0x55ea09b, '4989d64989f74989fd4881c6c0070000488dbc2440090000e878bd550048bb0000000000000080498bafa00000004989ec49c1e4054889e848c1e83b0f95c0488d53f84939d40f97c108c1741031ff4c89e6ff15a553ef00e9de8e00004c89ac24b80500004889542430'),
    ('clone_first_vector_guard', 0x55ea0b8, '48bb0000000000000080498bafa00000004989ec49c1e4054889e848c1e83b0f95c0488d53f84939d40f97c108c1741031ff4c89e6ff15a553ef00e9de8e00004c89ac24b805000048895424304d85e47457498b9f980000004c89e7ff156653ef004885c00f84d78d00004989c54885ed742a31c04889e94939c47420488d14030f10020f104a10410f114c0510410f114405004883c02048ffc975db48bb0000000000000080eb0641bd08000000'),
    ('clone_first_vector_alloc_failure', 0x55f2efa, 'bf08000000e9e671ffff'),
    ('clone_failure_trap', 0x55f2fd6, '0f0b'),
    ('clone_input_save', 0x55ea29f, '4c897c24084d8bbfc80000004885db0f84dc0000004889dfff15c351ef0048898424000100004885c00f84368c0000488b44244048898424f00200004885c07414488bbc24000100004c89fe4889daff151452ef004c8b7c2408'),
    ('clone_output_restore', 0x55eeab4, '4d89e775424983bfe80d0000004c8bb424b80500007476498bb7d80d00004885f60f844f410000498b97e00d0000488dbc24f0010000e8f139c3ff48b80000000000000080eb5e498db7d00d0000488dbc24a0220000e871a324004c8bb424b8050000'),
    ('clone_input_restore', 0x55f1946, '4c8b7c2408498db7983e0000488dbc2420040000e8f1f65400'),
    ('clone_forward_one', 0x55f21a1, '410f1087e8100000410f1186e8100000'),
    ('clone_forward_two', 0x55f22bf, '410f1087f8100000410f1186f8100000'),
    ('expanded_state_prefix', 0x548ce9b, '4989f64889fb488b87900b000048894424180fb7af980b0000440fb6a79a0b0000488db7880d0000488dbc24183000004c8b3d36260501ba6003000041ffd7488db308110000488dbc2498330000bad826000041ffd7'),
    ('expanded_state_middle', 0x548d766, '0f1083e81000000f118424783300000f1083784100000f118424086400000f1083884100000f118424186400000f1083284200000f118424b8640000f20f10442408f20f118424c86400000f1083f81000000f11842488330000'),
    ('expanded_state_tail', 0x548d82f, 'bf384e0000ff15461c05014885c0743e488db42420170000ba384e00004889c74989c6ff15b01c0501bec84200004889df31d2ff15381c05014c89f04881c4586500005b415c415d415e415f5dc3bf08000000be384e0000ff15031c05010f0b'),
    ('consumer_inputs', 0x2cbfd10, '554157415641554154534881eca80100004989f64889fb4c8b2e4d8b7d204d8b65184c897c244848c74424280000000048c7442430080000000f57c00f114424384c897c242048c704240000000048c7442408080000000f11442410410fb6859a0b00003c0375178b052ade830385c00f85ab020000488d0503de8303eb090fb6f8ff15505e8203'),
    ('consumer_state_address', 0x2cbfd98, '498d8d880d0000488b104885d2740b0f104008b801000000eb050f57c031c048898424e000000048c78424e80000000000000048899424f00000000f138424f8000000488984240001000048c78424080100000000000048899424100100000f1184241801000048898c2428010000488d7c2450488db424e0000000e877d68501'),
    ('consumer_return', 0x2cbffc4, '488d742450ba900000004889dfff1531f58103488dbc24e0000000e8bc03feff4889d84881c4a80100005b415c415d415e415f5dc3'),
    ('lookup_inputs', 0x24b7920, '554157415641554154534881ece80f00004989d7488b2e8b829000000089442440f30f6f8280000000660f7f442430488b85580e00004889c148f7d94889bc24e8000000712b'),
    ('lookup_compare', 0x24b7a50, '4839c1744a66662e0f1f8400000000004885c90f84780100004889ca4883c170f30f6f4254660f6e4c2440660f6e5264660f74442430660f74d1660fdbc2660fd7f081feffff000074454839c175c1410f104610410f110648898c24780300004889842480030000488b942468030000488b8424700300004839c20f8410010000488d4a7048898c2468030000eb918b5a504883c2548b721089742420f30f6f02660f7f44241041b5014839c10f855dffffffeb9a'),
    ('lookup_selected_key', 0x24b7beb, '8b44242089842410010000660f6f442410660f7f84240001000089842470020000660f7f842460020000895c240c'),
    ('lookup_missing_branch', 0x24b7be1, '41f6c5010f84b90b0000'),
    ('lookup_missing_failure', 0x24b87a4, '488d05258df7034889842460030000488d0596f4feff4889842468030000488d4424304889842470030000488b050a8302044889842478030000488d3d0a91f7fd488d15f48cf703488db42460030000ff15be6e0204e909010000'),
]
FIELDS = [
    ('clone_source_one', 0x55f21a1, '410f1087e8100000', 4, 4),
    ('clone_destination_one', 0x55f21a9, '410f1186e8100000', 4, 4),
    ('clone_source_two', 0x55f22bf, '410f1087f8100000', 4, 4),
    ('clone_destination_two', 0x55f22c7, '410f1186f8100000', 4, 4),
    ('expanded_input_first', 0x548cebc, '488db7880d0000', 3, 4),
    ('expanded_stack_first', 0x548cec3, '488dbc2418300000', 4, 4),
    ('expanded_input_last', 0x548ceda, '488db308110000', 3, 4),
    ('expanded_stack_last', 0x548cee1, '488dbc2498330000', 4, 4),
    ('expanded_input_mid_one', 0x548d766, '0f1083e8100000', 3, 4),
    ('expanded_stack_mid_one', 0x548d76d, '0f11842478330000', 4, 4),
    ('expanded_input_mid_two', 0x548d7b1, '0f1083f8100000', 3, 4),
    ('expanded_stack_mid_two', 0x548d7b8, '0f11842488330000', 4, 4),
    ('expanded_output_base', 0x548d83f, '488db42420170000', 4, 4),
    ('context_state_source_30', 0x2af142f, '488b5130', 3, 1),
    ('context_state_source_10', 0x2af1433, '488b7110', 3, 1),
    ('context_state_source_28', 0x2af1437, '488b7928', 3, 1),
    ('context_state_source_18', 0x2af143b, '0f104118', 3, 1),
    ('context_copy_state_10', 0x2af144a, '4889b378050000', 3, 4),
    ('context_copy_state_28', 0x2af1451, '4889bb80050000', 3, 4),
    ('context_copy_state_18_20', 0x2af1458, '0f118388050000', 3, 4),
    ('context_copy_state_30', 0x2af1466, '488993a0050000', 3, 4),
    ('context_derived_destination', 0x2af146d, '488dbba8050000', 3, 4),
    ('context_lookup_destination', 0x2af14c6, '488dbb78060000', 3, 4),
    ('context_record_source', 0x2af15cd, '488db368050000', 3, 4),
    ('context_record_destination', 0x2af15dc, '488dab20080000', 3, 4),
    ('request_word', 0x3c12822, '4c8b7b18', 3, 1),
    ('state_match_word', 0x3c128ca, '498b442428', 4, 1),
    ('state_write_request', 0x3c128dd, '4d897c2410', 4, 1),
    ('state_counter_read', 0x3c128e2, '498b442418', 4, 1),
    ('state_next_source', 0x3c128e7, '498b742430', 4, 1),
    ('state_counter_write', 0x3c128fa, '49894c2418', 4, 1),
    ('state_next_write', 0x3c128ff, '4989742420', 4, 1),
    ('state_zero_word', 0x3c12904, '49c78424e810000000000000', 4, 4),
    ('state_copy_one', 0x3c12910, '4989b424f00d0000', 4, 4),
    ('state_helper_one', 0x3c12918, '4d8dbc24880d0000', 4, 4),
    ('state_next_reload', 0x3c12931, '498b742430', 4, 1),
    ('state_copy_two', 0x3c12936, '4989b424f80e0000', 4, 4),
    ('state_helper_two', 0x3c1293e, '498dbc24d80e0000', 4, 4),
    ('state_helper_three', 0x3c1294b, '498dbc24c0400000', 4, 4),
    ('state_zero_short_one', 0x3c12959, '6641c78424283e00000000', 5, 4),
    ('state_zero_short_two', 0x3c12964, '6641c78424e03e00000000', 5, 4),
    ('state_set_byte', 0x3c1296f, '41c68424b039000002', 4, 4),
    ('consumer_state_word_20', 0x2cbfd2a, '4d8b7d20', 3, 1),
    ('consumer_state_word_18', 0x2cbfd2e, '4d8b6518', 3, 1),
    ('consumer_state_mode', 0x2cbfd6c, '410fb6859a0b0000', 4, 4),
    ('consumer_state_subobject', 0x2cbfd98, '498d8d880d0000', 3, 4),
    ('lookup_state_sequence', 0x24b794f, '488b85580e0000', 3, 4),
    ('lookup_key_low', 0x24b7941, 'f30f6f8280000000', 4, 4),
    ('lookup_key_high', 0x24b7937, '8b8290000000', 2, 4),
    ('lookup_record_stride', 0x24b7a6c, '4883c170', 3, 1),
    ('lookup_record_key_low', 0x24b7a70, 'f30f6f4254', 4, 1),
    ('lookup_record_key_high', 0x24b7a7b, '660f6e5264', 4, 1),
]

# Selected branch/call sites: expected targets are checked, never assumed by the decoder.
EDGES = [
    ('outer_b_to_parent', 0x2cb7771, 0x2cbbbe0),
    ('outer_b_completed', 0x2cb777e, 0x2cb7789),
    ('outer_b_pending', 0x2cb7784, 0x2cb801d),
    ('outer_b_prefix_copy', 0x2cb779e, 0x64df508),
    ('outer_b_next_constructor', 0x2cb7a0f, 0x64e7440),
    ('parent_a_alternate_input', 0x2af06dc, 0x2af07eb),
    ('parent_a_check_boundary', 0x2af07ba, 0x64e7468),
    ('parent_a_check_failure', 0x2af07c7, 0x2af3815),
    ('parent_a_version_format', 0x2af388d, 0x2a5dc30),
    ('parent_a_version_raise', 0x2af38e1, 0x64df6b8),
    ('parent_a_version_trap', 0x2af38e7, 0x2af397f),
    ('parent_a_emit_copy', 0x2af07da, 0x64df508),
    ('parent_a_emit_return', 0x2af07e6, 0x2af2438),
    ('parent_a_terminal_jump', 0x2af353e, 0x2af07b2),
    ('parent_a_refcount_a', 0x2af09cc, 0x2af397f),
    ('parent_a_refcount_b', 0x2af09da, 0x2af397f),
    ('parent_a_alloc', 0x2af0a16, 0x64df480),
    ('parent_a_alloc_failure', 0x2af0a1f, 0x2af35a2),
    ('parent_a_alloc_failure_call', 0x2af35ac, 0x64df490),
    ('parent_a_alloc_failure_trap', 0x2af35b2, 0x2af397f),
    ('parent_a_copy', 0x2af0a38, 0x64df508),
    ('parent_a_to_middle', 0x2af0a5f, 0x2b41b70),
    ('parent_a_completed', 0x2af0a7a, 0x2af0a8a),
    ('parent_a_pending', 0x2af0a85, 0x2af242b),
    ('parent_a_drop', 0x2af0ac5, 0x2a973a0),
    ('parent_a_release', 0x2af0ad4, 0x64df4a0),
    ('parent_a_mismatch', 0x2af0b2a, 0x2af360b),
    ('parent_a_lookup', 0x2af0df0, 0x24b7920),
    ('parent_a_consumer', 0x2af0e13, 0x2cbfd10),
    ('parent_a_context_copy', 0x2af15f0, 0x64df508),
    ('parent_b_check_boundary', 0x2cbc535, 0x64e7468),
    ('parent_b_alternate_input', 0x2cbbc61, 0x2cbbdfb),
    ('parent_b_check_failure', 0x2cbc53e, 0x2cbee73),
    ('parent_b_version_format', 0x2cbeeeb, 0x2b7b7a0),
    ('parent_b_version_raise', 0x2cbef3f, 0x64df6b8),
    ('parent_b_version_trap', 0x2cbef45, 0x2cbf001),
    ('parent_b_emit_copy', 0x2cbc559, 0x64df508),
    ('parent_b_emit_return', 0x2cbc565, 0x2cbdb10),
    ('parent_b_terminal_jump', 0x2cbeb8e, 0x2cbc52d),
    ('parent_b_alloc', 0x2cbc022, 0x64df480),
    ('parent_b_alloc_failure', 0x2cbc02b, 0x2cbebb5),
    ('parent_b_alloc_failure_call', 0x2cbebbf, 0x64df490),
    ('parent_b_alloc_failure_trap', 0x2cbebc5, 0x2cbf001),
    ('parent_b_copy', 0x2cbc044, 0x64df508),
    ('parent_b_to_middle', 0x2cbc06b, 0x2b41b70),
    ('parent_b_completed', 0x2cbc086, 0x2cbc08f),
    ('parent_b_drop', 0x2cbc0ca, 0x2c85400),
    ('parent_b_release', 0x2cbc0d9, 0x64df4a0),
    ('parent_b_mismatch', 0x2cbc12f, 0x2cbece6),
    ('drop_a_outside_guard', 0x2a973ac, 0x2a975be),
    ('drop_b_outside_guard', 0x2c8540d, 0x2c8577e),
    ('parent_b_pending', 0x2cbc08a, 0x2cbdafb),
    ('parent_b_lookup', 0x2cbc3f5, 0x24b7920),
    ('parent_b_consumer', 0x2cbc415, 0x2cbfd10),
    ('parent_b_context_copy', 0x2cbccc5, 0x64df508),
    ('middle_even_input', 0x2b41bd0, 0x2b41d2a),
    ('middle_direct_input', 0x2b41d36, 0x2b41ecf),
    ('middle_optional_check', 0x2b41d3c, 0x64e7720),
    ('middle_optional_result', 0x2b41d46, 0x2b41eb3),
    ('middle_range_failure', 0x2b41ebb, 0x2b42d07),
    ('middle_loader_boundary', 0x2b41f2d, 0x64e7728),
    ('middle_other_input', 0x2b41f3d, 0x2b41f5d),
    ('middle_cleanup_needed', 0x2b41f52, 0x2b429b6),
    ('middle_direct_delivery', 0x2b41f58, 0x2b429ca),
    ('middle_first_unwrap', 0x2b41fce, 0x2b42a9c),
    ('middle_poll_one', 0x2b420f8, 0x2e4adb0),
    ('middle_poll_one_completed', 0x2b42102, 0x2b42124),
    ('middle_poll_one_return', 0x2b4211f, 0x2b42a0c),
    ('middle_poll_one_error_a', 0x2b42165, 0x2b42b73),
    ('middle_poll_one_error_b', 0x2b4217e, 0x2b42ba9),
    ('middle_poll_two', 0x2b42429, 0x2af45f0),
    ('middle_poll_two_completed', 0x2b42433, 0x2b42442),
    ('middle_poll_two_pending', 0x2b4243d, 0x2b426ea),
    ('middle_poll_three', 0x2b42641, 0x2e4aae0),
    ('middle_poll_three_completed', 0x2b4264e, 0x2b42663),
    ('middle_poll_three_pending', 0x2b4265e, 0x2b426ea),
    ('middle_poll_three_error', 0x2b4269d, 0x2b42bd8),
    ('middle_nested_completed', 0x2b426e8, 0x2b42707),
    ('middle_nested_pending', 0x2b42702, 0x2b42a0c),
    ('middle_poll_four', 0x2b428c9, 0x2e4b280),
    ('middle_poll_four_completed', 0x2b428d3, 0x2b428fa),
    ('middle_poll_four_pending', 0x2b428f5, 0x2b42a0c),
    ('middle_cleanup_one', 0x2b429b4, 0x2b429ca),
    ('middle_cleanup_two', 0x2b429d2, 0x2b429e8),
    ('loader_overflow', 0x3c12856, 0x3c129de),
    ('loader_location_boundary', 0x3c128a2, 0x64e9628),
    ('loader_error_result', 0x3c128af, 0x3c129ed),
    ('loader_height_mismatch', 0x3c128d7, 0x3c12a16),
    ('loader_cleanup_one', 0x3c12923, 0x420b9c0),
    ('loader_cleanup_two', 0x3c1292b, 0x64e4f08),
    ('loader_cleanup_three', 0x3c12946, 0x420b900),
    ('loader_cleanup_four', 0x3c12953, 0x64e4f10),
    ('location_helper', 0x3c13536, 0x422e410),
    ('location_nonerror', 0x3c1353f, 0x3c13587),
    ('location_materializer_boundary', 0x3c135c2, 0x64e73a0),
    ('materializer_construct', 0x3c13665, 0x64e9630),
    ('materializer_alloc', 0x3c13670, 0x64df480),
    ('materializer_alloc_failure', 0x3c13679, 0x3c136ad),
    ('materializer_copy', 0x3c13689, 0x64df508),
    ('consumer_mode_other', 0x2cbfd76, 0x2cbfd8f),
    ('consumer_copy', 0x2cbffd1, 0x64df508),
    ('lookup_key_match', 0x24b7a98, 0x24b7adf),
    ('lookup_key_missing', 0x24b7be5, 0x24b87a4),
    ('next_object_builder', 0x5a6c058, 0x55ea030),
    ('clone_size_valid', 0x55ea0e6, 0x55ea0f8),
    ('clone_size_failure_call', 0x55ea0ed, 0x64df498),
    ('clone_size_failure_trap', 0x55ea0f3, 0x55f2fd6),
    ('clone_empty_allocation', 0x55ea108, 0x55ea161),
    ('clone_vector_alloc', 0x55ea114, 0x64df480),
    ('clone_vector_alloc_failure', 0x55ea11d, 0x55f2efa),
    ('clone_vector_failure_join', 0x55f2eff, 0x55ea0ea),
    ('clone_vector_copy_loop', 0x55ea153, 0x55ea130),
    ('clone_vector_copy_done', 0x55ea15f, 0x55ea167),
    ('next_object_alloc', 0x5a6c062, 0x64df480),
    ('next_object_alloc_failure', 0x5a6c06b, 0x5a6c696),
    ('next_to_expanded', 0x5a6c0aa, 0x548ce30),
    ('next_object_alloc_failure_call', 0x5a6c6a0, 0x64df490),
    ('expanded_object_alloc', 0x548d834, 0x64df480),
    ('expanded_object_alloc_failure', 0x548d83d, 0x548d87d),
    ('expanded_object_copy', 0x548d852, 0x64df508),
    ('expanded_input_release', 0x548d862, 0x64df4a0),
    ('expanded_alloc_failure_call', 0x548d887, 0x64df490),
]

# Relocation targets are boundary anchors when their role is prefixed 'boundary'.
RELOCATIONS = [
    ('alloc', 0x64df480, 8, 0, 0x6355830),
    ('alloc_failure', 0x64df490, 8, 0, 0x141e251),
    ('clone_size_failure', 0x64df498, 8, 0, 0x141e264),
    ('release', 0x64df4a0, 8, 0, 0x635de30),
    ('copy', 0x64df508, 6, 7, 0),
    ('boundary_loader', 0x64e7728, 8, 0, 0x3c12800),
    ('boundary_location', 0x64e9628, 8, 0, 0x3c13520),
    ('boundary_materializer', 0x64e73a0, 8, 0, 0x3c13610),
    ('materializer_constructor', 0x64e9630, 8, 0, 0x3c2e860),
    ('optional_check', 0x64e7720, 8, 0, 0x595b1a0),
    ('reset_helper_one', 0x64e4f08, 8, 0, 0x3c374e0),
    ('reset_helper_two', 0x64e4f10, 8, 0, 0x3bec320),
    ('next_constructor', 0x64e7440, 8, 0, 0x5a6bfb0),
]

# Values and targets are read from the selected entries, then checked against pins.
TABLES = [
    ('parent_initial', 0x6042a8, [0x2af06bb, 0x2af37fb, 0x2af3808, 0x2af074c, 0x2af071d]),
    ('parent_nested', 0x6042bc, [0x2af0772, 0x2af38ec, 0x2af38fe, 0x2af0a45, 0x2af0ea1]),
    ('parent_b_initial', 0x60bc10, [0x2cbbc40, 0x2cbee02, 0x2cbedf5, 0x2cbbcb2, 0x2cbbce5]),
    ('parent_b_nested', 0x60bc34, [0x2cbbcd4, 0x2cbef6e, 0x2cbef80, 0x2cbc051, 0x2cbc579]),
    ('middle_initial', 0x60499c, [0x2b41baa, 0x2b42b1e, 0x2b42b11, 0x2b41cdb, 0x2b41bfa, 0x2b41c8f]),
    ('middle_nested', 0x6049d4, [0x2b41c1b, 0x2b42c4d, 0x2b42c3b, 0x2b41c51, 0x2b41e60, 0x2b41e69]),
    ('drop_a', 0x6033d4, [0x2a973c5, 0x2a975be, 0x2a975be, 0x2a97409, 0x2a973fb, 0x2a97447]),
    ('drop_b', 0x60afe0, [0x2c85426, 0x2c8577e, 0x2c8577e, 0x2c854ad, 0x2c8545a, 0x2c854f6]),
]

LOCATIONS = [
    ('state_overflow', 0x6476750, b'l1/src/abci/state.rs', 76, 77),
    ('state_error_result', 0x6476778, b'l1/src/abci/state.rs', 79, 100),
    ('state_mismatch', 0x6476790, b'l1/src/abci/state.rs', 82, 21),
    ('state_location_boundary', 0x64767a8, b'l1/src/abci/state.rs', 123, 37),
    ('startup_mismatch', 0x6447fb0, b'node/src/startup.rs', 92, 13),
    ('startup_parse_failure', 0x6447fe0, b'node/src/startup.rs', 101, 43),
    ('startup_unwrap_one', 0x6448058, b'node/src/startup.rs', 238, 79),
    ('startup_unwrap_two', 0x6448088, b'node/src/startup.rs', 240, 64),
    ('startup_unwrap_three', 0x64480b8, b'node/src/startup.rs', 337, 49),
    ('startup_version_failure_a', 0x6448100, b'node/src/startup.rs', 60, 21),
    ('startup_version_failure_b', 0x644e3f8, b'node/src/startup.rs', 60, 21),
    ('startup_mismatch_b', 0x644e350, b'node/src/startup.rs', 92, 13),
]

REFERENCES = [
    ('state_overflow', 0x3c129de, 0x6476750),
    ('state_error_result', 0x3c129ff, 0x6476778),
    ('state_mismatch', 0x3c12a16, 0x6476790),
    ('state_location_boundary', 0x3c1352f, 0x64767a8),
    ('startup_mismatch', 0x2af360b, 0x6447fb0),
    ('startup_parse_failure', 0x2af3693, 0x6447fe0),
    ('startup_unwrap_one', 0x2b42aaf, 0x6448058),
    ('startup_unwrap_two', 0x2b42bbc, 0x6448088),
    ('startup_unwrap_three', 0x2b42c1f, 0x64480b8),
    ('startup_version_failure_a', 0x2af38d2, 0x6448100),
    ('startup_version_failure_b', 0x2cbef30, 0x644e3f8),
    ('version_descriptor_a', 0x2af383c, 0x43bcbc),
    ('version_descriptor_b', 0x2cbee9a, 0x43bcbc),
    ('startup_mismatch_b', 0x2cbece6, 0x644e350),
]

LITERALS = [
    ('unwrap', 0x605542, b'called `Result::unwrap()` on an `Err` value'),
    ('async_touch', 0x6054ff, b'async_touch'),
    ('async_touch_alert_on_fail', 0x60550a, b'async_touch_alert_on_fail'),
    ('client_block_or_tx', 0x605f60, b'client block or tx'),
    ('execution_state', 0x605f72, b'execution state'),
    ('version_failure', 0x43bcbd, b'failed to validate hardfork version: '),
]


# The immediate byte counts and call encodings are validated independently.
COPY_SITES = [
    ('a_consumer_into_context', 0x2af147b, 0x2af1487, 0x2af1474, 0x90),
    ('a_lookup_into_context', 0x2af14cd, 0x2af14d5, 0x2af1474, 0xb8),
    ('a_context_forward', 0x2af15e3, 0x2af15f0, None, 0x2b8),
    ('a_result_emit', 0x2af07d5, 0x2af07da, None, 0x3b8),
    ('b_consumer_into_context', 0x2cbcb50, 0x2cbcb5c, 0x2cbcb49, 0x90),
    ('b_lookup_into_context', 0x2cbcba2, 0x2cbcbaa, 0x2cbcb49, 0xb8),
    ('b_context_forward', 0x2cbccb8, 0x2cbccc5, None, 0x2b8),
    ('b_result_emit', 0x2cbc54c, 0x2cbc559, None, 0x3b8),
    ('b_outer_prefix', 0x2cb7799, 0x2cb779e, None, 0x380),
    ('constructor_heap_input', 0x5a6c083, 0x5a6c08b, 0x5a6c07c, 0x42c8),
    ('constructor_argument', 0x5a6c096, 0x5a6c0a1, 0x5a6c07c, 0xb70),
    ('expanded_first_region', 0x548ced2, 0x548ced7, 0x548cecb, 0x360),
    ('expanded_last_region', 0x548cee9, 0x548ceee, 0x548cecb, 0x26d8),
    ('expanded_final_object', 0x548d847, 0x548d852, None, 0x4e38),
]

# Linked stack offsets from the final parent result to the upper caller.
STITCH = [
    ('a_parent', 0x2af07cd, b'\x48\x8d\xb4\x24', 0x2af351c, b'\x4c\x89\xb4\x24', 'a_result_emit'),
    ('b_parent', 0x2cbc544, b'\x48\x8d\xb4\x24', 0x2cbeb6c, b'\x4c\x89\xb4\x24', 'b_result_emit'),
    ('b_outer', 0x2cb7761, b'\x48\x8d\xbc\x24', 0x2cb77a4, b'\x48\x8b\xac\x24', 'b_outer_prefix'),
]


PROJECTION = [
    ('state_word_10', 'context_state_source_10', 'context_copy_state_10'),
    ('state_word_28', 'context_state_source_28', 'context_copy_state_28'),
    ('state_words_18_20', 'context_state_source_18', 'context_copy_state_18_20'),
    ('state_word_30', 'context_state_source_30', 'context_copy_state_30'),
]


def authenticate(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('node #115 SHA-256 mismatch')
    return actual


def mapping(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA range')
    if va + size > 1 << 64:
        raise ValueError('VA range overflow')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA range is not uniquely file-backed')
    s = matches[0]
    return s, s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    _, off = mapping(secs, va, size)
    out = data[off:off + size]
    if len(out) != size:
        raise ValueError('truncated file mapping')
    return bytes(out)


def unique_section(secs, name):
    found = [s for s in secs if s['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicate or NOBITS section: ' + name)
    return found[0]


def selected_fdes(data, secs):
    index_secs, index = unwind_index(data)
    if index_secs != secs:
        raise ValueError('section mismatch between readers')
    _, records = eh_frame_records(data, secs)
    by_fde = {f['fde']: f for f in records}
    by_start = {f['start']: f for f in records}
    by_header = {row['start']: row for row in index}
    if len(by_fde) != len(records) or len(by_start) != len(records):
        raise ValueError('duplicate FDE address or start')
    out = []
    for label, start, end in FUNCTIONS:
        f = by_start.get(start)
        h = by_header.get(start)
        if f is None or h is None or f['end'] != end or h['fde'] != f['fde']:
            raise ValueError('selected FDE mismatch: ' + label)
        sec, off = mapping(secs, start, end - start)
        if sec['name'] != '.text' or not sec['flags'] & 4:
            raise ValueError('FDE not in executable .text')
        raw = read_va(data, secs, start, end - start)
        out.append([label, hex(start), hex(end), hex(off), str(len(raw)),
                    hex(f['fde']), hex(f['cie']), hex(f['lsda']) if f['lsda'] else '',
                    hashlib.sha256(raw).hexdigest()])
    return out


def verify_window(data, secs, window):
    label, address, expected = window
    actual = read_va(data, secs, address, len(bytes.fromhex(expected)))
    if actual.hex() != expected:
        raise ValueError('selected bytes changed: ' + label)
    return actual


def windows_table(data, secs):
    out = []
    for entry in WINDOWS:
        label, va, _ = entry
        raw = verify_window(data, secs, entry)
        _, off = mapping(secs, va, len(raw))
        out.append([label, hex(va), hex(off), str(len(raw)), raw.hex()])
    return out


def fields_table(data, secs):
    out = []
    for label, va, expected, offset, width in FIELDS:
        raw = verify_window(data, secs, (label, va, expected))
        if width not in (1, 4) or offset < 0 or offset + width > len(raw):
            raise ValueError('invalid field operand')
        disp = int.from_bytes(raw[offset:offset + width], 'little', signed=False)
        _, off = mapping(secs, va, len(raw))
        out.append([label, hex(va), hex(off), raw.hex(), hex(disp)])
    return out


def decode_edge(data, secs, va):
    first = read_va(data, secs, va, 1)[0]
    if first in (0xe8, 0xe9):
        raw = read_va(data, secs, va, 5)
        kind = 'call_rel32' if first == 0xe8 else 'jmp_rel32'
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif first == 0xeb or 0x70 <= first <= 0x7f:
        raw = read_va(data, secs, va, 2)
        kind = 'jmp_rel8' if first == 0xeb else 'jcc_rel8'
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif first == 0x0f:
        raw = read_va(data, secs, va, 6)
        if not 0x80 <= raw[1] <= 0x8f:
            raise ValueError('unsupported near branch opcode')
        kind = 'jcc_rel32'
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif first == 0xff:
        raw = read_va(data, secs, va, 6)
        if raw[1] != 0x15:
            raise ValueError('unsupported indirect-call opcode')
        kind = 'call_rip_slot'
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported selected transfer opcode')
    return kind, raw, va + len(raw) + disp


def edges_table(data, secs):
    out = []
    for label, va, expected in EDGES:
        kind, raw, target = decode_edge(data, secs, va)
        if target != expected:
            raise ValueError('selected transfer target changed: ' + label)
        _, off = mapping(secs, va, len(raw))
        out.append([label, hex(va), hex(off), kind, raw.hex(), hex(target)])
    return out


def selected_relocations(data, secs):
    sec = unique_section(secs, '.rela.dyn')
    if sec['size'] % 24:
        raise ValueError('truncated relocation table')
    wanted = {x[1] for x in RELOCATIONS} | {x[1] for x in LOCATIONS}
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in wanted:
            if slot in found:
                raise ValueError('duplicate selected relocation')
            found[slot] = (off, info & 0xffffffff, info >> 32, addend)
    if set(found) != wanted:
        raise ValueError('missing selected relocation')
    rows = []
    for label, slot, rtype, sym, addend in RELOCATIONS:
        off, actual_type, actual_sym, actual_addend = found[slot]
        if (actual_type, actual_sym, actual_addend) != (rtype, sym, addend):
            raise ValueError('relocation changed: ' + label)
        rows.append([label, hex(slot), hex(off), str(actual_type), str(actual_sym), hex(actual_addend)])
    dynsym = unique_section(secs, '.dynsym')
    dynstr = unique_section(secs, '.dynstr')
    entry = dynsym['offset'] + 7 * 24
    if entry + 24 > dynsym['offset'] + dynsym['size']:
        raise ValueError('symbol index outside dynsym')
    name_off = struct.unpack_from('<I', data, entry)[0]
    if name_off >= dynstr['size']:
        raise ValueError('symbol name outside dynstr')
    start = dynstr['offset'] + name_off
    limit = dynstr['offset'] + dynstr['size']
    end = data.find(b'\0', start, limit)
    if end < 0 or bytes(data[start:end]) != b'memcpy':
        raise ValueError('selected dynamic symbol changed')
    return found, rows


def locations_table(data, secs, relocations):
    rows = []
    for label, va, path, expected_line, expected_col in LOCATIONS:
        reloc_off, typ, sym, string_va = relocations[va]
        if typ != 8 or sym != 0:
            raise ValueError('invalid Location relocation: ' + label)
        _, file_off = mapping(secs, va, 24)
        length, line, col = struct.unpack('<QII', read_va(data, secs, va + 8, 16))
        if length != len(path) or (line, col) != (expected_line, expected_col):
            raise ValueError('Location coordinates changed: ' + label)
        actual = read_va(data, secs, string_va, length)
        if actual != path:
            raise ValueError('Location path changed: ' + label)
        rows.append([label, hex(va), hex(file_off), hex(reloc_off), hex(string_va),
                     str(length), str(line), str(col), actual.decode('ascii')])
    return rows


def references_table(data, secs):
    rows = []
    for label, va, expected in REFERENCES:
        raw = read_va(data, secs, va, 7)
        if raw[0] & 0xf0 != 0x40 or raw[1] != 0x8d or raw[2] & 0xc7 != 0x05:
            raise ValueError('unsupported RIP-relative LEA: ' + label)
        target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != expected:
            raise ValueError('Location reference changed: ' + label)
        _, off = mapping(secs, va, len(raw))
        rows.append([label, hex(va), hex(off), raw.hex(), hex(target)])
    return rows


def tables_table(data, secs):
    rows = []
    for label, base, targets in TABLES:
        for index, expected in enumerate(targets):
            slot = base + 4 * index
            raw = read_va(data, secs, slot, 4)
            target = base + struct.unpack('<i', raw)[0]
            if target != expected:
                raise ValueError('jump-table entry changed: ' + label)
            sec, _ = mapping(secs, target, 1)
            if sec['name'] != '.text' or not sec['flags'] & 4:
                raise ValueError('jump-table target is not executable')
            _, off = mapping(secs, slot, 4)
            rows.append([label, hex(base), str(index), hex(slot), hex(off), raw.hex(), hex(target)])
    return rows


def literals_table(data, secs):
    rows = []
    for label, va, expected in LITERALS:
        raw = read_va(data, secs, va, len(expected))
        if raw != expected:
            raise ValueError('literal changed: ' + label)
        if label == 'version_failure':
            framing = read_va(data, secs, va - 1, len(raw) + 3)
            if framing != bytes([len(raw)]) + raw + b'\xc0\x00':
                raise ValueError('version descriptor changed')
        _, off = mapping(secs, va, len(raw))
        rows.append([label, hex(va), hex(off), str(len(raw)), raw.hex(), raw.decode('ascii')])
    return rows


def copies_table(data, secs):
    rows = []
    for label, imm_va, call_va, load_va, expected_count in COPY_SITES:
        imm = read_va(data, secs, imm_va, 5)
        if imm[0] != 0xba:
            raise ValueError('copy length opcode changed: ' + label)
        length = struct.unpack_from('<I', imm, 1)[0]
        if length != expected_count:
            raise ValueError('copy length changed: ' + label)
        if load_va is None:
            kind, call, slot = decode_edge(data, secs, call_va)
            if kind != 'call_rip_slot':
                raise ValueError('copy direct slot call changed')
            load = b''
        else:
            load = read_va(data, secs, load_va, 7)
            registers = {b'\x4c\x8b\x2d': b'\x41\xff\xd5',
                         b'\x4c\x8b\x3d': b'\x41\xff\xd7'}
            expected_call = registers.get(load[:3])
            if expected_call is None:
                raise ValueError('copy function load changed')
            slot = load_va + len(load) + struct.unpack_from('<i', load, 3)[0]
            call = read_va(data, secs, call_va, 3)
            if call != expected_call:
                raise ValueError('copy register call changed')
        if slot != 0x64df508:
            raise ValueError('copy slot changed: ' + label)
        _, off = mapping(secs, imm_va, len(imm))
        rows.append([label, hex(imm_va), hex(off), imm.hex(), str(length),
                     hex(load_va) if load_va is not None else '', load.hex(),
                     hex(call_va), call.hex(), hex(slot)])
    return rows


def projection_table(fields, copies):
    fields = {row[0]: row for row in fields}
    copies = {row[0]: row for row in copies}
    base = int(fields['context_record_source'][4], 16)
    copied = int(copies['a_context_forward'][4])
    rows = []
    for label, source, destination in PROJECTION:
        src, dst = fields[source], fields[destination]
        source_offset, destination_offset = int(src[4], 16), int(dst[4], 16)
        insn = bytes.fromhex(dst[3])
        if insn.startswith(b'\x48\x89'):
            width = 8
        elif insn.startswith(b'\x0f\x11'):
            width = 16
        else:
            raise ValueError('unsupported projection store')
        relative = destination_offset - base
        if relative < 0 or relative + width > copied:
            raise ValueError('projection outside copied record')
        rows.append([label, src[1], hex(source_offset), dst[1], hex(destination_offset),
                     hex(relative), str(width)])
    return rows


def stitch_table(data, secs, copies):
    sizes = {r[0]: int(r[4]) for r in copies}
    rows = []
    for label, base_va, base_op, slot_va, slot_op, copy_name in STITCH:
        base_raw = read_va(data, secs, base_va, 8)
        slot_raw = read_va(data, secs, slot_va, 8)
        if base_raw[:4] != base_op or slot_raw[:4] != slot_op:
            raise ValueError('result stack operand changed: ' + label)
        base = struct.unpack_from('<I', base_raw, 4)[0]
        slot = struct.unpack_from('<I', slot_raw, 4)[0]
        relative = slot - base
        if relative != 0x380:
            raise ValueError('result pointer offset changed: ' + label)
        length = sizes[copy_name]
        if length != (0x380 if label.endswith('outer') else 0x3b8):
            raise ValueError('result copy length changed: ' + label)
        rows.append([label, hex(base_va), base_raw.hex(), hex(base), hex(slot_va),
                     slot_raw.hex(), hex(slot), hex(relative), str(length)])
    return rows


def expanded_projection_table(fields, copies):
    fields = {row[0]: row for row in fields}
    lengths = {row[0]: int(row[4]) for row in copies}
    base = int(fields['expanded_output_base'][4], 16)
    specs = [
        ('first', 'expanded_input_first', 'expanded_stack_first', lengths['expanded_first_region']),
        ('middle_one', 'expanded_input_mid_one', 'expanded_stack_mid_one', 16),
        ('middle_two', 'expanded_input_mid_two', 'expanded_stack_mid_two', 16),
        ('last', 'expanded_input_last', 'expanded_stack_last', lengths['expanded_last_region']),
    ]
    total = lengths['expanded_final_object']
    rows = []
    for label, src, dst, length in specs:
        source, destination = int(fields[src][4], 16), int(fields[dst][4], 16)
        relative = destination - base
        if relative < 0 or relative + length > total:
            raise ValueError('expanded projection outside output')
        rows.append([label, fields[src][1], hex(source), fields[dst][1],
                     hex(destination), hex(relative), str(length)])
    for one, two in zip(rows, rows[1:]):
        if int(one[2], 16) + int(one[6]) != int(two[2], 16):
            raise ValueError('expanded source ranges are not contiguous')
        if int(one[5], 16) + int(one[6]) != int(two[5], 16):
            raise ValueError('expanded destination ranges are not contiguous')
    return rows


def forwarding_table(fields, expanded):
    fields = {row[0]: row for row in fields}
    expanded = {row[0]: row for row in expanded}
    rows = []
    for suffix, projection in [('one', 'middle_one'), ('two', 'middle_two')]:
        src, dst = fields['clone_source_' + suffix], fields['clone_destination_' + suffix]
        projection_row = expanded[projection]
        if (bytes.fromhex(src[3])[:4] != b'\x41\x0f\x10\x87' or
                bytes.fromhex(dst[3])[:4] != b'\x41\x0f\x11\x86'):
            raise ValueError('clone forwarding opcode changed')
        source, destination = int(src[4], 16), int(dst[4], 16)
        if source != destination or destination != int(projection_row[2], 16):
            raise ValueError('clone forwarding offset changed')
        rows.append([suffix, src[1], hex(source), dst[1], hex(destination),
                     projection_row[1], projection_row[3], projection_row[5], '16'])
    return rows


def clone_guard_table(data, secs):
    # Decode only this pinned sequence: count * 2**shift must fit both tests.
    initial = read_va(data, secs, 0x55ea0b8, 42)
    if (initial[:2] != b'\x48\xbb' or initial[10:13] != b'\x49\x8b\xaf' or
            initial[17:24] != b'\x49\x89\xec\x49\xc1\xe4\x05' or
            initial[24:31] != b'\x48\x89\xe8\x48\xc1\xe8\x3b' or
            initial[31:34] != b'\x0f\x95\xc0' or initial[34:37] != b'\x48\x8d\x53' or
            initial[38:42] != b'\x49\x39\xd4\x0f'):
        raise ValueError('clone size guard encoding changed')
    suffix = read_va(data, secs, 0x55ea0e1, 5)
    if suffix != b'\x0f\x97\xc1\x08\xc1':
        raise ValueError('clone size guard condition changed')
    source = read_va(data, secs, 0x55ea10a, 7)
    if source[:3] != b'\x49\x8b\x9f':
        raise ValueError('clone source pointer encoding changed')
    sentinel = struct.unpack_from('<Q', initial, 2)[0]
    count_offset = struct.unpack_from('<I', initial, 13)[0]
    pointer_offset = struct.unpack_from('<I', source, 3)[0]
    shift = initial[23]
    high_shift = initial[30]
    adjust = struct.unpack_from('<b', initial, 37)[0]
    if sentinel != 1 << 63 or shift != 5 or high_shift != 59 or adjust != -8:
        raise ValueError('clone size guard constant changed')
    limit = sentinel + adjust
    max_count = min(limit >> shift, (1 << high_shift) - 1)
    _, off = mapping(secs, 0x55ea0b8, len(initial))
    return [[hex(0x55ea0b8), hex(off), hex(count_offset), hex(pointer_offset),
             str(1 << shift), str(high_shift), hex(limit), hex(max_count)]]


def collect(data, check_digest=True):
    if check_digest:
        authenticate(data)
    secs = sections(data)
    functions = selected_fdes(data, secs)
    relocations, reloc_rows = selected_relocations(data, secs)
    field_rows = fields_table(data, secs)
    copy_rows = copies_table(data, secs)
    expanded = expanded_projection_table(field_rows, copy_rows)
    return {
        'ranges.tsv': (['label', 'start_va', 'end_va_exclusive', 'file_offset', 'length', 'fde_va', 'cie_va', 'lsda_va', 'sha256'], functions),
        'windows.tsv': (['label', 'va', 'file_offset', 'length', 'bytes_hex'], windows_table(data, secs)),
        'fields.tsv': (['label', 'va', 'file_offset', 'instruction_hex', 'unsigned_operand'], field_rows),
        'copies.tsv': (['label', 'length_va', 'file_offset', 'length_bytes', 'length', 'slot_load_va', 'slot_load_bytes', 'call_va', 'call_bytes', 'symbol_slot_va'], copy_rows),
        'projection.tsv': (['label', 'source_va', 'source_offset', 'destination_va', 'destination_offset', 'record_relative_offset', 'width'], projection_table(field_rows, copy_rows)),
        'handoff.tsv': (['label', 'buffer_va', 'buffer_instruction', 'buffer_stack_offset', 'pointer_va', 'pointer_instruction', 'pointer_stack_offset', 'pointer_relative_offset', 'copy_length'], stitch_table(data, secs, copy_rows)),
        'expanded-projection.tsv': (['label', 'source_va', 'source_offset', 'destination_va', 'stack_offset', 'output_relative_offset', 'length'], expanded),
        'forwarding.tsv': (['label', 'clone_load_va', 'state_offset', 'clone_store_va', 'clone_offset', 'expanded_load_va', 'expanded_store_va', 'expanded_output_offset', 'length'], forwarding_table(field_rows, expanded)),
        'clone-guard.tsv': (['guard_va', 'file_offset', 'count_offset', 'pointer_offset', 'element_bytes', 'high_bit_shift', 'byte_limit', 'max_count'], clone_guard_table(data, secs)),
        'edges.tsv': (['label', 'va', 'file_offset', 'form', 'bytes_hex', 'target_va'], edges_table(data, secs)),
        'tables.tsv': (['label', 'table_va', 'index', 'slot_va', 'file_offset', 'bytes_hex', 'target_va'], tables_table(data, secs)),
        'relocations.tsv': (['label', 'slot_va', 'record_file_offset', 'type', 'symbol_index', 'addend'], reloc_rows),
        'locations.tsv': (['label', 'va', 'file_offset', 'relocation_file_offset', 'path_va', 'path_length', 'line', 'column', 'path'], locations_table(data, secs, relocations)),
        'references.tsv': (['label', 'va', 'file_offset', 'bytes_hex', 'target_va'], references_table(data, secs)),
        'literals.tsv': (['label', 'va', 'file_offset', 'length', 'bytes_hex', 'ascii'], literals_table(data, secs)),
    }


def emit(out, tables):
    out.mkdir(parents=True, exist_ok=True)
    for filename in sorted(tables):
        header, rows = tables[filename]
        with (out / filename).open('w', encoding='utf-8', newline='') as handle:
            writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
            writer.writerow(header)
            writer.writerows(rows)
    summary = {'binary_sha256': SHA256, 'coordinate_system': 'linked ELF virtual address',
               'counts': {name: len(rows) for name, (_, rows) in sorted(tables.items())},
               'coverage': 'selected static evidence only; FDE ranges are not a function census'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    data = BINARY.read_bytes()
    emit(args.out, collect(data))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print('abci_loader_handoff115:', error, file=sys.stderr)
        raise SystemExit(1)
