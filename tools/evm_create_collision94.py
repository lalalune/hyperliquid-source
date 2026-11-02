#!/usr/bin/env python3
"""Export selected node 94 create-address and collision evidence without executing code."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected unwind starts, not an exhaustive function census.
FUNCTIONS = (
    (0x4597bb0, '85-byte address digest'),
    (0x4675da0, 'reverse journal dispatcher'),
    (0x49d9990, 'payload digest'),
    (0x4c09420, 'plain interpreter loop'),
    (0x4c98d40, 'selected opcode handler'),
    (0x4da5f30, 'revision-18 callback adapter'),
    (0x4da6f00, 'revision-9 callback adapter'),
    (0x4dd63d0, 'checkpoint rollback'),
    (0x4dd6580, 'checkpoint and account transition'),
    (0x4dd6b40, 'caller nonce update'),
    (0x4dd8d50, 'creation frame and registry probe'),
)

# Fixed, manually reviewed instruction boundaries. Values are checked before export.
ANCHORS = (
    ('loop_reset_and_fetch', 0x4c094b5, '410fb686f301000084c0753a6666666666662e0f1f840000000000498b86d00100000fb60848ffc0498986d00100004c89f74c89e641ff54cd00'),
    ('loop_action_return', 0x4c094fb, '4180be88010000707535498b8ee801000048894b30410f1086d80100000f114320488d0ded7fb30048890b48c74308010000000f57c00f114310884338eb2a488b04240f10000f1048100f1050200f1058300f115b300f1153200f114b100f110341c6868801000070'),
    ('opcode_mode_gates', 0x4c98d51, '80bff001000000741280bff2010000007422c687f301000057eb07c687f3010000674881c4180400005b415c415d415e415f5dc3'),
    ('opcode_gas_and_stack', 0x4c98d85, '488b87e0010000483dff7c0000762348050083ffff488987e0010000488b8f280100004883f9047312c687f30100005bebbcc687f301000050ebb3'),
    ('opcode_fetch_and_pop', 0x4c98dc0, '488b87d00100000fb600488b97200100004889ce48c1e6054c8b4416a04c894424584c8b6c16a84c8b7416b0488b6c16b84883c1fc48898f2801000048c1e1054c8b040a4c89442460488b5c0a084c8b7c0a104c8b640a180f104416e00f104c16f00f298c24900000000f298424800000000f104416c00f104c16d00f298c24b00000000f298424a0000000'),
    ('opcode_input_checks', 0x4c98e4c, '833f020f85a504000048897c2408488b4f08483981980000000f86a8040000488b8990000000c1e005488d34014883c6184c8b0401488b540108488b4c0110488d7c241041ff104909df4d09e77428488b442408c680f301000054488d7c2428488b442410488b742418488b542420ff5020e9b0feffff'),
    ('opcode_memory_and_growth', 0x4c98ec3, '488b5c24604885db488b442408746a4d09ee4909ee75c6488b7424584889f14801d948c7c2ffffffff480f43d1488b88f0000000482b88100100000f828b0400004839ca763a488db8e0000000488db0d8010000ff1523b0ad0084c0488b442408488b5c2460488b7424587513c680f301000051e96bffffff48c7c6ffffffff'),
    ('opcode_decode_boundary', 0x4c99049, '488dbc24e0000000488db42430020000ff15e9aead0031c0483b8424e00000000f80bd020000'),
    ('opcode_extra_gas', 0x4c9908a, '0fb6ac24f00300004084ed0f84ca020000488b4424204883c01f48c7c1ffffffff480f43c848c1e9044883e1fe488d1449488b442408488b88e00100004829d17330c680f301000050488dbc2440030000e8a0931100488b442430488b742438488d7c2448488b542440ff5020e9abfdffff'),
    ('opcode_salt_byte_reversal', 0x4c990fc, '488988e0010000660f6f8424a0000000660f6f8c24b0000000660fefd2660f6fd9660f60da660f70db4ef20f70db1bf30f70db1b660f68ca660f70c94ef20f70c91bf30f70c91b660f67cb660f7f8c24c0000000660f6fc8660f60ca660f70c94ef20f70c91bf30f70c91b660f68c2660f70c04ef20f70c01bf30f70c01b660f67c1660f7f8424d0000000'),
    ('opcode_two_hash_calls', 0x4c991a1, '488dbc2430020000488db424e0000000e8da07d4ff488b442408488d9880000000488d7c246c488d9424c0000000488d8c24300200004889dee8d1e98fff'),
    ('opcode_gas_and_caller_copy', 0x4c991df, '488b4424084c8bb0e00100004c89f148c1e9064929ce488988e0010000c680f3010000208b4310898424280200000f10030f11842418020000'),
    ('opcode_derived_key_copy', 0x4c99220, '488db424400300004c8b3db14dad00bad80000004889df41ffd70f284424300f284c24400f118424080300000f118c24180300000f1044246c0f118424280300008b44247c89842438030000'),
    ('opcode_frame_publish', 0x4c99294, '488dbc24e0000000ba100100004889de41ffd7bf50010000e86fa814004989c6488db424e0000000ba500100004889c7ff15164dad00488b442408488db850010000e865b01100488b4424084c89b050010000c680880100006e48ff80d0010000'),
    ('opcode_unwind_publish', 0x4c993a8, '4889c3488b4424084c89b050010000c680880100006e4889dfe84a6d9c00'),
    ('opcode_diagnostic_exit', 0x4c9932c, '0fb68424e800000088842430020000488d3d3bb1a7fb488d0d87b9aa004c8d0518a2aa00488d942430020000be18000000ff15e54cad00eb37488d3d29b1a7fb488d150da2aa00be43000000ff151a4dad00eb1c488d3df1a0aa00ff158b4dad00eb0d488d3dcaa0aa00ff15b44dad000f0b'),
    ('opcode_eof_location', 0x4c992fa, '488d3d72b1a7fb488d1590a2aa00be0a000000ff155551ad00488d3d4bb1a7fb488d152fa2aa00be0e000000ff153c51ad00'),
    ('payload_hash_input', 0x49d9990, '4157415641554154534881ecc00100004989f74989fc4c8b7608488b5e10'),
    ('payload_hash_configuration', 0x49d9a00, '48c78424d00000008800000066c78424d800000001004889e74c89f64889daff15b347d900'),
    ('payload_hash_output', 0x49d9a3e, 'ba200000004c89ef4c89e6ff159147d900'),
    ('address_hash_preimage', 0x4597bbf, '8b4610894424100f10060f2904240f100a0f1052100f115424240f114c24140f10090f1051100f115424440f114c2434c644245bff0f1144245c8b4424108944246c488b44241448894424708b44241c894424780f284424200f1144247c0f284424300f1184248c0000000f284424400f1184249c0000008b442450898424ac000000'),
    ('address_hash_configuration', 0x4597cad, '48c78424a00100008800000066c78424a801000001004c8db424d0000000488d74245bba550000004c89f7ff15fa641d01'),
    ('address_hash_output', 0x4597cf7, '488db424b0000000ba200000004c89ffff15d3641d018b8424cc0000008943100f108424bc0000000f1103'),
    ('adapter_revision18_and_call', 0x4da5f30, '415653504889cb4989fe4889d6ba12000000e8092e0300'),
    ('adapter_revision18_cleanup', 0x4da5f47, '4889dfe881f70000be500100004889df31d2ff15b1809c004c89f04883c4085b415ec3'),
    ('adapter_revision_and_call', 0x4da6f00, '415653504889cb4989fe4889d6ba09000000e8391e0300'),
    ('adapter_cleanup', 0x4da6f17, '4889dfe8b1e70000be500100004889df31d2ff15e1709c004c89f04883c4085b415ec3'),
    ('create_input_select', 0x4dd8d61, '4989ce89d54989f74889fb31c0483b010f81db00000049bc0000000000000080'),
    ('create_decode_failure', 0x4dd8d81, '498d7620498b4608498b5610498b4e18488dbc24a0010000ff100f108424a00100000f108c24b00100000f298c24b00200000f298424a0020000488dbc24a0000000488db424a0020000ff1587c099004c39a424a00000000f85ed020000418b8648010000898424b0000000410f1086380100000f298424a0000000488db424a00000004c89ffe833ddffff498b863001000048c70302000000488d0dd6a3960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434014c6434800e984010000'),
    ('create_direct_key', 0x4dd8e52, '498db6f0000000498b86d8000000498b96e0000000498b8ee8000000488dbc24a0000000ff10488dbc24b80300004c89f6e858830100418b860801000089842490000000410f1086f80000000f298424800000000f108424a00000000f108c24b00000000f298424800200000f298c249002000041b501'),
    ('create_depth_gate', 0x4dd8efe, '4981bfa8000000000400000f86d9000000498b863001000048c70302000000488d0dd4a2960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434011c6434800'),
    ('create_caller_load', 0x4dd8fe8, '418b8648010000898424b0010000410f1086380100000f298424a0010000498b8fe0000000488dbc24a0000000488d9424a00100004c89fee88bcdffff80bc24a0000000050f856e010000'),
    ('create_balance_compare', 0x4dd9033, '488b9424a8000000488b4258498db610010000498b8e280100004839c87530488b4250498b8e200100004839c87520488b4248498b8e180100004839c87510488b4240488b0e4839c80f844a0200004839c80f8341020000498b863001000048c70302000000488d0d58a1960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434012e97ffeffff'),
    ('create_validate_boundary', 0x4dd90cc, '4c8da424a0020000488db424a0000000bad80000004c89e7ff15f64e99000f108424780100000f108c24880100000f294c24100f2904244c89e7e8e5520b003c020f85c3000000498bb7d8000000440fb6ae580100004584ed0f84d0030000'),
    ('create_validation_failure', 0x4dd91d6, '418b8648010000898424b0000000410f1086380100000f298424a0000000488db424a00000004c89ffe83cd9ffff498b863001000048c70302000000488d0ddf9f960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434014c6434800'),
    ('create_nonce_call', 0x4dd92cc, '48897424584d8da638010000418b442410898424b0000000410f1004240f298424a0000000488db424a00000004c89ffe83fd8ffffa80174224584ed7468'),
    ('create_direct_key_forward', 0x4dd930a, '8b842490000000894424500f288424800000000f29442440e921030000'),
    ('create_nonce_limit_status', 0x4dd9327, '498b863001000048c70302000000488d0dbc9e960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434002e9e3fbffff'),
    ('create_rlp_header', 0x4dd9372, '4889d148ffc9480fbdf183f638c1ee034889f04883f01f4881f980000000ba17000000480f43d08d42bf880424c64424019448c744241600000000c644241e00410f1004240f11442402418b442410894424124885c90f84660100004881f9800000000f8360010000884c2416e98f010000'),
    ('create_rlp_long_number', 0x4dd9534, 'c644241680eb38480fc948898c24a0000000b8080000004829f08d48804801e64881c6a0000000884c2416488d7c24174989d54889c2ff15704a99004c89ea'),
    ('create_rlp_hash_call', 0x4dd95de, '48c78424700200008800000066c78424780200000100488dbc24a00100004889e6ff15d34b9900'),
    ('create_rlp_hash_output', 0x4dd9623, '488d742460ba200000004c89efff15aa4b99000f1044246c0f294424408b44247c89442450'),
    ('create_registry_probe', 0x4dd9648, '4983bfe8000000007413498dbfe8000000488d742440e84d3aabffeb11498bbff0000000488d742440e83a3aabff84c07441'),
    ('create_registry_hit_status', 0x4dd967a, '498b863001000048c70302000000488d0d699b960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c643405ee990f8ffff'),
    ('create_after_registry_miss', 0x4dd96bb, '8b442450898424b00100000f284424400f298424a0010000498b8fe0000000488dbc24a0000000488d9424a00100004c89fee8bec6ffff0fb68424a00000003c050f85bd000000'),
    ('create_checkpoint_call', 0x4dd9742, '440fb6cd488dbc24a00100004889e2488d6c24604c8d8424a00000004c89fe4889e9e817ceffff80bc24a0010000010f85ab000000'),
    ('create_checkpoint_error', 0x4dd9777, '0fb68424a1010000498b8e3001000048c70302000000488d15649a96004889530848c74310010000000f57c00f11431848894b2848894b3048c7433800000000884340e98cf7ffff'),
    ('create_success_output', 0x4dd9822, '4c8bbc24a80100004c8bac24b0010000488b442420488b542428488d742438488b4c2430488dbc24a0000000ff104c89bc24980000000f108424a00000000f108c24b00000000f294c24100f290424488dbc24a0010000488db424a0020000e85a79010048c78424a00000000100000048c78424a800000001000000488dbc24b0000000488db424a0010000bad8000000ff1527479900bfe8000000e85da200004989c7488db424a0000000bae80000004889c7ff15044799004c89bc24a800000048c78424a000000002000000c68424a001000000c68424a303000000418b44241089842490030000410f1004240f29842480030000488b4424580f10000f1048100f294c24700f29442460488d842480030000488dbc24900400004889e6488d9424a0000000488d8c24a00100004c8d4424404c8d8c24a30300005550e82a4bebff4883c410498b9630010000488dbc2470050000488db4249004000031c9ff15b7b49900488b942498000000c684246107000001488dbc24a0000000488d7424404c8d8424700500004c89e9ff15a9b499000f108424f00000000f1143500f108424e00000000f1143400f108424a00000000f108c24b00000000f109424c00000000f109c24d00000000f115b300f1153200f114b100f1103'),
    ('nonce_entry_and_max', 0x4dd6b40, '4157415641554154534989f64989ff4883c730e8d87cabff4885c00f84f20000004889c348837860ff0f84d8000000'),
    ('nonce_dirty_journal', 0x4dd6b6f, '498b47284885c00f84e4000000f683b0000000047560498b4f20488d04404c8d24c14c8b6cc1f84c3b6cc1e8750e488d3cc14883c7e8ff15c5c69900498b4424f0496bcd58c6040802410f10060f11440801418b56108954081149ffc54d896c24f8808bb000000004498b47284885c00f8488000000'),
    ('nonce_append_and_increment', 0x4dd6be5, '498b4f20488d04404c8d3cc14c8b64c1f84c3b64c1e8750e488d3cc14883c7e8ff1565c69900498b47f0496bcc58c6040804410f10060f11440801418b56108954081149ffc44d8967f8488b53604883faff744148ffc248895360b801000000eb0231c0'),
    ('nonce_error_locations', 0x4dd6c53, '488d3d76e29600ff1510789900488d3d81e29600ff1503789900488d3d8ce29600ff15f6779900488d3d97e29600ff1591749900'),
    ('checkpoint_open', 0x4dd6580, '554157415641554154534881ec880000004c89442428488b86a80000004883f8ff0f84790300004989cf4989f54889fb44894c242448895424584c8b66104c8b762848ffc0488986a80000004c3b7618750a498d7d18ff154ce89900498b45204b8d0c7648c704c80000000048c744c8080800000048c744c81000000000498d460149894528'),
    ('checkpoint_account_guard', 0x4dd6606, '498d6d304889ef4c897c24184c89fee81682abff4885c00f84d60200004989c7498b45284885c00f84d3020000f3410f6f4768f3410f6f4f78660f740d99e542fb660f740511fb42fb660fdbc1660fd7c881f9ffff0000750749837f600074284c89ef4c89e64c89f2e85cfdffffc643015eb00188034881c4880000005b415c415d415e415f5dc3'),
    ('checkpoint_creation_tag5', 0x4dd668e, '4c89642450498b4d20488d0440488d14c141808fb000000001488d04c14883c0e848894424104c8b62f848895424084c3b62e8750b488b7c2410ff15a2cb9900488b742408488b46f0496bcc58c6040805488b542418f30f6f02f30f7f4408018b52108954081149ffc44c8966f841833f0474084c89ffe8b6bcfdff'),
    ('checkpoint_touch_tag2', 0x4dd670a, '49c7070400000041f687b0000000047550488b4424084c8b60f84c3b60e8750b488b7c2410ff153bcb9900488b742408488b46f0496bcc58c6040802488b542418f30f6f02f30f7f4408018b52108954081149ffc44c8966f841808fb000000004'),
    ('checkpoint_balance_addition', 0x4dd676b, '4c8b4424284d8b104d8b5808498b4810498b475048894c24484801c8400f92c6498b4f404c01d1498b57484c11da4883d000400f92c74008f74d8b60184d8b47584f8d0c04400fb6f783e6014c01ce400f92c74c896424404d01e04c8b6424500f82110100004084ff0f85080100004c895c24304c8954243849894f40498957484989475049897758807c242404760849c7476001000000'),
    ('checkpoint_debit', 0x4dd6803, '4889ef4c8b6c24584c89eee81d80abff4885c00f84f7000000488b4c243848294840488b4c243048194848488b4c244848194850488b4c244048194858'),
    ('checkpoint_transfer_tag3', 0x4dd6840, '488b4424280f10000f1048100f114c24780f11442468488b4424084c8b78f84c3b78e8750b488b7c2410ff1500ca9900488b742408488b46f0496bcf58c6040803418b551089540811410f1045000f11440801488b5424180f10020f114408158b521089540825f30f6f442461f30f6f4c2471f30f7f440829f30f7f4c0839488b942480000000488954084849ffc74c897ef84c8963084c89731031c0e998fdffff'),
    ('checkpoint_overflow_status', 0x4dd68e2, '4c89ef4c89e64c89f2e8e0faffffc643015fe97ffdffff'),
    ('checkpoint_missing_account_traps', 0x4dd68f9, '488d3dd8e49600ff156a7b9900488d3de3e49600ff155d7b9900488d3deee49600ff15507b9900'),
    ('checkpoint_counter_failure', 0x4dd6920, '488d3d99e49600ff15eb77990049c707040000004889c7e8d4978800'),
    ('rollback_depth_and_reverse', 0x4dd63dd, '80bfb0000000050f9344240f4889d3488b97a80000004885d20f84280100004989fe4989f4488d4730488d4f5848ffca488997a8000000488b57284889d64829de0f820d010000498b7e20488d1452488d14d748897c241048895424184889742420742648ffce488944242848894c2430488d44240f4889442438488d7c2410488d542428e839f989ff'),
    ('rollback_truncation', 0x4dd6467, '4d8b6e104d39ec76214d8b7e284929df720a498b462049895e2875644883c4405b415c415d415e415fc34f8d3ca449c1e7044d037e084d8966104d29e549ffc5'),
    ('rollback_index_traps', 0x4dd6524, '488d3d1de89600ff151f7c9900488d3d28e89600ff15127c9900'),
    ('journal_table_first_dispatch', 0x4675e4d, '488b8424b80000000fb60088442417486bc9584801d14c8d79a80fb651a80fb659a9488d41aa0f1041c80f1144247e0f1041ba0f29442470f30f6f41aa660f7f442460488b69d84c8b69e04c8b71e84c8b61f0488b79f8488d35891108fc48630c964801f1ffe1'),
    ('journal_table_next_dispatch', 0x4676070, '488b1c244c39fb0f8493050000410fb64fa8410fb65fa9498d47aa410f1047c80f1144247e410f1047ba0f29442470f3410f6f47aa660f7f442460498b6fd84d8b6fe04d8b77e84d8b67f0498b7ff84983c7a8488d156a0f08fc48630c8a4801d1ffe1'),
    ('journal_tag2_clear', 0x467602a, '807c241700488d7424207420662e0f1f8400000000008b442430483500000003480b442420480b442428741a488b7c2418e8d08721004885c00f845406000080a0b0000000fb'),
    ('journal_tag3_restore', 0x4676108, '488b7c2418488db42490000000e816872100660f1f4400004885c00f843a050000488b48504c01f10f92c2480168404c1168484883d100400f92c64008d6488b50584c01e2400fb6f683e6014801d64889485048897058488b7c2418488d742420e8c28621004885c00f8434050000482968404c1968484c1970504c196058'),
    ('journal_tag5_restore', 0x4676190, '885c24208b44246f488d4c242189410f660f6f442460f30f7f01488b7c2418488d742420e8778621000f1f80000000004885c00f84d004000080a0b0000000fe488b8888000000'),
    ('journal_tag5_nonce_clear', 0x4676250, '48c7406000000000e917feffff'),
    ('journal_tag4_nonce_reverse', 0x4676260, '885c24208b44246f488d4c242189410f660f6f442460f30f7f01488b7c2418488d742420e8a78521000f1f80000000004885c00f84f7030000488b48604885c90f843804000048ffc948894860e9befdffff'),
)

# Fixed transfer sites; both the opcode and displacement are checked.
EDGES = (
    ('opcode_mode_zero', 0x4c98d58, '7412', 'conditional', 0x4c98d6c),
    ('opcode_readonly', 0x4c98d61, '7422', 'conditional', 0x4c98d85),
    ('opcode_gas_low', 0x4c98d92, '7623', 'conditional', 0x4c98db7),
    ('opcode_stack_enough', 0x4c98dac, '7312', 'conditional', 0x4c98dc0),
    ('opcode_input_reject', 0x4c98ed8, '75c6', 'conditional', 0x4c98ea0),
    ('opcode_growth_failed', 0x4c98f2e, '7513', 'conditional', 0x4c98f43),
    ('opcode_container_decode', 0x4c99059, 'ff15e9aead00', 'indirect-call-slot', 0x5773f48),
    ('opcode_decode_fail', 0x4c99069, '0f80bd020000', 'conditional', 0x4c9932c),
    ('opcode_variable_gas', 0x4c990ca, '7330', 'conditional', 0x4c990fc),
    ('opcode_hash_payload', 0x4c991b1, 'e8da07d4ff', 'call', 0x49d9990),
    ('opcode_hash_address', 0x4c991da, 'e8d1e98fff', 'call', 0x4597bb0),
    ('opcode_allocate_frame', 0x4c992ac, 'e86fa81400', 'call', 0x4de3b20),
    ('opcode_drop_prior_action', 0x4c992d6, 'e865b01100', 'call', 0x4db4340),
    ('payload_absorb', 0x49d9a1f, 'ff15b347d900', 'indirect-call-slot', 0x576e1d8),
    ('payload_finalize', 0x49d9a49, 'ff159147d900', 'indirect-call-slot', 0x576e1e0),
    ('address_absorb', 0x4597cd8, 'ff15fa641d01', 'indirect-call-slot', 0x576e1d8),
    ('address_finalize', 0x4597d07, 'ff15d3641d01', 'indirect-call-slot', 0x576e1e0),
    ('adapter18_create', 0x4da5f42, 'e8092e0300', 'call', 0x4dd8d50),
    ('adapter18_release', 0x4da5f4a, 'e881f70000', 'call', 0x4db56d0),
    ('adapter_create', 0x4da6f12, 'e8391e0300', 'call', 0x4dd8d50),
    ('adapter_release', 0x4da6f1a, 'e8b1e70000', 'call', 0x4db56d0),
    ('create_first_variant', 0x4dd8d71, '0f81db000000', 'conditional', 0x4dd8e52),
    ('create_decode', 0x4dd8dcb, 'ff1587c09900', 'indirect-call-slot', 0x5774e58),
    ('create_decode_sentinel', 0x4dd8dd9, '0f85ed020000', 'conditional', 0x4dd90cc),
    ('create_nonce_decode_error', 0x4dd8e08, 'e833ddffff', 'call', 0x4dd6b40),
    ('create_clone', 0x4dd8e83, 'e858830100', 'call', 0x4df11e0),
    ('create_depth', 0x4dd8f09, '0f86d9000000', 'conditional', 0x4dd8fe8),
    ('create_caller_load', 0x4dd9020, 'e88bcdffff', 'call', 0x4dd5db0),
    ('create_caller_error', 0x4dd902d, '0f856e010000', 'conditional', 0x4dd91a1),
    ('create_balance_equal', 0x4dd907c, '0f844a020000', 'conditional', 0x4dd92cc),
    ('create_balance_enough', 0x4dd9085, '0f8341020000', 'conditional', 0x4dd92cc),
    ('create_validate', 0x4dd9106, 'e8e5520b00', 'call', 0x4e8e3f0),
    ('create_validate_error', 0x4dd910d, '0f85c3000000', 'conditional', 0x4dd91d6),
    ('create_nonce_validate_error', 0x4dd91ff, 'e83cd9ffff', 'call', 0x4dd6b40),
    ('create_nonce', 0x4dd92fc, 'e83fd8ffff', 'call', 0x4dd6b40),
    ('create_nonce_failed', 0x4dd9303, '7422', 'conditional', 0x4dd9327),
    ('create_derived_key_select', 0x4dd9308, '7468', 'conditional', 0x4dd9372),
    ('create_rlp_hash', 0x4dd95ff, 'ff15d34b9900', 'indirect-call-slot', 0x576e1d8),
    ('create_rlp_finalize', 0x4dd9630, 'ff15aa4b9900', 'indirect-call-slot', 0x576e1e0),
    ('create_borrowed_switch', 0x4dd9650, '7413', 'conditional', 0x4dd9665),
    ('create_owned_lookup', 0x4dd965e, 'e84d3aabff', 'call', 0x488d0b0),
    ('create_borrowed_lookup', 0x4dd9671, 'e83a3aabff', 'call', 0x488d0b0),
    ('create_miss', 0x4dd9678, '7441', 'conditional', 0x4dd96bb),
    ('create_target_load', 0x4dd96ed, 'e8bec6ffff', 'call', 0x4dd5db0),
    ('create_target_error', 0x4dd96fc, '0f85bd000000', 'conditional', 0x4dd97bf),
    ('create_checkpoint', 0x4dd9764, 'e817ceffff', 'call', 0x4dd6580),
    ('create_checkpoint_success', 0x4dd9771, '0f85ab000000', 'conditional', 0x4dd9822),
    ('create_success_frame', 0x4dd9961, 'e82a4bebff', 'call', 0x4c8e490),
    ('create_success_step', 0x4dd9983, 'ff15b7b49900', 'indirect-call-slot', 0x5774e40),
    ('create_success_output', 0x4dd99b1, 'ff15a9b49900', 'indirect-call-slot', 0x5774e60),
    ('nonce_find', 0x4dd6b53, 'e8d87cabff', 'call', 0x488e830),
    ('nonce_max', 0x4dd6b69, '0f84d8000000', 'conditional', 0x4dd6c47),
    ('nonce_already_dirty', 0x4dd6b83, '7560', 'conditional', 0x4dd6be5),
    ('checkpoint_missing_dest', 0x4dd661d, '0f84d6020000', 'conditional', 0x4dd68f9),
    ('checkpoint_collision_check', 0x4dd665d, '7507', 'conditional', 0x4dd6666),
    ('checkpoint_nonce_zero', 0x4dd6664, '7428', 'conditional', 0x4dd668e),
    ('checkpoint_collision_revert', 0x4dd666f, 'e85cfdffff', 'call', 0x4dd63d0),
    ('checkpoint_add_overflow1', 0x4dd67cb, '0f8211010000', 'conditional', 0x4dd68e2),
    ('checkpoint_add_overflow2', 0x4dd67d4, '0f8508010000', 'conditional', 0x4dd68e2),
    ('checkpoint_source_find', 0x4dd680e, 'e81d80abff', 'call', 0x488e830),
    ('checkpoint_overflow_revert', 0x4dd68eb, 'e8e0faffff', 'call', 0x4dd63d0),
    ('rollback_journal', 0x4dd6462, 'e839f989ff', 'call', 0x4675da0),
)

RELATIVE_SLOTS = (
    (0x57245e8, 0x4c98d40, 'revision-9 opcode table entry ec'),
    (0x5724de8, 0x4c98d40, 'revision-18 opcode table entry ec'),
    (0x5743568, 0x1fe6bb, 'source location for subcontainer diagnostic'),
    (0x5743580, 0x1fe6bb, 'source location for data-section diagnostic'),
    (0x5743598, 0x1fe6bb, 'source location for EOF diagnostic'),
    (0x5744d48, 0x1e3a8c, 'rollback location one'),
    (0x5744d60, 0x1e3a8c, 'rollback location two'),
    (0x5744dc0, 0x1e3a8c, 'checkpoint counter location'),
    (0x5744dd8, 0x1e3a8c, 'checkpoint target location'),
    (0x5744df0, 0x1e3a8c, 'checkpoint journal location'),
    (0x5744e08, 0x1e3a8c, 'checkpoint source location'),
    (0x5744ed0, 0x1e3a8c, 'nonce account location'),
    (0x5744ee8, 0x1e3a8c, 'nonce journal location one'),
    (0x5744f00, 0x1e3a8c, 'nonce journal location two'),
    (0x5744f18, 0x1e3a8c, 'nonce overflow location'),
    (0x5745cd8, 0x4da5f30, 'revision-18 descriptor method'),
    (0x5745e28, 0x4da6f00, 'revision-9 descriptor method'),
    (0x574f0b0, 0x4e9d2a0, 'prior address-09 callback'),
    (0x576e1d8, 0x4f59a10, 'prior digest absorb boundary'),
    (0x576e1e0, 0x4f59e40, 'prior digest finalize boundary'),
    (0x5773f40, 0x4e8fcb0, 'prior memory growth boundary'),
    (0x5773f48, 0x4ea4790, 'opcode decode boundary'),
    (0x5774e58, 0x4ea4470, 'external decode boundary'),
)

LOCATION_SITES = (
    (0x4c99349, 0x5743568, 0x1fe6bb, 'revm-interpreter-15.0.0/src/instructions/contract.rs'),
    (0x4c9936c, 0x5743580, 0x1fe6bb, 'revm-interpreter-15.0.0/src/instructions/contract.rs'),
    (0x4c99301, 0x5743598, 0x1fe6bb, 'revm-interpreter-15.0.0/src/instructions/contract.rs'),
    (0x4dd6524, 0x5744d48, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6531, 0x5744d60, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6920, 0x5744dc0, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd68f9, 0x5744dd8, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6906, 0x5744df0, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6913, 0x5744e08, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6c53, 0x5744ed0, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6c60, 0x5744ee8, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6c6d, 0x5744f00, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
    (0x4dd6c7a, 0x5744f18, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs'),
)

# Fixed instruction prefixes with immediates to extract, not a general decoder.
# The labels identify the local use; branch relationships are in transfers.tsv.
IMMEDIATES = (
    ('opcode_readonly_status', 0x4c98d63, 'c687f3010000', 'u8'),
    ('opcode_mode_zero_status', 0x4c98d6c, 'c687f3010000', 'u8'),
    ('opcode_maximum_rejected_gas', 0x4c98d8c, '483d', 'u32'),
    ('opcode_base_gas_cost', 0x4c98d94, '4805', 'negative_i32'),
    ('opcode_stack_minimum', 0x4c98da8, '4883f9', 'u8'),
    ('opcode_stack_status', 0x4c98dae, 'c687f3010000', 'u8'),
    ('opcode_gas_status', 0x4c98db7, 'c687f3010000', 'u8'),
    ('opcode_high_word_status', 0x4c98ea0, 'c680f3010000', 'u8'),
    ('opcode_growth_status', 0x4c98f30, 'c680f3010000', 'u8'),
    ('opcode_frame_size', 0x4c992a7, 'bf', 'u32'),
    ('opcode_action_tag', 0x4c992e7, 'c68088010000', 'u8'),
    ('create_decode_failure_status', 0x4dd8e45, 'c64340', 'u8'),
    ('create_depth_limit', 0x4dd8efe, '4981bfa8000000', 'u32'),
    ('create_depth_failure_status', 0x4dd8f47, 'c64340', 'u8'),
    ('create_balance_failure_status', 0x4dd90c3, 'c64340', 'u8'),
    ('create_nonce_failure_status', 0x4dd935f, 'c64340', 'u8'),
    ('create_registry_hit_status', 0x4dd96b2, 'c64340', 'u8'),
    ('nonce_maximum', 0x4dd6b64, '48837860', 'sign_extended_i8'),
    ('nonce_dirty_flag', 0x4dd6bd1, '808bb0000000', 'u8'),
    ('nonce_dirty_journal_tag', 0x4dd6bb4, 'c60408', 'u8'),
    ('nonce_increment_journal_tag', 0x4dd6c13, 'c60408', 'u8'),
    ('checkpoint_collision_status', 0x4dd6674, 'c64301', 'u8'),
    ('checkpoint_created_flag', 0x4dd669f, '41808fb0000000', 'u8'),
    ('checkpoint_creation_journal_tag', 0x4dd66db, 'c60408', 'u8'),
    ('checkpoint_dirty_journal_tag', 0x4dd6742, 'c60408', 'u8'),
    ('checkpoint_nonce_revision_boundary', 0x4dd67f4, '807c2424', 'u8'),
    ('checkpoint_transfer_journal_tag', 0x4dd687d, 'c60408', 'u8'),
    ('checkpoint_overflow_status', 0x4dd68f0, 'c64301', 'u8'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    actual = hashlib.sha256(data).hexdigest()
    require(actual == DIGEST, 'node 94 SHA-256 mismatch')
    return actual


def file_offset(secs, va, size, file_size):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual-address range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'virtual range is absent, NOBITS, crossing or ambiguous')
    sec = matches[0]
    offset = sec['offset'] + va - sec['address']
    require(0 <= offset and offset + size <= file_size, 'section mapping leaves input file')
    return offset


def read_at(data, secs, va, size):
    off = file_offset(secs, va, size, len(data))
    return data[off:off + size]


def executable_extent(secs, start, end):
    require(type(start) is int and type(end) is int and 0 <= start < end,
            'invalid executable extent')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4
               and s['address'] <= start and end <= s['address'] + s['size']]
    require(len(matches) == 1, 'FDE is outside an unambiguous file-backed executable section')
    return matches[0]


def expect_window(actual, expected):
    require(actual == expected, 'reviewed instruction window changed')
    return actual


def decode_transfer(site, raw):
    """Decode only the explicitly selected x86-64 transfer shapes."""
    if len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
        return ('jump' if raw[0] == 0xeb else 'conditional', site + 2 + struct.unpack('<b', raw[1:])[0])
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return ('call' if raw[0] == 0xe8 else 'jump', site + 5 + struct.unpack('<i', raw[1:])[0])
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return ('conditional', site + 6 + struct.unpack('<i', raw[2:])[0])
    if len(raw) == 6 and raw[:2] == b'\xff\x15':
        return ('indirect-call-slot', site + 6 + struct.unpack('<i', raw[2:])[0])
    raise ValueError('unsupported selected transfer shape')


def checked_transfer(site, actual, expected_raw, expected_kind, expected_target):
    expect_window(actual, expected_raw)
    kind, target = decode_transfer(site, actual)
    require(kind == expected_kind and target == expected_target, 'selected transfer target changed')
    return kind, target


def decode_immediate(raw, prefix, encoding):
    formats = {'u8': '<B', 'u32': '<I', 'negative_i32': '<i',
               'sign_extended_i8': '<b'}
    require(encoding in formats, 'unsupported immediate encoding')
    fmt = formats[encoding]
    require(len(raw) == len(prefix) + struct.calcsize(fmt) and raw.startswith(prefix),
            'selected immediate instruction changed')
    value = struct.unpack_from(fmt, raw, len(prefix))[0]
    if encoding == 'negative_i32':
        require(value < 0, 'expected negative immediate')
        value = -value
    if encoding == 'sign_extended_i8':
        value &= (1 << 64) - 1
    return value


def relative_record(raw, expected_slot):
    require(len(raw) == 24, 'truncated RELA')
    slot, info, addend = struct.unpack('<QQq', raw)
    require(slot == expected_slot and info == 8 and addend >= 0,
            'expected a symbol-free R_X86_64_RELATIVE relocation')
    return addend


def relocation_rows(data, secs):
    wanted = {slot: (target, label) for slot, target, label in RELATIVE_SLOTS}
    found = {}
    for sec in secs:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'unaligned ELF64 RELA section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            raw = data[off:off + 24]
            slot = struct.unpack_from('<Q', raw)[0]
            if slot not in wanted:
                continue
            require(slot not in found, 'duplicate selected relocation')
            target = relative_record(raw, slot)
            expected, label = wanted[slot]
            require(target == expected, 'selected relocation addend changed')
            found[slot] = {'label': label, 'slot_va': hex(slot),
                           'rela_file_offset': hex(off), 'info': '0x8',
                           'addend_va': hex(target), 'raw': raw.hex()}
    require(len(found) == len(wanted), 'selected relocation missing')
    return [found[k] for k in sorted(found)]


def bounded_relative_table(data, secs, va, count, first, last):
    require(type(count) is int and 0 < count <= 256 and first < last, 'invalid table bound')
    raw = read_at(data, secs, va, count * 4)
    rows = []
    for index in range(count):
        delta = struct.unpack_from('<i', raw, index * 4)[0]
        target = va + delta
        require(first <= target < last, 'selected table target outside expected interval')
        rows.append({'index': index, 'entry_va': hex(va + 4 * index),
                     'raw': raw[index * 4:index * 4 + 4].hex(), 'target_va': hex(target)})
    return rows


def parse_lsda(data, secs, frame):
    """Read the bounded call-site records for the encodings observed here."""
    if frame['lsda'] is None:
        return None
    matches = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(matches) == 1, 'missing or duplicate exception section')
    sec = matches[0]
    begin = file_offset(secs, frame['lsda'], 1, len(data))
    pos, end = begin, sec['offset'] + sec['size']
    require(pos + 2 <= end and data[pos] == 0xff, 'unsupported LSDA landing encoding')
    pos += 1
    typ = data[pos]
    pos += 1
    type_va = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_va = sec['address'] + pos - sec['offset'] + delta
        require(type_va <= sec['address'] + sec['size'], 'LSDA type table outside section')
    else:
        require(typ == 0xff, 'unsupported LSDA type encoding')
    require(pos < end and data[pos] == 1, 'unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, end)
    table_start, table_end = pos, pos + size
    require(table_end <= end, 'LSDA call-site table outside section')
    entries = []
    while pos < table_end:
        start, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        first = frame['start'] + start
        require(frame['start'] <= first and first + length <= frame['end'],
                'LSDA interval outside FDE')
        if landing:
            require(frame['start'] <= frame['start'] + landing < frame['end'],
                    'LSDA landing outside FDE')
        entries.append({'start_va': hex(first), 'length': length,
                        'landing_va': hex(frame['start'] + landing) if landing else None,
                        'action': action})
    return {'function_va': hex(frame['start']), 'lsda_va': hex(frame['lsda']),
            'file_offset': hex(begin), 'type_encoding': typ,
            'type_table_va': hex(type_va) if type_va is not None else None,
            'header_bytes': data[begin:table_start].hex(),
            'call_site_bytes': data[table_start:table_end].hex(), 'entries': entries}


def record_bytes(data, secs, va):
    size = struct.unpack('<I', read_at(data, secs, va, 4))[0]
    require(4 <= size < 0xffffffff, 'invalid unwind record size')
    return read_at(data, secs, va, 4 + size)


def decode_rip_lea(site, raw):
    require(len(raw) == 7 and raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and
            raw[2] & 0xc7 == 0x05, 'unsupported RIP-relative LEA')
    return site + 7 + struct.unpack('<i', raw[3:])[0]


def source_location(data, secs, va, string_va, expected_suffix):
    """Retain only a relative suffix and digest of the binary's location path."""
    raw = read_at(data, secs, va, 24)
    _, size, line, column = struct.unpack('<QQII', raw)
    require(0 < size < 4096 and line > 0 and column > 0, 'invalid source location')
    path = read_at(data, secs, string_va, size)
    try:
        count = len(expected_suffix.split('/'))
        suffix = b'/'.join(path.split(b'/')[-count:]).decode('ascii')
    except UnicodeDecodeError as error:
        raise ValueError('non-ASCII source location suffix') from error
    require(suffix == expected_suffix, 'selected source location suffix changed')
    return {'location_va': hex(va), 'location_file_offset': hex(file_offset(secs, va, 24, len(data))),
            'location_raw': raw.hex(), 'path_va': hex(string_va), 'path_length': size,
            'path_sha256': hashlib.sha256(path).hexdigest(), 'relative_suffix': suffix,
            'line': line, 'column': column}


def create2_preimage(address, salt, payload_hash):
    """Synthetic projection of the pinned 85-byte input; this does not run target code."""
    if not all(isinstance(x, bytes) for x in (address, salt, payload_hash)):
        raise ValueError('expected byte strings')
    if (len(address), len(salt), len(payload_hash)) != (20, 32, 32):
        raise ValueError('expected 20, 32 and 32 bytes')
    return b'\xff' + address + salt + payload_hash


def rlp_address_nonce(address, nonce):
    """Synthetic projection of the selected 20-byte-key and u64 branch."""
    if not isinstance(address, bytes) or len(address) != 20:
        raise ValueError('expected a 20-byte address')
    if type(nonce) is not int or not 0 <= nonce < 1 << 64:
        raise ValueError('nonce outside u64')
    if nonce == 0:
        number = b'\x80'
    elif nonce < 0x80:
        number = bytes([nonce])
    else:
        value = nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big')
        number = bytes([0x80 + len(value)]) + value
    payload = b'\x94' + address + number
    return bytes([0xc0 + len(payload)]) + payload


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def tsv_bytes(columns, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(k, '') for k in columns])
    return out.getvalue().encode()


def collect(data):
    actual_digest = verify_digest(data)
    secs, index = unwind_index(data)
    cies, all_frames = eh_frame_records(data, secs)
    del cies
    by_start = {}
    requested_starts = {start for start, _ in FUNCTIONS}
    for frame in all_frames:
        if frame['start'] in requested_starts:
            require(frame['start'] not in by_start, 'duplicate selected FDE start')
            by_start[frame['start']] = frame
    table = {row['start']: row for row in index}
    functions, bodies, unwind, exceptions = [], [], [], []
    headers = [s for s in secs if s['name'] == '.eh_frame_hdr' and s['type'] != 8]
    require(len(headers) == 1, 'missing or duplicate file-backed unwind header')
    header = headers[0]
    for start, role in FUNCTIONS:
        require(start in by_start and start in table, 'selected FDE not indexed')
        frame = by_start[start]
        require(table[start]['fde'] == frame['fde'] and frame['end'] > start,
                'unwind index and FDE disagree')
        executable_extent(secs, start, frame['end'])
        off = file_offset(secs, start, frame['end'] - start, len(data))
        body = data[off:off + frame['end'] - start]
        functions.append({'start_va': hex(start), 'end_va': hex(frame['end']),
                          'size': len(body), 'file_offset': hex(off),
                          'fde_va': hex(frame['fde']), 'cie_va': hex(frame['cie']),
                          'lsda_va': hex(frame['lsda']) if frame['lsda'] else '',
                          'sha256': hashlib.sha256(body).hexdigest(), 'role': role})
        bodies.append({'start_va': hex(start), 'file_offset': hex(off), 'bytes': body.hex()})
        index_offset = header['offset'] + 12 + 8 * table[start]['index']
        require(index_offset + 8 <= header['offset'] + header['size'],
                'selected unwind-index record crosses its section')
        unwind.append({'start_va': hex(start), 'index': table[start]['index'],
                       'index_file_offset': hex(index_offset),
                       'index_bytes': data[index_offset:index_offset + 8].hex(),
                       'fde_va': hex(frame['fde']),
                       'fde_bytes': record_bytes(data, secs, frame['fde']).hex(),
                       'cie_va': hex(frame['cie']),
                       'cie_bytes': record_bytes(data, secs, frame['cie']).hex()})
        exception = parse_lsda(data, secs, frame)
        if exception is not None:
            exceptions.append(exception)
    frames = [by_start[start] for start, _ in FUNCTIONS]
    windows = []
    for label, va, expected_hex in ANCHORS:
        expected = bytes.fromhex(expected_hex)
        frame = [f for f in frames if f['start'] <= va and va + len(expected) <= f['end']]
        require(len(frame) == 1, 'reviewed window outside selected FDEs')
        actual = expect_window(read_at(data, secs, va, len(expected)), expected)
        windows.append({'label': label, 'start_va': hex(va),
                        'end_va': hex(va + len(actual)),
                        'file_offset': hex(file_offset(secs, va, len(actual), len(data))),
                        'bytes': actual.hex()})
    transfers = []
    for label, va, raw_hex, expected_kind, expected_target in EDGES:
        expected = bytes.fromhex(raw_hex)
        frame = [f for f in frames if f['start'] <= va and va + len(expected) <= f['end']]
        require(len(frame) == 1, 'selected transfer outside selected FDEs')
        actual = read_at(data, secs, va, len(expected))
        kind, target = checked_transfer(va, actual, expected, expected_kind, expected_target)
        transfers.append({'label': label, 'site_va': hex(va), 'kind': kind,
                          'target_or_slot_va': hex(target), 'bytes': actual.hex()})
    immediates = []
    for label, va, prefix_hex, encoding in IMMEDIATES:
        prefix = bytes.fromhex(prefix_hex)
        size = len(prefix) + (4 if encoding in ('u32', 'negative_i32') else 1)
        require(any(f['start'] <= va and va + size <= f['end'] for f in frames),
                'selected immediate outside selected FDEs')
        raw = read_at(data, secs, va, size)
        value = decode_immediate(raw, prefix, encoding)
        immediates.append({'label': label, 'site_va': hex(va),
                           'file_offset': hex(file_offset(secs, va, size, len(data))),
                           'instruction_bytes': raw.hex(), 'encoding': encoding,
                           'value_hex': hex(value), 'value_decimal': value})
    relocations = relocation_rows(data, secs)
    relocation_targets = {int(row['slot_va'], 16): int(row['addend_va'], 16)
                          for row in relocations}
    prior_executors = [f for f in all_frames if f['start'] == 0x47f3090]
    require(len(prior_executors) == 1 and table[0x47f3090]['fde'] == prior_executors[0]['fde'],
            'prior executor unwind boundary changed')
    prior_executor = prior_executors[0]
    executable_extent(secs, prior_executor['start'], prior_executor['end'])
    action_table = bounded_relative_table(data, secs, 0x6fd0ec, 4,
                                          prior_executor['start'], prior_executor['end'])
    journal = by_start[0x4675da0]
    journal_table = bounded_relative_table(data, secs, 0x6f7034, 15,
                                           journal['start'], journal['end'])
    next_delta = struct.unpack('<i', read_at(data, secs, 0x6f7034 + 15 * 4, 4))[0]
    next_target = 0x6f7034 + next_delta
    require(not journal['start'] <= next_target < journal['end'], 'journal prefix boundary changed')
    key = read_at(data, secs, 0x574f0c0, 20)
    require(key == b'\0' * 19 + b'\x09', 'prior address-09 key changed')
    empty_hash = read_at(data, secs, 0x206160, 16) + read_at(data, secs, 0x204be0, 16)
    require(empty_hash.hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
            'selected code-hash comparison bytes changed')
    locations = []
    for site, va, string_va, expected_suffix in LOCATION_SITES:
        require(any(f['start'] <= site and site + 7 <= f['end'] for f in frames),
                'location LEA outside selected FDE')
        raw = read_at(data, secs, site, 7)
        require(decode_rip_lea(site, raw) == va and relocation_targets.get(va) == string_va,
                'location LEA or relocation changed')
        location = source_location(data, secs, va, string_va, expected_suffix)
        location.update({'site_va': hex(site), 'site_bytes': raw.hex()})
        locations.append(location)
    eof_diagnostic = read_at(data, secs, 0x714473, 10)
    subcontainer_diagnostic = read_at(data, secs, 0x71447d, 24)
    require(eof_diagnostic == b'EOF is set' and
            subcontainer_diagnostic == b'Subcontainer is verified', 'diagnostic bytes changed')
    bindings = []
    for table_base, descriptor, adapter in ((0x5723e88, 0x5745e00, 0x4da6f00),
                                             (0x5724688, 0x5745cb0, 0x4da5f30)):
        require(relocation_targets.get(table_base + 0xec * 8) == 0x4c98d40 and
                relocation_targets.get(descriptor + 0x28) == adapter,
                'callback table and descriptor relocation mismatch')
        immediate = read_at(data, secs, adapter + 13, 5)
        require(immediate[0] == 0xba, 'callback immediate encoding changed')
        bindings.append({'table_base_va': hex(table_base),
                         'opcode_ec_slot_va': hex(table_base + 0xec * 8),
                         'descriptor_base_va': hex(descriptor),
                         'descriptor_method_slot_va': hex(descriptor + 0x28),
                         'adapter_va': hex(adapter), 'immediate_bytes': immediate.hex(),
                         'revision_byte': struct.unpack('<I', immediate[1:])[0]})
    links = {'target_sha256': actual_digest, 'callback_bindings': bindings,
             'address_09_key_va': '0x574f0c0',
             'address_09_key_file_offset': hex(file_offset(secs, 0x574f0c0, 20, len(data))),
             'address_09_key_hex': key.hex(),
             'account_hash_16_0_va': '0x206160', 'account_hash_16_1_va': '0x204be0',
             'account_hash_hex': empty_hash.hex(),
             'location_records': locations,
             'diagnostics': [{'va': '0x714473', 'bytes': eof_diagnostic.hex()},
                             {'va': '0x71447d', 'bytes': subcontainer_diagnostic.hex()}],
             'action_table_base_va': '0x6fd0ec', 'action_table_selected_entries': action_table,
             'journal_table_base_va': '0x6f7034', 'journal_table_selected_entries': journal_table,
             'journal_first_unselected_index': 15, 'journal_first_unselected_target_va': hex(next_target),
             'limitations': 'Data slots and selected instruction windows do not prove live callback installation, capture execution, or all valid table tags.'}
    summary = {'target_sha256': actual_digest, 'selected_fdes': len(functions),
               'selected_body_bytes': sum(row['size'] for row in functions),
               'reviewed_windows': len(windows), 'selected_transfers': len(transfers),
               'selected_immediates': len(immediates),
               'selected_relative_relocations': len(relocations),
               'action_table_selected_entries': len(action_table),
               'journal_table_selected_entries': len(journal_table),
               'lsda_tables': len(exceptions),
               'lsda_call_site_entries': sum(len(x['entries']) for x in exceptions),
               'limitations': 'Selected FDEs and fixed windows are bounded static evidence, not complete control flow or node coverage.'}
    return {
        'functions.tsv': tsv_bytes(['start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'role'], functions),
        'windows.tsv': tsv_bytes(['label', 'start_va', 'end_va', 'file_offset', 'bytes'], windows),
        'transfers.tsv': tsv_bytes(['label', 'site_va', 'kind', 'target_or_slot_va', 'bytes'], transfers),
        'immediates.tsv': tsv_bytes(['label', 'site_va', 'file_offset', 'instruction_bytes',
                                    'encoding', 'value_hex', 'value_decimal'], immediates),
        'relocations.tsv': tsv_bytes(['label', 'slot_va', 'rela_file_offset', 'info', 'addend_va', 'raw'], relocations),
        'function-bytes.json': json_bytes(bodies),
        'unwind.json': json_bytes(unwind),
        'exceptions.json': json_bytes(exceptions),
        'linkage.json': json_bytes(links),
        'summary.json': json_bytes(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    # Complete authentication and collection before creating or changing output files.
    outputs = collect((ROOT / TARGET).read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(outputs):
        (args.out / name).write_bytes(outputs[name])
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print(f'evm_create_collision94: {error}', file=sys.stderr)
        raise SystemExit(1)
