#!/usr/bin/env python3
"""Extract the node-94 private CREATE-family path without executing captured code."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

# fde_extents imports its sibling elf_index by module name.
_TOOL_DIR = Path(__file__).resolve().parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = _TOOL_DIR.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selection is by actual FDE start. End and digest are independent fixed controls;
# an FDE is an unwind interval, not proof of a source function boundary.
FUNCTIONS = (
    (0x24f0410, 0x24f07d4, 'aa514de2b2f4bed80a93afe40173840ea12988e2909366703e7dd4e5da72ebf0', 'opcode_f0'),
    (0x24f07e0, 0x24f0bdf, 'c8506367a7cc83c26d360085ccaedce6676e1695970781bcabc7bc8d9a0cdb65', 'opcode_f5'),
    (0x276e8c0, 0x276e939, '5d3b8f9bbcc8c5df57fad168344916745bcc54ae7eb65c6d4ff97dafa3687d93', 'revision_18_frame_adapter'),
    (0x2787ca0, 0x2788044, '9717060912402341eb4e6c6bf43b3fd1712e79f2aabf2d9da6c0618cea1efea6', 'creation_checkpoint_and_transfer'),
    (0x2788220, 0x278834a, '84ac861a20325c0a551757049485dc56c7369f723a3bb4a480fad2edb0cf74b6', 'caller_nonce_journal'),
    (0x278b410, 0x278bdb0, '74ccecbb04416daf8317e43b2b144ef94654199941491e70421efe3f7a52326f', 'creation_frame_and_membership'),
    (0x27c52e0, 0x27c53ef, 'd7fd76a930c22767b574377acb81fd996ba5a8dac27d1c6f9e35f0be07537576', 'address_membership_probe'),
    (0x4c95d80, 0x4c96144, 'ca77ddb3c88058b4d5deaa88a2e912307c85a04659374498e294b5328531ed48', 'standard_revision18_opcode_f0'),
    (0x4c96150, 0x4c9651b, '9b3aee09cbbf006cd0e1941f94e5fb4de9a2959cfa53ca1d05336cddafefa096', 'standard_revision9_opcode_f0'),
    (0x4c96540, 0x4c9693f, 'e4f81aa48e335f7d4e74efba79e8e8f3c8567941c13e86fbcaa261a8899f84ed', 'standard_revision18_opcode_f5'),
    (0x4c96d10, 0x4c9710e, '0aba20c5bdac32f6907307066ea08adbb2df255a9d9d01811f483fb9f3de6c11', 'standard_revision9_opcode_f5'),
)

# Reviewed instruction-bounded windows. The bytes pin the specific machine
# instruction forms from which the packet's selected interpretation follows.
PINS = (
    ('create_static_gate', 0x24f041e, '80bff201000001750cc687f301000057e9ef020000'),
    ('create_stack_gate', 0x24f0433, '488b97280100004883fa03730cc687f30100005be9d6020000'),
    ('create_stack_pop', 0x24f047f, '4a8b4c09d84883c2fd4889972801000048c1e205'),
    ('create_size_upper_limbs', 0x24f0493, '4d8b5411104d0b5411084d0b541118740cc687f301000054e972020000498b1411'),
    ('create_size_gate', 0x24f04de, '488bb6d800000041b900c0000083be1001000001750f4c8b8e180100004d85c9780f4d01c940b6644c39ca0f87f8010000'),
    ('create_word_charge', 0x24f050f, '4889d64883c61f49c7c2ffffffff4c0f43d649c1ea044983e2fe4c8b8fe001000040b6504d29d10f82cb0100004c898fe0010000'),
    ('create_offset_upper_limbs', 0x24f0543, '4c09c040b6544809c80f85b5010000'),
    ('create_memory_bounds', 0x24f0552, '4c89f14801d148c7c0ffffffff480f43c1488b8ff0000000482b8f100100000f82ba0100004839c80f87560100004c89f04801d00f82b4010000488bb7e80000004989ff4803b7100100004c01f6488d7c2460'),
    ('create_copy_input', 0x24f059d, '4c01f6488d7c2460ff1585fc2703'),
    ('create_base_gas_and_forward', 0x24f05e9, '488b87e001000040b650483d007d00000f820801000048050083ffff4889c148c1e9064829c848898fe0010000'),
    ('create_frame_fields', 0x24f0616, '8b8f90000000898c24e00000004989ff0f1087800000000f118424d00000000f2804240f284c24100f118424880000000f118c249800000048c7442460000000000f284424400f284c24500f118424a80000000f118c24b800000048898424c8000000bf88000000'),
    ('create_action_publish', 0x24f0689, '4889c3488d742460ba880000004889c7ff1541d92703498dbf50010000e895cf010049899f5001000041c687880100006d41c687f301000020eb5e'),
    ('create_memory_failure', 0x24f06d6, '4989d7488d8fe00000004989fc488db7d80100004889cf4889c2ff154a38280340b65184c04c89e74c89fa0f8579feffff4088b7f3010000488b0424488b742408488b5424104889dfff5020'),
    ('create_unwind_publication', 0x24f0786, '4989c649899f5001000041c687880100006d4c89f7'),
    ('create2_static_gate', 0x24f07ee, '80bff201000001750cc687f301000057e906030000'),
    ('create2_stack_gate', 0x24f0803, '488b8f280100004883f903730cc687f30100005be9ed020000'),
    ('create2_stack_pop', 0x24f085a, '4883c1fd48898f280100004989ca'),
    ('create2_size_upper_limbs', 0x24f0868, '49c1e2054f8b5c11104f0b5c11084f0b5c1118740cc687f301000054e9800200004f8b3411'),
    ('create2_size_gate', 0x24f08b7, '488bb6d8000000b900c0000083be1001000001750f488b8e180100004885c9780f4801c940b6644939ce0f8707020000'),
    ('create2_word_charge', 0x24f08e7, '4c89f14883c11f49c7c1ffffffff4c0f43c949c1e9044983e1fe488b8fe001000040b6504c29c90f82da01000048898fe0010000'),
    ('create2_offset_upper_limbs', 0x24f091b, '4c09c040b6544809d00f85c4010000'),
    ('create2_memory_bounds', 0x24f092a, '4c89f84c01f048c7c2ffffffff480f43d0488b87f0000000482b87100100000f82f30100004839c20f87c00100004c89f84c01f00f82ed010000488bb7e80000004989fc4803b7100100004c01fe'),
    ('create2_copy_input', 0x24f0978, '488d7c24484c89f2ff15aaf82703'),
    ('create2_salt_pop', 0x24f09c4, '498b8c24280100004885c90f841601000048ffc948898f28010000'),
    ('create2_base_gas_and_hash_charge', 0x24f09df, '4983c61f48c7c0ffffffff490f43c648c1e805488d0440488d1445007d0000488b87e001000040b6504829d00f82dd000000'),
    ('create2_salt_load', 0x24f0a11, '488b972001000048c1e1050f10040a0f104c0a100f114c24600f11442450'),
    ('create2_forward', 0x24f0a2f, '4889c148c1e9064829c848898fe0010000'),
    ('create2_frame_fields', 0x24f0a40, '8b8f90000000898c24c80000004989ff0f1087800000000f118424b80000000f2804240f284c24100f114424700f118c248000000048c7442448010000000f288424d00000000f288c24e00000000f118424900000000f118c24a000000048898424b0000000bf88000000'),
    ('create2_action_publish', 0x24f0ab3, '488d742448ba880000004889c7ff151ad52703498dbf50010000e86ecb010049899f5001000041c687880100006d41c687f301000020eb1e'),
    ('create2_failure_and_drop', 0x24f0aeb, '40b65b4088b7f3010000488b0424488b742408488b5424104889dfff5020'),
    ('create2_memory_failure', 0x24f0b18, '488d87e00000004989fc488db7d80100004889c7ff150e34280340b65184c04c89e70f8518feffffebac'),
    ('create2_unwind_publication', 0x24f0b78, '4989c649899f5001000041c687880100006d4c89f7e87ef51603'),
    ('callback_adapter', 0x276e8c0, '415653504889cb4989fe4889d6ba12000000e839cb0100488b4328488b7330488d7b40488b5338ff5020be880000004889df31d2ff1516f7ff024c89f04883c4085b415ec3'),
    ('depth_guard', 0x278b421, '4989ce4889fb4881bea8000000000400007642498b466848c70301000000488d0dc21cf30248894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434011c6434800e928090000'),
    ('revision_prefix_guard', 0x278b476, '4989f789d580fa127627488b05217efe02488b5010493956387216488b7808498b7630ff15d92efe0285c00f846b040000'),
    ('caller_load', 0x278b4a7, '418b868000000089442450410f1046700f29442440498b8fe0000000488dbc24f0010000488d5424404c89fee888bfffff80bc24f0010000050f8587000000'),
    ('balance_comparison', 0x278b4ee, '488b42584d8d6e48498b4e604839c87527488b4250498b4e584839c8751a488b4248498b4e504839c8750d488b4240498b4d004839c8746d4839c87368'),
    ('balance_fail_status', 0x278b526, '4839c87368498b466848c70301000000488d0dcb1bf30248894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434012c6434800e931080000'),
    ('caller_nonce_update', 0x278b593, '4d8d6670418b44241089842400020000410f1004240f298424f0010000488db424f00100004c89ffe860ccffffa8010f8408030000'),
    ('scheme_branch', 0x278b5db, '41803e004c89ac24480100000f8467030000'),
    ('salt_load_and_swap', 0x278b667, '410f1046080f29842430010000660fefd2f3410f6f4618660f6fc8660f60ca660f70c94ef20f70c91bf30f70c91b660f68c2660f70c04ef20f70c01bf30f70c01b660f67c1660f7f842420010000'),
    ('payload_hash_call', 0x278b6b5, '488d7c2440ff15182bfe024c8dac24f0010000bae00000004c89ef488d742440ff150529fe02488db42450010000ba200000004c89efff15ef2afe02'),
    ('preimage_caller_and_digest', 0x278b6f1, '0f288424500100000f288c24600100000f118c24b50100000f118424a5010000410f1004240f11842471010000418b44241089842481010000c6842470010000ff'),
    ('preimage_salt_halves', 0x278b732, '0f288424200100000f11842485010000660f6f8c2430010000660f6fc1660fefd2660f60c2660f70c04ef20f70c01bf30f70c01b660f68ca660f70c94ef20f70c91bf30f70c91b660f67c8f30f7f8c2495010000'),
    ('preimage_hash', 0x278b809, '488d7c2440488db42470010000ba55000000ff15b729fe024c8dac24f0010000bae00000004c89ef488d742440ff15a427fe024889e6ba200000004c89efff159329fe02'),
    ('digest_slice_owned_probe', 0x278b84d, '0f1044240c0f294424208b44241c894424304983bfe8000000004c8bac24480100000f8467020000498dbfe8000000488d742420e85a9a030084c00f8467020000'),
    ('hit_status', 0x278b88e, '498b466848c70301000000488d0d6818f30248894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c643405ec6434800e9ce040000'),
    ('nonce_overflow_status', 0x278b8d0, '498b466848c70301000000488d0d2618f30248894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434002c6434800e98c040000'),
    ('prefix_reject_status', 0x278b912, '498b466848c70301000000488d0de417f30248894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c6434013c6434800e94a040000'),
    ('nonce_rlp_head', 0x278b954, '4889d148ffc9480fbdf183f638c1ee034889f04883f01f4881f980000000ba17000000480f43d08d42bf880424c64424019448c744241600000000c644241e00410f1004240f11442402418b44241089442412'),
    ('nonce_rlp_number', 0x278b9a7, '4885c9740f4881f980000000730d884c2416eb3fc644241680eb38480fc948898c24f0010000b8080000004829f08d48804801e64881c6f0010000884c2416488d7c24174989d54889c2ff15e925fe024c89ea'),
    ('nonce_rlp_hash', 0x278ba6f, '488d7c24404889e6ff155b27fe024c8dac24f0010000bae00000004c89ef488d742440ff154825fe02488db42470010000ba200000004c89efff153227fe020f1084247c0100000f294424208b84248c01000089442430'),
    ('borrowed_probe', 0x278bac6, '4983bfe8000000004c8bac24480100000f8599fdffff498bbff0000000488d742420e8f397030084c00f8599fdffff'),
    ('miss_load', 0x278baf5, '498b8fe0000000488dbc24f0010000488d5424204c89fee84fb9ffff0fb68424f00100003c050f85b2000000'),
    ('checkpoint_handoff', 0x278bb56, '440fb6cd4c89ed4c8d6c2440488d942470010000488d4c24204c8d8424f00100004c89ef4c89fee81ec1ffff807c2440010f8598000000'),
    ('checkpoint_error_propagation', 0x278bb8d, '0fb6442441498b4e6848c70301000000488d156415f3024889530848c74310010000000f57c00f11431848894b2848894b3048c7433800000000884340c6434800e9cb010000'),
    ('post_checkpoint_success', 0x278bc25, '488b4424484889842430010000488b4424504889842420010000498d7640498b4628498b5630498b4e38488dbc24f0030000ff10'),
    ('nonce_overflow_guard', 0x2788231, '4883c730e8464404004885c00f84e00000004889c348837860ff0f84c1000000'),
    ('nonce_touch_journal', 0x278825e, 'f683b0000000044d8b7f204c8d244075494f8d2ce74b8b6ce7f84b3b6ce7e8750e4b8d3ce74883c7e8ff15e3affe02498b45f0486bcd58c6040802410f10060f11440801418b56108954081148ffc549896df8808bb000000004'),
    ('nonce_increment_journal', 0x27882b8, '4f8d2ce74b8b6ce7f84b3b6ce7e8750e4b8d3ce74883c7e8ff159aaffe02498b45f0486bcd58c6040804410f10060f11440801418b56108954081148ffc549896df8488b53604883faff743948ffc248895360b801000000eb02'),
    ('empty_probe_and_hash_a', 0x27c52e0, '48837f18000f8401010000488b15ee90fa024c8b124c8b460c4d31d0488b0e488b46084833420849f7e04989c04989d1488b56044c31d248334f204889c848f7e24931d14d31c14c31c8'),
    ('hash_finalize_and_fingerprint', 0x27c532a, '4883f01449f7e24831c24889d048c1e839488b0f488b7f08660f6ec0660f60c0f20f70c000660f70c0444c8d41d04531c9660f76c94821fa'),
    ('candidate_group', 0x27c5362, 'f30f6f1411660f6fda660f74d866440fd7d34585d27457f3410fbcc24801d04821f848f7d8488d044048c1e004'),
    ('full_key_compare', 0x27c538f, 'f30f6f1ef3410f6f2400660f74e3660f6e5e1066410f6e6c0010660f74eb660fdbec66440fd7ddb0014181fbffff0000742d'),
    ('empty_and_triangular_probe', 0x27c53c1, '418d42ff664421d04189c275ab6690660f74d1660fd7c285c075104c01ca4883c2104983c110e973ffffff31c0c3'),
    ('checkpoint_begin', 0x2787cb1, '4c89442430488b86a80000004883f8ff0f84610300004989cf4989f54889fb44894c242c4889542458488b4e1048894c24204c8b762848ffc0488986a80000004c3b7618750a498d7d18ff1527d1fe02498b45204b8d0c7648c704c80000000048c744c8080800000048c744c810000000004d8d66014d896528498d6d30'),
    ('checkpoint_account_guards', 0x2787d3a, 'e8414904004885c00f84c60200004989c7f30f6f4068f30f6f4878660f740d83cea7fd660f7405fbe3a7fd660fdbc1660fd7c03dffff0000750749837f6000742a4c89ef488b7424204c89f2e865fdffffc643015eb00188034881c4880000005b415c415d415e415f5dc3'),
    ('checkpoint_touch_and_journal', 0x2787da5, '498b45204b8d0c64488d14c841808fb000000001488d04c84883c0e848894424104c8b62f848895424084c3b62e8750b488b7c2410ff1590b4fe02488b742408488b46f0496bcc58c6040805488b542418f30f6f02f30f7f4408018b52108954081149ffc44c8966f841833f0474084c89ffe84499ffff49c70704000000'),
    ('checkpoint_overflow_test', 0x2787e7d, '4c8b442430498b104d8b58084d8b6010498b47504c01e0400f92c6498b4f4048895424504801d1498b57484c11da4883d000400f92c74008f74d8b50184d8b47584f8d0c02400fb6f783e6014c01ce400f92c74c895424484d01d00f82170100004084ff0f850e010000'),
    ('checkpoint_balance_and_nonce', 0x2787ee7, '4c896424384c895c24404c8b6c245049894f40498957484989475049897758807c242c04760849c7476001000000'),
    ('checkpoint_source_debit', 0x2787f15, '4889ef4c8b6424584c89e6e85b4704004885c00f84ed0000004c296840488b4c244048194848488b4c243848194850488b4c244848194858'),
    ('checkpoint_transfer_journal', 0x2787f7d, '488b742408488b46f0496bcf58c6040803418b54241089540811410f1004240f11440801488b5424180f10020f114408158b521089540825f30f6f442461f30f6f4c2471f30f7f440829f30f7f4c0839488b942480000000488954084849ffc74c897ef8'),
    ('checkpoint_overflow_failure', 0x2787ff5, '4c89ef488b7424204c89f2e8ebfaffffc643015fe981fdffff'),
)

PINS += (
    ('caller_error_tag', 0x278b56d, '0f288424f0010000660f6f8c24000200000f114308f30f7f4b1848c70304000000e90b080000'),
    ('candidate_error_tag', 0x278bbd3, '8b8c24f10100008b9424f401000089530c894b09488b8c24f80100000fb6942400020000488bb4240802000048897320488bb424010200004889731988430848894b1088531848c70304000000e979010000'),
    ('std9_f0_gates', 0x4c96161, '80bff201000001750cc687f301000057e9e0020000488b8f280100004883f903730cc687f30100005be9c7020000'),
    ('std9_f0_zero_and_offset', 0x4c96218, '4d85f6741f4809d04809f07437b1544c8d2dcacfaa0041bf010000004531f6e90702000041bf01000000488b87e0010000b150483d007d00000f83de000000e9e7010000'),
    ('std9_f0_memory_bounds', 0x4c9625c, '4889e84c01f048c7c2ffffffff480f43d0488b87f0000000482b87100100000f82e70100004839c20f877f0100004889e84c01f00f82e1010000'),
    ('std9_f0_copy_before_base', 0x4c96296, '4c8ba7e80000004889fb4c8baf100100004c89f7ff15287dad004885c00f84cd0100004989c74d01ec4901ec4889c74c89e64c89f2ff150f7dad004c89fd4883cd0141f6c701490f45ef4c8b2d617ead004c0f442d517ead00488b0424488b742408488b542410488d7c2418ff50204c892c244c897c24084c8974241048896c24184889df4c8d442418'),
    ('std9_f0_base_and_forward', 0x4c96320, '488b87e0010000b150483d007d00000f820e01000048050083ffff4889c148c1e9064829c848898fe0010000'),
    ('std9_f0_frame_publish', 0x4c963a9, 'bf88000000ff15247cad004885c0743b4889c3488d742440ba880000004889c7ff15117cad00498dbe50010000e865df110049899e5001000041c686880100006d41c686f301000020'),
    ('std9_f5_gates', 0x4c96d21, '80bff201000001750cc687f301000057e9d7020000488b87280100004883f803730cc687f30100005be9be020000'),
    ('std9_f5_length_and_offset', 0x4c96ddb, '4d85f674234809d14809f10f8438010000b1544c8d2d03c4aa0041bf010000004531f6e9f701000041bf01000000'),
    ('std9_f5_memory_bounds', 0x4c96f24, '4889e84c01f048c7c2ffffffff480f43d0488b87f0000000482b87100100000f82120100004839c20f87cd0000004889e84c01f00f820c010000'),
    ('std9_f5_copy_before_salt', 0x4c96f5e, '4c8ba7e80000004889fb4c8baf100100004c89f7ff156070ad004885c00f84f80000004989c74d01ec4901ec4889c74c89e64c89f2ff154770ad004c89fd4883cd0141f6c701490f45ef4c8b2d9971ad004c0f442d8971ad00488b0424488b742408488b542410488d7c2418ff50204c892c244c897c24084c8974241048896c24184889df488b83280100004c8d4424184885c00f851afeffff'),
    ('std9_f5_salt_and_gas', 0x4c96e09, '4885c00f84e601000048ffc8488987280100004c89f14883c11f48c7c2ffffffff480f43d148c1ea05488d0c52488d344d007d0000488b97e0010000b1504829f20f82aa010000'),
    ('std9_f5_forward', 0x4c96e6e, '4889d048c1e8064829c2488987e0010000'),
    ('std9_f5_frame_publish', 0x4c96edc, 'bf88000000e83acc14004889c3488d742440ba880000004889c7ff15e470ad00498dbe50010000e838d4110049899e5001000041c686880100006d41c686f301000020'),
    ('std18_f0_gates', 0x4c95d8e, '80bff201000001750cc687f301000057e9ef020000488b97280100004883fa03730cc687f30100005be9d6020000'),
    ('std18_f0_size_gate', 0x4c95e4e, '488bb6d800000041b900c0000083be1001000001750f4c8b8e180100004d85c9780f4d01c940b6644c39ca0f87f8010000'),
    ('std18_f0_word_charge', 0x4c95e7f, '4889d64883c61f49c7c2ffffffff4c0f43d649c1ea044983e2fe4c8b8fe001000040b6504d29d10f82cb0100004c898fe0010000'),
    ('std18_f0_base_gas', 0x4c95f59, '488b87e001000040b650483d007d00000f820801000048050083ffff4889c148c1e9064829c848898fe0010000'),
    ('std18_f0_frame_publish', 0x4c95fe9, 'bf88000000ff15e47fad004885c0743b4889c3488d742460ba880000004889c7ff15d17fad00498dbf50010000e825e3110049899f5001000041c687880100006d41c687f301000020'),
    ('std18_f5_gates', 0x4c9654e, '80bff201000001750cc687f301000057e906030000488b8f280100004883f903730cc687f30100005be9ed020000'),
    ('std18_f5_size_gate', 0x4c96617, '488bb6d8000000b900c0000083be1001000001750f488b8e180100004885c9780f4801c940b6644939ce0f8707020000'),
    ('std18_f5_word_charge', 0x4c96647, '4c89f14883c11f49c7c1ffffffff4c0f43c949c1e9044983e1fe488b8fe001000040b6504c29c90f82da01000048898fe0010000'),
    ('std18_f5_salt_base_gas', 0x4c96724, '498b8c24280100004885c90f841601000048ffc948898f280100004983c61f48c7c0ffffffff490f43c648c1e805488d0440488d1445007d0000488b87e001000040b6504829d00f82dd000000'),
    ('std18_f5_frame_publish', 0x4c96806, 'bf88000000e810d314004889c3488d742448ba880000004889c7ff15ba77ad00498dbf50010000e80edb110049899f5001000041c687880100006d41c687f301000020'),
)

# Only these transfer sites are decoded. These do not claim a complete CFG.
# The target column is an independent corruption check, not a source symbol.
TRANSFERS = (
    ('f0_static_continue', 0x24f0425, 0x24f0433),
    ('f0_stack_continue', 0x24f043e, 0x24f044c),
    ('f0_size_limb_continue', 0x24f04a2, 0x24f04b0),
    ('f0_zero_length', 0x24f04d8, 0x24f05e9),
    ('f0_length_exceeds_cap', 0x24f0509, 0x24f0707),
    ('f0_word_charge_borrow', 0x24f0536, 0x24f0707),
    ('f0_offset_high', 0x24f054c, 0x24f0707),
    ('f0_memory_grow', 0x24f057a, 0x24f06d6),
    ('f0_memory_window_underflow', 0x24f0571, 0x24f0731),
    ('f0_memory_range_overflow', 0x24f0586, 0x24f0740),
    ('f0_base_gas_borrow', 0x24f05f9, 0x24f0707),
    ('f0_old_action_drop', 0x24f06a6, 0x250d640),
    ('f0_unwind_resume', 0x24f079b, 0x5660110),
    ('f0_memory_grow_success', 0x24f0701, 0x24f0580),
    ('f5_static_continue', 0x24f07f5, 0x24f0803),
    ('f5_stack_continue', 0x24f080e, 0x24f081c),
    ('f5_size_limb_continue', 0x24f087b, 0x24f0889),
    ('f5_zero_length', 0x24f08b1, 0x24f09cc),
    ('f5_length_exceeds_cap', 0x24f08e1, 0x24f0aee),
    ('f5_word_charge_borrow', 0x24f090e, 0x24f0aee),
    ('f5_offset_high', 0x24f0924, 0x24f0aee),
    ('f5_memory_grow', 0x24f0952, 0x24f0b18),
    ('f5_memory_window_underflow', 0x24f0949, 0x24f0b42),
    ('f5_memory_range_overflow', 0x24f095e, 0x24f0b51),
    ('f5_missing_fourth_stack_word', 0x24f09cf, 0x24f0aeb),
    ('f5_base_and_hash_gas_borrow', 0x24f0a0b, 0x24f0aee),
    ('f5_old_action_drop', 0x24f0acd, 0x250d640),
    ('f5_unwind_resume', 0x24f0b8d, 0x5660110),
    ('f5_memory_grow_success', 0x24f0b3a, 0x24f0958),
    ('adapter_to_creation', 0x276e8d2, 0x278b410),
    ('adapter_payload_unwind_resume', 0x276e91b, 0x5660110),
    ('adapter_call_unwind_resume', 0x276e92e, 0x5660110),
    ('depth_continue', 0x278b432, 0x278b476),
    ('revision_guard', 0x278b47e, 0x278b4a7),
    ('prefix_length_guard', 0x278b48f, 0x278b4a7),
    ('prefix_equal_reject', 0x278b4a1, 0x278b912),
    ('caller_load', 0x278b4d3, 0x2787460),
    ('caller_load_error', 0x278b4e0, 0x278b56d),
    ('funds_equal', 0x278b524, 0x278b593),
    ('funds_sufficient', 0x278b529, 0x278b593),
    ('nonce_update', 0x278b5bb, 0x2788220),
    ('nonce_rejected', 0x278b5c2, 0x278b8d0),
    ('plain_creation', 0x278b5e7, 0x278b954),
    ('borrowed_selection', 0x278b86f, 0x278badc),
    ('owned_membership', 0x278b881, 0x27c52e0),
    ('owned_miss', 0x278b888, 0x278baf5),
    ('nonce_zero_rlp', 0x278b9aa, 0x278b9bb),
    ('nonce_long_rlp', 0x278b9b3, 0x278b9c2),
    ('plain_owned_selection', 0x278bad6, 0x278b875),
    ('borrowed_membership', 0x278bae8, 0x27c52e0),
    ('borrowed_hit', 0x278baef, 0x278b88e),
    ('created_account_load', 0x278bb0c, 0x2787460),
    ('created_account_error', 0x278bb1b, 0x278bbd3),
    ('checkpoint', 0x278bb7d, 0x2787ca0),
    ('checkpoint_success', 0x278bb87, 0x278bc25),
    ('nonce_overflow', 0x278824b, 0x2788312),
    ('nonce_touch_skip', 0x278826d, 0x27882b8),
    ('lookup_empty', 0x27c52e5, 0x27c53ec),
    ('lookup_no_fingerprint', 0x27c5377, 0x27c53d0),
    ('lookup_key_match', 0x27c53bf, 0x27c53ee),
    ('lookup_more_candidates', 0x27c53cc, 0x27c5379),
    ('lookup_empty_control', 0x27c53da, 0x27c53ec),
    ('lookup_next_group', 0x27c53e7, 0x27c535f),
    ('checkpoint_depth_overflow', 0x2787cc1, 0x2788028),
    ('checkpoint_find_target', 0x2787d3a, 0x27cc680),
    ('checkpoint_missing_target', 0x2787d42, 0x278800e),
    ('checkpoint_hash_mismatch', 0x2787d72, 0x2787d7b),
    ('checkpoint_nonce_zero', 0x2787d79, 0x2787da5),
    ('checkpoint_collision_rollback', 0x2787d86, 0x2787af0),
    ('checkpoint_carry_first', 0x2787ed8, 0x2787ff5),
    ('checkpoint_carry_second', 0x2787ee1, 0x2787ff5),
    ('checkpoint_nonce_revision', 0x2787f0b, 0x2787f15),
    ('checkpoint_find_source', 0x2787f20, 0x27cc680),
    ('checkpoint_add_overflow_rollback', 0x2788000, 0x2787af0),
    ('std9_f0_zero_length', 0x4c9621b, 0x4c9623c),
    ('std9_f0_offset_valid', 0x4c96223, 0x4c9625c),
    ('std9_f0_memory_grow', 0x4c96284, 0x4c96409),
    ('std9_f0_base_gas_failure', 0x4c9632f, 0x4c96443),
    ('std9_f5_zero_length', 0x4c96dde, 0x4c96e03),
    ('std9_f5_offset_valid', 0x4c96de6, 0x4c96f24),
    ('std9_f5_missing_salt', 0x4c96e0c, 0x4c96ff8),
    ('std9_f5_base_gas_failure', 0x4c96e4a, 0x4c96ffa),
    ('std9_f5_memory_grow', 0x4c96f4c, 0x4c9701f),
    ('std9_f5_salt_after_copy', 0x4c96ff2, 0x4c96e12),
    ('std18_f0_size_limit', 0x4c95e79, 0x4c96077),
    ('std18_f0_word_charge_failure', 0x4c95ea6, 0x4c96077),
    ('std18_f0_base_gas_failure', 0x4c95f69, 0x4c96077),
    ('std18_f5_size_limit', 0x4c96641, 0x4c9684e),
    ('std18_f5_word_charge_failure', 0x4c9666e, 0x4c9684e),
    ('std18_f5_missing_salt', 0x4c9672f, 0x4c9684b),
    ('std18_f5_base_gas_failure', 0x4c9676b, 0x4c9684e),
)

# File-backed relocation entries used at the integration boundary and by the
# selected routines. Both SHT_RELA sections are checked for duplicate offsets.
RELOCATIONS = (
    (0x56acf08, 0x24f0410, 'opcode_f0_slot'),
    (0x56acf30, 0x24f07e0, 'opcode_f5_slot'),
    (0x56bfb58, 0x276e8c0, 'creation_callback_method'),
    (0x574f0b0, 0x4e9d2a0, 'prior_address09_callback'),
    (0x576e1d8, 0x4f59a10, 'sponge_absorb_boundary'),
    (0x576e1e0, 0x4f59e40, 'sponge_final_boundary'),
    (0x576e3e0, 0x5788348, 'process_seed_pointer'),
    (0x5770230, 0x1511010, 'input_copy_boundary'),
    (0x5774e28, 0x4e7c550, 'journal_growth_boundary'),
    (0x5774e40, 0x4e8fa30, 'post_checkpoint_helper_one'),
    (0x5774e50, 0x4e88b50, 'post_checkpoint_helper_two'),
    (0x5724608, 0x4c96150, 'standard_revision9_f0_slot'),
    (0x5724630, 0x4c96d10, 'standard_revision9_f5_slot'),
    (0x5724e08, 0x4c95d80, 'standard_revision18_f0_slot'),
    (0x5724e30, 0x4c96540, 'standard_revision18_f5_slot'),
    (0x56b8318, 0x200b23, 'private_memory_location_a'),
    (0x56b83a0, 0x200b23, 'private_memory_location_b'),
    (0x5743460, 0x200b23, 'standard_memory_location_a'),
    (0x57434c0, 0x200b23, 'standard_memory_location_b'),
    (0x56be258, 0x1e3a8c, 'checkpoint_location_a'),
    (0x56be270, 0x1e3a8c, 'checkpoint_location_b'),
    (0x56be240, 0x1e3a8c, 'checkpoint_location_c'),
    (0x56be318, 0x1e3a8c, 'nonce_location_a'),
    (0x56be330, 0x1e3a8c, 'nonce_location_b'),
    (0x56be348, 0x1e3a8c, 'nonce_location_c'),
)

class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def authenticate(data):
    actual = hashlib.sha256(data).hexdigest()
    require(actual == DIGEST, 'target digest mismatch')
    return actual


def file_offset(secs, va, size, file_size, *, executable=False):
    """Map an entire allocated, file-backed interval with no ambiguous section."""
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid address or size')
    require(va + size <= 1 << 64, 'address interval overflow')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and s['size']
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'not uniquely file-backed')
    sec = matches[0]
    if executable:
        require(bool(sec['flags'] & 4), 'not executable')
    off = sec['offset'] + va - sec['address']
    require(0 <= off and off + size <= file_size, 'file interval out of bounds')
    return off


def read_at(data, secs, va, size, *, executable=False):
    off = file_offset(secs, va, size, len(data), executable=executable)
    return data[off:off + size]


def verify_pins(data, secs):
    rows = []
    for name, va, expected in PINS:
        pin = bytes.fromhex(expected)
        actual = read_at(data, secs, va, len(pin), executable=True)
        require(actual == pin, 'selected instruction bytes changed: ' + name)
        rows.append({'name': name, 'va': hex(va),
                     'file_offset': hex(file_offset(secs, va, len(pin), len(data), executable=True)),
                     'size': len(pin), 'bytes': actual.hex()})
    return rows


def decode_transfer(data, secs, va):
    first = read_at(data, secs, va, 2, executable=True)
    if first[0] in (0xe8, 0xe9):
        size, kind = 5, 'call' if first[0] == 0xe8 else 'jmp'
        raw = read_at(data, secs, va, size, executable=True)
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif 0x70 <= first[0] <= 0x7f:
        size, kind, raw = 2, 'jcc_' + format(first[0] & 15, 'x'), first
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        size, kind = 6, 'jcc_' + format(first[1] & 15, 'x')
        raw = read_at(data, secs, va, size, executable=True)
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif first[0] == 0xeb:
        size, kind, raw = 2, 'jmp', first
        disp = struct.unpack_from('<b', raw, 1)[0]
    else:
        raise EvidenceError('unsupported selected direct transfer')
    return kind, va + size + disp, raw


def extract_transfers(data, secs):
    out = []
    for name, va, expected_target in TRANSFERS:
        kind, target, raw = decode_transfer(data, secs, va)
        require(target == expected_target, 'selected transfer changed: ' + name)
        require(any(start <= va and va + len(raw) <= end for start, end, _, _ in FUNCTIONS),
                'selected transfer outside selected FDEs')
        out.append({'name': name, 'va': hex(va),
                    'file_offset': hex(file_offset(secs, va, len(raw), len(data), executable=True)),
                    'bytes': raw.hex(), 'kind': kind, 'target_va': hex(target)})
    return out


def read_relative_relocations(data, secs):
    wanted = {off for off, _, _ in RELOCATIONS}
    hits = {off: [] for off in wanted}
    for sec in secs:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'malformed RELA section size')
        for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot in wanted:
                hits[slot].append((sec['name'], pos, info, addend, data[pos:pos + 24].hex()))
    rows = []
    for slot, addend, name in RELOCATIONS:
        require(len(hits[slot]) == 1, 'missing or duplicate selected relocation: ' + name)
        sec_name, off, info, actual_addend, raw = hits[slot][0]
        require(info == 8 and actual_addend == addend, 'wrong RELATIVE relocation: ' + name)
        rows.append({'name': name, 'slot_va': hex(slot), 'section': sec_name,
                     'record_file_offset': hex(off), 'info': hex(info),
                     'addend': hex(actual_addend), 'record_bytes': raw})
    return rows


def record_bytes(data, secs, va):
    length = struct.unpack('<I', read_at(data, secs, va, 4))[0]
    require(4 <= length < 0xffffffff, 'unsupported unwind record length')
    return read_at(data, secs, va, length + 4)


def parse_exception_table(data, secs, frame):
    if frame['lsda'] is None:
        return None
    options = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(options) == 1, 'exception section unavailable or ambiguous')
    sec = options[0]
    pos = file_offset(secs, frame['lsda'], 1, len(data))
    begin, end = pos, sec['offset'] + sec['size']
    require(pos + 2 <= end and data[pos] == 0xff, 'unsupported landing encoding')
    pos += 1
    encoding = data[pos]
    pos += 1
    type_va = None
    if encoding == 0x9b:
        distance, pos = uleb(data, pos, end)
        type_va = sec['address'] + pos - sec['offset'] + distance
        require(type_va <= sec['address'] + sec['size'], 'type table outside exception section')
    else:
        require(encoding == 0xff, 'unsupported type encoding')
    require(pos < end and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, end)
    table_start, table_end = pos, pos + length
    require(table_end <= end, 'exception table outside section')
    entries = []
    while pos < table_end:
        start, pos = uleb(data, pos, table_end)
        span, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        first = frame['start'] + start
        require(frame['start'] <= first and first + span <= frame['end'],
                'exception interval outside FDE')
        require(not landing or frame['start'] <= frame['start'] + landing < frame['end'],
                'exception landing outside FDE')
        entries.append({'start_va': hex(first), 'length': span,
                        'landing_va': hex(frame['start'] + landing) if landing else None,
                        'action': action})
    return {'function_va': hex(frame['start']), 'lsda_va': hex(frame['lsda']),
            'file_offset': hex(begin), 'type_encoding': encoding,
            'type_table_va': hex(type_va) if type_va is not None else None,
            'header_bytes': data[begin:table_start].hex(),
            'call_site_bytes': data[table_start:table_end].hex(), 'entries': entries}


def selected_frames(data, secs, index, frames):
    required = {start for start, _, _, _ in FUNCTIONS}
    found = {}
    for frame in frames:
        start = frame['start']
        if start in required:
            require(start not in found, 'duplicate selected FDE')
            found[start] = frame
    idx = {row['start']: row for row in index if row['start'] in required}
    require(set(found) == required and set(idx) == required, 'selected FDE missing')
    functions, bodies, unwind, exceptions = [], [], [], []
    headers = [s for s in secs if s['name'] == '.eh_frame_hdr' and s['type'] != 8]
    require(len(headers) == 1, 'missing or duplicate unwind header')
    header = headers[0]
    for start, end, expected_hash, role in FUNCTIONS:
        frame = found[start]
        require(frame['end'] == end and idx[start]['fde'] == frame['fde'], 'FDE extent mismatch')
        raw = read_at(data, secs, start, end - start, executable=True)
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_hash, 'selected FDE bytes changed: ' + role)
        offset = file_offset(secs, start, len(raw), len(data), executable=True)
        functions.append({'start_va': hex(start), 'end_va': hex(end), 'size': len(raw),
                          'file_offset': hex(offset), 'fde_va': hex(frame['fde']),
                          'cie_va': hex(frame['cie']),
                          'lsda_va': hex(frame['lsda']) if frame['lsda'] is not None else '',
                          'sha256': digest, 'role': role})
        bodies.append({'start_va': hex(start), 'end_va': hex(end), 'bytes': raw.hex()})
        ix = idx[start]['index']
        ix_offset = header['offset'] + 12 + ix * 8
        unwind.append({'start_va': hex(start), 'header_index': ix,
                       'header_entry_file_offset': hex(ix_offset),
                       'header_entry_bytes': data[ix_offset:ix_offset + 8].hex(),
                       'fde_va': hex(frame['fde']), 'fde_bytes': record_bytes(data, secs, frame['fde']).hex(),
                       'cie_va': hex(frame['cie']), 'cie_bytes': record_bytes(data, secs, frame['cie']).hex()})
        exception = parse_exception_table(data, secs, frame)
        if exception is not None:
            exceptions.append(exception)
    return functions, bodies, unwind, exceptions

# These are integration anchors in previously documented FDEs, not selected
# function bodies. The earlier provider/executor observations remain dependencies.
DEPENDENCIES = (
    ('handler_table_source', 0x2465d61, '488dbc24e0010000488d35186a2403ba00080000'),
    ('creation_descriptor_store', 0x279308f, '4c897350488d0d96caf20248894b58'),
    ('action_table_dispatch', 0x2515cb2, '8d50943c6c0fb6c2ba030000000f42c20fb6c0488d15b8faecfd486304824801d0ffe0'),
    ('creation_callback_call', 0x2515f19, '488b83480200004c8b8350020000498b501048ffca4883e2f0488d34104883c61040b5014531e441b501488dbc24f00100004889da41ff5028'),
    ('standard_revision9_table_lea', 0x44bce6a, '488d3517702601ba00080000'),
    ('standard_revision18_table_lea', 0x44bd991, '488d35f06c2601ba00080000'),
)

# Each row decodes the stack displacement in the selected instruction and
# subtracts the frame base from the tag-store instruction of that opcode.
LANE_STORES = (
    ('f0', 'input_low', 0x24f063e, 4, 4, 16),
    ('f0', 'input_high', 0x24f0646, 4, 4, 16),
    ('f0', 'value_low', 0x24f0661, 4, 4, 16),
    ('f0', 'value_high', 0x24f0669, 4, 4, 16),
    ('f0', 'gas', 0x24f0671, 4, 4, 8),
    ('f0', 'caller_low', 0x24f062d, 4, 4, 16),
    ('f0', 'caller_high', 0x24f061c, 3, 4, 4),
    ('f5', 'salt_low', 0x24f0a2a, 4, 1, 16),
    ('f5', 'salt_high', 0x24f0a25, 4, 1, 16),
    ('f5', 'input_low', 0x24f0a68, 4, 1, 16),
    ('f5', 'input_high', 0x24f0a6d, 4, 4, 16),
    ('f5', 'value_low', 0x24f0a8e, 4, 4, 16),
    ('f5', 'value_high', 0x24f0a96, 4, 4, 16),
    ('f5', 'gas', 0x24f0a9e, 4, 4, 8),
    ('f5', 'caller_low', 0x24f0a57, 4, 4, 16),
    ('f5', 'caller_high', 0x24f0a46, 3, 4, 4),
)

SOURCE_LOCATIONS = (
    (0x24f0731, 0x56b8318, 0x200b23, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', '1bb18872f783dbe2f6a7228989d02718ded52826006f687551918c7b07c8edc0'),
    (0x24f0740, 0x56b83a0, 0x200b23, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', '1bb18872f783dbe2f6a7228989d02718ded52826006f687551918c7b07c8edc0'),
    (0x4c96468, 0x5743460, 0x200b23, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', '1bb18872f783dbe2f6a7228989d02718ded52826006f687551918c7b07c8edc0'),
    (0x4c96477, 0x57434c0, 0x200b23, 'revm-interpreter-15.0.0/src/interpreter/shared_memory.rs', '1bb18872f783dbe2f6a7228989d02718ded52826006f687551918c7b07c8edc0'),
    (0x278800e, 0x56be258, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
    (0x278801b, 0x56be270, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
    (0x2788028, 0x56be240, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
    (0x2788323, 0x56be318, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
    (0x2788330, 0x56be330, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
    (0x278833d, 0x56be348, 0x1e3a8c, 'revm-19.2.0/src/journaled_state.rs', 'f394284fc128d5f58206be6e0286783867270d1c629e7027a9a9bf0f7766d804'),
)


def extract_lanes(data, secs):
    bases = {}
    for opcode, site in (('f0', 0x24f064e), ('f5', 0x24f0a75)):
        raw = read_at(data, secs, site, 9, executable=True)
        require(raw[:4] == b'\x48\xc7\x44\x24', 'frame tag store shape changed')
        bases[opcode] = raw[4]
    out = []
    for opcode, name, site, disp_index, disp_size, width in LANE_STORES:
        raw = read_at(data, secs, site, disp_index + disp_size, executable=True)
        stack_disp = int.from_bytes(raw[disp_index:disp_index + disp_size], 'little')
        delta = stack_disp - bases[opcode]
        require(0 <= delta and delta + width <= 0x88, 'frame store outside selected allocation')
        out.append({'opcode': opcode, 'field': name, 'instruction_va': hex(site),
                    'bytes': raw.hex(), 'stack_offset': hex(stack_disp),
                    'frame_base': hex(bases[opcode]), 'frame_offset': hex(delta), 'width': width})
    expected = {'input_low': 0x28, 'input_high': 0x38, 'value_low': 0x48,
                'value_high': 0x58, 'gas': 0x68, 'caller_low': 0x70, 'caller_high': 0x80,
                'salt_low': 0x08, 'salt_high': 0x18}
    for row in out:
        require(int(row['frame_offset'], 16) == expected[row['field']], 'frame lane mismatch')
    return out


def extract_salted_preimage_lanes(data, secs):
    """Project selected copy and byte-reversal lanes; no target instructions run."""
    names = {'caller_nonce_update', 'salt_load_and_swap', 'payload_hash_call',
             'preimage_caller_and_digest', 'preimage_salt_halves', 'preimage_hash'}
    pins = {name: (va, bytes.fromhex(raw)) for name, va, raw in PINS if name in names}
    require(set(pins) == names, 'missing preimage instruction window')
    for name, (va, expected) in pins.items():
        require(read_at(data, secs, va, len(expected), executable=True) == expected,
                'preimage instruction window changed: ' + name)

    def insn(va, expected, n):
        raw = read_at(data, secs, va, n, executable=True)
        require(raw.startswith(expected), 'unexpected preimage operand shape')
        return raw

    caller = insn(0x278b593, b'\x4d\x8d\x66', 4)[3]
    salt0 = insn(0x278b667, b'\x41\x0f\x10\x46', 5)[4]
    salt1 = insn(0x278b678, b'\xf3\x41\x0f\x6f\x46', 6)[5]
    prefix_store = insn(0x278b72a, b'\xc6\x84\x24', 8)
    stack_base = struct.unpack_from('<I', prefix_store, 3)[0]
    marker = prefix_store[7]
    low_caller = struct.unpack_from('<I', insn(0x278b716, b'\x0f\x11\x84\x24', 8), 4)[0] - stack_base
    high_caller = struct.unpack_from('<I', insn(0x278b723, b'\x89\x84\x24', 7), 3)[0] - stack_base
    low_salt = struct.unpack_from('<I', insn(0x278b73a, b'\x0f\x11\x84\x24', 8), 4)[0] - stack_base
    high_salt = struct.unpack_from('<I', insn(0x278b77d, b'\xf3\x0f\x7f\x8c\x24', 9), 5)[0] - stack_base
    low_digest = struct.unpack_from('<I', insn(0x278b709, b'\x0f\x11\x84\x24', 8), 4)[0] - stack_base
    high_digest = struct.unpack_from('<I', insn(0x278b701, b'\x0f\x11\x8c\x24', 8), 4)[0] - stack_base
    digest_length = struct.unpack_from('<I', insn(0x278b6e3, b'\xba', 5), 1)[0]
    preimage_length = struct.unpack_from('<I', insn(0x278b816, b'\xba', 5), 1)[0]
    require((marker, salt1 - salt0, high_caller - low_caller,
             high_salt - low_salt, high_digest - low_digest, digest_length) ==
            (0xff, 16, 16, 16, 16, 32), 'unexpected preimage lane layout')

    rows = [{'preimage_offset': 0, 'source': 'literal', 'source_offset': '',
             'literal_byte': hex(marker), 'basis_window': 'preimage_caller_and_digest'}]
    for i in range(high_caller - low_caller + 4):
        rows.append({'preimage_offset': low_caller + i, 'source': 'frame',
                     'source_offset': hex(caller + i), 'literal_byte': '',
                     'basis_window': 'preimage_caller_and_digest'})
    for i in range(digest_length):
        rows.append({'preimage_offset': low_salt + i, 'source': 'frame',
                     'source_offset': hex(salt0 + digest_length - 1 - i), 'literal_byte': '',
                     'basis_window': 'salt_load_and_swap;preimage_salt_halves'})
    for i in range(digest_length):
        rows.append({'preimage_offset': low_digest + i, 'source': 'digest_output',
                     'source_offset': hex(i), 'literal_byte': '',
                     'basis_window': 'payload_hash_call;preimage_caller_and_digest'})
    rows.sort(key=lambda x: x['preimage_offset'])
    require([r['preimage_offset'] for r in rows] == list(range(preimage_length)),
            'preimage lane coverage mismatch')
    return rows


def extract_source_locations(data, secs, relocations):
    by_slot = {int(r['slot_va'], 16): int(r['addend'], 16) for r in relocations}
    out = []
    for site, location, path_va, suffix, expected_hash in SOURCE_LOCATIONS:
        raw = read_at(data, secs, site, 7, executable=True)
        require(raw[:3] == b'\x48\x8d\x3d', 'source location LEA shape changed')
        require(site + 7 + struct.unpack_from('<i', raw, 3)[0] == location,
                'source location LEA target changed')
        require(by_slot.get(location) == path_va, 'source location relocation changed')
        record = read_at(data, secs, location, 24)
        pointer, length, line, column = struct.unpack('<QQII', record)
        require(pointer == 0 and 0 < length < 4096 and line > 0 and column > 0,
                'source location record malformed')
        path = read_at(data, secs, path_va, length)
        digest = hashlib.sha256(path).hexdigest()
        require(digest == expected_hash, 'source path digest mismatch')
        count = len(suffix.split('/'))
        try:
            tail = b'/'.join(path.split(b'/')[-count:]).decode('ascii')
        except UnicodeDecodeError as exc:
            raise EvidenceError('source suffix is not ASCII') from exc
        require(tail == suffix, 'source suffix mismatch')
        out.append({'lea_va': hex(site), 'lea_bytes': raw.hex(),
                    'location_va': hex(location), 'location_bytes': record.hex(),
                    'path_va': hex(path_va), 'path_length': length,
                    'path_sha256': digest, 'relative_suffix': tail,
                    'line': line, 'column': column})
    return out


def relative_table(data, secs, base, count):
    raw = read_at(data, secs, base, count * 4)
    return [base + value for value in struct.unpack('<' + 'i' * count, raw)]


def compare_revision18_windows(data, secs):
    pairs = (('f0_size_gate', 0x24f04de, 0x4c95e4e, 0x31),
             ('f0_word_charge', 0x24f050f, 0x4c95e7f, 0x34),
             ('f5_size_gate', 0x24f08b7, 0x4c96617, 0x30),
             ('f5_word_charge', 0x24f08e7, 0x4c96647, 0x34))
    rows = []
    for name, a, b, length in pairs:
        left = read_at(data, secs, a, length, executable=True)
        right = read_at(data, secs, b, length, executable=True)
        require(left == right, 'selected private/standard revision-18 window changed')
        rows.append({'name': name, 'private_va': hex(a), 'standard_va': hex(b),
                     'private_file_offset': hex(file_offset(secs, a, length, len(data), executable=True)),
                     'standard_file_offset': hex(file_offset(secs, b, length, len(data), executable=True)),
                     'size': length, 'private_bytes': left.hex(), 'standard_bytes': right.hex(),
                     'private_sha256': hashlib.sha256(left).hexdigest(),
                     'standard_sha256': hashlib.sha256(right).hexdigest(),
                     'comparison': 'raw_equal', 'normalization_mask': 'none'})
    return rows


def extract_dependencies(data, secs):
    out = []
    for name, va, expected in DEPENDENCIES:
        actual = read_at(data, secs, va, len(bytes.fromhex(expected)), executable=True)
        require(actual.hex() == expected, 'integration boundary changed: ' + name)
        out.append({'name': name, 'va': hex(va),
                    'file_offset': hex(file_offset(secs, va, len(actual), len(data), executable=True)),
                    'bytes': actual.hex()})
    source = read_at(data, secs, 0x2465d69, 7, executable=True)
    require(source[:3] == b'\x48\x8d\x35', 'table LEA form changed')
    table = 0x2465d69 + 7 + struct.unpack_from('<i', source, 3)[0]
    copy = read_at(data, secs, 0x2465d70, 5, executable=True)
    require(copy[0] == 0xba, 'table size instruction changed')
    size = struct.unpack_from('<I', copy, 1)[0]
    desc = read_at(data, secs, 0x2793093, 7, executable=True)
    require(desc[:3] == b'\x48\x8d\x0d', 'descriptor LEA form changed')
    descriptor = 0x2793093 + 7 + struct.unpack_from('<i', desc, 3)[0]
    dispatch_site = 0x2515cc5
    table_insn = read_at(data, secs, dispatch_site, 7, executable=True)
    require(table_insn[:3] == b'\x48\x8d\x15', 'action table LEA form changed')
    action_table = dispatch_site + 7 + struct.unpack_from('<i', table_insn, 3)[0]
    destinations = relative_table(data, secs, action_table, 4)
    require(table == 0x56ac788 and size == 0x800 and descriptor == 0x56bfb30,
            'prior table or descriptor relation changed')
    require(destinations[1] == 0x2515f19, 'action table index 1 changed')
    obj = read_at(data, secs, 0x574f0c0, 20)
    require(obj == b'\x00' * 19 + b'\x09', 'prior address key changed')
    return {'prior_code_windows': out,
            'opcode_table_va': hex(table), 'opcode_table_size': size,
            'opcode_slot_f0': hex(table + 0xf0 * 8), 'opcode_slot_f5': hex(table + 0xf5 * 8),
            'descriptor_va': hex(descriptor), 'descriptor_method_slot': hex(descriptor + 0x28),
            'action_table_va': hex(action_table),
            'action_table_bytes': read_at(data, secs, action_table, 16).hex(),
            'action_destinations': [hex(x) for x in destinations],
            'prior_address09_va': hex(0x574f0c0), 'prior_address09_bytes': obj.hex()}


def extract_selector_and_matrix(data, secs, relocations):
    selector_base = 0x6f2a8c
    cases = []
    for raw, expected_case, lea in ((9, 0x44bce62, 0x44bce6a),
                                    (10, 0x44bce62, 0x44bce6a),
                                    (18, 0x44bd989, 0x44bd991)):
        entry_va = selector_base + raw * 4
        entry = read_at(data, secs, entry_va, 4)
        case = selector_base + struct.unpack('<i', entry)[0]
        require(case == expected_case, 'prior revision selector table changed')
        instr = read_at(data, secs, lea, 12, executable=True)
        require(instr[:3] == b'\x48\x8d\x35' and instr[7] == 0xba, 'selector table-copy shape changed')
        table = lea + 7 + struct.unpack_from('<i', instr, 3)[0]
        count = struct.unpack_from('<I', instr, 8)[0]
        require(count == 0x800, 'selector copy size changed')
        require(table == (0x5724688 if raw == 18 else 0x5723e88), 'selector opcode table changed')
        cases.append({'raw_revision': raw, 'selector_entry_va': hex(entry_va),
                      'selector_entry_bytes': entry.hex(), 'case_va': hex(case),
                      'table_lea_va': hex(lea), 'table_lea_and_copy_size': instr.hex(),
                      'opcode_table_va': hex(table), 'copy_size': count})
    by_slot = {int(r['slot_va'], 16): int(r['addend'], 16) for r in relocations}
    rows = []
    for family, revision, table, prefix in (
            ('private', 18, 0x56ac788, 'private18'),
            ('standard', 9, 0x5723e88, 'std9'),
            ('standard', 18, 0x5724688, 'std18')):
        for opcode in (0xf0, 0xf5):
            slot = table + 8 * opcode
            require(slot in by_slot, 'missing opcode relocation')
            target = by_slot[slot]
            rows.append({'family': family, 'raw_revision': revision, 'opcode': hex(opcode),
                         'opcode_table_va': hex(table), 'slot_va': hex(slot),
                         'target_fde_start_va': hex(target),
                         'selected_word_gate': 'configured_limit_and_rounded_word_charge'
                         if revision == 18 else 'not_in_selected_revision9_path',
                         'selected_cost_window': (('create' if opcode == 0xf0 else 'create2') + '_base_gas_and_forward')
                         if prefix == 'private18' and opcode == 0xf0
                         else ('create2_base_gas_and_hash_charge' if prefix == 'private18'
                               else prefix + ('_f0_base_and_forward' if opcode == 0xf0 and revision == 9
                                              else '_f5_salt_and_gas' if opcode == 0xf5 and revision == 9
                                              else '_f0_base_gas' if opcode == 0xf0
                                              else '_f5_salt_base_gas'))})
    # This comparison is confined to the four explicitly selected windows.
    compare_revision18_windows(data, secs)
    return cases, rows


def extract_constants(data, secs):
    u32 = lambda va: struct.unpack('<I', read_at(data, secs, va, 4, executable=True))[0]
    byte = lambda va: read_at(data, secs, va, 1, executable=True)[0]
    return {
        'revision_argument': u32(0x276e8ce),
        'default_input_limit': u32(0x24f04e7),
        'create_base_gas': u32(0x24f05f5),
        'create2_base_gas': u32(0x24f09fa),
        'create_frame_size': u32(0x24f067a),
        'create2_frame_size': u32(0x24f0aa7),
        'call_depth_limit': u32(0x278b42e),
        'preimage_length': u32(0x278b817),
        'action_tag_f0': byte(0x24f06b9),
        'action_tag_f5': byte(0x24f0ae0),
        'status_action_f0': byte(0x24f06c1),
        'status_static_f0': byte(0x24f042d),
        'status_stack_f0': byte(0x24f0446),
        'status_high_limb_f0': byte(0x24f04aa),
        'status_size_limit_f0': byte(0x24f0505),
        'status_gas_f0': byte(0x24f0532),
        'status_growth_f0': byte(0x24f06f8),
        'status_static_f5': byte(0x24f07fd),
        'status_stack_f5': byte(0x24f0816),
        'status_high_limb_f5': byte(0x24f0883),
        'status_size_limit_f5': byte(0x24f08dd),
        'status_gas_f5': byte(0x24f090a),
        'status_growth_f5': byte(0x24f0b34),
        'status_depth': byte(0x278b46c),
        'status_funds': byte(0x278b563),
        'status_collision': byte(0x278b8c6),
        'status_nonce_limit': byte(0x278b908),
        'status_prefix': byte(0x278b94a),
        'status_checkpoint_overflow': byte(0x2788008),
        'outer_caller_error_tag': u32(0x278b58a),
        'outer_target_error_tag': u32(0x278bc1c),
    }


def selected_exception_edges(tables):
    selected = (
        ('f0_old_action_drop', 0x24f06a6, 0x24f0786),
        ('f5_old_action_drop', 0x24f0acd, 0x24f0b78),
        ('adapter_creation_call', 0x276e8d2, 0x276e920),
        ('adapter_payload_drop', 0x276e8e7, 0x276e905),
    )
    rows = []
    for name, site, landing in selected:
        candidates = [e for t in tables for e in t['entries']
                      if int(e['start_va'], 16) <= site < int(e['start_va'], 16) + e['length']]
        require(len(candidates) == 1, 'missing or ambiguous selected exception edge')
        entry = candidates[0]
        require(entry['landing_va'] == hex(landing), 'selected exception landing changed')
        rows.append({'name': name, 'call_va': hex(site), 'site_start_va': entry['start_va'],
                     'site_length': entry['length'], 'landing_va': entry['landing_va'],
                     'action': entry['action']})
    return rows


def failure_paths(transfers, constants):
    # The statuses are instruction-derived constants, not source enum labels.
    sites = {r['name']: r for r in transfers}
    records = (
        ('f0_static_continue', 'static flag equals one', 'status_static_f0', 'before stack access'),
        ('f0_stack_continue', 'fewer than three stack words', 'status_stack_f0', 'before stack consumption'),
        ('f0_size_limb_continue', 'nonzero high size limb', 'status_high_limb_f0', 'three words removed'),
        ('f0_length_exceeds_cap', 'nonzero length exceeds selected cap', 'status_size_limit_f0', 'three words removed'),
        ('f0_word_charge_borrow', 'insufficient gas for word charge', 'status_gas_f0', 'three words removed'),
        ('f0_offset_high', 'nonzero high offset limb', 'status_high_limb_f0', 'word charge stored'),
        ('f0_memory_grow_success', 'memory growth helper returns zero', 'status_growth_f0', 'word charge stored'),
        ('f0_base_gas_borrow', 'insufficient gas for base charge', 'status_gas_f0', 'word charge stored'),
        ('f5_static_continue', 'static flag equals one', 'status_static_f5', 'before stack access'),
        ('f5_stack_continue', 'fewer than three stack words', 'status_stack_f5', 'before stack consumption'),
        ('f5_size_limb_continue', 'nonzero high size limb', 'status_high_limb_f5', 'three words removed'),
        ('f5_length_exceeds_cap', 'nonzero length exceeds selected cap', 'status_size_limit_f5', 'three words removed'),
        ('f5_word_charge_borrow', 'insufficient gas for word charge', 'status_gas_f5', 'three words removed'),
        ('f5_offset_high', 'nonzero high offset limb', 'status_high_limb_f5', 'word charge stored'),
        ('f5_memory_grow_success', 'memory growth helper returns zero', 'status_growth_f5', 'word charge stored'),
        ('f5_missing_fourth_stack_word', 'salt stack word absent', 'status_stack_f5', 'three words removed; memory path may have run'),
        ('f5_base_and_hash_gas_borrow', 'insufficient gas for base and hash charge', 'status_gas_f5', 'salt removed and word charge stored'),
        ('depth_continue', 'context depth greater than limit', 'status_depth', 'before caller load'),
        ('caller_load_error', 'caller load result byte differs from five', 'outer_caller_error_tag', 'before balance comparison and nonce update'),
        ('funds_sufficient', 'caller four-limb value below requested value', 'status_funds', 'after caller load; before nonce update'),
        ('nonce_rejected', 'nonce helper returns zero', 'status_nonce_limit', 'before preimage and membership'),
        ('owned_miss', 'owned membership returns nonzero', 'status_collision', 'after nonce update; before new checkpoint'),
        ('borrowed_hit', 'borrowed membership returns nonzero', 'status_collision', 'after nonce update; before new checkpoint'),
        ('created_account_error', 'candidate account load result byte differs from five', 'outer_target_error_tag', 'after nonce update and membership miss'),
        ('checkpoint_hash_mismatch', 'account hash differs from selected constant', 'status_collision', 'checkpoint opened and rollback called'),
        ('checkpoint_nonce_zero', 'matching account hash and nonzero account nonce', 'status_collision', 'checkpoint opened and rollback called'),
        ('checkpoint_carry_first', 'target value addition carries beyond 256 bits', 'status_checkpoint_overflow', 'checkpoint opened; selected journal writes precede rollback'),
    )
    out = []
    fallthrough = {'f0_static_continue', 'f0_stack_continue', 'f0_size_limb_continue',
                   'f0_memory_grow_success', 'f5_static_continue', 'f5_stack_continue',
                   'f5_size_limb_continue', 'f5_memory_grow_success', 'depth_continue',
                   'funds_sufficient', 'owned_miss', 'checkpoint_nonce_zero'}
    for name, predicate, status, prior in records:
        transfer = sites[name]
        out.append({'branch': name, 'branch_va': transfer['va'], 'branch_bytes': transfer['bytes'],
                    'branch_target_va': transfer['target_va'], 'failure_condition': predicate,
                    'failure_edge': 'fallthrough' if name in fallthrough else 'taken',
                    'outcome_kind': 'outer_tag' if status.startswith('outer_') else 'status_byte',
                    'outcome': hex(constants[status]), 'observed_order': prior})
    return out


def collect(data):
    actual = authenticate(data)
    secs, index = unwind_index(data)
    _, frames = eh_frame_records(data, secs)
    functions, bodies, unwind, exceptions = selected_frames(data, secs, index, frames)
    pins = verify_pins(data, secs)
    transfers = extract_transfers(data, secs)
    relas = read_relative_relocations(data, secs)
    sources = extract_source_locations(data, secs, relas)
    lanes = extract_lanes(data, secs)
    preimage_lanes = extract_salted_preimage_lanes(data, secs)
    dependencies = extract_dependencies(data, secs)
    selector_cases, fork_matrix = extract_selector_and_matrix(data, secs, relas)
    comparisons = compare_revision18_windows(data, secs)
    constants = extract_constants(data, secs)
    require(constants['create_base_gas'] == constants['create2_base_gas'] == 32000,
            'creation gas immediate mismatch')
    require(constants['action_tag_f0'] == constants['action_tag_f5'] == 0x6d,
            'creation action tags mismatch')
    require(constants['create_frame_size'] == constants['create2_frame_size'] == 136,
            'creation frame size mismatch')
    bss = [s for s in secs if s['type'] == 8 and s['name'] == '.bss'
           and s['address'] <= 0x5788348 < s['address'] + s['size']]
    require(len(bss) == 1, 'process seed is not in the expected NOBITS section')
    dependencies['process_seed_section'] = bss[0]['name']
    dependencies['process_seed_target_va'] = hex(0x5788348)
    dependencies['process_seed_file_bytes'] = None
    constants['empty_account_hash'] = (
        read_at(data, secs, 0x206160, 16) + read_at(data, secs, 0x204be0, 16)).hex()
    exception_edges = selected_exception_edges(exceptions)
    failures = failure_paths(transfers, constants)
    summary = {'binary_sha256': actual, 'selected_fde_count': len(functions),
               'selected_fde_bytes': sum(row['size'] for row in functions),
               'instruction_window_count': len(pins), 'selected_transfer_count': len(transfers),
               'selected_relocation_count': len(relas), 'frame_lane_count': len(lanes),
               'salted_preimage_lane_count': len(preimage_lanes),
               'source_location_count': len(sources),
               'revision_selector_cases': len(selector_cases), 'fork_matrix_rows': len(fork_matrix),
               'raw_equal_window_pairs': len(comparisons),
               'exception_tables': len(exceptions),
               'exception_call_sites': sum(len(t['entries']) for t in exceptions),
               'exception_landings': sum(e['landing_va'] is not None for t in exceptions for e in t['entries']),
               'selected_exception_edges': len(exception_edges), 'failure_path_count': len(failures),
               'limitations': 'Selected static ranges and branch sites only; not an execution or whole-component census.'}
    return {'functions.tsv': tsv_bytes(functions), 'bodies.json': json_bytes(bodies),
            'unwind.json': json_bytes(unwind), 'exception-sites.json': json_bytes(exceptions),
            'exception-edges.tsv': tsv_bytes(exception_edges), 'failure-paths.tsv': tsv_bytes(failures),
            'windows.tsv': tsv_bytes(pins), 'transfers.tsv': tsv_bytes(transfers),
            'relocations.tsv': tsv_bytes(relas), 'frame-lanes.tsv': tsv_bytes(lanes),
            'salted-preimage-lanes.tsv': tsv_bytes(preimage_lanes),
            'source-locations.tsv': tsv_bytes(sources),
            'selector-cases.tsv': tsv_bytes(selector_cases), 'fork-matrix.tsv': tsv_bytes(fork_matrix),
            'window-comparison.tsv': tsv_bytes(comparisons),
            'dependencies.json': json_bytes(dependencies), 'constants.json': json_bytes(constants),
            'summary.json': json_bytes(summary)}


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def tsv_bytes(rows):
    require(bool(rows), 'empty table')
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('ascii')

MASK64 = (1 << 64) - 1


def fold64(a, b):
    product = a * b
    return ((product & MASK64) ^ (product >> 64)) & MASK64


def address_hash(key, seed, secret0, secret1):
    """Model only the pinned overlapping-load multiply/xor sequence."""
    require(isinstance(key, bytes) and len(key) == 20, 'address must be 20 bytes')
    require(all(type(n) is int and 0 <= n <= MASK64 for n in (seed, secret0, secret1)),
            'invalid seed word')
    words = [int.from_bytes(key[p:p + 8], 'little') for p in (0, 4, 8, 12)]
    inner = fold64(words[2] ^ secret1, words[3] ^ secret0)
    inner ^= fold64(words[0] ^ seed, words[1] ^ secret0)
    return fold64(inner ^ 20, secret0)


def probe(key, controls, keys, seed, secret0, secret1):
    """Synthetic finite-table projection; controls use 0xff as empty.

    A bounded rejection of invalid/full tables is a model guard, not a claim
    about the target's behavior on malformed internal hash tables.
    """
    require(isinstance(key, bytes) and len(key) == 20, 'address must be 20 bytes')
    require(isinstance(controls, bytes) and isinstance(keys, (list, tuple)), 'invalid table')
    count = len(controls)
    require(count >= 16 and count & (count - 1) == 0 and len(keys) == count,
            'invalid modeled capacity')
    require(all(k is None or isinstance(k, bytes) and len(k) == 20 for k in keys),
            'invalid modeled key')
    if not any(c < 0x80 for c in controls):
        return False
    h = address_hash(key, seed, secret0, secret1)
    fingerprint, mask = h >> 57, count - 1
    group, stride = h & mask, 0
    for _ in range(count // 16):
        positions = [(group + i) & mask for i in range(16)]
        for i in positions:
            if controls[i] == fingerprint:
                require(keys[i] is not None, 'occupied modeled control lacks key')
                if keys[i] == key:
                    return True
        if any(controls[i] == 0xff for i in positions):
            return False
        stride += 16
        group = (group + stride) & mask
    raise EvidenceError('model rejected full table without empty control')


def create_preimage(caller, old_nonce):
    """Project the RLP-shaped nonce arm after the successful nonce increment."""
    require(isinstance(caller, bytes) and len(caller) == 20, 'address must be 20 bytes')
    require(type(old_nonce) is int and 0 <= old_nonce < MASK64, 'nonce cannot be incremented')
    if old_nonce == 0:
        encoded_nonce = b'\x80'
    elif old_nonce < 0x80:
        encoded_nonce = bytes([old_nonce])
    else:
        magnitude = old_nonce.to_bytes((old_nonce.bit_length() + 7) // 8, 'big')
        encoded_nonce = bytes([0x80 + len(magnitude)]) + magnitude
    payload = b'\x94' + caller + encoded_nonce
    return bytes([0xc0 + len(payload)]) + payload


def create2_preimage(caller, salt_word, initcode_digest):
    """Project the 85-byte preimage, with the frame's u256 salt reversed."""
    require(isinstance(caller, bytes) and len(caller) == 20, 'address must be 20 bytes')
    require(isinstance(salt_word, bytes) and len(salt_word) == 32, 'salt must be 32 bytes')
    require(isinstance(initcode_digest, bytes) and len(initcode_digest) == 32, 'digest must be 32 bytes')
    return b'\xff' + caller + salt_word[::-1] + initcode_digest


def projected_gas(length, initial, salted, revision=18):
    """Project selected charges with zero memory cost; size/growth gates are excluded."""
    require(type(length) is int and 0 <= length <= MASK64, 'length outside u64')
    require(type(initial) is int and 0 <= initial <= MASK64, 'gas outside u64')
    require(type(salted) is bool, 'salted flag must be bool')
    require(type(revision) is int and revision in (9, 18), 'unsupported modeled revision')
    rounded = min(length + 31, MASK64)
    first = ((rounded >> 4) & ~1) if revision == 18 else 0
    if initial < first:
        return {'status': 0x50, 'remaining': initial, 'child': None}
    after_first = initial - first
    second = 32000 + (6 * (rounded >> 5) if salted else 0)
    if after_first < second:
        return {'status': 0x50, 'remaining': after_first, 'child': None}
    rest = after_first - second
    parent = rest >> 6
    return {'status': 0x20, 'remaining': parent, 'child': rest - parent}


def add_limbs(left, right):
    """Project the selected four-limb target-balance addition and final carry."""
    require(len(left) == len(right) == 4, 'expected four limbs')
    require(all(type(n) is int and 0 <= n <= MASK64 for n in (*left, *right)),
            'invalid limb')
    out, carry = [], 0
    for a, b in zip(left, right):
        total = a + b + carry
        out.append(total & MASK64)
        carry = total >> 64
    return tuple(out), carry


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    evidence = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, raw in sorted(evidence.items()):
        (args.out / name).write_bytes(raw)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError, struct.error, ValueError) as error:
        print('re21_private_create94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
