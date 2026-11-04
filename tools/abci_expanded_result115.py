#!/usr/bin/env python3
"""Reproduce selected node-115 expanded ABCI item/result evidence from ELF bytes.

The x86 windows are explicitly selected, not a general disassembler. The shared
ELF and unwind readers are the repository's tools, and no target is executed.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FDE_SPECS = (
    ('loader_callback_worker', 0x5a6e1e0, 0x5a70656, '6607dd0ca52fd0a9423ab9d85cd2d0fd98b7cce3dcfdce534dc547bd1263ac87'),
    ('item_loop', 0x5865d80, 0x586629e, '8aadb168958ea4b664274e38a8080694d072a6e033b6aaaaed55285008c95509'),
    ('location_handler', 0x54851a0, 0x5485a5f, '2efac4ef3ef5a5eb6cf9c14ac94597941f16c628ea70f6366ac7a90e0215e59d'),
    ('nested_result', 0x55f4760, 0x55f4d56, 'bb311b55ad8620da1cba40dacd16d9ecabe7cef6a96009fd98554957f9a8c047'),
    ('row_insertion', 0x4ef54c0, 0x4ef589b, '803a2f18a90b350ddaa9e7b90b91e8c773d6cb48fb71e8c2100b3ed0bd2f6d5a'),
    ('result_projection', 0x5961310, 0x5961474, '9d447793759bc66a20ae4b76c2da6ebe60b8b3315189a293e941583d63208e90'),
)
WINDOWS = (
    ('worker_entry', 0x5a6e1e0, '554157415641554154534881ec580d00004c89c54989cd4889942460010000897424584889fb4c89842430020000'),
    ('worker_save_callback', 0x5a6e273, '488d4340488984249003000048895c2428'),
    ('worker_next', 0x5a6e318, '488dbc2468040000488bb42460010000e8c38a040083bc2468040000010f854c1d0000488bac2470040000488b9424780400004885ed7430'),
    ('worker_identity', 0x5a6e360, '48b800000000000000804c8d60014c396528754c488d4530eb5c660f1f440000488954246848c7442460000000004c89f74c89e64889d5ba01000000e85f4dfffff048ff4d000f856cffffff488d7c2468ff150169a700e95cffffff0f1f4000488d4d28488d85b80000004c39a5b8000000480f44c1488b403048898424d8030000483b8424680100000f85081d0000f048ff45000f8e6d1d0000f048ff020f8e631d0000'),
    ('worker_pending_test', 0x5a6e47a, '488dbc24f8040000488db424c80300004c89faff155592a70048b8000000000000008048398424f80400000f8535010000'),
    ('worker_allocation', 0x5a6e66f, '4885db746e4c8bb424280300004889dfff15fb0da7004885c00f849c1a0000'),
    ('worker_reload', 0x5a6e72a, '4c8b742428498b86f805000048b900000000000000804839c80f84a6000000498b8e080600004885c97464'),
    ('worker_pending_store', 0x5a6e7ef, '4d89a6f80500004d89be000600004d89a6080600004d89ae1006000049899e18060000498996200600004989ae28060000'),
    ('worker_set_callback', 0x5a6e855, '488d7c24604c8b6c2418ff152b21a7004d89f783bc24480d0000000f8488000000'),
    ('worker_result_address', 0x5a6e96e, '488d6c24604889eee8e5e432fe'),
    ('worker_argument', 0x5a6e97b, '660f108424b0010000660f29842490020000488b8424c001000048898424a0020000488d84242003000048898424a8020000498b9fa00600004c8d7310488d0558c7ecfa48898424b801000048c78424c00100001900000048c78424b0010000000000004881c3400100004c89b424b00200004c89ac24b80200004889ef4889de488d94249002000031c94c8d05d3a1a4004d89e5e8ab384aff'),
    ('worker_return_projection', 0x5a6ea15, '4c8da424e8030000488b44247048898424900100000f104424600f298424800100000fb68424800000008944245c488b4424784889842420010000488d842488000000660f1000660f104810660f29842450050000660f298c2460050000488b40204889842470050000'),
    ('worker_post_block_pending', 0x5a6eaa6, '4c89742460488b8424a80300004889442468488d84249002000048894424704889df488d74246031d2488d0d22a1a400e835014bff498b87f805000048b9000000000000008049898ff80500004839c80f85b9000000'),
    ('worker_early_return', 0x5a70087, '488dbc2478050000e8dc15feff4c89efe864a2feff488bbc2460010000e8a7a0fcff4881c4580d00005b415c415d415e415f5dc3'),
    ('worker_bad_identity', 0x5a700f8, '4c8d0dc98aa400488db424d8030000488d94243002000031ff31c9ff15bf7fa700eb4d'),
    ('worker_alloc_failure', 0x5a7012a, 'b8080000004889842418010000488bbc24180100004889deff1550f3a600eb1eb8080000004889842418010000488bbc24180100004889deff1530f3a6000f0b'),
    ('worker_block_landing', 0x5a70365, 'e984020000'),
    ('worker_block_unwind', 0x5a705ee, '4989c741b401488dbc2420030000e80ffdfdff488dbc24a0010000e88222feff4584e4740d488dbc24c8030000e8200dfeff488dbc2478050000e84310feff4c89efe8cb9cfeff488bbc2460010000e80e9bfcff4c89ffe806049800'),
    ('nested_prologue', 0x55f4760, '554157415641554154534881ec680200004989cc4989d74989f64889fb8b4210898424c0000000f30f6f02660f7f8424b0000000'),
    ('context_sort_branches', 0x58682fb, '4883fd15731dba010000004c89ef4889ee488d8c24d0000000e8573ab8ffe963ffffff4c89ef4889ee488d9424d0000000ff15b637c800e94affffff'),
    ('handler_inline_key', 0x54851c7, '4889542428488d410348894424088b4113898424c00100000f1041030f298424b0010000'),
    ('context_count_pointer', 0x5b3250a, '488d4c241048c744241000000000'),
    ('context_state_in', 0x586805f, '488b014889442408'),
    ('context_state_out', 0x5868232, '488d4424064889442460488b44240848894424684c896c2470488b4424284889442478'),
    ('context_call_args', 0x5868255, '488d7c2410488d742440'),
    ('context_entry', 0x5b32518, '410f1006410f104e100f294c24600f29442450410f104620410f104e300f114c24400f1144243048894c241848c7442420000000004889442428488d7c2450488d742418e81f38d3ff488b442410488943100f1004240f11034889d84883c4785b415c415e415fc3'),
    ('context_compact', 0x5868264, '4c8b6c2418488b6c2420488d44240748898424d00000004883fd02737a488b442410488d0ced000000004801e9498d4ccd004c89ac24d00000004c89ac24d800000048898424e000000048898c24e8000000488dbc2460010000488db424d0000000e845900f00488b842470010000498946100f10842460010000410f1106'),
    ('item_setup', 0x5865d91, '488b6f0848897c2408488b471848894424504839c548897424280f843c0400004c8b6608488b46184889442448488b46304889442440488b46284883c0204889442430488b462048894424384f8d3ce449c1e7034c037e10'),
    ('item_row_out', 0x5865df0, '4788342f0f288424b0000000430f11442f010f108424bf000000430f11442f10488b4424584b89442f208b4424044388442f280f28442470430f11442f298b8424800000004389442f39488b4424604b89442f4049ffc44983c548'),
    ('item_endcheck', 0x5865e4b, '488b442468483b4424500f8496030000'),
    ('item_row_in', 0x5865e5b, '4a8d346d000000004801eeba90000000488dbc2460020000ff158f96c7004a8d0c6d900000004801e9488b44240848894c246848894808'),
    ('item_gate', 0x5865f0c, '6681bc2470010000a2010f85d4000000428b446d33898424a0000000420f10446d230f29842490000000b00189442404488b4424480fb61884db0f85bc000000'),
    ('item_zero_result', 0x5865f73, 'e808c596ff66c78424b0000000c600'),
    ('item_initial_state', 0x5865fc5, '488b442438488b008338010f849f01000048c70001000000b901000000e9a0010000'),
    ('item_call_handler', 0x5866008, '488b4c24308b4110898424c00000000f10010f298424b0000000488dbc24e0010000488b7424384c89f2488d8c24800200004c8d8424b0000000e859f1c1ff80bc24e00100000f410fb696650100000f85a3000000'),
    ('item_return_convert', 0x58660b8, '488d7c24104c8db424b00000004c89f6e8c3655eff488b442420488d8c2450010000488941100f104424100f1101c68424480100000f4c89f7e87ab10e0041b60feb24'),
    ('item_post_state', 0x5866164, '488b442438488b008338010f8561feffff488b480848ffc148c7c2ffffffff480f44ca48894808'),
    ('item_exit', 0x58661ed, '4c8b6608488b442428488b004c8920488b7c2408e80acc1600'),
    ('item_unwind', 0x5866252, '80f30184db741c0fb78424700100003da2010000740d488dbc2470010000e8fbaf0e00488b442428488b004c8920488b7c2408e886cb16004c89f7e8bea7b800'),
    ('handler_tag', 0x54851b1, '4c894424204989fd0fb7013da20100000f85b80000004889542428488d41034889442408'),
    ('handler_map_count', 0x5485219, '488b064889442410488b98e81400004885db0f840d0100004883fb010f85ab000000488b442410488b80e0140000'),
    ('handler_singleton', 0x5485247, 'f30f6f4048660f6e8c24c0000000660f6e5058660f748424b0000000660f74d1660fdbc2660fd7c03dffff00000f85c4000000e9ac010000'),
    ('handler_multi', 0x54852e6, '4c8b742410498bbe10150000498bb618150000488b542408e85df2a6ff498b8ee0140000488d9424b0000000488954243048894c243848895c2440498dbef0140000488d5424304889c6e8cb9ca7ff4885c00f85ed000000'),
    ('handler_tree', 0x548533e, '488b4424104c8bb8e81b00004d85ff0f84ad000000'),
    ('handler_fallback', 0x5485400, '488b442410488db0f8180000488d7c2430488b542408ff15fcfa050166b83600807c2430010f857b020000'),
    ('handler_counter_first', 0x5485438, '4c8b742410498b86b016000048ffc048c7c3ffffffff480f44c3498986b0160000'),
    ('handler_dispatch', 0x5485485, '488d7c2430488d9424400100004889c6488b4c24084d89f84531c9ff154a2a06010fb74424303da20100000f859e010000498daed8140000498b86b816000048ffc0480f44c34d8d5e60498986b8160000'),
    ('handler_mode', 0x54854d6, '41833c24010f85e4010000498b442408'),
    ('handler_clock_test', 0x548558d, '4801ca31c94885d2480f4fca4839c80f8323010000'),
    ('handler_mul_five', 0x54855a2, '4c895c24204983c4104c89e7ff156cf90501b90500000048f7e10f80430400004989c44c89eb'),
    ('handler_hit_test', 0x54855c8, '498bbe10150000498bb6181500004c8b7c24084c89fae87defa6ff4989c5418b4710898424e0000000410f10070f298424d0000000f3410f6f86e0140000488d8424d00000004889842440010000f30f7f8424480100004981c6f0140000488d9424400100004c89f74c89eee8c799a7ff4885c00f84b30200004c897424484c896c24504531f6'),
    ('handler_nonselected', 0x5485654, '0f10842490000000410f1145700f10842482000000410f1145620f10442472410f114552f30f6f442432f30f6f4c2442f30f6f5424520f105c2462410f115d42f3410f7f5532f3410f7f4d22f3410f7f4512664189451041c645000f4c89e84881c4e80100005b415c415d415e415f5dc3'),
    ('handler_normal_init', 0x54856c5, '4889eb498d7c241048897c2418ff1548f805014889c5'),
    ('handler_normal_lookup', 0x54856db, '488b5424088b4210898424e00000000f10020f298424d0000000498bbe10150000498bb618150000e858eea6ff4989c4410f1086e0140000488d8424d000000048898424400100000f118424480100004d8dbef0140000488d9424400100004c89ff4c89e6e8bb98a7ff4885c0740f4c897c24484c896424504531ffeb1d488d4424488b8c24e00000008948100f288424d00000000f11004c89e0'),
    ('handler_normal_update', 0x5485776, '4c897c243048895c24384889442440488d7c2430e8c16a3a004803680848c7c1ffffffff480f43cd480f43cd48894808498d5660488b0a8b520889503848894830'),
    ('handler_nested_call', 0x54857b7, '4c8b642428450fb68424650100004d8b0c24498b442408488b5424208b4a10898c24510100000f10020f11842441010000c684244001000001488d7c24304c89f6488b542408488b4c24184c8d942440010000415250e84eef16004883c410'),
    ('handler_observer', 0x5485816, '4d8bbee84d00004d85ff746f498b9ef04d00000fb66c2430488dbc24d00000004c89e6ff15e9f605016681bc24d0000000a2010f851801000031d24080fd0f0f94c24c8bb424d80000004c8ba424e0000000488b8c24e8000000488db424b00100004c89ffff53204d85f6740e4c89e74c89f631d2ff150f9c0501'),
    ('handler_fast_update', 0x54858f5, '488d4424488b8c24e0000000894810660f6f8424d0000000f30f7f004c89e84c8974243048896c24384889442440488d7c2430e823693a004c03600848c7c1ffffffff490f43cc490f43cc48894808488b6c2420488b4d008b55088950384889483066b8d0004989dd66894310e944fdffff'),
    ('handler_diagnostic', 0x54859db, '488d3d504d4afb488d0d575402014c8d0518480201488d942440010000be2b000000ff159d9c05010f0b'),
    ('nested_singleton', 0x55f4794, '4c8bae204800004d85ed74454983fd017546498b8618480000f30f6f4008660f6e8c24c0000000660f6e5018660f74d1660f748424b0000000660fdbc2660fd7c831d281f9ffff00000f858d000000eb5e31d2e984000000'),
    ('nested_lookup', 0x55f47ec, '4c896424084489c54d89cc498bbe48480000498bb6504800004c89fae8332c12ff488d9424b0000000498dbe104800004889c6e88cdd8dfea801743b4c39ea0f83dc0400004d89e14189e8498b86184800004c8b642408'),
    ('nested_alias_choice', 0x55f4843, '488d0c5248c1e1048b54082c89542421f30f6f44081cf30f7f442411b201eb0d31d24d89e14189e84c8b6424084c8bac24a8020000488b8424a0020000488d4c241184d2490f44cf0f10010f118424ac0100008b4910898c24bc010000'),
    ('nested_original_key', 0x55f48e0, '410f10070f11842498010000418b4f10898c24a8010000'),
    ('nested_dispatch', 0x55f491f, '410f104500410f104d100f118424c10100000f118c24d1010000410fb64520888424e1010000498db6304c0000488dbc24b0000000488d942438010000ff153635ef000fb68424b00000003c100f85ba0000000fb78c24c000000081f9d00000000f85a6000000'),
    ('nested_four', 0x55f4986, '4c89e7ff159105ef004989c448c1e83e0f856503000049c1e402'),
    ('nested_update_lookup', 0x55f49a0, '498bbe10150000498bb6181500004c89fae8aafb8fff4989c5418b4710898424a0000000410f10070f29842490000000410f1086e0140000488d84249000000048898424e80100000f118424f00100004d8dbef0140000488d9424e80100004c89ff4c89eee8f6a590ff498d8ed81400004885c00f84ab0000004c897c24284c896c24304531ffe9b6000000'),
    ('nested_result_switch', 0x55f4a94, '3c100f84ed0000003c0f0f857101000041807d00010f85b10100004889df4c89f64c89fa4c89e1e8d0e4eaffe93e010000'),
    ('nested_update_write', 0x55f4ac5, '488d4424288b9424a00000008950100f288424900000000f11004c89e84c897c241048894c24184889442420488d7c2410e8557723004c03600848c7c1ffffffff490f43cc490f43cc48894808498b4e60418b566889503848894830'),
    ('nested_return', 0x55f4be4, '0f1143700f114b600f1153500f1173400f116b300f1163200f115b10c6030f4881c4680200005b415c415d415e415f5dc3'),
    ('nested_flag_branch', 0x55f4c60, '49ffc5498b465048ffc048c7c5ffffffff480f45e849896e5041c6467801488d7c24104c89f64c89fa4c89e1e8ffe2eaff41c64678004981c6c00700004c89f74c89fe4889ea4c89e94d89e0ff15b66fef00'),
    ('nested_overflow_bounds', 0x55f4d01, '49c7c4ffffffffe993fcffff488d051ceee9004889d74c89ee4889c2ff15fda8ee00'),
    ('insert_input', 0x4ef54ce, '4c8b6e184c8b7208488b5a104c8b264c8b56084531db4889c8'),
    ('insert_probe', 0x4ef54f0, '4c21d0f3410f6f0404660fd7e885ed75204983fbf00f844c0300004983c3104c01d873dc488d3d05965a01ff15ff9f5e01f3440fbcdd4c01d80f82350300004c21d0450fb61c044584db7813'),
    ('insert_capacity', 0x4ef554f, '4c8b7e104d85ff400f94c54180e3014184eb0f85cd000000450fb6db4d29df0f82fd0200004c897e10'),
    ('insert_control_index', 0x4ef5578, '4c8d58f04d21d34983fbef0f87f50200004989ca49c1ea39458814044788541c104d89ea4983fdff0f844f02000049ffc24c89561848c1e0034929c44d896c24f8483b1a0f84eb000000'),
    ('insert_row', 0x4ef55c2, '488d045b48c1e00549890c06410f1001410f104910410f105120410f105930410f11440608410f114c0618410f11540628410f115c0638410f1000410f11440648458b4010458944065848ffc348895a10'),
    ('insert_return', 0x4ef5613, '4889174c8967084889771048894f184889f84883c4385b415c415d415e415f5dc3'),
    ('insert_growth', 0x4ef56ad, '4c894c24104c894424084889d54889342448897c24184989cd488d041b49bf55555555555555014c39f84c0f42f84c89f84829d84883f8010f8617010000488d7c242041b80800000041b9600000004889de4c89f24c89f9e846dfa600837c2420010f84ed0000004c8b7424284889ea4c8975084c897d00'),
    ('insert_error', 0x4ef5802, '4c8d7b01488d7c242041b80800000041b9600000004889de4c89f24c89f9e82bdea600837c242001745f'),
    ('insert_traps', 0x4ef5857, '488d3daa925a01ff15bc9c5e01488d3ddd945a01ff15af9c5e01488d3da0945a01ff15ca9f5e01488d3dbb935a01ff15959c5e01488b7c2428488b742430ff15fd9b5e01'),
    ('projection_setup', 0x596131e, '4989f648897c2408488b7610498b1e4d8b6e08488d04f500000000498b4e184989df4939cd7443'),
    ('projection_copy', 0x5961350, '410f104500410f104d10410f105520410f105d304983c548410f115f30410f115720410f114f10410f11074983c7404939cd75cc4d896e08'),
    ('projection_transfer', 0x5961388, '4c8d24c04929df49c1ef064889c84c29e848ba8fe3388ee3388ee348f7e248895c24104c897c2418488974242049c746100000000049c7060800000049c746080800000049c7461808000000'),
    ('projection_remainder', 0x59613d4, '4c39e974184889d548c1ed064c89efe8b843ffff4983c54848ffcd75ef41f6c438743d'),
    ('projection_shrink', 0x59613f7, '4d89e54889df4983e5c074214c89eeff157ce1b7004889c34885c07520bf080000004c89eeff156ee0b7000f0b4c89e631d2ff1571e0b700bb08000000'),
    ('projection_return', 0x5961434, '49c1ec06488b4424084c8920488958084c8978104883c4285b415c415d415e415f5dc3'),
    ('projection_unwind', 0x5961457, '4889c3488d7c2410e8fcc7feff4c89f7e8946afeff4889dfe8dcf5a800'),
)
TRANSFERS = (
    (0x5a6e328, 'e8c38a0400', 'rel', 0x5ab6df0),
    (0x5a6e335, '0f854c1d0000', 'jcc32', 0x5a70087),
    (0x5a6e34e, '7430', 'jcc8', 0x5a6e380),
    (0x5a6e372, '754c', 'jcc8', 0x5a6e3c0),
    (0x5a6e3ea, '0f85081d0000', 'jcc32', 0x5a700f8),
    (0x5a6e3f5, '0f8e6d1d0000', 'jcc32', 0x5a70168),
    (0x5a6e3ff, '0f8e631d0000', 'jcc32', 0x5a70168),
    (0x5a6e48d, 'ff155592a700', 'slot', 0x64e76e8),
    (0x5a6e4a5, '0f8535010000', 'jcc32', 0x5a6e5e0),
    (0x5a6e688, '0f849c1a0000', 'jcc32', 0x5a7012a),
    (0x5a6e743, '0f84a6000000', 'jcc32', 0x5a6e7ef),
    (0x5a6e753, '7464', 'jcc8', 0x5a6e7b9),
    (0x5a6e85f, 'ff152b21a700', 'slot', 0x64e0990),
    (0x5a6e870, '0f8488000000', 'jcc32', 0x5a6e8fe),
    (0x5a6e976, 'e8e5e432fe', 'rel', 0x3d9ce60),
    (0x5a6ea10, 'e8ab384aff', 'rel', 0x4f122c0),
    (0x5a6ead6, 'e835014bff', 'rel', 0x4f1ec10),
    (0x5a6eaf6, '0f85b9000000', 'jcc32', 0x5a6ebb5),
    (0x5a7008f, 'e8dc15feff', 'rel', 0x5a51670),
    (0x5a70097, 'e864a2feff', 'rel', 0x5a5a300),
    (0x5a700a4, 'e8a7a0fcff', 'rel', 0x5a3a150),
    (0x5a70113, 'ff15bf7fa700', 'slot', 0x64e80d8),
    (0x5a70142, 'ff1550f3a600', 'slot', 0x64df498),
    (0x5a70365, 'e984020000', 'rel', 0x5a705ee),
    (0x5a705fc, 'e80ffdfdff', 'rel', 0x5a50310),
    (0x5a70609, 'e88222feff', 'rel', 0x5a52890),
    (0x5a7061b, 'e8200dfeff', 'rel', 0x5a51340),
    (0x5a70628, 'e84310feff', 'rel', 0x5a51670),
    (0x5a70630, 'e8cb9cfeff', 'rel', 0x5a5a300),
    (0x5a7063d, 'e80e9bfcff', 'rel', 0x5a3a150),
    (0x5a70645, 'e806049800', 'rel', 0x63f0a50),
    (0x586827f, '737a', 'jcc8', 0x58682fb),
    (0x58682ff, '731d', 'jcc8', 0x586831e),
    (0x5868314, 'e8573ab8ff', 'rel', 0x53ebd70),
    (0x5868319, 'e963ffffff', 'rel', 0x5868281),
    (0x586832c, 'ff15b637c800', 'slot', 0x64ebae8),
    (0x5868332, 'e94affffff', 'rel', 0x5868281),
    (0x5b3255c, 'e81f38d3ff', 'rel', 0x5865d80),
    (0x5865dab, '0f843c040000', 'jcc32', 0x58661ed),
    (0x5865e55, '0f8496030000', 'jcc32', 0x58661f1),
    (0x5865f16, '0f85d4000000', 'jcc32', 0x5865ff0),
    (0x5865f46, '0f85bc000000', 'jcc32', 0x5866008),
    (0x5866042, 'e859f1c1ff', 'rel', 0x54851a0),
    (0x5866057, '0f85a3000000', 'jcc32', 0x5866100),
    (0x586616f, '0f8561feffff', 'jcc32', 0x5865fd6),
    (0x58682c6, 'e845900f00', 'rel', 0x5961310),
    (0x54851c1, '0f85b8000000', 'jcc32', 0x548527f),
    (0x548522b, '0f840d010000', 'jcc32', 0x548533e),
    (0x5485235, '0f85ab000000', 'jcc32', 0x54852e6),
    (0x5485274, '0f85c4000000', 'jcc32', 0x548533e),
    (0x5485338, '0f85ed000000', 'jcc32', 0x548542b),
    (0x548534d, '0f84ad000000', 'jcc32', 0x5485400),
    (0x5485425, '0f857b020000', 'jcc32', 0x54856a6),
    (0x54854b0, '0f859e010000', 'jcc32', 0x5485654),
    (0x54854db, '0f85e4010000', 'jcc32', 0x54856c5),
    (0x548559c, '0f8323010000', 'jcc32', 0x54856c5),
    (0x54855bc, '0f8043040000', 'jcc32', 0x5485a05),
    (0x548563c, '0f84b3020000', 'jcc32', 0x54858f5),
    (0x5485748, '740f', 'jcc8', 0x5485759),
    (0x548578a, 'e8c16a3a00', 'rel', 0x582c250),
    (0x548580d, 'e84eef1600', 'rel', 0x55f4760),
    (0x5485820, '746f', 'jcc8', 0x5485891),
    (0x5485849, '0f8518010000', 'jcc32', 0x5485967),
    (0x548587b, 'ff5320', 'reg', 0x20),
    (0x5485928, 'e823693a00', 'rel', 0x582c250),
    (0x54859fd, 'ff159d9c0501', 'slot', 0x64df6a0),
    (0x55f479e, '7445', 'jcc8', 0x55f47e5),
    (0x55f47a4, '7546', 'jcc8', 0x55f47ec),
    (0x55f47dd, '0f858d000000', 'jcc32', 0x55f4870),
    (0x55f4826, '743b', 'jcc8', 0x55f4863),
    (0x55f482b, '0f83dc040000', 'jcc32', 0x55f4d0d),
    (0x55f495c, 'ff153635ef00', 'slot', 0x64e7e98),
    (0x55f496c, '0f85ba000000', 'jcc32', 0x55f4a2c),
    (0x55f4980, '0f85a6000000', 'jcc32', 0x55f4a2c),
    (0x55f4996, '0f8565030000', 'jcc32', 0x55f4d01),
    (0x55f49b1, 'e8aafb8fff', 'rel', 0x4ef4560),
    (0x55f4a05, 'e8f6a590ff', 'rel', 0x4eff000),
    (0x55f4a14, '0f84ab000000', 'jcc32', 0x55f4ac5),
    (0x55f4a96, '0f84ed000000', 'jcc32', 0x55f4b89),
    (0x55f4a9e, '0f8571010000', 'jcc32', 0x55f4c15),
    (0x55f4aa9, '0f85b1010000', 'jcc32', 0x55f4c60),
    (0x55f4abb, 'e8d0e4eaff', 'rel', 0x54a2f90),
    (0x55f4af6, 'e855772300', 'rel', 0x582c250),
    (0x55f4c8c, 'e8ffe2eaff', 'rel', 0x54a2f90),
    (0x55f4cac, 'ff15b66fef00', 'slot', 0x64ebc68),
    (0x55f4d1d, 'ff15fda8ee00', 'slot', 0x64df620),
    (0x4ef54ff, '7520', 'jcc8', 0x4ef5521),
    (0x4ef5505, '0f844c030000', 'jcc32', 0x4ef5857),
    (0x4ef5512, '73dc', 'jcc8', 0x4ef54f0),
    (0x4ef5529, '0f8235030000', 'jcc32', 0x4ef5864),
    (0x4ef5561, '0f85cd000000', 'jcc32', 0x4ef5634),
    (0x4ef556e, '0f82fd020000', 'jcc32', 0x4ef5871),
    (0x4ef5583, '0f87f5020000', 'jcc32', 0x4ef587e),
    (0x4ef55a0, '0f844f020000', 'jcc32', 0x4ef57f5),
    (0x4ef55bc, '0f84eb000000', 'jcc32', 0x4ef56ad),
    (0x4ef570f, '0f84ed000000', 'jcc32', 0x4ef5802),
    (0x4ef582a, '745f', 'jcc8', 0x4ef588b),
    (0x5961343, '7443', 'jcc8', 0x5961388),
    (0x5961382, '75cc', 'jcc8', 0x5961350),
    (0x59613d7, '7418', 'jcc8', 0x59613f1),
    (0x59613ef, '75ef', 'jcc8', 0x59613e0),
    (0x59613f5, '743d', 'jcc8', 0x5961434),
    (0x5961401, '7421', 'jcc8', 0x5961424),
    (0x5961412, '7520', 'jcc8', 0x5961434),
    (0x596141c, 'ff156ee0b700', 'slot', 0x64df490),
)

# Operands are extracted from the pinned instruction windows. The offset and
# width identify immediate/displacement bytes in the named instruction.
OPERANDS = (
    ('worker_saved_callback', 0x5a6e27f, 5, 4, 1),
    ('worker_reloaded_callback', 0x5a6e72a, 5, 4, 1),
    ('worker_captured_owner', 0x5a6e9ad, 7, 3, 4),
    ('worker_owner_body', 0x5a6e9b4, 4, 3, 1),
    ('worker_owner_guard', 0x5a6e9df, 7, 3, 4),
    ('worker_owner_argument_store', 0x5a6e9e6, 8, 4, 4),
    ('worker_argument_base', 0x5a6e9fc, 8, 4, 4),
    ('worker_result_base', 0x5a6e96e, 5, 4, 1),
    ('worker_result_head_source', 0x5a6ea2a, 5, 4, 1),
    ('worker_result_head_destination', 0x5a6ea2f, 8, 4, 4),
    ('worker_result_word_source', 0x5a6ea1d, 5, 4, 1),
    ('worker_result_word_destination', 0x5a6ea22, 8, 4, 4),
    ('worker_result_extra_source', 0x5a6ea43, 5, 4, 1),
    ('worker_result_extra_destination', 0x5a6ea48, 8, 4, 4),
    ('worker_result_flag_source', 0x5a6ea37, 8, 4, 4),
    ('worker_result_flag_destination', 0x5a6ea3f, 4, 3, 1),
    ('worker_result_tail_source', 0x5a6ea50, 8, 4, 4),
    ('worker_result_tail_destination', 0x5a6ea61, 9, 5, 4),
    ('worker_result_tail_second', 0x5a6ea6a, 9, 5, 4),
    ('worker_result_tail_word', 0x5a6ea77, 8, 4, 4),
    ('worker_pending_write_offset', 0x5a6e7ef, 7, 3, 4),
    ('worker_pending_read_offset', 0x5a6eadb, 7, 3, 4),
    ('worker_pending_clear_offset', 0x5a6eaec, 7, 3, 4),
    ('worker_pending_sentinel', 0x5a6eae2, 10, 2, 8),
    ('projection_capacity_first_sib', 0x5961331, 8, 3, 1),
    ('projection_capacity_second_sib', 0x5961388, 4, 3, 1),
    ('handler_flag_store_offset', 0x54857e8, 8, 3, 4),
    ('handler_flag_address_offset', 0x5485802, 8, 4, 4),
    ('nested_frame_size', 0x55f476a, 7, 3, 4),
    ('nested_flag_stack_offset', 0x55f4870, 8, 4, 4),
    ('gate_zero_code', 0x5865f78, 10, 8, 2),
    ('membership_miss_code', 0x548541c, 4, 2, 2),
    ('handler_nested_flag', 0x54857e8, 8, 7, 1),
    ('nested_flag_compare', 0x55f4aa4, 5, 4, 1),
    ('sort_first_count', 0x586827b, 4, 3, 1),
    ('sort_second_count', 0x58682fb, 4, 3, 1),
    ('handler_key_head', 0x54851cc, 4, 3, 1),
    ('handler_key_tail', 0x54851d5, 3, 2, 1),
    ('alias_key_tail', 0x55f47bb, 5, 4, 1),
    ('handler_clock_head', 0x54857a6, 4, 3, 1),
    ('handler_clock_tail', 0x54857ad, 3, 2, 1),
    ('handler_value_clock_head', 0x54857b3, 4, 3, 1),
    ('handler_value_clock_tail', 0x54857b0, 3, 2, 1),
    ('nested_clock_head', 0x55f4b12, 4, 3, 1),
    ('nested_clock_tail', 0x55f4b16, 4, 3, 1),
    ('nested_value_clock_head', 0x55f4b1d, 4, 3, 1),
    ('nested_value_clock_tail', 0x55f4b1a, 3, 2, 1),
    ('wrapper_count_pointer', 0x5b3250a, 5, 4, 1),
    ('wrapper_count_stack', 0x5b32561, 5, 4, 1),
    ('wrapper_count_output', 0x5b32566, 4, 3, 1),
    ('parent_output_base', 0x5868255, 5, 4, 1),
    ('parent_output_pointer', 0x5868264, 5, 4, 1),
    ('parent_output_count', 0x5868269, 5, 4, 1),
    ('parent_output_capacity', 0x5868281, 5, 4, 1),
    ('projection_argument_begin_store', 0x5868296, 8, 4, 4),
    ('projection_argument_cursor_store', 0x586829e, 8, 4, 4),
    ('projection_argument_capacity_store', 0x58682a6, 8, 4, 4),
    ('projection_argument_end_store', 0x58682ae, 8, 4, 4),
    ('projection_argument_base', 0x58682be, 8, 4, 4),
    ('projection_input_cursor', 0x596132d, 4, 3, 1),
    ('projection_input_capacity', 0x5961326, 4, 3, 1),
    ('projection_input_end', 0x5961339, 4, 3, 1),
    ('guard_slot_saved', 0x5868062, 5, 4, 1),
    ('guard_slot_reloaded', 0x586823c, 5, 4, 1),
    ('guard_slot_argument_store', 0x5868241, 5, 4, 1),
    ('guard_argument_base', 0x586825a, 5, 4, 1),
    ('wrapper_input_chunk', 0x5b3252b, 5, 4, 1),
    ('wrapper_output_chunk', 0x5b3253a, 5, 4, 1),
    ('wrapper_argument_base', 0x5b32557, 5, 4, 1),
    ('item_slot_input', 0x5865dd4, 4, 3, 1),
    ('item_slot_saved', 0x5865dd8, 5, 4, 1),
    ('item_slot_reloaded', 0x586602a, 5, 4, 1),
    ('item_input_stride', 0x5865e66, 5, 1, 4),
    ('item_output_stride', 0x5865e47, 4, 3, 1),
    ('item_output_tail', 0x5865e3f, 5, 4, 1),
    ('item_tag', 0x5865f0c, 10, 8, 2),
    ('handler_tag', 0x54851bc, 5, 1, 4),
    ('handler_map_count', 0x5485221, 7, 3, 4),
    ('handler_map_rows', 0x5485240, 7, 3, 4),
    ('handler_counter_before', 0x548543d, 7, 3, 4),
    ('handler_map_base', 0x54854b6, 7, 3, 4),
    ('handler_counter_after', 0x54854bd, 7, 3, 4),
    ('handler_multiplier', 0x54855b4, 5, 1, 4),
    ('handler_value_word', 0x54857a2, 4, 3, 1),
    ('handler_return_code', 0x5485957, 4, 2, 2),
    ('alias_count', 0x55f4794, 7, 3, 4),
    ('alias_rows', 0x55f47a6, 7, 3, 4),
    ('alias_key', 0x55f47ad, 5, 4, 1),
    ('alias_stride_sib', 0x55f4843, 4, 3, 1),
    ('alias_stride_shift', 0x55f4847, 4, 3, 1),
    ('alias_value_head', 0x55f4853, 6, 5, 1),
    ('alias_value_tail', 0x55f484b, 4, 3, 1),
    ('nested_result_tag', 0x55f496a, 2, 1, 1),
    ('nested_result_code', 0x55f497a, 6, 2, 4),
    ('nested_overflow_shift', 0x55f4992, 4, 3, 1),
    ('nested_multiplier_shift', 0x55f499c, 4, 3, 1),
    ('nested_value_word', 0x55f4b0e, 4, 3, 1),
    ('insert_stride_sib', 0x4ef55c2, 4, 3, 1),
    ('insert_stride_shift', 0x4ef55c6, 4, 3, 1),
    ('insert_value', 0x4ef55e1, 6, 5, 1),
    ('insert_key_head', 0x4ef55fd, 6, 5, 1),
    ('insert_key_tail', 0x4ef5607, 5, 4, 1),
    ('insert_element_size', 0x4ef56f6, 6, 2, 4),
    ('projection_input_stride', 0x5961364, 4, 3, 1),
    ('projection_output_stride', 0x596137b, 4, 3, 1),
    ('projection_remainder_mask', 0x59613f1, 4, 3, 1),
    ('projection_align_mask', 0x59613fd, 4, 3, 1),
)


def authenticate(data, expected=SHA115):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('input SHA-256 mismatch')
    return digest


def named_section(sec_rows, name):
    matches = [s for s in sec_rows if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, duplicate, or fileless section')
    return matches[0]


def file_offset(data, sec_rows, va, size, *, executable=False):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid address range')
    matches = [s for s in sec_rows if s['type'] != 8 and s['size'] and s['flags'] & 2
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address has no unique file-backed mapping')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('mapped range outside input')
    return off


def read_va(data, sec_rows, va, size, *, executable=False):
    off = file_offset(data, sec_rows, va, size, executable=executable)
    return bytes(data[off:off + size])


def select_fdes(data, sec_rows):
    parsed_sections, index = unwind_index(data)
    if parsed_sections != sec_rows:
        raise ValueError('ELF section views disagree')
    _, records = eh_frame_records(data, sec_rows)
    by_record = {f['fde']: f for f in records}
    by_start = {r['start']: r for r in index}
    if len(by_record) != len(records) or len(by_start) != len(index):
        raise ValueError('duplicate unwind record or start')
    result = []
    for role, start, end, expected in FDE_SPECS:
        entry = by_start.get(start)
        rec = by_record.get(entry['fde']) if entry else None
        if rec is None or rec['start'] != start or rec['end'] != end:
            raise ValueError('selected FDE/header mismatch')
        if end > entry['next_index_upper_bound']:
            raise ValueError('selected FDE crosses next indexed start')
        body = read_va(data, sec_rows, start, end - start, executable=True)
        if hashlib.sha256(body).hexdigest() != expected:
            raise ValueError('selected FDE bytes changed')
        result.append(dict(rec, role=role, index=entry['index'], body=body))
    ordered = sorted(result, key=lambda r: r['start'])
    if any(a['end'] > b['start'] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('selected FDEs overlap')
    return result


def check_windows(data, sec_rows, specs=WINDOWS):
    rows = []
    for label, va, expected_hex in specs:
        expected = bytes.fromhex(expected_hex)
        off = file_offset(data, sec_rows, va, len(expected), executable=True)
        actual = bytes(data[off:off + len(expected)])
        if actual != expected:
            raise ValueError('selected instruction window changed')
        rows.append((label, hex(va), hex(off), len(actual), actual.hex()))
    return rows


def decode_transfer(va, raw):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return 'rel', va + len(raw) + struct.unpack_from('<i', raw, 1)[0]
    if len(raw) == 6 and raw[:2] == b'\xff\x15':
        return 'slot', va + len(raw) + struct.unpack_from('<i', raw, 2)[0]
    if len(raw) == 3 and raw[:2] == b'\xff\x53':
        return 'reg', raw[2]
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        return 'jcc8', va + 2 + struct.unpack_from('<b', raw, 1)[0]
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return 'jcc32', va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError('unsupported selected transfer')


def covered_by_window(va, size):
    return any(start <= va and va + size <= start + len(bytes.fromhex(raw))
               for _, start, raw in WINDOWS)


def transfer_rows(data, sec_rows, fdes):
    rows = []
    for va, expected_hex, expected_kind, expected_target in TRANSFERS:
        size = len(bytes.fromhex(expected_hex))
        if not covered_by_window(va, size):
            raise ValueError('transfer not in pinned window')
        off = file_offset(data, sec_rows, va, size, executable=True)
        raw = bytes(data[off:off + size])
        kind, target = decode_transfer(va, raw)
        if raw.hex() != expected_hex or (kind, target) != (expected_kind, expected_target):
            raise ValueError('selected transfer changed')
        owner = next((f['role'] for f in fdes if f['start'] <= va < f['end']), 'context')
        if kind.startswith('jcc'):
            cc = raw[0] & 15 if kind == 'jcc8' else raw[1] & 15
            condition = ('overflow', 'no_overflow', 'below', 'above_or_equal',
                         'equal', 'not_equal', 'below_or_equal', 'above',
                         'sign', 'not_sign', 'parity', 'not_parity',
                         'less', 'greater_or_equal', 'less_or_equal', 'greater')[cc]
        else:
            condition = '-'
        rows.append((owner, hex(va), hex(off), raw.hex(), kind, hex(target), condition))
    return rows


def count_pushes(raw):
    """Count the pinned low/extended-register push sequence in the nested prologue."""
    count = 0
    pos = 0
    while pos < len(raw):
        if raw[pos] == 0x41:
            pos += 1
        if pos >= len(raw) or not 0x50 <= raw[pos] <= 0x57:
            raise ValueError('unsupported prologue push')
        count += 1
        pos += 1
    return count


def operand_rows(data, sec_rows):
    rows, values = [], {}
    for name, va, size, offset, width in OPERANDS:
        if not 0 <= offset < size or width < 1 or offset + width > size:
            raise ValueError('invalid operand specification')
        if not covered_by_window(va, size):
            raise ValueError('operand not in pinned window')
        raw = read_va(data, sec_rows, va, size, executable=True)
        value = int.from_bytes(raw[offset:offset + width], 'little')
        values[name] = value
        rows.append((name, hex(va), hex(file_offset(data, sec_rows, va, size, executable=True)),
                     raw.hex(), offset, width, hex(value)))
    push_va = 0x55f4760
    push_raw = read_va(data, sec_rows, push_va, 10, executable=True)
    if not covered_by_window(push_va, len(push_raw)):
        raise ValueError('nested prologue not in pinned window')
    values['nested_push_count'] = count_pushes(push_raw)
    rows.append(('nested_push_count', hex(push_va),
                 hex(file_offset(data, sec_rows, push_va, len(push_raw), executable=True)),
                 push_raw.hex(), 0, len(push_raw), hex(values['nested_push_count'])))
    return rows, values


def selected_relocations(data, sec_rows, wanted):
    sec = named_section(sec_rows, '.rela.dyn')
    if sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('bad relocation section')
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        target, info, addend = struct.unpack_from('<QQq', data, off)
        if target in wanted:
            if target in found:
                raise ValueError('duplicate selected relocation')
            if info != 8 or addend < 0:
                raise ValueError('unexpected selected relocation')
            found[target] = (addend, off)
    if set(found) != set(wanted):
        raise ValueError('missing selected relocation')
    return found


def contextual_worker_slot(data, sec_rows):
    """Recheck an existing callback slot solely as a boundary, not new ownership."""
    slot = 0x64e71d0
    addend, offset = selected_relocations(data, sec_rows, [slot])[slot]
    raw = read_va(data, sec_rows, slot, 8)
    if raw != bytes(8) or addend != 0x5a6e1e0:
        raise ValueError('contextual worker slot changed')
    return [('context', hex(slot), hex(file_offset(data, sec_rows, slot, 8)),
             hex(offset), 8, 0, hex(addend), raw.hex())]


def location_rows(data, sec_rows):
    wanted = ((0x64767a8, 123, 37), (0x64aa208, 460, 78))
    relocs = selected_relocations(data, sec_rows, [a for a, _, _ in wanted])
    rows = []
    for address, expected_line, expected_column in wanted:
        raw = read_va(data, sec_rows, address, 24)
        ptr, length, line, column = struct.unpack('<QQII', raw)
        string_va, relocation_off = relocs[address]
        if ptr != 0 or (line, column) != (expected_line, expected_column):
            raise ValueError('Location bytes changed')
        value = read_va(data, sec_rows, string_va, length)
        if value != b'l1/src/abci/state.rs':
            raise ValueError('Location path changed')
        rows.append((hex(address), hex(file_offset(data, sec_rows, address, 24)),
                     hex(relocation_off), hex(string_va), length, line, column,
                     value.decode('ascii'), raw.hex()))
    return rows


def lsda_rows(data, sec_rows, fde):
    if fde['lsda'] is None:
        return []
    sec = named_section(sec_rows, '.gcc_except_table')
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = file_offset(data, sec_rows, va, 1)
    limit = sec['offset'] + sec['size']
    if pos + 2 > limit or data[pos] != 0xff or data[pos + 1] not in (0x9b, 0xff):
        raise ValueError('unsupported LSDA encoding')
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding == 0x9b:
        type_delta, pos = uleb(data, pos, limit)
        type_base = pos + type_delta
    else:
        type_base = limit
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('bad LSDA header')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    if end > limit or end > type_base:
        raise ValueError('LSDA table outside bounds')
    rows = []
    while pos < end:
        begin = pos
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + length > fde['end'] - fde['start']:
            raise ValueError('LSDA call range outside FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('LSDA landing outside FDE')
        rows.append((fde['role'], hex(va), hex(begin), hex(fde['start'] + start),
                     hex(fde['start'] + start + length),
                     hex(fde['start'] + landing) if landing else '-', action,
                     bytes(data[begin:pos]).hex()))
    if pos != end:
        raise ValueError('misaligned LSDA table')
    return rows


def link_unwind(transfers, rows, fdes):
    by_role = {f['role']: f for f in fdes}
    result = []
    for role, site, _, raw, kind, target, _condition in transfers:
        if role == 'context' or kind not in ('rel', 'slot', 'reg'):
            continue
        # Unconditional jumps do not have call-site semantics here.
        if bytes.fromhex(raw)[0] == 0xe9:
            continue
        addr = int(site, 16)
        matches = [r for r in rows if r[0] == role and int(r[3], 16) <= addr < int(r[4], 16)]
        if len(matches) > 1:
            raise ValueError('ambiguous LSDA call site')
        if matches:
            status, landing, action = 'covered', matches[0][5], matches[0][6]
        else:
            status = 'no_lsda' if by_role[role]['lsda'] is None else 'not_in_table'
            landing, action = '-', '-'
        result.append((role, site, kind, target, status, landing, action))
    return result


def verify_joins(values, transfer_records):
    if values['worker_saved_callback'] != values['worker_reloaded_callback']:
        raise ValueError('worker did not reload its callback pointer')
    if (values['worker_captured_owner'], values['worker_owner_body'],
            values['worker_owner_guard']) != (0x6a0, 0x10, 0x140):
        raise ValueError('worker owner layout differs from the contextual boundary')
    worker_owner_arg = values['worker_owner_argument_store'] - values['worker_argument_base']
    if worker_owner_arg != 0x20:
        raise ValueError('worker owner pointer is not at input offset 0x20')
    result_base = values['worker_result_base']
    result_head = values['worker_result_head_destination']
    tail_destination = values['worker_result_tail_destination']
    if not (values['worker_result_head_source'] == result_base and
            values['worker_result_word_source'] == result_base + 16 and
            values['worker_result_word_destination'] == result_head + 16 and
            values['worker_result_extra_source'] == result_base + 24 and
            values['worker_result_flag_source'] == result_base + 32 and
            values['worker_result_tail_source'] == result_base + 40 and
            values['worker_result_tail_second'] == tail_destination + 16 and
            values['worker_result_tail_word'] == tail_destination + 32):
        raise ValueError('worker block-result slices do not join')
    if not (values['worker_pending_write_offset'] == values['worker_pending_read_offset'] ==
            values['worker_pending_clear_offset'] == 0x5f8 and
            values['worker_pending_sentinel'] == 1 << 63):
        raise ValueError('worker pending slot or sentinel changed')
    if values['guard_slot_saved'] != values['guard_slot_reloaded']:
        raise ValueError('guard saved state-slot pointer was not reloaded')
    arg_offset = values['guard_slot_argument_store'] - values['guard_argument_base']
    source_delta = arg_offset - values['wrapper_input_chunk']
    if not 0 <= source_delta <= 8:
        raise ValueError('state-slot pointer is outside the copied 16-byte chunk')
    forwarded = values['wrapper_output_chunk'] + source_delta - values['wrapper_argument_base']
    if forwarded != values['item_slot_input'] or values['item_slot_saved'] != values['item_slot_reloaded']:
        raise ValueError('state-slot pointer handoff does not join')
    if values['wrapper_count_pointer'] != values['wrapper_count_stack']:
        raise ValueError('wrapper length pointer and reload differ')
    if values['wrapper_count_output'] != values['parent_output_count'] - values['parent_output_base']:
        raise ValueError('wrapper and parent count fields differ')
    base = values['projection_argument_base']
    fields = (('projection_argument_begin_store', 0),
              ('projection_argument_cursor_store', values['projection_input_cursor']),
              ('projection_argument_capacity_store', values['projection_input_capacity']),
              ('projection_argument_end_store', values['projection_input_end']))
    if any(values[store] - base != member for store, member in fields):
        raise ValueError('parent and projection argument fields do not join')
    if values['item_input_stride'] != 2 * values['item_output_stride']:
        raise ValueError('input and output strides do not join')
    capacity_first = values['projection_capacity_first_sib']
    if capacity_first & 0x3f != (6 << 3) | 5:
        raise ValueError('projection capacity does not scale its input register')
    capacity_sib = values['projection_capacity_second_sib']
    if (capacity_sib & 7) != ((capacity_sib >> 3) & 7):
        raise ValueError('projection capacity factor has different base and index')
    capacity_factor = ((1 << (values['projection_capacity_first_sib'] >> 6)) *
                       (1 + (1 << (capacity_sib >> 6))))
    if capacity_factor != values['projection_input_stride']:
        raise ValueError('projection capacity factor differs from input stride')
    if values['item_output_stride'] != values['projection_input_stride']:
        raise ValueError('item and projection strides do not join')
    if values['item_output_tail'] != values['projection_output_stride']:
        raise ValueError('projection tail boundary does not join')
    if not (values['handler_key_tail'] - values['handler_key_head'] ==
            values['alias_key_tail'] - values['alias_key'] ==
            values['alias_value_tail'] - values['alias_value_head'] == 16):
        raise ValueError('selected 16-byte key and replacement heads do not join')
    if not (values['handler_clock_head'] == values['nested_clock_head'] and
            values['handler_clock_head'] + values['handler_clock_tail'] == values['nested_clock_tail'] and
            values['handler_value_clock_head'] == values['nested_value_clock_head'] and
            values['handler_value_clock_tail'] == values['nested_value_clock_tail'] and
            values['handler_value_clock_tail'] - values['handler_value_clock_head'] == 8):
        raise ValueError('clock-word copying offsets do not join')
    if values['handler_tag'] != values['item_tag']:
        raise ValueError('item and handler tags differ')
    if values['handler_map_rows'] - values['handler_map_base'] != values['insert_value']:
        raise ValueError('map and row pointer offsets do not join')
    insert_sib = values['insert_stride_sib']
    alias_sib = values['alias_stride_sib']
    if any((sib & 7) != ((sib >> 3) & 7) for sib in (insert_sib, alias_sib)):
        raise ValueError('stride does not use matching base and index registers')
    stride = (1 + (1 << (insert_sib >> 6))) << values['insert_stride_shift']
    if stride != values['insert_element_size']:
        raise ValueError('insertion stride differs from growth element size')
    if values['handler_value_word'] != values['nested_value_word']:
        raise ValueError('normal and nested value offsets differ')
    if values['nested_overflow_shift'] + values['nested_multiplier_shift'] != 64:
        raise ValueError('nested multiply overflow width differs')
    if values['handler_flag_store_offset'] != values['handler_flag_address_offset']:
        raise ValueError('initialized nested flag is not the supplied address')
    stack_argument = values['nested_flag_stack_offset'] - values['nested_frame_size'] - 8 * values['nested_push_count']
    if stack_argument != 16:
        raise ValueError('nested flag is not the second stack argument')
    if values['handler_nested_flag'] != values['nested_flag_compare']:
        raise ValueError('supplied nested flag differs from compared flag')
    if values['nested_result_code'] != values['handler_return_code']:
        raise ValueError('selected result codes differ')
    edges = {int(row[1], 16): int(row[5], 16) for row in transfer_records}
    expected = {0x5a6e743: 0x5a6e7ef, 0x5a6e870: 0x5a6e8fe,
                0x5a6ea10: 0x4f122c0, 0x5a6ead6: 0x4f1ec10, 0x5a6eaf6: 0x5a6ebb5,
                0x5b3255c: 0x5865d80, 0x5866042: 0x54851a0,
                0x548580d: 0x55f4760, 0x58682c6: 0x5961310}
    if any(edges.get(site) != target for site, target in expected.items()):
        raise ValueError('selected direct-call join changed')
    return {
        'worker_callback_owner_offset': hex(values['worker_captured_owner']),
        'worker_allocation_to_body_offset': hex(values['worker_owner_body']),
        'worker_owner_guard_offset': hex(values['worker_owner_guard']),
        'worker_owner_argument_offset': hex(worker_owner_arg),
        'worker_result_base': hex(result_base),
        'worker_result_head_destination': hex(result_head),
        'worker_result_extra_destination': hex(values['worker_result_extra_destination']),
        'worker_result_flag_destination': hex(values['worker_result_flag_destination']),
        'worker_result_tail_destination': hex(tail_destination),
        'worker_pending_offset': hex(values['worker_pending_write_offset']),
        'worker_pending_sentinel': hex(values['worker_pending_sentinel']),
        'guard_state_argument_offset': hex(arg_offset),
        'item_state_argument_offset': hex(forwarded),
        'sort_first_count': hex(values['sort_first_count']),
        'sort_second_count': hex(values['sort_second_count']),
        'wrapper_count_output_offset': hex(values['wrapper_count_output']),
        'parent_output_pointer_offset': hex(values['parent_output_pointer'] - values['parent_output_base']),
        'projection_cursor_offset': hex(values['projection_input_cursor']),
        'projection_capacity_offset': hex(values['projection_input_capacity']),
        'projection_end_offset': hex(values['projection_input_end']),
        'item_input_stride': hex(values['item_input_stride']),
        'item_output_stride': hex(values['item_output_stride']),
        'projected_stride': hex(values['projection_output_stride']),
        'projection_capacity_factor': hex(capacity_factor),
        'omitted_row_tail_bytes': hex(values['item_output_stride'] - values['projection_output_stride']),
        'handler_map_state_offset': hex(values['handler_map_base']),
        'insert_row_stride': hex(stride),
        'insert_row_key_offset': hex(values['insert_key_head']),
        'insert_value_offset': hex(values['insert_value']),
        'handler_and_nested_value_offset': hex(values['handler_value_word']),
        'combined_row_word_offset': hex(values['insert_value'] + values['handler_value_word']),
        'alias_row_stride': hex((1 + (1 << (alias_sib >> 6))) << values['alias_stride_shift']),
        'handler_inline_key_offset': hex(values['handler_key_head']),
        'alias_key_offset': hex(values['alias_key']),
        'alias_replacement_offset': hex(values['alias_value_head']),
        'nested_multiplier': hex(1 << values['nested_multiplier_shift']),
        'gate_zero_code': hex(values['gate_zero_code']),
        'membership_miss_code': hex(values['membership_miss_code']),
        'handler_nested_flag': hex(values['handler_nested_flag']),
        'nested_stack_argument_offset': hex(stack_argument),
        'handler_multiplier': hex(values['handler_multiplier']),
        'state_clock_offset': hex(values['handler_clock_head']),
        'value_clock_offset': hex(values['handler_value_clock_head']),
        'conditions': 'Selected paths and static layout only; runtime aliases, helper effects and dispatch remain unresolved.',
    }


def historical_check(data):
    """Optional, separately authenticated #94 historical anchor; emits no file."""
    authenticate(data, SHA94)
    sec_rows = sections(data)
    loc = 0x56dfbf8
    historical_slot = 0x57755a8
    relocations = selected_relocations(data, sec_rows, [loc, historical_slot])
    rel = relocations[loc]
    if relocations[historical_slot][0] != 0x3273810:
        raise ValueError('historical relocation changed')
    old_call = read_va(data, sec_rows, 0x3272785, 6, executable=True)
    if decode_transfer(0x3272785, old_call) != ('slot', historical_slot):
        raise ValueError('historical caller changed')
    ptr, length, line, col = struct.unpack('<QQII', read_va(data, sec_rows, loc, 24))
    path = read_va(data, sec_rows, rel[0], length)
    if ptr != 0 or (line, col) != (107, 37) or not path.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical Location changed')
    _, fdes = eh_frame_records(data, sec_rows)
    matches = [f for f in fdes if f['start'] == 0x3273810]
    if len(matches) != 1 or matches[0]['end'] != 0x327396c:
        raise ValueError('historical FDE changed')
    reference = read_va(data, sec_rows, 0x3273856, 7, executable=True)
    if (reference[:3] != b'\x48\x8d\x0d' or
            0x3273856 + 7 + struct.unpack_from('<i', reference, 3)[0] != loc):
        raise ValueError('historical reference changed')
    outer = [f for f in fdes if f['start'] == 0x32725d0]
    if len(outer) != 1 or not outer[0]['start'] <= 0x3272785 < outer[0]['end']:
        raise ValueError('historical caller FDE changed')



def reference_rows(data, sec_rows):
    # A Location reference in the newly selected handler, not the old loader call.
    va = 0x54859e9
    if not covered_by_window(va, 7):
        raise ValueError('Location reference not in pinned window')
    raw = read_va(data, sec_rows, va, 7, executable=True)
    if raw[:2] != b'\x4c\x8d' or raw[2] & 0xc7 != 5:
        raise ValueError('unsupported Location reference')
    target = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    if target != 0x64aa208:
        raise ValueError('Location reference target changed')
    return [('handler_location', hex(va), hex(file_offset(data, sec_rows, va, 7, executable=True)),
             raw.hex(), hex(target))]


def saturating_add(left, right):
    limit = (1 << 64) - 1
    if not (0 <= left <= limit and 0 <= right <= limit):
        raise ValueError('operand outside unsigned word')
    return min(left + right, limit)


def saturating_multiply(value, factor):
    limit = (1 << 64) - 1
    if not (0 <= value <= limit and factor in (4, 5)):
        raise ValueError('invalid selected multiplier or unsigned word')
    return min(value * factor, limit)


def sorting_lane(count, first, second):
    """Synthetic model of the two selected unsigned row-count branches."""
    if not (0 <= count < 1 << 64 and 0 < first < second):
        raise ValueError('invalid row count or thresholds')
    return 0 if count < first else 1 if count < second else 2


def next_item_state(tag, count):
    """Synthetic model of the selected low-dword tag and saturated count stores."""
    maximum = (1 << 64) - 1
    if not (0 <= tag <= maximum and 0 <= count <= maximum):
        raise ValueError('state word outside unsigned range')
    if (tag & 0xffffffff) == 1:
        return tag, min(count + 1, maximum)
    return 1, 1


def projection_capacity(capacity, input_stride, output_stride):
    """Synthetic model of the selected 64-bit capacity arithmetic only."""
    if not (0 <= capacity < 1 << 64 and input_stride > 0 and output_stride > 0):
        raise ValueError('invalid capacity or stride')
    wrapped_bytes = (capacity * input_stride) & ((1 << 64) - 1)
    return wrapped_bytes // output_stride


def compact_rows(raw, input_stride, output_stride):
    """Synthetic byte model, not a captured execution or ownership simulation."""
    if not (0 < output_stride <= input_stride) or len(raw) % input_stride:
        raise ValueError('invalid row framing')
    data = bytearray(raw)
    dest = 0
    for source in range(0, len(data), input_stride):
        chunk = bytes(data[source:source + output_stride])
        data[dest:dest + output_stride] = chunk
        dest += output_stride
    return bytes(data[:dest])


def singleton_alias(original, stored_key, replacement):
    """Synthetic 20-byte singleton branch, preserving the original on mismatch."""
    if any(len(part) != 20 for part in (original, stored_key, replacement)):
        raise ValueError('keys must each be 20 bytes')
    return replacement if original == stored_key else original


def tsv(headers, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('utf-8')


def collect(data):
    digest = authenticate(data)
    sec_rows = sections(data)
    fdes = select_fdes(data, sec_rows)
    windows = check_windows(data, sec_rows)
    transfers = transfer_rows(data, sec_rows, fdes)
    operands, values = operand_rows(data, sec_rows)
    locations = location_rows(data, sec_rows)
    boundary = contextual_worker_slot(data, sec_rows)
    references = reference_rows(data, sec_rows)
    unwind = [row for fde in fdes for row in lsda_rows(data, sec_rows, fde)]
    unwind_links = link_unwind(transfers, unwind, fdes)
    joins = verify_joins(values, transfers)
    function_rows = [(f['role'], hex(f['start']), hex(f['end']),
                      hex(file_offset(data, sec_rows, f['start'], len(f['body']), executable=True)),
                      len(f['body']), hex(f['fde']), hex(f['cie']),
                      hex(f['lsda']) if f['lsda'] else '-', f['index'],
                      hashlib.sha256(f['body']).hexdigest(), f['body'].hex()) for f in fdes]
    summary = {
        'binary_sha256': digest,
        'coordinate_system': 'linked ELF virtual addresses and separately named file offsets',
        'selected_fdes': len(fdes),
        'instruction_windows': len(windows),
        'context_windows': sum(row[0].startswith('context_') for row in windows),
        'transfers': len(transfers),
        'operands': len(operands),
        'locations': len(locations),
        'contextual_worker_relocations': len(boundary),
        'selected_location_references': len(references),
        'lsda_rows': len(unwind),
        'unwind_call_links': len(unwind_links),
        'lsda_covered_calls': sum(row[4] == 'covered' for row in unwind_links),
        'limitations': 'Selections are not a complete CFG, runtime execution, or a coverage denominator.',
    }
    files = {
        'functions.tsv': tsv(('role','start_va','end_va_exclusive','file_offset','length','fde_va','cie_va','lsda_va','unwind_index','sha256','body_hex'), function_rows),
        'windows.tsv': tsv(('label','va','file_offset','length','bytes_hex'), windows),
        'transfers.tsv': tsv(('role','va','file_offset','bytes_hex','kind','target_va_or_offset','condition_code'), transfers),
        'operands.tsv': tsv(('label','va','file_offset','bytes_hex','operand_offset','width','value'), operands),
        'locations.tsv': tsv(('va','file_offset','relocation_file_offset','path_va','length','line','column','path','record_hex'), locations),
        'boundary-relocation.tsv': tsv(('ownership','slot_va','file_offset','relocation_file_offset','type','symbol','addend_va','slot_hex'), boundary),
        'references.tsv': tsv(('label','va','file_offset','bytes_hex','target_va'), references),
        'unwind.tsv': tsv(('role','lsda_va','entry_file_offset','start_va','end_va_exclusive','landing_va','action','raw_hex'), unwind),
        'unwind-links.tsv': tsv(('role','call_va','kind','target_va_or_offset','status','landing_va','action'), unwind_links),
        'joins.json': json_bytes(joins),
        'summary.json': json_bytes(summary),
    }
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--old-elf', type=Path, help='optional separately authenticated release 94')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    # Authenticate before opening the optional historical input or creating output.
    authenticate(data)
    if args.old_elf is not None:
        historical_check(args.old_elf.read_bytes())
    outputs = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()
