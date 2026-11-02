#!/usr/bin/env python3
"""Extract selected node 115 EVM preflight bytes without executing target code."""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
U128 = (1 << 128) - 1
U256 = (1 << 256) - 1

# Unwind-described ranges selected here, not a complete function census.
FUNCTIONS = (
    ('environment validation', 0x2b92c10, 0x2b93026),
    ('input cost admission', 0x2b93030, 0x2b931c1),
    ('cost calculation', 0x5be0720, 0x5be0a92),
    ('mode to schedule cache', 0x5be0aa0, 0x5be0cac),
    ('mode-13 once adapter', 0x5be2a93, 0x5be2adc),
    ('schedule initializer slot 18', 0x5be2ce0, 0x5be2d11),
    ('schedule initializer slot 20', 0x5be29d0, 0x5be2a01),
    ('schedule allocation and coefficients', 0x5be2560, 0x5be29c7),
    ('payer account and code wrapper', 0x299f4d0, 0x299f676),
    ('account cache loader', 0x4323870, 0x4323f10),
    ('account map entry', 0x3ed7040, 0x3ed71a8),
    ('account policy membership', 0x5bdf8e0, 0x5bdf9f7),
    ('policy associated map membership', 0x5bdef30, 0x5bdf01f),
    ('policy fallback map membership', 0x5bdf020, 0x5bdf10f),
    ('recipient account and code wrapper', 0x2971760, 0x2971888),
    ('payer budget and balance', 0x2973440, 0x29738de),
)

# Byte windows are independently checked before any derived rows are emitted.
# The windows labelled prior are short handoff anchors in a previously owned FDE.
PINS = (
    ('prior_context_base', 0x29a12be, '488dbc24100b0000ff15045ab403488dbc2430020000e8270bfdff'),
    ('prior_tx_subobject', 0x29a1b94, '4c8dbc24f00b00004c89ff'),
    ('prior_lookup_key', 0x2a6bc5d, '488db190000000e8f7060000'),
    ('prior_default_mode_call', 0x5be7920, 'bf0d000000ff15ad1d90004989c6c64424700d4889442458'),
    ('prior_validate_gate', 0x29a1bba, '488dbc2430020000488db424100b0000e841101f00488b8424300200004883f8257534'),
    ('prior_cost_gate', 0x29a1c44, '48890424488dbc24300200004c89fe4531c0e8d5131f00488b8424300200000f108424380200000f294424500f108424480200000f294424604883f8210f85bd030000'),
    ('prior_payer_key', 0x29a1ca3, '488db424800d00008b8424e80c0000898424b0010000f30f6f8424d80c0000660f7f8424a0010000488dbc2430020000488d9424a0010000e8f0d7ffff'),
    ('prior_payer_balance_call', 0x29a1d19, '498b5c2468488bac24d00c0000440fb6ac24710d000080bc24730d0000000f84630300004584ed0f84820300004d8d6c2428f3410f6f4500f3410f6f4d10660f7f8c24b0010000660f7f8424a0010000488dbc2430020000488db424a0010000488d8c24100b00004c89fae8b716fdff'),
    ('prior_payload_clone', 0x29a2ddd, '488b8424200c0000488b9424280c0000488db424380c0000488b8c24300c0000488dbc2410010000ff10488dac24d80c0000'),
    ('prior_frame_key_input', 0x29a2e0f, '80bc24ec0c0000010f85170100008b8424fd0c000089842430080000f30f6f8424ed0c0000660f7f84242008000089842440020000660f7f842430020000'),
    ('prior_recipient_call', 0x29a2e4d, '4c8da424a80e0000488d942430020000488dbc24800d00004c89e6b9010000004531c0e8ebe8fcff80fa020f8407290000'),
    ('prior_frame_key_store', 0x29a30d1, '0f288424200800000f118424c00200008b842430080000898424d0020000'),
    ('prior_frame_second_key', 0x29a3113, '8b842430080000898424e4020000660f6f842420080000f30f7f8424d4020000'),
    ('prior_frame_allocation', 0x29a3133, '48c784243002000000000000c68424fe0200000066c78424fc0200000000bfd0000000ff1524c3b3034885c00f84592400004989c6488db42430020000bad00000004889c7ff158ac3b303'),
    ('prior_frame_call', 0x29a31c3, '488dbc2430020000488db424100b0000488d942450090000e8d0b0fcff'),
    ('validator_prefix', 0x2b92c10, '4889f80fb68e6802000080f9087626f686bc00000001747c80f90a7618488b1641b101480b5608750f48c70021000000c6400801c34531c9'),
    ('validator_flags', 0x2b92c4b, '0fb69ef10100000fb69664020000488bbe98000000f6c31f410f94c080fb05410f93c241bbff000000440f42db'),
    ('validator_network', 0x2b92c78, '80be6002000000743883be000100000175264c8b86080100004c3b8658020000741fba0c000000e91603000048c70021000000c6400800c34508c20f84a2000000'),
    ('validator_type_dispatch', 0x2b92cb9, '80be650200000074514180fb040f8779010000450fb6c34c8d158546a7fd4f6304824d01d041ffe0'),
    ('validator_type0_fee', 0x2b92ce1, '80f9060f86750200004c8b86380100004839be300100004983d800400f93c74008d70f853c010000ba01000000e9a7020000'),
    ('validator_type4_fee', 0x2b92d65, '80f90b0f86dc0100004c8b86380100004c8b8e300100004c3b8ef00000004d89c24c1b96f8000000410f92c2442296e00000004939f94983d800400f93c74008d7400fb6ff89fac1e20548ffc24531db4584d2490f45d34180f2014420d74080ff010f857b0100004883beb001000000756eba19000000e9d9010000'),
    ('validator_type2_fee', 0x2b92de1, '80f9070f86670100004c8b86380100004c8b8e300100004c3b8ef00000004d89c24c1b96f8000000410f92c2442296e00000004939f94983d800400f93c74008d7400fb6ff89fac1e20548ffc24531db4584d2490f45d34180f2014484d70f8403010000'),
    ('validator_type3_fee_and_list', 0x2b92e9e, '4584c90f84b10000004c8b86380100004c8b8e300100004c3b8ef00000004d89c24c1b96f8000000410f92c2442296e00000004939f94983d800400f93c74008d7400fb6ff89fac1e20548ffc24531db4584d2490f45d34180f2014420d74080ff017546488b96900100004c8b9698010000488bbe600100004c8b8e68010000f606010f84ae000000488b5e104c8b5e184839df4d89c84d19d80f8397000000ba120000004989daeb72eb70'),
    ('validator_size', 0x2b92d13, '4531d280f90d4d19d280be400200000074154c8b96480200004c8b86b80100004d39d07719eb884981ca000000014c8b86b80100004d39d00f8671ffffffba0e000000e95f020000ba0d000000e955020000'),
    ('validator_limit', 0x2b92e45, '80be6202000000751a488b96b8010000483b9690000000760aba02000000e95201000080f90a0f822f01000080bedc010000000f8522010000488b962001000080be10020000000f84d4000000488bbe18020000e9f6000000'),
    ('validator_initcode', 0x2b92f66, '4883be00020000017511488bbe080200004885ff78244801ffeb1331ff80f90e400f93c7c1e70e4881c700c000004839fa7607ba0b000000eb1a'),
    ('validator_success', 0x2b92fa0, '4883bec0010000ff740b48c700250000005b415ec3ba080000004889104c8940084c8958184c895010488978204c8948285b415ec3'),
    ('validator_list', 0x2b92fd5, '4d85d2743e4c8b9e200200004c8b86280200004c89d348c1e3054531f642803c320175264983c6204c39f375f04d39c20f97c24184d30f8434feffffba15000000eba2ba13000000eb9bba16000000eb94'),
    ('cost_count_access', 0x2b9304b, '80be110100000074404d8b8fa00000004d85c97434498b87980000004883c0104531d24c89ca6666666666662e0f1f8400000000004c03100f82110100004883c03048ffca75eeeb064531d24531c9'),
    ('cost_helper_call', 0x2b9309a, '498b5738498b47404531c04180bffc00000000410f94c04889e74889ce4889c141ffb7d00000004152ff15cf3095034883c410'),
    ('cost_initial_gate', 0x2b930cd, '4584e4740948c7442418000000004084ed7407488b4c2408eb0b48c74424080000000031c9482b4c24100f82aa000000488b04244801c10f82aa000000498b97d80000004839d1761148c7030300000048894b0848895310eb63'),
    ('cost_floor_and_extra_gate', 0x2b93127, '4180fe0b7613488b4c24184839d1760948c70304000000ebdd488b4c24504839ca0f97c24084d57422488b5424184839c2480f47c24839c8761148c703040000004889430848894b10eb18'),
    ('cost_result', 0x2b93172, '0f1004240f104c24100f114b180f11430848c703210000004889d84883c4205b415c415e415f5dc3'),
    ('cost_overflow_tails', 0x2b9319a, '488d3d67428a03ff1579c39403488d3d02998b03ff1594c69403488d3d0d998b03ff155fc39403'),
    ('gas_count_zero_bytes', 0x5be0729, '4989d34c8b264d8bac24f000000031f64885c9742131c04889f231f641803c0300400f94c64801d60f826b02000048ffc04839c175e1'),
    ('gas_tokens_and_auth', 0x5be075f, '4889c84829f049f7e50f806e0200004889c34801f30f826f0200004d8bb424580100004d03b42470010000488b74243848c7c0ffffffff4c0f42f0498b9424e80000004c01f2480f42d04889f048f7e20f80410200004989c24889f049f7e60f803f0200004889c64929c20f8240020000'),
    ('gas_base_and_access', 0x5be07d0, '4889d849f7a424f80000000f803c0200004889c34c89c849f7a424100100000f80350200004989c74901df0f82ce010000488b5c24304889d849f7a424180100000f80200200004989c64d01fe0f82ac0100004d03b424200100000f829e0100004d01d60f8295010000'),
    ('gas_create', 0x5be083a, '4584c074474d03b424280100000f822b020000488d411f48c1e80549f7a424300100000f80420100004989c24d01f20f82460100004903b424680100007310488d3da8ea8d00ff159aec8f004d89f2'),
    ('gas_floor_item_weight', 0x5be0889, 'ba140000004c89c848f7e20f80eb0000004889da48c1ea3b0f85f200000048c1e3054801d849c7c0ffffffff490f42c049f7a4248001000070034989c0'),
    ('gas_floor_tokens', 0x5be08c6, '4d39ac247801000075114889c849f7e50f80a90100004889c1eb4a4531c94885c9742731c00f1f4400004c89ca4531c941803c0300410f94c14901d10f82ba00000048ffc04839c175e04c29c94889c849f7e50f80bd0000004889c14c01c90f82be0000004d8b8c2400010000'),
    ('gas_floor_and_output', 0x5be0933, '4c89c848f7e10f80050100004889c149038c24080100000f82010100004c89c049f7e10f80020100004801c10f820601000048c74710000000004c89174889770848894f184889f85b415c415d415e415fc3'),
    ('gas_overflow_tails', 0x5be0985, '48c7c0ffffffff4889da48c1ea3b0f840effffff48c7c3ffffffffe906ffffff49c7c2ffffffff4d01f20f83bafeffff488d3d54e98d00ff155eeb8f00488d3dd7e98d00ff1551eb8f00488d3ddae88d00ff1544eb8f00488d3d8de98d00ff1587ee8f00488d3d98e98d00ff152aeb8f00488d3d6be88d00ff156dee8f00488d3d76e88d00ff1560ee8f00488d3d81e88d00ff152bee8f00488d3d8ce88d00ff1546ee8f00488d3d97e88d00ff1539ee8f00488d3da2e88d00ff152cee8f00488d3d05e88d00ff151fee8f00488d3df8e78d00ff15c2ea8f00488d3ddbe88d00ff1505ee8f00488d3de6e88d00ff15a8ea8f00488d3d79e88d00ff159bea8f00488d3dace78d00ff15deed8f00'),
    ('selector_table', 0x5be0aa5, '40887c240f400fb6c7488d0ddf16d6fa486304814801c8ffe0'),
    ('selector_mode13', 0x5be0b26, '8b053cd59100488d1d2dd5910085c00f844a010000488d74240f4889dfe84b1f0000488b03f048ff000f8f39010000'),
    ('once_descriptor', 0x5be2a93, '8b470885c07501c34883ec28488d442410488930488978084883c708488d4c240748894810488d542408488902488d0d99c98d004c8d05bac98d006a015eff1519cf8f004883c428c3'),
    ('initializer_callback', 0x5be2ce0, '53488b0f488b01488b590848c701000000004885c0740d0fb638e861f8ffff4889035bc3488d3dfdc88d00ff151fcb8f00cc'),
    ('initializer_callback_alt', 0x5be29d0, '53488b0f488b01488b590848c701000000004885c0740d0fb638e871fbffff4889035bc3488d3d0dcc8d00ff152fce8f00'),
    ('schedule_begin', 0x5be2560, '554157415641554154534881ecd800000089fb4531f684db41bf007d00004d0f44fe80fb0241bca86100004d0f42e6'),
    ('schedule_mode6', 0x5be25a9, '80fb067255b80400000048898424a80000000f856b020000'),
    ('schedule_common_constants', 0x5be282c, '31c080fb08b9c0120000480f43e94c0f43e84531f680fb0a410f93c64501f60f280d5e4087fa0f281d770987fa0f281570f186fa0f299424b00000000f2815f10287fa0f299424c00000000f2815021c87fa80fb0c0f829400000080fb0d0f86c1000000'),
    ('schedule_mode13', 0x5be2951, '0f295c24500f295424600f294c2470b8007d000048894424080f57c00f29842490000000f30f1005df7687fa0f29442420f30f10051e7587fa0f294424400f28052a3f87fa0f294424300f28055ed986fa0f298424800000000f57c00f29442410e9bbfcffff'),
    ('schedule_allocation', 0x5be2672, 'bf10080000ff1503ce8f004885c00f843103000080fb03b932000000ba0a000000480f43d1'),
    ('schedule_write_coefficients_a', 0x5be2778, '488b8c24a8000000488988f000000048c780f8000000040000000f284424300f1180000100000f284424500f11801001000048c78020010000085200004c89b8280100004c89b030010000'),
    ('schedule_write_coefficients_b', 0x5be27c3, '0f1188380100000f284424400f1180480100000f288424900000000f1180580100000f284424100f1180680100000f284424200f118078010000'),
    ('account_wrapper_entry', 0x299f4d0, '554157415641554154534881eca80000004889d14889fb488d9628010000488d7c24104531c0ff155c78b4030fb66c24484080fd020f8447010000'),
    ('account_wrapper_digest', 0x299f545, '49837c2470000f85a4000000f3410f6f442448f3410f6f4c2458660f7f8c2490000000660f7f842480000000660f740da72aabfd660f74056f42abfd660fdbc1660fd7c03dffff0000742e'),
    ('account_wrapper_cache', 0x299f590, '498d442448f30f6f00f30f6f4810660f7f4c2420660f7f442410498b7d00488d742410ff159f6eb4034989c6eb184c8b35b376b403418b460885c0756e4d8b36f049ff067e7a4d8d7c2470498b074885c0740ff048ff0875094c89ffff15b659b4034d8937'),
    ('account_wrapper_result', 0x299f5f5, '0f284424700f1143080f284424500f114320488b442460488943308b4424088b4c240b894339894b3c4c89234c896b1840886b384881c4a80000005b415c415d415e415f5dc3488b3d3676b403e87e4395ff4d8b36f049ff067f860f0b488d3d9750abfd488d15b023aa03be21000000ff154d00b4034d89374889c7e8da13a503'),
    ('account_loader_entry', 0x4323870, '554157415641554154534881ec680200004589c64989cc48895424204989f74889fb4881c6c80000008b411089842400010000f30f6f01660f7f8424f0000000488d7c24404c8dac24f00000004c89eae87b37bbff488b6c24404885ed0f84d4000000'),
    ('account_loader_policy_backend', 0x432390e, '498d7f484c89e6ff15bd6d1c024180f6018944240c4108c60f840d050000488b442420488b304883c620418b44241089842490010000410f1004240f29842480010000488d7c2440488d942480010000e80d50a2ff488b4424404883f8027566488b4424484883f8020f826f010000'),
    ('account_loader_key_check', 0x432399a, '31d2ff15feba1b02e945010000488b6c24484c8dad70ffffff8b45f8413b87200100000f85e1030000f645fc100f85d703000031ede98e030000'),
    ('account_loader_insert_choice', 0x4323ad4, '807c240c000f8467010000e99c010000488b064889f7ff10'),
    ('account_loader_default_account', 0x4323aec, '418b87200100008944241c4c8b357a311c02418b460885c00f8587030000498b06f048ff000f8e930300000f57c00f294424500f2944244048c7842480000000000000000f1005694a13fc0f294424600f10056d4a13fc0f29442470c7842490000000000000004889842488000000'),
    ('account_loader_journal', 0x4323c3f, '807c240c00753a4d8b77284d3b7718750a498d7f18ff158e2c1c02498b4720496bce58c6040800410f1004240f11440801418b5424108954081149ffc64d897728'),
    ('account_loader_insert', 0x4323c98, '4c8b7500488b45084889c14c8b4c24384c21c9f3410f6f040e660fd7d085d20f84950100004c8b4424104c896424104989ecf30fbcd24801ca4821c2410fb60c1684c90f89990100008b6c240c4080f50149c1e939488d72f04821c645880c1645884c361080e1010fb6c1492944241048f7da4c69eaa80000004f89842e58ffffff488b4424284b89842e60ffffff8b4424304389842e68ffffff4b8d3c2e4881c76cffffff488d742440ba94000000ff15bab71b0249ff4424184d01f54981c570ffffff4c8b642410'),
    ('account_loader_result', 0x4323d62, '498d4718418b8f200100004983c770418b542410895334f3410f6f0424f30f7f43244c892b488943084c897b10488b44242048894318894b2040886b38e999000000'),
    ('account_loader_refresh', 0x4323da4, '498d7f484c89e6ff1527691c024180f6018944240c4108c64180fe017577418b87200100000fb64dfc89ca80e2ef8855fc8945f8f6c140740c4c89efe8db1affff8065fcbf4c89efff15ee681c028065fc7f4d8b77284d3b77180f84b30000008b6c240c4080f501498b4720496bce58c6040800f3410f6f0424f30f7f440801418b5424108954081149ffc64d897728e929ffffffc64338024889d84881c4680200005b415c415d415e415f5d'),
    ('account_loader_exceptions', 0x4323e91, '488b3de02d1c02e8ffc60200498b06f048ff000f8f6dfcffff0f0bff1536e41b02e9ecfcffff498d7f18ff15272a1c02e93effffff4889c3488b8424880000004885c0742cf048ff087526488dbc2488000000ff15be101c02eb16ff15ceb51b024889c3488dbc24f0000000e80e1903004889dfe846cb0c02ff15b0b51b02'),
    ('entry_map_hash', 0x3ed7040, '41574156415453504989d64889fb488b0a488b05208a6002488b38448b421048334e20488b42084831f848f7e14931d04c31c048f7e74831c24889d748c1ef39'),
    ('entry_map_probe', 0x3ed7080, '488b06488b4e08660f6ec7660f60c0f20f70c000660f70c04431ff660f76c94989d04921c8f3420f6f1400660f6fda660f74d866440fd7cb4585c97463f3450fbcd14d01c24921ca49f7da4d69d2a8000000f3420f6f9c1058fffffff3410f6f26660f74e366420f6e9c1068ffffff66410f6e6e10660f74eb660fdbec66440fd7dd4181fbffff00007433458d51ff664521ca4589d175a50f1f840000000000660f74d166440fd7ca4585c975244901f84983c0104883c710e964ffffff4c01d0488943084889731048c70300000000eb1f'),
    ('entry_map_miss_reserve', 0x3ed7152, '48837e10007427418b4610894320f3410f6f06f30f7f4310488933488953084889d84883c4085b415c415e415fc3488d46204989f7be010000004c89ff4989d44889c2b901000000ff15a8fb60024c89e24c89feebb1'),
    ('member_special_key', 0x5bdf8e0, '4156534883ec184989f64889fb8b461089442411f30f6f06f30f7f442401807f68017531f30f6f442401f30f6f4b69660f74c8660f6e442411660f6e5379660f74d0660fdbd1660fd7c23dffff00000f849c000000'),
    ('member_hash_map', 0x5bdf935, '488d7b284c89f6e8eff5ffff89c1b00184c90f858600000048837b18007479'),
    ('member_direct_bit', 0x5bdf954, 'f3410f6f06660fefc9660f74c8660fd7c135ffff0000755b41807e1000755441807e1100754d410fb7461266c1c0080fb7c03d2c010000733a488b4b50488b7358488904244889f248c1ea034839c2764a4889ca4883e2f883e10783e607488d0cce4801c189c8c1e806488b04c248d3e8eb0c'),
    ('member_fallback_return', 0x5bdf9c7, '807b7d00741031c0eb02b00124014883c4185b415ec34889df4c89f64883c4185b415ee931f6ffff4889e7e809000000'),
    ('member_dynamic_map', 0x5bdef30, '48837f18000f84e1000000488b0e488b05330b90004c8b00448b4e1048334f20488b46084c31c048f7e14931d14c31c849f7e04831c24889d048c1e839488b0f488b7f08660f6ec0660f60c0f20f70c000660f70c0444531c0660f76c94821faf30f6f1411660f6fda660f74d866440fd7cb4585c97459'),
    ('member_dynamic_compare', 0x5bdefa7, 'f3410fbcc14801d04821f848c1e0064989ca4929c2f30f6f1ef3410f6f62c0660f74e3660f6e5e1066410f6e6ad0660f74eb660fdbec66440fd7d5b0014181faffff00007431418d41ff664421c84189c175ad660f1f440000660f74d1660fd7c285c075104c01c24883c2104983c010e971ffffff31c0c3'),
    ('member_fallback_map', 0x5bdf020, '48837f18000f84e1000000488b0e488b05430a90004c8b00448b4e1048334f20488b46084c31c048f7e14931d14c31c849f7e04831c24889d048c1e839488b0f488b7f08660f6ec0660f60c0f20f70c000660f70c0444531c0660f76c94821faf30f6f1411660f6fda660f74d866440fd7cb4585c97459'),
    ('member_fallback_compare', 0x5bdf097, 'f3410fbcc14801d04821f848f7d8488d0480f30f6f1ef30f6f6481ec660f74e3660f6e5e10660f6e6c81fc660f74eb660fdbec66440fd7d5b0014181faffff00007434418d41ff664421c84189c175b0660f1f840000000000660f74d1660fd7c285c075104c01c24883c2104983c010e971ffffff31c0c3'),
    ('target_loader_entry', 0x2971760, '5541574156534883ec6889cb4889d14889f24889fe4889e7ff15da55b7030fb654243880fa027505e9c4000000488b042484db0f84b800000048837870000f85ad000000'),
    ('target_loader_code_choice', 0x29717a4, 'f30f6f4048f30f6f4858660f7f4c2450660f7f442440660f740d5e08aefd660f74052620aefd488b4c2418660fdbc1660fd7f081feffff00007433488d7048f30f6f06f30f6f4e10660f7f4c2410660f7f0424488b394889e689d34989c6ff15504cb70389da4889c34c89f0eb17488b1d5f54b7038b4b0885c9753c488b1bf048ff037e52'),
    ('target_loader_replace', 0x2971829, '4c8d7070498b0e4885c97419f048ff0975134c89f789d54989c7ff155f37b7034c89f889ea49891e4883c4685b415e415f5dc3488b3d1554b70389d54989c6e8582198ff4c89f089ea488b1bf048ff037fae0f0b49891e4889c7e8c8f1a703'),
    ('payment_checked_mul', 0x2973440, '554157415641554154534881ece80000004989d64c8b92d80000004c8b5a584c89d849f7e24989c0498b5e50410f90c14c89d048f7e34c01c2410f92c04508c841b907000000753a'),
    ('payment_required_value', 0x2973488, '48899c24880000004d8b7e60498b5e684c897c24484901c74889dd4811d54d8b66704c896424404983d4004d8b6e784c896c24504983d5007305e965010000'),
    ('payment_kind', 0x2973519, '410fb68e110100004189cb80f903488974243048895c2438756a'),
    ('payment_aux_limit', 0x2973533, '48894424604889542458498b8eb80000004889c848c1e82f0f854d03000048c1e1114889c849f7a6880000004889c3400f90c64889c849f7a6800000004801da0f92c14008f10f85c30200004901c74811d54983d4004983d500488b542458488b4424600f828f000000'),
    ('payment_balance_compare', 0x297359d, '4c397c2410488b4c24184819e9488b4c24204c19e1488b4c24284c19e90f8389000000'),
    ('payment_failure_return', 0x2973623, '41b9060000004c89f74c890f48895f0848894f104881c4e80000005b415c415d415e415f5dc3'),
    ('payment_price_cap', 0x2973649, '4180fb027311488b5c24304c8b6424484c8b6c2440eb6d41f60601488b5c24304c8b6424484c8b6c24407458498b46184c8b4424684d0346104883d00048c7c1ffffffff480f42c14c0f42c1488bb424880000004939f04889c1488b5424704819d14c0f43c6480f43c249f7e24889c1400f90c64c89d049f7e04801ca410f92c04108f0'),
    ('payment_cost_overflow', 0x29736cd, '41f6c0010f857e0100004c01e048135424384d89e94983d100488b7424504883d6000f8260010000'),
    ('payment_aux_actual', 0x29736f5, '4180fb030f85870000004c8b8424800000004989c3498b8eb80000004889c848c1e82f0f85800100004989df4889d348c1e111488b44247848f7e14989c2400f90c54c89c048f7e14989c04889d14c01d10f92c04008e831d2440fb654240f4180e201480f44ca4c0f44c24184c20f85220100004889da4c89d84c01c04811ca4983d1004883d6004c89fb0f82cf000000'),
    ('payment_subtract_and_result', 0x2973786, '4c29e0481b5424384d19e9481b7424504c8b4424284c89c14829f14c8b5c24104929c34c8b5424184919d2488b5424204c19ca4883d9000f92c04c891b4c8953084889531048894b184939f0721584c075110f10030f104b100f298c24a0000000eb0b0f57c00f298424a00000000f298424900000000f288424900000000f288c24a00000000f114f180f11470848c70721000000'),
    ('payment_aux_saturation', 0x2973842, '48c7c2ffffffff48c7c0ffffffffe92afdffff'),
    ('payment_aux_actual_saturation', 0x297388b, '48c7c1ffffffff49c7c0ffffffffe9cbfeffff488d3dab02ad03ff15c5bfb603'),
    ('payment_failure_paths', 0x2973820, 'bf08000000be20000000ff1560bcb603bf08000000be20000000ff1550bcb603eb4748c7c2ffffffff48c7c0ffffffffe92afdffff48c78424b000000007000000488d3d5cdfc8fd488d0de905ad034c8d05aae4ac03488d9424b0000000be49000000ff1517beb6030f0b48c7c1ffffffff49c7c0ffffffffe9cbfeffff488d3dab02ad03ff15c5bfb6034989c6488dbc24b0000000e895d807004c89f7e88dd1a7034989c6be200000004889df31d2ff15cabbb6034c89f7e872d1a703'),
)

# Only selected relative transfers are decoded; this is not a whole-body CFG.
EDGES = (
    ('validation call', 0x29a1bca, 0x2b92c10),
    ('validation rejection', 0x29a1bdb, 0x29a1c11),
    ('cost call', 0x29a1c56, 0x2b93030),
    ('cost rejection', 0x29a1c81, 0x29a2044),
    ('payer account call', 0x29a1cdb, 0x299f4d0),
    ('balance helper call', 0x29a1d84, 0x2973440),
    ('balance rejection', 0x29a1db5, 0x29a2106),
    ('non-call form selects alternate frame', 0x29a2e17, 0x29a2f34),
    ('recipient account call', 0x29a2e70, 0x2971760),
    ('prior frame handoff', 0x29a31db, 0x296e2b0),
    ('validation old revision', 0x2b92c1d, 0x2b92c45),
    ('validation missing flag', 0x2b92c26, 0x2b92ca4),
    ('validation zero environment', 0x2b92c37, 0x2b92c48),
    ('validation network match', 0x2b92c98, 0x2b92cb9),
    ('validation network mismatch', 0x2b92c9f, 0x2b92fba),
    ('validation network type rejection', 0x2b92cb3, 0x2b92d5b),
    ('validation type one old revision', 0x2b92ce4, 0x2b92f5f),
    ('validation low price accepted', 0x2b92d03, 0x2b92e45),
    ('validation length override absent', 0x2b92d23, 0x2b92d3a),
    ('validation length exceeds limit', 0x2b92d36, 0x2b92d51),
    ('validation input within limit', 0x2b92d4b, 0x2b92cc2),
    ('validation type four old revision', 0x2b92d68, 0x2b92f4a),
    ('validation type two old revision', 0x2b92de4, 0x2b92f51),
    ('validation type four price failure', 0x2b92dc7, 0x2b92f48),
    ('validation type four item present', 0x2b92dd5, 0x2b92e45),
    ('validation type two price failure', 0x2b92e3f, 0x2b92f48),
    ('validation general size skip', 0x2b92e4c, 0x2b92e68),
    ('validation general size pass', 0x2b92e5c, 0x2b92e68),
    ('validation type three old revision', 0x2b92ea1, 0x2b92f58),
    ('validation type three price failure', 0x2b92f00, 0x2b92f48),
    ('validation type three skips word check', 0x2b92f21, 0x2b92fd5),
    ('validation type three word check passes', 0x2b92f38, 0x2b92fd5),
    ('validation initcode pass', 0x2b92f97, 0x2b92fa0),
    ('validation sentinel', 0x2b92fa8, 0x2b92fb5),
    ('validation empty list', 0x2b92fd8, 0x2b93018),
    ('validation list element bad', 0x2b92ff7, 0x2b9301f),
    ('validation list length accepted', 0x2b9300b, 0x2b92e45),
    ('access count overflow', 0x2b93083, 0x2b9319a),
    ('cost initial accepted', 0x2b93114, 0x2b93127),
    ('cost old revision', 0x2b9312b, 0x2b93140),
    ('cost floor accepted', 0x2b93135, 0x2b93140),
    ('cost extra gate disabled', 0x2b9314e, 0x2b93172),
    ('cost extra threshold accepted', 0x2b9315f, 0x2b93172),
    ('schedule mode13 adapter', 0x5be0b43, 0x5be2a93),
    ('schedule initializer method one', 0x5be2cfa, 0x5be2560),
    ('schedule initializer method two', 0x5be29ea, 0x5be2560),
    ('schedule 12-13 arm', 0x5be288a, 0x5be2951),
    ('schedule allocation join', 0x5be29b2, 0x5be2672),
    ('account entry call', 0x43238c0, 0x3ed7040),
    ('account map entry occupied', 0x43238cd, 0x43239a7),
    ('account vacant policy failure', 0x4323926, 0x4323e39),
    ('account backend call', 0x432395e, 0x3d48970),
    ('account backend non-two', 0x432396c, 0x43239d4),
    ('account backend non-one default', 0x4323a0d, 0x4323aec),
    ('account new journal selected', 0x4323ad9, 0x4323c46),
    ('account skip new journal', 0x4323c44, 0x4323c80),
    ('account journal capacity available', 0x4323c4e, 0x4323c5a),
    ('account refresh policy failure', 0x4323dc0, 0x4323e39),
    ('account refresh flag clear', 0x4323ddb, 0x4323de9),
    ('account refresh journal grow', 0x4323dfe, 0x4323eb7),
    ('membership special key disabled', 0x5bdf902, 0x5bdf935),
    ('membership special key equal', 0x5bdf92f, 0x5bdf9d1),
    ('membership associated map call', 0x5bdf93c, 0x5bdef30),
    ('membership associated map hit', 0x5bdf947, 0x5bdf9d3),
    ('membership representation absent', 0x5bdf952, 0x5bdf9cd),
    ('membership compact address bound', 0x5bdf98b, 0x5bdf9c7),
    ('membership compact bit out of range', 0x5bdf9a3, 0x5bdf9ef),
    ('membership fallback enabled', 0x5bdf9cb, 0x5bdf9dd),
    ('membership fallback tail call', 0x5bdf9ea, 0x5bdf020),
    ('membership range error helper', 0x5bdf9f2, 0x5bdfa00),
    ('associated map empty', 0x5bdef35, 0x5bdf01c),
    ('associated map exact match', 0x5bdefeb, 0x5bdf01e),
    ('fallback map empty', 0x5bdf025, 0x5bdf10c),
    ('fallback map exact match', 0x5bdf0d8, 0x5bdf10e),
    ('account map existing', 0x3ed7109, 0x3ed713e),
    ('account map empty control', 0x3ed712c, 0x3ed7152),
    ('account map reserve', 0x3ed7157, 0x3ed7180),
    ('account result error', 0x299f505, 0x299f652),
    ('account cached code', 0x299f54b, 0x299f5f5),
    ('account default digest', 0x299f58e, 0x299f5be),
    ('recipient result error', 0x2971786, 0x297178d),
    ('recipient no code requested', 0x2971793, 0x2971851),
    ('recipient cached code', 0x297179e, 0x2971851),
    ('recipient default digest', 0x29717dd, 0x2971812),
    ('balance multiplication overflow', 0x2973486, 0x29734c2),
    ('balance required addition', 0x29734c0, 0x29734c7),
    ('balance skip auxiliary requirement', 0x2973531, 0x297359d),
    ('balance auxiliary count overflow', 0x297354b, 0x297389e),
    ('balance auxiliary cap saturation', 0x2973579, 0x2973842),
    ('balance auxiliary required overflow', 0x2973597, 0x297362c),
    ('balance sufficient', 0x29735ba, 0x2973649),
    ('balance price no adjustment', 0x297364d, 0x2973660),
    ('balance cost overflow', 0x29736d1, 0x2973855),
    ('balance skip auxiliary charge', 0x29736f9, 0x2973786),
    ('balance auxiliary count recheck', 0x2973718, 0x297389e),
    ('balance auxiliary charge saturation', 0x2973763, 0x297388b),
    ('balance final addition overflow', 0x2973780, 0x2973855),
    ('balance clamp', 0x29737d2, 0x29737e9),
)

# (name, instruction VA, fixed prefix, instruction length, displacement offset,
# expected destination). Relocation slots are link-time VAs, never process pointers.
RIPS = (
    ('default schedule selector slot', 0x5be7925, 'ff15', 6, 2, 0x64e96d8),
    ('cost helper slot', 0x2b930c3, 'ff15', 6, 2, 0x64e6198),
    ('payer cache slot', 0x299f4f6, 'ff15', 6, 2, 0x64e6d58),
    ('recipient cache slot', 0x2971778, 'ff15', 6, 2, 0x64e6d58),
    ('code fetch slot', 0x299f5b3, 'ff15', 6, 2, 0x64e6458),
    ('recipient code fetch slot', 0x2971802, 'ff15', 6, 2, 0x64e6458),
    ('payer rejected result helper', 0x299f665, 'ff15', 6, 2, 0x64df6b8),
    ('account vacancy policy slot', 0x4323915, 'ff15', 6, 2, 0x64ea6d8),
    ('account refresh policy slot', 0x4323dab, 'ff15', 6, 2, 0x64ea6d8),
    ('account journal capacity slot', 0x4323c54, 'ff15', 6, 2, 0x64e68e8),
    ('account map reserve slot', 0x3ed719a, 'ff15', 6, 2, 0x64e6d48),
    ('payer digest latter half', 0x299f571, '660f740d', 8, 4, 0x452020),
    ('payer digest first half', 0x299f579, '660f7405', 8, 4, 0x4537f0),
    ('recipient digest latter half', 0x29717ba, '660f740d', 8, 4, 0x452020),
    ('recipient digest first half', 0x29717c2, '660f7405', 8, 4, 0x4537f0),
    ('default digest first half', 0x4323b30, '0f1005', 7, 3, 0x4585a0),
    ('default digest latter half', 0x4323b3c, '0f1005', 7, 3, 0x4585b0),
    ('account map secret pointer', 0x3ed7051, '488b05', 7, 3, 0x64dfa78),
    ('schedule descriptor slot', 0x5be2ac0, '488d0d', 7, 3, 0x64bf460),
    ('initial cost and item coefficients', 0x5be299b, '0f2805', 7, 3, 0x450300),
    ('floor coefficients', 0x5be298f, '0f2805', 7, 3, 0x4568c0),
    ('access coefficients', 0x5be2852, '0f281d', 7, 3, 0x4531d0),
    ('per-byte floor multiplier', 0x5be2975, 'f30f1005', 8, 4, 0x45a05c),
    ('revm pre-execution location', 0x297386f, '4c8d05', 7, 3, 0x6441d20),
    ('transaction location', 0x297389e, '488d3d', 7, 3, 0x6443b50),
    ('gas calculation location', 0x5be0a44, '488d3d', 7, 3, 0x64bf250),
    ('gas admission location', 0x2b931a7, '488d3d', 7, 3, 0x644cab0),
)
RELATIVE_SLOTS = {
    0x64e96d8: 0x5be0aa0,
    0x64e6198: 0x5be0720,
    0x64e6d58: 0x4323870,
    0x64e6458: 0x43c8ec0,
    0x64df6b8: 0x1680e80,
    0x64ea6d8: 0x5bdf8e0,
    0x64e68e8: 0x43bc980,
    0x64e6d48: 0x3ee52a0,
    0x64bf478: 0x5be2ce0,
    0x64bf480: 0x5be29d0,
    0x64dfa78: 0x64ffe90,
    0x64c0748: 0x5c165b0,
    0x64eaee8: 0x5c16650,
    0x6441d20: 0x44319c,
    0x6443b50: 0x4431e4,
    0x64bf250: 0x438be7,
    0x644cab0: 0x44bb5b,
}
SOURCE_SLOTS = (0x6441d20, 0x6443b50, 0x64bf250, 0x644cab0)
IMMEDIATES = (
    ('validator success tag', 0x2b92faa, '48c700', 4, 0x25),
    ('initial cost rejection tag', 0x2b93116, '48c703', 4, 3),
    ('floor cost rejection tag', 0x2b93137, '48c703', 4, 4),
    ('balance width rejection tag', 0x2973480, '41b9', 4, 7),
    ('balance insufficient tag', 0x2973623, '41b9', 4, 6),
    ('balance success tag', 0x2973814, '48c707', 4, 0x21),
    ('auxiliary kind', 0x2973524, '80f9', 1, 3),
    ('auxiliary count overflow shift', 0x2973547, '48c1e8', 1, 47),
    ('auxiliary units shift', 0x2973551, '48c1e1', 1, 17),
    ('adjusted price kind threshold', 0x2973649, '4180fb', 1, 2),
    ('journal entry stride', 0x4323c5e, '496bce', 1, 0x58),
    ('new entry journal tag', 0x4323c62, 'c60408', 1, 0),
    ('account bucket stride', 0x4323d0b, '4c69ea', 4, 0xa8),
    ('type three record stride shift', 0x2b92feb, '48c1e3', 1, 5),
    ('type one revision comparison', 0x2b92ce1, '80f9', 1, 6),
    ('type two revision comparison', 0x2b92de1, '80f9', 1, 7),
    ('type four revision comparison', 0x2b92d65, '80f9', 1, 11),
)


def check_digest(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


def mapped(data, secs, va, size):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid byte range')
    candidates = [s for s in secs if s['type'] != 8 and
                  s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('non-file-backed or ambiguous byte range')
    s = candidates[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('byte range outside input')
    return data[off:off + size], off, s['name']


def take(data, secs, va, size):
    return mapped(data, secs, va, size)[0]


def checked_windows(data, secs, pins=PINS):
    rows = []
    names = set()
    for name, va, encoded in pins:
        if name in names:
            raise ValueError('duplicate window name')
        names.add(name)
        expected = bytes.fromhex(encoded)
        actual, off, section = mapped(data, secs, va, len(expected))
        if section != '.text' or actual != expected:
            raise ValueError('instruction window mismatch: ' + name)
        rows.append({'name': name, 'va': hex(va), 'file_offset': hex(off),
                     'section': section, 'bytes': actual.hex()})
    return rows


def branch(data, secs, site):
    op = take(data, secs, site, 1)[0]
    if op in (0xe8, 0xe9):
        n, displacement = 5, 1
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        n, displacement = 2, 1
    elif op == 0x0f and 0x80 <= take(data, secs, site + 1, 1)[0] <= 0x8f:
        n, displacement = 6, 2
    else:
        raise ValueError('unsupported branch shape')
    raw, off, section = mapped(data, secs, site, n)
    if section != '.text':
        raise ValueError('branch outside text')
    rel = int.from_bytes(raw[displacement:], 'little', signed=True)
    return site + n + rel, raw, off


def edge_rows(data, secs, edges=EDGES):
    rows = []
    for name, site, expected in edges:
        target, raw, off = branch(data, secs, site)
        if target != expected:
            raise ValueError('branch destination mismatch: ' + name)
        rows.append({'name': name, 'site_va': hex(site), 'file_offset': hex(off),
                     'bytes': raw.hex(), 'target_va': hex(target)})
    return rows


def rip_target(data, secs, site, prefix, length, displacement):
    raw, off, section = mapped(data, secs, site, length)
    if section != '.text' or not raw.startswith(bytes.fromhex(prefix)) or displacement + 4 != length:
        raise ValueError('RIP-relative instruction mismatch')
    return site + length + struct.unpack_from('<i', raw, displacement)[0], raw, off


def rip_rows(data, secs, specs=RIPS):
    rows = []
    for name, site, prefix, length, offset, expected in specs:
        target, raw, off = rip_target(data, secs, site, prefix, length, offset)
        if target != expected:
            raise ValueError('RIP-relative destination mismatch: ' + name)
        rows.append({'name': name, 'site_va': hex(site), 'file_offset': hex(off),
                     'bytes': raw.hex(), 'target_va': hex(target)})
    return rows


def immediate_rows(data, secs, specs=IMMEDIATES):
    rows = []
    for name, site, prefix, size, expected in specs:
        pattern = bytes.fromhex(prefix)
        raw, off, section = mapped(data, secs, site, len(pattern) + size)
        if section != '.text' or not raw.startswith(pattern):
            raise ValueError('immediate instruction mismatch: ' + name)
        value = int.from_bytes(raw[len(pattern):], 'little')
        if value != expected:
            raise ValueError('immediate value mismatch: ' + name)
        rows.append({'name': name, 'site_va': hex(site), 'file_offset': hex(off),
                     'raw_bytes': raw.hex(), 'value': value})
    return rows


def relocations(data, secs, wanted):
    relas = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(relas) != 1 or relas[0]['size'] % 24:
        raise ValueError('missing or invalid RELA section')
    s = relas[0]
    found = {}
    for pos in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, pos)
        if offset not in wanted:
            continue
        if offset in found or info != 8 or addend != wanted[offset]:
            raise ValueError('duplicate or altered relative relocation')
        found[offset] = {'slot_va': hex(offset), 'info': hex(info),
                         'addend_va': hex(addend), 'entry_file_offset': hex(pos),
                         'raw_bytes': data[pos:pos + 24].hex()}
    if set(found) != set(wanted):
        raise ValueError('missing relative relocation')
    return [found[k] for k in sorted(found)]


def record_bytes(data, secs, va):
    n = struct.unpack('<I', take(data, secs, va, 4))[0]
    if n in (0, 0xffffffff):
        raise ValueError('unsupported unwind record length')
    return take(data, secs, va, n + 4)


def selected_functions(data, secs):
    _, records = eh_frame_records(data, secs)
    _, index = unwind_index(data)
    by_start = {}
    for f in records:
        by_start.setdefault(f['start'], []).append(f)
    index_map = {e['start']: e for e in index}
    result = []
    for role, start, end in FUNCTIONS:
        choices = by_start.get(start, [])
        if len(choices) != 1 or choices[0]['end'] != end:
            raise ValueError('selected FDE mismatch')
        f = choices[0]
        if start not in index_map or index_map[start]['fde'] != f['fde']:
            raise ValueError('unwind index mismatch')
        raw, off, sec = mapped(data, secs, start, end - start)
        if sec != '.text':
            raise ValueError('selected FDE outside text')
        result.append({'role_inferred': role, 'start_va': hex(start),
                       'end_va_exclusive': hex(end), 'file_offset': hex(off),
                       'section': sec, 'byte_count': len(raw),
                       'sha256': hashlib.sha256(raw).hexdigest(),
                       'raw_bytes': raw.hex(), 'fde_va': hex(f['fde']),
                       'fde_bytes': record_bytes(data, secs, f['fde']).hex(),
                       'cie_va': hex(f['cie']),
                       'cie_bytes': record_bytes(data, secs, f['cie']).hex(),
                       'lsda_va': None if f['lsda'] is None else hex(f['lsda'])})
    return result, by_start


def parse_lsda(blob, start, end):
    if not 0 <= start < end or len(blob) < 4 or blob[0] != 0xff or blob[1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    p, type_end = 2, None
    if blob[1] == 0x9b:
        delta, p = uleb(blob, p, len(blob))
        type_end = p + delta
        if type_end > len(blob):
            raise ValueError('LSDA type table outside section')
    if p >= len(blob) or blob[p] != 1:
        raise ValueError('unsupported call-site encoding')
    p += 1
    n, p = uleb(blob, p, len(blob))
    first, stop = p, p + n
    if stop > len(blob) or (type_end is not None and stop > type_end):
        raise ValueError('truncated call-site table')
    rows = []
    while p < stop:
        previous = p
        begin, p = uleb(blob, p, stop)
        size, p = uleb(blob, p, stop)
        landing, p = uleb(blob, p, stop)
        action, p = uleb(blob, p, stop)
        if begin + size > end - start or (landing and landing >= end - start):
            raise ValueError('call-site outside FDE')
        rows.append({'start_va': hex(start + begin), 'end_va_exclusive': hex(start + begin + size),
                     'landing_va': None if not landing else hex(start + landing),
                     'action_index': action, 'raw_bytes': blob[previous:p].hex()})
    return {'header_bytes': blob[:first].hex(), 'type_encoding': blob[1],
            'callsite_byte_count': n}, rows


def exception_rows(data, secs, by_start):
    sec = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(sec) != 1:
        raise ValueError('exception section missing')
    sec = sec[0]
    out = []
    for role, start, end in FUNCTIONS:
        fde = by_start[start][0]
        if fde['lsda'] is None:
            continue
        _, off, name = mapped(data, secs, fde['lsda'], 1)
        if name != '.gcc_except_table':
            raise ValueError('LSDA outside exception section')
        blob = data[off:sec['offset'] + sec['size']]
        header, rows = parse_lsda(blob, start, end)
        out.append({'role_inferred': role, 'function_va': hex(start),
                    'lsda_va': hex(fde['lsda']), 'file_offset': hex(off),
                    'header': header, 'call_sites': rows})
    return out


def schedule(data, secs):
    # The mode-13 arm and stores are fixed-byte pinned above. The numeric values
    # below are read from the selected immediates and RIP-relative data objects.
    def imm(va, offset, size):
        return int.from_bytes(take(data, secs, va + offset, size), 'little')
    def pair(va):
        return struct.unpack('<QQ', take(data, secs, va, 16))
    init, item = pair(0x450300)
    floor_factor, floor_base = pair(0x4568c0)
    address_fee, slot_fee = pair(0x4531d0)
    mode = imm(0x5be7920, 1, 4)
    threshold = imm(0x5be2841, 2, 1)
    if mode != 13 or threshold != 10:
        raise ValueError('default mode path mismatch')
    fields = {
        '0xe8': item,
        '0xf0': imm(0x5be25ae, 1, 4),
        '0xf8': imm(0x5be2787, 7, 4),
        '0x100': floor_factor,
        '0x108': floor_base,
        '0x110': address_fee,
        '0x118': slot_fee,
        '0x120': imm(0x5be27aa, 7, 4),
        '0x128': imm(0x5be2578, 2, 4),
        '0x130': 2 * int(mode >= threshold),  # checked setae and self-add
        '0x158': 0, '0x168': 0, '0x170': 0,
        '0x178': imm(0x45a05c, 0, 4), '0x180': 0,
    }
    expected = {'0xe8': 25000, '0xf0': 4, '0xf8': 4, '0x100': 10,
                '0x108': 21000, '0x110': 2400, '0x118': 1900,
                '0x120': 21000, '0x128': 32000, '0x130': 2,
                '0x158': 0, '0x168': 0, '0x170': 0, '0x178': 1, '0x180': 0}
    if fields != expected or init != 200:
        raise ValueError('mode-13 coefficient mismatch')
    return {'mode': mode, 'allocation_base_fields': fields,
            'other_literal_qword_0xe0': init,
            'qualification': 'Conditional on default context, this initialized cache and no intervening replacement.'}


def gate_table(data, secs):
    base = 0x60735c
    expected = (0x2b92cea, 0x2b92ce1, 0x2b92de1, 0x2b92e9e, 0x2b92d65)
    rows = []
    for index, dest in enumerate(expected):
        raw, off, section = mapped(data, secs, base + 4 * index, 4)
        target = base + struct.unpack('<i', raw)[0]
        if section != '.rodata' or target != dest:
            raise ValueError('validation dispatch table mismatch')
        rows.append({'index': index, 'entry_va': hex(base + 4 * index),
                     'file_offset': hex(off), 'raw_bytes': raw.hex(), 'target_va': hex(target)})
    mode = struct.unpack('<I', take(data, secs, 0x5be7921, 4))[0]
    if mode != 13:
        raise ValueError('unexpected default schedule mode')
    entry = 0x942194 + mode * 4
    raw, off, section = mapped(data, secs, entry, 4)
    target = 0x942194 + struct.unpack('<i', raw)[0]
    if section != '.rodata' or target != 0x5be0b26:
        raise ValueError('default schedule selector mismatch')
    return {'validation_type_entries': rows,
            'default_schedule_selector': {'index': mode, 'entry_va': hex(entry),
                                          'file_offset': hex(off), 'raw_bytes': raw.hex(),
                                          'target_va': hex(target)}}


def displacement(data, secs, va, prefix):
    """Extract an explicitly recognized x86 disp32 instruction operand."""
    pattern = bytes.fromhex(prefix)
    raw = take(data, secs, va, len(pattern) + 4)
    if not raw.startswith(pattern):
        raise ValueError('unexpected operand shape')
    return struct.unpack_from('<I', raw, len(pattern))[0]


def flow_lineage(data, secs):
    context = displacement(data, secs, 0x29a12be, '488dbc24')
    tx = displacement(data, secs, 0x29a1b94, '4c8dbc24')
    if take(data, secs, 0x29a1c50, 3) != bytes.fromhex('4c89fe'):
        raise ValueError('transaction subobject argument mismatch')
    offset_ptr = take(data, secs, 0x2b9309a, 4)
    offset_len = take(data, secs, 0x2b9309e, 4)
    if offset_ptr[:3] != bytes.fromhex('498b57') or offset_len[:3] != bytes.fromhex('498b47'):
        raise ValueError('input operand shape mismatch')
    cost_ptr = tx + offset_ptr[3]
    cost_len = tx + offset_len[3]
    clone_ptr = displacement(data, secs, 0x29a2de5, '488b9424')
    clone_len = displacement(data, secs, 0x29a2df5, '488b8c24')
    key = displacement(data, secs, 0x29a2e2b, 'f30f6f8424')
    key_tail = displacement(data, secs, 0x29a2e1d, '8b8424')
    key_tmp = displacement(data, secs, 0x29a2e34, '660f7f8424')
    key_reload = displacement(data, secs, 0x29a30d1, '0f288424')
    key_store = displacement(data, secs, 0x29a30d9, '0f118424')
    key_tail_store = displacement(data, secs, 0x29a30e8, '898424')
    frame = displacement(data, secs, 0x29a3168, '488db424')
    second_key_store = displacement(data, secs, 0x29a312a, 'f30f7f8424')
    second_key_tail = displacement(data, secs, 0x29a311a, '898424')
    lookup_key = displacement(data, secs, 0x2a6bc5d, '488db1')
    if (cost_ptr != clone_ptr or cost_len != clone_len or key_tail != key + 16
            or key_tmp != key_reload or key_tail_store != key_store + 16
            or second_key_tail != second_key_store + 16
            or key_store - frame != lookup_key or second_key_store - frame != lookup_key + 20):
        raise ValueError('context, payload or key lineage mismatch')
    if not context <= key < key_tail < tx + 0x200:
        raise ValueError('unexpected context input range')
    return {
        'coordinate_system': 'offsets from the selected driver stack pointer',
        'context_stack_offset': hex(context), 'input_subobject_stack_offset': hex(tx),
        'input_pointer_stack_offset': hex(cost_ptr), 'input_length_stack_offset': hex(cost_len),
        'input_pointer_context_offset': hex(cost_ptr - context),
        'input_length_context_offset': hex(cost_len - context),
        'recipient_first16_stack_offset': hex(key), 'recipient_last4_stack_offset': hex(key_tail),
        'recipient_context_offset': hex(key - context),
        'recipient_temporary_stack_offset': hex(key_tmp), 'frame_stack_offset': hex(frame),
        'first_key_frame_offset': hex(key_store - frame),
        'second_key_frame_offset': hex(second_key_store - frame),
        'lookup_key_frame_offset': hex(lookup_key),
        'qualification': 'Conditional on this branch, normal dynamic clone/allocation returns, and no alias mutation.'
    }


def source_locations(data, secs):
    rows = []
    for slot in SOURCE_SLOTS:
        raw, off, section = mapped(data, secs, slot, 24)
        _, length, line, column = struct.unpack('<QQII', raw)
        ptr = RELATIVE_SLOTS[slot]
        if not 0 < length < 512:
            raise ValueError('invalid source descriptor length')
        path = take(data, secs, ptr, length)
        marker = b'z_vendor/'
        at = path.find(marker)
        if at < 0 or b'\x00' in path:
            raise ValueError('unexpected source descriptor')
        suffix = path[at:].decode('ascii')
        rows.append({'descriptor_va': hex(slot), 'file_offset': hex(off), 'section': section,
                     'string_va': hex(ptr), 'original_length': length,
                     'relative_suffix': suffix, 'suffix_bytes': path[at:].hex(),
                     'line': line, 'column': column})
    return rows


def identity_anchor(data, secs):
    record, off, section = mapped(data, secs, 0x64c0730, 56)
    key = record[32:52]
    if key != bytes(19) + b'\x09':
        raise ValueError('address-09 anchor mismatch')
    return {'record_va': '0x64c0730', 'file_offset': hex(off), 'section': section,
            'record_bytes': record.hex(), 'key_offset': 32, 'key_bytes': key.hex(),
            'callback_slot_va': '0x64c0748', 'callback_addend_va': '0x5c165b0',
            'status': 'prior PR boundary only'}


def code_digest_literals(data, secs):
    def literal(va, size):
        raw, off, name = mapped(data, secs, va, size)
        return {'va': hex(va), 'file_offset': hex(off), 'section': name,
                'bytes': raw.hex()}
    first = literal(0x4537f0, 16)
    second = literal(0x452020, 16)
    whole = literal(0x4585a0, 32)
    if first['bytes'] + second['bytes'] != whole['bytes']:
        raise ValueError('default code digest literals mismatch')
    return {'first_comparison_half': first, 'second_comparison_half': second,
            'default_account_literal': whole,
            'qualification': 'Byte equality only; no hash algorithm or runtime value is assumed.'}


def membership_layout(data, secs):
    key = take(data, secs, 0x64c0750, 20)
    compare = take(data, secs, 0x5bdf986, 5)
    first_byte = take(data, secs, 0x5bdf96c, 5)
    second_byte = take(data, secs, 0x5bdf973, 5)
    final_word = take(data, secs, 0x5bdf97a, 5)
    length_shift = take(data, secs, 0x5bdf99c, 4)
    pointer_mask = take(data, secs, 0x5bdf9ac, 3)
    length_mask = take(data, secs, 0x5bdf9af, 3)
    word_shift = take(data, secs, 0x5bdf9bb, 3)
    if (compare[0] != 0x3d or first_byte[:3] != b'\x41\x80\x7e'
            or second_byte[:3] != b'\x41\x80\x7e' or first_byte[4] or second_byte[4]
            or final_word[:4] != b'\x41\x0f\xb7\x46'
            or length_shift[:3] != b'\x48\xc1\xea'
            or pointer_mask[:2] != b'\x83\xe1' or length_mask[:2] != b'\x83\xe6'
            or word_shift[:2] != b'\xc1\xe8'):
        raise ValueError('membership operand shape mismatch')
    limit = struct.unpack('<I', compare[1:])[0]
    prefix = final_word[4]
    if ((first_byte[3], second_byte[3], prefix) != (16, 17, 18)
            or limit != 300 or length_shift[3] != 3 or pointer_mask[2] != 7
            or length_mask[2] != 7 or word_shift[2] != 6
            or key[:prefix] != bytes(prefix)):
        raise ValueError('membership operand value mismatch')
    return {'address_anchor_va': '0x64c0750', 'key_bytes': key.hex(),
            'zero_prefix_bytes': prefix, 'big_endian_suffix': int.from_bytes(key[prefix:], 'big'),
            'exclusive_suffix_bound': limit, 'packed_length_shift': length_shift[3],
            'pointer_tag_mask': pointer_mask[2], 'length_tag_mask': length_mask[2],
            'word_index_shift': word_shift[2],
            'qualification': 'This key reaches the compact arm only after earlier membership tests miss.'}


def checked_u64(n):
    if type(n) is not int or not 0 <= n <= U64:
        raise ValueError('expected unsigned 64-bit integer')
    return n


def account_hash_model(key, seed, secret):
    """Unsigned arithmetic in the selected account-map hash; inputs are synthetic."""
    if not isinstance(key, bytes) or len(key) != 20:
        raise ValueError('expected 20-byte key')
    checked_u64(seed)
    checked_u64(secret)
    a, b, c = struct.unpack('<QQI', key)
    wide = (a ^ seed) * (b ^ secret)
    mixed = ((wide & U64) ^ (wide >> 64) ^ c) * secret
    return (mixed & U64) ^ (mixed >> 64)


def account_probe_model(key, seed, secret, controls, keys):
    """Logical 16-wide probes; mirrored physical control storage is not modeled."""
    hashed = account_hash_model(key, seed, secret)
    if not isinstance(controls, bytes) or not isinstance(keys, list):
        raise ValueError('invalid map')
    n = len(controls)
    if n < 16 or n & (n - 1) or len(keys) != n:
        raise ValueError('invalid map capacity')
    for control, item in zip(controls, keys):
        if control < 0x80:
            if not isinstance(item, bytes) or len(item) != 20:
                raise ValueError('invalid occupied key')
        elif control not in (0x80, 0xff):
            raise ValueError('unsupported control byte')
    start, stride = hashed & (n - 1), 0
    for _ in range(n // 16):
        group = [(start + i) & (n - 1) for i in range(16)]
        for index in group:
            if controls[index] == hashed >> 57 and keys[index] == key:
                return index
        if any(controls[index] == 0xff for index in group):
            return None
        stride += 16
        start = (start + stride) & (n - 1)
    return None


def membership_compact_model(key, tagged_pointer, packed_length, words):
    """Synthetic compact-arm bit access, after the earlier policy tests miss."""
    if not isinstance(key, bytes) or len(key) != 20 or key[:18] != bytes(18):
        raise ValueError('not a compact key')
    suffix = int.from_bytes(key[18:], 'big')
    if suffix >= 300:
        raise ValueError('outside compact-key range')
    checked_u64(tagged_pointer)
    checked_u64(packed_length)
    if not isinstance(words, list):
        raise ValueError('invalid backing words')
    for word in words:
        checked_u64(word)
    if suffix >= packed_length >> 3:
        raise IndexError('compact bit index exceeds logical length')
    bit = ((tagged_pointer & 7) << 3) + (packed_length & 7) + suffix
    if bit // 64 >= len(words):
        raise ValueError('backing words too short')
    return (words[bit // 64] >> (bit % 64)) & 1


def loader_miss_model(mode, membership):
    """Selected boolean policy gate and new-entry journal decision."""
    if type(mode) is not int or mode not in (0, 1):
        raise ValueError('expected boolean mode byte')
    if type(membership) is not int or membership not in (0, 1):
        raise ValueError('expected boolean membership result')
    if mode and not membership:
        return 'result-byte-2'
    return 'append-tag-0' if not membership else 'no-tag-0'


def cost_model(payload, address_count, slot_count, auth_count, create, fields):
    """A synthetic normal-return model for the observed mode-13 schedule only."""
    if not isinstance(payload, bytes) or type(create) is not bool:
        raise ValueError('invalid payload or create flag')
    address_count, slot_count, auth_count = map(checked_u64, (address_count, slot_count, auth_count))
    def add(a, b):
        v = a + b
        if v > U64:
            raise OverflowError('checked addition')
        return v
    def mul(a, b):
        v = a * b
        if v > U64:
            raise OverflowError('checked multiplication')
        return v
    zeros = payload.count(0)
    tokens = add(zeros, mul(len(payload) - zeros, fields['0xf0']))
    initial = mul(tokens, fields['0xf8'])
    initial = add(initial, mul(address_count, fields['0x110']))
    initial = add(initial, mul(slot_count, fields['0x118']))
    initial = add(initial, fields['0x120'])
    initial = add(initial, mul(auth_count, fields['0xe8']))
    if create:
        initial = add(initial, fields['0x128'])
        initial = add(initial, mul((len(payload) + 31) // 32, fields['0x130']))
    floor = add(mul(tokens, fields['0x100']), fields['0x108'])
    return {'tokens': tokens, 'initial': initial, 'floor': floor}


def admission_model(initial, floor, limit, mode, extra_enabled=False, ceiling=U64):
    """Selected admission predicates; no target instructions are executed."""
    for x in (initial, floor, limit, ceiling):
        checked_u64(x)
    if type(mode) is not int or not 0 <= mode <= 255 or type(extra_enabled) is not bool:
        raise ValueError('invalid mode or flag')
    if initial > limit:
        return 3
    if mode > 11 and floor > limit:
        return 4
    if extra_enabled and limit > ceiling and max(initial, floor) > ceiling:
        return 4
    return 0x21


def payment_model(balance, gas, cap, value):
    """Kind below two, no auxiliary charge; exposes the observed u128 bound."""
    if any(type(v) is not int or v < 0 for v in (balance, gas, cap, value)):
        raise ValueError('invalid payment argument')
    if balance > U256 or value > U256 or gas > U64 or cap > U128:
        raise ValueError('payment argument out of range')
    charge = gas * cap
    if charge > U128 or charge + value > U256:
        return 7, None
    if balance < charge + value:
        return 6, None
    return 0x21, max(0, balance - charge)


def payment_extended_model(balance, gas, cap, value, kind, adjusted, base, tip,
                           item_count, auxiliary_cap, auxiliary_enabled, auxiliary_price):
    """Synthetic model of selected price and auxiliary arithmetic, not native code."""
    if any(type(v) is not int or v < 0 for v in
           (balance, gas, cap, value, kind, base, tip, item_count, auxiliary_cap, auxiliary_price)):
        raise ValueError('invalid payment argument')
    if (balance > U256 or value > U256 or gas > U64 or cap > U128 or kind > 4
            or base > U64 or tip > U128 or item_count > U64
            or auxiliary_cap > U128 or auxiliary_price > U128):
        raise ValueError('payment argument out of range')
    if type(adjusted) is not bool or type(auxiliary_enabled) is not bool:
        raise ValueError('invalid flags')
    maximum = gas * cap
    if maximum > U128 or maximum + value > U256:
        return 'return', 7, None
    required = maximum + value
    if kind == 3:
        if item_count >> 47:
            return 'error-helper', 'count-overflow', None
        units = item_count << 17
        required += min(U128, units * auxiliary_cap)
        if required > U256:
            return 'return', 7, None
    if balance < required:
        return 'return', 6, None
    effective = min(cap, min(U128, base + tip)) if kind >= 2 and adjusted else cap
    charge = gas * effective
    if charge > U128 or charge + value > U256:
        return 'error-helper', 'charge-overflow', None
    auxiliary = 0
    if kind == 3 and auxiliary_enabled:
        auxiliary = min(U128, (item_count << 17) * auxiliary_price)
    if charge + value + auxiliary > U256:
        return 'error-helper', 'charge-overflow', None
    return 'return', 0x21, max(0, balance - charge - auxiliary)


def prefix_model(mode, flag, word0, word1):
    for x in (mode, flag):
        if type(x) is not int or not 0 <= x <= 255:
            raise ValueError('expected byte')
    checked_u64(word0)
    checked_u64(word1)
    if mode > 8 and not (flag & 1):
        return 0x21, 0
    if mode > 10 and not (word0 | word1):
        return 0x21, 1
    return None


def type_fee_model(kind, price, other, minimum, compare_enabled, minimum_disabled):
    """Selected type-dispatch comparisons for canonical boolean flags."""
    if type(kind) is not int or kind not in (0, 1, 2, 3, 4):
        raise ValueError('invalid selected type')
    if type(price) is not int or type(other) is not int or not 0 <= price <= U128 or not 0 <= other <= U128:
        raise ValueError('invalid 128-bit value')
    checked_u64(minimum)
    if type(compare_enabled) is not bool or type(minimum_disabled) is not bool:
        raise ValueError('expected boolean flags')
    if kind >= 2 and compare_enabled and price < other:
        return 0
    if not minimum_disabled and price < minimum:
        return 1
    return None


def type3_list_model(records, limit_enabled, limit):
    """Selected type-3 list checks, for materializable fixed-size records."""
    if not isinstance(records, list) or type(limit_enabled) is not bool:
        raise ValueError('invalid list or flag')
    checked_u64(limit)
    if any(not isinstance(item, bytes) or len(item) != 32 for item in records):
        raise ValueError('invalid list record')
    if not records:
        return 0x13
    if any(item[0] != 1 for item in records):
        return 0x16
    if limit_enabled and len(records) > limit:
        return 0x15
    return None


def json_output(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def tsv_output(rows, columns):
    text = ['\t'.join(columns)]
    for row in rows:
        values = [str(row.get(col, '')) for col in columns]
        if any('\t' in x or '\n' in x for x in values):
            raise ValueError('invalid TSV field')
        text.append('\t'.join(values))
    return ('\n'.join(text) + '\n').encode('ascii')


def generate(data):
    check_digest(data, SHA115)
    secs = sections(data)
    functions, by_start = selected_functions(data, secs)
    windows = checked_windows(data, secs)
    edges = edge_rows(data, secs)
    rips = rip_rows(data, secs)
    immediates = immediate_rows(data, secs)
    relas = relocations(data, secs, RELATIVE_SLOTS)
    tables = gate_table(data, secs)
    coefficients = schedule(data, secs)
    lineage = flow_lineage(data, secs)
    sources = source_locations(data, secs)
    exceptions = exception_rows(data, secs, by_start)
    anchor = identity_anchor(data, secs)
    code_literals = code_digest_literals(data, secs)
    membership = membership_layout(data, secs)
    summary = {'target_sha256': SHA115, 'selected_fde_count': len(functions),
               'selected_fde_bytes': sum(x['byte_count'] for x in functions),
               'byte_windows': len(windows), 'selected_direct_transfers': len(edges),
               'rip_relative_references': len(rips), 'relative_relocations': len(relas),
               'immediate_operands': len(immediates),
               'type_table_entries': len(tables['validation_type_entries']),
               'source_descriptors': len(sources), 'lsda_count': len(exceptions),
               'lsda_call_site_entries': sum(len(x['call_sites']) for x in exceptions),
               'scope': 'Selected static ranges; no whole-EVM coverage or equivalence.'}
    return {
        'functions.json': json_output(functions),
        'windows.tsv': tsv_output(windows, ('name', 'va', 'file_offset', 'section', 'bytes')),
        'edges.tsv': tsv_output(edges, ('name', 'site_va', 'file_offset', 'bytes', 'target_va')),
        'rip-references.tsv': tsv_output(rips, ('name', 'site_va', 'file_offset', 'bytes', 'target_va')),
        'immediates.json': json_output(immediates),
        'relocations.json': json_output(relas),
        'tables.json': json_output(tables),
        'schedule.json': json_output(coefficients),
        'input-lineage.json': json_output(lineage),
        'source-locations.json': json_output(sources),
        'exceptions.json': json_output(exceptions),
        'address-anchor.json': json_output(anchor),
        'code-digest-literals.json': json_output(code_literals),
        'membership-layout.json': json_output(membership),
        'summary.json': json_output(summary),
    }


def legacy_check(data):
    check_digest(data, SHA94)
    secs = sections(data)
    old_key, key_off, _ = mapped(data, secs, 0x574f0c0, 20)
    _, record_off, _ = mapped(data, secs, 0x574f0a8, 48)
    _, old_validation_off, _ = mapped(data, secs, 0x1e6c427, 7)
    old_result = take(data, secs, 0x1e6c427, 7)
    if old_key != bytes(19) + b'\x09' or old_result != bytes.fromhex('48c70719000000'):
        raise ValueError('historical anchor mismatch')
    relocations(data, secs, {0x574f0b0: 0x4e9d2a0})
    _, fdes = eh_frame_records(data, secs)
    expected = {0x1e6c0d0: 0x1e6c471, 0x21b9430: 0x21b94bf,
                0x4e9d2a0: 0x4e9d47b}
    selected = [f for f in fdes if f['start'] in expected]
    if len(selected) != len(expected) or any(expected[f['start']] != f['end'] for f in selected):
        raise ValueError('historical FDE mismatch')
    return {'sha256': SHA94, 'address_bytes': old_key.hex(),
            'record_va': '0x574f0a8', 'record_file_offset': hex(record_off),
            'key_va': '0x574f0c0', 'key_file_offset': hex(key_off),
            'callback_slot_va': '0x574f0b0', 'callback_addend_va': '0x4e9d2a0',
            'old_validation_success_instruction_va': '0x1e6c427',
            'old_validation_success_instruction_file_offset': hex(old_validation_off),
            'old_validation_success_instruction': old_result.hex()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--legacy', type=Path)
    args = ap.parse_args()
    files = generate(TARGET.read_bytes())
    if args.legacy is not None:
        print(json.dumps(legacy_check(args.legacy.read_bytes()), sort_keys=True))
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('re21_preflight115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
