#!/usr/bin/env python3
"""RE-017: derive selected loader-task paths from authenticated ELF bytes."""
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
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected instruction-aligned windows; exact patterns from node #94.
WINDOWS = (
    ('poll_input_and_spawn', 0x22b899f, 'c684242e02000000488d35ba7b3e03488d7c2418e85862feff488903'),
    ('poll_result_and_error', 0x22b89bb, '488d7c24184889de4c89f2e8a5e1d8ff0fb66c24184084ed7404b003eb304c8b7424200f104424280f290424488b3bb984000000b8cc000000f0480fb10f7407488b4710ff5020b0014d85f6751188430889e84881c4806300005b415e5dc34c897424180f2804240f11442420488d3d5eee11fe488d0dda593e034c8d055b7b3e03488d542418be2b000000ff15fb554b030f0b'),
    ('alternate_poll_input', 0x2032514, 'c684242602000000488d353d4a6603488d7c2410e8e3c62600488903488d7c24104889de4c89f2e830460100837c2410017513b103b002eb3f'),
    ('alternate_poll_result', 0x203255a, '4c8b7424180f104424200f290424488b3bb984000000b8cc000000f0480fb10f7407488b4710ff5020b001b1014d85f6750e884b084881c4786300005b415ec3'),
    ('third_poll_input', 0x247bd53, 'c684248602000000488d7c2470488d3521c12303e8a42ee2ff4889442410488d7c2470488d742410488d542450e8ebadbcff488b5c24704883fb01751041b403'),
    ('spawn_copy_and_allocate', 0x229ec7b, '4989f64989ff488d7c2410ba686300004c89feff154cf34c03bf68630000ff1539f34c034885c00f84a70000004889c3ba686300004889c74c89feff1524f34c03'),
    ('spawn_tls_and_failure', 0x229ecd0, '41bf01000000f04c0fc1384d85ff74f049c7c4d8eeffff64488b3c25000000004c01e764410fb644244883f801747f83f80275604889dfe8b47cfbffbe686300004889df31d2ff15f4f24c0340b501'),
    ('spawn_mode_and_calls', 0x229ed7e, '64498b042448b9ffffffffffffff7f4839c8734b48ffc0644989042464498b4424084883f80274464883c710a801740d4889de4c89fae8b74e1200eb0b4889de4c89fae88a955e00'),
    ('spawn_rejection_and_release', 0x229eddd, '488d3dfc154003ff15ae054d030f0b4889dfe8cc7bfbff31edbe686300004889df31d2ff150af24c036449ff0c24'),
    ('spawn_first_lane', 0x23c3c7b, '4c8b37f049ff060f8eab0000004989d44d8dbe88000000bacc0000004889f74c89f64c89e1e8fb76c4ff4889c34c89ff4889c64889c2e88a4b3e004989c7'),
    ('spawn_second_lane', 0x288835d, '4c8b27f049ff04240f8e930000004989d54989fe4d8d7c2478bacc0000004889f74c89e64c89e9e897b977ff4889c34c89ff4889c64889c2e8f606f2ff4989c7'),
    ('first_task_constructor', 0x200b3b0, '488b86f00100000f57c00f57c94885c07411f048ff000f8ec50000000f108ef00100004889142448c744240800000000488d05b9a06803488944241048c744241800000000488974242048894c2428c74424300000000048897c24380f2944245048c7442460000000000f294c2470bf80000000be07000000ff15612e76034885c0744d'),
    ('second_task_constructor', 0x2003d30, '488b86900100000f57c00f57c94885c07411f048ff000f8ec50000000f108e900100004889142448c744240800000000488d05e9f86803488944241048c744241800000000488974242048894c2428c74424300000000048897c24380f2944245048c7442460000000000f294c2470bf80000000be07000000ff15e1a47603'),
    ('constructor_copy_and_alloc_failure', 0x2003daf, '4885c0744d0f284424700f2940700f284424600f2940600f284424500f2940500f284424400f2940400f2804240f284c24100f285424200f285c24300f2958300f2950200f2948100f2900488d65f85b5dc3bf80000000be80000000ff150fa276030f0b'),
    ('first_task_entry_thunk', 0x22a3d20, 'e9cb8badff'),
    ('second_task_entry_thunk', 0x22a4460, 'e9cba4aeff'),
    ('first_scheduler_admission', 0x1d7c8f0, '41574156534883ec504889fb488b07eb286666666666662e0f1f8400000000004889c14883e1f848ffc189c2c0ea0580e201f0480fb10b742ba8040f841d020000a80374db4883f83f0f8628020000488d48c04883f9400f92c280ca02f0480fb10b75d50fb6c2488d0daef863fe486304814801c8ffe0'),
    ('first_scheduler_call', 0x1d7c967, '488b05ba1d9f03488944244048895c24484c8d7320488d442440488944242848c74424300000000048894424204c8d7c24204c89f74c89fee85c72290084c00f8457010000'),
    ('first_scheduler_nonzero', 0x1d7c9ac, '488b034889e166666666662e0f1f840000000000a8010f84b8010000a82075344889c24883e2dea80475494883f83f0f86860100004883c2c04883fa40400f92c64000f6eb3e66666666662e0f1f84000000000040b6034889cf31d2488917833c24017433eb41666666662e0f1f8400000000004885c00f88700100004883c24040b60148c70424010000004c89ff488917833c24017510488b542420f0480fb1130f856cffffff400fb6c6488d0dbdf763fe486304814801c8ffe0'),
    ('first_scheduler_completion', 0x1d7cac1, '4c8d7320c70424020000004889e64c89f7e879f7290031c0488b4b2848894c242848894424304889542438c744242001000000488d7424204c89f7e84ff72900eb2531c031c948894c240848894424104889542418c70424010000004889e64c89f7e828f729004889dfe8b09f0300'),
    ('first_scheduler_terminal', 0x1d7cb3a, 'c70424020000004889e64c89f7e804f72900eb89488d3d473da5fe488d15047e9d03be24000000ff15a1159f03'),
    ('second_scheduler_admission', 0x1d8e930, '41574156534883ec504889fb488b07eb286666666666662e0f1f8400000000004889c14883e1f848ffc189c2c0ea0580e201f0480fb10b742ba8040f8407020000a80374db4883f83f0f8612020000488d48c04883f9400f92c280ca02f0480fb10b75d50fb6c2488d0d2ee162fe486304814801c8ffe0'),
    ('second_scheduler_call', 0x1d8e9a7, '488b057afd9d03488944244048895c24484c8d7320488d442440488944240848c744241000000000488904244989e74c89f74c89fee81f52280084c00f843e010000'),
    ('second_scheduler_nonzero', 0x1d8e9e9, '488b03488d4c24206666666666662e0f1f840000000000a8010f84a2010000a82075344889c24883e2dea80475494883f83f0f86700100004883c2c04883fa40400f92c64000f6eb3e66666666662e0f1f84000000000040b6034889cf31d2488917837c2420017434eb416666662e0f1f8400000000004885c00f885a0100004883c24040b60148c7442420010000004c89ff488917837c242001750f488b1424f0480fb1130f856bffffff400fb6c6488d0d3ce062fe486304814801c8ffe0'),
    ('second_scheduler_completion', 0x1d8eae5, '4c8d7320c744242002000000488d7424204c89f7e852d7280031c0488b4b2848894c240848894424104889542418c70424010000004889e64c89f7e82bd72800eb2831c031c948894c242848894424304889542438c744242001000000488d7424204c89f7e801d728004889dfe829a10200'),
    ('second_scheduler_terminal', 0x1d8eb61, 'c744242002000000488d7424204c89f7e8dad62800eb86488d3d1d1da4fe488d15da5d9c03be24000000ff1577f59d03'),
    ('task_future_wrapper', 0x2013c00, '5541574156415541545350837f100075344989fe4883c7184d8b6e0849c7c4d8eeffff64488b1c25000000004c01e364410fb644244883f801744983f802751e4531ffeb4b488d3d860c3bfe488d159d316803be75000000ff153aa47503488d05cb2ef6024989ff4889df4889f54889c6ff1569b575034c89ff4889ee6441c644244801644d8b7c2430644d896c24304c893c24e807ac290064410fb654244883fa01742bb10183fa02750984c0742ce98d00000089c5488d35722ef6024889dfff1519b575036441c64424480189e8644d897c243031c984c075664d8d7e1089c584c97512498b4608644d8b742430644989442430eb034531f64c8934244c89ffe80900f9ff41c7070200000064410fb64c244883f90189e8742083f902742189c5488d35062ef6024889dfff15adb475036441c64424480189e8644d897424304883c4085b415c415d415e415f5dc3'),
    ('task_future_wrapper_unwind_code', 0x2013d51, '4889c341c707020000004889e7ff159cba7503eb12ff15bca375034889c34889e7ff1588ba75034889dfe890c36403ff15a2a37503'),
    ('result_replace', 0x201c250, '55415741564155415453504989f64989ff488b6f0849c7c4d8eeffff64488b1c25000000004c01e364410fb644244883f801742183f80275054531edeb23488d359ba8f5024889dfff15422f75036441c644244801644d8b6c24306449896c24304c892c244983c7104c89ffe84f7af8ff410f1006410f104e10410f114f10410f110764410fb644244883f801741c83f802741d488d3545a8f5024889dfff15ec2e75036441c644244801644d896c24304883c4085b415c415d415e415f5dc3'),
    ('result_replace_unwind_code', 0x201c310, '4889c34c89f7e8f579f8ffeb1e4889c3410f1006410f104e10410f114f10410f11074889e7ff15c53475034889dfe8cd3d6403ff15df1d7503'),
    ('variant_destructor', 0x1fa3d10, '41574156538b0785c0745b83f801755048837f08007449488b5f104885db74404c8b7f18498b074885c074054889dfffd0498b77084885f67426498b4710f3480fbcc831d24839f00f47d14883f8110f43d14889df5b415e415fff25a0a27c035b415e415fc3488b5f084889dfe8ce240200be686300004889df31d25b415e415fff2579a27c03'),
    ('variant_destructor_unwind_code', 0x1fa3d97, '4989c6498b77084885f67430498b4710f3480fbcc831d24839f00f47d14883f8110f43d14889dfeb0d4989c6be686300004889df31d2ff153da27c034c89f7e835c36b03'),
    ('future_drop_dispatch', 0x1fc6250, '4156534883ec280fb6871602000083c0fd83f80a0f87470300004889fb488d0dc8d43ffe486304814801c8ffe00fb6833602000083f8040f842c03000083f8030f85cd020000488dbb48020000e82eeffdffe9bc020000'),
    ('future_drop_common', 0x1fc6548, '488bb3380100004885f6740f488bbb4001000031d2ff15ad7a7a03c783100200000000000048c783080200000000000080bb05020000007420488bb3a80000004889f048f7d87011730f488bbbb000000031d2ff156f7a7a03c683050200000066c7831402000000004883c4285b415ec3'),
    ('future_drop_nested', 0x1fc65b9, '0fb6837002000083f804743983f8037599488dbb78020000e83ad2ffffeb8b0fb6837002000083f804745283f8030f8576ffffff488dbb78020000e817d2ffffe965ffffff80bb18030000030f8558ffffff80bb10030000030f854bffffff80bb08030000030f853effffff488dbb90020000e8dffafeffe92dffffff80bb18030000030f8520ffffff80bb10030000030f8513ffffff80bb08030000030f8506ffffff488dbb90020000e8a7fafeffe9f5feffff'),
    ('first_reader_thunk', 0x229f990, 'e92b90abff'),
    ('second_reader_thunk', 0x229f710, 'e9ab92abff'),
    ('completion_reader', 0x1d589c0, '4157415641554154534883ec404889f34989fe488d7750ff15335da10384c07456410f104630410f104e400f294c24300f2944242041c7463002000000837c2420010f858f000000498b46484889442410410f1046380f290424803b00742648c703000000000f2804240f114308488b442410488943184883c4405b415c415d415e415fc348837b080074d34c8b73104d85f674ca4c8b6b18498b45004885c074094c8d63084c89f7ffd0498b75084885f674ab498b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff157b55a103eb88488d3dce4766fe488d159b5f9303be45000000ff15e855a1030f0b'),
    ('completion_reader_unwind_code', 0x1d58ab2, '4989c7498b75084885f67421498b4510f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff153155a10348c70300000000488b44241049894424100f280424410f1104244c89ffe80f7690034989c7488d7c2420e8827efdff4c89ffe8fa759003ff150c56a103'),
    ('future_drop_case_3', 0x1fc627d, '0fb68336020000'),
    ('future_drop_case_4', 0x1fc6344, '0fb68336020000'),
    ('future_drop_case_5', 0x1fc62c9, '488dbbc8020000'),
    ('future_drop_case_6', 0x1fc6319, '488dbbb0020000'),
    ('future_drop_case_7', 0x1fc62a7, '488dbbb0020000'),
    ('future_drop_case_8', 0x1fc636e, '488dbbb0020000'),
    ('future_drop_case_9', 0x1fc63be, '80bbc802000003'),
    ('future_drop_case_10', 0x1fc6327, '488dbbf8210000'),
    ('future_drop_case_11', 0x1fc6476, '488dbb30220000'),
    ('future_drop_case_12', 0x1fc62b8, '488dbb18020000'),
    ('future_drop_case_13', 0x1fc63f8, '488dbb60030000'),
    ('alternate_error_diagnostic', 0x20325a8, '488d3d691d39fe488d0d9a0366034c8d05d3496603488d542410be2b000000ff157bba73030f0b'),
    ('spawn_unwind_code', 0x229ee10, '4989c64889dfe86556faffeb56ff1505f34c034989c6be686300004889df31d2ff15daf14c036449ff0c244c89f7e8cd123c034989c66449ff0c244c89f7e8bd123c034989c64889dfe82256faffeb13ff15c2f24c034989c6488d7c2410e84d7bfbff4c89f7e895123c03ff15a7f24c034989c6be686300004889df31d2ff157cf14c034c89f7e874123c03'),
    ('input_drop_dispatch', 0x22569c0, '4156534883ec280fb6871602000083c0fd83f80a0f87470300004889fb488d0dacf117fe486304814801c8ffe00fb6833602000083f8040f842c03000083f8030f85cd020000488dbb48020000e81ec5feffe9bc020000'),
    ('input_drop_allocation', 0x2244480, '415653504889fbe834250100be686300004889df31d24883c4085b415eff256d9b52034989c6be686300004889df31d2ff155a9b52034c89f7e852bc4103'),
    ('input_drop_case_3', 0x22569ed, '0fb68336020000'),
    ('input_drop_case_4', 0x2256ab4, '0fb68336020000'),
    ('input_drop_case_5', 0x2256a39, '488dbbc8020000'),
    ('input_drop_case_6', 0x2256a89, '488dbbb0020000'),
    ('input_drop_case_7', 0x2256a17, '488dbbb0020000'),
    ('input_drop_case_8', 0x2256ade, '488dbbb0020000'),
    ('input_drop_case_9', 0x2256b2e, '80bbc802000003'),
    ('input_drop_case_10', 0x2256a97, '488dbbf8210000'),
    ('input_drop_case_11', 0x2256be6, '488dbb30220000'),
    ('input_drop_case_12', 0x2256a28, '488dbb18020000'),
    ('input_drop_case_13', 0x2256b68, '488dbb60030000'),
    ('spawn_failure_paths', 0x229ed1f, '40886c240f488d44240f4889442410488b055b064d034889442418488d3d0cb7f4fd488d7424104c89f2ff1549f34c03bf08000000be68630000ff15c1f24c03e986000000488d35d50259004989fdff156c044d036441c6442448014c89ef'),
    ('first_constructor_alloc_failure', 0x200b47a, '488d65f85b5dc3bf80000000be80000000ff158f2b76030f0b'),
    ('first_constructor_unwind', 0x200b493, '4889c34889e7e892f1f9ff4889dfe86a4c6503ff157c2c7603'),
    ('second_constructor_unwind', 0x2003e13, '4889c34889e7e8325ffaff4889dfe8eac26503ff15fca27603'),
    ('first_task_cleanup', 0x1faa630, '415653504889fb488b4720f048ff08750a488d7b20ff152d407c03488d7b30e8bc96ffff488b43604885c07407488b7b68ff5018488b43704885c0741af048ff0875144883c3704889df4883c4085b415eff25e93f7c034883c4085b415ec34989c6488d7b30e87596ffffeb30ff15853a7c034989c6488b43704885c0742af048ff0875244883c3704889dfff15ae3f7c03eb15ff155e3a7c034989c64883c3504889dfe8873f01004c89f7e82f5a6b03ff15413a7c03'),
    ('second_task_cleanup', 0x1fa9d50, '415653504889fb488b4720f048ff08750a488d7b20ff15fd487c03488d7b30e89c9fffff488b43604885c07407488b7b68ff5018488b43704885c0741af048ff0875144883c3704889df4883c4085b415eff25c9487c034883c4085b415ec34989c6488d7b30e8559fffffeb30ff1565437c034989c6488b43704885c0742af048ff0875244883c3704889dfff158e487c03eb15ff153e437c034989c64883c3504889dfe8674801004c89f7e80f636b03ff1521437c03'),
    ('first_scheduler_unwind', 0x1d7cc9c, '4989c7c70424020000004889e64c89f7e89ff529004c89ffff155e1a9f03488b0d5f1a9f03f048ff096448ff0c25d8fbffff64c60425e0fbffff00488b4b28e927feffffff1542149f03'),
    ('second_scheduler_unwind', 0x1d8ecc6, '4989c7c744242002000000488d7424204c89f7e872d528004c89ffff1531fa9d03488b0d32fa9d03f048ff096448ff0c25d8fbffff64c60425e0fbffff00488b4b28e91efeffffff1515f49d03'),
    ('entry_unwind', 0x22b8a69, 'eb004989c6c64308024c89f7e896763a034989c6488b3bb984000000b8cc000000f0480fb10f741c488b4710ff5020eb13ff1588564b034989c6488d7c2418e813b4f9ffc64308024c89f7e857763a03ff1569564b03'),
    ('alternate_entry_unwind', 0x20325e9, '4989c6c64308024c89f7e818db62034989c6c64308024c89f7e809db62034989c6488b3bb984000000b8cc000000f0480fb10f741c488b4710ff5020eb13ff15fbba73034989c6488d7c2410e8a6d3f8ffc64308024c89f7e8cada6203ff15dcba7303'),
    ('first_scheduler_notify_and_release', 0x1d7ca68, '488b43204883c010c6442420014889042448895c2408488d4424204889442410488d35698b9d034889e7e8b9fc1e0348c7c0c0fffffff0480fc1034883f83f0f86050100004883e0c04883f84075794889dfe85196fbffeb6f'),
    ('second_scheduler_notify_and_release', 0x1d8eaa9, '488d15d05f9c034c89f74889dee8b5dd1d0348c7c0c0fffffff0480fc1034883f83f0f860b0100004883e0c04883f840757c4889dfe8dd6cfaffeb72'),
    ('table_target_1d7c967', 0x1d7c967, '488b05ba1d9f03'),
    ('table_target_1d7cac1', 0x1d7cac1, '4c8d7320c70424'),
    ('table_target_1d7cb30', 0x1d7cb30, '4883c4505b415e'),
    ('table_target_1d7cab7', 0x1d7cab7, '4889dfe85196fb'),
    ('table_target_1d7ca68', 0x1d7ca68, '488b43204883c0'),
    ('table_target_1d7cb3a', 0x1d7cb3a, 'c7042402000000'),
    ('table_target_1d8e9a7', 0x1d8e9a7, '488b057afd9d03'),
    ('table_target_1d8eae5', 0x1d8eae5, '4c8d7320c74424'),
    ('table_target_1d8eb57', 0x1d8eb57, '4883c4505b415e'),
    ('table_target_1d8eadb', 0x1d8eadb, '4889dfe8dd6cfa'),
    ('table_target_1d8eaa9', 0x1d8eaa9, '488d15d05f9c03'),
    ('table_target_1d8eb61', 0x1d8eb61, 'c7442420020000'),
)

# FDE endpoints and byte hashes pin the ranges from which windows are selected.
# An unwind range is not, by itself, a complete source function boundary.
FUNCTIONS = (
    ('entry_poll', 0x22b8920, 0x22b8abf, '027e0ffa565d35a25a4495df77a863a20c8fe3542a91c17ef71f6a1bfaa9ea48'),
    ('alternate_entry', 0x2032480, 0x203264c, '370f28e5cf78347dd1d61d8a61cea4418ecd7a067e5dd4f52cf8167650d1ea52'),
    ('third_entry', 0x247bbf0, 0x247c01a, 'e3e6cd89b3ef09e16d3f24db52370b12504ea2cdb12729dcfa4f0b535dccd5b6'),
    ('spawn', 0x229ec10, 0x229ee9c, '3931714fa349b51c98f2f2c05dfd10da7e9fd3a6e71cc341ff88a10fdc04479b'),
    ('first_spawn_lane', 0x23c3c70, 0x23c3d9b, 'f3871d42fd72b376847c5f44d867538fc6dfd718b80ee86438152b6a3263b7b8'),
    ('second_spawn_lane', 0x2888350, 0x2888464, 'ab7a225a08a27020be720d19f2bb553e74d4d346964e518bb0d247edfa0718dd'),
    ('first_constructor', 0x200b3a0, 0x200b4ac, 'cca715d4b2b1e82297f8526429b08dd478ac4912b7d6714aed8c77f94069b9a8'),
    ('second_constructor', 0x2003d20, 0x2003e2c, 'ba67303a50f56b4fe15d744340e83cfb066d64e330937290f69439f79667e63f'),
    ('first_task_cleanup', 0x1faa630, 0x1faa6e7, 'cc446280ff94bc238b0da754fb6c36302bd283b3904aa28c2d67937c98266a75'),
    ('second_task_cleanup', 0x1fa9d50, 0x1fa9e07, 'c08dc53fa524011bb8904b7d104751b0025848b79c371335a8ec91fe7b3cafb9'),
    ('first_schedule_thunk', 0x22a3d20, 0x22a3d25, '65bbd401744379561e47bcf48df587895aa699722701f8b05ae6749b0b182f78'),
    ('second_schedule_thunk', 0x22a4460, 0x22a4465, '81ae4ba6c65e5a822149d685bf60d0170c4b93eb9636d1d3f1c707d16de6c742'),
    ('first_scheduler', 0x1d7c8f0, 0x1d7cce6, 'f820bd074d5fbed6da7204fb9af8d18b785535e7e9c3294fb683e4261e1b66e9'),
    ('second_scheduler', 0x1d8e930, 0x1d8ed13, 'a25412a6e797f1f370d90e81017822f159218628b6df4ececa86a6f9d167ddc8'),
    ('future_wrapper', 0x2013c00, 0x2013d86, '83961a1b001f713fba2f9ceb1917d2483acc9bcc5d0330d06eb92ca208d9529d'),
    ('replace_result', 0x201c250, 0x201c349, 'e2f6cf1354d434e65457549a0edc34daef2c036c8d624bca002bca2989ea8930'),
    ('drop_variant', 0x1fa3d10, 0x1fa3ddb, '73afdb830c1f3fc182e284f48c68180fac3790cf8eb18e7acdb59505e6badbc4'),
    ('drop_future', 0x1fc6250, 0x1fc6910, 'c8229400c9cc6ffadfde38406a36c37a86c8d6c6855498778b2fe6fbe6e1d365'),
    ('drop_input_future', 0x22569c0, 0x2257080, '363e51eb166e56918e49989fed3a44507144884350f0c886a67203e8f14a6b0f'),
    ('drop_input_allocation', 0x2244480, 0x22444be, 'd1821f4b521bee69d82be2bf73670dd589b9daabaf7c363080e64b0ddc2ef765'),
    ('first_reader_thunk', 0x229f990, 0x229f995, '68610d1be040b77709460caf771b1073f735bea389ec6618617d42ea6ec81d84'),
    ('second_reader_thunk', 0x229f710, 0x229f715, 'e6a789f3ba0f69d85dc8ad81e58f228c2d4eaf81c4074b7039926ec1b3cc4f9f'),
    ('read_completion', 0x1d589c0, 0x1d58b1c, '9859319809e8db04479bd3c8cae3ee8d5cefeecca7712da2c3d6ae990bbfe84f'),
)

# Names describe the selected site, not source symbols. Targets are calculated
# from the matched instruction bytes; no disassembler output is parsed.
SITES = (
    ('entry_spawn_location', 0x22b89a7, 'lea'),
    ('entry_spawn', 0x22b89b3, 'call'),
    ('entry_result_boundary', 0x22b89c6, 'call'),
    ('entry_result_tag_zero', 0x22b89d3, 'jcc'),
    ('entry_state_exchange', 0x22b89f9, 'jcc'),
    ('entry_nonzero_payload', 0x22b8a07, 'jcc'),
    ('entry_error_text', 0x22b8a28, 'lea'),
    ('entry_error_location', 0x22b8a36, 'lea'),
    ('entry_diagnostic', 0x22b8a47, 'slot'),
    ('entry_spawn_resume', 0x22b8a75, 'call'),
    ('entry_unwind_cleanup', 0x22b8aa8, 'call'),
    ('entry_unwind_resume', 0x22b8ab4, 'call'),
    ('alternate_spawn_location', 0x203251c, 'lea'),
    ('alternate_entry_spawn', 0x2032528, 'call'),
    ('alternate_entry_result_boundary', 0x203253b, 'call'),
    ('alternate_entry_tag', 0x2032545, 'jcc'),
    ('alternate_error_text', 0x20325a8, 'lea'),
    ('alternate_error_location', 0x20325b6, 'lea'),
    ('alternate_diagnostic', 0x20325c7, 'slot'),
    ('alternate_unwind_resume_a', 0x20325f3, 'call'),
    ('alternate_unwind_resume_b', 0x2032602, 'call'),
    ('alternate_unwind_resume_c', 0x2032641, 'call'),
    ('third_spawn_location', 0x247bd60, 'lea'),
    ('third_entry_spawn', 0x247bd67, 'call'),
    ('third_entry_result_boundary', 0x247bd80, 'call'),
    ('third_entry_tag', 0x247bd8e, 'jcc'),
    ('spawn_allocation_null', 0x229eca2, 'jcc'),
    ('spawn_counter_retry', 0x229ecde, 'jcc'),
    ('spawn_tls_one', 0x229ecfd, 'jcc'),
    ('spawn_tls_other', 0x229ed02, 'jcc'),
    ('spawn_reject_drop', 0x229ed07, 'call'),
    ('spawn_reject_free', 0x229ed16, 'slot'),
    ('spawn_tls_diagnostic', 0x229ed49, 'slot'),
    ('spawn_alloc_failure', 0x229ed59, 'slot'),
    ('spawn_counter_limit', 0x229ed90, 'jcc'),
    ('spawn_tls_mode_two', 0x229eda4, 'jcc'),
    ('spawn_tls_low_bit', 0x229edac, 'jcc'),
    ('spawn_first_lane', 0x229edb4, 'call'),
    ('spawn_second_lane', 0x229edc1, 'call'),
    ('spawn_tls_two_drop', 0x229edef, 'call'),
    ('spawn_tls_two_free', 0x229ee00, 'slot'),
    ('spawn_counter_limit_diagnostic', 0x229ede4, 'slot'),
    ('spawn_unwind_drop_a', 0x229ee16, 'call'),
    ('spawn_unwind_drop_b', 0x229ee59, 'call'),
    ('first_construct', 0x23c3ca0, 'call'),
    ('second_construct', 0x2888384, 'call'),
    ('first_table_reference', 0x200b3e0, 'lea'),
    ('second_table_reference', 0x2003d60, 'lea'),
    ('first_refcount_limit', 0x200b3c6, 'jcc'),
    ('second_refcount_limit', 0x2003d46, 'jcc'),
    ('first_alloc_null', 0x200b432, 'jcc'),
    ('second_alloc_null', 0x2003db2, 'jcc'),
    ('first_alloc_failure', 0x200b48b, 'slot'),
    ('second_alloc_failure', 0x2003e0b, 'slot'),
    ('first_constructor_unwind_drop', 0x200b499, 'call'),
    ('second_constructor_unwind_drop', 0x2003e19, 'call'),
    ('first_cleanup_refcount', 0x1faa63f, 'jcc'),
    ('first_cleanup_ref_release', 0x1faa645, 'slot'),
    ('first_cleanup_variant', 0x1faa64f, 'call'),
    ('first_cleanup_callback_null', 0x1faa65b, 'jcc'),
    ('first_cleanup_last_null', 0x1faa66b, 'jcc'),
    ('first_cleanup_last_count', 0x1faa671, 'jcc'),
    ('first_cleanup_last_release', 0x1faa681, 'slot_jump'),
    ('first_cleanup_variant_on_unwind', 0x1faa696, 'call'),
    ('first_cleanup_resume', 0x1faa6dc, 'call'),
    ('second_cleanup_refcount', 0x1fa9d5f, 'jcc'),
    ('second_cleanup_ref_release', 0x1fa9d65, 'slot'),
    ('second_cleanup_variant', 0x1fa9d6f, 'call'),
    ('second_cleanup_callback_null', 0x1fa9d7b, 'jcc'),
    ('second_cleanup_last_null', 0x1fa9d8b, 'jcc'),
    ('second_cleanup_last_count', 0x1fa9d91, 'jcc'),
    ('second_cleanup_last_release', 0x1fa9da1, 'slot_jump'),
    ('second_cleanup_variant_on_unwind', 0x1fa9db6, 'call'),
    ('second_cleanup_resume', 0x1fa9dfc, 'call'),
    ('first_schedule_thunk', 0x22a3d20, 'jump'),
    ('second_schedule_thunk', 0x22a4460, 'jump'),
    ('first_admission_retry_success', 0x1d7c927, 'jcc'),
    ('first_admission_flag_four', 0x1d7c92b, 'jcc'),
    ('first_admission_low_bits', 0x1d7c933, 'jcc'),
    ('first_admission_small_word', 0x1d7c939, 'jcc'),
    ('first_admission_retry', 0x1d7c952, 'jcc'),
    ('first_admission_table', 0x1d7c957, 'lea'),
    ('first_poll_wrapper', 0x1d7c99f, 'call'),
    ('first_poll_zero', 0x1d7c9a6, 'jcc'),
    ('first_postpoll_flag_one', 0x1d7c9c2, 'jcc'),
    ('first_postpoll_flag_twenty', 0x1d7c9ca, 'jcc'),
    ('first_postpoll_flag_four', 0x1d7c9d5, 'jcc'),
    ('first_postpoll_small_word', 0x1d7c9db, 'jcc'),
    ('first_postpoll_signed', 0x1d7ca23, 'jcc'),
    ('first_postpoll_retry', 0x1d7ca4e, 'jcc'),
    ('first_postpoll_table', 0x1d7ca58, 'lea'),
    ('first_postpoll_notify', 0x1d7ca92, 'call'),
    ('first_release_small_word', 0x1d7caa7, 'jcc'),
    ('first_release_not_last', 0x1d7cab5, 'jcc'),
    ('first_release_last', 0x1d7caba, 'call'),
    ('first_cancel_replace', 0x1d7cad2, 'call'),
    ('first_cancel_complete_replace', 0x1d7cafc, 'call'),
    ('first_complete_replace', 0x1d7cb23, 'call'),
    ('first_finish', 0x1d7cb2b, 'call'),
    ('first_other_replace', 0x1d7cb47, 'call'),
    ('first_bad_state_diagnostic', 0x1d7cb61, 'slot'),
    ('first_poll_unwind_replace', 0x1d7ccac, 'call'),
    ('second_admission_retry_success', 0x1d8e967, 'jcc'),
    ('second_admission_flag_four', 0x1d8e96b, 'jcc'),
    ('second_admission_low_bits', 0x1d8e973, 'jcc'),
    ('second_admission_small_word', 0x1d8e979, 'jcc'),
    ('second_admission_retry', 0x1d8e992, 'jcc'),
    ('second_admission_table', 0x1d8e997, 'lea'),
    ('second_poll_wrapper', 0x1d8e9dc, 'call'),
    ('second_poll_zero', 0x1d8e9e3, 'jcc'),
    ('second_postpoll_flag_one', 0x1d8ea02, 'jcc'),
    ('second_postpoll_flag_twenty', 0x1d8ea0a, 'jcc'),
    ('second_postpoll_flag_four', 0x1d8ea15, 'jcc'),
    ('second_postpoll_small_word', 0x1d8ea1b, 'jcc'),
    ('second_postpoll_signed', 0x1d8ea63, 'jcc'),
    ('second_postpoll_retry', 0x1d8ea8f, 'jcc'),
    ('second_postpoll_table', 0x1d8ea99, 'lea'),
    ('second_postpoll_notify', 0x1d8eab6, 'call'),
    ('second_release_small_word', 0x1d8eacb, 'jcc'),
    ('second_release_not_last', 0x1d8ead9, 'jcc'),
    ('second_release_last', 0x1d8eade, 'call'),
    ('second_cancel_replace', 0x1d8eaf9, 'call'),
    ('second_cancel_complete_replace', 0x1d8eb20, 'call'),
    ('second_complete_replace', 0x1d8eb4a, 'call'),
    ('second_finish', 0x1d8eb52, 'call'),
    ('second_other_replace', 0x1d8eb71, 'call'),
    ('second_bad_state_diagnostic', 0x1d8eb8b, 'slot'),
    ('second_poll_unwind_replace', 0x1d8ecd9, 'call'),
    ('wrapper_nonzero_tag', 0x2013c0f, 'jcc'),
    ('wrapper_tls_one', 0x2013c39, 'jcc'),
    ('wrapper_tls_other', 0x2013c3e, 'jcc'),
    ('wrapper_tag_diagnostic', 0x2013c58, 'slot'),
    ('wrapper_location_bound_future', 0x2013c94, 'call'),
    ('wrapper_restore_tls_one', 0x2013ca3, 'jcc'),
    ('wrapper_restore_tls_other', 0x2013caa, 'jcc'),
    ('wrapper_poll_zero_no_tls', 0x2013cae, 'jcc'),
    ('wrapper_poll_nonzero', 0x2013cda, 'jcc'),
    ('wrapper_without_tls', 0x2013ce4, 'jcc'),
    ('wrapper_drop_variant', 0x2013d02, 'call'),
    ('wrapper_after_drop_tls_one', 0x2013d1a, 'jcc'),
    ('wrapper_after_drop_tls_two', 0x2013d1f, 'jcc'),
    ('wrapper_unwind_tls', 0x2013d72, 'slot'),
    ('wrapper_unwind_resume', 0x2013d7b, 'call'),
    ('replace_tls_one', 0x201c282, 'jcc'),
    ('replace_tls_other', 0x201c287, 'jcc'),
    ('replace_drop_old', 0x201c2bc, 'call'),
    ('replace_restore_tls_one', 0x201c2dd, 'jcc'),
    ('replace_restore_tls_two', 0x201c2e2, 'jcc'),
    ('replace_unwind_tls', 0x201c335, 'slot'),
    ('replace_unwind_resume', 0x201c33e, 'call'),
    ('drop_tag_zero', 0x1fa3d19, 'jcc'),
    ('drop_tag_other', 0x1fa3d1e, 'jcc'),
    ('drop_word_zero', 0x1fa3d25, 'jcc'),
    ('drop_pointer_zero', 0x1fa3d2e, 'jcc'),
    ('drop_callback_zero', 0x1fa3d3a, 'jcc'),
    ('drop_size_zero', 0x1fa3d48, 'jcc'),
    ('drop_payload_free', 0x1fa3d6a, 'slot_jump'),
    ('drop_future_call', 0x1fa3d7d, 'call'),
    ('drop_future_free', 0x1fa3d91, 'slot_jump'),
    ('drop_future_unwind_free', 0x1fa3dcd, 'slot'),
    ('drop_future_unwind_resume', 0x1fa3dd6, 'call'),
    ('future_drop_outside_table', 0x1fc6264, 'jcc'),
    ('future_drop_table', 0x1fc626d, 'lea'),
    ('future_drop_subtag_four', 0x1fc6287, 'jcc'),
    ('future_drop_subtag_three', 0x1fc6290, 'jcc'),
    ('future_drop_nested_call', 0x1fc629d, 'call'),
    ('future_drop_flag_zero', 0x1fc657f, 'jcc'),
    ('future_drop_signed_overflow', 0x1fc658e, 'jcc'),
    ('future_drop_signed_zero', 0x1fc6590, 'jcc'),
    ('future_drop_conditional_free', 0x1fc659b, 'slot'),
    ('future_drop_substate_four', 0x1fc65c3, 'jcc'),
    ('future_drop_substate_three', 0x1fc65c8, 'jcc'),
    ('future_drop_nested_test_a', 0x1fc6605, 'jcc'),
    ('future_drop_nested_test_b', 0x1fc6612, 'jcc'),
    ('future_drop_nested_test_c', 0x1fc661f, 'jcc'),
    ('input_drop_outside_table', 0x22569d4, 'jcc'),
    ('input_drop_table', 0x22569dd, 'lea'),
    ('input_drop_subtag_four', 0x22569f7, 'jcc'),
    ('input_drop_subtag_three', 0x2256a00, 'jcc'),
    ('input_drop_nested_call', 0x2256a0d, 'call'),
    ('input_allocation_drop', 0x2244487, 'call'),
    ('input_allocation_free', 0x224449d, 'slot_jump'),
    ('input_allocation_unwind_free', 0x22444b0, 'slot'),
    ('input_allocation_unwind_resume', 0x22444b9, 'call'),
    ('first_reader_thunk', 0x229f990, 'jump'),
    ('second_reader_thunk', 0x229f710, 'jump'),
    ('reader_admit_boundary', 0x1d589d7, 'slot'),
    ('reader_admit_zero', 0x1d589df, 'jcc'),
    ('reader_wrong_tag', 0x1d58a02, 'jcc'),
    ('reader_destination_tag', 0x1d58a1d, 'jcc'),
    ('reader_old_word_zero', 0x1d58a4a, 'jcc'),
    ('reader_old_pointer_zero', 0x1d58a53, 'jcc'),
    ('reader_old_callback_zero', 0x1d58a60, 'jcc'),
    ('reader_old_size_zero', 0x1d58a72, 'jcc'),
    ('reader_old_release', 0x1d58a8f, 'slot'),
    ('reader_wrong_tag_diagnostic', 0x1d58aaa, 'slot'),
)

# Each table is admitted only with its exact expected targets. The two task
# tables have their size bounded by the selected state computations. The drop
# table bound is the immediate in the authenticated subtraction/compare.
TABLES = (
    ('first_admission', 0x3bc20c, 0x1d7c8f0,
     (0x1d7c967, 0x1d7cac1, 0x1d7cb30, 0x1d7cab7)),
    ('first_postpoll', 0x3bc21c, 0x1d7c8f0,
     (0x1d7cb30, 0x1d7ca68, 0x1d7cab7, 0x1d7cb3a)),
    ('second_admission', 0x3bcacc, 0x1d8e930,
     (0x1d8e9a7, 0x1d8eae5, 0x1d8eb57, 0x1d8eadb)),
    ('second_postpoll', 0x3bcadc, 0x1d8e930,
     (0x1d8eb57, 0x1d8eaa9, 0x1d8eadb, 0x1d8eb61)),
    ('future_drop_poll', 0x3c373c, 0x1fc6250,
     (0x1fc627d, 0x1fc6344, 0x1fc62c9, 0x1fc6319, 0x1fc62a7,
      0x1fc636e, 0x1fc63be, 0x1fc6327, 0x1fc6476, 0x1fc62b8, 0x1fc63f8)),
    ('future_drop_input', 0x3d5b90, 0x22569c0,
     (0x22569ed, 0x2256ab4, 0x2256a39, 0x2256a89, 0x2256a17,
      0x2256ade, 0x2256b2e, 0x2256a97, 0x2256be6, 0x2256a28, 0x2256b68)),
)

# Offsets within these two task callback tables, not a claim about their full
# runtime or type identity. RELATIVE entries and the thunks are checked below.
RELOCATIONS = (
    ('first_schedule', 0x56954a0, 0x22a3d20),
    ('first_read', 0x56954b8, 0x229f990),
    ('second_schedule', 0x5693650, 0x22a4460),
    ('second_read', 0x5693668, 0x229f710),
)

LOCATIONS = (
    ('alternate_spawn', 0x5696f60, 5, 5),
    ('alternate_error', 0x5696f90, 5, 39),
    ('entry_spawn', 0x56a0568, 5, 5),
    ('entry_error', 0x56a0598, 5, 39),
    ('third_spawn', 0x56b7e88, 5, 5),
)

# Hashes cover only the LSDA header and call-site table, not action/type tables.
# These are pins for the shared FDE reader's selected LSDA pointers.
LSDA_PINS = {
    0x22b8920: (0x9e1c9c, '4492b6f37f0c5f02e2ff659699d5b34f67f92d8a38a390f5b312673ac9cfec5e', 8),
    0x2032480: (0x9b872c, 'c9f936f93f911356f62d69fc4c295ded3534d06f4447cd01d7cd41b3d4670393', 9),
    0x247bbf0: (0x9f8028, '1d9cbdca33f9824bfec1ea640fc67a8623e1ab9b327cb92e9b4499b87b2d73ab', 17),
    0x229ec10: (0x9df830, '157c039c9a80376c84d2a2ac796a0574279d48b7b842a6086c16e4b624a0e519', 13),
    0x23c3c70: (0x9e9598, '446b4f09844edf117cd53e81808f0d67aa294f431947e943944c4702f815a82e', 7),
    0x2888350: (0xa30b3c, 'a80f78cb37e3f4eb43b07ad091546ac3cd7bb458404df0b115952d777b7ec573', 7),
    0x200b3a0: (0x9b4868, 'a6a6a340282878726bf3ca1cf0c06e3492e5015dcc30ac2991a979b737db0681', 3),
    0x2003d20: (0x9b3acc, 'a6a6a340282878726bf3ca1cf0c06e3492e5015dcc30ac2991a979b737db0681', 3),
    0x1faa630: (0x9abd84, 'f82d4325cf22bb53e3fa83cbe0e693a209edb4abf7283a066764a7b5a8f00984', 8),
    0x1fa9d50: (0x9abc3c, 'f82d4325cf22bb53e3fa83cbe0e693a209edb4abf7283a066764a7b5a8f00984', 8),
    0x1d7c8f0: (0x989b5c, '6ef386920d4add0c03e6403ff4c80ec5cb5a8b41722be57d32570bdfeace9901', 11),
    0x1d8e930: (0x98b348, '16323753af6eb278297ddfdc004df9ba7df42efc5bfd4527e125af64d56be0ec', 11),
    0x2013c00: (0x9b58e4, '4c7b25bbf0d1bcfe1f98e89213b66655ddf6a65545ad281a5e8a061aa96bdee4', 8),
    0x201c250: (0x9b695c, '19873159d02234b1d626f8c1b69d63324c54cd2659ccd98e644e51c1238a65c9', 5),
    0x1fa3d10: (0x9aaf10, 'b1b8e72063882fc21459ae39a648950ce2b62b28a5e7f5c4d144a91e2fe45ca8', 3),
    0x1fc6250: (0x9afe70, '7b6e5037132b3a3fbb1156b6b837b7c8c6314c2c072b49d4b48ba7bccbdc1446', 19),
    0x22569c0: (0x9dba84, '7b6e5037132b3a3fbb1156b6b837b7c8c6314c2c072b49d4b48ba7bccbdc1446', 19),
    0x2244480: (0x9d93e8, 'a8b8128d842fd92180e4987f9a0c924e728d042202fef4d9dd4aff6b96689b01', 2),
    0x1d589c0: (0x9866ec, '1d5516be9538546a1d3f20b83945a7b2073d5110073e1ab86b13697595e1175a', 6),
}

CONDITIONS = {
    0x70: 'overflow', 0x71: 'not_overflow', 0x72: 'below', 0x73: 'not_below',
    0x74: 'equal', 0x75: 'not_equal', 0x76: 'below_or_equal',
    0x77: 'above', 0x78: 'sign', 0x79: 'not_sign',
    0x7a: 'parity', 0x7b: 'not_parity', 0x7c: 'less',
    0x7d: 'greater_or_equal', 0x7e: 'less_or_equal', 0x7f: 'greater',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == SHA256, 'node 94 SHA-256 mismatch')
    return digest


class Image:
    """Map VAs only through unique file-backed ELF sections."""

    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def location(self, va, size):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid VA or size')
        matches = [s for s in self.sections if s['type'] != 8 and s['size']
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'VA not in exactly one file-backed section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off >= 0 and off + size <= len(self.data), 'file offset outside image')
        return s, off

    def read(self, va, size):
        _, off = self.location(va, size)
        return bytes(self.data[off:off + size])

    def number(self, va, size, signed=False):
        return int.from_bytes(self.read(va, size), 'little', signed=signed)


def fde_rows(image):
    secs, index = unwind_index(image.data)
    _, records = eh_frame_records(image.data, secs)
    selected = {row[1] for row in FUNCTIONS}
    records_by_start = {}
    for record in records:
        start = record['start']
        if start in selected:
            require(start not in records_by_start, 'duplicate selected FDE start')
            records_by_start[start] = record
    index_by_start = {}
    for row in index:
        if row['start'] in selected:
            require(row['start'] not in index_by_start, 'duplicate selected unwind start')
            index_by_start[row['start']] = row
    result = []
    for role, start, expected_end, expected_hash in FUNCTIONS:
        require(start in records_by_start and start in index_by_start, 'missing selected FDE')
        fde, entry = records_by_start[start], index_by_start[start]
        require(fde['fde'] == entry['fde'] and fde['end'] == expected_end,
                'FDE/header mismatch or changed extent')
        sec, off = image.location(start, fde['end'] - start)
        require(sec['flags'] & 4, 'FDE is not file-backed executable code')
        actual_hash = hashlib.sha256(image.read(start, fde['end'] - start)).hexdigest()
        require(actual_hash == expected_hash, 'selected FDE bytes differ')
        _, fde_offset = image.location(fde['fde'], 4)
        result.append(dict(role=role, start=start, end=fde['end'], fde=fde['fde'],
                           fde_file_offset=fde_offset, code_file_offset=off,
                           index=entry['index'], lsda=fde['lsda'], sha256=actual_hash))
    return result


def owner_for(rows, va, size=1):
    matches = [r for r in rows if r['start'] <= va and va + size <= r['end']]
    require(len(matches) == 1, 'site outside selected FDEs or ambiguous')
    return matches[0]


def window_rows(image, fdes):
    rows = []
    names = set()
    for name, va, expected in WINDOWS:
        require(name not in names, 'duplicate window name')
        names.add(name)
        pattern = bytes.fromhex(expected)
        require(image.read(va, len(pattern)) == pattern, 'fixed instruction window mismatch: ' + name)
        owner = owner_for(fdes, va, len(pattern))
        sec, off = image.location(va, len(pattern))
        rows.append(dict(name=name, owner=owner['start'], va=va, end=va + len(pattern),
                         file_offset=off, section=sec['name'], data=pattern.hex()))
    return rows


def decode_site(image, va, kind):
    """Decode only the exact rel32/rel8 and RIP forms used by SITES."""
    first = image.read(va, 2)
    condition = ''
    if kind == 'jcc':
        if 0x70 <= first[0] <= 0x7f:
            n, op = 2, first[0]
        else:
            require(first[0] == 0x0f and 0x80 <= first[1] <= 0x8f,
                    'wrong conditional opcode')
            n, op = 6, first[1] - 0x10
        condition = CONDITIONS[op]
        raw = image.read(va, n)
        displacement = int.from_bytes(raw[-1:] if n == 2 else raw[-4:], 'little', signed=True)
    elif kind in ('call', 'jump'):
        require(first[0] == (0xe8 if kind == 'call' else 0xe9), 'wrong direct transfer opcode')
        n = 5
        raw = image.read(va, n)
        displacement = int.from_bytes(raw[-4:], 'little', signed=True)
    elif kind in ('slot', 'slot_jump'):
        require(first == (b'\xff\x15' if kind == 'slot' else b'\xff\x25'),
                'wrong RIP-indirect opcode')
        n = 6
        raw = image.read(va, n)
        displacement = int.from_bytes(raw[-4:], 'little', signed=True)
    elif kind == 'lea':
        n = 7
        raw = image.read(va, n)
        require(raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and raw[2] & 0xc7 == 0x05,
                'wrong RIP-relative LEA opcode')
        displacement = int.from_bytes(raw[-4:], 'little', signed=True)
    else:
        raise ValueError('unsupported selected opcode kind')
    target = va + n + displacement
    require(0 <= target < 1 << 64, 'relative target outside address space')
    return dict(va=va, kind=kind, condition=condition, bytes=raw.hex(),
                target=target, displacement=displacement)


def flow_rows(image, fdes, windows):
    result = []
    names = set()
    for name, va, kind in SITES:
        require(name not in names, 'duplicate site name')
        names.add(name)
        row = decode_site(image, va, kind)
        size = len(bytes.fromhex(row['bytes']))
        owner = owner_for(fdes, va, size)
        if kind == 'jcc':
            require(owner['start'] <= row['target'] < owner['end'],
                    'conditional target outside selected FDE')
        require(any(w['va'] <= va and va + size <= w['end'] for w in windows),
                'site not covered by a matched window: ' + name)
        sec, off = image.location(va, size)
        row.update(name=name, owner=owner['start'], file_offset=off, section=sec['name'])
        result.append(row)
    return result


def relocation_rows(image):
    secs = [s for s in image.sections if s['name'] == '.rela.dyn']
    require(len(secs) == 1 and secs[0]['type'] == 4, 'missing, ambiguous or non-RELA .rela.dyn')
    sec = secs[0]
    require(sec['size'] % 24 == 0, 'truncated .rela.dyn')
    wanted = {slot: (name, target) for name, slot, target in RELOCATIONS}
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate selected relocation')
        name, expected = wanted[slot]
        require(info == 8 and addend == expected, 'changed relocation type, symbol or addend')
        require(image.read(slot, 8) == bytes(8), 'expected zero before RELATIVE relocation')
        _, slot_file_offset = image.location(slot, 8)
        found[slot] = dict(name=name, slot=slot, slot_file_offset=slot_file_offset,
                           entry_file_offset=off, type=info & 0xffffffff, symbol=info >> 32,
                           addend=addend, bytes=bytes(image.data[off:off + 24]).hex())
    require(set(found) == set(wanted), 'missing selected relocation')
    return [found[slot] for slot in sorted(found)]


def location_rows(image):
    """Validate the selected file/line/column records and their relocations."""
    secs = [s for s in image.sections if s['name'] == '.rela.dyn']
    require(len(secs) == 1 and secs[0]['type'] == 4 and secs[0]['size'] % 24 == 0, 'invalid .rela.dyn')
    wanted = {va: (name, line, column) for name, va, line, column in LOCATIONS}
    found = {}
    sec = secs[0]
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate Location relocation')
        require(info == 8 and addend >= 0, 'invalid Location relocation')
        name, expected_line, expected_col = wanted[slot]
        require(image.read(slot, 8) == bytes(8), 'nonzero Location pointer before relocation')
        length, line, col = struct.unpack('<QII', image.read(slot + 8, 16))
        require(length == len(b'src/hl_node.rs') and line == expected_line and col == expected_col,
                'changed Location length, line or column')
        path_bytes = image.read(addend, length)
        require(path_bytes == b'src/hl_node.rs', 'changed Location path bytes')
        _, record_off = image.location(slot, 24)
        _, path_off = image.location(addend, length)
        found[slot] = dict(name=name, va=slot, file_offset=record_off, relocation_offset=off,
                           path_va=addend, path_file_offset=path_off, path=path_bytes.decode('ascii'),
                           length=length, line=line, column=col)
    require(set(found) == set(wanted), 'missing Location relocation')
    return [found[slot] for slot in sorted(found)]


def literal_rows(image):
    """Bind the two length-setup sequences to their exact diagnostic bytes."""
    expected = b'called `Result::unwrap()` on an `Err` value'
    rows = []
    for name, lea, length_instruction, trap in (
        ('entry_unwrap', 0x22b8a28, 0x22b8a42, 0x22b8a4d),
        ('alternate_unwrap', 0x20325a8, 0x20325c2, 0x20325cd),
    ):
        target = decode_site(image, lea, 'lea')['target']
        require(image.read(length_instruction, 1) == b'\xbe', 'changed literal length opcode')
        length = image.number(length_instruction + 1, 4)
        require(length == len(expected), 'changed literal length')
        content = image.read(target, length)
        require(content == expected, 'changed literal bytes')
        require(image.read(trap, 2) == b'\x0f\x0b', 'missing fallthrough trap')
        _, offset = image.location(target, length)
        rows.append(dict(name=name, lea=lea, va=target, file_offset=offset, length=length,
                         length_instruction=length_instruction, trap=trap,
                         sha256=hashlib.sha256(content).hexdigest(), text=content.decode('ascii')))
    return rows


def lsda_rows(image, fdes):
    """Read selected omitted-LPStart ULEB call-site tables, not action chains."""
    except_sections = [s for s in image.sections if s['name'] == '.gcc_except_table']
    require(len(except_sections) == 1 and except_sections[0]['type'] != 8,
            'missing, duplicate or NOBITS exception table section')
    section = except_sections[0]
    limit = section['offset'] + section['size']
    headers, rows, seen = [], [], set()
    for fde in fdes:
        if fde['lsda'] is None:
            require(fde['start'] not in LSDA_PINS, 'selected LSDA absent')
            continue
        require(fde['start'] in LSDA_PINS, 'unexpected selected LSDA')
        expected_va, expected_hash, expected_count = LSDA_PINS[fde['start']]
        require(fde['lsda'] == expected_va, 'changed LSDA pointer')
        actual_section, origin = image.location(expected_va, 2)
        require(actual_section['name'] == '.gcc_except_table', 'LSDA outside exception table')
        require(expected_va not in seen, 'duplicate selected LSDA')
        seen.add(expected_va)
        data, pos = image.data, origin
        require(data[pos] == 0xff and data[pos + 1] in (0xff, 0x9b), 'unsupported LSDA header')
        type_encoding = data[pos + 1]
        pos += 2
        if type_encoding == 0x9b:
            distance, pos = uleb(data, pos, limit)
            type_base = pos + distance
            require(type_base <= limit, 'LSDA type table outside section')
        else:
            type_base = None
        require(pos < limit and data[pos] == 1, 'unsupported LSDA call-site encoding')
        length, pos = uleb(data, pos + 1, limit)
        table_start, table_end = pos, pos + length
        require(table_end <= limit and (type_base is None or table_end <= type_base),
                'LSDA call-site table outside bounds')
        previous, index = fde['start'], 0
        while pos < table_end:
            entry_offset = pos
            fields = []
            for _ in range(4):
                value, pos = uleb(data, pos, table_end)
                fields.append(value)
            start_delta, size, landing_delta, action = fields
            start = fde['start'] + start_delta
            end = start + size
            landing = fde['start'] + landing_delta if landing_delta else None
            require(fde['start'] <= start < end <= fde['end'] and start >= previous,
                    'overlapping or out-of-range LSDA row')
            require(landing is None or fde['start'] <= landing < fde['end'],
                    'LSDA landing outside FDE')
            rows.append(dict(owner=fde['start'], lsda=expected_va, index=index,
                             entry_file_offset=entry_offset, bytes=bytes(data[entry_offset:pos]).hex(),
                             start=start, end=end, landing=landing, action=action))
            previous, index = end, index + 1
        require(pos == table_end and index == expected_count, 'changed LSDA row count')
        raw = bytes(data[origin:table_end])
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_hash, 'LSDA call-site bytes changed')
        headers.append(dict(owner=fde['start'], va=expected_va, file_offset=origin,
                            type_encoding=type_encoding, call_site_encoding=1,
                            table_bytes=table_end - table_start, prefix_bytes=raw.hex(),
                            sha256=digest, count=index))
    require({h['owner'] for h in headers} == set(LSDA_PINS), 'selected LSDA set mismatch')
    return headers, rows


def lsda_call_rows(flow, rows):
    result = []
    for call in flow:
        if call['kind'] not in ('call', 'slot'):
            continue
        lookup = call['va'] + len(bytes.fromhex(call['bytes'])) - 1
        matches = [r for r in rows if r['owner'] == call['owner'] and r['start'] <= lookup < r['end']]
        require(len(matches) <= 1, 'overlapping LSDA call lookup')
        hit = matches[0] if matches else None
        result.append(dict(name=call['name'], owner=call['owner'], site=call['va'], lookup=lookup,
                           row_index=hit['index'] if hit else None,
                           landing=hit['landing'] if hit else None,
                           action=hit['action'] if hit else None))
    return result


def table_rows(image, fdes):
    rows = []
    # 83 c0 fd; 83 f8 0a: zero-extend a byte, subtract three modulo 2^32,
    # then an unsigned comparison with ten. Out-of-range tags do not index.
    require(image.read(0x1fc625e, 6) == bytes.fromhex('83c0fd83f80a'), 'drop table guard mismatch')
    require(image.read(0x22569ce, 6) == bytes.fromhex('83c0fd83f80a'), 'input drop table guard mismatch')
    bias = image.number(0x1fc6260, 1, signed=True)
    maximum = image.number(0x1fc6263, 1)
    for name, base, owner, expected_targets in TABLES:
        fde = next((r for r in fdes if r['start'] == owner), None)
        require(fde is not None, 'table owner absent')
        if name.startswith('future_drop_'):
            require(len(expected_targets) == maximum + 1 and bias == -3,
                    'drop table length does not match guard')
        for index, expected in enumerate(expected_targets):
            address = base + 4 * index
            raw = image.read(address, 4)
            displacement = int.from_bytes(raw, 'little', signed=True)
            target = base + displacement
            require(target == expected and fde['start'] <= target < fde['end'],
                    'changed or out-of-range table entry')
            anchors = [bytes.fromhex(pattern) for _, address, pattern in WINDOWS if address == target]
            require(anchors and any(image.read(target, len(pattern)) == pattern for pattern in anchors),
                    'jump-table target has no matching fixed window')
            sec, off = image.location(address, 4)
            rows.append(dict(table=name, base=base, index=index,
                             input_tag=(index - bias if name.startswith('future_drop_') else ''),
                             entry=address, file_offset=off, section=sec['name'], bytes=raw.hex(),
                             displacement=displacement, target=target, owner=owner))
    paired = [[r['target'] - r['owner'] for r in rows if r['table'] == name]
              for name in ('future_drop_poll', 'future_drop_input')]
    require(paired[0] == paired[1] and len(paired[0]) == maximum + 1,
            'drop table relative targets differ')
    return rows


def future_drop_case(tag):
    """Static model of the authenticated byte/unsigned jump-table guard."""
    require(type(tag) is int and 0 <= tag <= 255, 'tag must be a byte')
    adjusted = (tag - 3) & 0xffffffff
    return adjusted if adjusted <= 10 else None


def admission_model(word):
    """Model the selected pre-CAS admission calculation, assuming CAS success."""
    require(type(word) is int and 0 <= word < 1 << 64, 'state word must be unsigned 64-bit')
    if not word & 4:
        return 'missing_bit_4', None, None
    if not word & 3:
        return 'compare_exchange', ((word & ~7) + 1) & ((1 << 64) - 1), (word >> 5) & 1
    if word <= 0x3f:
        return 'small_word', None, None
    new = word - 0x40
    return 'compare_exchange', new, 2 + int(new < 0x40)


def initial_admission_rows(image, tables):
    """Bind the constructor's immediate to the selected index in both tables."""
    rows = []
    for name, immediate_site, table in (
        ('first', 0x23c3c92, 'first_admission'),
        ('second', 0x2888376, 'second_admission'),
    ):
        raw = image.read(immediate_site, 5)
        require(raw[0] == 0xba, 'changed initial-state immediate opcode')
        old = int.from_bytes(raw[1:], 'little')
        disposition, new, selector = admission_model(old)
        require(disposition == 'compare_exchange', 'initial word does not admit CAS')
        matches = [r for r in tables if r['table'] == table and r['index'] == selector]
        require(len(matches) == 1, 'initial admission table entry absent')
        rows.append(dict(name=name, immediate_site=immediate_site, immediate_bytes=raw.hex(),
                         old=old, new=new, selector=selector, table=table, target=matches[0]['target']))
    return rows


def layout_rows(image):
    """Extract selected operands; input initialization offsets are relative."""
    values = []

    def add(name, value, source):
        values.append(dict(name=name, value=value, source=source))

    for name, store, lea in (
        ('entry_future_tag_offset', 0x22b899f, 0x22b89ae),
        ('alternate_future_tag_offset', 0x2032514, 0x2032523),
        ('third_future_tag_offset', 0x247bd53, 0x247bd5b),
    ):
        require(image.read(store, 3) == bytes.fromhex('c68424'), 'unexpected byte-store form')
        require(image.read(lea, 4) == bytes.fromhex('488d7c24'), 'unexpected stack LEA form')
        add(name, image.number(store + 3, 4) - image.number(lea + 4, 1), hex(store) + ',' + hex(lea))
    for name, va, size in (
        ('future_copy_size', 0x229ec87, 4),
        ('future_alloc_size', 0x229ec95, 4),
        ('task_alloc_size', 0x2003da0, 4),
        ('task_table_offset', 0x2003d6b, 1),
        ('task_context_offset', 0x2003d79, 1),
        ('task_variant_offset', 0x2003d82, 1),
        ('task_future_offset', 0x2003d8b, 1),
        ('scheduler_context_offset', 0x1d8e9bb, 1),
        ('wrapper_variant_offset', 0x2013c0d, 1),
        ('wrapper_future_offset', 0x2013c17, 1),
        ('wrapper_completed_tag', 0x2013d0a, 4),
        ('replacement_variant_offset', 0x201c2b8, 1),
        ('completion_tag', 0x1d7cb19, 4),
        ('reader_variant_offset', 0x1d589f8, 1),
        ('reader_consumed_tag', 0x1d589f9, 4),
        ('drop_allocation_size', 0x1fa3d83, 4),
    ):
        add(name, image.number(va, size), hex(va))
    by_name = {row['name']: row['value'] for row in values}
    require(by_name['future_copy_size'] == by_name['future_alloc_size'] == by_name['drop_allocation_size'],
            'future allocation/copy/drop sizes disagree')
    require(len({by_name[n] for n in ('entry_future_tag_offset', 'alternate_future_tag_offset',
                                     'third_future_tag_offset')}) == 1, 'input tag offsets disagree')
    require(by_name['task_variant_offset'] == by_name['scheduler_context_offset'] + by_name['wrapper_variant_offset']
            == by_name['scheduler_context_offset'] + by_name['replacement_variant_offset']
            == by_name['reader_variant_offset'], 'task variant offsets disagree')
    require(by_name['task_future_offset'] == by_name['scheduler_context_offset'] + by_name['wrapper_future_offset'],
            'future pointer offsets disagree')
    return values


def caller_candidates(image):
    targets = {0x229ec10, 0x2013c00}
    expected = {0x229ec10: [0x2032528, 0x22b89b3, 0x247bd67],
                0x2013c00: [0x1d7c99f, 0x1d8e9dc]}
    found = {target: [] for target in targets}
    wanted_sections = ('.text', '.init', '.fini', '.plt')
    seen = []
    for section in image.sections:
        if section['name'] not in wanted_sections or section['type'] == 8 or not section['size']:
            continue
        seen.append(section['name'])
        base, off, size = section['address'], section['offset'], section['size']
        data = image.data[off:off + size]
        pos = data.find(b'\xe8')
        while pos >= 0 and pos + 5 <= size:
            target = base + pos + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if target in targets:
                found[target].append(base + pos)
            pos = data.find(b'\xe8', pos + 1)
    require(set(seen) == set(wanted_sections) and len(seen) == len(wanted_sections),
            'missing or duplicate scan section')
    for target in sorted(found):
        found[target].sort()
        require(found[target] == expected[target], 'changed byte-pattern call candidate set')
    return found


def collect(data, check_digest=True):
    digest = verify_digest(data) if check_digest else hashlib.sha256(data).hexdigest()
    image = Image(data)
    fdes = fde_rows(image)
    windows = window_rows(image, fdes)
    flow = flow_rows(image, fdes, windows)
    relocations = relocation_rows(image)
    locations = location_rows(image)
    literals = literal_rows(image)
    lsda_headers, lsda = lsda_rows(image, fdes)
    lsda_calls = lsda_call_rows(flow, lsda)
    tables = table_rows(image, fdes)
    initial_admission = initial_admission_rows(image, tables)
    layout = layout_rows(image)
    candidates = caller_candidates(image)
    return dict(digest=digest, fdes=fdes, windows=windows, flow=flow,
                relocations=relocations, locations=locations, literals=literals, tables=tables, layout=layout,
                initial_admission=initial_admission, lsda_headers=lsda_headers, lsda=lsda,
                lsda_calls=lsda_calls, candidates=candidates)


def hx(value):
    return '' if value is None or value == '' else hex(value)


def write_tsv(out, name, headings, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(headings)
        writer.writerows(rows)


def write_evidence(out, result):
    out.mkdir(parents=True, exist_ok=True)
    fs, ws, fl, rel, locs, lits, tbl, layout = (result[k] for k in
                                               ('fdes', 'windows', 'flow', 'relocations', 'locations',
                                                'literals', 'tables', 'layout'))
    write_tsv(out, 'extents.tsv', ('role', 'start_va', 'end_va_exclusive', 'size', 'fde_va',
                                  'fde_file_offset', 'code_file_offset', 'unwind_index', 'lsda_va', 'sha256'),
              ((r['role'], hx(r['start']), hx(r['end']), r['end'] - r['start'], hx(r['fde']),
                hx(r['fde_file_offset']), hx(r['code_file_offset']), r['index'], hx(r['lsda']), r['sha256']) for r in fs))
    write_tsv(out, 'windows.tsv', ('name', 'owner_va', 'start_va', 'end_va_exclusive', 'file_offset',
                                  'section', 'exact_bytes_hex'),
              ((r['name'], hx(r['owner']), hx(r['va']), hx(r['end']), hx(r['file_offset']), r['section'], r['data']) for r in ws))
    write_tsv(out, 'flow.tsv', ('name', 'owner_va', 'site_va', 'file_offset', 'kind', 'condition',
                               'bytes', 'signed_displacement', 'target_va'),
              ((r['name'], hx(r['owner']), hx(r['va']), hx(r['file_offset']), r['kind'], r['condition'],
                r['bytes'], r['displacement'], hx(r['target'])) for r in fl))
    write_tsv(out, 'relocations.tsv', ('name', 'slot_va', 'slot_file_offset', 'entry_file_offset', 'type',
                                      'symbol', 'addend_va', 'entry_bytes'),
              ((r['name'], hx(r['slot']), hx(r['slot_file_offset']), hx(r['entry_file_offset']),
                r['type'], r['symbol'], hx(r['addend']), r['bytes']) for r in rel))
    write_tsv(out, 'locations.tsv', ('name', 'record_va', 'file_offset', 'relocation_file_offset',
                                    'path_va', 'path_file_offset', 'path', 'length', 'line', 'column'),
              ((r['name'], hx(r['va']), hx(r['file_offset']), hx(r['relocation_offset']), hx(r['path_va']),
                hx(r['path_file_offset']), r['path'], r['length'], r['line'], r['column']) for r in locs))
    write_tsv(out, 'literals.tsv', ('name', 'lea_va', 'literal_va', 'file_offset', 'length',
                                   'length_instruction_va', 'fallthrough_trap_va', 'sha256', 'text'),
              ((r['name'], hx(r['lea']), hx(r['va']), hx(r['file_offset']), r['length'],
                hx(r['length_instruction']), hx(r['trap']), r['sha256'], r['text']) for r in lits))
    write_tsv(out, 'lsda-headers.tsv', ('owner_va', 'lsda_va', 'file_offset', 'type_encoding',
                                       'call_site_encoding', 'call_site_bytes', 'row_count', 'sha256', 'header_and_table_bytes'),
              ((hx(r['owner']), hx(r['va']), hx(r['file_offset']), hex(r['type_encoding']),
                r['call_site_encoding'], r['table_bytes'], r['count'], r['sha256'], r['prefix_bytes'])
               for r in result['lsda_headers']))
    write_tsv(out, 'lsda.tsv', ('owner_va', 'lsda_va', 'row_index', 'entry_file_offset', 'entry_bytes',
                               'start_va', 'end_va_exclusive', 'landing_va', 'action_offset'),
              ((hx(r['owner']), hx(r['lsda']), r['index'], hx(r['entry_file_offset']), r['bytes'],
                hx(r['start']), hx(r['end']), hx(r['landing']), r['action']) for r in result['lsda']))
    write_tsv(out, 'lsda-calls.tsv', ('name', 'owner_va', 'site_va', 'return_pc_minus_one',
                                     'row_index', 'landing_va', 'action_offset'),
              ((r['name'], hx(r['owner']), hx(r['site']), hx(r['lookup']),
                '' if r['row_index'] is None else r['row_index'], hx(r['landing']),
                '' if r['action'] is None else r['action']) for r in result['lsda_calls']))
    write_tsv(out, 'tables.tsv', ('table', 'base_va', 'index', 'input_tag', 'entry_va', 'file_offset',
                                 'section', 'bytes', 'signed_displacement', 'target_va', 'owner_va'),
              ((r['table'], hx(r['base']), r['index'], r['input_tag'], hx(r['entry']), hx(r['file_offset']),
                r['section'], r['bytes'], r['displacement'], hx(r['target']), hx(r['owner'])) for r in tbl))
    write_tsv(out, 'initial-admission.tsv', ('lane', 'immediate_site_va', 'immediate_bytes', 'initial_word',
                                            'word_if_cas_succeeds', 'selector', 'table', 'target_va'),
              ((r['name'], hx(r['immediate_site']), r['immediate_bytes'], hex(r['old']), hex(r['new']),
                r['selector'], r['table'], hx(r['target'])) for r in result['initial_admission']))
    write_tsv(out, 'layout.tsv', ('name', 'value_decimal', 'value_hex', 'operand_va'),
              ((r['name'], r['value'], hex(r['value']), r['source']) for r in layout))
    candidates = result['candidates']
    write_tsv(out, 'call-candidates.tsv', ('target_va', 'site_va', 'form'),
              ((hx(target), hx(site), 'e8 rel32') for target in sorted(candidates) for site in candidates[target]))
    counts = {name: len(value) for name, value in
              (('fde_extents', fs), ('fixed_windows', ws), ('selected_relative_sites', fl),
               ('relocations', rel), ('location_records', locs), ('literal_records', lits),
               ('jump_table_entries', tbl), ('layout_operands', layout))}
    counts['scanned_call_candidates'] = sum(len(v) for v in candidates.values())
    counts['lsda_headers'] = len(result['lsda_headers'])
    counts['lsda_rows'] = len(result['lsda'])
    counts['selected_call_lookups'] = len(result['lsda_calls'])
    counts['call_lookups_with_landing'] = sum(r['landing'] is not None for r in result['lsda_calls'])
    counts['initial_admission_lanes'] = len(result['initial_admission'])
    summary = {'target_sha256': result['digest'], 'coordinate_system': 'ELF link-time VA and file offset',
               'counts': counts, 'scan_sections': ['.fini', '.init', '.plt', '.text'],
               'scan_form': 'all byte offsets matching e8 rel32; candidates may include unaligned bytes',
               'limitations': 'Selected fixed windows and unwind ranges; not a complete call graph or runtime trace.'}
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    result = collect(TARGET.read_bytes())
    write_evidence(args.out, result)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_loader_task_poll94:', error, file=sys.stderr)
        raise SystemExit(1)
