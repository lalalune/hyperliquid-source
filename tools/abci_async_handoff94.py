#!/usr/bin/env python3
"""Reproduce selected node 94 async state-loader handoff evidence without execution."""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

# The existing FDE helper itself imports elf_index as a top-level module.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# These are selected FDE starts, not a complete program function inventory.
FUNCTIONS = {
    'future_cleanup': 0x22569c0,
    'poll_cleanup': 0x1fc6250,
    'driver': 0x2893110,
    'outer_driver': 0x247c020,
    'local_driver': 0x2885a80,
    'outer_parent': 0x2032480,
    'local_parent': 0x22b8920,
    'tls_parent': 0x247bbf0,
    'spawn': 0x229ec10,
    'queue_a': 0x2888350,
    'queue_b': 0x23c3c70,
    'allocate_a': 0x2003d20,
    'allocate_b': 0x200b3a0,
    'poll_stub_a': 0x22a4460,
    'poll_stub_b': 0x22a3d20,
    'scheduler_a': 0x1d8e930,
    'scheduler_b': 0x1d7c8f0,
    'poll_bridge': 0x2013c00,
    'replace_slot': 0x201c250,
    'drop_slot': 0x1fa3d10,
    'read_stub_a': 0x229f710,
    'read_stub_b': 0x229f990,
    'read_result': 0x1d589c0,
    'finish_a': 0x1db8c80,
    'finish_b': 0x1db6ae0,
}

# Each window is an exact fixed byte pattern, chosen at observed instruction
# boundaries. It is not a general x86 decoder or a claim of full CFG recovery.
WINDOWS = [
    ('outer_parent_dispatch', 0x20324e4,
     '4989f6488b07488b5f08488b38488b36e8070cf40284c07450488b1b0fb64308488d0dd91539fe486304814801c8ffe0c684'
     '242602000000488d353d4a6603488d7c2410e8e3c62600488903488d7c24104889de4c89f2e830460100837c2410017513b1'
     '03b002eb3f'
    ),
    ('local_parent_dispatch', 0x22b8985,
     '4989f64889fb0fb64708488d0d62dd11fe486304814801c8ffe0c684242e02000000488d35ba7b3e03488d7c2418e85862fe'
     'ff488903488d7c24184889de4c89f2e8a5e1d8ff'
    ),
    ('local_parent_result', 0x22b89cb,
     '0fb66c24184084ed7404b003eb304c8b7424200f104424280f290424488b3bb984000000b8cc000000f0480fb10f7407488b'
     '4710ff5020b0014d85f6751188430889e84881c4806300005b415e5dc3'
    ),
    ('local_parent_unwrap', 0x22b8a1a,
     '4c897424180f2804240f11442420488d3d5eee11fe488d0dda593e034c8d055b7b3e03488d542418be2b000000ff15fb554b'
     '030f0b'
    ),
    ('tls_parent_dispatch', 0x247bd3e,
     '0fb6442418488d0d626df6fd486304814801c8ffe0c684248602000000488d7c2470488d3521c12303e8a42ee2ff48894424'
     '10488d7c2470488d742410488d542450e8ebadbcff488b5c24704883fb01751041b403eb4966662e0f1f8400000000004c8b'
     '6c2478488d8424800000000f10000f29442440488b7c2410b8cc000000b984000000f0480fb10f7407488b4710ff502041b4'
     '014d85ed0f85cf000000'
    ),
    ('spawn_allocate_and_copy', 0x229ec7b,
     '4989f64989ff488d7c2410ba686300004c89feff154cf34c03bf68630000ff1539f34c034885c00f84a70000004889c3ba68'
     '6300004889c74c89feff1524f34c03'
    ),
    ('spawn_tls_gate', 0x229ecf3,
     '64410fb644244883f801747f83f80275604889dfe8b47cfbffbe686300004889df31d2ff15f4f24c0340b501'
    ),
    ('spawn_runtime_choice', 0x229ed7e,
     '64498b042448b9ffffffffffffff7f4839c8734b48ffc0644989042464498b4424084883f80274464883c710a801740d4889'
     'de4c89fae8b74e1200eb0b4889de4c89fae88a955e006449ff0c244881c4786300005b415c415d415e415f5dc3'
    ),
    ('spawn_tls_error', 0x229edec,
     '4889dfe8cc7bfbff31edbe686300004889df31d2ff150af24c036449ff0c24e90fffffff'
    ),
    ('queue_b_entry', 0x23c3c7b,
     '4c8b37f049ff060f8eab0000004989d44d8dbe88000000bacc0000004889f74c89f64c89e1e8fb76c4ff4889c34c89ff4889'
     'c64889c2e88a4b3e00'
    ),
    ('queue_a_entry', 0x288835d,
     '4c8b27f049ff04240f8e930000004989d54989fe4d8d7c2478bacc0000004889f74c89e64c89e9e897b977ff4889c34c89ff'
     '4889c64889c2e8f606f2ff'
    ),
    ('allocate_a_fields', 0x2003d30,
     '488b86900100000f57c00f57c94885c07411f048ff000f8ec50000000f108e900100004889142448c744240800000000488d'
     '05e9f86803488944241048c744241800000000488974242048894c2428c74424300000000048897c24380f2944245048c744'
     '2460000000000f294c2470bf80000000be07000000ff15e1a476034885c0744d'
    ),
    ('allocate_a_copy_and_failure', 0x2003db4,
     '0f284424700f2940700f284424600f2940600f284424500f2940500f284424400f2940400f2804240f284c24100f28542420'
     '0f285c24300f2958300f2950200f2948100f2900488d65f85b5dc3bf80000000be80000000ff150fa276030f0b'
    ),
    ('allocate_b_fields', 0x200b3b0,
     '488b86f00100000f57c00f57c94885c07411f048ff000f8ec50000000f108ef00100004889142448c744240800000000488d'
     '05b9a06803488944241048c744241800000000488974242048894c2428c74424300000000048897c24380f2944245048c744'
     '2460000000000f294c2470bf80000000be07000000ff15612e76034885c0744d'
    ),
    ('allocate_b_copy_and_failure', 0x200b434,
     '0f284424700f2940700f284424600f2940600f284424500f2940500f284424400f2940400f2804240f284c24100f28542420'
     '0f285c24300f2958300f2950200f2948100f2900488d65f85b5dc3bf80000000be80000000ff158f2b76030f0b'
    ),
    ('poll_stub_a', 0x22a4460,
     'e9cba4aeff'
    ),
    ('poll_stub_b', 0x22a3d20,
     'e9cb8badff'
    ),
    ('read_stub_a', 0x229f710,
     'e9ab92abff'
    ),
    ('read_stub_b', 0x229f990,
     'e92b90abff'
    ),
    ('scheduler_b_admission', 0x1d7c910,
     '4889c14883e1f848ffc189c2c0ea0580e201f0480fb10b742ba8040f841d020000a80374db4883f83f0f8628020000488d48'
     'c04883f9400f92c280ca02f0480fb10b75d50fb6c2488d0daef863fe486304814801c8ffe0'
    ),
    ('scheduler_b_poll', 0x1d7c967,
     '488b05ba1d9f03488944244048895c24484c8d7320488d442440488944242848c74424300000000048894424204c8d7c2420'
     '4c89f74c89fee85c72290084c00f8457010000'
    ),
    ('scheduler_b_requeue', 0x1d7c9c0,
     'a8010f84b8010000a82075344889c24883e2dea80475494883f83f0f86860100004883c2c04883fa40400f92c64000f6eb3e'
     '66666666662e0f1f84000000000040b6034889cf31d2488917833c24017433eb41666666662e0f1f8400000000004885c00f'
     '88700100004883c24040b60148c70424010000004c89ff488917833c24017510488b542420f0480fb1130f856cffffff400f'
     'b6c6488d0dbdf763fe486304814801c8ffe0'
    ),
    ('scheduler_b_notify', 0x1d7ca68,
     '488b43204883c010c6442420014889042448895c2408488d4424204889442410488d35698b9d034889e7e8b9fc1e0348c7c0'
     'c0fffffff0480fc1034883f83f0f86050100004883e0c04883f84075794889dfe85196fbffeb6f'
    ),
    ('scheduler_b_completion', 0x1d7cac1,
     '4c8d7320c70424020000004889e64c89f7e879f7290031c0488b4b2848894c242848894424304889542438c7442420010000'
     '00488d7424204c89f7e84ff72900eb2531c031c948894c240848894424104889542418c70424010000004889e64c89f7e828'
     'f729004889dfe8b09f03004883c4505b415e415fc3c70424020000004889e64c89f7e804f72900eb89'
    ),
    ('scheduler_b_assertions', 0x1d7cb4e,
     '488d3d473da5fe488d15047e9d03be24000000ff15a1159f03488d3d683ea5fe488d15c37e9d03be26000000ff1588159f03'
     '488d3df23ca5fe488d15ba7d9d03be23000000ff156f159f03488d3d5c3ea5fe488d15a97e9d03be2f000000ff1556159f03'
     '488d3df63da5fe488d15607e9d03be27000000ff153d159f03'
    ),
    ('scheduler_a_admission', 0x1d8e950,
     '4889c14883e1f848ffc189c2c0ea0580e201f0480fb10b742ba8040f8407020000a80374db4883f83f0f8612020000488d48'
     'c04883f9400f92c280ca02f0480fb10b75d50fb6c2488d0d2ee162fe486304814801c8ffe0'
    ),
    ('scheduler_a_poll', 0x1d8e9a7,
     '488b057afd9d03488944244048895c24484c8d7320488d442440488944240848c744241000000000488904244989e74c89f7'
     '4c89fee81f52280084c00f843e010000'
    ),
    ('scheduler_a_requeue', 0x1d8ea00,
     'a8010f84a2010000a82075344889c24883e2dea80475494883f83f0f86700100004883c2c04883fa40400f92c64000f6eb3e'
     '66666666662e0f1f84000000000040b6034889cf31d2488917837c2420017434eb416666662e0f1f8400000000004885c00f'
     '885a0100004883c24040b60148c7442420010000004c89ff488917837c242001750f488b1424f0480fb1130f856bffffff40'
     '0fb6c6488d0d3ce062fe486304814801c8ffe0'
    ),
    ('scheduler_a_notify', 0x1d8eaa9,
     '488d15d05f9c034c89f74889dee8b5dd1d0348c7c0c0fffffff0480fc1034883f83f0f860b0100004883e0c04883f840757c'
     '4889dfe8dd6cfaffeb72'
    ),
    ('scheduler_a_completion', 0x1d8eae5,
     '4c8d7320c744242002000000488d7424204c89f7e852d7280031c0488b4b2848894c240848894424104889542418c7042401'
     '0000004889e64c89f7e82bd72800eb2831c031c948894c242848894424304889542438c744242001000000488d7424204c89'
     'f7e801d728004889dfe829a102004883c4505b415e415fc3c744242002000000488d7424204c89f7e8dad62800eb86'
    ),
    ('scheduler_a_assertions', 0x1d8eb78,
     '488d3d1d1da4fe488d15da5d9c03be24000000ff1577f59d03488d3d3e1ea4fe488d15995e9c03be26000000ff155ef59d03'
     '488d3dc81ca4fe488d15905d9c03be23000000ff1545f59d03488d3d321ea4fe488d157f5e9c03be2f000000ff152cf59d03'
     '488d3dcc1da4fe488d15365e9c03be27000000ff1513f59d03'
    ),
    ('poll_bridge_entry', 0x2013c0b,
     '837f100075344989fe4883c7184d8b6e0849c7c4d8eeffff64488b1c25000000004c01e364410fb644244883f801744983f8'
     '02751e4531ffeb4b488d3d860c3bfe488d159d316803be75000000ff153aa47503'
    ),
    ('poll_bridge_call', 0x2013c5e,
     '488d05cb2ef6024989ff4889df4889f54889c6ff1569b575034c89ff4889ee6441c644244801644d8b7c2430644d896c2430'
     '4c893c24e807ac2900'
    ),
    ('poll_bridge_branch', 0x2013c99,
     '64410fb654244883fa01742bb10183fa02750984c0742ce98d00000089c5488d35722ef6024889dfff1519b575036441c644'
     '24480189e8644d897c243031c984c075664d8d7e1089c584c97512498b4608644d8b742430644989442430eb034531f64c89'
     '34244c89ffe80900f9ff'
    ),
    ('poll_bridge_done', 0x2013d07,
     '41c7070200000064410fb64c244883f90189e8742083f902742189c5488d35062ef6024889dfff15adb475036441c6442448'
     '0189e8644d897424304883c4085b415c415d415e415f5dc3'
    ),
    ('poll_bridge_unwind', 0x2013d51,
     '4889c341c707020000004889e7ff159cba7503eb12ff15bca375034889c34889e7ff1588ba75034889dfe890c36403ff15a2'
     'a37503'
    ),
    ('replace_drop_and_copy', 0x201c2b1,
     '4c892c244983c7104c89ffe84f7af8ff410f1006410f104e10410f114f10410f1107'
    ),
    ('replace_unwind', 0x201c310,
     '4889c34c89f7e8f579f8ffeb1e4889c3410f1006410f104e10410f114f10410f11074889e7ff15c53475034889dfe8cd3d64'
     '03ff15df1d7503'
    ),
    ('drop_tag_switch', 0x1fa3d15,
     '8b0785c0745b83f801755048837f08007449488b5f104885db74404c8b7f18498b074885c074054889dfffd0498b77084885'
     'f67426498b4710f3480fbcc831d24839f00f47d14883f8110f43d14889df5b415e415fff25a0a27c035b415e415fc3488b5f'
     '084889dfe8ce240200be686300004889df31d25b415e415fff2579a27c03'
    ),
    ('read_output_take', 0x1d589cd,
     '4889f34989fe488d7750ff15335da10384c07456410f104630410f104e400f294c24300f2944242041c7463002000000837c'
     '2420010f858f000000498b46484889442410410f1046380f290424803b00742648c703000000000f2804240f114308488b44'
     '2410488943184883c4405b415c415d415e415fc3'
    ),
    ('read_output_previous_and_panic', 0x1d58a45,
     '48837b080074d34c8b73104d85f674ca4c8b6b18498b45004885c074094c8d63084c89f7ffd0498b75084885f674ab498b45'
     '10f3480fbcc831d24839f00f47d14883f8110f43d14c89f7ff157b55a103eb88488d3dce4766fe488d159b5f9303be450000'
     '00ff15e855a1030f0b'
    ),
    ('finalizer_b_state', 0x1db6aec,
     '488b07904889c14883f103f0480fb10b75f2a8010f842a010000a8020f853b010000a8087518488d7b20c744244002000000'
     '488d742440e828572600eb60a810745c488b43604885c00f8487010000488b7b68ff5010488b0366662e0f1f840000000000'
     '4889c14883e1eff0480fb10b75f2a8020f8477010000a8100f8484010000a8087518488b43604885c07407488b7b68ff5018'
     '48c7436000000000'
    ),
    ('finalizer_a_state', 0x1db8c8c,
     '488b07904889c14883f103f0480fb10b75f2a8010f8427010000a8020f8538010000a8087518488d7b20c744244002000000'
     '488d742440e888352600eb60a810745c488b43604885c00f8484010000488b7b68ff5010488b0366662e0f1f840000000000'
     '4889c14883e1eff0480fb10b75f2a8020f8474010000a8100f8481010000a8087518488b43604885c07407488b7b68ff5018'
     '48c7436000000000'
    ),
]

WINDOWS += [
    ('driver_entry_and_guard', 0x2893110,
     '554157415641554154534881ec58020000488d9c24780100004889dfbe01000000e87a856d0266c784244d02000001014889'
     'e74889deff15cccced02833c24020f8499000000'
    ),
    ('driver_initial_failure', 0x28931ef,
     '488b4424084889842480000000488d3d8c19b6fd488d0dee1de3024c8d05f734e302488d942480000000be1b000000ff1524'
     'aeed02e92d090000'
    ),
    ('driver_direct_parent', 0x2893460,
     '4883f8ff0f847e04000048ffc0644889451848893c244c894424084889442410894c24188954241cc684241801000000488d'
     'bc24f0000000488db42410010000e84b87beff84c00f858f0400004889e7e84bbafaffe9c3050000'
    ),
    ('driver_outer_parent', 0x2893815,
     '4889042448894c240848c744243000000000c6442438004889e048898424100100004c89e74c89ee488d9424e8000000e8d6'
     '87beff3c027449a80175214889e741ffd7488b4424204885c00f847affffff488b7c2428ff5018e96dffffff4889e7ff15b4'
     'c5ed02488b4424204885c00f84c2010000488b7c2428ff5018e9b5010000488d3dd411b6fd488d0d1317e3024c8d05a425e3'
     '02488d9424f0000000be1b000000ff1589a7ed02e992020000'
    ),
    ('driver_local_parent', 0x28939dc,
     '488d9424f80000004883c3284889e64889dfe88d20ffff4989c648837c2410000f85f600000089d348c7442410ffffffff48'
     '8b7c24184885ff740fe844cdfaff488b44241048ffc0eb0231c04c8974241848894424104889e7ff1515c4ed024889e7e87d'
     '92fafff6c3010f84bb000000'
    ),
    ('outer_drive_poll', 0x247c103,
     '448874240e44887c240f488d7c24284c89e6e86663bbff4189c54180fe02740f640fb6454883f801743383f802750b4180fd'
     '027438e988000000'
    ),
    ('outer_drive_result', 0x247c160,
     '64448875446444887d454180fd02755564803c25f0fbffff014889d87511488b384883c710e8a631af02e931ffffff4889df'
     '31f6e827a8af024885c075e0488d3dba4c35fe488d0dd4922d034c8d0505932d03488d54240ebe2b000000ff15851e2f030f'
     '0b'
    ),
    ('local_drive_poll', 0x2885b97,
     '40886c241044887c2411488b7c2428488d742448e8702da3ff4189c54080fd02743664410fb644244883f801741e83f80274'
     '25488b7c2408488d355a0f6f02ff150496ee026441c6442448016441886c24446445887c2445'
    ),
    ('local_drive_result', 0x2885bef,
     '49837e08000f850102000049c74608ffffffff498b6e1049c74610000000004885ed0f842c02000049c74608000000004584'
     'ed0f84cf010000498b16448b7a70'
    ),
]

WINDOWS += [
    ('future_cleanup_full_fde', 0x22569c0,
     '4156534883ec280fb6871602000083c0fd83f80a0f87470300004889fb488d0dacf117fe486304814801c8ffe00fb6833602'
     '000083f8040f842c03000083f8030f85cd020000488dbb48020000e81ec5feffe9bc020000488dbbb0020000e82d260000e9'
     'c2000000488dbb18020000e81c260000e9e0010000488dbbc8020000e80b2600000f57c00f294424100f2904240f28442410'
     '0f1183400200000f2804240f1183300200000f1005e157fbfd0f1183400200000f1005c357fbfd0f118330020000e9c30000'
     '00488dbbb0020000e8bb250000eb53488dbbf8210000e87d240000488dbb30020000e8f16afeffe9980000000fb683360200'
     '0083f8040f848402000083f8030f8506020000488dbb48020000e857c4feffe9f5010000488dbbb0020000e8662500000f57'
     'c00f294424100f2904240f284424100f1183280200000f2804240f1183180200000f10053c57fbfd0f1183280200000f1005'
     '1e57fbfd0f118318020000e9a501000080bbc802000003751580bbc002000003750c488dbb48020000e80471ffff488bb318'
     '0200004885f60f8477010000488bbb20020000e963010000488dbb60030000e8dc2400000f57c00f294424100f2904240f28'
     '4c24100f118bd80200000f280c240f118bc80200000f100db256fbfd0f118bd80200000f10159456fbfd0f1193c80200000f'
     '294424100f2904240f284424100f1183400200000f2804240f1183300200000f118b400200000f119330020000e9ed000000'
     '488dbb30220000e82e230000488bb3182200004885f6740f488bbb2022000031d2ff1503745103488dbb50020000e88769fe'
     'ff0f57c00f294424100f2904240f284424100f1183600100000f2804240f1183500100000f10050d56fbfd0f118360010000'
     '0f1005ef55fbfd0f11835001000080bb06020000007420488bb3380200004889f048f7d87011730f488bbb4002000031d2ff'
     '158f735103c683060200000080bb07020000007420488bb3200200004889f048f7d87011730f488bbb2802000031d2ff155f'
     '735103c6830702000000488bb3380100004885f6740f488bbb4001000031d2ff153d735103c783100200000000000048c783'
     '080200000000000080bb05020000007420488bb3a80000004889f048f7d87011730f488bbbb000000031d2ff15ff725103c6'
     '83050200000066c7831402000000004883c4285b415ec30fb6837002000083f804743983f8037599488dbb78020000e80af0'
     'ffffeb8b0fb6837002000083f804745283f8030f8576ffffff488dbb78020000e8e7efffffe965ffffff80bb18030000030f'
     '8558ffffff80bb10030000030f854bffffff80bb08030000030f853effffff488dbb90020000e8af6effffe92dffffff80bb'
     '18030000030f8520ffffff80bb10030000030f8513ffffff80bb08030000030f8506ffffff488dbb90020000e8776effffe9'
     'f5feffff4989c6e91e010000eb004989c6e937020000e92b0100004989c6e9070100004989c6488bb3182200004885f6740f'
     '488bbb2022000031d2ff15f5715103488dbb50020000e87967feffe9f70000004989c60f57c00f294424100f2904240f284c'
     '24100f118bd80200000f280c240f118bc80200000f100df753fbfd0f118bd80200000f1015d953fbfd0f1193c80200000f29'
     '4424100f2904240f284424100f1183400200000f2804240f1183300200000f118b400200000f119330020000e986010000e9'
     '3f0100004989c6488dbb30020000e8eb66feffeb4dff156b725103e9230100004989c60f57c00f294424100f2904240f2844'
     '24100f1183400200000f2804240f1183300200000f10056153fbfd0f1183400200000f10054353fbfd0f118330020000488b'
     'b3180200004885f60f8413010000488bbb20020000e9bb0000004989c60f57c00f294424100f2904240f284424100f118360'
     '0100000f2804240f1183500100000f10050353fbfd0f1183600100000f1005e552fbfd0f11835001000080bb060200000074'
     '23488bb338020000488d0475000000004885c0740f488bbb4002000031d2ff1582705103c683060200000080bb0702000000'
     '7423488bb320020000488d0475000000004885c0740f488bbb2802000031d2ff154f705103c6830702000000488bb3380100'
     '004885f67453488bbb4001000031d2ff152d705103eb424989c60f57c00f294424100f2904240f284424100f118328020000'
     '0f2804240f1183180200000f10053e52fbfd0f1183280200000f10052052fbfd0f118318020000c783100200000000000048'
     'c783080200000000000080bb05020000007423488bb3a8000000488d0475000000004885c0740f488bbbb000000031d2ff15'
     'a86f5103c683050200000066c7831402000000004c89f7e890904003'
    ),
]
WINDOWS += [('spawn_unwind_drop', 0x229ee60, 'ff15c2f24c034989c6488d7c2410e84d7bfbff4c89f7e895123c03')]

WINDOWS += [
    ('poll_cleanup_full_fde', 0x1fc6250,
     '4156534883ec280fb6871602000083c0fd83f80a0f87470300004889fb488d0dc8d43ffe486304814801c8ffe00fb6833602'
     '000083f8040f842c03000083f8030f85cd020000488dbb48020000e82eeffdffe9bc020000488dbbb0020000e8cd3b0000e9'
     'c2000000488dbb18020000e8bc3b0000e9e0010000488dbbc8020000e8ab3b00000f57c00f294424100f2904240f28442410'
     '0f1183400200000f2804240f1183300200000f1005515f24fe0f1183400200000f1005335f24fe0f118330020000e9c30000'
     '00488dbbb0020000e85b3b0000eb53488dbbf8210000e81d3a0000488dbb30020000e8618dfdffe9980000000fb683360200'
     '0083f8040f848402000083f8030f8506020000488dbb48020000e867eefdffe9f5010000488dbbb0020000e8063b00000f57'
     'c00f294424100f2904240f284424100f1183280200000f2804240f1183180200000f1005ac5e24fe0f1183280200000f1005'
     '8e5e24fe0f118318020000e9a501000080bbc802000003751580bbc002000003750c488dbb48020000e834fdfeff488bb318'
     '0200004885f60f8477010000488bbb20020000e963010000488dbb60030000e87c3a00000f57c00f294424100f2904240f28'
     '4c24100f118bd80200000f280c240f118bc80200000f100d225e24fe0f118bd80200000f1015045e24fe0f1193c80200000f'
     '294424100f2904240f284424100f1183400200000f2804240f1183300200000f118b400200000f119330020000e9ed000000'
     '488dbb30220000e8ce380000488bb3182200004885f6740f488bbb2022000031d2ff15737b7a03488dbb50020000e8f78bfd'
     'ff0f57c00f294424100f2904240f284424100f1183600100000f2804240f1183500100000f10057d5d24fe0f118360010000'
     '0f10055f5d24fe0f11835001000080bb06020000007420488bb3380200004889f048f7d87011730f488bbb4002000031d2ff'
     '15ff7a7a03c683060200000080bb07020000007420488bb3200200004889f048f7d87011730f488bbb2802000031d2ff15cf'
     '7a7a03c6830702000000488bb3380100004885f6740f488bbb4001000031d2ff15ad7a7a03c783100200000000000048c783'
     '080200000000000080bb05020000007420488bb3a80000004889f048f7d87011730f488bbbb000000031d2ff156f7a7a03c6'
     '83050200000066c7831402000000004883c4285b415ec30fb6837002000083f804743983f8037599488dbb78020000e83ad2'
     'ffffeb8b0fb6837002000083f804745283f8030f8576ffffff488dbb78020000e817d2ffffe965ffffff80bb18030000030f'
     '8558ffffff80bb10030000030f854bffffff80bb08030000030f853effffff488dbb90020000e8dffafeffe92dffffff80bb'
     '18030000030f8520ffffff80bb10030000030f8513ffffff80bb08030000030f8506ffffff488dbb90020000e8a7fafeffe9'
     'f5feffff4989c6e91e010000eb004989c6e937020000e92b0100004989c6e9070100004989c6488bb3182200004885f6740f'
     '488bbb2022000031d2ff1565797a03488dbb50020000e8e989fdffe9f70000004989c60f57c00f294424100f2904240f284c'
     '24100f118bd80200000f280c240f118bc80200000f100d675b24fe0f118bd80200000f1015495b24fe0f1193c80200000f29'
     '4424100f2904240f284424100f1183400200000f2804240f1183300200000f118b400200000f119330020000e986010000e9'
     '3f0100004989c6488dbb30020000e85b89fdffeb4dff15db797a03e9230100004989c60f57c00f294424100f2904240f2844'
     '24100f1183400200000f2804240f1183300200000f1005d15a24fe0f1183400200000f1005b35a24fe0f118330020000488b'
     'b3180200004885f60f8413010000488bbb20020000e9bb0000004989c60f57c00f294424100f2904240f284424100f118360'
     '0100000f2804240f1183500100000f1005735a24fe0f1183600100000f1005555a24fe0f11835001000080bb060200000074'
     '23488bb338020000488d0475000000004885c0740f488bbb4002000031d2ff15f2777a03c683060200000080bb0702000000'
     '7423488bb320020000488d0475000000004885c0740f488bbb2802000031d2ff15bf777a03c6830702000000488bb3380100'
     '004885f67453488bbb4001000031d2ff159d777a03eb424989c60f57c00f294424100f2904240f284424100f118328020000'
     '0f2804240f1183180200000f1005ae5924fe0f1183280200000f1005905924fe0f118318020000c783100200000000000048'
     'c783080200000000000080bb05020000007423488bb3a8000000488d0475000000004885c0740f488bbbb000000031d2ff15'
     '18777a03c683050200000066c7831402000000004c89f7e800986903'
    ),
]

# Expected target addresses are cross-checks, not substitutes for displacement
# decoding. The Location-bearing target and previously catalogued await helper
# are boundary references; their bodies are not part of this packet.
EDGES = [
    ('poll_cleanup_nested_first_3', 0x1fc629d, 0xe8, 0x1fa51d0),
    ('poll_cleanup_stage7_object', 0x1fc62ae, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage12_object', 0x1fc62bf, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage5_object', 0x1fc62d0, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage6_object', 0x1fc6320, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage10_first', 0x1fc632e, 0xe8, 0x1fc9d50),
    ('poll_cleanup_stage10_second', 0x1fc633a, 0xe8, 0x1f9f0a0),
    ('poll_cleanup_nested_second_3', 0x1fc6364, 0xe8, 0x1fa51d0),
    ('poll_cleanup_stage8_object', 0x1fc6375, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage9_nested', 0x1fc63d7, 0xe8, 0x1fb6110),
    ('poll_cleanup_stage13_object', 0x1fc63ff, 0xe8, 0x1fc9e80),
    ('poll_cleanup_stage11_first', 0x1fc647d, 0xe8, 0x1fc9d50),
    ('poll_cleanup_stage11_second', 0x1fc64a4, 0xe8, 0x1f9f0a0),
    ('poll_cleanup_nested_first_4_3', 0x1fc65d1, 0xe8, 0x1fc3810),
    ('poll_cleanup_nested_second_4_3', 0x1fc65f4, 0xe8, 0x1fc3810),
    ('poll_cleanup_nested_first_4_4', 0x1fc662c, 0xe8, 0x1fb6110),
    ('poll_cleanup_nested_second_4_4', 0x1fc6664, 0xe8, 0x1fb6110),
    ('spawn_tls_to_future_cleanup', 0x229ed07, 0xe8, 0x22569c0),
    ('spawn_runtime_to_future_cleanup', 0x229edef, 0xe8, 0x22569c0),
    ('spawn_unwind_to_future_cleanup', 0x229ee6e, 0xe8, 0x22569c0),
    ('spawn_unwind_to_resume_boundary', 0x229ee76, 0xe8, 0x5660110),
    ('cleanup_nested_first_3', 0x2256a0d, 0xe8, 0x2242f30),
    ('cleanup_stage7_object', 0x2256a1e, 0xe8, 0x2259050),
    ('cleanup_stage12_object', 0x2256a2f, 0xe8, 0x2259050),
    ('cleanup_stage5_object', 0x2256a40, 0xe8, 0x2259050),
    ('cleanup_stage6_object', 0x2256a90, 0xe8, 0x2259050),
    ('cleanup_stage10_first', 0x2256a9e, 0xe8, 0x2258f20),
    ('cleanup_stage10_second', 0x2256aaa, 0xe8, 0x223d5a0),
    ('cleanup_nested_second_3', 0x2256ad4, 0xe8, 0x2242f30),
    ('cleanup_stage8_object', 0x2256ae5, 0xe8, 0x2259050),
    ('cleanup_stage9_nested', 0x2256b47, 0xe8, 0x224dc50),
    ('cleanup_stage13_object', 0x2256b6f, 0xe8, 0x2259050),
    ('cleanup_stage11_first', 0x2256bed, 0xe8, 0x2258f20),
    ('cleanup_stage11_second', 0x2256c14, 0xe8, 0x223d5a0),
    ('cleanup_nested_first_4_3', 0x2256d41, 0xe8, 0x2255d50),
    ('cleanup_nested_second_4_3', 0x2256d64, 0xe8, 0x2255d50),
    ('cleanup_nested_first_4_4', 0x2256d9c, 0xe8, 0x224dc50),
    ('cleanup_nested_second_4_4', 0x2256dd4, 0xe8, 0x224dc50),
    ('driver_to_tls_parent', 0x28934a0, 0xe8, 0x247bbf0),
    ('driver_to_outer_driver', 0x2893845, 0xe8, 0x247c020),
    ('outer_driver_to_outer_parent', 0x247c115, 0xe8, 0x2032480),
    ('driver_to_local_driver', 0x28939ee, 0xe8, 0x2885a80),
    ('local_driver_to_local_parent', 0x2885bab, 0xe8, 0x22b8920),
    ('outer_parent_to_spawn', 0x2032528, 0xe8, 0x229ec10),
    ('local_parent_to_spawn', 0x22b89b3, 0xe8, 0x229ec10),
    ('tls_parent_to_spawn', 0x247bd67, 0xe8, 0x229ec10),
    ('local_parent_to_previous_await_boundary', 0x22b89c6, 0xe8, 0x2046b70),
    ('spawn_to_queue_b', 0x229edb4, 0xe8, 0x23c3c70),
    ('spawn_to_queue_a', 0x229edc1, 0xe8, 0x2888350),
    ('queue_a_to_allocate_a', 0x2888384, 0xe8, 0x2003d20),
    ('queue_b_to_allocate_b', 0x23c3ca0, 0xe8, 0x200b3a0),
    ('poll_stub_a_to_scheduler_a', 0x22a4460, 0xe9, 0x1d8e930),
    ('poll_stub_b_to_scheduler_b', 0x22a3d20, 0xe9, 0x1d7c8f0),
    ('scheduler_a_to_poll_bridge', 0x1d8e9dc, 0xe8, 0x2013c00),
    ('scheduler_b_to_poll_bridge', 0x1d7c99f, 0xe8, 0x2013c00),
    ('poll_bridge_to_previous_state_location_boundary', 0x2013c94, 0xe8, 0x22ae8a0),
    ('poll_bridge_to_drop', 0x2013d02, 0xe8, 0x1fa3d10),
    ('scheduler_a_ready_to_replace', 0x1d8eb4a, 0xe8, 0x201c250),
    ('scheduler_b_ready_to_replace', 0x1d7cb23, 0xe8, 0x201c250),
    ('scheduler_a_cancel_to_replace', 0x1d8eaf9, 0xe8, 0x201c250),
    ('scheduler_b_cancel_to_replace', 0x1d7cad2, 0xe8, 0x201c250),
    ('finalizer_a_to_replace', 0x1db8cc3, 0xe8, 0x201c250),
    ('finalizer_b_to_replace', 0x1db6b23, 0xe8, 0x201c250),
    ('replace_to_drop', 0x201c2bc, 0xe8, 0x1fa3d10),
    ('read_stub_a_to_reader', 0x229f710, 0xe9, 0x1d589c0),
    ('read_stub_b_to_reader', 0x229f990, 0xe9, 0x1d589c0),
    ('drop_box_to_poll_cleanup', 0x1fa3d7d, 0xe8, 0x1fc6250),
]

# Conditions describe the comparison whose bytes are in the corresponding
# fixed window. The destinations themselves are decoded from branch operands.
BRANCHES = [
    ('cleanup_stage_outside_3_to_13', 0x22569d4, 0x2256d21),
    ('cleanup_nested_first_four', 0x22569f7, 0x2256d29),
    ('cleanup_nested_first_not_three', 0x2256a00, 0x2256cd3),
    ('cleanup_nested_second_four', 0x2256abe, 0x2256d48),
    ('cleanup_nested_second_not_three', 0x2256ac7, 0x2256cd3),
    ('cleanup_stage9_first_not_three', 0x2256b35, 0x2256b4c),
    ('cleanup_stage9_second_not_three', 0x2256b3e, 0x2256b4c),
    ('cleanup_word_218_zero', 0x2256b56, 0x2256cd3),
    ('cleanup_word_2218_zero', 0x2256bfc, 0x2256c0d),
    ('cleanup_flag_206_zero', 0x2256c5f, 0x2256c81),
    ('cleanup_word_238_min_signed', 0x2256c6e, 0x2256c81),
    ('cleanup_word_238_zero', 0x2256c70, 0x2256c81),
    ('cleanup_flag_207_zero', 0x2256c8f, 0x2256cb1),
    ('cleanup_word_220_min_signed', 0x2256c9e, 0x2256cb1),
    ('cleanup_word_220_zero', 0x2256ca0, 0x2256cb1),
    ('cleanup_word_138_zero', 0x2256cc2, 0x2256cd3),
    ('cleanup_flag_205_zero', 0x2256cef, 0x2256d11),
    ('cleanup_word_a8_min_signed', 0x2256cfe, 0x2256d11),
    ('cleanup_word_a8_zero', 0x2256d00, 0x2256d11),
    ('cleanup_nested_first_second_four', 0x2256d33, 0x2256d6e),
    ('cleanup_nested_first_second_not_three', 0x2256d38, 0x2256cd3),
    ('cleanup_nested_second_second_four', 0x2256d52, 0x2256da6),
    ('cleanup_nested_second_second_not_three', 0x2256d57, 0x2256cd3),
    ('cleanup_nested_first_318_not_three', 0x2256d75, 0x2256cd3),
    ('cleanup_nested_first_310_not_three', 0x2256d82, 0x2256cd3),
    ('cleanup_nested_first_308_not_three', 0x2256d8f, 0x2256cd3),
    ('cleanup_nested_second_318_not_three', 0x2256dad, 0x2256cd3),
    ('cleanup_nested_second_310_not_three', 0x2256dba, 0x2256cd3),
    ('cleanup_nested_second_308_not_three', 0x2256dc7, 0x2256cd3),
    ('driver_setup_tag_two', 0x2893150, 0x28931ef),
    ('driver_tls_counter_max', 0x2893464, 0x28938e8),
    ('driver_tls_parent_nonzero', 0x28934a7, 0x289393c),
    ('driver_outer_result_two', 0x289384c, 0x2893897),
    ('driver_outer_low_bit_set', 0x2893850, 0x2893873),
    ('driver_local_word_nonzero', 0x28939fc, 0x2893af8),
    ('outer_driver_result_two', 0x247c136, 0x247c170),
    ('local_driver_word_nonzero', 0x2885bf4, 0x2885dfb),
    ('local_driver_pointer_null', 0x2885c11, 0x2885e43),
    ('local_driver_poll_result_zero', 0x2885c22, 0x2885df7),
    ('parent_output_byte_zero', 0x22b89d3, 0x22b89d9),
    ('parent_old_task_word_equal', 0x22b89f9, 0x22b8a02),
    ('parent_result_word_nonzero', 0x22b8a07, 0x22b8a1a),
    ('spawn_allocation_null', 0x229eca2, 0x229ed4f),
    ('spawn_tls_byte_one', 0x229ecfd, 0x229ed7e),
    ('spawn_tls_byte_not_two', 0x229ed02, 0x229ed64),
    ('spawn_tls_counter_at_least_max_signed', 0x229ed90, 0x229eddd),
    ('spawn_runtime_word_two', 0x229eda4, 0x229edec),
    ('spawn_runtime_low_bit_zero', 0x229edac, 0x229edbb),
    ('allocate_a_reference_null', 0x2003d40, 0x2003d53),
    ('allocate_a_reference_overflow', 0x2003d46, 0x2003e11),
    ('allocate_a_null', 0x2003db2, 0x2003e01),
    ('allocate_b_reference_null', 0x200b3c0, 0x200b3d3),
    ('allocate_b_reference_overflow', 0x200b3c6, 0x200b491),
    ('allocate_b_null', 0x200b432, 0x200b481),
    ('sched_a_notified_bit_clear', 0x1d8e96b, 0x1d8eb78),
    ('sched_a_low_bits_clear', 0x1d8e973, 0x1d8e950),
    ('sched_a_refcount_below_threshold', 0x1d8e979, 0x1d8eb91),
    ('sched_a_poll_result_zero', 0x1d8e9e3, 0x1d8eb27),
    ('sched_a_running_bit_clear', 0x1d8ea02, 0x1d8ebaa),
    ('sched_a_flag_20_set', 0x1d8ea0a, 0x1d8ea40),
    ('sched_a_sign_bit_set', 0x1d8ea63, 0x1d8ebc3),
    ('sched_b_notified_bit_clear', 0x1d7c92b, 0x1d7cb4e),
    ('sched_b_low_bits_clear', 0x1d7c933, 0x1d7c910),
    ('sched_b_refcount_below_threshold', 0x1d7c939, 0x1d7cb67),
    ('sched_b_poll_result_zero', 0x1d7c9a6, 0x1d7cb03),
    ('sched_b_running_bit_clear', 0x1d7c9c2, 0x1d7cb80),
    ('sched_b_flag_20_set', 0x1d7c9ca, 0x1d7ca00),
    ('sched_b_sign_bit_set', 0x1d7ca23, 0x1d7cb99),
    ('poll_stage_nonzero', 0x2013c0f, 0x2013c45),
    ('poll_return_zero_tls_two', 0x2013cae, 0x2013cdc),
    ('poll_return_nonzero_tls_one', 0x2013cda, 0x2013d42),
    ('drop_tag_zero', 0x1fa3d19, 0x1fa3d76),
    ('drop_tag_other_than_one', 0x1fa3d1e, 0x1fa3d70),
    ('drop_payload_word_zero', 0x1fa3d25, 0x1fa3d70),
    ('drop_payload_pointer_null', 0x1fa3d2e, 0x1fa3d70),
    ('read_guard_zero', 0x1d589df, 0x1d58a37),
    ('read_tag_not_one', 0x1d58a02, 0x1d58a97),
    ('read_previous_output_tag_zero', 0x1d58a1d, 0x1d58a45),
    ('read_previous_payload_zero', 0x1d58a4a, 0x1d58a1f),
    ('read_previous_pointer_null', 0x1d58a53, 0x1d58a1f),
    ('finish_a_running_bit_clear', 0x1db8ca0, 0x1db8dcd),
    ('finish_a_flag_two_set', 0x1db8ca8, 0x1db8de6),
    ('finish_b_running_bit_clear', 0x1db6b00, 0x1db6c30),
    ('finish_b_flag_two_set', 0x1db6b08, 0x1db6c49),
]

# Identical relative branch positions are checked separately in the poll cleanup copy.
CLEANUP_DELTA = 0x1fc6250 - 0x22569c0
BRANCHES += [('poll_' + label, site + CLEANUP_DELTA, target + CLEANUP_DELTA)
             for label, site, target in BRANCHES if label.startswith('cleanup_')]

# The two cleanup ranges have eleven entries each; the other tables have four selected entries.
# The scheduler computations bound their indices to 0..3. The three parent tables are bounded observations only:
# no check that their incoming byte is <=3 is claimed.
JUMP_TABLES = [
    ('poll_cleanup', 0x1fc626d, 0x3c373c, (0x1fc627d, 0x1fc6344, 0x1fc62c9, 0x1fc6319, 0x1fc62a7, 0x1fc636e, 0x1fc63be, 0x1fc6327, 0x1fc6476, 0x1fc62b8, 0x1fc63f8)),
    ('future_cleanup', 0x22569dd, 0x3d5b90, (0x22569ed, 0x2256ab4, 0x2256a39, 0x2256a89, 0x2256a17, 0x2256ade, 0x2256b2e, 0x2256a97, 0x2256be6, 0x2256a28, 0x2256b68)),
    ('outer_parent', 0x2032504, 0x3c3ae4, (0x2032514, 0x20325dc, 0x20325cf, 0x2032530)),
    ('local_parent', 0x22b898f, 0x3d66f8, (0x22b899f, 0x22b8a5c, 0x22b8a4f, 0x22b89bb)),
    ('tls_parent', 0x247bd43, 0x3e2aac, (0x247bd53, 0x247bf21, 0x247bf30, 0x247bd71)),
    ('scheduler_a_before_poll', 0x1d8e997, 0x3bcacc, (0x1d8e9a7, 0x1d8eae5, 0x1d8eb57, 0x1d8eadb)),
    ('scheduler_a_after_poll', 0x1d8ea99, 0x3bcadc, (0x1d8eb57, 0x1d8eaa9, 0x1d8eadb, 0x1d8eb61)),
    ('scheduler_b_before_poll', 0x1d7c957, 0x3bc20c, (0x1d7c967, 0x1d7cac1, 0x1d7cb30, 0x1d7cab7)),
    ('scheduler_b_after_poll', 0x1d7ca58, 0x3bc21c, (0x1d7cb30, 0x1d7ca68, 0x1d7cab7, 0x1d7cb3a)),
]

# A two-word subset of each relocated table connects polling and reading.
VTABLES = [
    ('a', 0x2003d60, 0x5693650, 0x22a4460, 0x229f710),
    ('b', 0x200b3e0, 0x56954a0, 0x22a3d20, 0x229f990),
]

CLEANUP_FIELDS = [
    ('stage5_word_218', 0x2256b4c, '488bb3', 0),
    ('stage5_arg_220', 0x2256b5c, '488bbb', 0),
    ('stage11_word_2218', 0x2256bf2, '488bb3', 0),
    ('stage11_arg_2220', 0x2256bfe, '488bbb', 0),
    ('guard_flag_206', 0x2256c58, '80bb', 1),
    ('guard_word_238', 0x2256c61, '488bb3', 0),
    ('guard_arg_240', 0x2256c72, '488bbb', 0),
    ('guard_flag_207', 0x2256c88, '80bb', 1),
    ('guard_word_220', 0x2256c91, '488bb3', 0),
    ('guard_arg_228', 0x2256ca2, '488bbb', 0),
    ('guard_word_138', 0x2256cb8, '488bb3', 0),
    ('guard_arg_140', 0x2256cc4, '488bbb', 0),
    ('guard_flag_205', 0x2256ce8, '80bb', 1),
    ('guard_word_a8', 0x2256cf1, '488bb3', 0),
    ('guard_arg_b0', 0x2256d02, '488bbb', 0),
    ('stage_byte', 0x22569c7, '0fb687', 0),
    ('nested_236_first', 0x22569ed, '0fb683', 0),
    ('nested_236_second', 0x2256ab4, '0fb683', 0),
    ('nested_270_first', 0x2256d29, '0fb683', 0),
    ('nested_270_second', 0x2256d48, '0fb683', 0),
    ('stage3_helper_object', 0x2256a06, '488dbb', 0),
    ('stage7_helper_object', 0x2256a17, '488dbb', 0),
    ('stage12_helper_object', 0x2256a28, '488dbb', 0),
    ('stage5_helper_object', 0x2256a39, '488dbb', 0),
    ('stage6_helper_object', 0x2256a89, '488dbb', 0),
    ('stage10_helper_first_object', 0x2256a97, '488dbb', 0),
    ('stage10_helper_second_object', 0x2256aa3, '488dbb', 0),
    ('stage4_helper_object', 0x2256acd, '488dbb', 0),
    ('stage8_helper_object', 0x2256ade, '488dbb', 0),
    ('stage9_guard_first', 0x2256b2e, '80bb', 1),
    ('stage9_guard_second', 0x2256b37, '80bb', 1),
    ('stage9_helper_object', 0x2256b40, '488dbb', 0),
    ('stage13_helper_object', 0x2256b68, '488dbb', 0),
    ('stage11_helper_first_object', 0x2256be6, '488dbb', 0),
    ('stage11_helper_second_object', 0x2256c0d, '488dbb', 0),
    ('nested_first_object_278', 0x2256d3a, '488dbb', 0),
    ('nested_second_object_278', 0x2256d5d, '488dbb', 0),
    ('nested_first_guard_318', 0x2256d6e, '80bb', 1),
    ('nested_first_guard_310', 0x2256d7b, '80bb', 1),
    ('nested_first_guard_308', 0x2256d88, '80bb', 1),
    ('nested_first_object_290', 0x2256d95, '488dbb', 0),
    ('nested_second_guard_318', 0x2256da6, '80bb', 1),
    ('nested_second_guard_310', 0x2256db3, '80bb', 1),
    ('nested_second_guard_308', 0x2256dc0, '80bb', 1),
    ('nested_second_object_290', 0x2256dcd, '488dbb', 0),
    ('clear_flag_206', 0x2256c81, 'c683', 1),
    ('clear_flag_207', 0x2256cb1, 'c683', 1),
    ('clear_word_210', 0x2256cd3, 'c783', 4),
    ('clear_word_208', 0x2256cdd, '48c783', 4),
    ('clear_flag_205', 0x2256d11, 'c683', 1),
    ('clear_word_214', 0x2256d18, '66c783', 2),
    ('stage5_reset_low', 0x2256a7d, '0f1183', 0),
    ('stage5_reset_high', 0x2256a6f, '0f1183', 0),
    ('stage678_reset_low', 0x2256b22, '0f1183', 0),
    ('stage678_reset_high', 0x2256b14, '0f1183', 0),
    ('stage1112_reset_low', 0x2256c51, '0f1183', 0),
    ('stage1112_reset_high', 0x2256c43, '0f1183', 0),
    ('stage13_first_reset_low', 0x2256bac, '0f1193', 0),
    ('stage13_first_reset_high', 0x2256b9e, '0f118b', 0),
    ('stage13_second_reset_low', 0x2256bda, '0f1193', 0),
    ('stage13_second_reset_high', 0x2256bd3, '0f118b', 0),
]

RESET_LOADS = [
    (0x2256a68, 0x20c250), (0x2256a76, 0x20c240),
    (0x2256b0d, 0x20c250), (0x2256b1b, 0x20c240),
    (0x2256b97, 0x20c250), (0x2256ba5, 0x20c240),
    (0x2256c3c, 0x20c250), (0x2256c4a, 0x20c240),
]

LITERALS = [
    ('notified_assertion', 0x1d7cb4e, 0x1d7cb5c),
    ('reference_count_assertion', 0x1d7cb67, 0x1d7cb75),
    ('running_assertion', 0x1d7cb80, 0x1d7cb8e),
    ('signed_bound_assertion', 0x1d7cb99, 0x1d7cba7),
    ('previous_reference_assertion', 0x1d7cbb2, 0x1d7cbc0),
    ('parent_unwrap_literal', 0x22b8a28, 0x22b8a42),
]


def require_identity(data, expected=TARGET_SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('target SHA-256 mismatch')
    return actual


def section_named(secs, name):
    found = [s for s in secs if s['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicate, or fileless section: ' + name)
    return found[0]


def va_offset(data, secs, va, length, executable=False):
    if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
        raise ValueError('invalid address or length')
    matches = [s for s in secs
               if s['type'] != 8 and (s['flags'] & 2) and
               (not executable or s['flags'] & 4) and
               s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address has no unique file-backed allocated section')
    s = matches[0]
    offset = s['offset'] + va - s['address']
    if offset < 0 or offset + length > len(data):
        raise ValueError('file mapping exceeds input')
    return offset, s['name']


def read_va(data, secs, va, length, executable=False):
    offset, _ = va_offset(data, secs, va, length, executable)
    return bytes(data[offset:offset + length])


def selected_frames(secs, header_rows, records):
    names = set(FUNCTIONS.values())
    if len(names) != len(FUNCTIONS):
        raise ValueError('duplicate selected start')
    by_start = {}
    for row in records:
        if row['start'] in names:
            by_start.setdefault(row['start'], []).append(row)
    idx = {}
    for row in header_rows:
        if row['start'] in names:
            idx.setdefault(row['start'], []).append(row)
    out = {}
    for name, start in FUNCTIONS.items():
        if len(by_start.get(start, ())) != 1 or len(idx.get(start, ())) != 1:
            raise ValueError('missing or ambiguous FDE/index entry: ' + name)
        fde = by_start[start][0]
        if idx[start][0]['fde'] != fde['fde'] or fde['end'] <= start:
            raise ValueError('FDE/index disagreement: ' + name)
        matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4 and
                   s['address'] <= start < fde['end'] <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('FDE is not within one executable file-backed section')
        out[name] = fde
    return out


def window_rows(data, secs, frames, windows=WINDOWS):
    rows = []
    for name, start, expected_hex in windows:
        expected = bytes.fromhex(expected_hex)
        if not expected:
            raise ValueError('empty fixed window')
        owners = [n for n, f in frames.items() if f['start'] <= start and start + len(expected) <= f['end']]
        if len(owners) != 1:
            raise ValueError('fixed window lacks a unique selected FDE: ' + name)
        offset, sec = va_offset(data, secs, start, len(expected), executable=True)
        observed = bytes(data[offset:offset + len(expected)])
        if observed != expected:
            raise ValueError('fixed byte pattern mismatch: ' + name)
        rows.append((name, owners[0], hex(start), hex(offset), sec, len(observed), observed.hex()))
    return rows


def checked_rel32(raw, address, opcode, expected):
    if len(raw) != 5 or raw[0] != opcode or opcode not in (0xe8, 0xe9):
        raise ValueError('invalid rel32 transfer')
    displacement = struct.unpack_from('<i', raw, 1)[0]
    dest = address + len(raw) + displacement
    if dest != expected:
        raise ValueError('rel32 transfer target mismatch')
    return displacement, dest


def checked_lea(raw, address, expected):
    if (len(raw) != 7 or not 0x48 <= raw[0] <= 0x4f or raw[1] != 0x8d or
            raw[2] & 0xc7 != 0x05):
        raise ValueError('invalid RIP-relative LEA')
    displacement = struct.unpack_from('<i', raw, 3)[0]
    target = address + len(raw) + displacement
    if target != expected:
        raise ValueError('LEA target mismatch')
    return target


def checked_branch(raw, address, expected):
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        size = 2
        displacement = struct.unpack_from('<b', raw, 1)[0]
        condition = raw[0] & 15
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size = 6
        displacement = struct.unpack_from('<i', raw, 2)[0]
        condition = raw[1] & 15
    else:
        raise ValueError('unsupported conditional branch')
    target = address + size + displacement
    if target != expected:
        raise ValueError('conditional branch target mismatch')
    names = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
             's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')
    return size, names[condition], displacement, target


def relocation_rows(data, secs):
    sec = section_named(secs, '.rela.dyn')
    if sec['type'] != 4 or sec['size'] % 24:
        raise ValueError('unsupported RELA section')
    end = sec['offset'] + sec['size']
    if end > len(data):
        raise ValueError('RELA section exceeds file')
    for off in range(sec['offset'], end, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        yield slot, info & 0xffffffff, info >> 32, addend, off


def select_relocations(rows, expected):
    selected = {slot: [] for slot in expected}
    for row in rows:
        if row[0] in selected:
            selected[row[0]].append(row)
    for slot, target in expected.items():
        if len(selected[slot]) != 1:
            raise ValueError('missing or duplicate selected relocation')
        _, typ, sym, addend, _ = selected[slot][0]
        if (typ, sym, addend) != (8, 0, target):
            raise ValueError('selected relocation differs')
    return selected


def table_targets(raw, base, expected):
    if len(raw) != 4 * len(expected):
        raise ValueError('table byte length mismatch')
    targets = tuple(base + struct.unpack_from('<i', raw, 4 * i)[0]
                    for i in range(len(expected)))
    if targets != tuple(expected):
        raise ValueError('jump table differs')
    return targets


def _imm8(data, secs, va, opcode):
    raw = read_va(data, secs, va, len(opcode) + 1, True)
    if raw[:-1] != opcode:
        raise ValueError('immediate setup differs')
    return raw[-1]


def model_constants(data, secs, variant='b'):
    # Both copies must independently provide the same operands. Every
    # containing instruction range has already passed window_rows in build().
    sites = {
        'a': (0x1d8e969, 0x1d8e971, 0x1d8e975, 0x1d8e97f,
              0x1d8e953, 0x1d8e95c, 0x1d8e95f, 0x1d8ea00,
              0x1d8ea08, 0x1d8ea0f, 0x1d8ea13, 0x1d8ea17, 0x1d8ea69),
        'b': (0x1d7c929, 0x1d7c931, 0x1d7c935, 0x1d7c93f,
              0x1d7c913, 0x1d7c91c, 0x1d7c91f, 0x1d7c9c0,
              0x1d7c9c8, 0x1d7c9cf, 0x1d7c9d3, 0x1d7c9d7, 0x1d7ca29),
    }
    if variant not in sites:
        raise ValueError('unknown scheduler variant')
    (admit, low, limit, sub, mask, shift, index_mask, running,
     wake, post_mask, post_admit, post_limit, post_add) = sites[variant]
    def sign(imm):
        return struct.unpack('<b', bytes([imm]))[0]
    return {
        'admit_bit': _imm8(data, secs, admit, b'\xa8'),
        'low_mask': _imm8(data, secs, low, b'\xa8'),
        'limit': _imm8(data, secs, limit, b'\x48\x83\xf8'),
        'subtract': -sign(_imm8(data, secs, sub, b'\x48\x8d\x48')),
        'admit_mask': sign(_imm8(data, secs, mask, b'\x48\x83\xe1')) & MASK64,
        'admit_shift': _imm8(data, secs, shift, b'\xc0\xea'),
        'admit_index_mask': _imm8(data, secs, index_mask, b'\x80\xe2'),
        'running_bit': _imm8(data, secs, running, b'\xa8'),
        'wake_bit': _imm8(data, secs, wake, b'\xa8'),
        'post_mask': sign(_imm8(data, secs, post_mask, b'\x48\x83\xe2')) & MASK64,
        'post_admit_bit': _imm8(data, secs, post_admit, b'\xa8'),
        'post_limit': _imm8(data, secs, post_limit, b'\x48\x83\xf8'),
        'post_add': _imm8(data, secs, post_add, b'\x48\x83\xc2'),
    }


def model_pre(word, c):
    """One successful CAS attempt, given a supplied raw u64; no execution."""
    if not 0 <= word <= MASK64:
        raise ValueError('word must be u64')
    if not word & c['admit_bit']:
        return 'notified_assertion', None, None
    if not word & c['low_mask']:
        return 'cas', (word & c['admit_mask']) + 1, (word >> c['admit_shift']) & c['admit_index_mask']
    if word <= c['limit']:
        return 'reference_count_assertion', None, None
    new = word - c['subtract']
    return 'cas', new, 2 | int(new < c['subtract'])


def cleanup_release_guard(flag, word):
    """Model the selected cmp/neg/jo/jae guard on synthetic raw values."""
    if not 0 <= flag <= 0xff or not 0 <= word <= MASK64:
        raise ValueError('guard inputs must be u8 and u64')
    carry = word != 0
    overflow = word == 1 << 63
    return bool(flag) and not overflow and carry


def model_post(word, c):
    """Selected nonzero-poll branch, assuming one successful CAS attempt."""
    if not 0 <= word <= MASK64:
        raise ValueError('word must be u64')
    if not word & c['running_bit']:
        return 'running_assertion', None, None
    if word & c['wake_bit']:
        return 'no_cas', None, 3
    new = word & c['post_mask']
    if word & c['post_admit_bit']:
        if word & (1 << 63):
            return 'signed_bound_assertion', None, None
        return 'cas', new + c['post_add'], 1
    if word <= c['post_limit']:
        return 'reference_count_assertion', None, None
    new -= c['subtract']
    return 'cas', new, 2 * int(new < c['post_add'])


def owner_for(site, length, frames):
    hits = [name for name, f in frames.items()
            if f['start'] <= site and site + length <= f['end']]
    if len(hits) != 1:
        raise ValueError('site lacks one selected owner')
    return hits[0]


def is_in_window(site, length):
    return any(start <= site and site + length <= start + len(bytes.fromhex(raw))
               for _, start, raw in WINDOWS)


def selected_candidate_scan(data, secs, frames):
    """Scan every .text byte for selected E8/E9 targets; unaligned hits remain candidates."""
    targets = {0x1fc6250, 0x22569c0, 0x2032480, 0x22b8920, 0x247bbf0, 0x247c020, 0x2885a80,
               0x229ec10, 0x23c3c70, 0x2888350, 0x2003d20, 0x200b3a0,
               0x1d8e930, 0x1d7c8f0, 0x2013c00, 0x22ae8a0}
    sec = section_named(secs, '.text')
    if not sec['flags'] & 4:
        raise ValueError('.text is not executable')
    start, end = sec['offset'], sec['offset'] + sec['size']
    rows = []
    for opcode in (0xe8, 0xe9):
        pos = data.find(bytes([opcode]), start, end)
        while pos >= 0 and pos + 5 <= end:
            site = sec['address'] + pos - start
            target = site + 5 + struct.unpack_from('<i', data, pos + 1)[0]
            if target in targets:
                owners = [name for name, f in frames.items() if f['start'] <= site and site + 5 <= f['end']]
                rows.append((site, opcode, target, owners[0] if len(owners) == 1 else 'not-selected',
                             bytes(data[pos:pos + 5]).hex()))
            pos = data.find(bytes([opcode]), pos + 1, end)
    return sorted(rows)


def layout_rows(data, secs):
    def u32(va):
        return struct.unpack('<I', read_va(data, secs, va, 4, True))[0]

    out = []
    for label, store, lea in (
        ('outer_parent_future_state_offset', 0x2032514, 0x2032523),
        ('local_parent_future_state_offset', 0x22b899f, 0x22b89ae),
        ('tls_parent_future_state_offset', 0x247bd53, 0x247bd5b),
    ):
        raw = read_va(data, secs, store, 8, True)
        lr = read_va(data, secs, lea, 5, True)
        if raw[:3] != b'\xc6\x84\x24' or raw[7] != 0 or lr[:4] != b'\x48\x8d\x7c\x24':
            raise ValueError('unexpected future setup')
        out.append((label, hex(store), hex(struct.unpack_from('<I', raw, 3)[0] - lr[4])))
        out.append((label.replace('_offset', '_value'), hex(store), hex(raw[7])))
    stage_load = read_va(data, secs, 0x22569c7, 7, True)
    if stage_load[:3] != b'\x0f\xb6\x87':
        raise ValueError('unexpected future cleanup selector')
    out.append(('future_cleanup_selector_offset', hex(0x22569c7),
                hex(struct.unpack_from('<I', stage_load, 3)[0])))
    for label, site, op in (
        ('future_copy_bytes', 0x229ec86, 0xba),
        ('future_allocation_bytes', 0x229ec94, 0xbf),
        ('future_heap_copy_bytes', 0x229ecab, 0xba),
        ('future_drop_bytes', 0x1fa3d82, 0xbe),
        ('task_allocation_a_bytes', 0x2003d9f, 0xbf),
        ('task_allocation_b_bytes', 0x200b41f, 0xbf),
    ):
        if read_va(data, secs, site, 1, True) != bytes([op]):
            raise ValueError('unexpected immediate operation')
        out.append((label, hex(site), hex(u32(site + 1))))
    # Variant-specific input offsets are encoded as disp32 operands.
    for label, site in (('allocator_a_source_offset', 0x2003d30),
                        ('allocator_b_source_offset', 0x200b3b0)):
        raw = read_va(data, secs, site, 7, True)
        if raw[:3] != b'\x48\x8b\x86':
            raise ValueError('unexpected source-offset instruction')
        out.append((label, hex(site), hex(struct.unpack_from('<I', raw, 3)[0])))
    # These operands are imm8/displacements in pinned x86 instructions.
    task_offset = _imm8(data, secs, 0x1d7c978, b'\x4c\x8d\x73')
    task_offset_a = _imm8(data, secs, 0x1d8e9b8, b'\x4c\x8d\x73')
    if task_offset != task_offset_a:
        raise ValueError('scheduler object offsets differ')
    tag_offset = _imm8(data, secs, 0x2013c0b, b'\x83\x7f')
    child_offset = _imm8(data, secs, 0x2013c14, b'\x48\x83\xc7')
    table_offset = _imm8(data, secs, 0x2003d67, b'\x48\x89\x44\x24')
    out.extend([
        ('scheduler_inner_object_offset_a', hex(0x1d8e9b8), hex(task_offset_a)),
        ('scheduler_inner_object_offset_b', hex(0x1d7c978), hex(task_offset)),
        ('task_stage_tag_offset', hex(0x2013c0b), hex(task_offset + tag_offset)),
        ('task_future_pointer_offset', hex(0x2013c14), hex(task_offset + child_offset)),
        ('task_table_pointer_offset', hex(0x2003d67), hex(table_offset)),
    ])
    return out


def build(data):
    digest = require_identity(data)
    secs, hdr = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    frames = selected_frames(secs, hdr, fdes)
    windows = window_rows(data, secs, frames)

    functions = []
    for name, start in sorted(FUNCTIONS.items(), key=lambda x: x[1]):
        f = frames[name]
        offset, sec = va_offset(data, secs, start, f['end'] - start, True)
        body = data[offset:offset + f['end'] - start]
        functions.append((name, hex(start), hex(f['end']), hex(offset), sec,
                          hex(f['fde']), hex(f['cie']), len(body), hashlib.sha256(body).hexdigest()))

    edges = []
    for name, site, op, expected in EDGES:
        raw = read_va(data, secs, site, 5, True)
        if not is_in_window(site, len(raw)):
            raise ValueError('transfer not in a pinned window')
        disp, target = checked_rel32(raw, site, op, expected)
        edges.append((name, owner_for(site, 5, frames), hex(site), hex(va_offset(data, secs, site, 5, True)[0]),
                      raw.hex(), disp, hex(target)))

    branches = []
    for name, site, expected in BRANCHES:
        raw = read_va(data, secs, site, 6, True)
        size, cc, disp, target = checked_branch(raw, site, expected)
        if not is_in_window(site, size):
            raise ValueError('branch not in a pinned window: ' + name)
        owner = owner_for(site, size, frames)
        if not frames[owner]['start'] <= target < frames[owner]['end']:
            raise ValueError('selected branch leaves its owner')
        branches.append((name, owner, hex(site), raw[:size].hex(), cc, disp, hex(target), hex(site + size)))

    table_rows = []
    table_lookup = {}
    for owner, lea, table, expected in JUMP_TABLES:
        raw_lea = read_va(data, secs, lea, 7, True)
        frame_owner = owner.removesuffix('_before_poll').removesuffix('_after_poll')
        if owner_for(lea, 7, frames) != frame_owner or not is_in_window(lea, 7):
            raise ValueError('jump-table LEA not in pinned owner: ' + owner)
        checked_lea(raw_lea, lea, table)
        raw_table = read_va(data, secs, table, 4 * len(expected))
        targets = table_targets(raw_table, table, expected)
        table_lookup[owner] = targets
        for index, target in enumerate(targets):
            if not frames[frame_owner]['start'] <= target < frames[frame_owner]['end']:
                raise ValueError('selected table target escapes its owner')
            table_rows.append((owner, hex(lea), raw_lea.hex(), hex(table), index,
                               raw_table[4 * index:4 * index + 4].hex(), hex(target)))

    relocation_expected = {}
    for label, lea, table, poll, reader in VTABLES:
        if not is_in_window(lea, 7):
            raise ValueError('table setup not pinned')
        checked_lea(read_va(data, secs, lea, 7, True), lea, table)
        relocation_expected[table] = poll
        relocation_expected[table + 24] = reader
    selected = select_relocations(relocation_rows(data, secs), relocation_expected)
    relocations = []
    for label, lea, table, poll, reader in VTABLES:
        for index, slot in ((0, table), (3, table + 24)):
            slot_bytes = read_va(data, secs, slot, 8)
            if slot_bytes != b'\0' * 8:
                raise ValueError('nonzero pre-relocation table slot')
            _, typ, sym, addend, off = selected[slot][0]
            relocations.append((label, hex(lea), hex(table), index, hex(slot), slot_bytes.hex(),
                                hex(off), typ, sym, hex(addend)))

    cleanup_fields = []
    reset_values = []
    for variant, delta in (('spawn', 0), ('poll', CLEANUP_DELTA)):
        for label, original_site, prefix_hex, immediate_size in CLEANUP_FIELDS:
            site = original_site + delta
            prefix = bytes.fromhex(prefix_hex)
            size = len(prefix) + 4 + immediate_size
            raw = read_va(data, secs, site, size, True)
            if raw[:len(prefix)] != prefix or not is_in_window(site, size):
                raise ValueError('cleanup field instruction differs: ' + label)
            offset = struct.unpack_from('<I', raw, len(prefix))[0]
            immediate = '' if immediate_size == 0 else hex(int.from_bytes(raw[-immediate_size:], 'little'))
            cleanup_fields.append((label if variant == 'spawn' else 'poll_' + label,
                                   hex(site), raw.hex(), hex(offset), immediate))
        for original_site, expected_target in RESET_LOADS:
            site = original_site + delta
            raw = read_va(data, secs, site, 7, True)
            if raw[:2] != b'\x0f\x10' or raw[2] & 0xc7 != 0x05 or not is_in_window(site, 7):
                raise ValueError('cleanup reset load differs')
            target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
            if target != expected_target:
                raise ValueError('cleanup reset target differs')
            reset_values.append((hex(site), raw.hex(), hex(target), read_va(data, secs, target, 16).hex()))

    literal_rows = []
    for label, lea, mov in LITERALS:
        raw = read_va(data, secs, lea, 7, True)
        if not (raw[:3] == b'\x48\x8d\x3d' and is_in_window(lea, 7)):
            raise ValueError('unrecognized literal LEA')
        target = lea + 7 + struct.unpack_from('<i', raw, 3)[0]
        imm = read_va(data, secs, mov, 5, True)
        if imm[0] != 0xbe or not is_in_window(mov, 5):
            raise ValueError('unrecognized literal length')
        length = struct.unpack_from('<I', imm, 1)[0]
        if not 0 < length <= 256:
            raise ValueError('unexpected literal length')
        content = read_va(data, secs, target, length)
        if not all(32 <= x < 127 for x in content):
            raise ValueError('literal is not printable ASCII')
        literal_rows.append((label, hex(lea), hex(target), length, content.hex(), content.decode('ascii')))

    candidates = selected_candidate_scan(data, secs, frames)
    candidate_rows = [(hex(site), hex(op), hex(target), owner, raw)
                      for site, op, target, owner, raw in candidates]
    selected_sites = {(site, op, target) for _, site, op, target in EDGES
                      if target in {0x1fc6250, 0x22569c0, 0x2032480, 0x22b8920, 0x247bbf0, 0x247c020, 0x2885a80,
                                    0x229ec10, 0x23c3c70, 0x2888350, 0x2003d20,
                                    0x200b3a0, 0x1d8e930, 0x1d7c8f0, 0x2013c00, 0x22ae8a0}}
    if not selected_sites.issubset({(site, op, target) for site, op, target, _, _ in candidates}):
        raise ValueError('selected transfer missing from candidate scan')

    cleanup_stages = []
    cleanup_parameters = []
    for variant, delta, owner in (('spawn', 0, 'future_cleanup'),
                                  ('poll', CLEANUP_DELTA, 'poll_cleanup')):
        bias_site, cmp_site, branch_site = 0x22569ce + delta, 0x22569d1 + delta, 0x22569d4 + delta
        bias_raw = _imm8(data, secs, bias_site, b'\x83\xc0')
        bias = struct.unpack('<b', bytes([bias_raw]))[0]
        upper = _imm8(data, secs, cmp_site, b'\x83\xf8')
        if upper + 1 != len(table_lookup[owner]):
            raise ValueError('cleanup table range mismatch')
        raw_branch = read_va(data, secs, branch_site, 6, True)
        _, cc, _, default = checked_branch(raw_branch, branch_site, 0x2256d21 + delta)
        if cc != 'a':
            raise ValueError('cleanup range guard differs')
        cleanup_parameters.append((bias, upper))
        for tag in range(256):
            index = (tag + bias) & 0xffffffff
            selected = index <= upper
            target = table_lookup[owner][index] if selected else default
            cleanup_stages.append((tag, hex(index), 'table' if selected else 'default', hex(target), variant))
    if cleanup_parameters[0] != cleanup_parameters[1]:
        raise ValueError('cleanup selector bounds differ')

    guard_rows = []
    for flag in (0, 1, 2, 255):
        for word in (0, 1, 2, (1 << 63) - 1, 1 << 63, (1 << 63) + 1, MASK64):
            guard_rows.append((flag, hex(word), int(cleanup_release_guard(flag, word))))

    constants = model_constants(data, secs, 'b')
    if model_constants(data, secs, 'a') != constants:
        raise ValueError('scheduler operands differ')
    values = list(range(256)) + sorted({(1 << 63) - 1, 1 << 63, (1 << 63) + 1,
                                       (1 << 64) - 65, (1 << 64) - 64, (1 << 64) - 1})
    scenarios = []
    for word in values:
        pre, pre_new, pre_idx = model_pre(word, constants)
        post, post_new, post_idx = model_post(word, constants)
        def address(table, idx):
            return '' if idx is None else hex(table_lookup[table][idx])
        scenarios.append((hex(word), pre, '' if pre_new is None else hex(pre_new),
                          '' if pre_idx is None else pre_idx,
                          address('scheduler_a_before_poll', pre_idx), address('scheduler_b_before_poll', pre_idx),
                          post, '' if post_new is None else hex(post_new),
                          '' if post_idx is None else post_idx,
                          address('scheduler_a_after_poll', post_idx), address('scheduler_b_after_poll', post_idx)))

    outputs = {
        'functions.tsv': (('name', 'start_va', 'end_va_exclusive', 'file_offset', 'section', 'fde_va', 'cie_va', 'size', 'sha256'), functions),
        'windows.tsv': (('name', 'owner', 'start_va', 'file_offset', 'section', 'length', 'bytes_hex'), windows),
        'edges.tsv': (('name', 'owner', 'site_va', 'file_offset', 'bytes_hex', 'displacement', 'target_va'), edges),
        'branches.tsv': (('predicate', 'owner', 'site_va', 'bytes_hex', 'condition_code', 'displacement', 'taken_va', 'fallthrough_va'), branches),
        'jump-tables.tsv': (('owner', 'lea_va', 'lea_bytes', 'table_va', 'index', 'entry_bytes', 'target_va'), table_rows),
        'relocations.tsv': (('variant', 'lea_va', 'table_va', 'slot_index', 'slot_va', 'file_bytes', 'relocation_file_offset', 'type', 'symbol', 'addend'), relocations),
        'literals.tsv': (('label', 'lea_va', 'literal_va', 'length', 'bytes_hex', 'ascii'), literal_rows),
        'layout.tsv': (('field', 'instruction_va', 'value_hex'), layout_rows(data, secs)),
        'scan-candidates.tsv': (('site_va', 'opcode', 'target_va', 'selected_owner', 'bytes_hex'), candidate_rows),
        'cleanup-stages.tsv': (('synthetic_tag', 'u32_index', 'dispatch', 'target_va', 'variant'), cleanup_stages),
        'cleanup-guards.tsv': (('synthetic_flag', 'synthetic_word', 'indirect_call_selected'), guard_rows),
        'cleanup-fields.tsv': (('name', 'site_va', 'instruction_bytes', 'object_offset', 'immediate'), cleanup_fields),
        'cleanup-reset-values.tsv': (('load_site', 'load_bytes', 'data_va', 'data_bytes'), reset_values),
        'synthetic-cases.tsv': (('word', 'before_action', 'before_new', 'before_index', 'before_a', 'before_b',
                                 'after_action', 'after_new', 'after_index', 'after_a', 'after_b'), scenarios),
    }
    summary = {'binary_sha256': digest, 'coordinate_system': 'ELF link-time virtual addresses and file offsets',
               'selected_fdes': len(functions), 'fixed_windows': len(windows), 'direct_edges': len(edges),
               'conditional_branches': len(branches), 'jump_table_entries': len(table_rows),
               'selected_relative_relocations': len(relocations), 'ascii_literals': len(literal_rows),
               'raw_scan_candidates': len(candidate_rows), 'synthetic_words': len(scenarios),
               'synthetic_cleanup_tags': len(cleanup_stages), 'synthetic_guard_cases': len(guard_rows),
               'cleanup_field_sites': len(cleanup_fields), 'cleanup_reset_loads': len(reset_values),
               'model_constants': {k: hex(v) for k, v in sorted(constants.items())},
               'model_constant_sources': ['scheduler_a', 'scheduler_b'],
               'scan_scope': 'every .text byte as e8/e9 for sixteen selected targets; candidates may be unaligned',
               'limitations': 'Selected fixed windows, not complete CFG or a native execution. FDE extents are unwind metadata. Parent table counts are selected entries.'}
    return outputs, summary


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as handle:
        w = csv.writer(handle, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    with TARGET.open('rb') as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            outputs, summary = build(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(outputs):
        header, rows = outputs[name]
        write_tsv(args.out / name, header, rows)
    (args.out / 'summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('abci_async_handoff94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
