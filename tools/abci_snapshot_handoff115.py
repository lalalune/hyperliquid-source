#!/usr/bin/env python3
"""Extract selected node-115 state snapshot handoff facts from ELF bytes only."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected unwind ranges, not a claim of complete function boundaries.
SELECTED = (
    ('snapshot_owner_entry', 0x5648a30, 0x5649054),
    ('owner_guard_adapter', 0x4e47ca0, 0x4e47f8c),
    ('owner_trace_adapter', 0x4f279d0, 0x4f28332),
    ('owner_snapshot_entry', 0x4fc2330, 0x4fc2961),
    ('dispatch', 0x59ebeb0, 0x59ec1f7),
    ('scheduler_adapter', 0x59ea8a0, 0x59eaa4c),
    ('snapshot_callback', 0x5669160, 0x56693db),
    ('snapshot_builder', 0x5444fa0, 0x5445292),
    ('guarded_wrapper', 0x4e48ee0, 0x4e4910c),
    ('aggregate_builder', 0x4e36140, 0x4e363bf),
    ('state_serialization', 0x4e4b860, 0x4e4bc20),
    ('state_encoder', 0x5480950, 0x548168c),
)

# Fixed windows were selected at instruction boundaries during static inspection.
# They are validated against the authenticated input before any output is written.
WINDOWS = (
    ('top_entry', 0x5648a30, bytes.fromhex('554157415641554154534881ece80000004989f54989ff488954246848894c247048897424084889742410488d4424684889442418488dbc24c0000000488d742408ba01000000e824f27fff498d9d500b0000b10131c0f0410fb08d500b00000f85c9040000488d7c2408ff15ef7ee900')),
    ('top_quotient', 0x5648b43, bytes.fromhex('31c04885c9480f4fc1498b8d580b00004889c24809ca48c1ea20741331d248f7f1493b85600b00007716e94d03000031d2f7f1493b85600b00000f863c030000498985600b0000')),
    ('top_reset', 0x5648b83, bytes.fromhex('498985600b0000488d05641c2efb488944246848c74424701f000000660f280589a9e0fa660f11442478c684248800000001bf01000000e821b763004989c489d549c785680b000000000000')),
    ('top_alloc_body', 0x5648ca0, bytes.fromhex('4c8b7424704d85f6790d31ff4c89f6ff15e367e9000f0b4c89ac24a00000004c89bc249800000048899c24900000000f84450100004989ef488b6c24684c89f7ff159a67e9004885c00f84ef0200004989c54889c74889ee4c89f2ff150768e900')),
    ('top_counter_return', 0x5648ebf, bytes.fromhex('498b85680b000048ffc048c7c1ffffffff480f45c849898d680b000031c9b001f0410fb08d500b00000f8584000000488b8424e0000000498947200f108424c00000000f108c24d0000000410f114f10410f11074c89f84881c4e80000005b415c415d415e415f5dc3')),
    ('top_lock_fallbacks', 0x5648f5f, bytes.fromhex('4889dfba00ca9a3bff158b72e900e924fbffff4889df31f6ff15bb7fe900e96cffffff')),
    ('top_failure_unwind', 0x5648fde, bytes.fromhex('bf01000000488b9c24900000004c89fde9b9fcffff4989c6eb1d4989c6eb0e4989c631c9b001f00fb04d00751f31c9b001f00fb00b7526488dbc24c0000000e8fe2bfeff4c89f7e8267ada00488b3d3771e90031f6ff15ff7ee900ebd04889df31f6ff15f27ee900ebcd')),
    ('outer_check', 0x4e47cce, bytes.fromhex('488d152b5e6501488d7c240a488d74240be89c8ec5004885c00f85f2000000807c240a000f848f000000')),
    ('outer_forward', 0x4e47d87, bytes.fromhex('0f1045000f1144243848c7442430000000004c897c24104981c7300100004c896c2418488d44243048894424204c8d057d706501488d5424104889df4c89fe31c9e803fc0d004889d8')),
    ('middle_entry', 0x4f279d0, bytes.fromhex('554157415641554154534881ec980100004889b424d8000000807e200074534d8b384d8b6808418b68104c89bc24300100004c89ac243801000089ac244001000049c7c480eeffff64488b1c25000000004c01e364410fb644242083f801746b83f802752d488d3d1c7e5701ff15668f5b014889fb4889d6e8e3a809004889d84881c4980100005b415c415d415e415f5dc3')),
    ('middle_alternate', 0x4f2820b, bytes.fromhex('4c89f7488bb42420010000e815a10900488dbc2480000000e82857faff4c89f0e920f8ffff')),
    ('owner_entry', 0x4fc2330, bytes.fromhex('554157415641554154534881ec080100004889bc24d8000000488b1e4c8b7608488b4610488b481048898c24f0000000660f1000660f298424e00000000fb683400b000088442407bf01000000e85e1fcc004989c44189d54c8dbba8060000488b83a806000089c183e108c1e9034883f8f00f93c208ca74124c89ff31f6b900ca9a3bff151fec5101eb0b488d4810f0490fb10f75e3')),
    ('owner_first_call', 0x4fc2429, bytes.fromhex('81bb2801000000ca9a3b0f85b4000000488d93b0060000498bb6480b00004883ee80488d7c2450e85b9aa200488b4424704889442430660f10442450660f104c2460660f294c2420660f2944241048c74424380000000048c7c0f0ffffff488dbba8060000e933020000')),
    ('owner_second_call', 0x4fc2533, bytes.fromhex('8b4c2460b800ca9a3b48f76424584989c44901cc4883d2004531ed48f7da4d19ed0fb644245088442406488d93b0060000498bb6480b00004883ee80488dbc24a0000000e83499a200488b8424c00000004889442470660f108424a0000000660f108c24b0000000660f294c2460660f294424504c8bb3180100004d85f60f84c9000000')),
    ('owner_release', 0x4fc2680, bytes.fromhex('31c0488dbba8060000488b8c24c000000048894c2430660f108c24a0000000660f109424b0000000660f29542420660f294c24104889442438f20f1144244048c7c0f0fffffff0480fc1074883e0f24883f8120f84ca010000')),
    ('owner_output', 0x4fc27c1, bytes.fromhex('807c240700741480bba006000001750bbf32000000ff154ce85101498b4620488944243066410f100666410f104e10660f294c2420660f2944241081bb2801000000ca9a3b743ef6842488000000017434488d7b28f20f10842490000000488b8424f00000004889442460660f288c24e0000000660f294c2450488d742450ff1512485201488dbb200b0000488b5318488b4b20488db424e0000000f20f10442448f20f104c2408ff1539895201488b442430488b8c24d8000000488941200f284424100f284c24200f1149100f11014881c4080100005b415c415d415e415f5dc3')),
    ('owner_unwind', 0x4fc28ae, bytes.fromhex('4889c34c89f7e8b7ddf6ffe988000000ff15fccb51014889c3488d7c2450e89fddf6ffeb274889c3488d7c2410e890ddf6ffeb64ff15d8cb51014889c3488d7c2410e87bddf6ffeb4f4889c348c7c0f0ffffff488b4c2408f0480fc1014883e0f24883f8127531488b7c2408ff15c8e65101eb24ff1598cb510148c7c1f0ffffff488b542408f0480fc10a4889c34883e1f24883f91274084889dfe802e14201488b7c2408ff158fe65101ebebff155fcb5101')),
    ('dispatcher_gate', 0x59ebed0, bytes.fromhex('4989d64889f14989ff48c7c078fbffff64488b104885d20f8400020000488b82100100004883e8804839c80f8500020000498d9e50040000')),
    ('dispatcher_snapshot', 0x59ebf01, bytes.fromhex('498d9e50040000bf01000000e8ce83290048894424308954240c48c744241000000000488d7c2468488d5424104889deb901000000e8a5cf45ff488b4424684889442428488b5c24704c8b642478488b84248000000048890424488b84248800000048894424200f108424900000000f29442450')),
    ('dispatcher_copies', 0x59ebf75, bytes.fromhex('4d8bb650040000498b6e28498db600120000488d7c24684c8b2d7535af00ba1008000041ffd5498db6081b0000488dbc2478080000ba1008000041ffd54981c610240000488dbc2488100000ba100800004c89f641ffd5bf30180000ff15a934af004885c00f84310100004989c6488d742468ba301800004889c7ff151235af00')),
    ('dispatcher_assemble', 0x59ebff6, bytes.fromhex('488b442428488944247848899c24800000004c89a4248800000048c74424680100000048c74424700100000048b8030000000000008048898424900000004c89b424980000004889ac2410010000bfb0000000ff153134af004885c00f84d30000004989c5488d742468bab00000004889c7ff159a34af00')),
    ('dispatcher_output', 0x59ec0ba, bytes.fromhex('488b042449894708488b442420498947100f28442450410f1147184d892f4c89f84881c4981800005b415c415d415e415f5dc3488d357cafac004c89ff4c89f2e8011452ffebd74c89ff4889ce4c89f1e891e7ffffebc74989dc488b5c2428bf08000000be30180000ff156733af00eb15488d5c2478bf08000000beb0000000ff155033af00')),
    ('scheduler_capture', 0x59ea8a0, bytes.fromhex('554157415641554154534883ec584989d64989f44889fb49bdffffffffffffff7f488d8210010000488b9200010000488944243848c7442440000000004889542448c64424500148894c2408498d450248894424184c8b3e488bae80000000488d355ae8c7ff488d5424084c89e7e80d551d00')),
    ('scheduler_lock', 0x59ea913, bytes.fromhex('4c31fd48ba0000000001000000498dbc2458010000f0834c24c0006690498b8424700100004885d075144889c14809d1f0490fb18c247001000075e1eb034889c189c8c1e8100fb7c94839c80f82bd0000004883fd020f92c239c80f95c04885c9740420c2747f')),
    ('scheduler_result', 0x59ea97a, bytes.fromhex('488b4424404883f8037564488b442418f30f6f4424204a8d0c2849ffc54c39e8b801000000480f47c14883f801741b4883f802755a66480f7ec7660f70c0ee66480f7ec6ff15dcc2af000f104c2410488b4424300f110bf30f7f4310488943204883c4585b415c415d415e415f5dc34c89f7488d742440ff15b9c2af00eb8cbe01000000ff15a4c2af00e971ffffff488d3d7ce2f3fa488d1551deab00be28000000ff150e4daf00488d3d372ead00ff15194eaf000f')),
    ('callback_entry', 0x5669160, bytes.fromhex('554157415641554154534883ec48488b3748c707000000004885f60f847f0100004889fb49be000000000000008048c7c078fbffff4d8d6e0364488338000f843e010000488d7c2420e8f2bdddff4c8b6424204c8b6c24284c8b7c2430488b4424384889442418488b6c2440')),
    ('callback_replacement', 0x56691cc, bytes.fromhex('488b4310498d0c0648ffc94c39f0b801000000480f47c14885c074784883f8017529488d7b08488b07f048ff087506ff15dfc9e700488b73104c39f674564885f67451488b7b1831d2eb434c897c24104c8b7b184c8b7320498b064885c074054c89ffffd04c89ff498b76084885f64c8b7c2410741e498b4610f3480fbcc831d24839f00f47d14883f8110f43d1ff154062e700')),
    ('callback_publish', 0x5669260, bytes.fromhex('4c8963084c896b104c897b18488b4424184889432048896b280fb66b48488b4330488b384080fd01750ff048ff070f8e0c01000048897c2408488b7340b803000000488743384883f802750c4881c7d8010000e8287b55004084ed7416488b442408f048ff08750b488d7c2408ff150d79e7004883c4485b415c415d415e415f5dc3')),
    ('callback_fails', 0x56692e2, bytes.fromhex('488d3dcbf92bfb488d15d8f5e300be36000000ff153564e700e9a0000000488d3d2923e400ff152365e700e98e')),
    ('callback_landing', 0x56693a8, bytes.fromhex('4889c7ff15d76ae7004989c74889542418488b05d06ae700f048ff086448ff0c25a0fbffff64c60425a8fbffff00e9f1fdffff')),
    ('builder_entry', 0x5444fc0, bytes.fromhex('4989f64989ff488d9e50040000bf01000000e809f3830048894424308954240c48c744241000000000488d7c2468488d5424104889deb901000000e8e03ea0ff')),
    ('builder_readback', 0x5445000, bytes.fromhex('488b4424684889442428488b5c24704c8b642478488b84248000000048890424488b84248800000048894424200f108424900000000f294424504d8bb650040000498b6e28')),
    ('builder_copies', 0x5445045, bytes.fromhex('498db600120000488d7c24684c8b2db0a40901ba1008000041ffd5498db6081b0000488dbc2478080000ba1008000041ffd54981c610240000488dbc2488100000ba100800004c89f641ffd5bf30180000ff15e4a309014885c00f840a0100004989c6488d742468ba301800004889c7ff154da40901')),
    ('builder_assemble', 0x54450bb, bytes.fromhex('488b442428488944247848899c24800000004c89a4248800000048c74424680100000048c74424700100000048b8030000000000008048898424900000004c89b424980000004889ac2410010000bfb0000000ff156ca309014885c00f84ac0000004989c5488d742468bab00000004889c7ff15d5a30901')),
    ('builder_output', 0x544517f, bytes.fromhex('488b042449894708488b442420498947100f28442450410f1147184d892f4881c4981800005b415c415d415e415f5dc34989dc488b5c2428bf08000000be30180000ff15c9a20901eb10bf08000000beb0000000ff15b7a209010f0b')),
    ('builder_alloc_fail', 0x54451af, bytes.fromhex('4989dc488b5c2428bf08000000be30180000ff15c9a20901eb10bf08000000beb0000000ff15b7a209010f0b')),
    ('dispatcher_alloc_fail', 0x59ec111, bytes.fromhex('4989dc488b5c2428bf08000000be30180000ff156733af00eb15488d5c2478bf08000000beb0000000ff155033af000f0b')),
    ('scheduler_landing', 0x59eaa31, bytes.fromhex('4889c3488d7c2408e8728705004889dfe80a60a000ff15744aaf00')),
    ('guard_entry', 0x4e48ee0, bytes.fromhex('554157415641554154534883ec284889fb4c8b2e4c8b224c8b7a0885c97473c644240600c644240700488d15f04b6501488d7c2406488d742407e8c177c5004885c07571807c24060074470fb66c240748c7c1d0eeffff644c8b3425000000004901ce640fb6414883f8010f849900000083f802757840886c2408c644240900488d3df1686501ff153b7a6901e95a0100004889df4c89ee4c89e24c89f9e8bdd1feff4889d84883c4285b415c415d415e415f5dc3')),
    ('guard_tls', 0x4e48f95, bytes.fromhex('48894424184889542420488d4424184889442408488d0570d37c004889442410488d3d9b285ffb488d153d4b6501488d742408ff15ea666901488d353b64e9004c89f7ff153275690148c7c1d0eeffff64c6414801640fb7414464c641440040886c24086689442409640fb669464080fd020f849100000064c641460240886c24184889df4c89ee4c89e24c89f9e818d1feff')),
    ('inner_entry', 0x4e36140, bytes.fromhex('55415741564154534883ec604989c84889d14989f74889fb4c8b76284881c608110000488d7c24284c89f2ff155f006b014c89742440c644240600c644240700488d1579796601488d7c2406488d742407e84a80c6004885c00f8591000000807c240600744d')),
    ('inner_direct', 0x4e361f3, bytes.fromhex('488d7c24484c89fee8605601000f104424280f104c24380f114b280f1143180f104424480f1103488b442458488943104883c4605b415c415e415f5dc3')),
    ('inner_fail', 0x4e36335, bytes.fromhex('488d153c996601be3d000000488d3de136aefbeb13488d156ff86801be45000000488d3dd069b1fbff1555936a010f0b')),
    ('serializer_setup', 0x4e4b860, bytes.fromhex('554157415641554154534881ecf80000004989f64889fbbf01000000e85f8ae3004989c489d5498b462848898424c00000004c89b424c800000048c74424700000000048c74424780100000048c784248000000000000000488d44247048890424c744240800040001c644240c00488d7c2420488db424c80000004889e2e86d50630049bf00000000000000804c8b742420498d47044939c60f8560020000')),
    ('serializer_success', 0x4e4b8ff, bytes.fromhex('488b4424704889442410488b44247848894424184c8bb42480000000')),
    ('serializer_return', 0x4e4bafe, bytes.fromhex('488b442410488903488b442418488943084c8973104881c4f80000005b415c415d415e415f5dc3')),
    ('serializer_reject', 0x4e4bb5f, bytes.fromhex('488b5c24284c8b7c2430488b7424704885f6740d488b7c247831d2ff15203969014c8974242048895c24284c897c2430488d3dcfccacfb488d0d1b2065014c8d05541e6501488d542420be2b000000ff15ec3a69010f0b')),
    ('serializer_landing', 0x4e4bbcb, bytes.fromhex('4889c3488b7424704885f67440488b7c2478eb314889c3488b7424704885f67e12488b7c247831d2ff15a7386901eb034889c348837c2410007412488b7c2418488b74241031d2ff15883869014889dfe8304e5a01')),
    ('encoder_headers', 0x5480950, bytes.fromhex('415741564154534883ec184989d64989f74889fb49bc0400000000000080807a0b0074334889e74c89f6ba01000000e87cd73400488b04244883f8027433488b4c24084983c4fc4c89234889430848894b10e9ce0c00004889e74c89f6ba01000000e8e9e13400488b04244883f80275cd4d8b3f41807e0b007441488d35f685fdfaba080000004c89f7e881ee34004883f8020f856f0c000041807e0b00741c4889e74c89f6ba3b000000e800d73400488b04244883f802741ceb604889e74c89f6ba3b000000e884e13400488b04244883f8027546')),
    ('encoder_ctx', 0x5480a26, bytes.fromhex('41807e0b007452488d35508b4afbba050000004c89f7e81fee34004883f8020f850d0c000041807e0b00742d4889e74c89f6ba11000000e89ed63400488b04244883f802742d488b4c240866480f6ec9660f6ec0e9e30b00004889e74c89f6ba11000000e811e13400488b04244883f80275d341807e0b01751e488d35c3884afbba030000004c89f7e8aced34004883f8020f859a0b00004889e74c89fe4c89f2e8642591ff488b04244c39e00f85ab0b0000')),
    ('encoder_fields', 0x5480ad9, bytes.fromhex('41807e0b01751e488d3586884afbba030000004c89f7e86ced34004883f8020f855a0b00004d8d87c0070000488d15e08e4afb4889e7b90e0000004c89f6e8147ae7ff488b04244c39e00f855b0b0000')),
    ('encoder_exit', 0x5481640, bytes.fromhex('89f64c89fae806421f00488b04244c39e075314c8923eb1d66480f6ec066480f6eca660f6cc14983c4fc4c89e0488903f30f7f43084889d84883c4185b415c415e415fc3f30f6f442408ebe1')),
)

# label, site, encoding, expected destination. Destination of ff15 is the slot,
# not its dynamic runtime value. Register calls are intentionally not resolved.
TRANSFERS = (
    ('top_owner_adapter', 0x5648a77, 'call', 0x4e47ca0),
    ('top_lock_fallback', 0x5648a90, 'jcc32', 0x5648f5f),
    ('top_div32', 0x5648b5d, 'jcc8', 0x5648b72),
    ('top_bucket_update64', 0x5648b6b, 'jcc8', 0x5648b83),
    ('top_bucket_keep32', 0x5648b7d, 'jcc32', 0x5648ebf),
    ('top_nonnegative_length', 0x5648ca8, 'jcc8', 0x5648cb7),
    ('top_allocation', 0x5648ce0, 'slot', 0x64df480),
    ('top_allocation_failure', 0x5648ce9, 'jcc32', 0x5648fde),
    ('top_copy', 0x5648cfb, 'slot', 0x64df508),
    ('top_unlock_fallback', 0x5648ee8, 'jcc32', 0x5648f72),
    ('top_lock_boundary', 0x5648f67, 'slot', 0x64e01f8),
    ('top_unlock_boundary', 0x5648f77, 'slot', 0x64e0f38),
    ('top_failure_join', 0x5648fee, 'jmp32', 0x5648cac),
    ('top_unwind_cleanup', 0x564901d, 'call', 0x562bc20),
    ('top_unwind_resume', 0x5649025, 'call', 0x63f0a50),
    ('outer_check_helper', 0x4e47cdf, 'call', 0x5aa0b80),
    ('outer_check_nonzero', 0x4e47ce7, 'jcc32', 0x4e47ddf),
    ('outer_check_flag_zero', 0x4e47cf2, 'jcc32', 0x4e47d87),
    ('outer_middle_adapter', 0x4e47dc8, 'call', 0x4f279d0),
    ('middle_no_instrumentation', 0x4f279ed, 'jcc8', 0x4f27a42),
    ('middle_direct_owner', 0x4f27a48, 'call', 0x4fc2330),
    ('middle_instrumented_owner', 0x4f28216, 'call', 0x4fc2330),
    ('owner_acquire_fast', 0x4fc23a7, 'jcc8', 0x4fc23bb),
    ('owner_acquire_retry_boundary', 0x4fc23c4, 'jcc8', 0x4fc23a9),
    ('owner_nonsentinel_path', 0x4fc2433, 'jcc32', 0x4fc24ed),
    ('owner_sentinel_path', 0x4fc24e7, 'jcc32', 0x4fc2439),
    ('owner_first_dispatch', 0x4fc2450, 'call', 0x59ebeb0),
    ('owner_second_dispatch', 0x4fc2577, 'call', 0x59ebeb0),
    ('owner_no_timestamp', 0x4fc25b1, 'jcc32', 0x4fc2680),
    ('owner_release_boundary', 0x4fc26d3, 'jcc32', 0x4fc28a3),
    ('owner_skip_extra_sentinel', 0x4fc2806, 'jcc8', 0x4fc2846),
    ('owner_skip_extra_flag', 0x4fc2810, 'jcc8', 0x4fc2846),
    ('owner_optional_boundary', 0x4fc2840, 'slot', 0x64e7058),
    ('owner_final_boundary', 0x4fc2869, 'slot', 0x64eb1a8),
    ('dispatch_missing_tls', 0x59ebee7, 'jcc32', 0x59ec0ed),
    ('dispatch_other_thread', 0x59ebefb, 'jcc32', 0x59ec101),
    ('dispatch_direct', 0x59ebf36, 'call', 0x4e48ee0),
    ('dispatch_copy_symbol', 0x59ebf8c, 'movrip', 0x64df508),
    ('dispatch_copy_allocation', 0x59ebff0, 'slot', 0x64df508),
    ('dispatch_missing_adapter', 0x59ec0fa, 'call', 0x4f0d500),
    ('dispatch_scheduled_adapter', 0x59ec10a, 'call', 0x59ea8a0),
    ('callback_address', 0x59ea8ff, 'lea', 0x5669160),
    ('scheduler_call', 0x59ea90e, 'call', 0x5bbfe20),
    ('scheduler_wait', 0x59ea983, 'jcc8', 0x59ea9e9),
    ('scheduler_wait_boundary', 0x59ea9f1, 'slot', 0x64e6cb0),
    ('scheduler_wait_join', 0x59ea9f7, 'jmp8', 0x59ea985),
    ('scheduler_inline_result', 0x59ea9a7, 'jcc8', 0x59ea9c4),
    ('scheduler_invalid_result', 0x59ea9ad, 'jcc8', 0x59eaa09),
    ('scheduler_result_boundary', 0x59ea9be, 'slot', 0x64e6ca0),
    ('callback_no_input', 0x566917b, 'jcc32', 0x5669300),
    ('callback_no_tls', 0x566919e, 'jcc32', 0x56692e2),
    ('callback_builder', 0x56691a9, 'call', 0x5444fa0),
    ('callback_skip_cleanup', 0x56691e6, 'jcc8', 0x5669260),
    ('callback_virtual_cleanup', 0x56691ec, 'jcc8', 0x5669217),
    ('callback_no_wake', 0x56692aa, 'jcc8', 0x56692b8),
    ('callback_wake', 0x56692b3, 'call', 0x5bc0de0),
    ('callback_landing_join', 0x56693d6, 'jmp32', 0x56691cc),
    ('builder_guard', 0x5444ffb, 'call', 0x4e48ee0),
    ('builder_copy_symbol', 0x5445051, 'movrip', 0x64df508),
    ('builder_copy_allocation', 0x54450b5, 'slot', 0x64df508),
    ('builder_copy_record', 0x544512d, 'slot', 0x64df508),
    ('builder_chunk_oom', 0x544509f, 'jcc32', 0x54451af),
    ('builder_record_oom', 0x5445117, 'jcc32', 0x54451c9),
    ('guard_direct', 0x4e48efd, 'jcc8', 0x4e48f72),
    ('guard_empty', 0x4e48f29, 'jcc8', 0x4e48f72),
    ('guard_aggregate', 0x4e48f7e, 'call', 0x4e36140),
    ('guard_tls_aggregate', 0x4e49023, 'call', 0x4e36140),
    ('aggregate_meta_slot', 0x4e3616b, 'slot', 0x64e61d0),
    ('aggregate_check', 0x4e36191, 'call', 0x5a9e1e0),
    ('aggregate_check_failure', 0x4e36199, 'jcc32', 0x4e36230),
    ('aggregate_direct', 0x4e361a4, 'jcc8', 0x4e361f3),
    ('aggregate_serializer', 0x4e361fb, 'call', 0x4e4b860),
    ('aggregate_tls_serializer', 0x4e362c2, 'call', 0x4e4b860),
    ('serializer_encoder', 0x4e4b8de, 'call', 0x5480950),
    ('serializer_error', 0x4e4b8f9, 'jcc32', 0x4e4bb5f),
    ('serializer_diagnostic', 0x4e4bb8f, 'lea', 0x918865),
    ('serializer_location', 0x4e4bb9d, 'lea', 0x649d9f8),
    ('encoder_mode', 0x5480972, 'jcc8', 0x54809a7),
    ('encoder_first_header', 0x548097f, 'call', 0x57ce100),
    ('encoder_first_ok', 0x548098c, 'jcc8', 0x54809c1),
    ('encoder_second_header', 0x54809fb, 'call', 0x57ce100),
    ('encoder_exchange', 0x54809cb, 'lea', 0x458fc8),
    ('encoder_locus', 0x5480a2d, 'lea', 0x929584),
    ('encoder_ctx', 0x5480aa0, 'lea', 0x92936a),
)

# label, VA, checked opcode prefix, immediate/displacement width.
OPERANDS = (
    ('top_guard_offset', 0x5648a7c, '498d9d', 4),
    ('top_denominator_offset', 0x5648b4c, '498b8d', 4),
    ('top_bucket_compare_offset', 0x5648b64, '493b85', 4),
    ('top_bucket_store_offset', 0x5648b83, '498985', 4),
    ('top_counter_reset_offset', 0x5648bc4, '49c785', 4),
    ('top_counter_reset_value', 0x5648bc4, '49c785680b0000', 4),
    ('top_message_length', 0x5648b96, '48c7442470', 4),
    ('top_counter_load_offset', 0x5648ebf, '498b85', 4),
    ('top_counter_store_offset', 0x5648ed4, '49898d', 4),
    ('outer_owner_adjust', 0x4e47d9e, '4981c7', 4),
    ('middle_mode_offset', 0x4f279e9, '807e', 1),
    ('owner_context_first', 0x4fc2439, '488d93', 4),
    ('owner_context_second', 0x4fc255d, '488d93', 4),
    ('owner_guard_offset', 0x4fc2388, '4c8dbb', 4),
    ('owner_guard_busy_bit', 0x4fc2398, '83e1', 1),
    ('owner_guard_limit_signed_byte', 0x4fc239e, '4883f8', 1),
    ('owner_guard_acquire_step', 0x4fc23bb, '488d48', 1),
    ('owner_guard_release_delta_i32', 0x4fc26bf, '48c7c0', 4),
    ('owner_guard_release_mask_signed_byte', 0x4fc26cb, '4883e0', 1),
    ('owner_guard_release_wake_value', 0x4fc26cf, '4883f8', 1),
    ('owner_selector_offset', 0x4fc2429, '81bb', 4),
    ('owner_selector_sentinel', 0x4fc2429, '81bb28010000', 4),
    ('owner_final_argument', 0x4fc2846, '488dbb', 4),
    ('dispatch_state_slot', 0x59ebf01, '498d9e', 4),
    ('dispatch_height', 0x59ebf7c, '498b6e', 1),
    ('dispatch_chunk_1', 0x59ebf80, '498db6', 4),
    ('dispatch_chunk_2', 0x59ebf9b, '498db6', 4),
    ('dispatch_chunk_3', 0x59ebfb2, '4981c6', 4),
    ('dispatch_chunk_size', 0x59ebf93, 'ba', 4),
    ('dispatch_chunk_allocation', 0x59ebfcc, 'bf', 4),
    ('dispatch_record_allocation', 0x59ec044, 'bf', 4),
    ('callback_status_offset', 0x56692a2, '488743', 1),
    ('callback_result_offset', 0x5669260, '4c8963', 1),
    ('builder_state_slot', 0x5444fc6, '488d9e', 4),
    ('builder_height', 0x5445041, '498b6e', 1),
    ('builder_chunk_1', 0x5445045, '498db6', 4),
    ('builder_chunk_2', 0x5445060, '498db6', 4),
    ('builder_chunk_3', 0x5445077, '4981c6', 4),
    ('builder_chunk_size_1', 0x5445058, 'ba', 4),
    ('builder_chunk_size_2', 0x544506f, 'ba', 4),
    ('builder_chunk_size_3', 0x5445086, 'ba', 4),
    ('builder_chunk_allocation', 0x5445091, 'bf', 4),
    ('builder_record_allocation', 0x5445109, 'bf', 4),
    ('record_stack_base', 0x544504c, '488d7c24', 1),
    ('record_prefix_first_stack', 0x54450d5, '48c74424', 1),
    ('record_prefix_first_value', 0x54450d5, '48c7442468', 4),
    ('record_prefix_second_stack', 0x54450de, '48c74424', 1),
    ('record_prefix_second_value', 0x54450de, '48c7442470', 4),
    ('record_serialized0_stack', 0x54450c0, '48894424', 1),
    ('record_serialized1_stack', 0x54450c5, '48899c24', 4),
    ('record_serialized2_stack', 0x54450cd, '4c89a424', 4),
    ('record_marker_value', 0x54450e7, '48b8', 8),
    ('record_marker_stack', 0x54450f1, '48898424', 4),
    ('record_blob_stack', 0x54450f9, '4c89b424', 4),
    ('record_height_stack', 0x5445101, '4889ac24', 4),
    ('record_copy_length', 0x5445125, 'ba', 4),
    ('aggregate_height', 0x4e36158, '4c8b76', 1),
    ('aggregate_subobject', 0x4e3615c, '4881c6', 4),
    ('writer_flags', 0x4e4b8c1, 'c7442408', 4),
    ('serializer_marker', 0x4e4b8e3, '49bf', 8),
    ('serializer_diagnostic_length', 0x4e4bba9, 'be', 4),
    ('encoder_success_tag', 0x5480964, '49bc', 8),
    ('callback_marker', 0x5669184, '49be', 8),
    ('callback_landing_tag_increment', 0x5669195, '4d8d6e', 1),
    ('callback_done_status', 0x566929d, 'b8', 4),
    ('scheduler_done_status', 0x59ea97f, '4883f8', 1),
    ('outer_header_count', 0x548097a, 'ba', 4),
    ('inner_header_count', 0x54809f6, 'ba', 4),
    ('exchange_length', 0x54809d2, 'ba', 4),
    ('locus_length', 0x5480a34, 'ba', 4),
    ('ctx_length', 0x5480aa7, 'ba', 4),
)

RELOCS = (
    ('loader_location', 0x64767a8),
    ('serializer_location', 0x649d9f8),
    ('aggregate_helper_slot', 0x64e61d0),
)


def authenticate(data, expected=SHA115):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


def unique_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    if len(matches) != 1 or matches[0]['type'] == 8:
        raise ValueError('missing, ambiguous or fileless section')
    return matches[0]


def file_range(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address range')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
               and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not in one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def read(data, secs, va, size):
    off = file_range(secs, va, size)
    if off + size > len(data):
        raise ValueError('file-backed range is truncated')
    return data[off:off + size]


def check_window(actual, expected):
    if actual != expected:
        raise ValueError('selected byte window changed')


def decode_transfer(va, raw, kind):
    if kind == 'call' and len(raw) == 5 and raw[0] == 0xe8:
        displacement = struct.unpack_from('<i', raw, 1)[0]
    elif kind == 'slot' and len(raw) == 6 and raw[:2] == b'\xff\x15':
        displacement = struct.unpack_from('<i', raw, 2)[0]
    elif kind == 'lea' and len(raw) == 7 and raw[0] in (0x48, 0x4c) and raw[1] == 0x8d and raw[2] & 0xc7 == 5:
        displacement = struct.unpack_from('<i', raw, 3)[0]
    elif kind == 'movrip' and len(raw) == 7 and raw[:3] == b'\x4c\x8b\x2d':
        displacement = struct.unpack_from('<i', raw, 3)[0]
    elif kind == 'jcc32' and len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack_from('<i', raw, 2)[0]
    elif kind == 'jcc8' and len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif kind == 'jmp8' and len(raw) == 2 and raw[0] == 0xeb:
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif kind == 'jmp32' and len(raw) == 5 and raw[0] == 0xe9:
        displacement = struct.unpack_from('<i', raw, 1)[0]
    else:
        raise ValueError('unsupported selected transfer')
    return va + len(raw) + displacement


def unique_relocation(rows, slot):
    found = [(off, info, addend) for off, info, addend in rows if off == slot]
    if len(found) != 1 or found[0][1] != 8 or found[0][2] < 0:
        raise ValueError('missing, duplicate or non-relative relocation')
    return found[0]


def read_relocations(data, secs):
    section = unique_section(secs, '.rela.dyn')
    if section['size'] % 24:
        raise ValueError('truncated relocation table')
    begin = section['offset']
    return list(struct.iter_unpack('<QQq', data[begin:begin + section['size']]))


def dynamic_copy_anchor(data, secs, rows):
    """Resolve this selected dynamic-symbol anchor, without claiming its slot."""
    slot = 0x64df508
    found = [(off, info, addend) for off, info, addend in rows if off == slot]
    if len(found) != 1:
        raise ValueError('missing or duplicate copy anchor relocation')
    off, info, addend = found[0]
    index, kind = info >> 32, info & 0xffffffff
    if kind != 6 or addend != 0:
        raise ValueError('unexpected copy anchor relocation')
    symbols, strings = unique_section(secs, '.dynsym'), unique_section(secs, '.dynstr')
    if symbols['type'] != 11 or strings['type'] != 3 or symbols['size'] % 24:
        raise ValueError('unexpected dynamic symbol sections')
    if index >= symbols['size'] // 24:
        raise ValueError('copy symbol index outside table')
    sym_off = symbols['offset'] + index * 24
    raw = data[sym_off:sym_off + 24]
    name_offset, info_byte, other, shndx, value, size = struct.unpack('<IBBHQQ', raw)
    if name_offset >= strings['size']:
        raise ValueError('copy symbol name outside table')
    names = data[strings['offset']:strings['offset'] + strings['size']]
    end = names.find(b'\0', name_offset)
    if end < 0 or names[name_offset:end] != b'memcpy' or info_byte != 0x12 or shndx != 0:
        raise ValueError('unexpected copy anchor symbol')
    return ('anchor-only', hex(off), hex(info), addend, index, hex(sym_off), raw.hex(),
            names[name_offset:end].decode('ascii'))


def check_locations(data, secs, relocs):
    rows = []
    for label, va, expected_line, expected_column in (
            ('loader_boundary', 0x64767a8, 123, 37),
            ('serialization_failure', 0x649d9f8, 161, 83)):
        _, _, pointer = unique_relocation(relocs, va)
        raw = read(data, secs, va, 24)
        _, length, line, column = struct.unpack('<QQII', raw)
        if length != 20 or line != expected_line or column != expected_column:
            raise ValueError('source Location fields changed')
        path = read(data, secs, pointer, length)
        if path != b'l1/src/abci/state.rs':
            raise ValueError('source Location path changed')
        rows.append((label, hex(va), hex(file_range(secs, va, 24)), raw.hex(),
                     hex(pointer), length, line, column, path.decode('ascii')))
    return rows


def decode_lsda(data, secs, fde):
    """Decode only the observed ULEB call-site framing; action meanings stay unknown."""
    if fde['lsda'] is None:
        return []
    table = unique_section(secs, '.gcc_except_table')
    pos = file_range(secs, fde['lsda'], 1)
    limit = table['offset'] + table['size']
    if not table['offset'] <= pos < limit or limit > len(data):
        raise ValueError('LSDA outside exception table')
    if pos + 2 > limit or data[pos] != 0xff:
        raise ValueError('unsupported LSDA base encoding')
    type_encoding = data[pos + 1]
    pos += 2
    type_base = None
    if type_encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        if type_base > limit:
            raise ValueError('LSDA type table outside section')
    elif type_encoding != 0xff:
        raise ValueError('unsupported LSDA type encoding')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    if end > limit or (type_base is not None and end > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    rows = []
    previous = fde['start']
    while pos < end:
        entry = pos
        relative_start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        relative_landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        start = fde['start'] + relative_start
        stop = start + length
        landing = fde['start'] + relative_landing if relative_landing else None
        if (start < previous or stop > fde['end'] or
                (landing is not None and not fde['start'] <= landing < fde['end'])):
            raise ValueError('invalid LSDA call-site or landing range')
        rows.append((entry, start, stop, landing, action))
        previous = stop
    return rows


def check_fdes(fdes, selected=SELECTED):
    result = []
    for label, start, end in selected:
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1 or found[0]['end'] != end or 'index' not in found[0]:
            raise ValueError('missing, duplicate or mismatched selected FDE')
        f = found[0]
        if any(g is not f and g['start'] < end and g['end'] > start for g in fdes):
            raise ValueError('selected FDE overlaps another FDE')
        result.append((label, f))
    return result


def immediate(data, secs, va, prefix, width):
    before = bytes.fromhex(prefix)
    raw = read(data, secs, va, len(before) + width)
    if not raw.startswith(before):
        raise ValueError('operand instruction changed')
    return int.from_bytes(raw[len(before):], 'little')


def tag_number(word):
    """Model only the unsigned local tag arithmetic; native validity is separate."""
    if not 0 <= word < 1 << 64:
        raise ValueError('word outside u64')
    marker = 1 << 63
    return 1 if word <= marker else word - marker - 1


def classify_old_word(word):
    n = tag_number(word)
    return 'skip' if n == 0 else ('refcount' if n == 1 else 'vtable')


def classify_result_word(word):
    n = tag_number(word)
    return 'inline' if n == 1 else ('helper' if n == 2 else 'diagnostic')


def owner_guard_fast(word, compare_exchange_matches):
    """Model the local fast/slow decision for a valid u64 and one CAS outcome."""
    if not 0 <= word < 1 << 64 or type(compare_exchange_matches) is not bool:
        raise ValueError('invalid guard input')
    return not (word & 8 or word >= (1 << 64) - 16) and compare_exchange_matches


def owner_guard_wakes(old_word):
    """Model the post-xadd bit test, without assuming helper semantics."""
    if not 0 <= old_word < 1 << 64:
        raise ValueError('invalid guard word')
    return old_word & ((1 << 64) - 14) == 0x12


def owner_counter_step(numerator, denominator, bucket, count):
    """Model the local quotient/update after the numerator has been computed."""
    if not 0 <= numerator < 1 << 63 or not 0 <= denominator < 1 << 64:
        raise ValueError('invalid numerator or denominator')
    if not 0 <= bucket < 1 << 64 or not 0 <= count < 1 << 64:
        raise ValueError('invalid prior owner words')
    if denominator == 0:
        raise ZeroDivisionError('selected divide has a zero divisor')
    route = 'div32' if (numerator | denominator) >> 32 == 0 else 'div64'
    quotient = numerator // denominator
    updated = quotient > bucket
    if updated:
        bucket, count = quotient, 0
    count = min(count + 1, (1 << 64) - 1)
    return route, bucket, count, updated


def write_tsv(path, headers, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(headers)
        w.writerows(rows)


def write_json(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def validate_layout(vals):
    if not (vals['owner_context_first'] == vals['owner_context_second'] == 0x6b0
            and vals['top_guard_offset'] == 0xb50 and vals['top_denominator_offset'] == 0xb58
            and vals['top_bucket_compare_offset'] == vals['top_bucket_store_offset'] == 0xb60
            and vals['top_counter_reset_offset'] == vals['top_counter_load_offset'] == vals['top_counter_store_offset'] == 0xb68
            and vals['top_counter_reset_value'] == 0
            and vals['top_message_length'] == 31
            and vals['outer_owner_adjust'] == 0x130 and vals['middle_mode_offset'] == 0x20
            and vals['owner_guard_offset'] == 0x6a8 and vals['owner_selector_offset'] == 0x128
            and vals['owner_guard_busy_bit'] == 8 and vals['owner_guard_limit_signed_byte'] == 0xf0
            and vals['owner_guard_acquire_step'] == 16 and vals['owner_guard_release_delta_i32'] == 0xfffffff0
            and vals['owner_guard_release_mask_signed_byte'] == 0xf2 and vals['owner_guard_release_wake_value'] == 0x12
            and vals['owner_selector_sentinel'] == 1000000000 and vals['owner_final_argument'] == 0xb20
            and vals['dispatch_state_slot'] == vals['builder_state_slot'] == 0x450
            and vals['dispatch_height'] == vals['builder_height'] == vals['aggregate_height'] == 0x28
            and vals['builder_chunk_1'] == vals['dispatch_chunk_1'] == 0x1200
            and vals['builder_chunk_2'] == vals['dispatch_chunk_2'] == 0x1b08
            and vals['builder_chunk_3'] == vals['dispatch_chunk_3'] == 0x2410
            and vals['builder_chunk_size_1'] == vals['builder_chunk_size_2'] == vals['builder_chunk_size_3'] == vals['dispatch_chunk_size'] == 0x810
            and vals['builder_chunk_allocation'] == vals['dispatch_chunk_allocation'] == 3 * vals['builder_chunk_size_1']
            and vals['builder_record_allocation'] == vals['dispatch_record_allocation'] == 0xb0
            and vals['record_copy_length'] == vals['builder_record_allocation']
            and vals['record_stack_base'] == vals['record_prefix_first_stack'] == 0x68
            and vals['record_prefix_first_value'] == vals['record_prefix_second_value'] == 1
            and (vals['record_prefix_second_stack'], vals['record_serialized0_stack'],
                 vals['record_serialized1_stack'], vals['record_serialized2_stack']) == (0x70, 0x78, 0x80, 0x88)
            and (vals['record_marker_stack'], vals['record_blob_stack'], vals['record_height_stack']) == (0x90, 0x98, 0x110)
            and vals['record_marker_value'] == (1 << 63) + 3
            and vals['callback_status_offset'] == 0x38 and vals['callback_result_offset'] == 8
            and vals['aggregate_subobject'] == 0x1108 and vals['writer_flags'] == 0x01000400
            and vals['serializer_marker'] == vals['callback_marker'] == 1 << 63
            and vals['encoder_success_tag'] == vals['serializer_marker'] + 4
            and vals['serializer_diagnostic_length'] == 43
            and vals['callback_landing_tag_increment'] == 3
            and vals['callback_done_status'] == vals['scheduler_done_status'] == 3
            and vals['outer_header_count'] == 1 and vals['inner_header_count'] == 59
            and (vals['exchange_length'], vals['locus_length'], vals['ctx_length']) == (8, 5, 3)):
        raise ValueError('selected layout relations changed')


def make_records(data):
    authenticate(data)
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    choices = check_fdes(fdes)
    functions = []
    for label, f in choices:
        raw = read(data, secs, f['start'], f['end'] - f['start'])
        functions.append({'label': label, 'start_va': hex(f['start']), 'end_va_exclusive': hex(f['end']),
                          'file_offset': hex(file_range(secs, f['start'], len(raw))),
                          'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                          'lsda_va': None if f['lsda'] is None else hex(f['lsda']),
                          'unwind_index': f['index'], 'length': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest(), 'raw_hex': raw.hex()})
    unwind_rows, by_function = [], {}
    for label, f in choices:
        entries = decode_lsda(data, secs, f)
        by_function[label] = (f, entries)
        for offset, start, stop, landing, action in entries:
            unwind_rows.append((label, hex(offset), hex(start), hex(stop),
                                '' if landing is None else hex(landing), action))
    windows = []
    for label, va, expected in WINDOWS:
        raw = read(data, secs, va, len(expected))
        check_window(raw, expected)
        windows.append((label, hex(va), hex(file_range(secs, va, len(raw))), len(raw), raw.hex()))
    sizes = {'call': 5, 'slot': 6, 'lea': 7, 'movrip': 7, 'jcc32': 6, 'jcc8': 2, 'jmp8': 2, 'jmp32': 5}
    transfers = []
    for label, va, kind, destination in TRANSFERS:
        raw = read(data, secs, va, sizes[kind])
        actual = decode_transfer(va, raw, kind)
        if actual != destination:
            raise ValueError('selected transfer target changed')
        transfers.append((label, hex(va), hex(file_range(secs, va, len(raw))), raw.hex(), kind, hex(actual)))
    unwind_links = []
    for label, va, kind, destination in TRANSFERS:
        if kind not in ('call', 'slot'):
            continue
        owners = [(name, f, rows) for name, (f, rows) in by_function.items() if f['start'] <= va < f['end']]
        if len(owners) != 1:
            raise ValueError('transfer does not have one selected owner')
        name, f, rows = owners[0]
        matching = [r for r in rows if r[1] <= va < r[2]]
        if len(matching) > 1:
            raise ValueError('ambiguous LSDA call-site')
        landing = matching[0][3] if matching else None
        unwind_links.append((label, name, hex(va), 'no_lsda' if f['lsda'] is None else ('covered' if matching else 'not_in_table'),
                             '' if landing is None else hex(landing)))
    operand_rows, vals = [], {}
    for label, va, prefix, width in OPERANDS:
        value = immediate(data, secs, va, prefix, width)
        vals[label] = value
        size = len(bytes.fromhex(prefix)) + width
        operand_rows.append((label, hex(va), hex(file_range(secs, va, size)), read(data, secs, va, size).hex(), width, hex(value)))
    validate_layout(vals)
    rex = read(data, secs, 0x54450c0, 1)[0]
    if not 0x40 <= rex <= 0x4f or not rex & 8:
        raise ValueError('record store is not REX.W')
    record_word_width = 8
    relocs = read_relocations(data, secs)
    dynamic_anchor = dynamic_copy_anchor(data, secs, relocs)
    relocation_rows = []
    for label, slot in RELOCS:
        off, info, addend = unique_relocation(relocs, slot)
        if label == 'aggregate_helper_slot' and addend != 0x38c2e00:
            raise ValueError('aggregate helper addend changed')
        relocation_rows.append((label, hex(off), hex(file_range(secs, off, 8)), hex(info), hex(addend)))
    location_rows = check_locations(data, secs, relocs)
    literal_rows = []
    for label, va, size, expected in (('exchange', 0x458fc8, vals['exchange_length'], b'exchange'),
                                       ('locus', 0x929584, vals['locus_length'], b'locus'),
                                       ('ctx', 0x92936a, vals['ctx_length'], b'ctx'),
                                       ('serializer_diagnostic', 0x918865, vals['serializer_diagnostic_length'],
                                        b'called `Result::unwrap()` on an `Err` value')):
        raw = read(data, secs, va, size)
        check_window(raw, expected)
        literal_rows.append((label, hex(va), hex(file_range(secs, va, size)), size, raw.hex(), raw.decode('ascii')))
    layout = {name: hex(value) for name, value in sorted(vals.items())}
    layout.update({'copied_chunk_total': hex(3 * vals['builder_chunk_size_1']),
                   'owner_state_slot': hex(vals['owner_context_first'] + vals['dispatch_state_slot']),
                   'top_mode_owner_offset': hex(vals['outer_owner_adjust'] + vals['middle_mode_offset']),
                   'owner_guard_fast_limit_u64': hex((1 << 64) + vals['owner_guard_limit_signed_byte'] - 256),
                   'owner_guard_release_mask_u64': hex((1 << 64) + vals['owner_guard_release_mask_signed_byte'] - 256),
                   'record_word_width': hex(record_word_width),
                   'callback_landing_tag': hex(vals['callback_marker'] + vals['callback_landing_tag_increment']),
                   'historical_scope': 'separate node-94 verification is optional; no old addresses are transferred',
                   'conditions': 'selected branches, normal returns, valid objects and no conflicting alias writes'})
    copy_segments = []
    for i in range(1, 4):
        source = vals['builder_chunk_' + str(i)]
        length = vals['builder_chunk_size_' + str(i)]
        copy_segments.append((i, hex(source), hex(source + length), hex((i - 1) * length),
                              hex(i * length), hex(length)))
    base = vals['record_stack_base']
    width = hex(record_word_width)
    remainder_start = vals['record_blob_stack'] - base + record_word_width
    remainder_end = vals['record_height_stack'] - base
    state_source_start = vals['builder_chunk_1'] + remainder_start
    state_source_end = vals['builder_chunk_1'] + remainder_end
    record_layout = [
        ('prefix_first', hex(vals['record_prefix_first_stack'] - base), width, 'immediate', '', ''),
        ('prefix_second', hex(vals['record_prefix_second_stack'] - base), width, 'immediate', '', ''),
        ('serialized_word_0', hex(vals['record_serialized0_stack'] - base), width, 'aggregate_result', '', ''),
        ('serialized_word_1', hex(vals['record_serialized1_stack'] - base), width, 'aggregate_result', '', ''),
        ('serialized_word_2', hex(vals['record_serialized2_stack'] - base), width, 'aggregate_result', '', ''),
        ('blob_marker', hex(vals['record_marker_stack'] - base), width, 'immediate', '', ''),
        ('blob_pointer', hex(vals['record_blob_stack'] - base), width, 'allocation_result', '', ''),
        ('first_copy_remainder', hex(remainder_start), hex(remainder_end - remainder_start),
         'first_copy_if_unchanged', hex(state_source_start), hex(state_source_end)),
        ('height_readback', hex(vals['record_height_stack'] - base), width, 'state_word', '', ''),
    ]
    summary = {'target_sha256': SHA115, 'selected_fdes': len(functions), 'windows': len(windows),
               'transfers': len(transfers), 'operands': len(operand_rows), 'relocations': len(relocation_rows),
               'locations': len(location_rows), 'literals': len(literal_rows), 'dynamic_symbol_anchors': 1,
               'unwind_rows': len(unwind_rows), 'unwind_links': len(unwind_links), 'copy_segments': len(copy_segments),
               'record_layout_rows': len(record_layout),
               'coverage': 'selected facts only; not a function census or equivalence measurement'}
    return functions, windows, transfers, operand_rows, relocation_rows, location_rows, literal_rows, unwind_rows, unwind_links, copy_segments, record_layout, dynamic_anchor, layout, summary


def generate(data, out):
    records = make_records(data)  # authenticate and validate before creating output
    out.mkdir(parents=True, exist_ok=True)
    functions, windows, transfers, operands, relocs, locs, lits, unwind, links, copy_segments, record_layout, dynamic_anchor, layout, summary = records
    write_json(out / 'functions.json', functions)
    write_tsv(out / 'windows.tsv', ('label', 'va', 'file_offset', 'length', 'bytes_hex'), windows)
    write_tsv(out / 'transfers.tsv', ('label', 'va', 'file_offset', 'bytes_hex', 'kind', 'target_va'), transfers)
    write_tsv(out / 'operands.tsv', ('label', 'va', 'file_offset', 'bytes_hex', 'width', 'value'), operands)
    write_tsv(out / 'relocations.tsv', ('label', 'slot_va', 'file_offset', 'info', 'addend'), relocs)
    write_tsv(out / 'locations.tsv', ('label', 'record_va', 'file_offset', 'record_hex', 'path_va', 'path_length', 'line', 'column', 'path'), locs)
    write_tsv(out / 'literals.tsv', ('label', 'va', 'file_offset', 'length', 'bytes_hex', 'ascii'), lits)
    write_tsv(out / 'unwind.tsv', ('function', 'entry_file_offset', 'start_va', 'end_va_exclusive', 'landing_va', 'action'), unwind)
    write_tsv(out / 'unwind-links.tsv', ('label', 'function', 'call_va', 'status', 'landing_va'), links)
    write_tsv(out / 'copy-segments.tsv', ('segment', 'source_offset', 'source_end_exclusive', 'destination_offset', 'destination_end_exclusive', 'length'), copy_segments)
    write_tsv(out / 'record-layout.tsv', ('field', 'offset', 'length', 'source', 'state_source_offset', 'state_source_end_exclusive'), record_layout)
    write_tsv(out / 'dynamic-symbols.tsv', ('scope', 'slot_va', 'relocation_info', 'addend', 'symbol_index', 'symbol_file_offset', 'symbol_hex', 'name'), [dynamic_anchor])
    write_json(out / 'layout.json', layout)
    write_json(out / 'summary.json', summary)
    return summary


def check_historical(data):
    authenticate(data, SHA94)
    secs = sections(data)
    relocs = read_relocations(data, secs)
    _, _, pointer = unique_relocation(relocs, 0x56dfbf8)
    raw = read(data, secs, 0x56dfbf8, 24)
    _, length, line, column = struct.unpack('<QQII', raw)
    if (length, line, column) != (49, 107, 37):
        raise ValueError('historical Location changed')
    path = read(data, secs, pointer, length)
    if not path.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical source suffix changed')
    call = read(data, secs, 0x3272785, 6)
    if decode_transfer(0x3272785, call, 'slot') != 0x57755a8:
        raise ValueError('historical caller changed')
    if unique_relocation(relocs, 0x57755a8)[2] != 0x3273810:
        raise ValueError('historical callee changed')
    lea = read(data, secs, 0x3273856, 7)
    if decode_transfer(0x3273856, lea, 'lea') != 0x56dfbf8:
        raise ValueError('historical Location reference changed')
    check_window(read(data, secs, 0x3273871, 4), bytes.fromhex('4983fd02'))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path)
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    authenticate(data)
    if args.historical is not None:
        check_historical(args.historical.read_bytes())
    summary = generate(data, args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('snapshot_handoff: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
