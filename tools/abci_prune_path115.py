#!/usr/bin/env python3
"""Extract a bounded #115 loader-linked result-to-path selection trace."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The selected FDEs are new scope; the separately labeled context windows
# join previous work without claiming its functions or call sites.
NEW_FUNCTIONS = [
    ('metadata_classifier', 0x150bad0, 0x150bd0e, 'e75b8ea7d22ea6a0f0b7e9997282419194384392a39380fb8c2fd6835cf10e4c'),
    ('tree32_builder', 0x14994f0, 0x1499e0a, '1e64f3459e3c137a594737bfffc31fd222a6af702350320760dc041ffe06d5dd'),
    ('tree32_cursor', 0x153b6d0, 0x153ba8e, '37f6395a1a7c7cce742fb8a0b1a5df1e434977a976433db802c5bfee5d14f969'),
    ('tree24_builder', 0x149bab0, 0x149c12e, '2cdf486f1a2bd2d2b833674fc77b9ae45ed0dc4a0b9a6b35eaebf3057844c484'),
    ('tree24_cursor', 0x153c970, 0x153cd1a, 'cacac9c915a9c4c8ad04f4eda0dbabce07a1d7f9147afebe69ae09dd7668654c'),
    ('numeric_collector', 0x1532810, 0x1532b6b, '484d5059142f3fb3c37c0c0bb8b4cdebdd2904c63770f95050c7410224653d88'),
    ('numeric_parser', 0x1568570, 0x1568705, '7a64ef1313c270ee358d5580df0189ca1d4ed3ceac6c3ba7d0f427eb45ad609d'),
    ('numeric_large_sort', 0x15504d0, 0x155062b, 'de85b551c17d62cd5985bc72ff51cffea991a5b83f890c0fac7383ac6d271304'),
    ('numeric_heap_fallback', 0x1550630, 0x15506c7, '2a21308205827547cb72d80c93aae9941535a5c9889f6ce2af62f7c8d1646618'),
    ('numeric_partition', 0x15506d0, 0x15509ec, '5cebbecf71aca7b212c222a4d03f9bfd71ed5e7cb83378d7cbba50f321594d0d'),
    ('path_vector_builder', 0x15331c0, 0x15332c6, '4136f8ab2a113621cf45db6ea078ee8473ebb68f337f86c2171fb1ab03bca4ff'),
    ('path_formatter_loop', 0x1532490, 0x15325cf, '84bede62f8dc60d28598100ba816c4c932e53528abbb2eb7fad01af18e3e2d62'),
]

WINDOWS = [
    ('loader_location', 'context', 0x3c13520, '41574156534883ec504989ce4889d3488d1572328602e8d5ae61004883f801754649'),
    ('callback_to_sink', 'context', 0x5a6f979, '488bbc24a0030000488bb42420010000488d942490020000e81aadeeff'),
    ('sink_bucket', 'context', 0x595a6c1, '31c0483b47180f809f04000048899424b0000000488d5f184883fe014883d6ff48b94b598638d6c56d344889f048f7e148c1ea0b4c69f2102700004c3b77680f8621040000'),
    ('sink_flag', 'context', 0x595a7a5, '4d89756841807d70000f850c030000'),
    ('sink_adapter', 'context', 0x595a83e, '4c89ff4c89e6ff15de60b80084c00f846e020000488dbc24c00000004c89fe4c89e2ff156a61b80083bc24c0000000017512488bbc24c8000000488b07ff10e93e020000'),
    ('sink_vector_call', 'context', 0x595a882, '488d8424c8000000488b481048898c24100100000f10000f29842400010000488d7c2468488db424000100004c89fa4c89e14531c0ff154b69b800'),
    ('sink_pop_last', 'context', 0x595a8bd, '4c8b7c24784d85ff0f844101000049ffcf4c897c24784c8b6c2468488b6c24704b8d047f4c8d24c5000000004901ec488b74c500488d0475000000004885c0740d498b7c240831d2ff15954bb80048896c24084c896c24184c896424204989ee4d85ff0f8414010000'),
    ('sink_advance_cursor', 'context', 0x595a926, '4c89ac24880000004889ac24800000004c8d75184c89a424a8000000eb1c4983c6184983c418488b8424a80000004939c44989c40f842c010000'),
    ('sink_consume_earlier', 'context', 0x595a960, '498b6ee848b800000000000000804839c50f84b30000004d8d66e84d8b6c24084d8b7c24108b054d58b90085c0753a488d7c24584c89ee4c89faff158860b800807c245801750a488b7c2460488b07ff104885ed748e4c89ef4889ee31d2ff15dc4ab800e97bffffff'),
    ('adapter_first_pipeline', 'context', 0x1502205, '488d44246048890424488d7c24204889e6e8e5380b00'),
    ('adapter_second_pipeline', 'context', 0x150226f, '488d7b08488d742418e863370b0031c0488903'),
    ('first_pipeline_collector', 'context', 0x15b5b1d, '488d7c2408488d742420e8d49df8ff'),
    ('metadata_call_first', 'context', 0x153f950, '4c89e74c89feff15bc15fa04837c2470010f8507020000488b4424784885c07411488b4b1048894c24600f10030f29442450488b8c2480000000488b542460498956100f28442450410f110648898424a000000048898c24a80000004c89e7488d7424104c89eae814c1fcff488b6c247048b800000000000000804839c57480'),
    ('metadata_call_next', 'context', 0x153fa60, '4889ef488d742418ff15aa14fa04837c2470010f8525010000488b4424784885c07411488b4b1048894c24600f10030f29442450488b8c2480000000488b542460498956100f28442450410f110648898424a000000048898c24a80000004889ef488db424d00000004c89eae8ffbffcff4c8b7c247048b800000000000000804939c70f8477ffffff'),
    ('first_pipeline_builder', 'context', 0x15b5b61, '488d7424204889dfe87241f8ff'),
    ('tree32_builder_call', 'context', 0x1539d7f, '488d7c2410488d742458488d542408e85df7f5ff'),
    ('second_pipeline_collector', 'context', 0x15b5a18, '488d7c2408488d742420e819b0f8ff'),
    ('cursor32_first_filter', 'context', 0x1540a70, '4c89ff4c89f6e855acffff488b4424504885c0743e488b4c246048c1e1054c8b240848ba00000000000000804939d474224801c84c8b6808807818010f85860000004d85e474b94c89ef4c89e631d2ffd3ebad'),
    ('cursor32_next_filter', 'context', 0x1540bd0, '4c89e74c89eee8f5aaffff488b4424384885c00f84a0000000488b4c244848c1e105488b2c0848ba00000000000000804839d50f84800000004801c84c8b70088078180175114885ed74b54c89f74889ee31d2ffd3eba9'),
    ('second_pipeline_builder', 'context', 0x15b5a5d, '488d7424204889dfe87643f8ff'),
    ('tree24_builder_call', 'context', 0x1539e57, '488d7c2410488d742420488d542408e8451cf6ff'),
    ('prefix_guard_format', 'context', 0x1562400, '4885c9740b807c0aff2f0f846d0100004d85c0b801000000490f45c04d0f44c848894424584c894c2460488d4424484889442410488d05659708004889442418488d35c876eefe488d7c24304c8d7424104c89f2ff158ed2f704'),
    ('numeric_collector_boundary', 'context', 0x15624ef, '488d7c2430488db42498000000e80f03fdff'),
    ('numeric_sort_length', 'context', 0x1562501, '4c8b7c24384c8b6424404983fc020f8383000000'),
    ('numeric_projection', 'context', 0x1562515, '488b4424304b8d0ce74c897c24684c897c2470488944247848898c24800000004c89b424880000004c89ac2490000000'),
    ('numeric_result_boundary', 'context', 0x1562545, '488d7424684889dfe86e0cfdff'),
    ('prefix_assertion', 'context', 0x156257d, '488d3dcc51f0fe488d15ddbee904be2a000000ff159ad1f7040f0b'),
    ('numeric_small_sort', 'context', 0x1562598, '4983fc1573524b8d04e7498d4f08ba08000000eb174c89ff4889374883c1084883c2084839c10f8451ffffff4c8b41f8488b314c39c673e34889d74d89043f4883ff0874d04d8b443ff04883c7f84c39c672e84c01ffebc0'),
    ('numeric_large_sort_boundary', 'context', 0x15625f0, '488d54240f4c89ff4c89e6ff15afeaf704'),
    ('metadata_null_and_setup', 'new', 0x150bae1, '4889fb488b02488b4a084885c07476488944240848894c24100f1042100f11442418488b52204889542428488b7018488b50204c8b44241849ffc8488d7c2430ff153150fd044c8b7424384c8b7c2440488d7c24484c89f64c89faff15ee4dfd04'),
    ('metadata_tag_and_mode', 'new', 0x150bb42, '837c244802753e488b442450488d7c24504889442450c644244801e82e90760431edeb3648894c244848b80000000000000080488903488d7c2448e80e0a0000e90c010000b800f00000238424800000003d00400000400f94c5488d7c24484c89f64c89fa'),
    ('name_conversion', 'new', 0x150bba7, 'ff15fb40fd04837c244801754148b80000000000000080488903488b7424304885f6740b4c89f731d2ff15ca38fd04'),
    ('owned_name_length_and_copy', 'new', 0x150bbf5, '4c8b7c24584d85ff790d31ff4c89feff158e38fd040f0b742b4c8b6c24504c89ffff156438fd044885c00f84830000004989c44889c74c89ee4c89faff15d138fd04eb0641bc010000004c893b4c8963084c897b1040886b18'),
    ('metadata_cleanup', 'new', 0x150bc4e, '488b7424304885f6740b4c89f731d2ff153d38fd04488b442408f048ff08750b488d7c2408ff15e74efd04488b7c2410488b742418c607004885f6740831d2ff150d38fd04'),
    ('metadata_alloc_failure', 'new', 0x150bca8, 'bf01000000e94fffffff'),
    ('metadata_unwind', 'new', 0x150bcb2, 'eb004889c3488b7c2410488b742418c607004885f6743731d2ff15cf37fd044889dfe8774dee044889c3eb184889c3488b7424304885f6740b4c89f731d2ff15aa37fd04488d7c2408e8d00700004889dfe8484dee04ff15b237fd04'),
    ('tree32_write_count', 'new', 0x1499630, '8d48016641898f6a010000c1e00549891c074d89640708498954071041887407188b4c24188b54241b41894c0719418954071c488b44244048ff00'),
    ('tree32_adjacent_key_flag', 'new', 0x1499742, '4d8b45004939f80f8481000000410f104508498b4518488d4c2458488941100f1101483b54246075684c894424284d89fd4189f7488b742458488b7c24104989fc4989d6ff156c62040585c07552443a7c246848bf000000000000008075394885db4d89ef0f84e3feffff4c89e74889de31d2ff15e55c040548bf0000000000000080e9c6feffff'),
    ('tree32_capacity', 'new', 0x149980f, '410fb7876a0100004883f80b0f820ffeffff'),
    ('tree32_internal_alloc', 'new', 0x149985d, 'bfd0010000ff15185c04054885c00f84360500004989c748c7806001000000000000'),
    ('tree32_leaf_alloc', 'new', 0x14998c2, 'bf70010000ff15b35b04054885c00f84a40400004989c64d89ec48c7806001000000000000'),
    ('tree32_failure', 'new', 0x1499d36, 'bf08000000bed0010000ff154a570405eb7e488d3d6b22fcfe488d153ae5f504be19000000ff15cf590405488d3d8923fcfe488d1559e6f504be27000000ff15b6590405bf08000000be70010000ff1506570405eb3a488d3d2de8fbfe488d1556e5f504be20000000ff158b590405eb1fbf08000000bed0010000ff15d9560405eb0d488d3d48e5f504ff156a5a04050f0b'),
    ('tree24_write_count', 'new', 0x149bbd0, '8d48016641898f12010000488d04404d8964c708488b4c240849894cc71049896cc718488b44246048ff00'),
    ('tree24_adjacent_keys', 'new', 0x149bc7d, '483b5c2418746c4c8d6b184c896c24404c8b3348b800000000000000804939c674510f104308488d4424280f1100483b6c24307548488b742428488b7c24084889eaff15333d040585c075314c89eb4d85e40f843bffffff488b7c24084c89e631d2ff15bb3704054c89ebe923ffffff'),
    ('tree24_capacity', 'new', 0x149bcff, '410fb787120100004883f80b0f82bffeffff'),
    ('tree24_internal_alloc', 'new', 0x149bd44, 'bf78010000ff15313704054885c00f84730300004989c748c70000000000'),
    ('tree24_leaf_alloc', 'new', 0x149bd94, 'bf18010000ff15e13604054885c00f84f60200004989c64989dd48c70000000000'),
    ('tree24_failure', 'new', 0x149c073, 'bf08000000be78010000ff150d340405eb65488d3d2efffbfe488d15fdc1f504be19000000ff1592360405bf08000000be18010000ff15e2330405eb3a488d3d09c5fbfe488d1532c2f504be20000000ff1567360405eb1fbf08000000be78010000ff15b5330405eb0d488d3d24c2f504ff15463704050f0b'),
    ('cursor32_entry', 'new', 0x153b6de, '488b46404885c00f842e01000048ffc848894640833e010f8584030000488b7e084885ff0f8597000000'),
    ('cursor32_index', 'new', 0x153b79f, '488b46104c8b76180fb78f6a0100004939ce0f83e40000004989c44989ff'),
    ('cursor32_yield', 'new', 0x153b951, '4d897d004d8965084d8975104889460848c746100000000048895618e9d6000000'),
    ('cursor32_failures', 'new', 0x153ba57, '4885c0b870010000bed0010000480f44f031d2ff15303afa04488d3de11dec04ff15b33dfa040f0b488d3d021eec04ff15a43dfa040f0b'),
    ('cursor24_entry', 'new', 0x153c97e, '488b46404885c00f842e01000048ffc848894640833e010f8570030000488b7e084885ff0f8597000000'),
    ('cursor24_index', 'new', 0x153ca3f, '488b46104c8b76180fb78f120100004939ce0f83d00000004989c44989ff'),
    ('cursor24_yield', 'new', 0x153cbe1, '4d897d004d8965084d8975104889460848c746100000000048895618e9d2000000'),
    ('cursor24_failures', 'new', 0x153cce3, '4885c0b818010000be78010000480f44f031d2ff15a427fa04488d3d550bec04ff15272bfa040f0b488d3d760bec04ff15182bfa040f0b'),
    ('collect_first', 'new', 0x1532850, '4c89ff4c89f6e815a10000488b4424504885c00f8493010000488b4c2460488d1449488b4cd0084839d90f847c010000488d04d04883c0080f104008410f11450048894c24504c89e74c89fee8cf5c0300a80174ab'),
    ('collect_first_alloc', 'new', 0x15328a5, '48896c24404989d7bf20000000ff15c8cbfa044885c00f84400200004c893848c7442408040000004889442438488944241048c744241801000000'),
    ('collect_next', 'new', 0x1532950, '4c89e74c89eee815a00000488b4424204885c00f8415010000488b4c2430488d1449488b4cd0084839d90f84fe000000488d04d04883c0080f104008410f110748894c24204889ef4c89e6e8d05b0300a80174ac4989d6'),
    ('collect_append', 'new', 0x15329a7, '488b3424483b7424087528ba01000000b90800000041b808000000488d7c2408e88482f9ff488b4424104889442438488b3424488b4424384c8934f048ffc6488934244889742418488d842498000000e94cffffff'),
    ('collect_empty', 'new', 0x15329fc, '48c745000000000048c745080800000048c7451000000000'),
    ('collect_return_failure', 'new', 0x1532ada, '488b442418488945100f104424080f1145004889e84881c4a80000005b415c415d415e415f5dc3bf08000000be20000000ff1587c9fa040f0b'),
    ('parse_entire', 'new', 0x1568570, '55415741564155415453504989f6488b0f488b014c8b4608488b5e104c8b78104889dd4c29fd73054531edeb434c8b6908488b78084d89c44c89c64c89faff154474f70485c07522498b55084829d572194b8d043c498b7d00488d34284989d5ff152274f70485c0742f4531ed4d89e0498b364885f6740b4c89c731d2ff15ad6ef7044c89e8488b14244883c4085b415c415d415e415f5dc34b8d043c4885ed4d89e0741f4c89ea4883fd01751b0fb6004531ed83f82b0f84b300000083f82d74aeeb084989edeba70fb60031c93c2b0f94c14889c848f7d84829cd4883fd11734241bd010000004885ed0f84840000004c01c14801c34829d331d2420fb6043983c0d083f8097779488d149289c0488d145049ffc74c39fb75e148891424e94cffffff4801c34829d34c01c14531edbe0a00000048c70424000000004c39fb7448488b042448f7e67025420fb6143983c2d04801d0400f92c783fa0977114889042449ffc74084ff74d2e900ffffffe9fbfeffff48c7042400000000e9eefeffff4531ede9e6feffff41bd01000000e9dbfeffff'),
    ('sort_entire', 'new', 0x15504d0, '4883fe020f82500100004989d0488b07488b4f08ba020000004839c173284883fe0274284989c9660f1f8400000000004d89ca4c8b0cd74d39d1731048ffc24839d675eceb3e4883fe02751f4839f274334889f04883c801480fbdc883f13f01c983f17e31d2e9950100004989c966904d89ca4c8b0cd74d39d172d048ffc24839d675ec4839c10f83cd0000004889f048d1e84883fe08730731c9e98600000048b9fcffffffffffff074821c14889c24883e2fc48f7da4c8d47104c8d0cf74983c1f04531d2662e0f1f840000000000f3410f6f40f0f3410f6f08f3430f6f54d1f0f3430f6f1cd1660f70db4e660f70d24ef3410f7f58f0f3410f7f10660f70c04e660f70c94ef3430f7f04d1f3430f7f4cd1f04983c2fc4983c0204c39d275af4839c8743448f7d8488d14cf48f7d9488d34f74883c6f80f1f840000000000488b3a4c8b04ce4c890248893cce48ffc94883c2084839c875e6c3'),
    ('heap_fallback_entire', 'new', 0x1550630, '4889f048d1e84801f0750ac30f1f40004885c074f648ffc84889c14829f17310488b0f488b14c748891748890cc731c94839c64889c2480f42d64c8d044d010000004939d073c94c8d0c090f1f4400004d8d51024939d2730d4e8b14c74e3b54cf104983d0004d89c24c8b04cf4e8b0cd74d39c8739a4c890ccf4e8904d74f8d0c124e8d0455010000004c89d14939d072bee979ffffff'),
    ('partition_entry', 'new', 0x15506d0, '55415741564155415453504c8904244989f64989ff4883fe21731d4c89ff4c89f6488b14244883c4085b415c415d415e415f5de9185df7ff89cd4989d4eb42904839d6488b34c1498930488914c14883d8ff4c39f00f83bf020000498b0f498b14c749891749890cc7488d48014929ce4d8d3cc74983c7084531e44983fe21729a85ed0f8477020000'),
    ('partition_recurse', 'new', 0x155092d, '4c39f60f83b40000004d8d2cf7498b07498b0cf749890f498904f7498d1cf74883c3084889f048f7d04901c64c89ff4c89e289e94c8b0424e866fdffff4d89ec4989df4983fe210f83d7fdffffe96cfdffff'),
    ('partition_depth_failure', 'new', 0x15509d0, '4c89ff4c89f64883c4085b415c415d415e415f5dff25ce06f9040f0b'),
    ('path_vector_entire', 'new', 0x15331c0, '415741564154534883ec484889f34c8b66184c2b660848b8a8aaaaaaaaaaaa2a4939c4760d31ff4c89feff15a8c2fa040f0b4989fe4f8d3c644d85ff74144c89ffff1579c2fa044885c0747049c1ec03eb08b8080000004531e44c896424084889442410488d4c241848c74424180000000048894c242048c74424280000000048894424300f1043200f11442438488d7424204889dfe835f2ffff488b442418498946100f10442408410f11064c89f04883c4485b415c415e415fc3bf08000000e961ffffff4989c6488d7c2408e8ad6000004c89f7e8b5d7eb044989c6488b73104885f675084c89f7e8a1d7eb04488b3b48c1e60331d2ff15e2c1fa044c89f7e88ad7eb04'),
    ('path_loop_entire', 'new', 0x1532490, '554157415641554154534883ec68488b5f0848897c24084c8b77184c39f348897424100f84a3000000488b6e084c8b7e184c8b66204c8d2c6d000000004901ed49c1e5034c036e100f1f840000000000488b0348894424184c897c2420488d051cf9ffff4889442428488d4424184889442430488b058ee5fa0448894424384c89642440488d0585960b004889442448488d7c2450488d359be9f0fe488d542420ff15b1d1fa044883c308488b442460498945100f10442450410f11450048ffc54983c5184c39f37586eb04488b6e08488b442410488b00488928488b442408488b70104885f6740f488b3848c1e60331d2ff1518cffa044883c4685b415c415d415e415f5dc34989c7488b442410488b00488928488b442408488b70104885f67414488b442408488b3848c1e60331d2ff15d9cefa044c89ffe881e4eb04'),
]
EDGES = [
    ('location_ref', 'context', 0x3c1352f, 'lea', 0x64767a8),
    ('worker_sink', 'context', 0x5a6f991, 'call', 0x595a6b0),
    ('sink_unchanged_bucket', 'context', 0x595a700, 'branch', 0x595ab27),
    ('sink_flag_bypass', 'context', 0x595a7ae, 'branch', 0x595aac0),
    ('sink_predicate', 'context', 0x595a844, 'slot', 0x64e0928),
    ('sink_predicate_false', 'context', 0x595a84c, 'branch', 0x595aac0),
    ('sink_directory_adapter', 'context', 0x595a860, 'slot', 0x64e09d0),
    ('sink_adapter_normal', 'context', 0x595a86e, 'branch', 0x595a882),
    ('sink_numeric_path', 'context', 0x595a8b7, 'slot', 0x64e1208),
    ('sink_no_result', 'context', 0x595a8c5, 'branch', 0x595aa0c),
    ('sink_empty_after_pop', 'context', 0x595a920, 'branch', 0x595aa3a),
    ('sink_sentinel_stop', 'context', 0x595a971, 'branch', 0x595aa2a),
    ('sink_consume_boundary', 'context', 0x595a99a, 'slot', 0x64e0a28),
    ('adapter_rows32', 'context', 0x1502216, 'call', 0x15b5b00),
    ('adapter_rows24', 'context', 0x1502278, 'call', 0x15b59e0),
    ('collector32_entry', 'context', 0x15b5b27, 'call', 0x153f900),
    ('classify_first', 'context', 0x153f9b7, 'call', 0x150bad0),
    ('classify_next', 'context', 0x153facc, 'call', 0x150bad0),
    ('process32_entry', 'context', 0x15b5b69, 'call', 0x1539ce0),
    ('build32_entry', 'context', 0x1539d8e, 'call', 0x14994f0),
    ('collector24_entry', 'context', 0x15b5a22, 'call', 0x1540a40),
    ('cursor32_next_first', 'context', 0x1540a76, 'call', 0x153b6d0),
    ('cursor32_next_later', 'context', 0x1540bd6, 'call', 0x153b6d0),
    ('process24_entry', 'context', 0x15b5a65, 'call', 0x1539de0),
    ('build24_entry', 'context', 0x1539e66, 'call', 0x149bab0),
    ('prefix_trailing_slash', 'context', 0x156240a, 'branch', 0x156257d),
    ('prefix_format_descriptor', 'context', 0x1562440, 'lea', 0x449b0f),
    ('prefix_formatter', 'context', 0x1562454, 'slot', 0x64df6e8),
    ('prefix_assertion_literal', 'context', 0x156257d, 'lea', 0x467750),
    ('prefix_assertion_failure', 'context', 0x1562590, 'slot', 0x64df730),
    ('collect_numbers', 'context', 0x15624fc, 'call', 0x1532810),
    ('format_results', 'context', 0x156254d, 'call', 0x15331c0),
    ('sort_at_least_two', 'context', 0x156250f, 'branch', 0x1562598),
    ('sort_large_cutoff', 'context', 0x156259c, 'branch', 0x15625f0),
    ('large_sort', 'context', 0x15625fb, 'slot', 0x64e10b0),
    ('metadata_missing', 'new', 0x150baee, 'branch', 0x150bb66),
    ('metadata_path_helper', 'new', 0x150bb21, 'slot', 0x64e0b58),
    ('metadata_stat', 'new', 0x150bb3c, 'slot', 0x64e0930),
    ('metadata_tag_select', 'new', 0x150bb47, 'branch', 0x150bb87),
    ('name_decode', 'new', 0x150bba7, 'slot', 0x64dfca8),
    ('name_decode_success', 'new', 0x150bbb2, 'branch', 0x150bbf5),
    ('name_length_signed', 'new', 0x150bbfd, 'branch', 0x150bc0c),
    ('name_alloc', 'new', 0x150bc16, 'slot', 0x64df480),
    ('name_alloc_fail', 'new', 0x150bc1f, 'branch', 0x150bca8),
    ('name_copy', 'new', 0x150bc31, 'slot', 0x64df508),
    ('tree32_length_mismatch', 'new', 0x1499769, 'branch', 0x14997d3),
    ('tree32_key_compare', 'new', 0x1499786, 'slot', 0x64df9f8),
    ('tree32_key_mismatch', 'new', 0x149978e, 'branch', 0x14997e2),
    ('tree32_flag_mismatch', 'new', 0x149979f, 'branch', 0x14997da),
    ('tree32_under_capacity', 'new', 0x149981b, 'branch', 0x1499630),
    ('tree32_internal_alloc', 'new', 0x1499862, 'slot', 0x64df480),
    ('tree32_internal_null', 'new', 0x149986b, 'branch', 0x1499da7),
    ('tree32_leaf_alloc', 'new', 0x14998c7, 'slot', 0x64df480),
    ('tree24_length_mismatch', 'new', 0x149bcb0, 'branch', 0x149bcfa),
    ('tree24_key_compare', 'new', 0x149bcbf, 'slot', 0x64df9f8),
    ('tree24_key_mismatch', 'new', 0x149bcc7, 'branch', 0x149bcfa),
    ('tree24_under_capacity', 'new', 0x149bd0b, 'branch', 0x149bbd0),
    ('tree24_internal_alloc', 'new', 0x149bd49, 'slot', 0x64df480),
    ('tree24_internal_null', 'new', 0x149bd52, 'branch', 0x149c0cb),
    ('tree24_leaf_alloc', 'new', 0x149bd99, 'slot', 0x64df480),
    ('cursor32_exhausted', 'new', 0x153b6e5, 'branch', 0x153b819),
    ('cursor32_invalid_tag', 'new', 0x153b6f5, 'branch', 0x153ba7f),
    ('cursor32_move_up', 'new', 0x153b7b1, 'branch', 0x153b89b),
    ('cursor32_bad_parent', 'new', 0x153ba77, 'slot', 0x64df830),
    ('cursor24_exhausted', 'new', 0x153c985, 'branch', 0x153cab9),
    ('cursor24_invalid_tag', 'new', 0x153c995, 'branch', 0x153cd0b),
    ('cursor24_move_up', 'new', 0x153ca51, 'branch', 0x153cb27),
    ('cursor24_bad_parent', 'new', 0x153cd03, 'slot', 0x64df830),
    ('cursor24_first', 'new', 0x1532856, 'call', 0x153c970),
    ('numeric_empty_first', 'new', 0x1532863, 'branch', 0x15329fc),
    ('numeric_sentinel_first', 'new', 0x153287a, 'branch', 0x15329fc),
    ('parse_first', 'new', 0x153289c, 'call', 0x1568570),
    ('skip_invalid_first', 'new', 0x15328a3, 'branch', 0x1532850),
    ('first_numeric_alloc', 'new', 0x15328b2, 'slot', 0x64df480),
    ('first_numeric_alloc_fail', 'new', 0x15328bb, 'branch', 0x1532b01),
    ('cursor24_later', 'new', 0x1532956, 'call', 0x153c970),
    ('parse_later', 'new', 0x153299b, 'call', 0x1568570),
    ('skip_invalid_later', 'new', 0x15329a2, 'branch', 0x1532950),
    ('numeric_has_capacity', 'new', 0x15329b0, 'branch', 0x15329da),
    ('numeric_grow', 'new', 0x15329c7, 'call', 0x14cac50),
    ('prefix_too_long', 'new', 0x1568596, 'branch', 0x156859d),
    ('prefix_compare', 'new', 0x15685ae, 'slot', 0x64df9f8),
    ('prefix_mismatch', 'new', 0x15685b6, 'branch', 0x15685da),
    ('suffix_too_long', 'new', 0x15685bf, 'branch', 0x15685da),
    ('suffix_compare', 'new', 0x15685d0, 'slot', 0x64df9f8),
    ('suffix_match', 'new', 0x15685d8, 'branch', 0x1568609),
    ('empty_middle', 'new', 0x1568613, 'branch', 0x1568634),
    ('single_plus_rejected', 'new', 0x1568627, 'branch', 0x15686e0),
    ('single_minus_rejected', 'new', 0x1568630, 'branch', 0x15685e0),
    ('checked_parser', 'new', 0x1568650, 'branch', 0x1568694),
    ('unchecked_invalid_digit', 'new', 0x1568677, 'branch', 0x15686f2),
    ('checked_multiply_overflow', 'new', 0x15686b9, 'branch', 0x15686e0),
    ('checked_invalid_digit', 'new', 0x15686cd, 'branch', 0x15686e0),
    ('checked_add_overflow', 'new', 0x15686d9, 'branch', 0x15686ad),
    ('sort_two_or_more', 'new', 0x15504d4, 'branch', 0x155062a),
    ('sort_non_decreasing', 'new', 0x15504ec, 'branch', 0x1550516),
    ('sort_descending_break', 'new', 0x155050a, 'branch', 0x155051c),
    ('sort_general_partition', 'new', 0x1550536, 'jump', 0x15506d0),
    ('sort_ascending_break', 'new', 0x155054a, 'branch', 0x155051c),
    ('sort_already_ascending', 'new', 0x1550557, 'branch', 0x155062a),
    ('partition_small', 'new', 0x15506e9, 'branch', 0x1550708),
    ('partition_small_helper', 'new', 0x1550703, 'jump', 0x14c6420),
    ('partition_depth_exhausted', 'new', 0x1550753, 'branch', 0x15509d0),
    ('partition_recurse', 'new', 0x1550965, 'call', 0x15506d0),
    ('partition_depth_fallback', 'new', 0x15509e4, 'rip_jump', 0x64e10b8),
    ('heap_nonempty', 'new', 0x1550639, 'branch', 0x1550645),
    ('heap_done', 'new', 0x1550643, 'branch', 0x155063b),
    ('heap_build_phase', 'new', 0x155064e, 'branch', 0x1550660),
    ('heap_no_child', 'new', 0x1550675, 'branch', 0x1550640),
    ('heap_only_left_child', 'new', 0x1550687, 'branch', 0x1550696),
    ('heap_parent_not_smaller', 'new', 0x15506a4, 'branch', 0x1550640),
    ('heap_descend', 'new', 0x15506c0, 'branch', 0x1550680),
    ('heap_next_pass', 'new', 0x15506c2, 'jump', 0x1550640),
    ('vector_size_guard', 'new', 0x15331e3, 'branch', 0x15331f2),
    ('vector_no_allocation', 'new', 0x15331fc, 'branch', 0x1533212),
    ('vector_allocate', 'new', 0x1533201, 'slot', 0x64df480),
    ('vector_null_allocation', 'new', 0x153320a, 'branch', 0x153327c),
    ('vector_format_loop', 'new', 0x1533256, 'call', 0x1532490),
    ('path_empty', 'new', 0x15324b3, 'branch', 0x153255c),
    ('first_path_callback', 'new', 0x15324ed, 'lea', 0x1531e10),
    ('integer_format_callback', 'new', 0x1532503, 'rip_load', 0x64e0a98),
    ('last_path_callback', 'new', 0x1532514, 'lea', 0x15ebba0),
    ('path_format_descriptor', 'new', 0x1532525, 'lea', 0x440ec7),
    ('path_format', 'new', 0x1532531, 'slot', 0x64df6e8),
    ('path_loop', 'new', 0x1532558, 'branch', 0x15324e0),
    ('path_resume', 'new', 0x15325ca, 'call', 0x63f0a50),
]

# All operands are read from the listed instruction bytes and checked windows.
FIELDS = [
    ('metadata_error_tag', 0x150bb42, 4, 1),
    ('metadata_mode_mask', 0x150bb87, 1, 4),
    ('metadata_directory_mode', 0x150bb93, 1, 4),
    ('conversion_error_tag', 0x150bbad, 4, 1),
    ('metadata_flag_offset', 0x150bc4a, 3, 1),
    ('tree32_length_offset', 0x149980f, 4, 4),
    ('tree32_capacity', 0x1499817, 3, 1),
    ('tree32_internal_bytes', 0x149985d, 1, 4),
    ('tree32_leaf_bytes', 0x14998c2, 1, 4),
    ('tree24_length_offset', 0x149bcff, 4, 4),
    ('tree24_capacity', 0x149bd07, 3, 1),
    ('tree24_internal_bytes', 0x149bd44, 1, 4),
    ('tree24_leaf_bytes', 0x149bd94, 1, 4),
    ('cursor32_remaining_offset', 0x153b6de, 3, 1),
    ('cursor24_remaining_offset', 0x153c97e, 3, 1),
    ('numeric_first_allocation', 0x15328ad, 1, 4),
    ('numeric_initial_capacity', 0x15328c4, 5, 4),
    ('numeric_growth_item_bytes', 0x15329bc, 2, 4),
    ('numeric_checked_digit_cutoff', 0x156864c, 3, 1),
    ('numeric_ascii_adjustment', 0x1568671, 2, 1),
    ('numeric_max_digit', 0x1568674, 2, 1),
    ('numeric_radix', 0x15686a0, 1, 4),
    ('numeric_sort_cutoff', 0x1562598, 3, 1),
    ('large_sort_min_count', 0x15504d0, 3, 1),
    ('partition_small_cutoff', 0x15506e5, 3, 1),
    ('sink_output_stride', 0x595a944, 3, 1),
    ('sink_stop_sentinel', 0x595a964, 2, 8),
    ('path_input_byte_bound', 0x15331d6, 2, 8),
]

# These existing slots are boundary bindings, not newly claimed GOT work.
# Entries name only relocations needed to interpret the selected trace.
RELOCATIONS = [
    ('state_location_path', 0x64767a8, 8, 0, 0x443168),
    ('numeric_path_boundary', 0x64e1208, 8, 0, 0x15623e0),
    ('metadata_path_helper', 0x64e0b58, 8, 0, 0x5c89400),
    ('metadata_helper', 0x64e0930, 8, 0, 0x5c9c810),
    ('name_conversion_helper', 0x64dfca8, 8, 0, 0x16815e0),
    ('numeric_large_sort', 0x64e10b0, 8, 0, 0x15504d0),
    ('numeric_heap_fallback', 0x64e10b8, 8, 0, 0x1550630),
    ('allocation_boundary', 0x64df480, 8, 0, 0x6355830),
    ('allocation_failure', 0x64df498, 8, 0, 0x141e264),
    ('release_boundary', 0x64df4a0, 8, 0, 0x635de30),
    ('numeric_formatter', 0x64e0a98, 8, 0, 0x1689420),
    ('formatted_output', 0x64df6e8, 8, 0, 0x141e3a0),
    ('copy_import', 0x64df508, 6, 7, 0),
    ('comparison_import', 0x64df9f8, 6, 11, 0),
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=TARGET_SHA256):
    actual = digest(data)
    require(actual == expected, 'input SHA-256 mismatch')
    return actual


def named_section(secs, name):
    matches = [s for s in secs if s['name'] == name]
    require(len(matches) == 1 and matches[0]['type'] != 8,
            'missing, duplicate, or fileless section: ' + name)
    return matches[0]


def file_offset(data, secs, va, size, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual address or size')
    found = [s for s in secs if s['type'] != 8 and s['size'] and
             (not executable or s['flags'] & 4) and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(found) == 1, 'address lacks a unique file-backed section')
    off = found[0]['offset'] + va - found[0]['address']
    require(off >= 0 and off + size <= len(data), 'mapping exceeds file')
    return off


def read_va(data, secs, va, size, executable=False):
    off = file_offset(data, secs, va, size, executable)
    return data[off:off + size]


def selected_fdes(data, secs, table, fdes, specs=None):
    specs = NEW_FUNCTIONS if specs is None else specs
    result = []
    for label, start, end, expected_hash in specs:
        hits = [f for f in fdes if f['start'] == start]
        require(len(hits) == 1 and hits[0]['end'] == end and end > start,
                'selected FDE extent mismatch: ' + label)
        fde = hits[0]
        overlaps = [f for f in fdes if f['start'] < end and start < f['end']]
        require(len(overlaps) == 1 and overlaps[0]['fde'] == fde['fde'],
                'selected FDE overlap: ' + label)
        headers = [r for r in table if r['start'] == start]
        require(len(headers) == 1 and headers[0]['fde'] == fde['fde'],
                'unwind table/FDE mismatch: ' + label)
        body = read_va(data, secs, start, end - start, True)
        require(digest(body) == expected_hash, 'selected body changed: ' + label)
        result.append({'label': label, 'start_va': hex(start), 'end_va_exclusive': hex(end),
                       'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                       'lsda_va': '-' if fde['lsda'] is None else hex(fde['lsda']),
                       'index': headers[0]['index'],
                       'file_offset': hex(file_offset(data, secs, start, len(body), True)),
                       'size': len(body), 'sha256': digest(body), 'body_hex': body.hex()})
    return result


def selected_windows(data, secs, specs=None):
    specs = WINDOWS if specs is None else specs
    rows = []
    for label, scope, va, expected in specs:
        pin = bytes.fromhex(expected)
        require(scope in ('new', 'context') and pin, 'invalid window specification')
        raw = read_va(data, secs, va, len(pin), True)
        require(raw == pin, 'selected bytes changed: ' + label)
        rows.append({'label': label, 'scope': scope, 'start_va': hex(va),
                     'end_va_exclusive': hex(va + len(raw)),
                     'file_offset': hex(file_offset(data, secs, va, len(raw), True)),
                     'raw_hex': raw.hex()})
    return rows


def decode_edge(data, secs, va, kind):
    if kind == 'call':
        raw = read_va(data, secs, va, 5, True)
        require(raw[0] == 0xe8, 'not a rel32 call')
    elif kind == 'slot':
        raw = read_va(data, secs, va, 6, True)
        require(raw[:2] == b'\xff\x15', 'not a RIP-relative indirect call')
    elif kind == 'rip_jump':
        raw = read_va(data, secs, va, 6, True)
        require(raw[:2] == b'\xff\x25', 'not a RIP-relative indirect jump')
    elif kind == 'lea':
        raw = read_va(data, secs, va, 7, True)
        require(raw[0] & 0xf0 == 0x40 and raw[1] == 0x8d and raw[2] & 0xc7 == 5,
                'not a RIP-relative address calculation')
    elif kind == 'rip_load':
        raw = read_va(data, secs, va, 7, True)
        require(raw[:3] == b'\x48\x8b\x05', 'not the selected RIP-relative load')
    elif kind == 'branch':
        raw = read_va(data, secs, va, 2, True)
        if raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
            raw = read_va(data, secs, va, 6, True)
        else:
            require(0x70 <= raw[0] <= 0x7f, 'unsupported branch')
            return raw, va + 2 + struct.unpack('<b', raw[1:])[0]
    elif kind == 'jump':
        first = read_va(data, secs, va, 1, True)
        if first == b'\xe9':
            raw = read_va(data, secs, va, 5, True)
        elif first == b'\xeb':
            raw = read_va(data, secs, va, 2, True)
            return raw, va + 2 + struct.unpack('<b', raw[1:])[0]
        else:
            raise ValueError('unsupported jump')
    else:
        raise ValueError('unsupported transfer kind')
    return raw, va + len(raw) + struct.unpack('<i', raw[-4:])[0]


def selected_edges(data, secs, specs=None, windows=None):
    specs = EDGES if specs is None else specs
    windows = WINDOWS if windows is None else windows
    rows = []
    for label, scope, va, kind, expected in specs:
        raw, target = decode_edge(data, secs, va, kind)
        require(target == expected, 'selected target changed: ' + label)
        spans = [s for _, s, start, pattern in windows if s == scope and
                 start <= va and va + len(raw) <= start + len(bytes.fromhex(pattern))]
        require(spans, 'transfer is outside selected windows: ' + label)
        rows.append({'label': label, 'scope': scope, 'kind': kind, 'site_va': hex(va),
                     'file_offset': hex(file_offset(data, secs, va, len(raw), True)),
                     'raw_hex': raw.hex(), 'target_va': hex(target)})
    return rows


def selected_fields(data, secs, fields=None, windows=None):
    fields = FIELDS if fields is None else fields
    windows = WINDOWS if windows is None else windows
    spans = [(start, start + len(bytes.fromhex(pin))) for _, _, start, pin in windows]
    rows, values = [], {}
    for label, va, offset, width in fields:
        require(label not in values and width in (1, 2, 4, 8) and offset >= 0,
                'invalid field specification')
        require(any(lo <= va and va + offset + width <= hi for lo, hi in spans),
                'field outside pinned windows: ' + label)
        raw = read_va(data, secs, va + offset, width, True)
        values[label] = int.from_bytes(raw, 'little')
        rows.append({'label': label, 'instruction_va': hex(va),
                     'operand_va': hex(va + offset),
                     'file_offset': hex(file_offset(data, secs, va + offset, width, True)),
                     'raw_hex': raw.hex(), 'value': hex(values[label])})
    return rows, values


def selected_relocations(data, secs, specs=None):
    specs = RELOCATIONS if specs is None else specs
    wanted = {slot: (label, typ, symbol, addend) for label, slot, typ, symbol, addend in specs}
    require(len(wanted) == len(specs), 'duplicate selected relocation specification')
    sec = named_section(secs, '.rela.dyn')
    require(sec['size'] % 24 == 0, 'invalid RELA section size')
    found = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate selected relocation')
        label, typ, symbol, expected = wanted[slot]
        file_offset(data, secs, slot, 8)
        require((info & 0xffffffff, info >> 32, addend) == (typ, symbol, expected),
                'selected relocation changed: ' + label)
        found[slot] = {'label': label, 'slot_va': hex(slot), 'record_file_offset': hex(off),
                       'type': typ, 'symbol_index': symbol, 'addend': hex(addend),
                       'raw_hex': data[off:off + 24].hex()}
    require(len(found) == len(wanted), 'missing selected relocation')
    return [found[slot] for slot in sorted(found)]


def dynamic_symbol(data, secs, index):
    sym = named_section(secs, '.dynsym')
    strings = named_section(secs, '.dynstr')
    require(sym['size'] % 24 == 0 and 0 <= index < sym['size'] // 24,
            'invalid dynamic symbol index')
    off = sym['offset'] + index * 24
    nameoff = struct.unpack_from('<I', data, off)[0]
    require(nameoff < strings['size'], 'dynamic symbol name is outside table')
    begin = strings['offset'] + nameoff
    end = data.find(b'\0', begin, strings['offset'] + strings['size'])
    require(end >= 0, 'unterminated dynamic symbol name')
    return data[begin:end].decode('ascii')


def location_record(data, secs, reloc_rows):
    row = next(r for r in reloc_rows if r['label'] == 'state_location_path')
    pointer = int(row['addend'], 16)
    raw = read_va(data, secs, 0x64767a8, 24)
    length, line, column = struct.unpack_from('<QII', raw, 8)
    require(length == 20 and line == 123 and column == 37, 'state Location changed')
    path = read_va(data, secs, pointer, length).decode('ascii')
    require(path == 'l1/src/abci/state.rs', 'state Location path changed')
    return {'record_va': hex(0x64767a8),
            'record_file_offset': hex(file_offset(data, secs, 0x64767a8, len(raw))),
            'raw_hex': raw.hex(), 'path_va': hex(pointer),
            'path_file_offset': hex(file_offset(data, secs, pointer, length)),
            'path': path, 'length': length, 'line': line, 'column': column}


def lsda_rows(data, secs, fde):
    require(fde['lsda'] is not None, 'FDE has no LSDA')
    sec = named_section(secs, '.gcc_except_table')
    va = fde['lsda']
    require(sec['address'] <= va < sec['address'] + sec['size'], 'LSDA outside section')
    pos = file_offset(data, secs, va, 2)
    limit = sec['offset'] + sec['size']
    require(data[pos] == 0xff and data[pos + 1] in (0x9b, 0xff),
            'unsupported LSDA header')
    typ = data[pos + 1]
    pos += 2
    type_base = limit
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    require(type_base <= limit and pos < limit and data[pos] == 1,
            'unsupported LSDA call-site encoding')
    length, pos = uleb(data, pos + 1, limit)
    stop = pos + length
    require(stop <= min(limit, type_base), 'truncated LSDA call-site table')
    rows = []
    while pos < stop:
        first = pos
        start, pos = uleb(data, pos, stop)
        size, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        require(start + size <= fde['end'] - fde['start'], 'LSDA range outside FDE')
        require(not landing or landing < fde['end'] - fde['start'], 'LSDA landing outside FDE')
        rows.append({'entry_file_offset': hex(first), 'start_va': hex(fde['start'] + start),
                     'end_va_exclusive': hex(fde['start'] + start + size),
                     'landing_va': hex(fde['start'] + landing) if landing else '-',
                     'action': action, 'raw_hex': data[first:pos].hex()})
    require(pos == stop, 'misaligned LSDA table')
    return rows


def collect_exception_rows(data, secs, fdes):
    by_start = {f['start']: f for f in fdes}
    rows = []
    for label, start, _, _ in NEW_FUNCTIONS:
        fde = by_start[start]
        if fde['lsda'] is not None:
            for row in lsda_rows(data, secs, fde):
                rows.append({'function': label, **row})
    return rows



def join_unwind_calls(edges, exceptions, functions):
    """Join selected new calls to encoded call-site intervals, without action decoding."""
    rows = []
    for edge in edges:
        if edge['scope'] != 'new' or edge['kind'] not in ('call', 'slot'):
            continue
        site = int(edge['site_va'], 16)
        owners = [f for f in functions if int(f['start_va'], 16) <= site < int(f['end_va_exclusive'], 16)]
        require(len(owners) == 1, 'call lacks a unique selected FDE')
        owner = owners[0]
        candidates = [r for r in exceptions if r['function'] == owner['label'] and
                      int(r['start_va'], 16) <= site < int(r['end_va_exclusive'], 16)]
        require(len(candidates) <= 1, 'overlapping LSDA call-site rows')
        if candidates:
            row = candidates[0]
            require(site + len(bytes.fromhex(edge['raw_hex'])) <= int(row['end_va_exclusive'], 16),
                    'call instruction crosses LSDA row')
            status = 'matched'
            landing, action = row['landing_va'], str(row['action'])
            begin, end = row['start_va'], row['end_va_exclusive']
        else:
            status = 'no-lsda' if owner['lsda_va'] == '-' else 'no-row'
            landing = action = begin = end = '-'
        rows.append({'call': edge['label'], 'function': owner['label'], 'site_va': edge['site_va'],
                     'target_va': edge['target_va'], 'status': status, 'range_start_va': begin,
                     'range_end_va_exclusive': end, 'landing_va': landing, 'action': action})
    return rows

def selected_pools(data, secs):
    pools = [('prefix_format', 0x449b0f, bytes.fromhex('c0012f00')),
             ('three_arguments_format', 0x440ec7, bytes.fromhex('c0c0c000')),
             ('base_slash_assertion', 0x467750, b"assertion failed: !base_dir.ends_with('/')")]
    rows = []
    for label, va, pin in pools:
        raw = read_va(data, secs, va, len(pin))
        require(raw == pin, 'selected data changed: ' + label)
        rows.append({'label': label, 'va': hex(va),
                     'file_offset': hex(file_offset(data, secs, va, len(raw))),
                     'length': len(raw), 'raw_hex': raw.hex()})
    return rows


def verify_historical(data):
    """Check the retired #94 lead separately; never merge old bytes into output."""
    authenticate(data, HISTORICAL_SHA256)
    secs, header = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    for start, end in ((0x32725d0, 0x3272b3a), (0x3273810, 0x327396c)):
        hits = [f for f in fdes if f['start'] == start and f['end'] == end]
        heads = [row for row in header if row['start'] == start]
        require(len(hits) == len(heads) == 1 and hits[0]['fde'] == heads[0]['fde'],
                'historical FDE/index mismatch')
    relsec = named_section(secs, '.rela.dyn')
    want = {0x57755a8: 0x3273810, 0x56dfbf8: 0x1dd8eb}
    seen = {}
    for off in range(relsec['offset'], relsec['offset'] + relsec['size'], 24):
        slot, info, add = struct.unpack_from('<QQq', data, off)
        if slot in want:
            require(slot not in seen and info == 8 and add == want[slot],
                    'historical relocation changed')
            seen[slot] = add
    require(seen == want, 'historical relocation missing')
    raw, slot = decode_edge(data, secs, 0x3272785, 'slot')
    require(slot == 0x57755a8 and raw.hex() == 'ff151d2e5002', 'historical call changed')
    old_ref, old_target = decode_edge(data, secs, 0x3273856, 'lea')
    require(old_ref.hex() == '488d0d9bc34602' and old_target == 0x56dfbf8,
            'historical Location reference changed')
    require(read_va(data, secs, 0x3273871, 4, True).hex() == '4983fd02',
            'historical tag check changed')
    length, line, column = struct.unpack('<QII', read_va(data, secs, 0x56dfc00, 16))
    path = read_va(data, secs, seen[0x56dfbf8], length)
    require((line, column) == (107, 37) and path.endswith(b'l1/src/abci/state.rs'),
            'historical Location changed')


def to_tsv(rows):
    require(rows, 'empty evidence table')
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def to_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


def collect(data):
    binary_hash = authenticate(data)
    secs, table = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    functions = selected_fdes(data, secs, table, fdes)
    windows = selected_windows(data, secs)
    edges = selected_edges(data, secs)
    fields, values = selected_fields(data, secs)
    relocs = selected_relocations(data, secs)
    location = location_record(data, secs, relocs)
    pools = selected_pools(data, secs)
    exceptions = collect_exception_rows(data, secs, fdes)
    unwind_links = join_unwind_calls(edges, exceptions, functions)
    require(dynamic_symbol(data, secs, 11) == 'bcmp', 'unexpected comparison import')
    require(dynamic_symbol(data, secs, 7) == 'memcpy', 'unexpected copy import')
    require(values['tree32_capacity'] == values['tree24_capacity'] == 11,
            'tree capacity mismatch')
    require(values['numeric_radix'] == 10 and values['numeric_max_digit'] == 9,
            'numeric parser constants changed')
    records = {'functions.tsv': to_tsv(functions), 'windows.tsv': to_tsv(windows),
               'edges.tsv': to_tsv(edges), 'fields.tsv': to_tsv(fields),
               'relocations.tsv': to_tsv(relocs), 'pools.tsv': to_tsv(pools),
               'exceptions.tsv': to_tsv(exceptions), 'unwind-links.tsv': to_tsv(unwind_links),
               'location.json': to_json(location)}
    summary = {'binary_sha256': binary_hash, 'target': 'node #115 Linux x86-64',
               'coordinate_system': 'linked ELF virtual address before load bias',
               'counts': {'new_fdes': len(functions),
                          'selected_fde_bytes': sum(row['size'] for row in functions),
                          'new_windows': sum(row['scope'] == 'new' for row in windows),
                          'context_windows': sum(row['scope'] == 'context' for row in windows),
                          'new_transfers': sum(row['scope'] == 'new' for row in edges),
                          'context_transfers': sum(row['scope'] == 'context' for row in edges),
                          'selected_operands': len(fields), 'relocations': len(relocs),
                          'exception_rows': len(exceptions),
                          'selected_new_call_links': len(unwind_links),
                          'calls_with_lsda_row': sum(row['status'] == 'matched' for row in unwind_links),
                          'data_records': len(pools)},
               'selected_operand_values': {k: hex(v) for k, v in sorted(values.items())},
               'derived_path_element_bound': hex(values['path_input_byte_bound'] // values['numeric_growth_item_bytes']),
               'symbol_bindings': {'comparison': dynamic_symbol(data, secs, 11),
                                   'copy': dynamic_symbol(data, secs, 7)},
               'limitations': 'Selected static records only; FDEs are unwind ranges, not a complete function census.'}
    records['summary.json'] = to_json(summary)
    return records



# Conditional models exercise selected byte-backed decisions; they do not
# execute the target or resolve external helpers, scheduling, or aliasing.
def metadata_flag(tag, mode, error_tag=2, mask=0xf000, directory=0x4000):
    """Model the selected metadata result byte, assuming prior calls return."""
    return int(tag != error_tag and (mode & mask) == directory)


def parse_numeric_component(name, prefix, suffix, radix=10, checked_cutoff=17):
    require(radix == 10 and checked_cutoff == 17, 'unexpected parser constants')
    if len(name) < len(prefix) + len(suffix):
        return None
    if not name.startswith(prefix) or (suffix and not name.endswith(suffix)):
        return None
    stop = len(name) - len(suffix)
    digits = name[len(prefix):stop]
    if digits.startswith(b'+'):
        digits = digits[1:]
    if not digits:
        return None
    value = 0
    for byte in digits:
        digit = byte - 48
        if digit < 0 or digit > 9:
            return None
        product = value * radix
        if len(digits) >= checked_cutoff and (product >= 1 << 64 or product + digit >= 1 << 64):
            return None
        value = product + digit
    return value


def deduplicate_adjacent(rows, compare_flag):
    """Model a selected sorted-input run; each row is (name, flag, marker)."""
    kept = []
    for row in rows:
        if kept and kept[-1][0] == row[0] and (not compare_flag or kept[-1][1] == row[1]):
            kept[-1] = row
        else:
            kept.append(row)
    return kept


def sort_small(values, cutoff=21):
    require(2 <= len(values) < cutoff, 'not the selected small-sort route')
    require(all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'not unsigned 64-bit values')
    result = list(values)
    for i in range(1, len(result)):
        value = result[i]
        j = i
        while j and value < result[j - 1]:
            result[j] = result[j - 1]
            j -= 1
        result[j] = value
    return result


def monotone_sort_route(values):
    require(all(type(v) is int and 0 <= v < 1 << 64 for v in values), 'not unsigned 64-bit values')
    if len(values) < 2:
        return 'short', list(values)
    if all(a <= b for a, b in zip(values, values[1:])):
        return 'ascending', list(values)
    if all(a > b for a, b in zip(values, values[1:])):
        return 'descending', list(reversed(values))
    return 'partition', None


def heap_fallback(values):
    """Model the unsigned heap fallback for a valid finite numeric slice."""
    require(all(type(v) is int and 0 <= v < 1 << 64 for v in values),
            'not unsigned 64-bit values')
    result = list(values)
    count = len(result)
    cursor = count + count // 2
    require(cursor < 1 << 64, 'heap cursor would wrap')
    while cursor:
        cursor -= 1
        index = cursor - count
        if cursor < count:
            result[0], result[cursor] = result[cursor], result[0]
            index = 0
        limit = min(cursor, count)
        child = 2 * index + 1
        while child < limit:
            if child + 1 < limit and result[child] < result[child + 1]:
                child += 1
            if result[index] >= result[child]:
                break
            result[index], result[child] = result[child], result[index]
            index = child
            child = 2 * index + 1
    return result


def sink_iteration(rows, sentinel):
    """After the selected nonempty pop, stop before the first sentinel row."""
    if not rows:
        return None, []
    last = rows[-1]
    visited = []
    for row in rows[:-1]:
        if row == sentinel:
            break
        visited.append(row)
    return last, visited


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path,
                        help='optionally authenticate and cross-check the separately retained #94 capture')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    records = collect(data)
    if args.historical is not None:
        verify_historical(args.historical.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(records.items()):
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, struct.error) as error:
        print('abci_prune_path115:', error, file=sys.stderr)
        raise SystemExit(1)
