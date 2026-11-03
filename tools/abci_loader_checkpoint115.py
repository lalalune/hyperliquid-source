#!/usr/bin/env python3
"""Extract selected static checkpoint evidence from the authenticated node 115 ELF.

No captured code is executed. The selected instruction forms are fixed byte
windows, not a general disassembler or a whole-program control-flow analysis.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# These are selected unwind ranges, not a source-function census. Ends are
# cross-checked against the repository's full CIE/FDE parser and unwind header.
FUNCTIONS = [
    ('config_head', 0x154abf0, 0x154ad4d),
    ('startup_checkpoint', 0x5a6dd30, 0x5a6e1e0),
    ('checkpoint_record', 0x595ac30, 0x595afec),
    ('compact_dispatch', 0x4e4a740, 0x4e4a95a),
    ('compact_capture', 0x4e35990, 0x4e35c05),
    ('compact_writer', 0x4e4a960, 0x4e4ac6f),
    ('compact_route', 0x50dd9d0, 0x50ddcb4),
    ('compact_text', 0x5482640, 0x54828a5),
    ('expanded_dispatch', 0x4e46e40, 0x4e4705a),
    ('expanded_capture', 0x4e35c10, 0x4e35e85),
    ('expanded_writer', 0x4e4ac70, 0x4e4af7f),
    ('expanded_route', 0x50deb30, 0x50dee14),
    ('expanded_text', 0x5481690, 0x54818f5),
]

# Whole-window SHA-256 values pin the exact selected bytes. Addresses in
# windows labelled context belong to prior work and are not claimed as FDEs.
WINDOWS = [
    ('upper_mode_save', 0x2cb758f, 0x2cb75d3, 'context', 'bea7bd1e6c9a1c9cd68f20a030a1dee5d35d9f719bf40daf106777be54a84eda'),
    ('upper_owner_argument', 0x2cb7a09, 0x2cb7a0c, 'context', 'ec338fcdd03faa6eef89de052266363fc3c459ed98e2047940751f4194122a87'),
    ('compact_block_cell', 0x5a04f5f, 0x5a04f6f, 'context', '740c3845a02f6ec9d13fc3e68d77afa82dc921a74230117090c7e93612b788bd'),
    ('upper_parent_result', 0x2cb7776, 0x2cb77ac, 'context', '563bf3386d7a260cf93db04e153f8d3b1e421459262aab8552e00b8ea2c7dec2'),
    ('upper_pointer_save', 0x2cb7830, 0x2cb7838, 'context', '9b4abc2a045dc59c9e3b745582d9794800465dd966163300967e68240beeae27'),
    ('upper_checkpoint_call', 0x2cb7959, 0x2cb7976, 'context', 'e627e512d946ca2a14ae9a54f373832f8addb5ea330549aa02ad6d86af051636'),
    ('upper_result_tail', 0x2cb7cd2, 0x2cb7cf2, 'context', '5a5fc6a232a69253d7e377a3e244c995dbfde8a8781c649eae0b3002b9291ecf'),
    ('upper_copy_stage1', 0x2cb7e6c, 0x2cb7e86, 'context', 'fea69fa84f4abddf0bb2ea0c093ca21dd9483c6237592350aae5b2c251271a51'),
    ('upper_copy_stage2', 0x2cb7ffe, 0x2cb8010, 'context', 'f13a50a27d8daa9021039fea551fe66c5596724e2c09e5a8f409449d567c67f8'),
    ('upper_copy_stage3', 0x2cb8039, 0x2cb8054, 'context', '9a1dade1d8754934aa3487ca3a25bac561b181bb2d0bba47a5e29f7e53a41138'),
    ('upper_copy_stage4', 0x2cb806f, 0x2cb8085, 'context', '0206cbe9b84b38967705c7957763ba77781b87b99e4991050caa12315b05ffe7'),
    ('compact_mismatch', 0x5a05cfd, 0x5a05d2e, 'context', '5421b87901d39b33e0796ca29aca1502185d572cf4f383773e9ee63c484b25c8'),
    ('compact_failure_entry', 0x5a060ec, 0x5a06155, 'context', '77c8c36a8f0e3c27d3891b54869b5c54d9497f084bfcd86e2d3a2fe4aef6c424'),
    ('compact_failure_release', 0x5a06155, 0x5a06172, 'context', 'a6d87736d87f507f90c64e32b98c18242930a59ae7059c1bb7420a9a88398f5a'),
    ('compact_failure_terminal', 0x5a061fa, 0x5a0621d, 'context', 'f5f4f8f9f9baf666568dd3c574be3fa2c4faf8536f6bf3c15c49d72fe3ce6a6a'),
    ('expanded_mismatch', 0x5a0751e, 0x5a0754e, 'context', 'acd61c7c24214b78a92bc11499e7861dee0ba324f0881d87727639a4dcd57335'),
    ('expanded_failure_entry', 0x5a0793f, 0x5a079aa, 'context', '713d9735fc5c052fdb2d58b48a0b7cc5560c8b6cff1263ed2cce0301fe04fd96'),
    ('expanded_failure_release', 0x5a079aa, 0x5a079c7, 'context', '943ddad9c4233a20760f51a72bfe0970efb5a6ae5ff670aecddf79317bd62c0c'),
    ('startup_entry', 0x5a6dd30, 0x5a6dd53, 'new', '53e52beb05a788148c21936242b97a9e4976d015a04c71885a2fdd9cbf339e1b'),
    ('startup_format', 0x5a6dd8a, 0x5a6de0d, 'new', 'b5afab4d36c2b7297ca5c2c240375240aa2ab28ed2b00252cba5a1c7518465f1'),
    ('startup_mode_gate', 0x5a6de17, 0x5a6de5b, 'new', 'cbc886ac12a9f36a87545a398ba32bce922b13531bd2c136e708a61756ce14aa'),
    ('startup_checkpoint_args', 0x5a6de68, 0x5a6debd, 'new', 'befcf43dcea6ca7b598d53794209b8b423fab6f528ba640f00ea91e52551aed9'),
    ('startup_checkpoint_release', 0x5a6debd, 0x5a6ded4, 'new', '0f75e03ed43274890170ecaf56804e6501f2d60f24dbaffbccb5b081ab5e9e5f'),
    ('startup_task_launch', 0x5a6df95, 0x5a6dfbf, 'new', '5bd257f2feb1c3e8faf12955d89f72a22238cd320167ede69dc0d7c23edfc4fd'),
    ('startup_result', 0x5a6e01d, 0x5a6e070, 'new', 'b45c89057cf69847b289e0919cdf2f92412448733981ebc589a502be7f71cc85'),
    ('startup_return', 0x5a6e070, 0x5a6e085, 'new', 'fc9b248f72275f6c26449a8dce1bda9e72eacaaff90d986aa28f6888fd9034ad'),
    ('startup_task_failure', 0x5a6e125, 0x5a6e151, 'new', '70d3e766698c0475068309fd4684ef5a6eabdeeb31adb815fd9aa70f1fb3163b'),
    ('startup_cleanup', 0x5a6e151, 0x5a6e1e0, 'new', '5238972cdce5a230907c735aa4eb69af2d55545aca2bca036cb1c846057a4d64'),
    ('result_entry', 0x595ac30, 0x595ac69, 'new', 'b758fd9bd081a521702e50261e9420c21de8eeb8c4003ab6dee26880698a29d9'),
    ('result_output', 0x595ae9d, 0x595af11, 'new', 'f47cc3f5bbc2e07b44c9b8ac61e5a8e225065dfb3ca460ffd4e4cee2ea94fde6'),
    ('result_failure', 0x595af8d, 0x595afa8, 'new', '924993bace29c1fc17e055e99593bfa65ca7380eff71bf046feb9ed4675c06f8'),
    ('compact_dispatch_entry', 0x4e4a740, 0x4e4a782, 'new', 'd0197a0f6e107f2b0d0eb97efeb03be9229b60691a8ed33a486169f9a9f5edda'),
    ('compact_dispatch_direct', 0x4e4a7ce, 0x4e4a7ee, 'new', '4b5813a201a5c35f2cc6ca5265ce3de7844fbed9c19babc816fe45352e166d7b'),
    ('compact_dispatch_guarded', 0x4e4a859, 0x4e4a87e, 'new', '890677486edcadc6fc925a4e9a017749a6eb09965db81601340766629eb3fd97'),
    ('compact_dispatch_failure', 0x4e4a8ec, 0x4e4a91c, 'new', '6ee05056d10d7610da2102eec4c8bd4b102bf30988fd51163e920fbf26e14267'),
    ('compact_dispatch_unwind', 0x4e4a928, 0x4e4a95a, 'new', '8f25b16be55db0771c70376d3c9577fff50dc99821cce868c8e546cb124287af'),
    ('compact_capture_input', 0x4e3599c, 0x4e359e1, 'new', '93f3533ae502634ae6d9e85010c4893f91e594dd57828864d99b1ff844557bed'),
    ('compact_capture_guard', 0x4e359eb, 0x4e35a0d, 'new', '42680b91e7fe1f2019daa103386a242e449ef189a63e445c4ca8c630a026ccaa'),
    ('compact_capture_direct', 0x4e35a59, 0x4e35a80, 'new', 'c2d2c188a4a55aacba546b848d6e97efaa01ec129c8072beebe3e578036a77a5'),
    ('compact_capture_guarded', 0x4e35afb, 0x4e35b17, 'new', '401ebd582235246c2e3613f8df47ac076e5c4d1e487d28177b9813b366e6326e'),
    ('compact_capture_unwind', 0x4e35bb7, 0x4e35c05, 'new', '72628754d905d361b8af8f0888a31e94c50ddb46e0e214b45164c5ee846e8a98'),
    ('compact_writer_entry', 0x4e4a960, 0x4e4a9bb, 'new', '26ab49330d050551ddd0092d352c0f759d1c87f97e957b577a93d7a85f8a012b'),
    ('compact_writer_failure', 0x4e4abc5, 0x4e4abf1, 'new', '2c068067b2cebbd8f1e341cf2f64a18f98b41a3ac80098e0dfa28ba657d74408'),
    ('compact_writer_unwind', 0x4e4ac2c, 0x4e4ac6f, 'new', 'd82e246bb5fea113ca2222905211e0a92870297c23719ffe7ee73f124df15db7'),
    ('compact_route_shortcut', 0x50dd9d0, 0x50dda32, 'new', 'd89b07e3a1dfc7eff3a514da46242807c73a611e19bf858235c5186f251c5c41'),
    ('compact_route_extension', 0x50dda4f, 0x50ddacd, 'new', '41ab15852847d8fea2083f7721705e32893caf0cafa6ee913a48dfb6ed96ea6c'),
    ('compact_route_binary', 0x50ddacd, 0x50ddb3e, 'new', '29fbd952841f182bed6baea8da801219b8f425741431e6358b1e72b3f787491b'),
    ('compact_route_text', 0x50ddb3e, 0x50ddbb6, 'new', '893c2b46cd6c2e8436a173f75b641c53fa61c7602207821b8c72365c356c8971'),
    ('compact_route_output', 0x50ddbb6, 0x50ddc0c, 'new', '2858b9a6d59aa59d85b1dc46d88e8bed6059a83303a856bf49996eca6f8c53c3'),
    ('compact_route_text_failure', 0x50ddc0c, 0x50ddc31, 'new', '721c6f68ef8c016cab11482c7b369218f42c6f25b1f2f3e03eb76a1374be5239'),
    ('compact_route_binary_failure', 0x50ddc31, 0x50ddc71, 'new', 'eac73f9fbf00af33f55d04d66bc381e581622362a139eebee0c277babb0e3660'),
    ('compact_route_unwind', 0x50ddc71, 0x50ddcb4, 'new', 'db7cb6377f69c733f67d96738cbe61e0e51024921fdc6a2f0675fbf230d297f3'),
    ('compact_text_prefix', 0x5482640, 0x54826a8, 'new', '388def82cb197a6484126247a528331649d21f61ab2c1fcade8b7e1b3f9c46b0'),
    ('compact_text_value', 0x54826a8, 0x54826f9, 'new', '68a35044b55ecd70de3308e2d4571335d68584f7212008d6927d8ac24c433d04'),
    ('compact_text_close', 0x54827ac, 0x54827d9, 'new', '0315c8fdc20e1fedad283ecbe0bcd4e268b627fd3b7debfff76705c29468dd0a'),
    ('compact_text_failure', 0x54827d9, 0x54828a5, 'new', '278f392d882fd2f461249e37141ac910e3655c327e01bc4b5397491010d695e7'),
    ('expanded_dispatch_entry', 0x4e46e40, 0x4e46e82, 'new', '24f99fc67c2f47ebc801791672beb5445e68fb7dc8d89881fe42b643681a7ecc'),
    ('expanded_dispatch_direct', 0x4e46ece, 0x4e46eee, 'new', '08456c5bd4e261473098529184748a28f4332aa08fc118e3ba8d9597a735777b'),
    ('expanded_dispatch_guarded', 0x4e46f59, 0x4e46f7e, 'new', '90ff7614fd17c654187f5c7d7797f145c3224da44d4e9505f64832b09eafe11a'),
    ('expanded_dispatch_failure', 0x4e46fec, 0x4e4701c, 'new', '0e792d0b6c9eddf78a0291f10007d485a67a0fc431cdb149b5a8645ad16c69cb'),
    ('expanded_dispatch_unwind', 0x4e47028, 0x4e4705a, 'new', '0afc816eebb046fe9d2b99ed3c124dd099ddc4bbb1c12ca0aea24b396da4ace5'),
    ('expanded_capture_input', 0x4e35c1c, 0x4e35c61, 'new', 'cfdcaa77c95182467d9ce21585b4f198ca82b1857f5c75bd4c5c58e32e0a572f'),
    ('expanded_capture_guard', 0x4e35c6b, 0x4e35c8d, 'new', 'cab7f98c82d1c02dc26996a199f45e2519f53fda53679fdffe076f46f7ae2370'),
    ('expanded_capture_direct', 0x4e35cd9, 0x4e35d00, 'new', 'bc98e4ed67efb609e501cf5b72ec521f88d52104e4af4770a314e686b142cac6'),
    ('expanded_capture_guarded', 0x4e35d7b, 0x4e35d97, 'new', 'fa9e7efa1135eada50e93bef50307f855a6b4bbccf4f48c4a69f648d7059bea8'),
    ('expanded_capture_unwind', 0x4e35e37, 0x4e35e85, 'new', 'd4c63560102e2e6b10fdc764fd791df4d818dc6d2e6e2bdad6c50b0944e40efd'),
    ('expanded_writer_entry', 0x4e4ac70, 0x4e4accb, 'new', '49e536028ee0c7d13a77d12724c1d09e1815b973439f55ff9a3eae1f2058a513'),
    ('expanded_writer_failure', 0x4e4aed5, 0x4e4af01, 'new', '297f569dcbdd4bd1fb4f331bedbb0db4c7aa89a24b4b9350d6335820140b04cf'),
    ('expanded_writer_unwind', 0x4e4af3c, 0x4e4af7f, 'new', 'a1df277743fc340914b4b75e7f0b8d0dc90ddc227098ffad3437c9fa62f4d2e6'),
    ('expanded_route_shortcut', 0x50deb30, 0x50deb92, 'new', 'd89b07e3a1dfc7eff3a514da46242807c73a611e19bf858235c5186f251c5c41'),
    ('expanded_route_extension', 0x50debaf, 0x50dec2d, 'new', 'bad029766f2a37b1c1cc027b9ab347dc98afe47c7f7bcb87343d63cf9ab8f1b1'),
    ('expanded_route_binary', 0x50dec2d, 0x50dec9e, 'new', 'ccc830c524b25670c120dc17360ea17f85ceeaefa2ca3dec245baaa3bc97785a'),
    ('expanded_route_text', 0x50dec9e, 0x50ded16, 'new', '06d592d7e687a9b9ef6034b10abdc5dbebf1d1a22d2f9a7956538ffbbac67a39'),
    ('expanded_route_output', 0x50ded16, 0x50ded6c, 'new', '6115267b1c230af0be79f16c7691567e4ca764cd8cc2b70fbe84615baf6c6744'),
    ('expanded_route_text_failure', 0x50ded6c, 0x50ded91, 'new', 'de9a048df2c77a2f2badd2cbec72fbd9a2427308b10d3d15e73e8c7df475e63f'),
    ('expanded_route_binary_failure', 0x50ded91, 0x50dedd1, 'new', '858f46b680d44808121305acf59caf6eec6dbda385d59806c9755a4cbaa952bd'),
    ('expanded_route_unwind', 0x50dedd1, 0x50dee14, 'new', 'c76463109a4bb129b77635715baf87c8c5149549f03f5c76ebb91204d727edfe'),
    ('expanded_text_prefix', 0x5481690, 0x54816f8, 'new', 'fa37dcba53258939d2ccc860bc7cfbdc8bcd1b5b77d8ba63f17f629c8ed67457'),
    ('expanded_text_value', 0x54816f8, 0x5481749, 'new', '368d6da9f64493dcab1b3f7e1edffd0552cba672662d165b376e6a4131777ce2'),
    ('expanded_text_close', 0x54817fc, 0x5481829, 'new', '0315c8fdc20e1fedad283ecbe0bcd4e268b627fd3b7debfff76705c29468dd0a'),
    ('expanded_text_failure', 0x5481829, 0x54818f5, 'new', '20e6e3c00ad22c2f9cc694685000b58fc6e6f57319c2e945ffd382f62ff40467'),
    ('upper_parent_output', 0x2cb7761, 0x2cb7769, 'context', '5e162eecb056767d0295779767531fd80ce17630bb9fe9646dcceec1e65be880'),
    ('record_time_check', 0x595ae25, 0x595ae49, 'new', '9b3edd841281f927aa473c60fc5d27b3add51ef59bd288f38525366a23dafa82'),
    ('loader_comparison', 0x3c1353b, 0x3c1353f, 'context', '05c41577354ef904ab753a5b2ce89885a04ca4225e1fdbe28525a469509736df'),
    ('parent_object_entry', 0x2cb6552, 0x2cb656c, 'context', 'ee0b8469e5df7384135f593fc018a9d5d1984f34bfe0b90481ca91991380702a'),
    ('parent_object_reload', 0x2cb7baa, 0x2cb7bb4, 'context', '8df2da626ced1baa9834c1ef5b3abc6dffd3fb7cc02083547a8b6ac75c706252'),
    ('compact_mismatch_trap', 0x5a0639a, 0x5a0639c, 'context', '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('expanded_mismatch_terminal', 0x5a07a54, 0x5a07a72, 'context', '7bea01c4b5bdc13c3ab5ff30c44e7835720093e20a722ed7dbd63ad03f4cc0f6'),
    ('expanded_mismatch_trap', 0x5a07c10, 0x5a07c12, 'context', '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('config_entry', 0x154abf0, 0x154ac13, 'new', '09d2546e3f6977d4a71c8f06ded07b03bdb32b1b11edbd8a3c705cbac97cbead'),
    ('config_marker', 0x154ac13, 0x154ac34, 'new', 'b35d32f16d974ab6ee57b1859e544b023e9bd336edb65cf3fababff780c752b1'),
    ('config_copy', 0x154ac34, 0x154ac6a, 'new', 'e6cebf6ccc5480fa84224aede39a3f7ab58e35c51ae03cd34b5331db7b4da2a1'),
    ('config_result', 0x154ac6a, 0x154aca1, 'new', '0487290411b932b9ff2d5d886425f95fccacb4be7098233e28f61f40ef978288'),
    ('config_lazy_init', 0x154aca1, 0x154acf9, 'new', '9368b266e994a1ee9a543cda56bd5f27a48afc698875aea1746fe0040ffe3722'),
    ('config_sentinel_init', 0x154acf9, 0x154ad3f, 'new', '6326c7da9526ca401bc5bd434d8de32d9329259bf3a9eadf2ec7cd9bfd135181'),
    ('config_alloc_failure', 0x154ad3f, 0x154ad4d, 'new', 'ffa7bc7a1781d7c0e723a52bae2dcf140bbaa8ce74998895f2a80997519ced48'),
    ('config_following_trap_byte', 0x154ad4d, 0x154ad4e, 'context', '1dd8312636f6a0bf3d21fa2855e63072507453e93a5ced4301b364e91c9d87d6'),
]

# Selected instruction addresses are checked against the pinned windows before
# decoding. FF 15 destinations are slot addresses, not inferred runtime calls.
TRANSFERS = [
    ('parent_not_pending', 0x2cb777e), ('parent_checkpoint_boundary', 0x2cb7970),
    ('compact_mismatch', 0x5a05d28), ('compact_dump_boundary', 0x5a06150),
    ('compact_dump_release_skip', 0x5a06160), ('compact_terminal_boundary', 0x5a06212),
    ('compact_terminal_trap', 0x5a06218),
    ('expanded_mismatch', 0x5a07548), ('expanded_dump_boundary', 0x5a079a5),
    ('expanded_dump_release_skip', 0x5a079b5), ('expanded_terminal_boundary', 0x5a07a67),
    ('expanded_terminal_trap', 0x5a07a6d),
    ('format_checkpoint_name', 0x5a6de00), ('format_failure', 0x5a6de07),
    ('mode_two_skips_checkpoint', 0x5a6de25), ('checkpoint_configuration', 0x5a6de40),
    ('sentinel_skips_checkpoint', 0x5a6de55), ('startup_to_compact_dispatch', 0x5a6deb8),
    ('startup_release_skip', 0x5a6dec5), ('startup_followup', 0x5a6dfa7),
    ('startup_followup_error', 0x5a6dfb9), ('startup_result_boundary', 0x5a6e055),
    ('startup_failure_boundary', 0x5a6e149), ('startup_unwind_resume', 0x5a6e1db),
    ('record_time_failure', 0x595ae3d), ('record_failure_boundary', 0x595afa0),
    ('config_lazy_init', 0x154ac0d), ('config_marker_sentinel', 0x154ac26),
    ('config_empty', 0x154ac32), ('config_allocate', 0x154ac41),
    ('config_allocation_failed', 0x154ac4a), ('config_copy', 0x154ac5c),
    ('config_copy_length_check', 0x154ac68), ('config_sentinel_init', 0x154ac72),
    ('config_failure_boundary', 0x154ad47),
    ('compact_dispatch_zero', 0x4e4a751), ('compact_dispatch_probe', 0x4e4a771),
    ('compact_dispatch_probe_failure', 0x4e4a779), ('compact_dispatch_plain', 0x4e4a7d9),
    ('compact_dispatch_tls_failure', 0x4e4a864), ('compact_dispatch_guarded', 0x4e4a879),
    ('compact_dispatch_failure', 0x4e4a914),
    ('compact_capture_existing_boundary', 0x4e359c7), ('compact_capture_probe', 0x4e359fc),
    ('compact_capture_probe_failure', 0x4e35a04), ('compact_capture_plain', 0x4e35a5e),
    ('compact_capture_guarded', 0x4e35b0b), ('compact_capture_unwind', 0x4e35bfa),
    ('compact_route_call', 0x4e4a9ad), ('compact_route_error', 0x4e4a9b5),
    ('compact_route_failure', 0x4e4abe9), ('compact_route_unwind', 0x4e4ac4f),
    ('compact_shortcut_length', 0x50dd9fe), ('compact_shortcut_content', 0x50dda19),
    ('compact_shortcut_return', 0x50dda1d), ('compact_path_parser', 0x50dda57),
    ('compact_component_tag', 0x50dda61), ('compact_two_dots', 0x50dda7c),
    ('compact_no_dot', 0x50dda93), ('compact_scan', 0x50ddaa7),
    ('compact_first_dot', 0x50ddaac), ('compact_suffix_compare', 0x50ddac4),
    ('compact_suffix_fallback', 0x50ddacb), ('compact_binary_encode', 0x50ddb12),
    ('compact_binary_error', 0x50ddb2d), ('compact_alloc_failure', 0x50ddb4c),
    ('compact_text_encode', 0x50ddb98), ('compact_text_error', 0x50ddba3),
    ('compact_prepare', 0x50ddbc1), ('compact_prepare_error', 0x50ddbca),
    ('compact_write_boundary', 0x50ddbdb), ('compact_release_skip', 0x50ddbe4),
    ('compact_text_error_wrap', 0x50ddc2a), ('compact_binary_error_wrap', 0x50ddc6a),
    ('compact_allocator_failure', 0x50ddc7b), ('compact_unwind', 0x50ddcaf),
    ('compact_text_key', 0x54826a3), ('compact_text_nested', 0x54826e6),
    ('compact_text_nested_error', 0x54826ee), ('compact_text_grow', 0x54827f2),
    ('expanded_dispatch_zero', 0x4e46e51), ('expanded_dispatch_probe', 0x4e46e71),
    ('expanded_dispatch_probe_failure', 0x4e46e79), ('expanded_dispatch_plain', 0x4e46ed9),
    ('expanded_dispatch_tls_failure', 0x4e46f64), ('expanded_dispatch_guarded', 0x4e46f79),
    ('expanded_dispatch_failure', 0x4e47014),
    ('expanded_capture_existing_boundary', 0x4e35c47), ('expanded_capture_probe', 0x4e35c7c),
    ('expanded_capture_probe_failure', 0x4e35c84), ('expanded_capture_plain', 0x4e35cde),
    ('expanded_capture_guarded', 0x4e35d8b), ('expanded_capture_unwind', 0x4e35e7a),
    ('expanded_route_call', 0x4e4acbd), ('expanded_route_error', 0x4e4acc5),
    ('expanded_route_failure', 0x4e4aef9), ('expanded_route_unwind', 0x4e4af5f),
    ('expanded_shortcut_length', 0x50deb5e), ('expanded_shortcut_content', 0x50deb79),
    ('expanded_shortcut_return', 0x50deb7d), ('expanded_path_parser', 0x50debb7),
    ('expanded_component_tag', 0x50debc1), ('expanded_two_dots', 0x50debdc),
    ('expanded_no_dot', 0x50debf3), ('expanded_scan', 0x50dec07),
    ('expanded_first_dot', 0x50dec0c), ('expanded_suffix_compare', 0x50dec24),
    ('expanded_suffix_fallback', 0x50dec2b), ('expanded_binary_encode', 0x50dec72),
    ('expanded_binary_error', 0x50dec8d), ('expanded_alloc_failure', 0x50decac),
    ('expanded_text_encode', 0x50decf8), ('expanded_text_error', 0x50ded03),
    ('expanded_prepare', 0x50ded21), ('expanded_prepare_error', 0x50ded2a),
    ('expanded_write_boundary', 0x50ded3b), ('expanded_release_skip', 0x50ded44),
    ('expanded_text_error_wrap', 0x50ded8a), ('expanded_binary_error_wrap', 0x50dedca),
    ('expanded_allocator_failure', 0x50deddb), ('expanded_unwind', 0x50dee0f),
    ('expanded_text_key', 0x54816f3), ('expanded_text_nested', 0x5481736),
    ('expanded_text_nested_error', 0x548173e), ('expanded_text_grow', 0x5481842),
]

# Address, observed byte count. Only hex bytes, not decoded path names, are
# exported. Some captured strings contain machine-specific absolute paths.
LITERALS = [
    ('checkpoint_aux_destination', 0x93af86, 27, 0x5a6de75),
    ('checkpoint_state_destination', 0x93afa1, 24, 0x5a6de94),
    ('mismatch_aux_destination', 0x93a5dd, 27, 0x5a060f4),
    ('mismatch_state_destination', 0x93a5f8, 35, 0x5a06129),
    ('binary_suffix', 0x4659e5, 3, 0x50ddab8), ('text_key', 0x458fc8, 8, 0x5482694),
]
LOCATIONS = [
    ('loader_context', 0x64767a8, 123, 37),
    ('writer_call', 0x649d9c8, 151, 17),
    ('writer_error', 0x649d9e0, 151, 35),
]
ANCHOR_SLOTS = {0x64e1050: 0x154abf0, 0x64e7438: 0x5a6dd30, 0x64ebf70: 0x595ac30}


def authenticate(data, expected=TARGET_SHA):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


def read_va(data, secs, va, size):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid file-backed address range')
    matches = [s for s in secs if s['type'] not in (0, 8) and s['flags'] & 2
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('missing or ambiguous file-backed address range')
    s = matches[0]
    offset = s['offset'] + va - s['address']
    if offset < 0 or offset + size > len(data):
        raise ValueError('address range outside file')
    return offset, data[offset:offset + size]


def unique_section(secs, name, typ=None):
    matches = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(matches) != 1 or (typ is not None and matches[0]['type'] != typ):
        raise ValueError('missing, duplicate or invalid section ' + name)
    return matches[0]


def relative_relocations(data, sec, wanted):
    if sec['size'] % 24 or sec['offset'] < 0 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('malformed ELF64 relocation section')
    found = {}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in wanted:
            continue
        if slot in found or info != 8 or addend < 0:
            raise ValueError('duplicate or unsupported selected relocation')
        found[slot] = (addend, pos, bytes(data[pos:pos + 24]))
    if set(found) != set(wanted):
        raise ValueError('missing selected relocation')
    return found


def check_window(raw, expected_hash):
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('selected instruction bytes differ')


def decode_transfer(va, raw):
    if len(raw) >= 5 and raw[0] in (0xe8, 0xe9):
        size = 5
        kind = 'call_rel32' if raw[0] == 0xe8 else 'jump_rel32'
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, kind = 6, 'jcc_rel32_' + format(raw[1] & 15, 'x')
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) >= 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        size = 2
        kind = 'jump_rel8' if raw[0] == 0xeb else 'jcc_rel8_' + format(raw[0] & 15, 'x')
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        size = 6
        kind = 'call_rip_slot' if raw[1] == 0x15 else 'jump_rip_slot'
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported or truncated selected transfer')
    return kind, size, va + size + disp


def map_copy(position, source, destination, size, width):
    if min(position, source, destination, size) < 0 or width <= 0:
        raise ValueError('invalid copy geometry')
    if position < source or position + width > source + size:
        raise ValueError('tracked value outside copy')
    return destination + position - source


def mode_result(mode):
    if type(mode) is not int or not 0 <= mode <= 255:
        raise ValueError('mode must be a byte')
    return int(mode != 2)


def config_model(marker, length, allocation_succeeds):
    """Selected global triple and allocation branches, with synthetic inputs."""
    if any(type(value) is not int or not 0 <= value < 1 << 64 for value in (marker, length)):
        raise ValueError('configuration words must be unsigned 64-bit integers')
    sentinel = 1 << 63
    if marker == sentinel:
        return 'marker_sentinel', sentinel, None, sentinel
    if length == 0:
        return 'empty', 0, 1, 0
    if not allocation_succeeds:
        return 'allocation_failure', None, None, None
    if length == sentinel:
        return 'length_sentinel_after_copy', sentinel, None, sentinel
    return 'allocated_after_copy', length, None, length


def startup_model(mode, format_nonzero, config_sentinel, router_nonzero, followup_zero):
    """Selected simple-return branches only; router failure traps inside the writer."""
    flag = mode_result(mode)
    if format_nonzero:
        return 'format_failure', None
    if not flag:
        return 'mode_bypass', flag
    if config_sentinel:
        return 'config_bypass', flag
    if router_nonzero:
        return 'router_failure', None
    if followup_zero:
        return 'followup_failure', None
    return 'selected_normal', flag


def compare_mask(left, right):
    if len(left) != 32 or len(right) != 32:
        raise ValueError('comparison operands must each have 32 bytes')
    return sum((left[i] == right[i] and left[i + 16] == right[i + 16]) << i
               for i in range(16))


def ascii_fold(data):
    return bytes(x + 32 if 65 <= x <= 90 else x for x in data)


def route_model(destination, parser_tag, component):
    """Model only pinned selection after the separately supplied parser result."""
    if destination == bytes.fromhex('2f6465762f6e756c6c'):
        return 'shortcut'
    if parser_tag != 9 or component == b'..':
        return 'text'
    dot = component.rfind(b'.')
    if dot <= 0:
        return 'text'
    return 'binary' if ascii_fold(component[dot + 1:]) == b'rmp' else 'text'


def parse_lsda(data, secs, fde):
    if fde['lsda'] is None:
        return []
    sec = unique_section(secs, '.gcc_except_table')
    pos, _ = read_va(data, secs, fde['lsda'], 2)
    limit = sec['offset'] + sec['size']
    if not (sec['offset'] <= pos < limit) or pos + 2 > limit or data[pos] != 0xff:
        raise ValueError('unsupported LSDA header')
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
    elif type_encoding == 0xff:
        type_base = limit
    else:
        raise ValueError('unsupported LSDA type encoding')
    if type_base > limit or pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    table_size, pos = uleb(data, pos + 1, limit)
    end = pos + table_size
    if end > limit or end > type_base:
        raise ValueError('LSDA call-site table out of bounds')
    rows = []
    while pos < end:
        begin = pos
        start, pos = uleb(data, pos, end)
        size, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + size > fde['end'] - fde['start'] or (landing and landing >= fde['end'] - fde['start']):
            raise ValueError('LSDA call-site outside selected FDE')
        rows.append((begin, fde['start'] + start, fde['start'] + start + size,
                     fde['start'] + landing if landing else None, action, bytes(data[begin:pos])))
    return rows


def select_callsite(rows, address, size):
    if size <= 0:
        raise ValueError('invalid instruction length')
    hits = [r for r in rows if r[1] <= address and address + size <= r[2]]
    overlap = [r for r in rows if address < r[2] and r[1] < address + size]
    if len(hits) > 1 or len(overlap) != len(hits):
        raise ValueError('ambiguous or crossing LSDA call-site')
    return hits[0] if hits else None


def tsv(headings, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headings)
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')


def checked_instruction(data, secs, address, expected):
    _, raw = read_va(data, secs, address, len(expected))
    if raw != expected:
        raise ValueError('selected operand instruction differs')
    return raw


def offset32(data, secs, address, prefix, at):
    _, raw = read_va(data, secs, address, at + 4)
    if not raw.startswith(bytes.fromhex(prefix)):
        raise ValueError('operand instruction form differs')
    return struct.unpack_from('<I', raw, at)[0]


def location_rows(data, secs, relocs):
    rows = []
    for label, address, expected_line, expected_column in LOCATIONS:
        off, raw = read_va(data, secs, address, 24)
        stored, length, line, column = struct.unpack('<QQII', raw)
        if stored != 0 or (length, line, column) != (20, expected_line, expected_column):
            raise ValueError('selected Location record differs')
        path_va, rel_off, rel_raw = relocs[address]
        path_off, path = read_va(data, secs, path_va, length)
        if path != b'l1/src/abci/state.rs':
            raise ValueError('selected Location suffix differs')
        rows.append([label, hex(address), hex(off), raw.hex(), hex(path_va), hex(path_off),
                     path.decode('ascii'), length, line, column, hex(rel_off), rel_raw.hex()])
    return rows


def lea_target(data, secs, va, prefixes):
    off, raw = read_va(data, secs, va, 7)
    if raw[:3] not in prefixes:
        raise ValueError('unexpected selected RIP-relative LEA')
    return off, raw, va + 7 + struct.unpack_from('<i', raw, 3)[0]


def make_joins(data, secs):
    # All values below come from checked immediate bytes. In each case the
    # prefix is long enough to distinguish the selected instruction form.
    loader_comparison = checked_instruction(data, secs, 0x3c1353b, bytes.fromhex('4883f801'))[-1]
    checked_instruction(data, secs, 0x2cb6552, bytes.fromhex('4889fb'))
    checked_instruction(data, secs, 0x2cb6567, bytes.fromhex('48897c2410'))
    checked_instruction(data, secs, 0x2cb7baa, bytes.fromhex('488b5c2410'))
    output_base = offset32(data, secs, 0x2cb7761, '488dbc24', 4)
    saved = offset32(data, secs, 0x2cb77a4, '488bac24', 4)
    pointer_slot = offset32(data, secs, 0x2cb7830, '4889ac24', 4)
    pointer_arg = offset32(data, secs, 0x2cb7968, '488d9424', 4)
    out_start = offset32(data, secs, 0x2cb7960, '488dbc24', 4)
    mode_source = offset32(data, secs, 0x2cb758f, '0fb68b', 3)
    mode_saved = offset32(data, secs, 0x2cb75cd, '888b', 2)
    mode_arg = offset32(data, secs, 0x2cb7959, '0fb6b3', 3)
    checked_instruction(data, secs, 0x5a6dd44, bytes.fromhex('89f5'))
    if mode_saved != mode_arg:
        raise ValueError('parent mode save-to-argument join differs')
    checked_instruction(data, secs, 0x2cb7a09, bytes.fromhex('4889ef'))
    mismatch_context_cell = offset32(data, secs, 0x5a04f5f, '498d8424', 4)
    mismatch_cell_saved = offset32(data, secs, 0x5a04f67, '48898424', 4)
    mismatch_cell_loaded = offset32(data, secs, 0x5a0610f, '488b8424', 4)
    checked_instruction(data, secs, 0x5a06117, bytes.fromhex('4889442410'))
    checked_instruction(data, secs, 0x5a06146, bytes.fromhex('488d742410'))
    if mismatch_cell_saved != mismatch_cell_loaded:
        raise ValueError('compact mismatch state-cell join differs')
    if pointer_slot != pointer_arg or saved < output_base:
        raise ValueError('parent result-to-argument join differs')
    checked_instruction(data, secs, 0x154ac1d, bytes.fromhex('31c0'))
    config_marker_offset = offset32(data, secs, 0x154ac1f, '493b87', 3)
    config_length_offset = offset32(data, secs, 0x154ac28, '4d8bb7', 3)
    config_pointer_offset = offset32(data, secs, 0x154ac37, '4d8bbf', 3)
    checked_instruction(data, secs, 0x154ac13, bytes.fromhex('49bc0000000000000080'))
    checked_instruction(data, secs, 0x154ac85, bytes.fromhex('4c8937'))
    checked_instruction(data, secs, 0x154ac88, bytes.fromhex('48895f08'))
    checked_instruction(data, secs, 0x154ac8c, bytes.fromhex('4c897710'))
    checked_instruction(data, secs, 0x5a6dd41, bytes.fromhex('4989d4'))
    checked_instruction(data, secs, 0x5a6de8a, bytes.fromhex('4c89642450'))
    checked_instruction(data, secs, 0x5a6deae, bytes.fromhex('488d742450'))
    checked_instruction(data, secs, 0x4e4a753, bytes.fromhex('4989f7'))
    checked_instruction(data, secs, 0x4e4a7d6, bytes.fromhex('4c89fe'))
    checked_instruction(data, secs, 0x4e359a2, bytes.fromhex('4c8b26'))
    checked_instruction(data, secs, 0x4e359a9, bytes.fromhex('498b3424'))
    for address, expected_length in ((0x5a6de81, 27), (0x5a6dea0, 24), (0x5a06135, 35)):
        if offset32(data, secs, address, '48c74424', 5) != expected_length:
            raise ValueError('destination length differs')
    if offset32(data, secs, 0x5a06103, '48c78424', 8) != 27:
        raise ValueError('auxiliary destination length differs')
    capture_height = checked_instruction(data, secs, 0x4e359ad, bytes.fromhex('4c8b7e28'))[-1]
    capture_member = offset32(data, secs, 0x4e359b1, '4881c6', 3)
    destination_pair_offset = checked_instruction(data, secs, 0x4e359d2, bytes.fromhex('410f104610'))[-1]
    checked_instruction(data, secs, 0x4e359d7, bytes.fromhex('4c89642448'))
    checked_instruction(data, secs, 0x4e359dc, bytes.fromhex('0f11442450'))
    checked_instruction(data, secs, 0x4e35a59, bytes.fromhex('488d7c2448'))
    checked_instruction(data, secs, 0x4e4a96f, bytes.fromhex('4c8b27'))
    checked_instruction(data, secs, 0x4e4a972, bytes.fromhex('4c8b7708'))
    checked_instruction(data, secs, 0x4e4a976, bytes.fromhex('4c8b7f10'))
    checked_instruction(data, secs, 0x4e4a989, bytes.fromhex('498b0424'))
    writer_height = checked_instruction(data, secs, 0x4e4a98d, bytes.fromhex('488b4828'))[-1]
    checked_instruction(data, secs, 0x4e35c22, bytes.fromhex('4c8b26'))
    checked_instruction(data, secs, 0x4e35c29, bytes.fromhex('498b3424'))
    expanded_height = checked_instruction(data, secs, 0x4e35c2d, bytes.fromhex('4c8b7e28'))[-1]
    expanded_member = offset32(data, secs, 0x4e35c31, '4881c6', 3)
    checked_instruction(data, secs, 0x4e4ac99, bytes.fromhex('498b0424'))
    expanded_writer_height = checked_instruction(data, secs, 0x4e4ac9d, bytes.fromhex('488b4828'))[-1]
    checked_instruction(data, secs, 0x4e4a996, bytes.fromhex('4889442470'))
    checked_instruction(data, secs, 0x4e4a9a2, bytes.fromhex('488d7c2470'))
    checked_instruction(data, secs, 0x4e4a9a7, bytes.fromhex('4c89f6'))
    checked_instruction(data, secs, 0x4e4a9aa, bytes.fromhex('4c89fa'))
    checked_instruction(data, secs, 0x50dd9ea, bytes.fromhex('4989fc'))
    checked_instruction(data, secs, 0x50ddb0f, bytes.fromhex('4c89e6'))
    checked_instruction(data, secs, 0x5a6e02b, bytes.fromhex('31c04080fd020f95c0'))
    checked_instruction(data, secs, 0x5a6e034, bytes.fromhex('498b0c24'))
    result_height = checked_instruction(data, secs, 0x5a6e038, bytes.fromhex('4c8b4928'))[-1]
    checked_instruction(data, secs, 0x5a6e03c, bytes.fromhex('890424'))
    checked_instruction(data, secs, 0x595ac30, bytes.fromhex('55415741564155415453'))
    frame = offset32(data, secs, 0x595ac3a, '4881ec', 3)
    result_saved = checked_instruction(data, secs, 0x595ac41, bytes.fromhex('4c894c2458'))[-1]
    flag_stack = offset32(data, secs, 0x595ae9d, '0fb68424', 4)
    checked_instruction(data, secs, 0x595aeef, bytes.fromhex('488b4c2458'))
    height_field = checked_instruction(data, secs, 0x595aef4, bytes.fromhex('49894e68'))[-1]
    flag_field = checked_instruction(data, secs, 0x595aef8, bytes.fromhex('41884670'))[-1]
    if len({capture_height, writer_height, expanded_height, expanded_writer_height, result_height}) != 1 or result_saved != 0x58:
        raise ValueError('selected height operand mismatch')
    # Six saved registers plus the call's return word and local frame.
    if flag_stack != frame + 6 * 8 + 8:
        raise ValueError('seventh-argument stack projection differs')
    old_height = out_start + height_field
    old_flag = out_start + flag_field
    lane_src = offset32(data, secs, 0x2cb7ce2, '0f108424', 4)
    lane_dst = offset32(data, secs, 0x2cb7cea, '0f298424', 4)
    q_src = offset32(data, secs, 0x2cb7cd2, '488b8424', 4)
    q_dst = offset32(data, secs, 0x2cb7cda, '48898424', 4)
    height = map_copy(old_height, lane_src, lane_dst, 16, 8)
    flag = map_copy(old_flag, q_src, q_dst, 8, 1)
    src1 = offset32(data, secs, 0x2cb7e6c, '488db424', 4)
    dst1 = offset32(data, secs, 0x2cb7e74, '4c8dbc24', 4)
    n1 = offset32(data, secs, 0x2cb7e7c, 'ba', 1)
    dst2 = offset32(data, secs, 0x2cb7ffe, '488dbc24', 4)
    n2 = offset32(data, secs, 0x2cb8006, 'ba', 1)
    checked_instruction(data, secs, 0x2cb800b, bytes.fromhex('4c89fe'))
    dst3 = offset32(data, secs, 0x2cb8039, '488dbc24', 4)
    src3 = offset32(data, secs, 0x2cb8041, '488db424', 4)
    n3 = offset32(data, secs, 0x2cb8049, 'ba', 1)
    dst4 = offset32(data, secs, 0x2cb806f, '488dbb', 3)
    src4 = offset32(data, secs, 0x2cb8076, '488db424', 4)
    n4 = offset32(data, secs, 0x2cb807e, 'ba', 1)
    if src3 != dst2 or src4 != dst3:
        raise ValueError('copy-stage pointer join differs')
    copies = [(src1, dst1, n1), (dst1, dst2, n2), (src3, dst3, n3), (src4, dst4, n4)]
    projections = []
    for source, destination, length in copies:
        height = map_copy(height, source, destination, length, 8)
        flag = map_copy(flag, source, destination, length, 1)
        projections.append({'source': hex(source), 'destination': hex(destination),
                            'length': hex(length), 'height': hex(height), 'flag': hex(flag)})
    return {
        'prior_parent_result_prefix_base': hex(output_base),
        'pointer_word_relative_to_parent_result': hex(saved - output_base),
        'parent_pointer_stack_slot': hex(pointer_slot), 'parent_result_stack_base': hex(out_start),
        'parent_mode_source_offset': hex(mode_source), 'parent_mode_saved_offset': hex(mode_saved),
        'compact_mismatch_context_cell_offset': hex(mismatch_context_cell),
        'compact_mismatch_cell_stack_offset': hex(mismatch_cell_saved),
        'loader_context_comparison': loader_comparison,
        'config_marker_offset': hex(config_marker_offset), 'config_pointer_offset': hex(config_pointer_offset),
        'config_length_offset': hex(config_length_offset),
        'capture_height_offset': hex(capture_height), 'capture_member_offset': hex(capture_member),
        'expanded_capture_height_offset': hex(expanded_height),
        'expanded_capture_member_offset': hex(expanded_member),
        'snapshot_input_cell_offset': hex(0), 'snapshot_destination_pair_offset': hex(destination_pair_offset),
        'snapshot_pointer_chain': 'startup input cell -> dispatch input -> capture cell -> writer cell -> binary serializer input',
        'result_height_offset': hex(result_height), 'result_record_height_offset': hex(height_field),
        'result_record_flag_offset': hex(flag_field), 'record_callee_frame_size': hex(frame),
        'record_stack_argument_offset': hex(flag_stack), 'record_r9_save_stack_offset': hex(result_saved),
        'parent_lane_source': hex(lane_src), 'parent_lane_destination': hex(lane_dst),
        'parent_flag_source': hex(q_src), 'parent_flag_destination': hex(q_dst),
        'later_copy_stages': projections,
        'limits': 'Conditional static projection: normal calls, the selected no-suspension continuation, stable pointer identity, and no interfering alias writes are required. Only the flag byte is semantically identified.',
    }


def validate_selected_fde_overlap(fdes, selected_ids):
    ordered = sorted((f['start'], f['end'], f['fde']) for f in fdes)
    maximum_earlier_end = -1
    found = set()
    for i, (start, end, identity) in enumerate(ordered):
        if end < start:
            raise ValueError('invalid FDE interval')
        if identity in selected_ids:
            found.add(identity)
            if maximum_earlier_end > start:
                raise ValueError('overlapping earlier FDE')
            if i + 1 < len(ordered) and ordered[i + 1][0] < end:
                raise ValueError('overlapping later FDE')
        maximum_earlier_end = max(maximum_earlier_end, end)
    if found != selected_ids:
        raise ValueError('selected FDE missing from interval set')


def collect(data):
    authenticate(data)
    secs, entries = unwind_index(data)
    _, all_fdes = eh_frame_records(data, secs)
    by_fde = {f['fde']: f for f in all_fdes}
    if len(by_fde) != len(all_fdes):
        raise ValueError('duplicate FDE addresses')
    idx_by_start = {e['start']: e for e in entries}
    if len(idx_by_start) != len(entries):
        raise ValueError('duplicate unwind starts')
    selected = {}
    for role, start, expected_end in FUNCTIONS:
        entry = idx_by_start.get(start)
        f = by_fde.get(entry['fde']) if entry else None
        if f is None or f['start'] != start or f['end'] != expected_end:
            raise ValueError('selected FDE and unwind header disagree')
        if f['end'] > entry['next_index_upper_bound']:
            raise ValueError('selected FDE exceeds next indexed start')
        _, body = read_va(data, secs, start, expected_end - start)
        selected[start] = (role, f, entry, body)
    # Check actual FDE intervals, including long nested earlier intervals.
    validate_selected_fde_overlap(all_fdes, {item[1]['fde'] for item in selected.values()})
    function_rows = []
    lsda_by_start = {}
    for start in sorted(selected):
        role, f, entry, body = selected[start]
        offset, _ = read_va(data, secs, start, len(body))
        lsda_by_start[start] = parse_lsda(data, secs, f)
        function_rows.append([role, hex(start), hex(f['end']), hex(offset), len(body),
                              hex(f['fde']), hex(f['cie']), '' if f['lsda'] is None else hex(f['lsda']),
                              entry['index'], hashlib.sha256(body).hexdigest()])
    window_rows = []
    for label, begin, end, ownership, expected in WINDOWS:
        off, raw = read_va(data, secs, begin, end - begin)
        check_window(raw, expected)
        if ownership == 'new' and not any(s <= begin and end <= f['end'] for s, (_, f, _, _) in selected.items()):
            raise ValueError('new window is outside selected FDEs')
        if ownership not in ('new', 'context'):
            raise ValueError('invalid window ownership')
        window_rows.append([label, ownership, hex(begin), hex(end), hex(off), len(raw), expected, raw.hex()])
    edge_rows, decoded_edges = [], []
    for label, site in TRANSFERS:
        _, raw = read_va(data, secs, site, 6)
        kind, length, target = decode_transfer(site, raw)
        covers = [w for w in WINDOWS if w[1] <= site and site + length <= w[2]]
        if not covers:
            raise ValueError('selected transfer not in a pinned window: ' + label)
        ownership = 'new' if any(w[3] == 'new' for w in covers) else 'context'
        off, insn = read_va(data, secs, site, length)
        edge_rows.append([label, ownership, hex(site), hex(off), insn.hex(), kind, hex(target)])
        decoded_edges.append((label, site, length, kind, ownership))
    needed = set(ANCHOR_SLOTS) | {loc[1] for loc in LOCATIONS}
    relocs = relative_relocations(data, unique_section(secs, '.rela.dyn', 4), needed)
    reloc_rows = []
    for slot, expected in sorted(ANCHOR_SLOTS.items()):
        addend, off, raw = relocs[slot]
        if addend != expected:
            raise ValueError('selected boundary relocation differs')
        slot_off, slot_raw = read_va(data, secs, slot, 8)
        role = {0x64e1050: 'new_config', 0x64e7438: 'context_parent', 0x64ebf70: 'new_result'}[slot]
        reloc_rows.append([role, hex(slot),
                           hex(slot_off), slot_raw.hex(), hex(off), raw.hex(), 8, hex(addend)])
    refs = []
    for label, va, expected in [('loader_context', 0x3c1352f, 0x64767a8),
                                ('compact_writer_call', 0x4e4a99b, 0x649d9c8),
                                ('expanded_writer_call', 0x4e4acab, 0x649d9c8),
                                ('compact_writer_error', 0x4e4abd8, 0x649d9e0),
                                ('expanded_writer_error', 0x4e4aee8, 0x649d9e0)]:
        off, raw, target = lea_target(data, secs, va, (bytes.fromhex('488d0d'), bytes.fromhex('488d15'), bytes.fromhex('4c8d05')))
        if target != expected:
            raise ValueError('Location reference target differs')
        refs.append([label, hex(va), hex(off), raw.hex(), hex(target)])
    literal_rows = []
    for label, va, size, reference in LITERALS:
        ref_off, ref_raw, ref_target = lea_target(data, secs, reference,
                                                  tuple(bytes.fromhex(x) for x in ('488d05', '488d15', '488d35')))
        if ref_target != va:
            raise ValueError('literal reference target differs')
        off, raw = read_va(data, secs, va, size)
        literal_rows.append([label, hex(va), hex(off), len(raw), raw.hex(), hashlib.sha256(raw).hexdigest(),
                             hex(reference), hex(ref_off), ref_raw.hex()])
    lsda_rows, links = [], []
    for start in sorted(selected):
        role, f, _, _ = selected[start]
        rows = lsda_by_start[start]
        for off, begin, end, landing, action, raw in rows:
            lsda_rows.append([role, hex(off), raw.hex(), hex(begin), hex(end),
                              '' if landing is None else hex(landing), action])
        for label, site, length, kind, ownership in decoded_edges:
            if not kind.startswith('call') or not start <= site < f['end']:
                continue
            hit = select_callsite(rows, site, length)
            status = 'no_lsda' if f['lsda'] is None else ('covered' if hit else 'not_in_table')
            links.append([label, role, hex(site), status,
                          '' if hit is None or hit[3] is None else hex(hit[3]),
                          '' if hit is None else hit[4]])
    joins = make_joins(data, secs)
    output = {
        'functions.tsv': tsv(['role', 'start_va', 'end_va_exclusive', 'file_offset', 'length',
                              'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256'], function_rows),
        'windows.tsv': tsv(['label', 'ownership', 'start_va', 'end_va_exclusive', 'file_offset',
                            'length', 'sha256', 'raw_hex'], window_rows),
        'transfers.tsv': tsv(['label', 'ownership', 'va', 'file_offset', 'raw_hex', 'form', 'target_va'], edge_rows),
        'relocations.tsv': tsv(['role', 'slot_va', 'slot_file_offset', 'slot_raw_hex',
                                'relocation_file_offset', 'relocation_raw_hex', 'type', 'addend'], reloc_rows),
        'locations.tsv': tsv(['label', 'va', 'file_offset', 'raw_hex', 'path_va', 'path_file_offset',
                              'path_suffix', 'path_length', 'line', 'column', 'relocation_file_offset',
                              'relocation_raw_hex'], location_rows(data, secs, relocs)),
        'location-refs.tsv': tsv(['label', 'va', 'file_offset', 'raw_hex', 'target_va'], refs),
        'literals.tsv': tsv(['role', 'va', 'file_offset', 'length', 'raw_hex', 'sha256',
                             'reference_va', 'reference_file_offset', 'reference_raw_hex'], literal_rows),
        'unwind.tsv': tsv(['function', 'record_file_offset', 'record_raw_hex', 'start_va',
                           'end_va_exclusive', 'landing_va', 'action_raw'], lsda_rows),
        'unwind-links.tsv': tsv(['transfer', 'function', 'call_va', 'status', 'landing_va', 'action_raw'], links),
        'joins.json': json_bytes(joins),
    }
    summary = {
        'artifact_sha256': TARGET_SHA, 'release': 115,
        'coordinate_system': 'linked ELF virtual addresses before load bias; ends exclusive',
        'selected_fdes': len(function_rows), 'new_windows': sum(w[3] == 'new' for w in WINDOWS),
        'context_windows': sum(w[3] == 'context' for w in WINDOWS), 'selected_transfers': len(edge_rows),
        'locations': len(LOCATIONS), 'location_references': len(refs), 'boundary_relocations': len(reloc_rows),
        'literals': len(literal_rows), 'lsda_rows': len(lsda_rows), 'selected_callsite_links': len(links),
        'generated_evidence_files': len(output) + 1,
        'limitations': 'Selections are not a function census or coverage denominator; no node code is executed.',
    }
    output['summary.json'] = json_bytes(summary)
    return output


def verify_historical(data):
    authenticate(data, HISTORICAL_SHA)
    secs = sections(data)
    address = 0x56dfbf8
    _, raw = read_va(data, secs, address, 24)
    stored, length, line, col = struct.unpack('<QQII', raw)
    reloc = relative_relocations(data, unique_section(secs, '.rela.dyn', 4), {address})[address]
    _, old_path = read_va(data, secs, reloc[0], length)
    if stored != 0 or (length, line, col) != (49, 107, 37) or not old_path.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical Location differs')
    _, _, target = lea_target(data, secs, 0x3273856, (bytes.fromhex('488d0d'),))
    if target != address:
        raise ValueError('historical Location reference differs')
    checked_instruction(data, secs, 0x3273871, bytes.fromhex('4983fd02'))
    return {'release': 94, 'sha256': HISTORICAL_SHA, 'location_va': hex(address),
            'line': line, 'column': col, 'reference_va': hex(0x3273856),
            'comparison_va': hex(0x3273871), 'comparison_immediate': 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical-node', type=Path)
    args = parser.parse_args()
    raw = TARGET.read_bytes()
    files = collect(raw)  # Authenticate and validate before creating output.
    if args.historical_node is not None:
        historical = verify_historical(args.historical_node.read_bytes())
        print(json.dumps(historical, sort_keys=True))
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])
    print('generated ' + str(len(files)) + ' deterministic evidence files')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('abci_loader_checkpoint115: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
