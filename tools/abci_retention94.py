#!/usr/bin/env python3
"""Record selected node 94 post-block retention instructions from ELF bytes."""

import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MAX_U64 = (1 << 64) - 1

# The listed extents are selected questions, not a census of node functions.
# Hashes are of original, unmasked bytes. FDE bounds are independently parsed.
FUNCTIONS = (
    ('low_merge56', 0x1b021c0, 0x1b02585, '0988f23ac0e2ed3d673acd944435bd5b420ff9213075568b7a6750b294346af2'),
    ('low_merge32', 0x1b02980, 0x1b02d32, 'f964d960fb3ce442b7aa7a392212e60ffc325b99c153ed9b73c63eb2bb3c36d8'),
    ('low_count32', 0x1b02d40, 0x1b02e79, '52000584190ff08c4f9feebd05dbbde7b43f5eaa4008d976d3b6341abaf55af0'),
    ('low_count56', 0x1b02fc0, 0x1b030e5, 'fd51027f7e67ab0a5dd3751d2dfd6fda0448a3b67ad79e1af081bf11981c4aaa'),
    ('low_split56', 0x1b030f0, 0x1b03d00, '6dac38eec01cb5b8c13702d673bcf4831bd9b7d59282ca6ba70b77c8ff92ec71'),
    ('low_split32', 0x1b03d00, 0x1b04894, 'bba36e1b5d40e74b111fcc539f3e328725299e0ce33584d07e6c69d0419b3fc7'),
    ('low_drop56', 0x28a9950, 0x28a9a1e, '3d2006ab28b5db09239fbfaf6a2a13232c7df74d33def9b787f9aa3cc213039d'),
    ('shared_merge56', 0x4286680, 0x4286a45, '850584116250f0942743f0fc4a80f3c091c3552171fe17e3f3ca81c07a8f7589'),
    ('shared_merge32', 0x4286a50, 0x4286e02, '0f3faa1d701d2e4c8deec2e066676e922b054c53c1943267048a6692a8a1aaa2'),
    ('shared_count56', 0x4287a40, 0x4287b65, 'fd51027f7e67ab0a5dd3751d2dfd6fda0448a3b67ad79e1af081bf11981c4aaa'),
    ('shared_count32', 0x4287cb0, 0x4287de9, '52000584190ff08c4f9feebd05dbbde7b43f5eaa4008d976d3b6341abaf55af0'),
    ('shared_split32', 0x4288070, 0x4288c04, '2964f7f5eebf570c2ee3550017674cac53ac4476989347833802f4c0dd2d79a3'),
    ('shared_split56', 0x428b270, 0x428be80, 'b0886f62b6df4afb5eca93a0b8420201fb673a23ac41cb07f1d81cfd8b2f4bd7'),
    ('shared_drop56', 0x49ad7a0, 0x49adb79, 'fbe6898a27e0c420454825a2e05def29d1ab6b0690032d0e3a587fa3def92e9d'),
)

# BEGIN_WINDOWS
WINDOWS = (
    ('low_third_update', 0x220aecc, 0x220af9d, 'd948235774efd0679b5b5fea4d07ab2959e11daae58309f5b3905de3e6563e2b'),
    ('low_third_unrolled', 0x220b3ce, 0x220b465, 'd5836da5ccc86d84ce767c314619a940fc48b1820133ee113bb05c39046c0e95'),
    ('primary_third_update', 0x42e4ea8, 0x42e4f69, '13a14fb2cd1a3d941c28080b8047d36f13ba2e21041bb2f096168089d418d757'),
    ('primary_third_unrolled', 0x42e539f, 0x42e542b, 'c4b20e3cca4fb56bd0e3bad42455bb3aff5b7f3516fa973b2854f7919bb5992e'),
    ('secondary_third_update', 0x42e6572, 0x42e6639, 'e09f32a83e7b2548e6ef522dc76482fb9c570d3e5bfe45916bd6b189695cd48e'),
    ('secondary_third_unrolled', 0x42e6a5f, 0x42e6aeb, '669d5951d57b54eb81fdbdb7046110f957e16cd9b16d667744dbfb31ef8ae4e0'),
    ('low_choice', 0x220b3a2, 0x220b3ce, '9b35d4405b000c3e08bb6e809cd316b092650160a447fcffa7c19a37b7b39e74'),
    ('low_max', 0x220b465, 0x220b517, '3153a4af617d29f9cbe2d3b82ed3611969e6c739cf550a39f988db986f1e246d'),
    ('low_unrolled', 0x220b7e2, 0x220b87e, '7685c870e026c03e7d0868b7507f204d8864a95d435d21878eb749c2c0f0b234'),
    ('low_first_two', 0x220b517, 0x220b612, '6406e0a7708b52d12e754beebb36310d6d0b7a603dbcc682406d26951e097574'),
    ('low_third', 0x220b624, 0x220b6d6, 'd6b22739bc033c2a447505f51f211a26834151fe26753fb0ecce2c2a33a6a583'),
    ('primary_choice', 0x42e5372, 0x42e539f, '497cdeaba192de6aaaa795c85beadf9e5c9f2ae48601849981d759c3ee04a226'),
    ('primary_max', 0x42e542b, 0x42e54d3, '6aa563d740b922cc8d3a5c8444ba2fceb82dd318203f2d5cbdda6fa0c21bb9ac'),
    ('primary_unrolled', 0x42e57c0, 0x42e585c, '44747ea5381e2aa057971e4a5ca8fc81895879e14e38110d1822b65d4add3c1e'),
    ('primary_first_two', 0x42e54d3, 0x42e55d1, '53891cc70423abba4267cd8e5d7c76558d6563a4a1f0ab21ebfe0dd20e858649'),
    ('primary_third', 0x42e55e2, 0x42e568d, '61f6b2d9ed688d0e942e595f993475ac85e645955901358c1b5fde7b3beeeb65'),
    ('secondary_choice', 0x42e6a32, 0x42e6a5f, 'b7296d1f841eda6b734fefbe3dbea2f947cccd4a211326eaf465fcf83bba677a'),
    ('secondary_max', 0x42e6aeb, 0x42e6b93, 'fe32ebbb4f9d0882a0774773b03ca5a7b4bd7763d84cbdf4631b8a87a0b12e61'),
    ('secondary_unrolled', 0x42e6e58, 0x42e6eec, 'dc6c7062a8ddc63e15a0f60d92b492e6bc7ac7d6f99826ec14faa728b08053d1'),
    ('secondary_first_two', 0x42e6b93, 0x42e6c91, '9fa2455fec483a433a4ec7e3c0fd7f5474ee1eec5a4c13af5dc400f3496ab2ab'),
    ('secondary_third', 0x42e6ca2, 0x42e6d4d, '36ca552362912a43e0638922d2d964976b0fa8e9a5a1509d0a52174405a5b29b'),
    ('low32_setup', 0x1b03d00, 0x1b03def, '899c0529e6b7ac2876aa9e2d3ba554d80e816d34aba9ffe022f44f0fdaf1f23a'),
    ('low32_search', 0x1b03def, 0x1b03e43, 'bd49056e37e8610e025e49fe03f0a3a5b881828798c3dbd41a3da6ed72b85e73'),
    ('low32_partition', 0x1b03e43, 0x1b03ea0, '4fff58ac24449d4f66abdcb75082a46d750903011fed25f56b780abf60eab2e9'),
    ('low32_repair', 0x1b03f93, 0x1b0408b, '685052c52feefa46128192e77cc18ef1bc25921584bfa218ecfa0f5817409374'),
    ('low32_return_and_fail', 0x1b047f4, 0x1b04894, '33344be3e19015288e1cecfecf7936634def582670c0e022231546019cc52c19'),
    ('shared32_setup', 0x4288070, 0x428815f, '849927de60a1fe8a7071926bac681475ae820014d7f8aaa50a87e09c85974f16'),
    ('shared32_search', 0x428815f, 0x42881b3, 'bd49056e37e8610e025e49fe03f0a3a5b881828798c3dbd41a3da6ed72b85e73'),
    ('shared32_partition', 0x42881b3, 0x4288210, '3dd0e3553785dfb92040d93d0fe45fc7abad1c8b5abfe43eee03a28f8f646aab'),
    ('shared32_repair', 0x4288303, 0x42883fb, '548fea782f6ecd45a6695f9eda10236cf87d5f35933538052781736dfd927813'),
    ('shared32_right_redistribute', 0x42883fb, 0x428842b, '7d5684b5eb4ec15825aae690a7239f4780a3d21c0beb60751aaa52a18520a6e3'),
    ('shared32_repair_nonempty', 0x4288680, 0x42886aa, '21ecf3db749878931f96983bfecafcc240094f900b0d4330ce072fdaa32ea8bd'),
    ('shared32_old_collapse', 0x42886d0, 0x4288706, '98d3490133ccd855bf323e2c67c82415d4f41df5c1a73d6fd8d2d73705dafef6'),
    ('shared32_new_collapse', 0x4288706, 0x4288753, '62bab044743c96bf44803ecca4a252293300c1eef6262545dade4aaea9dad58a'),
    ('shared32_left_repair', 0x4288770, 0x4288818, 'c431bc44e447301232a8e9f3b9822f36d4ae8e6eaa79eef4dd03bbdaffb53a83'),
    ('shared32_left_nonempty', 0x4288b00, 0x4288b1e, '8a2ea592fbd53acef635cccb0e0cdc6aa5f2b91ba505500e99f150b8f8461c82'),
    ('shared32_return_and_fail', 0x4288b64, 0x4288c04, 'e355d96c52a883140e373879c3b69f5cd6290229b30574767c11605b85c00859'),
    ('low56_setup', 0x1b030f0, 0x1b031ce, 'a3305c798680829e6c39cab01b4bc06faa671dc6b9d1207b106cef76cb8c26a4'),
    ('low56_search', 0x1b031ce, 0x1b03222, 'ae02a665016fd8bddc979706fc775a021612b0a0c6d298a468948edc01fa1f36'),
    ('low56_partition', 0x1b03222, 0x1b0327a, '3a0a6c661a1a58cb2b95566ffcb07cf36ce9c9cd357b40022d7d59458e2557fe'),
    ('low56_repair', 0x1b0334f, 0x1b03433, 'c26f8f594c47e3c5f7e5885a1148485bab67af3c9002f479344a799933e31c7a'),
    ('low56_return_and_fail', 0x1b03c60, 0x1b03d00, 'bc81e28411cd821082b301efbf90abe9f6ed37b25798cee652ecb022b0402797'),
    ('shared56_setup', 0x428b270, 0x428b34e, '4616759c7f2d11de1a737ff721e1e047a651da3f401e6d490b681aa5eac1bd6e'),
    ('shared56_search', 0x428b34e, 0x428b3a2, 'ae02a665016fd8bddc979706fc775a021612b0a0c6d298a468948edc01fa1f36'),
    ('shared56_partition', 0x428b3a2, 0x428b3fa, '29c59cf5c6e99c3a8a6b892c994430b9d647cdceedbfec577ba01dd558f8b81b'),
    ('shared56_repair', 0x428b4cf, 0x428b5b3, 'affd5392fa2e77dd46f980d9e1674fc9a17ce3e898ffba409a817e896500b706'),
    ('shared56_return_and_fail', 0x428bde0, 0x428be80, 'f8b25ff7b7b14b8c64dc2bf22219a88feef71327a872e2e7bcf8458f1286dd4a'),
    ('low_count32', 0x1b02d40, 0x1b02e79, '52000584190ff08c4f9feebd05dbbde7b43f5eaa4008d976d3b6341abaf55af0'),
    ('low_count56', 0x1b02fc0, 0x1b030e5, 'fd51027f7e67ab0a5dd3751d2dfd6fda0448a3b67ad79e1af081bf11981c4aaa'),
    ('shared_count32', 0x4287cb0, 0x4287de9, '52000584190ff08c4f9feebd05dbbde7b43f5eaa4008d976d3b6341abaf55af0'),
    ('shared_count56', 0x4287a40, 0x4287b65, 'fd51027f7e67ab0a5dd3751d2dfd6fda0448a3b67ad79e1af081bf11981c4aaa'),
    ('low_merge32_guard', 0x1b02980, 0x1b029b5, '072ed261482d8368df66df1505d7fb575e22b57a132aa10262721b1f31aa6caa'),
    ('low_merge56_guard', 0x1b021c0, 0x1b021fa, 'a8f527aa0df8db81e525b87d86078061498c8fe1fbe2c5b8b1531a84b6ecdd7a'),
    ('shared_merge32_guard', 0x4286a50, 0x4286a85, '072ed261482d8368df66df1505d7fb575e22b57a132aa10262721b1f31aa6caa'),
    ('shared_merge56_guard', 0x4286680, 0x42866ba, 'a8f527aa0df8db81e525b87d86078061498c8fe1fbe2c5b8b1531a84b6ecdd7a'),
    ('low_drop56', 0x28a9950, 0x28a9a03, 'eee05444f9e51811c9ee95f2f7f78e7816698e8adb813d1e4a27a5072ad32135'),
    ('shared_drop56', 0x49ad7a0, 0x49ad87c, '991c519b4238401ce8dd013d5acdff00e7319a99056cc3506264c9066795e7ec'),
    ('low_missing_root', 0x220b987, 0x220b999, '15f5e0aca67207527dd9005142fac73f1b072daaba6e14a54b81ed9cfe7da967'),
    ('primary_missing_root', 0x42e58fc, 0x42e590e, 'e344537a44638ae5b97761cf57cd1d3c78ddb1c43ef33573fc288208458a0ad8'),
    ('secondary_missing_root', 0x42e6f8c, 0x42e6f9e, 'cc975ef6e8401ac8d1c29c68681d29fc21453351ffdbb2b052b024f7efb1e8dd'),
    ('low_missing_root_terminal', 0x220bc3e, 0x220bc40, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('primary_missing_root_terminal', 0x42e5b59, 0x42e5b5b, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('secondary_missing_root_terminal', 0x42e71f9, 0x42e71fb, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('low_checkpoint_gate', 0x220b6d6, 0x220b70d, '797deb628d0a9986610358e2e9b16200d742b2eeaafea440892c4d73c963d156'),
    ('primary_checkpoint_gate', 0x42e568d, 0x42e56c0, 'f2afe672b18f66b7fa721727bb72d06bec998c740e647041ba315e807f211290'),
    ('secondary_checkpoint_gate', 0x42e6d4d, 0x42e6d80, '4e44eecac68354abd4141fa928de9f54510572cf44294b6d856de348e9c6dead'),
)
# END_WINDOWS

# All sites were checked as instruction starts during bounded human review.
# Prior owner functions supply only these previously unreported connecting sites.
BRANCH_SITES = (
    ('low_third_source_empty', 0x220aed7), ('low_third_source_one', 0x220af0c),
    ('low_third_source_unrolled', 0x220af36), ('low_third_source_loop', 0x220af72),
    ('low_third_unrolled_done', 0x220b3fe),
    ('primary_third_source_empty', 0x42e4eb3), ('primary_third_source_one', 0x42e4ee4),
    ('primary_third_source_unrolled', 0x42e4f0e), ('primary_third_source_loop', 0x42e4f42),
    ('primary_third_unrolled_done', 0x42e53ce),
    ('secondary_third_source_empty', 0x42e657d), ('secondary_third_source_one', 0x42e65ae),
    ('secondary_third_source_unrolled', 0x42e65d8), ('secondary_third_source_loop', 0x42e6612),
    ('secondary_third_unrolled_done', 0x42e6a8e),
    ('low_empty_matches', 0x220b3a9), ('low_one_match', 0x220b3bb),
    ('low_empty_32', 0x220b521), ('low_missing_32_root', 0x220b528),
    ('low_empty_56', 0x220b59e), ('low_missing_56_root', 0x220b5a5),
    ('low_third_disabled', 0x220b62b), ('low_empty_third', 0x220b663),
    ('low_missing_third_root', 0x220b669),
    ('primary_empty_matches', 0x42e537a), ('primary_one_match', 0x42e538c),
    ('primary_empty_32', 0x42e54dd), ('primary_missing_32_root', 0x42e54e4),
    ('primary_empty_56', 0x42e555c), ('primary_missing_56_root', 0x42e5563),
    ('primary_third_disabled', 0x42e55ea), ('primary_empty_third', 0x42e561e),
    ('primary_missing_third_root', 0x42e5624),
    ('secondary_empty_matches', 0x42e6a3a), ('secondary_one_match', 0x42e6a4c),
    ('secondary_empty_32', 0x42e6b9d), ('secondary_missing_32_root', 0x42e6ba4),
    ('secondary_empty_56', 0x42e6c1c), ('secondary_missing_56_root', 0x42e6c23),
    ('secondary_third_disabled', 0x42e6caa), ('secondary_empty_third', 0x42e6cde),
    ('secondary_missing_third_root', 0x42e6ce4),
    ('low_release_key_vector_skip', 0x220b6e1), ('low_checkpoint_bypass', 0x220b703),
    ('primary_release_key_vector_skip', 0x42e5698), ('primary_checkpoint_bypass', 0x42e56b6),
    ('secondary_release_key_vector_skip', 0x42e6d58), ('secondary_checkpoint_bypass', 0x42e6d76),
    ('shared32_original_root_nonempty', 0x428832a), ('shared32_original_depth_loop', 0x428835e),
    ('shared32_right_merge_guard', 0x42883b3), ('shared32_right_no_redistribution', 0x42883f5),
    ('shared32_right_empty_failure', 0x428868b), ('shared32_right_depth_loop', 0x428869a),
    ('shared32_old_root_nonempty', 0x42886d8), ('shared32_old_root_collapse_loop', 0x4288704),
    ('shared32_new_depth_zero', 0x4288709), ('shared32_new_root_nonempty', 0x4288718),
    ('shared32_new_root_collapse_loop', 0x428873f), ('shared32_left_merge_guard', 0x428879c),
    ('shared32_left_no_redistribution', 0x42887e4), ('shared32_left_empty_failure', 0x4288b09),
    ('shared32_left_depth_loop', 0x4288b18),
    ('low_count32_depth_choice', 0x1b02d4e), ('low_count32_old_leaf', 0x1b02d61),
    ('low_count32_old_descent', 0x1b02d92), ('low_count32_old_parent_index', 0x1b02da4),
    ('low_count32_old_no_parent', 0x1b02dba), ('low_count32_old_parent_exhausted', 0x1b02dd5),
    ('low_count32_new_leaf', 0x1b02dec), ('low_count32_new_descent', 0x1b02e22),
    ('low_count32_new_parent_index', 0x1b02e34), ('low_count32_new_no_parent', 0x1b02e4a),
    ('low_count32_new_parent_exhausted', 0x1b02e61),
) + tuple((name + '_' + role, base + offset)
          for name, base, offsets in (
              ('low32', 0x1b03d00, (0x2b, 0x4b, 0x6b, 0x125, 0x13d)),
              ('shared32', 0x4288070, (0x2b, 0x4b, 0x6b, 0x125, 0x13d)),
              ('low56', 0x1b030f0, (0x2b, 0x47, 0x6b, 0x115, 0x12c)),
              ('shared56', 0x428b270, (0x2b, 0x47, 0x6b, 0x115, 0x12c)),
          ) for role, offset in zip(('leaf_alloc', 'zero_depth', 'branch_alloc',
                                     'key_loop', 'right_nonempty'), offsets)) + (
    ('low_merge32_capacity', 0x1b029af), ('low_merge56_capacity', 0x1b021f4),
    ('shared_merge32_capacity', 0x4286a7f), ('shared_merge56_capacity', 0x42866b4),
)

DIRECT_CALLS = (
    ('low_split32', 0x220b539, 0x1b03d00), ('low_count32', 0x220b559, 0x1b02d40),
    ('low_old32_drop_boundary', 0x220b576, 0x28abf00),
    ('low_split56', 0x220b5b6, 0x1b030f0), ('low_count56', 0x220b5d6, 0x1b02fc0),
    ('low_old56_drop', 0x220b5f4, 0x28a9950),
    ('low_third_split32', 0x220b67a, 0x1b03d00), ('low_third_count32', 0x220b69a, 0x1b02d40),
    ('low_third_old_drop_boundary', 0x220b6b8, 0x28abf00),
    ('primary_split32', 0x42e54f5, 0x4288070), ('primary_count32', 0x42e5515, 0x4287cb0),
    ('primary_old32_drop_boundary', 0x42e5533, 0x49a8520),
    ('primary_split56', 0x42e5574, 0x428b270), ('primary_count56', 0x42e5594, 0x4287a40),
    ('primary_old56_drop', 0x42e55b2, 0x49ad7a0),
    ('primary_third_split32', 0x42e5635, 0x4288070), ('primary_third_count32', 0x42e5655, 0x4287cb0),
    ('primary_third_old_drop_boundary', 0x42e5673, 0x49a8520),
    ('secondary_split32', 0x42e6bb5, 0x4288070), ('secondary_count32', 0x42e6bd5, 0x4287cb0),
    ('secondary_old32_drop_boundary', 0x42e6bf3, 0x49a8520),
    ('secondary_split56', 0x42e6c34, 0x428b270), ('secondary_count56', 0x42e6c54, 0x4287a40),
    ('secondary_old56_drop', 0x42e6c72, 0x49ad7a0),
    ('secondary_third_split32', 0x42e6cf5, 0x4288070), ('secondary_third_count32', 0x42e6d15, 0x4287cb0),
    ('secondary_third_old_drop_boundary', 0x42e6d33, 0x49a8520),
    ('low32_merge_a', 0x1b0406d, 0x1b02980), ('low32_merge_b', 0x1b0445a, 0x1b02980),
    ('low56_merge_a', 0x1b0342e, 0x1b021c0), ('low56_merge_b', 0x1b0386a, 0x1b021c0),
    ('shared32_merge_a', 0x42883dd, 0x4286a50), ('shared32_merge_b', 0x42887ca, 0x4286a50),
    ('shared56_merge_a', 0x428b5ae, 0x4286680), ('shared56_merge_b', 0x428b9ea, 0x4286680),
    ('low_drop_iterator_boundary', 0x28a99b1, 0x286d9e0),
    ('low_drop_value_boundary', 0x28a99e1, 0x28b0ae0),
    ('shared_drop_iterator_boundary', 0x49ad808, 0x4951230),
    ('low_checkpoint_boundary', 0x220b708, 0x220bed0),
    ('primary_checkpoint_boundary', 0x42e56bb, 0x42e73d0),
    ('secondary_checkpoint_boundary', 0x42e6d7b, 0x42e7980),
)

INDIRECT_CALLS = (
    ('low32_allocate', 0x1b03d22, 0x576dfd8), ('low32_copy', 0x1b03e7f, 0x576dfe0),
    ('low32_alloc_failure', 0x1b0488c, 0x576e020),
    ('low56_allocate', 0x1b03112, 0x576dfd8), ('low56_copy', 0x1b0325a, 0x576dfe0),
    ('low56_alloc_failure', 0x1b03cf8, 0x576e020),
    ('shared32_allocate', 0x4288092, 0x576dfd8), ('shared32_copy', 0x42881ef, 0x576dfe0),
    ('shared32_alloc_failure', 0x4288bfc, 0x576e020),
    ('shared56_allocate', 0x428b292, 0x576dfd8), ('shared56_copy', 0x428b3da, 0x576dfe0),
    ('shared56_alloc_failure', 0x428be78, 0x576e020),
    ('shared32_assertion', 0x4288b8f, 0x576e108),
    ('shared56_assertion', 0x428be0b, 0x576e108),
    ('shared32_old_root_free', 0x4288352, 0x576e010),
    ('shared32_new_root_free', 0x4288733, 0x576e010),
    ('low_missing_root_failure', 0x220b98e, 0x576e470),
    ('primary_missing_root_failure', 0x42e5903, 0x576e470),
    ('secondary_missing_root_failure', 0x42e6f93, 0x576e470),
)

FAILURE_JUMPS = (
    ('low_missing_root', 0x220b994, 0x220bc3e),
    ('primary_missing_root', 0x42e5909, 0x42e5b59),
    ('secondary_missing_root', 0x42e6f99, 0x42e71f9),
)

LITERALS = (
    (0x3b3e3e, b'assertion failed: right_node.len() == 0'),
    (0x3b3cbc, b'assertion failed: len > 0'),
    (0x3b3db9, b'assertion failed: src.len() == dst.len()'),
    (0x3b3fa7, b'assertion failed: new_left_len <= CAPACITY'),
    (0x6ee2de, b'assertion failed: right_node.len() == 0'),
    (0x6ee15c, b'assertion failed: len > 0'),
    (0x6ee259, b'assertion failed: src.len() == dst.len()'),
    (0x6ee447, b'assertion failed: new_left_len <= CAPACITY'),
)

LITERAL_REFS = (
    (0x1b0480c, 0x3b3e3e), (0x1b04837, 0x3b3cbc), (0x1b04850, 0x3b3cbc), (0x1b04869, 0x3b3db9),
    (0x1b03c78, 0x3b3e3e), (0x1b03ca3, 0x3b3cbc), (0x1b03cbc, 0x3b3cbc), (0x1b03cd5, 0x3b3db9),
    (0x4288b7c, 0x6ee2de), (0x4288ba7, 0x6ee15c), (0x4288bc0, 0x6ee15c), (0x4288bd9, 0x6ee259),
    (0x428bdf8, 0x6ee2de), (0x428be23, 0x6ee15c), (0x428be3c, 0x6ee15c), (0x428be55, 0x6ee259),
    (0x1b02d00, 0x3b3fa7), (0x1b02553, 0x3b3fa7), (0x4286dd0, 0x6ee447), (0x4286a13, 0x6ee447),
    (0x1b02d19, 0x3b3db9), (0x1b0256c, 0x3b3db9), (0x4286de9, 0x6ee259), (0x4286a2c, 0x6ee259),
)

# Each field offset comes from the indicated instruction's disp32 operand.
LAYOUT = (
    ('low', 'third_marker_tag', 0x220af8f, '488988', 0x3af8, ''),
    ('low', 'third_marker_value', 0x220af96, '488990', 0x3b00, ''),
    ('primary', 'third_marker_tag', 0x42e4f5b, '49898f', 0x4578, ''),
    ('primary', 'third_marker_value', 0x42e4f62, '498997', 0x4580, ''),
    ('secondary', 'third_marker_tag', 0x42e662b, '49898f', 0x3af8, ''),
    ('secondary', 'third_marker_value', 0x42e6632, '498997', 0x3b00, ''),
    ('low', 'marker_tag', 0x220b4f3, '4889b7', 0x3ae8, ''),
    ('low', 'marker_value', 0x220b508, '488997', 0x3af0, ''),
    ('low', 'first_length', 0x220b517, '4c8bb7', 0x3b38, ''),
    ('low', 'second_length', 0x220b594, '4c8bb0', 0x3b20, ''),
    ('low', 'third_flag', 0x220b624, '80be', 0x3af8, '00'),
    ('low', 'third_value', 0x220b635, '488b82', 0x3b00, ''),
    ('low', 'third_length', 0x220b659, '4c8bb2', 0x3b50, ''),
    ('low', 'checkpoint_tag', 0x220b6fb, '4183be', 0x3ae8, '02'),
    ('primary', 'marker_tag', 0x42e54af, '4989b7', 0x4568, ''),
    ('primary', 'marker_value', 0x42e54c4, '498997', 0x4570, ''),
    ('primary', 'first_length', 0x42e54d3, '4d8bb7', 0x45b8, ''),
    ('primary', 'second_length', 0x42e5552, '4c8bb0', 0x45a0, ''),
    ('primary', 'third_flag', 0x42e55e2, '4180bf', 0x4578, '00'),
    ('primary', 'third_value', 0x42e55f0, '498b87', 0x4580, ''),
    ('primary', 'third_length', 0x42e5614, '4d8bb7', 0x45d0, ''),
    ('primary', 'checkpoint_tag', 0x42e56ae, '4183bf', 0x4568, '02'),
    ('secondary', 'marker_tag', 0x42e6b6f, '4989b7', 0x3ae8, ''),
    ('secondary', 'marker_value', 0x42e6b84, '498997', 0x3af0, ''),
    ('secondary', 'first_length', 0x42e6b93, '4d8bb7', 0x3b38, ''),
    ('secondary', 'second_length', 0x42e6c12, '4c8bb0', 0x3b20, ''),
    ('secondary', 'third_flag', 0x42e6ca2, '4180bf', 0x3af8, '00'),
    ('secondary', 'third_value', 0x42e6cb0, '498b87', 0x3b00, ''),
    ('secondary', 'third_length', 0x42e6cd4, '4d8bb7', 0x3b50, ''),
    ('secondary', 'checkpoint_tag', 0x42e6d6e, '4183bf', 0x3ae8, '02'),
)

LSDA_PINS = {
    'low_split32': (0x968c0c, '084a57254eca4ccde5ce12db21d12f0553670031d838adea35dd86ba87947abb'),
    'low_split56': (0x968bf8, 'f114e947d8799395eb74b3cd52bfae1b1a87c5469ee365a999af88ded2f3f2f7'),
    'shared_split32': (0xb2586c, '084a57254eca4ccde5ce12db21d12f0553670031d838adea35dd86ba87947abb'),
    'shared_split56': (0xb258bc, 'f114e947d8799395eb74b3cd52bfae1b1a87c5469ee365a999af88ded2f3f2f7'),
}


def checked_digest(data, expected=DIGEST):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('node 94 SHA-256 mismatch')
    return actual


def file_offset(secs, va, size):
    """Translate only a unique, allocated, file-backed section interval."""
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid VA interval')
    end = va + size
    if end > 1 << 64:
        raise ValueError('VA interval overflow')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2
               and s['address'] <= va and end <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA interval is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    off = file_offset(secs, va, size)
    result = data[off:off + size]
    if len(result) != size:
        raise ValueError('short file interval')
    return result


def checked_window(data, secs, start, end, expected):
    raw = read_va(data, secs, start, end - start)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('selected byte window differs')
    return raw


def checked_literal(data, secs, va, expected):
    raw = read_va(data, secs, va, len(expected))
    if raw != expected:
        raise ValueError('selected literal differs')
    return raw


def layout_operand(data, secs, site, prefix, expected, suffix):
    pre, post = bytes.fromhex(prefix), bytes.fromhex(suffix)
    raw = read_va(data, secs, site, len(pre) + 4 + len(post))
    if raw[:len(pre)] != pre or raw[len(pre) + 4:] != post:
        raise ValueError('layout instruction form differs')
    value = struct.unpack_from('<I', raw, len(pre))[0]
    if value != expected:
        raise ValueError('layout displacement differs')
    return raw, value


def literal_ref(data, secs, site, expected_va, expected_length):
    raw = read_va(data, secs, site, 25)
    if raw[:3] != b'\x48\x8d\x3d' or raw[7:10] != b'\x48\x8d\x15' or raw[14] != 0xbe:
        raise ValueError('literal reference form differs')
    target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
    context = site + 14 + struct.unpack_from('<i', raw, 10)[0]
    length = struct.unpack_from('<I', raw, 15)[0]
    slot = transfer(raw[19:25], site + 19, indirect=True)
    if target != expected_va or length != expected_length or slot != 0x576e108:
        raise ValueError('literal reference target, length or slot differs')
    return raw, target, context, length, slot


def branch(raw, site):
    """Decode only the specified conditional relative x86 forms."""
    names = {2: 'b', 3: 'ae', 4: 'e', 5: 'ne', 6: 'be', 7: 'a'}
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f and (raw[0] & 15) in names:
        n, disp, cc = 2, struct.unpack_from('<b', raw, 1)[0], raw[0] & 15
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f and (raw[1] & 15) in names:
        n, disp, cc = 6, struct.unpack_from('<i', raw, 2)[0], raw[1] & 15
    else:
        raise ValueError('unsupported branch encoding')
    return n, names[cc], site + n + disp


def transfer(raw, site, indirect=False):
    if indirect:
        if len(raw) != 6 or raw[:2] != b'\xff\x15':
            raise ValueError('expected RIP-relative indirect call')
        return site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('expected rel32 call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def direct_jump(raw, site):
    if len(raw) != 5 or raw[0] != 0xe9:
        raise ValueError('expected rel32 jump')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def relocation_rows(data, secs, slots):
    found = {}
    rs = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(rs) != 1 or rs[0]['size'] % 24:
        raise ValueError('invalid .rela.dyn')
    s = rs[0]
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot in slots:
            if slot in found:
                raise ValueError('duplicate selected relocation')
            found[slot] = (info & 0xffffffff, info >> 32, addend, off)
    if set(found) != set(slots):
        raise ValueError('missing selected relocation')
    expected = {0x576dfd8: (8, 0, 0x54c06b0), 0x576dfe0: (6, 6, 0),
                0x576e010: (8, 0, 0x54c8cb0),
                0x576e020: (8, 0, 0x1345e2a), 0x576e108: (8, 0, 0x157b7f0),
                0x576e470: (8, 0, 0x157a9f0)}
    for slot in slots:
        if found[slot][:3] != expected[slot]:
            raise ValueError('selected relocation differs')
    return found


def lsda_rows(data, secs, fde, pin=None):
    """Selected omitted-base, ULEB call-site tables; actions remain opaque."""
    va = fde['lsda']
    if va is None:
        raise ValueError('missing selected LSDA')
    matches = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing exception section')
    s = matches[0]
    if not s['address'] <= va < s['address'] + s['size']:
        raise ValueError('LSDA outside exception section')
    off = file_offset(secs, va, 4)
    end_section = s['offset'] + s['size']
    if data[off:off + 3] != b'\xff\xff\x01':
        raise ValueError('unsupported LSDA encoding')
    size, pos = uleb(data, off + 3, end_section)
    end = pos + size
    if end > end_section:
        raise ValueError('LSDA call table out of bounds')
    if pin is not None and (va != pin[0] or hashlib.sha256(data[off:end]).hexdigest() != pin[1]):
        raise ValueError('selected LSDA bytes differ')
    rows = []
    while pos < end:
        start, pos = uleb(data, pos, end)
        length, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + length > fde['end'] - fde['start']:
            raise ValueError('LSDA call range outside FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('LSDA landing outside FDE')
        rows.append((fde['start'] + start, fde['start'] + start + length,
                     fde['start'] + landing if landing else 0, action))
    return rows


def table(header, rows):
    output = io.StringIO(newline='')
    w = csv.writer(output, delimiter='\t', lineterminator='\n')
    w.writerow(header)
    w.writerows(rows)
    return output.getvalue().encode('utf-8')


def analyze(data, *, verify_sha=True):
    if verify_sha:
        checked_digest(data)
    secs = sections(data)
    _, unwind = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    by_start = {}
    for fde in records:
        by_start.setdefault(fde['start'], []).append(fde)
    indexed = {}
    for row in unwind:
        indexed.setdefault(row['start'], []).append(row)
    functions = []
    selected = {}
    bodies = {}
    for name, start, end, expected in FUNCTIONS:
        fs, ix = by_start.get(start, []), indexed.get(start, [])
        if len(fs) != 1 or len(ix) != 1:
            raise ValueError('selected FDE or index not unique')
        fde = fs[0]
        if fde['end'] != end or ix[0]['fde'] != fde['fde']:
            raise ValueError('selected FDE/index mismatch')
        raw = checked_window(data, secs, start, end, expected)
        bodies[name] = raw
        selected[name] = fde
        functions.append((name, hex(start), hex(end), end - start,
                          hex(file_offset(secs, start, end - start)), hex(fde['fde']),
                          hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] else '',
                          expected, raw.hex()))
    windows = []
    for name, start, end, expected in WINDOWS:
        raw = checked_window(data, secs, start, end, expected)
        windows.append((name, hex(start), hex(end), hex(file_offset(secs, start, end - start)),
                        end - start, expected, raw.hex()))
    branches = []
    for name, site in BRANCH_SITES:
        raw = read_va(data, secs, site, 6)
        n, condition, target = branch(raw, site)
        branches.append((name, hex(site), hex(file_offset(secs, site, n)),
                         raw[:n].hex(), condition, hex(site + n), hex(target)))
    calls = []
    for name, site, expected in DIRECT_CALLS:
        raw = read_va(data, secs, site, 5)
        target = transfer(raw, site)
        if target != expected:
            raise ValueError('direct call target differs')
        calls.append((name, hex(site), hex(file_offset(secs, site, 5)), 'rel32', raw.hex(), hex(target)))
    slots = set()
    for name, site, expected in INDIRECT_CALLS:
        raw = read_va(data, secs, site, 6)
        target = transfer(raw, site, indirect=True)
        if target != expected:
            raise ValueError('indirect call slot differs')
        slots.add(target)
        calls.append((name, hex(site), hex(file_offset(secs, site, 6)), 'rip-slot', raw.hex(), hex(target)))
    jumps = []
    for name, site, expected in FAILURE_JUMPS:
        raw = read_va(data, secs, site, 5)
        target = direct_jump(raw, site)
        if target != expected or read_va(data, secs, target, 2) != b'\x0f\x0b':
            raise ValueError('failure jump or terminal bytes differ')
        jumps.append((name, hex(site), hex(file_offset(secs, site, 5)), raw.hex(), hex(target), '0f0b'))
    rels = relocation_rows(data, secs, slots)
    relocations = [(hex(slot), hex(rels[slot][3]), rels[slot][0], rels[slot][1],
                    hex(rels[slot][2]) if rels[slot][2] >= 0 else str(rels[slot][2]))
                   for slot in sorted(rels)]
    literals = []
    for va, expected in LITERALS:
        actual = checked_literal(data, secs, va, expected)
        literals.append((hex(va), hex(file_offset(secs, va, len(actual))), len(actual), actual.decode('ascii')))
    literal_sizes = {va: len(value) for va, value in LITERALS}
    refs = []
    for site, target in LITERAL_REFS:
        raw, addr, context, size, slot = literal_ref(data, secs, site, target, literal_sizes[target])
        refs.append((hex(site), hex(file_offset(secs, site, len(raw))), raw.hex(), hex(addr),
                     size, hex(context), hex(slot)))
    layout = []
    for lane, field, site, prefix, expected, suffix in LAYOUT:
        raw, value = layout_operand(data, secs, site, prefix, expected, suffix)
        layout.append((lane, field, hex(site), hex(file_offset(secs, site, len(raw))), raw.hex(), hex(value)))
    lsda = []
    for name in ('low_split32', 'low_split56', 'shared_split32', 'shared_split56'):
        fde = selected[name]
        for index, (start, end, landing, action) in enumerate(lsda_rows(data, secs, fde, LSDA_PINS[name])):
            lsda.append((name, hex(fde['lsda']), index, hex(start), hex(end),
                         hex(landing) if landing else '', action))
    comparisons = {}
    for a, b in (('low_count32', 'shared_count32'), ('low_count56', 'shared_count56')):
        comparisons[a + '__' + b] = {'left_bytes': len(bodies[a]), 'right_bytes': len(bodies[b]),
                                     'raw_equal': bodies[a] == bodies[b], 'normalization_masks': []}
        if bodies[a] != bodies[b]:
            raise ValueError('paired count bodies differ')
    files = {
        'functions.tsv': table(('name', 'start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va',
                                'lsda_va', 'sha256', 'body_hex'), functions),
        'windows.tsv': table(('name', 'start_va', 'end_va', 'file_offset', 'size', 'sha256', 'bytes'), windows),
        'branches.tsv': table(('name', 'site_va', 'file_offset', 'bytes', 'condition', 'fallthrough_va', 'target_va'), branches),
        'calls.tsv': table(('name', 'site_va', 'file_offset', 'form', 'bytes', 'target_or_slot_va'), calls),
        'failure-jumps.tsv': table(('name', 'site_va', 'file_offset', 'bytes', 'target_va', 'terminal_bytes'), jumps),
        'relocations.tsv': table(('slot_va', 'entry_file_offset', 'type', 'symbol_index', 'addend'), relocations),
        'literals.tsv': table(('va', 'file_offset', 'length', 'ascii'), literals),
        'literal-refs.tsv': table(('site_va', 'file_offset', 'bytes', 'literal_va', 'length', 'context_va', 'call_slot_va'), refs),
        'lane-layout.tsv': table(('lane', 'field', 'site_va', 'file_offset', 'bytes', 'field_offset'), layout),
        'lsda.tsv': table(('function', 'lsda_va', 'row', 'call_start_va', 'call_end_va', 'landing_va', 'action'), lsda),
    }
    summary = {'schema': 'abci-retention-94/v1', 'target_sha256': DIGEST,
               'coordinates': 'ELF link-time virtual addresses; file offsets separate; ends exclusive',
               'selected_counts': {'functions': len(functions), 'windows': len(windows),
                                   'branches': len(branches), 'calls': len(calls),
                                   'failure_jumps': len(jumps),
                                   'relocations': len(relocations), 'literals': len(literals),
                                   'literal_refs': len(refs), 'layout_operands': len(layout),
                                   'lsda_rows': len(lsda)},
               'raw_comparisons': comparisons,
               'limitations': 'Selected fixed sites only; FDEs do not prove complete function boundaries. '
                              'No unlisted indirect targets, runtime reachability, Rust types or full CFG claimed.'}
    files['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8')
    return files


def _u64(x):
    if type(x) is not int or not 0 <= x <= MAX_U64:
        raise ValueError('expected u64')
    return x


def cutoff_model(instructions, candidate, old_tag, old_value):
    """Synthetic selected-instruction model; inputs are raw u64 words."""
    expected = bytes.fromhex('4839d0400f92c64084f1480f44d0be01000000480f45f1'
                             '4989b7e83a000048ffc048c7c1ffffffff480f45c8')
    if instructions != expected:
        raise ValueError('cutoff instruction signature differs')
    candidate, old_tag, old_value = map(_u64, (candidate, old_tag, old_value))
    keep_old = bool(old_tag & 1) and candidate < old_value
    tag = old_tag if keep_old else 1
    value = old_value if keep_old else candidate
    cutoff = candidate + 1 if candidate != MAX_U64 else MAX_U64
    return tag, value, cutoff


def max_key_model(instructions, keys):
    """Synthetic unsigned maximum for the selected nonempty key-vector path."""
    if instructions != bytes.fromhex('488b3a4839f9480f46cf480f46f24883c20848ffc875e9'):
        raise ValueError('maximum loop instruction signature differs')
    if not keys:
        return None
    best = _u64(keys[0])
    for value in keys[1:]:
        value = _u64(value)
        if best <= value:
            best = value
    return best


def header_gate_model(instructions, root, count):
    """Synthetic count and root decisions at the selected first-map gate."""
    if instructions != bytes.fromhex('4d85f6744c49837d00000f84e2030000'):
        raise ValueError('header gate instruction signature differs')
    root, count = _u64(root), _u64(count)
    if count == 0:
        return 'empty'
    return 'missing-root' if root == 0 else 'split'


def third_gate_model(instructions, raw_flag):
    if instructions != bytes.fromhex('4180bff83a0000000f849d000000'):
        raise ValueError('third-map gate instruction signature differs')
    return bool(_u64(raw_flag) & 0xff)


def third_source_model(loop_bytes, update_bytes, records, old_tag, old_value):
    """Synthetic third-map marker and cutoff for 88-byte source records."""
    if loop_bytes != bytes.fromhex('4e8b0c064c39ca490f46d14983c0584c39c775ec'):
        raise ValueError('third-source loop signature differs')
    if update_bytes != bytes.fromhex('4839ca400f92c64084f0480f45d1b901000000480f45c8'):
        raise ValueError('third-source update signature differs')
    old_tag, old_value = map(_u64, (old_tag, old_value))
    if not isinstance(records, bytes) or len(records) % 88:
        raise ValueError('invalid third-source record bytes')
    tag, value = old_tag, old_value
    if records:
        maximum = max(struct.unpack_from('<Q', records, i)[0] for i in range(0, len(records), 88))
        if not (old_tag & 1 and maximum < old_value):
            tag, value = 1, maximum
    enabled = bool(tag & 0xff)
    cutoff = min(value + 1, MAX_U64) if enabled else None
    return tag, value, enabled, cutoff


def checkpoint_gate_model(instructions, raw_tag):
    if instructions != bytes.fromhex('4183bfe83a0000027408'):
        raise ValueError('checkpoint gate instruction signature differs')
    return (_u64(raw_tag) & 0xffffffff) != 2


def leaf_model(instructions, keys, cutoff):
    """Synthetic depth-zero ordered-node model; no allocator or target executes."""
    if instructions != bytes.fromhex('4c3b7cd0084c89f277e9'):
        raise ValueError('leaf search instruction signature differs')
    cutoff = _u64(cutoff)
    if len(keys) > 11 or any(_u64(x) != x for x in keys):
        raise ValueError('invalid leaf')
    if any(a >= b for a, b in zip(keys, keys[1:])):
        raise ValueError('keys must be sorted and distinct')
    index = 0
    while index < len(keys) and cutoff > keys[index]:
        index += 1
    return tuple(keys[:index]), tuple(keys[index:])


def leaf_record_model(search, copy_setup, records, cutoff):
    """Synthetic leaf split with opaque fixed-width values and no aliasing."""
    widths = {
        bytes.fromhex('4c89f648c1e6054801ee4c89ea48c1e2054c89e7'): 32,
        bytes.fromhex('496bc638488d34284883c660498d7d60496bd438'): 56,
    }
    width = widths.get(bytes(copy_setup))
    if width is None:
        raise ValueError('value copy instruction signature differs')
    if any(not isinstance(value, bytes) or len(value) != width for _, value in records):
        raise ValueError('invalid opaque value width')
    before, _ = leaf_model(search, [key for key, _ in records], cutoff)
    index = len(before)
    return tuple(records[:index]), tuple(records[index:])


def merge_gate(instructions, left, right):
    """Synthetic comparison at the selected sibling-merge guard."""
    if instructions != bytes.fromhex('4883fa0c'):
        raise ValueError('merge comparison instruction signature differs')
    if type(left) is not int or type(right) is not int or not 0 <= left <= 11 or not 0 <= right <= 11:
        raise ValueError('invalid sibling length')
    return left + 1 + right < instructions[-1]


def repair32_model(merge_bytes, minimum_bytes, write_bytes, side, left, right):
    """Model only the pinned shared 32-byte sibling-count repair decisions."""
    patterns = {
        'right': (
            '418d041cffc083f80c733b',
            '664183fc050f8785020000',
            '41bf060000004d29e74989de4d29fe664489b1c20100006641c785c20100000600',
        ),
        'left': (
            '418d143683fa0c7342',
            '6683fb050f8716030000',
            'b9060000004829d948890c2448897424384c896424084989f44929cc'
            '6641c785c20100000600664489a5c2010000',
        ),
    }
    if side not in patterns or (merge_bytes, minimum_bytes, write_bytes) != tuple(
            bytes.fromhex(raw) for raw in patterns[side]):
        raise ValueError('repair instruction signature differs')
    if type(left) is not int or type(right) is not int or not 0 <= left <= 11 or not 0 <= right <= 11:
        raise ValueError('invalid sibling length')
    if left + right + 1 < 12:
        return 'merge', left, right
    short = right if side == 'right' else left
    if short >= 6:
        return 'unchanged', left, right
    moved = 6 - short
    if side == 'right':
        return 'redistribute', left - moved, 6
    return 'redistribute', 6, right - moved


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args(argv)
    with TARGET.open('rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            files = analyze(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_retention94:', error, file=sys.stderr)
        raise SystemExit(1)
