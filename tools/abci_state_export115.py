#!/usr/bin/env python3
"""Reproduce selected node-115 state read, serialization and output evidence."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Exact release-specific FDE starts, ends, records and unmodified body hashes.
FDE_PINS = [
    (0x2cd8370, 0x2cd83af, 0xd8be0c, 'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e58ba0565f592ba2b60d6'),
    (0x2ae1690, 0x2ae27b2, 0x117c394, '6ca0595c13836bca0cb0173bd591a09d6da6791532e23a5a71c63715380727d9'),
    (0x2b404b0, 0x2b40666, 0x118342c, '05ef87dc8cdf209d34d246b129dfe209764fe409efda8ee0ad73ceebb54fedac'),
    (0x2ae41e0, 0x2ae6d66, 0x117c49c, '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b758f8e2f2ac880545b730b'),
    (0x2cde430, 0x2ce0dd1, 0x11986ac, '99c49a3e20f63cf199f2a160ba9560e439acb2b49a66968623aa9607acfa417b'),
    (0x422ed40, 0x422f024, 0x1298290, '342d6aadcf5a7c06f5505911c9b6fa49a44993e78139adefff1a5ba21c11f52b'),
    (0x3c136f0, 0x3c13955, 0xe51138, 'd9d11e73ebaaf255a2cd2eb29f605331060fc5451543dbdcde25434b540a75a8'),
    (0x3c13960, 0x3c154c1, 0xe51184, '290b189680a9d08a432c8da1c696f5975e6aa88d33bef5d40eb40248ae43d54d'),
    (0x159fca0, 0x159fde1, 0xcb9990, 'ac11f05bed149a170fada78c896cfb163aa669eacdd14aa19f2e3b4132e66574'),
    (0x15020f0, 0x15021c2, 0xcb139c, 'f9381117b20db7c810572e47e140e5d2002c87ac79d3c8464734356aca020cd1'),
    (0x15024a0, 0x15026d1, 0x104b114, 'c6dde6a5bd3291ee39eeeb72b131d975272458eef151ec90ee8f2c3325bed742'),
    (0x3d4f6d0, 0x3d4f999, 0xe5e32c, 'c91d8474029221bb365f3c8eac4ff8d8137d66208a4c6104bbaea9eb5c56bda3'),
    (0x3d52310, 0x3d5235e, 0xe5e7b4, '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa'),
    (0x5ca5110, 0x5ca53a1, 0x13cd658, '523e9330a90fad9aff9b186750ada9dcff7ced1ba020b16a2125755d37d9c1cf'),
]

# Selected instruction-aligned windows, bounded and hashed without masks.
WINDOWS = [
    ('outer_entry', 0x2cd8395, 0x2cd83af, '76c6991e6b1812e6b2c567965d8a14f3ec5f11b2315bd732b3b8b4c5a7a18e77'),
    ('parent_choose', 0x2ae18cb, 0x2ae18df, 'ef885aa845e24906410a5d853958c2b1adea0e5378b168b59751d5b82d178992'),
    ('parent_poll_a', 0x2ae1a32, 0x2ae1a73, 'b44c10193eae94f8db27fbb815637ad5a3634cf5f962a72b691df676e3a24142'),
    ('parent_poll_a_done', 0x2ae1aa0, 0x2ae1ad1, '890ef1c87e0ddeb61797a55f4c159b524ba634395a48deabd772abfc1caa520f'),
    ('parent_done_a', 0x2ae1d46, 0x2ae1d72, 'd5d26e3f16d575a02bc4dc0362c49bb13e67d7ad30697d27c8f0b0854e71eb88'),
    ('parent_poll_b', 0x2ae1ed2, 0x2ae1f18, '71a76b670a3b94be7f1f0fbc5225907631c76f78fe32689a39b5518f46199ea2'),
    ('parent_poll_b_done', 0x2ae1f50, 0x2ae1f63, '599f215ed427027bd823dee5048e99c569d4978d15a0044c3866aa9ef1c58ae5'),
    ('parent_done_b', 0x2ae2010, 0x2ae2027, '6c3e8e296f765f30e511cbb6494bd263d863daa7f9d62dcd6a781fecf0f7a910'),
    ('a_state_dispatch', 0x2ae41f1, 0x2ae420b, '42821ba97fccce659e2ba95cb92477790a28e624cdacbf64fe01ed84f358acb0'),
    ('a_command_dispatch', 0x2ae4586, 0x2ae45b7, '2ec849317c5d22b4e2440175f37a7e0d0795fdd57eef67c21b509e5f78eb854c'),
    ('a_read_write', 0x2ae4ebc, 0x2ae4f55, 'bbe65f7fda06eecd6220a2e56e5060349e4d251ae06004b8f6ce6839a32306d9'),
    ('a_success_cleanup', 0x2ae50a5, 0x2ae50d4, 'ff317c6bf9b457f1d2b4725bb0b3b072d36fa733e7845393e8e225a571b5a41f'),
    ('a_finish', 0x2ae5df4, 0x2ae5e75, 'dbef39c0d42740c2aa2c1e7d2e9431e7214c2652b0f93b0f0f2266bb312785cf'),
    ('a_failure', 0x2ae5f3c, 0x2ae5fa6, '9544cae1ff5eefd1e8814dab434cf5e29f7df25e3b74e1ec86fb1f30cc1107f7'),
    ('a_terminal', 0x2ae6348, 0x2ae634a, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('b_state_dispatch', 0x2cde495, 0x2cde4b0, '774a94c064138a8d687b9b91a45a62cfb73f0bd54ac2fc59ee4eee1c1f611c55'),
    ('b_command_dispatch', 0x2cde64b, 0x2cde67c, '13e064481a53a28cb10a826decfc9442c1c6452989f42e2c51aa203c041141c3'),
    ('b_read_write', 0x2cdefb5, 0x2cdf051, 'be220ca66cf00068105fc4ff3970950167d930ef0f4e306438b110e1d4b7d3b5'),
    ('b_success_cleanup', 0x2cdf1a3, 0x2cdf1bb, '6674787fde060e926f379db6554047e0e751c44e47647cb5b99cc660aec8f720'),
    ('b_finish', 0x2cdfece, 0x2cdff3d, 'b95cd00bd3ba3fafbc6d6f833d9335f0f9bd5bd21c3808aa0f3a12a2fc90fb67'),
    ('b_failure', 0x2cdfff8, 0x2ce0062, 'ea87655862eb4b9ac8d2bf50fbc2bf35cdcb5f85b36b1c222f9ff071d22476c6'),
    ('b_terminal', 0x2ce03da, 0x2ce03dc, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('writer_route', 0x422ed51, 0x422ee3d, '013c18604230daf0fe99b4d27ce83c71bcdc3b69326de5fe49532e36cbcf9b70'),
    ('writer_binary', 0x422ee3d, 0x422eeae, '2a2d8c1b8b4e52f5d8bdb351744a64e776dedd6d4395b77c7feb9b555905dab3'),
    ('writer_text', 0x422eeae, 0x422ef26, 'f8fac263d4dd2a6a34c8d6dd0f9e164b66192b883f8267a36deb339e8ddd94ce'),
    ('writer_commit', 0x422ef26, 0x422efe1, '94512d7acd4ab78a222f504814a511b60ca1df96840b4e1511525bfc6347f352'),
    ('writer_alloc_failure', 0x422efe1, 0x422eff3, '6830a36a1bd193aa1fc69db200f243c1626f15b221039aacbe45cc67288bb30f'),
    ('fold_entry', 0x159fca0, 0x159fcb3, '1793c03701e22a67ebfcfcbe583d8fac325527346663197e8b75a377cf0e824b'),
    ('fold_scalar', 0x159fd98, 0x159fde1, 'd9ed983b4b943690c6f821cfd677e8e5bc7c98bc9612a6c13eed47a787a1aa24'),
    ('text_prefix', 0x3c136fa, 0x3c137a9, '57910dbfe48a34a9172ef20e65578c8efa5dfa95205cd480db0509953c8bd79c'),
    ('text_finish', 0x3c137a4, 0x3c1387a, '24a50e60f1b1f983f6bf3c368675e926817ef83eb616078febebb083dea2010b'),
    ('binary_header', 0x3c13977, 0x3c13aee, 'f0d1a52f5d8323a25f1b31b1d3c9b6b7fc7d4eecc6ffa81cad8abe47c183ce27'),
    ('field_cls', 0x3c13b08, 0x3c13b46, '71f9a7d629fe81100b14cf79bd88bc34166bdcc9231c9715501b42085ddb1915'),
    ('field_spot_infos', 0x3c13c0e, 0x3c13c40, 'cc3226baf16b8d3d8d871eebcc595ce8f601d755278771dc17d5869296cf1619'),
    ('field_token_infos', 0x3c13c55, 0x3c13c93, '5d6edb759030acb664fce15652b5425723bf9007e98bb7288143c49b13c9dd8a'),
    ('field_canonical', 0x3c13dbb, 0x3c13ded, 'acf6c79ddfe2cc8bd9c9a0366944d66418a48ac0e054a3117ada4294cc98138f'),
    ('field_duplicate', 0x3c13dfb, 0x3c13e3e, '41ce6e141ac00a2bcf1745db0d8beb6c6a799b1e155b64fba9fb04e469bff1b7'),
    ('field_fee', 0x3c14437, 0x3c14469, '2f5640e0a46054afeb59b55b93372d6c2cbe63dde2b41d9fe266ffa5cee1c39b'),
    ('field_unrewarded', 0x3c1447e, 0x3c144b0, 'f622fa5fa1849780714474ef24aee0665f29d280c2899dad9f0db6a9b599f261'),
    ('field_users', 0x3c144c5, 0x3c144f7, 'a12c6de87ba91750a73a3accc53ccfa3b94f41878ecbe8f369719eb4f4b051cc'),
    ('field_agent', 0x3c14a6c, 0x3c14a9e, '4034e7dc58bd4942e20e262f77cb8550bbbcbcb32b0d40f8ff4b3aaac480d134'),
    ('field_nonces', 0x3c14b41, 0x3c14b73, '3dfcee1eb7cb993304066420ebd89f0c487c48330b8f611936bc711122fad148'),
    ('prepare', 0x15020fd, 0x15021c2, '568f105bcfec622a9868dcc5e510ce40b46501240aa05d06e7a8e19060e6b967'),
    ('publish_a', 0x15024b1, 0x150257f, '3a69be39b6b612c641cdc6343fe45417f3409ce8863667e48fcff97a0c31b872'),
    ('publish_b', 0x150257f, 0x150267e, '8689750e387a17a8adea804ea3803013faedd4bae1890da1a46a816f78515fc3'),
    ('publish_unwind', 0x150268d, 0x15026d1, '432cc58a73f427f426b3cbc8ba8da20f5922fa11165cde0fd82836e53103398f'),
    ('map_marker', 0x3d4f6de, 0x3d4f75b, '1658ab48d926afb583f963dc0a9d1761cf5dcbf06fda049c527c8ede382f2961'),
    ('map_u16', 0x3d4f7de, 0x3d4f7f3, 'eee2021a2febb3f04d28ee7fd02d2dc54617679761384dbf3e54fb3d03658d20'),
    ('map_failure', 0x3d4f814, 0x3d4f82b, '369ade4d7e19bf5d1b83b648601a6769ff340050a300d23498b8d918e821414f'),
    ('map_result', 0x3d4f844, 0x3d4f865, 'd5741aaff165c46e3e0d2e7ab1bb143a41d3d8a25441ff1352b752fa68461ceb'),
    ('pack_marker', 0x3d52310, 0x3d5235e, '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa'),
    ('a_parent_copy', 0x2ae19b7, 0x2ae19da, '1264eafe0d4d2fee355a5d23f7b8b81acdc9fc4e242cdee7847a87ead2bc9be1'),
    ('io_setup', 0x5ca5124, 0x5ca515f, '09138855001e2518e46344dbc4e8a96725628e582a8de2b033381e0dd313d4ba'),
    ('io_open_results', 0x5ca5267, 0x5ca52c6, '7468978bd97c334981c4a435210afdb016187d071147a7f5d99034aebc0db1db'),
    ('io_write_loop', 0x5ca52c6, 0x5ca5355, '1bc7825f07ae6538babcf5ca1ce7e1aab9d8d5f12d3b1881cc8bf00379ccb209'),
    ('io_exits', 0x5ca5355, 0x5ca53a1, 'f6ce34dbcb17b639f8e215c312db7853c997aa6f3c9e5f6b4df4e15ea20d58d7'),
    ('b_entry_guard', 0x2cde441, 0x2cde495, '2589d707e84af4e02063283722831ba8a4daaab8faeb43bfb1fbfff6166ff3d0'),
    ('alt_guard', 0x2b404b0, 0x2b40538, 'd9758b7fd6b2463f37da37b7f064b14205df042bc58c4ad75663bfdef452f0e1'),
    ('alt_poll', 0x2b40538, 0x2b405be, '4433aa48dfec88640785a0b2be40dcca0e95f71f928efd53d6c9691847951ad2'),
    ('alt_result', 0x2b405b8, 0x2b40619, 'faba5f0177f202602f9b874460b3980dbc87ab86a946c4cfd7f059059dd70e5b'),
    ('a_after_write', 0x2ae4f55, 0x2ae50a5, 'ca62d2c9435ac8ae4fb50e079f25439887255d299824267c9e01250228cf301c'),
    ('b_after_write', 0x2cdf051, 0x2cdf1a3, '144b54b2ab5ce9c98ef5927de09b8ee55c496d15f88fde846747687443f9a157'),
]

# Instruction sites selected by bounded manual inspection. Targets below are
# checked after decoding the displacements; they are not a caller census.
EDGE_PINS = [
    ('outer_to_parent', 0x2cd83a2, 0x2ae1690, 'e8'),
    ('parent_select', 0x2ae18d9, 0x2ae1b0a, '0f85'),
    ('parent_poll_a', 0x2ae1a47, 0x2ae41e0, 'e8'),
    ('parent_a_pending', 0x2ae1a6c, 0x2ae1ab2, '75'),
    ('parent_a_done', 0x2ae1a6e, 0x2ae1d46, 'e9'),
    ('parent_poll_b', 0x2ae1eeb, 0x2cde430, 'e8'),
    ('parent_b_pending', 0x2ae1f11, 0x2ae1f63, '74'),
    ('parent_b_done', 0x2ae1f13, 0x2ae2010, 'e9'),
    ('a_read_boundary', 0x2ae4f0b, 0x422e410, 'e8'),
    ('a_read_failure', 0x2ae4f15, 0x2ae5f3c, '0f85'),
    ('a_write', 0x2ae4f3f, 0x422ed40, 'e8'),
    ('a_write_failure', 0x2ae4f47, 0x2ae5f71, '0f85'),
    ('a_drop_state', 0x2ae4f50, 0x2a9ff60, 'e8'),
    ('a_failure_read', 0x2ae5f6c, 0x2ae6348, 'e9'),
    ('a_failure_write', 0x2ae5fa1, 0x2ae6348, 'e9'),
    ('b_read_boundary', 0x2cdf007, 0x422e410, 'e8'),
    ('b_read_failure', 0x2cdf011, 0x2cdfff8, '0f85'),
    ('b_write', 0x2cdf03b, 0x422ed40, 'e8'),
    ('b_write_failure', 0x2cdf043, 0x2ce002d, '0f85'),
    ('b_drop_state', 0x2cdf04c, 0x2c86fc0, 'e8'),
    ('b_failure_read', 0x2ce0028, 0x2ce03da, 'e9'),
    ('b_failure_write', 0x2ce005d, 0x2ce03da, 'e9'),
    ('sink_length_differs', 0x422ed6e, 0x422ed92, '75'),
    ('sink_byte_differs', 0x422ed89, 0x422ed97, '75'),
    ('sink_returns', 0x422ed8d, 0x422ef6a, 'e9'),
    ('path_parser', 0x422edc7, 0x64e0938, 'ff15'),
    ('path_tag_other', 0x422edd1, 0x422eeae, '0f85'),
    ('two_dots', 0x422edec, 0x422eeae, '0f84'),
    ('no_dot', 0x422ee03, 0x422eeae, '0f84'),
    ('find_dot_loop', 0x422ee17, 0x422ee00, '75'),
    ('leading_dot', 0x422ee1c, 0x422eeae, '0f84'),
    ('extension_compare', 0x422ee34, 0x159fca0, 'e8'),
    ('extension_other', 0x422ee3b, 0x422eeae, '74'),
    ('binary_serializer', 0x422ee82, 0x3c13960, 'e8'),
    ('binary_error', 0x422ee9d, 0x422efa1, '0f85'),
    ('text_allocate', 0x422eeb3, 0x64df480, 'ff15'),
    ('text_alloc_error', 0x422eebc, 0x422efe1, '0f84'),
    ('text_serializer', 0x422ef08, 0x3c136f0, 'e8'),
    ('text_error', 0x422ef13, 0x422ef7c, '75'),
    ('text_sentinel', 0x422ef24, 0x422ef92, '70'),
    ('prepare_output', 0x422ef31, 0x64e0028, 'ff15'),
    ('prepare_failed', 0x422ef3a, 0x422ef51, '75'),
    ('output_publish', 0x422ef4b, 0x64e09e8, 'ff15'),
    ('release_output', 0x422ef61, 0x64df4a0, 'ff15'),
    ('binary_error_wrap', 0x422efda, 0x422f740, 'e8'),
    ('text_error_wrap', 0x422ef9a, 0x422f670, 'e8'),
    ('outer_map_header', 0x3c13994, 0x3d4f6d0, 'e8'),
    ('outer_array_header', 0x3c139ca, 0x3d50270, 'e8'),
    ('state_header', 0x3c13a16, 0x3d4f6d0, 'e8'),
    ('text_state', 0x3c13796, 0x3c2f460, 'e8'),
    ('prepare_probe', 0x1502178, 0x64e0928, 'ff15'),
    ('prepare_already', 0x1502180, 0x15021a5, '75'),
    ('prepare_create', 0x150219a, 0x64e0940, 'ff15'),
    ('prepare_create_error', 0x15021a3, 0x15021af, '75'),
    ('publish_name', 0x150252e, 0x64e09f0, 'ff15'),
    ('publish_write', 0x150255d, 0x64e09f8, 'ff15'),
    ('publish_write_ok', 0x1502566, 0x150257f, '74'),
    ('publish_prepare', 0x1502625, 0x64e0940, 'ff15'),
    ('publish_prepare_ok', 0x150262e, 0x150263f, '74'),
    ('publish_final', 0x150264b, 0x64e0a00, 'ff15'),
    ('map_pack_marker', 0x3d4f71d, 0x3d52310, 'e8'),
    ('map_initial_grow', 0x3d4f709, 0x3d4f865, '0f84'),
    ('map_second_grow', 0x3d4f727, 0x3d4f936, '0f84'),
    ('map_wide', 0x3d4f749, 0x3d4f7f3, '0f84'),
    ('map_short_finish', 0x3d4f75b, 0x3d4f844, '0f85'),
    ('map_u16_ready', 0x3d4f76e, 0x3d4f7de, '77'),
    ('io_open_short', 0x5ca5284, 0x5ca52a0, '74'),
    ('io_open_long', 0x5ca52c4, 0x5ca52a0, '74'),
    ('io_empty', 0x5ca52cd, 0x5ca5349, '74'),
    ('io_minus_one', 0x5ca52fb, 0x5ca5310, '74'),
    ('io_zero', 0x5ca5300, 0x5ca536a, '74'),
    ('io_valid_write', 0x5ca5308, 0x5ca52e0, '73'),
    ('io_overreported', 0x5ca530a, 0x5ca5373, 'eb'),
    ('io_errno_other', 0x5ca5339, 0x5ca534c, '75'),
    ('io_errno_retry', 0x5ca5347, 0x5ca52e6, 'eb'),
    ('b_entry_probe', 0x2cde488, 0x5ce5fb0, 'e8'),
    ('b_entry_probe_zero', 0x2cde48f, 0x2cde706, '0f84'),
    ('alt_busy_on_entry', 0x2b404c3, 0x2b40526, '75'),
    ('alt_guard_failure', 0x2b40533, 0x2b40617, 'e9'),
    ('alt_poll_a', 0x2b40577, 0x2ae41e0, 'e8'),
    ('alt_busy_on_return', 0x2b405bd, 0x2b405f1, '75'),
    ('alt_empty_saved_value', 0x2b405d6, 0x2b405fe, '74'),
    ('a_post_write_no_buffer', 0x2ae5093, 0x2ae50a5, '7e'),
    ('a_cleanup_first_empty', 0x2ae50ad, 0x2ae50bc, '74'),
    ('a_cleanup_second_empty', 0x2ae50c4, 0x2ae5e0a, '0f84'),
    ('a_cleanup_second_present', 0x2ae50cf, 0x2ae5e02, 'e9'),
    ('b_post_write_no_buffer', 0x2cdf17b, 0x2cdf18d, '7e'),
    ('b_cleanup_first_empty', 0x2cdf194, 0x2cdf1a3, '74'),
    ('b_cleanup_second_empty', 0x2cdf1ab, 0x2cdfece, '0f84'),
    ('b_cleanup_second_present', 0x2cdf1b6, 0x2cdfec6, 'e9'),
]

# Imported dynamic symbols may be interposed at runtime.
IMPORT_PINS = {0x64df508: 'memcpy', 0x64dffc0: 'write',
               0x64dffc8: '__errno_location', 0x64dfe78: 'close'}

# Relocations are resolved from .rela.dyn, never inferred from file bytes in a slot.
RELOCATION_PINS = {
    0x64e0938: 0x5cab560, 0x64df480: 0x6355830,
    0x64e0028: 0x15020f0, 0x64e09e8: 0x15024a0,
    0x64df4a0: 0x635de30, 0x64e0928: 0x1500a60,
    0x64e0940: 0x5c8f4c0, 0x64e09f0: 0x1502f90,
    0x64e09f8: 0x5ca5110, 0x64e0a00: 0x1502da0,
}

TABLES = [
    ('a_resume', 0x6040e4, 14, 0x2ae41e0, 0x2ae6d66),
    ('a_command', 0x60411c, 13, 0x2ae41e0, 0x2ae6d66),
    ('b_resume', 0x60bf88, 14, 0x2cde430, 0x2ce0dd1),
    ('b_command', 0x60bfc0, 13, 0x2cde430, 0x2ce0dd1),
]

FDE_ROLES = {
    0x2cd8370: 'upper_wrapper', 0x2ae1690: 'poll_parent',
    0x2b404b0: 'alternate_poll_wrapper',
    0x2ae41e0: 'state_export_poll_a', 0x2cde430: 'state_export_poll_b',
    0x422ed40: 'format_router', 0x3c136f0: 'text_serializer',
    0x3c13960: 'binary_serializer', 0x159fca0: 'ascii_compare',
    0x15020f0: 'output_preparation', 0x15024a0: 'output_wrapper',
    0x3d4f6d0: 'map_header_writer', 0x3d52310: 'marker_pack',
    0x5ca5110: 'file_write_loop',
}

TABLE_HASHES = {
    'a_resume': '921946ba5679d3386e7cfd466e99298ed83c77782b9b420032649ad51bd5d58b',
    'a_command': '4b2ad83c757dad87b405aba40dca377f18c294f94b7c8d398257f1bf3297aa5e',
    'b_resume': '7ac69be7a2671adbd6c95b7c9e170766c0a465d62925774880cba9369a0dfa3b',
    'b_command': '49271fc81a7a1dd13b91b48d56218b973df48583d6905e0844759aed95675e92',
}
NAME_HASH = 'b78182fd38e06e4f1de141acc6788ab47f9896dd2614e574d30b6cd6f270ec36'

# Name instruction, adjacent state-operand instruction, access kind.
FIELD_PINS = [
    (0x3c13b08, 0x3c13b26, 'address'),
    (0x3c13c0e, 0x3c13c2c, 'address'),
    (0x3c13c55, 0x3c13c73, 'address'),
    (0x3c13dbb, 0x3c13dd9, 'address'),
    (0x3c13e0e, 0x3c13dfb, 'byte_load'),
    (0x3c14437, 0x3c14455, 'address'),
    (0x3c1447e, 0x3c1449c, 'address'),
    (0x3c144c5, 0x3c144e3, 'address'),
    (0x3c14a6c, 0x3c14a8a, 'address'),
    (0x3c14b41, 0x3c14b5f, 'address'),
]

# Fixed instruction shapes and little-endian operands, selected by inspection.
OPERAND_PINS = [
    ('outer_flag_offset', 0x2cd8395, 'c68424', 'I', 0x222, '00'),
    ('parent_compare_offset', 0x2ae18cb, '4883bc24', 'I', 0xe0, '01'),
    ('parent_copy_length', 0x2ae19bf, 'ba', 'I', 0x2c40, ''),
    ('a_state_offset', 0x2ae41f4, '0fb687', 'I', 0x21a, ''),
    ('a_command_offset', 0x2ae4586, '488d83', 'I', 0xc0, ''),
    ('a_command_subtrahend', 0x2ae4593, '4883e9', 'B', 2, ''),
    ('a_borrow_index', 0x2ae4597, 'ba', 'I', 12, ''),
    ('b_state_offset', 0x2cde498, '410fb685', 'I', 0x21a, ''),
    ('b_command_offset', 0x2cde64b, '498d85', 'I', 0xc0, ''),
    ('b_command_subtrahend', 0x2cde658, '4883e9', 'B', 2, ''),
    ('b_borrow_index', 0x2cde65c, 'ba', 'I', 12, ''),
    ('alternate_guard_offset', 0x2b404be, '48837f', 'B', 8, '00'),
    ('alternate_saved_offset', 0x2b404ef, '4c897b', 'B', 0x10, ''),
    ('serializer_flag_offset', 0x3c13981, '807a', 'B', 0xb, '00'),
    ('serializer_success_word', 0x3c13977, '48bd', 'Q', 0x8000000000000004, ''),
    ('text_allocation_length', 0x422eeae, 'bf', 'I', 0x80, ''),
]

LOCATION_REF_PINS = [
    ('a_read', 0x2ae4f04, '488d15', 0x64767d8),
    ('a_write', 0x2ae4f2d, '488d0d', 0x64767c0),
    ('b_read', 0x2cdf000, '488d15', 0x64767d8),
    ('b_write', 0x2cdf029, '488d0d', 0x64767c0),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data):
    if digest(data) != DIGEST:
        raise ValueError('node 115 SHA-256 mismatch')


def file_offset(secs, va, length):
    if type(va) is not int or type(length) is not int or va < 0 or length <= 0:
        raise ValueError('invalid address or length')
    candidates = [s for s in secs if s['type'] != 8 and s['size'] and
                  s['address'] <= va and va + length <= s['address'] + s['size']]
    if len(candidates) != 1:
        raise ValueError('address is not uniquely file-backed')
    s = candidates[0]
    return s['offset'] + va - s['address']


def read(data, secs, va, length):
    pos = file_offset(secs, va, length)
    part = data[pos:pos + length]
    if len(part) != length:
        raise ValueError('truncated mapped bytes')
    return part


def unique_sections(data):
    secs = sections(data)
    for name in ('.text', '.rodata', '.rela.dyn', '.eh_frame', '.eh_frame_hdr', '.dynsym', '.dynstr'):
        matches = [s for s in secs if s['name'] == name]
        if len(matches) != 1 or matches[0]['type'] == 8:
            raise ValueError('missing, duplicate, or NOBITS required section')
    return secs


def selected_relocations(data, secs, wanted):
    rel = next(s for s in secs if s['name'] == '.rela.dyn')
    if rel['type'] != 4 or rel['size'] % 24:
        raise ValueError('malformed relocation section')
    found = {}
    for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in wanted:
            if slot in found:
                raise ValueError('duplicate selected relocation')
            if info != 8 or addend < 0:
                raise ValueError('selected relocation is not symbol-zero RELATIVE')
            found[slot] = {'slot': slot, 'target': addend, 'file_offset': pos}
    if set(found) != set(wanted):
        raise ValueError('selected relocation missing')
    return found


def selected_imports(data, secs):
    """Resolve the selected dynamic symbol as context for the parent copy."""
    named = {s['name']: s for s in secs if s['name'] in ('.rela.dyn', '.dynsym', '.dynstr')}
    rel, sym, strings = named['.rela.dyn'], named['.dynsym'], named['.dynstr']
    if rel['type'] != 4 or rel['size'] % 24 or sym['type'] != 11 or sym['size'] % 24 or strings['type'] != 3:
        raise ValueError('malformed dynamic symbol sections')
    found = {}
    for pos in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in IMPORT_PINS:
            continue
        if slot in found:
            raise ValueError('duplicate selected dynamic import')
        sym_index, typ = info >> 32, info & 0xffffffff
        if typ != 6 or addend != 0 or sym_index >= sym['size'] // 24:
            raise ValueError('unexpected dynamic import relocation')
        symbol_offset = sym['offset'] + sym_index * 24
        name_offset = struct.unpack_from('<I', data, symbol_offset)[0]
        if name_offset >= strings['size']:
            raise ValueError('dynamic symbol name outside string table')
        begin = strings['offset'] + name_offset
        end = data.find(b'\x00', begin, strings['offset'] + strings['size'])
        if end < 0 or data[begin:end] != IMPORT_PINS[slot].encode('ascii'):
            raise ValueError('dynamic symbol name mismatch')
        found[slot] = {'slot': slot, 'relocation_offset': pos, 'type': typ,
                       'symbol_index': sym_index, 'symbol_offset': symbol_offset,
                       'name_offset': begin, 'name': IMPORT_PINS[slot]}
    if set(found) != set(IMPORT_PINS):
        raise ValueError('missing selected dynamic import')
    return [found[slot] for slot in sorted(found)]


def selected_fdes(data, secs):
    _, fdes = eh_frame_records(data, secs)
    _, hdr = unwind_index(data)
    chosen = []
    for start, expected_end, expected_fde, expected_hash in FDE_PINS:
        fs = [f for f in fdes if f['start'] == start]
        hs = [h for h in hdr if h['start'] == start]
        if len(fs) != 1 or len(hs) != 1:
            raise ValueError('missing or duplicate selected FDE')
        f = fs[0]
        if f['end'] != expected_end or f['fde'] != expected_fde or hs[0]['fde'] != f['fde']:
            raise ValueError('FDE and unwind index do not agree')
        if any(other is not f and other['start'] < f['end'] and start < other['end'] for other in fdes):
            raise ValueError('selected FDE overlaps another range')
        code = read(data, secs, start, f['end'] - start)
        if digest(code) != expected_hash:
            raise ValueError('selected FDE body mismatch')
        chosen.append({'role': FDE_ROLES[start], 'start': start, 'end': f['end'], 'fde': f['fde'], 'cie': f['cie'],
                       'lsda': f['lsda'], 'file_offset': file_offset(secs, start, len(code)),
                       'length': len(code), 'sha256': digest(code)})
    return chosen


def selected_windows(data, secs):
    rows = []
    for label, start, end, expected in WINDOWS:
        raw = read(data, secs, start, end - start)
        if digest(raw) != expected:
            raise ValueError('selected instruction window mismatch: ' + label)
        rows.append({'label': label, 'start': start, 'end': end,
                     'file_offset': file_offset(secs, start, len(raw)),
                     'sha256': digest(raw), 'bytes': raw.hex()})
    return rows


def transfer(data, secs, site):
    first = read(data, secs, site, 2)
    if first[0] in (0xe8, 0xe9):
        size = 5
        kind = 'call' if first[0] == 0xe8 else 'jump'
        displacement = struct.unpack('<i', read(data, secs, site + 1, 4))[0]
    elif first == b'\xff\x15':
        size = 6
        kind = 'call_slot'
        displacement = struct.unpack('<i', read(data, secs, site + 2, 4))[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        size = 6
        kind = 'jcc_' + format(first[1] & 15, 'x')
        displacement = struct.unpack('<i', read(data, secs, site + 2, 4))[0]
    elif 0x70 <= first[0] <= 0x7f or first[0] == 0xeb:
        size = 2
        kind = 'jump' if first[0] == 0xeb else 'jcc_' + format(first[0] & 15, 'x')
        displacement = struct.unpack('<b', first[1:2])[0]
    else:
        raise ValueError('unsupported selected transfer')
    return kind, size, site + size + displacement


def selected_edges(data, secs, relocations):
    rows = []
    for label, site, expected, opcode in EDGE_PINS:
        if read(data, secs, site, len(bytes.fromhex(opcode))).hex() != opcode:
            raise ValueError('selected transfer opcode mismatch: ' + label)
        kind, size, target = transfer(data, secs, site)
        if target != expected:
            raise ValueError('selected transfer target mismatch: ' + label)
        if kind == 'call_slot' and (target not in RELOCATION_PINS or target not in relocations):
            raise ValueError('unregistered selected call slot')
        resolved = relocations[target]['target'] if kind == 'call_slot' else None
        rows.append({'label': label, 'site': site, 'file_offset': file_offset(secs, site, size),
                     'bytes': read(data, secs, site, size).hex(), 'kind': kind,
                     'target': target, 'resolved': resolved,
                     'fallthrough': site + size if kind.startswith('jcc_') else None})
    return rows


def selected_tables(data, secs):
    rows = []
    for label, base, count, start, end in TABLES:
        if digest(read(data, secs, base, 4 * count)) != TABLE_HASHES[label]:
            raise ValueError('selected dispatch table mismatch')
        for index in range(count):
            site = base + 4 * index
            raw = read(data, secs, site, 4)
            offset = struct.unpack('<i', raw)[0]
            target = base + offset
            if not start <= target < end:
                raise ValueError('table target outside selected FDE')
            rows.append({'label': label, 'index': index, 'entry': site,
                         'file_offset': file_offset(secs, site, 4),
                         'bytes': raw.hex(), 'target': target})
    by_key = {(r['label'], r['index']): r['target'] for r in rows}
    if (by_key['a_resume', 0], by_key['a_command', 2], by_key['b_resume', 0],
            by_key['b_command', 2]) != (0x2ae420b, 0x2ae4ebc, 0x2cde4b0, 0x2cdefb5):
        raise ValueError('selected dispatch targets mismatch')
    return rows


def selected_locations(data, secs, relocations):
    out = []
    for label, va, expected_line, expected_col in (
            ('read_location', 0x64767d8, 102, 40),
            ('write_location', 0x64767c0, 113, 9)):
        pointer = relocations[va]['target']
        length, line, col = struct.unpack('<QII', read(data, secs, va + 8, 16))
        if length != 20 or line != expected_line or col != expected_col:
            raise ValueError('Location length or coordinate mismatch')
        path = read(data, secs, pointer, length)
        if path != b'l1/src/abci/state.rs':
            raise ValueError('Location path mismatch')
        out.append({'label': label, 'va': va, 'file_offset': file_offset(secs, va, 24),
                    'relocation_offset': relocations[va]['file_offset'],
                    'path_va': pointer, 'path': path.decode('ascii'),
                    'length': length, 'line': line, 'column': col})
    return out


def selected_location_refs(data, secs):
    rows = []
    for label, site, prefix, expected in LOCATION_REF_PINS:
        raw = read(data, secs, site, 7)
        if raw[:3].hex() != prefix:
            raise ValueError('Location reference opcode mismatch: ' + label)
        target = site + 7 + struct.unpack('<i', raw[3:])[0]
        if target != expected:
            raise ValueError('Location reference target mismatch: ' + label)
        rows.append({'label': label, 'site': site, 'file_offset': file_offset(secs, site, 7),
                     'bytes': raw.hex(), 'target': target})
    return rows


def selected_operands(data, secs):
    rows = []
    for label, site, prefix_hex, fmt, expected, suffix_hex in OPERAND_PINS:
        prefix, suffix = bytes.fromhex(prefix_hex), bytes.fromhex(suffix_hex)
        width = struct.calcsize('<' + fmt)
        raw = read(data, secs, site, len(prefix) + width + len(suffix))
        if raw[:len(prefix)] != prefix or (suffix and raw[-len(suffix):] != suffix):
            raise ValueError('operand instruction shape mismatch: ' + label)
        value = struct.unpack('<' + fmt, raw[len(prefix):len(prefix) + width])[0]
        if value != expected:
            raise ValueError('operand value mismatch: ' + label)
        rows.append({'label': label, 'site': site, 'file_offset': file_offset(secs, site, len(raw)),
                     'bytes': raw.hex(), 'value': value})
    return rows


def name_at(data, secs, site):
    raw = read(data, secs, site, 20)
    if raw[:3] != b'\x48\x8d\x35' or raw[7] != 0xba or raw[15] != 0xe8:
        raise ValueError('unsupported name reference')
    if raw[12:15] not in (b'\x4c\x89\xf7', b'\x4c\x89\xef', b'\x48\x89\xdf'):
        raise ValueError('unsupported name writer register')
    dest = site + 7 + struct.unpack('<i', raw[3:7])[0]
    length = struct.unpack('<I', raw[8:12])[0]
    target = site + 20 + struct.unpack('<i', raw[16:20])[0]
    if target != 0x41c6110 or not 0 < length <= 80:
        raise ValueError('unexpected name writer or size')
    literal = read(data, secs, dest, length)
    if not all(0x20 <= x < 0x7f for x in literal):
        raise ValueError('non-ASCII name')
    return {'instruction': site, 'file_offset': file_offset(secs, site, 20),
            'literal_va': dest, 'length': length, 'name': literal.decode('ascii'),
            'callee': target, 'bytes': raw.hex()}


def selected_names(data, secs):
    start, end = 0x3c13960, 0x3c154c1
    body = read(data, secs, start, end - start)
    pat = re.compile(rb'\x48\x8d\x35....\xba....(?:\x4c\x89\xf7|\x4c\x89\xef|\x48\x89\xdf)\xe8....', re.S)
    names = []
    for match in pat.finditer(body):
        try:
            names.append(name_at(data, secs, start + match.start()))
        except ValueError:
            continue
    if len(names) != 27 or digest(b'\x00'.join(n['name'].encode('ascii') for n in names)) != NAME_HASH:
        raise ValueError('unexpected selected name references')
    return names


def selected_fields(data, secs, names):
    names = {item['instruction']: item for item in names}
    rows = []
    for name_site, op_site, kind in FIELD_PINS:
        if name_site not in names:
            raise ValueError('field name site missing')
        raw = read(data, secs, op_site, 8 if kind == 'byte_load' else 7)
        if kind == 'byte_load':
            if raw[:4] != b'\x41\x0f\xb6\x87':
                raise ValueError('unexpected byte field operand')
            offset = struct.unpack('<I', raw[4:8])[0]
        else:
            if raw[:3] not in (b'\x49\x8d\x97', b'\x49\x8d\xb7', b'\x4d\x8d\x87'):
                raise ValueError('unexpected address field operand')
            offset = struct.unpack('<I', raw[3:7])[0]
        rows.append({'name': names[name_site]['name'], 'name_site': name_site,
                     'operand_site': op_site, 'access': kind, 'state_offset': offset,
                     'operand_bytes': raw.hex()})
    return rows


def fold_ascii(byte):
    # Corresponds to the pinned scalar compare window, including non-ASCII bytes.
    return byte | 0x20 if 0x41 <= byte <= 0x5a else byte


def route_case(full_path, component_tag, component, sink, suffix):
    """Model only the pinned post-parser fragment; component is synthetic."""
    if full_path == sink:
        return 'sink'
    if component_tag != 9 or component == b'..':
        return 'text'
    split = component.rfind(b'.')
    if split <= 0:
        return 'text'
    ext = component[split + 1:]
    if len(ext) == len(suffix) and all(fold_ascii(a) == fold_ascii(b) for a, b in zip(ext, suffix)):
        return 'binary'
    return 'text'


def extract_constants(data, secs):
    immediate = read(data, secs, 0x422ed70, 10)
    last = read(data, secs, 0x422ed82, 4)
    ref = read(data, secs, 0x422ee28, 7)
    if immediate[:2] != b'\x48\xb8' or last[:3] != b'\x48\x83\xf1' or ref[:3] != b'\x48\x8d\x15':
        raise ValueError('unexpected routing constant instruction')
    sink = immediate[2:] + last[3:4]
    suffix_va = 0x422ee28 + 7 + struct.unpack('<i', ref[3:7])[0]
    suffix = read(data, secs, suffix_va, 3)
    if sink.hex() != '2f6465762f6e756c6c' or suffix != b'rmp':
        raise ValueError('routing constants mismatch')
    return sink, suffix_va, suffix


def synthetic_cases(sink, suffix):
    cases = [('exact_sink', sink, 9, b'anything'),
             ('sink_extra', sink + b'x', 9, b'x.rmp'),
             ('sink_case', sink[:-1] + b'L', 9, b'x.rmp'),
             ('plain', b'file', 9, b'file'),
             ('leading_dot', b'.rmp', 9, b'.rmp'),
             ('empty_extension', b'x.', 9, b'x.'),
             ('double_dot', b'..', 9, b'..'),
             ('other_tag', b'x.rmp', 8, b'x.rmp'),
             ('long_extension', b'x.rmps', 9, b'x.rmps'),
             ('short_extension', b'x.rm', 9, b'x.rm'),
             ('double_dot_suffix', b'x..rmp', 9, b'x..rmp')]
    for mask in range(8):
        mix = bytes(ch - 32 if mask & (1 << i) else ch for i, ch in enumerate(suffix))
        cases.append(('case_' + str(mask), b'x.' + mix, 9, b'x.' + mix))
    return [{'label': name, 'full_hex': full.hex(), 'component_tag': tag,
             'component_hex': comp.hex(), 'route': route_case(full, tag, comp, sink, suffix)}
            for name, full, tag, comp in cases]


def rows_tsv(columns, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(col, '') for col in columns])
    return stream.getvalue()


def hexrows(rows, keys):
    return [{k: (hex(v) if k in keys and v is not None else v) for k, v in row.items()}
            for row in rows]


def format_constants(data, secs):
    config = read(data, secs, 0x422ee5f, 11)
    outer = read(data, secs, 0x3c1398f, 5)
    inner = read(data, secs, 0x3c13a11, 5)
    text_open = read(data, secs, 0x3c1372e, 4)
    text_separator = read(data, secs, 0x3c13785, 6)
    text_close = read(data, secs, 0x3c13869, 5)
    if (config[:7] != bytes.fromhex('c7842490000000') or outer[:1] != b'\xba'
            or inner[:1] != b'\xba' or text_open[:3] != bytes.fromhex('c60401')
            or text_separator[:4] != bytes.fromhex('66c70430')
            or text_close[:4] != bytes.fromhex('42c60430')):
        raise ValueError('unsupported serializer constant instruction')
    values = {'binary_config_le_hex': config[7:].hex(),
              'outer_requested_entries': struct.unpack('<I', outer[1:])[0],
              'inner_requested_entries': struct.unpack('<I', inner[1:])[0],
              'text_open_hex': text_open[3:].hex(),
              'text_separator_hex': text_separator[4:].hex(),
              'text_close_hex': text_close[4:].hex()}
    if values != {'binary_config_le_hex': '00040001', 'outer_requested_entries': 1,
                  'inner_requested_entries': 59, 'text_open_hex': '7b',
                  'text_separator_hex': '3a20', 'text_close_hex': '7d'}:
        raise ValueError('serializer constants mismatch')
    return values


def map_header(count):
    """Model the pinned u32 map-header path, not a target execution."""
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        raise ValueError('map count must fit u32')
    if count < 16:
        return bytes([0x80 | count])
    if count < 0x10000:
        return bytes([0xde]) + count.to_bytes(2, 'big')
    return bytes([0xdf]) + count.to_bytes(4, 'big')


def map_cases(data, secs):
    wide = read(data, secs, 0x3d4f6de, 6)
    short = read(data, secs, 0x3d4f6e9, 3)
    if wide[:2] != bytes.fromhex('81fa') or short[:2] != bytes.fromhex('83fa'):
        raise ValueError('unexpected map width guards')
    wide_limit = struct.unpack('<I', wide[2:])[0]
    short_limit = short[2]
    if (short_limit, wide_limit) != (16, 65536):
        raise ValueError('map width guards differ')
    inner = struct.unpack('<I', read(data, secs, 0x3c13a11, 5)[1:])[0]
    counts = (0, 1, short_limit - 1, short_limit, short_limit + 1, inner,
              wide_limit - 1, wide_limit, wide_limit + 1, (1 << 32) - 1)
    return [{'count': x, 'header_hex': map_header(x).hex()} for x in counts]


def command_index(tag):
    """Model the pinned subtract/carry dispatch, without a bounds assumption."""
    if type(tag) is not int or not 0 <= tag < 1 << 64:
        raise ValueError('command word must fit u64')
    return tag - 2 if tag >= 2 else 12


def command_cases():
    tags = (0, 1, 2, 3, 4, 13, 14, 15, (1 << 64) - 1)
    return [{'tag': str(tag), 'index': str(command_index(tag)),
             'inside_selected_table': int(command_index(tag) < 13)} for tag in tags]


def write_step(remaining, result_word, errno):
    """Model one checked write-loop step under the observed 64-bit ABI."""
    if (type(remaining) is not int or not 0 <= remaining < 1 << 64
            or type(result_word) is not int or not 0 <= result_word < 1 << 64
            or type(errno) is not int or not 0 <= errno < 1 << 32):
        raise ValueError('invalid synthetic write-loop word')
    if remaining == 0:
        return 'done', 0, 0
    if result_word == (1 << 64) - 1:
        return ('retry' if errno == 4 else 'error'), remaining, 0
    if result_word == 0:
        return 'error', remaining, 0
    if result_word > remaining:
        return 'trap', remaining, 0
    new_remaining = remaining - result_word
    return ('done' if new_remaining == 0 else 'again'), new_remaining, result_word


def write_cases():
    inputs = [(0, 0, 0), (8, 8, 0), (8, 3, 0), (8, 0, 0),
              (8, (1 << 64) - 1, 4), (8, (1 << 64) - 1, 5),
              (8, 9, 0), (1, 1, 0), (1, 2, 0)]
    rows = []
    for remaining, result_word, errno in inputs:
        outcome, left, advanced = write_step(remaining, result_word, errno)
        rows.append({'remaining': remaining, 'result_word': hex(result_word), 'errno': errno,
                     'outcome': outcome, 'remaining_after': left, 'pointer_advance': advanced})
    return rows


def analyse(data):
    authenticate(data)
    secs = unique_sections(data)
    fdes = selected_fdes(data, secs)
    imports = selected_imports(data, secs)
    windows = selected_windows(data, secs)
    loc_sites = (0x64767d8, 0x64767c0)
    reloc = selected_relocations(data, secs, set(RELOCATION_PINS) | set(loc_sites))
    for slot, target in RELOCATION_PINS.items():
        if reloc[slot]['target'] != target:
            raise ValueError('selected relocation target mismatch')
    edges = selected_edges(data, secs, reloc)
    tables = selected_tables(data, secs)
    locations = selected_locations(data, secs, reloc)
    location_refs = selected_location_refs(data, secs)
    operands = selected_operands(data, secs)
    names = selected_names(data, secs)
    fields = selected_fields(data, secs, names)
    sink, suffix_va, suffix = extract_constants(data, secs)
    cases = synthetic_cases(sink, suffix)
    constants = format_constants(data, secs)
    map_vectors = map_cases(data, secs)
    write_vectors = write_cases()
    command_vectors = command_cases()
    summary = {'binary_sha256': DIGEST, 'selected_fdes': len(fdes), 'windows': len(windows),
               'transfers': len(edges), 'table_entries': len(tables), 'locations': len(locations),
               'location_references': len(location_refs), 'scalar_operands': len(operands),
               'name_references': len(names), 'field_operands': len(fields), 'cases': len(cases),
               'map_cases': len(map_vectors), 'write_cases': len(write_vectors),
               'command_cases': len(command_vectors), 'dynamic_imports': len(imports),
               'sink_hex': sink.hex(), 'suffix_hex': suffix.hex(), 'suffix_va': hex(suffix_va),
               'scope': 'selected static evidence; no execution or complete CFG'}
    return fdes, windows, edges, tables, locations, location_refs, operands, names, fields, reloc, imports, cases, constants, map_vectors, write_vectors, command_vectors, summary


def generate(data, output):
    fdes, windows, edges, tables, locations, location_refs, operands, names, fields, reloc, imports, cases, constants, map_vectors, write_vectors, command_vectors, summary = analyse(data)
    output.mkdir(parents=True, exist_ok=True)
    specs = [
        ('extents.tsv', ['role','start','end','file_offset','length','fde','cie','lsda','sha256'], fdes,
         {'start','end','file_offset','fde','cie','lsda'}),
        ('windows.tsv', ['label','start','end','file_offset','sha256','bytes'], windows,
         {'start','end','file_offset'}),
        ('edges.tsv', ['label','site','file_offset','bytes','kind','target','resolved','fallthrough'], edges,
         {'site','file_offset','target','resolved','fallthrough'}),
        ('dispatch.tsv', ['label','index','entry','file_offset','bytes','target'], tables,
         {'entry','file_offset','target'}),
        ('locations.tsv', ['label','va','file_offset','relocation_offset','path_va','length','line','column','path'], locations,
         {'va','file_offset','relocation_offset','path_va'}),
        ('location-refs.tsv', ['label','site','file_offset','bytes','target'], location_refs,
         {'site','file_offset','target'}),
        ('operands.tsv', ['label','site','file_offset','bytes','value'], operands,
         {'site','file_offset','value'}),
        ('names.tsv', ['instruction','file_offset','literal_va','length','name','callee','bytes'], names,
         {'instruction','file_offset','literal_va','callee'}),
        ('fields.tsv', ['name','name_site','operand_site','access','state_offset','operand_bytes'], fields,
         {'name_site','operand_site','state_offset'}),
        ('imports.tsv', ['slot','relocation_offset','type','symbol_index','symbol_offset','name_offset','name'], imports,
         {'slot','relocation_offset','symbol_offset','name_offset'}),
        ('relocations.tsv', ['slot','file_offset','target'], [reloc[k] for k in sorted(reloc)],
         {'slot','file_offset','target'}),
        ('cases.tsv', ['label','full_hex','component_tag','component_hex','route'], cases, set()),
        ('map-cases.tsv', ['count','header_hex'], map_vectors, set()),
        ('write-cases.tsv', ['remaining','result_word','errno','outcome','remaining_after','pointer_advance'], write_vectors, set()),
        ('dispatch-cases.tsv', ['tag','index','inside_selected_table'], command_vectors, set()),
    ]
    for name, columns, rows, keys in specs:
        (output / name).write_text(rows_tsv(columns, hexrows(rows, keys)), encoding='utf-8')
    (output / 'constants.json').write_text(json.dumps(constants, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def check_historical(data):
    """Optionally verify the old release as a navigation comparison only."""
    old_sha = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
    if digest(data) != old_sha:
        raise ValueError('historical node 94 SHA-256 mismatch')
    secs = unique_sections(data)
    _, frames = eh_frame_records(data, secs)
    _, hdr = unwind_index(data)
    selected = [f for f in frames if f['start'] == 0x22ae8a0]
    entries = [h for h in hdr if h['start'] == 0x22ae8a0]
    if (len(selected) != 1 or len(entries) != 1 or selected[0]['end'] != 0x22b107c
            or entries[0]['fde'] != selected[0]['fde']):
        raise ValueError('historical FDE/index mismatch')
    window = read(data, secs, 0x22aef91, 0x22af07b - 0x22aef91)
    if digest(window) != 'bb0154781d240f9e844ea3414fb283b8a5b8832ec8bea4b931a9ecdd494b2df0':
        raise ValueError('historical window mismatch')
    locs = [(0x56dfc28, 86, 40, 0x22aefdb),
            (0x56dfc10, 97, 9, 0x22af04e),
            (0x56dfbf8, 107, 37, 0x3273856)]
    rel = selected_relocations(data, secs, {x[0] for x in locs})
    records = []
    for va, line, col, site in locs:
        path_va = rel[va]['target']
        length, got_line, got_col = struct.unpack('<QII', read(data, secs, va + 8, 16))
        path = read(data, secs, path_va, length)
        insn = read(data, secs, site, 7)
        if (length != 49 or (got_line, got_col) != (line, col)
                or not path.endswith(b'l1/src/abci/state.rs') or insn[:3] != bytes.fromhex('488d0d')
                or site + 7 + struct.unpack('<i', insn[3:])[0] != va):
            raise ValueError('historical Location cross-check mismatch')
        records.append({'location_va': hex(va), 'line': line, 'column': col,
                        'reference_va': hex(site), 'reference_bytes': insn.hex(),
                        'path_suffix': 'l1/src/abci/state.rs'})
    old_edges = []
    for site, target in ((0x22aefea, 0x3c155a0), (0x22af003, 0x22b06e9),
                         (0x22af060, 0x3c165b0), (0x22af068, 0x22b03c1),
                         (0x3273862, 0x3c155a0)):
        kind, size, actual = transfer(data, secs, site)
        if actual != target:
            raise ValueError('historical transfer mismatch')
        old_edges.append({'site': hex(site), 'target': hex(target), 'kind': kind,
                          'bytes': read(data, secs, site, size).hex()})
    if read(data, secs, 0x22aefff, 4) != bytes.fromhex('4983fe02') or read(data, secs, 0x22af065, 3) != bytes.fromhex('4885c0'):
        raise ValueError('historical result tests mismatch')
    return {'sha256': old_sha, 'fde_start': hex(selected[0]['start']),
            'fde_end_exclusive': hex(selected[0]['end']), 'fde': hex(selected[0]['fde']),
            'window_sha256': digest(window), 'locations': records, 'transfers': old_edges,
            'read_check_bytes': '4983fe02', 'write_check_bytes': '4885c0'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--old-elf', type=Path, help='optional authenticated historical node 94')
    args = parser.parse_args()
    historical = check_historical(args.old_elf.read_bytes()) if args.old_elf is not None else None
    result = generate(TARGET.read_bytes(), args.out)
    print(json.dumps({'current': result, 'historical': historical}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_state_export115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
