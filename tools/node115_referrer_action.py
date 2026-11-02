#!/usr/bin/env python3
"""Reproduce selected static node #115 referral-action control-flow evidence.

The target is read as data. No captured executable or external program is run.
"""
import argparse
import csv
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
MAX_U64 = (1 << 64) - 1

# Labels identify deliberately selected ranges. They are not a complete CFG.
FUNCTIONS = (
    ('variant_key_matcher', 0x287e450),
    ('variant_key_adapter', 0x1df0720),
    ('variant_envelope', 0x2943460),
    ('variant_visitor', 0x1df5340),
    ('expected_variant_name', 0x292d250),
    ('variant_serializer', 0x28e7450),
    ('variant_clone', 0x2936420),
    ('apply_parent', 0x2bf00f0),
    ('vote_gate_helper', 0x2699750),
    ('vote_process', 0x28b02b0),
    ('vote_two_stage_predicate', 0x28a9b70),
    ('vote_predicate_first', 0x36c7f70),
    ('vote_predicate_second', 0x14cf1d0),
    ('action_apply', 0x28cd7a0),
    ('registration_wrapper', 0x285c730),
    ('referrer_core', 0x3c193d0),
    ('profile_entry', 0x3ccb770),
    ('code_entry', 0x3cc9c90),
    ('compact_profile_insert', 0x4548960),
    ('compact_code_insert', 0x45479a0),
    ('tree_code_remove', 0x39023e0),
)

# The following hashes pin raw, unmasked target windows, including branch and
# call operands. Every window was selected at instruction boundaries.
WINDOWS = (
    ('name_matcher_entry', 0x287e450, 0x287e48c, '4b44f7477aa4793bb217a9452a6d19a8a1d111cc11cf14ed40b8ad2b388c826c'),
    ('name_matcher_k', 0x287e94c, 0x287e955, '897989bc1bec4a29dd996ff19dbfec5e4edd67e91a0e016fb244112bc3e4b11d'),
    ('name_matcher_j', 0x287ea2d, 0x287ea36, '5d1f8b7deab756f6b62c87e79dff51ca582e8828b25d4734a65ac154728cb29a'),
    ('name_matcher_l', 0x287e9dc, 0x287e9e5, 'f4e4cd684415eb7bb047596f27f3b55ecbcfd8a1ea0626351db886b135d1ae2c'),
    ('name_adapter', 0x1df07c5, 0x1df0850, '663d89b3fadaf1e34cb841bdcbb8d6cd28195765b140338b82b7ee5490345cb3'),
    ('envelope_key_route', 0x2943539, 0x29435ee, 'fa5cf89364c4ef4a5607b8ba8f5277c074543b337606fd49d316a78a059c4ba3'),
    ('envelope_visit', 0x2943c20, 0x2943c3e, '5efc1a1f3c5305341ca9fa9b4c3ee3bf48abad4ebdd56f65281d7b89509f52a2'),
    ('envelope_copy_result', 0x29436c1, 0x29436ef, '70a1c80d46a71c928b2bd00636e3a06a81bd0a8a04f37449796c6d596fe000b0'),
    ('parent_acquire', 0x2bf03d2, 0x2bf0456, '8935c3216b98d1e26c7257e477cd84b99adcc602bbaaab36d9b325f6593a7319'),
    ('parent_admission', 0x2bf01cf, 0x2bf0218, '02eb34e97ee778efc986661b3399bd7d788bedde7d94f492bffa5f73b544490a'),
    ('parent_reject', 0x2bf0456, 0x2bf0472, 'e7e0e4afb76caf02d26fcf27e4e7dc6dd1ea471904340e6d5b67ec5fe3dea447'),
    ('parent_input_gate', 0x2bf0218, 0x2bf0273, '3671bb95619b25725a8e13f5b2be911d92b3263910569dbdf20a314847a77781'),
    ('parent_prepare_action', 0x2bf02ee, 0x2bf0339, 'd646cf59f9bbd265dc532328a2c6a9af2b32bca490321e37da5df568b4c89ab8'),
    ('vote_gate_helper', 0x2699750, 0x269979d, '46b07abaa361d1d6dd0a343d28f58269e2fb26ff012dffc5441dc52ea49666d7'),
    ('vote_gate_result', 0x26998f3, 0x2699909, '9adabe0dd37fb8074c3fdd0bb64d19e48a6ef09a012483ec3855e8416087b06d'),
    ('vote_process_input', 0x28b02c1, 0x28b02df, 'ec41451cb29ff3be2d082600330b776dd3fe1c132bdb8d985882140f88d9b016'),
    ('vote_clone_input', 0x28b0495, 0x28b04a7, '9a631eac99370549659d30491f3b435e4cbda5b67f47008299ac99f4bcaa5e70'),
    ('vote_record_gate', 0x28b150a, 0x28b1532, '480a957832a3b76a8f4f4de9eeb0ac7d01ff8df4a573f4d1e4d03d2684c328f1'),
    ('vote_record_write', 0x28b1532, 0x28b1588, '462d7c79d4f354ab7147714865b52d486f3146266591856ce71bf675a3d338af'),
    ('vote_selected_copy', 0x28b1588, 0x28b15a0, 'a332c4f35388a31e510f0d79ecc9c181c6adb05201728efe3884d61ee01417df'),
    ('vote_selected_return', 0x28b1722, 0x28b17d8, '946e241deeb2058ffd0c1fc198e6bf3a994d338c7957dcdd666d1b6c0db95eb8'),
    ('vote_process_output', 0x28b1988, 0x28b19a6, '16701584d5821361de4db89afb8e4a8bcedc1550b4ad63976c941c4ff2365daa'),
    ('predicate_first', 0x28a9c43, 0x28a9c71, '5ac55182736668617e189492172e164893ae7eaa74399cca447dc32d4aa22435'),
    ('predicate_false', 0x28a9ca8, 0x28a9caf, '559649d4b306e9b22a6c1a044eadde54754183b27c26e50e3758c6e47f0825e8'),
    ('predicate_second', 0x28a9d39, 0x28a9d77, '6c1c3860bedd05a3baf358cd9104f5fc764ff51ca84e8100dd3218d0aaf9345f'),
    ('predicate_lookup_tree', 0x36c7f8b, 0x36c7fa7, 'b2eaa22e6a14002f481efe51ff1fec2881a7e290903d68190fab9a9a16d0c47e'),
    ('predicate_lookup_compact', 0x36c8027, 0x36c8041, 'ce21bfd92f09fe9de65a161b65e990f17b15fdc27e95297bceeb59b56a3deb49'),
    ('predicate_key_absent', 0x36c80a3, 0x36c80bb, '7b43a437bf948ec22a1e927f64569e729b66d50a474b10bf782b206f943d4314'),
    ('predicate_second_entry', 0x14cf1d0, 0x14cf20d, '84e74bdeabac2360fa280d0652c804bc54a24a00f3d0586d1e72d25081988f53'),
    ('parent_second_switch', 0x2bf04da, 0x2bf04ff, '228599ca48de0a7129d17e59d52a2da1a56f9fdc706dde4d17cae887fd5376ee'),
    ('parent_apply_call', 0x2bf0515, 0x2bf0556, 'bc1b92c8318638c4acd0f1bf8420b60922a46a6e8825227becf0d2fdc5061618'),
    ('parent_error_copy', 0x2bf0556, 0x2bf05c4, 'da820dde721ceb66f21f82d7030c1e416299332f32c4a2255e21b60a2be714bb'),
    ('parent_tag_copy', 0x2bf15bf, 0x2bf162e, 'd0c9fecddab3866ee3c21c721abce2ad57036a7a8b8f6a271abbf8f554ca38e2'),
    ('profile_grow', 0x3ccb8ad, 0x3ccb91e, '1649fef6b987f0969c28a7969a5683ce7c08c04dbb1b83f2f2c525c1c1a08d9c'),
    ('code_grow', 0x3cc9e56, 0x3cc9ec4, 'bdcd310a49e3565573b20df225a8786309caec93e5507645a8715ae66087db60'),
    ('tree_remove_search', 0x39023e0, 0x390240f, 'ffb8d6d10a5b88761911eaa889f61a3f0d7460e209570c0197abc14c84630867'),
    ('tree_remove_found', 0x39024b5, 0x390252d, 'e7d8c0d97e8eb26c29eb21d3f1bbc53ab997dc678133d9c35d2bc490bfc1183b'),
    ('parser_container', 0x1df53cb, 0x1df53dd, '74ee98501e14b62e1149090b67ccf9cae5d3fcf67e40b1ec9d6c32f7fc6a84d0'),
    ('parser_keys', 0x1df54bc, 0x1df54e8, 'e20c480a5801225b71d9b762b6f0a30d11910240affd388759a99be85140664e'),
    ('parser_n', 0x1df556d, 0x1df5615, '67a9b086d4918870fa054ea63cb15a7691e50cdfc22439ea2cfe3bad2f501413'),
    ('parser_c_check', 0x1df5615, 0x1df5672, '637e6637956fff3353a886259d09baff627450ee6c334119f6220d2b59f02e65'),
    ('parser_u_check', 0x1df5672, 0x1df56c6, '2ab20138b1360f99755daebc6c4952b3a0ae70e9e7deb57e689ac1e861c33afc'),
    ('parser_c_read', 0x1df56c6, 0x1df571b, 'f19019966ed53d9c244ec7fcb2c540d5e9bb37961b9e15aeaf580741338ccb1a'),
    ('parser_u_read', 0x1df571b, 0x1df57d3, '721a0ea5d3085c8433a4a36b1aa19a7a2f83ed1e02ba3c2f79be24c4041adfbd'),
    ('parser_required_c', 0x1df595e, 0x1df5972, '3980eb86764797c66fbd2cce4b57fb67c649286c0a6f9f7e2b4e7f801d15dd73'),
    ('parser_missing_c', 0x1df5972, 0x1df59cf, '1f5465db229f852175fbe87c34595cb81c25679b2e8c95df9680e1a7f707dbc2'),
    ('parser_missing_u', 0x1df5bdc, 0x1df5c35, '4b3247d53120e8661d7a21b025daadf399b2f3e04eee73bd3ef1d8b0862e97f9'),
    ('parser_duplicate_u', 0x1df5ea5, 0x1df5ef2, '53cb50911773b45e9a7abe53c8277f14752da610bf0e767cde609b6a2c822cd3'),
    ('parser_duplicate_n', 0x1df5ef2, 0x1df5f3f, '392acea3a2e79ad0ef7053c3919bac8cdc16e0b5a403ae637e5fa490f9b2ebba'),
    ('parser_duplicate_c', 0x1df5f3f, 0x1df5f8c, 'aa10d3b988c8d3d0aa5bb3150bac3a19aabe4d268aff9b00c276d95c1355afc7'),
    ('parser_sequence_success', 0x1df5a3b, 0x1df5ae2, 'bdc57e0372e05cebcdafe7d83515d0fb27e6206c252a82f033a5c216dbfb344f'),
    ('parser_missing_literal', 0x1df5ae2, 0x1df5af5, 'f3638f1f907de70638e07acce15f2af242694cd5404e8d0fd90bcef34ca697ba'),
    ('parser_map_success', 0x1df5b25, 0x1df5bdc, '3fe46e6a2425029aefc57f9afbb037eb09ea5cff9e33d38d95c6bd53e07a0e89'),
    ('parser_return_stage', 0x1df5d36, 0x1df5d81, '45d157ef05c18534f03611e85e0f3e088c81f94c8e0fe10629d8d45852057af5'),
    ('parser_return_copy', 0x1df5de6, 0x1df5e2d, 'f12b658ab6701296cafe64b4bb4b7f1f4dea7c00137a758f98b21eaf3fa62753'),
    ('parser_type_error', 0x1df5e70, 0x1df5e87, 'ef84fcee4eda0acd6d838c527788cd50d8db4493035b5bf0cacd111f63832e08'),
    ('expecting_formatter', 0x292d250, 0x292d269, '0c96cf4fe8d36bd8150ff2fa54d7e55e7022fb0e7d3229fc65d7c46a10e5d23c'),
    ('serializer_dispatch', 0x28e745e, 0x28e7481, '413467dee3396912a0d13c91c9e1952df7ee1a4867e199bd1dac7333647bffd9'),
    ('serializer_variant', 0x28e7cd5, 0x28e7dae, '9acdec4fa8b311d2483daebb0b49911d5df0f920401436fe3dfb569edfbce769'),
    ('clone_dispatch', 0x293642f, 0x2936452, '3fec43ce0a7380cd22af2c535d63b273c0c8b50bc5f46b9123782ce4a8a44963'),
    ('clone_arm', 0x2937008, 0x2937058, 'baa8accbd4a65e145fc97eeeb5b0c2d598248669841f11c1be7811a47272409a'),
    ('apply_dispatch', 0x28cd7b7, 0x28cd7df, '5344182f097a51267579512a3367a6c32303a72f5647e669e46f07ab1642b13e'),
    ('apply_variant', 0x28ce583, 0x28ce60c, 'e248943a45f182d804439360bc37b2b84e794e307274fc5a79c2ee9f19989b45'),
    ('apply_length_error', 0x28d14d1, 0x28d14ec, 'ea1238e25625a0e559c41203ae7d9e1338321cbea61f3a05c2b06e89f843b72b'),
    ('apply_call', 0x28d241a, 0x28d2454, '8e681f4e144ca4399b4d080bc4f3cf8ac25e000f836155339d04ce04c5c26a83'),
    ('apply_error_copy', 0x28d42d3, 0x28d4326, 'a21caa9c52768d62a1d678295fadeb320f75ff133e7462eda412c49e4dfb74d6'),
    ('apply_error_cleanup', 0x28d5d3a, 0x28d5d61, 'faeaf6bb4380e86f779297cd7e93a88a12447c32a3447b8cae9f82e6f5b39bf7'),
    ('apply_success', 0x28d5df4, 0x28d5e21, '9790e0c62380f7aa4ec0b7cbc8c767134305db19ed84f4a37569f12ff3bcb619'),
    ('registration_wrapper', 0x285c730, 0x285c7dd, '5b16a98eb9b6298ca682485f6234e5cfef6a3cebb484ebc109013472428b6d31'),
    ('core_modes', 0x3c193e1, 0x3c19460, '105e8677731dc7c03d35f309ace5c518e79437133d2d9d09cffd87a073fc1476'),
    ('core_user_lookup', 0x3c19460, 0x3c19489, 'b8a398c27c65696f512106ee41f4e1a727faba10cf627b762b2609140bd66821'),
    ('core_sum', 0x3c195d0, 0x3c1962e, 'febfae899fb295ee82635c15480322db8405b2e7b44558194f441c83fe8dac69'),
    ('core_after_volume', 0x3c1962e, 0x3c1967f, 'd651b70a66d80282daf0681cb91873f1496cd812270d1a2ade1698ba0acdda55'),
    ('core_code_entry', 0x3c1967f, 0x3c19707, 'a04e5648bd5be69ce94ee6f0d9a099729f8c276b56240989b90a733121567b54'),
    ('core_existing_start', 0x3c197af, 0x3c197f5, '80961601416a56b8a5086a2e3885bc133f92082a7b2be3a2cbea76316b259b1f'),
    ('core_tree_code_search', 0x3c197dc, 0x3c198e4, 'ed5d249f3ca2c381eb83e2f19c2572a057860627610ea21a1b7f5e6fe65820f9'),
    ('core_code_search', 0x3c198e4, 0x3c19985, '5ac7ac8e4cc62fa91239246a59fe84b1e777199d506df389147c8f73ea19d683'),
    ('core_new_profile', 0x3c19985, 0x3c199dc, '77e146f00161b54dda8488c07195190065473d1f35fa50ef9d054995771863a5'),
    ('core_insert_profile', 0x3c19a5d, 0x3c19b11, '6b42fb3e8c961a2a0f40320b546c2a07ca7cded46a98bce3e1697a695030bb82'),
    ('core_insert_reverse', 0x3c19b11, 0x3c19b82, 'a2ac73affc1475375fe2f1e51b669f15f0d7d0aed2ae12c999e44355c38a352b'),
    ('core_remove', 0x3c19bf9, 0x3c19c6d, 'd7b531d858bdc85a4d522028b052618a86e75fb0771357d28b05ace91b08ef7c'),
    ('core_reinsert', 0x3c19ee5, 0x3c19f68, '97ac82df6cfbd9fc2c1b59ff582f900ff157a0c1a2234a3228875aa8e78d4819'),
    ('core_update_fields', 0x3c1a0b6, 0x3c1a11c, '94833934943d84599f3e995fbbdb2f1433cae2ef50ad95d01f95d87ac519bc1a'),
    ('core_failures', 0x3c1a11c, 0x3c1a1f8, '0dcd6cf380f5f598757600487624e3fb11177dc9f4604465cb59348074683a6f'),
    ('profile_entry_compaction', 0x3ccb78d, 0x3ccb7c7, 'ddbaca13577311d02ec07c0647419c9e20bf6fec894fa6fdab240c3b2a4c6379'),
    ('code_entry_compaction', 0x3cc9cac, 0x3cc9ce6, 'd8741f9e991b95bcd5202efa33a4696b4bae5470b0170294ff1ee6acb54baf8a'),
    ('compact_profile_guard', 0x4548968, 0x4548996, '8a5ca0040670e94e0b8db0348e752ffbd0212bdc1930d65044b2a42acc2ba196'),
    ('compact_profile_increment', 0x45489d6, 0x45489ed, '77a563bd8aacc81377caa38c74d5cb444e8cdd9239e28b797f6df5e6bced2fe5'),
    ('compact_profile_store', 0x4548a22, 0x4548a6c, '71908072f1d54149fda19a02363f7f7d60b7b947ebe881a39f234911fff12aec'),
    ('compact_code_guard', 0x45479a8, 0x45479d6, 'c028cf5bfb89a3c9f6a113dee60d3d134518dc214b118999513a86aa38a9537d'),
    ('compact_code_increment', 0x4547a16, 0x4547a2d, '77a563bd8aacc81377caa38c74d5cb444e8cdd9239e28b797f6df5e6bced2fe5'),
    ('compact_code_store', 0x4547a62, 0x4547a90, '72cf4ca06f9503a652789e266522327481aa5baadb8569b82ce1a17669d1a2ab'),
)

# Conditional branch addresses with their exact encodings and destinations.
BRANCHES = (
    (0x287e457, '0f8446020000', 0x287e6a3),
    (0x287e467, '0f85fd030000', 0x287e86a),
    (0x287e476, '0f87ee030000', 0x287e86a),
    (0x1df07d9, '0f84b0000000', 0x1df088f),
    (0x1df083f, '7537', 0x1df0878),
    (0x2943560, '757a', 0x29435dc),
    (0x294359b, '0f8596000000', 0x2943637),
    (0x2bf03f3, '750f', 0x2bf0404),
    (0x2bf01d9, '7525', 0x2bf0200),
    (0x2bf020f, '0f8441020000', 0x2bf0456),
    (0x2bf0234, '0f8f06010000', 0x2bf0340),
    (0x2bf023e, '0f8410010000', 0x2bf0354),
    (0x2bf0248, '0f8406010000', 0x2bf0354),
    (0x2bf0333, '0f8548010000', 0x2bf0481),
    (0x2699777, '750c', 0x2699785),
    (0x28b150d, '0f85cdeeffff', 0x28b03e0),
    (0x28b152c, '0f84aeeeffff', 0x28b03e0),
    (0x28b17a1, '0f8446ecffff', 0x28b03ed),
    (0x28a9c6f, '7437', 0x28a9ca8),
    (0x36c7f94, '0f818d000000', 0x36c8027),
    (0x36c7fa1, '0f84fc000000', 0x36c80a3),
    (0x36c8039, '7568', 0x36c80a3),
    (0x36c803f, '7362', 0x36c80a3),
    (0x2bf0537, '751d', 0x2bf0556),
    (0x3ccb7a9, '0f85fe000000', 0x3ccb8ad),
    (0x3ccb8db, '0f8684000000', 0x3ccb965),
    (0x3cc9cc8, '0f8588010000', 0x3cc9e56),
    (0x3cc9e82, '0f86b0000000', 0x3cc9f38),
    (0x39023f7, '0f84ff000000', 0x39024fc),
    (0x390248b, '7428', 0x39024b5),
    (0x1df53ce, "0f84ff030000", 0x1df57d3),
    (0x1df53d7, "0f85930a0000", 0x1df5e70),
    (0x1df54d0, "0f843f010000", 0x1df5615),
    (0x1df54d9, "0f848e000000", 0x1df556d),
    (0x1df54e2, "0f848a010000", 0x1df5672),
    (0x1df5573, "0f8579090000", 0x1df5ef2),
    (0x1df5623, "0f8516090000", 0x1df5f3f),
    (0x1df5677, "0f8528080000", 0x1df5ea5),
    (0x1df596c, "0f85b3010000", 0x1df5b25),
    (0x1df5b2a, "0f84ac000000", 0x1df5bdc),
    (0x28ce5c2, "0f87092f0000", 0x28d14d1),
    (0x28ce5d3, "0f84413e0000", 0x28d241a),
    (0x28ce5e6, "0f82313e0000", 0x28d241d),
    (0x28d244e, "0f857f1e0000", 0x28d42d3),
    (0x3c193fa, "7464", 0x3c19460),
    (0x3c19400, "0f8742020000", 0x3c19648),
    (0x3c19429, "0f8550020000", 0x3c1967f),
    (0x3c19476, "0f84a7010000", 0x3c19623),
    (0x3c195d9, "721d", 0x3c195f8),
    (0x3c19621, "730b", 0x3c1962e),
    (0x3c19646, "760b", 0x3c19653),
    (0x3c19672, "740b", 0x3c1967f),
    (0x3c196fa, "750b", 0x3c19707),
    (0x3c198f6, "0f8509030000", 0x3c19c05),
    (0x3c19903, "0f83fc020000", 0x3c19c05),
    (0x3c1996f, "0f8484020000", 0x3c19bf9),
    (0x3c19b77, "0f829f050000", 0x3c1a11c),
    (0x3c19c67, "0f8570020000", 0x3c19edd),
    (0x3c1a0d5, "0f84ff000000", 0x3c1a1da),
    (0x4548972, "0f87f4000000", 0x4548a6c),
    (0x45479b2, "0f87d8000000", 0x4547a90),
)


def verify_digest(data, expected=SHA256):
    observed = hashlib.sha256(data).hexdigest()
    if observed != expected:
        raise ValueError('node #115 SHA-256 mismatch')
    return observed


def file_offset(secs, address, size=1):
    """Map an entire VA range to one file-backed section, refusing ambiguity."""
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError('Invalid address range')
    ends = address + size
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
               and ends <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('Address is not unambiguously file-backed')
    s = matches[0]
    return s['offset'] + address - s['address']


def read_va(data, secs, address, size):
    off = file_offset(secs, address, size)
    raw = data[off:off + size]
    if len(raw) != size:
        raise ValueError('Truncated file-backed range')
    return raw


def exact(data, secs, address, expected):
    actual = read_va(data, secs, address, len(expected))
    if actual != expected:
        raise ValueError(f'Instruction bytes differ at {address:#x}')
    return actual


def pinned_window(data, secs, address, end, expected):
    raw = read_va(data, secs, address, end - address)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError(f'Window bytes differ at {address:#x}')
    return raw


def decode_branch(address, raw):
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('Unsupported or truncated conditional branch')
    return address + len(raw) + displacement


def check_branch(address, raw, expected_hex, expected_destination):
    if raw.hex() != expected_hex:
        raise ValueError('Conditional branch bytes differ')
    if decode_branch(address, raw) != expected_destination:
        raise ValueError('Conditional branch destination differs')
    return expected_destination


def relative_call(data, secs, address, target):
    raw = read_va(data, secs, address, 5)
    if raw[0] != 0xe8:
        raise ValueError('Expected rel32 call')
    destination = address + 5 + struct.unpack_from('<i', raw, 1)[0]
    if destination != target:
        raise ValueError('Call target mismatch')
    return raw


def relative_lea(data, secs, address, target):
    raw = read_va(data, secs, address, 7)
    if raw[:2] not in (b'\x48\x8d', b'\x4c\x8d') or raw[2] & 0xc7 != 5:
        raise ValueError('Expected RIP-relative lea')
    dest = address + 7 + struct.unpack_from('<i', raw, 3)[0]
    if dest != target:
        raise ValueError('RIP-relative destination mismatch')
    return raw


def read_rela(data, section, wanted):
    """Decode selected ELF64 Rela slots; reject missing and duplicate slots."""
    if section['type'] != 4 or section['size'] % 24:
        raise ValueError('Invalid RELA section')
    start, end = section['offset'], section['offset'] + section['size']
    if start < 0 or end > len(data):
        raise ValueError('Truncated RELA section')
    found = {}
    for pos in range(start, end, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in wanted:
            if slot in found:
                raise ValueError('Duplicate selected relocation')
            found[slot] = (info, addend, pos)
    if set(found) != set(wanted):
        raise ValueError('Selected relocation missing')
    return found


def dynamic_symbol_name(data, secs, index):
    """Read one ELF64 dynamic-symbol name from sections selected by name."""
    sym = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(sym) != 1 or len(strings) != 1 or type(index) is not int or index < 0:
        raise ValueError('Invalid dynamic symbol sections or index')
    sym, strings = sym[0], strings[0]
    if sym['size'] % 24 or index >= sym['size'] // 24:
        raise ValueError('Dynamic symbol index out of range')
    offset = sym['offset'] + 24 * index
    if offset + 24 > len(data) or strings['offset'] + strings['size'] > len(data):
        raise ValueError('Truncated dynamic symbol data')
    name_index = struct.unpack_from('<I', data[offset:offset + 4])[0]
    if name_index >= strings['size']:
        raise ValueError('Dynamic symbol name out of range')
    raw = data[strings['offset'] + name_index:strings['offset'] + strings['size']]
    end = raw.find(b'\0')
    if end < 0:
        raise ValueError('Unterminated dynamic symbol')
    try:
        return raw[:end].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('Invalid dynamic symbol name') from exc


def signed_table_target(data, secs, table, index, lo, hi):
    if type(index) is not int or index < 0:
        raise ValueError('Invalid table index')
    entry = table + 4 * index
    raw = read_va(data, secs, entry, 4)
    dest = table + struct.unpack('<i', raw)[0]
    if not lo <= dest < hi:
        raise ValueError('Table target outside selected FDE')
    return entry, raw, dest


def match_single_variant_name(data, secs, name_byte, fde_start, fde_end):
    """Read the selected one-byte matcher table and its result instruction."""
    if type(name_byte) is not int or not 0 <= name_byte <= 255:
        raise ValueError('Expected one byte')
    exact(data, secs, 0x287e463, b'\x48\x83\xfa\x01')
    bias = struct.unpack('<b', instr(data, secs, 0x287e470, b'\x83\xc1', 3)[2:])[0]
    maximum = instr(data, secs, 0x287e473, b'\x83\xf9', 3)[2]
    index = name_byte + bias
    if not 0 <= index <= maximum:
        raise ValueError('Single-byte name is outside the table gate')
    relative_lea(data, secs, 0x287e47c, 0x5f9f68)
    entry, raw, dest = signed_table_target(data, secs, 0x5f9f68, index, fde_start, fde_end)
    arm = instr(data, secs, dest, b'\xc6\x40\x01', 9)
    if arm[4:] != b'\x31\xc9\x88\x08\xc3':
        raise ValueError('Selected name arm is not the expected success return')
    return index, entry, raw, dest, arm[3]


def validate_functions(data, secs):
    # The shared parser decodes the complete .eh_frame. The unwind header is
    # separately checked to point at the same start/FDE pair for each selection.
    _, index = unwind_index(data)
    _, records = eh_frame_records(data, secs)
    by_start = {}
    for row in records:
        if row['start'] in {s for _, s in FUNCTIONS}:
            if row['start'] in by_start:
                raise ValueError('Duplicate selected FDE start')
            by_start[row['start']] = row
    by_index = {r['start']: r for r in index}
    out = {}
    for role, start in FUNCTIONS:
        if start not in by_start or start not in by_index:
            raise ValueError('Selected FDE is not indexed')
        fde = by_start[start]
        if fde['fde'] != by_index[start]['fde'] or fde['end'] <= start:
            raise ValueError('FDE/header mismatch')
        text = [s for s in secs if s['name'] == '.text' and s['type'] != 8]
        if len(text) != 1 or not (text[0]['address'] <= start < fde['end']
                                  <= text[0]['address'] + text[0]['size']):
            raise ValueError('Selected FDE outside file-backed text')
        out[role] = fde
    return out


def checked_u64(value):
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError('Expected unsigned 64-bit integer')
    return value


def selected_arm_model(length, flag, value, limit):
    """A synthetic decision model of the observed three admission branches."""
    length, flag, value = map(checked_u64, (length, flag, value))
    checked_u64(limit)
    if length > 100:
        return ('length', 0x158, None)
    if flag == 0:
        return ('call', None, 0)
    if value >= limit:
        return ('number', 0x154, None)
    return ('call', None, value)


def selected_parser_model(keys):
    """Model key-presence decisions, assuming each decoded value/skip succeeds."""
    seen = set()
    for key in keys:
        if key in ('c', 'n', 'u'):
            if key in seen:
                return f'duplicate-{key}'
            seen.add(key)
    if 'c' not in seen:
        return 'missing-c'
    if 'u' not in seen:
        return 'missing-u'
    return 'tag-0x37'


def selected_core_model(mode, length, user_found, total, profile, code_owner):
    """Model normal logical branches; allocation/representation effects excluded."""
    if mode not in (0, 1) or type(mode) is not int:
        raise ValueError('Invalid core mode')
    checked_u64(length)
    checked_u64(total)
    if type(user_found) is not bool or type(profile) is not bool:
        raise ValueError('Expected boolean lookup results')
    if code_owner not in ('absent', 'same', 'other'):
        raise ValueError('Invalid code lookup result')
    if mode == 0 and (not user_found or total < 1_000_000):
        return (0xa9, 'reject')
    if length > 100:
        return (0xa4, 'reject')
    if mode == 0 and profile:
        return (0xa8, 'reject')
    if mode == 1 and profile:
        return (0xa7, 'reject') if code_owner == 'other' else (0x1a2, 'replace')
    if code_owner != 'absent':
        return (0xa7, 'reject')
    return (0x1a2, 'insert')


def saturated_sum(words):
    result = 0
    overflows = 0
    for word in words:
        checked_u64(word)
        if result + word > MAX_U64:
            result = MAX_U64
            overflows += 1
        else:
            result += word
    return result, overflows


def instr(data, secs, address, prefix, width):
    raw = read_va(data, secs, address, width)
    if not raw.startswith(prefix):
        raise ValueError(f'Unexpected instruction form at {address:#x}')
    return raw


def branch_at(data, secs, address, expected_opcode):
    length = 6 if expected_opcode[0] == 0x0f else 2
    raw = read_va(data, secs, address, length)
    if not raw.startswith(expected_opcode):
        raise ValueError('Unexpected branch condition')
    return decode_branch(address, raw)


def instruction_arm(data, secs, length, flag, value):
    """Interpret selected real x86 gate instructions, stopping before the call.

    Only the loaded scalar words and flags needed by the branch chain are
    modelled; pointer copies, the callee, cleanup and unwind are not executed.
    Opcode prefixes and branch destinations are checked before their operands
    are used. Mutation of a compare immediate affects this evaluator.
    """
    length, flag, value = map(checked_u64, (length, flag, value))
    # mov r8,[r15+disp8]; mov rax,[r15+disp8]; mov r9,[r15+disp8]
    code_len = instr(data, secs, 0x28ce583, b'\x4d\x8b\x47', 4)
    option_tag = instr(data, secs, 0x28ce59c, b'\x49\x8b\x47', 4)
    option_value = instr(data, secs, 0x28ce5a0, b'\x4d\x8b\x4f', 4)
    fields = {0x28: length, 0x08: flag, 0x10: value}
    try:
        r8, rax, r9 = fields[code_len[3]], fields[option_tag[3]], fields[option_value[3]]
    except KeyError as exc:
        raise ValueError('Gate read outside selected scalar fields') from exc
    cmp_length = instr(data, secs, 0x28ce5be, b'\x49\x83\xf8', 4)[3]
    too_long = branch_at(data, secs, 0x28ce5c2, b'\x0f\x87')
    if too_long != 0x28d14d1:
        raise ValueError('Unexpected length-failure target')
    if r8 > cmp_length:
        raw = instr(data, secs, 0x28d14d6, b'\x66\xc7\x01', 5)
        return ('length', struct.unpack_from('<H', raw, 3)[0], None)
    on_zero = branch_at(data, secs, 0x28ce5d3, b'\x0f\x84')
    if on_zero != 0x28d241a:
        raise ValueError('Unexpected zero-option target')
    exact(data, secs, 0x28ce5d0, b'\x48\x85\xc0')
    if rax == 0:
        exact(data, secs, on_zero, b'\x45\x31\xc9')
        r9 = 0
    else:
        limit_raw = instr(data, secs, 0x28ce5d9, b'\x48\xb8', 10)
        limit = struct.unpack_from('<Q', limit_raw, 2)[0]
        exact(data, secs, 0x28ce5e3, b'\x49\x39\xc1')
        in_range = branch_at(data, secs, 0x28ce5e6, b'\x0f\x82')
        if in_range != 0x28d241d:
            raise ValueError('Unexpected nonzero-option target')
        if r9 >= limit:
            raw = instr(data, secs, 0x28ce5fe, b'\x66\xc7\x00', 5)
            return ('number', struct.unpack_from('<H', raw, 3)[0], None)
    exact(data, secs, 0x28d243b, b'\x6a\x01')
    instr(data, secs, 0x28d243d, b'\xff\x15', 6)
    return ('call', None, r9)


def registration_wrapper_gate(data, secs, length):
    """Interpret the wrapper's length guard and the two fixed call arguments."""
    checked_u64(length)
    raw = instr(data, secs, 0x285c73f, bytes.fromhex('4983f8'), 4)
    first_rejected = raw[3]
    if branch_at(data, secs, 0x285c743, bytes.fromhex('72')) != 0x285c751:
        raise ValueError('Unexpected registration wrapper length branch')
    if length >= first_rejected:
        raw = instr(data, secs, 0x285c745, bytes.fromhex('66c74310'), 6)
        return ('reject', struct.unpack_from('<H', raw, 4)[0], None, None)
    exact(data, secs, 0x285c75c, bytes.fromhex('c7042400000000'))
    exact(data, secs, 0x285c76e, bytes.fromhex('4531c9'))
    return ('call', None, 0, 0)


def parent_input_gate(data, secs, tag):
    """Interpret the low-range parent input switch, ending at its route split."""
    checked_u64(tag)
    exact(data, secs, 0x2bf0220, bytes.fromhex('488b0e'))
    bias = instr(data, secs, 0x2bf0223, bytes.fromhex('4883e9'), 4)[3]
    exact(data, secs, 0x2bf0227, bytes.fromhex('b84d000000480f43c1'))
    bound = instr(data, secs, 0x2bf0230, bytes.fromhex('4883f8'), 4)[3]
    if branch_at(data, secs, 0x2bf0234, bytes.fromhex('0f8f')) != 0x2bf0340:
        raise ValueError('Unexpected high-range parent route')
    if not bias <= tag <= bias + bound:
        raise ValueError('Tag is outside the selected low-range model')
    special_a = instr(data, secs, 0x2bf023a, bytes.fromhex('4883f8'), 4)[3]
    special_b = instr(data, secs, 0x2bf0244, bytes.fromhex('4883f8'), 4)[3]
    for site in (0x2bf023e, 0x2bf0248):
        if branch_at(data, secs, site, bytes.fromhex('0f84')) != 0x2bf0354:
            raise ValueError('Unexpected special parent route')
    index = tag - bias
    return 'special' if index in (special_a, special_b) else 'vote-gate'


def parent_admission(data, secs, status, prior_flag):
    """Interpret admission status and flag after the selected callee returns."""
    if type(status) is not int or not 0 <= status <= 0xffff:
        raise ValueError('Expected a 16-bit synthetic status')
    if type(prior_flag) is not int or not 0 <= prior_flag <= 255:
        raise ValueError('Expected a synthetic byte flag')
    raw = instr(data, secs, 0x2bf01cf, bytes.fromhex('6681bc24f0010000'), 10)
    success = struct.unpack_from('<H', raw, 8)[0]
    if branch_at(data, secs, 0x2bf01d9, bytes.fromhex('75')) != 0x2bf0200:
        raise ValueError('Unexpected parent admission branch')
    if status == success:
        return ('continue', None)
    exact(data, secs, 0x2bf020d, bytes.fromhex('84db'))
    if branch_at(data, secs, 0x2bf020f, bytes.fromhex('0f84')) != 0x2bf0456:
        raise ValueError('Unexpected parent admission failure branch')
    if prior_flag:
        return ('continue', None)
    raw = instr(data, secs, 0x2bf045e, bytes.fromhex('6641c70424'), 7)
    return ('reject', struct.unpack_from('<H', raw, 5)[0])


def vote_selected_gate(data, secs, flag, predicate, copied_tag):
    """Interpret three selected vote-result conditions, not the surrounding loop."""
    for value in (flag, predicate):
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('Expected a synthetic byte value')
    checked_u64(copied_tag)
    exact(data, secs, 0x28b150a, bytes.fromhex('4084ed'))
    if branch_at(data, secs, 0x28b150d, bytes.fromhex('0f85')) != 0x28b03e0:
        raise ValueError('Unexpected vote-flag branch')
    if flag:
        return 'continue-scan'
    exact(data, secs, 0x28b152a, bytes.fromhex('84c0'))
    if branch_at(data, secs, 0x28b152c, bytes.fromhex('0f84')) != 0x28b03e0:
        raise ValueError('Unexpected vote-predicate branch')
    if not predicate:
        return 'continue-scan'
    raw = instr(data, secs, 0x28b179a, bytes.fromhex('4881fb'), 7)
    marker = struct.unpack_from('<I', raw, 3)[0]
    if branch_at(data, secs, 0x28b17a1, bytes.fromhex('0f84')) != 0x28b03ed:
        raise ValueError('Unexpected vote-marker branch')
    return 'continue-scan' if copied_tag == marker else 'write-selected-tag'


def predicate_short_circuit(data, secs, first, second):
    """Evaluate the caller-visible byte given two stubbed predicate returns."""
    for value in (first, second):
        if type(value) is not int or not 0 <= value <= 255:
            raise ValueError('Expected synthetic byte predicate results')
    exact(data, secs, 0x28a9c60, bytes.fromhex('89c5'))
    exact(data, secs, 0x28a9c6c, bytes.fromhex('4084ed'))
    if branch_at(data, secs, 0x28a9c6f, bytes.fromhex('74')) != 0x28a9ca8:
        raise ValueError('Unexpected two-stage predicate branch')
    if not first:
        exact(data, secs, 0x28a9ca8, bytes.fromhex('31c0'))
        return 0
    exact(data, secs, 0x28a9d5a, bytes.fromhex('89c3'))
    exact(data, secs, 0x28a9d66, bytes.fromhex('89d8'))
    return second


def mode1_core_with_lookup_stubs(data, secs, length, profile_found, code_owner):
    """Interpret selected mode-1 and compact-code branches with lookup stubs.

    Container searches, allocator calls, record writes and error cleanup are
    stubs. The selected status and branch operands are still read from the
    authenticated instructions. This is not a whole-function emulator.
    """
    checked_u64(length)
    if type(profile_found) is not bool or code_owner not in ('absent', 'same', 'other'):
        raise ValueError('Invalid synthetic lookup result')
    exact(data, secs, 0x3c193f2, bytes.fromhex('80bc243002000000'))
    if branch_at(data, secs, 0x3c193fa, b'\x74') != 0x3c19460:
        raise ValueError('Unexpected mode branch')
    maximum = instr(data, secs, 0x3c193fc, b'\x49\x83\xfc', 4)[3]
    if branch_at(data, secs, 0x3c19400, b'\x0f\x87') != 0x3c19648:
        raise ValueError('Unexpected core length branch')
    if length > maximum:
        raw = instr(data, secs, 0x3c19648, b'\x66\xc7\x45\x00', 6)
        return struct.unpack_from('<H', raw, 4)[0], 'reject'
    exact(data, secs, 0x3c19421, bytes.fromhex('83bc245001000001'))
    if branch_at(data, secs, 0x3c19429, b'\x0f\x85') != 0x3c1967f:
        raise ValueError('Unexpected profile-entry branch')
    if not profile_found:
        exact(data, secs, 0x3c196f1, bytes.fromhex('498d4501'))
        exact(data, secs, 0x3c196f5, bytes.fromhex('4839442420'))
        if branch_at(data, secs, 0x3c196fa, b'\x75') != 0x3c19707:
            raise ValueError('Unexpected new-code branch')
        if code_owner != 'absent':
            raw = instr(data, secs, 0x3c196fc, b'\x66\xc7\x45\x00', 6)
            return struct.unpack_from('<H', raw, 4)[0], 'reject'
        result = 'insert'
    else:
        exact(data, secs, 0x3c198f1, b'\xa8\x01')
        if branch_at(data, secs, 0x3c198f6, b'\x0f\x85') != 0x3c19c05:
            raise ValueError('Unexpected compact-code miss branch')
        if branch_at(data, secs, 0x3c1996f, b'\x0f\x84') != 0x3c19bf9:
            raise ValueError('Unexpected existing-code equality branch')
        if code_owner == 'other':
            raw = instr(data, secs, 0x3c1997a, b'\x66\xc7\x45\x00', 6)
            return struct.unpack_from('<H', raw, 4)[0], 'reject'
        result = 'replace'
    raw = instr(data, secs, 0x3c1a11c, b'\x66\xc7\x45\x00', 6)
    return struct.unpack_from('<H', raw, 4)[0], result


def entry_compacts(data, secs, role, first_word, count):
    """Evaluate the selected representation guard of either entry helper."""
    checked_u64(first_word)
    checked_u64(count)
    sites = {'profile': (0x3ccb794, 0x3ccb79d, 0x3ccb7a9, 0x3ccb8ad),
             'code': (0x3cc9cb3, 0x3cc9cbc, 0x3cc9cc8, 0x3cc9e56)}
    if role not in sites:
        raise ValueError('Unknown entry helper')
    neg, compare, branch, no_compaction = sites[role]
    move = '4889e9' if role == 'profile' else '4889d9'
    exact(data, secs, neg, bytes.fromhex(move + '48f7d90f90c1'))
    threshold = instr(data, secs, compare, b'\x48\x83\xf8', 4)[3]
    exact(data, secs, compare + 4, bytes.fromhex('0f92c220ca80fa01'))
    if branch_at(data, secs, branch, b'\x0f\x85') != no_compaction:
        raise ValueError('Unexpected entry representation branch')
    return first_word == 1 << 63 and count < threshold


def collect_constants(data, secs):
    """Read individual immediates from the already pinned instruction forms."""
    specs = (
        ('matcher_j_ordinal', 0x287ea2d, 'c64001', 1),
        ('matcher_k_ordinal', 0x287e94c, 'c64001', 1),
        ('matcher_l_ordinal', 0x287e9dc, 'c64001', 1),
        ('parser_tag_sequence', 0x1df5aa6, '48c7842450010000', 4),
        ('parser_tag_map', 0x1df5b79, '48c7842450010000', 4),
        ('serializer_ordinal', 0x28e7cfd, '41b8', 4),
        ('clone_tag', 0x293704c, '48c703', 4),
        ('parent_forwarded_tag', 0x2bf1621, '48c70424', 4),
        ('parent_admission_success', 0x2bf01cf, '6681bc24f0010000', 2),
        ('parent_admission_rejected', 0x2bf045e, '6641c70424', 2),
        ('parent_input_bias', 0x2bf0223, '4883e9', 1),
        ('parent_input_bound', 0x2bf0230, '4883f8', 1),
        ('parent_special_a', 0x2bf023a, '4883f8', 1),
        ('parent_special_b', 0x2bf0244, '4883f8', 1),
        ('vote_result_marker', 0x28b179a, '4881fb', 4),
        ('apply_bias', 0x28cd7bd, '4883e8', 1),
        ('apply_max_code_bytes', 0x28ce5be, '4983f8', 1),
        ('apply_number_limit', 0x28ce5d9, '48b8', 8),
        ('apply_number_error', 0x28ce5fe, '66c700', 2),
        ('apply_length_error', 0x28d14d6, '66c701', 2),
        ('apply_success', 0x28d5e06, '66c74500', 2),
        ('wrapper_first_rejected_length', 0x285c73f, '4983f8', 1),
        ('wrapper_length_error', 0x285c745, '66c74310', 2),
        ('core_max_code_bytes', 0x3c193fc, '4983fc', 1),
        ('core_volume_threshold', 0x3c1961a, '4881fb', 4),
        ('core_ineligible', 0x3c19623, '66c74500', 2),
        ('core_length_error', 0x3c19648, '66c74500', 2),
        ('core_profile_exists', 0x3c19674, '66c74500', 2),
        ('core_code_exists', 0x3c196fc, '66c74500', 2),
        ('core_success', 0x3c1a11c, '66c74500', 2),
        ('representation_sentinel', 0x3c196bd, '49bd', 8),
        ('profile_rebuild_below', 0x3ccb79d, '4883f8', 1),
        ('code_rebuild_below', 0x3cc9cbc, '4883f8', 1),
    )
    rows = []
    values = {}
    for label, address, prefix_hex, width in specs:
        prefix = bytes.fromhex(prefix_hex)
        raw = instr(data, secs, address, prefix, len(prefix) + width)
        value = int.from_bytes(raw[-width:], 'little')
        values[label] = value
        rows.append((label, hex(address), hex(file_offset(secs, address, len(raw))),
                     raw.hex(), str(value), hex(value)))
    if not (values['parser_tag_sequence'] == values['parser_tag_map'] == values['clone_tag'] ==
            values['parent_forwarded_tag'] == values['apply_bias'] + values['serializer_ordinal']):
        raise ValueError('Selected tag, ordinal and bias disagree')
    if values['matcher_k_ordinal'] != values['serializer_ordinal']:
        raise ValueError('Name matcher and serializer disagree')
    if values['wrapper_first_rejected_length'] != values['apply_max_code_bytes'] + 1:
        raise ValueError('Length guards disagree')
    return values, rows


def literal_rows(data, secs, relocations):
    rows = []
    # The three short identifiers are passed with length one in the selected
    # serializer arm. They are characters, not assumed long field names.
    literals = (
        ('enum_name', 0x28e7cdf, 0x454da0, 16, b'VoteGlobalAction'),
        ('variant_name_argument', 0x28e7ce6, 0x5ff060, 1, b'K'),
        ('first_field_argument', 0x28e7d2c, 0x5fe991, 1, b'c'),
        ('second_field_argument', 0x28e7d56, 0x5fe81b, 1, b'n'),
        ('third_field_argument', 0x28e7d80, 0x5fec77, 1, b'u'),
        ('missing_c_argument', 0x1df5972, 0x5d28be, 1, b'c'),
        ('missing_u_argument', 0x1df5bdc, 0x5d2405, 1, b'u'),
        ('duplicate_u_argument', 0x1df5ea5, 0x5d2405, 1, b'u'),
        ('duplicate_n_argument', 0x1df5ef2, 0x5d1fff, 1, b'n'),
        ('duplicate_c_argument', 0x1df5f3f, 0x5d28be, 1, b'c'),
        ('expecting_type', 0x292d25b, 0x7dad41, 47,
         b'struct variant VoteGlobalAction::ModifyReferrer'),
    )
    for label, site, target, size, expected in literals:
        raw = relative_lea(data, secs, site, target)
        value = read_va(data, secs, target, size)
        if value != expected:
            raise ValueError('Unexpected literal')
        rows.append((label, hex(site), raw.hex(), hex(target),
                     hex(file_offset(secs, target, size)), str(size), value.decode('ascii')))
    info, addend, _ = relocations[0x6422778]
    if info != 8 or addend != 0x5d5dcb:
        raise ValueError('Unexpected variant-description relocation')
    size = struct.unpack('<Q', read_va(data, secs, 0x6422780, 8))[0]
    expected = b'struct variant VoteGlobalAction::ModifyReferrer with 3 elements'
    if size != len(expected) or read_va(data, secs, addend, size) != expected:
        raise ValueError('Variant-description pointer/length mismatch')
    raw = relative_lea(data, secs, 0x1df5ae2, 0x6422778)
    rows.append(('sequence_error_description', hex(0x1df5ae2), raw.hex(), hex(addend),
                 hex(file_offset(secs, addend, size)), str(size), expected.decode('ascii')))
    return rows


def render_tsv(header, rows):
    import io
    output = io.StringIO(newline='')
    writer = csv.writer(output, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return output.getvalue().encode('utf-8')


def collect(data):
    digest = verify_digest(data)
    secs = sections(data)
    fdes = validate_functions(data, secs)
    fn_rows = []
    for role, start in FUNCTIONS:
        fde = fdes[role]
        end = fde['end']
        raw = read_va(data, secs, start, end - start)
        fn_rows.append((role, hex(start), hex(end), hex(file_offset(secs, start, len(raw))),
                        hex(fde['fde']), hex(file_offset(secs, fde['fde'], 1)),
                        hex(fde['cie']), hex(fde['lsda']) if fde['lsda'] else '',
                        str(len(raw)), hashlib.sha256(raw).hexdigest()))
    window_rows = []
    for label, start, end, digest_window in WINDOWS:
        owners = [role for role, _ in FUNCTIONS if fdes[role]['start'] <= start < end <= fdes[role]['end']]
        if len(owners) != 1:
            raise ValueError('Window is not inside one selected FDE')
        raw = pinned_window(data, secs, start, end, digest_window)
        window_rows.append((label, owners[0], hex(start), hex(end),
                            hex(file_offset(secs, start, len(raw))), raw.hex(), digest_window))
    branch_rows = []
    for address, raw_hex, expected in BRANCHES:
        raw = read_va(data, secs, address, len(bytes.fromhex(raw_hex)))
        dest = check_branch(address, raw, raw_hex, expected)
        owners = [role for role, _ in FUNCTIONS if fdes[role]['start'] <= address
                  and address + len(raw) <= fdes[role]['end']]
        if len(owners) != 1 or not fdes[owners[0]]['start'] <= dest < fdes[owners[0]]['end']:
            raise ValueError('Selected branch leaves its recorded FDE')
        branch_rows.append((owners[0], hex(address), hex(file_offset(secs, address, len(raw))),
                            raw.hex(), hex(dest)))
    values, constants = collect_constants(data, secs)
    model_constants = {
        'apply_max_code_bytes': 100,
        'apply_number_error': 0x154,
        'apply_length_error': 0x158,
        'core_max_code_bytes': 100,
        'core_volume_threshold': 1_000_000,
        'core_ineligible': 0xa9,
        'core_length_error': 0xa4,
        'core_profile_exists': 0xa8,
        'core_code_exists': 0xa7,
        'core_success': 0x1a2,
        'representation_sentinel': 1 << 63,
        'profile_rebuild_below': 32,
        'code_rebuild_below': 32,
    }
    if any(values[name] != expected for name, expected in model_constants.items()):
        raise ValueError('A selected decision-model constant disagrees with the target')
    tag = values['parser_tag_map']
    index = tag - values['apply_bias']
    switches = []
    for label, role, lea, expected_table, expected_arm in (
        ('apply', 'action_apply', 0x28cd7cf, 0x5fc024, 0x28ce583),
        ('serializer', 'variant_serializer', 0x28e7471, 0x5fc5c4, 0x28e7cd5),
        ('clone', 'variant_clone', 0x2936442, 0x5fdc9c, 0x2937008),
        ('outer_decoder', 'variant_envelope', 0x29435de, 0x5fe344, 0x2943c20),
        ('parent_first', 'apply_parent', 0x2bf0446, 0x60a558, 0x2bf15bf),
        ('parent_second', 'apply_parent', 0x2bf04ef, 0x60a558, 0x2bf15bf),
    ):
        lea_raw = relative_lea(data, secs, lea, expected_table)
        fde = fdes[role]
        entry, raw, dest = signed_table_target(data, secs, expected_table, index, fde['start'], fde['end'])
        if dest != expected_arm:
            raise ValueError('Selected table arm differs')
        switches.append((label, hex(lea), lea_raw.hex(), hex(expected_table),
                         str(index), hex(tag), hex(entry), hex(file_offset(secs, entry, 4)),
                         raw.hex(), hex(dest), hex(fde['start']), hex(fde['end'])))
    name_rows = []
    matcher = fdes['variant_key_matcher']
    for character, expected in ((ord('J'), 0x22), (ord('K'), 0x23), (ord('L'), 0x24)):
        m_index, entry, raw, dest, ordinal = match_single_variant_name(
            data, secs, character, matcher['start'], matcher['end'])
        if ordinal != expected:
            raise ValueError('One-byte name maps to unexpected ordinal')
        name_rows.append((chr(character), hex(character), str(m_index), hex(entry),
                          hex(file_offset(secs, entry, 4)), raw.hex(), hex(dest), str(ordinal)))
    if name_rows[1][-1] != str(index):
        raise ValueError('Selected name and action ordinal disagree')
    rela_sections = [s for s in secs if s['name'] == '.rela.dyn']
    if len(rela_sections) != 1:
        raise ValueError('Expected one .rela.dyn section')
    slots = {0x64e6a38: 0x3c193d0, 0x6422778: 0x5d5dcb,
             0x6425088: 0x292d250, 0x64e0160: 0x14cf1d0, 0x64df508: None}
    reloc = read_rela(data, rela_sections[0], slots)
    reloc_rows = []
    for slot, expected in slots.items():
        info, addend, offset = reloc[slot]
        if expected is None:
            if info & 0xffffffff != 6 or addend != 0:
                raise ValueError('Selected dynamic import relocation differs')
            symbol = dynamic_symbol_name(data, secs, info >> 32)
            if symbol != 'memcpy':
                raise ValueError('Selected copy slot is not the expected import')
        else:
            if info != 8 or addend != expected:
                raise ValueError('Selected RELATIVE relocation differs')
            symbol = ''
        reloc_rows.append((hex(slot), hex(file_offset(secs, slot, 8)), hex(offset),
                           hex(info), hex(addend), symbol))
    lit_rows = literal_rows(data, secs, reloc)
    edge_rows = []
    direct = (
        ('envelope_to_key_adapter', 0x2943548, 0x1df0720),
        ('key_adapter_to_matcher', 0x1df07cf, 0x287e450),
        ('envelope_to_visitor', 0x2943c34, 0x1df5340),
        ('parent_to_apply', 0x2bf0528, 0x28cd7a0),
        ('parent_to_vote_gate', 0x2bf0323, 0x2699750),
        ('vote_gate_to_process', 0x2699767, 0x28b02b0),
        ('vote_process_clone_input', 0x28b04a2, 0x2936420),
        ('vote_process_predicate', 0x28b1525, 0x28a9b70),
        ('vote_predicate_first', 0x28a9c5b, 0x36c7f70),
        ('profile_entry', 0x3c1941c, 0x3ccb770),
        ('profile_entry_user', 0x3c19665, 0x3ccb770),
        ('code_entry_insert', 0x3c196ec, 0x3cc9c90),
        ('compact_profile_insert', 0x3c19af8, 0x4548960),
        ('compact_code_insert', 0x3c19b6e, 0x45479a0),
        ('tree_remove', 0x3c19c32, 0x39023e0),
        ('code_entry_replace', 0x3c19f48, 0x3cc9c90),
    )
    for label, site, dest in direct:
        raw = relative_call(data, secs, site, dest)
        if dest not in {f['start'] for f in fdes.values()}:
            raise ValueError('Selected call does not target recorded FDE')
        edge_rows.append((label, 'rel32', hex(site), hex(file_offset(secs, site, len(raw))),
                          raw.hex(), '', hex(dest), ''))
    for label, site in (('apply_to_core', 0x28d243d), ('wrapper_to_core', 0x285c771)):
        raw = instr(data, secs, site, b'\xff\x15', 6)
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        if slot != 0x64e6a38:
            raise ValueError('Unexpected core call slot')
        edge_rows.append((label, 'rip_indirect_relative', hex(site),
                          hex(file_offset(secs, site, len(raw))), raw.hex(), hex(slot),
                          hex(reloc[slot][1]), ''))
    site = 0x28a9d54
    raw = instr(data, secs, site, b'\xff\x15', 6)
    slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if slot != 0x64e0160 or reloc[slot][1] != fdes['vote_predicate_second']['start']:
        raise ValueError('Unexpected second predicate relocation')
    edge_rows.append(('vote_predicate_second', 'rip_indirect_relative', hex(site),
                      hex(file_offset(secs, site, len(raw))), raw.hex(), hex(slot),
                      hex(reloc[slot][1]), ''))
    for label, site in (('parent_copy_input', 0x2bf026d),
                        ('parent_copy_to_gate', 0x2bf0301),
                        ('parent_copy_return_a', 0x2bf0419),
                        ('parent_copy_return_b', 0x2bf0496),
                        ('vote_gate_copy_result', 0x2699903),
                        ('vote_process_copy_result', 0x28b19a0)):
        raw = instr(data, secs, site, b'\xff\x15', 6)
        slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
        if slot != 0x64df508:
            raise ValueError('Unexpected dynamic copy import slot')
        edge_rows.append((label, 'rip_indirect_import', hex(site),
                          hex(file_offset(secs, site, len(raw))), raw.hex(), hex(slot),
                          '', 'memcpy'))
    # The vtable's function pointer and the visitor's description pointer are
    # static relocations; the dynamic transfer of the parsed object is separate.
    if reloc[0x6425088][1] != fdes['expected_variant_name']['start']:
        raise ValueError('Expected-name vtable target mismatch')
    relative_lea(data, secs, 0x1df5e70, 0x6425070)
    gate_rows = []
    gate_tags = (values['parent_input_bias'],
                 values['parent_input_bias'] + values['parent_special_a'],
                 values['parent_input_bias'] + values['parent_special_a'] + 1,
                 values['parent_input_bias'] + values['parent_special_b'],
                 values['parent_input_bias'] + values['parent_special_b'] + 1,
                 tag - 1, tag, tag + 1,
                 values['parent_input_bias'] + values['parent_input_bound'])
    for input_tag in gate_tags:
        path = parent_input_gate(data, secs, input_tag)
        expected = ('special' if input_tag - values['parent_input_bias'] in
                    (values['parent_special_a'], values['parent_special_b']) else 'vote-gate')
        if path != expected:
            raise ValueError('Selected parent input gate disagrees with model')
        gate_rows.append((hex(input_tag), input_tag - values['parent_input_bias'], path))
    if parent_input_gate(data, secs, tag) != 'vote-gate':
        raise ValueError('Selected input tag does not enter vote-gate helper')
    admission_rows = []
    success_status = values['parent_admission_success']
    rejection_status = values['parent_admission_rejected']
    for status, flag in itertools.product((0, success_status), (0, 1)):
        actual = parent_admission(data, secs, status, flag)
        expected = ('reject', rejection_status) if status != success_status and not flag else ('continue', None)
        if actual != expected:
            raise ValueError('Parent admission branch sequence disagrees with model')
        admission_rows.append((hex(status), flag, actual[0], '' if actual[1] is None else hex(actual[1])))
    vote_gate_rows = []
    marker = values['vote_result_marker']
    for flag, predicate, copied_tag in itertools.product((0, 1), (0, 1), (tag, marker)):
        actual = vote_selected_gate(data, secs, flag, predicate, copied_tag)
        expected = ('write-selected-tag' if not flag and predicate and copied_tag != marker
                    else 'continue-scan')
        if actual != expected:
            raise ValueError('Selected vote-result branch sequence disagrees with model')
        vote_gate_rows.append((flag, predicate, hex(copied_tag), actual))
    predicate_rows = []
    for first, second in itertools.product((0, 1), repeat=2):
        result = predicate_short_circuit(data, secs, first, second)
        if result != (second if first else 0):
            raise ValueError('Two-stage predicate differs from its bounded model')
        predicate_rows.append((first, second, result))
    arm_rows = []
    length_values = (0, 1, values['apply_max_code_bytes'] - 1,
                     values['apply_max_code_bytes'], values['apply_max_code_bytes'] + 1,
                     values['apply_max_code_bytes'] + 2, MAX_U64)
    flag_values = (0, 1, 2, MAX_U64)
    limit = values['apply_number_limit']
    word_values = (0, limit - 1, limit, limit + 1, MAX_U64)
    for length, flag, value in itertools.product(length_values, flag_values, word_values):
        actual = instruction_arm(data, secs, length, flag, value)
        expected = selected_arm_model(length, flag, value, limit)
        if actual != expected:
            raise ValueError('Instruction-level gate and decision model disagree')
        reason, status, forwarded = actual
        arm_rows.append((str(length), str(flag), str(value), reason,
                         '' if status is None else hex(status),
                         '' if forwarded is None else str(forwarded)))
    wrapper_rows = []
    wrapper_limit = values['wrapper_first_rejected_length']
    for length in (0, wrapper_limit - 2, wrapper_limit - 1, wrapper_limit,
                   wrapper_limit + 1, MAX_U64):
        actual = registration_wrapper_gate(data, secs, length)
        expected = (('reject', values['wrapper_length_error'], None, None)
                    if length >= wrapper_limit else ('call', None, 0, 0))
        if actual != expected:
            raise ValueError('Wrapper instruction gate disagrees with its model')
        reason, status, mode, word = actual
        wrapper_rows.append((length, reason, '' if status is None else hex(status),
                             '' if mode is None else mode, '' if word is None else word))
    parser_rows = []
    for n in range(5):
        for keys in itertools.product(('c', 'n', 'u', 'x'), repeat=n):
            parser_rows.append((''.join(keys) or '-', selected_parser_model(keys)))
    core_rows = []
    maximum = values['core_max_code_bytes']
    threshold = values['core_volume_threshold']
    for mode, length, user_found, total, profile, code_owner in itertools.product(
            (0, 1), (0, maximum, maximum + 1), (False, True),
            (0, threshold - 1, threshold, MAX_U64), (False, True), ('absent', 'same', 'other')):
        status, result = selected_core_model(mode, length, user_found, total, profile, code_owner)
        core_rows.append((mode, length, int(user_found), total, int(profile), code_owner,
                          hex(status), result))
    mode1_rows = []
    for length, profile, code_owner in itertools.product(
            (0, maximum, maximum + 1), (False, True), ('absent', 'same', 'other')):
        actual = mode1_core_with_lookup_stubs(data, secs, length, profile, code_owner)
        expected = selected_core_model(1, length, False, 0, profile, code_owner)
        if actual != expected:
            raise ValueError('Selected mode-1 instruction decisions disagree with the model')
        mode1_rows.append((length, int(profile), code_owner, hex(actual[0]), actual[1]))
    representation_rows = []
    sentinel = values['representation_sentinel']
    rebuild = values['profile_rebuild_below']
    for role, first_word, count in itertools.product(
            ('profile', 'code'), (0, sentinel),
            (0, rebuild - 1, rebuild, rebuild + 1, 2 * rebuild - 1, 2 * rebuild)):
        actual = entry_compacts(data, secs, role, first_word, count)
        expected = first_word == sentinel and count < rebuild
        if actual != expected:
            raise ValueError('Selected representation guard disagrees with the model')
        representation_rows.append((role, hex(first_word), count, int(actual)))
    sum_rows = []
    for words in ((), (0,), (threshold - 1,), (threshold,), (MAX_U64,),
                  (MAX_U64, 0), (MAX_U64, 1), (MAX_U64 - 1, 2, 1)):
        total, count = saturated_sum(words)
        sum_rows.append((','.join(map(str, words)), total, count))
    files = {
        'functions.tsv': render_tsv(('role', 'start_va', 'end_va_exclusive', 'file_offset', 'fde_va',
                                     'fde_file_offset', 'cie_va', 'lsda_va', 'byte_count', 'sha256'), fn_rows),
        'windows.tsv': render_tsv(('label', 'role', 'start_va', 'end_va_exclusive', 'file_offset',
                                   'raw_hex', 'sha256'), window_rows),
        'branches.tsv': render_tsv(('role', 'site_va', 'file_offset', 'raw_hex', 'taken_va'), branch_rows),
        'switches.tsv': render_tsv(('role', 'lea_va', 'lea_hex', 'table_va', 'ordinal', 'tag', 'slot_va',
                                    'slot_file_offset', 'slot_hex', 'target_va', 'fde_start', 'fde_end'), switches),
        'name-neighbors.tsv': render_tsv(('name', 'byte', 'table_index', 'slot_va', 'file_offset',
                                          'slot_hex', 'target_va', 'ordinal'), name_rows),
        'relocations.tsv': render_tsv(('slot_va', 'slot_file_offset', 'rela_file_offset',
                                       'r_info', 'addend', 'dynamic_symbol'), reloc_rows),
        'literals.tsv': render_tsv(('role', 'lea_va', 'lea_hex', 'literal_va', 'literal_file_offset',
                                    'length', 'text'), lit_rows),
        'constants.tsv': render_tsv(('role', 'site_va', 'file_offset', 'instruction_hex', 'decimal', 'hex'), constants),
        'calls.tsv': render_tsv(('role', 'kind', 'site_va', 'file_offset', 'raw_hex', 'slot_va',
                                 'target_va', 'dynamic_symbol'), edge_rows),
        'parent-gate-vectors.tsv': render_tsv(('input_tag', 'normalized', 'route'), gate_rows),
        'parent-admission-vectors.tsv': render_tsv(('callee_status', 'prior_flag', 'route',
                                                    'result_status'), admission_rows),
        'vote-gate-vectors.tsv': render_tsv(('prior_flag', 'predicate_byte', 'copied_tag',
                                             'route'), vote_gate_rows),
        'predicate-gate-vectors.tsv': render_tsv(('first_byte', 'second_byte',
                                                  'returned_byte'), predicate_rows),
        'arm-vectors.tsv': render_tsv(('length', 'option_tag', 'option_value', 'result', 'status',
                                       'forwarded_word'), arm_rows),
        'wrapper-vectors.tsv': render_tsv(('length', 'result', 'status', 'mode',
                                           'forwarded_word'), wrapper_rows),
        'parser-vectors.tsv': render_tsv(('keys', 'presence_model_result'), parser_rows),
        'core-vectors.tsv': render_tsv(('mode', 'length', 'user_found', 'volume_sum', 'profile_found',
                                        'code_owner', 'status', 'logical_result'), core_rows),
        'mode1-core-vectors.tsv': render_tsv(('length', 'profile_found', 'code_owner',
                                              'status', 'logical_result'), mode1_rows),
        'representation-vectors.tsv': render_tsv(('helper', 'first_word', 'count',
                                                   'enter_rebuild'), representation_rows),
        'sum-vectors.tsv': render_tsv(('words', 'saturated_total', 'overflow_callbacks'), sum_rows),
    }
    summary = {
        'target_sha256': digest,
        'selected_functions': len(fn_rows),
        'pinned_windows': len(window_rows),
        'conditional_branches': len(branch_rows),
        'selected_switch_entries': len(switches),
        'selected_name_matcher_entries': len(name_rows),
        'selected_relocations': len(reloc_rows),
        'selected_calls': len(edge_rows),
        'parent_input_gate_vectors': len(gate_rows),
        'parent_admission_vectors': len(admission_rows),
        'vote_result_gate_vectors': len(vote_gate_rows),
        'predicate_short_circuit_vectors': len(predicate_rows),
        'literal_records': len(lit_rows),
        'arm_instruction_model_vectors': len(arm_rows),
        'registration_wrapper_vectors': len(wrapper_rows),
        'synthetic_parser_presence_vectors': len(parser_rows),
        'synthetic_core_decision_vectors': len(core_rows),
        'mode1_stubbed_instruction_vectors': len(mode1_rows),
        'representation_guard_vectors': len(representation_rows),
        'synthetic_saturating_sum_vectors': len(sum_rows),
        'scope': 'Selected static paths and bounded synthetic models; not node execution or full CFG coverage.',
    }
    files['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode()
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    files = collect(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (args.out / name).write_bytes(files[name])
    print(f'Generated {len(files)} selected evidence files for node #115.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print(f'node115_referrer_action: {exc}', file=sys.stderr)
        raise SystemExit(1)
