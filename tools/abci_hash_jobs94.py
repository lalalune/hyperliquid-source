#!/usr/bin/env python3
"""Inspect node 94 app-hash job partitioning, collection and unwind records.

All extraction is static. Only selected x86 instruction forms are decoded;
reported FDEs are unwind extents, not proof of source-function boundaries.
"""
import argparse
import bisect
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
import elf_index
import fde_extents

TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected starts are candidate code entries; ends come from FDE pc ranges.
# Pinned full-range hashes also make post-authentication corruption detectable.
FUNCTIONS = {
    0x4f7c290: ('task_enqueue', 0x4f7c83d, '8052e0a35c1ba3f050aae626a308dbf288f9f76dda1c34731de3f2a76a40e95e', '0bba41626fb7e8a4bc478bb73e29dc931a6a0e783137d832f53154519f73539f'),
    0x1d8b750: ('task_poll', 0x1d8bbf1, 'ac037ee3dff1760f2800246cabc36dece3262632e84ddecb2f50c4c0f6bfbcb4', '79fff42edb10abfdafb8a4dd3d419e550344b7260282eb425f2f0c4c75af3001'),
    0x1dd1db0: ('finish_list', 0x1dd1f6d, '4f5b9e285f9ac06a704c649ce7775e65204216bcde07edf874a7bb15d9da22be', '12b2f380a46eb213b557e9d35a04173a70796d0194d340e01c29954388cc3dc8'),
    0x22a4500: ('task_thunk', 0x22a4505, 'e70bb7f546a1ad6acc32c31bf36ac77e1fa4e901b074beeecc22d119a93db5b8', None),
    0x2289e30: ('partition', 0x228a084, 'ded5648951c540ab182447e3a7767e69e590c14cb2f9e9b280f5009d66e9e2b5', 'dbd6af8e8f8a910facf8555c321ab86fe55a04c5d85ae5441386b22e369731e8'),
    0x251c2e0: ('serial_collect', 0x251c415, '42f31edf90e5ed48ec00c6da044a23e9ea3d9aa00bf2e1e6afc2af00b50f2e7b', 'c8875418a95677d91027a0344bab1e3b41bb18f1a1d0b1b4420be981ae392fb1'),
    0x2428460: ('dispatch_by_tls', 0x24284e7, '33f5e3023bba4d9f8463d0867b941031b9d79bcd6ceaa312ae9bd83c90d1a35f', '42d09fdca98cb515e52eafb93e23514e6c6d099ed8fdb61189af51fd1b3b6f77'),
    0x2404010: ('parallel_join', 0x240468c, '777d911b4cf99be444eb786f29774380e797d3fbdc862dc96bc7f810a4ab2df1', 'b29548d73241a9bf85836b6433b63cf37988299e3e0ed90463b303afca595786'),
    0x24a8800: ('right_worker', 0x24a8a4f, '05fe2313a9647257259e1ad227445b9c16291ee758b89999c206966b48c0ca8f', 'bc4ef8672f30c37ca728d7af0f9d471830a5e070fb843ce3f2e9fb2c83eb7b84'),
    0x1eacd90: ('invoke_and_drop', 0x1eace35, 'c5c17c156073b5fae2473a7a6139fa14807eb27a070e332b3f88db56701ead3b', '3f8dd32760a634428a41e49579775fd1d1c38a36aff96901e0b0203bfa768071'),
    0x2505660: ('drop_remaining_pairs', 0x2505748, '15e36b2f59d78984a519bba1ccf752bf50b2d9371b9a9f0e4750356e82f12189', 'ffa2d5e43773872d364a1382aec6ce29e5e1ecdb1614485d751a296dcbc092e5'),
    0x2452e50: ('drop_split', 0x2452ec6, 'b288c67cda749566c7528fee53df230abd63b735e41edc0593751b95073d4c8e', '052db7845a0855dafc61ea3122d72385ea5b46064f918f9b9fb02d31bcaa9883'),
    0x241bd40: ('dispatch_without_tls', 0x241c033, '32f4bc6f419cb9b3f1ca0422c86953ce29fe568adc4ca67f1b6008163f61d5ab', '1e1df23e10a0702a6e793966b326838bf92804f2c6cbdb3140859fbd9ff8fd06'),
    0x24276f0: ('dispatch_other_pool', 0x24279d6, '8f6ac450465c61891311cd6d83bd82edab46ef6cacc0a5dca231911e965a1277', 'b91d08fc4e7c6af7bd96fd0159e4964b9b1e776d90110bc9ef6cb2d67e2304c7'),
    0x2490b20: ('callback_without_tls', 0x2490df1, '37ed93a68b9f9a497584e667df8813cd501edfa66f46d31e9e347dc35d3ed86a', '12ce8325f333cd6eb26cee5aa6c893c782fe7185d431913daab823e9a4fc09d3'),
    0x24a59d0: ('callback_other_pool', 0x24a5d1d, 'b14a31ee3a39b10b2762d9f026f5d7d7b7d908fc5cd4bd10a2a9ddede4f7b9cd', '653fa94150fb85c0f972ee565d6fa0421ecd21bead325b9d9e10a4993cf494d7'),
    0x2456fa0: ('drop_external_context_a', 0x24570bc, '3aa01f723fa86944ab5c8df0516a39188f00d5574cb74bf27b1a260d61949703', '3a622e97ca394ffe6638e2df214dfab75f70b9421a3bca4fd91decad1f712366'),
    0x2456250: ('drop_external_context_b', 0x2456368, '688e8daa1d4c00359967d8568e720712c0bf09039e966b655ebbc05aa9ea1ba4', '7283df0844211acb9c1837adf60309a0b39686dfa622ede22bb4f530647a3fed'),
    0x245f590: ('drop_queued_job', 0x245f65e, 'e8d6e33dad202bfb295d6eff67f812e2ba14eab4d24ab122b3ad8692c9cc9d0e', 'c5c424411a0a9f79e7c8d0c6f448577387fdbd4ac1e2dbab48c5b7558c5758fd'),
    0x2453ce0: ('drop_tagged', 0x2453d69, '2302139ff08cbd9763f680b25e27e96a36a84e478dc5bf2e1e8ba5f67dd2502a', '679e0c4ea037adf049d8b9146f6dc9312c4d80b4acca2e709cfef0e8dd545f16'),
}

# These slices are selected observations, not a complete disassembly or CFG.
WINDOWS = (
    ('context_host_assemble', 0x22b5507, 0x22b551f, '0a768d3d40839166fbf03d51d4b9aa1a4e03e36dd8d41c3dc799fbbeda3b4f2d'),
    ('context_host_task_data', 0x22b5577, 0x22b5589, 'eda1b973a327b989a2ad8bddecb800039dddb881ccbb4d6a059166a36f5ae3e9'),
    ('context_host_task_copy', 0x22b55cc, 0x22b55d7, '808de4c98ee7523eaf50955d1bd80a342b02c634f8e1be4a76d0b0e1a543f995'),
    ('context_host_constructor_args', 0x22b55eb, 0x22b55fa, 'e23a39c34fcf53d52d5250e01c82673882ef023fd9954bdb92af1cff78756b94'),
    ('context_constructor_save', 0x2020cf1, 0x2020cfa, '2837f4c7a52fc2c3fd227a97d6891984fdd6b2817e565637333fc1aead8ce510'),
    ('context_constructor_src_ref', 0x2020d67, 0x2020d6a, '2d9eb11b4dd8ee6ea21c9a916020b0705e399b16d1fa660adb9116ac2887d693'),
    ('context_constructor_src_empty', 0x2020d7c, 0x2020d7f, '2d9eb11b4dd8ee6ea21c9a916020b0705e399b16d1fa660adb9116ac2887d693'),
    ('context_constructor_input', 0x2020d82, 0x2020d96, '58203c7e8ea62fdd463ce6b7966601fe6d962cc3fc7c3ed17f5d006496023119'),
    ('context_constructor_state', 0x2020d99, 0x2020db1, 'a7a08028d378fd46dab0200107389c9a9231e0b46a6128900511b189c2f139dc'),
    ('context_constructor_table', 0x2020db1, 0x2020dbf, '70a740541297b868d94204b2d48e731731bf7eccc492ed1952938e0995c24f48'),
    ('context_constructor_payload', 0x2020def, 0x2020e07, '0c0b0364c9436494838841ef1d1d84a56a7dfa01c1f83167463a6ae3326878a2'),
    ('context_constructor_alloc', 0x2020e31, 0x2020e3b, '360919cced3a58e56e0d971cdcd150066fd68dc2cd4f9f4862ddbfbe9114310d'),
    ('context_constructor_heap_copy', 0x2020e4a, 0x2020e5d, '0880cfd4db75fd74f243230f966fd6e5b1358a7d80a8d7f2cf88da13012b8a49'),
    ('context_scheduler_submit', 0x2020e63, 0x2020e79, '1dd22189ffd399dfca9b1ffd98b94ef698cb729e3c6f5bee2d012a0b6c2f8f7e'),
    ('context_bridge_take', 0x2017d41, 0x2017d75, '6acf32a91f28c702cc41255c924bd9be7d056ccd7b43bb1ecdf75ee43875e9f7'),
    ('context_bridge_repack', 0x2017da3, 0x2017dc0, 'c1586362cd43b93b6d54e830d65ee60df96074fcdd8a91cbf067403bf5820053'),
    ('context_bridge_apply', 0x2017fb4, 0x2017fc7, 'f195e527074bfece762be5f8f9939e50a8b2aa98c13a33c73b275234e9fce821'),
    ('context_builder_jobs', 0x2756fb1, 0x2756fc5, '44cc9dc89fee4a896f4c3ca16267991ad23b3b428b9a33e0743361a2ca3c36e5'),
    ('context_builder_input', 0x2756fc5, 0x2756ffe, 'ad477b36d72a0bf7c0953b53042e19e259028a950d3e29652444749b435bc765'),
    ('context_builder_result', 0x2757003, 0x275701f, '2dee8c1ac4a2bfda5a61a54fb587109bbe08c2cbd1bf6eeae1fe4d45b3ce10b1'),
    ('context_builder_hash_input', 0x2757097, 0x27570a7, '1268b682f027707279c95bb39a8cc2ab0212a9beccc08a0fff69781e0ccd2bb2'),
    ('context_vector_to_adapter', 0x25b7f34, 0x25b7f87, '9b0c9d9fcba633fb8ccefce07fd17ca82daf563d88ccf774591e1f6e47a68fef'),
    ('context_vector_result_check', 0x25b7f87, 0x25b7faf, '6c96756e009b2438b4f4c6589ae706567379d4158b83ffe98a6f912cea5059a7'),
    ('context_vector_bad_result', 0x25b8002, 0x25b804a, 'e702e99a865bb91aef18b4584d0eefbae5199779383da04fca1e66357188fbec'),
    ('context_adapter_input', 0x255d27e, 0x255d2bc, 'ee4946e151c4493bdaaba94d3802411b29f72f4eea06e69600a74f8cd8ed074d'),
    ('context_adapter_partition_args', 0x255d2d9, 0x255d325, '9be8983154879d8e24f03aebbcc6c868a2f9ae18e64b9a4d3f4bdf0c25369271'),
    ('context_list_sentinel', 0x1e5de66, 0x1e5de70, 'a78af96bc6e860d2b09855b5854bbfc2fff7e24b7b0dc0034b9884b00b5a50b6'),
    ('context_list_input', 0x1e5de8b, 0x1e5dea7, '7d015acce00dec1abc482ac3434dfd710fcfdb496da1ed1deb67ac8024b4b924'),
    ('context_array_begin', 0x1e5deb4, 0x1e5decd, 'ce45123614fba800c2a526b4da0b967c5957c92810cdb63608dcbc244cfb7c36'),
    ('context_list_init', 0x1e5decd, 0x1e5dee4, '73d4eb066434cb94b3dc71c49650a01015f71320b7b8e8b885bae93bcee6b3ea'),
    ('context_list_hex_args', 0x1e5df2b, 0x1e5df34, '2eea738fc899d3f3979785e33fa5df16d5536c8828d465c66ad7a0ae6f8a9934'),
    ('context_list_text_handoff', 0x1e5df37, 0x1e5df4c, 'e4576a5d4d4ea0f0cfa9b72717ab219faf5465267e792871df7b872ed1a50822'),
    ('context_list_next', 0x1e5df4c, 0x1e5df56, '4b0a2b0b15683986fa654935f026e69056b49542e6a6066048e33482a7769978'),
    ('context_list_finish_args', 0x1e5df56, 0x1e5df95, '95902453eae66242cfb4092fd1ae5453ed341a5b684605c0aa7b83045f53ebf2'),
    ('context_array_u16_write', 0x25a9cde, 0x25a9cec, '1aac276ba4127a063e1d56722454770c2cc4d3e22033bca045b20103a2d7017f'),
    ('context_string_str8', 0x25aa81f, 0x25aa82a, 'a736456f146e994bfffb918051ea305979a49982112afcee8562bd47f9f77093'),
    ('context_string_length', 0x25aa93a, 0x25aa950, 'ed9f444aeec933c56d49fcb8eebc6cc45f376b339332cf4872e0de04c50bec21'),
    ('context_string_payload', 0x25aabad, 0x25aabc6, 'ba4e25f963137e738d679e007fa4f0f981cf99bf5d8ad5d874079058f84d6ca2'),
    ('context_hash_result_gate', 0x28192b1, 0x28192db, '8f6da3c6d3e60a34bd336a86b80e03ebf0da43a6b4ad7100daecc86573cf3ba8'),
    ('context_hash_sponge_setup', 0x28192db, 0x281935b, '68b6084f2bf08cf15e324892d5d8a92c1047fc3456753d73bcfc1704c1475af7'),
    ('task_entry_flags', 0x1d8b77f, 0x1d8b7e7, '8c1b37a76c257de825b8cc622933fd941102821adb9e399a9b1488a7f1738394'),
    ('task_table_jump', 0x1d8b7d4, 0x1d8b7e7, '47dc9c60f287d540a8561b239e7451f235b7f9c68b1ec992e64e0b2431bf5fc1'),
    ('task_poll_and_result', 0x1d8b7e7, 0x1d8b86d, '46590b40dcfdb8306e4305c9a7b7a7d4eb9db81ba9415715b2a28436b4a5a86f'),
    ('task_publish', 0x1d8b86d, 0x1d8b8e7, '9ad4e7a64f2ae8810c133b621d1061ef17146c69022b84850367433f2e62be9d'),
    ('task_pending', 0x1d8b946, 0x1d8ba10, '29cdd368b16273a0377d5b3ceaf6096f19fb5aebe95c3c34236b3fcef428ef0e'),
    ('scheduler_lock', 0x4f7c2a3, 0x4f7c2d1, '121ced40637fd975a99114a05fc5c1163f7020f36b51c445f15bd6a80c385b8f'),
    ('scheduler_closed', 0x4f7c2d1, 0x4f7c2fc, 'adeb720f38976e6dcef8c7af82599da1ff6e454a19bb0d7d308f05d0e2c4d0d7'),
    ('scheduler_enqueue', 0x4f7c30e, 0x4f7c35e, 'f9eea72f43304f2bdd25e2d21c27b59d760eb91151bc98408f36ca626cf8bdec'),
    ('scheduler_slow_and_error', 0x4f7c64e, 0x4f7c67f, '316b681f4dd1b9ffa0a974e749b17ee8833ef08a17b770b56ac0d047f8968ab7'),
    ('finish_sentinel', 0x1dd1dbe, 0x1dd1dec, 'ae0d33af539d9797edea3ec4efd07943b16bce674f2b4d7807d5d41765013d7c'),
    ('finish_buffered_begin', 0x1dd1dec, 0x1dd1e3c, 'd27509736e2891864ba09f2ab4dfa5d91d2413e6724280376e3332c7cd0b821e'),
    ('finish_error_drop', 0x1dd1e3c, 0x1dd1e99, '78f25faf32108e1d925574798f2cd6b97c5c199167f1042da94658c406524192'),
    ('finish_buffer_copy', 0x1dd1eed, 0x1dd1f27, '65bc24cd9401e36953d91d46f4126ff3fcb7c6d06db66e08bd3ae04aea190589'),
    ('split_test', 0x2289e5a, 0x2289eb1, '8135ca0554ce71c0b3669dcf0841d86b57d57b875e877309cf4f7f8067390af7'),
    ('split_budget', 0x2289eb1, 0x2289ef3, 'e09d9bcee92f10c6270022b9268436a606dd176d954a56b912a2cbc4245585cc'),
    ('split_ranges', 0x2289ef3, 0x2289fac, '488831d12713cc8401d4d1d6b08b3ab8b0c7b60eb04acd9a6c8c90fe8f0b4fcd'),
    ('split_merge', 0x2289fb1, 0x2289fea, '77eee686b3b73c58d8b0d9cb8a67f2eb1987cbaeaa3d2b8ce7c6dce14f23cf7a'),
    ('leaf_bounds', 0x251c2ee, 0x251c340, '91e760f979064b999dc2ff93d8479b8f910be75880d0aa09823b633c2945ec57'),
    ('leaf_callback_and_write', 0x251c340, 0x251c38b, '160286cf5cbfd6ed38be5d5eda0abaf2452831656e2ab2d0dff3c27cc8e9a784'),
    ('leaf_return', 0x251c390, 0x251c3ca, '6a6b51dbfe18616ace29d56cfde6cce65a3d67057bd8ccf75efd7d440ce88c15'),
    ('leaf_fail_and_unwind', 0x251c3ca, 0x251c415, 'ba545525ae06a7bf0b2815d2bbb30f520fe83b27b09e008ac671d82e08179d05'),
    ('dynamic_callback', 0x1eacd95, 0x1eacddb, 'c3d96da29918075624f2742928c810467a4049bd4fbae448c75d7e1e7e46fb31'),
    ('callback_cleanup', 0x1eacde4, 0x1eace35, '45d2c1904be146c52194669868adf51245c9003b849310a5944a700b1da43aa9'),
    ('drop_pairs', 0x250566b, 0x25056d8, '6d73717399ed6f2b9b287fb59dde6dff34e086f0ee93586326288901adbf4911'),
    ('dispatch_tls', 0x2428465, 0x24284ce, 'a7a237c00be5030bf9cf0b2b9515eca8a00ba88d4073892744bc103f170a06f2'),
    ('dispatch_cleanup', 0x24284ce, 0x24284e7, '268dbe4d576baab6d801ddd056e4297c94b9608b0d3f1612fef3335c23a69bf7'),
    ('join_enqueue', 0x2404107, 0x2404152, '0bac1da769fbac8a86503ff3f9fdbda86bfb0a9991d6e32c36bfb1d482f4757e'),
    ('join_left_args', 0x24041ab, 0x2404203, '9d6977184a91fed2b1762a07faaba0f2ce3a0c10db391ef333cdce9057d2ddbc'),
    ('join_wait', 0x2404230, 0x24042b8, '97234b908bf785acbcbefd15d90fddfdba5ea659e743ae14bb66209b3328da99'),
    ('join_ordered_return', 0x24042b8, 0x2404342, 'ddc18d68d8b3b546404abc2d37415d9ee6b8230b4c6b88ad7c574997395c6ae9'),
    ('join_inline_right', 0x24043be, 0x24044b5, 'cbfaf55c99006928f761ad2ca7335a83ec0aae29444bae311a0f703b949d1fa7'),
    ('join_cleanup', 0x240461c, 0x240468c, 'b0fb4fa0d755dd2a7b66294c89c102a2c08528ebf917f961438ea160049b3b10'),
    ('right_worker_inputs', 0x24a880e, 0x24a8877, '7182fe5a95fe25a4f194c46617781bcef6ea4e86db310ea170ff906b187ad481'),
    ('right_worker_result', 0x24a8886, 0x24a88ed, '9c539b4c87b41b95f424299fa918385f28814438049886689279224b76967644'),
    ('right_worker_publish', 0x24a88ed, 0x24a892f, '0b7874381ca234b29f4e1df6f170fce9c36cab4fd93f616da5d99222d11a3091'),
    ('foreign_submit_a', 0x241bde5, 0x241be06, '460f2ebbb12f03a5b9fb6e3c1823e2bd7f97ed98a31b9b42dc4c8288d1724457'),
    ('foreign_callback_a', 0x2490c24, 0x2490c38, '2306ef1ccc77d82972521b9b8458d1115c4014593b10ac18c201df4b62081751'),
    ('foreign_submit_b', 0x242778b, 0x24277a7, '8c5aa502800373d689d7a14e8a9f5cae6fd4c6cc2c5ec5ffcf37bd1d4d803425'),
    ('foreign_callback_b', 0x24a5ad2, 0x24a5ae6, 'ed89a6ed6ff2696dcfcafb1b38d789bbba7ade5dc7b83517c35872d17f53d4c2'),
    ('cleanup_split', 0x2452e54, 0x2452e98, '7c01c247acad99b0e9131a888b8fd5147b5bfdde12195181e8ff03e08c2e92b1'),
    ('cleanup_context_a', 0x2456fa5, 0x2456ff2, 'a72bd0a90460dd2225b25d86fdc37d2740a473669f56bf43d98c25529273bf77'),
    ('cleanup_context_b', 0x2456255, 0x245629e, 'c0916002fc5d13789d4c70504ee1296a5e01b215335c6190694087d19d3a2b8b'),
    ('cleanup_job', 0x245f595, 0x245f5c2, '5269d0791092629364d9085eefe5ac4b440740e7541f4be0199478b8481fe553'),
    ('cleanup_tagged', 0x2453ce5, 0x2453d34, '90aac9e06fedd552f7137294e96032620ac5d99d08b9b6b5b440107b7089f87f'),
)

# A guard and branch are each pinned; targets are decoded from signed ELF bytes.
BRANCHES = (
    ('enqueue_lock_slow', 0x4f7c2bb, 0x4f7c2c1, 'f0410fb04e40', '0f8587030000', 0x4f7c64e),
    ('enqueue_open', 0x4f7c2c7, 0x4f7c2cf, '4180bec400000000', '743d', 0x4f7c30e),
    ('enqueue_closed_sub_carry', 0x4f7c2d1, 0x4f7c2d6, 'f049832f40', '0f8285030000', 0x4f7c661),
    ('enqueue_space', 0x4f7c316, 0x4f7c319, '4839c8', '7512', 0x4f7c32d),
    ('task_missing_queued_flag', 0x1d8b7a9, 0x1d8b7ab, 'a804', '0f8499020000', 0x1d8ba4a),
    ('task_idle_bits', 0x1d8b7b1, 0x1d8b7b3, 'a803', '74db', 0x1d8b790),
    ('task_low_count', 0x1d8b7b5, 0x1d8b7b9, '4883f83f', '0f86a4020000', 0x1d8ba63),
    ('task_poll_tag_two', 0x1d8b859, 0x1d8b85d, '4883fd02', '0f84e3000000', 0x1d8b946),
    ('task_poll_tag_three', 0x1d8b863, 0x1d8b867, '4883fd03', '0f8468030000', 0x1d8bbd5),
    ('finish_direct_or_buffered', 0x1dd1dd1, 0x1dd1dd4, '48f7d8', '7116', 0x1dd1dec),
    ('finish_header_error', 0x1dd1e0c, 0x1dd1e10, '4883f802', '7552', 0x1dd1e64),
    ('finish_capacity_fits', 0x1dd1e2e, 0x1dd1e31, '4939ec', '0f86b6000000', 0x1dd1eed),
    ('finish_size_carry', 0x1dd1e37, 0x1dd1e3a, '4c01e7', '735d', 0x1dd1e99),
    ('finish_copy_grow', 0x1dd1eed, 0x1dd1ef0, '4939ec', '7735', 0x1dd1f27),
    ('split_half_min', 0x2289e66, 0x2289e69, '4d39c4', '7346', 0x2289eb1),
    ('split_thief_flag', 0x2289eb4, 0x2289eb6, '84d2', '7417', 0x2289ecf),
    ('split_budget_zero', 0x2289ecf, 0x2289ed2, '4d85ed', '7497', 0x2289e6b),
    ('split_right_count_underflow', 0x2289efd, 0x2289f00, '4d29e7', '0f82f9000000', 0x2289fff),
    ('split_output_count_underflow', 0x2289f14, 0x2289f17, '4c29e0', '0f82fb000000', 0x228a018),
    ('merge_nonadjacent', 0x2289fca, 0x2289fcf, '483b742428', '750e', 0x2289fdf),
    ('merge_first_carry', 0x2289fd1, 0x2289fd6, '48034c2430', '725b', 0x228a033),
    ('merge_second_carry', 0x2289fd8, 0x2289fdd, '4803542438', '7261', 0x228a040),
    ('leaf_empty', 0x251c314, 0x251c317, '4885d2', '7477', 0x251c390),
    ('leaf_capacity', 0x251c355, 0x251c35a, '4c3b7c2410', '736e', 0x251c3ca),
    ('leaf_next', 0x251c383, 0x251c386, '4c39e0', '75b8', 0x251c340),
    ('callback_no_drop', 0x1eacda7, 0x1eacdaa, '4885c0', '7405', 0x1eacdb1),
    ('callback_no_free', 0x1eacdb5, 0x1eacdb8, '4885f6', '7421', 0x1eacddb),
    ('callback_unwind_no_free', 0x1eacdeb, 0x1eacdee, '4885f6', '7437', 0x1eace27),
    ('dispatch_has_tls', 0x2428476, 0x2428479, '4885d2', '751b', 0x2428496),
    ('dispatch_tls_still_empty', 0x2428488, 0x242848b, '4885d2', '741f', 0x24284ac),
    ('dispatch_pool_differs', 0x242848d, 0x2428494, '4839b210010000', '7527', 0x24284bd),
    ('join_ring_compare', 0x24040d3, 0x24040d6, '4839f1', '7c26', 0x24040fe),
    ('join_negative_capacity', 0x24040d8, 0x24040db, '4885f6', '0f8875040000', 0x2404556),
    ('join_zero_capacity', 0x24040fe, 0x2404101, '4885f6', '0f8421040000', 0x2404528),
    ('join_ready_queue_compare', 0x2404281, 0x2404284, '4809ce', '0f84bd000000', 0x2404347),
    ('join_wait_state', 0x24042ae, 0x24042b2, '4883f803', '0f8548020000', 0x2404500),
    ('join_result_success', 0x24042df, 0x24042e3, '4883f801', '741b', 0x2404300),
    ('join_result_not_panic', 0x24042e5, 0x24042e9, '4883f802', '0f85f3010000', 0x24044e2),
    ('join_steal_missing', 0x24043c6, 0x24043c9, '4885c0', '0f8447010000', 0x2404516),
    ('join_steal_count_underflow', 0x24043e1, 0x24043e4, '482b31', '0f8283010000', 0x240456d),
    ('join_inline_result_tag', 0x240442d, 0x2404436, '4883bc241001000002', '7247', 0x240447f),
    ('worker_claim_missing', 0x24a8820, 0x24a8823, '4885d2', '0f8430010000', 0x24a8959),
    ('worker_count_underflow', 0x24a8837, 0x24a883a, '482b31', '0f822b010000', 0x24a896b),
    ('worker_old_result', 0x24a888b, 0x24a888f, '837b4002', '724c', 0x24a88dd),
    ('worker_no_drop', 0x24a88a2, 0x24a88a5, '4885c0', '7405', 0x24a88ac),
    ('worker_no_free', 0x24a88b4, 0x24a88bc, '4885f64c8b742410', '741f', 0x24a88dd),
    ('worker_notify', 0x24a891d, 0x24a8921, '4883f802', '750c', 0x24a892f),
    ('worker_ref_drop', 0x24a8939, 0x24a893d, 'f048ff08', '750b', 0x24a894a),
    ('no_tls_flag', 0x241bd67, 0x241bd6c, '6480790c00', '0f84c5010000', 0x241bf37),
    ('no_tls_status_success', 0x241beaa, 0x241beae, '4883f801', '741b', 0x241becb),
    ('no_tls_status_bad', 0x241beb0, 0x241beb4, '4883f802', '0f85ad000000', 0x241bf67),
    ('wrong_pool_status_success', 0x242785e, 0x2427862, '4883f801', '7415', 0x2427879),
    ('wrong_pool_status_bad', 0x2427864, 0x2427868, '4883f802', '0f8592000000', 0x2427900),
    ('wrong_pool_done', 0x2427826, 0x242782a, '4883f803', '0f85af000000', 0x24278df),
    ('drop_empty', 0x250566b, 0x250566e, '4885f6', '7468', 0x25056d8),
    ('drop_no_callback', 0x25056a5, 0x25056a8, '4885c0', '7405', 0x25056af),
    ('drop_no_free', 0x25056b3, 0x25056b6, '4885f6', '74d8', 0x2505690),
    ('drop_loop_end', 0x2505694, 0x2505697, '48ffcb', '743f', 0x25056d8),
    ('cleanup_context_a_empty', 0x2456fa8, 0x2456fad, '48837f0800', '743a', 0x2456fe9),
    ('cleanup_context_b_empty', 0x2456258, 0x245625c, '48833f00', '743a', 0x2456298),
    ('cleanup_tag_a', 0x2456fe9, 0x2456ff0, '83bb8000000002', '724a', 0x245703c),
    ('cleanup_tag_b', 0x2456298, 0x245629c, '837b7802', '724a', 0x24562e8),
    ('cleanup_job_empty', 0x245f598, 0x245f59c, '48833f00', '741d', 0x245f5bb),
    ('cleanup_tagged', 0x2453ce5, 0x2453ce8, '833f02', '7244', 0x2453d2e),
)

# Direct transfers and RIP-relative callback addresses. The two context edges
# belong to earlier FDEs; the old state-loader GOT and its call are not read.
TRANSFERS = (
    ('context_submit_slot', 0x2020e73, 'ff15', 0x5773580),
    ('enqueue_grow_slot', 0x4f7c31f, 'ff15', 0x57777c0),
    ('enqueue_slow_lock_slot', 0x4f7c656, 'ff15', 0x576ef30),
    ('context_task_table_address', 0x2020db1, '488d05', 0x5696da0),
    ('task_thunk_poll', 0x22a4500, 'e9', 0x1d8b750),
    ('task_jump_table_address', 0x1d8b7d7, '488d0d', 0x3bc94c),
    ('task_poll_bridge', 0x1d8b821, 'e8', 0x2017c80),
    ('task_publish_result', 0x1d8b8e0, 'e8', 0x201ee00),
    ('context_vector_adapter', 0x25b7f82, 'e8', 0x255d270),
    ('context_adapter_partition', 0x255d31c, 'e8', 0x2289e30),
    ('context_list_array_header', 0x1e5deb9, 'e8', 0x25a9bd0),
    ('context_list_string_writer', 0x1e5df3d, 'e8', 0x25aa7f0),
    ('context_list_finish', 0x1e5df95, 'e8', 0x1dd1db0),
    ('finish_buffer_header', 0x1dd1e02, 'e8', 0x25a9bd0),
    ('finish_buffer_grow', 0x1dd1f3b, 'e8', 0x251b070),
    ('partition_serial', 0x2289e96, 'e8', 0x251c2e0),
    ('partition_dispatch', 0x2289fac, 'e8', 0x2428460),
    ('serial_invoke', 0x251c350, 'e8', 0x1eacd90),
    ('serial_drop_rest', 0x251c39d, 'e8', 0x2505660),
    ('serial_unwind_drop', 0x251c402, 'e8', 0x2505660),
    ('tls_direct', 0x242849e, 'e8', 0x2404010),
    ('tls_missing', 0x24284b6, 'e8', 0x241bd40),
    ('tls_other', 0x24284c7, 'e8', 0x24276f0),
    ('tls_unwind_drop', 0x24284d4, 'e8', 0x2452e50),
    ('join_right_callback', 0x2404125, '4c8d2d', 0x24a8800),
    ('join_left_partition', 0x24041fa, 'e8', 0x2289e30),
    ('join_inline_partition', 0x2404424, 'e8', 0x2289e30),
    ('worker_partition', 0x24a886e, 'e8', 0x2289e30),
    ('foreign_a_callback', 0x241bdef, '488d35', 0x2490b20),
    ('foreign_a_join', 0x2490c33, 'e8', 0x2404010),
    ('foreign_b_callback', 0x2427795, '488d35', 0x24a59d0),
    ('foreign_b_join', 0x24a5ae1, 'e8', 0x2404010),
    ('drop_split_first', 0x2452e6f, 'e8', 0x2505660),
    ('drop_split_second', 0x2452e93, 'e9', 0x2505660),
    ('drop_a_first', 0x2456fc7, 'e8', 0x2505660),
    ('drop_a_second', 0x2456fe4, 'e8', 0x2505660),
    ('drop_b_first', 0x2456276, 'e8', 0x2505660),
    ('drop_b_second', 0x2456293, 'e8', 0x2505660),
    ('drop_job_list', 0x245f5b6, 'e8', 0x2505660),
    ('drop_join_unwind', 0x2404630, 'e8', 0x245f590),
    ('drop_join_tagged', 0x240465e, 'e8', 0x2453ce0),
    ('drop_foreign_a', 0x241bfbc, 'e8', 0x2456fa0),
    ('drop_foreign_b', 0x2427950, 'e8', 0x2456250),
)

# Register-indirect calls have no statically resolved target here.
INDIRECTS = (
    ('enqueue_closed_callback', 0x4f7c2e3, 'ff5030'),
    ('call_closure_vtable_18', 0x1eacda1, 'ff5118'),
    ('call_pair_drop', 0x1eacdaf, 'ffd0'),
    ('run_ready_callback', 0x240428d, 'ffd0'),
    ('drop_remaining_callback', 0x25056ad, 'ffd0'),
)

COND = ('o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
        's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def file_offset(sections, data_len, va, size, executable=False):
    """Map a nonempty linked VA interval to one allocated, file-backed section."""
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid virtual address interval')
    candidates = [s for s in sections if s['type'] != 8 and s['flags'] & 2
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'range not uniquely file-backed')
    section = candidates[0]
    offset = section['offset'] + va - section['address']
    require(0 <= offset and offset + size <= data_len, 'range outside file')
    return offset


def verify_digest(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'artifact SHA-256 mismatch')


class Image:
    def __init__(self, data, authenticate=True):
        self.data = data
        if authenticate:
            verify_digest(data)
        self.sections = elf_index.sections(data)
        self.cies, frames = fde_extents.eh_frame_records(data, self.sections)
        _, index = elf_index.unwind_index(data)
        header = [s for s in self.sections if s['name'] == '.eh_frame_hdr' and s['type'] != 8]
        frame = [s for s in self.sections if s['name'] == '.eh_frame' and s['type'] != 8]
        require(len(header) == len(frame) == 1, 'ambiguous frame sections')
        relative = struct.unpack_from('<i', data, header[0]['offset'] + 4)[0]
        require(header[0]['address'] + 4 + relative == frame[0]['address'],
                'frame header pointer mismatch')
        starts = [x['start'] for x in frames]
        require(len(starts) == len(set(starts)), 'duplicate FDE start')
        self.frames = {x['start']: x for x in frames}
        self.starts = sorted(self.frames)
        self.index = {x['start']: x for x in index}
        require(len(self.index) == len(index), 'duplicate unwind index start')
        for start, (_, end, _, lsda_hash) in FUNCTIONS.items():
            record = self.frames.get(start)
            entry = self.index.get(start)
            require(record is not None and entry is not None, 'selected FDE missing')
            require(record['end'] == end and entry['fde'] == record['fde'],
                    'selected FDE/index disagreement')
            require((record['lsda'] is None) == (lsda_hash is None),
                    'selected FDE exception-data presence changed')
            self.read(start, end - start, executable=True)

    def off(self, va, size, executable=False):
        return file_offset(self.sections, len(self.data), va, size, executable)

    def read(self, va, size, executable=False):
        offset = self.off(va, size, executable)
        return bytes(self.data[offset:offset + size])

    def owner(self, va, size=1):
        index = bisect.bisect_right(self.starts, va) - 1
        require(index >= 0, 'range has no preceding FDE')
        item = self.frames[self.starts[index]]
        require(item['start'] <= va and va + size <= item['end'],
                'range is outside its FDE')
        entry = self.index.get(item['start'])
        require(entry is not None and entry['fde'] == item['fde'],
                'range FDE absent from unwind index')
        return item

    def check_bodies(self):
        for start, (name, end, digest, _) in FUNCTIONS.items():
            actual = hashlib.sha256(self.read(start, end - start, True)).hexdigest()
            require(actual == digest, 'selected body changed: ' + name)


def selected_functions(image):
    image.check_bodies()
    rows = []
    for start in sorted(FUNCTIONS):
        name, end, _, _ = FUNCTIONS[start]
        frame = image.frames[start]
        cie = image.cies[frame['cie']]
        raw = image.read(start, end - start, True)
        rows.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                     'file_offset': hex(image.off(start, len(raw), True)),
                     'byte_count': len(raw), 'fde_va': hex(frame['fde']),
                     'cie_va': hex(frame['cie']),
                     'personality_slot_va': (hex(cie['personality_slot'])
                                             if cie['personality_slot'] is not None else ''),
                     'lsda_va': hex(frame['lsda']) if frame['lsda'] is not None else '',
                     'sha256': hashlib.sha256(raw).hexdigest(), 'bytes_hex': raw.hex()})
    return rows


def read_windows(image):
    rows = []
    for name, start, end, expected in WINDOWS:
        raw = image.read(start, end - start, True)
        require(hashlib.sha256(raw).hexdigest() == expected, 'window changed: ' + name)
        owner = image.owner(start, end - start)
        context = name.startswith('context_')
        require(context != (owner['start'] in FUNCTIONS), 'window ownership mismatch: ' + name)
        rows.append({'name': name, 'scope': 'prior-context' if context else 'selected',
                     'owner_fde_start_va': hex(owner['start']),
                     'start_va': hex(start), 'end_va': hex(end),
                     'file_offset': hex(image.off(start, len(raw), True)),
                     'sha256': expected, 'bytes_hex': raw.hex()})
    return rows


def decode_conditional(va, raw):
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        condition, displacement = raw[0] & 15, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        condition, displacement = raw[1] & 15, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported conditional branch')
    return COND[condition], va + len(raw) + displacement


def read_branches(image):
    rows = []
    for name, guard, site, expected_guard, expected_branch, target in BRANCHES:
        old_guard = bytes.fromhex(expected_guard)
        expected = bytes.fromhex(expected_branch)
        require(guard + len(old_guard) == site, 'guard is not adjacent')
        actual_guard = image.read(guard, len(old_guard), True)
        raw = image.read(site, len(expected), True)
        require(actual_guard == old_guard and raw == expected, 'branch changed: ' + name)
        condition, decoded_target = decode_conditional(site, raw)
        require(decoded_target == target, 'branch target changed: ' + name)
        owner = image.owner(guard, len(old_guard) + len(raw))
        require(owner['start'] in FUNCTIONS and owner['start'] <= target < owner['end'],
                'selected branch target outside owner')
        rows.append({'name': name, 'owner_fde_start_va': hex(owner['start']),
                     'guard_va': hex(guard), 'guard_bytes': actual_guard.hex(),
                     'branch_va': hex(site), 'branch_file_offset': hex(image.off(site, len(raw), True)),
                     'branch_bytes': raw.hex(), 'condition': condition,
                     'taken_va': hex(decoded_target), 'fallthrough_va': hex(site + len(raw))})
    return rows


def read_transfers(image):
    rows = []
    for name, site, prefix_hex, target in TRANSFERS:
        prefix = bytes.fromhex(prefix_hex)
        raw = image.read(site, len(prefix) + 4, True)
        require(raw.startswith(prefix), 'transfer opcode changed: ' + name)
        actual_target = site + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
        require(actual_target == target, 'transfer target changed: ' + name)
        owner = image.owner(site, len(raw))
        context = name.startswith('context_')
        require(context != (owner['start'] in FUNCTIONS), 'transfer owner mismatch: ' + name)
        rows.append({'name': name, 'scope': 'prior-context' if context else 'selected',
                     'owner_fde_start_va': hex(owner['start']), 'site_va': hex(site),
                     'file_offset': hex(image.off(site, len(raw), True)), 'bytes_hex': raw.hex(),
                     'kind': ('rip_lea' if len(prefix) == 3 else
                              'rip_indirect_call_slot' if prefix == b'\xff\x15' else
                              'direct_call' if prefix == b'\xe8' else 'direct_jump'),
                     'target_va': hex(actual_target)})
    for name, site, expected in INDIRECTS:
        raw = bytes.fromhex(expected)
        require(image.read(site, len(raw), True) == raw, 'indirect opcode changed: ' + name)
        owner = image.owner(site, len(raw))
        require(owner['start'] in FUNCTIONS, 'indirect owner changed')
        rows.append({'name': name, 'scope': 'selected',
                     'owner_fde_start_va': hex(owner['start']), 'site_va': hex(site),
                     'file_offset': hex(image.off(site, len(raw), True)), 'bytes_hex': raw.hex(),
                     'kind': 'indirect_call', 'target_va': 'unresolved'})
    return rows


def read_task_table(image):
    """Bind the selected task table relocation and four-entry branch table."""
    def immediate(address, prefix):
        opcode = bytes.fromhex(prefix)
        data = image.read(address, len(opcode) + 4, True)
        require(data.startswith(opcode), 'task handoff instruction changed')
        return struct.unpack_from('<I', data, len(opcode))[0]

    sections = [s for s in image.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(sections) == 1 and sections[0]['size'] % 24 == 0,
            'unsupported relocation table')
    section = sections[0]
    expected_slots = {0x5696da0: 0x22a4500, 0x5773580: 0x4f7c290}
    matches = {slot: [] for slot in expected_slots}
    for offset in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, offset)
        if slot in matches:
            matches[slot].append((offset, info, addend))
    relocation = []
    for slot, expected in sorted(expected_slots.items()):
        require(len(matches[slot]) == 1, 'task slot relocation is not unique')
        offset, info, addend = matches[slot][0]
        require(info == 8 and addend == expected, 'task slot relocation changed')
        slot_bytes = image.read(slot, 8)
        require(slot_bytes == bytes(8), 'task slot file bytes changed')
        relocation.append({'slot_va': hex(slot),
                           'slot_file_offset': hex(image.off(slot, 8)), 'slot_bytes': slot_bytes.hex(),
                           'record_file_offset': hex(offset),
                           'record_bytes': bytes(image.data[offset:offset + 24]).hex(),
                           'type': info & 0xffffffff, 'symbol_index': info >> 32,
                           'addend_va': hex(addend)})
    base = 0x3bc94c
    raw = image.read(base, 16)
    targets = [base + value for value in struct.unpack('<4i', raw)]
    require(targets == [0x1d8b7e7, 0x1d8b8e7, 0x1d8ba18, 0x1d8ba10],
            'task dispatch table changed')
    require(all(image.frames[0x1d8b750]['start'] <= target < image.frames[0x1d8b750]['end']
                for target in targets), 'task dispatch target outside selected FDE')
    dispatch = [{'index': i, 'entry_va': hex(base + 4 * i),
                 'file_offset': hex(image.off(base + 4 * i, 4)),
                 'bytes_hex': raw[4 * i:4 * i + 4].hex(), 'target_va': hex(target)}
                for i, target in enumerate(targets)]
    state_raw = image.read(0x2020d99, 12, True)
    require(state_raw[:8] == bytes.fromhex('48c7842480000000'), 'task initial-state instruction changed')
    state = struct.unpack_from('<I', state_raw, 8)[0]
    require(state & 4 and not state & 3, 'task initial state selects a different arm')
    desired, index = (state & ~7) + 1, (state >> 5) & 1
    require(index == 0 and targets[index] == 0x1d8b7e7, 'task initial dispatch changed')
    host_bytes = immediate(0x22b55cc, 'ba')
    input_bytes = immediate(0x2020d91, 'ba')
    allocation_bytes = immediate(0x2020e31, 'bf')
    bridge_bytes = immediate(0x2017d70, 'ba')
    stage_dst = immediate(0x2020d82, '488dbc24')
    payload_dst = immediate(0x2020def, '488dbc24')
    stage_src = immediate(0x2020df7, '4c8dac24')
    object_src = immediate(0x2020e4d, '488db424')
    payload_offset = payload_dst - object_src + stage_dst - stage_src
    require(image.read(0x1d8b7f7, 4, True) == bytes.fromhex('4c8d7320') and
            image.read(0x2017d41, 4, True) == bytes.fromhex('4c8b7620') and
            image.read(0x2017d64, 4, True) == bytes.fromhex('4883c628'),
            'task poll offsets changed')
    first_offset = 0x20 + 0x20
    body_offset = 0x20 + 0x28
    first_dst = immediate(0x2017da3, '4c89b424')
    body_dst = immediate(0x2017dab, '488dbc24')
    apply_src = immediate(0x2017fb7, '488db424')
    require(host_bytes == input_bytes == bridge_bytes + 8 == 0x3ec0 and
            allocation_bytes == 0x3f80 and payload_offset == first_offset == 0x40 and
            body_offset == 0x48 and body_dst == first_dst + 8 and apply_src == first_dst,
            'task handoff spans disagree')
    return relocation, dispatch, {'initial_state': hex(state), 'cas_desired': hex(desired),
                                  'uncontended_table_index': index,
                                  'input_bytes': input_bytes, 'allocation_bytes': allocation_bytes,
                                  'bridge_tail_bytes': bridge_bytes, 'task_input_offset': hex(payload_offset),
                                  'task_tail_offset': hex(body_offset)}


def parse_lsda(image, start):
    """Decode the selected header and ULEB call-site rows; actions stay opaque."""
    record = image.frames[start]
    va = record['lsda']
    sections = [s for s in image.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(sections) == 1, 'missing exception table')
    section = sections[0]
    offset = image.off(va, 1)
    require(section['offset'] <= offset < section['offset'] + section['size'],
            'LSDA outside exception table')
    data = image.data
    limit = section['offset'] + section['size']
    pos = offset
    require(pos + 2 <= limit and data[pos] == 0xff, 'unsupported landing base')
    pos += 1
    type_encoding = data[pos]
    pos += 1
    type_base = None
    if type_encoding == 0x9b:
        type_delta, pos = fde_extents.uleb(data, pos, limit)
        type_base = pos + type_delta
        require(type_base <= limit, 'type table outside section')
    else:
        require(type_encoding == 0xff, 'unsupported type encoding')
    require(pos < limit and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length, pos = fde_extents.uleb(data, pos, limit)
    end = pos + length
    require(end <= limit and (type_base is None or end <= type_base), 'bad call-site table length')
    rows = []
    previous = start
    while pos < end:
        row_offset = pos
        begin, pos = fde_extents.uleb(data, pos, end)
        size, pos = fde_extents.uleb(data, pos, end)
        landing, pos = fde_extents.uleb(data, pos, end)
        action, pos = fde_extents.uleb(data, pos, end)
        lo, hi = start + begin, start + begin + size
        pad = start + landing if landing else None
        require(size > 0 and previous <= lo < hi <= record['end'], 'invalid LSDA range')
        require(pad is None or start <= pad < record['end'], 'landing pad outside FDE')
        previous = hi
        rows.append({'owner_fde_start_va': hex(start), 'start_va': hex(lo), 'end_va': hex(hi),
                     'landing_va': hex(pad) if pad is not None else '', 'action': action,
                     'row_file_offset': hex(row_offset), 'bytes_hex': bytes(data[row_offset:pos]).hex()})
    require(pos == end, 'truncated LSDA row')
    raw = bytes(data[offset:end])
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == FUNCTIONS[start][3], 'LSDA bytes changed: ' + FUNCTIONS[start][0])
    header = {'name': FUNCTIONS[start][0], 'owner_fde_start_va': hex(start),
              'lsda_va': hex(va), 'file_offset': hex(offset),
              'type_encoding': hex(type_encoding), 'call_encoding': '0x1',
              'byte_count': len(raw), 'rows': len(rows), 'sha256': digest, 'bytes_hex': raw.hex()}
    return header, rows


def read_lsdas(image):
    headers, rows = [], []
    for start in sorted(FUNCTIONS):
        if FUNCTIONS[start][3] is None:
            continue
        header, section_rows = parse_lsda(image, start)
        headers.append(header)
        rows.extend(section_rows)
    return headers, rows


# Calls matched against their actual LSDA ranges; nonzero actions are opaque.
FAILURE_LINKS = (
    ('enqueue_closed_callback', 0x4f7c290, 0x4f7c2e3, 0x4f7c7c9, 0),
    ('enqueue_grow', 0x4f7c290, 0x4f7c31f, 0x4f7c77b, 0),
    ('enqueue_slow_lock', 0x4f7c290, 0x4f7c656, 0x4f7c6c1, 0),
    ('task_poll_bridge', 0x1d8b750, 0x1d8b821, 0x1d8bb8b, 5),
    ('task_publish_result', 0x1d8b750, 0x1d8b8e0, 0x1d8babf, 7),
    ('finish_buffer_header', 0x1dd1db0, 0x1dd1e02, 0x1dd1f48, 0),
    ('finish_buffer_grow', 0x1dd1db0, 0x1dd1f3b, 0x1dd1f46, 0),
    ('serial_invoke', 0x251c2e0, 0x251c350, 0x251c3e5, 0),
    ('serial_capacity_failure', 0x251c2e0, 0x251c3dd, 0x251c3e7, 0),
    ('dynamic_callback', 0x1eacd90, 0x1eacda1, 0x1eace19, 0),
    ('callback_drop', 0x1eacd90, 0x1eacdaf, 0x1eacde4, 0),
    ('join_left_partition', 0x2404010, 0x24041fa, 0x24045d6, 3),
    ('join_inline_partition', 0x2404010, 0x2404424, 0x2404653, 0),
    ('worker_partition', 0x24a8800, 0x24a886e, 0x24a89e3, 7),
    ('foreign_a_join', 0x2490b20, 0x2490c33, 0x2490d7f, 7),
    ('foreign_b_join', 0x24a59d0, 0x24a5ae1, 0x24a5cae, 7),
    ('drop_split_first', 0x2452e50, 0x2452e6f, 0x2452e98, 0),
)


def read_failure_links(rows):
    output = []
    for name, owner, call, landing, action in FAILURE_LINKS:
        matches = [r for r in rows if int(r['owner_fde_start_va'], 16) == owner
                   and int(r['start_va'], 16) <= call < int(r['end_va'], 16)]
        require(len(matches) == 1, 'call has no unique LSDA row: ' + name)
        row = matches[0]
        require(row['landing_va'] == hex(landing) and row['action'] == action,
                'selected landing or action changed: ' + name)
        output.append({'name': name, 'owner_fde_start_va': hex(owner),
                       'call_va': hex(call), 'covered_start_va': row['start_va'],
                       'covered_end_va': row['end_va'], 'landing_va': row['landing_va'],
                       'action': row['action'], 'lsda_row_file_offset': row['row_file_offset'],
                       'lsda_row_bytes': row['bytes_hex']})
    return output


def read_parameters(image):
    # The count has three independent witnesses in the prior builder window.
    raw = image.read(0x2756fb1, 12, True)
    require(raw[:8] == bytes.fromhex('48c7842450030000'), 'builder count encoding changed')
    n = struct.unpack_from('<I', raw, 8)[0]
    raw2 = image.read(0x2756fe0, 12, True)
    require(raw2[:8] == bytes.fromhex('48c7842460030000'), 'builder length encoding changed')
    raw3 = image.read(0x2756ff9, 5, True)
    require(raw3[:1] == b'\xbe', 'builder argument encoding changed')
    require(n == struct.unpack_from('<I', raw2, 8)[0] == struct.unpack_from('<I', raw3, 1)[0],
            'builder count witnesses disagree')
    in_shift = image.read(0x251c30c, 4, True)
    out_shift = image.read(0x251c32b, 4, True)
    require(in_shift[:3] == bytes.fromhex('48c1e0') and out_shift[:3] == bytes.fromhex('49c1e6'),
            'stride encoding changed')
    input_stride, output_stride = 1 << in_shift[3], 1 << out_shift[3]
    require(image.read(0x251c333, 4, True) == bytes.fromhex('4883c310'), 'input loop step changed')
    require(image.read(0x251c377, 4, True) == bytes.fromhex('4983c510'), 'output index step changed')
    require(input_stride == 16 and output_stride == 32 and n == 41, 'unexpected job parameters')
    return {'jobs': n, 'input_stride': input_stride, 'output_stride': output_stride}


def read_encoding(image, parameters):
    """Compose the bounded successful-list layout using prior helper evidence."""
    count = parameters['jobs']
    sentinel_load = image.read(0x1e5de66, 10, True)
    require(sentinel_load[:2] == b'\x48\xbd', 'list sentinel encoding changed')
    sentinel = struct.unpack_from('<Q', sentinel_load, 2)[0]
    require(sentinel == 1 << 63, 'list sentinel changed')
    require(image.read(0x1e5decd, 5, True) == bytes.fromhex('48896c2410') and
            image.read(0x1e5df56, 5, True) == bytes.fromhex('488b442410') and
            image.read(0x1e5df7e, 5, True) == bytes.fromhex('4889442440'),
            'list sentinel handoff changed')
    require(image.read(0x1dd1dcb, 0x21, True) == bytes.fromhex(
        '488b1e4889d848f7d871164983c6044d89374883c4285b415c415d415e415f5dc3'),
        'list direct finish changed')
    size_raw = image.read(0x1e5df26, 5, True)
    cap_raw = image.read(0x1e5df21, 5, True)
    require(size_raw[:1] == b'\xb9' and cap_raw[:1] == b'\xbe', 'list setup changed')
    digest_bytes = struct.unpack_from('<I', size_raw, 1)[0]
    capacity = struct.unpack_from('<I', cap_raw, 1)[0]
    require(image.read(0x1e5df2b, 9, True) == bytes.fromhex('4889df4c89f24531c0'),
            'list helper argument setup changed')
    require(digest_bytes == parameters['output_stride'] and capacity == 2 + digest_bytes * 2,
            'hex helper dimensions disagree')
    array = image.read(0x25a9bde, 25, True)
    require(array == bytes.fromhex('81fa000001000f92c034dd83fa100fb6c0bd900000000f43e8'),
            'array marker selection changed')
    require(16 <= count < 65536, 'count outside selected array16 domain')
    require(image.read(0x25a9cde, 14, True) == bytes.fromhex('89f866c1c008498b4e0866890431'),
            'array length store changed')
    require(image.read(0x25acc25, 12, True) == bytes.fromhex('8d9140ffffff83fa207301c3'),
            'marker passthrough changed')
    marker = array[10] ^ int(count < 65536)
    array_header = bytes([marker]) + count.to_bytes(2, 'big')
    string_start = image.read(0x25aa806, 5, True)
    string_next = image.read(0x25aa81f, 11, True)
    require(string_start == bytes.fromhex('83fa207314') and
            string_next == bytes.fromhex('81fa00010000731440b5d9'), 'string marker selection changed')
    require(32 <= capacity < 256, 'text outside selected str8 domain')
    entry_header = bytes([string_next[-1], capacity])
    prefix_instruction = image.read(0x29ed392, 5, True)
    require(prefix_instruction[:3] == bytes.fromhex('66c707'), 'hex prefix store changed')
    prefix = prefix_instruction[3:]
    alphabet = image.read(0x208620, 16)
    require(prefix == b'0x' and alphabet == b'0123456789abcdef', 'hex data changed')
    require(image.read(0x1e5df37, 21, True) == bytes.fromhex(
        '4c89e74889c6e8aec874004883f8020f859d010000'), 'list string handoff changed')
    require(image.read(0x25aa93a, 22, True) == bytes.fromhex(
        '4939fc0f84e8020000498b410844883c38bf01000000'), 'string length write changed')
    require(image.read(0x25aabad, 25, True) == bytes.fromhex(
        '49037908488b7424204c89fa4c89cbff151e341c034c017b10'), 'string payload copy changed')
    return {'array_header_hex': array_header.hex(), 'entry_header_hex': entry_header.hex(),
            'hex_prefix_ascii': prefix.decode('ascii'), 'alphabet_ascii': alphabet.decode('ascii'),
            'digest_bytes': digest_bytes, 'text_bytes': capacity,
            'direct_finish_result': hex(sentinel + 4),
            'entry_bytes': len(entry_header) + capacity,
            'total_bytes': len(array_header) + count * (len(entry_header) + capacity)}


MASK64 = (1 << 64) - 1


def merge_segments(left, right, stride):
    """Model the selected three-word merge, including 64-bit wrapped address arithmetic."""
    require(type(stride) is int and stride == 32, 'unsupported output stride')
    require(len(left) == len(right) == 3 and all(type(x) is int and 0 <= x <= MASK64
                                                for x in (*left, *right)), 'invalid segment word')
    end = (left[0] + ((left[2] * stride) & MASK64)) & MASK64
    if end != right[0]:
        return 'nonadjacent', tuple(left)
    first = left[1] + right[1]
    if first > MASK64:
        raise OverflowError('first aggregate word carry')
    second = left[2] + right[2]
    if second > MASK64:
        raise OverflowError('second aggregate word carry')
    return 'merged', (left[0], first, second)


def leaf_ranges(start, n, cutoff):
    """Synthetic topology: model the observed floor-half split, not scheduler decisions."""
    require(type(start) is int and type(n) is int and type(cutoff) is int and
            start >= 0 and n >= 0 and cutoff >= 1, 'invalid partition model input')
    if n <= cutoff:
        return [(start, start + n)]
    left = n // 2
    return leaf_ranges(start, left, cutoff) + leaf_ranges(start + left, n - left, cutoff)


def checked_slots(n, input_stride, output_stride, leaves):
    """Return slot placement only if leaves cover the ordered input exactly once."""
    require(type(n) is int and n >= 0 and input_stride == 16 and output_stride == 32,
            'invalid slot model input')
    cursor = 0
    for lo, hi in leaves:
        require(type(lo) is int and type(hi) is int and lo == cursor and lo <= hi <= n,
                'overlapping, reordered, or missing leaf range')
        cursor = hi
    require(cursor == n, 'incomplete leaf ranges')
    return [(i, i * input_stride, i * output_stride, (i + 1) * output_stride)
            for i in range(n)]


def result_slots(parameters, encoding):
    n = parameters['jobs']
    ins, outs = parameters['input_stride'], parameters['output_stride']
    header_size = len(bytes.fromhex(encoding['array_header_hex']))
    entry_header_size = len(bytes.fromhex(encoding['entry_header_hex']))
    return [{'job_index': i, 'input_record_offset': hex(inp), 'output_start_offset': hex(out),
             'output_end_offset': hex(end),
             'preimage_entry_offset': hex(header_size + i * encoding['entry_bytes']),
             'preimage_text_offset': hex(header_size + i * encoding['entry_bytes'] + entry_header_size),
             'preimage_entry_end': hex(header_size + (i + 1) * encoding['entry_bytes'])}
            for i, inp, out, end in checked_slots(n, ins, outs, leaf_ranges(0, n, 1))]


def tsv(rows):
    require(bool(rows), 'cannot emit empty table')
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def collect(image):
    functions = selected_functions(image)
    windows = read_windows(image)
    branches = read_branches(image)
    transfers = read_transfers(image)
    headers, lsda_rows = read_lsdas(image)
    parameters = read_parameters(image)
    encoding = read_encoding(image, parameters)
    task_relocation, task_dispatch, task_state = read_task_table(image)
    slots = result_slots(parameters, encoding)
    failure_links = read_failure_links(lsda_rows)
    tables = {'functions.tsv': functions, 'windows.tsv': windows, 'branches.tsv': branches,
              'transfers.tsv': transfers, 'lsda-headers.tsv': headers, 'lsda.tsv': lsda_rows,
              'failure-links.tsv': failure_links, 'result-slots.tsv': slots,
              'task-relocation.tsv': task_relocation, 'task-dispatch.tsv': task_dispatch}
    summary = {'schema': 1, 'target': 'node-94', 'artifact_sha256': SHA256,
               'coordinates': 'ELF link-time virtual addresses and file offsets',
               'scope': 'selected static ranges and derived successful-path layout',
               'parameters': parameters, 'task_uncontended_model': task_state,
               'successful_list_encoding': encoding, 'table_rows': {name: len(rows) for name, rows in tables.items()},
               'lsda_note': 'ULEB call-site rows only; nonzero actions and personality semantics unresolved',
               'identity_note': 'loader-to-builder object identity and runtime scheduling are not established'}
    output = {name: tsv(rows) for name, rows in tables.items()}
    output['summary.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8')
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    with TARGET.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        image = Image(data)
        contents = collect(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(contents.items()):
        (args.out / name).write_bytes(data)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_hash_jobs94:', error, file=sys.stderr)
        raise SystemExit(1)
