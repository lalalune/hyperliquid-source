#!/usr/bin/env python3
"""Extract selected node-115 result-container and delivery evidence, without execution."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = [
    ('tree_split', 0x4c71540, 0x4c724b4),
    ('tree_bulk_build', 0x4d016b0, 0x4d02031),
    ('deduplicate_next', 0x4d5f920, 0x4d5fb5b),
    ('ring_to_tree', 0x515f660, 0x515f82e),
    ('tree_iterator', 0x51e62a0, 0x51e664a),
    ('tree_insert', 0x51ef230, 0x51ef3bb),
    ('tree_cleanup', 0x52545b0, 0x52546e3),
    ('small_sort', 0x53ef8f0, 0x53ef9e1),
    ('ring_insert', 0x57ea380, 0x57ea4af),
    ('ring_move', 0x5812d50, 0x5812fc3),
    ('joined_cleanup', 0x59d35b0, 0x59d3726),
    ('value_cleanup', 0x5b232a0, 0x5b2343a),
    ('ring_drain', 0x5b759a0, 0x5b75bf5),
    ('tree_to_ring', 0x5b98a90, 0x5b98d98),
]

# The fixed window hashes are independent corruption controls, not a disassembler.
# Context windows refer to existing proposals and do not claim their functions.
WINDOWS = [
    ('loader_state_stores', 'context', 0x3c128ca, 0x3c12918, '3bd768ad2df998e8907dcdd4833a64341d8422391775a956123e249997d92d95'),
    ('begin_state_stores', 'context', 0x5483fd3, 0x5484003, 'c242b73c6ae559827cd4029126f715dd452460b14b3877df8b2aa6a5580334d9'),
    ('item_first_counter', 'context', 0x560dbcc, 0x560dbe8, '497b00bed69e61eede9071e4465b3650b3a36166baf55c3cee68f5dc38731972'),
    ('item_second_counter', 'context', 0x560dc22, 0x560dc47, 'a6c09772322a0a4612cf92c062ceb4dddd29d6a9bd548c592531c88285fb8773'),
    ('engine_index_seed', 'context', 0x5a0691d, 0x5a06931, '93615190f90676bcd05c82740ef6f53b0d8716765347d97c2c8a09c1df754fcf'),
    ('engine_index_step', 'context', 0x5a06977, 0x5a06993, 'f114c822f9905fa1996f6cdc34da46e596c03532a7e1bc7c88ed3fdf36d6b847'),
    ('engine_input_filter', 'context', 0x5a06993, 0x5a069ad, 'bff9c6555db3c05a43cc8933cf6dbf7b51fd3cd59dfb79601dbe391c49478da0'),
    ('engine_group_key', 'context', 0x5a06a07, 0x5a06a3b, 'e3f293f10348822982fb3622d14c70ce78164a6d18a6efc2a7a3b4c5e69cc45e'),
    ('zip_input_row', 'context', 0x5b30d90, 0x5b30db6, '3cc3feb5ca783277dcac901a13817fe043890219a50f94bc8a24d74e55b1ae3a'),
    ('zip_input_vector', 'context', 0x5b30d20, 0x5b30d38, 'ddb5574535e23a189988b141194dce2ae87d830d34e8579e608aee72a598cd81'),
    ('zip_output', 'context', 0x5b30d38, 0x5b30d90, '70d61e587bd694344323971a1bc9aea3ad07cb41b8cb1366be5cbdb43ccf759b'),
    ('parent_tree_shrink_test', 'context', 0x4dd0035, 0x4dd0057, 'a7d1c18989056f175f681bb654b866a595e1fadf01b777a90adc3388740b1ec6'),
    ('parent_tree_shrink_setup', 'context', 0x4dd0057, 0x4dd00cd, 'e73f53b36364bed5bd2b05e3867aa01a0cf0abb940baf5484092fa0eab797261'),
    ('parent_tree_shrink_result', 'context', 0x4dd00d2, 0x4dd00e1, '4324571c305310a27cc005731234977043e14d1b7b4d544c6deb0f9bec22efd3'),
    ('parent_tree_shrink_store', 'context', 0x4dd0137, 0x4dd0159, 'f6f905a2710a110cd750183bde814ee10881280013ccf51f25d2ed92957ff907'),
    ('parent_grow_test', 'context', 0x4dd017c, 0x4dd0197, '26ceab558b509eb30f33ccb0d27d0c7af62b2136b67f3b3dee54431ab38e09cd'),
    ('parent_ring_item', 'context', 0x4dd0227, 0x4dd0271, '1d0998c71c7652a4d0ff5d272d30b6c98e8558d51c9a720ca077dd00ba482ee7'),
    ('parent_tree_item', 'context', 0x4dd03bf, 0x4dd042d, '5094e394653aeee2793c6aea79d3978a22b3a183bc412067d975a07d469c7b85'),
    ('collector_ring_get', 'context', 0x5b785e7, 0x5b78653, '7ebba47ef53690c22969ff8951d960823fe121ba0486175f0abe38e6727706f3'),
    ('collector_tree_get', 'context', 0x5b78663, 0x5b786ac, '0650d6703b3f20b34bb889b010ee2f36d5aafb8b3a59489a28c633b8e959f69b'),
    ('collector_entry_stage', 'context', 0x5b787ea, 0x5b78818, '285126edb0e94e38866312117e3ecc54c2026a318db4ddea2f7bb45e63930caa'),
    ('collector_payload_stage', 'context', 0x5b7883f, 0x5b788a3, 'ada26c8467a99fe0112c692f4be6bb1dd3712e6e600aa381badc5aceb4fd1f49'),
    ('collector_first_output', 'context', 0x5b7892b, 0x5b7895a, '622a37a2955d323b0f975342b37b0dece1926a3c2aa60b2716259a6de112e8d5'),
    ('collector_next_payload', 'context', 0x5b78ab4, 0x5b78b42, 'f2a89ae02cf17dcd218219ef6b3d01f0fd8d58c203d42cbfe15d256744ca5eb8'),
    ('collector_next_output', 'context', 0x5b789d0, 0x5b78a15, 'a606c82b01a1436b00ea395e3a9de1c0c82d5b88bba02096d28b538769519b53'),
    ('collector_return', 'context', 0x5b78ced, 0x5b78d04, '179b16eca66d52f8f3b6d8748a119d7612d49b94e2f59d7a157f5c3d4c14d115'),
    ('engine_collector_out', 'context', 0x5a07851, 0x5a07888, '4e7baf6ed2484d08e17c9881b6d2d84a03320d30c42c6babf8094cbc9f9b2135'),
    ('parent_result_forward', 'context', 0x4fcb79a, 0x4fcb7b6, '34d0fbf1c8e5c7cb98844abd6105655cf82f59a2175db9603465c1e80bd0856e'),
    ('parent_to_outer_result', 'context', 0x4fcb910, 0x4fcb926, '7a4dd71d8972d65f905b72386f7dc7ed95b2662251b9e3ca93963b809dbf0db7'),
    ('parent_return', 'context', 0x4fcbb80, 0x4fcbbba, 'dace6c94aa5a45892bc4a624f5ffb8f653fb816689cee0515aef0e318ca3ca6d'),
    ('worker_save_result', 'context', 0x5a6ea15, 0x5a6ea37, 'f492321a455fc4922e89f64d198f8ee49738138d9cd489bb9fb0d0c3c696a828'),
    ('worker_hash_argument', 'context', 0x5a6ecfc, 0x5a6ed0c, 'b83bad399ac0702620233f1cc34a1e180679a3a3c5495a2a2c3948910548170e'),
    ('ring_guard', 'selected', 0x57ea388, 0x57ea3b6, 'f99b24dfc94cfe6d71cadd9ed6ff87c0294fc893466624630937a79c2a696c3e'),
    ('ring_choose', 'selected', 0x57ea3b6, 0x57ea3c2, 'ba541fd56add3443b8c102f132727b56fd856b1cd24cc88870515bd30ef61316'),
    ('ring_shift_suffix', 'selected', 0x57ea3c2, 0x57ea40d, '194a6e390533e1b31f1ffd93b8c7cf510f9e862fd2e6ca3619d5e28ee816c211'),
    ('ring_shift_prefix', 'selected', 0x57ea40d, 0x57ea442, '0d94991f38766985c45e2d236a67b88f23ff63e50dcef70bb241bc6ad5571178'),
    ('ring_write64', 'selected', 0x57ea442, 0x57ea46f, 'b835c415e3a13198002b6c8d541f787d156699fd7667a9644ab5235c629aa750'),
    ('ring_bad_index', 'selected', 0x57ea47b, 0x57ea496, '080b9eb847f530aa793bea327a215821e57282ecb125cda554c6f6bbea5bad1d'),
    ('ring_move_guards', 'selected', 0x5812d5b, 0x5812d9b, 'b4b674e8652e7143644667b884ee71586379b4305bbc28b27e888bb936c26d6e'),
    ('ring_move_first', 'selected', 0x5812d9b, 0x5812e10, 'f8b8a1683c99ba4797e52a973c166e32e451bf3a81f33361de839c201c621485'),
    ('ring_move_empty', 'selected', 0x5812e10, 0x5812e1f, '4e0e6a740773d89fadd82c67dedefbe95b66c81e013f8788b214b3c31a1f3551'),
    ('grow_drain', 'selected', 0x515f660, 0x515f69f, 'fd2899d04a5cf76c396193c2b0558c3d47597e215aefaa46a80fe21d6ebf7c53'),
    ('grow_initial', 'selected', 0x515f69f, 0x515f6f4, 'b58179efa68f4eee7e7644814299a5cec740b0b7f7ec00848aa5cfdfda1eefab'),
    ('grow_build', 'selected', 0x515f702, 0x515f756, '3e83914796f1ba08435940779f52c6a271c7907aae97e4c1f5d32048df63d575'),
    ('grow_sort', 'selected', 0x515f79c, 0x515f7d8, '9e183f1ec3330b49cfc069cb7fe1c2fcb17adcd1736106b3d8408bd2da2d5778'),
    ('drain_allocate', 'selected', 0x5b759a0, 0x5b75a16, '5b1e0862520e5193d577c955bff21dc7c6d3abd032a348479ce3827ec8975964'),
    ('drain_first_segment', 'selected', 0x5b75a28, 0x5b75aca, 'e98abd604be1bb793188816f24d5245d6703ff628212f3664971735f9237036d'),
    ('drain_second_segment', 'selected', 0x5b75aca, 0x5b75b4c, '39f8c5f3f2260f1a518a7b04983792fd219e0fcadaf99b6f7692c11ead91c6de'),
    ('drain_return', 'selected', 0x5b75b4c, 0x5b75bae, '49423c7e1c94a62cc8ecad8c7c1f4aa7aac7d5163aa9d026ecd15806d3c3b137'),
    ('sort_guard', 'selected', 0x53ef8f0, 0x53ef903, '496a108f5646d6e251b43fe68e7024570b8af576a8c6b61f613d01d021cc87a3'),
    ('sort_compare', 'selected', 0x53ef94d, 0x53ef963, '251823c03e94bbce6416434bae1d49462d621b50579fae84ef1b4b571502fb7f'),
    ('sort_move', 'selected', 0x53ef987, 0x53ef9df, '0d1c4f936fbf1333c144a8e00294efbd79ef92194a1bc80501fdd257f7a4172e'),
    ('dedup_start', 'selected', 0x4d5f931, 0x4d5f97a, '8820a769560ac3d6e3d5b57a90f18292fb716d4021c4463dec37ac9ddbdd0b30'),
    ('dedup_read', 'selected', 0x4d5f994, 0x4d5f9e0, 'ff08881dcc5f82cb4335af539f26e4806d2abfc9e3cee586801fef07ef26c650'),
    ('dedup_equal', 'selected', 0x4d5fa60, 0x4d5fa90, '72e5ab63b7f27275a6e7ddcca3feda1f665343d34e6655221f576df82c1ad338'),
    ('dedup_cleanup', 'selected', 0x4d5fa90, 0x4d5fad0, 'cd146c505c8008b92d73cafbd6eb8d61496d40391db1b9c6f49e5c9ff6f00ce0'),
    ('dedup_emit', 'selected', 0x4d5fad0, 0x4d5fb08, 'd556fab0d5a340c647a2efc36794b5558a06a61acae15df916afdd4baa1c19f1'),
    ('bulk_current', 'selected', 0x4d0179f, 0x4d017f6, '2fa308f608e11fd7d0ea72a98fd3a783cc95b37257e9bed64cdae51d3c6d2176'),
    ('bulk_write', 'selected', 0x4d01800, 0x4d01888, '7167092327ac24490374f2671ec3383ab52a6a56cc2444c3bf235136ba5621fa'),
    ('bulk_advance', 'selected', 0x4d01888, 0x4d018e0, '18323f21bf57db137f3e8cd8aca241998302e4d5b31f438a7296816dd452fde8'),
    ('bulk_root_grow', 'selected', 0x4d018e0, 0x4d0193a, 'fbc3b03908e13ca1935a1a224b1cac6f0ba429910eaa96648e8a23daba8d5161'),
    ('bulk_capacity', 'selected', 0x4d019bd, 0x4d01a30, '4e99d64e8b371e7ba9a33d56be4e02bbea12ca6e0e52c05aea2131ab49c0a9cc'),
    ('insert_existing', 'selected', 0x51ef23b, 0x51ef27b, '00ca4de4f51749e040d9909bb1c3ed93e38fe5da6202d18e68173fb359a3d692'),
    ('insert_empty', 'selected', 0x51ef291, 0x51ef2c9, '660cf29ebae92f478f2553327ffc75d14662fa8ef0b79f9a88221ba8f7b5915d'),
    ('insert_leaf_value', 'selected', 0x51ef2c9, 0x51ef33c, 'c3951bc149160ed42292d1777df8b365259c6a698bed73702b3e9eca1ea8d505'),
    ('insert_return', 'selected', 0x51ef33c, 0x51ef362, '26fe0eeaf238c95f928dc2cad788c06944b5dc84d40e0151a59cc472aa9574c2'),
    ('insert_fail', 'selected', 0x51ef362, 0x51ef38f, '05551abc30d197bf4bcfe3397080a29dcfa35b56088828f44057456e0fdd07bf'),
    ('split_decide', 'selected', 0x4c71557, 0x4c71596, '36ccc23128a6fb1a20e30210f0bcc383e92b6c42a4f7bd28b3c04a6c7b08afbd'),
    ('split_no_full', 'selected', 0x4c71596, 0x4c715dd, 'ca23d13ff3c5edad26bc47bd729983f003d7700aa1c1357509deff7722c095c8'),
    ('split_pivot', 'selected', 0x4c715dd, 0x4c71604, '5ab14139c4395211a437c39c361d9fa85892dadb9903ec43f77ec63c529eb763'),
    ('split_insert_move', 'selected', 0x4c71604, 0x4c716d9, 'e1a0dedff62844aac753a4ba9551daa76a6fc58bc988725a127867642e6361b8'),
    ('split_allocate', 'selected', 0x4c716f9, 0x4c71731, '21b30f2ede67b3c1c90360bdf63de92d5873581d89f5d59b46e3a513643e3d82'),
    ('split_right_count', 'selected', 0x4c71731, 0x4c7178e, 'a97d9d66d9a2ba8a7f23a50e85da965c800c3f3e59fb740101d3060c62050974'),
    ('split_fail', 'selected', 0x4c7234f, 0x4c723df, 'eb7581a44e111778af1a5f744c44f753b40c9e56e56089e76317fa1d850a8583'),
    ('iterate_guard', 'selected', 0x51e62ab, 0x51e62f0, 'ce4f92922924b996228525d7f8b5cb6b4579cc64275bcca0bb783cef6be66ccc'),
    ('iterate_null', 'selected', 0x51e6349, 0x51e63db, '3f5ad969246aa5980216d32ceaf2d46351184047f5eb37da2167e82e84de46db'),
    ('iterate_descent', 'selected', 0x51e63db, 0x51e6484, 'c04ea92d3f312db48263975d307697fc5c4c2a2842b0cf9eea68a253ba56da67'),
    ('iterate_yield', 'selected', 0x51e64e8, 0x51e656c, '73595db20f9d52c8bbe0d5966a0fde15295cb58b7ccaf653ce682004a27e0eab'),
    ('iterate_panic', 'selected', 0x51e6613, 0x51e664a, '0eb373c3987741ba51bd1d60dae1e107b1a6ffc471c93df77bc5c6b63706ef40'),
    ('flatten_allocate', 'selected', 0x5b98a90, 0x5b98b21, 'c0fe85cdfd74971a29db6cb9a58ea4393a57b3901ce42b5e34dc2091d78a27d3'),
    ('flatten_next', 'selected', 0x5b98bc0, 0x5b98c1a, '7505dd553fcfbec9d63ba6ac4aac10aa4d99a59410a057d9ac7f6158a9772662'),
    ('flatten_copy', 'selected', 0x5b98c1a, 0x5b98c52, '284a40d80eb713db97ec2ea3cee27adca1dc8ae2cec54ab30735a9407435545c'),
    ('flatten_drop', 'selected', 0x5b98c52, 0x5b98ce8, '69e8df7dcf49a439613e78d8dadf0c8c81edc11970ad1dda5b713352a0f1eb3b'),
    ('flatten_return', 'selected', 0x5b98ce8, 0x5b98d10, '46ec18b11b8bf52bfd161a7abfe01cf4e6ac9a45cac129633dd982891e8d30c1'),
    ('cleanup_tree', 'selected', 0x52545b0, 0x5254670, '25537b7b70e3ff52af8d066d313307a9b1f5b1b25a51e8c2aa13f151d9674cdc'),
    ('cleanup_joined', 'selected', 0x59d35b0, 0x59d3699, '25db76246940a81b9a961a523c9aff898029fd79f0502d0a67b42fc97dd3ef5c'),
    ('variant_drop_entry', 'selected', 0x5b232ab, 0x5b232e7, 'cf20adba43b527fd7ac89b9fb137d17dfbf0df7e072f8ca568f4e8b4dd89dcd4'),
    ('variant_drop_items', 'selected', 0x5b232e7, 0x5b23362, '34711ee8aee853bfb4da02eeaca56156261bae824a4edd25a2451d41bf8c329c'),
    ('variant_drop_status', 'selected', 0x5b23362, 0x5b23401, '3e6f9dc0ebae195ae5f5b744c24ac0065701e49667359a7d684db38bc10d2cb7'),
    ('variant_drop_finish', 'selected', 0x5b23401, 0x5b2343a, '258e17ac1bc2f08a1f1670ea0417b53f5380d4a9a3c6dd2412f04dbef043fee8'),
    ('location_lea', 'context', 0x3c1352f, 0x3c13536, 'f50ae9114cd5bb10aeaaf83f5b9e76da76a684828a626b20e9343284bb4cbc6c'),
    ('location_cmp', 'context', 0x3c1353b, 0x3c13541, '09139983e5d4c0df7e80b615403af43be14877b35a000c7e26457be8898d76cb'),
    ('prior_projector_copy', 'context', 0x5961350, 0x5961384, '442a794762801c510923d68a3491aef8e4f2cf59eee2a11b62f7f5957f1b841b'),
    ('prior_serializer_input', 'context', 0x531e3ae, 0x531e3e7, '4fde4c39d6df3dbce439c85fa4389c58a388c81ad85221294eced29c3b2711b9'),
]

# Each entry is an instruction address and exact original instruction bytes.
# Only these instruction-aligned forms are decoded; no bytewise disassembly.
TRANSFERS = [
    (0x57ea392, '0f87e3000000'),
    (0x57ea3a4, '7510'),
    (0x57ea3a9, 'ff15b1bacf00'),
    (0x57ea3c0, '734b'),
    (0x57ea3f1, 'e85a890200'),
    (0x57ea40b, 'eb35'),
    (0x57ea426, 'e825890200'),
    (0x57ea48e, 'ff152452cf00'),
    (0x57ea49c, 'e83f00ffff'),
    (0x57ea4a4, 'e8a765c000'),
    (0x5812d61, '0f84a9000000'),
    (0x5812d6a, '0f84a0000000'),
    (0x5812d8c, '0f868d000000'),
    (0x5812d95, '0f83dd000000'),
    (0x5812da2, '0f865b010000'),
    (0x5812dc9, 'ff1599c7cc00'),
    (0x5812de2, 'ff1580c7cc00'),
    (0x5812e0b, 'e9a3010000'),
    (0x515f68c, 'e80f63a100'),
    (0x515f699, '0f84b7000000'),
    (0x515f6b2, '0f85e4000000'),
    (0x515f6cc, 'ff15aefd3701'),
    (0x515f6d5, '0f84db000000'),
    (0x515f73e, 'e86d1fbaff'),
    (0x515f76a, 'e851fa9e00'),
    (0x515f777, '7411'),
    (0x515f784, 'ff1516fd3701'),
    (0x515f7a0, '7326'),
    (0x515f7ac, 'e83f012900'),
    (0x515f7c0, 'ff15cafc3701'),
    (0x515f7cd, 'ff15a5613801'),
    (0x5b759d5, '740a'),
    (0x5b759d9, 'ff15b99a9600'),
    (0x5b759e7, '741b'),
    (0x5b759ef, 'ff158b9a9600'),
    (0x5b759f8, '7512'),
    (0x5b75a3b, '0f8404010000'),
    (0x5b75a6a, '745e'),
    (0x5b75ac8, '75c6'),
    (0x5b75acd, '737a'),
    (0x5b75b38, '75c6'),
    (0x5b75b70, 'e80b39ceff'),
    (0x5b75b88, 'ff1512999600'),
    (0x53ef8f7, '0f83e2000000'),
    (0x53ef900, '7501'),
    (0x53ef961, '73ea'),
    (0x53ef9c3, '0f8457ffffff'),
    (0x53ef9d5, '72b9'),
    (0x4d5f9a0, '753e'),
    (0x4d5f9a7, '0f8423010000'),
    (0x4d5f9d9, '7532'),
    (0x4d5fa74, '7469'),
    (0x4d5fa79, '7564'),
    (0x4d5fab3, '0f84c7feffff'),
    (0x4d5fac5, 'ff15d5f97701'),
    (0x4d01892, 'e889e00500'),
    (0x4d0189c, '0f84ab020000'),
    (0x4d018b3, '0f8247ffffff'),
    (0x4d018c6, '7418'),
    (0x4d018d4, '73ea'),
    (0x4d018f0, 'ff158adb7d01'),
    (0x4d018f9, '0f8457060000'),
    (0x4d0194e, '0f84bc050000'),
    (0x4d019c9, '0f8353050000'),
    (0x51ef249, '7446'),
    (0x51ef276, 'e8c522a8ff'),
    (0x51ef299, 'ff15e1012f01'),
    (0x51ef2a2, '0f84ba000000'),
    (0x51ef2f9, '7379'),
    (0x51ef36c, 'ff151e012f01'),
    (0x51ef387, 'ff15a3032f01'),
    (0x4c71566, '722e'),
    (0x4c71582, '7359'),
    (0x4c715a9, '7659'),
    (0x4c715dd, '0f84fb000000'),
    (0x4c715e7, '0f85fa000000'),
    (0x4c71631, 'ff1531df8601'),
    (0x4c71684, 'ff15dede8601'),
    (0x4c71702, 'ff1578dd8601'),
    (0x4c7170b, '0f84570c0000'),
    (0x4c71788, '0f83c10b0000'),
    (0x4c72360, 'ff150ad28601'),
    (0x4c72372, 'ff1518d18601'),
    (0x51e62b5, '0f848e000000'),
    (0x51e62c5, '0f8570030000'),
    (0x51e62d2, '0f8403010000'),
    (0x51e62ea, '0f8394010000'),
    (0x51e62f9, '0f84e9010000'),
    (0x51e6330, '75ee'),
    (0x51e6363, '7569'),
    (0x51e6368, '0f84fe010000'),
    (0x51e63ea, '7472'),
    (0x51e647e, '0f826cfeffff'),
    (0x51e64a6, '0f8467010000'),
    (0x51e64d6, '73c8'),
    (0x51e6633, 'ff15f7912f01'),
    (0x51e6642, 'ff15e8912f01'),
    (0x5b98acb, '740a'),
    (0x5b98add, '741b'),
    (0x5b98aee, '7512'),
    (0x5b98b5c, '0f87ae010000'),
    (0x5b98bc6, 'e8d5d664ff'),
    (0x5b98bd3, '747d'),
    (0x5b98c18, '7438'),
    (0x5b98c4d, 'e96effffff'),
    (0x5b98c61, 'e83ad664ff'),
    (0x5b98cd9, 'e8c2d564ff'),
    (0x5b98d22, 'e8e9acdcff'),
    (0x52545c7, 'e8d41cf9ff'),
    (0x52545d3, '0f8497000000'),
    (0x52545f6, 'e8a51cf9ff'),
    (0x5254602, '746c'),
    (0x5254634, '741a'),
    (0x525463d, 'e85eec8c00'),
    (0x5b232b4, '7516'),
    (0x5b232bd, '0f8468010000'),
    (0x5b232cf, '0f8756010000'),
    (0x5b232f1, '0f8034010000'),
    (0x5b232f7, '72ca'),
    (0x5b23305, '0f8420010000'),
    (0x5b23323, '0f84d8000000'),
    (0x5b23347, '0f84b4000000'),
    (0x5b23355, '74e9'),
    (0x5b2336d, '7437'),
    (0x5b23387, '741d'),
    (0x5b2338f, '72ef'),
    (0x5b23399, '74e5'),
    (0x5b233ad, '747c'),
    (0x5b233c0, '743f'),
    (0x5b233e7, '7418'),
    (0x5b233f0, '74ee'),
    (0x5b233f5, '74e9'),
    (0x5b23408, '7421'),
    (0x5b23425, 'ff2575c09b00'),
]

# Exact instructions and positions of little-endian constants within them.
# "sibscale" derives the scale from the actual x86 SIB byte.
OPERANDS = [
    ('projected_source_stride', 0x5961364, '4983c548', 3, 1, 'imm'),
    ('projected_result_stride', 0x596137b, '4983c740', 3, 1, 'imm'),
    ('zip_first_stride', 0x5b30da8, '4983c528', 3, 1, 'imm'),
    ('zip_second_stride', 0x5b30d20, '488d4218', 3, 1, 'imm'),
    ('zip_result_stride', 0x5b30d87, '4883c140', 3, 1, 'imm'),
    ('key_scale', 0x51ef305, '488954c808', 3, 1, 'sibscale'),
    ('leaf_value_offset', 0x51ef335, '0f11441060', 4, 1, 'imm'),
    ('leaf_value_stride', 0x51ef30a, '486bd138', 3, 1, 'imm'),
    ('leaf_entry_limit', 0x51ef2f5, '4883f90b', 3, 1, 'imm'),
    ('leaf_allocation_bytes', 0x51ef294, 'bfd0020000', 1, 4, 'imm'),
    ('internal_allocation_bytes', 0x4d018eb, 'bf30030000', 1, 4, 'imm'),
    ('ring_to_tree_threshold', 0x4dd0186, '4883fe40', 3, 1, 'imm'),
    ('tree_to_ring_threshold', 0x4dd0045, '4883f820', 3, 1, 'imm'),
    ('small_sort_upper_threshold', 0x515f79c, '4883fe15', 3, 1, 'imm'),
    ('outer_output_stride', 0x5b78a11, '4883c538', 3, 1, 'imm'),
    ('serializer_nested_pointer', 0x531e3ae, '498b6c2428', 4, 1, 'imm'),
    ('serializer_nested_count', 0x531e3b3, '4d8b642430', 4, 1, 'imm'),
    ('cleanup_table_maximum_tag', 0x5b232cc, '83f80c', 2, 1, 'imm'),
    ('ring_element_shift', 0x57ea442, '49c1e606', 3, 1, 'imm'),
    ('split_lower_cut', 0x4c71571, '4983ff05', 3, 1, 'imm'),
    ('split_upper_cut', 0x4c715e3, '4983ff06', 3, 1, 'imm'),
    ('split_right_adjust', 0x4c716e7, '4983c7f9', 3, 1, 'simm'),
    ('split_left_pivot', 0x4c71589, '41bf04000000', 2, 4, 'imm'),
    ('split_mid_pivot', 0x4c715ed, '41bf05000000', 2, 4, 'imm'),
    ('split_right_pivot', 0x4c716f0, '41bf06000000', 2, 4, 'imm'),
    ('collector_nonempty_vector_minimum', 0x5b788ce, 'bb04000000', 1, 4, 'imm'),
    ('collector_allocation_limit', 0x5b788e3, '48b84992244992244902', 2, 8, 'imm'),
]


def authenticate(data, expected=SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def mapped_offset(data, secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] > 0
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address does not have exactly one file-backed section')
    sec = matches[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file mapping outside input')
    return off


def read_va(data, secs, va, size):
    off = mapped_offset(data, secs, va, size)
    return data[off:off + size]


def check_window(raw, expected_digest):
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError('selected instruction window changed')


def check_operand(raw, expected_hex, offset, width, kind):
    if raw != bytes.fromhex(expected_hex):
        raise ValueError('selected operand instruction changed')
    if offset < 0 or width <= 0 or offset + width > len(raw):
        raise ValueError('operand outside instruction')
    value = int.from_bytes(raw[offset:offset + width], 'little')
    if kind == 'sibscale':
        if width != 1:
            raise ValueError('invalid SIB scale')
        return 1 << (value >> 6)
    if kind == 'simm':
        return int.from_bytes(raw[offset:offset + width], 'little', signed=True)
    if kind != 'imm':
        raise ValueError('unsupported operand type')
    return value


def decode_transfer(va, raw):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return ('call' if raw[0] == 0xe8 else 'jump', va + 5 + struct.unpack_from('<i', raw, 1)[0])
    if len(raw) == 2 and raw[0] == 0xeb:
        return ('jump', va + 2 + struct.unpack_from('<b', raw, 1)[0])
    if len(raw) == 2 and 0x70 <= raw[0] <= 0x7f:
        return (f'jcc_{raw[0] & 15:x}', va + 2 + struct.unpack_from('<b', raw, 1)[0])
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return (f'jcc_{raw[1] & 15:x}', va + 6 + struct.unpack_from('<i', raw, 2)[0])
    if len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return ('call_slot' if raw[1] == 0x15 else 'jump_slot', va + 6 + struct.unpack_from('<i', raw, 2)[0])
    raise ValueError('unsupported selected transfer encoding')


def checked_transfer(va, raw, expected_hex):
    if raw != bytes.fromhex(expected_hex):
        raise ValueError('selected transfer changed')
    return decode_transfer(va, raw)


def relocation_at(data, secs, slot):
    found_sections = [s for s in secs if s['name'] == '.rela.dyn']
    if len(found_sections) != 1:
        raise ValueError('missing or ambiguous relocation section')
    sec = found_sections[0]
    if sec['type'] != 4 or sec['size'] % 24:
        raise ValueError('invalid relocation section')
    found = []
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        address, info, addend = struct.unpack_from('<QQq', data, off)
        if address == slot:
            found.append((address, info & 0xffffffff, info >> 32, addend, off))
    if len(found) != 1 or found[0][1:3] != (8, 0):
        raise ValueError('missing, duplicated or non-relative Location relocation')
    return found[0]


DROP_WORDS = ('02571e05', '55571e05', 'cb571e05', '9e561e05', '87561e05',
              '87561e05', 'cb571e05', 'cb571e05', 'cb571e05', 'cb571e05',
              'cb571e05', 'cb571e05', 'b8561e05')


def decode_drop_table(raw, table_va, count):
    if count != len(DROP_WORDS) or len(raw) != count*4:
        raise ValueError('incorrect drop table length')
    entries = []
    for tag, expected in enumerate(DROP_WORDS):
        word = raw[tag*4:tag*4+4]
        if word != bytes.fromhex(expected):
            raise ValueError('drop table entry changed')
        target = table_va + struct.unpack('<i', word)[0]
        if not 0x5b232a0 <= target < 0x5b2343a:
            raise ValueError('drop table target outside selected FDE')
        entries.append((tag, word, target))
    return entries


def source_location(data, secs, loc):
    _, typ, sym, string_va, reloc_off = relocation_at(data, secs, loc)
    ptr, length, line, col = struct.unpack('<QQII', read_va(data, secs, loc, 24))
    if ptr != 0 or length <= 0 or length > 512:
        raise ValueError('invalid Location record')
    text = read_va(data, secs, string_va, length)
    if not text.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('unexpected Location suffix')
    return {'location_va': hex(loc), 'location_file_offset': hex(mapped_offset(data, secs, loc, 24)),
            'string_va': hex(string_va), 'file_suffix': 'l1/src/abci/state.rs',
            'string_length': length, 'line': line, 'column': col,
            'relocation_file_offset': hex(reloc_off), 'relocation_type': typ, 'relocation_symbol': sym}


def check_historical_extents(fdes, index):
    # Old coordinates remain attached to the authenticated #94 artifact.
    for start, end, site in ((0x32725d0, 0x3272b3a, 0x3272785),
                             (0x3273810, 0x327396c, 0x3273871)):
        matches = [f for f in fdes if f['start'] == start]
        entries = [r for r in index if r['start'] == start]
        if (len(matches) != 1 or len(entries) != 1 or matches[0]['end'] != end
                or entries[0]['fde'] != matches[0]['fde']
                or entries[0]['section'] != '.text' or not start <= site < end):
            raise ValueError('historical FDE or unwind index changed')


def verify_historical(data):
    authenticate(data, OLD_SHA256)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    check_historical_extents(fdes, index)
    loc = source_location(data, secs, 0x56dfbf8)
    if (loc['line'], loc['column']) != (107, 37):
        raise ValueError('historical Location changed')
    lea = read_va(data, secs, 0x3273856, 7)
    if lea[:3] != b'\x48\x8d\x0d' or 0x3273856 + 7 + struct.unpack_from('<i', lea, 3)[0] != 0x56dfbf8:
        raise ValueError('historical Location reference changed')
    if read_va(data, secs, 0x3273871, 4) != b'\x49\x83\xfd\x02':
        raise ValueError('historical comparison changed')
    _, typ, sym, addend, _ = relocation_at(data, secs, 0x57755a8)
    if (typ, sym, addend) != (8, 0, 0x3273810):
        raise ValueError('historical slot target changed')
    insn = read_va(data, secs, 0x3272785, 6)
    kind, slot = decode_transfer(0x3272785, insn)
    if (kind, slot) != ('call_slot', 0x57755a8):
        raise ValueError('historical call changed')
    # This validates the prior clue only; it does not add #94 bytes to output.
    return loc


def parse_call_sites(data, secs, fde):
    """Decode the observed omitted-LPStart ULEB call-site form, not action chains."""
    if fde['lsda'] is None:
        return []
    ex = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(ex) != 1:
        raise ValueError('missing or ambiguous exception table')
    sec = ex[0]
    va = fde['lsda']
    if not sec['address'] <= va < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception section')
    pos = mapped_offset(data, secs, va, 1)
    limit = sec['offset'] + sec['size']
    if pos + 2 > limit or data[pos] != 0xff or data[pos+1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    type_enc = data[pos+1]
    pos += 2
    if type_enc == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        if type_base > limit:
            raise ValueError('type table outside section')
    else:
        type_base = limit
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported call-site encoding')
    length, pos = uleb(data, pos+1, limit)
    stop = pos + length
    if stop > limit or stop > type_base:
        raise ValueError('call-site table outside section')
    rows = []
    while pos < stop:
        record = pos
        relative, pos = uleb(data, pos, stop)
        span, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        extent = fde['end'] - fde['start']
        if relative + span > extent or (landing and landing >= extent):
            raise ValueError('LSDA row outside FDE')
        rows.append((fde['start']+relative, fde['start']+relative+span,
                     fde['start']+landing if landing else None, action,
                     record, bytes(data[record:pos]).hex()))
    return rows


def select_functions(fdes, index):
    index_by_start = {}
    for r in index:
        if r['start'] in index_by_start:
            raise ValueError('duplicate unwind start')
        index_by_start[r['start']] = r
    desired = {start for _, start, _ in FUNCTIONS}
    selected = {}
    for fde in fdes:
        if fde['start'] in desired:
            if fde['start'] in selected:
                raise ValueError('duplicate selected FDE')
            selected[fde['start']] = fde
    if set(selected) != desired:
        raise ValueError('missing selected FDE')
    ranges = []
    for role, start, end in FUNCTIONS:
        r = selected[start]
        table = index_by_start.get(start)
        if r['end'] != end or table is None or table['fde'] != r['fde'] or table['section'] != '.text':
            raise ValueError('selected FDE differs from unwind table or expected range')
        ranges.append((start, end))
    ranges.sort()
    if any(b[0] < a[1] for a, b in zip(ranges, ranges[1:])):
        raise ValueError('selected FDE extents overlap')
    return selected, index_by_start


def split_pivot(index, facts):
    if not isinstance(index, int) or not 0 <= index <= facts['leaf_entry_limit']:
        raise ValueError('split insertion index out of range')
    low, high = facts['split_lower_cut'], facts['split_upper_cut']
    if index < low:
        return facts['split_left_pivot'], 0, index
    if index == low:
        return facts['split_mid_pivot'], 0, index
    if index == high:
        return facts['split_mid_pivot'], 1, 0
    return facts['split_right_pivot'], 1, index + facts['split_right_adjust']


def transition(tree, count, lookup_nonzero, facts):
    if not isinstance(count, int) or not 0 <= count < 1 << 64:
        raise ValueError('count outside u64')
    if tree and count < facts['tree_to_ring_threshold']:
        return 'tree_to_ring'
    if not tree and lookup_nonzero and count >= facts['ring_to_tree_threshold']:
        return 'ring_to_tree'
    return 'keep'


def lea_target(va, insn):
    if len(insn) != 7 or insn[:3] not in (b'\x48\x8d\x0d', b'\x48\x8d\x15'):
        raise ValueError('unsupported selected LEA')
    return va + 7 + struct.unpack_from('<i', insn, 3)[0]


def tsv(headers, rows):
    import io
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def jbytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')


def collect(data):
    digest = authenticate(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    selected, index_by_start = select_functions(fdes, index)
    func_rows = []
    for role, start, end in FUNCTIONS:
        fde = selected[start]
        raw = read_va(data, secs, start, end - start)
        func_rows.append([role, hex(start), hex(end), hex(mapped_offset(data, secs, start, end-start)),
                          end-start, hex(fde['fde']), hex(fde['cie']),
                          hex(fde['lsda']) if fde['lsda'] is not None else '-',
                          index_by_start[start]['index'], hashlib.sha256(raw).hexdigest(), raw.hex()])
    window_rows = []
    for name, scope, start, end, expected in WINDOWS:
        raw = read_va(data, secs, start, end-start)
        check_window(raw, expected)
        if scope == 'selected' and sum(a <= start < end <= b for _, a, b in FUNCTIONS) != 1:
            raise ValueError('selected window outside its FDE')
        window_rows.append([name, scope, hex(start), hex(end), hex(mapped_offset(data, secs, start, end-start)),
                            end-start, hashlib.sha256(raw).hexdigest(), raw.hex()])
    context_hits = {}
    for name, scope, start, end, _ in WINDOWS:
        if scope != 'context':
            continue
        hits = [f for f in fdes if f['start'] <= start < end <= f['end']]
        if len(hits) != 1:
            raise ValueError('context window has no unambiguous FDE')
        fde = hits[0]
        table = index_by_start.get(fde['start'])
        if table is None or table['fde'] != fde['fde'] or fde['start'] in selected:
            raise ValueError('invalid context FDE')
        context_hits.setdefault(fde['start'], (fde, []))[1].append(name)
    context_rows = []
    for start in sorted(context_hits):
        fde, names = context_hits[start]
        context_rows.append([hex(start), hex(fde['end']), hex(fde['fde']),
                             hex(fde['cie']), index_by_start[start]['index'], ','.join(sorted(names))])
    transfer_rows = []
    for va, expected in TRANSFERS:
        raw = read_va(data, secs, va, len(expected)//2)
        kind, target = checked_transfer(va, raw, expected)
        owners = [role for role, start, end in FUNCTIONS if start <= va and va + len(raw) <= end]
        if len(owners) != 1:
            raise ValueError('transfer outside selected FDE')
        transfer_rows.append([owners[0], hex(va), hex(mapped_offset(data, secs, va, len(raw))), raw.hex(), kind, hex(target)])
    call_sites = {}
    unwind_rows = []
    for role, start, end in FUNCTIONS:
        fde = selected[start]
        rows = parse_call_sites(data, secs, fde)
        call_sites[role] = rows
        for begin, finish, landing, action, record_off, rawhex in rows:
            unwind_rows.append([role, hex(fde['lsda']), hex(record_off), hex(begin), hex(finish),
                                hex(landing) if landing is not None else '-', action, rawhex])
    unwind_links = []
    for role, site, off, rawhex, kind, target in transfer_rows:
        if kind not in ('call', 'call_slot'):
            continue
        address = int(site, 16)
        matches = [r for r in call_sites[role] if r[0] <= address < r[1]]
        if len(matches) > 1:
            raise ValueError('overlapping call-site records')
        if matches and address + len(bytes.fromhex(rawhex)) > matches[0][1]:
            raise ValueError('call instruction crosses LSDA record')
        fde = next(selected[start] for name, start, _ in FUNCTIONS if name == role)
        status = 'listed' if matches else ('no_lsda' if fde['lsda'] is None else 'not_listed')
        landing = hex(matches[0][2]) if matches and matches[0][2] is not None else '-'
        action = matches[0][3] if matches else '-'
        unwind_links.append([role, site, kind, target, status, landing, action])
    facts = {}
    operand_rows = []
    for name, va, expected, offset, width, kind in OPERANDS:
        raw = read_va(data, secs, va, len(expected)//2)
        value = check_operand(raw, expected, offset, width, kind)
        facts[name] = value
        operand_rows.append([name, hex(va), hex(mapped_offset(data, secs, va, len(raw))), raw.hex(), kind, offset, width, value])
    key = facts['key_scale']
    triple = facts['zip_second_stride']
    outer = facts['outer_output_stride']
    row = facts['zip_result_stride']
    if not (row == key + outer and outer == facts['leaf_value_stride'] and
            row == facts['projected_result_stride'] == (1 << facts['ring_element_shift']) and
            facts['serializer_nested_pointer'] == outer-triple+key and
            facts['serializer_nested_count'] == outer-key and
            facts['leaf_entry_limit'] == 11 and facts['ring_to_tree_threshold'] == 64 and
            facts['tree_to_ring_threshold'] == 32):
        raise ValueError('selected result-layout relationship changed')
    loc_va = lea_target(0x3c1352f, read_va(data, secs, 0x3c1352f, 7))
    if loc_va != 0x64767a8:
        raise ValueError('node Location reference changed')
    loc = source_location(data, secs, loc_va)
    if (loc['line'], loc['column']) != (123, 37):
        raise ValueError('node Location changed')
    table_va = lea_target(0x5b232d7, read_va(data, secs, 0x5b232d7, 7))
    n = facts['cleanup_table_maximum_tag'] + 1
    table_raw = read_va(data, secs, table_va, 4*n)
    entries = decode_drop_table(table_raw, table_va, n)
    table_rows = [[tag, hex(table_va + 4*tag), hex(mapped_offset(data, secs, table_va + 4*tag, 4)),
                   raw.hex(), hex(target)] for tag, raw, target in entries]
    pivot_rows = [[i, *split_pivot(i, facts)] for i in range(facts['leaf_entry_limit'] + 1)]
    boundaries = []
    for is_tree in (False, True):
        for count in (0, facts['tree_to_ring_threshold'] - 1, facts['tree_to_ring_threshold'],
                      facts['ring_to_tree_threshold'] - 1, facts['ring_to_tree_threshold']):
            for lookup_nonzero in (False, True):
                boundaries.append([int(is_tree), count, int(lookup_nonzero), transition(is_tree, count, lookup_nonzero, facts)])
    facts.update({'target_sha256': digest, 'key_bytes': key, 'nested_vector_metadata_bytes': triple,
                  'outer_value_bytes': outer, 'identifier_bytes': outer-triple,
                  'joined_row_bytes': row, 'location': loc,
                  'selected_function_count': len(func_rows), 'selected_window_count': sum(w[1] == 'selected' for w in window_rows),
                  'context_window_count': sum(w[1] == 'context' for w in window_rows),
                  'context_function_count': len(context_rows),
                  'transfer_count': len(transfer_rows), 'operand_count': len(operand_rows),
                  'drop_table_entries': len(table_rows), 'lsda_rows': len(unwind_rows),
                  'selected_call_link_records': len(unwind_links),
                  'matched_call_to_lsda_links': sum(row[4] == 'listed' for row in unwind_links),
                  'unmatched_call_link_records': sum(row[4] == 'not_listed' for row in unwind_links),
                  'calls_in_fdes_without_lsda': sum(row[4] == 'no_lsda' for row in unwind_links)})
    return {
        'functions.tsv': tsv(['role','start_va','end_va_exclusive','file_offset','size','fde_va','cie_va','lsda_va','unwind_index','sha256','body_hex'],func_rows),
        'windows.tsv': tsv(['name','scope','start_va','end_va_exclusive','file_offset','size','sha256','bytes'],window_rows),
        'context-functions.tsv': tsv(['start_va','end_va_exclusive','fde_va','cie_va','unwind_index','windows'], context_rows),
        'transfers.tsv': tsv(['function','site_va','file_offset','bytes','kind','target_or_slot_va'],transfer_rows),
        'operands.tsv': tsv(['name','site_va','file_offset','bytes','kind','byte_offset','width','value'],operand_rows),
        'drop-table.tsv': tsv(['tag','entry_va','file_offset','bytes','target_va'],table_rows),
        'unwind.tsv': tsv(['function','lsda_va','record_file_offset','start_va','end_va_exclusive','landing_va','action','bytes'],unwind_rows),
        'unwind-links.tsv': tsv(['function','call_site_va','kind','target_or_slot_va','status','landing_va','action'],unwind_links),
        'pivot-cases.tsv': tsv(['index','pivot','right','local_index'],pivot_rows),
        'transition-cases.tsv': tsv(['tree_representation','count','lookup_nonzero','selected_result'],boundaries),
        'facts.json': jbytes(facts),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--historical-node', type=Path)
    args = ap.parse_args()
    data = TARGET.read_bytes()
    authenticate(data)
    if args.historical_node is not None:
        verify_historical(args.historical_node.read_bytes())
    files = collect(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in files.items():
        (args.out / name).write_bytes(contents)
    print(f'Wrote {len(files)} evidence files; input digest verified.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print(f'evidence extraction failed: {type(exc).__name__}', file=sys.stderr)
        raise SystemExit(1)
