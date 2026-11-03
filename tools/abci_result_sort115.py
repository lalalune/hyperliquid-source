#!/usr/bin/env python3
"""Static, digest-bound RE-017 result-row sorting evidence for node #115.

The fixed windows are instruction-aligned observations, not a general x86
instruction decoder. Earlier proposals supply the surrounding context; the
selected unwind ranges are the only new code bodies examined here.
"""
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
from fde_extents import eh_frame_records

TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64_MAX = (1 << 64) - 1

# FDE ends are exclusive and are unwind extents, not source-body boundaries.
OWNED = {
    0x4e66e70: ('pivot_choice', 0x4e66f1a),
    0x4eb7970: ('partition_dispatch', 0x4eb7f38),
    0x4f304e0: ('unwind_cleanup', 0x4f30536),
    0x4f40550: ('sort_buffer_adapter', 0x4f40696),
    0x4f73c60: ('run_scanner_merge', 0x4f742ee),
    0x5417a80: ('small_run_sort', 0x5418198),
    0x57f8cd0: ('ring_key_lookup', 0x57f8df1),
    0x5b4f1c0: ('nested_row_drop', 0x5b4f23e),
}

# Names beginning with context_ denote existing proposed FDEs/sites, not new
# ownership. These byte patterns independently pin the joins used below.
WINDOWS = [
('context_location', 0x3c1352f, '488d1572328602e8d5ae61004883f8017546'),
('context_loader_writes', 0x3c128ca, '498b44242848894424584c39f80f85390100004d897c2410498b442418498b74243048ffc048c7c1ffffffff480f45c849894c2418498974242049c78424e810000000000000'),
('context_begin', 0x5483fd3, '498b752848ffc648c7c2ffffffff480f45d64989552849c745000000000049894d3049898d7819000049898d981a000041f6852045000001'),
('context_item_counter', 0x560dbcc, '488b86b016000048ffc049c7c5ffffffff490f44c5488986b0160000'),
('context_item_tag', 0x560dc22, '66817c2410a201751c498b86b816000048ffc0490f44c5498986b8160000'),
('context_index_init', 0x5a0692e, '4531f6eb60'),
('context_index_increment', 0x5a06984, '49ffc64c39eb4c89eb'),
('context_index_store', 0x5a06a0f, '488d0cad000000004801e94c8934c8'),
('context_ring_dispatch', 0x515f68c, 'e80f63a100488b7424204885f60f84b7000000488b7c2418488d44240f48894424404883fe010f85e4000000'),
('context_ring_sort_branch', 0x515f79c, '4883fe157326488d4c2440ba01000000e83f012900e902ffffffbf08000000bed0020000ff15cafc37010f0b488d542440ff15a5613801e9e0feffff'),
('context_ring_tree_setup', 0x515f702, '49c1e7064d01e74c896424404c896424484c897424504c897c245848b801000000000000804889842488000000488d7c2430488d742440488d542428e86d1fbaff0f10442430488b4424280f110348894310'),
('context_tree_reduce_call', 0x4d01888, '488d7c2430488d742470e889e005004c396424580f84ab020000'),
('context_reduce_comparison', 0x4d5fa71, '4939ff7469493b00756448ffc34c89e76666666666662e0f1f840000000000'),
('context_reduce_return', 0x4d5fadf, '488b4c24084889014889c80f284424600f284c24700f1141080f1149184c8971284c89613048895938'),
('adapter_cap', 0x4f4056d, '4989d64889f148d1e94889f04829c84881fe48e80100bb48e80100480f42de4839c3480f46d84883fb41722d4989dc49c1e40648c1e83a0f95c048b9f8ffffffffffff7f4939cc0f97c108c1741731ff4c89e6ff15d2ee5901'),
('adapter_alloc', 0x4f405c6, '4c8d7c2418b940000000eb324989fd4889f54c89e7ff159fee59014885c074664989c748891c24488944240848c7442410000000004889d94889ee4c89ef4531c04883fe41410f92c04c89fa4d89f1e846360300'),
('adapter_cleanup', 0x4f4061a, '4883fb40761a4889e7e898ebc00048c1e3064c89ff4889de31d2ff1566ee59014881c4181000005b415c415d415e415f5dc3bf080000004c89e6ff153eee59014989c648c1e3064c89ff4889de31d2ff1531ee59014c89f7e8d9034b014989c64883fb4076084889e7e858fefeff4c89f7e8c0034b01'),
('sort_minrun', 0x4f73c80, '4883fe020f82520600004989cd4889d748b8000000000000004031d248f7f64883fa014883d8ff48894424784881fe0110000048897424304889f0731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb274883c801480fbdc889c8d1e883e10101c1b80100000048d3e048d3ee4801c648d1ee4889742420'),
('sort_run_init', 0x4f73d30, '41bc0100000031ed4531c948897c24184c89ac2490000000488b7424304829ee7627eb3c6666662e0f1f84000000000049ffc14889f048d1e84801c54989f4488b7424304829ee771731ffbe010000004983f9020f831f020000e9f7040000904889e948c1e106488b442410488d3c08483b7424207349'),
('sort_short_run', 0x4f73da7, '807c24540074524883fe20b820000000480f43f0488b442428488904244c89e94531c04c89cb4531c94989f6ff15ef7a57014989d9488b5424184489f0e977010000'),
('sort_run_direction', 0x4f73df0, '4883fe02732a4889f0e9620100006690488b4424204839c6480f43f04801f6e9540100006666662e0f1f8400000000004c8b1f4c8b77404d39de4989f7724ab8020000004883fe020f8422010000'),
('sort_asc_compare', 0x4f73e60, '4d89ca4d8b084d39d1726248ffc04983c0404939c775e9eb3e'),
('sort_desc_compare', 0x4f73ea0, '4d89ca4d8b084d39d1732248ffc04983c0404939c775e9'),
('sort_reverse_guard', 0x4f73ede, '4d39de400f93c64989c049d1e8400f94c74008f7756c'),
('sort_reverse_move', 0x4f73f10, '0f1046d00f104fd00f114ed00f1147d00f1046e00f104fe00f114ee00f1147e00f1046f00f104ff00f114ef00f1147f00f10060f100f0f110e0f11074883c6404883c7c049ffc875b7'),
('sort_pack_run', 0x4f73f60, '488d3445010000004c89e048d1e84889f148d1e9488d3c6d000000004829c7488d0469488b4c2478480faff9480fafc14831f8bf7f000000480fbdf883f73f'),
('sort_merge_decision', 0x4f7402c, '4238bc0ca50000000f824c02000049ffc94a8b84cce80000004889c348d1eb4d89e749d1ef4e8d343b4d39ee772689c14409e183e101751c4d01f64d89f44983f90177bce90b02000066662e0f1f840000000000'),
('sort_sort_left', 0x4f74080, '4c29f548c1e50648036c2410a8014c894c2448755b4889d84883c8014c0fbdc04183f03f4501c04183f07e488b442428488904244889ef4889de4c89e94531c9ff1502785701'),
('sort_sort_right', 0x4f740f6, '4889df48c1e7064801ef4c89f84883c8014c0fbdc04183f03f4501c04183f07e488b442428488904244c89fe4c89e94531c9ff159a775701'),
('sort_merge_setup', 0x4f7414b, '4885db0f84befeffff4939df4989dc4d0f42e74d39e50f82abfeffff4989dd49c1e5064901ed4c39fb4889ee490f47f549c1e4064889d74c89e2ff157db35601'),
('sort_backward_merge', 0x4f741a0, '498d4dc0498d5424c0498b7424c031ff4531c0493b75c0400f92c7410f93c0480f42d10f10020f104a100f1052200f105a300f1158300f1150200f1148100f110041c1e0064d01c54983c5c0c1e7064901fc4983c4c04939ed0f84e2fdffff4883c0c04d39cc7598e9d4fdffff'),
('sort_forward_merge', 0x4f7420d, '4c89ce4c8b8424800000000f1f8400000000004889f2498b4d0031c031f6483b0a0f92c1400f93c64889d7490f42fd0f10070f104f100f1057200f105f300f115d300f1155200f114d100f114500c1e6064801d64883c5404c39e60f8479fdffff88c8c1e0064901c54d39c575a5e967fdffff'),
('sort_finish', 0x4f74280, '41b9010000004e89a4cce80000004288bc0ca600000048396c24300f87bffaffff41f6c4017535488b7424304889f04883c8014c0fbdc04183f03f4501c04183f07e488b44242848890424488b7c24104c89e94531c9ff15ec7557014881c4f80200005b415c415d415e415f5dc3'),
('partition_small', 0x4eb7992, '4883fe2173084889c7e930050000'),
('partition_pivot', 0x4eb79c0, '85ed0f84e00400004c89e148c1e9034989ce49c1e608488b7c24084901fe4869d1c00100004801fa4983fc407332488b07498b0e4839c8400f92c64c8b024c39c00f92c04030f04c39c10f92c14030f14c0f45f284c04c0f45f7eb140f1f40004c89f6e848f4faff488b7c24084989c6'),
('partition_guard', 0x4eb7a63, '48837c242000896c241c7411488b442420488b00493b060f83300200004c39e30f827e040000'),
('partition_split', 0x4eb7ab0, '4c8b084883c1c04d89e849c1e0064d3b0e4989c94d0f42cf0f10000f1048100f1050200f105830430f115c0130430f11540120430f114c0110430f1104014983d5004883c0404839f072b5'),
('partition_recurse', 0x4eb7c62, '4d39ec0f829e020000488b4c24104801f9488b8424c0000000488904244889cf4c89fa4889d94189e84c8d4c2440ff15323c63014d89ec4983fd210f831dfdffffe923020000'),
('partition_fallback', 0x4eb7ea8, '488b7c24084c89e64c89fa4889d941b8010000004c8b8c24c0000000e897bd0b00eb1b488b7c24084c89ee4c89fa4889d94c8b8424c0000000e89afb55004881c4880000005b415c415d415e415f5dc3'),
('partition_failure', 0x4eb7f07, '0f0b488d3d4c09a6fb488d15315c5e01be13000000ff1596776201488d0d375c5e014889ef4c89e64c89e2ff1538766201'),
('small_input_guard', 0x5417a8e, '4883fe020f8275060000488d46104839c10f82d50600004889d34989f449d1ec4883fe070f86a8020000'),
('small_network', 0x5417ac9, '483b0f410f93c2410f92c14531c0483b9780000000410f92c041c1e1064a8d040f41c1e2064a8d0c174589c341c1e3064a8d141f4881c2800000004183f00341c1e0064e8b9c1f800000004e8b34074e8b14174d39d64989cf4c0f42fa4e3b1c0f4c0f42f8480f42c24e8d0407480f42d14d39d6490f43c8490f42d04c8b024d3b074d89f84c0f42c2490f42d7'),
('small_insertion', 0x5417e42, '4e8b0c134e3b4c13c073b0'),
('small_forward', 0x5418084, '4c8b394531db4531e44889ca4d3b38400f93c7410f92c772034c89c2'),
('small_failure', 0x5418169, 'b0014c8b74240884c07499ff15de790c010f0b4989c44c89f74889de488b542450ff1578730c014c89e7e8b888fd00'),
('pivot_recurse', 0x4e66e81, '4883f908725848c1e9034989cf49c1e7084a8d343f4c69e1c00100004a8d14274989cde8c7ffffff'),
('pivot_median', 0x4e66edf, '488b07488b0b4839c80f92c2498b364839f00f92c030d04839f10f92c130d1490f45de84c0480f45df4889d8'),
('drop_path', 0x4f304e0, '415653504889fbe8d4ecc100488b334885f67417488b7b0848c1e60631d24883c4085b415eff2595ef5a014883c4085b415ec34989c6488b334885f67410488b7b0848c1e60631d2ff1572ef5a014c89f7e81a054c01'),
('lookup_ring_split', 0x57f8cd0, '488b47184885c00f8497000000488b17488b4f104531c04839d14c0f43c24c29c14829ca4989c14929d1767e'),
('lookup_wrap_choose', 0x57f8cfc, '4c8b47084d8b10488b3e4939fa0f97c01c000fb6c084c00f84c30000003dff0000000f85b900000031c94983f9017433'),
('lookup_wrap_search', 0x57f8d30, '4889c84c89ce48d1ee4801f14989ca49c1e2064b393c10480f47c84929f14983f90177dc4889c848c1e0064d8b14004939fa74044883d10031c04939fa0f95c04801cac3'),
('lookup_first_select', 0x57f8d74, '31d231c9eb064801c84889c24829ca48c1e10648034f08b8010000004885d27459'),
('lookup_first_search', 0x57f8d95, '488b3631ff4883fa0174244989f84989d149d1e94c01cf4989fa49c1e2064a393411490f47f84c29ca4883fa0177dc4889fa48c1e20648393411750431c0eb044883d7004889fa'),
('lookup_tail', 0x57f8ddd, '48c1e1064c01c1b8010000004885d275a731d2c3'),
('context_lookup_and_convert', 0x4dd0163, '4c39eb0f8498010000488db424b00000004c89ffe8548ba2004885c00f95c1498b77184883fe40400f93c74084f90f8490000000'),
('context_hit_or_insert', 0x4dd0227, '498b0f4c39e90f84d1000000a8017469'),
('context_hit_address', 0x4dd02a0, '4839f20f83d30100004903571031c04839ca480f43c14829c2498b470848c1e2064801d04883c008e9ad000000'),
('context_replace_value', 0x4dd037a, '488b483049894e300f10000f1048100f105020410f115620410f114e10410f11060f1045000f104d100f1055200f11000f1148100f115020488b4d3048894830e98f000000'),
('nested_drop', 0x5b4f1cb, '4c8b77104d85f6745b4c8b7f084531e4eb0b0f1f0049ffc44d39f474474c89e548c1e5064d8b6c2f384d85ed7418498b5c2f3066904889dfe89840fdff4883c34049ffcd75ef4c01fd488b75284885f674c3488b7d3048c1e60631d2ff1573029900ebb1'),
('context_detach_before_convert', 0x4dd0197, '410f1007410f104f100f294c24200f2944241049c7070000000049c74708080000000f57c0410f114710488d7c2460488d742410e890f43800'),
('context_index_failure', 0x4dd047c, '488d3d1f6db4fb488d157ec76c01be14000000ff15dbf270010f0b'),
('context_unwind_field_stores', 0x4dd0497, '4989c6eb1b4989c6498b374885f67410488b7d0048c1e60631d2ff15e9ef70014d892f488b442470488945100f104424600f114500eb204989c649891f49896f0849c74710000000004d896f18eb0848896c24084989c6488b7c2408e838bc0100eb11ff15c0ef70014989c64889efe825bc0100'),
('context_drain_allocation', 0x5b759ae, '4c8b7e184c89fe48c1e6064c89f848c1e83a0f95c048b9f8ffffffffffff7f4839ce0f97c108c1740a31ffff15b99a96000f0b4889fb4885f6741b4989f44889f7ff158b9a96004885c07512bf080000004c89e6ebd5b8080000004531ff4c897c24204889442428'),
('context_tree_allocation', 0x515f6c7, 'bfd0020000ff15aefd37014885c00f84db00000048c7000000000066c780ca0200000000'),
('adapter_prologue', 0x4f40550, '554157415641554154534881ec0010000048c70424000000004883ec18'),
]

# (role, instruction VA, exact opcode, expected branch/call/slot target).
# RIP-indirect transfers report a slot, not a runtime binding.
TRANSFERS = [
    ('context_ring_convert', 0x4dd01cb, 'e8', 0x515f660),
    ('context_invalid_index', 0x4dd02a3, '0f83', 0x4dd047c),
    ('context_bounds_failure', 0x4dd048f, 'ff15', 0x64df770),
    ('context_drain_allocate', 0x5b759ef, 'ff15', 0x64df480),
    ('context_drain_null', 0x5b759f8, '75', 0x5b75a0c),
    ('context_tree_allocate', 0x515f6cc, 'ff15', 0x64df480),
    ('context_tree_null', 0x515f6d5, '0f84', 0x515f7b6),
    ('context_lookup_call', 0x4dd0177, 'e8', 0x57f8cd0),
    ('context_no_conversion', 0x4dd0191, '0f84', 0x4dd0227),
    ('context_existing_key', 0x4dd0235, '74', 0x4dd02a0),
    ('context_insert_absent', 0x4dd0271, 'e8', 0x57ea380),
    ('lookup_empty', 0x57f8cd7, '0f84', 0x57f8d74),
    ('lookup_one_segment', 0x57f8cfa, '76', 0x57f8d7a),
    ('lookup_boundary_equal', 0x57f8d13, '0f84', 0x57f8ddc),
    ('lookup_before_boundary', 0x57f8d1e, '0f85', 0x57f8ddd),
    ('lookup_wrap_single', 0x57f8d2a, '74', 0x57f8d5f),
    ('lookup_wrap_loop', 0x57f8d52, '77', 0x57f8d30),
    ('lookup_wrap_equal', 0x57f8d62, '74', 0x57f8d68),
    ('lookup_empty_join', 0x57f8d78, 'eb', 0x57f8d80),
    ('lookup_no_rows', 0x57f8d93, '74', 0x57f8dee),
    ('lookup_first_single', 0x57f8d9e, '74', 0x57f8dc4),
    ('lookup_first_loop', 0x57f8dc2, '77', 0x57f8da0),
    ('lookup_first_absent', 0x57f8dcf, '75', 0x57f8dd5),
    ('lookup_found_return', 0x57f8dd3, 'eb', 0x57f8dd9),
    ('lookup_first_nonempty', 0x57f8dec, '75', 0x57f8d95),
    ('context_location_ref', 0x3c1352f, '488d15', 0x64767a8),
    ('context_ring_long_branch', 0x515f7a0, '73', 0x515f7c8),
    ('context_long_sort_slot', 0x515f7cd, 'ff15', 0x64e5978),
    ('context_bulk_build', 0x515f73e, 'e8', 0x4d016b0),
    ('context_reducer', 0x4d01892, 'e8', 0x4d5f920),
    ('stack_buffer', 0x4f40597, '72', 0x4f405c6),
    ('allocation_size_ok', 0x4f405b9, '74', 0x4f405d2),
    ('size_failure', 0x4f405c0, 'ff15', 0x64df498),
    ('stack_to_driver', 0x4f405d0, 'eb', 0x4f40604),
    ('allocate_scratch', 0x4f405db, 'ff15', 0x64df480),
    ('null_allocation', 0x4f405e4, '74', 0x4f4064c),
    ('run_driver', 0x4f40615, 'e8', 0x4f73c60),
    ('skip_heap_cleanup', 0x4f4061e, '76', 0x4f4063a),
    ('drop_scratch_elements', 0x4f40623, 'e8', 0x5b4f1c0),
    ('allocation_failure', 0x4f40654, 'ff15', 0x64df498),
    ('free_after_unwind', 0x4f40669, 'ff15', 0x64df4a0),
    ('cleanup_on_unwind', 0x4f40683, 'e8', 0x4f304e0),
    ('run_count_under_two', 0x4f73c84, '0f82', 0x4f742dc),
    ('scheduler_multiple_runs', 0x4f73d84, '0f83', 0x4f73fa9),
    ('scheduler_single_run', 0x4f73d8a, 'e9', 0x4f74286),
    ('scheduler_more_input', 0x4f7429b, '0f87', 0x4f73d60),
    ('scheduler_sorted_finish', 0x4f742a5, '75', 0x4f742dc),
    ('large_min_run', 0x4f73cbb, '73', 0x4f73cda),
    ('scan_existing_run', 0x4f73da5, '73', 0x4f73df0),
    ('defer_small_run', 0x4f73dac, '74', 0x4f73e00),
    ('short_run_sort', 0x4f73dd3, 'ff15', 0x64eb8c8),
    ('scan_two_or_more', 0x4f73df4, '73', 0x4f73e20),
    ('descending_first_pair', 0x4f73e2d, '72', 0x4f73e79),
    ('ascending_break', 0x4f73e69, '72', 0x4f73ecd),
    ('descending_break_including_equal', 0x4f73ea9, '73', 0x4f73ecd),
    ('skip_reverse', 0x4f73ef2, '75', 0x4f73f60),
    ('merge_capacity_exceeded', 0x4f74058, '77', 0x4f74080),
    ('merge_unsorted_run', 0x4f74062, '75', 0x4f74080),
    ('sort_left_run', 0x4f740c0, 'ff15', 0x64eb8c8),
    ('sort_right_run', 0x4f74128, 'ff15', 0x64eb8c8),
    ('merge_scratch_too_small', 0x4f74161, '0f82', 0x4f74012),
    ('copy_smaller_run', 0x4f74185, 'ff15', 0x64df508),
    ('forward_when_left_not_larger', 0x4f74196, '76', 0x4f7420d),
    ('forward_left_end', 0x4f74268, '0f84', 0x4f73fe7),
    ('forward_loop', 0x4f74279, '75', 0x4f74220),
    ('deferred_sort', 0x4f742d6, 'ff15', 0x64eb8c8),
    ('partition_at_least_33', 0x4eb7996, '73', 0x4eb79a0),
    ('partition_small_route', 0x4eb799b, 'e9', 0x4eb7ed0),
    ('partition_depth_zero', 0x4eb79c2, '0f84', 0x4eb7ea8),
    ('partition_large_pivot', 0x4eb79ec, '73', 0x4eb7a20),
    ('recursive_pivot', 0x4eb7a23, 'e8', 0x4e66e70),
    ('partition_scratch_failure', 0x4eb7a83, '0f82', 0x4eb7f07),
    ('partition_recursion', 0x4eb7c90, 'ff15', 0x64eb8c8),
    ('partition_fallback', 0x4eb7ec4, 'e8', 0x4f73c60),
    ('small_run_callee', 0x4eb7ee1, 'e8', 0x5417a80),
    ('small_under_two', 0x5417a92, '0f82', 0x541810d),
    ('small_buffer_too_short', 0x5417a9f, '0f82', 0x541817a),
    ('small_seven_or_less', 0x5417ab2, '0f86', 0x5417d60),
    ('insertion_equal_stays', 0x5417e4b, '73', 0x5417dfd),
    ('pivot_base_case', 0x4e66e85, '72', 0x4e66edf),
    ('pivot_self_call', 0x4e66ea4, 'e8', 0x4e66e70),
    ('unwind_drop', 0x4f304e7, 'e8', 0x5b4f1c0),
    ('nested_row_drop_call', 0x5b4f203, 'e8', 0x5b232a0),
]

RELOCATIONS = {
    # kind, symbol index, addend, symbol name (where dynamically imported)
    0x64767a8: (8, 0, 0x443168, ''),          # context: #115 Location string
    0x64e5978: (8, 0, 0x4f40550, ''),         # context: proposed conversion slot
    0x64eb8c8: (8, 0, 0x4eb7970, ''),         # partition/small-sort dispatch
    0x64df480: (8, 0, 0x6355830, ''),         # allocation boundary
    0x64df498: (8, 0, 0x141e264, ''),         # failure boundary
    0x64df4a0: (8, 0, 0x635de30, ''),         # release boundary
    0x64df508: (6, 7, 0, 'memcpy'),            # dynamic symbol, not a binding proof
}


def require_digest(data, expected=TARGET_SHA256):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def only_section(secs, name):
    found = [s for s in secs if s['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicated, or NOBITS section: ' + name)
    return found[0]


def mapped_offset(data, secs, va, size):
    if va < 0 or size <= 0 or va + size > 1 << 64:
        raise ValueError('invalid address range')
    matches = [s for s in secs if s['type'] != 8 and (s['flags'] & 2)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not in one file-backed allocated section')
    section = matches[0]
    off = section['offset'] + va - section['address']
    if off < 0 or off + size > len(data):
        raise ValueError('mapped bytes outside file')
    return off


def read_va(data, secs, va, size):
    off = mapped_offset(data, secs, va, size)
    return bytes(data[off:off + size])


def check_window(data, secs, va, expected_hex):
    expected = bytes.fromhex(expected_hex)
    if read_va(data, secs, va, len(expected)) != expected:
        raise ValueError('selected byte window mismatch at ' + hex(va))


def check_windows(data, secs):
    for _, va, expected in WINDOWS:
        check_window(data, secs, va, expected)


def parse_relocations(data, secs, selected):
    rela = only_section(secs, '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('invalid RELA section size')
    symbols = only_section(secs, '.dynsym')
    strings = only_section(secs, '.dynstr')
    rows = []
    for off in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in selected:
            continue
        sym_index, kind = info >> 32, info & 0xffffffff
        sym_off = symbols['offset'] + 24 * sym_index
        if sym_off + 24 > symbols['offset'] + symbols['size']:
            raise ValueError('relocation symbol index outside dynsym')
        name_offset = struct.unpack_from('<I', data, sym_off)[0]
        if name_offset >= strings['size']:
            raise ValueError('symbol name offset outside dynstr')
        name_start = strings['offset'] + name_offset
        name_end = data.find(b'\x00', name_start, strings['offset'] + strings['size'])
        if name_end < 0:
            raise ValueError('unterminated symbol name')
        name = bytes(data[name_start:name_end]).decode('ascii')
        rows.append({'slot': slot, 'type': kind, 'symbol_index': sym_index,
                     'addend': addend, 'symbol': name, 'file_offset': off,
                     'raw': bytes(data[off:off + 24]).hex()})
    validate_relocations(rows, selected)
    return sorted(rows, key=lambda r: r['slot'])


def validate_relocations(rows, selected):
    by_slot = {}
    for row in rows:
        slot = row['slot']
        if slot in by_slot:
            raise ValueError('duplicate selected relocation')
        by_slot[slot] = row
    if set(by_slot) != set(selected):
        raise ValueError('missing or unexpected selected relocation')
    for slot, (kind, sym, addend, name) in selected.items():
        r = by_slot[slot]
        if (r['type'], r['symbol_index'], r['addend'], r['symbol']) != (kind, sym, addend, name):
            raise ValueError('selected relocation mismatch at ' + hex(slot))


def location(data, secs, rows, address, expected_line, expected_col, expected_suffix):
    row = next(r for r in rows if r['slot'] == address)
    n, line, col = struct.unpack('<QII', read_va(data, secs, address + 8, 16))
    if n == 0 or n > 256:
        raise ValueError('invalid Location path length')
    path = read_va(data, secs, row['addend'], n)
    if not path.endswith(expected_suffix) or (line, col) != (expected_line, expected_col):
        raise ValueError('Location record mismatch')
    return {'va': hex(address), 'file_offset': hex(mapped_offset(data, secs, address, 24)),
            'path_va': hex(row['addend']), 'path_length': n,
            'path_suffix': expected_suffix.decode('ascii'), 'line': line, 'column': col,
            'raw_hex': read_va(data, secs, address, 24).hex()}


def checked_fdes(data, secs):
    _, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    by_start, by_index_start = {}, {}
    for row in fdes:
        by_start.setdefault(row['start'], []).append(row)
    for row in index:
        by_index_start.setdefault(row['start'], []).append(row)
    selected = []
    for start, (role, end) in sorted(OWNED.items()):
        found, entry = by_start.get(start, []), by_index_start.get(start, [])
        if len(found) != 1 or len(entry) != 1:
            raise ValueError('missing or ambiguous selected FDE')
        fde, hdr = found[0], entry[0]
        if fde['fde'] != hdr['fde'] or fde['end'] != end or fde['cie'] not in cies:
            raise ValueError('FDE/header/end mismatch')
        overlaps = [x for x in fdes if x['start'] < end and x['end'] > start]
        if len(overlaps) != 1:
            raise ValueError('selected FDE overlaps another FDE')
        off = mapped_offset(data, secs, start, end - start)
        raw = bytes(data[off:off + end - start])
        selected.append({'role': role, 'start': start, 'end': end, 'offset': off,
                         'fde': fde['fde'], 'cie': fde['cie'], 'lsda': fde['lsda'],
                         'index': hdr['index'], 'size': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest(), 'raw_hex': raw.hex()})
    return selected


def decode_transfer(data, secs, va, opcode):
    op = bytes.fromhex(opcode)
    if opcode in ('e8', 'e9'):
        length, disp_at, disp_fmt = 5, 1, '<i'
    elif opcode == 'ff15' or opcode.startswith('488d'):
        length, disp_at, disp_fmt = (6, 2, '<i') if opcode == 'ff15' else (7, 3, '<i')
    elif len(op) == 1 and (0x70 <= op[0] <= 0x7f or op[0] == 0xeb):
        length, disp_at, disp_fmt = 2, 1, '<b'
    elif len(op) == 2 and op[0] == 0x0f and 0x80 <= op[1] <= 0x8f:
        length, disp_at, disp_fmt = 6, 2, '<i'
    else:
        raise ValueError('unsupported selected transfer encoding')
    raw = read_va(data, secs, va, length)
    if not raw.startswith(op):
        raise ValueError('selected transfer opcode mismatch at ' + hex(va))
    disp = struct.unpack_from(disp_fmt, raw, disp_at)[0]
    return va + length + disp, raw


def check_transfers(data, secs):
    rows = []
    for role, va, op, expected in TRANSFERS:
        target, raw = decode_transfer(data, secs, va, op)
        if target != expected:
            raise ValueError('selected transfer target mismatch at ' + hex(va))
        rows.append({'role': role, 'va': va, 'offset': mapped_offset(data, secs, va, len(raw)),
                     'opcode': op, 'target': target, 'raw': raw.hex(),
                     'kind': 'slot' if op == 'ff15' else 'code_or_data_va'})
    return rows


def constants(data, secs):
    u8 = lambda a: read_va(data, secs, a, 1)[0]
    u32 = lambda a: struct.unpack('<I', read_va(data, secs, a, 4))[0]
    u64 = lambda a: struct.unpack('<Q', read_va(data, secs, a, 8))[0]
    result = {
        'row_shift': u8(0x4f4059f),
        'run_power_scale': u64(0x4f73c92),
        'entry_count_cap': u32(0x4f4057f),
        'stack_threshold': u8(0x4f40596),
        'small_mode_threshold': u8(0x4f4060a),
        'maximum_allocation_bytes': u64(0x4f405a9),
        'minrun_threshold': u32(0x4f73caf),
        'minrun_cap': u8(0x4f73cc9),
        'partition_small_threshold': u8(0x4eb7995),
        'small_extra_capacity': u8(0x5417a9b),
        'context_sort_threshold': u8(0x515f79f),
        'ring_conversion_count': u8(0x4dd0189),
    }
    expected = {'row_shift': 6, 'run_power_scale': 0x4000000000000000,
                'entry_count_cap': 125000, 'stack_threshold': 65,
                'small_mode_threshold': 65, 'maximum_allocation_bytes': 0x7ffffffffffffff8,
                'minrun_threshold': 4097, 'minrun_cap': 64,
                'partition_small_threshold': 33, 'small_extra_capacity': 16,
                'context_sort_threshold': 21, 'ring_conversion_count': 64}
    if result != expected:
        raise ValueError('decoded immediate mismatch')
    return result


def classify_buffer(n, c):
    if not isinstance(n, int) or n < 0 or n > U64_MAX:
        raise ValueError('count outside unsigned 64-bit range')
    half = n - (n >> 1)
    computed = max(min(n, c['entry_count_cap']), half)
    mode = n < c['small_mode_threshold']
    if computed < c['stack_threshold']:
        return {'count': n, 'computed': computed, 'storage': 'stack',
                'scratch_elements': c['stack_threshold'] - 1, 'bytes_wrapped': None,
                'small_mode': mode, 'size_error': False}
    shifted = (computed << c['row_shift']) & U64_MAX
    overflow = bool(half >> (64 - c['row_shift'])) or shifted > c['maximum_allocation_bytes']
    return {'count': n, 'computed': computed, 'storage': 'size_error' if overflow else 'heap',
            'scratch_elements': computed, 'bytes_wrapped': shifted,
            'small_mode': mode, 'size_error': overflow}


def min_run(n, c):
    if not isinstance(n, int) or n < 0 or n > U64_MAX:
        raise ValueError('count outside unsigned 64-bit range')
    if n < 2:
        return None
    if n < c['minrun_threshold']:
        return min(n - (n >> 1), c['minrun_cap'])
    highest_bit = (n | 1).bit_length() - 1
    shift = (highest_bit >> 1) + (highest_bit & 1)
    return ((n >> shift) + (1 << shift)) >> 1


def scan_run(rows):
    if not rows:
        return 0, 'empty'
    if len(rows) == 1:
        return 1, 'single'
    descending = rows[1][0] < rows[0][0]
    i = 2
    while i < len(rows):
        prev, curr = rows[i - 1][0], rows[i][0]
        if (curr >= prev) if descending else (curr < prev):
            break
        i += 1
    return i, 'strict_descending' if descending else 'nondecreasing'


def validate_sorted_rows(rows):
    for index, item in enumerate(rows):
        if len(item) != 2 or not isinstance(item[0], int) or not 0 <= item[0] <= U64_MAX:
            raise ValueError('invalid synthetic row')
        if index and rows[index - 1][0] > item[0]:
            raise ValueError('synthetic run is not sorted')


def merge_forward(left, right, *, left_wins_tie=True):
    validate_sorted_rows(left)
    validate_sorted_rows(right)
    i = j = 0
    result = []
    while i < len(left) and j < len(right):
        take_right = right[j][0] < left[i][0] or (not left_wins_tie and right[j][0] == left[i][0])
        if take_right:
            result.append(right[j]); j += 1
        else:
            result.append(left[i]); i += 1
    return result + left[i:] + right[j:]


def merge_backward(left, right):
    validate_sorted_rows(left)
    validate_sorted_rows(right)
    i, j, result = len(left) - 1, len(right) - 1, []
    while i >= 0 and j >= 0:
        if right[j][0] < left[i][0]:
            result.append(left[i]); i -= 1
        else:
            result.append(right[j]); j -= 1
    result.extend(reversed(left[:i + 1]))
    result.extend(reversed(right[:j + 1]))
    return list(reversed(result))


def reduce_last(rows):
    validate_sorted_rows(rows)
    result = []
    for row in rows:
        if result and result[-1][0] == row[0]:
            result[-1] = row
        else:
            result.append(row)
    return result


def two_run_example(c):
    count = c['stack_threshold'] - 1
    if count != 64 or count % 2:
        raise ValueError('example requires the observed 64-entry stack case')
    half = count // 2
    left = [(i, i) for i in range(half - 1)] + [(count - 1, half - 1)]
    right = [(i, half + i) for i in range(half)]
    both = left + right
    first, direction_a = scan_run(both)
    second, direction_b = scan_run(both[first:])
    if (first, second, direction_a, direction_b) != (half, half, 'nondecreasing', 'nondecreasing'):
        raise ValueError('example does not form the selected two-run case')
    if min_run(count, c) != half or classify_buffer(count, c)['storage'] != 'stack':
        raise ValueError('example does not take the selected buffer/run cases')
    merged = merge_forward(left, right)
    if merged != merge_backward(left, right):
        raise ValueError('two merge directions disagree on synthetic rows')
    return both, merged, reduce_last(merged)


def ring_lookup_model(capacity, head, keys, key):
    """Model the selected wrapped-ring search; synthetic inputs only.

    The model requires a well-formed ring and sorted unsigned keys. Its bounded
    capacity prevents accidental huge synthetic allocations; that is not a
    target restriction. It returns (0, position) for a hit, (1, position) for
    a miss. The byte-backed branches do not validate the caller's invariants.
    """
    if not isinstance(capacity, int) or not 0 <= capacity <= 65536:
        raise ValueError('invalid synthetic capacity')
    if not isinstance(head, int) or head < 0 or (head >= capacity if capacity else head != 0):
        raise ValueError('invalid synthetic head')
    if len(keys) > capacity or not isinstance(key, int) or not 0 <= key <= U64_MAX:
        raise ValueError('invalid synthetic lookup input')
    validate_sorted_rows([(item, i) for i, item in enumerate(keys)])
    if not keys:
        return 1, 0
    physical = [None] * capacity
    for i, item in enumerate(keys):
        physical[(head + i) % capacity] = item
    first_count = min(len(keys), capacity - head)
    if len(keys) <= first_count:
        start, length, logical_base = head, first_count, 0
    else:
        boundary_key = physical[0]
        if boundary_key == key:
            return 0, first_count
        if boundary_key < key:
            start, length, logical_base = 0, len(keys) - first_count, first_count
        else:
            start, length, logical_base = head, first_count, 0
    index, remaining = 0, length
    while remaining > 1:
        half = remaining >> 1
        probe = index + half
        if physical[start + probe] <= key:
            index = probe
        remaining -= half
    value = physical[start + index]
    if value == key:
        return 0, logical_base + index
    return 1, logical_base + index + int(value < key)


def ring_decision(found_tag, count, c):
    if found_tag not in (0, 1) or not 0 <= count <= U64_MAX:
        raise ValueError('invalid synthetic decision')
    if found_tag == 0:
        return 'replace'
    return 'convert' if count >= c['ring_conversion_count'] else 'insert'


def run_power(n, start, previous_length, current_length, c):
    """Selected nonzero-XOR case from the run scheduler's integer operands."""
    if (n < 2 or not 0 <= start < n or not 0 <= previous_length <= start
            or not 0 < current_length <= n - start):
        raise ValueError('invalid synthetic run')
    scale = (c['run_power_scale'] + n - 1) // n
    a = ((2 * start - previous_length) * scale) & U64_MAX
    b = ((2 * start + current_length) * scale) & U64_MAX
    mixed = a ^ b
    if not mixed:
        raise ValueError('zero XOR is outside this selected model')
    return 64 - mixed.bit_length()


def example_path(c):
    count = c['stack_threshold'] - 1
    half = count // 2
    p0 = run_power(count, 0, 0, half, c)
    p1 = run_power(count, half, half, half, c)
    if (p0, p1) != (2, 1):
        raise ValueError('unexpected example scheduling powers')
    return [
        ['assumed_prior_conversion', hex(0x4dd0191), count, '', '', '', 'assumed_absent_and_full'],
        ['stack_adapter', hex(0x4f40597), count, '', '', count, 'stack'],
        ['first_run', hex(0x4f73e69), count, 0, half, p0, 'nondecreasing'],
        ['second_run', hex(0x4f73e69), count, half, half, p1, 'nondecreasing'],
        ['merge_trigger', hex(0x4f7402c), count, half, half, 0, 'merge_runs'],
        ['merge_direction', hex(0x4f74196), count, half, half, half, 'forward_left_scratch'],
        ['merge_equal', hex(0x4f7422b), count, half, half, '', 'left_first'],
        ['context_reduce', hex(0x4d5fa76), count, half, half, '', 'last_per_key'],
    ]


def check_historical(data):
    """Optional, independent #94 control; it never supplies #115 bytes or output."""
    require_digest(data, HISTORICAL_SHA256)
    secs = sections(data)
    selected = {0x56dfbf8: (8, 0, 0x1dd8eb, ''),
                0x57755a8: (8, 0, 0x3273810, '')}
    rows = parse_relocations(data, secs, selected)
    loc = location(data, secs, rows, 0x56dfbf8, 107, 37, b'l1/src/abci/state.rs')
    if loc['path_length'] != 49:
        raise ValueError('historical Location length mismatch')
    check_window(data, secs, 0x3272785, 'ff151d2e5002')
    check_window(data, secs, 0x3273856, '488d0d9bc34602')
    check_window(data, secs, 0x3273871, '4983fd027541')
    if decode_transfer(data, secs, 0x3272785, 'ff15')[0] != 0x57755a8:
        raise ValueError('historical slot reference mismatch')
    if decode_transfer(data, secs, 0x3273856, '488d0d')[0] != 0x56dfbf8:
        raise ValueError('historical Location reference mismatch')
    _, entries = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {r['start']: r for r in fdes}
    by_index = {r['start']: r for r in entries}
    for start in (0x32725d0, 0x3273810):
        if start not in by_start or start not in by_index or by_start[start]['fde'] != by_index[start]['fde']:
            raise ValueError('historical FDE/header mismatch')
    if by_start[0x3273810]['end'] != 0x327396c:
        raise ValueError('historical FDE end mismatch')


def as_tsv(headers, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def produce(data):
    require_digest(data)
    secs = sections(data)
    check_windows(data, secs)
    rels = parse_relocations(data, secs, RELOCATIONS)
    loc = location(data, secs, rels, 0x64767a8, 123, 37, b'l1/src/abci/state.rs')
    if loc['path_length'] != 20:
        raise ValueError('target Location length mismatch')
    funcs = checked_fdes(data, secs)
    transfers = check_transfers(data, secs)
    c = constants(data, secs)
    input_rows, merged, reduced = two_run_example(c)
    stack_limit = c['stack_threshold'] - 1
    size_limit = 2 * (c['maximum_allocation_bytes'] >> c['row_shift'])
    candidate_counts = sorted({0, 1, c['context_sort_threshold'] - 1,
        c['context_sort_threshold'], c['partition_small_threshold'] - 1,
        c['partition_small_threshold'], stack_limit - 1, stack_limit,
        stack_limit + 1, c['minrun_threshold'] - 1, c['minrun_threshold'],
        c['entry_count_cap'] - 1, c['entry_count_cap'], c['entry_count_cap'] + 1,
        2 * c['entry_count_cap'], 2 * c['entry_count_cap'] + 1,
        size_limit - 1, size_limit, size_limit + 1, U64_MAX})
    buffer_rows = []
    for n in candidate_counts:
        r = classify_buffer(n, c)
        buffer_rows.append([n, r['computed'], r['storage'], r['scratch_elements'],
            '' if r['bytes_wrapped'] is None else r['bytes_wrapped'],
            int(r['small_mode']), int(r['size_error']),
            '' if min_run(n, c) is None else min_run(n, c)])

    outputs = {}
    outputs['functions.tsv'] = as_tsv(
        ['role', 'start_va', 'end_va_exclusive', 'file_offset', 'length', 'fde_va',
         'cie_va', 'lsda_va', 'unwind_index', 'body_sha256', 'body_hex'],
        [[r['role'], hex(r['start']), hex(r['end']), hex(r['offset']), r['size'],
          hex(r['fde']), hex(r['cie']), '' if r['lsda'] is None else hex(r['lsda']),
          r['index'], r['sha256'], r['raw_hex']] for r in funcs])
    outputs['windows.tsv'] = as_tsv(
        ['ownership', 'role', 'va', 'file_offset', 'length', 'raw_hex'],
        [['context' if role.startswith('context_') else 'new', role, hex(va),
          hex(mapped_offset(data, secs, va, len(bytes.fromhex(raw)))), len(bytes.fromhex(raw)),
          read_va(data, secs, va, len(bytes.fromhex(raw))).hex()]
         for role, va, raw in WINDOWS])
    outputs['transfers.tsv'] = as_tsv(
        ['ownership', 'role', 'va', 'file_offset', 'opcode', 'raw_hex', 'target_kind', 'target_va'],
        [['context' if r['role'].startswith('context_') else 'new', r['role'], hex(r['va']),
          hex(r['offset']), r['opcode'], r['raw'], r['kind'], hex(r['target'])]
         for r in transfers])
    outputs['relocations.tsv'] = as_tsv(
        ['slot_va', 'rela_file_offset', 'type', 'symbol_index', 'symbol', 'addend', 'rela_raw_hex'],
        [[hex(r['slot']), hex(r['file_offset']), r['type'], r['symbol_index'], r['symbol'],
          hex(r['addend']), r['raw']] for r in rels])
    outputs['buffer-cases.tsv'] = as_tsv(
        ['synthetic_n', 'computed_elements', 'selected_storage', 'scratch_elements',
         'wrapped_heap_bytes', 'small_mode', 'size_error', 'min_run'], buffer_rows)
    outputs['synthetic-input.tsv'] = as_tsv(
        ['position', 'key_u64', 'identity'], [[i, k, ident] for i, (k, ident) in enumerate(input_rows)])
    outputs['synthetic-merged.tsv'] = as_tsv(
        ['position', 'key_u64', 'identity'], [[i, k, ident] for i, (k, ident) in enumerate(merged)])
    outputs['synthetic-survivors.tsv'] = as_tsv(
        ['position', 'key_u64', 'identity'], [[i, k, ident] for i, (k, ident) in enumerate(reduced)])
    outputs['synthetic-path.tsv'] = as_tsv(
        ['synthetic_event', 'instruction_va', 'row_count', 'start', 'run_length', 'value', 'decision'],
        example_path(c))
    lookup_cases = []
    for capacity in (1, 4, 7, c['ring_conversion_count']):
        for head in sorted({0, capacity - 1}):
            for count in sorted({0, capacity // 2, capacity}):
                keys = [2 * i for i in range(count)]
                for query in sorted({0, 1, max(0, 2 * count - 2), max(0, 2 * count - 1), 2 * count}):
                    tag, index = ring_lookup_model(capacity, head, keys, query)
                    lookup_cases.append([capacity, head, count, query, tag, index,
                                         ring_decision(tag, count, c)])
    outputs['synthetic-lookup.tsv'] = as_tsv(
        ['capacity', 'head', 'count', 'query', 'return_tag', 'logical_index', 'context_route'], lookup_cases)
    normal_count = c['ring_conversion_count']
    normal_keys = list(range(normal_count))
    normal_head = normal_count - 1
    miss_tag, miss_index = ring_lookup_model(normal_count, normal_head, normal_keys, normal_count)
    hit_tag, hit_index = ring_lookup_model(normal_count, normal_head, normal_keys, normal_count - 1)
    normal_run = scan_run([(key, key) for key in normal_keys])
    if (miss_tag, miss_index, hit_tag, hit_index, normal_run) != (1, normal_count, 0, normal_count - 1,
                                                                  (normal_count, 'nondecreasing')):
        raise ValueError('unexpected sorted-ring example')
    outputs['synthetic-sorted64.tsv'] = as_tsv(
        ['position', 'key_u64', 'identity'], [[i, key, key] for i, key in enumerate(normal_keys)])
    outputs['synthetic-fast-path.tsv'] = as_tsv(
        ['event', 'instruction_va', 'input_count', 'observed_or_model_value', 'decision'], [
            ['lookup_existing', hex(0x57f8d5f), normal_count, hit_index, ring_decision(hit_tag, normal_count, c)],
            ['lookup_absent', hex(0x4dd0191), normal_count, miss_index, ring_decision(miss_tag, normal_count, c)],
            ['buffer', hex(0x4f40597), normal_count, classify_buffer(normal_count, c)['scratch_elements'], 'stack'],
            ['scan', hex(0x4f73e69), normal_count, normal_run[0], normal_run[1]],
            ['remaining_runs', hex(0x4f73d84), normal_count, 1, 'single_run'],
            ['finish', hex(0x4f742a5), normal_count, 2 * normal_run[0] + 1, 'return'],
        ])
    compare_cases = []
    for current, query in ((0, 1), (1, 1), (2, 1)):
        carry = int(current < query)
        above = int(current > query)
        order_byte = (above - carry) & 0xff
        route = 'wrapped_search' if order_byte == 0xff else ('equal' if order_byte == 0 else 'initial_search')
        compare_cases.append([current, query, carry, above, hex(order_byte), route])
    outputs['synthetic-compare.tsv'] = as_tsv(
        ['current_key', 'query', 'carry', 'set_above', 'result_byte', 'wrapped_split_decision'], compare_cases)
    threshold_cases = [[count, tag, ring_decision(tag, count, c)]
                       for count in (c['ring_conversion_count'] - 1, c['ring_conversion_count'],
                                     c['ring_conversion_count'] + 1) for tag in (0, 1)]
    outputs['synthetic-threshold.tsv'] = as_tsv(
        ['count', 'lookup_tag', 'context_decision'], threshold_cases)
    merge_cases = []
    for left_key, right_key in ((0, 1), (1, 1), (1, 0)):
        left, right = [(left_key, 'L')], [(right_key, 'R')]
        order = merge_forward(left, right)
        if order != merge_backward(left, right):
            raise ValueError('synthetic forward/backward comparison disagreement')
        merge_cases.append([left_key, right_key, order[0][1], order[-1][1]])
    outputs['synthetic-merge-truth.tsv'] = as_tsv(
        ['left_key', 'right_key', 'forward_first', 'backward_last'], merge_cases)
    summary = {'target_release': 115, 'target_sha256': TARGET_SHA256,
               'address_coordinates': 'linked ELF virtual address before rebasing',
               'source_location_context': loc, 'decoded_constants': c,
               'counts': {'selected_fdes': len(funcs), 'all_windows': len(WINDOWS),
                          'context_windows': sum(role.startswith('context_') for role, _, _ in WINDOWS),
                          'selected_transfers': len(transfers), 'selected_relocations': len(rels),
                          'buffer_cases_synthetic': len(buffer_rows),
                          'lookup_cases_synthetic': len(lookup_cases),
                          'comparison_cases_synthetic': len(compare_cases),
                          'threshold_cases_synthetic': len(threshold_cases),
                          'merge_truth_cases_synthetic': len(merge_cases),
                          'example_input_rows': len(input_rows), 'example_merged_rows': len(merged),
                          'example_survivors': len(reduced)},
               'example': {'kind': 'synthetic two sorted runs, not target execution',
                           'first_run_length': len(input_rows) // 2,
                           'second_run_length': len(input_rows) // 2,
                           'duplicate_keys': len(merged) - len(reduced)},
               'sorted_ring_example': {'capacity': normal_count, 'head': normal_head,
                                       'run_length': normal_run[0], 'absent_key': normal_count,
                                       'absent_return': [miss_tag, miss_index],
                                       'present_key': normal_count - 1,
                                       'present_return': [hit_tag, hit_index]},
               'scope': 'Selected static evidence only; FDE extents are not whole-function coverage.'}
    outputs['facts.json'] = (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode('utf-8')
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical-node', type=Path,
                        help='optionally verify the independently authenticated historical artifact')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    require_digest(data)
    if args.historical_node is not None:
        check_historical(args.historical_node.read_bytes())
    outputs = produce(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(outputs.items()):
        (args.out / name).write_bytes(content)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_result_sort115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
