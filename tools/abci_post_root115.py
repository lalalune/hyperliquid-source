#!/usr/bin/env python3
"""Extract one node-115 ABCI post-block result path from authenticated ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK = (1 << 64) - 1
SENTINEL = 1 << 63

# New selected unwind ranges only. Existing loader, block, selector, queue and
# owner bodies are contextual dependencies, not selected ownership claims.
FDE_PINS = (
    ('restart_owner_builder', 0x2504590, 0x2504aee, 'a3398cb925324e40935450bc14e8129015a6e3ae41cf049b648b854d0019dcfa'),
    ('compact_capture', 0x4e35e90, 0x4e3613e, '305c1914fd9a4af399a613aead96090d890e6e0fb9a1bfb6911f619047960302'),
    ('root_aux_update', 0x4e3a7a0, 0x4e3a97d, 'b4394a45fca195eeb2ee382a3480419031ce99f202d486c52e5cfd7f554cd077'),
    ('restart_instrument', 0x4e45700, 0x4e45a22, 'efa53d7bb44e7d941d5f8a05031939ed2362ab09789b9099dd48f8d74993d18a'),
    ('compact_capture_dispatch', 0x4e49960, 0x4e49b7a, '935f553b8b700d581dc9a9bf52915d70b6772b987e957545d983d985224ef8da'),
    ('compact_state_encoder', 0x4e4af80, 0x4e4b3ee, '5e41d695178d7829e82accc10e55dde1b4a1e67a9539e847c0daf96568f7f484'),
    ('restart_dispatch', 0x4f2a840, 0x4f2b1a2, '2c0bd9bba804d6fa270769bcfc716ea8bc50f2dd2f78df40a74abe9e3ca0ec9d'),
    ('restart_guard', 0x4fc99a0, 0x4fca1bb, 'b0417d24e9b6cc35b19a9c1f6a37a300fc234ad840e6f523da1d3bb722cb20ff'),
    ('compact_snapshot_wrapper', 0x5485a60, 0x5485f7f, '8b5974d4336d50147887c07620e07cfe5cabfaddc1663871fddb201df854b147'),
    ('compact_root_bridge', 0x548dad0, 0x548dcd3, 'fc4926a17e2fb4e56d5a62e0fc1a01a8229a053816966a1aaadc75a3ff9e0dfa'),
    ('restart_wrapper', 0x5647da0, 0x56483fe, '47f8ab1733256c5e785ba87dc4c31eded7b0cfaeb67234ccc35b1efe93c63216'),
    ('restart_compare', 0x59ed8f0, 0x59edc46, 'dd2a2e707655f07a1a07f09992a257e3e52e95721b91485a13b782b265fae2be'),
    ('post_result_builder', 0x5a6d390, 0x5a6d75a, 'f4487a162e5fd9970aa8f545e7f821405f9bbbe58b59926d225993f391e3cfe1'),
    ('restart_fallback', 0x5a6d760, 0x5a6db2a, '063347d2884183bee4e270a999fad472070b3758aee88724b143de10d7e15997'),
    ('post_result_gate', 0x5a6db30, 0x5a6dd2f, '53cffc0c18ba7c8d4cee0eb10d44b5d53129f3d34176e0454d7fa0d3d3a1f97c'),
)

# Pin bounded windows in already researched FDEs solely for the inter-packet
# joins. These are not additional owned function bodies.
CONTEXT_PINS = (
    ('parent_source_and_new_owner', 0x2cb8582, 0x2cb869b, 'c53f24366278fceae0ca049e9bbebb92baba8fb827b9d5d8c22185915387832f'),
    ('callback_task_save', 0x5a34440, 0x5a3445e, '98162d1a21ace1a93c7272c1ce73bb0497181a7b45e2b095fd938cad28b0f729'),
    ('initial_queue_handoff', 0x5a34512, 0x5a345a1, '78769e1cdc78255022781de4cf538589120629def8171cc7c36137cc00c4d04f'),
    ('callback_task_reload', 0x5a34e1d, 0x5a34e4e, 'd477a6d0b5b7e1397b3cba9e09b9d0e2969778d10d1992f7f3e49312b6e33482'),
    ('callback_apply_arguments', 0x5a34e4e, 0x5a34f12, '1562c0d7e996e90a8939a88f7202d88760165fb1fadb268ce67fdf0b78075e9e'),
    ('forwarded_apply_arguments', 0x4e479ff, 0x4e47a81, '5d8f8704b00305789176a58926515e421808509ddd1ed54e7503410f0079adaa'),
    ('apply_bridge_input', 0x4fcade0, 0x4fcae4d, 'f816e1efef44ed070b69711d213ff1956286c8be37fee0cd4db05cade9f51ef4'),
    ('bridge_context_entry', 0x59ec241, 0x59ec2ad, 'f0a3ed15d40aadae7c9f51f1ce4f278c671e00bdd78a0ea34cb84534a3724248'),
    ('bridge_post_gate', 0x59ec7fe, 0x59ec82a, 'cf6b2b42aff43448d4768f8050f9399ce9ef2b25a5dda07ec11f4993acc88eb8'),
    ('bridge_pending_store', 0x59ecb67, 0x59ecbf2, '2b46a996d48b37074b099996f77bc0d96820c990af72abba13dbd5458faa25e6'),
    ('bridge_pending_loop_setup', 0x59ecc22, 0x59eccab, '18a3e3d0b87d07e53474363df3036ee048e632077c436a31d5e4f3078b8d5db6'),
    ('bridge_pending_match', 0x59eccab, 0x59ecd86, 'a0558292803af27fdc40ff8bdbc38857aa45df7f840a407e9b1385054dbeb437'),
    ('bridge_pending_to_builder', 0x59ecd86, 0x59ecded, 'cf89ee8834d00d9719cddb53470bf0272d6798c41f796ff304cf416d4eb8080b'),
    ('bridge_builder_and_return', 0x59ecded, 0x59ece50, '3424f8eeed74267a55119605ab4bb83232cd012d5943aff78f644b469e8bab44'),
    ('bridge_output', 0x59ecfdd, 0x59ecffe, '6fb2d88bd4952637fcc7f4ed65b3d0551844c11eab27200f1a9694c4df046b90'),
    ('end_selected_hash', 0x5a07ec0, 0x5a080be, 'd2cc10f3fecb54d2363f348713c2fcc045aca1c88af9486100d0ec27081045a9'),
    ('end_mixed_consumer', 0x5a08255, 0x5a0826c, '7710f25a5c5f4d79d3e7dbd7c9e76d7fc39422dec3e7e378200c6b0bd74129a1'),
    ('end_result_staging', 0x5a082b5, 0x5a08351, '2b535221ec0a49e82116d606963baea683d7866280465cd19808f23b1dc8b8ce'),
    ('end_result_output', 0x5a083da, 0x5a08439, '0a87a8365c0c1fe4178801617c4bfa1992388e6c7e1f0ef1a98e77c85bbb08db'),
    ('engine_end_and_copy', 0x5a05fc1, 0x5a060da, '8f47e56bd8cd33a2e7055d4cd894391ca42459f7a5a125f1d270f12786ac18c9'),
    ('callback_apply_result', 0x5a34f12, 0x5a34fb8, '6ec16cbfc5bc1a7de8cc3489a1de51574eb174ff718b2edd1fb815a8d7b3e41b'),
    ('old_owner_write', 0x4fcc078, 0x4fcc0a9, 'e7338aeb8def16b15ef7b056711b1f68e7e25a0490c73d665980b440ee9106cb'),
)

# Each row pins label, instruction VA, type, target, and the full instruction bytes.
# Targets are linked ELF virtual addresses, not rebased runtime addresses.
TRANSFER_PINS = (
    ('parent_restart_fallback', 0x2cb85d3, 'slot_call', 0x64e7450, 'ff1577ee8203'),
    ('parent_new_owner_builder', 0x2cb8625, 'call', 0x2504590, 'e866bf84ff'),
    ('initial_queue', 0x5a3459c, 'call', 0x581a4f0, 'e84f5fdeff'),
    ('selected_begin', 0x5a04fe9, 'call', 0x5483850, 'e862e8a7ff'),
    ('selected_end', 0x5a05fc9, 'call', 0x5a07ec0, 'e8f21e0000'),
    ('selected_hash', 0x5a07fce, 'call', 0x548dad0, 'e8fd5aa8ff'),
    ('selected_raw_consumer', 0x5a07fe5, 'call', 0x5a03fa0, 'e8b6bfffff'),
    ('selected_snapshot', 0x5a0801e, 'call', 0x5485a60, 'e83ddaa7ff'),
    ('selected_mix', 0x5a080b9, 'call', 0x452aab0, 'e8f229b2fe'),
    ('selected_mix_consumer', 0x5a08267, 'call', 0x5a046f0, 'e884c4ffff'),
    ('bridge_post_gate', 0x59ec817, 'call', 0x5a6db30, 'e814130800'),
    ('builder_invocation', 0x59ece1c, 'call', 0x5a6d390, 'e86f050800'),
    ('callback_apply', 0x5a34f0d, 'call', 0x4e47900, 'e8ee2941ff'),
    ('callback_skip_write', 0x5a34f24, 'branch', 0x5a34fb8, '0f848e000000'),
    ('callback_write', 0x5a34fb3, 'call', 0x4f18bd0, 'e8183c4eff'),
    ('end_root_capture', 0x548db0f, 'call', 0x4e46090, 'e87c859bff'),
    ('end_root_format', 0x548db1a, 'slot_call', 0x64e7820, 'ff15009d0501'),
    ('end_root_aux_update', 0x548dbf9, 'call', 0x4e3a7a0, 'e8a2cb9aff'),
    ('aux_lookup', 0x4e3a7e0, 'slot_call', 0x64e0f80, 'ff159a676a01'),
    ('aux_existing_non_sentinel', 0x4e3a7f1, 'branch', 0x4e3a817, '7124'),
    ('aux_result_sentinel_on_skip', 0x4e3a7f6, 'branch', 0x4e3a937, '0f843b010000'),
    ('aux_result_empty_on_skip', 0x4e3a7ff, 'branch', 0x4e3a937, '0f8432010000'),
    ('aux_result_sentinel_on_update', 0x4e3a81e, 'branch', 0x4e3a8bc, '0f8498000000'),
    ('aux_convert', 0x4e3a863, 'slot_call', 0x64e0020, 'ff15b7576a01'),
    ('aux_release_previous', 0x4e3a86c, 'call', 0x4e507b0, 'e83f5f0100'),
    ('aux_apply', 0x4e3a8dc, 'call', 0x50e5fc0, 'e8dfb62a00'),
    ('aux_option_off', 0x4e3a8fe, 'branch', 0x4e3a937, '7437'),
    ('aux_global_off', 0x4e3a90c, 'branch', 0x4e3a937, '7429'),
    ('aux_current_sentinel', 0x4e3a911, 'branch', 0x4e3a937, '7424'),
    ('aux_optional_first', 0x4e3a916, 'call', 0x14c3950, 'e8359068fc'),
    ('aux_optional_second', 0x4e3a91e, 'call', 0x1533e80, 'e85d956ffc'),
    ('aux_optional_empty', 0x4e3a926, 'branch', 0x4e3a937, '740f'),
    ('aux_optional_third', 0x4e3a932, 'call', 0x14c4d00, 'e8c9a368fc'),
    ('aux_unwind_resume', 0x4e3a978, 'call', 0x63f0a50, 'e8d3605b01'),
    ('snapshot_name', 0x5485ae0, 'call', 0x5942870, 'e88bcd4b00'),
    ('snapshot_dispatch', 0x5485b2b, 'call', 0x4e49960, 'e8303e9cff'),
    ('snapshot_store_failure', 0x5485b89, 'branch', 0x5485e0e, '0f857f020000'),
    ('snapshot_direct_capture', 0x4e499f9, 'call', 0x4e35e90, 'e892c4feff'),
    ('compact_state_save', 0x4e35ec9, 'slot_call', 0x64e61d0, 'ff1501036b01'),
    ('compact_encoder_call', 0x4e35f6d, 'call', 0x4e4af80, 'e80e500100'),
    ('encoder_serialize', 0x4e4b010, 'call', 0x5480950, 'e83b596300'),
    ('encoder_bad_tag', 0x4e4b02e, 'branch', 0x4e4b2f8, '0f85c4020000'),
    ('encoder_write', 0x4e4b063, 'slot_call', 0x64e09e8, 'ff157f596901'),
    ('encoder_write_failure', 0x4e4b071, 'branch', 0x4e4b28e, '0f8517020000'),
    ('gate_admissible', 0x5a6db79, 'branch', 0x5a6dbc0, '7445'),
    ('gate_sentinel_cleanup', 0x5a6db8b, 'branch', 0x5a6dcee, '0f845d010000'),
    ('gate_first_empty', 0x5a6db94, 'branch', 0x5a6dba2, '740c'),
    ('gate_second_empty', 0x5a6dba9, 'branch', 0x5a6dcee, '0f843f010000'),
    ('gate_discard_done', 0x5a6dbbb, 'jump', 0x5a6dcee, 'e92e010000'),
    ('gate_flag_bypass', 0x5a6dbc3, 'branch', 0x5a6dca8, '0f84df000000'),
    ('gate_tag_other', 0x5a6dbd0, 'branch', 0x5a6dbe5, '7513'),
    ('gate_freeze_past', 0x5a6dbd9, 'branch', 0x5a6dd01, '0f8222010000'),
    ('gate_freeze_equal', 0x5a6dbdf, 'branch', 0x5a6dca8, '0f84c3000000'),
    ('gate_queue_closed', 0x5a6dc22, 'branch', 0x5a6dca3, '757f'),
    ('gate_queue_counter_limit', 0x5a6dc28, 'branch', 0x5a6dcfb, '0f84cd000000'),
    ('gate_queue_retry', 0x5a6dc3b, 'branch', 0x5a6dc20, '75e3'),
    ('gate_queue_publish', 0x5a6dc49, 'call', 0x581a4f0, 'e8a2c8daff'),
    ('gate_notify_retry', 0x5a6dc70, 'branch', 0x5a6dc60, '75ee'),
    ('gate_notify_busy', 0x5a6dc75, 'branch', 0x5a6dca8, '7531'),
    ('gate_wake_absent', 0x5a6dc9c, 'branch', 0x5a6dca8, '740a'),
    ('gate_counter_failure', 0x5a6dcfb, 'slot_call', 0x64e02e8, 'ff15e725a700'),
    ('gate_assertion', 0x5a6dd14, 'slot_call', 0x64df730, 'ff15161aa700'),
    ('gate_unwind_cleanup', 0x5a6dd22, 'call', 0x5a4f110, 'e8e913feff'),
    ('builder_first_kind', 0x5a6d3e8, 'branch', 0x5a6d40f, '7125'),
    ('builder_first_empty', 0x5a6d3ef, 'branch', 0x5a6d436, '7445'),
    ('builder_first_invalid', 0x5a6d3f8, 'branch', 0x5a6d6c0, '0f84c2020000'),
    ('builder_first_slice', 0x5a6d405, 'call', 0x521b8a0, 'e896e47aff'),
    ('builder_first_alternative', 0x5a6d417, 'call', 0x58318f0, 'e8d444dcff'),
    ('builder_second_kind', 0x5a6d47c, 'branch', 0x5a6d4a2, '7524'),
    ('builder_second_empty', 0x5a6d483, 'branch', 0x5a6d4ca, '7445'),
    ('builder_second_invalid', 0x5a6d48c, 'branch', 0x5a6d6cf, '0f843d020000'),
    ('builder_second_slice', 0x5a6d49b, 'call', 0x521b8a0, 'e800e47aff'),
    ('builder_second_alternative', 0x5a6d4ab, 'call', 0x5856030, 'e8808bdeff'),
    ('builder_callback', 0x5a6d566, 'slot_call', 0x64e7370, 'ff15049ea700'),
    ('builder_callback_ready', 0x5a6d578, 'branch', 0x5a6d587, '740d'),
    ('builder_callback_cleanup', 0x5a6d582, 'call', 0x5a4b050, 'e8c9dafdff'),
    ('builder_alloc_fail', 0x5a6d668, 'branch', 0x5a6d6ae, '7444'),
    ('builder_alloc_handler', 0x5a6d6b8, 'slot_call', 0x64df490, 'ff15d21da700'),
    ('restart_decode', 0x5a6d801, 'call', 0x50db0f0, 'e8ead866ff'),
    ('restart_bad_result', 0x5a6d81f, 'branch', 0x5a6da5e, '0f8439020000'),
    ('restart_present', 0x5a6d88d, 'branch', 0x5a6d897, '7508'),
    ('restart_wrapper_call', 0x5a6d8fc, 'call', 0x5647da0, 'e89fa4bdff'),
    ('restart_alloc_fail', 0x5a6d9d7, 'branch', 0x5a6da92, '0f84b5000000'),
    ('restart_bad_diagnostic', 0x5a6da8a, 'slot_call', 0x64df6a0, 'ff15101ca700'),
    ('restart_wrap_to_instrument', 0x5647df1, 'call', 0x4e45700, 'e80ad97fff'),
    ('restart_instrument_to_dispatch', 0x4e4584f, 'call', 0x4f2a840, 'e8ec4f0e00'),
    ('restart_dispatch_direct', 0x4f2a8b8, 'call', 0x4fc99a0, 'e8e3f00900'),
    ('restart_guard_compare', 0x4fc9b21, 'call', 0x59ed8f0, 'e8ca3da200'),
    ('restart_missing_tls', 0x59ed915, 'branch', 0x59edb02, '0f84e7010000'),
    ('restart_wrong_tls', 0x59ed929, 'branch', 0x59edb2e, '0f85ff010000'),
    ('restart_recompute', 0x59ed94a, 'call', 0x5484670, 'e8216da9ff'),
    ('restart_digest_mismatch', 0x59ed9f8, 'branch', 0x59edb38, '0f853a010000'),
    ('restart_first_validation', 0x59eda66, 'slot_call', 0x64e0ad0, 'ff156430af00'),
    ('restart_first_reject', 0x59eda6e, 'branch', 0x59edbc6, '0f8452010000'),
    ('restart_second_validation', 0x59eda86, 'slot_call', 0x64e0af0, 'ff156430af00'),
    ('restart_second_reject', 0x59eda8e, 'branch', 0x59edbc6, '0f8432010000'),
    ('restart_reject_diagnostic', 0x59edbea, 'slot_call', 0x64df6a0, 'ff15b01aaf00'),
    ('owner_negative_size', 0x25045ed, 'branch', 0x25045ff, '7910'),
    ('owner_first_alloc_fail', 0x2504616, 'branch', 0x2504a3d, '0f8421040000'),
    ('owner_second_alloc_fail', 0x250464a, 'branch', 0x2504a47, '0f84f7030000'),
)

# Each operand pin includes the full fixed instruction and a byte range to
# decode as an unsigned little-endian immediate or displacement.
OPERAND_PINS = (
    ('parent_old_owner_slot', 0x2cb85b9, '488b8b40080000', 3, 4), # 0x840
    ('parent_new_owner_size', 0x2cb865d, 'bff0060000', 1, 4), # 0x6f0
    ('parent_new_owner_slot', 0x2cb868d, '4c89bbe80a0000', 3, 4), # 0xae8
    ('callback_task_save_slot', 0x5a34451, '48897c2410', 4, 1), # 0x10
    ('callback_task_initial_reload', 0x5a34512, '488b442410', 4, 1), # 0x10
    ('callback_task_queue_reload', 0x5a3454f, '488b442410', 4, 1), # 0x10
    ('callback_task_apply_reload', 0x5a34e1d, '488b5c2410', 4, 1), # 0x10
    ('callback_init_queue_slot', 0x5a3455d, '488b5828', 3, 1), # 0x28
    ('callback_apply_task_slot', 0x5a34ea4, '48895c2468', 4, 1), # 0x68
    ('callback_apply_input_base', 0x5a34f03, '488d742440', 4, 1), # 0x40
    ('callback_pending_pointer', 0x5a34ea9, '488d8c24d0010000', 4, 4), # 0x1d0
    ('callback_pending_pointer_store', 0x5a34eb1, '48894c2470', 4, 1), # 0x70
    ('wrapper_src_lane', 0x4e47a1b, '410f105620', 4, 1), # 0x20
    ('wrapper_dst_lane', 0x4e47a2a, '0f29542440', 4, 1), # 0x40
    ('wrapper_pending_src_lane', 0x4e47a20, '410f105e30', 4, 1), # 0x30
    ('wrapper_pending_dst_lane', 0x4e47a25, '0f295c2450', 4, 1), # 0x50
    ('wrapper_input_base', 0x4e47a72, '488d542420', 4, 1), # 0x20
    ('owner_src_lane', 0x4fcadf8, '66410f105620', 5, 1), # 0x20
    ('owner_dst_lane', 0x4fcae0b, '660f29942480000000', 5, 4), # 0x80
    ('owner_pending_src_lane', 0x4fcadfe, '410f105e30', 4, 1), # 0x30
    ('owner_pending_dst_lane', 0x4fcae03, '0f299c2490000000', 4, 4), # 0x90
    ('owner_bridge_base', 0x4fcae43, '488d542460', 4, 1), # 0x60
    ('bridge_task_load', 0x59ec24b, '4c8b6128', 3, 1), # 0x28
    ('bridge_pending_input', 0x59ec24f, '488b4130', 3, 1), # 0x30
    ('bridge_pending_save', 0x59ec253, '48898424c0000000', 4, 4), # 0xc0
    ('bridge_output_base', 0x59ec29b, '488dbc24c0020000', 4, 4), # 0x2c0
    ('bridge_context_slot', 0x59ec2ad, '498dad50040000', 3, 4), # 0x450
    ('bridge_gate_input', 0x59ec801, '488d942438030000', 4, 4), # 0x338
    ('bridge_pending_load', 0x59ecb67, '488b9c24c0000000', 4, 4), # 0xc0
    ('bridge_pending_loop_load', 0x59ecc4d, '4c8bac24c0000000', 4, 4), # 0xc0
    ('bridge_pending_row_stride', 0x59ecc22, '4c6bf968', 3, 1), # 0x68
    ('bridge_pending_next_row', 0x59ecc9d, '4983c668', 3, 1), # 0x68
    ('bridge_pending_row_key_disp', 0x59eccc5, '498b4e98', 3, 1), # -0x68
    ('bridge_pending_match_offset', 0x59ecd1e, '49394d38', 3, 1), # 0x38
    ('bridge_pending_base', 0x59ecc63, '4d8d6508', 3, 1), # 0x8
    ('bridge_stage_base', 0x59ecc67, '488d6c2448', 4, 1), # 0x48
    ('bridge_builder_arg', 0x59ece07, '488d742440', 4, 1), # 0x40
    ('bridge_stage_low_src', 0x59ecd3b, '410f10442450', 5, 1), # 0x50
    ('bridge_stage_low_dst', 0x59ecd41, '0f114550', 3, 1), # 0x50
    ('bridge_stage_high_src', 0x59ecd31, '410f10442460', 5, 1), # 0x60
    ('bridge_stage_high_dst', 0x59ecd37, '0f114560', 3, 1), # 0x60
    ('bridge_stage_tail_src', 0x59ecd28, '498b4c2470', 4, 1), # 0x70
    ('bridge_stage_tail_dst', 0x59ecd2d, '48894d70', 3, 1), # 0x70
    ('selector_state_pointer', 0x5a07ed7, '488bb650040000', 3, 4), # 0x450
    ('selector_height_read', 0x5a07ede, '4c8b7e28', 3, 1), # 0x28
    ('selector_aux_context', 0x5a07fbb, '498d9630030000', 3, 4), # 0x330
    ('aux_bridge_save', 0x548dae4, '4889542418', 4, 1), # 0x18
    ('aux_bridge_reload', 0x548dbf4, '488b7c2418', 4, 1), # 0x18
    ('aux_old_head', 0x4e3a7e8, '493b4648', 3, 1), # 0x48
    ('aux_old_object', 0x4e3a817, '498d5e48', 3, 1), # 0x48
    ('aux_block_last_lane', 0x4e3a876, '0f114340', 3, 1), # 0x40
    ('aux_meta_word', 0x4e3a89d, '4189ae98000000', 3, 4), # 0x98
    ('aux_flag_first', 0x4e3a8a9, '418886a8000000', 3, 4), # 0xa8
    ('aux_flag_second', 0x4e3a8b5, '418886a9000000', 3, 4), # 0xa9
    ('aux_input_word_store', 0x4e3a8e5, '418986a4000000', 3, 4), # 0xa4
    ('aux_input_qword_store', 0x4e3a8ef, '4989869c000000', 3, 4), # 0x9c
    ('aux_optional_flag', 0x4e3a8f6, '4180beaa00000000', 3, 4), # 0xaa
    ('selector_raw_output', 0x5a07fc6, '488dbc2430010000', 4, 4), # 0x130
    ('selector_raw_consumer', 0x5a07fda, '488d942430010000', 4, 4), # 0x130
    ('selector_raw_stage_source', 0x5a08331, '0f10842430010000', 4, 4), # 0x130
    ('selector_mix_output', 0x5a080a9, '488dbc2480010000', 4, 4), # 0x180
    ('selector_mix_consumer', 0x5a0825c, '488d942480010000', 4, 4), # 0x180
    ('selector_mix_stage_source', 0x5a08311, '0f10842480010000', 4, 4), # 0x180
    ('selector_copy_height_src', 0x5a08422, '0f109c24d8000000', 4, 4), # 0xd8
    ('selector_copy_height_dst', 0x5a0842a, '0f115b30', 3, 1), # 0x30
    ('selector_copy_mixed0_src', 0x5a083fe, '0f108424e8000000', 4, 4), # 0xe8
    ('selector_copy_mixed0_dst', 0x5a08406, '0f114340', 3, 1), # 0x40
    ('selector_copy_mixed1_src', 0x5a083f2, '0f108424f8000000', 4, 4), # 0xf8
    ('selector_copy_mixed1_dst', 0x5a083fa, '0f114350', 3, 1), # 0x50
    ('selector_copy_raw0_src', 0x5a083e6, '0f10842408010000', 4, 4), # 0x108
    ('selector_copy_raw0_dst', 0x5a083ee, '0f114360', 3, 1), # 0x60
    ('selector_copy_raw1_src', 0x5a083da, '0f10842418010000', 4, 4), # 0x118
    ('selector_copy_raw1_dst', 0x5a083e2, '0f114370', 3, 1), # 0x70
    ('engine_stage_base', 0x5a05fc1, '488d7c2410', 4, 1), # 0x10
    ('engine_copy_height_src', 0x5a060b6, '0f105c2440', 4, 1), # 0x40
    ('engine_copy_height_dst', 0x5a060bb, '0f1198a8000000', 3, 4), # 0xa8
    ('engine_copy_mixed0_src', 0x5a0609b, '0f10442450', 4, 1), # 0x50
    ('engine_copy_mixed0_dst', 0x5a060a0, '0f1180b8000000', 3, 4), # 0xb8
    ('engine_copy_mixed1_src', 0x5a0608f, '0f10442460', 4, 1), # 0x60
    ('engine_copy_mixed1_dst', 0x5a06094, '0f1180c8000000', 3, 4), # 0xc8
    ('engine_copy_raw0_src', 0x5a06083, '0f10442470', 4, 1), # 0x70
    ('engine_copy_raw0_dst', 0x5a06088, '0f1180d8000000', 3, 4), # 0xd8
    ('engine_copy_raw1_src', 0x5a06074, '0f10842480000000', 4, 4), # 0x80
    ('engine_copy_raw1_dst', 0x5a0607c, '0f1180e8000000', 3, 4), # 0xe8
    ('end_stage_base', 0x5a0840a, '0f108424a8000000', 4, 4), # 0xa8
    ('end_height_stage', 0x5a08309, '4c89bc24e0000000', 4, 4), # 0xe0
    ('end_mixed_stage', 0x5a08321, '0f118424e8000000', 4, 4), # 0xe8
    ('end_raw_stage', 0x5a08341, '0f11842408010000', 4, 4), # 0x108
    ('engine_end_output_offset', 0x5a060d0, '0f114078', 3, 1), # 0x78
    ('gate_height', 0x5a6db42, '488b5028', 3, 1), # 0x28
    ('gate_multiplier', 0x5a6db46, '48be917efb3a70ce88d2', 2, 8), # 0xd288ce703afb7e91
    ('gate_rotate', 0x5a6db54, '48c1ce04', 3, 1), # 0x4
    ('gate_bound', 0x5a6db58, '48bfcb10c7bab88d0600', 2, 8), # 0x68db8bac710cb
    ('gate_flag_value', 0x5a6dbc0, '803901', 2, 1), # 0x1
    ('gate_tag_offset', 0x5a6dbc9, '83b8e810000001', 2, 4), # 0x10e8
    ('gate_tag_value', 0x5a6dbc9, '83b8e810000001', 6, 1), # 0x1
    ('gate_freeze_offset', 0x5a6dbd2, '483990f0100000', 3, 4), # 0x10f0
    ('gate_mixed_second', 0x5a6dbe9, '0f104350', 3, 1), # 0x50
    ('gate_mixed_first', 0x5a6dbf2, '0f104340', 3, 1), # 0x40
    ('gate_record_height', 0x5a6dbe5, '488b4338', 3, 1), # 0x38
    ('gate_queue_slot', 0x5a6dc09, '4c8b7928', 3, 1), # 0x28
    ('gate_queue_counter', 0x5a6dc0d, '498b87c0010000', 3, 4), # 0x1c0
    ('gate_queue_step', 0x5a6dc2e, '488d4802', 3, 1), # 0x2
    ('gate_queue_body', 0x5a6dc3d, '498dbf80000000', 3, 4), # 0x80
    ('gate_queue_data', 0x5a6dc44, '488d742408', 4, 1), # 0x8
    ('builder_record_height', 0x5a6d3bc, '4c8b7e38', 3, 1), # 0x38
    ('builder_record_raw_base', 0x5a6d56c, '4d8d6660', 3, 1), # 0x60
    ('builder_raw_first_stage', 0x5a6d615, '0f11b42468010000', 4, 4), # 0x168
    ('builder_raw_second_stage', 0x5a6d61d, '0f11bc2478010000', 4, 4), # 0x178
    ('builder_staging_source', 0x5a6d63c, '488db424f0000000', 4, 4), # 0xf0
    ('builder_staging_destination', 0x5a6d637, '4c8d642450', 4, 1), # 0x50
    ('builder_staging_length', 0x5a6d644, 'ba98000000', 1, 4), # 0x98
    ('builder_heap_height_stage', 0x5a6d652, '4c89bc24e8000000', 4, 4), # 0xe8
    ('builder_heap_copy_source', 0x5a6d671, '488d742440', 4, 1), # 0x40
    ('builder_heap_copy_length', 0x5a6d676, 'bab0000000', 1, 4), # 0xb0
    ('builder_result_prefix_src', 0x5a6d66d, '4983c618', 3, 1), # 0x18
    ('builder_result_pointer', 0x5a6d695, '4c897d20', 3, 1), # 0x20
    ('restart_expected_first', 0x59ed9c5, 'f3410f6f5530', 5, 1), # 0x30
    ('restart_expected_second', 0x59ed9cb, 'f3410f6f5d40', 5, 1), # 0x40
    ('restart_computed_first', 0x59ed999, 'f30f6f4c2450', 5, 1), # 0x50
    ('restart_computed_second', 0x59ed98a, 'f30f6f442460', 5, 1), # 0x60
    ('restart_compare_mask', 0x59ed9f3, '3dffff0000', 1, 4), # 0xffff
    ('compact_height', 0x4e35eaf, '4c8b7e28', 3, 1), # 0x28
    ('compact_state_member', 0x4e35eb3, '4881c608110000', 3, 4), # 0x1108
    ('encoder_config', 0x4e4aff1, 'c744241800040001', 4, 4), # 0x1000400
    ('encoder_config_tail', 0x4e4aff9, 'c644241c00', 4, 1), # 0x0
    ('encoder_success_delta', 0x4e4b027, '4883c004', 3, 1), # 0x4
    ('owner_record_low', 0x250494f, '410f1187a8060000', 4, 4), # 0x6a8
    ('owner_record_mid', 0x2504947, '410f118fb8060000', 4, 4), # 0x6b8
    ('owner_record_high', 0x250493f, '410f1197c8060000', 4, 4), # 0x6c8
)



def sha256(data):
    return hashlib.sha256(data).hexdigest()


def authenticate(data, expected=TARGET_SHA256, size=TARGET_SIZE):
    if (size is not None and len(data) != size) or sha256(data) != expected:
        raise ValueError('target digest or size mismatch')


def mapping(secs, address, size):
    if not isinstance(address, int) or not isinstance(size, int) or address < 0 or size <= 0:
        raise ValueError('invalid file-backed address range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and s['size'] > 0
               and s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address range lacks a unique file-backed allocated section')
    s = matches[0]
    return s, s['offset'] + address - s['address']


def read_at(data, secs, address, size):
    _, off = mapping(secs, address, size)
    if off < 0 or off + size > len(data):
        raise ValueError('file range truncated')
    return data[off:off + size]


def unique_section(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('missing or ambiguous section: ' + name)
    return found[0]


def check_body(data, secs, label, start, end, digest):
    section, off = mapping(secs, start, end - start)
    if not section['flags'] & 4:
        raise ValueError('selected FDE is not executable: ' + label)
    raw = read_at(data, secs, start, end - start)
    if sha256(raw) != digest:
        raise ValueError('selected FDE bytes changed: ' + label)
    return section['name'], off, raw


def selected_fdes(data, secs, index, all_fdes):
    by_start = {}
    for fde in all_fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    header = {}
    for row in index:
        header.setdefault(row['start'], []).append(row)
    selected = []
    for label, start, end, digest in FDE_PINS:
        matches = by_start.get(start, [])
        if len(matches) != 1 or len(header.get(start, [])) != 1:
            raise ValueError('selected FDE missing or ambiguous: ' + label)
        f = matches[0]
        if f['end'] != end or f['fde'] != header[start][0]['fde']:
            raise ValueError('FDE and unwind index disagree: ' + label)
        overlaps = [other for other in all_fdes if other is not f and other['start'] < end and start < other['end']]
        if overlaps:
            raise ValueError('another FDE intersects selected extent: ' + label)
        section, off, raw = check_body(data, secs, label, start, end, digest)
        selected.append((label, f, header[start][0]['index'], section, off, raw))
    return selected


def decode_transfer(raw, va):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        kind = 'call' if raw[0] == 0xe8 else 'jump'
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
        kind = 'jump' if raw[0] == 0xeb else 'branch'
        disp = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        kind = 'branch'
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        kind = 'slot_call' if raw[1] == 0x15 else 'slot_jump'
        disp = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported fixed transfer instruction')
    return kind, va + len(raw) + disp


def transfer_length(kind, opcode):
    if kind in ('call', 'jump') and opcode in (0xe8, 0xe9):
        return 5
    if kind in ('branch', 'jump') and (opcode == 0xeb or 0x70 <= opcode <= 0x7f):
        return 2
    if kind in ('branch', 'slot_call', 'slot_jump') and opcode in (0x0f, 0xff):
        return 6
    raise ValueError('unexpected transfer opcode')


def checked_transfer(data, secs, label, va, kind, target, expected_hex):
    first = read_at(data, secs, va, 1)[0]
    raw = read_at(data, secs, va, transfer_length(kind, first))
    got_kind, got_target = decode_transfer(raw, va)
    if raw != bytes.fromhex(expected_hex) or (got_kind, got_target) != (kind, target):
        raise ValueError('transfer changed: ' + label)
    _, off = mapping(secs, va, len(raw))
    return (label, hex(va), hex(off), kind, hex(got_target), raw.hex())


def checked_operand(data, secs, label, va, expected, at, width):
    expected = bytes.fromhex(expected)
    if at < 0 or width <= 0 or at + width > len(expected):
        raise ValueError('invalid operand definition')
    raw = read_at(data, secs, va, len(expected))
    if raw != expected:
        raise ValueError('operand instruction changed: ' + label)
    value = int.from_bytes(raw[at:at + width], 'little')
    _, off = mapping(secs, va, len(raw))
    return (label, hex(va), hex(off), raw.hex(), at, width, hex(value))


def tsv(headers, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode('ascii')


def encode_json(obj):
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')

BOUNDARY_SLOTS = {
    0x64767a8: 0x443168,
    0x64e0020: 0x14c3b30,
    0x64e0f80: 0x1546570,
    0x64e09e8: 0x15024a0,
    0x64e0ad0: 0x1506e40,
    0x64e0af0: 0x1507680,
    0x64e61d0: 0x38c2e00,
    0x64e7370: 0x56471b0,
    0x64e7450: 0x5a6d760,
    0x64e7820: 0x41c5140,
}


def collect_relocations(data, secs, wanted):
    sec = unique_section(secs, '.rela.dyn')
    if sec['type'] != 4 or sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('malformed .rela.dyn')
    found = {slot: [] for slot in wanted}
    for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot in found:
            found[slot].append((slot, info & 0xffffffff, info >> 32, addend, pos))
    for slot, expected in wanted.items():
        rows = found[slot]
        if len(rows) != 1 or rows[0][1:4] != (8, 0, expected):
            raise ValueError('missing, duplicate, or altered relative relocation')
    return [found[slot][0] for slot in sorted(wanted)]


def location_record(data, secs, address, pointer):
    raw = read_at(data, secs, address, 24)
    length, line, column = struct.unpack_from('<QII', raw, 8)
    if not 1 <= length <= 512:
        raise ValueError('invalid Location path length')
    name = read_at(data, secs, pointer, length)
    suffix = b'l1/src/abci/state.rs'
    if not name.endswith(suffix):
        raise ValueError('unexpected Location path')
    _, offset = mapping(secs, address, 24)
    return {'address': hex(address), 'file_offset': hex(offset), 'file_length': length,
            'line': line, 'column': column, 'path_suffix': suffix.decode('ascii'),
            'pointer': hex(pointer), 'record_hex': raw.hex()}


def checked_location_reference(data, secs, va, prefix, target):
    raw = read_at(data, secs, va, 7)
    if raw[:3] != bytes.fromhex(prefix):
        raise ValueError('unexpected Location reference opcode')
    actual = va + 7 + struct.unpack_from('<i', raw, 3)[0]
    if actual != target:
        raise ValueError('Location reference target changed')
    return {'reference_va': hex(va), 'reference_hex': raw.hex(),
            'reference_target_va': hex(actual)}


def check_historical(data):
    authenticate(data, HISTORICAL_SHA256, None)
    secs = sections(data)
    slots = {0x56dfbf8: 0x1dd8eb, 0x57755a8: 0x3273810}
    collect_relocations(data, secs, slots)
    loc = location_record(data, secs, 0x56dfbf8, slots[0x56dfbf8])
    if (loc['line'], loc['column']) != (107, 37):
        raise ValueError('historical Location changed')
    reference = checked_location_reference(data, secs, 0x3273856, '488d0d', 0x56dfbf8)
    if read_at(data, secs, 0x3273871, 4) != bytes.fromhex('4983fd02'):
        raise ValueError('historical comparison changed')
    if read_at(data, secs, 0x3272785, 6) != bytes.fromhex('ff151d2e5002'):
        raise ValueError('historical call changed')
    return {'sha256': HISTORICAL_SHA256, 'location': loc,
            'reference': reference, 'comparison_va': hex(0x3273871),
            'comparison_operand': read_at(data, secs, 0x3273871, 4)[-1],
            'call_va': hex(0x3272785), 'slot': hex(0x57755a8), 'callee': hex(0x3273810)}


def parse_lsda(data, secs, fde):
    """Read the selected call-site table; action/type table meanings remain open."""
    address = fde['lsda']
    if address is None:
        return []
    sec = unique_section(secs, '.gcc_except_table')
    if sec['offset'] < 0 or sec['size'] < 0 or sec['offset'] + sec['size'] > len(data):
        raise ValueError('exception table is truncated')
    if not sec['address'] <= address < sec['address'] + sec['size']:
        raise ValueError('LSDA outside exception table')
    p = sec['offset'] + address - sec['address']
    ceiling = sec['offset'] + sec['size']
    if p + 2 > ceiling or data[p] != 0xff or data[p + 1] not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header')
    type_encoding = data[p + 1]
    p += 2
    type_base = ceiling
    if type_encoding == 0x9b:
        delta, p = uleb(data, p, ceiling)
        type_base = p + delta
    if type_base > ceiling or p >= ceiling or data[p] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    length, p = uleb(data, p + 1, ceiling)
    limit = p + length
    if limit > ceiling or limit > type_base:
        raise ValueError('LSDA call-site table exceeds bounds')
    rows = []
    while p < limit:
        first = p
        start, p = uleb(data, p, limit)
        size, p = uleb(data, p, limit)
        landing, p = uleb(data, p, limit)
        action, p = uleb(data, p, limit)
        span = fde['end'] - fde['start']
        if start + size > span or landing >= span and landing != 0:
            raise ValueError('LSDA row escapes the selected FDE')
        rows.append({'record_offset': first, 'start': fde['start'] + start,
                     'end': fde['start'] + start + size,
                     'landing': fde['start'] + landing if landing else None,
                     'action': action, 'raw': data[first:p]})
    if p != limit:
        raise ValueError('LSDA call-site table not consumed')
    return rows


def callsite_witness(rows, address, size):
    if size <= 0:
        raise ValueError('invalid call size')
    touching = [r for r in rows if address < r['end'] and r['start'] < address + size]
    complete = [r for r in touching if r['start'] <= address and address + size <= r['end']]
    if len(touching) != len(complete) or len(complete) > 1:
        raise ValueError('ambiguous or partial LSDA call-site coverage')
    return complete[0] if complete else None


def project_copy(position, source, destination, size, width):
    if min(position, source, destination) < 0 or size < 0 or width <= 0:
        raise ValueError('invalid copy geometry')
    if not source <= position or position + width > source + size:
        raise ValueError('tracked range is outside the copy')
    return destination + position - source


def build_joins(operand_rows):
    v = {r[0]: int(r[-1], 16) for r in operand_rows}
    if len(v) != len(operand_rows):
        raise ValueError('duplicate operand labels')
    task_input = v['callback_apply_task_slot'] - v['callback_apply_input_base']
    pending_input = v['callback_pending_pointer_store'] - v['callback_apply_input_base']
    task_after_wrapper = project_copy(task_input, v['wrapper_src_lane'],
                                      v['wrapper_dst_lane'] - v['wrapper_input_base'], 16, 8)
    pending_after_wrapper = project_copy(pending_input, v['wrapper_pending_src_lane'],
                                         v['wrapper_pending_dst_lane'] - v['wrapper_input_base'], 16, 8)
    pending_after_owner = project_copy(pending_after_wrapper, v['owner_pending_src_lane'],
                                       v['owner_pending_dst_lane'] - v['owner_bridge_base'], 16, 8)
    task_after_owner = project_copy(task_after_wrapper, v['owner_src_lane'],
                                    v['owner_dst_lane'] - v['owner_bridge_base'], 16, 8)
    result_from_engine = v['bridge_gate_input'] - v['bridge_output_base']
    height = v['end_height_stage'] - v['end_stage_base']
    mixed = v['end_mixed_stage'] - v['end_stage_base']
    raw = v['end_raw_stage'] - v['end_stage_base']
    copy_raw_stage = project_copy(v['builder_raw_first_stage'], v['builder_staging_source'],
                                  v['builder_staging_destination'], v['builder_staging_length'], 16)
    copy_raw_stage2 = project_copy(v['builder_raw_second_stage'], v['builder_staging_source'],
                                   v['builder_staging_destination'], v['builder_staging_length'], 16)
    heap_raw = project_copy(copy_raw_stage, v['builder_heap_copy_source'], 0,
                            v['builder_heap_copy_length'], 16)
    heap_raw2 = project_copy(copy_raw_stage2, v['builder_heap_copy_source'], 0,
                             v['builder_heap_copy_length'], 16)
    heap_height = project_copy(v['builder_heap_height_stage'], v['builder_heap_copy_source'], 0,
                               v['builder_heap_copy_length'], 8)
    owner_record = v['owner_record_low'] + 8
    inverse = pow(v['gate_multiplier'], -1, 1 << 64)
    period = inverse << v['gate_rotate']
    conditions = [
        v['callback_task_save_slot'] == v['callback_task_initial_reload'] ==
            v['callback_task_queue_reload'] == v['callback_task_apply_reload'],
        v['aux_bridge_save'] == v['aux_bridge_reload'],
        v['aux_old_head'] == v['aux_old_object'],
        v['aux_old_object'] + v['aux_block_last_lane'] + 16 == v['aux_meta_word'],
        v['aux_flag_second'] == v['aux_flag_first'] + 1,
        v['aux_optional_flag'] == v['aux_flag_second'] + 1,
        v['aux_input_word_store'] == v['aux_input_qword_store'] + 8,
        v['bridge_context_slot'] == v['selector_state_pointer'],
        v['selector_height_read'] == v['gate_height'],
        v['selector_raw_output'] == v['selector_raw_consumer'] == v['selector_raw_stage_source'],
        v['selector_mix_output'] == v['selector_mix_consumer'] == v['selector_mix_stage_source'],
        task_after_owner == v['bridge_task_load'],
        pending_after_owner == v['bridge_pending_input'],
        v['bridge_pending_save'] == v['bridge_pending_load'] == v['bridge_pending_loop_load'],
        v['bridge_pending_row_stride'] == v['bridge_pending_next_row'] ==
            0x100 - v['bridge_pending_row_key_disp'],
        v['bridge_pending_match_offset'] == v['gate_record_height'],
        v['bridge_pending_base'] + v['bridge_stage_low_src'] ==
            v['bridge_stage_base'] + v['bridge_stage_low_dst'] - v['bridge_builder_arg'],
        v['bridge_pending_base'] + v['bridge_stage_high_src'] ==
            v['bridge_stage_base'] + v['bridge_stage_high_dst'] - v['bridge_builder_arg'],
        v['bridge_pending_base'] + v['bridge_stage_tail_src'] ==
            v['bridge_stage_base'] + v['bridge_stage_tail_dst'] - v['bridge_builder_arg'],
        v['callback_init_queue_slot'] == v['gate_queue_slot'],
        result_from_engine == v['engine_end_output_offset'],
        height == v['gate_record_height'] == v['builder_record_height'],
        mixed == v['gate_mixed_first'] and mixed + 16 == v['gate_mixed_second'],
        raw == v['builder_record_raw_base'],
        heap_raw2 == heap_raw + 16,
        heap_height + 8 == v['builder_heap_copy_length'],
        v['owner_record_mid'] == owner_record + 8,
        v['owner_record_high'] == owner_record + 24,
        v['restart_expected_second'] == v['restart_expected_first'] + 16,
        v['restart_computed_second'] == v['restart_computed_first'] + 16,
        v['gate_rotate'] == 4,
        period == 10000,
        v['gate_bound'] == MASK // period,
    ]
    tracked = [('height', height, 8), ('mixed0', mixed, 16), ('mixed1', mixed + 16, 16),
               ('raw0', raw, 16), ('raw1', raw + 16, 16)]
    for label, position, width in tracked:
        conditions.append(project_copy(v['end_stage_base'] + position,
                                       v['selector_copy_' + label + '_src'],
                                       v['selector_copy_' + label + '_dst'], 16, width) == position)
        conditions.append(project_copy(v['engine_stage_base'] + position,
                                       v['engine_copy_' + label + '_src'],
                                       v['engine_copy_' + label + '_dst'], 16, width) ==
                          v['engine_end_output_offset'] + position)
    if not all(conditions):
        raise ValueError('selected operand projections do not join')
    return {
        'task_capture': {'saved_task_stack_offset': hex(v['callback_task_save_slot']),
                         'input_offset': hex(task_input), 'after_wrapper': hex(task_after_wrapper),
                         'bridge_input_offset': hex(task_after_owner),
                         'pending_pointer_input_offset': hex(pending_input),
                         'pending_pointer_bridge_offset': hex(pending_after_owner),
                         'queue_slot_in_task': hex(v['gate_queue_slot']),
                         'queue_object_inner_offset': hex(v['gate_queue_body']),
                         'pending_row_stride': hex(v['bridge_pending_row_stride'])},
        'end_result': {'tracked_segments': len(tracked), 'verified_copy_stages': 2,
                       'selector_state_slot': hex(v['selector_state_pointer']),
                       'selector_height_read_offset': hex(v['selector_height_read']),
                       'raw_stack_buffer': hex(v['selector_raw_output']),
                       'mixed_stack_buffer': hex(v['selector_mix_output']),
                       'offset_in_engine_output': hex(result_from_engine),
                       'height_offset': hex(height), 'mixed_32_offset': hex(mixed),
                       'raw_32_offset': hex(raw)},
        'root_aux_object': {'offset_in_selector_context': hex(v['selector_aux_context']),
                            'head_and_record_offset': hex(v['aux_old_object']),
                            'record_size': hex(v['aux_block_last_lane'] + 16),
                            'metadata_word_offset': hex(v['aux_meta_word']),
                            'input_qword_offset': hex(v['aux_input_qword_store']),
                            'input_word_offset': hex(v['aux_input_word_store']),
                            'flag_offsets': [hex(v['aux_flag_first']), hex(v['aux_flag_second'])]},
        'builder_heap': {'size': hex(v['builder_heap_copy_length']),
                         'raw_32_offset': hex(heap_raw), 'height_offset': hex(heap_height),
                         'prefix_source_offset': hex(v['builder_result_prefix_src']),
                         'pointer_offset_in_result': hex(v['builder_result_pointer']),
                         'output_record_offset_in_owner': hex(owner_record)},
        'restart_comparison': {'saved_32_offset': hex(v['restart_expected_first']),
                               'computed_32_offset': hex(v['restart_computed_first'] - 0x10),
                               'mask': hex(v['restart_compare_mask'])},
        'compact_serialization': {'height_offset': hex(v['compact_height']),
                                  'member_offset': hex(v['compact_state_member']),
                                  'serializer_config_little_endian_hex':
                                      v['encoder_config'].to_bytes(4, 'little').hex() +
                                      v['encoder_config_tail'].to_bytes(1, 'little').hex(),
                                  'success_sentinel': hex(SENTINEL + v['encoder_success_delta'])},
        'gate': {'height_offset': hex(v['gate_height']), 'tag_offset': hex(v['gate_tag_offset']),
                 'target_offset': hex(v['gate_freeze_offset']), 'flag_value': v['gate_flag_value'],
                 'tag_value': v['gate_tag_value'], 'multiplier': hex(v['gate_multiplier']),
                 'rotate': v['gate_rotate'], 'bound': hex(v['gate_bound']),
                 'inverse_mod_2_64': inverse, 'period': period,
                 'queue_counter_offset': hex(v['gate_queue_counter']),
                 'queue_counter_step': v['gate_queue_step']},
    }


def checked_aux_replay(data, secs):
    starts = (0x4e3a871, 0x4e3a949)
    length = 0x4e3a89d - starts[0]
    raw = [read_at(data, secs, address, length) for address in starts]
    if raw[0] != raw[1]:
        raise ValueError('auxiliary record stores differ on selected unwind path')
    return [(label, hex(address), hex(mapping(secs, address, length)[1]), raw[i].hex())
            for i, (label, address) in enumerate(zip(('normal', 'unwind'), starts))]


def gate_model(height, head, flag, tag, target, queue_word):
    """Synthetic selected machine-branch model; no target code is run."""
    numbers = (height, head, target, queue_word)
    if any(type(x) is not int or not 0 <= x <= MASK for x in numbers):
        raise ValueError('expected unsigned 64-bit value')
    if type(flag) is not int or not 0 <= flag <= 255 or type(tag) is not int or not 0 <= tag <= 0xffffffff:
        raise ValueError('invalid flag or tag')
    product = (height * 0xd288ce703afb7e91) & MASK
    rotated = ((product >> 4) | (product << 60)) & MASK
    if rotated > 0x68db8bac710cb or head == SENTINEL:
        return 'sentinel'
    if flag == 1:
        return 'copy_without_queue'
    if tag == 1:
        if target < height:
            return 'assertion'
        if target == height:
            return 'copy_without_queue'
    if queue_word & 1:
        return 'copy_closed_queue'
    if queue_word == MASK - 1:
        return 'counter_failure'
    return 'enqueue_then_copy'


def equal_saved_digest(saved, computed):
    if len(saved) != 32 or len(computed) != 32:
        raise ValueError('expected two 32-byte values')
    return all(a == b for a, b in zip(saved, computed))


def check_window(data, secs, label, start, end, expected):
    raw = read_at(data, secs, start, end - start)
    if sha256(raw) != expected:
        raise ValueError('context window changed: ' + label)
    section, off = mapping(secs, start, end - start)
    if not section['flags'] & 4:
        raise ValueError('context window is not executable')
    return (label, hex(start), hex(end), hex(off), raw.hex(), expected)


def checked_context(data, secs):
    return [check_window(data, secs, *pin) for pin in CONTEXT_PINS]


def generate(data):
    authenticate(data)
    secs, index = unwind_index(data)
    _, all_fdes = eh_frame_records(data, secs)
    selected = selected_fdes(data, secs, index, all_fdes)
    function_rows = [(label, hex(f['start']), hex(f['end']), hex(f['fde']), hex(f['cie']),
                      '' if f['lsda'] is None else hex(f['lsda']), str(i), name, hex(off),
                      str(len(raw)), sha256(raw), raw.hex())
                     for label, f, i, name, off, raw in selected]
    context_rows = checked_context(data, secs)
    transfer_rows = [checked_transfer(data, secs, *pin) for pin in TRANSFER_PINS]
    operand_rows = [checked_operand(data, secs, *pin) for pin in OPERAND_PINS]
    joins = build_joins(operand_rows)
    aux_replay = checked_aux_replay(data, secs)
    relas = collect_relocations(data, secs, BOUNDARY_SLOTS)
    relocation_rows = []
    for slot, typ, sym, addend, offset in relas:
        _, slot_offset = mapping(secs, slot, 8)
        slot_bytes = read_at(data, secs, slot, 8)
        relocation_rows.append((hex(slot), typ, sym, hex(addend), hex(offset),
                                data[offset:offset + 24].hex(), hex(slot_offset), slot_bytes.hex()))
    location = location_record(data, secs, 0x64767a8, BOUNDARY_SLOTS[0x64767a8])
    if (location['line'], location['column']) != (123, 37):
        raise ValueError('node-115 Location changed')
    comparison = read_at(data, secs, 0x3c1353b, 4)
    if comparison != bytes.fromhex('4883f801'):
        raise ValueError('node-115 comparison changed')
    location.update(checked_location_reference(data, secs, 0x3c1352f, '488d15', 0x64767a8))
    location.update({'sha256': TARGET_SHA256, 'comparison_va': hex(0x3c1353b),
                     'comparison_hex': comparison.hex(), 'comparison_operand': comparison[-1]})

    unwinds = {}
    unwind_rows = []
    for label, fde, _, _, _, _ in selected:
        entries = parse_lsda(data, secs, fde)
        unwinds[label] = entries
        for entry in entries:
            unwind_rows.append((label, hex(fde['start']), hex(fde['lsda']),
                                hex(entry['record_offset']), hex(entry['start']), hex(entry['end']),
                                '' if entry['landing'] is None else hex(entry['landing']),
                                entry['action'], entry['raw'].hex()))
    link_rows = []
    for row in transfer_rows:
        label, site_hex, _, kind, target_hex, raw_hex = row
        if kind not in ('call', 'slot_call'):
            continue
        site, size = int(site_hex, 16), len(bytes.fromhex(raw_hex))
        owners = [(name, fde) for name, fde, _, _, _, _ in selected if fde['start'] <= site < fde['end']]
        if len(owners) > 1:
            raise ValueError('call overlaps selected FDEs')
        if not owners:
            continue
        name, _ = owners[0]
        witness = callsite_witness(unwinds[name], site, size)
        link_rows.append((label, name, site_hex, target_hex,
                          'no_entry' if witness is None else 'covered',
                          '' if witness is None or witness['landing'] is None else hex(witness['landing']),
                          '' if witness is None else str(witness['action'])))
    summary = {'target_sha256': TARGET_SHA256, 'selected_fdes': len(selected),
               'context_windows': len(context_rows), 'transfers': len(transfer_rows),
               'decoded_operands': len(operand_rows), 'boundary_relocations': len(relocation_rows),
               'lsda_callsite_rows': len(unwind_rows), 'callsite_witnesses': len(link_rows),
               'scope': 'selected static evidence; no whole-node coverage denominator'}
    return {
        'aux-replay.tsv': tsv(('path', 'start_va', 'file_offset', 'bytes'), aux_replay),
        'functions.tsv': tsv(('label', 'start_va', 'end_va', 'fde_va', 'cie_va', 'lsda_va',
                              'unwind_index', 'section', 'file_offset', 'size', 'sha256', 'body_hex'), function_rows),
        'context.tsv': tsv(('label', 'start_va', 'end_va', 'file_offset', 'bytes', 'sha256'), context_rows),
        'transfers.tsv': tsv(('label', 'va', 'file_offset', 'kind', 'target_or_slot_va', 'bytes'), transfer_rows),
        'operands.tsv': tsv(('label', 'va', 'file_offset', 'instruction', 'operand_offset', 'width', 'value'), operand_rows),
        'boundary-relocations.tsv': tsv(('slot_va', 'type', 'symbol', 'addend_va', 'record_file_offset',
                                         'record_hex', 'slot_file_offset', 'slot_file_bytes'), relocation_rows),
        'unwind.tsv': tsv(('label', 'fde_start', 'lsda_va', 'record_file_offset', 'start_va', 'end_va',
                           'landing_va', 'action', 'raw'), unwind_rows),
        'unwind-links.tsv': tsv(('label', 'fde_label', 'call_va', 'target_or_slot_va', 'status',
                                 'landing_va', 'action'), link_rows),
        'location.json': encode_json(location),
        'joins.json': encode_json(joins),
        'summary.json': encode_json(summary),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--historical', type=Path, help='optional separately authenticated node-94 comparison')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    evidence = generate(data)
    if args.historical is not None:
        historical = check_historical(args.historical.read_bytes())
        print(json.dumps(historical, sort_keys=True))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, contents in sorted(evidence.items()):
        (args.out / name).write_bytes(contents)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('abci_post_root115:', exc, file=sys.stderr)
        raise SystemExit(1)
