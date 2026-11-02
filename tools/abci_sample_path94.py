#!/usr/bin/env python3
"""Regenerate selected node-94 ABCI sample-path evidence from ELF bytes only."""
import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Starts select FDE records; they do not define function ends or a census.
FUNCTIONS = (
    ('save_spawn', 0x474ba90),
    ('thread_builder', 0x4331a70),
    ('thread_callback', 0x433a7c0),
    ('thread_drop', 0x4341050),
    ('sample_guard', 0x4523150),
    ('tls_null_adapter', 0x46a90f0),
    ('tls_other_adapter', 0x46b9df0),
    ('tls_null_callback', 0x47a6af0),
    ('tls_other_callback', 0x47a5fa0),
    ('callback_queue_push', 0x4e19c40),
    ('callback_queue_pop', 0x4e19e50),
    ('callback_queue_run', 0x4e15970),
    ('callback_notify', 0x47799c0),
    ('line_writer', 0x45b5910),
    ('sample_writer', 0x48fe6b0),
    ('lag_field_adapter', 0x4972060),
    ('lag_field_writer', 0x4a7c270),
    ('integer_field_writer', 0x4a87800),
    ('decimal_formatter', 0x4a10c80),
    ('time_field_writer', 0x4a8f530),
    ('freeze_field_writer', 0x4a9b850),
    ('string_writer', 0x4ad4100),
)

# Prior-work callers and loops are short integration boundaries, not owned FDEs.
BOUNDARIES = (
    ('prior_constructor_return', 0x474a9e1, 0x474aa0d),
    ('prior_return_saved', 0x226ee70, 0x226ee92),
    ('prior_return_parent_slot', 0x226f270, 0x226f285),
    ('prior_parent_copy', 0x226f2d7, 0x226f2f2),
    ('prior_outer_result_copy', 0x2276920, 0x2276988),
    ('prior_slow_argument', 0x227720c, 0x2277222),
    ('save_argument_and_new_edge', 0x22772a0, 0x22772b7),
    ('prior_loop_argument', 0x432e941, 0x432e94e),
    ('prior_loop_base', 0x432e99a, 0x432e9ab),
    ('prior_loop_sample_address', 0x432e9ba, 0x432e9c2),
    ('prior_loop_getter_edge', 0x432e9fd, 0x432ea14),
    ('prior_getter_arguments', 0x4748db1, 0x4748dbd),
    ('prior_getter_sample_edge', 0x4748e58, 0x4748ec2),
    ('prior_getter_return_copy', 0x4749355, 0x4749397),
    ('prior_loop_lag_override', 0x432efa6, 0x432efc1),
    ('prior_loop_writer_edge', 0x432efd0, 0x432eff9),
    ('prior_writer_line_edge', 0x470c141, 0x470c167),
)

# Hashes pin bytes independently of the input-digest check. They also make
# targeted corruption tests fail even when the test calls the parser directly.
PINNED = {
    'save_spawn': '8dc39fc089d7ce52a59a0cf299c6295b2b2de02cebbaf897285541591e6aa930',
    'thread_builder': '7c93d47c4b9218f2aca8dbdc22a4c94232f2fe6cbaaf29d48b56ae5447b28afe',
    'thread_callback': '7f74d4a43f9f22b082106e1e5c46ab4e2efd0bb81475bf2813bfef6385e83e1c',
    'thread_drop': 'c2d08bc3d500260ca4a8bf231986b38742854e1f64c7ad6919e5976a872d152a',
    'sample_guard': 'af721641ee020b484552b5819d761520ac1faa9f0376c0eb0676993d2de03335',
    'tls_null_adapter': 'f603703ac6b99309a23f05e0bcdc2e61b05364634305a734b6ae9a9a7e90600f',
    'tls_other_adapter': '9215b00f2da7e0c3674f2f6cad7c6a3891cd9cdb19ea7885e30aec16c806a4d9',
    'tls_null_callback': '513417880db44977d05e64e68d3ebaa3ba1b1d2a84b03f1e7aceca8791f08259',
    'tls_other_callback': '52d57fd5214d4ae952a6a862365ac4a09f49564c76b88d6b7bbbe3dfd64eacef',
    'callback_queue_push': '5e1eb623ee54420a52896512e2fade719d64d4236726c982a7452562d3fab677',
    'callback_queue_pop': '3e2686cb1024b169fe526e537024eeb8690baa3935e42f98f8a46a688e9b6c97',
    'callback_queue_run': 'a93641fc38675ba34b6c7e9fdad71afedf43036d239fbbf6de957940f1126a77',
    'callback_notify': '11e9dd9e9c996be8fb2229eecf9e4b9d1e6c3a5aa2cf23249801333538e583e4',
    'line_writer': 'f90e45fdb90ce379eaa499a8499545e42f43332831bb54902a690a7ae960c5f7',
    'sample_writer': 'd77144f4d28bd4a672423904fbad4df42ee61e35bdc8dd00d4f12e13884bb237',
    'lag_field_adapter': 'e5a2351bc8e301ba61f7b72570ff21f8e2e9896cbe5c2f22c6ebeba5ef8776bc',
    'lag_field_writer': '616d6ce644a7861a6e77bceb4448af4b3907e681fcccc8d93bea5d0677e2d96d',
    'integer_field_writer': '4a5adafcd5ab21c855d5260f5bdfa8c207ed7495140662bde66f5457855ebd75',
    'decimal_formatter': 'e1f557d129c2c8d7dfc7688948e53aab1d10711e221cd1a59ed26c8622d165f7',
    'time_field_writer': '3be2c80678eb2e21d68e37faed8c90435e122a3ea582c2340d9c21922c200045',
    'freeze_field_writer': '8c47135706ad8147b97772ed77f7c1a1a35c4302ef1a4e6218bf7e994de2d7e3',
    'string_writer': 'c86f18e4ba8438e6f0854877155f955638ffeb799fcacbc351eb38835945a4a3',
    'prior_constructor_return': '9794f5d711d2acb69dc74361f23747030da5e99146ca99fafee727d35ff1dedc',
    'prior_return_saved': 'e13a521e9a82625cbcca6053f131539c983cf194322e2209169951c81f089e30',
    'prior_return_parent_slot': '477d187327bce1dc3caea63f994142f9e57bd44b52a995b1ad11cf3a21055df4',
    'prior_parent_copy': 'fa649e7b6574759512a8e8d8f04f9e8bab3a10d1fc6ea7b202cdeea6368b7c69',
    'prior_outer_result_copy': 'aef442f15b384b59cbc8c83371a8686a4fa8f4bbb9d6f9c8838052e0ee1f9562',
    'prior_slow_argument': '3682e190d8e7ac0471df99d72dbc4e7d81209771cc30584b788b05872e3ee563',
    'save_argument_and_new_edge': '8add03e7592b2e15f55840c32db6343b6012142748995fe2c2cda8f93b099bf3',
    'prior_loop_argument': '94be41bb98a075332aa995c96eda58fb554b49f7c9585fd808d2bafc1b4aa264',
    'prior_loop_base': 'bef7e6991d73e79f921e521d68042d4e4af1f25b5c0cf5ff45932b6817d2d1b5',
    'prior_loop_sample_address': 'c9874d4ba8b2cf5968dd2454ec5650d6d9a9a9d61560c8ab03e5c944047c2003',
    'prior_loop_getter_edge': '1bf5c31af87088a442a4041b6c73c0c6526920da9b43cd4948910bc125715f85',
    'prior_getter_arguments': '09ff076e5bee22df201177b958fbc097fff50b996e637ada666236130d22b652',
    'prior_getter_sample_edge': 'f35264fd11a3ad715def822e8f9b16fc73e272dbad9be0963ea79cebfb3ee731',
    'prior_getter_return_copy': '5c3b439e5c1c13c6fd43c0227d6b85f4aec693132031d446d5b562021a1adf61',
    'prior_loop_lag_override': '3e24f386e46da7273f465aa6bc21a1d33f7a639f52eae25065511716dc4146f8',
    'prior_loop_writer_edge': '73e9521046819d280b6ca57a045438e07b9d780f2d760abec1781aa1da35f5c9',
    'prior_writer_line_edge': '4b468251d142d780c3fe3bb07529fed862c9d22b69c2304af578824b8f5b01c5',
}

# A selected condition with the immediately preceding flag-producing bytes.
# These are not an exhaustive control-flow graph.
DECISIONS = (
    ('save_refcount', 0x474bac8, 0x474bacd),
    ('name_allocation', 0x474bb8d, 0x474bb90),
    ('spawn_result_zero', 0x474bc0c, 0x474bc0f),
    ('builder_payload_allocation', 0x4331c70, 0x4331c73),
    ('builder_closure_allocation', 0x4331d2a, 0x4331d2d),
    ('builder_envelope_allocation', 0x4331d8b, 0x4331d8e),
    ('builder_thread_result', 0x4331db1, 0x4331db3),
    ('sample_acquire_conditions', 0x452318c, 0x452319d),
    ('sample_cas_failed', 0x45231b5, 0x45231ba),
    ('sample_tls_null', 0x4523236, 0x452323d),
    ('sample_tls_other', 0x4523243, 0x452324a),
    ('sample_release_wake', 0x45232c8, 0x45232d0),
    ('null_adapter_bad_counts', 0x46a919a, 0x46a919d),
    ('null_adapter_result_tag', 0x46a9225, 0x46a9229),
    ('other_adapter_bad_counts', 0x46b9eac, 0x46b9eaf),
    ('other_adapter_completion', 0x46b9ed3, 0x46b9ed7),
    ('null_callback_input_null', 0x47a6b0d, 0x47a6b10),
    ('null_callback_tls_null', 0x47a6b20, 0x47a6b25),
    ('other_callback_input_null', 0x47a5fbb, 0x47a5fbe),
    ('other_callback_tls_null', 0x47a5fce, 0x47a5fd3),
    ('queue_push_slot_sentinel', 0x4e19c9c, 0x4e19ca0),
    ('queue_push_allocation', 0x4e19ce2, 0x4e19ce5),
    ('queue_push_ticket_overflow', 0x4e19cff, 0x4e19d03),
    ('queue_push_rotate', 0x4e19d5a, 0x4e19d5e),
    ('queue_pop_ticket_overflow', 0x4e19eda, 0x4e19ede),
    ('queue_pop_rotation', 0x4e19f2a, 0x4e19f2e),
    ('queue_pop_ready', 0x4e19f6b, 0x4e19f6d),
    ('queue_run_retry', 0x4e15be0, 0x4e15be4),
    ('queue_run_empty', 0x4e15be6, 0x4e15be9),
    ('queue_run_nonnull_callback', 0x4e15c17, 0x4e15c1a),
    ('notify_lock_contended', 0x47799d4, 0x47799d8),
    ('notify_already_closed', 0x47799f2, 0x47799f4),
    ('line_allocation', 0x45b592f, 0x45b5932),
    ('line_time_error', 0x45b597d, 0x45b5980),
    ('line_sample_error', 0x45b59bc, 0x45b59bf),
    ('line_capacity_sentinel', 0x45b5a1a, 0x45b5a1d),
    ('line_newline_growth', 0x45b5a36, 0x45b5a39),
    ('field_initial_error', 0x48fe701, 0x48fe704),
    ('field_initial_state', 0x48fe70a, 0x48fe70f),
    ('field_height_error', 0x48fe72f, 0x48fe732),
    ('field_height_state', 0x48fe738, 0x48fe73d),
    ('field_freeze_error', 0x48fe75c, 0x48fe75f),
    ('field_freeze_state', 0x48fe765, 0x48fe76a),
    ('field_consensus_error', 0x48fe78a, 0x48fe78d),
    ('field_consensus_state', 0x48fe793, 0x48fe798),
    ('field_wall_error', 0x48fe7b4, 0x48fe7b7),
    ('field_lag_error', 0x48fe7ca, 0x48fe7cd),
    ('sample_close_blocked', 0x48fe7d1, 0x48fe7d6),
    ('sample_close_absent', 0x48fe7d8, 0x48fe7dd),
    ('freeze_writer_state', 0x4a9b85e, 0x4a9b861),
    ('freeze_low_bit', 0x4a9b903, 0x4a9b907),
    ('freeze_null_capacity', 0x4a9b94d, 0x4a9b951),
    ('lag_writer_state', 0x4a7c27e, 0x4a7c281),
    ('lag_low_bit', 0x4a7c324, 0x4a7c328),
    ('lag_finite_bits', 0x4a7c346, 0x4a7c349),
    ('string_formatter_error', 0x4ad417d, 0x4ad417f),
)

# Calls/jumps are decoded from their linked instruction bytes. The first and
# two boundary edges only link prior work to the newly selected functions.
EDGES = (
    ('startup_to_save_boundary', 0x22772b1),
    ('save_to_builder', 0x474bbfd),
    ('callback_to_prior_loop', 0x433a81f),
    ('prior_loop_to_getter', 0x432ea0f),
    ('prior_getter_to_sample', 0x4748e7a),
    ('sample_to_null_adapter', 0x4523454),
    ('sample_to_other_adapter', 0x452346e),
    ('null_adapter_to_dispatch', 0x46a914e),
    ('other_adapter_to_dispatch', 0x46b9e54),
    ('queue_run_to_pop', 0x4e15bd6),
    ('queue_run_to_callback', 0x4e15cdf),
    ('null_callback_notify', 0x47a6c1d),
    ('prior_loop_to_writer', 0x432eff4),
    ('prior_writer_to_line', 0x470c162),
    ('line_to_timestamp', 0x45b5975),
    ('line_to_sample', 0x45b59b4),
    ('line_to_existing_sink', 0x45b5a4f),
    ('sample_initial_field', 0x48fe6fc),
    ('sample_height_field', 0x48fe72a),
    ('sample_freeze_field', 0x48fe757),
    ('sample_consensus_field', 0x48fe785),
    ('sample_wall_field', 0x48fe7af),
    ('sample_lag_field', 0x48fe7c5),
    ('lag_adapter_tail', 0x4972074),
    ('integer_format_boundary', 0x4a878b2),
    ('freeze_format_boundary', 0x4a9b90c),
    ('time_string_writer', 0x4a8f5f0),
)
EXPECTED_EDGE_TARGETS = (
    0x474ba90, 0x4331a70, 0x432e930, 0x4748da0, 0x4523150,
    0x46a90f0, 0x46b9df0, 0x4e19c40, 0x4e19c40, 0x4e19e50,
    None, 0x47799c0, 0x470bf20,
    0x45b5910, 0x4ad4100, 0x48fe6b0, 0x13d12a0, 0x4a87800,
    0x4a87800, 0x4a9b850, 0x4a8f530, 0x4a8f530, 0x4972060,
    0x4a7c270, 0x4a10c80, 0x4a10c80, 0x4ad4100,
)
REFERENCES = (
    ('thread_descriptor', 0x4331d74, '488d05', 0x571cb48),
    ('null_adapter_callback', 0x46a913f, '488d35', 0x47a6af0),
    ('other_adapter_callback', 0x46b9e45, '488d35', 0x47a5fa0),
    ('decimal_digit_table', 0x4a10ca2, '4c8d0d', 0x704d88),
)

# label, instruction VA, opcode prefix, byte position and width of little-endian
# displacement/immediate, source coordinate. All values emitted are decoded.
OPERANDS = (
    ('constructor_return_allocation', 0x474a9e1, 'bf', 1, 4, 'allocation'),
    ('constructor_return_saved', 0x226ee8d, '48895424', 4, 1, 'startup_rsp'),
    ('constructor_return_reloaded', 0x226f278, '488b5424', 4, 1, 'startup_rsp'),
    ('constructor_parent_slot', 0x226f27d, '48899424', 4, 4, 'startup_rsp'),
    ('constructor_parent_address', 0x226f2df, '488db424', 4, 4, 'startup_rsp'),
    ('constructor_parent_size', 0x226f2e7, 'ba', 1, 4, 'copy_length'),
    ('outer_parent_address', 0x227696b, '498dbe', 3, 4, 'outer_parent'),
    ('outer_parent_size', 0x2276981, 'ba', 1, 4, 'copy_length'),
    ('slow_worker_parent_field', 0x227720c, '498bb6', 3, 4, 'parent'),
    ('save_worker_parent_field', 0x22772a0, '498bbe', 3, 4, 'parent'),
    ('builder_frame_size', 0x4331a7a, '4881ec', 3, 4, 'stack'),
    ('builder_stack_argument', 0x4331a91, '488b8424', 4, 4, 'builder_rsp'),
    ('builder_saved_argument', 0x4331a99, '48894424', 4, 1, 'builder_rsp'),
    ('builder_payload_argument', 0x4331ca7, '48898c24', 4, 4, 'builder_rsp'),
    ('builder_closure_size', 0x4331d1f, 'bf', 1, 4, 'allocation'),
    ('builder_payload_load', 0x4331d43, '0f289424', 4, 4, 'builder_rsp'),
    ('builder_payload_store', 0x4331d4b, '0f1150', 3, 1, 'payload'),
    ('callback_payload_field', 0x433a7d1, '4c8b77', 3, 1, 'payload'),
    ('queue_push_index_mask', 0x4e19c98, '4183e5', 3, 1, 'ticket'),
    ('queue_push_rotation_index', 0x4e19d5a, '4183fd', 3, 1, 'ticket'),
    ('queue_push_segment_size', 0x4e19cd7, 'bf', 1, 4, 'allocation'),
    ('queue_push_callback_normal', 0x4e19db7, '49894cc7', 4, 1, 'segment'),
    ('queue_push_context_normal', 0x4e19dc1, '49894cc7', 4, 1, 'segment'),
    ('queue_push_flag_normal', 0x4e19dc6, 'f049834cc7', 5, 1, 'segment'),
    ('queue_push_callback_rotation', 0x4e19d89, '498987', 3, 4, 'segment'),
    ('queue_push_context_rotation', 0x4e19d95, '498987', 3, 4, 'segment'),
    ('queue_push_flag_rotation', 0x4e19d9c, 'f049838f', 4, 4, 'segment'),
    ('queue_push_tail', 0x4e19c5b, '488b9f', 3, 4, 'queue'),
    ('queue_push_segment', 0x4e19c62, '4c8bbf', 3, 4, 'queue'),
    ('queue_pop_tail', 0x4e19ef2, '498b97', 3, 4, 'queue'),
    ('queue_run_owner', 0x4e15bae, '4c8bbb', 3, 4, 'worker'),
    ('queue_run_negated_adjust', 0x4e15bba, '4983ef', 3, 1, 'owner'),
    ('decimal_initial_buffer', 0x4a10c81, 'b8', 1, 4, 'buffer'),
    ('decimal_group_base', 0x4a10c86, '4881ff', 3, 4, 'integer'),
    ('decimal_group_multiplier', 0x4a10c98, '49b8', 2, 8, 'integer'),
    ('decimal_group_shift', 0x4a10cc3, '48c1ea', 3, 1, 'integer'),
    ('decimal_pair_pre_shift', 0x4a10cd7, '41c1eb', 3, 1, 'integer'),
    ('decimal_pair_multiplier', 0x4a10cdf, '4169db', 3, 4, 'integer'),
    ('decimal_pair_shift', 0x4a10ce6, 'c1eb', 2, 1, 'integer'),
    ('sample_lock_offset', 0x452317c, '4d8dbc24', 4, 4, 'B'),
    ('sample_state_offset', 0x452321c, '498d8c24', 4, 4, 'B'),
    ('sample_tls_identity_offset', 0x4523215, '488b80', 3, 4, 'B'),
    ('sample_queue_adjust', 0x4523224, '488db0', 3, 4, 'owner'),
    ('sample_initial_source', 0x4523250, '4d8bac24', 4, 4, 'B'),
    ('sample_height_source', 0x4523258, '4d8bb424', 4, 4, 'B'),
    ('sample_freeze_source', 0x4523260, '410f108424', 5, 4, 'B'),
    ('sample_time_tail_source', 0x452326e, '418b8424', 4, 4, 'B'),
    ('sample_time_head_source', 0x452327a, '498b8424', 4, 4, 'B'),
    ('sample_initial_stack', 0x4523292, '4c896c24', 4, 1, 'sample_stack'),
    ('sample_height_stack', 0x4523297, '4c897424', 4, 1, 'sample_stack'),
    ('sample_freeze_stack', 0x45232a1, '0f294424', 4, 1, 'sample_stack'),
    ('sample_lag_zero_stack', 0x45232a6, '48c74424', 4, 1, 'sample_stack'),
    ('sample_last_output', 0x45233ef, '488943', 3, 1, 'sample_output'),
    ('null_callback_initial', 0x47a6b2b, '4c8b78', 3, 1, 'E'),
    ('null_callback_height', 0x47a6b2f, '4c8b60', 3, 1, 'E'),
    ('null_callback_freeze_tag', 0x47a6b33, '4c8ba8', 3, 4, 'E'),
    ('null_callback_freeze_value', 0x47a6b3a, '4c8bb0', 3, 4, 'E'),
    ('null_callback_time_tail', 0x47a6b41, '8b48', 2, 1, 'E'),
    ('null_callback_time_head', 0x47a6b48, '488b40', 3, 1, 'E'),
    ('other_callback_initial', 0x47a5fd9, '4c8b78', 3, 1, 'E'),
    ('other_callback_height', 0x47a5fdd, '4c8b60', 3, 1, 'E'),
    ('other_callback_freeze_tag', 0x47a5fe1, '4c8ba8', 3, 4, 'E'),
    ('other_callback_freeze_value', 0x47a5fe8, '4c8bb0', 3, 4, 'E'),
    ('other_callback_time_tail', 0x47a5fef, '8b48', 2, 1, 'E'),
    ('other_callback_time_head', 0x47a5ff6, '488b40', 3, 1, 'E'),
)

# Field name pointer is RIP-relative, byte length is an immediate, and the
# argument offset is taken from the selected address-setup instruction.
FIELDS = (
    ('initial', 0x48fe6e7, 0x48fe6eb, 0x48fe6f7, 0x48fe6fc),
    ('height', 0x48fe715, 0x48fe719, 0x48fe725, 0x48fe72a),
    ('freeze', 0x48fe754, 0x48fe743, 0x48fe74f, 0x48fe757),
    ('consensus', 0x48fe770, 0x48fe774, 0x48fe780, 0x48fe785),
    ('wall', 0x48fe79a, 0x48fe79e, 0x48fe7aa, 0x48fe7af),
    ('lag', 0x48fe7b9, 0x4972068, 0x497206f, 0x4972074),
)
EXPECTED_FIELDS = (
    ('initial_height', 0x20), ('height', 0x28),
    ('scheduled_freeze_height', 0), ('consensus_time', 0x30),
    ('wall_clock_time', 0x3c), ('reference_lag', 0x10),
)

OUTPUTS = ('functions.tsv', 'windows.tsv', 'boundaries.tsv', 'decisions.tsv',
           'edges.tsv', 'references.tsv', 'operands.tsv', 'fields.tsv', 'descriptor.tsv',
           'literals.tsv', 'decimal-table.tsv', 'lsda.tsv', 'summary.json')


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def unique_mapping(secs, va, size, *, executable=False):
    require(size > 0 and va >= 0, 'invalid virtual range')
    candidates = [s for s in secs if s['type'] != 8 and (s['flags'] & 2)
                  and (not executable or s['flags'] & 4)
                  and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(candidates) == 1, 'virtual range has no unique file-backed section')
    sec = candidates[0]
    return sec, sec['offset'] + va - sec['address']


class Image:
    def __init__(self, data):
        self.data = data
        require(hashlib.sha256(data).hexdigest() == SHA256, 'node-94 SHA-256 mismatch')
        self.secs = sections(data)
        _, self.fdes = eh_frame_records(data, self.secs)
        _, index = unwind_index(data)
        self.by_start = {}
        for record in self.fdes:
            self.by_start.setdefault(record['start'], []).append(record)
        self.index = {row['start']: row['fde'] for row in index}
        self._rels = None

    def read(self, va, size, *, executable=False):
        sec, off = unique_mapping(self.secs, va, size, executable=executable)
        require(off + size <= len(self.data), 'mapped range exceeds image')
        return sec, off, bytes(self.data[off:off + size])

    def fde(self, va):
        rows = self.by_start.get(va, ())
        require(len(rows) == 1, 'missing or duplicate selected FDE')
        row = rows[0]
        require(self.index.get(va) == row['fde'], 'FDE and unwind index disagree')
        self.read(va, row['end'] - va, executable=True)
        return row

    def relocations(self):
        if self._rels is None:
            sections_found = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] != 8]
            require(len(sections_found) == 1, 'missing or duplicate dynamic relocation section')
            s = sections_found[0]
            require(s['size'] % 24 == 0, 'misaligned dynamic relocation table')
            rels = {}
            for off in range(s['offset'], s['offset'] + s['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', self.data, off)
                rels.setdefault(slot, []).append((info & 0xffffffff, info >> 32, addend,
                                                 s['address'] + off - s['offset'], off))
            self._rels = rels
        return self._rels

    def relative_reloc(self, slot):
        rows = self.relocations().get(slot, ())
        require(len(rows) == 1, 'missing or duplicate selected relocation')
        row = rows[0]
        require(row[0] == 8 and row[1] == 0 and row[2] >= 0, 'not a symbol-zero RELATIVE relocation')
        self.read(slot, 8)
        return row


def pinned_windows(image):
    functions, windows, boundaries = [], [], []
    specs = [(name, image.fde(start)) for name, start in FUNCTIONS]
    for name, fde in specs:
        start, end = fde['start'], fde['end']
        _, off, raw = image.read(start, end - start, executable=True)
        sha = hashlib.sha256(raw).hexdigest()
        require(PINNED.get(name) == sha, 'selected FDE bytes changed: ' + name)
        functions.append((name, hex(start), hex(end), end - start, hex(off), hex(fde['fde']),
                          hex(fde['cie']), '' if fde['lsda'] is None else hex(fde['lsda']), sha))
        windows.append((name, hex(start), hex(end), hex(off), raw.hex(), sha))
    for name, start, end in BOUNDARIES:
        _, off, raw = image.read(start, end - start, executable=True)
        sha = hashlib.sha256(raw).hexdigest()
        require(PINNED.get(name) == sha, 'boundary bytes changed: ' + name)
        boundaries.append((name, hex(start), hex(end), hex(off), raw.hex(), sha))
    require(set(PINNED) == {name for name, _ in FUNCTIONS} | {x[0] for x in BOUNDARIES},
            'pin catalogue mismatch')
    return specs, functions, windows, boundaries


def decode_branch(image, site):
    _, off, head = image.read(site, 2, executable=True)
    if 0x70 <= head[0] <= 0x7f:
        length, condition, disp = 2, head[0] & 15, struct.unpack('<b', head[1:2])[0]
    elif head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        _, off, head = image.read(site, 6, executable=True)
        length, condition, disp = 6, head[1] & 15, struct.unpack('<i', head[2:6])[0]
    else:
        raise ValueError('unsupported conditional-branch encoding')
    target = site + length + disp
    image.read(target, 1, executable=True)
    return off, head, condition, disp, site + length, target


def decision_rows(image):
    rows = []
    for name, guard, branch in DECISIONS:
        _, guard_off, raw_guard = image.read(guard, branch - guard, executable=True)
        off, raw, condition, disp, fallthrough, target = decode_branch(image, branch)
        rows.append((name, hex(guard), hex(guard_off), raw_guard.hex(), hex(branch), hex(off),
                     raw.hex(), condition, disp, hex(fallthrough), hex(target)))
    return rows


def decode_edge(image, site):
    _, off, first = image.read(site, 2, executable=True)
    if first == b'\x41\xff':
        _, off, raw = image.read(site, 3, executable=True)
        require(raw == b'\x41\xff\xd7', 'unsupported register call')
        return off, raw, 'call_reg_r15', None, None, None
    if first[0] in (0xe8, 0xe9):
        _, off, raw = image.read(site, 5, executable=True)
        target = site + 5 + struct.unpack_from('<i', raw, 1)[0]
        image.read(target, 1, executable=True)
        return off, raw, 'call_rel32' if first[0] == 0xe8 else 'jump_rel32', None, target, None
    require(first == b'\xff\x15', 'unsupported selected edge encoding')
    _, off, raw = image.read(site, 6, executable=True)
    slot = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    reloc = image.relative_reloc(slot)
    image.read(reloc[2], 1, executable=True)
    return off, raw, 'call_rip_slot', slot, reloc[2], reloc


def edge_rows(image):
    rows = []
    require(len(EDGES) == len(EXPECTED_EDGE_TARGETS), 'edge catalogue mismatch')
    for (name, site), expected in zip(EDGES, EXPECTED_EDGE_TARGETS):
        off, raw, kind, slot, target, rel = decode_edge(image, site)
        require(target == expected, 'selected edge target changed: ' + name)
        rows.append((name, hex(site), hex(off), raw.hex(), kind,
                     '' if slot is None else hex(slot), '' if target is None else hex(target),
                     '' if rel is None else hex(rel[3]), '' if rel is None else hex(rel[4]),
                     '' if rel is None else rel[0], '' if rel is None else rel[1]))
    return rows


def operand_rows(image):
    rows = []
    for name, site, prefix, at, width, coordinate in OPERANDS:
        _, off, raw = image.read(site, at + width, executable=True)
        require(raw.startswith(bytes.fromhex(prefix)), 'operand opcode changed: ' + name)
        value = int.from_bytes(raw[at:at + width], 'little')
        rows.append((name, hex(site), hex(off), raw.hex(), coordinate, value, hex(value)))
    return rows


def rip_target(image, site, prefix):
    _, off, raw = image.read(site, 7, executable=True)
    require(raw[:3] == prefix, 'unsupported selected RIP-relative instruction')
    target = site + len(raw) + struct.unpack_from('<i', raw, 3)[0]
    return off, raw, target


def reference_rows(image):
    rows = []
    for name, site, prefix, expected in REFERENCES:
        off, raw, target = rip_target(image, site, bytes.fromhex(prefix))
        require(target == expected, 'selected reference target changed: ' + name)
        _, target_off, _ = image.read(target, 1, executable=name not in ('thread_descriptor', 'decimal_digit_table'))
        rows.append((name, hex(site), hex(off), raw.hex(), hex(target), hex(target_off)))
    return rows


def field_rows(image):
    rows = []
    require(len(FIELDS) == len(EXPECTED_FIELDS), 'field catalogue mismatch')
    for (name, arg_site, name_site, length_site, edge_site), expected in zip(FIELDS, EXPECTED_FIELDS):
        _, arg_off, prefix = image.read(arg_site, 3, executable=True)
        if prefix == b'\x48\x8d\x4b':
            _, arg_off, arg = image.read(arg_site, 4, executable=True)
            displacement = arg[3]
        elif prefix == b'\x48\x89\xd9':
            arg, displacement = prefix, 0
        elif prefix == b'\x48\x83\xc3':
            _, arg_off, arg = image.read(arg_site, 4, executable=True)
            displacement = arg[3]
        else:
            raise ValueError('unsupported field input setup')
        name_off, name_raw, pointer = rip_target(image, name_site, b'\x48\x8d\x35')
        _, length_off, imm = image.read(length_site, 5, executable=True)
        require(imm[0] == 0xba, 'unsupported field length setup')
        size = struct.unpack_from('<I', imm, 1)[0]
        _, literal_off, literal = image.read(pointer, size)
        require(literal and all(0x20 <= ch < 0x7f for ch in literal), 'invalid field-name bytes')
        require((literal.decode('ascii'), displacement) == expected, 'selected field changed: ' + name)
        edge_off, edge, kind, slot, target, _ = decode_edge(image, edge_site)
        require(slot is None, 'field edge unexpectedly indirect')
        rows.append((name, hex(arg_site), hex(arg_off), arg.hex(), displacement,
                     hex(name_site), hex(name_off), name_raw.hex(), hex(pointer), hex(literal_off),
                     size, literal.hex(), literal.decode('ascii'), hex(length_site), hex(length_off),
                     imm.hex(), hex(edge_site), hex(edge_off), edge.hex(), kind, hex(target)))
    return rows


def descriptor_rows(image):
    _, lea, table = rip_target(image, 0x4331d74, b'\x48\x8d\x05')
    rows = []
    for index in range(4):
        va = table + index * 8
        _, off, raw = image.read(va, 8)
        word = struct.unpack('<Q', raw)[0]
        rel = image.relocations().get(va, ())
        if rel:
            typ, sym, target, record_va, record_off = image.relative_reloc(va)
            image.read(target, 1, executable=True)
        else:
            typ = sym = target = record_va = record_off = None
        rows.append((index, hex(table), lea.hex(), hex(va), hex(off), raw.hex(), hex(word),
                     '' if typ is None else typ, '' if sym is None else sym,
                     '' if target is None else hex(target),
                     '' if record_va is None else hex(record_va),
                     '' if record_off is None else hex(record_off)))
    require(rows[0][9] == hex(0x4341050) and rows[3][9] == hex(0x433a7c0),
            'descriptor target mismatch')
    require([row[6] for row in rows] == [hex(0), hex(0x30), hex(8), hex(0)]
            and all(rows[i][7] == '' for i in (1, 2)), 'descriptor size or alignment changed')
    return rows


def read_lock_case(image, word, compare_exchange_succeeds):
    """Model just the pinned acquire predicate; this does not run the node."""
    require(type(word) is int and 0 <= word < 1 << 64, 'lock word outside u64')
    require(type(compare_exchange_succeeds) is bool, 'CAS outcome must be boolean')
    _, _, raw = image.read(0x452318c, 0x452319f - 0x452318c, executable=True)
    require(raw == bytes.fromhex('89c183e108c1e9034883f8f00f93c208ca7412'),
            'acquire predicate bytes changed')
    bit = raw[4]
    threshold = (1 << 64) + struct.unpack('<b', raw[11:12])[0]
    _, _, add = image.read(0x45231b1, 4, executable=True)
    require(add[:3] == bytes.fromhex('488d48'), 'acquire increment opcode changed')
    increment = add[3]
    if word & bit or word >= threshold or not compare_exchange_succeeds:
        return 'slow', word
    return 'fast', word + increment


def release_wakes(image, old_word):
    require(type(old_word) is int and 0 <= old_word < 1 << 64, 'lock word outside u64')
    _, _, raw = image.read(0x45232c8, 8, executable=True)
    require(raw[:3] == bytes.fromhex('4883e0') and raw[4:7] == bytes.fromhex('4883f8'),
            'release predicate opcode changed')
    mask = (1 << 64) + struct.unpack('<b', raw[3:4])[0]
    value = raw[7]
    return (old_word & mask) == value


def freeze_case(image, tag):
    require(type(tag) is int and 0 <= tag < 1 << 64, 'option tag outside u64')
    _, _, raw = image.read(0x4a9b903, 6, executable=True)
    require(raw == bytes.fromhex('41f6c601743a'), 'freeze predicate changed')
    return 'number' if tag & raw[3] else 'null'


def lag_case(image, tag, binary64_bits):
    require(type(tag) is int and 0 <= tag < 1 << 64, 'option tag outside u64')
    require(type(binary64_bits) is int and 0 <= binary64_bits < 1 << 64,
            'floating-point bits outside u64')
    _, _, test = image.read(0x4a7c324, 6, executable=True)
    require(test == bytes.fromhex('41f6c6017421'), 'lag predicate changed')
    _, _, magnitude = image.read(0x4a7c32f, 10, executable=True)
    _, _, exponent = image.read(0x4a7c33c, 10, executable=True)
    _, _, comparison = image.read(0x4a7c346, 5, executable=True)
    require(magnitude[:2] == b'\x48\xb9' and exponent[:2] == b'\x48\xb8'
            and comparison == bytes.fromhex('4839c17c29'), 'lag finite test changed')
    mask = struct.unpack_from('<Q', magnitude, 2)[0]
    limit = struct.unpack_from('<Q', exponent, 2)[0]
    return 'number' if (tag & test[3]) and (binary64_bits & mask) < limit else 'null'


def queue_slot_layout(image, index):
    """Compute the selected published record offsets, without scheduling work."""
    require(type(index) is int and 0 <= index <= 62, 'queue index outside selected slots')
    _, _, code = image.read(0x4e19da7, 11, executable=True)
    require(code == bytes.fromhex('4a8d046d000000004c01e8'), 'queue stride instructions changed')
    values = {row[0]: row[5] for row in operand_rows(image)}
    base = values['queue_push_callback_normal']
    context = values['queue_push_context_normal']
    flag = values['queue_push_flag_normal']
    if index == values['queue_push_rotation_index']:
        return (values['queue_push_callback_rotation'], values['queue_push_context_rotation'],
                values['queue_push_flag_rotation'])
    return base + 24 * index, context + 24 * index, flag + 24 * index


def queue_ticket_case(image, ticket):
    require(type(ticket) is int and 0 <= ticket < 1 << 64, 'ticket outside u64')
    _, _, code = image.read(0x4e19c92, 16, executable=True)
    require(code == bytes.fromhex('4189dd41d1ed4183e53f4183fd3f7528'),
            'queue index instructions changed')
    index = (ticket >> 1) & code[9]
    if index == code[13]:
        return 'retry', index
    _, _, rotation = image.read(0x4e19d5a, 4, executable=True)
    require(rotation[:3] == bytes.fromhex('4183fd'), 'queue rotation predicate changed')
    return ('rotate' if index == rotation[3] else 'normal'), index


DECIMAL_TABLE_HASH = 'bedfbc17dfedc3a783c817da8b2eec13baff8e36c4e6a61c346332973895315a'


def decimal_table(image):
    _, insn, va = rip_target(image, 0x4a10ca2, b'\x4c\x8d\x0d')
    require(va == 0x704d88, 'decimal table reference changed')
    _, off, raw = image.read(va, 200)
    sha = hashlib.sha256(raw).hexdigest()
    require(sha == DECIMAL_TABLE_HASH, 'decimal digit table changed')
    return va, off, insn, raw, sha


class DecimalModel:
    """Model the selected u64 formatter using pinned immediates and table bytes."""
    def __init__(self, image):
        fde = image.fde(0x4a10c80)
        _, _, code = image.read(fde['start'], fde['end'] - fde['start'], executable=True)
        require(hashlib.sha256(code).hexdigest() == PINNED['decimal_formatter'],
                'decimal formatter bytes changed')
        _, _, _, self.digits, _ = decimal_table(image)
        values = {row[0]: row[5] for row in operand_rows(image)}
        self.capacity = values['decimal_initial_buffer']
        self.base = values['decimal_group_base']
        self.multiplier = values['decimal_group_multiplier']
        self.shift = 64 + values['decimal_group_shift']
        self.pair_pre_shift = values['decimal_pair_pre_shift']
        self.pair_multiplier = values['decimal_pair_multiplier']
        self.pair_shift = values['decimal_pair_shift']
        require((self.capacity, self.base) == (20, 10000), 'unexpected decimal dimensions')
        delta = self.multiplier * self.base - (1 << self.shift)
        require(0 <= delta < self.base and ((1 << 64) - 1) * delta < 1 << self.shift,
                'group multiplier does not cover u64')
        for value in range(self.base):
            require(((value >> self.pair_pre_shift) * self.pair_multiplier) >> self.pair_shift
                    == value // 100, 'pair multiplier mismatch')

    def format(self, value):
        require(type(value) is int and 0 <= value < 1 << 64, 'decimal input outside u64')
        buf = bytearray(self.capacity)
        pos = self.capacity
        while value >= self.base:
            quotient = (value * self.multiplier) >> self.shift
            group = value - quotient * self.base
            require(0 <= group < self.base and pos >= 4, 'decimal group outside buffer')
            pair = ((group >> self.pair_pre_shift) * self.pair_multiplier) >> self.pair_shift
            remainder = group - pair * 100
            pos -= 4
            buf[pos:pos + 2] = self.digits[2 * pair:2 * pair + 2]
            buf[pos + 2:pos + 4] = self.digits[2 * remainder:2 * remainder + 2]
            value = quotient
        if value >= 100:
            pair = ((value >> self.pair_pre_shift) * self.pair_multiplier) >> self.pair_shift
            remainder = value - pair * 100
            pos -= 2
            buf[pos:pos + 2] = self.digits[2 * remainder:2 * remainder + 2]
            value = pair
        if value >= 10:
            pos -= 2
            buf[pos:pos + 2] = self.digits[2 * value:2 * value + 2]
        else:
            pos -= 1
            buf[pos] = 0x30 | value
        require(pos >= 0, 'decimal output outside buffer')
        return bytes(buf[pos:])


def ensure_selected_coverage(image, specs):
    """Refuse a selected code site outside the hashed extents or boundaries."""
    ranges = [(fde['start'], fde['end']) for _, fde in specs]
    ranges.extend((start, end) for _, start, end in BOUNDARIES)
    sites = [(guard, branch + len(decode_branch(image, branch)[1]))
             for _, guard, branch in DECISIONS]
    sites.extend((site, site + len(decode_edge(image, site)[1])) for _, site in EDGES)
    sites.extend((site, site + 7) for _, site, _, _ in REFERENCES)
    sites.extend((site, site + at + width) for _, site, _, at, width, _ in OPERANDS)
    for _, arg_site, name_site, length_site, edge_site in FIELDS:
        sites.extend(((arg_site, arg_site + 3), (name_site, name_site + 7),
                      (length_site, length_site + 5), (edge_site, edge_site + 5)))
    for start, end in sites:
        require(any(lo <= start < end <= hi for lo, hi in ranges),
                'selected code site outside pinned extents')


def literal_rows(image):
    # Each string has a separately pinned length or is one byte of punctuation.
    specs = (('thread_label', 0x474ba9d, b'\x48\x8d\x05', 0x474baa9, 26),
             ('spawn_failure', 0x474bcbf, b'\x48\x8d\x3d', 0x474bcd9, 22),
             ('closing_brace', 0x48fe7e7, b'\x48\x8d\x35', 0x48fe7ee, 1))
    rows = []
    for name, pointer_site, opcode, length_site, expected_length in specs:
        poff, insn, va = rip_target(image, pointer_site, opcode)
        if name == 'thread_label':
            _, loff, length_insn = image.read(length_site, 9, executable=True)
            require(length_insn[:5] == b'\x48\xc7\x44\x24\x58', 'unexpected length instruction')
            length = struct.unpack_from('<I', length_insn, 5)[0]
        else:
            _, loff, length_insn = image.read(length_site, 5, executable=True)
            require(length_insn[0] in (0xbe, 0xba), 'unexpected length instruction')
            length = struct.unpack_from('<I', length_insn, 1)[0]
        require(length == expected_length, 'unexpected literal length')
        _, off, literal = image.read(va, length)
        require(all(0x20 <= ch < 0x7f for ch in literal), 'nonprintable selected literal')
        rows.append((name, hex(pointer_site), hex(poff), insn.hex(), hex(length_site), hex(loff),
                     length_insn.hex(), hex(va), hex(off), length, literal.hex(), literal.decode('ascii')))
    return rows


def lsda_rows(image, specs):
    rows = []
    for name, fde in specs:
        if fde['lsda'] is None:
            continue
        sec, off = unique_mapping(image.secs, fde['lsda'], 2)
        require(sec['name'] == '.gcc_except_table', 'LSDA outside exception table')
        end = sec['offset'] + sec['size']
        data = image.data
        require(data[off] == 0xff, 'unsupported LSDA landing-pointer encoding')
        type_enc = data[off + 1]
        p = off + 2
        if type_enc == 0x9b:
            type_offset, p = uleb(data, p, end)
            type_end = p + type_offset
            require(p < type_end <= end, 'LSDA type table outside section')
        elif type_enc == 0xff:
            type_end = end
        else:
            raise ValueError('unsupported LSDA type encoding')
        require(p < type_end and data[p] == 1, 'unsupported LSDA call encoding')
        p += 1
        length, p = uleb(data, p, type_end)
        table_end = p + length
        require(table_end <= type_end, 'LSDA call table outside type table')
        previous = fde['start']
        while p < table_end:
            row_off = p
            delta, p = uleb(data, p, table_end)
            size, p = uleb(data, p, table_end)
            landing, p = uleb(data, p, table_end)
            action, p = uleb(data, p, table_end)
            start = fde['start'] + delta
            stop = start + size
            pad = fde['start'] + landing if landing else None
            require(previous <= start < stop <= fde['end'], 'invalid LSDA range')
            require(pad is None or fde['start'] <= pad < fde['end'], 'LSDA landing outside FDE')
            require(pad is not None or action == 0, 'LSDA action without landing')
            if type_enc == 0x9b and action:
                require(table_end + action - 1 < type_end, 'LSDA action outside table')
            rows.append((name, hex(fde['lsda']), hex(off), hex(start), hex(stop),
                         '' if pad is None else hex(pad), action, hex(row_off),
                         bytes(data[row_off:p]).hex()))
            previous = stop
        require(p == table_end, 'LSDA call table not consumed')
    return rows


def tsv(header, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def generate(data):
    image = Image(data)
    specs, funcs, windows, boundaries = pinned_windows(image)
    ensure_selected_coverage(image, specs)
    decisions = decision_rows(image)
    edges = edge_rows(image)
    references = reference_rows(image)
    operands = operand_rows(image)
    fields = field_rows(image)
    descriptor = descriptor_rows(image)
    literals = literal_rows(image)
    digit_va, digit_off, digit_insn, digit_bytes, digit_sha = decimal_table(image)
    lsda = lsda_rows(image, specs)
    summary = {
        'artifact_sha256': hashlib.sha256(data).hexdigest(),
        'coordinates': 'ELF link-time virtual addresses and file offsets',
        'counts': {'selected_fde_extents': len(funcs), 'full_fde_byte_windows': len(windows),
                   'selected_fde_bytes': sum(row[3] for row in funcs),
                   'prior_work_boundary_windows': len(boundaries), 'selected_decisions': len(decisions),
                   'selected_edges': len(edges), 'selected_operands': len(operands),
                   'selected_references': len(references),
                   'serialized_fields': len(fields), 'descriptor_words': len(descriptor),
                   'length_bound_literals': len(literals), 'lsda_call_site_rows': len(lsda)},
        'limitations': ['FDE ranges are unwind extents, not verified full function boundaries',
                        'edges and decisions are selected, not exhaustive',
                        'prior FDEs are integration boundaries',
                        'static evidence does not prove runtime scheduling or equivalence'],
    }
    output = {
        'functions.tsv': tsv(('role','fde_start_va','end_va_exclusive','bytes','file_offset','fde_va','cie_va','lsda_va','sha256'), funcs),
        'windows.tsv': tsv(('role','start_va','end_va_exclusive','file_offset','bytes_hex','sha256'), windows),
        'boundaries.tsv': tsv(('role','start_va','end_va_exclusive','file_offset','bytes_hex','sha256'), boundaries),
        'decisions.tsv': tsv(('role','guard_va','guard_file_offset','guard_bytes','branch_va','branch_file_offset','branch_bytes','condition_code','signed_displacement','fallthrough_va','target_va'), decisions),
        'edges.tsv': tsv(('role','site_va','file_offset','bytes_hex','kind','slot_va','target_va','relocation_record_va','relocation_file_offset','relocation_type','symbol_index'), edges),
        'references.tsv': tsv(('role','site_va','file_offset','instruction_bytes','target_va','target_file_offset'), references),
        'operands.tsv': tsv(('role','site_va','file_offset','bytes_hex','coordinate','value','value_hex'), operands),
        'fields.tsv': tsv(('role','argument_site_va','argument_file_offset','argument_bytes','sample_offset','name_site_va','name_site_file_offset','name_instruction','name_va','name_file_offset','name_length','name_bytes','name_text','length_site_va','length_file_offset','length_bytes','edge_site_va','edge_file_offset','edge_bytes','edge_kind','target_va'), fields),
        'descriptor.tsv': tsv(('word_index','table_va','table_lea_bytes','word_va','file_offset','bytes_hex','raw_word','relocation_type','symbol_index','relocation_addend','relocation_record_va','relocation_file_offset'), descriptor),
        'literals.tsv': tsv(('role','pointer_site_va','pointer_file_offset','pointer_bytes','length_site_va','length_file_offset','length_bytes','literal_va','literal_file_offset','length','bytes_hex','text'), literals),
        'decimal-table.tsv': tsv(('reference_site_va','reference_bytes','table_va','file_offset','size','bytes_hex','sha256'),
                                 [(hex(0x4a10ca2), digit_insn.hex(), hex(digit_va), hex(digit_off),
                                   len(digit_bytes), digit_bytes.hex(), digit_sha)]),
        'lsda.tsv': tsv(('role','lsda_va','lsda_file_offset','range_start_va','range_end_va_exclusive','landing_va','action_index','row_file_offset','bytes_hex'), lsda),
        'summary.json': (json.dumps(summary, sort_keys=True, indent=2) + '\n').encode('utf-8'),
    }
    require(set(output) == set(OUTPUTS), 'output catalogue mismatch')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    with BINARY.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        output = generate(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name in OUTPUTS:
        (args.out / name).write_bytes(output[name])


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('abci_sample_path94: ' + str(exc), file=sys.stderr)
        sys.exit(1)
