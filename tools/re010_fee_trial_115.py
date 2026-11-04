#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract selected node #115 startFeeTrial observations from authenticated ELF bytes.

This is a bounded evidence extractor. It does not execute the captured image,
parse disassembler output, infer all function boundaries, or emulate the node.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

# Selected FDEs are newly studied ranges. Existing execute/wrapper functions
# are recorded only as contextual edges and are not included in this set.
FUNCTIONS = (
    ('action_delayer_decoder', 0x1bdd100),
    ('delayed_map_value_decoder', 0x18f38a0),
    ('delayed_bucket_vector_decoder', 0x27ba880),
    ('delayed_bucket_decoder', 0x1b447c0),
    ('delayed_vector_decoder', 0x2684690),
    ('delayed_queue_extractor', 0x3bed8a0),
    ('delayed_execution_adapter', 0x231bf90),
    ('action_decoder', 0x2bd6140),
    ('payload_decoder', 0x2117d20),
    ('value_adapter', 0x2121af0),
    ('value_unbox_adapter', 0x2121060),
    ('string_value_decoder', 0x200e0c0),
    ('rate_converter', 0x36a5540),
    ('state_core', 0x3c18390),
    ('checked_date_adapter', 0x1506a00),
    ('packed_date_add_helper', 0x16290d0),
    ('independent_field_formatter', 0x36ab000),
)

# Windows have instruction-aligned start/end chosen during static inspection.
# Their hex and hashes come solely from the authenticated file.
WINDOWS = (
    ('delayer_sequence_field', 0x1bdd2a0, 0x1bdd31f),
    ('delayer_field_dispatch', 0x1bdd448, 0x1bdd478),
    ('delayer_map_field_decode', 0x1bdd478, 0x1bdd4cd),
    ('delayer_field_key_match', 0x1bddd72, 0x1bddd9e),
    ('delayer_field_key_zero', 0x1bddec0, 0x1bddec7),
    ('delayer_descriptor', 0x1bde0b0, 0x1bde0e1),
    ('delayer_missing_field_name', 0x1bde3f2, 0x1bde422),
    ('delayer_duplicate_field_name', 0x1bdf195, 0x1bdf1c0),
    ('map_value_entry', 0x18f38a0, 0x18f3911),
    ('map_value_nested_decode', 0x18f399e, 0x18f3a1b),
    ('bucket_vector_allocation', 0x27ba880, 0x27ba8f5),
    ('bucket_vector_append', 0x27ba900, 0x27ba93d),
    ('bucket_vector_item_decode', 0x27ba93d, 0x27ba9b5),
    ('bucket_decoder_entry', 0x1b447c0, 0x1b44830),
    ('bucket_decoder_vector', 0x1b44937, 0x1b449c7),
    ('context_delayed_record_entry', 0x18edd30, 0x18eddd9),
    ('context_delayed_map_action_decode', 0x18ee229, 0x18ee2f8),
    ('context_delayed_sequence_action_decode', 0x18eedf6, 0x18eee39),
    ('context_delayed_sequence_action_save', 0x18ef094, 0x18ef0e6),
    ('context_delayed_record_action_assembly', 0x18efda3, 0x18efe0b),
    ('context_delayed_record_finish', 0x18efeb4, 0x18eff34),
    ('context_delayed_record_output_copy', 0x18ef6a7, 0x18ef6c2),
    ('context_delayed_action_missing', 0x18ef19d, 0x18ef1cb),
    ('context_delayed_action_duplicate', 0x18eff81, 0x18effce),
    ('delayed_vector_entry', 0x2684690, 0x2684705),
    ('delayed_vector_copy_record', 0x2684710, 0x268473d),
    ('delayed_vector_item_decode', 0x268473d, 0x26847d9),
    ('delayed_vector_result', 0x26847d9, 0x2684817),
    ('queue_entry_and_partition', 0x3bed8a0, 0x3bed93e),
    ('queue_compare_keys', 0x3bed93e, 0x3beda10),
    ('queue_allocation_guard', 0x3beda10, 0x3beda59),
    ('queue_take_vector_and_replace', 0x3beddd9, 0x3bede0c),
    ('queue_vector_and_count_update', 0x3bede92, 0x3bedf3f),
    ('queue_item_filter', 0x3bedf3f, 0x3bedf6e),
    ('queue_key_lookup_and_decrement', 0x3bee030, 0x3bee0b7),
    ('queue_return_vector', 0x3bee2ca, 0x3bee2fb),
    ('adapter_size_and_alloc', 0x231bf90, 0x231c009),
    ('adapter_consumer_and_return', 0x231c009, 0x231c07e),
    ('adapter_failure_paths', 0x231c07e, 0x231c0b3),
    ('action_envelope_and_table', 0x2bd6183, 0x2bd624b),
    ('action_selected_arm', 0x2bd7fa7, 0x2bd801d),
    ('action_error_and_tag_store', 0x2bd835d, 0x2bd8384),
    ('payload_kind_selection', 0x2117d20, 0x2117d55),
    ('payload_key_kind_table', 0x2117e9d, 0x2117ec8),
    ('payload_numeric_field_table', 0x2117ec8, 0x2117ee8),
    ('payload_small_integer_table', 0x2117f2d, 0x2117f50),
    ('payload_field_switch', 0x2117fbd, 0x2117fe9),
    ('payload_field_0', 0x2117fe9, 0x2118070),
    ('payload_field_2', 0x2118070, 0x21180fc),
    ('payload_field_3', 0x2118100, 0x2118195),
    ('payload_field_1', 0x21181a0, 0x211822c),
    ('payload_sequence_entry', 0x2118348, 0x21183c8),
    ('payload_missing_first', 0x21184de, 0x2118572),
    ('payload_missing_second', 0x2118572, 0x21185dc),
    ('payload_missing_fourth', 0x211863b, 0x21186be),
    ('payload_missing_third', 0x21187e7, 0x211885a),
    ('payload_return_layout', 0x21188ac, 0x2118914),
    ('payload_duplicate_first', 0x21191f4, 0x211925b),
    ('payload_duplicate_fourth', 0x2119260, 0x21192c4),
    ('payload_duplicate_second', 0x211930a, 0x2119378),
    ('payload_duplicate_third', 0x2119378, 0x21193e4),
    ('value_adapter_entry', 0x2121af0, 0x2121b2b),
    ('value_adapter_normal_and_error', 0x2121b49, 0x2121be4),
    ('nested_value_adapter_entry', 0x2121060, 0x212109b),
    ('nested_value_adapter_normal_and_error', 0x21210b9, 0x2121154),
    ('string_value_switch_and_copy', 0x200e0c0, 0x200e10c),
    ('string_value_variants', 0x200e10c, 0x200e13f),
    ('string_value_allocate_and_fail', 0x200e13f, 0x200e19b),
    ('string_value_unsupported', 0x200e1ac, 0x200e1cf),
    ('converter_first', 0x36a5540, 0x36a55c6),
    ('converter_second', 0x36a55c6, 0x36a563c),
    ('converter_third', 0x36a563c, 0x36a56af),
    ('converter_fourth_and_result', 0x36a56af, 0x36a5714),
    ('converter_limit_error', 0x36a5714, 0x36a5726),
    ('converter_parse_error', 0x36a5726, 0x36a578d),
    ('converter_other_length_errors', 0x36a57f5, 0x36a5804),
    ('core_entry_and_special_keys', 0x3c18390, 0x3c18437),
    ('core_prior_record_and_flag', 0x3c18437, 0x3c184b9),
    ('core_conversion_gate', 0x3c184b9, 0x3c18500),
    ('core_template_compare', 0x3c18500, 0x3c1858c),
    ('core_error_copy', 0x3c1858c, 0x3c18600),
    ('core_flag_error', 0x3c18600, 0x3c1863b),
    ('core_override_compare', 0x3c1863b, 0x3c1867f),
    ('core_date_gates', 0x3c1867f, 0x3c186e7),
    ('core_discount_scan', 0x3c186e7, 0x3c18754),
    ('core_float_improvement', 0x3c18754, 0x3c187f1),
    ('core_float_minimum', 0x3c187f1, 0x3c18845),
    ('core_linked_vector_gate', 0x3c18845, 0x3c1886e),
    ('core_linked_record_write', 0x3c1886e, 0x3c18929),
    ('core_linked_lookup', 0x3c18929, 0x3c189bd),
    ('core_primary_record_write', 0x3c189bd, 0x3c18a5c),
    ('core_no_improvement_and_panic', 0x3c18a5c, 0x3c18a7e),
    ('date_checked_adapter', 0x1506a00, 0x1506a2a),
    ('date_add_fast_gate', 0x16290d0, 0x1629106),
    ('date_add_slow_year_path', 0x1629106, 0x1629159),
    ('date_add_slow_bounds', 0x16291c9, 0x1629222),
    ('date_add_return_paths', 0x1629246, 0x16292ae),
    ('date_add_panic_paths', 0x16292ae, 0x16292fc),
    ('formatter_entry', 0x36ab000, 0x36ab05e),
    ('formatter_fields', 0x36ab05e, 0x36ab10f),
    ('formatter_error', 0x36ab10f, 0x36ab12d),
    # These three selected slices corroborate the previously published path;
    # their containing FDEs are not claimed as newly studied functions.
    ('context_state_decoder_to_delayer', 0x1851d8b, 0x1851e43),
    ('context_state_duplicate_delayer_name', 0x185b3e4, 0x185b3ff),
    ('context_state_delayer_result_copy', 0x185d881, 0x185d8f9),
    ('context_engine_extract_and_dispatch', 0x2d237ad, 0x2d2381e),
    ('context_vector_memcpy_slot', 0x27048ef, 0x2704903),
    ('context_vector_memcpy_loop_slot', 0x2704910, 0x2704927),
    ('context_vector_item_and_action_copy', 0x27049d9, 0x2704a78),
    ('context_vector_to_outer_dispatch', 0x2704bd0, 0x2704c6c),
    ('context_outer_dispatch_index', 0x2bda82a, 0x2bda84c),
    ('context_outer_dispatch_arm', 0x2bdb060, 0x2bdb07a),
    ('context_outer_wrapper_gates', 0x2c154b6, 0x2c1552c),
    ('context_formatter_index', 0x2bc95f4, 0x2bc9616),
    ('context_formatter_arm', 0x2bcb75e, 0x2bcb7b5),
    ('context_execute_index', 0x2bdbb0c, 0x2bdbb2f),
    ('context_execute_arm', 0x2bdc804, 0x2bdc82c),
    ('context_wrapper_gate', 0x2385543, 0x2385557),
    ('context_wrapper_identity_gate', 0x2385557, 0x23855f4),
    ('context_wrapper_call_arguments', 0x23855f4, 0x238564d),
    ('context_wrapper_return_test', 0x238564d, 0x238565a),
)

# Branch sites are selected instruction starts, not a byte-pattern census.
BRANCHES = (
    ('delayer_field_duplicate', 0x1bdd472), ('delayer_field_error', 0x1bdd4c2),
    ('delayer_field_key_equal', 0x1bddd87),
    ('map_value_depth_zero', 0x18f39a9), ('map_value_depth_limit', 0x18f39b6),
    ('map_value_child_error', 0x18f39f5),
    ('bucket_vector_empty', 0x27ba8b5), ('bucket_vector_alloc_error', 0x27ba8d6),
    ('bucket_vector_key_error', 0x27ba961), ('bucket_vector_key_zero', 0x27ba96f),
    ('bucket_vector_item_error', 0x27ba98e), ('bucket_vector_capacity', 0x27ba9e7),
    ('bucket_depth_zero', 0x1b44942), ('bucket_depth_limit', 0x1b4494f),
    ('bucket_vector_error', 0x1b44983), ('bucket_count_zero', 0x1b449a2),
    ('bucket_count_underflow', 0x1b449aa),
    ('delayed_vector_item_error', 0x2684770),
    ('queue_representation', 0x3bed8ce), ('queue_empty', 0x3bed8e5),
    ('queue_invalid_empty_backing', 0x3bed8f4), ('queue_allocation_failure', 0x3beda53),
    ('queue_output_empty', 0x3bedec5), ('queue_items_done', 0x3bedf39),
    ('queue_filter_representation', 0x3bedf4e), ('queue_lookup_miss', 0x3bee03d),
    ('queue_lookup_out_of_range', 0x3bee048), ('queue_count_ge_two', 0x3bee0a3),
    ('adapter_size_overflow', 0x231bfc8), ('adapter_empty', 0x231bfda),
    ('adapter_allocation_failure', 0x231bfeb),
    ('action_envelope_non_error', 0x2bd61a7), ('action_payload_error', 0x2bd7fd8),
    ('action_selected_join', 0x2bd8018),
    ('payload_sequence_kind', 0x2117d46), ('payload_other_kind', 0x2117d4f),
    ('payload_key_kind_range', 0x2117ea2), ('payload_numeric_key_range', 0x2117ed2),
    ('payload_integer_key_range', 0x2117f31), ('payload_key_error', 0x2117fc4),
    ('payload_duplicate_0', 0x2117ff1), ('payload_duplicate_2', 0x2118075),
    ('payload_duplicate_3', 0x2118108), ('payload_duplicate_1', 0x21181a5),
    ('payload_value_0_error', 0x2118049), ('payload_value_2_error', 0x21180cd),
    ('payload_value_3_error', 0x2118163), ('payload_value_1_error', 0x21181fd),
    ('payload_sequence_first_present', 0x2118391), ('payload_sequence_extra', 0x2118461),
    ('value_boxed', 0x2121afd), ('value_boxed_result', 0x2121b29),
    ('value_direct_result', 0x2121b57), ('unbox_nested', 0x212106d),
    ('unbox_nested_result', 0x2121099), ('unbox_direct_result', 0x21210c7),
    ('string_kind_range', 0x200e0dc), ('string_length_nonnegative', 0x200e146),
    ('string_length_zero', 0x200e155), ('string_alloc_failure', 0x200e167),
    ('convert_length_1', 0x36a5555), ('convert_parse_1', 0x36a5577),
    ('convert_float_1', 0x36a55aa), ('convert_length_0', 0x36a55ce),
    ('convert_parse_0', 0x36a55ed), ('convert_float_0', 0x36a5620),
    ('convert_length_3', 0x36a5644), ('convert_parse_3', 0x36a5663),
    ('convert_float_3', 0x36a5696), ('convert_length_2', 0x36a56b8),
    ('convert_parse_2', 0x36a56cf),
    ('core_special_ff', 0x3c183fc), ('core_special_fe', 0x3c18431),
    ('core_prior_absent', 0x3c1844e), ('core_prior_inactive', 0x3c18453),
    ('core_prior_or_flag', 0x3c18482), ('core_default_flag', 0x3c184b3),
    ('core_conversion_failure', 0x3c184e9), ('core_templates_empty', 0x3c184fa),
    ('core_template_exhausted', 0x3c18547),
    ('core_template_lane0_ne', 0x3c18556), ('core_template_lane0_unordered', 0x3c18558),
    ('core_template_lane2_ne', 0x3c18564), ('core_template_lane2_unordered', 0x3c18566),
    ('core_template_lane1_ne', 0x3c18575), ('core_template_lane1_unordered', 0x3c18577),
    ('core_template_lane3_ne', 0x3c18583), ('core_template_lane3_unordered', 0x3c18585),
    ('core_no_matching_pair', 0x3c1863f), ('core_overrides_empty', 0x3c18648),
    ('core_overrides_exhausted', 0x3c18667),
    ('core_override_lane1_ne', 0x3c18673), ('core_override_lane1_unordered', 0x3c18675),
    ('core_override_lane3_ne', 0x3c1867b), ('core_override_lane3_unordered', 0x3c1867d),
    ('core_prior_date_absent', 0x3c186af), ('core_prior_date_zero', 0x3c186b9),
    ('core_cooldown_strict', 0x3c186cc), ('core_date_overflow', 0x3c186e1),
    ('core_discount_empty', 0x3c18706), ('core_discount_first', 0x3c18716),
    ('core_discount_done', 0x3c18733), ('core_discount_continue', 0x3c18748),
    ('core_no_improvement', 0x3c187eb), ('core_no_linked_vector', 0x3c18848),
    ('core_empty_linked_vector', 0x3c18856), ('core_linked_loop_done', 0x3c18923),
    ('core_linked_lookup_hit', 0x3c18995), ('date_negative_delta', 0x1506a03),
    ('date_none_result', 0x1506a0d),
    ('date_fast_nonpositive_or_overflow', 0x16290ee),
    ('date_fast_ordinal_in_year', 0x1629100), ('date_slow_internal_zero', 0x1629153),
    ('date_slow_add_overflow', 0x162915f), ('date_slow_sub_nonnegative', 0x16291c7),
    ('date_slow_bad_day', 0x16291cf), ('date_slow_bad_year', 0x16291df),
    ('date_slow_sub_underflow', 0x16291fb), ('date_slow_ordinal_bound', 0x1629219),
    ('date_slow_absolute_bound', 0x1629228), ('date_slow_ordinal_reject', 0x1629244),
    ('date_slow_year_reject', 0x1629265),
)

DIRECT_CALLS = (
    ('context_state_decoder_delayer', 0x1851dae),
    ('delayer_sequence_to_map', 0x1bdd2e2), ('delayer_field_to_map', 0x1bdd485),
    ('map_value_to_buckets', 0x18f39d5), ('bucket_vector_to_bucket', 0x27ba984),
    ('bucket_to_delayed_vector', 0x1b44977),
    ('context_delayed_map_action_decoder', 0x18ee245),
    ('context_delayed_sequence_action_decoder', 0x18eee06),
    ('delayed_vector_item', 0x268474e),
    ('queue_partition_a', 0x3bed900), ('queue_partition_b', 0x3bed920),
    ('queue_collect_vector', 0x3bedea2), ('queue_find_record', 0x3bee036),
    ('adapter_to_prior_consumer', 0x231c058),
    ('context_engine_to_adapter', 0x2d23819),
    ('context_vector_outer_dispatch_a', 0x2704c0c),
    ('context_vector_outer_dispatch_b', 0x2704c54),
    ('context_outer_dispatch_to_wrapper', 0x2bdb070),
    ('context_outer_wrapper_to_handler', 0x2c15527),
    ('action_envelope', 0x2bd6198), ('action_to_payload', 0x2bd7fc8),
    ('payload_value_0', 0x211803d), ('payload_value_1', 0x21181f1),
    ('payload_value_2', 0x21180c1), ('payload_value_3', 0x2118157),
    ('payload_missing_0', 0x2118546), ('payload_missing_1', 0x21185ca),
    ('payload_missing_2', 0x2118845), ('payload_missing_3', 0x21186a1),
    ('payload_duplicate_0', 0x211924e), ('payload_duplicate_1', 0x2119369),
    ('payload_duplicate_2', 0x21193d7), ('payload_duplicate_3', 0x21192bf),
    ('value_boxed_to_unbox', 0x2121b1e), ('value_direct_to_unbox', 0x2121b4c),
    ('unbox_boxed_to_string', 0x212108e), ('unbox_direct_to_string', 0x21210bc),
    ('string_convert_a', 0x200e126), ('string_convert_b', 0x200e138),
    ('string_error', 0x200e1be), ('converter_cleanup_1', 0x36a55be),
    ('converter_cleanup_0', 0x36a5634), ('converter_cleanup_3', 0x36a56aa),
    ('core_prior_lookup', 0x3c18446), ('core_to_converter', 0x3c184d6),
    ('core_cooldown_lookup', 0x3c186a7), ('core_linked_hash', 0x3c1893a),
    ('core_linked_lookup', 0x3c1898d), ('core_linked_record', 0x3c188ab),
    ('core_primary_lookup', 0x3c189d3), ('core_primary_record', 0x3c189db),
    ('formatter_start', 0x36ab01f), ('formatter_field_0', 0x36ab072),
    ('formatter_field_1', 0x36ab09c), ('formatter_field_2', 0x36ab0c2),
    ('formatter_field_3', 0x36ab0ef), ('formatter_finish', 0x36ab102),
    ('context_dispatch_to_wrapper', 0x2bdc827),
)
RIP_CALLS = (
    ('converter_decimal_1', 0x36a5567), ('converter_float_1', 0x36a559b),
    ('converter_decimal_0', 0x36a55dd), ('converter_float_0', 0x36a5611),
    ('converter_decimal_3', 0x36a5653), ('converter_float_3', 0x36a5687),
    ('converter_decimal_2', 0x36a56bf), ('core_date_90', 0x3c186c0),
    ('core_date_14', 0x3c186d9), ('date_adapter_checked_add', 0x1506a05),
    ('context_wrapper_to_core', 0x2385647),
    ('context_engine_to_queue', 0x2d237d7),
)

STORE_SITES = (
    (0x3c188b0, 0x3c189e0), (0x3c188bf, 0x3c189ef),
    (0x3c188cb, 0x3c189fb), (0x3c188d5, 0x3c18a05),
    (0x3c188df, 0x3c18a0f), (0x3c188e9, 0x3c18a19),
    (0x3c188f2, 0x3c18a22), (0x3c188fc, 0x3c18a2c),
    (0x3c18905, 0x3c18a35), (0x3c1890d, 0x3c18a3d),
    (0x3c18916, 0x3c18a46),
)
SOURCE_SITES = (
    (0x3c188b7, 0x3c189e7), (0x3c188c3, 0x3c189f3),
    (0x3c188cf, 0x3c189ff), (0x3c188da, 0x3c18a0a),
    (0x3c188e4, 0x3c18a14), (0x3c188ed, 0x3c18a1d),
    (0x3c188f7, 0x3c18a27), (0x3c18900, 0x3c18a30),
    (0x3c18909, 0x3c18a39), (0x3c18910, 0x3c18a40),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=DIGEST):
    require(hashlib.sha256(data).hexdigest() == expected, 'target SHA-256 mismatch')


def file_offset(secs, va, size, executable=False):
    require(isinstance(va, int) and isinstance(size, int), 'non-integer range')
    require(va >= 0 and size > 0 and va + size <= 1 << 64, 'invalid address range')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']
            and (not executable or s['flags'] & 4)]
    require(len(hits) == 1, 'range is not uniquely file-backed in a suitable section')
    return hits[0]['offset'] + va - hits[0]['address']


class Image:
    def __init__(self, data):
        verify_digest(data)
        self.data = data
        self.secs = sections(data)
        matches = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
        require(len(matches) == 1, 'expected one RELA section')
        sec = matches[0]
        require(sec['size'] % 24 == 0, 'malformed RELA section')
        self.relocations = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, off)
            require(slot not in self.relocations, 'duplicate dynamic relocation slot')
            self.relocations[slot] = (info, addend, off)

    def offset(self, va, size, executable=False):
        off = file_offset(self.secs, va, size, executable)
        require(off + size <= len(self.data), 'file range outside image')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]

    def expect(self, va, prefix, executable=True):
        raw = self.read(va, len(prefix), executable)
        require(raw == prefix, 'unexpected instruction or data pattern at ' + hex(va))
        return raw

    def dynamic_import(self, slot):
        """Resolve a selected GLOB_DAT slot with the shared section records."""
        require(slot in self.relocations, 'missing dynamic relocation')
        info, addend, rela_off = self.relocations[slot]
        index, kind = info >> 32, info & 0xffffffff
        require(kind == 6 and index > 0 and addend == 0, 'expected GLOB_DAT import')
        symbols = [s for s in self.secs if s['name'] == '.dynsym' and s['type'] == 11]
        strings = [s for s in self.secs if s['name'] == '.dynstr' and s['type'] == 3]
        require(len(symbols) == len(strings) == 1, 'missing dynamic symbol sections')
        syms, names = symbols[0], strings[0]
        require(index * 24 + 24 <= syms['size'], 'dynamic symbol index out of range')
        sym_off = syms['offset'] + index * 24
        name_off, info_byte, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.data, sym_off)
        require(shndx == 0 and value == 0 and name_off < names['size'], 'not an undefined import')
        start = names['offset'] + name_off
        end = self.data.find(b'\x00', start, names['offset'] + names['size'])
        require(start < end, 'unterminated dynamic symbol')
        name = self.data[start:end].decode('ascii')
        return name, index, rela_off, sym_off, start

    def relative_relocation(self, slot):
        require(slot in self.relocations, 'missing dynamic relocation')
        info, addend, off = self.relocations[slot]
        require(info == 8 and addend >= 0, 'expected R_X86_64_RELATIVE without symbol')
        return addend, off, self.data[off:off + 24]


def branch(raw, va):
    require(len(raw) >= 2, 'truncated branch')
    if 0x70 <= raw[0] <= 0x7f:
        n, kind, disp = 2, 'jcc_' + format(raw[0] & 15, 'x'), struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0x0f and len(raw) >= 6 and 0x80 <= raw[1] <= 0x8f:
        n, kind, disp = 6, 'jcc_' + format(raw[1] & 15, 'x'), struct.unpack_from('<i', raw, 2)[0]
    elif raw[0] == 0xeb:
        n, kind, disp = 2, 'jmp', struct.unpack_from('<b', raw, 1)[0]
    elif raw[0] == 0xe9 and len(raw) >= 5:
        n, kind, disp = 5, 'jmp', struct.unpack_from('<i', raw, 1)[0]
    else:
        raise ValueError('unsupported branch opcode')
    return kind, n, va + n + disp


def rel_call(raw, va):
    require(len(raw) == 5 and raw[0] == 0xe8, 'expected direct rel32 call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def rip_target(raw, va, prefix):
    require(len(raw) == len(prefix) + 4 and raw.startswith(prefix), 'unexpected RIP-relative opcode')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def table_entry(image, table, index, count):
    require(0 <= index < count, 'table index out of bounded selection')
    slot = table + 4 * index
    raw = image.read(slot, 4)
    return slot, table + struct.unpack('<i', raw)[0], raw


def decoded_store(raw):
    """Decode only the four store forms used by the two selected write blocks."""
    if raw.startswith(b'\x48\xc7\x00') and len(raw) >= 7:
        return 0, 8, 7, int.from_bytes(raw[3:7], 'little', signed=True)
    forms = ((b'\x0f\x11\x40', 16), (b'\xf2\x0f\x11\x40', 8),
             (b'\x89\x48', 4))
    for prefix, size in forms:
        if raw.startswith(prefix) and len(raw) >= len(prefix) + 1:
            disp = struct.unpack_from('<b', raw, len(prefix))[0]
            require(disp >= 0, 'negative record offset')
            return disp, size, len(prefix) + 1, None
    raise ValueError('unsupported record store opcode')


def decoded_stack_load(raw):
    """Decode only stack-load forms used by the two selected write blocks."""
    if raw.startswith(bytes.fromhex('0f288424')) and len(raw) >= 8:
        return struct.unpack_from('<i', raw, 4)[0], 16, 8
    forms = ((bytes.fromhex('f20f104424'), 8), (bytes.fromhex('0f284424'), 16),
             (bytes.fromhex('8b4c24'), 4))
    for prefix, width in forms:
        if raw.startswith(prefix) and len(raw) >= len(prefix) + 1:
            return struct.unpack_from('<b', raw, len(prefix))[0], width, len(prefix) + 1
    raise ValueError('unsupported stack load opcode')


def state_copy(raw_load, raw_store):
    """Decode selected stack-to-output MOV pairs, checking the register match."""
    if (len(raw_load) == 8 and len(raw_store) == 7 and
            raw_load[:2] == bytes.fromhex('0f10') and raw_load[3] == 0x24 and
            raw_store[:2] == bytes.fromhex('0f11') and
            raw_load[2] & 0xc7 == 0x84 and raw_store[2] & 0xc7 == 0x83):
        require((raw_load[2] >> 3) & 7 == (raw_store[2] >> 3) & 7,
                'state copy registers differ')
        return struct.unpack_from('<i', raw_load, 4)[0], struct.unpack_from('<i', raw_store, 3)[0], 16
    if (len(raw_load) == 8 and len(raw_store) == 7 and
            raw_load[:4] == bytes.fromhex('488b8424') and
            raw_store[:3] == bytes.fromhex('488983')):
        return struct.unpack_from('<i', raw_load, 4)[0], struct.unpack_from('<i', raw_store, 3)[0], 8
    raise ValueError('unsupported state copy opcode')


def selected_conversion_path(lengths, parser_words, float_ok):
    """Synthetic converter control flow with helper results as explicit inputs."""
    require(len(lengths) == len(parser_words) == len(float_ok) == 4, 'need four inputs')
    for field in (1, 0, 3, 2):
        require(isinstance(lengths[field], int) and 0 <= lengths[field] < 1 << 64,
                'invalid field length')
        if lengths[field] >= 101:
            return ('length', field, 0x158)
        if parser_words[field] != 0x1a2:
            return ('parser', field, parser_words[field])
        if field != 2 and not float_ok[field]:
            return ('float', field, 0xaf)
    return ('success', None, 0x1a2)


def signed32(n):
    require(isinstance(n, int) and 0 <= n < 1 << 32, 'not a u32')
    return n if n < (1 << 31) else n - (1 << 32)


def supports_template(field_values, templates, overrides):
    """Synthetic model of the selected ordered-ucomisd comparisons only.

    The argument uses descriptor order; template rows use the observed
    converter output lane order. It does not validate decimal parsing, state,
    date arithmetic, allocation, or any target execution.
    """
    require(len(field_values) == 4, 'need four field values')
    lanes = (field_values[1], field_values[0], field_values[3], field_values[2])
    pair = False
    for row in templates:
        require(len(row) == 4, 'need four template lanes')
        if row[0] == lanes[0] and row[2] == lanes[2]:
            pair = True
            if row[1] == lanes[1] and row[3] == lanes[3]:
                return 'exact'
    if pair and any(v == lanes[1] and v == lanes[3] for v in overrides):
        return 'override'
    return 'reject'


def date_fast_path(packed, delta):
    """Return the selected same-year path, or None if the slow path is taken.

    This is an algebraic model of the retained fast-path bytes, not an
    implementation of the full date function or validation of a date input.
    """
    require(isinstance(packed, int) and 0 <= packed < (1 << 32), 'not a packed u32')
    require(isinstance(delta, int) and -(1 << 31) <= delta < (1 << 31), 'not an i32 delta')
    ordinal = (packed >> 4) & 0x1ff
    total = ordinal + delta
    limit = 366 - ((packed >> 3) & 1)
    if total <= 0 or total >= (1 << 31) or total > limit:
        return None
    return (packed & 0xffffe00f) | (total << 4)


def selected_precedence(flag, active, conversion_word, accepted, prior_date,
                        adjusted_90, now_date, adjusted_14, improves):
    """Synthetic normal-control model; date helper results are explicit inputs."""
    require(0 <= flag <= 255, 'flag is not a byte')
    if flag or active:
        return ('word', 0x149 + 4 * flag)
    if conversion_word != 0x1a2:
        return ('word', conversion_word)
    if not accepted:
        return ('word', 0x14a)
    if prior_date:
        if adjusted_90 == 0:
            return ('panic90', None)
        if signed32(adjusted_90) > signed32(now_date):
            return ('word', 0x14c)
    if adjusted_14 == 0:
        return ('panic14', None)
    if not improves:
        return ('word', 0x14b)
    return ('word', 0x1a2)


def tsv(rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


def build(image):
    _, index = unwind_index(image.data)
    _, frames = eh_frame_records(image.data, image.secs)
    indexed = {row['start']: row for row in index}
    by_start = {}
    for frame in frames:
        by_start.setdefault(frame['start'], []).append(frame)
    selected = {}
    funcs = [['role', 'start_va', 'end_va_exclusive', 'file_offset', 'size',
              'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'body_sha256']]
    bodies = [['role', 'start_va', 'file_offset', 'body_hex']]
    for role, start in FUNCTIONS:
        found = by_start.get(start, [])
        require(len(found) == 1 and start in indexed, 'selected FDE missing or ambiguous')
        f = found[0]
        require(indexed[start]['fde'] == f['fde'] and f['end'] > start, 'FDE/index mismatch')
        body = image.read(start, f['end'] - start, True)
        selected[start] = (role, f)
        funcs.append([role, hex(start), hex(f['end']), hex(image.offset(start, len(body), True)),
                      len(body), hex(f['fde']), hex(f['cie']),
                      '' if f['lsda'] is None else hex(f['lsda']), indexed[start]['index'],
                      hashlib.sha256(body).hexdigest()])
        bodies.append([role, hex(start), hex(image.offset(start, len(body), True)), body.hex()])

    def selected_owner(va, end):
        found = [(role, f) for role, f in selected.values() if f['start'] <= va < end <= f['end']]
        return found[0][0] if len(found) == 1 else ''

    windows = [['name', 'scope', 'owner', 'start_va', 'end_va_exclusive', 'file_offset',
                'size', 'bytes_hex', 'sha256']]
    for name, lo, hi in WINDOWS:
        data = image.read(lo, hi - lo, True)
        context = name.startswith('context_')
        owner = selected_owner(lo, hi)
        require(context or owner, 'window outside selected FDE')
        windows.append([name, 'context' if context else 'selected', owner, hex(lo), hex(hi),
                        hex(image.offset(lo, len(data), True)), len(data), data.hex(),
                        hashlib.sha256(data).hexdigest()])

    branches = [['name', 'site_va', 'file_offset', 'raw_hex', 'kind', 'fallthrough_va', 'target_va']]
    for name, va in BRANCHES:
        raw = image.read(va, 6, True)
        kind, n, target = branch(raw, va)
        require(selected_owner(va, va + n) and
                selected_owner(va, va + n) == selected_owner(target, target + 1),
                'selected branch not contained in its selected FDE')
        branches.append([name, hex(va), hex(image.offset(va, n, True)), raw[:n].hex(),
                         kind, hex(va + n), hex(target)])

    edges = [['name', 'scope', 'site_va', 'file_offset', 'instruction_hex', 'kind',
              'slot_va', 'relocation_file_offset', 'relocation_hex', 'target_va', 'target_role']]
    for name, va in DIRECT_CALLS:
        raw = image.read(va, 5, True)
        target = rel_call(raw, va)
        context = name.startswith('context_')
        require(context or selected_owner(va, va + 5), 'call outside selected FDEs')
        image.read(target, 1, True)
        role = selected[target][0] if target in selected else 'external_or_prior'
        edges.append([name, 'context' if context else 'selected', hex(va),
                      hex(image.offset(va, 5, True)), raw.hex(), 'rel32', '', '', '', hex(target), role])
    for name, va in RIP_CALLS:
        raw = image.read(va, 6, True)
        slot = rip_target(raw, va, b'\xff\x15')
        target, off, relocation = image.relative_relocation(slot)
        image.read(target, 1, True)
        context = name.startswith('context_')
        require(context or selected_owner(va, va + 6), 'slot call outside selected FDEs')
        role = selected[target][0] if target in selected else 'external_or_prior'
        edges.append([name, 'context' if context else 'selected', hex(va),
                      hex(image.offset(va, 6, True)), raw.hex(), 'rip_relative_rela',
                      hex(slot), hex(off), relocation.hex(), hex(target), role])

    # Resolve selected imported comparator and copy symbols from ELF records.
    imports = [['name', 'scope', 'site_va', 'site_file_offset', 'instruction_hex',
                'slot_va', 'relocation_file_offset', 'relocation_hex', 'symbol_index',
                'symbol_file_offset', 'symbol_hex', 'name_file_offset', 'symbol_name']]
    for name, site, prefix, expected in (
            ('field_key_comparator', 0x1bddd7f, bytes.fromhex('ff15'), 'bcmp'),
            ('context_consumer_copy_first', 0x27048f7, bytes.fromhex('488b0d'), 'memcpy'),
            ('context_consumer_copy_loop', 0x270491c, bytes.fromhex('488b1d'), 'memcpy')):
        raw = image.read(site, len(prefix) + 4, True)
        slot = rip_target(raw, site, prefix)
        symbol, index, rela_off, sym_off, name_off = image.dynamic_import(slot)
        require(symbol == expected, 'unexpected imported function')
        imports.append([name, 'context' if name.startswith('context_') else 'selected',
                        hex(site), hex(image.offset(site, len(raw), True)), raw.hex(), hex(slot),
                        hex(rela_off), image.data[rela_off:rela_off + 24].hex(), index,
                        hex(sym_off), image.data[sym_off:sym_off + 24].hex(), hex(name_off), symbol])
    image.expect(0x2704a72, bytes.fromhex('ffd1'))
    image.expect(0x27049c3, bytes.fromhex('4889d9'))

    # Fix the complete instruction forms used by the date fast-path model.
    image.expect(0x16290d3, bytes.fromhex('89f9c1e90481e1ff01000089c801f00f90c2'))
    image.expect(0x16290f0, bytes.fromhex('89fac1e21cc1fa1f81c26e01000039d0'))
    image.expect(0x162929c, bytes.fromhex('81e70fe0ffffc1e00409f8'))

    # Confirm the selected action name, count, internally stored tag, and the
    # switch entry in the independent decoder. The prior executor is only a
    # contextual byte check; no whole old function is enrolled above.
    action_name_va = rip_target(image.read(0x2bd7fa7, 7, True), 0x2bd7fa7, b'\x48\x8d\x15')
    field_table_va = rip_target(image.read(0x2bd7fae, 7, True), 0x2bd7fae, b'\x4c\x8d\x05')
    image.expect(0x2bd7fbd, b'\xb9')
    name_len = struct.unpack('<I', image.read(0x2bd7fbe, 4, True))[0]
    image.expect(0x2bd7fc2, b'\x41\xb9')
    field_count = struct.unpack('<I', image.read(0x2bd7fc4, 4, True))[0]
    require(field_count == 4, 'unexpected action field count')
    action_name = image.read(action_name_va, name_len).decode('ascii')
    require(action_name == 'StartFeeTrialAction', 'unexpected action type literal')
    image.expect(0x2bd8013, b'\xb8')
    tag = struct.unpack('<I', image.read(0x2bd8014, 4, True))[0]
    image.expect(0x2bdbb10, b'\x48\x2d')
    bias = struct.unpack('<I', image.read(0x2bdbb12, 4, True))[0]
    require(tag >= bias, 'selected tag precedes execute bias')
    ordinal = tag - bias
    action_table = rip_target(image.read(0x2bd623b, 7, True), 0x2bd623b, b'\x48\x8d\x0d')
    outer_table = rip_target(image.read(0x2bda83c, 7, True), 0x2bda83c, b'\x48\x8d\x05')
    image.expect(0x2bda82d, bytes.fromhex('482d86000000'))
    execute_table = rip_target(image.read(0x2bdbb1f, 7, True), 0x2bdbb1f, b'\x48\x8d\x05')
    format_table = rip_target(image.read(0x2bc9606, 7, True), 0x2bc9606, b'\x48\x8d\x05')
    image.expect(0x2bd6242, bytes.fromhex('486304814801c8ffe0'))
    image.expect(0x2bdbb16, bytes.fromhex('b914000000480f43c8'))
    tables = [['name', 'index', 'table_va', 'slot_va', 'slot_file_offset', 'raw_hex', 'target_va']]
    def add_table(name, table, i, count, expected=None):
        slot, target, raw = table_entry(image, table, i, count)
        if expected is not None:
            require(target == expected, 'selected table target mismatch')
        image.read(target, 1, True)
        tables.append([name, i, hex(table), hex(slot), hex(image.offset(slot, 4)), raw.hex(), hex(target)])
    delayer_field_table = rip_target(image.read(0x1bdd450, 7, True), 0x1bdd450, bytes.fromhex('488d0d'))
    image.expect(0x1bdd457, bytes.fromhex('486304814801c8ffe0'))
    add_table('delayer_delayed_actions_field', delayer_field_table, 0, 7, 0x1bdd460)
    add_table('action_selected', action_table, ordinal, ordinal + 1, 0x2bd7fa7)
    add_table('context_outer_selected', outer_table, ordinal, ordinal + 1, 0x2bdb060)
    add_table('context_execute_selected', execute_table, ordinal, ordinal + 1, 0x2bdc804)
    add_table('context_format_selected', format_table, ordinal, ordinal + 1, 0x2bcb75e)
    require(rel_call(image.read(0x2bd7fc8, 5, True), 0x2bd7fc8) == 0x2117d20,
            'action arm did not call selected payload FDE')
    slot = rip_target(image.read(0x2385647, 6, True), 0x2385647, b'\xff\x15')
    require(image.relative_relocation(slot)[0] == 0x3c18390, 'wrapper relocation does not reach core')
    image.expect(0x2117e9f, bytes.fromhex('83f8'))
    key_kind_count = image.read(0x2117ea1, 1, True)[0] + 1
    image.expect(0x2117ed0, bytes.fromhex('3c'))
    key_value_count = image.read(0x2117ed1, 1, True)[0] + 1
    image.expect(0x2117f2d, bytes.fromhex('4883fe'))
    small_integer_count = image.read(0x2117f30, 1, True)[0] + 1
    image.expect(0x200e0d9, bytes.fromhex('83f8'))
    string_kind_count = image.read(0x200e0db, 1, True)[0] + 1
    for name, lea, count in (('payload_key_kind', 0x2117eb8, key_kind_count),
                             ('payload_key_value', 0x2117ed8, key_value_count),
                             ('payload_small_integer', 0x2117f37, small_integer_count),
                             ('payload_field', 0x2117fcf, field_count),
                             ('string_input_kind', 0x200e0e2, string_kind_count)):
        base = rip_target(image.read(lea, 7, True), lea, b'\x48\x8d\x0d')
        for i in range(count):
            add_table(name, base, i, count)

    fields = [['index', 'descriptor_va', 'file_offset', 'relocation_file_offset',
               'relocation_hex', 'literal_va', 'length', 'literal_hex', 'literal_ascii']]
    field_names = []
    for i in range(field_count):
        va = field_table_va + i * 16
        ptr, reloc_off, reloc = image.relative_relocation(va)
        n = struct.unpack('<Q', image.read(va + 8, 8))[0]
        require(0 < n <= 100, 'unexpected field literal length')
        literal = image.read(ptr, n)
        name = literal.decode('ascii')
        field_names.append(name)
        fields.append([i, hex(va), hex(image.offset(va, 16)), hex(reloc_off), reloc.hex(),
                       hex(ptr), n, literal.hex(), name])
    require(field_names == ['perpAddBaseRate', 'perpCrossBaseRate',
                            'spotAddBaseRate', 'spotCrossBaseRate'], 'unexpected field descriptors')

    # Independently bind each field table arm to its duplicate/missing name,
    # value-decoder call, and selected normal-return output offset. The
    # intervening register/stack transfer is retained in the raw windows.
    routes = [['index', 'field_name', 'arm_va', 'duplicate_branch_va',
               'duplicate_target_va', 'duplicate_name_va', 'missing_name_va',
               'value_call_va', 'value_callee_va', 'output_store_va', 'output_offset', 'store_hex']]
    route_sites = (
        (0x2117ff1, 0x2119204, 0x21184fe, 0x211803d, 0x21188b4),
        (0x21181a5, 0x211931a, 0x2118585, 0x21181f1, 0x21188cf),
        (0x2118075, 0x2119388, 0x2118800, 0x21180c1, 0x21188ee),
        (0x2118108, 0x2119270, 0x211865c, 0x2118157, 0x2118905),
    )
    payload_table = rip_target(image.read(0x2117fcf, 7, True), 0x2117fcf, bytes.fromhex('488d0d'))
    for i, (duplicate, duplicate_lea, missing_lea, value_call, output) in enumerate(route_sites):
        _, arm, _ = table_entry(image, payload_table, i, field_count)
        raw_branch = image.read(duplicate, 6, True)
        _, _, duplicate_target = branch(raw_branch, duplicate)
        dup_name = rip_target(image.read(duplicate_lea, 7, True), duplicate_lea, bytes.fromhex('488d05'))
        missing_name = rip_target(image.read(missing_lea, 7, True), missing_lea, bytes.fromhex('488d05'))
        n = len(field_names[i])
        require(image.read(dup_name, n) == field_names[i].encode('ascii') and
                image.read(missing_name, n) == field_names[i].encode('ascii'), 'field name mismatch')
        callee = rel_call(image.read(value_call, 5, True), value_call)
        require(callee == 0x2121af0, 'field value call mismatch')
        raw_store = image.read(output, 5, True)
        if i == 0:
            require(raw_store[:4] == bytes.fromhex('49891424'), 'unexpected first field store')
            record_offset, store_bytes = 0, raw_store[:4]
        else:
            require(raw_store[0:2] == bytes.fromhex('4989') and raw_store[3] == 0x24,
                    'unexpected field store')
            record_offset, store_bytes = raw_store[4], raw_store
        require(record_offset == 24 * i, 'unexpected field output order')
        routes.append([i, field_names[i], hex(arm), hex(duplicate), hex(duplicate_target),
                       hex(dup_name), hex(missing_name), hex(value_call), hex(callee),
                       hex(output), hex(record_offset), store_bytes.hex()])

    # The four selected length reads and four scalar result stores bind the
    # 24-byte input records to the physical 8-byte result lanes.
    length_sites = ((0x36a554d, bytes.fromhex('488b56'), 3),
                    (0x36a55c6, bytes.fromhex('498b56'), 3),
                    (0x36a563c, bytes.fromhex('498b56'), 3),
                    (0x36a56b3, bytes.fromhex('49837e'), 3))
    output_sites = (0x36a56e4, 0x36a56f2, 0x36a5700, 0x36a5705)
    lane_rows = [['lane', 'field_index', 'field_name', 'length_read_va', 'length_disp',
                  'length_raw_hex', 'output_store_va', 'output_disp', 'output_raw_hex']]
    for lane, ((site, prefix, disp_i), store) in enumerate(zip(length_sites, output_sites)):
        raw = image.read(site, 5 if site == 0x36a56b3 else 4, True)
        require(raw.startswith(prefix), 'unexpected length read')
        displacement = raw[disp_i]
        require(displacement >= 16 and (displacement - 16) % 24 == 0, 'length is not on field stride')
        field = (displacement - 16) // 24
        require(field < field_count, 'field displacement outside descriptor')
        out = image.read(store, 5, True)
        require(out[:3] == bytes.fromhex('f20f11') and out[3] in (0x43, 0x4b),
                'unexpected scalar output store')
        out_disp = out[4]
        require(out_disp == 8 + 8 * lane, 'unexpected result lane position')
        lane_rows.append([lane, field, field_names[field], hex(site), hex(displacement), raw.hex(),
                          hex(store), hex(out_disp), out.hex()])

    stores = [['path', 'site_va', 'file_offset', 'instruction_hex', 'record_offset', 'width', 'immediate']]
    layouts = [[], []]
    for loop_site, primary_site in STORE_SITES:
        for which, site in enumerate((loop_site, primary_site)):
            raw = image.read(site, 7, True)
            off, width, n, imm = decoded_store(raw)
            layouts[which].append((off, width, imm))
            stores.append(['linked' if which == 0 else 'primary', hex(site),
                           hex(image.offset(site, n, True)), raw[:n].hex(), hex(off), width,
                           '' if imm is None else imm])
    require(layouts[0] == layouts[1] and layouts[0][0] == (0, 8, 1), 'write layouts differ')

    # Bind the source stack displacements to each corresponding store in both
    # blocks. Stack producer meanings are inferred separately from the windows.
    require(len(SOURCE_SITES) == len(STORE_SITES) - 1, 'store source count mismatch')
    flow = [['path', 'load_va', 'load_file_offset', 'load_hex', 'stack_offset',
             'load_width', 'store_va', 'record_offset', 'store_width']]
    for source_pair, store_pair in zip(SOURCE_SITES, STORE_SITES[1:]):
        for which, (load_site, store_site) in enumerate(zip(source_pair, store_pair)):
            source = image.read(load_site, 8, True)
            stack_off, load_width, n = decoded_stack_load(source)
            store_off, store_width, _, _ = decoded_store(image.read(store_site, 7, True))
            require(stack_off >= 0, 'negative stack source')
            flow.append(['linked' if which == 0 else 'primary', hex(load_site),
                         hex(image.offset(load_site, n, True)), source[:n].hex(), hex(stack_off),
                         load_width, hex(store_site), hex(store_off), store_width])

    # Previously studied state decoder context: decode only the eight actual
    # load/store pairs transferring its staged ActionDelayer into the result.
    state_copies = [['load_va', 'load_file_offset', 'load_hex', 'stack_offset',
                     'store_va', 'store_file_offset', 'store_hex', 'output_offset', 'width']]
    state_sites = ((0x185d881, 0x185d8a1), (0x185d889, 0x185d8a8),
                   (0x185d891, 0x185d8af), (0x185d899, 0x185d8b6),
                   (0x185d8bd, 0x185d8c5), (0x185d8cc, 0x185d8d4),
                   (0x185d8db, 0x185d8e3), (0x185d8ea, 0x185d8f2))
    for i, (load_site, store_site) in enumerate(state_sites):
        load = image.read(load_site, 8, True)
        store = image.read(store_site, 7, True)
        stack, output, width = state_copy(load, store)
        require(stack == 0x848 + 16 * i and output == 0x25a0 + 16 * i and
                width == (8 if i == 7 else 16), 'non-contiguous context state copy')
        state_copies.append([hex(load_site), hex(image.offset(load_site, 8, True)), load.hex(),
                             hex(stack), hex(store_site), hex(image.offset(store_site, 7, True)),
                             store.hex(), hex(output), width])

    immediates = [['name', 'site_va', 'instruction_hex', 'value']]
    def immediate(name, site, prefix, width):
        raw = image.read(site, len(prefix) + width, True)
        require(raw.startswith(prefix), 'unexpected immediate opcode')
        val = int.from_bytes(raw[len(prefix):], 'little')
        immediates.append([name, hex(site), raw.hex(), val])
        return val
    immediate('context_delayed_record_copy_size', 0x18efecb, bytes.fromhex('ba'), 4)
    immediate('delayed_vector_record_stride', 0x26846c4, bytes.fromhex('4969df'), 4)
    immediate('queue_record_stride', 0x3beded3, bytes.fromhex('4869c0'), 4)
    immediate('context_engine_record_stride', 0x2d237e7, bytes.fromhex('4869542440'), 4)
    immediate('context_consumer_record_stride', 0x2704a55, bytes.fromhex('488d93'), 4)
    immediate('context_consumer_action_offset', 0x27049e2, bytes.fromhex('488d73'), 1)
    immediate('context_consumer_action_size', 0x2704a6a, bytes.fromhex('ba'), 4)
    immediate('execute_bias', 0x2bdbb10, bytes.fromhex('482d'), 4)
    immediate('action_success_tag', 0x2bd8013, bytes.fromhex('b8'), 4)
    immediate('action_failure_tag', 0x2bd836e, bytes.fromhex('b8'), 4)
    immediate('payload_field_count', 0x2bd7fc2, bytes.fromhex('41b9'), 4)
    immediate('converter_first_length_reject_at', 0x36a5551, bytes.fromhex('4883fa'), 1)
    immediate('converter_success_word', 0x36a570a, bytes.fromhex('66c703'), 2)
    immediate('converter_length_failure_word', 0x36a5718, bytes.fromhex('66c703'), 2)
    immediate('converter_float_failure_word', 0x36a5789, bytes.fromhex('66b8'), 2)
    immediate('template_failure_word', 0x3c184f3, bytes.fromhex('66b9'), 2)
    immediate('flag_failure_base', 0x3c1861c, bytes.fromhex('8d0c85'), 4)
    immediate('date_fast_ordinal_mask', 0x16290d8, bytes.fromhex('81e1'), 4)
    immediate('date_fast_base_year_limit', 0x16290f8, bytes.fromhex('81c2'), 4)
    immediate('date_fast_preserved_bits', 0x162929c, bytes.fromhex('81e7'), 4)
    immediate('cooldown_days', 0x3c186bb, bytes.fromhex('be'), 4)
    immediate('cooldown_failure_word', 0x3c186c6, bytes.fromhex('66b9'), 2)
    immediate('duration_days', 0x3c186d4, bytes.fromhex('be'), 4)
    immediate('no_improvement_word', 0x3c18a5c, bytes.fromhex('66b9'), 2)
    immediate('success_word', 0x3c18a4b, bytes.fromhex('66b9'), 2)
    immediate('context_wrapper_gate_byte', 0x2385543, bytes.fromhex('80b99a0b0000'), 1)
    immediate('context_wrapper_failure_word', 0x238554c, bytes.fromhex('66c74310'), 2)
    immediate('context_wrapper_identity_failure_word', 0x23855b9, bytes.fromhex('66c74310'), 2)

    literals = [['name', 'va', 'file_offset', 'length', 'raw_hex', 'ascii_or_float']]
    def literal(name, va, n, text=''):
        raw = image.read(va, n)
        literals.append([name, hex(va), hex(image.offset(va, n)), n, raw.hex(), text])
        return raw
    delayer_descriptor_va = rip_target(image.read(0x1bde0c9, 7, True), 0x1bde0c9, bytes.fromhex('488d15'))
    delayer_ptr, delayer_off, delayer_rela = image.relative_relocation(delayer_descriptor_va)
    delayer_len = struct.unpack('<Q', image.read(delayer_descriptor_va + 8, 8))[0]
    require(0 < delayer_len <= 100, 'unexpected delayer descriptor length')
    delayer_raw = image.read(delayer_ptr, delayer_len)
    require(delayer_raw == b'struct ActionDelayer with 6 elements', 'unexpected delayer descriptor')
    delayer_field_va = rip_target(image.read(0x1bddd75, 7, True), 0x1bddd75, bytes.fromhex('488d35'))
    delayer_duplicate_va = rip_target(image.read(0x1bdf195, 7, True), 0x1bdf195, bytes.fromhex('488d05'))
    delayer_missing_va = rip_target(image.read(0x1bde3f7, 7, True), 0x1bde3f7, bytes.fromhex('488d05'))
    require(delayer_field_va == delayer_duplicate_va == delayer_missing_va and
            image.read(delayer_field_va, 15) == b'delayed_actions', 'delayer field mismatch')
    literal('delayer_field', delayer_field_va, 15, 'delayed_actions')
    state_field_va = rip_target(image.read(0x185b3e4, 7, True), 0x185b3e4, bytes.fromhex('488d05'))
    require(branch(image.read(0x1851d9b, 6, True), 0x1851d9b)[2] == 0x185b3e4,
            'state duplicate-field branch mismatch')
    require(image.read(state_field_va, 14) == b'action_delayer', 'state field name mismatch')
    literal('context_state_delayer_field', state_field_va, 14, 'action_delayer')
    descriptor_va = rip_target(image.read(0x18ef0f3, 7, True), 0x18ef0f3, bytes.fromhex('488d15'))
    descriptor_ptr, descriptor_off, descriptor_rela = image.relative_relocation(descriptor_va)
    descriptor_len = struct.unpack('<Q', image.read(descriptor_va + 8, 8))[0]
    require(0 < descriptor_len <= 100, 'unexpected delayed descriptor length')
    descriptor_raw = image.read(descriptor_ptr, descriptor_len)
    require(descriptor_raw == b'struct DelayedAction with 6 elements', 'unexpected delayed type descriptor')
    descriptors = [['name', 'descriptor_va', 'file_offset', 'rela_file_offset', 'rela_hex',
                    'literal_va', 'length', 'literal_hex', 'literal_ascii'],
                   ['action_delayer_type', hex(delayer_descriptor_va), hex(image.offset(delayer_descriptor_va, 16)),
                    hex(delayer_off), delayer_rela.hex(), hex(delayer_ptr), delayer_len,
                    delayer_raw.hex(), delayer_raw.decode('ascii')],
                   ['context_delayed_type', hex(descriptor_va), hex(image.offset(descriptor_va, 16)),
                    hex(descriptor_off), descriptor_rela.hex(), hex(descriptor_ptr), descriptor_len,
                    descriptor_raw.hex(), descriptor_raw.decode('ascii')]]
    literal('action_type', action_name_va, name_len, action_name)
    wire_va = rip_target(image.read(0x2bcb7a0, 7, True), 0x2bcb7a0, bytes.fromhex('488d05'))
    image.expect(0x2bcb7ac, bytes.fromhex('48c7442438'))
    wire_len = struct.unpack('<I', image.read(0x2bcb7b1, 4, True))[0]
    wire = image.read(wire_va, wire_len).decode('ascii')
    require(wire == 'startFeeTrial', 'unexpected contextual formatter literal')
    literal('context_wire_name', wire_va, wire_len, wire)
    for label, site, count in (('missing_field_prefix', 0x4325c4, 16),
                               ('duplicate_field_prefix', 0x43351a, 18)):
        raw = image.read(site, count)
        require(raw[0] + 1 == count, 'unexpected diagnostic prefix length')
        literal(label, site, count, raw[1:].decode('ascii'))
    ff_const = rip_target(image.read(0x3c183d9, 8, True), 0x3c183d9, bytes.fromhex('660f740d'))
    fe_tail = rip_target(image.read(0x3c18414, 8, True), 0x3c18414, bytes.fromhex('660f740d'))
    fe_head = rip_target(image.read(0x3c1841c, 8, True), 0x3c1841c, bytes.fromhex('660f7405'))
    literal('ff_key_tail_mask', ff_const, 16)
    literal('fe_key_tail_mask', fe_tail, 16)
    literal('fe_key_head_mask', fe_head, 16)
    one_va = rip_target(image.read(0x3c18769, 8, True), 0x3c18769, bytes.fromhex('f20f101d'))
    one = image.read(one_va, 8)
    literal('floating_one', one_va, 8, repr(struct.unpack('<d', one)[0]))
    panic_va = rip_target(image.read(0x3c18a65, 7, True), 0x3c18a65, bytes.fromhex('488d3d'))
    image.expect(0x3c18a73, b'\xbe')
    panic_len = struct.unpack('<I', image.read(0x3c18a74, 4, True))[0]
    literal('date_overflow_message', panic_va, panic_len, image.read(panic_va, panic_len).decode('ascii'))

    summary = {
        'schema': 're010-start-fee-trial-115/v1', 'binary_sha256': DIGEST,
        'coordinate_system': 'linked ELF VA and zero-based file offset',
        'selected_fdes': len(funcs) - 1, 'contextual_functions_enrolled_as_selected': 0,
        'selected_windows': sum(1 for w in windows[1:] if w[1] == 'selected'),
        'context_windows': sum(1 for w in windows[1:] if w[1] == 'context'),
        'selected_branch_sites': len(branches) - 1,
        'selected_call_edges': sum(1 for e in edges[1:] if e[1] == 'selected'),
        'context_call_edges': sum(1 for e in edges[1:] if e[1] == 'context'),
        'table_entries': len(tables) - 1, 'field_descriptors': len(fields) - 1,
        'record_store_sites': len(stores) - 1, 'record_source_sites': len(flow) - 1,
        'context_state_copy_sites': len(state_copies) - 1, 'imported_symbol_sites': len(imports) - 1,
        'action_type': action_name, 'internal_tag': hex(tag), 'execute_bias': hex(bias),
        'ordinal': ordinal,
        'scope': 'selected static paths; no target execution, full CFG, Rust implementation or equivalence',
    }
    return {
        'functions.tsv': tsv(funcs), 'bodies.tsv': tsv(bodies), 'windows.tsv': tsv(windows),
        'branches.tsv': tsv(branches), 'calls.tsv': tsv(edges), 'tables.tsv': tsv(tables),
        'fields.tsv': tsv(fields), 'field-routes.tsv': tsv(routes),
        'descriptors.tsv': tsv(descriptors), 'lane-map.tsv': tsv(lane_rows), 'stores.tsv': tsv(stores), 'write-dataflow.tsv': tsv(flow), 'state-copy.tsv': tsv(state_copies), 'imports.tsv': tsv(imports),
        'immediates.tsv': tsv(immediates), 'literals.tsv': tsv(literals),
        'summary.json': (json.dumps(summary, indent=2, sort_keys=True) + '\n').encode(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    image = Image(BINARY.read_bytes())
    generated = build(image)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in generated.items():
        (args.out / name).write_bytes(data)


if __name__ == '__main__':
    main()
