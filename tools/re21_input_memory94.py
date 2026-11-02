#!/usr/bin/env python3
"""Export selected node #94 EVM input/memory paths directly from ELF bytes.

No target bytes are executed. The x86 walker checks instruction lengths and
selected operands; semantic labels and synthetic models remain interpretations.
"""
import argparse
import csv
import hashlib
import io
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

TARGET = ROOT / 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
U256 = (1 << 256) - 1

# Labels are hypotheses grounded by these relocation slots and operations.
# Ends are exclusive decoded FDE ends, checked against both unwind structures.
FUNCTIONS = {
    0x21c27c0: (0x21c2824, 'e376e29d4292c252d2244a26ec349fecaf0b23963af00e90904da82fdd53035f', 'overlap-safe range-copy adapter'),
    0x24e5650: (0x24e56c7, 'cb278a345a727cf79858d07ed0e641aa54a66672cd103f99a9d6a59facb1b86f', 'PUSH1'),
    0x24e6c90: (0x24e6cec, '224f2696839a5ffd0121af63908f0a7929e9112ed7c641eab6242346a4558023', 'PUSH0'),
    0x26bc9e0: (0x26bca94, '14453ca40c12dd34fc549d5844e361256fe4dc42eb7fb66784d55de6f544d228', 'copy-then-zero-pad helper'),
    0x26bd260: (0x26bd413, '76161c3eea1c6fea9079aa5f6074c5f6702efa4eab42aff0557da905986ade90', 'MCOPY'),
    0x26bd420: (0x26bd553, 'dbc68182f392834342d11a9f6f268cc441a39edb9732aa2fa22930d5f105cd82', 'MLOAD'),
    0x26bd5f0: (0x26bd79e, '4dcbc38a5a3329b5e5756f16d7c55bb42d693fa05c5e7ef3e4366c3a207c9554', 'MSTORE'),
    0x26bd7a0: (0x26bd8ae, 'eb1c46a985da96e473fb10d6e60d4a8d25e2d34aaa19885dd2f6030e2b008734', 'MSTORE8'),
    0x26bd8b0: (0x26bdad3, 'a820c7b28244ff7ede4ea1f9290a8b7c7263d7277dbf98b269189a7a9def04a2', 'CALLDATACOPY'),
    0x26bdae0: (0x26bdbb3, 'ae9a90f39db5ce8001c45b8b3af3115cd0c6b7cfdbdb5f8ca8f4f2d66a856015', 'CALLDATALOAD'),
    0x26bdbc0: (0x26bdc29, '112ed2ac8e11edcc69da844e71409349f8434ca732edff460f832c46dc092396', 'CALLDATASIZE'),
    0x26bdc30: (0x26bdddb, 'ac0552be762e3af1570faa2bdfcf32f4bd402d29f4e20c395110a72818472876', 'RETURNDATACOPY'),
    0x26bdf10: (0x26bdf7c, '558a9ac08be7d80fd26b696eeca35dd2c0bab93216a1a320ee63a96539364ee1', 'RETURNDATASIZE'),
    0x26be730: (0x26bea52, '1cf433b09a9a8caf59981328b526da36d847e48dec6c89e4c1cf9db24bed138a', 'return result assembly and publication'),
    0x26beaf0: (0x26beafa, '7a4f36b01fd6c6a92ef27efe01c92c8aefcd617826dc60ed11234cabb3684ae9', 'RETURN'),
    0x276e120: (0x276e174, 'eb6c213376af9541d16dc8700ec8cf2c3de76a7edcb993ff43e4d0861499fb84', 'result callback adapter'),
    0x279e770: (0x279e9ca, '7ec5c45b3b8350a8391d3f4ff268a33d0964c098ea2b5795870ac522282dff75', 'creation-result gates and code installation'),
    0x2788050: (0x2788217, '19aa1e37b82eba3ca9f3bbb3399bc44b5fa0f29639d7fc6acfe2114415e1dbd5', 'journal and account code replacement'),
    0x26bcaa0: (0x26bcc51, '0adf902306216e4301e91e71d84ce28a3a4a92cfecb74861ee6c77fce9fecafa', 'owned code preparation and zero padding'),
}
TABLE_VA = 0x56ac788
OPCODES = {
    0x35: 0x26bdae0, 0x36: 0x26bdbc0, 0x37: 0x26bd8b0,
    0x3d: 0x26bdf10, 0x3e: 0x26bdc30, 0x51: 0x26bd420,
    0x52: 0x26bd5f0, 0x53: 0x26bd7a0, 0x5e: 0x26bd260,
    0x5f: 0x24e6c90, 0x60: 0x24e5650, 0xf3: 0x26beaf0,
}
# Indirect symbols and the previously researched growth callback are boundaries.
# 6=R_X86_64_GLOB_DAT and 8=R_X86_64_RELATIVE on this ELF.
SLOTS = {
    0x576dfe0: (6, 'memcpy', 0),
    0x576e0e0: (6, 'memmove', 0),
    0x576e1f8: (6, 'memset', 0),
    0x576dfb8: (8, '', 0x1346068),
    0x576dfd8: (8, '', 0x54c06b0),
    0x576e020: (8, '', 0x1345e2a),
    0x576e098: (8, '', 0x157b810),
    0x576e118: (8, '', 0x157b480),
    0x576e150: (8, '', 0x157b520),
    0x5773f40: (8, '', 0x4e8fcb0),
    0x56bfb88: (8, '', 0x276e120),
    0x5773270: (8, '', 0x4e7c4e0),
    0x5773278: (8, '', 0x4ea4990),
    0x5774718: (8, '', 0x4e8e8d0),
    0x576e010: (8, '', 0x54c8cb0),
    0x576e1b0: (8, '', 0x157b4a0),
    0x576e470: (8, '', 0x157a9f0),
}

# Individually reviewed byte windows; endpoints must be instruction boundaries.
# Together with complete body bytes, these expose the control/data-flow evidence.
WINDOWS = [
    ('push1-charge-stack-and-byte', 0x24e5650, 0x24e56c7),
    ('push0-charge-and-stack', 0x24e6c90, 0x24e6cec),
    ('input-copy-three-pops', 0x26bd8bb, 0x26bd936),
    ('input-copy-charge-and-zero', 0x26bd936, 0x26bd980),
    ('input-copy-offsets-and-growth-check', 0x26bd980, 0x26bd9c0),
    ('input-copy-clamp-and-memcpy', 0x26bd9c0, 0x26bda0c),
    ('input-copy-zero-pad', 0x26bda0c, 0x26bda5b),
    ('input-copy-growth-and-failures', 0x26bda5b, 0x26bdad3),
    ('input-load-charge-and-stack', 0x26bdae0, 0x26bdb20),
    ('input-load-zero-clamp-copy', 0x26bdb20, 0x26bdb79),
    ('input-load-word-stores', 0x26bdb81, 0x26bdbb3),
    ('input-size-charge-push', 0x26bdbc0, 0x26bdc29),
    ('return-copy-three-pops', 0x26bdc30, 0x26bdcb4),
    ('return-copy-charge-source-bounds', 0x26bdcb4, 0x26bdd2a),
    ('return-copy-destination-growth', 0x26bdd2a, 0x26bdd84),
    ('return-copy-growth-and-failure', 0x26bdd84, 0x26bdddb),
    ('return-size-charge-push', 0x26bdf10, 0x26bdf7c),
    ('copy-helper-clamp-and-copy', 0x26bc9e0, 0x26bca29),
    ('copy-helper-zero-tail-and-checks', 0x26bca29, 0x26bca94),
    ('mload-charge-stack', 0x26bd420, 0x26bd489),
    ('mload-memory-and-word-stores', 0x26bd489, 0x26bd503),
    ('mload-growth-and-errors', 0x26bd503, 0x26bd553),
    ('mstore-charge-pop-and-check', 0x26bd5f0, 0x26bd679),
    ('mstore-slice-and-byte-shuffle', 0x26bd679, 0x26bd742),
    ('mstore-growth-and-errors', 0x26bd742, 0x26bd79e),
    ('mstore8-charge-pop-and-check', 0x26bd7a0, 0x26bd81c),
    ('mstore8-byte-and-memory', 0x26bd81c, 0x26bd867),
    ('mstore8-growth-and-errors', 0x26bd867, 0x26bd8ae),
    ('mcopy-pop-charge', 0x26bd260, 0x26bd324),
    ('mcopy-bounds-and-tailcall', 0x26bd324, 0x26bd3a1),
    ('mcopy-growth-errors', 0x26bd3a1, 0x26bd413),
    ('mcopy-adapter-range-and-memmove', 0x21c27c0, 0x21c27ec),
    ('mcopy-adapter-bounds-errors', 0x21c27ec, 0x21c2824),
    ('return-opcode-adapter', 0x26beaf0, 0x26beafa),
    ('return-two-pop-and-size', 0x26be730, 0x26be7a5),
    ('return-zero-size-and-growth', 0x26be7a5, 0x26be823),
    ('return-buffer-allocation-and-copy', 0x26be823, 0x26be8d0),
    ('return-status-and-action', 0x26be8d0, 0x26be955),
    ('return-growth-and-error-branches', 0x26be964, 0x26be9d5),
    ('return-unwind-cleanup', 0x26be9d5, 0x26bea52),
    ('result-callback-adapter', 0x276e120, 0x276e174),
    ('creation-status-and-prefix', 0x279e770, 0x279e7e6),
    ('creation-size-and-gas-gates', 0x279e7e6, 0x279e84d),
    ('creation-depth-and-preparation', 0x279e84d, 0x279e8c1),
    ('creation-install-and-result', 0x279e8c1, 0x279e963),
    ('creation-failures-and-unwind', 0x279e963, 0x279e9ca),
    ('code-preparation-tag-copy', 0x26bcaa0, 0x26bcae4),
    ('code-preparation-size-and-allocation', 0x26bcae4, 0x26bcb48),
    ('code-preparation-zero-tail', 0x26bcb48, 0x26bcb90),
    ('code-preparation-publication', 0x26bcb90, 0x26bcbea),
    ('code-preparation-failure-and-unwind', 0x26bcbea, 0x26bcc51),
    ('account-hash-and-lookup', 0x2788050, 0x27880ab),
    ('account-flag-and-journal2', 0x27880ab, 0x2788115),
    ('account-journal9-and-hash', 0x2788115, 0x2788169),
    ('account-drop-and-publish-code', 0x2788169, 0x27881a6),
    ('account-failure-and-unwind', 0x27881a6, 0x2788217),
]

# Each operand is decoded at a known instruction: name, VA, opcode prefix,
# width and independently reviewed expected value. No disassembler text is read.
OPERANDS = [
    ('stack_count', 0x26bd8bb, '4c8b9f', 4, 0x128),
    ('stack_pointer', 0x26bd8d4, '4c8bb7', 4, 0x120),
    ('input_pointer', 0x26bd9eb, '480377', 1, 0x48),
    ('input_length', 0x26bd9c0, '488b47', 1, 0x50),
    ('memory_pointer', 0x26bd9ef, '4c8ba7', 4, 0xe8),
    ('memory_window_start', 0x26bd9f6, '4c03a7', 4, 0x110),
    ('memory_window_end', 0x26bd9a3, '488b87', 4, 0xf0),
    ('gas_remaining', 0x26bd958, '4c8b9f', 4, 0x1e0),
    ('copy_round_up_addend', 0x26bd93d, '4983c3', 1, 0x1f),
    ('copy_round_up_shift', 0x26bd94c, '49c1ef', 1, 5),
    ('copy_base_charge', 0x26bd954, '4983c7', 1, 3),
    ('return_pointer', 0x26bdd6c, '4c8b87', 4, 0x1b8),
    ('return_length', 0x26bdd09, '4c8b8f', 4, 0x1c0),
    ('return_mode', 0x26bdd15, '80bf', 4, 0x1f0),
    ('status_offset', 0x26bd964, 'c687', 4, 0x1f3),
    ('status_gas', 0x26bd964, 'c687f3010000', 1, 0x50),
    ('status_memory_growth', 0x26bda89, 'c687f3010000', 1, 0x51),
    ('status_range', 0x26bd92a, 'c687f3010000', 1, 0x54),
    ('status_stack_underflow', 0x26bd8c8, 'c687f3010000', 1, 0x5b),
    ('status_stack_overflow', 0x24e5677, 'c687f3010000', 1, 0x5c),
    ('status_return_bounds', 0x26bdd1e, 'c687f3010000', 1, 0x5d),
    ('push1_charge_signed_byte', 0x24e565d, '4883c0', 1, 0xfd),
    ('push0_charge_signed_byte', 0x24e6c9d, '4883c0', 1, 0xfe),
    ('program_counter', 0x24e5687, '488b8f', 4, 0x1d0),
    ('stack_word_shift', 0x24e5699, '48c1e0', 1, 5),
    ('push1_stack_limit_minus_one', 0x24e566f, '483d', 4, 0x3ff),
    ('push0_stack_limit', 0x24e6caf, '483d', 4, 0x400),
    ('input_load_size', 0x26bdb4e, 'ba', 4, 0x20),
    ('return_status', 0x26beaf0, 'be', 4, 2),
    ('return_action_offset', 0x26be91c, '488d9f', 4, 0x150),
    ('return_action_tag_offset', 0x26be94e, '4188ae', 4, 0x188),
    ('create_result_status_offset', 0x279e7ab, '8079', 1, 0x38),
    ('create_result_status_limit', 0x279e7ab, '807938', 1, 5),
    ('create_result_length_offset', 0x279e7b1, '498b4e', 1, 0x10),
    ('create_forbidden_first_byte', 0x279e7be, '8038', 1, 0xef),
    ('create_default_code_cap', 0x279e7ed, 'b8', 4, 0x6000),
    ('create_cap_override_flag', 0x279e7f2, '80bf', 4, 0x110),
    ('create_cap_override_value', 0x279e7fb, '488b87', 4, 0x118),
    ('create_cost_per_byte', 0x279e81d, 'ba', 4, 0xc8),
    ('create_prefix_error_status', 0x279e7c3, '40b5', 1, 0x63),
    ('create_size_error_status', 0x279e807, '40b5', 1, 0x62),
    ('create_gas_error_status', 0x279e83a, '40b5', 1, 0x50),
    ('create_success_status', 0x279e8c4, '40b5', 1, 2),
    ('create_result_gas_offset', 0x279e82e, '4d8b56', 1, 0x28),
    ('create_context_depth_offset', 0x279e854, '488b86', 4, 0xa8),
    ('code_padding_bytes', 0x26bcb07, '4983c6', 1, 0x21),
    ('account_flags_offset', 0x27880bb, 'f683', 4, 0xb0),
    ('account_flag_mask', 0x27880bb, 'f683b0000000', 1, 4),
    ('journal_flag_tag', 0x27880f2, 'c60411', 1, 2),
    ('journal_code_tag', 0x278813b, 'c60411', 1, 9),
    ('account_digest_low_offset', 0x2788165, '0f1143', 1, 0x68),
    ('account_digest_high_offset', 0x2788161, '0f114b', 1, 0x78),
    ('mload_width', 0x26bd491, '4883c0', 1, 0x20),
    ('mstore_width', 0x26bd67c, '4883c6', 1, 0x20),
    ('mstore_byte_shuffle_dword', 0x26bd6db, '660f70c9', 1, 0x4e),
    ('mstore_byte_shuffle_low', 0x26bd6e0, 'f20f70c9', 1, 0x1b),
    ('mstore_byte_shuffle_high', 0x26bd6e5, 'f30f70c9', 1, 0x1b),
]

# A bounded, human-reviewed subset; each row is verified against decoded bytes.
# The semantic labels describe taken/fallthrough interpretation, not reachability.
BRANCHES = [
    ('push1-gas', 0x24e565b, 0x24e567f, 'status-50', 'charge-stored'),
    ('push1-capacity', 0x24e5675, 0x24e5687, 'push-byte', 'status-5c'),
    ('push0-gas', 0x24e6c9b, 0x24e6cbf, 'status-50', 'charge-stored'),
    ('push0-capacity', 0x24e6cb5, 0x24e6cc7, 'push-zero', 'status-5c'),
    ('calldata-load-gas', 0x26bdaeb, 0x26bdb79, 'status-50', 'charge-stored'),
    ('calldata-load-stack', 0x26bdb06, 0x26bdbab, 'status-5b', 'read-word'),
    ('calldata-load-high-offset', 0x26bdb3b, 0x26bdb81, 'zero-word', 'check-input-range'),
    ('calldata-load-end', 0x26bdb48, 0x26bdb81, 'zero-word', 'copy-prefix'),
    ('calldata-copy-stack', 0x26bd8c6, 0x26bd8d4, 'pop-three', 'status-5b'),
    ('calldata-copy-size-width', 0x26bd928, 0x26bd936, 'calculate-charge', 'status-54'),
    ('calldata-copy-gas', 0x26bd962, 0x26bd970, 'charge-stored', 'status-50'),
    ('calldata-copy-zero-size', 0x26bd97a, 0x26bda90, 'return', 'check-offsets'),
    ('calldata-copy-destination-width', 0x26bd986, 0x26bd92a, 'status-54', 'clamp-source-offset'),
    ('calldata-copy-growth', 0x26bd9ba, 0x26bda5b, 'call-growth', 'source-check'),
    ('calldata-copy-source-end', 0x26bd9c7, 0x26bda26, 'zero-fill-all', 'copy-prefix'),
    ('calldata-copy-growth-result', 0x26bda83, 0x26bd9c0, 'source-check', 'status-51'),
    ('return-copy-stack', 0x26bdc44, 0x26bdc52, 'pop-three', 'status-5b'),
    ('return-copy-size-width', 0x26bdca6, 0x26bdcb4, 'calculate-charge', 'status-54'),
    ('return-copy-gas', 0x26bdce0, 0x26bdcee, 'charge-stored', 'status-50'),
    ('return-copy-source-range', 0x26bdd13, 0x26bdd2a, 'check-zero-size', 'check-mode-byte'),
    ('return-copy-mode', 0x26bdd1c, 0x26bdd2a, 'check-zero-size', 'status-5d'),
    ('return-copy-zero-size', 0x26bdd2d, 0x26bddc4, 'return', 'check-destination'),
    ('return-copy-destination-width', 0x26bdd39, 0x26bdca8, 'status-54', 'check-window'),
    ('return-copy-growth-result', 0x26bdda5, 0x26bddbc, 'status-51', 'copy-helper'),
    ('mstore-gas', 0x26bd602, 0x26bd62b, 'status-50', 'charge-stored'),
    ('mstore-stack', 0x26bd61a, 0x26bd63a, 'pop-two', 'status-5b'),
    ('mstore-offset-width', 0x26bd669, 0x26bd679, 'check-window', 'status-54'),
    ('mstore-growth-result', 0x26bd779, 0x26bd66b, 'status-51', 'write-word'),
    ('mcopy-stack', 0x26bd273, 0x26bd281, 'pop-three', 'status-5b'),
    ('mcopy-zero-size', 0x26bd327, 0x26bd3fa, 'return', 'check-offsets'),
    ('mcopy-growth-result', 0x26bd3c9, 0x26bd3f1, 'status-51', 'copy-adapter'),
    ('return-stack', 0x26be749, 0x26be757, 'pop-two', 'status-5b'),
    ('return-size-width', 0x26be797, 0x26be7a5, 'check-zero-size', 'status-54'),
    ('return-zero-size', 0x26be7c9, 0x26be8d0, 'publish-empty', 'check-offset'),
    ('return-offset-width', 0x26be7da, 0x26be7f5, 'check-window', 'status-54'),
    ('return-allocation-null', 0x26be865, 0x26be9cb, 'allocation-failure', 'copy-output'),
    ('return-growth-result', 0x26be98c, 0x26be823, 'continue', 'status-51'),
    ('creation-status', 0x279e7af, 0x279e7d6, 'rollback-original-status', 'check-code'),
    ('creation-empty', 0x279e7b8, 0x279e7e6, 'skip-prefix-check', 'check-first-byte'),
    ('creation-prefix', 0x279e7c1, 0x279e7e6, 'check-size', 'status-63-rollback'),
    ('creation-cap-select', 0x279e7f9, 0x279e802, 'default-cap', 'configured-cap'),
    ('creation-size', 0x279e805, 0x279e81a, 'calculate-cost', 'status-62-rollback'),
    ('creation-product-overflow', 0x279e828, 0x279e963, 'overflow-failure', 'check-gas'),
    ('creation-gas', 0x279e835, 0x279e84d, 'deduct-and-continue', 'status-50-rollback'),
    ('creation-depth', 0x279e85e, 0x279e972, 'depth-failure', 'decrement-depth'),
    ('creation-code-mode', 0x279e878, 0x279e8a6, 'alternate-code-record', 'prepare-code'),
    ('code-preparation-tag', 0x26bcab5, 0x26bcae4, 'prepare-padded', 'copy-existing'),
    ('code-preparation-length', 0x26bcafe, 0x26bcbea, 'length-failure', 'calculate-allocation'),
    ('code-preparation-layout', 0x26bcb0b, 0x26bcb1d, 'allocate', 'allocation-failure'),
    ('code-preparation-null', 0x26bcb2e, 0x26bcbf9, 'allocation-failure', 'copy-and-pad'),
    ('account-missing', 0x27880a5, 0x27881a6, 'missing-account-failure', 'check-journal'),
    ('account-journal-missing', 0x27880b5, 0x27881af, 'missing-journal-failure', 'check-flag'),
    ('account-flag', 0x27880ca, 0x2788115, 'skip-first-journal', 'journal-flag'),
    ('account-existing-code', 0x278816c, 0x2788176, 'publish-code', 'drop-old-code'),
]


def require(value, message):
    if not value:
        raise ValueError(message)


def check_digest(data, expected=TARGET_SHA256):
    digest = hashlib.sha256(data).hexdigest()
    require(digest == expected, 'target SHA-256 mismatch')
    return digest


def file_offset(secs, va, size, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0,
            'invalid address range')
    matches = [s for s in secs if s['type'] != 8
               and (not executable or s['flags'] & 4)
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(matches) == 1, 'unmapped, NOBITS or ambiguous file range')
    return matches[0]['offset'] + va - matches[0]['address']


def read_va(data, secs, va, size, executable=False):
    off = file_offset(secs, va, size, executable)
    raw = bytes(data[off:off + size])
    require(len(raw) == size, 'truncated file range')
    return raw


def operand(data, secs, site, prefix, width):
    prefix = bytes.fromhex(prefix)
    raw = read_va(data, secs, site, len(prefix) + width, True)
    require(raw.startswith(prefix), 'unexpected operand opcode')
    return int.from_bytes(raw[len(prefix):], 'little'), raw


def instruction(code, pos):
    """Restricted x86-64 length/operand reader; not a semantic interpreter."""
    start = pos
    prefixes = []

    def take(n):
        nonlocal pos
        require(n > 0 and pos + n <= len(code), 'truncated instruction')
        out = code[pos:pos + n]
        pos += n
        require(pos - start <= 15, 'oversized instruction')
        return out

    while pos < len(code) and (code[pos] in (0x66, 0x2e, 0x64, 0x65, 0xf0, 0xf2, 0xf3)
                               or 0x40 <= code[pos] <= 0x4f):
        prefixes.append(take(1)[0])
    rex = next((p for p in reversed(prefixes) if 0x40 <= p <= 0x4f), 0)
    word = 2 if 0x66 in prefixes else 4
    op = take(1)[0]
    opcode = [op]
    kind, immediate, relative, needs_modrm = 'ordinary', 0, False, False
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        immediate = 4 if op in (0xe8, 0xe9) else 1
        relative = True
        kind = 'call' if op == 0xe8 else 'jump' if op in (0xe9, 0xeb) else 'conditional'
    elif op in (0xc3, 0xcc):
        kind = 'return' if op == 0xc3 else 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99):
        pass
    elif 0xb0 <= op <= 0xb7 or op in (0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c, 0xa8, 0x6a):
        immediate = 1
    elif 0xb8 <= op <= 0xbf:
        immediate = 8 if rex & 8 else word
    elif op in (0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d, 0xa9, 0x68):
        immediate = word
    elif op == 0x0f:
        op2 = take(1)[0]
        opcode.append(op2)
        if 0x80 <= op2 <= 0x8f:
            relative, immediate, kind = True, 4, 'conditional'
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f or op2 in
              (0x10, 0x11, 0x1f, 0x28, 0x29, 0x54, 0x55, 0x56, 0x57,
               0x60, 0x61, 0x62, 0x67, 0x68, 0x6c, 0x6d, 0x6e, 0x6f,
               0x74, 0x75, 0x76, 0x7e, 0x7f, 0xaf, 0xb0, 0xb1, 0xb6,
               0xb7, 0xbc, 0xbd, 0xbe, 0xbf, 0xc1, 0xd4, 0xd6, 0xd7,
               0xdb, 0xdf, 0xeb, 0xef, 0xfb)):
            needs_modrm = True
        elif op2 in (0x70, 0x71, 0x72, 0x73, 0xba, 0xc2, 0xc4, 0xc5, 0xc6):
            needs_modrm, immediate = True, 1
        else:
            raise ValueError('unsupported two-byte opcode')
    elif op in (0x80, 0x83, 0xc0, 0xc1, 0xc6, 0x6b):
        needs_modrm, immediate = True, 1
    elif op in (0x81, 0xc7, 0x69):
        needs_modrm, immediate = True, word
    elif op in (0xf6, 0xf7, 0xfe, 0xff, 0x63, 0x84, 0x85, 0x86, 0x87,
                0x88, 0x89, 0x8a, 0x8b, 0x8d, 0xd0, 0xd1, 0xd2, 0xd3) or (
                op < 0x40 and op % 8 < 4):
        needs_modrm = True
    else:
        raise ValueError('unsupported opcode')
    row = {'kind': kind, 'opcode': bytes(opcode).hex()}
    rip_pos = None
    if needs_modrm:
        mr = take(1)[0]
        mod, reg, rm = mr >> 6, (mr >> 3) & 7, mr & 7
        row['modrm'] = mr
        if op == 0xff and reg in (2, 4):
            row['kind'] = 'indirect-call' if reg == 2 else 'indirect-jump'
        if op in (0xf6, 0xf7) and reg == 0:
            immediate = 1 if op == 0xf6 else word
        displacement = 0
        if mod != 3 and rm == 4:
            sib = take(1)[0]
            row['sib'] = sib
            if mod == 0 and sib & 7 == 5:
                displacement = 4
        elif mod == 0 and rm == 5:
            displacement, rip_pos = 4, pos
        if mod in (1, 2):
            displacement = 1 if mod == 1 else 4
        if displacement:
            row['displacement'] = int.from_bytes(take(displacement), 'little', signed=True)
    if immediate:
        raw = take(immediate)
        row['immediate'] = int.from_bytes(raw, 'little')
        if relative:
            row['target_offset'] = pos + int.from_bytes(raw, 'little', signed=True)
    if rip_pos is not None:
        row['rip_offset'] = pos + struct.unpack_from('<i', code, rip_pos)[0]
    if row['kind'] == 'conditional':
        row['condition'] = opcode[-1] & 15
    row['size'] = pos - start
    row['raw'] = bytes(code[start:pos]).hex()
    return row


def decode(code, base):
    rows, pos = [], 0
    while pos < len(code):
        try:
            row = instruction(code, pos)
        except (ValueError, IndexError, struct.error) as error:
            raise ValueError(f'instruction at {base + pos:#x}: {error}') from error
        row['va'] = base + pos
        for old, new in (('target_offset', 'target'), ('rip_offset', 'rip')):
            if old in row:
                row[new] = base + row.pop(old)
        rows.append(row)
        pos += row['size']
    boundaries = {row['va'] for row in rows}
    for row in rows:
        if 'target' in row and base <= row['target'] < base + len(code):
            require(row['target'] in boundaries, 'branch into instruction')
    return rows


def relocations(data, secs, wanted):
    names = ('.rela.dyn', '.dynsym', '.dynstr')
    matches = [[s for s in secs if s['name'] == name] for name in names]
    require(all(len(rows) == 1 for rows in matches), 'missing or duplicate relocation section')
    rel, sym, strings = (rows[0] for rows in matches)
    require((rel['type'], sym['type'], strings['type']) == (4, 11, 3),
            'unexpected relocation section type')
    require(rel['size'] % 24 == 0 and sym['size'] % 24 == 0, 'bad relocation size')
    out = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in wanted:
            continue
        require(slot not in out, 'duplicate relocation')
        index, typ = info >> 32, info & 0xffffffff
        name = ''
        symbol_raw = b''
        if index:
            symoff = sym['offset'] + index * 24
            require(symoff + 24 <= sym['offset'] + sym['size'], 'symbol outside table')
            symbol_raw = bytes(data[symoff:symoff + 24])
            name_index = struct.unpack_from('<I', symbol_raw)[0]
            require(name_index < strings['size'], 'symbol name outside table')
            first = strings['offset'] + name_index
            last = data.find(b'\0', first, strings['offset'] + strings['size'])
            require(last >= 0, 'unterminated symbol')
            name = bytes(data[first:last]).decode('ascii')
        out[slot] = {'slot': slot, 'type': typ, 'index': index, 'addend': addend,
                     'symbol': name, 'file_offset': off,
                     'raw': bytes(data[off:off + 24]).hex(), 'symbol_raw': symbol_raw.hex()}
    require(set(out) == set(wanted), 'missing relocation')
    return out


def checked_relative(relocs, slot, target):
    row = relocs[slot]
    require(row['type'] == 8 and row['index'] == 0 and row['addend'] == target,
            'relative relocation mismatch')
    return row


def checked_slot(relocs, slot, typ, symbol, addend):
    row = relocs[slot]
    require(row['type'] == typ and row['symbol'] == symbol and row['addend'] == addend,
            'indirect relocation mismatch')
    require((row['index'] == 0) == (symbol == ''), 'relocation symbol mismatch')
    return row


def tsv(rows, keys):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().encode('ascii')


def js(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode('ascii')


def shuffle_word_lanes(dword_imm, low_imm, high_imm):
    """Project the selected MSTORE SSE shuffle onto 32 symbolic byte lanes."""
    def reverse_half(half):
        low = list(half[:8])
        high = list(half[8:])

        def words(values):
            pairs = [values[i:i + 2] for i in range(0, 8, 2)]
            pairs = [pairs[(dword_imm >> (2 * j)) & 3] for j in range(4)]
            ordered = [v for pair in pairs for v in pair]
            return ([ordered[(low_imm >> (2 * j)) & 3] for j in range(4)]
                    + [ordered[4 + ((high_imm >> (2 * j)) & 3)] for j in range(4)])
        # PUNPCKHBW + PACKUSWB places the high eight lanes first.
        return words(high) + words(low)
    lanes = list(range(32))
    return reverse_half(lanes[16:]) + reverse_half(lanes[:16])


def _u256(value):
    require(type(value) is int and 0 <= value <= U256, 'invalid synthetic word')
    return value


def copy_charge(length):
    _u256(length)
    require(length <= U64, 'length does not fit u64')
    rounded = min(U64, length + 31)
    return 3 + 3 * (rounded >> 5)


def _grow(mem, end, gas):
    """Bounded conventional-growth projection; external helper may have more exits."""
    require(0 <= end <= 1_000_000 and len(mem) % 32 == 0,
            'outside bounded synthetic memory domain')
    if end <= len(mem):
        return bytearray(mem), gas, True
    old_words, new_words = len(mem) // 32, (end + 31) // 32
    cost = lambda w: 3 * w + w * w // 512
    charge = cost(new_words) - cost(old_words)
    if gas < charge:
        return bytearray(mem), gas, False
    out = bytearray(mem)
    out.extend(bytes(new_words * 32 - len(out)))
    return out, gas - charge, True


def copy_projection(source, memory, dst, src, length, gas, stack_count=3,
                    *, return_mode=None):
    """Synthetic projection of selected branches, not execution of target code.

    return_mode=None selects input copying; 0 and 1 are the two normalized
    return-buffer flag classes. Growth covers bounded valid buffers only.
    """
    require(isinstance(source, bytes) and isinstance(memory, (bytes, bytearray)), 'invalid buffers')
    dst, src, length = (_u256(v) for v in (dst, src, length))
    require(type(gas) is int and 0 <= gas <= U64, 'invalid gas')
    require(type(stack_count) is int and 0 <= stack_count <= 1024, 'invalid stack count')
    require(return_mode in (None, 0, 1), 'invalid return mode')
    mem = bytearray(memory)
    if stack_count < 3:
        return {'status': 0x5b, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    stack_count -= 3
    if length > U64:
        return {'status': 0x54, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    charge = copy_charge(length)
    if gas < charge:
        return {'status': 0x50, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    gas -= charge
    source_offset = min(src, U64)
    if return_mode is not None:
        source_end = min(U64, source_offset + length)
        if return_mode == 0 and source_end > len(source):
            return {'status': 0x5d, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    if length == 0:
        return {'status': 0, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    if dst > U64:
        return {'status': 0x54, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    end = min(U64, dst + length)
    mem, gas, ok = _grow(mem, end, gas)
    if not ok:
        return {'status': 0x51, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}
    n = min(length, max(0, len(source) - source_offset))
    mem[dst:dst + n] = source[source_offset:source_offset + n]
    mem[dst + n:dst + length] = bytes(length - n)
    return {'status': 0, 'gas': gas, 'stack_count': stack_count, 'memory': bytes(mem)}


def calldata_load(source, offset):
    require(isinstance(source, bytes), 'invalid source')
    _u256(offset)
    if offset > U64 or offset >= len(source):
        return 0
    return int.from_bytes(source[offset:offset + 32].ljust(32, b'\0'), 'big')


def move_projection(memory, dst, src, size):
    """A valid in-bounds overlap case; Python slice copy models memmove."""
    require(isinstance(memory, bytes), 'invalid source')
    require(all(type(v) is int and v >= 0 for v in (dst, src, size)), 'invalid range')
    require(dst + size <= len(memory) and src + size <= len(memory), 'range outside buffer')
    out = bytearray(memory)
    out[dst:dst + size] = memory[src:src + size]
    return bytes(out)


def synthetic_data():
    payload = bytearray((i * 73 + 19) & 255 for i in range(213))
    payload[:4] = (12).to_bytes(4, 'big')
    payload[-1] = 1
    return bytes(payload)


def return_projection(memory, offset, length, gas, stack_count=2):
    """Bounded, normal-return projection of the selected RETURN assembly."""
    require(isinstance(memory, (bytes, bytearray)), 'invalid memory')
    offset, length = _u256(offset), _u256(length)
    require(type(gas) is int and 0 <= gas <= U64, 'invalid gas')
    require(type(stack_count) is int and 0 <= stack_count <= 1024, 'invalid stack count')
    mem = bytearray(memory)
    if stack_count < 2:
        return {'status': 0x5b, 'gas': gas, 'stack_count': stack_count, 'output': None}
    stack_count -= 2
    if length > U64:
        return {'status': 0x54, 'gas': gas, 'stack_count': stack_count, 'output': None}
    if length == 0:
        return {'status': 2, 'action_tag': 2, 'gas': gas, 'stack_count': stack_count, 'output': b''}
    if offset > U64:
        return {'status': 0x54, 'gas': gas, 'stack_count': stack_count, 'output': None}
    mem, gas, ok = _grow(mem, min(U64, offset + length), gas)
    if not ok:
        return {'status': 0x51, 'gas': gas, 'stack_count': stack_count, 'output': None}
    return {'status': 2, 'action_tag': 2, 'gas': gas, 'stack_count': stack_count,
            'output': bytes(mem[offset:offset + length])}


def creation_projection(status, length, first_byte, gas, limit, depth):
    """Bounded scalar projection; journal, hash, allocators and drops are opaque."""
    require(type(status) is int and 0 <= status <= 255, 'invalid status')
    require(all(type(v) is int and 0 <= v <= U64 for v in (length, gas, limit, depth)),
            'invalid creation scalar')
    require(first_byte is None if length == 0 else type(first_byte) is int and 0 <= first_byte <= 255,
            'invalid first byte')
    if status >= 5:
        return {'outcome': 'rollback-original-status', 'status': status, 'gas': gas, 'depth': depth}
    if length and first_byte == 0xef:
        return {'outcome': 'rollback-prefix', 'status': 0x63, 'gas': gas, 'depth': depth}
    if length > limit:
        return {'outcome': 'rollback-size', 'status': 0x62, 'gas': gas, 'depth': depth}
    cost = length * 200
    if cost > U64:
        return {'outcome': 'product-overflow', 'status': None, 'gas': gas, 'depth': depth}
    if cost > gas:
        return {'outcome': 'rollback-gas', 'status': 0x50, 'gas': gas, 'depth': depth}
    gas -= cost
    if depth == 0:
        return {'outcome': 'depth-failure-after-charge', 'status': None, 'gas': gas, 'depth': depth}
    return {'outcome': 'conditional-install', 'status': 2, 'gas': gas, 'depth': depth - 1}


def creation_cases():
    examples = [
        ('empty', 2, 0, None, 0, 0x6000, 1),
        ('normal-64', 2, 64, 7, 19991, 0x6000, 1),
        ('gas-exact', 2, 64, 7, 12800, 0x6000, 1),
        ('gas-short', 2, 64, 7, 12799, 0x6000, 1),
        ('prefix-rejected-first', 2, 1, 0xef, 0, 0, 1),
        ('maximum-default-size', 2, 0x6000, 1, 0x6000 * 200, 0x6000, 1),
        ('default-size-too-large', 2, 0x6001, 1, U64, 0x6000, 1),
        ('status-before-prefix', 5, 1, 0xef, 0, 0, 1),
        ('product-overflow', 2, U64 // 200 + 1, 1, U64, U64, 1),
        ('depth-zero', 2, 1, 1, 200, 0x6000, 0),
    ]
    rows = []
    for name, status, length, first, gas, limit, depth in examples:
        result = creation_projection(status, length, first, gas, limit, depth)
        rows.append({'case': name, 'status_in': hex(status), 'length': length,
                     'first_byte': '' if first is None else hex(first), 'gas_in': gas,
                     'size_limit': limit, 'depth_in': depth, 'outcome': result['outcome'],
                     'status_out': '' if result['status'] is None else hex(result['status']),
                     'gas_out': result['gas'], 'depth_out': result['depth']})
    return rows


def return_cases():
    examples = [
        ('output-64', bytes(range(64)), 0, 64, 0, 2),
        ('zero-size-high-offset', b'', U256, 0, 0, 2),
        ('too-wide-size', b'', 0, 1 << 64, 0, 2),
        ('too-wide-offset', b'', 1 << 64, 1, 100, 2),
        ('short-stack', b'', 0, 0, 0, 1),
        ('growth-insufficient', b'', 0, 64, 5, 2),
        ('growth-exact', b'', 0, 64, 6, 2),
    ]
    rows = []
    for name, memory, off, length, gas, count in examples:
        result = return_projection(memory, off, length, gas, count)
        out = result['output']
        rows.append({'case': name, 'memory_length': len(memory), 'offset': hex(off),
                     'length': hex(length), 'gas_in': gas, 'stack_in': count,
                     'status': hex(result['status']), 'action_tag': result.get('action_tag', ''),
                     'gas_out': result['gas'], 'stack_out': result['stack_count'],
                     'output_length': len(out) if out is not None else '',
                     'output_sha256': hashlib.sha256(out).hexdigest() if out is not None else ''})
    return rows


def sample_cases():
    """Small concrete inputs for the projections, explicitly not native runs."""
    payload = synthetic_data()
    cases = [
        ('copy-213-exact-gas', payload, b'', 0, 0, 213, 45, 3, None),
        ('copy-213-growth-gas-short', payload, b'', 0, 0, 213, 44, 3, None),
        ('copy-213-base-gas-short', payload, b'', 0, 0, 213, 23, 3, None),
        ('copy-zero-high-offsets', payload, b'', U256, U256, 0, 3, 3, None),
        ('copy-zero-gas-short', payload, b'', U256, U256, 0, 2, 3, None),
        ('copy-high-length', payload, b'', 0, 0, 1 << 64, 100, 3, None),
        ('copy-high-destination', payload, b'', 1 << 64, 0, 1, 100, 3, None),
        ('copy-high-source-zero-fills', payload, b'', 0, 1 << 64, 4, 100, 3, None),
        ('copy-partial-source-zero-fills', b'abc', b'', 0, 2, 4, 100, 3, None),
        ('copy-stack-short', payload, b'', 0, 0, 213, 100, 2, None),
        ('return-exact-end', b'abcd', b'', 0, 2, 2, 100, 3, 0),
        ('return-over-end-mode-zero', b'abcd', b'', 0, 3, 2, 100, 3, 0),
        ('return-zero-size-past-end-mode-zero', b'abcd', b'', U256, 5, 0, 3, 3, 0),
        ('return-zero-size-past-end-mode-one', b'abcd', b'', U256, 5, 0, 3, 3, 1),
        ('return-over-end-mode-one', b'abcd', b'', 0, 3, 2, 100, 3, 1),
    ]
    rows = []
    for name, source, mem, dst, src, size, gas, stack, mode in cases:
        result = copy_projection(source, mem, dst, src, size, gas, stack, return_mode=mode)
        out = result.pop('memory')
        rows.append({'case': name, 'source_length': len(source), 'dst': hex(dst),
                     'src': hex(src), 'length': hex(size), 'gas_in': gas,
                     'stack_in': stack, 'return_mode': '' if mode is None else mode,
                     'status': hex(result['status']), 'gas_out': result['gas'],
                     'stack_out': result['stack_count'], 'memory_length': len(out),
                     'memory_sha256': hashlib.sha256(out).hexdigest(),
                     'first_bytes_hex': out[:16].hex()})
    return rows


def exception_table(data, secs, frame):
    """Decode bounded ULEB call-site records; action chains remain opaque."""
    if frame['lsda'] is None:
        return [], None
    matches = [s for s in secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(matches) == 1, 'missing exception section')
    sec = matches[0]
    pos = file_offset(secs, frame['lsda'], 1)
    end = sec['offset'] + sec['size']
    require(sec['offset'] <= pos and pos + 2 <= end, 'LSDA outside section')
    beginning = pos
    require(data[pos] == 0xff, 'unsupported landing-base encoding')
    type_encoding = data[pos + 1]
    pos += 2
    type_base = None
    if type_encoding != 0xff:
        require(type_encoding == 0x9b, 'unsupported LSDA type encoding')
        delta, pos = uleb(data, pos, end)
        type_base = pos + delta
        require(type_base <= end, 'type table outside section')
    require(pos < end and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, end)
    limit = pos + length
    require(limit <= end and (type_base is None or limit <= type_base),
            'invalid call-site extent')
    rows, previous_end = [], 0
    while pos < limit:
        row_start = pos
        start, pos = uleb(data, pos, limit)
        size, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        require(start >= previous_end and frame['start'] + start + size <= frame['end'],
                'invalid call-site interval')
        require(not landing or frame['start'] + landing < frame['end'],
                'invalid landing pad')
        previous_end = start + size
        rows.append({'function_va': hex(frame['start']), 'lsda_va': hex(frame['lsda']),
                     'file_offset': hex(row_start), 'start_va': hex(frame['start'] + start),
                     'end_va': hex(frame['start'] + start + size),
                     'landing_va': hex(frame['start'] + landing) if landing else '',
                     'action': action, 'raw': bytes(data[row_start:pos]).hex()})
    header = {'function_va': hex(frame['start']), 'lsda_va': hex(frame['lsda']),
              'file_offset': hex(beginning), 'type_encoding': hex(type_encoding),
              'header_and_sites_hex': bytes(data[beginning:limit]).hex(),
              'limits': 'Action chains and exception types remain opaque.'}
    return rows, header


def collect(data):
    check_digest(data)
    secs, idx = unwind_index(data)
    cies, frames = eh_frame_records(data, secs)
    index = {row['start']: row for row in idx}
    found = {}
    for frame in frames:
        if frame['start'] in FUNCTIONS:
            require(frame['start'] not in found, 'duplicate selected FDE')
            found[frame['start']] = frame
    require(set(found) == set(FUNCTIONS), 'missing selected FDE')
    frows, irows, crows, bodies, uwrows = [], [], [], [], []
    decoded, all_boundaries = {}, {}
    exception_rows, exception_headers = [], []
    for start, (expected_end, digest, role) in sorted(FUNCTIONS.items()):
        frame = found[start]
        require(frame['end'] == expected_end, 'selected FDE end changed')
        require(start in index and index[start]['fde'] == frame['fde'], 'FDE index mismatch')
        end = frame['end']
        off = file_offset(secs, start, end - start, True)
        body = read_va(data, secs, start, end - start, True)
        require(hashlib.sha256(body).hexdigest() == digest, 'function body changed')
        rows = decode(body, start)
        decoded[start] = rows
        all_boundaries[start] = {row['va'] for row in rows} | {end}
        sites, header = exception_table(data, secs, frame)
        for site in sites:
            require(int(site['start_va'], 16) in all_boundaries[start]
                    and int(site['end_va'], 16) in all_boundaries[start],
                    'exception interval not on instruction boundary')
            if site['landing_va']:
                require(int(site['landing_va'], 16) in all_boundaries[start],
                        'landing not on instruction boundary')
        exception_rows.extend(sites)
        if header is not None:
            exception_headers.append(header)
        for row in rows:
            irows.append({'owner_va': hex(start), 'va': hex(row['va']), 'size': row['size'],
                          'kind': row['kind'], 'opcode': row['opcode'], 'raw': row['raw'],
                          'modrm': hex(row['modrm']) if 'modrm' in row else '',
                          'displacement': row.get('displacement', ''),
                          'immediate': hex(row['immediate']) if 'immediate' in row else '',
                          'relative_target': hex(row['target']) if 'target' in row else '',
                          'rip_target': hex(row['rip']) if 'rip' in row else ''})
            if row['kind'] != 'ordinary':
                crows.append({'owner_va': hex(start), 'va': hex(row['va']), 'kind': row['kind'],
                              'condition': hex(row['condition']) if 'condition' in row else '',
                              'target': hex(row['target']) if 'target' in row else '',
                              'rip_target': hex(row['rip']) if 'rip' in row else '', 'raw': row['raw']})
        frows.append({'start_va': hex(start), 'end_va': hex(end), 'size': end - start,
                      'file_offset': hex(off), 'fde_va': hex(frame['fde']),
                      'cie_va': hex(frame['cie']),
                      'lsda_va': '' if frame['lsda'] is None else hex(frame['lsda']),
                      'sha256': digest, 'instruction_rows': len(rows), 'inferred_role': role})
        bodies.append({'start_va': hex(start), 'end_va': hex(end), 'bytes': body.hex()})
        fde_size = int.from_bytes(read_va(data, secs, frame['fde'], 4), 'little') + 4
        cie = cies[frame['cie']]
        cie_size = int.from_bytes(read_va(data, secs, frame['cie'], 4), 'little') + 4
        uwrows.append({'start_va': hex(start), 'fde_va': hex(frame['fde']),
                       'fde_bytes': read_va(data, secs, frame['fde'], fde_size).hex(),
                       'cie_va': hex(frame['cie']), 'cie_bytes': read_va(data, secs, frame['cie'], cie_size).hex(),
                       'cie_augmentation': cie['augmentation'],
                       'lsda_va': None if frame['lsda'] is None else hex(frame['lsda'])})
    reloc_slots = {TABLE_VA + 8 * opcode for opcode in OPCODES} | set(SLOTS)
    relocs = relocations(data, secs, reloc_slots)
    op_rows = []
    for opcode, expected in sorted(OPCODES.items()):
        slot = TABLE_VA + 8 * opcode
        row = checked_relative(relocs, slot, expected)
        op_rows.append({'opcode': hex(opcode), 'slot_va': hex(slot), 'function_va': hex(row['addend']),
                        'relocation_file_offset': hex(row['file_offset']), 'raw_rela': row['raw'],
                        'inferred_name': FUNCTIONS[expected][2]})
    for slot, (typ, symbol, target) in SLOTS.items():
        checked_slot(relocs, slot, typ, symbol, target)
    reloc_rows = [{'slot_va': hex(s), 'type': hex(r['type']), 'symbol_index': r['index'],
                   'symbol': r['symbol'], 'addend': hex(r['addend']),
                   'file_offset': hex(r['file_offset']), 'raw_rela': r['raw'],
                   'symbol_raw': r['symbol_raw']} for s, r in sorted(relocs.items())]
    instruction_by_va = {row['va']: (owner, row) for owner, rows in decoded.items() for row in rows}
    branch_rows = []
    for name, site, expected, taken, fallthrough in BRANCHES:
        require(site in instruction_by_va, 'missing selected branch')
        owner, row = instruction_by_va[site]
        require(row['kind'] == 'conditional' and row['target'] == expected, 'selected branch changed')
        branch_rows.append({'name': name, 'owner_va': hex(owner), 'site_va': hex(site),
                            'condition_nibble': hex(row['condition']), 'taken_va': hex(row['target']),
                            'fallthrough_va': hex(site + row['size']), 'raw': row['raw'],
                            'taken_interpretation': taken, 'fallthrough_interpretation': fallthrough})
    window_rows = []
    for name, start, end in WINDOWS:
        owners = [owner for owner, (limit, _, _) in FUNCTIONS.items() if owner <= start < end <= limit]
        require(len(owners) == 1, 'window outside selected FDE')
        owner = owners[0]
        require(start in all_boundaries[owner] and end in all_boundaries[owner],
                'window endpoint is not an instruction boundary')
        raw = read_va(data, secs, start, end - start, True)
        window_rows.append({'name': name, 'owner_va': hex(owner), 'start_va': hex(start),
                            'end_va': hex(end), 'file_offset': hex(file_offset(secs, start, len(raw), True)),
                            'bytes': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest()})
    field_rows, values = [], {}
    for name, site, prefix, width, expected in OPERANDS:
        owners = [owner for owner, bounds in all_boundaries.items() if site in bounds and site != FUNCTIONS[owner][0]]
        require(len(owners) == 1, 'operand not at selected instruction')
        value, raw = operand(data, secs, site, prefix, width)
        require(value == expected, 'operand value changed')
        values[name] = value
        field_rows.append({'name': name, 'site_va': hex(site), 'value': hex(value),
                           'operand_width': width, 'raw_prefix_operand': raw.hex()})
    # Pin lane-producing vector instructions and the add-three-times sequence.
    pins = {
        0x26bd6cf: '660fefc0660f6fca660f60c8660f70c94ef20f70c91bf30f70c91b660f68d0',
        0x26bd6ee: '660f70d24ef20f70d21bf30f70d21b660f67d1f30f7f1403',
        0x26bcb48: '0f57c0430f11043c430f11443c1043c6443c2000',
        0x26bd706: '660f6fcb660f60c8660f70c94ef20f70c91bf30f70c91b660f68d8660f70c34ef20f70c01bf30f70c01b660f67c1f30f7f440310',
        0x26bd4d4: '498b0c07498b540708498b740710498b440718480fc8480fce480fca480fc9488943e0488973e8488953f048894bf8',
        0x26bd841: '0fb62c01', 0x26bd85e: '40882c03',
        0x26bd950: '4f8d3c7f4983c703',
        0x26bd9c0: '488b47504839c6735d',
        0x26bdd09: '4c8b8fc00100004d39cb7615',
    }
    for site, expected in pins.items():
        require(read_va(data, secs, site, len(bytes.fromhex(expected)), True).hex() == expected,
                'selected semantic shape changed')
    lanes = shuffle_word_lanes(values['mstore_byte_shuffle_dword'],
                               values['mstore_byte_shuffle_low'], values['mstore_byte_shuffle_high'])
    require(lanes == list(reversed(range(32))), 'shuffle does not reverse the word')
    lane_rows = [{'memory_byte': i, 'stack_word_byte': lane} for i, lane in enumerate(lanes)]
    drop_site, landing = 0x26be926, 0x26be9ee
    matching = [r for r in exception_rows if r['function_va'] == hex(0x26be730)
                and int(r['start_va'], 16) <= drop_site < int(r['end_va'], 16)]
    require(len(matching) == 1 and matching[0]['landing_va'] == hex(landing),
            'return action drop landing changed')
    account_drop = 0x2788171
    account_landings = [r for r in exception_rows if r['function_va'] == hex(0x2788050)
                        and int(r['start_va'], 16) <= account_drop < int(r['end_va'], 16)]
    require(len(account_landings) == 1 and account_landings[0]['landing_va'] == hex(0x27881be),
            'account code drop landing changed')
    # The example supplies payload and program bytes, not a target execution.
    payload = synthetic_data()
    base_gas = 100_000
    push1_charge = 256 - values['push1_charge_signed_byte']
    push0_charge = 256 - values['push0_charge_signed_byte']
    after_pushes = base_gas - (push1_charge + 2 * push0_charge)
    sample = copy_projection(payload, b'', 0, 0, len(payload), after_pushes)
    sample_memory = sample.pop('memory')
    require(sample['status'] == 0 and sample_memory[:len(payload)] == payload, 'synthetic example failed')
    program = bytes.fromhex('60d55f5f375f5f60d55f600960fff460405f5f3e60405ff3')
    illustrative_return = bytes((i * 17 + 7) & 255 for i in range(64))
    resume_gas = 20000
    # The illustrative post-call segment executes these five PUSH operations.
    copy_stack_charge = push1_charge + 2 * push0_charge
    return_stack_charge = push1_charge + push0_charge
    # The earlier result-insertion path leaves one result word on the stack.
    resume_stack_count = 1
    resumed = copy_projection(illustrative_return, sample_memory, 0, 0, 64,
                              resume_gas - copy_stack_charge,
                              stack_count=resume_stack_count + 3, return_mode=0)
    require(resumed['status'] == 0 and resumed['gas'] >= return_stack_charge,
            'synthetic return copy failed')
    final = return_projection(resumed['memory'], 0, 64, resumed['gas'] - return_stack_charge,
                              stack_count=resumed['stack_count'] + 2)
    require(final['status'] == 2 and final['output'] == illustrative_return, 'synthetic return failed')
    creation = creation_projection(final['status'], len(final['output']), final['output'][0],
                                   final['gas'], values['create_default_code_cap'], 1)
    require(creation['outcome'] == 'conditional-install', 'synthetic creation failed')
    flow = {
        'kind': 'synthetic illustration, not executed code',
        'assumptions': ['zero-tag opcode table used by earlier interpreter packet',
                        'normal memory growth and memcpy semantics',
                        'prior call-frame and registry packets hold',
                        'the call handler, host, revision and gas gates succeed',
                        'the selected creation-frame callback and normal journal/hash helpers succeed'],
        'program_hex': program.hex(),
        'program_note': 'PUSH1 length; PUSH0 source and destination; CALLDATACOPY; build DELEGATECALL arguments; then RETURNDATACOPY and RETURN',
        'input_length': len(payload), 'first_four_bytes_hex': payload[:4].hex(),
        'last_byte_hex': payload[-1:].hex(), 'input_sha256': hashlib.sha256(payload).hexdigest(),
        'stack_before_delegatecall_bottom_first': [0, 0, program[8], 0, program[11], program[13]],
        'target_stack_word': program[11], 'requested_child_gas': program[13],
        'gas_initial': base_gas, 'gas_after_three_pushes': after_pushes,
        'gas_after_copy_and_modeled_growth': sample['gas'],
        'memory_len_after_copy': len(sample_memory),
        'copied_prefix_sha256': hashlib.sha256(sample_memory[:len(payload)]).hexdigest(),
        'memory_prefix_equals_input': sample_memory[:len(payload)] == payload,
        'synthetic_resume_gas': resume_gas,
        'synthetic_resume_gas_note': 'independent synthetic input; not derived from preceding call or initial gas',
        'synthetic_resume_stack_count': resume_stack_count,
        'synthetic_copy_stack_push_charge': copy_stack_charge,
        'synthetic_return_stack_push_charge': return_stack_charge,
        'synthetic_return_bytes_note': 'fabricated 64-byte payload; not a BLAKE2b output prediction',
        'synthetic_return_sha256': hashlib.sha256(illustrative_return).hexdigest(),
        'synthetic_action_output_sha256': hashlib.sha256(final['output']).hexdigest(),
        'synthetic_action_status': final['status'], 'synthetic_action_tag': final['action_tag'],
        'synthetic_return_copy_gas_after': resumed['gas'],
        'synthetic_return_copy_stack_after': resumed['stack_count'],
        'synthetic_return_action_gas_after': final['gas'],
        'synthetic_return_action_stack_after': final['stack_count'],
        'synthetic_creation_gas_after': creation['gas'], 'synthetic_creation_depth_after': creation['depth'],
        'synthetic_creation_outcome': creation['outcome'],
        'modeled_return': 'subsequent return-buffer bytes are conditional on earlier call and result packets',
    }
    summary = {
        'binary_sha256': TARGET_SHA256,
        'coordinate_system': 'linked ELF virtual addresses before load bias',
        'selected_fde_intervals': len(frows),
        'selected_fde_bytes': sum(row['size'] for row in frows),
        'linear_instruction_rows': len(irows), 'control_rows': len(crows),
        'reviewed_windows': len(window_rows), 'reviewed_branches': len(branch_rows),
        'checked_operand_rows': len(field_rows),
        'selected_opcode_relocations': len(op_rows), 'all_selected_relocations': len(reloc_rows),
        'symbolic_mstore_byte_lanes': len(lane_rows), 'synthetic_branch_examples': len(sample_cases()),
        'exception_call_site_rows': len(exception_rows), 'lsda_tables': len(exception_headers),
        'synthetic_return_examples': len(return_cases()),
        'synthetic_creation_examples': len(creation_cases()),
        'limits': ['linear byte decoding is not proof of reachability',
                   'dynamic memory and prior call/registry/compression boundaries are not closed',
                   'examples are Python arithmetic projections, not target execution'],
    }
    return {
        'functions.tsv': tsv(frows, ['start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'instruction_rows', 'inferred_role']),
        'instructions.tsv': tsv(irows, ['owner_va', 'va', 'size', 'kind', 'opcode', 'raw', 'modrm', 'displacement', 'immediate', 'relative_target', 'rip_target']),
        'failure-branches.tsv': tsv(branch_rows, ['name', 'owner_va', 'site_va', 'condition_nibble', 'taken_va', 'fallthrough_va', 'raw', 'taken_interpretation', 'fallthrough_interpretation']),
        'control.tsv': tsv(crows, ['owner_va', 'va', 'kind', 'condition', 'target', 'rip_target', 'raw']),
        'opcode-map.tsv': tsv(op_rows, ['opcode', 'slot_va', 'function_va', 'relocation_file_offset', 'raw_rela', 'inferred_name']),
        'relocations.tsv': tsv(reloc_rows, ['slot_va', 'type', 'symbol_index', 'symbol', 'addend', 'file_offset', 'raw_rela', 'symbol_raw']),
        'windows.tsv': tsv(window_rows, ['name', 'owner_va', 'start_va', 'end_va', 'file_offset', 'bytes', 'sha256']),
        'operands.tsv': tsv(field_rows, ['name', 'site_va', 'value', 'operand_width', 'raw_prefix_operand']),
        'mstore-lanes.tsv': tsv(lane_rows, ['memory_byte', 'stack_word_byte']),
        'synthetic-creation-cases.tsv': tsv(creation_cases(), ['case', 'status_in', 'length', 'first_byte', 'gas_in', 'size_limit', 'depth_in', 'outcome', 'status_out', 'gas_out', 'depth_out']),
        'synthetic-return-cases.tsv': tsv(return_cases(), ['case', 'memory_length', 'offset', 'length', 'gas_in', 'stack_in', 'status', 'action_tag', 'gas_out', 'stack_out', 'output_length', 'output_sha256']),
        'synthetic-cases.tsv': tsv(sample_cases(), ['case', 'source_length', 'dst', 'src', 'length', 'gas_in', 'stack_in', 'return_mode', 'status', 'gas_out', 'stack_out', 'memory_length', 'memory_sha256', 'first_bytes_hex']),
        'function-bytes.json': js(bodies), 'unwind.json': js(uwrows),
        'exception-sites.tsv': tsv(exception_rows, ['function_va', 'lsda_va', 'file_offset', 'start_va', 'end_va', 'landing_va', 'action', 'raw']),
        'exception-headers.json': js(exception_headers),
        'synthetic-flow.json': js(flow), 'summary.json': js(summary),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    evidence = collect(TARGET.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in sorted(evidence.items()):
        (args.out / name).write_bytes(content)
    print('generated {} evidence files'.format(len(evidence)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('re21_input_memory94: {}'.format(error), file=sys.stderr)
        raise SystemExit(1)
