"""RE-015: collect selected node 115 configuration and checkpoint-pruning evidence.

Reads the authenticated ELF only. Selected instruction starts are manual anchors;
this is not an x86 decoder or an instruction/function census.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = TOOLS.parent
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA115 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SHA94 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64_MAX = (1 << 64) - 1

# Names describe observed roles, not recovered source symbols. Extents are FDE ranges.
FRAME_SPECS = [
    ('outer_callback', 0x2dd4f10, 0x2dd50cd, '866f54c1d0f22e82fff69bdc2264eb03ce6d21ce135986d5a6147011234c2bd5'),
    ('maintenance', 0x4d98c40, 0x4d98f80, 'd2c382e08d58ae6fa00005ab7e06e2048f4ff83fd5e17981171fa9968f4da36f'),
    ('count_prune', 0x38c51f0, 0x38c56e4, '9746fa874dd89ce40af6a18511af67984172e094bb41851fa823f36e77d03902'),
    ('archive_prune', 0x38c56f0, 0x38c6589, 'a79ea0d56c65ace15c7dbdb88767bcee3a423704db2da12773ea02348d3579c5'),
    ('checkpoint_reader', 0x4468e30, 0x44699c0, '421edcae1144c573c8fddfa47a31632e1c6b62fb54142b847d013f66f9cba42e'),
    ('selected_path_collection', 0x3d5dab0, 0x3d5dc96, 'fdce0594a7d88ecbeb136ab70ad4c51e61c343a8ad873eaf3931b0cb3f7b0081'),
    ('skip_and_copy', 0x37c1330, 0x37c1473, '76b37100a2e25f0d97935fcb2802afdb94445e7eeef9ccc700fee71704b0afdc'),
    ('small_order', 0x436cb90, 0x436cc42, '3c15a485980b0fea3917dc4c08ae8e0dc64e3d2326905c7394bb3d576959c15f'),
    ('large_order_boundary', 0x36f2690, 0x36f27b4, '2a4347e8b6c308752f4a72231bb26a6727920d0de4ec4e4f6c235fb3eb261b94'),
    ('large_merge', 0x3e3f6f0, 0x3e3fd4e, '25bc17f1f46c33221cca76658d0031ac5b888dcb8643c828d327f23b8046ceed'),
    ('large_partition', 0x42edcb0, 0x42ee1b9, '0d0cfe35e979127fc3f6f75fcb2964a78f88d71cf8c3744a6f1753764c4e633b'),
    ('archive_selection', 0x3d5dca0, 0x3d5dfb0, '9a8f424f5ce8ab7e5a285f82cefd3a165429b03d0af75d1af800587c49871f7d'),
    ('name_error_gate', 0x1564120, 0x156421d, 'd64d3b5a0e66c286866bc5fedb85f56d22ffb5061ed760001a807a9c5354c580'),
    ('marker_formatter', 0x1696b90, 0x1696d23, '70860a23418080560f1cc3e15666f3076a5f3d427d408c0c514f67e78869953f'),
]

# These are selected instruction-aligned windows, not whole-function decoded CFGs.
WINDOWS = [
    ('outer_input_and_call', 0x2dd4f21, 0x2dd4f84),
    ('outer_completion', 0x2dd4f87, 0x2dd5002),
    ('outer_unwind_completion', 0x2dd5011, 0x2dd506a),
    ('mode_and_archive', 0x4d98c5d, 0x4d98cbe),
    ('archive_error_and_continuation', 0x4d98cbe, 0x4d98d51),
    ('count_mode', 0x4d98d51, 0x4d98d68),
    ('count_error_and_continuation', 0x4d98d68, 0x4d98df6),
    ('second_phase_and_release', 0x4d98e7a, 0x4d98eb8),
    ('date_failure', 0x4d98eb8, 0x4d98ee8),
    ('name_guard', 0x1564129, 0x1564145),
    ('name_gate_cleanup', 0x15641be, 0x156421d),
    ('count_reader_and_sort_split', 0x38c5217, 0x38c5263),
    ('count_collection_handoff', 0x38c5263, 0x38c52b0),
    ('count_remove_loop', 0x38c548a, 0x38c5537),
    ('count_return_and_order_dispatch', 0x38c5537, 0x38c5668),
    ('skip_count', 0x37c133e, 0x37c139c),
    ('skip_tail_and_copy', 0x37c13cc, 0x37c1455),
    ('collect_call_and_output', 0x3d5dab0, 0x3d5db2d),
    ('collect_publish', 0x3d5dbe1, 0x3d5dc01),
    ('small_order_compare', 0x436cbe7, 0x436cbf1),
    ('small_order_loop_compare', 0x436cc2a, 0x436cc40),
    ('large_order_dispatch', 0x36f2690, 0x36f275d),
    ('large_forward_merge', 0x3e3fc80, 0x3e3fcac),
    ('large_backward_merge', 0x3e3fc10, 0x3e3fc41),
    ('large_partition_key', 0x42eddf0, 0x42ede0a),
    ('large_partition_small_handoff', 0x42ee154, 0x42ee16a),
    ('reader_root_and_error', 0x4468e50, 0x4468f3c),
    ('reader_candidate_parse', 0x4469166, 0x4469250),
    ('reader_marker_checks', 0x4469250, 0x446932b),
    ('reader_accepted_record', 0x44690d5, 0x4469104),
    ('reader_incomplete_branch', 0x446932b, 0x44693da),
    ('marker_argument_selection', 0x1696be0, 0x1696c08),
    ('marker_suffix_format', 0x1696c3a, 0x1696c76),
    ('archive_prune_root', 0x38c5709, 0x38c5762),
    ('archive_prune_root_predicate', 0x38c5817, 0x38c584c),
    ('archive_prune_reader', 0x38c5903, 0x38c5923),
    ('archive_first_marker_scan', 0x38c5c50, 0x38c5ce7),
    ('archive_marker_build_and_check', 0x38c5c7c, 0x38c5cc6),
    ('archive_marker_scan_transition', 0x38c5f94, 0x38c5fe6),
    ('archive_marker_second_check', 0x38c5ff0, 0x38c603c),
    ('archive_prune_filter_handoff', 0x38c60ed, 0x38c6163),
    ('archive_filter_marker', 0x3d5dd80, 0x3d5ddae),
    ('archive_filter_comparisons', 0x3d5dde5, 0x3d5de01),
    ('archive_filter_interval', 0x3d5de80, 0x3d5dea1),
    ('archive_prune_remove_loop', 0x38c617a, 0x38c626e),
    ('archive_prune_no_archive_error', 0x38c6059, 0x38c6086),
    ('archive_prune_no_candidates_error', 0x38c5ce7, 0x38c5cef),
    ('archive_prune_no_candidates_build', 0x38c5e33, 0x38c5e67),
    ('archive_prune_return', 0x38c637c, 0x38c638c),
]

# Every listed address is a reviewed candidate instruction start. The collector
# reads opcode and displacement from the ELF and rejects unsupported forms.
BRANCH_SITES = [
    0x2dd4f90,0x2dd4f99,0x2dd4fa6,0x2dd4fb8,0x2dd4ff5,0x2dd501d,0x2dd5055,0x2dd507c,
    0x4d98c63,0x4d98c88,0x4d98c9b,0x4d98cb8,0x4d98d62,0x4d98e11,0x4d98e24,0x4d98e47,0x4d98e51,0x4d98e65,0x4d98e86,0x4d98e9a,
    0x1564135,0x1564143,
    0x38c522c,0x38c525d,0x38c52aa,0x38c5313,0x38c548d,0x38c54bf,0x38c54d6,0x38c54eb,0x38c5515,0x38c5522,0x38c553f,0x38c5577,0x38c55e4,
    0x37c1350,0x37c139a,0x37c13b7,0x37c13c0,0x37c13d1,0x37c13db,0x37c13f3,0x37c13f5,0x37c13ff,0x37c1415,0x37c143a,
    0x436cb97,0x436cba0,0x436cbe5,0x436cbef,0x436cc2e,0x436cc39,
    0x4468e97,0x4468ebe,0x4469173,0x4469178,0x446917e,0x4469186,0x446918b,0x44691af,0x44691b4,0x44691da,0x44691fa,0x446921f,0x446923b,0x4469246,0x44692ae,0x4469329,
    0x3d5dccb,0x3d5dd25,0x3d5ddac,0x3d5ddf4,0x3d5de88,0x3d5de91,0x3d5de9b,
    0x38c5715,0x38c578b,0x38c579e,0x38c5825,0x38c5846,0x38c591d,0x38c596a,0x38c5973,0x38c599f,0x38c6174,0x38c61b7,0x38c61e0,0x38c61f4,0x38c620b,0x38c623b,0x38c6248,0x38c6328,0x38c637a,
    0x3e3f714,0x3e3f74b,0x3e3f835,0x3e3fc06,0x3e3fc59,0x3e3fc66,0x3e3fcb9,0x3e3fcca,
    0x42edcd3,0x42edd02,0x42edd2c,0x42eddb0,0x42ee124,
    0x38c5c64,0x38c5c6d,0x38c5cd1,0x38c5d24,0x38c5f67,0x38c5f6f,0x38c5fa6,0x38c5fe0,0x38c5fe9,0x38c6047,
]

# Each slot call must resolve through an R_X86_64_RELATIVE entry to the stated
# linked target. Existing 0x1500a60 and 0x1561530 are boundaries, not new frames.
CALLS = [
    ('outer_to_maintenance',0x2dd4f7e,'slot',0x4d98c40),
    ('maintenance_clock_boundary',0x4d98c6c,'slot',0x1629690),
    ('maintenance_local_date_boundary',0x4d98c7c,'slot',0x1629fb0),
    ('maintenance_previous_date_boundary',0x4d98c93,'slot',0x16290d0),
    ('maintenance_date_failure',0x4d98ee0,'slot',0x1680bd0),
    ('maintenance_archive',0x4d98cab,'slot',0x38c40f0),
    ('maintenance_count_prune',0x4d98d59,'slot',0x38c51f0),
    ('maintenance_archive_error_log',0x4d98d3c,'slot',0x150b310),
    ('maintenance_count_error_log',0x4d98de1,'slot',0x150b310),
    ('maintenance_archive_prune',0x4d98e7d,'slot',0x38c56f0),
    ('maintenance_name_gate',0x4d98e8b,'slot',0x1564120),
    ('count_read',0x38c5217,'direct',0x4468e30),
    ('count_collect',0x38c529f,'direct',0x3d5dab0),
    ('small_sort',0x38c55f9,'direct',0x436cb90),
    ('large_sort',0x38c565a,'slot',0x36f2690),
    ('large_merge_worker',0x36f2758,'direct',0x3e3f6f0),
    ('large_partition_worker',0x3e3f863,'slot',0x42edcb0),
    ('small_partition_boundary',0x42ee165,'direct',0x43906e0),
    ('collect_skip_copy',0x3d5daf5,'direct',0x37c1330),
    ('count_path_predicate',0x38c54e6,'register',None),
    ('count_remove_boundary',0x38c550d,'direct',0x1561530),
    ('count_error_drop',0x38c551d,'register',None),
    ('reader_root_predicate',0x4468e8f,'slot',0x1500a60),
    ('reader_directory_boundary',0x4468eae,'slot',0x1501290),
    ('reader_enumeration_boundary',0x4468ff1,'slot',0x15623e0),
    ('reader_last_component',0x446916b,'direct',0x44e56d0),
    ('reader_first_marker',0x44692a6,'slot',0x1500d20),
    ('reader_second_marker_format',0x44692f6,'direct',0x1696b90),
    ('reader_second_marker',0x4469308,'slot',0x1500d20),
    ('marker_output_format',0x1696c70,'slot',0x141e3a0),
    ('archive_root_predicate',0x38c581d,'slot',0x1500a60),
    ('archive_directory_boundary',0x38c5836,'slot',0x15021d0),
    ('archive_checkpoint_reader',0x38c5908,'direct',0x4468e30),
    ('archive_marker_check_a',0x38c5cc0,'slot',0x1500d20),
    ('archive_marker_check_b',0x38c6036,'slot',0x1500d20),
    ('archive_no_candidates_error',0x38c5e5f,'direct',0x3915cf0),
    ('archive_no_marker_error',0x38c607e,'direct',0x3915cf0),
    ('archive_filter',0x38c615e,'direct',0x3d5dca0),
    ('archive_marker_format',0x3d5dd91,'slot',0x141e3a0),
    ('archive_marker_test',0x3d5dda4,'slot',0x1500d20),
    ('archive_path_predicate',0x38c6206,'register',None),
    ('archive_remove_boundary',0x38c6233,'direct',0x1561530),
    ('archive_error_drop',0x38c6243,'register',None),
    ('name_gate_log_boundary',0x15641b8,'slot',0x150b310),
    ('name_gate_error_drop',0x15641c5,'register',None),
    ('name_gate_unwind_drop',0x156420d,'register',None),
]

# Each entry supplies a complete selected template or length-delimited literal.
# Historic suffix references are context; their FDEs belong to earlier work.
POOL_SPECS = [
    ('prior_static_config',0x4401ef,b'\xc0\x0e/static_config\x00',0x177840e),
    ('prior_cham',0x44ab69,b'\xc0\x05/cham\x00',0x17780f3),
    ('data_component',0x448b77,b'\xc0\x06/data/\xc0\x00',0x38c5748),
    ('slash_component',0x43aa84,b'\xc0\x01/\xc0\x00',0x38c57ce),
    ('checkpoint_component',0x434739,b'\xc0\x0b/checkpoint\x00',0x4468e5c),
    ('completion_marker',0x44bb44,b'\xc0\x14/CHECKPOINT_COMPLETE\x00',0x4469284),
    ('typed_completion_prefix',0x442eac,b'\xc0\x15/CHECKPOINT_COMPLETE_\xc0\x00',0x1696c61),
    ('deletion_marker',0x44c7fa,b'\xc0\x14/MARKED_FOR_DELETION\x00',0x3d5dd85),
    ('archive_failure',0x44bf1f,b'\x1ctar_evm_checkpoints failed: \xc0\x00',0x4d98cfa),
    ('count_failure',0x43905d,b'\x25prune_lowest_evm_checkpoints failed: \xc0\x00',0x4d98d9f),
    ('archive_prune_failure',0x442eed,b'\x28prune_evm_checkpoints_if_tarred failed: \xc0\x00',0x1564174),
    ('archive_missing_candidates',0x4470e2,b'\x29no evm state checkpoints from yesterday: \xc0\x00',0x38c5e53),
    ('archive_missing_marker',0x445f13,b'\x21no tarred checkpoints to delete: \xc0\x00',0x38c6072),
    ('date_range_failure',0x465ab7,b'Local time out of range for `NaiveDateTime`',0x4d98ec4),
    ('date_subtract_failure',0x465a95,b'`NaiveDate - TimeDelta` overflowed',0x4d98ed9),
]


class Image:
    def __init__(self, data, expected_sha=SHA115):
        if hashlib.sha256(data).hexdigest() != expected_sha:
            raise ValueError('artifact SHA-256 mismatch')
        self.data = data
        self.secs = sections(data)
        self._relocs = None

    def offset(self, va, size=1, executable=False):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise ValueError('invalid virtual address or size')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('address is not uniquely file-backed in a suitable section')
        s = matches[0]
        off = s['offset'] + va - s['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('file-backed range outside input')
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return bytes(self.data[off:off + size])

    def relocation(self, slot):
        if self._relocs is None:
            rels = [s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
            if len(rels) != 1 or rels[0]['size'] % 24:
                raise ValueError('invalid dynamic relocation table')
            sec = rels[0]
            self._relocs = {}
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                va, info, addend = struct.unpack_from('<QQq', self.data, off)
                if va in self._relocs:
                    raise ValueError('duplicate dynamic relocation slot')
                self._relocs[va] = (info, addend, off)
        row = self._relocs.get(slot)
        if row is None or row[0] != 8:
            raise ValueError('expected symbol-free relative relocation')
        return row[1], row[2]

    def descriptor(self, slot):
        target, rel_off = self.relocation(slot)
        length = struct.unpack('<Q', self.read(slot + 8, 8))[0]
        if length > 256:
            raise ValueError('descriptor length exceeds selected bound')
        return target, length, self.read(target, length), rel_off


def decode_branch(code, site):
    """Decode only short/near x86 conditional relative branches at selected starts."""
    if len(code) >= 2 and 0x70 <= code[0] <= 0x7f:
        length, cc = 2, code[0] & 15
        displacement = struct.unpack_from('<b', code, 1)[0]
    elif len(code) >= 6 and code[0] == 0x0f and 0x80 <= code[1] <= 0x8f:
        length, cc = 6, code[1] & 15
        displacement = struct.unpack_from('<i', code, 2)[0]
    else:
        raise ValueError('unsupported conditional branch bytes')
    cond = ['o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g'][cc]
    return length, cond, site + length + displacement


def relative(code, site, prefix):
    if not code.startswith(prefix) or len(code) != len(prefix) + 4:
        raise ValueError('relative operand opcode mismatch')
    return site + len(code) + struct.unpack_from('<i', code, len(prefix))[0]


def must_bytes(im, va, expected, executable=True):
    actual = im.read(va, len(expected), executable)
    if actual != expected:
        raise ValueError('selected instruction or data bytes changed')
    return actual


def parameters(im):
    must_bytes(im, 0x156413b, bytes.fromhex('0fb64348'))
    add = must_bytes(im, 0x156413f, bytes.fromhex('04ed'))[1]
    last = must_bytes(im, 0x1564141, bytes.fromhex('3c01'))[1]
    must_bytes(im, 0x1564143, bytes.fromhex('7679'))
    keep = struct.unpack('<I', must_bytes(im, 0x4d98d51, bytes.fromhex('be64000000'))[1:])[0]
    small = must_bytes(im, 0x38c5259, bytes.fromhex('4983ff02'))[-1]
    large = must_bytes(im, 0x38c55e0, bytes.fromhex('4983ff15'))[-1]
    parse = must_bytes(im, 0x44691ab, bytes.fromhex('4883ff11'))[-1]
    must_bytes(im, 0x37c1341, bytes.fromhex('488b4720'))
    must_bytes(im, 0x37c1370, bytes.fromhex('4839e8'))
    must_bytes(im, 0x37c137b, bytes.fromhex('4c0f42f8'))
    must_bytes(im, 0x37c1420, bytes.fromhex('410f1006'))
    must_bytes(im, 0x4d98c61, bytes.fromhex('85f60f84e8000000'))
    must_bytes(im, 0x4d98c82, bytes.fromhex('8b7c245885ff0f842a020000'))
    must_bytes(im, 0x4d98c8e, bytes.fromhex('beffffffff'))
    must_bytes(im, 0x4d98c99, bytes.fromhex('85c00f842c020000'))
    must_bytes(im, 0x4d98ebf, bytes.fromhex('be2b000000'))
    must_bytes(im, 0x4d98ed4, bytes.fromhex('be22000000'))
    must_bytes(im, 0x4d98ee6, bytes.fromhex('0f0b'))
    must_bytes(im, 0x4d98d4c, bytes.fromhex('e929010000'))
    must_bytes(im, 0x4d98d62, bytes.fromhex('0f8429010000'))
    must_bytes(im, 0x4d98df1, bytes.fromhex('e99b000000'))
    must_bytes(im, 0x4d98e7a, bytes.fromhex('4889dfff15cd0675014885c074094889c7ff1597837401'))
    must_bytes(im, 0x2dd4fdb, bytes.fromhex('48c74518010000004c8975204c897d28'))
    must_bytes(im, 0x3d5ddaa, bytes.fromhex('84c07422'))
    must_bytes(im, 0x3d5de85, bytes.fromhex('4c3b287326488b04244c3b28721d488b4424484c3b280f86'))
    must_bytes(im, 0x3e3fc80, bytes.fromhex('4889f2488b4e1831c031f6493b4d180f92c1400f93c64889d7490f42fd'))
    must_bytes(im, 0x3e3fc10, bytes.fromhex('498d4de0498d5424e0498b75f831ff4531c0493b7424f8400f92c7410f93c0480f42d1'))
    bound_text = b'variant index 0 <= i < 79'
    must_bytes(im, 0x464893, bound_text, False)
    name_bound = int(bound_text.rsplit(b' ', 1)[1])
    return {'name_bias': add, 'name_last': last, 'name_first': (-add) & 255,
            'keep_count': keep, 'small_sort_min': small, 'large_sort_min': large,
            'checked_decimal_min_digits': parse, 'name_diagnostic_bound': name_bound}


def name_suppressed(tag, params):
    if type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError('name byte outside u8')
    return ((tag + params['name_bias']) & 255) <= params['name_last']


def parse_component(raw):
    """Model the selected decimal byte path, conditional on path extraction."""
    if not isinstance(raw, bytes):
        raise ValueError('expected raw component bytes')
    if not raw or raw in (b'+', b'-'):
        return None
    if raw.startswith(b'+'):
        raw = raw[1:]
    value = 0
    for byte in raw:
        if byte < 48 or byte > 57:
            return None
        digit = byte - 48
        if value > (U64_MAX - digit) // 10:
            return None
        value = value * 10 + digit
    return value


def selection_count(length, keep):
    """Count copied records when all encountered record tags are ordinary."""
    if type(length) is not int or type(keep) is not int or not (0 <= length <= U64_MAX and 0 <= keep <= U64_MAX):
        raise ValueError('length or keep outside u64')
    if keep == 0:
        return length
    skipped_before_one = min(keep - 1, length)
    if skipped_before_one == length:
        return 0
    return length - skipped_before_one - 1


def archive_selected(marker, height, lower, upper, max_height):
    if type(marker) is not bool or any(type(v) is not int or not 0 <= v <= U64_MAX for v in (height, lower, upper, max_height)):
        raise ValueError('invalid archive selection inputs')
    return marker or (lower <= height < upper and height <= max_height)


def merge_choice(left, right, backwards=False):
    """Choice at the two selected unsigned 64-bit merge instructions."""
    if type(backwards) is not bool or any(type(v) is not int or not 0 <= v <= U64_MAX for v in (left,right)):
        raise ValueError('invalid merge comparison')
    if backwards:
        return 'left' if left < right else 'right'
    return 'right' if left < right else 'left'


def date_transition(local_nonzero, previous_nonzero):
    """Model the two local date checks in mode one, given normal helper returns."""
    if type(local_nonzero) is not bool:
        raise ValueError('invalid local date result')
    if not local_nonzero:
        if previous_nonzero is not None:
            raise ValueError('previous-date helper is unreachable')
        return 'local_time_range_failure'
    if type(previous_nonzero) is not bool:
        raise ValueError('previous-date helper result required')
    return 'continue' if previous_nonzero else 'date_subtract_failure'


def maintenance_flow(mode, first_error, second_error, name, params):
    """Model only normally returning helpers in the selected outer route."""
    if mode not in (0,1) or type(mode) is not int or type(first_error) is not bool:
        raise ValueError('invalid maintenance mode or first result')
    if (mode == 0 and second_error is not None) or (mode == 1 and type(second_error) is not bool):
        raise ValueError('second phase is present only in mode one')
    suppressed=name_suppressed(name,params)
    return {'first_error_log_boundary':first_error, 'second_helper_called':mode==1,
            'second_error_log_boundary':mode==1 and second_error and not suppressed,
            'second_error_drop':mode==1 and second_error,
            'outer_completion_on_normal_returns':True}


def frame_records(im):
    secs, index = unwind_index(im.data)
    _, all_fdes = eh_frame_records(im.data, secs)
    by_fde = {f['fde']: f for f in all_fdes}
    if len(by_fde) != len(all_fdes):
        raise ValueError('duplicate FDE address')
    by_start = {}
    for row in index:
        if row['start'] in by_start:
            raise ValueError('duplicate unwind start')
        by_start[row['start']] = row
    found = []
    for name, start, end, expected in FRAME_SPECS:
        idx = by_start.get(start)
        f = by_fde.get(idx['fde']) if idx else None
        if not f or f['start'] != start or f['end'] != end:
            raise ValueError('selected FDE and unwind index mismatch')
        body = im.read(start, end - start, True)
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected:
            raise ValueError('selected body SHA-256 mismatch')
        found.append(dict(name=name, start=start, end=end, fde=f['fde'], cie=f['cie'],
                          lsda=f['lsda'], index=idx['index'], digest=digest,
                          file_offset=im.offset(start, len(body), True)))
    return found


def owner(frames, va, length=1):
    matched = [f for f in frames if f['start'] <= va and va + length <= f['end']]
    if len(matched) != 1:
        raise ValueError('site outside one selected FDE')
    return matched[0]


def exception_entries(im, frame):
    """Read selected Itanium call-site tables, without interpreting actions."""
    if frame['lsda'] is None:
        return []
    candidates=[s for s in im.secs if s['name']=='.gcc_except_table' and s['type']!=8]
    if len(candidates)!=1:
        raise ValueError('missing or duplicate exception section')
    sec=candidates[0]
    pos=im.offset(frame['lsda'],1)
    end=sec['offset']+sec['size']
    if not sec['offset'] <= pos < end or pos+2>end:
        raise ValueError('LSDA header outside exception section')
    data=im.data
    if data[pos] != 0xff:
        raise ValueError('unsupported LSDA landing-base encoding')
    type_encoding=data[pos+1]
    pos+=2
    type_table=None
    if type_encoding == 0x9b:
        type_offset,pos=uleb(data,pos,end)
        type_table=pos+type_offset
        if type_table>end:
            raise ValueError('LSDA type table outside exception section')
    elif type_encoding != 0xff:
        raise ValueError('unsupported LSDA type-table encoding')
    if pos>=end or data[pos]!=1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos+=1
    size,pos=uleb(data,pos,end)
    table_end=pos+size
    if table_end>end or (type_table is not None and table_end>type_table):
        raise ValueError('truncated LSDA call-site table')
    rows=[]
    previous_end=frame['start']
    while pos<table_end:
        start_pos=pos
        start,pos=uleb(data,pos,table_end)
        length,pos=uleb(data,pos,table_end)
        landing,pos=uleb(data,pos,table_end)
        action,pos=uleb(data,pos,table_end)
        first=frame['start']+start
        last=first+length
        pad=frame['start']+landing if landing else None
        if not frame['start']<=first<=last<=frame['end']:
            raise ValueError('LSDA call-site range outside FDE')
        if first<previous_end:
            raise ValueError('overlapping or unordered LSDA call sites')
        previous_end=last
        if pad is not None and not frame['start']<=pad<frame['end']:
            raise ValueError('LSDA landing outside FDE')
        rows.append({'entry_offset':start_pos,'start':first,'end':last,'landing':pad,
                     'action':action,'raw':bytes(data[start_pos:pos]).hex()})
    return rows


def write_tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def collect(im, out):
    params = parameters(im)
    frames = frame_records(im)
    out.mkdir(parents=True, exist_ok=True)
    frame_rows = [[f['name'],hex(f['start']),hex(f['end']),f['end']-f['start'],hex(f['file_offset']),
                   hex(f['fde']),hex(f['cie']),'' if f['lsda'] is None else hex(f['lsda']),f['index'],f['digest']] for f in frames]
    write_tsv(out/'functions.tsv',['role','start_va','end_va_exclusive','length','file_offset','fde_va','cie_va','lsda_va','unwind_index','sha256'],frame_rows)
    windows = []
    for label,start,end in WINDOWS:
        f=owner(frames,start,end-start)
        windows.append([label,f['name'],hex(start),hex(im.offset(start,end-start,True)),end-start,im.read(start,end-start,True).hex()])
    write_tsv(out/'windows.tsv',['role','function','start_va','file_offset','length','raw_hex'],windows)
    branches=[]
    for site in BRANCH_SITES:
        f=owner(frames,site)
        probe=im.read(site,min(6,f['end']-site),True)
        length,cond,target=decode_branch(probe,site)
        if not f['start'] <= target < f['end']:
            raise ValueError('selected conditional branch leaves its FDE')
        branches.append([f['name'],hex(site),hex(im.offset(site,length,True)),probe[:length].hex(),cond,hex(target)])
    write_tsv(out/'branches.tsv',['function','site_va','file_offset','raw_hex','condition','taken_va'],branches)
    exception_rows=[]
    exceptions={}
    for f in frames:
        entries=exception_entries(im,f)
        exceptions[f['name']]=entries
        for row in entries:
            exception_rows.append([f['name'],hex(f['lsda']),hex(row['entry_offset']),hex(row['start']),hex(row['end']),
                                   '' if row['landing'] is None else hex(row['landing']),row['action'],row['raw']])
    write_tsv(out/'exception-sites.tsv',['function','lsda_va','entry_file_offset','start_va','end_va_exclusive','landing_va','action_uleb','entry_hex'],exception_rows)
    call_rows=[]
    rel_slots={}
    for label,site,kind,expected in CALLS:
        f=owner(frames,site)
        if kind=='direct':
            b=im.read(site,5,True); target=relative(b,site,b'\xe8'); operand=target
        elif kind=='slot':
            b=im.read(site,6,True); operand=relative(b,site,b'\xff\x15'); target,ro=im.relocation(operand)
            rel_slots[operand]=(target,ro)
        else:
            b=im.read(site,3,True)
            if b[:2] in (b'\xff\x10',b'\xff\x11'):
                b=b[:2]
            elif b[:3] not in (b'\x41\xff\xd5',b'\x41\xff\xd6'):
                raise ValueError('unsupported selected register call')
            operand=target=None
        if expected is not None and target != expected:
            raise ValueError('selected call target mismatch')
        call_rows.append([label,f['name'],hex(site),hex(im.offset(site,len(b),True)),b.hex(),kind,
                          '' if operand is None else hex(operand),'' if target is None else hex(target)])
    write_tsv(out/'calls.tsv',['role','function','site_va','file_offset','raw_hex','kind','operand_va','resolved_target_va'],call_rows)
    exception_edges=[]
    for (label,site,_,_),row in zip(CALLS,call_rows):
        f=owner(frames,site)
        hits=[x for x in exceptions[f['name']] if x['start']<=site<x['end']]
        if len(hits)>1:
            raise ValueError('overlapping selected exception call sites')
        x=hits[0] if hits else None
        exception_edges.append([label,hex(site),'' if x is None else hex(x['start']),'' if x is None else hex(x['end']),
                                '' if x is None or x['landing'] is None else hex(x['landing']),'' if x is None else x['action']])
    write_tsv(out/'exception-edges.tsv',['role','call_va','protected_start_va','protected_end_va','landing_va','action_uleb'],exception_edges)
    register_bindings=[]
    for name,site,register,slot,want in [
            ('count_path_predicate',0x38c5498,'r14',0x64e0928,0x1500a60),
            ('archive_path_predicate',0x38c61c6,'r13',0x64e0928,0x1500a60)]:
        ins=im.read(site,7,True)
        if ins[:3] not in (b'\x4c\x8b\x35',b'\x4c\x8b\x2d') or relative(ins,site,ins[:3]) != slot:
            raise ValueError('register-load binding mismatch')
        target,ro=im.relocation(slot)
        if target!=want: raise ValueError('register-load target mismatch')
        rel_slots[slot]=(target,ro)
        register_bindings.append([name,register,hex(site),hex(im.offset(site,7,True)),ins.hex(),hex(slot),hex(target)])
    write_tsv(out/'register-bindings.tsv',['role','register','load_va','file_offset','load_hex','slot_va','target_va'],register_bindings)
    # The first seven bytes are deliberately checked as LEAs at their actual starts.
    pool=[]
    for label,va,want,site in POOL_SPECS:
        must_bytes(im,va,want,False)
        ins=im.read(site,7,True)
        if ins[:2] not in (b'\x48\x8d',b'\x4c\x8d') or (ins[2]&0xc7)!=5:
            raise ValueError('pool reference opcode mismatch')
        target=site+7+struct.unpack_from('<i',ins,3)[0]
        if target!=va:
            raise ValueError('pool reference target mismatch')
        pool.append([label,hex(va),hex(im.offset(va,len(want))),want.hex(),hex(site),hex(im.offset(site,7,True)),ins.hex()])
    write_tsv(out/'pools.tsv',['role','entry_va','entry_file_offset','entry_hex','reference_va','reference_file_offset','reference_hex'],pool)
    names=[]
    for tag in [18,19,20,21,33,34]:
        slot=0x63f8788+tag*16
        va,n,b,ro=im.descriptor(slot)
        names.append([tag,hex(slot),hex(ro),hex(va),hex(im.offset(va,n)),n,b.decode('ascii'),b.hex()])
        rel_slots[slot]=(va,ro)
    write_tsv(out/'name-boundaries.tsv',['tag','slot_va','relocation_file_offset','text_va','text_file_offset','length','text','text_hex'],names)
    literals=[]
    for name,slot in [('periodic_label',0x646ea00),('archive_marker',0x648b938)]:
        va,n,b,ro=im.descriptor(slot); rel_slots[slot]=(va,ro)
        literals.append([name,hex(slot),hex(ro),hex(va),hex(im.offset(va,n)),n,b.decode('ascii'),b.hex()])
    # The formatter selects the third pointer and third length with argument 2.
    va,ro=im.relocation(0x6408c60); n=struct.unpack('<Q',im.read(0x47b460,8))[0]
    if n>256: raise ValueError('marker component length outside bound')
    marker=im.read(va,n); rel_slots[0x6408c60]=(va,ro)
    literals.append(['typed_marker_component',hex(0x6408c60),hex(ro),hex(va),hex(im.offset(va,n)),n,marker.decode('ascii'),marker.hex()])
    write_tsv(out/'descriptors.tsv',['role','slot_va','relocation_file_offset','text_va','text_file_offset','length','text','text_hex'],literals)
    # The configuration pointer, and register-loaded predicate bindings, are not
    # necessarily call operands at the point where the register is used.
    for slot,want in [(0x64e0918,0x64f06c0),(0x64e0928,0x1500a60),(0x64e86a0,0x4d98c40)]:
        va,ro=im.relocation(slot)
        if va!=want: raise ValueError('selected context relocation mismatch')
        rel_slots[slot]=(va,ro)
    write_tsv(out/'relocations.tsv',['slot_va','slot_file_offset','type','symbol_index','addend_va','relocation_file_offset'],
              [[hex(slot),hex(im.offset(slot,8)),8,0,hex(target),hex(ro)] for slot,(target,ro) in sorted(rel_slots.items())])
    write_tsv(out/'name-cases.tsv',['input_byte','suppresses_selected_error_log'],
              [[i,int(name_suppressed(i,params))] for i in range(256)])
    raw_cases=[b'',b'+',b'-',b'0',b'+0',b'00',b'1',b'+001',b'-1',b'1x',b' 1',b'9'*16,b'9'*17,
               b'18446744073709551614',b'18446744073709551615',b'18446744073709551616',b'000000000000000000001',b'\xff']
    write_tsv(out/'numeric-cases.tsv',['component_hex','digit_count','selected_loop','parsed_u64_or_reject'],
              [[b.hex(),len(b)-(1 if b.startswith(b'+') else 0),
                'checked' if len(b)-(1 if b.startswith(b'+') else 0)>=params['checked_decimal_min_digits'] else 'short',
                'reject' if parse_component(b) is None else parse_component(b)] for b in raw_cases])
    sizes=[0,1,2,19,20,21,99,100,101,102,127,128,255]
    write_tsv(out/'retention-cases.tsv',['record_count','keep_count','copied_tail_count','sort_dispatch'],
              [[n,params['keep_count'],selection_count(n,params['keep_count']),
                'none' if n<params['small_sort_min'] else ('small' if n<params['large_sort_min'] else 'large')] for n in sizes])
    filters=[]
    for marker_flag in [False,True]:
        for height in [9,10,11,14,15,16,19,20,21]:
            filters.append([int(marker_flag),height,10,20,15,int(archive_selected(marker_flag,height,10,20,15))])
    write_tsv(out/'archive-filter-cases.tsv',['marker_test_true','height','lower_inclusive','upper_exclusive','max_inclusive','selected'],filters)
    merge_cases=[]
    for left in [0,1,2,255,U64_MAX]:
        for right in [0,1,2,255,U64_MAX]:
            merge_cases.append([left,right,merge_choice(left,right),merge_choice(left,right,True)])
    write_tsv(out/'merge-cases.tsv',['left_u64','right_u64','forward_choice','backward_choice'],merge_cases)
    dates=[]
    for local,previous in [(False,None),(True,False),(True,True)]:
        dates.append([int(local),'' if previous is None else int(previous),date_transition(local,previous)])
    write_tsv(out/'date-cases.tsv',['local_date_nonzero','previous_date_nonzero','selected_branch'],dates)
    flow=[]
    for mode in [0,1]:
        for first_err in [0,1]:
            for second_err in ([None] if mode==0 else [0,1]):
                for name in [18,19,20,21,33]:
                    result=maintenance_flow(mode,bool(first_err),None if second_err is None else bool(second_err),name,params)
                    flow.append([mode,first_err,'' if second_err is None else second_err,name,
                                 int(result['first_error_log_boundary']),int(result['second_helper_called']),
                                 int(result['second_error_log_boundary']),int(result['second_error_drop']),
                                 int(result['outer_completion_on_normal_returns'])])
    write_tsv(out/'flow-cases.tsv',['mode_bit','first_helper_error','second_helper_error','name_byte','first_error_log_boundary',
                                     'second_helper_called','second_error_log_boundary','second_error_drop',
                                     'outer_completion_on_normal_returns'],flow)
    summary={'artifact':'node 115','binary_sha256':SHA115,'coordinates':'linked ELF virtual addresses; section-derived file offsets',
             'selected_fde_count':len(frames),'selected_fde_bytes':sum(f['end']-f['start'] for f in frames),
             'selected_window_count':len(windows),'selected_branch_count':len(branches),'selected_call_count':len(call_rows),
             'selected_exception_site_count':len(exception_rows),
             'selected_relocation_count':len(rel_slots),'selected_pool_count':len(pool),'selected_name_descriptor_count':len(names),
             'name_input_domain_size':256,'name_diagnostic_bound':params['name_diagnostic_bound'],'parameters':params,
             'suppressed_name_bytes':[i for i in range(256) if name_suppressed(i,params)],
             'limitations':'Selected static instructions, conditional models and FDE extents; no target execution, complete CFG, Rust reconstruction or component gate.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def compare_old(current, old_bytes):
    """Compare a few old and current anchors only after hashing both captures."""
    old=Image(old_bytes,SHA94)
    # Historical locations and table are not used as current-release addresses.
    rows=[]
    for label,ov,nv,ob,nb,osite,nsite in [
        ('cham',0x1fc0ec,0x44ab69,b'\xc0\x05/cham\x00',b'\xc0\x05/cham\x00',0x164f840,0x17780f3),
        ('static_config',0x1ef5f5,0x4401ef,b'\xc0\x0e/static_config\x00',b'\xc0\x0e/static_config\x00',0x164fbae,0x177840e)]:
        must_bytes(old,ov,ob,False); must_bytes(current,nv,nb,False)
        for im,site,expect in [(old,osite,ov),(current,nsite,nv)]:
            ins=im.read(site,7,True)
            if ins[:2] not in (b'\x48\x8d',b'\x4c\x8d') or (ins[2]&0xc7)!=5 or site+7+struct.unpack_from('<i',ins,3)[0]!=expect:
                raise ValueError('historical pool reference mismatch')
        rows.append({'name':label,'old_entry_va':hex(ov),'old_entry_file_offset':hex(old.offset(ov,len(ob))),
                     'old_reference_va':hex(osite),'old_reference_file_offset':hex(old.offset(osite,7,True)),
                     'old_reference_hex':old.read(osite,7,True).hex(),
                     'new_entry_va':hex(nv),'new_entry_file_offset':hex(current.offset(nv,len(nb))),
                     'new_reference_va':hex(nsite),'new_reference_file_offset':hex(current.offset(nsite,7,True)),
                     'new_reference_hex':current.read(nsite,7,True).hex(),'entry_hex':nb.hex()})
    must_bytes(old,0x13cbcf7,bytes.fromhex('0fb64348247e3c127448'))
    must_bytes(current,0x156413b,bytes.fromhex('0fb6434804ed3c017679'))
    # Bind both arithmetic guards to the same complete diagnostic template and
    # the selected error-object handoff; no other old routine is inferred.
    failure=b'\x28prune_evm_checkpoints_if_tarred failed: \xc0\x00'
    must_bytes(old,0x1f2cba,failure,False)
    must_bytes(current,0x442eed,failure,False)
    for im,site,va in [(old,0x13cbd2b,0x1f2cba),(current,0x1564174,0x442eed)]:
        lea=im.read(site,7,True)
        if lea[:2]!=b'\x48\x8d' or (lea[2]&0xc7)!=5 or relative(lea,site,lea[:3])!=va:
            raise ValueError('gate diagnostic template reference mismatch')
    old_log=must_bytes(old,0x13cbd43,bytes.fromhex('ff152f2c3a04'))
    if old.relocation(relative(old_log,0x13cbd43,b'\xff\x15'))[0]!=0x143d010:
        raise ValueError('historical gate log target mismatch')
    must_bytes(old,0x13cbd49,bytes.fromhex('488b3c24488b07ff10'))
    if decode_branch(old.read(0x13cbcff,2,True),0x13cbcff)[2]!=0x13cbd49:
        raise ValueError('historical gate bypass mismatch')
    names=[]
    for spelling,old_tag,new_tag in [('SoloTestnet',18,19),('SoloMainnet',19,20),('NvTestnet',32,33)]:
        oa,ol,ob,oro=old.descriptor(0x5668288+16*old_tag)
        na,nl,nb,nro=current.descriptor(0x63f8788+16*new_tag)
        if ob!=nb or ob.decode('ascii')!=spelling:
            raise ValueError('cross-release descriptor mismatch')
        names.append({'text':spelling,'old_tag':old_tag,'old_slot_va':hex(0x5668288+16*old_tag),
                      'old_text_va':hex(oa),'old_relocation_file_offset':hex(oro),
                      'new_tag':new_tag,'new_slot_va':hex(0x63f8788+16*new_tag),
                      'new_text_va':hex(na),'new_relocation_file_offset':hex(nro)})
    old_secs,old_index=unwind_index(old.data)
    _,old_fdes=eh_frame_records(old.data,old_secs)
    indexed={row['fde']:row for row in old_index}
    containing=[f for f in old_fdes if f['start']<=0x13cbcf7<f['end'] and f['fde'] in indexed]
    if len(containing)!=1 or indexed[containing[0]['fde']]['start']!=containing[0]['start']:
        raise ValueError('historical gate FDE/index mismatch')
    old_frame=containing[0]
    return {'old_sha256':SHA94,'new_sha256':SHA115,'pools':rows,'name_samples':names,
            'old_gate_va':hex(0x13cbcf7),'old_gate_file_offset':hex(old.offset(0x13cbcf7,10,True)),
            'old_gate_fde_start':hex(old_frame['start']),'old_gate_fde_end':hex(old_frame['end']),
            'old_gate_fde_va':hex(old_frame['fde']),'old_gate_hex':'0fb64348247e3c127448',
            'gate_error_context':{'entry_hex':failure.hex(),
                                  'old_entry_va':hex(0x1f2cba),'old_entry_file_offset':hex(old.offset(0x1f2cba,len(failure))),
                                  'old_reference_va':hex(0x13cbd2b),'old_reference_file_offset':hex(old.offset(0x13cbd2b,7,True)),
                                  'old_log_va':hex(0x13cbd43),'old_log_target_va':hex(0x143d010),
                                  'old_bypass_va':hex(0x13cbd49),
                                  'new_entry_va':hex(0x442eed),'new_entry_file_offset':hex(current.offset(0x442eed,len(failure))),
                                  'new_reference_va':hex(0x1564174),'new_reference_file_offset':hex(current.offset(0x1564174,7,True)),
                                  'new_log_va':hex(0x15641b8),'new_bypass_va':hex(0x15641be)},
            'new_gate_va':hex(0x156413b),'new_gate_file_offset':hex(current.offset(0x156413b,10,True)),
            'new_gate_fde_start':hex(0x1564120),'new_gate_fde_end':hex(0x156421d),
            'new_gate_hex':'0fb6434804ed3c017679',
            'old_byte_cases':[i for i in range(256) if (i&0x7e)==0x12],
            'new_byte_cases':[i for i in range(256) if name_suppressed(i,parameters(current))]}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--compare-94',type=Path)
    args=parser.parse_args(argv)
    image=Image(TARGET.read_bytes())
    summary=collect(image,args.out)
    print(json.dumps(summary,sort_keys=True))
    if args.compare_94:
        print(json.dumps(compare_old(image,args.compare_94.read_bytes()),sort_keys=True))
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,struct.error,UnicodeError) as error:
        print('node115_evm_prune_policy: '+str(error),file=sys.stderr)
        raise SystemExit(1)
