#!/usr/bin/env python3
"""Extract the node-115 precompile-adjacent log and post-state evidence.

Only pinned ELF data is read.  No machine instructions are executed and the
small instruction recognizers accept only the shapes used by this packet.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
WORD_MASK = (1 << 64) - 1

# The ends below are checked against actual FDEs, not the next indexed start.
FUNCTIONS = [
    ('collect_nonzero_rows', 0x2346480, 0x234668e),
    ('small_row_sort', 0x26d4140, 0x26d427a),
    ('one_key_event', 0x2970eb0, 0x29710df),
    ('two_key_event', 0x29714f0, 0x2971759),
    ('finalize_candidate_rows', 0x2972200, 0x297238e),
    ('take_account_map', 0x2972c20, 0x2973124),
    ('reset_journal', 0x2973130, 0x2973434),
    ('classify_frame_status', 0x299c6d0, 0x299c929),
    ('lookup_nonzero_account', 0x29dee60, 0x29defea),
    ('large_row_sort_adapter', 0x36e3660, 0x36e3757),
    ('large_row_run_partition', 0x3dfd7e0, 0x3dfdeef),
]

# Role names are inferences.  Each predicate is an exact, digest-specific
# instruction window selected by the researcher, not an x86 disassembler.
WINDOWS = [
    ('transfer_revision_and_flag', 0x29714fe, '80bf260100000e0f82ed0100004889fb80bf24010000000f85dd010000'),
    ('transfer_nonzero', 0x297151b, 'f30f6f01f30f6f4910660febc8660fefc0660f76c10f50c083f00f0f84bc010000'),
    ('transfer_alloc_topics', 0x2971545, 'bf60000000ff1530dfb6034885c00f84ae010000'),
    ('transfer_addresses', 0x297155c, 'c74424600000000048c744245800000000410f1045000f11442464418b451089442474c74424100000000048c744240800000000418b44241089442424410f1004240f11442414488b442418498946508b442420418946588b4424244189465c488b442408498946408b442410418946488b4424144189464c'),
    ('transfer_topic_literal', 0x29715d5, '0f1005146caefd410f1146100f1005f86baefd410f11060f104424580f104c2468410f114620410f114e30'),
    ('transfer_amount_be', 0x2971600, '4c89f84d8b6f184d8b67104d8b3f488b6808bf20000000ff1563deb6034885c00f84f1000000490fcf480fcd490fcc490fcd4c89284c896008488968104c897818'),
    ('transfer_emitter_and_record', 0x297165d, '0f10054c01c9fd0f11442440c7442450fffffffe48c7442408030000004c8974241048c7442418030000004889542420488944242848c74424302000000048894c2438'),
    ('transfer_append', 0x29716a0, '4c8b73104c3b3375094889dfff1596e3b603488b43084b8d0cb648c1e1040f104424480f114408400f10442408f30f6f4c24180f105424280f105c24380f115c08300f11540820f30f7f4c08100f11040849ffc64c897310'),
    ('transfer_failures', 0x2971707, 'bf01000000be60000000ff1579ddb603bf01000000be20000000ff1571ddb6030f0b4889c3488d7c2408e87abb0700eb19ff1582ddb6034889c3be600000004c89f731d2ff154fddb6034889dfe8f7f2a703'),
    ('burn_revision_and_flag', 0x2970ebe, '80bf260100000e0f82b30100004889fb80bf24010000000f85a3010000'),
    ('burn_nonzero', 0x2970edb, 'f30f6f02f30f6f4a10660febc8660fefc0660f76c10f50c083f00f0f8482010000'),
    ('burn_alloc_topics', 0x2970f02, 'bf40000000ff1573e5b6034885c00f8477010000'),
    ('burn_address_topic', 0x2970f19, 'c74424100000000048c744240800000000418b44241089442424410f1004240f11442414488b442418498946308b442420418946388b4424244189463c488b442408498946208b442410418946288b4424144189462c0f1005ba77aefd410f1146100f10059e77aefd410f1106'),
    ('burn_amount_be', 0x2970f86, '4c89f84d8b6f184d8b67104d8b3f488b6808bf20000000ff15dde4b6034885c00f84f1000000490fcf480fcd490fcc490fcd4c89284c896008488968104c897818'),
    ('burn_emitter_and_record', 0x2970fe3, '0f1005c607c9fd0f11442440c7442450fffffffe48c7442408020000004c8974241048c7442418020000004889542420488944242848c74424302000000048894c2438'),
    ('burn_append', 0x2971026, '4c8b73104c3b3375094889dfff1510eab603488b43084b8d0cb648c1e1040f104424480f114408400f10442408f30f6f4c24180f105424280f105c24380f115c08300f11540820f30f7f4c08100f11040849ffc64c897310'),
    ('burn_failures', 0x297108d, 'bf01000000be40000000ff15f3e3b603bf01000000be20000000ff15ebe3b6030f0b4889c3488d7c2408e8f4c10700eb19ff15fce3b6034889c3be400000004c89f731d2ff15c9e3b6034889dfe871f9a703'),
    ('batch_revision_and_flags', 0x2972211, '80bf260100000e0f82f30000004989fe80bf24010000000f85e30000004180be25010000000f85d5000000'),
    ('batch_source_view', 0x297223c, '498b4638498b4e40488d0c89488d0c88498d96c8000000488944243848894c24404889542448488d7c2420488d742438'),
    ('batch_count_sort_gate', 0x2972271, '488b7c24284c8b7c2430488d44240f48894424184983ff020f83940000004c8b6c24204d85ff7467'),
    ('batch_emit_row', 0x29722c0, '8b4310894424600f10030f294424500f1043180f104b280f294424700f298c24800000004c89f74c89fe4c89e2e8beebffff'),
    ('batch_sort_paths', 0x2972323, '4983ff157322488d4c2418ba010000004889fb4c89fee8021ed6ff4c8b6c24204889dfe94effffff488d5424184889fb4c89feff15144ab703ebe0'),
    ('batch_cleanup', 0x297235e, '48895c24104989c64c8b6c2420eb034989c64d85ed7411496bf538488b7c241031d2ff151ad1b6034c89f7e8c2e6a703'),
    ('collect_iteration', 0x23464a0, '488b164c8b6e084c8d7424484c8d6424206666666666662e0f1f8400000000004c39ea0f8447010000488d5a1449891f4c89f74c89e6e885896900837c2448014889da75db'),
    ('collect_first_allocation', 0x23464e5, 'bfe0000000ff15908f19044885c00f845d0100004989c648896c2438'),
    ('collect_append', 0x23465a7, '4c3b7c2408488d5c24307522ba01000000b90800000041b838000000488d7c24084c89fee8807afdff4c8b742410496bc738488d542450488b4a3049894c06300f10020f104a100f105220410f11540620410f114c0610410f11040649ffc74c897c2418'),
    ('collect_empty', 0x2346610, '48c745000000000048c745080800000048c7451000000000eb17'),
    ('collect_fail_cleanup', 0x2346656, 'bf08000000bee0000000ff15328e1904eb004889c3488b4424084885c07411488b7c2410486bf03831d2ff151a8e19044889dfe8c2a30a04'),
    ('account_hash', 0x29dee60, '488b06488b3048837e18000f846e0100004889d1488b12488b05fa0bb0034c8b00448b491048335620488b41084c31c048f7e24931d14c31c849f7e04831c24989d049c1e839'),
    ('account_probe', 0x29deec7, '4821f2f30f6f1410660f6fda660f74d866440fd7cb4585c9745ff3450fbcd14901d24921f249f7da4d69d2a8000000f30f6f19f3420f6fa41058ffffff660f74e3660f6e591066420f6eac1068ffffff660f74eb660fdbec66440fd7dd4181fbffff00007435458d51ff664521ca4589d175a7660f1f440000660f74d166440fd7ca4585c90f858d0000004c01c24883c2104983c010e965ffffff'),
    ('account_nonzero', 0x29def62, '4c01d0f30f6f4098f30f6f48a8660febc8660fefc0660f76c10f50d083f20f745c4883c098'),
    ('account_result', 0x29def87, '0f10000f1048100f114c24f00f114424e08b4110894424d80f10010f294424c8488b4424f8488947380f284c24e80f114f280f1147088b4424d8894718488b4424dc4889471c8b4424e489472448c707010000004889f8c348c707000000004889f8c3'),
    ('small_sort_compare', 0x26d41d0, '498d76c8ba140000004c89f7ffd585c079dd'),
    ('small_sort_move', 0x26d4210, '4a8b442bf84a89442b30420f10442bc8420f104c2bd8420f10542be8420f11542b20420f114c2b10420f11042b4983fd380f8449ffffff4a8d342b4883c690ba140000004c89ffffd54983c5c885c078af4901dde92affffff'),
    ('large_sort_gate', 0x36e3669, '4881ec001000004889d34889f148d1e94889f04829c84881fe092e020041bc092e02004c0f42e64939c44c0f46e04983fc4a730a4989e6b949000000eb3e'),
    ('large_sort_alloc', 0x36e36a7, '4d6bfc3848b949922449922449024839c8760b31ff4c89feff15d3bddf024989fe4c89ff4989f5ff15acbddf024c89f74c89ee4989c64c89e14885c0743c'),
    ('large_sort_helper', 0x36e36e5, '4531c04883fe41410f92c04c89f24989d9e8e5a071004983fc49760f496bf4384c89f731d2ff1590bddf02'),
    ('large_sort_failure', 0x36e3721, 'bf080000004c89feff1569bddf024889c34983fc4a73084889dfe810d3d002496bf4384c89f731d2ff1551bddf024889dfe8f9d2d002'),
    ('large_run_initial', 0x3dfd7f6, '448944245448897c24104883fe020f82d30600004989c94989d4'),
    ('large_run_threshold', 0x3dfd82f, '4889f04881fe01100000731d48d1e84889f14829c14883f940b840000000480f42c14889442420eb2a4883c801480fbdc889c8d1e883e10101c1b80100000048d3e04889f248d3ea4801c248d1ea4889542420'),
    ('large_run_subsort_gate', 0x3dfd932, '483b4c24207357807c24540074604883f920b820000000480f43c8488b442430488904244c89e74989ce4889ce4c8b6424084c89e2488b5c24284889d94531c04531c9ff157dbf6e02'),
    ('large_run_initial_pair', 0x3dfd9c0, '4889cb498d7c2438ba140000004c89e6ff157a216e0285c0784a'),
    ('large_run_nondecreasing', 0x3dfda00, '498d77c8ba140000004c89ffff153e216e0285c0786f49ffc64983c7384c39f375de'),
    ('large_run_decreasing', 0x3dfda50, '498d77c8ba140000004c89ffff15ee206e0285c0791f49ffc64983c7384c39f375de'),
    ('large_run_reverse_rows', 0x3dfdac0, '488b71d0488b7ad0488979d0488972d0488b71d8488b7ad8488979d8488972d8488b71e0488b7ae0488979e0488972e0488b71e8488b7ae8488979e8488972e8488b71f0488b7af0488979f0488972f0488b71f8488b7af8488979f8488972f8488b31488b3a4889394889324883c1384883c2c848ffc87587'),
    ('status_dispatch', 0x299c6d0, '400fb6c6ffc8488d0dcf3fc6fd486304814801c8ffe0'),
    ('reset_fields', 0x2973254, '48c783180100000000000048c7432800000000c683b000000000'),
    ('reset_id_guard', 0x2973371, '8b8320010000ffc87473898320010000'),
    ('reset_log_length', 0x2973381, '4c8b73084c8b7b1048c743100000000049ffc7'),
    ('reset_failure_message', 0x29733ee, '488d3dfce2c8fd488d15b4daac03be2f000000ff15b1c2b603'),
    ('drain_initial', 0x2972c2e, '4989f648897c2440c686b0000000004c8ba6880000004d85e40f84df000000'),
    ('drain_addresses_clear', 0x2972d1a, '49c78688000000000000004989868000000049c7464000000000'),
    ('drain_take_and_replace', 0x2972d7e, '498b86e80000004889442430410f1086c8000000f3410f6f8ed8000000660f7f4c24200f294424100f10051beeac03410f1186c8000000f30f6f051beeac03f3410f7f86d8000000498996e8000000'),
    ('drain_revision_gate', 0x2972dcd, '4180be26010000020f8748010000488b4424284885c00f843a010000'),
    ('drain_log_length', 0x2972f23, '4d8b7e084d8b6e1049c746100000000049ffc54c8b2563c5b603'),
    ('drain_final', 0x2973084, '49c746280000000049c786180100000000000041c78620010000ffffffff488b442430488b4c2440488941200f284424100f284c24200f1149100f1101'),
]

# The driver and value-transfer callers are external ownership boundaries.
# Their selected call sites connect this packet's functions to the earlier
# address-09 research without selecting those callers' FDEs again.
EDGES = [
    ('transfer_event_boundary', 0x2970e88, 'call', 0x29714f0),
    ('driver_finalize', 0x29663d3, 'call', 0x2972200),
    ('driver_classify', 0x2966423, 'call', 0x299c6d0),
    ('driver_reset', 0x2966846, 'call', 0x2973130),
    ('driver_take_map', 0x29669b5, 'call', 0x2972c20),
    ('transfer_revision_skip', 0x2971505, 'jcc', 0x29716f8),
    ('transfer_flag_skip', 0x2971515, 'jcc', 0x29716f8),
    ('transfer_zero_skip', 0x2971536, 'jcc', 0x29716f8),
    ('transfer_topic_allocation_failure', 0x2971553, 'jcc', 0x2971707),
    ('transfer_data_allocation_failure', 0x2971620, 'jcc', 0x2971717),
    ('transfer_has_capacity', 0x29716a7, 'jcc', 0x29716b2),
    ('transfer_cleanup', 0x2971731, 'call', 0x29ed2b0),
    ('transfer_unwind', 0x2971754, 'call', 0x63f0a50),
    ('one_key_revision_skip', 0x2970ec5, 'jcc', 0x297107e),
    ('one_key_flag_skip', 0x2970ed5, 'jcc', 0x297107e),
    ('one_key_zero_skip', 0x2970ef6, 'jcc', 0x297107e),
    ('one_key_topic_allocation_failure', 0x2970f10, 'jcc', 0x297108d),
    ('one_key_data_allocation_failure', 0x2970fa6, 'jcc', 0x297109d),
    ('one_key_has_capacity', 0x297102d, 'jcc', 0x2971038),
    ('one_key_cleanup', 0x29710b7, 'call', 0x29ed2b0),
    ('one_key_unwind', 0x29710da, 'call', 0x63f0a50),
    ('batch_revision_skip', 0x2972218, 'jcc', 0x2972311),
    ('batch_flag_skip', 0x2972228, 'jcc', 0x2972311),
    ('batch_second_flag_skip', 0x2972236, 'jcc', 0x2972311),
    ('batch_collect', 0x297226c, 'call', 0x2346480),
    ('batch_sort_if_two', 0x2972289, 'jcc', 0x2972323),
    ('batch_no_rows', 0x2972297, 'jcc', 0x2972300),
    ('batch_emit', 0x29722ed, 'call', 0x2970eb0),
    ('batch_next_row', 0x29722f9, 'jcc', 0x29722c0),
    ('batch_large_sort', 0x2972327, 'jcc', 0x297234b),
    ('batch_small_sort', 0x2972339, 'call', 0x26d4140),
    ('batch_unwind', 0x2972389, 'call', 0x63f0a50),
    ('collect_initial_end', 0x23464c3, 'jcc', 0x2346610),
    ('collect_first_lookup', 0x23464d6, 'call', 0x29dee60),
    ('collect_first_miss', 0x23464e3, 'jcc', 0x23464c0),
    ('collect_allocation_failure', 0x23464f3, 'jcc', 0x2346656),
    ('collect_next_lookup', 0x2346598, 'call', 0x29dee60),
    ('collect_next_miss', 0x23465a5, 'jcc', 0x2346580),
    ('collect_grow', 0x23465cb, 'call', 0x231e050),
    ('collect_unwind', 0x2346689, 'call', 0x63f0a50),
    ('account_empty_map', 0x29dee6b, 'jcc', 0x29defdf),
    ('account_full_key_match', 0x29def2b, 'jcc', 0x29def62),
    ('account_empty_control', 0x29def4c, 'jcc', 0x29defdf),
    ('account_next_group', 0x29def5d, 'jmp', 0x29deec7),
    ('account_zero_balance', 0x29def81, 'jcc', 0x29defdf),
    ('small_sort_ordered', 0x26d41e0, 'jcc', 0x26d41bf),
    ('small_sort_continue_shift', 0x26d425f, 'jcc', 0x26d4210),
    ('large_sort_allocate', 0x36e369b, 'jcc', 0x36e36a7),
    ('large_sort_null', 0x36e36e3, 'jcc', 0x36e3721),
    ('large_sort_external', 0x36e36f6, 'call', 0x3dfd7e0),
    ('large_run_short_input', 0x3dfd804, 'jcc', 0x3dfdedd),
    ('large_run_size_threshold', 0x3dfd839, 'jcc', 0x3dfd858),
    ('large_run_minimum_check', 0x3dfd937, 'jcc', 0x3dfd990),
    ('large_run_subsort_flag', 0x3dfd93e, 'jcc', 0x3dfd9a0),
    ('large_run_initial_order', 0x3dfd9d8, 'jcc', 0x3dfda24),
    ('large_run_nondecreasing_end', 0x3dfda14, 'jcc', 0x3dfda85),
    ('large_run_nondecreasing_loop', 0x3dfda20, 'jcc', 0x3dfda00),
    ('large_run_decreasing_end', 0x3dfda64, 'jcc', 0x3dfda85),
    ('large_run_decreasing_loop', 0x3dfda70, 'jcc', 0x3dfda50),
    ('large_run_skip_reversal', 0x3dfdaa6, 'jcc', 0x3dfdb39),
    ('large_run_reverse_loop', 0x3dfdb37, 'jcc', 0x3dfdac0),
    ('reset_counter_error', 0x2973379, 'jcc', 0x29733ee),
    ('drain_revision_gt_two', 0x2972dd5, 'jcc', 0x2972f23),
    ('drain_empty_map', 0x2972de3, 'jcc', 0x2972f23),
]

# These are source-boundary instruction shapes, not an exhaustive RIP census.
RIP = [
    ('transfer_topic_hi', 0x29715d5, '0f1005', 0x4581f0),
    ('transfer_topic_lo', 0x29715e1, '0f1005', 0x4581e0),
    ('one_key_topic_hi', 0x2970f6f, '0f1005', 0x458730),
    ('one_key_topic_lo', 0x2970f7b, '0f1005', 0x458720),
    ('transfer_emitter', 0x297165d, '0f1005', 0x6017b0),
    ('one_key_emitter', 0x2970fe3, '0f1005', 0x6017b0),
    ('account_hash_secret_slot', 0x29dee77, '488b05', 0x64dfa78),
    ('batch_large_sort_slot', 0x2972356, 'ff15', 0x64e6d70),
    ('small_sort_comparator_slot', 0x26d4176, '488b2d', 0x64dfb50),
    ('large_run_subsort_slot', 0x3dfd975, 'ff15', 0x64e98f8),
    ('large_run_first_compare', 0x3dfd9d0, 'ff15', 0x64dfb50),
    ('large_run_nondecreasing_compare', 0x3dfda0c, 'ff15', 0x64dfb50),
    ('large_run_decreasing_compare', 0x3dfda5c, 'ff15', 0x64dfb50),
    ('status_switch_table', 0x299c6d6, '488d0d', 0x6006ac),
    ('next_table_reference', 0x299c941, '488d0d', 0x600788),
    ('reset_source_descriptor', 0x29733f5, '488d15', 0x6440eb0),
    ('drain_empty_header_0', 0x2972da6, '0f1005', 0x6441bc8),
    ('drain_empty_header_1', 0x2972db5, 'f30f6f05', 0x6441bd8),
]

RELATIVE = {
    0x6440eb0: 0x44abe5,
    0x6441bc8: 0x450150,
    0x64df480: 0x6355830,
    0x64df490: 0x141e251,
    0x64df498: 0x141e264,
    0x64df4a0: 0x635de30,
    0x64df4c0: 0x1680cab,
    0x64df8c0: 0x64040e8,
    0x64df8c8: 0x64040c0,
    0x64dfa48: 0x1437200,
    0x64dfa78: 0x64ffe90,
    0x64e6d70: 0x36e3660,
    0x64e98f8: 0x428c410,
}
LITERALS = [
    ('two_key_topic', 0x4581e0, 'ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'),
    ('one_key_topic', 0x458720, 'cc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5'),
    ('emitter', 0x6017b0, 'fffffffffffffffffffffffffffffffffffffffe'),
]


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target SHA-256 mismatch')


def read_va(data, sec, va, size):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid virtual range')
    possible = [s for s in sec if s['type'] != 8 and s['size'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(possible) != 1:
        raise ValueError('virtual range must be uniquely file-backed')
    s = possible[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file range is truncated')
    return data[off:off + size], off, s['name']


def match_window(data, sec, va, expected):
    raw, off, name = read_va(data, sec, va, len(expected))
    if raw != expected:
        raise ValueError('changed selected instruction window')
    return raw, off, name


def branch_destination(va, raw, kind):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        category = 'call' if raw[0] == 0xe8 else 'jmp'
        delta = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
        category = 'jmp' if raw[0] == 0xeb else 'jcc'
        delta = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        category = 'jcc'
        delta = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported relative branch shape')
    if category != kind:
        raise ValueError('wrong branch kind')
    return va + len(raw) + delta


def inspect_edge(data, sec, site, kind, expected):
    first = read_va(data, sec, site, 1)[0][0]
    size = 6 if first == 0x0f else (5 if first in (0xe8, 0xe9) else 2)
    raw, off, name = read_va(data, sec, site, size)
    target = branch_destination(site, raw, kind)
    if target != expected:
        raise ValueError('changed selected branch destination')
    return raw, off, name, target


def rip_destination(va, raw, prefix):
    if len(raw) != len(prefix) + 4 or not raw.startswith(prefix):
        raise ValueError('changed RIP-relative shape')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]


def collect_relocations(data, sec, selected):
    remaining = set(selected)
    found = {}
    tables = [s for s in sec if s['type'] == 4]
    for s in tables:
        if s['size'] % 24 or s['offset'] + s['size'] > len(data):
            raise ValueError('truncated RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            if slot not in selected:
                continue
            if slot in found:
                raise ValueError('duplicate selected relocation')
            if info != 8 or addend != selected[slot]:
                raise ValueError('unexpected relocation type, symbol, or addend')
            found[slot] = {'slot_va': hex(slot), 'section': s['name'],
                           'relocation_file_offset': hex(pos), 'raw_hex': data[pos:pos + 24].hex(),
                           'info': hex(info), 'addend_va': hex(addend)}
            remaining.remove(slot)
    if remaining:
        raise ValueError('missing selected relocation')
    return found


def symbol_relocation(data, sec, slot, symbol):
    results = []
    for s in sec:
        if s['type'] != 4:
            continue
        if s['size'] % 24 or s['offset'] + s['size'] > len(data):
            raise ValueError('truncated RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if where == slot:
                results.append((pos, info, addend, s['name']))
    if len(results) != 1:
        raise ValueError('missing or duplicate dynamic relocation')
    pos, info, addend, relname = results[0]
    idx, typ = info >> 32, info & 0xffffffff
    tables = [s for s in sec if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in sec if s['name'] == '.dynstr' and s['type'] == 3]
    if len(tables) != 1 or len(strings) != 1 or typ != 6 or not idx:
        raise ValueError('unexpected dynamic relocation')
    table, names = tables[0], strings[0]
    entry = table['offset'] + idx * 24
    if entry + 24 > table['offset'] + table['size']:
        raise ValueError('dynamic symbol outside table')
    nameoff = struct.unpack_from('<I', data, entry)[0]
    if nameoff >= names['size']:
        raise ValueError('dynamic symbol name outside table')
    first, limit = names['offset'] + nameoff, names['offset'] + names['size']
    last = data.find(b'\0', first, limit)
    if last < 0 or data[first:last] != symbol.encode('ascii'):
        raise ValueError('dynamic symbol does not match')
    return {'slot_va': hex(slot), 'symbol': symbol, 'symbol_index': idx,
            'type': typ, 'addend': addend, 'section': relname,
            'relocation_file_offset': hex(pos), 'raw_hex': data[pos:pos + 24].hex()}


SOURCE_DESCRIPTORS = [
    ('reset_guard', 0x6440eb0, 0x44abe5, 'z_vendor/revm-state/src/lib.rs'),
]


def decode_source_location(descriptor, source, suffix):
    if len(descriptor) != 24:
        raise ValueError('invalid source descriptor size')
    length, line, column = struct.unpack_from('<QII', descriptor, 8)
    tail = suffix.encode('ascii')
    if length != len(source) or not source.endswith(tail) or len(source) <= len(tail):
        raise ValueError('source descriptor or suffix mismatch')
    if source[-len(tail) - 1:-len(tail)] != b'/':
        raise ValueError('source suffix boundary mismatch')
    return {'length': length, 'line': line, 'column': column,
            'source_suffix': suffix, 'suffix_hex': tail.hex()}


def collect_source_locations(data, sec):
    rows = []
    for label, descriptor_va, source_va, suffix in SOURCE_DESCRIPTORS:
        raw, off, section = read_va(data, sec, descriptor_va, 24)
        length = struct.unpack_from('<Q', raw, 8)[0]
        if not 0 < length <= 1024:
            raise ValueError('source path length outside selected bound')
        source, source_off, source_section = read_va(data, sec, source_va, length)
        item = decode_source_location(raw, source, suffix)
        rows.append({'label': label, 'descriptor_va': hex(descriptor_va),
                     'descriptor_file_offset': hex(off), 'descriptor_section': section,
                     'descriptor_hex': raw.hex(), 'path_va': hex(source_va),
                     'path_file_offset': hex(source_off), 'path_section': source_section, **item})
    return rows


def selected_frames(data, sec):
    _, all_fdes = eh_frame_records(data, sec)
    wanted = {start: (role, end) for role, start, end in FUNCTIONS}
    chosen = {}
    for fde in all_fdes:
        start = fde['start']
        if start not in wanted:
            continue
        if start in chosen or fde['end'] != wanted[start][1]:
            raise ValueError('duplicate or changed selected FDE')
        chosen[start] = fde
    if set(chosen) != set(wanted):
        raise ValueError('missing selected FDE')
    _, index = unwind_index(data)
    indexed = {}
    for row in index:
        if row['start'] in wanted:
            if row['start'] in indexed:
                raise ValueError('duplicate indexed start')
            indexed[row['start']] = row
    if set(indexed) != set(wanted):
        raise ValueError('selected start missing from unwind index')
    frames = []
    for role, start, end in FUNCTIONS:
        f = chosen[start]
        if indexed[start]['fde'] != f['fde']:
            raise ValueError('FDE and unwind index disagree')
        raw, off, section = read_va(data, sec, start, end - start)
        if section != '.text':
            raise ValueError('selected range outside text')
        fde_header = read_va(data, sec, f['fde'], 4)[0]
        fde_size = 4 + struct.unpack('<I', fde_header)[0]
        fde_raw = read_va(data, sec, f['fde'], fde_size)[0]
        cie_header = read_va(data, sec, f['cie'], 4)[0]
        cie_size = 4 + struct.unpack('<I', cie_header)[0]
        cie_raw = read_va(data, sec, f['cie'], cie_size)[0]
        frames.append({'role_inferred': role, 'start_va': hex(start), 'end_va': hex(end),
                       'file_offset': hex(off), 'section': section, 'byte_count': len(raw),
                       'sha256': hashlib.sha256(raw).hexdigest(), 'raw_hex': raw.hex(),
                       'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                       'lsda_va': None if f['lsda'] is None else hex(f['lsda']),
                       'fde_hex': fde_raw.hex(), 'cie_hex': cie_raw.hex()})
    return frames, chosen


def parse_lsda(blob, function_start, function_end):
    """Decode a bounded call-site table; action chains are deliberately opaque."""
    if type(function_start) is not int or type(function_end) is not int or not 0 <= function_start < function_end:
        raise ValueError('invalid FDE interval')
    limit = len(blob)
    if limit < 3 or blob[0] != 0xff or blob[1] not in (0xff, 0x9b):
        raise ValueError('unsupported or truncated LSDA header')
    type_encoding = blob[1]
    p = 2
    type_off = None
    if type_encoding == 0x9b:
        relative, p = uleb(blob, p, limit)
        type_off = p + relative
        if type_off > limit:
            raise ValueError('LSDA type table outside section')
    if p >= limit or blob[p] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    p += 1
    length, p = uleb(blob, p, limit)
    first, stop = p, p + length
    if stop > limit or (type_off is not None and stop > type_off):
        raise ValueError('truncated LSDA call-site table')
    rows = []
    while p < stop:
        before = p
        relative_start, p = uleb(blob, p, stop)
        size, p = uleb(blob, p, stop)
        landing, p = uleb(blob, p, stop)
        action, p = uleb(blob, p, stop)
        begin, end = function_start + relative_start, function_start + relative_start + size
        landing_va = None if landing == 0 else function_start + landing
        if not function_start <= begin <= end <= function_end:
            raise ValueError('LSDA call-site outside FDE')
        if landing_va is not None and not function_start <= landing_va < function_end:
            raise ValueError('LSDA landing pad outside FDE')
        rows.append({'offset': before, 'raw_hex': blob[before:p].hex(),
                     'start_va': hex(begin), 'end_va': hex(end),
                     'landing_pad_va': None if landing_va is None else hex(landing_va),
                     'action_index': action})
    return {'header_hex': blob[:first].hex(), 'type_encoding': type_encoding,
            'type_table_offset': type_off, 'callsite_byte_count': length}, rows


def collect_lsda(data, sec, selected):
    candidates = [s for s in sec if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(candidates) != 1:
        raise ValueError('exception section missing or ambiguous')
    section = candidates[0]
    headers, records = [], []
    for role, start, _ in FUNCTIONS:
        fde = selected[start]
        if fde['lsda'] is None:
            continue
        va = fde['lsda']
        _, off, name = read_va(data, sec, va, 1)
        if name != '.gcc_except_table':
            raise ValueError('LSDA outside exception section')
        blob = data[off:section['offset'] + section['size']]
        hdr, rows = parse_lsda(blob, fde['start'], fde['end'])
        headers.append({'role_inferred': role, 'function_va': hex(start), 'lsda_va': hex(va),
                        'file_offset': hex(off), **hdr, 'callsite_count': len(rows)})
        for row in rows:
            entry = row.pop('offset')
            records.append({'function_va': hex(start), 'lsda_va': hex(va),
                            'entry_file_offset': hex(off + entry), **row})
    return headers, records


def decode_status_arm(body):
    """Recognize only the observed constant-store/ret arms of the status switch."""
    if body.startswith(b'\x0f\x0b'):
        return {'kind': 'ud2', 'byte_count': 2, 'raw_hex': body[:2].hex()}
    p, extra = 0, None
    if body.startswith(b'\xc6\x47\x08'):
        if len(body) < 4:
            raise ValueError('truncated status byte store')
        extra, p = body[3], 4
    if len(body) < p + 10 or body[p:p + 2] != b'\x48\xb8':
        raise ValueError('unsupported status arm constant load')
    value = struct.unpack_from('<Q', body, p + 2)[0]
    if value != 1 << 63:
        raise ValueError('unexpected status arm base')
    p += 10
    if body[p:p + 3] == b'\x48\x83\xc8':
        if len(body) < p + 4 or body[p + 3] >= 128:
            raise ValueError('bad status arm immediate')
        value |= body[p + 3]
        p += 4
    elif body[p:p + 3] == b'\x48\xff\xc0':
        value += 1
        p += 3
    if body[p:p + 3] != b'\x48\x89\x07':
        raise ValueError('missing status word store')
    p += 3
    if body[p:p + 3] == b'\xc6\x47\x08':
        if len(body) < p + 4 or extra is not None:
            raise ValueError('bad second status byte store')
        extra = body[p + 3]
        p += 4
    if body[p:p + 1] != b'\xc3':
        raise ValueError('missing status arm return')
    p += 1
    return {'kind': 'return', 'result_word': hex(value), 'extra_byte': extra,
            'byte_count': p, 'raw_hex': body[:p].hex()}


def status_table(data, sec):
    table_va, function_start, function_end = 0x6006ac, 0x299c6d0, 0x299c929
    # The next independently referenced table begins at 0x600788. This is
    # a bounded 55-entry inspection, not proof of the enum's valid domain.
    rows = []
    for status in range(1, (0x600788 - table_va) // 4 + 1):
        cell = table_va + 4 * (status - 1)
        raw, off, name = read_va(data, sec, cell, 4)
        target = table_va + struct.unpack('<i', raw)[0]
        if name != '.rodata' or not function_start <= target < function_end:
            raise ValueError('status table target outside selected FDE')
        arm, _, _ = read_va(data, sec, target, min(32, function_end - target))
        parsed = decode_status_arm(arm)
        rows.append({'status': hex(status), 'cell_va': hex(cell),
                     'cell_file_offset': hex(off), 'cell_hex': raw.hex(),
                     'target_va': hex(target), **parsed})
    return rows


def fold64(a, b):
    if type(a) is not int or type(b) is not int or not 0 <= a <= WORD_MASK or not 0 <= b <= WORD_MASK:
        raise ValueError('fold operands must be unsigned 64-bit integers')
    product = a * b
    return (product & WORD_MASK) ^ (product >> 64)


def account_hash(key, seed, secret):
    if not isinstance(key, bytes) or len(key) != 20:
        raise ValueError('account key must have 20 bytes')
    if type(seed) is not int or type(secret) is not int or not 0 <= seed <= WORD_MASK or not 0 <= secret <= WORD_MASK:
        raise ValueError('hash inputs must be unsigned 64-bit integers')
    left = int.from_bytes(key[:8], 'little') ^ seed
    right = int.from_bytes(key[8:16], 'little') ^ secret
    tail = int.from_bytes(key[16:], 'little')
    return fold64(fold64(left, right) ^ tail, secret)


def event_payload(kind, revision, disabled, sender, recipient, amount, constants):
    if kind not in ('two_key', 'one_key'):
        raise ValueError('unknown event kind')
    if type(revision) is not int or not 0 <= revision <= 255:
        raise ValueError('revision byte outside range')
    if type(disabled) is not int or not 0 <= disabled <= 255:
        raise ValueError('flag byte outside range')
    if not isinstance(sender, bytes) or len(sender) != 20:
        raise ValueError('first key must have 20 bytes')
    if kind == 'two_key' and (not isinstance(recipient, bytes) or len(recipient) != 20):
        raise ValueError('second key must have 20 bytes')
    if type(amount) is not int or not 0 <= amount < 1 << 256:
        raise ValueError('amount outside u256')
    if revision < 14 or disabled != 0 or amount == 0:
        return None
    topic = constants[kind + '_topic']
    emitter = constants['emitter']
    if len(topic) != 32 or len(emitter) != 20:
        raise ValueError('invalid literal lengths')
    topics = [topic, bytes(12) + sender]
    if kind == 'two_key':
        topics.append(bytes(12) + recipient)
    return {'emitter': emitter.hex(), 'topics': [v.hex() for v in topics],
            'data': amount.to_bytes(32, 'big').hex()}


def batch_gate(revision, first_flag, second_flag):
    fields = (revision, first_flag, second_flag)
    if any(type(v) is not int or not 0 <= v <= 255 for v in fields):
        raise ValueError('gate inputs must be bytes')
    return revision >= 14 and first_flag == 0 and second_flag == 0


def reset_guard(word):
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('reset field must be an unsigned 32-bit word')
    dec = (word - 1) & 0xffffffff
    return ('failure', None) if dec == 0 else ('store', dec)


def select_small_rows(keys, accounts):
    """Model a file-grounded bounded case; the large sort remains external."""
    if not isinstance(keys, list) or not isinstance(accounts, dict):
        raise ValueError('invalid synthetic inputs')
    rows = []
    for key in keys:
        if not isinstance(key, bytes) or len(key) != 20:
            raise ValueError('key must have 20 bytes')
        if key not in accounts:
            continue
        value = accounts[key]
        if type(value) is not int or not 0 <= value < 1 << 256:
            raise ValueError('value outside u256')
        if value:
            rows.append((key, value))
    if len(rows) >= 21:
        raise ValueError('large sort path is outside the synthetic model')
    rows.sort(key=lambda row: row[0])
    return rows


def row_sort_scratch(count):
    # Model the selected adapter's scratch-count decision, not the sorter.
    if type(count) is not int or not 0 <= count <= WORD_MASK:
        raise ValueError('row count outside u64')
    half_rounded_up = count - (count >> 1)
    requested = max(min(count, 0x22e09), half_rounded_up)
    return {'requested_rows': requested, 'heap_branch': requested >= 74,
            'short_sort_flag': count < 65}


def synthetic_cases(constants):
    address = lambda n: n.to_bytes(20, 'big')
    sender, recipient = address(4), address(9)
    amount = (1 << 192) + (1 << 64) + 3
    enabled = event_payload('two_key', 14, 0, sender, recipient, amount, constants)
    cases = []
    for label, rev, flag, value in [('below_revision', 13, 0, amount),
                                    ('at_revision', 14, 0, amount),
                                    ('disabled', 14, 1, amount),
                                    ('zero_value', 14, 0, 0)]:
        event = event_payload('two_key', rev, flag, sender, recipient, value, constants)
        cases.append({'label': label, 'revision': rev, 'disabled_flag': flag,
                      'amount': str(value), 'emitted': event is not None})
    keys = [address(9), address(1), address(3), address(2)]
    accounts = {address(9): 256, address(1): 0, address(3): 3}
    rows = select_small_rows(keys, accounts)
    events = [event_payload('one_key', 14, 0, key, None, val, constants) for key, val in rows]
    return {'notice': 'Synthetic model inputs, not captured execution or observed runtime state.',
            'two_key_example': enabled, 'gate_cases': cases,
            'batch_gate_cases': [{'revision': r, 'first_flag': a, 'second_flag': b,
                                  'proceeds': batch_gate(r, a, b)}
                                 for r, a, b in [(13, 0, 0), (14, 0, 0), (14, 1, 0), (14, 0, 1)]],
            'large_sort_scratch_cases': [{'rows': n, **row_sort_scratch(n)} for n in [21, 64, 65, 73, 74]],
            'reset_field_cases': [{'input': n, 'route': reset_guard(n)[0], 'stored': reset_guard(n)[1]}
                                  for n in [0, 1, 2, (1 << 32) - 1]],
            'small_batch_input_keys': [x.hex() for x in keys],
            'small_batch_selected': [{'key': k.hex(), 'value': str(v)} for k, v in rows],
            'small_batch_one_key_events': events,
            'synthetic_hash': {'key': recipient.hex(), 'seed': 7, 'secret': 11,
                               'hash': hex(account_hash(recipient, 7, 11))}}


def tsv(rows, fields):
    from io import StringIO
    stream = StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({k: '' if row.get(k) is None else row.get(k, '') for k in fields})
    return stream.getvalue().encode('ascii')


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def collect(data):
    authenticate(data)
    sec = sections(data)
    functions, fdes = selected_frames(data, sec)
    windows = []
    for label, va, expected in WINDOWS:
        raw, off, name = match_window(data, sec, va, bytes.fromhex(expected))
        windows.append({'label': label, 'va': hex(va), 'file_offset': hex(off),
                        'section': name, 'byte_count': len(raw), 'raw_hex': raw.hex()})
    edges = []
    for label, va, kind, target in EDGES:
        raw, off, name, actual = inspect_edge(data, sec, va, kind, target)
        edges.append({'label': label, 'kind': kind, 'site_va': hex(va),
                      'file_offset': hex(off), 'section': name,
                      'raw_hex': raw.hex(), 'target_va': hex(actual)})
    rip_rows = []
    for label, va, prefix, expected in RIP:
        bprefix = bytes.fromhex(prefix)
        raw, off, name = read_va(data, sec, va, len(bprefix) + 4)
        target = rip_destination(va, raw, bprefix)
        if target != expected:
            raise ValueError('changed RIP target')
        rip_rows.append({'label': label, 'site_va': hex(va), 'file_offset': hex(off),
                         'section': name, 'raw_hex': raw.hex(), 'target_va': hex(target)})
    rels = collect_relocations(data, sec, RELATIVE)
    secret_va = int(rels[0x64dfa78]['addend_va'], 16)
    secret_sections = [s for s in sec if s['type'] == 8 and
                       s['address'] <= secret_va < s['address'] + s['size']]
    if len(secret_sections) != 1 or secret_sections[0]['name'] != '.bss':
        raise ValueError('account secret storage is not uniquely NOBITS')
    rels['symbol'] = symbol_relocation(data, sec, 0x64dfb50, 'memcmp')
    literal_rows, constants = [], {}
    for label, va, expected in LITERALS:
        raw, off, name = match_window(data, sec, va, bytes.fromhex(expected))
        constants[label] = raw
        literal_rows.append({'label': label, 'va': hex(va), 'file_offset': hex(off),
                             'section': name, 'raw_hex': raw.hex()})
    statuses = status_table(data, sec)
    locations = collect_source_locations(data, sec)
    headers, sites = collect_lsda(data, sec, fdes)
    samples = synthetic_cases(constants)
    summary = {'target_release': '115', 'target_sha256': SHA256,
               'account_hash_secret': {'slot_va': hex(0x64dfa78),
                                       'target_va': hex(secret_va),
                                       'section': secret_sections[0]['name'],
                                       'section_type': secret_sections[0]['type']},
               'selected_fde_count': len(functions),
               'selected_fde_bytes': sum(f['byte_count'] for f in functions),
               'selected_windows': len(windows), 'selected_relative_edges': len(edges),
               'selected_rip_references': len(rip_rows), 'selected_relative_relocations': len(RELATIVE),
               'selected_symbol_relocations': 1, 'literal_count': len(literal_rows), 'selected_source_descriptors': len(locations),
               'inspected_status_entries': len(statuses),
               'lsda_headers': len(headers), 'lsda_callsite_rows': len(sites),
               'limitations': 'Selected windows, FDE ranges, statuses and LSDA call sites are not whole-node coverage.'}
    return {
        'functions.json': json_bytes(functions),
        'windows.tsv': tsv(windows, ['label', 'va', 'file_offset', 'section', 'byte_count', 'raw_hex']),
        'edges.tsv': tsv(edges, ['label', 'kind', 'site_va', 'file_offset', 'section', 'raw_hex', 'target_va']),
        'rip-references.tsv': tsv(rip_rows, ['label', 'site_va', 'file_offset', 'section', 'raw_hex', 'target_va']),
        'relocations.json': json_bytes({str(hex(k)): rels[k] for k in sorted(RELATIVE)} | {'dynamic_symbol': rels['symbol']}),
        'literals.json': json_bytes(literal_rows),
        'source-locations.json': json_bytes(locations),
        'status-table.json': json_bytes({'status_table': statuses}),
        'exceptions.json': json_bytes({'headers': headers, 'call_sites': sites}),
        'synthetic-cases.json': json_bytes(samples),
        'summary.json': json_bytes(summary),
    }


LEGACY_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def cross_release_check(current, legacy):
    # Optional check of previously reported anchors; these are not selected
    # functions or generated evidence in this packet.
    if hashlib.sha256(legacy).hexdigest() != LEGACY_SHA256:
        raise ValueError('historical target SHA-256 mismatch')
    authenticate(current)
    old_sec, new_sec = sections(legacy), sections(current)
    key = bytes(19) + b'\x09'
    if read_va(legacy, old_sec, 0x574f0c0, 20)[0] != key:
        raise ValueError('historical address key mismatch')
    if read_va(current, new_sec, 0x64c0750, 20)[0] != key:
        raise ValueError('current address key mismatch')
    collect_relocations(legacy, old_sec, {0x574f0b0: 0x4e9d2a0})
    collect_relocations(current, new_sec, {0x64c0748: 0x5c165b0, 0x64eaee8: 0x5c16650})
    _, fdes = eh_frame_records(legacy, old_sec)
    old = [f for f in fdes if f['start'] == 0x4e9d2a0]
    if len(old) != 1 or old[0]['end'] != 0x4e9d47b:
        raise ValueError('historical wrapper FDE mismatch')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--legacy', type=Path, help='optionally verify historical cross-release anchors')
    args = parser.parse_args()
    current = TARGET.read_bytes()
    if args.legacy is not None:
        cross_release_check(current, args.legacy.read_bytes())
        print('Historical and current address-key and callback anchors verified.')
    contents = collect(current)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in contents.items():
        (args.out / name).write_bytes(content)
    print('Generated', len(contents), 'evidence files for node 115.')


if __name__ == '__main__':
    main()
