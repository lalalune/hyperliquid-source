"""Extract a selected node 115 compact context-read route from authenticated ELF bytes."""

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# The labels are descriptive, and the exclusive ends are FDE ranges rather
# than a claim that source functions, cold fragments, or ownership end there.
FUNCTIONS = [
    ('locus_reader', 0x332c430, 0x333208d, '29b504265f31448dcc7c6c6b435f92e3de4d0adad5a2c492dfbac9ca1dd3e950'),
    ('context_reader', 0x30d1c60, 0x30d3ee7, 'ac0c296f80c2be4f678214f8e79f5f3862e8bf7c4515d79529ea33ff33c5ea12'),
    ('locus_field_key', 0x2fbbd20, 0x2fbbe89, '781bf4cffed789b30c6d92a42b8bb7112cc702ee1e080f8d21c2c0900c3d1754'),
    ('context_field_key', 0x41fbef0, 0x41fc480, '8fad1f781374f12e30f2cc514672c3d02f2b2870ebd197a35e0781af0d1b8585'),
    ('unsigned_value', 0x348e980, 0x348ec9e, '2ba16eaf9f603bd90c33ca77d6d1b291b92c84a6ed0b475747a400310fdb950a'),
    ('exchange_field_key', 0x3bd7d50, 0x3bda734, 'c17ef30702716c74ee400a59a34d340514e8a5319954fcfcbac18a3996a7b1dc'),
    ('exchange_numeric_key', 0x347f020, 0x347f2e1, '7176e12a9468bc94016b6867de2af0a4d67c9bc014336a1090c88df3bfc59df2'),
    ('locus_numeric_key', 0x33de700, 0x33de9c1, '9985d13193322919670d25ba67632b5492bed15d3a92f2e0178eede34a980ac9'),
    ('context_numeric_key', 0x348eca0, 0x348ef61, '1d92876fcdc22720bfa0a5f721bdd5767e5aac4d65c66c8ba5d6d7aecaa04e9b'),
]

# Windows in previous parent functions and the writer are context, not FDE ownership.
WINDOWS = [
    ('parent_locus_branch', 0x2fd78c1, '83bc24384b0000020f854a890000488dbc24380b00004c89ee31d2e84f4b35004c8bb424380b0000488d8424400b00000f10000f1048100f298424000600000f298c24100600004983fe020f84e2400000'),
    ('parent_string_key', 0x2fd9928, '0fb6c289c54829e90f82301800004d8b7510498d042e4989451049894d18488dbc24401f00004c89f64889eaff154e63500383bc24401f000001753c488dbc24380b00004c89f64889eae8d9e3bf000fb68424380b000083f809753e0fb68424390b0000888424f12e0000c68424f02e000009'),
    ('locus_ctx_branch', 0x332c7e9, '4883bc2488000000020f85a0380000488dbc24700c00004c89fe31d2e85654daff488b8c24700c00000fb68424780c0000888424780100000fb68424790c000088842480010000488d9424980c00008b42e2898424f00200000fb742e666898424f4020000488b8424800c000048894424480f1042f00f2984240006000048898c24880000004883f9020f8462220000'),
    ('locus_string_key', 0x332d566, '498b4718400fb6d689d54829e80f82231100004d8b6710498d0c2c49894f1049894718488dbc24000600004c89e64889eaff150b271b0383bc240006000001753c4c8db424700c00004c89f74c89e64889eae863e7c8ff80bc24700c000009753e0fb68424710c0000888424f1020000c68424f002000009e9def1ffff'),
    ('context_string_key', 0x30d276b, '488b4618448964242c400fb6d74189d44c29e00f82860c00004c89ac24680100004c8b6e104b8d0c2c48894e104889f548894618488d7c24084c89ee4c89e2ff15f8d44003837c2408017527488d7c24504c89ee4c89e2e829971201807c24500975240fb644245188442431c644243009eb54488b742410488b5424184c89ffe8e09e1201eb40488d4424100f1000488d8424c70100000f1100c644243007488b8424cf010000488d4c24314889410ff30f6f8424c0010000f30f7f01488d7c2450e89e4bf5ff4c8bac2468010000448b64242c'),
    ('context_height_guard', 0x30d23a6, '4883bc2400010000010f84ef1600004889ee0fb64d200fb64521c645200180f9010f850e080000488b4e184885c90f848c0e0000488b561048ffc90fb60248ffc24889561048894e1884c00f886d06000031c9e9dd070000'),
    ('context_height_result', 0x30d2bdb, '0fb6d10fb6c8488d7c24504889f5ff1591f940030fb6442450488b4c24583c090f852506000048898c2498010000b8010000004889842400010000e9b3f4ffff'),
    ('context_initial_guard', 0x30d219a, '4883bc2428010000010f84991800004889ee0fb64d200fb64521c645200180f9010f85c20a0000488b4e184885c90f8498100000488b561048ffc90fb60248ffc24889561048894e1884c00f88a708000031c9e9910a0000'),
    ('context_initial_result', 0x30d2c83, '0fb6d10fb6c8488d7c24504889f5ff15e9f840030fb6442450488b4c24583c090f857d05000048898c24b0010000b8010000004889842428010000e90bf4ffff'),
    ('context_complete', 0x30d2f54, 'f68424280100000148898c24f80000000f844708000031c0f684245001000001488b8c24f0000000480f44c8488b9424e8000000480f44d0f6842400010000010f859a010000e9be040000'),
    ('context_output', 0x30d3197, '4c893b4c897308488b8424b00100004889431048894b1848895320488b8424980100004889432848897b30488b84249001000048894338'),
    ('duplicate_initial', 0x30d3a42, '488d05dbfa6bfd488944243048c74424380f000000e9a6000000'),
    ('duplicate_height', 0x30d3aa4, '488d0588fa6bfd488944243048c744243806000000eb47'),
    ('missing_height', 0x30d3473, '488d05b9006cfd488944243048c744243806000000488d4424304889442408488d0557a360014889442410488d351ff135fd488d7c2450488d542408e88c32f7ff0fb64424503c090f85d1020000488b4424584889842498010000'),
    ('locus_copy_child', 0x332c879, '488d8c24980c0000488b415048898424d00400000f1041400f298424c00400000f10010f1049100f1051200f1059300f299c24b00400000f299424a00400000f298c24900400000f298424800400008b8424f0020000898424880100000fb78424f4020000668984248c0100000f288424000600000f29842410180000'),
    ('locus_stage_a', 0x332de6e, '4883bc2488000000020f84c4fbffff0fb784248c010000668984249c0100008b842488010000898424980100000f288424101800000f298424301800000f288424800400000f288c24900400000f289424a00400000f289c24b00400000f298424200500000f298c24300500000f299424400500000f299c24500500000f288424c00400000f29842460050000488b8424d00400004889842470050000'),
    ('locus_stage_b', 0x33309eb, '0f288424200500000f288c24300500000f289424400500000f289c24500500000f298424103800000f298c24203800000f299424303800000f299c2440380000'),
    ('locus_stage_c', 0x3330b1f, '488dbc24981c0000488db42410380000ba100a000041ffd5'),
    ('locus_return', 0x332e013, 'ffc06641894722488db424701c0000baa00b00004889dfff15d8141b03'),
    ('parent_copy_1', 0x2fd7912, '488dbc24401f0000ba780b0000488db424600b0000ff15db7b5003'),
    ('parent_copy_2', 0x2fd796b, '488db424401f0000ba780b0000488dbc24604b0000e94afeffff'),
    ('parent_copy_3', 0x2fda85b, '83bc24384b0000020f8436cdffff48899c24d0000000488dbc24f02e0000488db424384b0000baa00b0000ff157c4c5003'),
    ('parent_copy_4', 0x2fe464f, '488dbc24380b0000488db424f02e0000baa00b0000ffd5'),
    ('parent_copy_5', 0x2fe4c55, 'bae81000004889df488db424380b0000ffd5'),
    ('wrapper_copy_1', 0x32cb221, '488db42488400000488dbc2420980000ba80270000ff15cc422103660f6f8424a0800000660f6f8c24b0800000f30f7f842400980000f30f7f8c24109800004c89bc24f8970000'),
    ('wrapper_copy_2', 0x32cb797, '488dbc2498100000488db424f8970000baa8270000ff15563d21030fb743226683f8ff0f84d01c0000ffc066894322488db42498100000e995000000'),
    ('wrapper_copy_3', 0x32cb868, 'baa82700004c89f7ff15923c21034c89f7eb8d'),
    ('outer_allocate', 0x32666bf, 'baa8270000488dbc24502800004c8da424a80000004c89e64c8b2d2a8e270341ffd5bfa8270000ff15948d27034885c04c8b7c24780f84c1100000baa827000048894424384889c74c89e641ffd5'),
    ('writer_first_field', 0x4d930a9, '4d8b671041807e0b01751e488d352f30b8fbba0f0000004c89f7e898c7a3004883f8020f8594020000488d7c24084c89f64c89e2e8cecfa300488b4424084883f8020f8570020000'),
    ('fixint', 0x348ea7e, '84c90f889f0100000fb6c148894708e95c010000'),
    ('scalar_success', 0x348ebd4, '4883c1f8488b104883c008480fca4889461048894e1848895708c607094889f84883c4505bc3'),
    ('scalar_short', 0x348ebae, '4801c84889461048c7461800000000c60701488d052937fd02488947084889f84883c4505bc3'),
    ('scalar_negative', 0x348ec25, '480fbec1eb0a48894c2440eb084863c24889442440c644243802'),
    ('key_length_guard', 0x41fbef0, '4889f84883c2fd4883fa0d0f8776050000488d0d58b25cfc486314914801caffe2'),
    ('locus_length_guard', 0x3bd7d50, '4889f84883c2fe4883fa317729488d0d80adbdfc486314914801caffe2'),
    ('locus_literal', 0x3bd8665, '803e6c0f8518f7ffff807e016f0f850ef7ffff807e02630f8504f7ffff807e03750f85faf6ffff807e04730f85f0f6ffff31c9884801c60009c3'),
    ('ctx_selector', 0x2fbbd20, '4883fa030f854c0100000fb60683c09e83f8140f873d010000488d0dbc9069fd486304814801c8ffe0'),
    ('ctx_literal', 0x2fbbda6, '0fb6460183f8680f84cc00000083f86c0f84b200000083f8740f85b10000000fb64e0280f972b80a000000ba100000000f44d031c080f9780f45c2884701c60709c3'),
    ('height_literal', 0x41fc115, '803e680f8559030000807e01650f854f030000807e02690f8545030000807e03670f853b030000807e04680f8531030000b102807e05740f8525030000e922030000'),
]

# Field-name probes are hypotheses; their indexes and branch destinations are
# evaluated from the classifier instructions and relative tables in the ELF.
CONTEXT_KEYS = (
    'initial_height', 'hardfork_height', 'hardfork', 'height', 'tx_index',
    'round', 'consensus_round', 'time', 'prev_time', 'next_oid', 'next_lid',
    'next_twap_id', 'system_nonce', 'use_system_nonce', 'mac',
)
EXPECTED_KEYS = (0, 0, 1, 2, 3, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12)

# These are selected edges, not a machine-instruction census. The first parent
# is an existing boundary: the selected new edge enters the locus reader.
EDGES = [
    ('parent_duplicate_locus', 0x2fd78c9, 'jcc', 0x2fe0219),
    ('parent_locus_value', 0x2fd78dc, 'call', 0x332c430),
    ('parent_locus_error', 0x2fd790c, 'jcc', 0x2fdb9f4),
    ('parent_string_selector', 0x2fd9972, 'call', 0x3bd7d50),
    ('locus_duplicate_ctx', 0x332c7f2, 'jcc', 0x3330098),
    ('locus_ctx_value', 0x332c805, 'call', 0x30d1c60),
    ('locus_ctx_error', 0x332c873, 'jcc', 0x332eadb),
    ('locus_string_selector', 0x332d5b8, 'call', 0x2fbbd20),
    ('context_string_selector', 0x30d27c2, 'call', 0x41fbef0),
    ('context_initial_duplicate', 0x30d21a3, 'jcc', 0x30d3a42),
    ('context_height_duplicate', 0x30d23af, 'jcc', 0x30d3aa4),
    ('context_first_fixint_path', 0x30d21ed, 'jump', 0x30d2c83),
    ('context_height_fixint_path', 0x30d23f9, 'jump', 0x30d2bdb),
    ('context_next_oid_fixint_path', 0x30d2499, 'jump', 0x30d2c2f),
    ('context_next_lid_fixint_path', 0x30d260f, 'jump', 0x30d2cd7),
    ('context_twap_fixint_path', 0x30d23a1, 'jump', 0x30d2b87),
    ('context_mac_fixint_path', 0x30d2349, 'jump', 0x30d2b33),
    ('context_height_unsigned', 0x30d2be9, 'slot', 0x64e2580),
    ('context_height_error', 0x30d2bfb, 'jcc', 0x30d3226),
    ('context_initial_unsigned', 0x30d2c91, 'slot', 0x64e2580),
    ('context_height_present', 0x30d2f94, 'jcc', 0x30d3134),
    ('context_height_missing', 0x30d2f9a, 'jump', 0x30d345d),
    ('context_missing_format', 0x30d34af, 'call', 0x3046740),
    ('context_missing_non9', 0x30d34bb, 'jcc', 0x30d3792),
    ('context_first_missing_jump', 0x30d37b7, 'jump', 0x30d30a3),
    ('locus_zero_depth', 0x332c585, 'jcc', 0x332d913),
    ('locus_last_depth', 0x332c593, 'jcc', 0x332de1e),
    ('context_zero_depth', 0x30d1d68, 'jcc', 0x30d3d9f),
    ('context_last_depth', 0x30d1d75, 'jcc', 0x30d2e2b),
    ('context_duplicate_format', 0x30d3b24, 'call', 0x3046740),
    ('locus_missing_ctx', 0x332de77, 'jcc', 0x332da41),
    ('locus_final_copy', 0x332e02a, 'slot', 0x64df508),
    ('parent_final_copy', 0x2fda886, 'slot', 0x64df508),
    ('wrapper_exchange_child', 0x32cb0dc, 'call', 0x2fd7260),
    ('wrapper_exchange_non2', 0x32cb10d, 'jcc', 0x32cb221),
    ('wrapper_first_copy', 0x32cb236, 'slot', 0x64df508),
    ('wrapper_second_copy', 0x32cb7ac, 'slot', 0x64df508),
    ('wrapper_return_copy', 0x32cb870, 'slot', 0x64df508),
]

# Every listed table is read as signed 32-bit offsets relative to its own
# base. The context/parent labels denote only selected prior boundaries.
TABLES = [
    ('exchange_name_length', 0x7b2ae4, 50, 0x3bd7d50, 0x3bda734),
    ('context_name_length', 0x7c7160, 14, 0x41fbef0, 0x41fc480),
    ('locus_name_first_byte', 0x654dfc, 21, 0x2fbbd20, 0x2fbbe89),
    ('exchange_field_index', 0x655820, 60, 0x2fd7260, 0x2fe66a2),
    ('locus_field_index', 0x73da1c, 17, 0x332c430, 0x333208d),
    ('context_field_index', 0x68ac4c, 14, 0x30d1c60, 0x30d3ee7),
    ('unsigned_marker', 0x78f3d0, 33, 0x348e980, 0x348ec9e),
]


def authenticate(data, expected=DIGEST):
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ValueError('input SHA-256 mismatch')
    return actual


def named_section(secs, name):
    found = [s for s in secs if s['name'] == name]
    if len(found) != 1 or found[0]['type'] == 8:
        raise ValueError('missing, duplicate or NOBITS section: ' + name)
    return found[0]


def read_va(data, secs, va, size):
    """Read one unambiguous allocated, file-backed section without NOBITS."""
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid virtual-address range')
    end = va + size
    if end > (1 << 64):
        raise ValueError('virtual-address range overflow')
    hits = [s for s in secs if s['type'] != 8 and s['flags'] & 2
            and s['address'] <= va and end <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('unmapped or ambiguous file-backed range')
    off = hits[0]['offset'] + va - hits[0]['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file range outside input')
    return data[off:off + size], off


def bytes_at(data, secs, va, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    got, off = read_va(data, secs, va, len(expected))
    if got != expected:
        raise ValueError('selected instruction bytes differ at ' + hex(va))
    return off


def fde_rows(data, secs, functions=FUNCTIONS):
    _, header = unwind_index(data)
    _, decoded = eh_frame_records(data, secs)
    by_start = {}
    for record in decoded:
        by_start.setdefault(record['start'], []).append(record)
    indexed = {record['start']: record for record in header}
    rows = []
    ranges = []
    for label, start, end, expected_hash in functions:
        found = by_start.get(start, [])
        if len(found) != 1 or found[0]['end'] != end:
            raise ValueError('selected FDE extent mismatch: ' + label)
        record = found[0]
        index = indexed.get(start)
        if index is None or index['fde'] != record['fde']:
            raise ValueError('selected FDE index mismatch: ' + label)
        body, off = read_va(data, secs, start, end - start)
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected_hash:
            raise ValueError('selected FDE body mismatch: ' + label)
        ranges.append((start, end))
        rows.append([label, hex(start), hex(end), hex(off), end - start,
                     hex(record['fde']), hex(record['cie']),
                     '' if record['lsda'] is None else hex(record['lsda']), actual])
    ordered = sorted(ranges)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('overlapping selected FDEs')
    return rows


def selected_windows(data, secs):
    rows = []
    for label, va, raw in WINDOWS:
        off = bytes_at(data, secs, va, raw)
        ownership = 'context' if label.startswith(('parent_', 'wrapper_', 'outer_', 'writer_')) else 'selected'
        rows.append([label, ownership, hex(va), hex(off), len(raw) // 2, raw])
    return rows


def transfer(data, secs, va, kind):
    if kind == 'call':
        raw, off = read_va(data, secs, va, 5)
        prefix = b'\xe8'
    elif kind == 'jump':
        raw, off = read_va(data, secs, va, 5)
        prefix = b'\xe9'
    elif kind == 'slot':
        raw, off = read_va(data, secs, va, 6)
        prefix = b'\xff\x15'
    elif kind == 'jcc':
        raw, off = read_va(data, secs, va, 6)
        if raw[:2] not in (b'\x0f\x82', b'\x0f\x84', b'\x0f\x85', b'\x0f\x88'):
            raise ValueError('unsupported conditional branch')
        prefix = raw[:2]
    elif kind == 'jcc8':
        raw, off = read_va(data, secs, va, 2)
        if raw[0] not in (0x74, 0x75):
            raise ValueError('unsupported short conditional branch')
        return va + 2 + struct.unpack_from('<b', raw, 1)[0], raw, off
    else:
        raise ValueError('unsupported transfer kind')
    if not raw.startswith(prefix):
        raise ValueError('transfer opcode differs')
    target = va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0]
    return target, raw, off


def edge_rows(data, secs):
    rows = []
    for label, va, kind, expected in EDGES:
        target, raw, off = transfer(data, secs, va, kind)
        if target != expected:
            raise ValueError('selected transfer target differs: ' + label)
        scope = 'context' if label.startswith(('parent_', 'wrapper_')) else 'selected'
        rows.append([label, scope, hex(va), hex(off), raw.hex(), kind, hex(target)])
    return rows


def rip_relative(data, secs, va, prefix):
    raw, off = read_va(data, secs, va, len(prefix) + 4)
    if raw[:len(prefix)] != prefix:
        raise ValueError('RIP-relative opcode differs')
    return va + len(raw) + struct.unpack_from('<i', raw, len(prefix))[0], raw, off


def table_rows(data, secs):
    rows = []
    mapping = {}
    for name, base, count, start, end in TABLES:
        raw, off = read_va(data, secs, base, 4 * count)
        for index in range(count):
            delta = struct.unpack_from('<i', raw, index * 4)[0]
            target = base + delta
            if not start <= target < end:
                raise ValueError('table destination outside selected range: ' + name)
            rows.append([name, hex(base), index, hex(off + 4 * index),
                         raw[4 * index:4 * index + 4].hex(), hex(target)])
            mapping[(name, index)] = target
    return rows, mapping


# Each row binds a classifier index to the corresponding table cell, a
# guard/duplicate branch, and one value-decoder call reached on that arm.
# Some integer calls occur only after the selected marker-normalization path.
# Calls to other functions are observed boundaries, not claims of ownership.
FIELD_ARMS = [
    (0, 'initial_height|hardfork_height', '4883bc242801000001', 0x30d3a42, 0x30d2c91, 'slot', 0x64e2580),
    (1, 'hardfork', '4883bc245001000001', 0x30d3abb, 0x30d24b7, 'call', 0x32b03e0),
    (2, 'height', '4883bc240001000001', 0x30d3aa4, 0x30d2be9, 'slot', 0x64e2580),
    (3, 'tx_index', '4883bc247001000002', 0x30d3ac4, 0x30d2415, 'call', 0x451c540),
    (4, 'round|consensus_round', '4883bc243801000001', 0x30d3ad6, 0x30d22c5, 'call', 0x4524ae0),
    (5, 'time', '83bc24e400000000', 0x30d3a05, 0x30d250b, 'call', 0x3d4f3c0),
    (6, 'prev_time', '4585e4', 0x30d3a8d, 0x30d254b, 'call', 0x3d4f3c0),
    (7, 'next_oid', '4883bc242001000001', 0x30d3aed, 0x30d2c3d, 'slot', 0x64e2580),
    (8, 'next_lid', '4883bc241801000001', 0x30d3acd, 0x30d2ce5, 'slot', 0x64e2580),
    (9, 'next_twap_id', '4883bc240801000001', 0x30d3a76, 0x30d2b95, 'slot', 0x64e2580),
    (10, 'system_nonce', '4883bc243001000001', 0x30d3a39, 0x30d258b, 'call', 0x421db60),
    (11, 'use_system_nonce', '4180fd02', 0x30d3a1f, 0x30d2291, 'call', 0x37ce740),
    (12, 'mac', '4883bc241001000001', 0x30d3a5c, 0x30d2b41, 'slot', 0x64dfeb0),
]


def field_rows(data, secs, mapping):
    rows = []
    for index, names, guard, expected_branch, call, kind, expected_callee in FIELD_ARMS:
        entry = mapping[('context_field_index', index)]
        for name in names.split('|'):
            if classify_context(data, secs, name.encode('ascii')) != index:
                raise ValueError('field name does not select its arm')
        off = bytes_at(data, secs, entry, guard)
        branch_va = entry + len(bytes.fromhex(guard))
        branch, branch_raw, _ = transfer(data, secs, branch_va, 'jcc')
        branch_opcode = bytes.fromhex('0f85' if index in (3, 5, 6, 11) else '0f84')
        if branch != expected_branch or branch_raw[:2] != branch_opcode:
            raise ValueError('field duplicate branch differs')
        callee, call_raw, _ = transfer(data, secs, call, kind)
        if callee != expected_callee:
            raise ValueError('field helper boundary differs')
        rows.append([index, names, hex(entry), hex(off), guard,
                     hex(branch_va), branch_raw.hex(), hex(branch),
                     hex(call), call_raw.hex(), kind, hex(callee)])
    return rows


# Map-completion checks are listed in execution order. A formatting call is a
# boundary: its tag-9 return can continue and its other return takes the listed
# error route, so a missing key is not assumed to imply unconditional failure.
MISSING_ARMS = [
    ('hardfork_height', 0x30d2f54, 'f684242801000001', 0x30d2f64, 0x30d37b1, 'missing', 0x30d30a3, 0x793524, 0x30d30ce, 0x30d30df, 0x30d30eb, 'jcc'),
    ('height', 0x30d2f8c, 'f684240001000001', 0x30d2f94, 0x30d3134, 'present', 0x30d3473, 0x793533, 0x30d349e, 0x30d34af, 0x30d34bb, 'jcc'),
    ('time', 0x30d3156, '85ed', 0x30d3158, 0x30d34e9, 'missing', 0x30d3509, 0x459e8c, 0x30d3534, 0x30d3545, 0x30d3551, 'jcc'),
    ('prev_time', 0x30d315e, '4585e4', 0x30d3161, 0x30d3591, 'missing', 0x30d35ac, 0x79353e, 0x30d35d7, 0x30d35e8, 0x30d35f4, 'jcc'),
    ('next_oid', 0x30d3167, 'f684242001000001', 0x30d316f, 0x30d3637, 'missing', 0x30d3657, 0x458e38, 0x30d3682, 0x30d3693, 0x30d369f, 'jcc'),
    ('next_lid', 0x30d3175, 'f684241801000001', 0x30d317d, 0x30d36e0, 'missing', 0x30d3700, 0x459730, 0x30d372b, 0x30d373c, 0x30d3748, 'jcc8'),
]


def missing_rows(data, secs):
    rows = []
    for (name, guard_va, guard, branch_va, expected_branch, taken, name_ref,
         expected_name, template_ref, call_va, non9_va, branch_kind) in MISSING_ARMS:
        guard_off = bytes_at(data, secs, guard_va, guard)
        branch, branch_raw, _ = transfer(data, secs, branch_va, 'jcc')
        name_va, name_raw, _ = rip_relative(data, secs, name_ref, b'\x48\x8d\x05')
        template, template_raw, _ = rip_relative(data, secs, template_ref, b'\x48\x8d\x35')
        callee, call_raw, _ = transfer(data, secs, call_va, 'call')
        non9, non9_raw, _ = transfer(data, secs, non9_va, branch_kind)
        name_bytes, _ = read_va(data, secs, name_va, len(name))
        expected_opcode = bytes.fromhex('0f84' if taken == 'missing' else '0f85')
        non9_opcode = b'\x75' if branch_kind == 'jcc8' else b'\x0f\x85'
        if (branch != expected_branch or branch_raw[:2] != expected_opcode or
                not non9_raw.startswith(non9_opcode) or name_va != expected_name or
                name_bytes != name.encode('ascii') or template != 0x4325c4 or
                callee != 0x3046740 or non9 != 0x30d3792):
            raise ValueError('selected missing-field route differs: ' + name)
        bytes_at(data, secs, non9_va - 2, '3c09')
        rows.append([name, hex(guard_va), hex(guard_off), guard, hex(branch_va),
                     branch_raw.hex(), hex(branch), taken, hex(name_ref), name_raw.hex(),
                     hex(name_va), hex(template_ref), template_raw.hex(), hex(template),
                     hex(call_va), call_raw.hex(), hex(callee), hex(non9_va),
                     non9_raw.hex(), hex(non9)])
    return rows


def sequence_rows(data, secs):
    """Decode selected count guards; helper success is a stated precondition."""
    target, _, _ = transfer(data, secs, 0x30d3240, 'jump')
    later, _, _ = transfer(data, secs, 0x30d3a00, 'jump')
    formatter, _, _ = transfer(data, secs, 0x30d338e, 'call')
    if (target, later, formatter) != (0x30d338e, 0x30d338e, 0x2f7fe90):
        raise ValueError('sequence formatter chain differs')
    bytes_at(data, secs, 0x30d323e, '31f6')
    arg2, _ = read_va(data, secs, 0x30d3389, 5)
    arg5, _ = read_va(data, secs, 0x30d39fb, 5)
    if arg2[0] != 0xbe or arg5[0] != 0xbe:
        raise ValueError('sequence formatter operand opcode differs')
    args = (0, struct.unpack_from('<I', arg2, 1)[0], struct.unpack_from('<I', arg5, 1)[0])
    if args != (0, 2, 5):
        raise ValueError('sequence formatter operands differ')
    specs = [
        (0, 0x30d1e42, 0x30d1e45, 'jcc', 0x30d322b, None, None, None, args[0]),
        (1, 0x30d32cd, 0x30d32d1, 'jcc', 0x30d3376, 0x30d32b9, 'slot', 0x64e2580, args[1]),
        (2, 0x30d32f3, 0x30d32f7, 'jcc8', 0x30d3376, 0x30d32e1, 'call', 0x32b03e0, args[1]),
        (3, 0x30d3834, 0x30d3838, 'jcc', 0x30d39e8, 0x30d381c, 'slot', 0x64e2580, args[2]),
        (4, 0x30d3858, 0x30d385c, 'jcc', 0x30d39e8, 0x30d3846, 'call', 0x451c540, args[2]),
        (5, 0x30d388b, 0x30d388f, 'jcc', 0x30d39e8, 0x30d3879, 'call', 0x4524ae0, args[2]),
    ]
    rows = []
    for count, compare, branch_va, kind, expected_target, call_va, call_kind, expected_call, arg in specs:
        guard = '4585ff' if count == 0 else '4183ff' + bytes([count]).hex()
        off = bytes_at(data, secs, compare, guard)
        branch, branch_raw, _ = transfer(data, secs, branch_va, kind)
        if branch != expected_target or branch_raw[:1 if kind == 'jcc8' else 2] != (b'\x74' if kind == 'jcc8' else b'\x0f\x84'):
            raise ValueError('sequence count branch differs')
        helper = ''
        call_raw = b''
        if call_va is not None:
            helper, call_raw, _ = transfer(data, secs, call_va, call_kind)
            if helper != expected_call:
                raise ValueError('sequence helper boundary differs')
        rows.append([count, hex(compare), hex(off), guard, hex(branch_va), branch_raw.hex(),
                     hex(branch), '' if call_va is None else hex(call_va), call_raw.hex(),
                     '' if call_va is None else call_kind, '' if call_va is None else hex(helper),
                     arg, hex(formatter)])
    return rows


def numeric_key_rows(data, secs, mapping):
    """Check three inline nonnegative small-integer key selectors."""
    specs = [
        ('exchange', 0x347f078, 0x2fd7899, 0x64e27b0, 'exchange_field_index', 59),
        ('locus', 0x33de758, 0x332c7bb, 0x64e3db8, 'locus_field_index', 16),
        ('context', 0x348ecf8, 0x30d2172, 0x64e41e0, 'context_field_index', 13),
    ]
    rows = []
    for name, va, call_va, slot, table, expected_limit in specs:
        raw, off = read_va(data, secs, va, 30)
        limit = raw[10]
        template = bytes.fromhex('4585c075190fb6c180f900b9000000000f42c8884f01c607094889f85bc3')
        scrubbed = bytearray(raw)
        scrubbed[10] = 0
        scrubbed[12:16] = bytes(4)
        if (bytes(scrubbed) != template or struct.unpack_from('<I', raw, 12)[0] != limit or
                limit != expected_limit):
            raise ValueError('numeric key clamp bytes differ: ' + name)
        resolved, call_raw, _ = transfer(data, secs, call_va, 'slot')
        if resolved != slot:
            raise ValueError('numeric key call slot differs: ' + name)
        if (table, limit) not in mapping or (table, limit + 1) in mapping:
            raise ValueError('numeric key clamp and table bounds disagree')
        rows.append([name, 'context' if name == 'exchange' else 'selected', hex(va), hex(off),
                     raw.hex(), limit, hex(call_va), call_raw.hex(), hex(slot),
                     table, hex(mapping[(table, 0)]), hex(mapping[(table, limit)])])
    return rows


def selector(data, secs, start, end, table, minimum, count, unknown, value):
    """Evaluate only the selected compare/branch forms, never arbitrary x86."""
    if not isinstance(value, bytes):
        raise ValueError('selector input must be bytes')
    if not minimum <= len(value) < minimum + count:
        return unknown
    raw, _ = read_va(data, secs, table + 4 * (len(value) - minimum), 4)
    pc = table + struct.unpack('<i', raw)[0]
    reg = None
    equal = False

    def get(at, length):
        if at < start or at + length > end:
            raise ValueError('selector branch outside FDE')
        return read_va(data, secs, at, length)[0]

    for _ in range(300):
        op = get(pc, 1)[0]
        if op == 0x80:
            mod = get(pc, 2)[1]
            if mod == 0x3e:
                ins = get(pc, 3)
                index, immediate, length = 0, ins[2], 3
            elif mod == 0x7e:
                ins = get(pc, 4)
                index, immediate, length = ins[2], ins[3], 4
            else:
                raise ValueError('unsupported selector comparison')
            if index >= len(value):
                raise ValueError('selector comparison outside key')
            equal = value[index] == immediate
            pc += length
        elif op == 0x0f and get(pc, 2) == b'\x0f\xb6':
            mod = get(pc, 3)[2]
            if mod == 0x0e:
                index, length = 0, 3
            elif mod == 0x4e:
                index, length = get(pc, 4)[3], 4
            else:
                raise ValueError('unsupported selector byte load')
            if index >= len(value):
                raise ValueError('selector load outside key')
            reg = value[index]
            pc += length
        elif op == 0x83 and get(pc, 2) == b'\x83\xf9':
            if reg is None:
                raise ValueError('uninitialized selector register')
            equal = reg == get(pc, 3)[2]
            pc += 3
        elif op == 0xb1:
            reg = get(pc, 2)[1]
            pc += 2
        elif op == 0x31 and get(pc, 2) == b'\x31\xc9':
            reg = 0
            pc += 2
        elif op == 0x0f and get(pc, 2)[1] in (0x84, 0x85):
            ins = get(pc, 6)
            take = equal if ins[1] == 0x84 else not equal
            pc += 6 + (struct.unpack_from('<i', ins, 2)[0] if take else 0)
        elif op in (0x74, 0x75):
            ins = get(pc, 2)
            take = equal if op == 0x74 else not equal
            pc += 2 + (struct.unpack_from('<b', ins, 1)[0] if take else 0)
        elif op in (0xe9, 0xeb):
            length = 5 if op == 0xe9 else 2
            ins = get(pc, length)
            disp = struct.unpack_from('<i' if length == 5 else '<b', ins, 1)[0]
            pc += length + disp
        elif op == 0x88 and get(pc, 7) == b'\x88\x48\x01\xc6\x00\x09\xc3':
            if reg is None:
                raise ValueError('uninitialized selector result')
            return reg
        else:
            raise ValueError('unsupported selector opcode at ' + hex(pc))
    raise ValueError('selector step limit exceeded')


def classify_context(data, secs, key):
    return selector(data, secs, 0x41fbef0, 0x41fc480,
                    0x7c7160, 3, 14, 13, key)


def classify_exchange(data, secs, key):
    return selector(data, secs, 0x3bd7d50, 0x3bda734,
                    0x7b2ae4, 2, 50, 59, key)


def classify_locus_ctx(data, secs, key):
    """Evaluate the selected c/t/x arm only; other first bytes are unmodeled."""
    head = next(raw for name, _, raw in WINDOWS if name == 'ctx_selector')
    body = next(raw for name, _, raw in WINDOWS if name == 'ctx_literal')
    bytes_at(data, secs, 0x2fbbd20, head)
    bytes_at(data, secs, 0x2fbbda6, body)
    if len(key) != 3:
        return None
    # The checked LEA/table implements first-byte - 0x62 with a 0x14 bound.
    if key[0] < 0x62 or key[0] - 0x62 > 0x14:
        return None
    raw, _ = read_va(data, secs, 0x654dfc + 4 * (key[0] - 0x62), 4)
    if 0x654dfc + struct.unpack('<i', raw)[0] != 0x2fbbda6:
        return None
    if key[1] != 0x74:
        return None
    return 0 if key[2] == 0x78 else (10 if key[2] == 0x72 else 16)


def key_rows(data, secs):
    rows = []
    controls = 0
    observed = []
    for key, expected in zip(CONTEXT_KEYS, EXPECTED_KEYS):
        encoded = key.encode('ascii')
        got = classify_context(data, secs, encoded)
        if got != expected:
            raise ValueError('context selector result differs: ' + key)
        checked = 0
        for i, old in enumerate(encoded):
            for byte in range(256):
                if byte == old:
                    continue
                altered = encoded[:i] + bytes([byte]) + encoded[i + 1:]
                if classify_context(data, secs, altered) == got:
                    raise ValueError('context selector accepted substituted byte')
                checked += 1
        controls += checked
        observed.append(got)
        rows.append(['context', key, len(encoded), got, checked])
    if classify_exchange(data, secs, b'locus') != 0:
        raise ValueError('exchange selector does not select locus')
    for i, old in enumerate(b'locus'):
        for byte in range(256):
            if byte != old:
                altered = b'locus'[:i] + bytes([byte]) + b'locus'[i + 1:]
                if classify_exchange(data, secs, altered) == 0:
                    raise ValueError('exchange selector accepted substituted locus')
    rows.append(['exchange', 'locus', 5, 0, 5 * 255])
    if classify_locus_ctx(data, secs, b'ctx') != 0:
        raise ValueError('locus selector does not select ctx')
    rows.append(['locus_selected_arm', 'ctx', 3, 0, 0])
    if observed[0] != observed[1] or observed[5] != observed[6]:
        raise ValueError('selected alias indexes differ')
    return rows, controls


def selected_relocations(data, secs):
    rela = named_section(secs, '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('truncated relocation section')
    desired = {
        0x64e2580: ('unsigned_decoder', 8, 0, 0x348e980),
        0x64dfeb0: ('mac_decoder_boundary', 8, 0, 0x14b7aa0),
        0x64e27b0: ('exchange_numeric_key', 8, 0, 0x347f020),
        0x64e3db8: ('locus_numeric_key', 8, 0, 0x33de700),
        0x64e41e0: ('context_numeric_key', 8, 0, 0x348eca0),
        0x64767a8: ('state_location_context', 8, 0, 0x443168),
    }
    found = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in desired and slot != 0x64df508:
            continue
        if slot in found:
            raise ValueError('duplicate selected relocation slot')
        found[slot] = (info & 0xffffffff, info >> 32, addend, pos)
    if set(found) != set(desired) | {0x64df508}:
        raise ValueError('missing selected relocation')
    rows = []
    for slot, (label, typ, symbol, addend) in desired.items():
        got_type, got_symbol, got_addend, pos = found[slot]
        if (got_type, got_symbol, got_addend) != (typ, symbol, addend):
            raise ValueError('selected relative relocation differs: ' + label)
        rows.append([label, hex(slot), hex(pos), got_type, got_symbol, hex(got_addend)])
    typ, symbol, addend, pos = found[0x64df508]
    if typ != 6 or symbol == 0 or addend != 0:
        raise ValueError('selected copy relocation differs')
    dynsym = named_section(secs, '.dynsym')
    dynstr = named_section(secs, '.dynstr')
    if (symbol + 1) * 24 > dynsym['size']:
        raise ValueError('dynamic symbol outside section')
    symoff = dynsym['offset'] + symbol * 24
    name_off, _, _, shndx, _, _ = struct.unpack_from('<IBBHQQ', data, symoff)
    if shndx != 0 or name_off >= dynstr['size']:
        raise ValueError('invalid copy symbol')
    begin = dynstr['offset'] + name_off
    limit = dynstr['offset'] + dynstr['size']
    end = data.find(b'\x00', begin, limit)
    if end < 0 or data[begin:end] != b'memcpy':
        raise ValueError('copy symbol name differs')
    rows.append(['copy_import_context', hex(0x64df508), hex(pos), typ, symbol, '0x0'])
    return rows, found


def location_row(data, secs, relocs):
    va = 0x64767a8
    raw, off = read_va(data, secs, va, 24)
    path_len, line, column = struct.unpack_from('<QII', raw, 8)
    path_va = relocs[va][2]
    if path_len != 20 or (line, column) != (123, 37):
        raise ValueError('state Location record differs')
    path, _ = read_va(data, secs, path_va, path_len)
    if path != b'l1/src/abci/state.rs':
        raise ValueError('state Location path differs')
    return {'ownership': 'context', 'va': hex(va), 'file_offset': hex(off),
            'path_va': hex(path_va), 'path': path.decode('ascii'),
            'line': line, 'column': column}


# A selected immediate is decoded only after its complete opcode prefix is checked.
OPERANDS = [
    ('context_height_output', 0x30d31ba, '488943', 1, 0x28),
    ('context_initial_output', 0x30d31a6, '488943', 1, 0x10),
    ('locus_child_base', 0x332c7f8, '488dbc24', 4, 0xc70),
    ('locus_height_load', 0x332c879, '488d8c24', 4, 0xc98),
    ('locus_height_local_a', 0x332c8c0, '0f298424', 4, 0x480),
    ('locus_height_load_a', 0x332deab, '0f288424', 4, 0x480),
    ('locus_height_local_b', 0x332decb, '0f298424', 4, 0x520),
    ('locus_height_load_b', 0x33309eb, '0f288424', 4, 0x520),
    ('locus_height_local_c', 0x3330a0b, '0f298424', 4, 0x3810),
    ('locus_height_load_c', 0x3330b27, '488db424', 4, 0x3810),
    ('locus_height_local_d', 0x3330b1f, '488dbc24', 4, 0x1c98),
    ('locus_height_copy_length', 0x3330b2f, 'ba', 4, 0xa10),
    ('locus_initial_load', 0x332c84e, '488b8424', 4, 0xc80),
    ('locus_initial_local', 0x332c856, '48894424', 1, 0x48),
    ('locus_initial_reload', 0x3330b12, '488b4424', 1, 0x48),
    ('locus_initial_store', 0x3330b17, '48898424', 4, 0x1c80),
    ('locus_return_source', 0x332e01a, '488db424', 4, 0x1c70),
    ('locus_return_length', 0x332e022, 'ba', 4, 0xba0),
    ('exchange_child_base', 0x2fd78cf, '488dbc24', 4, 0xb38),
    ('exchange_height_source_a', 0x2fd791f, '488db424', 4, 0xb60),
    ('exchange_height_dest_a', 0x2fd7912, '488dbc24', 4, 0x1f40),
    ('exchange_height_length_a', 0x2fd791a, 'ba', 4, 0xb78),
    ('exchange_height_source_b', 0x2fd796b, '488db424', 4, 0x1f40),
    ('exchange_height_dest_b', 0x2fd7978, '488dbc24', 4, 0x4b60),
    ('exchange_height_length_b', 0x2fd7973, 'ba', 4, 0xb78),
    ('exchange_initial_source', 0x2fd78e9, '488d8424', 4, 0xb40),
    ('exchange_initial_local', 0x2fd78f8, '0f298424', 4, 0x600),
    ('exchange_initial_reload', 0x2fd794c, '0f288424', 4, 0x600),
    ('exchange_initial_dest', 0x2fd795c, '488d8424', 4, 0x4b40),
    ('exchange_full_source_a', 0x2fda879, '488db424', 4, 0x4b38),
    ('exchange_full_dest_a', 0x2fda871, '488dbc24', 4, 0x2ef0),
    ('exchange_full_length_a', 0x2fda881, 'ba', 4, 0xba0),
    ('exchange_full_source_b', 0x2fe4657, '488db424', 4, 0x2ef0),
    ('exchange_full_dest_b', 0x2fe464f, '488dbc24', 4, 0xb38),
    ('exchange_full_length_b', 0x2fe465f, 'ba', 4, 0xba0),
    ('exchange_return_source', 0x2fe4c5d, '488db424', 4, 0xb38),
    ('exchange_return_length', 0x2fe4c55, 'ba', 4, 0x10e8),
    ('wrapper_child_base', 0x32cb0cc, '488dbc24', 4, 0x4060),
    ('wrapper_height_source', 0x32cb221, '488db424', 4, 0x4088),
    ('wrapper_height_dest', 0x32cb229, '488dbc24', 4, 0x9820),
    ('wrapper_height_length', 0x32cb231, 'ba', 4, 0x2780),
    ('wrapper_record_base', 0x32cb260, '4c89bc24', 4, 0x97f8),
    ('wrapper_full_source', 0x32cb79f, '488db424', 4, 0x97f8),
    ('wrapper_full_dest', 0x32cb797, '488dbc24', 4, 0x1098),
    ('wrapper_full_length', 0x32cb7a7, 'ba', 4, 0x27a8),
    ('wrapper_return_source', 0x32cb7c6, '488db424', 4, 0x1098),
    ('wrapper_return_length', 0x32cb868, 'ba', 4, 0x27a8),
    ('outer_child_base', 0x3266af5, '488dbc24', 4, 0xa8),
    ('outer_source', 0x32666cc, '4c8da424', 4, 0xa8),
    ('outer_stage_length', 0x32666bf, 'ba', 4, 0x27a8),
    ('outer_allocation_copy_length', 0x32666fa, 'ba', 4, 0x27a8),
]


def operand_rows(data, secs):
    rows, values = [], {}
    for label, va, prefix_hex, width, expected in OPERANDS:
        prefix = bytes.fromhex(prefix_hex)
        raw, off = read_va(data, secs, va, len(prefix) + width)
        if raw[:len(prefix)] != prefix:
            raise ValueError('operand opcode differs: ' + label)
        value = int.from_bytes(raw[len(prefix):], 'little')
        if value != expected:
            raise ValueError('operand value differs: ' + label)
        rows.append([label, hex(va), hex(off), raw.hex(), width, hex(value)])
        values[label] = value
    return rows, values


def derive_flow(v):
    """Check byte-range arithmetic, not dynamic identity or helper purity."""
    h, i = v['context_height_output'], v['context_initial_output']
    require = [
        v['locus_height_load'] == v['locus_child_base'] + h,
        v['locus_initial_load'] == v['locus_child_base'] + i,
        v['locus_initial_local'] == v['locus_initial_reload'],
        v['locus_initial_store'] == v['locus_return_source'] + i,
        v['locus_height_local_a'] == v['locus_height_load_a'],
        v['locus_height_local_b'] == v['locus_height_load_b'],
        v['locus_height_local_c'] == v['locus_height_load_c'],
        v['locus_height_local_d'] == v['locus_return_source'] + h,
        v['locus_height_copy_length'] >= 8,
        v['locus_return_length'] > h + 7,
        v['exchange_height_source_a'] == v['exchange_child_base'] + h,
        v['exchange_height_dest_a'] == v['exchange_height_source_b'],
        v['exchange_height_length_a'] == v['exchange_height_length_b'],
        v['exchange_full_source_a'] + h == v['exchange_height_dest_b'],
        v['exchange_full_source_a'] + i == v['exchange_initial_dest'] + 8,
        v['exchange_initial_source'] + 8 == v['exchange_child_base'] + i,
        v['exchange_initial_local'] == v['exchange_initial_reload'],
        v['exchange_full_dest_a'] == v['exchange_full_source_b'],
        v['exchange_full_dest_b'] == v['exchange_return_source'],
        v['exchange_full_length_a'] == v['exchange_full_length_b'],
        v['exchange_full_length_a'] > h + 7,
        v['exchange_return_length'] > h + 7,
        v['wrapper_child_base'] + h == v['wrapper_height_source'],
        v['wrapper_record_base'] + h == v['wrapper_height_dest'],
        v['wrapper_height_length'] > 8,
        v['wrapper_full_source'] == v['wrapper_record_base'],
        v['wrapper_full_dest'] == v['wrapper_return_source'],
        v['wrapper_full_length'] == v['wrapper_return_length'],
        v['wrapper_return_length'] > h + 7,
        v['outer_child_base'] == v['outer_source'],
        v['outer_stage_length'] == v['outer_allocation_copy_length'],
        v['outer_stage_length'] > h + 7,
    ]
    if not all(require):
        raise ValueError('selected data-flow projection is inconsistent')
    return {'conditional': True, 'context_initial_offset': hex(i),
            'context_height_offset': hex(h), 'locus_output_initial_offset': hex(i),
            'outer_allocated_initial_offset': hex(i), 'locus_output_height_offset': hex(h),
            'exchange_output_height_offset': hex(h), 'outer_allocated_height_offset': hex(h),
            'checked_relations': len(require),
            'assumptions': ['selected success paths', 'ordinary copy binding',
                            'normal helper returns', 'no intervening alias writes'],
            'scope': 'offset arithmetic only; runtime object identity remains open'}


def scalar_model(marker, payload):
    """Model selected marker arms; boundary cases do not execute the capture."""
    if type(marker) is not int or not 0 <= marker <= 255 or not isinstance(payload, bytes):
        raise ValueError('invalid synthetic scalar input')
    if marker <= 0x7f:
        return ('tag9', marker, 0)
    if marker >= 0xe0:
        return ('negative_format_boundary', marker - 256, 0)
    unsigned = {0xcc: 1, 0xcd: 2, 0xce: 4, 0xcf: 8}
    signed = {0xd0: 1, 0xd1: 2, 0xd2: 4, 0xd3: 8}
    if marker not in unsigned and marker not in signed:
        return ('other_marker_boundary', None, 0)
    length = unsigned.get(marker, signed.get(marker))
    if len(payload) < length:
        return ('short_tag1', None, len(payload))
    value = int.from_bytes(payload[:length], 'big', signed=marker in signed)
    if value < 0:
        return ('negative_format_boundary', value, length)
    return ('tag9', value, length)


def scalar_rows(data, secs, table):
    # The marker table and representative guards pin the model to the ELF.
    destinations = {0xcc: 0x348ea57, 0xcd: 0x348eac9, 0xce: 0x348ea34,
                    0xcf: 0x348eba0, 0xd0: 0x348eb3c, 0xd1: 0x348ea92,
                    0xd2: 0x348e9fb, 0xd3: 0x348eb6d, 0xe0: 0x348ea7e}
    for marker, target in destinations.items():
        if table[('unsigned_marker', marker - 0xc0)] != target:
            raise ValueError('selected marker destination differs')
    cases = [(0, b''), (0x7f, b''), (0xe0, b''), (0xff, b''), (0xc0, b'')]
    for marker, width in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8),
                          (0xd0, 1), (0xd1, 2), (0xd2, 4), (0xd3, 8)):
        cases.append((marker, bytes(width)))
        cases.append((marker, bytes([0x7f]) + bytes([0xff]) * (width - 1)))
        cases.append((marker, bytes([0x80]) + bytes(width - 1)))
        cases.append((marker, bytes([0xff]) * width))
        for n in range(width):
            cases.append((marker, bytes(n)))
    rows = []
    for marker, payload in cases:
        outcome, value, consumed = scalar_model(marker, payload)
        rows.append([hex(marker), payload.hex(), outcome,
                     '' if value is None else str(value), consumed])
    return rows


WINDOWS.extend([
    ('locus_initial_capture', 0x332c84e, '488b8424800c00004889442448'),
    ('locus_initial_commit', 0x3330b12, '488b44244848898424801c0000'),
    ('parent_initial_capture', 0x2fd78e9, '488d8424400b00000f10000f1048100f298424000600000f298c2410060000'),
    ('parent_initial_commit', 0x2fd794c, '0f288424000600000f288c2410060000488d8424404b00000f1148100f1100'),
    ('wrapper_initial_capture', 0x32cb0e9, '0f108424684000000f298424a0800000'),
    ('wrapper_exchange_entry', 0x32cb0cc, '488dbc2460400000488db424a0bf0000e87fc1d0ff4c8bbc24604000000f108424684000000f298424a08000000f108424784000000f298424b08000004983ff020f850e010000'),
    ('wrapper_initial_commit', 0x32cb23c, '660f6f8424a0800000660f6f8c24b0800000f30f7f842400980000f30f7f8c2410980000'),
    ('depth_locus', 0x332c575, '400fb6c689442430410fb747226685c00f848813000066ffc866418947220f8485180000'),
    ('depth_context', 0x30d1d5d, '440fb6f70fb746226685c00f843120000066ffc8668946220f84b0100000'),
    ('height_marker_normalize', 0x30d2a64, 'b1e03cdf0f876d0100003c907369240fb180e960010000'),
])

WINDOWS.extend([
    ('scalar_unsigned_8', 0x348ea57, '488b46184885c00f8459010000488b4e1048ffc80fb61148ffc148894e1048894618e96c010000'),
    ('scalar_unsigned_16', 0x348eac9, '488b4610488b4e184883f9020f82d30000004883c1fe0fb7104883c00266c1c2084889461048894e180fb7c248894708e9f0000000'),
    ('scalar_unsigned_32', 0x348ea34, '488b4610488b4e184883f9040f82680100004883c1fc8b104883c0040fcae98b010000'),
    ('scalar_unsigned_64', 0x348eba0, '488b4610488b4e184883f9087326'),
    ('scalar_signed_8', 0x348eb3c, '488b46184885c07478488b561048ffc8480fbe0a48ffc248895610488946184885c90f88c700000048894f08e981000000'),
    ('scalar_signed_16', 0x348ea92, '488b4610488b4e184883f9020f820a0100004883c1fe0fb71066c1c2084883c0024889461048894e186685d27932480fbfc2e96c010000'),
    ('scalar_signed_32', 0x348e9fb, '488b4610488b4e184883f9040f82a10100004883c1fc8b104883c0040fca4889461048894e1885d20f880902000089d048894708e9ba010000'),
    ('scalar_signed_64', 0x348eb6d, '488b4610488b4e184883f90872334883c1f8488b10480fca4883c0084889461048894e184885d279544889542440e99a000000'),
    ('unknown_context_arm', 0x30d20b1, '488d7c24504889eeba01000000e88d3d1000807c2450090f855b1a000041ffce4889ee0f840d0e0000'),
    ('context_all_output_stores', 0x30d3197, '4c893b4c897308488b8424b00100004889431048894b1848895320488b8424980100004889432848897b30488b84249001000048894338488b84248801000048894340488b84244801000048894348488b8424f800000048894350488b84244001000048894358896b60488b8424a8010000488943644489636c488b8424a00100004889437044886b78'),
    ('context_selected_default_words', 0x30d2eee, '31c0f684243801000001488bbc24d8000000480f44f8f684240801000001488b8c2448010000480f44c848898c2448010000f684243001000001488b8c24f8000000480f44c84180e501f684241001000001488b942440010000480f44d04889942440010000'),
    ('context_selected_hardfork_default', 0x30d2f6a, '31c0f684245001000001488b8c24f0000000480f44c8488b9424e8000000480f44d0'),
    ('context_selected_tx_default', 0x30d3134, '4531f6488b8424700100004883f80241bf010000004c0f45f84c0f45b424b8010000'),
    ('context_fresh_marker', 0x30d1cb4, '41b0e03cdf77423c907309240f89c7e9950000003ca07309240f89c7e94a010000'),
    ('context_sequence_entry', 0x30d1e1f, '440fb6ff0fb746226685c00f847c1f000066ffc8668946220f84ee0f000048897424304585ff0f84e0130000'),
    ('context_sequence_empty', 0x30d322b, '488d155ef43803488d0d97f23803488d7c240831f6e949010000'),
    ('context_sequence_first_two', 0x30d32b9, 'ff15c1f240030fb64424084c8b6424103c09757e4183ff010f849f000000488d7c24084c89f631d2e8fad01d000fb64424083c090f850b0900004183ff02747d'),
    ('context_sequence_three_to_five', 0x30d381c, 'ff155eed40030fb64424084c8b6c24103c090f858d0100004183ff030f84aa010000488d7c24084c89f6e8f58c44010fb64424083c090f85a60300004183ff040f8486010000f30f6f442410660f7f842470010000488d7c24084c89f6e8621245010fb64424083c090f85730300004183ff050f8453010000488b6c2410'),
    ('context_sequence_short', 0x30d39e8, '488d15a1ec3803488d0ddaea3803488d7c2408be05000000e989f9ffff'),
    ('context_sequence_stage', 0x30d3c5a, '488b4424104885c0480f454424184080e5010f288424700100000f294424504c89642460660f6f842450010000f30f7f4424684c896c2478'),
    ('context_sequence_reload', 0x30d3d74, '660f6f442450660f6f4c24600f285424700f289c2480000000e93ff1ffff'),
    ('context_sequence_store', 0x30d2ed1, '0f115b300f115320f30f7f4b10f30f7f03'),
    ('parent_numeric_fresh', 0x2fd780b, '498b4d184885c90f8432310000498b551048ffc90fb60248ffc24989551049894d1884c0780431f6eb52'),
    ('parent_numeric_call_args', 0x2fd7887, '400fb6d60fb6c8488dbc24f02e00004c89eeff1511af50030fb68c24f02e000080f9090f855f4a00000fb68424f12e0000496304874c01f8ffe0'),
    ('locus_numeric_fresh', 0x332c735, '498b47184885c00f84f3180000498b571048ffc80fb60a48ffc2498957104989471884c9780431d2eb4b'),
    ('locus_numeric_call_args', 0x332c7aa, '0fb6d20fb6c9488dbc24f00200004c89feff15f7751b030fb68424f00200003c090f852a2700000fb68424f1020000488d0d3c1241fd486304814801c8ffe0'),
    ('context_numeric_fresh', 0x30d20eb, '488b46184885c00f84290f0000488b561048ffc80fb60a48ffc2488956104889461884c9780431d2eb51'),
    ('context_numeric_call_args', 0x30d2166, '0fb6d20fb6c94c89ff4889f5ff15682041030fb64424303c090f85940b00000fb6442431488d0dbb8a5bfd486304814801c8ffe0'),
    ('context_mac_marker_route', 0x30d22f6, '4883bc2410010000010f84571700004889ee0fb64d200fb64521c645200180f9010f8516080000488b4e184885c90f843c0f0000488b561048ffc90fb60248ffc24889561048894e1884c00f88ef06000031c9e9e5070000'),
    ('context_twap_marker_route', 0x30d234e, '4883bc2408010000010f84191700004889ee0fb64d200fb64521c645200180f9010f8512080000488b4e184885c90f84e40e0000488b561048ffc90fb60248ffc24889561048894e1884c00f88ae06000031c9e9e1070000'),
    ('context_next_oid_marker_route', 0x30d2446, '4883bc2420010000010f84981600004889ee0fb64d200fb64521c645200180f9010f85c2070000488b4e184885c90f84ec0d0000488b561048ffc90fb60248ffc24889561048894e1884c00f88e405000031c9e991070000'),
    ('context_next_lid_marker_route', 0x30d25bc, '4883bc2418010000010f84021500004889ee0fb64d200fb64521c645200180f9010f85f4060000488b4e184885c90f84760c0000488b561048ffc90fb60248ffc24889561048894e1884c00f889c04000031c9e9c3060000'),
])


OPERANDS.extend([
    ('wrapper_initial_source', 0x32cb0e9, '0f108424', 4, 0x4068),
    ('wrapper_initial_local', 0x32cb0f1, '0f298424', 4, 0x80a0),
    ('wrapper_initial_reload', 0x32cb23c, '660f6f8424', 4, 0x80a0),
    ('wrapper_initial_dest', 0x32cb24e, 'f30f7f8424', 4, 0x9800),
    ('sequence_initial_save', 0x30d3c79, '4c896424', 1, 0x60),
    ('sequence_height_save', 0x30d3c8d, '4c896c24', 1, 0x78),
    ('sequence_stage_base', 0x30d3d74, '660f6f4424', 1, 0x50),
    ('sequence_initial_load', 0x30d3d7a, '660f6f4c24', 1, 0x60),
    ('sequence_height_load', 0x30d3d80, '0f285424', 1, 0x70),
    ('sequence_initial_output', 0x30d2ed9, 'f30f7f4b', 1, 0x10),
    ('sequence_height_output', 0x30d2ed5, '0f1153', 1, 0x20),
])


def verify_wrapper_initial(v):
    i = v['context_initial_output']
    checks = [v['wrapper_initial_source'] + 8 == v['wrapper_child_base'] + i,
              v['wrapper_initial_local'] == v['wrapper_initial_reload'],
              v['wrapper_initial_dest'] + 8 == v['wrapper_record_base'] + i,
              v['wrapper_full_source'] == v['wrapper_record_base'],
              v['wrapper_full_dest'] == v['wrapper_return_source'],
              v['wrapper_return_length'] > i + 7]
    if not all(checks):
        raise ValueError('selected initial-height projection is inconsistent')
    return len(checks)


def verify_sequence_flow(v):
    """Check selected two qword projections across aligned SIMD copies."""
    checks = [v['sequence_initial_save'] == v['sequence_stage_base'] + v['context_initial_output'],
              v['sequence_height_save'] == v['sequence_stage_base'] + v['context_height_output'],
              v['sequence_initial_load'] == v['sequence_initial_save'],
              v['sequence_height_load'] + 8 == v['sequence_height_save'],
              v['sequence_initial_output'] == v['context_initial_output'],
              v['sequence_height_output'] + 8 == v['context_height_output']]
    if not all(checks):
        raise ValueError('sequence data-flow projection is inconsistent')
    return len(checks)


def literal_rows(data, secs):
    entries = [('selected_height', 0x793533, b'height'),
               ('duplicate_first_name', 0x793524, b'hardfork_height'),
               ('writer_first_name_context', 0x9160ea, b'hardfork_height'),
               ('duplicate_template', 0x43351a, b'\x11duplicate field `'),
               ('missing_template', 0x4325c4, b'\x0fmissing field `')]
    rows = []
    for label, va, expected in entries:
        raw, off = read_va(data, secs, va, len(expected))
        if raw != expected:
            raise ValueError('selected literal differs: ' + label)
        rows.append([label, hex(va), hex(off), len(raw), raw.decode('ascii').encode('unicode_escape').decode('ascii'), raw.hex()])
    return rows


def reference_rows(data, secs):
    refs = [
        ('context_name_table', 0x41fbf01, '488d0d', 0x7c7160),
        ('exchange_name_table', 0x3bd7d5d, '488d0d', 0x7b2ae4),
        ('locus_field_table', 0x332c7d9, '488d0d', 0x73da1c),
        ('context_field_table', 0x30d218a, '488d0d', 0x68ac4c),
        ('exchange_field_table', 0x2fd7444, '4c8d3d', 0x655820),
        ('unsigned_marker_table', 0x348e995, '4c8d05', 0x78f3d0),
        ('locus_name_table', 0x2fbbd39, '488d0d', 0x654dfc),
        ('duplicate_first_name', 0x30d3a42, '488d05', 0x793524),
        ('duplicate_height_name', 0x30d3aa4, '488d05', 0x793533),
        ('missing_height_name', 0x30d3473, '488d05', 0x793533),
        ('duplicate_template', 0x30d3b13, '488d35', 0x43351a),
        ('missing_template', 0x30d349e, '488d35', 0x4325c4),
        ('writer_first_name_context', 0x4d930b4, '488d35', 0x9160ea),
    ]
    rows = []
    for label, va, prefix, expected in refs:
        target, raw, off = rip_relative(data, secs, va, bytes.fromhex(prefix))
        if target != expected:
            raise ValueError('relative data reference differs: ' + label)
        rows.append([label, hex(va), hex(off), raw.hex(), hex(target)])
    return rows


def tsv(header, rows):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue().encode('utf-8')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def build(data, expected_digest=DIGEST):
    actual = authenticate(data, expected_digest)
    secs = sections(data)
    fdes = fde_rows(data, secs)
    wins = selected_windows(data, secs)
    edges = edge_rows(data, secs)
    tables, mapping = table_rows(data, secs)
    expected_cells = {
        ('exchange_name_length', 3): 0x3bd8665,
        ('context_name_length', 3): 0x41fc115,
        ('locus_name_first_byte', 1): 0x2fbbda6,
        ('exchange_field_index', 0): 0x2fd78c1,
        ('locus_field_index', 0): 0x332c7e9,
        ('context_field_index', 0): 0x30d219a,
        ('context_field_index', 2): 0x30d23a6,
        ('context_field_index', 13): 0x30d20b1,
    }
    if any(mapping.get(k) != v for k, v in expected_cells.items()):
        raise ValueError('selected dispatch cell differs')
    fields = field_rows(data, secs, mapping)
    missing = missing_rows(data, secs)
    sequence = sequence_rows(data, secs)
    numeric = numeric_key_rows(data, secs, mapping)
    relocs, found = selected_relocations(data, secs)
    location = location_row(data, secs, found)
    references = reference_rows(data, secs)
    literals = literal_rows(data, secs)
    keys, controls = key_rows(data, secs)
    operands, values = operand_rows(data, secs)
    flow = derive_flow(values)
    flow['wrapper_initial_relations'] = verify_wrapper_initial(values)
    flow['sequence_projection_relations'] = verify_sequence_flow(values)
    cases = scalar_rows(data, secs, mapping)
    summary = {'target': 'linux-x86_64-node-115', 'binary_sha256': actual,
               'selected_fdes': len(fdes), 'selected_windows': len(wins),
               'selected_transfers': len(edges), 'relative_table_cells': len(tables),
               'selected_relocations': len(relocs), 'selected_references': len(references),
               'context_field_guards': len(fields),
               'context_missing_checks': len(missing),
               'context_sequence_count_checks': len(sequence),
               'numeric_key_clamps': len(numeric),
               'selected_literals': len(literals), 'name_probes': len(keys),
               'context_single_byte_substitutions': controls,
               'exchange_single_byte_substitutions': 5 * 255,
               'projection_operands': len(operands), 'synthetic_scalar_cases': len(cases),
               'limitations': 'selected static path and synthetic models; no target execution or coverage claim'}
    return {
        'functions.tsv': tsv(['role', 'start_va', 'end_va_exclusive', 'file_offset',
                              'length', 'fde_va', 'cie_va', 'lsda_va', 'sha256'], fdes),
        'windows.tsv': tsv(['role', 'scope', 'va', 'file_offset', 'length', 'bytes'], wins),
        'edges.tsv': tsv(['role', 'scope', 'va', 'file_offset', 'bytes', 'kind', 'target'], edges),
        'tables.tsv': tsv(['table', 'base_va', 'index', 'file_offset', 'raw_delta', 'target_va'], tables),
        'field-arms.tsv': tsv(['index', 'name_probes', 'guard_va', 'guard_file_offset',
                               'guard_bytes', 'branch_va', 'branch_bytes', 'branch_target_va',
                               'value_call_va', 'value_call_bytes', 'kind', 'call_target_or_slot_va'], fields),
        'missing-arms.tsv': tsv(['field', 'guard_va', 'guard_file_offset', 'guard_bytes',
                                 'branch_va', 'branch_bytes', 'branch_target_va', 'taken_means',
                                 'name_reference_va', 'name_reference_bytes', 'name_va',
                                 'template_reference_va', 'template_reference_bytes', 'template_va',
                                 'format_call_va', 'format_call_bytes', 'format_callee_va',
                                 'non9_branch_va', 'non9_branch_bytes', 'non9_target_va'], missing),
        'sequence-checks.tsv': tsv(['count', 'guard_va', 'guard_file_offset', 'guard_bytes',
                                    'branch_va', 'branch_bytes', 'branch_target_va', 'helper_call_va',
                                    'helper_call_bytes', 'helper_kind', 'helper_target_or_slot_va',
                                    'formatter_operand', 'formatter_target_va'], sequence),
        'numeric-keys.tsv': tsv(['selector', 'call_scope', 'clamp_va', 'clamp_file_offset',
                                 'clamp_bytes', 'maximum_index', 'call_va', 'call_bytes',
                                 'slot_va', 'caller_table', 'zero_index_target',
                                 'maximum_index_target'], numeric),
        'relocations.tsv': tsv(['role', 'slot_va', 'record_file_offset', 'type', 'symbol', 'addend'], relocs),
        'references.tsv': tsv(['role', 'va', 'file_offset', 'bytes', 'target_va'], references),
        'literals.tsv': tsv(['role', 'va', 'file_offset', 'length', 'text', 'bytes'], literals),
        'keys.tsv': tsv(['selector', 'probe', 'length', 'index', 'single_byte_substitutions'], keys),
        'operands.tsv': tsv(['role', 'va', 'file_offset', 'bytes', 'width', 'value'], operands),
        'scalar-cases.tsv': tsv(['marker', 'payload_hex', 'outcome', 'value', 'payload_consumed'], cases),
        'flow.json': json_bytes(flow),
        'location.json': json_bytes(location),
        'summary.json': json_bytes(summary),
    }


def historical_location(old, secs):
    rela = named_section(secs, '.rela.dyn')
    if rela['size'] % 24:
        raise ValueError('historical relocation section is truncated')
    selected = {}
    for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', old, pos)
        if slot not in (0x56dfbf8, 0x57755a8):
            continue
        if slot in selected:
            raise ValueError('duplicate historical anchor')
        selected[slot] = (info & 0xffffffff, info >> 32, addend)
    if set(selected) != {0x56dfbf8, 0x57755a8}:
        raise ValueError('missing historical anchor')
    if selected[0x57755a8] != (8, 0, 0x3273810):
        raise ValueError('historical callee relocation differs')
    typ, sym, path_va = selected[0x56dfbf8]
    if (typ, sym) != (8, 0):
        raise ValueError('historical Location relocation differs')
    raw, _ = read_va(old, secs, 0x56dfbf8, 24)
    length, line, column = struct.unpack_from('<QII', raw, 8)
    if (length, line, column) != (49, 107, 37):
        raise ValueError('historical Location fields differ')
    path, _ = read_va(old, secs, path_va, length)
    if not path.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical Location suffix differs')
    target, _, _ = transfer(old, secs, 0x3272785, 'slot')
    location, _, _ = rip_relative(old, secs, 0x3273856, b'\x48\x8d\x0d')
    if target != 0x57755a8 or location != 0x56dfbf8:
        raise ValueError('historical call or Location reference differs')
    _, fdes = eh_frame_records(old, secs)
    caller = [item for item in fdes if item['start'] <= 0x3272785 < item['end']]
    callee = [item for item in fdes if item['start'] <= 0x3273856 < item['end']]
    if (len(caller) != 1 or caller[0]['start'] != 0x32725d0 or
            len(callee) != 1 or callee[0]['start'] != selected[0x57755a8][2]):
        raise ValueError('historical caller or callee FDE differs')
    return {'caller_va': hex(caller[0]['start']), 'call_va': '0x3272785',
            'callee_va': hex(callee[0]['start']), 'location_va': hex(location),
            'line': line, 'column': column}


def check_historical(old, current):
    """Authenticate and compare the retained historical selector when supplied."""
    authenticate(old, OLD_DIGEST)
    secs = sections(old)
    rows = [('historical_context_selector', 0x21e4170, 0x21e4663,
             '74645f0067b473f1fa7135d8255ae808234a7b9d0f8c4ceb97cf71cbde74234a')]
    historical_fde = fde_rows(old, secs, rows)[0]
    bytes_at(old, secs, 0x21e4170, '4889f84883c2fd4883fa0d0f87d9040000')
    old_table, _, _ = rip_relative(old, secs, 0x21e4181, b'\x48\x8d\x0d')
    new_secs = sections(current)
    current_fde = fde_rows(current, new_secs, [FUNCTIONS[3]])[0]
    new_table, _, _ = rip_relative(current, new_secs, 0x41fbf01, b'\x48\x8d\x0d')
    if (old_table, new_table) != (0x3d4114, 0x7c7160):
        raise ValueError('cross-release length-table references differ')
    table_bytes, _ = read_va(old, secs, old_table, 14 * 4)
    for i in range(14):
        target = old_table + struct.unpack_from('<i', table_bytes, i * 4)[0]
        if not 0x21e4170 <= target < 0x21e4663:
            raise ValueError('historical selector table destination outside FDE')
    old_results = []
    new_results = []
    old_anchor = historical_location(old, secs)
    for key in (b'initial_height', b'hardfork_height', b'height', b'round', b'consensus_round'):
        old_results.append(selector(old, secs, 0x21e4170, 0x21e4663,
                                    0x3d4114, 3, 14, 13, key))
        new_results.append(classify_context(current, new_secs, key))
    if old_results != [0, 13, 2, 4, 4] or new_results != [0, 0, 2, 4, 4]:
        raise ValueError('cross-release classifier comparison differs')
    return {'historical_sha256': OLD_DIGEST, 'historical_selector_va': historical_fde[1],
            'historical_selector_end_va_exclusive': historical_fde[2],
            'historical_length_table_va': hex(old_table),
            'historical_length_table_cells': len(table_bytes) // 4,
            'current_sha256': DIGEST, 'current_selector_va': current_fde[1],
            'current_selector_end_va_exclusive': current_fde[2],
            'current_length_table_va': hex(new_table),
            'keys': ['initial_height', 'hardfork_height', 'height', 'round', 'consensus_round'],
            'historical_indexes': old_results, 'current_indexes': new_results,
            'historical_state_anchor': old_anchor}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical', type=Path)
    args = parser.parse_args()
    data = TARGET.read_bytes()
    authenticate(data)
    comparison = None
    if args.historical is not None:
        comparison = check_historical(args.historical.read_bytes(), data)
    files = build(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (args.out / name).write_bytes(content)
    print(json.dumps({'generated': len(files), 'historical': comparison}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as error:
        print('abci_binary_context115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
