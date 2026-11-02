#!/usr/bin/env python3
"""Recover selected node 94 state-root and point-reader paths from ELF bytes."""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Labels describe this packet's inferred role, not symbols in the ELF.
FUNCTIONS = (
    ('outer_low', 0x26cd7f0, 0x26cd91a, '7aba4a506e226403764ed97c7ff1eac0e6bcf4b5112788715667a7a0e40738d8'),
    ('outer_shared', 0x42d6490, 0x42d65ba, '32f81089a1a69cd41908855d1ea66619fc3824f2a5bc3ed0f7f3c2a58ae34fc8'),
    ('collect_low', 0x25ecf10, 0x25ecfd9, 'c6bddf3ffc71cd056c448830cc45877c2ca4f75daf960997ce82ca0a6c55adf3'),
    ('collect_shared', 0x4603dd0, 0x4603e99, '88ab8bd356cb264b03953c506636b311718157e5d1d618b1cd2f38d064a02641'),
    ('tree_shared', 0x48758b0, 0x4875b9e, '157ada2c57ee076b9300b568626a27980ea042f877e802a6ca33f05e5b85902e'),
    ('seq_low', 0x1e42b50, 0x1e42ddb, '85c4cc9f2754cefe60c09179233fbe67097107886e87a6aef8f96a4b67988f4e'),
    ('seq_shared', 0x44315a0, 0x443182b, 'cc0464afb94bcf59a697978336611d43a24d6a1ea48cd6e8043cab7218dc6e75'),
    ('pair_low', 0x1df1990, 0x1df2006, 'bf2af2a127c1cfa1029f305648d069f57671b0b888ebd61ca523a80b79817d06'),
    ('pair_shared', 0x43d1820, 0x43d1e96, 'da5e34a94b4af14c6cbcdf8981714cfd2c05a2fee7645481a13856925bc09137'),
    ('key_low', 0x1e0d400, 0x1e0d53f, '4db60fe88005e74b874c7b29f56caed0a88d3d65494b2aee8ada3b150f28972c'),
    ('key_buffered', 0x1e0e050, 0x1e0e18f, '40c61120c3054e5351dd477e6f1ad5374013f2a9f8d79314bd5a761085458e28'),
    ('key_shared', 0x43f42c0, 0x43f43ff, 'ba2ad9710d1e9ee6d4a728ffcd6b1b9a9727830f39c81f1a1ec6e47c481e5617'),
    ('range_buffered', 0x26ccf30, 0x26cd12b, 'b6b0ded5c64017810a5e3ee61bfb56a4c3baa85cf0413df1d81f707f9bf19281'),
    ('range_direct', 0x26cd130, 0x26cd25d, '1ddd28e095810574856e8f6ab6fb4a5b2bfa7214a9136f23657157808b5d42d2'),
    ('points_buffered', 0x1e38a60, 0x1e38db4, '35e474ff400480676503480d50e68ed760fd674363935ed3b83ff82648f06957'),
    ('points_direct', 0x1e488f0, 0x1e48c44, '45a53265321b46f091b702a5f649fe529a057f2c82fe8f48bc1b1a6b7c3229ca'),
    ('point_buffered', 0x26ccd60, 0x26ccf26, '860575d99dd7c0f7ce9ea448be3434ff7fa61ebcaea1dba541d9fe15e8c77bef'),
    ('guard_shared', 0x470d220, 0x470d32f, 'a96782d2241c6786430385f09233b5e05df96dba0317411ed022502067be5c37'),
    ('points_reader_list', 0x24dc4a0, 0x24dc653, '4430542c5bfc7420ba13e290b057adaaca9134820e23bea05f04786cefb87de1'),
    ('point_reader', 0x17234e0, 0x17248b3, 'e4b3a62dc7ccf637ebe3b4478ab4d98d8f363bfe9c418d1de6b7a85de1c807d5'),
    ('key_buffered_shared', 0x43f4400, 0x43f453f, '17a555a5ef7f3ec4e1f307bcbf3f5d9c26c2949e3ed634a3fe515dc20b15cfa4'),
    ('range_buffered_shared', 0x42d6210, 0x42d640b, 'bff99a5c79460aa6615fe183b9b0e381df2aab00eef48ced7e007c4e715c675c'),
    ('range_direct_shared', 0x42d5eb0, 0x42d5fdd, '01c79667a183a100ad94c8d3d931a67eb4e1d9f6d67c73ecc81a8577e1dac466'),
    ('points_buffered_shared', 0x440d2f0, 0x440d644, '377bfc16520d92cdbc8d0eaae739a3d04ad20ee52c7cec101d3633cf72c1b653'),
    ('points_direct_shared', 0x442a780, 0x442aad4, 'c144557559619552bbc0012ade43f8373536dfb3df12985fe5adde49a3d0bb74'),
    ('point_buffered_shared', 0x42d5990, 0x42d5b56, '7ac09f54e93a7a63b3f8cbd10cea566b11686773c1abd3aaa9ca5e0b6d07a2f0'),
    ('point_direct_shared', 0x42d5da0, 0x42d5eb0, '4925cae1e62f13cb7e019a18ddb8708dd03adf54e97e8f170fdba1a32813d4e8'),
)

# Offsets are curated instruction starts; no full-section opcode scan is used.
BRANCHES = {
    'outer_low': (0x24,0x41,0x73,0x7a,0x94,0xb1,0xb8,0xd2,0xe9),
    'collect_low': (0x15,0x84,0xae),
    'seq_low': (0x36,0x56,0x75,0x9f,0xa8,0xda,0x10d,0x116,0x160,0x1bd,0x1fb,0x208,0x274),
    'pair_low': (0x2d,0x3e,0x4a,0x75,0xc9,0xdf,0x102,0x124,0x14b,0x157,0x165,0x17f,0x193,0x19c,0x1b9,0x1cc,0x222,0x235,0x25f,0x284,0x2b1,0x2bd,0x2c6,0x2ed,0x2fb,0x339,0x366,0x39c,0x3b6,0x3d6,0x453,0x45a,0x464,0x48f,0x546),
    'key_low': (0x27,0x52,0x6d,0x99,0xa1,0xab,0xe5),
    'key_buffered': (0x27,0x52,0x6d,0x99,0xa1,0xab,0xe5),
    'point_direct_shared': (0x2c,0x41,0x6b,0x70,0x77,0x91,0xaa,0xb1,0xcb,0xe4),
    'range_buffered': (0x2c,0x4e,0x66,0xa6,0xad,0xb9,0xd5,0x106),
    'range_direct': (0x22,0x3c,0x6b,0x72,0x8c,0xa5,0xac,0xc6,0xde),
    'points_buffered': (0x42,0x6b,0x91,0xb1,0xbe,0xd9,0xe5,0x106,0x113),
    'point_buffered': (0x2c,0x41,0x5b,0x64,0x6b,0x77,0x8f,0xb7,0xbe,0xca,0xde,0x102),
    'guard_shared': (0x24,0x3e,0x6d,0x78,0x92,0xaa,0xb1,0xcb,0xe3),
    'tree_shared': (0x30,0x40,0x54,0x69,0x7b,0xde,0xe8,0xf1,0xfe,0x113,0x11f,0x13d,0x149,0x159,0x19c,0x1ae,0x1ca,0x1e5,0x1ea,0x202,0x220,0x22c,0x26f,0x287),
    'points_reader_list': (0x28,0x47,0x99,0xb3,0xcb,0xd6,0x163,0x194),
    'point_reader': tuple(v-0x17234e0 for v in (0x17239e8,0x17239ff,0x1723a0b,0x1723a38,0x1723a6c,0x17240b8,0x17240c8,0x1724131,0x1724139,0x172416b,0x1724285,0x172428d,0x172429c,0x1724322,0x1724339,0x172438f,0x17242bf,0x17242eb,0x1723b22)),
}
MIRRORS = {'outer_low':'outer_shared', 'collect_low':'collect_shared',
           'seq_low':'seq_shared', 'pair_low':'pair_shared', 'key_low':'key_shared',
           'key_buffered':'key_buffered_shared', 'range_buffered':'range_buffered_shared',
           'range_direct':'range_direct_shared', 'points_buffered':'points_buffered_shared',
           'points_direct':'points_direct_shared', 'point_buffered':'point_buffered_shared'}

# Selected direct calls only. Unlisted indirect transfers are not counted.
CALLS = {
    'outer_low': (0x33,0x65,0x8b,0xa2,0xc9,0xdf),
    'collect_low': (0x6a,0x78),
    'seq_low': (0x67,0xbf,0x1ee,0x235),
    'pair_low': (0x67,0xbb,0xf4,0x13d,0x214,0x24e,0x2a0,0x392,0x3ac,0x3c9,0x3e4),
    'key_low': (0x45,0x8c,0xd8),
    'key_buffered': (0x45,0x8c,0xd8),
    'point_direct_shared': (0x34,0x5e,0x88,0x9d,0xc2,0xd7),
    'range_buffered': (0x98,0xfc),
    'range_direct': (0x2f,0x5e,0x83,0x98,0xbd,0xd1),
    'points_buffered': (0x83,0xc8,0xf9,0x146,0x1fd,0x22b),
    'points_direct': (0x83,0xc8,0xf9,0x146),
    'point_buffered': (0x34,0x4e,0xaa,0xf5,0x141),
    'guard_shared': (0x31,0x60,0x89,0x9d,0xc2,0xd6),
    'points_reader_list': (0xa7,),
    'point_reader': tuple(v-0x17234e0 for v in (0x17239f4,0x1723a2d,0x1723b16,0x17242b4,0x17242e2,0x172432e,0x172399a)),
}

# Small, explicitly selected windows support the memory and predicate readings.
# Context windows bind prior packets and are not included in the FDE ownership set.
WINDOWS = (
 ('prior_thunk_low',0x26bb320,14), ('prior_thunk_shared',0x42c0580,14),
 ('prior_reader_handoff',0x18df5cb,5), ('prior_capture_low',0x27566b2,18), ('prior_capture_box',0x27566c1,3),
 ('prior_capture_secondary',0x4d7d033,18), ('prior_capture_primary',0x4d7efe3,18),
 ('prior_row19_low',0x2756d5b,30), ('prior_row19_secondary',0x4d7d6d3,35),
 ('prior_row19_primary',0x4d7f692,14), ('prior_writer_low',0x2819085,32),
 ('prior_writer_shared',0x4ae5555,32), ('prior_writer_result',0x28190a5,42),
 ('prior_writer_digest_store',0x2819181,16), ('prior_transition_ptr',0x26fef73,7),
 ('prior_transition_store',0x26ff063,21),
 ('outer_mode_and_header',0x26cd810,40), ('outer_first_field',0x26cd865,50),
 ('outer_second_field',0x26cd8a3,50), ('outer_return',0x26cd8d4,48),
 ('guard_fields',0x470d28f,115), ('tree_allocation',0x48758b0,130),
 ('tree_elements',0x4875950,55), ('tree_navigation',0x48759f1,100), ('seq_loop',0x1e42d03,100),
 ('pair_none',0x1df1b0c,55), ('pair_seq_header',0x1df1b62,16),
 ('pair_other_none',0x1df1c7a,35), ('range_fields',0x26cd19d,102),
 ('point_header_tag',0x26ccd7b,32), ('point_tag_low_byte',0x26ccdb8,48),
 ('point_p',0x26cce20,70), ('point_direct_shared_fields',0x42d5dc0,215), ('reader_count_and_reserve',0x24dc4a0,90),
 ('reader_vector_loop',0x24dc510,130), ('reader_key_classify',0x17240b4,31),
 ('reader_key_classify_alt',0x1724133,32), ('reader_p_duplicate',0x1724283,66),
 ('reader_o_duplicate',0x1724319,51), ('reader_missing',0x1724370,53),
 ('reader_missing_diagnostic',0x1723960,72), ('reader_duplicate_diagnostic',0x17247a4,89),
)

LITERALS = (
 ('spot_to_range',0x26cd86c,b'spot_to_range'),
 ('ensure_order_bucket_guard',0x26cd8aa,b'ensure_order_bucket_guard'),
 ('last_bucket',0x470d29a,b'last_bucket'),
 ('bucket_millis',0x470d2d3,b'bucket_millis'),
 ('order_sz',0x26cd1a4,b'order_sz'),
 ('points',0x26cd1de,b'points'),
 ('point_order_key',0x42d5e19,b'o'), ('point_price_key',0x42d5e53,b'p'),
)


# Each fixed load is paired with the independently resolved writer literal.
# A missing displacement in the instruction means offset zero.
FIELD_BINDINGS = (
 ('holder','spot_to_range',0x26cd886,'498d7710',3),
 ('holder','ensure_order_bucket_guard',0x26cd8c9,'4c89fe',None),
 ('guard','last_bucket',0x470d28f,'4d8b6708',3),
 ('guard','bucket_millis',0x470d2ed,'498b17',None),
 ('range','order_sz',0x26cd1be,'498b5618',3),
 ('range','points',0x26cd1fe,'4c89f2',None),
 ('point','point_order_key',0x42d5e33,'498b5708',3),
 ('point','point_price_key',0x42d5e6d,'498b5710',3),
)

# Semantics are labels for the taken branch; offsets and displacements are read
# from the ELF.  Sites are deliberately selected, not an exhaustive CFG.
DECISIONS = (
 ('outer_mode_zero','outer_low',0x26cd814,'7432'),
 ('outer_first_name_failed','outer_low',0x26cd884,'755a'),
 ('outer_tree_child_failed','outer_low',0x26cd8a1,'754c'),
 ('outer_guard_child_failed','outer_low',0x26cd8d9,'7514'),
 ('tree_size_within_limit','tree_shared',0x48758e0,'740b'),
 ('tree_allocation_null','tree_shared',0x4875904,'0f8467020000'),
 ('tree_iterator_flag_clear','tree_shared',0x4875998,'0f84c4010000'),
 ('pair_direct_range_present','pair_low',0x1df1b0f,'0f853c020000'),
 ('pair_buffered_range_present','pair_low',0x1df1c7d,'0f8594000000'),
 ('point_zero_mode_header','point_buffered',0x26ccd8c,'741a'),
 ('point_tag_low_byte_zero','point_buffered',0x26ccdc4,'7453'),
 ('point_skip_optional_name','point_buffered',0x26ccdcb,'7433'),
 ('point_optional_helper_failed','point_buffered',0x26cce17,'7554'),
 ('point_skip_price_name','point_buffered',0x26cce1e,'752b'),
 ('reader_count_zero','points_reader_list',0x24dc4c8,'0f84b5000000'),
 ('reader_allocation_null','points_reader_list',0x24dc4e7,'0f842f010000'),
 ('reader_point_status_not_9','points_reader_list',0x24dc553,'7578'),
 ('reader_point_word_2_stop','points_reader_list',0x24dc56b,'742c'),
 ('reader_capacity_available','points_reader_list',0x24dc576,'7598'),
 ('reader_key_length_not_1','point_reader',0x17240b8,'0f8519020000'),
 ('reader_key_is_o','point_reader',0x17240c8,'0f844b020000'),
 ('reader_key_unknown','point_reader',0x1724285,'7450'),
 ('reader_known_key_is_o','point_reader',0x172428d,'0f8586000000'),
 ('reader_duplicate_p','point_reader',0x172429c,'0f850e050000'),
 ('reader_duplicate_o','point_reader',0x1724322,'0f857c040000'),
 ('reader_missing_p','point_reader',0x172438f,'0f84c8f5ffff'),
)


def digest_ok(data, expected=SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('input SHA-256 mismatch')


def decode_call(va, raw):
    if len(raw) != 5 or raw[0] != 0xe8:
        raise ValueError('expected direct rel32 call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_branch(va, raw):
    if len(raw) >= 2 and 0x70 <= raw[0] <= 0x7f:
        size, condition, delta = 2, raw[0] & 15, struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) >= 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, condition, delta = 6, raw[1] & 15, struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('expected x86 conditional relative branch')
    return size, condition, va + size + delta


def classify_key(key):
    # Selected branch of the reader, after it has obtained a byte string.
    if len(key) != 1:
        return 2
    return 0 if key[0] == 0x6f else 1 if key[0] == 0x70 else 2


def reserve_count(count):
    if not 0 <= count < 1 << 32:
        raise ValueError('count out of range')
    return min(count,0xaaaa)


def point_shape(tag, mode):
    if not (0 <= tag < 1 << 64 and 0 <= mode < 256):
        raise ValueError('tag or mode out of range')
    return ((tag + 1) & 0xffffffff, bool(tag & 0xff), bool(tag & 0xff) and mode != 0, mode == 1)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections, rows = unwind_index(data)
        _, frames = eh_frame_records(data, self.sections)
        by_fde = {r['fde']: r for r in frames}
        self.frames = {}
        for row in rows:
            frame = by_fde.get(row['fde'])
            if frame is None or frame['start'] != row['start']:
                raise ValueError('unwind index and FDE disagree')
            self.frames[row['start']] = frame
        self.by_name = {name:(start,end,sha) for name,start,end,sha in FUNCTIONS}
        for name, start, end, expected in FUNCTIONS:
            frame = self.frames.get(start)
            if frame is None or frame['end'] != end:
                raise ValueError('unexpected FDE extent for ' + name)
            if hashlib.sha256(self.read(start, end-start, executable=True)).hexdigest() != expected:
                raise ValueError('unexpected bytes for ' + name)

    def mapping(self, va, size, executable=False):
        if size <= 0 or va < 0:
            raise ValueError('invalid mapped range')
        matches = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                   and (not executable or s['flags'] & 4)
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('unmapped, ambiguous, or non-file-backed range')
        sec = matches[0]
        return sec, sec['offset'] + va - sec['address']

    def read(self, va, size, executable=False):
        sec, off = self.mapping(va, size, executable)
        result = self.data[off:off+size]
        if len(result) != size:
            raise ValueError('short file-backed range')
        return result

    def literal(self, site, expected):
        insn = self.read(site, 12, executable=True)
        if insn[:3] != b'\x48\x8d\x35' or insn[7] != 0xba:
            raise ValueError('unexpected literal reference')
        va = site + 7 + struct.unpack_from('<i', insn, 3)[0]
        n = struct.unpack_from('<I', insn, 8)[0]
        text = self.read(va, n)
        if text != expected:
            raise ValueError('unexpected field literal')
        return va, n, text


# These are short, prior-work handoffs; the builder extents remain unowned here.
CAPTURE_SITES = (
 ('low',0x27566b2,0x2756d5b,0x38d0,0x56bdc98),
 ('secondary',0x4d7d033,0x4d7d6d3,0x38d0,0x5744948),
 ('primary',0x4d7efe3,0x4d7f683,0x4350,0x5744948),
)


def capture_rows(image):
    rows = []
    for lane,capture_va,install_va,expected_offset,expected_table in CAPTURE_SITES:
        capture = image.read(capture_va,18,True)
        install = image.read(install_va,29,True)
        if (capture[:3] != bytes.fromhex('488d8d') or
                capture[7:11] != bytes.fromhex('48898424') or
                capture[15:] != bytes.fromhex('488908') or
                install[:4] != bytes.fromhex('488b8c24') or
                install[8:11] != bytes.fromhex('48898b') or
                install[15:18] != bytes.fromhex('488d0d') or
                install[22:25] != bytes.fromhex('48898b')):
            raise ValueError('unexpected prior capture instruction pattern')
        offset = struct.unpack_from('<I',capture,3)[0]
        saved = struct.unpack_from('<I',capture,11)[0]
        loaded = struct.unpack_from('<I',install,4)[0]
        row = struct.unpack_from('<I',install,11)[0]
        table = install_va+22+struct.unpack_from('<i',install,18)[0]
        table_row = struct.unpack_from('<I',install,25)[0]
        if (offset != expected_offset or saved != loaded or row != 19*16 or
                table_row != row+8 or table != expected_table):
            raise ValueError('prior capture or row handoff mismatch')
        rows.append((lane,hex(capture_va),capture.hex(),hex(offset),hex(saved),
                     hex(install_va),install.hex(),hex(row),row//16,hex(table_row),hex(table)))
    return rows


# Context edges are published only as handoffs from previously analyzed code.
EDGES = (
 ('prior_thunk_low',0x26bb324,0x2819050), ('prior_thunk_shared',0x42c0584,0x4ae5520),
 ('prior_closure_low',0x28190a0,0x26cd7f0), ('prior_closure_shared',0x4ae5570,0x42d6490),
 ('prior_points_handoff',0x18df5cb,0x24dc4a0),
 ('outer_to_tree_low',0x26cd892,0x25ecf10), ('outer_to_tree_shared',0x42d6532,0x4603dd0),
 ('collect_to_seq_low',0x25ecf88,0x1e42b50), ('collect_to_tree_shared',0x4603e3a,0x48758b0),
 ('collect_to_seq_shared',0x4603e48,0x44315a0), ('seq_to_pair_low',0x1e42c0f,0x1df1990),
 ('seq_to_pair_shared',0x443165f,0x43d1820), ('pair_to_range_buffered',0x1df1d22,0x26ccf30),
 ('pair_to_range_direct',0x1df1d59,0x26cd130), ('range_to_points_buffered',0x26cd02c,0x1e38a60),
 ('range_to_points_direct',0x26cd201,0x1e488f0), ('points_to_point_buffered',0x1e38b28,0x26ccd60),
 ('pair_to_range_shared_buffered',0x43d1bb2,0x42d6210), ('pair_to_range_shared_direct',0x43d1be9,0x42d5eb0),
 ('range_to_points_shared_buffered',0x42d630c,0x440d2f0), ('range_to_points_shared_direct',0x42d5f81,0x442a780),
 ('points_to_point_shared_buffered',0x440d3b8,0x42d5990), ('points_to_point_shared_direct',0x442a848,0x42d5da0),
 ('outer_to_guard_shared',0x42d656f,0x470d220), ('reader_to_point',0x24dc547,0x17234e0),
)


def checked_edge(read, site, expected):
    raw = read(site,5)
    target = decode_call(site,raw)
    if target != expected:
        raise ValueError('unexpected direct call target')
    return raw, target


def bounded_branch(image, name, va):
    start,end,_ = image.by_name[name]
    if not start <= va < end:
        raise ValueError('branch site outside pinned FDE')
    size,cond,target = decode_branch(va,image.read(va,6,True))
    if not start <= target < end or va + size > end:
        raise ValueError('branch target outside pinned FDE')
    return size,cond,target


def field_bindings(image):
    literal_specs = {label:(site,expected) for label,site,expected in LITERALS}
    rows = []
    for container,label,site,pattern,displacement_index in FIELD_BINDINGS:
        expected_load = bytes.fromhex(pattern)
        raw = image.read(site,len(expected_load),True)
        if raw != expected_load:
            raise ValueError('unexpected field load: ' + label)
        literal_site,expected_text = literal_specs[label]
        literal_va,_,text = image.literal(literal_site,expected_text)
        offset = raw[displacement_index] if displacement_index is not None else 0
        rows.append((container,text.decode('ascii'),hex(literal_site),hex(literal_va),
                     hex(site),raw.hex(),hex(offset)))
    return rows


def decision_rows(image):
    rows = []
    for label,role,site,pattern in DECISIONS:
        size,condition,target = bounded_branch(image,role,site)
        raw = image.read(site,size,True)
        if raw != bytes.fromhex(pattern):
            raise ValueError('unexpected decision bytes: ' + label)
        rows.append((label,role,hex(site),raw.hex(),hex(condition),hex(site+size),hex(target)))
    return rows


def parse_lsda(image, frame):
    """Decode only the observed omit/omit/ULEB call-site table; actions opaque."""
    va = frame['lsda']
    if va is None:
        return None, []
    section, off = image.mapping(va, 1)
    if section['name'] != '.gcc_except_table':
        raise ValueError('LSDA outside expected section')
    limit = section['offset'] + section['size']
    if image.data[off:off+3] != b'\xff\xff\x01':
        return 'unsupported-header', []
    count, pos = uleb(image.data, off+3, limit)
    end = pos + count
    if end > limit:
        raise ValueError('LSDA call-site table exceeds section')
    rows = []
    while pos < end:
        a, pos = uleb(image.data, pos, end)
        n, pos = uleb(image.data, pos, end)
        landing, pos = uleb(image.data, pos, end)
        action, pos = uleb(image.data, pos, end)
        if a + n > frame['end']-frame['start'] or (landing and landing >= frame['end']-frame['start']):
            raise ValueError('LSDA entry outside FDE')
        rows.append((a,n,landing,action))
    return 'omit-omit-uleb', rows


DATA = (
    ('missing_field_format',0x1df8f3,bytes.fromhex('0f6d697373696e67206669656c64')),
    ('duplicate_field_format',0x1e0fd5,bytes.fromhex('116475706c6963617465206669656c64')),
    ('diagnostic_order_key',0x3af648,b'o'), ('diagnostic_price_key',0x3afb62,b'p'),
)

PREDICATES = (
    ('reader_key_length',0x17240b4,'4883fa01'),
    ('reader_price_key',0x17240c1,'3c70'),
    ('reader_order_key',0x17240c6,'3c6f'),
    ('reader_reserve_cap',0x24dc4b1,'81fdaaaa0000'),
    ('reader_slot_stride',0x24dc4d1,'4489e0c1e0034c8d3c40'),
    ('point_header_count',0x26ccd83,'418d5501'),
    ('point_optional_low_byte',0x26ccdc1,'4584ed'),
    ('point_named_mode_nonzero',0x26ccd87,'41807e1b00'),
    ('point_price_name_mode_one',0x26cce19,'41807e1b01'),
)


def pinned_predicates(read):
    rows = []
    for label, va, pattern in PREDICATES:
        expected = bytes.fromhex(pattern)
        got = read(va, len(expected))
        if got != expected:
            raise ValueError('unexpected predicate bytes: ' + label)
        rows.append((label,hex(va),got.hex()))
    return rows


def relocation_tables(image):
    sec = next(s for s in image.sections if s['name'] == '.rela.dyn')
    if sec['type'] == 8 or sec['size'] % 24:
        raise ValueError('unsupported relocation section')
    wanted = {0x56bdcb0:0x26bb320, 0x5744960:0x42c0580}
    found = {}
    for off in range(sec['offset'],sec['offset']+sec['size'],24):
        where,info,addend = struct.unpack_from('<QQq',image.data,off)
        if where in wanted:
            if where in found or info != 8 or addend != wanted[where]:
                raise ValueError('unexpected or duplicate row relocation')
            found[where] = (off,addend)
    if set(found) != set(wanted):
        raise ValueError('missing row relocation')
    rows = []
    for label,base,slot in (('low',0x56bdc98,0x56bdcb0),('shared',0x5744948,0x5744960)):
        raw = image.read(base,32)
        qwords = struct.unpack('<QQQQ',raw)
        if qwords != (0,8,8,0):
            raise ValueError('unexpected row vtable bytes')
        off,addend = found[slot]
        rows.append((label,hex(base),raw.hex(),hex(slot),hex(off),'8','0',hex(addend)))
    return rows


def write_tsv(out, name, columns, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        writer.writerows(rows)


def generate(data, out):
    digest_ok(data)
    image = Image(data)
    out.mkdir(parents=True, exist_ok=True)
    frows, xrows, brows, crows, wrows, lrows, exrows, hrows = [], [], [], [], [], [], [], []
    for name,start,end,sha in FUNCTIONS:
        frame = image.frames[start]
        section, off = image.mapping(start,end-start,True)
        frows.append((name,hex(start),hex(end),end-start,hex(off),hex(frame['fde']),
                      hex(frame['lsda']) if frame['lsda'] is not None else '-',sha))
        xrows.append((name,hex(start),hex(end),image.read(start,end-start,True).hex()))
        encoding, table = parse_lsda(image,frame)
        if encoding is not None:
            _,lsda_off = image.mapping(frame['lsda'],8)
            hrows.append((name,hex(frame['lsda']),hex(lsda_off),image.read(frame['lsda'],8).hex(),encoding))
            for a,n,landing,action in table:
                exrows.append((name,hex(frame['lsda']),hex(start+a),n,
                               hex(start+landing) if landing else '-',action,encoding))
            if not table:
                exrows.append((name,hex(frame['lsda']),'-','-','-','-',encoding))
    for name, offsets in BRANCHES.items():
        names = (name,MIRRORS[name]) if name in MIRRORS else (name,)
        for member in names:
            start,end,_ = image.by_name[member]
            for delta in offsets:
                va = start+delta
                size, cond, target = bounded_branch(image,member,va)
                brows.append((member,hex(va),image.read(va,size,True).hex(),hex(cond),hex(target)))
    for name, offsets in CALLS.items():
        names = (name,MIRRORS[name]) if name in MIRRORS else (name,)
        for member in names:
            start,end,_ = image.by_name[member]
            for delta in offsets:
                va = start+delta
                if va+5 > end:
                    raise ValueError('call outside pinned FDE')
                raw = image.read(va,5,True)
                target = decode_call(va,raw)
                image.mapping(target,1,True)
                crows.append((member,hex(va),raw.hex(),hex(target)))
    for label,va,n in WINDOWS:
        sec,off = image.mapping(va,n,True)
        wrows.append((label,hex(va),hex(off),image.read(va,n,True).hex()))
    for label,site,expected in LITERALS:
        va,n,raw = image.literal(site,expected)
        _,off = image.mapping(va,n)
        lrows.append((label,hex(site),hex(va),hex(off),n,raw.hex(),raw.decode('ascii')))
    erows = []
    for label,site,expected in EDGES:
        raw,target = checked_edge(lambda va,n:image.read(va,n,True),site,expected)
        image.mapping(target,1,True)
        erows.append((label,hex(site),raw.hex(),hex(target)))
    drows = []
    for label,va,expected in DATA:
        raw = image.read(va,len(expected))
        if raw != expected:
            raise ValueError('unexpected diagnostic data')
        _,off = image.mapping(va,len(expected))
        drows.append((label,hex(va),hex(off),raw.hex()))
    caprows = capture_rows(image)
    fieldrows = field_bindings(image)
    decisions = decision_rows(image)
    predrows = pinned_predicates(lambda va,n:image.read(va,n,True))
    relrows = relocation_tables(image)
    write_tsv(out,'functions.tsv',('role','start_va','end_va_exclusive','length','file_offset','fde_va','lsda_va','sha256'),frows)
    write_tsv(out,'extents.tsv',('role','start_va','end_va_exclusive','bytes'),xrows)
    write_tsv(out,'branches.tsv',('role','site_va','bytes','condition_code','target_va'),brows)
    write_tsv(out,'calls.tsv',('role','site_va','bytes','target_va'),crows)
    write_tsv(out,'edges.tsv',('label','site_va','bytes','target_va'),erows)
    write_tsv(out,'windows.tsv',('label','va','file_offset','bytes'),wrows)
    write_tsv(out,'literals.tsv',('label','lea_va','literal_va','file_offset','length','bytes','ascii'),lrows)
    write_tsv(out,'lsda.tsv',('role','lsda_va','start_va','length','landing_pad_va','action_index','encoding'),exrows)
    write_tsv(out,'lsda-headers.tsv',('role','lsda_va','file_offset','first_8_bytes','encoding'),hrows)
    write_tsv(out,'capture-rows.tsv',('lane','capture_va','capture_bytes','state_offset','stack_slot','install_va','install_bytes','pair_offset','row_index','table_pair_offset','table_va'),caprows)
    write_tsv(out,'field-order.tsv',('container','name','literal_site_va','literal_va','load_site_va','load_bytes','source_offset'),fieldrows)
    write_tsv(out,'decisions.tsv',('taken_condition','role','site_va','bytes','condition_code','fallthrough_va','target_va'),decisions)
    write_tsv(out,'predicates.tsv',('label','site_va','bytes'),predrows)
    write_tsv(out,'diagnostic-data.tsv',('label','va','file_offset','bytes'),drows)
    write_tsv(out,'tables.tsv',('lane','table_va','table_bytes','slot_va','rela_file_offset','relocation_type','symbol_index','addend_va'),relrows)
    summary = {'artifact_sha256':SHA256, 'scope':'selected x86-64 instruction sites and FDEs, not an exhaustive call graph',
               'fde_count':len(frows), 'fde_bytes':sum(end-start for _,start,end,_ in FUNCTIONS), 'selected_branch_count':len(brows), 'selected_direct_call_count':len(crows),
               'selected_window_count':len(wrows), 'literal_count':len(lrows), 'lsda_rows':len(exrows), 'lsda_headers':len(hrows),
               'lsda_decoded_headers':sum(r[-1]=='omit-omit-uleb' for r in hrows),
               'lsda_unsupported_headers':sum(r[-1]=='unsupported-header' for r in hrows),
               'checked_path_edges':len(erows), 'predicate_pins':len(predrows), 'row_relocations':len(relrows),
               'diagnostic_data_pins':len(drows), 'prior_capture_rows':len(caprows), 'field_bindings':len(fieldrows), 'named_decisions':len(decisions),
               'fde_note':'unwind-described extents, not a census of all functions',
               'lsda_note':'only omit/omit/ULEB tables decoded; action values and other headers remain opaque'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args = parser.parse_args()
    with BINARY.open('rb') as stream, mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as data:
        summary = generate(data,args.out)
    print(json.dumps(summary,sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError,OSError,struct.error) as error:
        print('abci_hyperliquidity_root: '+str(error),file=sys.stderr)
        raise SystemExit(1)
