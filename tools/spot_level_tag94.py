#!/usr/bin/env python3
"""Collect byte-bound spot price-level option and split-marker evidence, offline."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = (
    ('spot_level_entry', 0x2878610, 0x2878760, 'c0b727f22d2d9d37ecdbb8e10fef17b8ab49fdc15b0267985f0d608a4e3674ec'),
    ('spot_level_insert_split', 0x1a94920, 0x1a9566a, '6b7a15c70a8255eb384305693c40bd05ce3ae63395e9807e97cd02640d282875'),
    ('halfs_field_writer', 0x4a987c0, 0x4a98b72, 'ad3f56bcf9371cacd2f1e2bcb3186705a4affce83ea3193b962fc2333acdaa5d'),
    ('half_levels_writer', 0x431e040, 0x431e29b, '9f52fb14f341922fda477d261d527655d23f66f8ebf11551b3129d74c3526c3b'),
    ('level_map_writer', 0x460b7a0, 0x460b866, '732756a2676e6c3bc3224e1e97073a4250b0d1f41a1b65a021609003ee82da08'),
    ('level_entry_writer', 0x4a407a0, 0x4a412d0, 'a2f0410ab87a1bd5e1d0c66c77aa1a26c06a231392e8e8c72b267550f3e2a391'),
)
# These are hand-selected instruction-boundary windows, checked by independent
# expected digests. The collector never derives an instruction list from text.
WINDOWS = (
 ('side_route',0x26ea3d5,0x26ea404,'32d4a38f72f8923f1667febf21967343e2b9be338493806154d7559470c73bb8'),
 ('book_halfs',0x431e741,0x431e75c,'1ce88acd75b2058a52ac2be7482c48d1ca64ab2267b9a40d6fbeadd8aa726d1d'),
 ('halfs_argument',0x4a987ce,0x4a987d9,'56bb2fa0edb00e5fb01c6e01253bf1a9c1f0fed9949260025e14f1b253c60978'),
 ('halfs_saved',0x4a98848,0x4a98856,'fcdbcc78ee0097629b8de49d7e4ce88f3b9b4cf1031473b93fdef65e2a1f70b7'),
 ('two_halves_a',0x4a988c7,0x4a988e5,'34a78dcbf12dcfe94c6247fc0fe58486b19ce34f1f5e1ea3eb5dfe6600c7e49f'),
 ('two_halves_b',0x4a988fb,0x4a9890a,'8f97cc7afde0c6255b89ff69c6e9cfb0f4d58a01c6b21c37f79e1bdb8c93ad27'),
 ('two_halves_c',0x4a98987,0x4a989a2,'9fb1bb62d1d2c0b51262b16e3e748de980cf921764a9d2a8532be18190b85484'),
 ('levels_field',0x431e094,0x431e0a8,'1089fd90d79fe7867c639b60203d6b6a2de4e7dd0a843d00daa693ef9cb6dc2e'),
 ('levels_call',0x431e0e0,0x431e0eb,'914b0425e30f73a6cfbc7329c648ccd195c35978da3ce8404de6f976e522f16c'),
 ('level_pairs',0x460b7fa,0x460b817,'5b21f893b1bba69782defaa997fb18e12ffb70111b8d23fd9cadab389c448aa8'),
 ('pair_value',0x4a40820,0x4a40836,'8ee87227ca82fd89be02d2f92561a39a004a42fa476a8c67ac57efd2063f0883'),
 ('level_tags',0x4a40aa0,0x4a40b2e,'43791593991c45617474ca560c8176ae5a0cb0a91ae25d88438136644c28e087'),
 ('first_field',0x4a40b2e,0x4a40b97,'e55e4ef4cbdd405313d203b87c82bc05e38483d22933426fda736db2d57da260'),
 ('last_field',0x4a40bff,0x4a40c73,'b7bd51a30a68e28de6fb15b469d84a0a4f1a5b75486071daf5a61f48cbb147f4'),
 ('queue_head',0x26ea59f,0x26ea5ba,'017a3b99d670c28d750db0fd4aa28ae72d0d89ac3b20e07374f5685d339d7ad2'),
 ('queue_tail',0x26ea606,0x26ea617,'090dbffc91f478aec63ed6227c509c063d53f43c12e0c8d123dde797dd49698c'),
 ('entry_occupied',0x2878699,0x28786b1,'0b72b59fece2f28cad9ac64f261b8e02ef652fe4daa88d0d05bf24deb896c4f2'),
 ('new_value',0x2878637,0x2878649,'a15db62d0ff4fc0eedf6e023f526a600f7e854488275e850095058f4654fc6cf'),
 ('leaf_init',0x28786b1,0x28786e5,'8b3bbc8f61c33dfd2e782c4efaabee00566d4de6bb3e85f87486ba38399f767b'),
 ('leaf_write',0x28786e5,0x2878737,'76189eface349ee64cf47f4fd072350b89ccfebc0357fc39f4b99ac93b40dad8'),
 ('full_gate',0x1a94937,0x1a9495c,'782863e6517a6b8443d4b153b3914932a4eec78fde865907ac98722624c1d880'),
 ('pivot_a',0x1a94980,0x1a949a5,'34a2b805d5ab0af949417d6835541457794888882143ccf53ec00da7f920dc9f'),
 ('pivot_b',0x1a94a73,0x1a94aa9,'10dc220d4cd9e96f2201e184a8b61098ce4001ad5c2384b767367e978c93c8ff'),
 ('no_split_tag',0x1a94a34,0x1a94a5f,'6202d2bd2e63a2bfac19cd2804392d6cb15eaad05c844d727247f85f211f9abb'),
 ('promoted_read',0x1a94afe,0x1a94b2d,'443596e63805f74d14c83fe0f542304d5614c51dcef0be5bcd673ce63d0f2183'),
 ('copy_and_truncate',0x1a94b5e,0x1a94b8c,'0df817a10aea7495ff42364ba823b1dabc71d4d4525a2536efcdf191699662f1'),
 ('insert_value',0x1a94c47,0x1a94c75,'61a82100b4b93e2e8f725b75de1215089d11cd2caa7aa56b9105a2fca04fa768'),
 ('promoted_decision',0x1a94c75,0x1a94cbb,'a8faec239666e9a6f21d0adaa5b9e32025e94dd6c1bdefde1dd0d320fe73d28c'),
 ('parent_choice',0x1a94ced,0x1a94d35,'4306f53a7cc07f41b6de45fa19308511fd695c0243cb0aea248cd9dea62e6a22'),
 ('internal_promoted_read',0x1a9502b,0x1a9506b,'4d962c7fbfe6854de2ed07c31183979a9ca4c4bdaef1ed0f519f70f98bde695d'),
 ('internal_promoted_decision',0x1a9536a,0x1a953b6,'9434bee36d51751600c444b2bdb19d374fea545df472be8ea43d5eefca7ed6e0'),
 ('root_record',0x1a9547b,0x1a954df,'6296bb299e454c7a43a18343370e838acf392e8366e5aa94840108415f76a996'),
 ('root_growth',0x1a9543e,0x1a9547b,'da0443e93fb8536aa8b3cda7c65247c04592d85c1498803474fba4591b4c2134'),
 ('return',0x1a954df,0x1a95519,'e0e7a2390e1725ca7d20ec430187117d0538e82cdee66af547be8b31e3daa3a4'),
 ('leaf_cleanup',0x1a95632,0x1a9564d,'3a4d72af8916bbc43a9a6dd48665f42c1b3e9f1a3beb1837b94970db2da7f38c'),
 ('internal_cleanup',0x1a9564f,0x1a9566a,'c07e61afa2e9f446ef9c7bde7b4a89d22e87b8c0c792f6c90748d3c21573fc17'),
)
# Each row pins predicate opcode as well as destination; the list is selected,
# not an exhaustive instruction or control-flow inventory.
BRANCHES = (
 (0x287861c,0x74,0x2878699,'occupied'),(0x287864f,0x74,0x28786b1,'empty_root'),
 (0x28786c4,0x74,0x2878737,'leaf_alloc_failure'),(0x28786f0,0x73,0x2878747,'leaf_capacity_failure'),
 (0x1a9495a,0x73,0x1a94980,'full_node'),(0x1a94976,0x76,0x1a949a5,'shift_nonfull_suffix'),
 (0x1a9498d,0x83,0x1a94a73,'pivot_at_least_five'),(0x1a94a73,0x74,0x1a94a8e,'pivot_equal_five'),
 (0x1a94a79,0x75,0x1a94a98,'pivot_above_six'),(0x1a94a59,0x85,0x1a94cbb,'nonfull_propagate'),
 (0x1a94ac0,0x84,0x1a955ae,'sibling_alloc_failure'),(0x1a94b31,0x83,0x1a95595,'sibling_copy_bounds'),
 (0x1a94bd9,0x76,0x1a94c3f,'append_in_split'),(0x1a94cb5,0x84,0x1a94a5f,'promoted_tag_is_stop'),
 (0x1a94cf7,0x84,0x1a953f2,'no_parent'),(0x1a94d15,0x85,0x1a95519,'height_mismatch'),
 (0x1a94d2f,0x83,0x1a94e40,'full_parent'),(0x1a94d3e,0x83,0x1a94e70,'append_parent'),
 (0x1a94e54,0x83,0x1a94fa0,'parent_pivot_at_least_five'),(0x1a94fa4,0x74,0x1a94fbf,'parent_pivot_equal_five'),
 (0x1a94faa,0x75,0x1a94fc7,'parent_pivot_above_six'),(0x1a94fee,0x84,0x1a9556a,'internal_alloc_failure'),
 (0x1a9505d,0x83,0x1a95532,'parent_copy_bounds'),(0x1a950e4,0x83,0x1a9554e,'edge_copy_bounds'),
 (0x1a950f4,0x85,0x1a9557a,'edge_length_mismatch'),(0x1a953b0,0x84,0x1a954df,'parent_tag_is_stop'),
 (0x1a9540d,0x84,0x1a955be,'missing_old_root'),(0x1a9542a,0x84,0x1a955cb,'root_alloc_failure'),
 (0x1a95454,0x84,0x1a955dd,'height_wrap'),(0x1a95475,0x85,0x1a955ec,'root_height_mismatch'),
 (0x1a95487,0x83,0x1a95605,'root_capacity_failure'),
 (0x4a40aeb,0x75,0x4a40b12,'level_any_low32_nonzero'),
 (0x4a40b28,0x85,0x4a40bff,'omit_first_unless_one'),(0x4a40b83,0x74,0x4a40bd0,'first_lowbyte_zero'),
 (0x4a40c04,0x85,0x4a40cdf,'omit_last_unless_one'),(0x4a40c5f,0x74,0x4a40cb0,'last_lowbyte_zero'),
 (0x4a988df,0x85,0x4a98a5b,'first_half_error'),(0x4a9899c,0x85,0x4a98a5b,'second_half_error'),
 (0x431e0ee,0x85,0x431e1c6,'levels_error'),(0x4a40b49,0x84,0x4a411f9,'first_key_error'),
 (0x4a40c25,0x84,0x4a411f9,'last_key_error'),(0x4a98817,0x84,0x4a98b58,'halfs_depth_limit'),
 (0x431e056,0x84,0x431e281,'half_depth_limit'),(0x4a407b6,0x84,0x4a412b6,'entry_depth_limit'),
)
CALLS = (
 (0x431e757,0x4a987c0,'book_to_halfs'),(0x4a988d7,0x431e040,'first_half'),
 (0x4a98994,0x431e040,'second_half'),(0x431e0e6,0x460b7a0,'half_to_levels'),
 (0x460b807,0x48758b0,'collect_level_pairs'),(0x460b812,0x4a407a0,'format_level_pairs'),
 (0x4a40b3f,0x4ab04c0,'first_key'),(0x4a40c1b,0x4ab04c0,'last_key'),
 (0x4a40b92,0x4355c60,'first_value'),(0x4a40c6e,0x4355c60,'last_value'),
 (0x26ea3ff,0x25a7640,'spot_to_search'),(0x26ea59a,0x232c410,'spot_to_slot_insert'),
 (0x25a76d2,0x2878610,'entry_found'),(0x25a76f1,0x2878610,'entry_empty_tree'),
 (0x25a771a,0x2878610,'entry_absent_key'),(0x2878680,0x1a94920,'insert_existing_root'),
 (0x1a95648,0x5660110,'leaf_resume'),(0x1a95665,0x5660110,'internal_resume'),
)
SLOTS = (
 (0x28786bb,0x576dfd8,'leaf_alloc'),(0x2878741,0x576e020,'entry_alloc_failure'),
 (0x1a94ab7,0x576dfd8,'split_leaf_alloc'),(0x1a94fe5,0x576dfd8,'split_internal_alloc'),
 (0x1a95421,0x576dfd8,'root_alloc'),(0x1a955b8,0x576e020,'split_leaf_alloc_failure'),
 (0x1a95574,0x576e020,'internal_alloc_failure'),(0x1a9563f,0x576e010,'leaf_free'),
 (0x1a9565c,0x576e010,'internal_free'),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(blob, expected=SHA256):
    require(hashlib.sha256(blob).hexdigest() == expected, 'target SHA-256 mismatch')


class Image:
    def __init__(self, blob, authenticate=True):
        if authenticate:
            verify_digest(blob)
        self.data = blob
        self.secs = sections(blob)
        _, index = unwind_index(blob)
        _, records = eh_frame_records(blob, self.secs)
        self.fdes = {}
        for f in records:
            require(f['start'] not in self.fdes, 'duplicate FDE start')
            self.fdes[f['start']] = f
        self.index = {e['start']: e['fde'] for e in index}

    def read(self, va, size, executable=False):
        require(isinstance(va, int) and isinstance(size, int) and size > 0, 'invalid range')
        matches = [s for s in self.secs if s['type'] != 8 and s['address'] <= va and
                   va + size <= s['address'] + s['size'] and (not executable or s['flags'] & 4)]
        require(len(matches) == 1, 'range is not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off >= 0 and off + size <= len(self.data), 'range outside file')
        return off, self.data[off:off + size]

    def fde(self, start, end):
        f = self.fdes.get(start)
        require(f is not None and f['end'] == end, 'unexpected FDE extent')
        require(self.index.get(start) == f['fde'], 'FDE not linked to unwind index')
        self.read(start, end - start, True)
        return f


def verify_window(image, a, b, expected):
    off, raw = image.read(a, b-a, True)
    require(hashlib.sha256(raw).hexdigest() == expected, 'witness bytes changed')
    return off, raw


def branch(image, site, opcode, expected):
    off, first = image.read(site, 2, True)
    if first[0] == 0x0f:
        require(first[1] == opcode and 0x80 <= opcode <= 0x8f, 'unexpected branch opcode')
        _, raw = image.read(site, 6, True)
        dest = site + 6 + struct.unpack_from('<i', raw, 2)[0]
    else:
        require(first[0] == opcode and 0x70 <= opcode <= 0x7f, 'unexpected branch opcode')
        raw = first
        dest = site + 2 + struct.unpack_from('<b', raw, 1)[0]
    require(dest == expected, 'unexpected branch destination')
    return off, raw, dest


def edge(image, site, expected, indirect=False):
    length = 6 if indirect else 5
    off, raw = image.read(site, length, True)
    require(raw[:2] == b'\xff\x15' if indirect else raw[:1] == b'\xe8', 'unexpected call opcode')
    dest = site + length + struct.unpack_from('<i', raw, 2 if indirect else 1)[0]
    require(dest == expected, 'unexpected call destination')
    return off, raw, dest


def imm(image, site, prefix, length):
    _, raw = image.read(site, len(prefix) + length, True)
    require(raw.startswith(prefix), 'unexpected immediate instruction')
    return int.from_bytes(raw[len(prefix):], 'little')


def constants(image):
    # Immediate offsets are fixed from the audited instruction boundaries.
    return {
        'full_node_keys': imm(image, 0x1a94942, bytes.fromhex('4883fb'), 1),
        'first_pivot_threshold': imm(image, 0x1a94984, bytes.fromhex('4883fb'), 1),
        'second_pivot_threshold': imm(image, 0x1a94a75, bytes.fromhex('4883fb'), 1),
        'small_pivot': imm(image, 0x1a94998, bytes.fromhex('bb'), 4),
        'middle_pivot': imm(image, 0x1a94a7b, bytes.fromhex('bb'), 4),
        'large_pivot': imm(image, 0x1a94aa1, bytes.fromhex('bb'), 4),
        'right_index_bias': 256 - imm(image, 0x1a94a98, bytes.fromhex('4883c3'), 1),
        'entry_zero_head': imm(image, 0x2878637, bytes.fromhex('48c7442430'), 4),
        'entry_zero_tail': imm(image, 0x2878640, bytes.fromhex('48c7442440'), 4),
        'non_split_marker': imm(image, 0x1a94a40, bytes.fromhex('b9'), 4),
        'promoted_marker_test': imm(image, 0x1a94cb1, bytes.fromhex('4883f9'), 1),
        'head_present_store': imm(image, 0x26ea5aa, bytes.fromhex('49c706'), 4),
        'tail_present_store': imm(image, 0x26ea606, bytes.fromhex('49c74610'), 4),
        'leaf_allocation': imm(image, 0x28786b6, bytes.fromhex('bf'), 4),
        'internal_allocation': imm(image, 0x1a9541c, bytes.fromhex('bf'), 4),
        'value_stride_shift': imm(image, 0x1a94b0e, bytes.fromhex('48c1e0'), 1),
    }


def split_cases(c):
    capacity = c['full_node_keys']
    low, high = c['first_pivot_threshold'], c['second_pivot_threshold']
    small, middle, large, bias = (c[k] for k in
        ('small_pivot', 'middle_pivot', 'large_pivot', 'right_index_bias'))
    require((capacity, low, high, small, middle, large, bias) == (11, 5, 6, 4, 5, 6, 7),
            'unexpected split immediates')
    rows = []
    for index in range(capacity + 1):
        if index < low:
            pivot, side, local = small, 'left', index
        elif index == low:
            pivot, side, local = index, 'left', index
        elif index == high:
            pivot, side, local = middle, 'right', 0
        else:
            pivot, side, local = large, 'right', index - bias
        left = pivot + (side == 'left')
        right = capacity - pivot - 1 + (side == 'right')
        rows.append((index, pivot, side, local, int(left), int(right)))
    return rows




def tag_uses(image):
    # Fixed encodings identify operand width, address form and immediate.
    sites = (
        ('append_head_byte', 0x26ea5a4, '41803e', 8),
        ('leaf_split_qword', 0x1a94cb1, '4883f9', 64),
        ('parent_split_qword', 0x1a953ac, '4883f9', 64),
        ('first_field_dword', 0x4a40b20, '41837d00', 32),
        ('first_payload_byte', 0x4a40b7e, '41807d00', 8),
        ('last_field_dword', 0x4a40bff, '41837d10', 32),
        ('last_payload_byte', 0x4a40c5a, '41807d10', 8),
    )
    rows = []
    for name, site, pattern, width in sites:
        prefix = bytes.fromhex(pattern)
        off, raw = image.read(site, len(prefix) + 1, True)
        require(raw.startswith(prefix), 'unexpected tag-test encoding')
        value = raw[-1]
        require(value == (2 if width == 64 else 1 if width == 32 else 0), 'unexpected tag-test immediate')
        rows.append((name, hex(site), hex(off), raw.hex(), width, value))
    return rows

def literal_rows(image):
    # RIP-relative LEA plus each fixed length instruction bind bytes to fields.
    specs = (('book_halfs',0x431e748,0x431e752,0x6eff88,b'halfs'),
             ('half_levels',0x431e094,0x431e09e,0x6efdd5,b'levels'),
             ('level_first',0x4a40b38,0x4a40b2e,0x704287,b'f'),
             ('level_last',0x4a40c14,0x4a40c0a,0x704291,b'l'))
    rows = []
    for label, lea, length_site, expected_va, expected in specs:
        _, raw = image.read(lea, 7, True)
        require(raw[:3] == b'\x48\x8d\x35', 'unexpected literal LEA')
        target = lea + 7 + struct.unpack_from('<i', raw, 3)[0]
        require(target == expected_va, 'unexpected literal address')
        size = imm(image, length_site, b'\xba', 4)
        require(size == len(expected), 'unexpected literal length')
        off, text = image.read(target, size)
        require(text == expected, 'changed literal bytes')
        rows.append((label, hex(lea), raw.hex(), hex(length_site), hex(target), hex(off), bytes(text).decode('ascii')))
    return rows

def relocation_rows(image):
    # ELF64 Rela records; the expected types and addends bind each selected
    # slot without assuming the resolved semantics of a function address.
    expected = {
        0x576dfd8: ('allocation_slot', 8, 0, 0x54c06b0),
        0x576e010: ('release_slot', 8, 0, 0x54c8cb0),
        0x576e020: ('allocation_failure_slot', 8, 0, 0x1345e2a),
        0x5778db0: ('unwind_plt_slot', 7, 7, 0),
    }
    dynsyms = [s for s in image.secs if s['name'] == '.dynsym' and s['type'] != 8]
    dynstrs = [s for s in image.secs if s['name'] == '.dynstr' and s['type'] != 8]
    require(len(dynsyms) == len(dynstrs) == 1, 'missing dynamic symbol data')
    symsec, strsec = dynsyms[0], dynstrs[0]
    rows = {}
    for sec in image.secs:
        if sec['type'] != 4:
            continue
        require(sec['size'] % 24 == 0, 'partial Rela section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, off)
            if slot not in expected:
                continue
            require(slot not in rows, 'duplicate selected relocation')
            name, typ, sym, value = expected[slot]
            require((info & 0xffffffff, info >> 32, addend) == (typ, sym, value), 'changed relocation')
            symbol = ''
            if sym:
                require((sym + 1) * 24 <= symsec['size'], 'symbol outside table')
                nameoff = struct.unpack_from('<I', image.data, symsec['offset'] + sym * 24)[0]
                require(nameoff < strsec['size'], 'symbol name outside string table')
                begin = strsec['offset'] + nameoff
                end = image.data.find(b'\0', begin, strsec['offset'] + strsec['size'])
                require(end >= 0, 'unterminated dynamic symbol')
                symbol = bytes(image.data[begin:end]).decode('ascii')
                require(symbol == '_Unwind_Resume', 'unexpected unwind symbol')
            rows[slot] = (name, hex(slot), sec['name'], hex(off), typ, sym,
                          hex(addend), symbol, image.data[off:off+24].hex())
    require(set(rows) == set(expected), 'missing selected relocation')
    _, raw = image.read(0x5660110, 6, True)
    require(raw[:2] == b'\xff\x25', 'unexpected unwind PLT opcode')
    slot = 0x5660110 + 6 + struct.unpack_from('<i', raw, 2)[0]
    require(slot == 0x5778db0, 'unexpected unwind PLT slot')
    return [rows[x] for x in sorted(rows)], raw.hex()

def lsda_rows(image, frame):
    """Read this FDE's omitted-base, omitted-type, ULEB call-site table."""
    va = frame['lsda']
    secs = [s for s in image.secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(secs) == 1 and va is not None, 'missing exception table')
    s = secs[0]
    require(s['address'] <= va < s['address'] + s['size'], 'LSDA outside exception table')
    start = s['offset'] + va - s['address']
    limit = s['offset'] + s['size']
    require(image.data[start:start+3] == b'\xff\xff\x01', 'unsupported LSDA header')
    size, pos = uleb(image.data, start + 3, limit)
    end = pos + size
    require(end <= limit, 'truncated LSDA')
    rows, previous = [], 0
    while pos < end:
        begin = pos
        vals = []
        for _ in range(4):
            value, pos = uleb(image.data, pos, end)
            vals.append(value)
        offset, length, landing, action = vals
        require(offset >= previous and offset + length <= frame['end'] - frame['start'], 'invalid LSDA interval')
        require(landing == 0 or landing < frame['end'] - frame['start'], 'invalid landing pad')
        previous = offset + length
        rows.append((hex(frame['start']+offset), hex(frame['start']+offset+length),
                     '' if not landing else hex(frame['start']+landing), action,
                     image.data[begin:pos].hex()))
    raw = image.data[start:end]
    require(hashlib.sha256(raw).hexdigest() == '7f137ef0837d338fc064808be0abe81c26ddd0118126ef5dc287e7233a0a245d',
            'LSDA bytes changed')
    return rows


def write_tsv(out, name, headers, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(headers)
        w.writerows(rows)


def collect(image, out):
    out.mkdir(parents=True, exist_ok=True)
    funcs = []
    for name, start, end, digest in FUNCTIONS:
        f = image.fde(start, end)
        off, raw = image.read(start, end-start, True)
        require(hashlib.sha256(raw).hexdigest() == digest, 'function bytes changed')
        funcs.append((name, hex(start), hex(end), hex(off), end-start, hex(f['fde']),
                      '' if f['lsda'] is None else hex(f['lsda']), digest))
    pins = []
    for name, start, end, digest in WINDOWS:
        off, raw = verify_window(image, start, end, digest)
        pins.append((name, hex(start), hex(end), hex(off), raw.hex(), digest))
    branches = []
    for site, op, dest, name in BRANCHES:
        require(any(start <= site < end and start <= dest < end for _, start, end, _ in FUNCTIONS),
                'branch leaves selected FDE')
        off, raw, actual = branch(image, site, op, dest)
        branches.append((name, hex(site), hex(off), raw.hex(), hex(site+len(raw)), hex(actual)))
    calls = []
    for indirect, items in ((False, CALLS), (True, SLOTS)):
        for site, dest, name in items:
            off, raw, actual = edge(image, site, dest, indirect)
            calls.append((name, 'rip_slot' if indirect else 'rel32_call', hex(site), hex(off), raw.hex(), hex(actual)))
    uses = tag_uses(image)
    literals = literal_rows(image)
    bindings, plt_hex = relocation_rows(image)
    exception_rows = lsda_rows(image, image.fdes[0x1a94920])
    c = constants(image)
    require(c['entry_zero_head'] == c['entry_zero_tail'] == 0, 'unexpected new-value tags')
    require(c['non_split_marker'] == c['promoted_marker_test'] == 2, 'unexpected split marker')
    require(c['head_present_store'] == c['tail_present_store'] == 1, 'unexpected link tag')
    cases = split_cases(c)
    write_tsv(out,'functions.tsv',('role','start_va','end_va_exclusive','file_offset','size','fde_va','lsda_va','sha256'),funcs)
    write_tsv(out,'witnesses.tsv',('role','start_va','end_va_exclusive','file_offset','raw_hex','sha256'),pins)
    write_tsv(out,'branches.tsv',('role','site_va','file_offset','raw_hex','fallthrough_va','taken_va'),branches)
    write_tsv(out,'calls.tsv',('role','encoding','site_va','file_offset','raw_hex','target_or_slot_va'),calls)
    write_tsv(out,'tag-uses.tsv',('role','site_va','file_offset','raw_hex','operand_bits','equal_immediate'),uses)
    write_tsv(out,'literals.tsv',('role','lea_va','lea_hex','length_site_va','data_va','file_offset','literal'),literals)
    write_tsv(out,'relocations.tsv',('role','slot_va','rela_section','file_offset','type','symbol_index','addend','symbol','raw_hex'),bindings)
    write_tsv(out,'unwind-sites.tsv',('start_va','end_va_exclusive','landing_va','action','raw_hex'),exception_rows)
    write_tsv(out,'split-cases.tsv',('insertion_index','old_pivot_index','new_key_side','new_local_index','left_count','right_count'),cases)
    summary = {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses, half-open ranges',
               'scope': 'selected byte windows, not an instruction census or runtime trace',
               'constants_read_from_instruction_bytes': c,
               'selected_functions': len(funcs), 'selected_witnesses': len(pins),
               'selected_conditional_branches': len(branches), 'selected_calls': len(calls),
               'synthetic_split_cases': len(cases), 'lsda_call_site_rows': len(exception_rows),
               'selected_relocations': len(bindings), 'selected_literals': len(literals), 'selected_tag_tests': len(uses), 'unwind_plt_bytes': plt_hex}
    (out / 'evidence.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    blob = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    collect(Image(blob), args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as e:
        print('spot_level_tag94: ' + str(e), file=sys.stderr)
        raise SystemExit(1)
