#!/usr/bin/env python3
"""Collect static evidence for selected node 94 configuration sequence readers.

The input is authenticated before ELF parsing. The x86 records are restricted
byte contracts at selected addresses, not a general disassembler or emulator.
"""
import argparse
import bisect
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
TARGET = ROOT / 'artifacts/node/94/hl-node'

# Exact unwind-described bodies newly selected here. Earlier parent/child
# routines are call boundaries, not members of this list.
FUNCTIONS = (
    ('vector_drop', 0x13b42e0, 0x13b435c, '0d2b42644c6e2112057d6dffe56bd9bfe13761bcd0ca84ca9229616bc44e1f5d'),
    ('raw_byte_collector', 0x14c06a0, 0x14c08cd, '79d2e086a78d26238acf1932719742f0cc27466066b296a2dcd775d9732cd959'),
    ('sequence_collector', 0x14c08d0, 0x14c0aea, 'ad31983d9d4feb6010d5647ae428e3ec3c495cdd9f5870808210eb40411c973d'),
    ('expected_sequence', 0x14c3e90, 0x14c3ea9, '2c811cc13377c4bc9de06fd3b5d826734b52f3cfb3f28419317cad2f450ba0db'),
    ('slice_error_a', 0x14d0d30, 0x14d0da3, '17f3024a1b21a981463a289f15822f3334b4e1d7a0b6aa9ed9ef8f021342ebae'),
    ('extension_error', 0x14d11f0, 0x14d1259, '6e984a9d85f3760fc489fbf675084b653ed62eba72f68590ac05aa80f3ee81ee'),
    ('byte_element_error', 0x14d2180, 0x14d21f2, 'e76a56a90c1c2ce850b5d0b4f0ca7267bdb54f477778988e154411592395fb32'),
    ('map_error', 0x14d4b80, 0x14d4be9, 'c04873b438b640040b27022644f44a7fe9f5a6ed3fc33bce3d498ce3f0d1e625'),
    ('slice_error_b', 0x14d5c10, 0x14d5c83, 'e139e0342bd75da049a83384ca9561d2fb11af26b996aa8407f99f82812d3c1f'),
)

# Each row is a fixed byte window; windows can contain multiple instructions.
# Prefix 'parent_' means context inside an earlier, non-selected routine.
PINS = (
    ('raw_bound', 0x14c06c2, '4829e8483daaaa000041bcaaaa00004c0f42e0'),
    ('raw_allocate_size', 0x14c06e4, 'c1e0034c8d3c40'),
    ('raw_empty', 0x14c0707, 'b8080000004531e4'),
    ('raw_loop_entry', 0x14c0721, '4885ed0f848f000000483b6c2420'),
    ('raw_byte', 0x14c0775, '0fb67500'),
    ('raw_tag', 0x14c0783, '0fb64424283c09'),
    ('raw_niche', 0x14c0791, '4c89e048f7d8'),
    ('raw_append', 0x14c0743, '488b4424084b8d0c764c8924c84c896cc80848895cc81049ffc64c89742410'),
    ('raw_success', 0x14c07b9, '488b4424104c8b6424184989442418488b04244989442408488b442408498944241041c6042409'),
    ('raw_error_copy', 0x14c07f2, '8b4c24298b54242c4c8b642418418954240441894c24010f10442430488b4c244041880424410f1144240849894c2418'),
    ('raw_free_stride', 0x14c0840, '4983c61848ffcb7413498b76f84885f674ee498b3e31d241ffd7eb'),
    ('raw_buffer_size', 0x14c0869, '488b7c240848c1e003488d344031d2'),
    ('seq_count_clamp', 0x14c08e3, '8b5e0881fbaaaa000041bcaaaa0000440f42e385db'),
    ('seq_alloc_size', 0x14c0903, '428d04e5000000004c8d3c40'),
    ('seq_decrement', 0x14c093b, 'ffcb'),
    ('seq_remaining', 0x14c0969, '895808'),
    ('seq_flag', 0x14c0974, 'ba01000000'),
    ('seq_tag', 0x14c097e, '0fb64424283c09'),
    ('seq_niche', 0x14c0990, '4889e848f7d8'),
    ('seq_append', 0x14c0940, '488b4424084b8d0c6448892cc84c896cc8084c8974c81049ffc44c89642410'),
    ('seq_empty', 0x14c09b8, '48c704240000000048c74424080800000048c744241000000000'),
    ('seq_publish', 0x14c09d2, '488b4424104c8b6424184989442418488b04244989442408488b442408498944241041c6042409'),
    ('seq_error_copy', 0x14c0a0b, '8b4c24298b54242c4c8b642418418954240441894c24010f10442430488b4c244049894c241841880424410f11442408'),
    ('seq_free_stride', 0x14c0a60, '4983c61848ffcb7413498b76f84885f674ee498b3e31d241ffd7eb'),
    ('seq_buffer_size', 0x14c0a89, '488b7c240848c1e003488d344031d2'),
    ('drop_stride', 0x13b4310, '4983c41849ffcf'),
    ('drop_size', 0x13b4336, '48c1e003488d3440'),
    ('wrapper_byte_kind', 0x14d2188, '400fb6c64889442440c644243801'),
    ('wrapper_byte_expect', 0x14d21a0, '488d05a9cf1904'),
    ('wrapper_byte_template', 0x14d21d8, '488d355ff7d2fe'),
    ('wrapper_map_kind', 0x14d4b88, 'c64424380b'),
    ('wrapper_map_expect', 0x14d4b97, '488d05d2a31904'),
    ('wrapper_extension_kind', 0x14d11f8, 'c644243809'),
    ('wrapper_slice_one_kind', 0x14d0d42, 'c644241806'),
    ('wrapper_slice_two_kind', 0x14d5c22, 'c644241805'),
    ('expected_seq_literal', 0x14c3e9b, '488d357386d5feba0a000000'),
    ('parent_state_dispatch', 0x13b563c, '440fb64e200fb64e21450fb6c1c6462001488d058ca9e5fe4e6314804901c241ffe2'),
    ('parent_fresh_marker', 0x13b57f7, '4c8b46184d85c00f848e010000488b461049ffc80fb60848ffc0488946104c89461884c90f8897010000'),
    ('parent_high_marker', 0x13b59b8, '41b1e080f9df0f879afcffff80f9900f83f6000000'),
    ('parent_high_routes', 0x13b5ac3, '80f9a00f834d01000080e10f'),
    ('parent_extended_gate', 0x13b5c19, '80f9c0736e'),
    ('parent_c5_len', 0x13b56c1, '4983f8020f82e40100004983c0fe0fb70866c1c1084883c002488946104c8946180fb7c9eb42'),
    ('parent_c6_len', 0x13b570b, '4983f8040f829a0100004983c0fc8b084883c0040fc9488946104c894618'),
    ('parent_depth_error', 0x13b5ce5, 'c60708'),
    ('parent_depth_underflow', 0x13b5d5d, '488d3d4c0c2b04ff15e6833b04'),
    ('parent_byte_bounds', 0x13b5729, '89c94929c80f82100200004c8d0c084c894e104c894618'),
    ('parent_mode', 0x13b5740, '84d20f8588040000'),
    ('parent_byte_vector', 0x13b575b, '488d7424204889fbe838af10004889d8'),
    ('parent_array_depth', 0x13b5ad2, '0fb746226685c00f847e02000066ffc8668946220f84f9010000'),
    ('parent_array_handoff', 0x13b5afa, '899c2488000000488d7c2420488db42480000000e8bdad1000'),
    ('parent_array_tag', 0x13b5b13, '0fb64424203c09753b'),
    ('parent_error_return', 0x13b5b82, '4c89f0e961010000'),
    ('parent_raw_return', 0x13b576b, 'e97b050000'),
    ('parent_epilogue', 0x13b5ceb, '4881c4900000005b415e415fc3'),
    ('parent_array_remaining', 0x13b5b30, '8b84248800000085c0744f29c3'),
    ('parent_array_drop', 0x13b5b3b, '29c30f8236020000c6042404895c2404488d7c2440e88be7ffffeb4b0f'),
    ('parent_array_restore', 0x13b5ba2, '4c89f7410fb747226683f8ff0f84b6010000ffc06641894722'),
    ('parent_c4_len', 0x13b56ef, '4d85c00f84ba01000049ffc80fb60848ffc0'),
    ('parent_truncated', 0x13b58af, '4c01c04889461048c7461800000000c60701'),
    ('parent_payload_fail', 0x13b5944, 'c6070148b8030000002500000048894708e9'),
    ('parent_fresh_ext', 0x13b5c8c, '440fb6c94181c140ffffff4c8d150ea7e5fe4f631c8a4d01d34189c941ffe3'),
    ('parent_map_reject', 0x13b5a00, 'e87bf111000fb64424203c090f8545010000'),
    ('parent_ext_reject', 0x13b5d16, 'e8d5b41100410fb74e226683f9ff7462ffc16641894e22'),
    ('parent_array_success', 0x13b5b8a, '488b44245048894424180f284424400f11442408c6042409'),
    ('parent_propagation', 0x13b5b57, '0f104424210f104c24300f114c246f0f294424600f1044246f410f1146100f28442460410f114601418806'),
)

# Curated conditional transfers in the collectors, vector drop and
# the prior parent's fresh-marker, length and counted-sequence handoffs.
BRANCHES = (
    (0x14c06e2,0x14c0707),(0x14c06f7,0x14c070f),(0x14c0724,0x14c07b9),
    (0x14c072f,0x14c07b9),(0x14c076a,0x14c07b9),(0x14c076f,0x14c0883),
    (0x14c078a,0x14c07f2),(0x14c0797,0x14c07b9),(0x14c07ac,0x14c0740),
    (0x14c082a,0x14c085c),(0x14c0847,0x14c085c),(0x14c0850,0x14c0840),
    (0x14c0863,0x14c07e0),(0x14c0898,0x14c08bd),
    (0x14c08fd,0x14c09b8),(0x14c091b,0x14c0aa3),(0x14c0962,0x14c09d2),
    (0x14c0985,0x14c0a0b),(0x14c0996,0x14c09d2),(0x14c09ab,0x14c0940),
    (0x14c0a43,0x14c0a7c),(0x14c0a67,0x14c0a7c),(0x14c0a70,0x14c0a60),
    (0x14c0a83,0x14c09f9),(0x14c0ab7,0x14c0ada),
    (0x13b42f7,0x13b432e),(0x13b4317,0x13b432e),(0x13b4321,0x13b4310),
    (0x13b4334,0x13b4352),
    (0x13b57fe,0x13b5992),(0x13b581b,0x13b59b8),
    (0x13b59be,0x13b565e),(0x13b59c7,0x13b5ac3),
    (0x13b5ac6,0x13b5c19),(0x13b5c1c,0x13b5c8c),
    (0x13b56c5,0x13b58af),(0x13b56f2,0x13b58b2),
    (0x13b570f,0x13b58af),(0x13b572e,0x13b5944),
    (0x13b5742,0x13b5bd0),(0x13b5ad9,0x13b5d5d),
    (0x13b5ae6,0x13b5ce5),(0x13b5b1a,0x13b5b57),
    (0x13b5b39,0x13b5b8a),(0x13b5b3d,0x13b5d79),
    (0x13b5bae,0x13b5d6a),
)

# Selected call and tail-transfer sites, including selected cross-boundaries.
# For a register-indirect transfer the third field is None.
CALLS = (
    (0x14c06ee,0x576dfd8),(0x14c0701,0x576dfb8),(0x14c077e,0x14d2180),
    (0x14c07b1,0x576ea38),(0x14c0857,None),(0x14c0878,0x576e010),
    (0x14c088a,0x576e118),(0x14c08a2,0x576e010),(0x14c08ab,0x14c95b0),
    (0x14c08b3,0x5660110),(0x14c08c0,0x14c95b0),(0x14c08c8,0x5660110),
    (0x14c0912,0x576dfd8),(0x14c0979,0x13bdcd0),(0x14c09b0,0x576ea38),
    (0x14c0a77,None),(0x14c0a98,0x576e010),(0x14c0aab,0x576dfb8),
    (0x14c0ac1,0x576e010),(0x14c0aca,0x14c95b0),(0x14c0ad2,0x5660110),
    (0x14c0add,0x14c95b0),(0x14c0ae5,0x5660110),
    (0x13b4329,None),(0x13b434c,0x576e010),(0x14c3ea7,None),
    (0x14d0d95,0x13b5360),(0x14d124b,0x13b5360),(0x14d21e4,0x13b5360),
    (0x14d4bdb,0x13b5360),(0x14d5c75,0x13b5360),
    (0x13b5763,0x14c06a0),(0x13b5b0e,0x14c08d0),(0x13b5b50,0x13b42e0),
    (0x13b5a3b,0x13b42e0),(0x13b5a00,0x14d4b80),
    (0x13b5bd9,0x14d0d30),(0x13b5a7a,0x14d0d30),
    (0x13b5ab6,0x14d5c10),(0x13b5d16,0x14d11f0),
)

FIELDS = (
    (0x21bba7, b'etherscan_keys', 0x13c836f, 0x13acd78),
    (0x21bbb5, b'etherscan_v2_keys', 0x13c7ff3, 0x13ad564),
    (0x21bbdc, b'ip_backup_keys', 0x13c82e1, 0x13ad3f6),
    (0x21bbea, b'ip_info_backup_keys', 0x13c7f3e, 0x13acfdf),
    (0x21bbfd, b'zip_and_upload_skip_cp', 0x13c7bcc, 0x13acacf),
)
TABLES = (
    ('cached_class',0x20ffe0,225,'0203335b306a62fe84a4c79b46bda339e502ab01f28e0c6b49b41bef953507ca'),
    ('cached_extended',0x210364,18,'9d9a60aa136dcff5fed813818b165645ad280542815fa379956f03d21f1b022e'),
    ('fresh_c0_df',0x2103ac,32,'bc19e2e7b2bf7237f10c5e49ab07fab78dbad9de1d34565729e0ee4f68029370'),
)
RELOCATIONS = (
    (0x566ef88,0x14c3e90,'sequence_expected_method'),
    (0x566f168,0x14c3f10,'string_expected_method_boundary'),
    (0x576dfb8,0x1346068,'allocation_failure_boundary'),
    (0x576dfd8,0x54c06b0,'allocation_boundary'),
    (0x576e010,0x54c8cb0,'deallocation_boundary'),
    (0x576e758,0x4eb8e30,'unexpected_kind_formatter_boundary'),
    (0x576e928,0x577b288,'prior_static_config_cell'),
    (0x576ea38,0x4f04bb0,'vector_growth_boundary'),
    (0x576eb70,0x577a898,'prior_config_cell'),
)
# The descriptor kind and both RIP-relative LEAs are byte-derived below.
# Function addresses are selected FDEs, not inferred vtable/function extents.
ERROR_DESCRIPTORS = (
    ('slice_a',0x14d0d30,0x14d0d42,6,0x14d0d51,0x566ef70,0x14d0d89),
    ('slice_b',0x14d5c10,0x14d5c22,5,0x14d5c31,0x566ef70,0x14d5c69),
    ('extension',0x14d11f0,0x14d11f8,9,0x14d1207,0x566ef70,0x14d123f),
    ('byte_element',0x14d2180,0x14d2191,1,0x14d21a0,0x566f150,0x14d21d8),
    ('map',0x14d4b80,0x14d4b88,11,0x14d4b97,0x566ef70,0x14d4bcf),
)
LSDA_DIGESTS = {
    0x14c06a0: '0cebe0a343fc57dfdffb003e66b508cb95bc095ca1ed4663d70bae288ab99304',
    0x14c08d0: '79b952d86a87a254cb58f7f0906ee1744f58a3d738ebdfb1ac2f895a968bddf0',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_identity(data, expected=DIGEST):
    if len(data) != SIZE or sha(data) != expected:
        raise ValueError('node 94 size or SHA-256 mismatch')


class View:
    def __init__(self, data, section_rows=None):
        self.data = data
        self.sections = sections(data) if section_rows is None else section_rows

    def offset(self, address, size, executable=False):
        if type(address) is not int or type(size) is not int or address < 0 or size <= 0 or address + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                and (not executable or s['flags'] & 4) and s['size']
                and s['address'] <= address and address + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('range is not uniquely allocated and file backed')
        off = hits[0]['offset'] + address - hits[0]['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('truncated mapped range')
        return off

    def read(self, address, size, executable=False):
        off = self.offset(address, size, executable)
        return bytes(self.data[off:off + size])


def require(view, address, expected, executable=False):
    raw = view.read(address, len(expected), executable)
    if raw != expected:
        raise ValueError('byte contract changed at ' + hex(address))
    return raw


def select_functions(view, fdes):
    result = []
    for role, start, end, digest in FUNCTIONS:
        found = [f for f in fdes if f['start'] == start]
        if len(found) != 1 or found[0]['end'] != end:
            raise ValueError('selected FDE missing, duplicated or changed')
        raw = view.read(start, end - start, executable=True)
        if sha(raw) != digest:
            raise ValueError('selected body digest mismatch: ' + role)
        result.append(dict(role=role, **found[0], file_offset=view.offset(start, len(raw), True),
                           size=len(raw), sha256=sha(raw), body=raw.hex()))
    return result


def branch(view, address, expected):
    first = view.read(address, 2, True)
    if first[0] in (0x70,0x72,0x73,0x74,0x75,0x76,0x77,0x78):
        raw = first
        target = address + 2 + struct.unpack('<b', raw[1:2])[0]
        opcode = raw[0]
    elif first[0] == 0x0f and first[1] in (0x80,0x82,0x83,0x84,0x85,0x86,0x87,0x88):
        raw = view.read(address, 6, True)
        target = address + 6 + struct.unpack('<i', raw[2:6])[0]
        opcode = raw[1] - 0x10
    else:
        raise ValueError('unsupported conditional branch encoding')
    if target != expected:
        raise ValueError('conditional branch target changed')
    condition = {0x70:'overflow',0x72:'below',0x73:'not_below',0x74:'equal',
                 0x75:'not_equal',0x76:'below_or_equal',0x77:'above',0x78:'sign'}[opcode]
    return (address, view.offset(address,len(raw),True), raw.hex(), condition, address+len(raw), target)


def transfer(view, address, expected):
    raw = view.read(address, 2, True)
    if raw[0] == 0xe8:
        raw = view.read(address,5,True)
        target = address + 5 + struct.unpack('<i', raw[1:])[0]
        kind = 'direct_call'
    elif raw in (b'\xff\x15', b'\xff\x25'):
        raw = view.read(address,6,True)
        target = address + 6 + struct.unpack('<i', raw[2:])[0]
        kind = 'rip_slot_call' if raw[1] == 0x15 else 'rip_slot_tail'
    elif raw == b'\xff\xe0':
        target, kind = None, 'register_tail'
    elif raw == b'\x41\xff':
        raw = view.read(address,3,True)
        if raw not in (b'\x41\xff\xd5', b'\x41\xff\xd7'):
            raise ValueError('unsupported register call')
        target, kind = None, 'register_call'
    else:
        raise ValueError('unsupported call encoding')
    if target != expected:
        raise ValueError('transfer target changed')
    return (address, view.offset(address,len(raw),True), raw.hex(), kind, target)


def relocs(view):
    wanted = {a:(target,label) for a,target,label in RELOCATIONS}
    result = {}
    for s in view.sections:
        if s['type'] != 4 or s['type'] == 8:
            continue
        if s['size'] % 24:
            raise ValueError('misaligned RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            address, info, addend = struct.unpack_from('<QQq', view.data, pos)
            if address not in wanted:
                continue
            target, label = wanted[address]
            if address in result or info != 8 or addend != target:
                raise ValueError('relocation contract mismatch')
            view.read(address,8)
            result[address] = (label,address,pos,info,addend)
    if set(result) != set(wanted):
        raise ValueError('missing relocation')
    return [result[a] for a in sorted(result)]


def rip_lea(view, address, prefix):
    raw=view.read(address,7,True)
    if raw[:3] != prefix:
        raise ValueError('unexpected descriptor LEA')
    target=address+7+struct.unpack('<i',raw[3:7])[0]
    view.read(target,1)
    return raw,target


def error_descriptors(view, relocation_rows):
    methods={row[1]:row[-1] for row in relocation_rows}
    selected={row[1] for row in FUNCTIONS}
    rows=[]
    for role,function,kind_va,kind,lea_va,expected_base,template_va in ERROR_DESCRIPTORS:
        raw=view.read(kind_va,5,True)
        if function not in selected or raw[:3]!=b'\xc6\x44\x24' or raw[3] not in (0x18,0x38) or raw[4]!=kind:
            raise ValueError('descriptor kind contract changed')
        lea,base=rip_lea(view,lea_va,b'\x48\x8d\x05')
        fmt,template=rip_lea(view,template_va,b'\x48\x8d\x35')
        slot=base+24
        if base!=expected_base or template!=0x20193e or slot not in methods:
            raise ValueError('descriptor binding changed')
        method=methods[slot]
        if method != (0x14c3f10 if role=='byte_element' else 0x14c3e90):
            raise ValueError('descriptor method changed')
        rows.append((role,function,kind_va,view.offset(kind_va,5,True),raw.hex(),raw[4],
                     lea_va,view.offset(lea_va,7,True),lea.hex(),base,slot,method,
                     template_va,view.offset(template_va,7,True),fmt.hex(),template))
    return rows


def fields(view):
    result = []
    for literal_va, spelling, leaf, expected_arm in FIELDS:
        literal = require(view, literal_va, spelling)
        leaf_raw = view.read(leaf,12,True)
        if leaf_raw[:3] != b'\xc6\x40\x08' or leaf_raw[4:] != bytes.fromhex('48c70000000000c3'):
            raise ValueError('unexpected field-tag leaf')
        tag = leaf_raw[3]
        if not 0x16 <= tag < 0x2e:
            raise ValueError('field tag outside known dispatcher')
        slot = 0x20faa0 + 4*(tag-0x16)
        word = view.read(slot,4)
        arm = 0x20faa0 + struct.unpack('<i',word)[0]
        if arm != expected_arm:
            raise ValueError('field dispatcher changed')
        require(view,arm+0x1d,b'\x31\xd2',True)
        call = transfer(view,arm+0x1f,0x13b5630)
        require(view,arm+0x24,bytes.fromhex('0fb68424f00200003c09'),True)
        test_branch = branch(view,arm+0x2e,0x13b0144)
        result.append((spelling.decode('ascii'), literal_va, view.offset(literal_va,len(literal)),
                       len(literal), leaf, leaf_raw.hex(),tag,slot,word.hex(),arm,
                       call[0],call[2],test_branch[-1]))
    if len({r[6] for r in result}) != len(result):
        raise ValueError('duplicate selected field tag')
    return result


def tables(view, parent):
    rows = []
    for name, base, count, digest in TABLES:
        raw = view.read(base,count*4)
        if sha(raw) != digest:
            raise ValueError('dispatch table digest mismatch: '+name)
        for i in range(count):
            cell = raw[4*i:4*i+4]
            target = base + struct.unpack('<i',cell)[0]
            if not parent['start'] <= target < parent['end']:
                raise ValueError('dispatch target outside prior reader extent')
            rows.append((name,i,base+4*i,view.offset(base+4*i,4),cell.hex(),target))
    by = {(n,i):t for n,i,_,_,_,t in rows}
    if (by['fresh_c0_df',4],by['fresh_c0_df',5],by['fresh_c0_df',6],
        by['cached_class',1],by['cached_class',0x90],by['cached_class',0xc4]) != (0x13b56ef,0x13b56c1,0x13b570b,0x13b57f7,0x13b5acf,0x13b56e7):
        raise ValueError('selected marker target mismatch')
    return rows


def exception_sites(view, fdes, selected):
    exception_section = [s for s in view.sections if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(exception_section) != 1:
        raise ValueError('exception table missing or ambiguous')
    sec = exception_section[0]
    all_lsda = sorted({f['lsda'] for f in fdes if f['lsda'] is not None})
    headers, rows = [], []
    for f in selected:
        if f['start'] not in LSDA_DIGESTS:
            if f['lsda'] is not None:
                raise ValueError('unexpected selected LSDA')
            continue
        va = f['lsda']
        i = bisect.bisect_right(all_lsda,va)
        if i == len(all_lsda):
            raise ValueError('missing LSDA upper bound')
        upper = all_lsda[i]
        if not sec['address'] <= va < upper <= sec['address']+sec['size']:
            raise ValueError('LSDA outside exception table')
        raw = view.read(va,upper-va)
        if sha(raw) != LSDA_DIGESTS[f['start']]:
            raise ValueError('LSDA bytes changed')
        if raw[:3] != b'\xff\xff\x01':
            raise ValueError('unsupported LSDA encoding')
        length,pos = uleb(raw,3,len(raw))
        end = pos+length
        if end > len(raw):
            raise ValueError('truncated LSDA call-site table')
        headers.append((f['role'],va,view.offset(va,len(raw)),upper,raw[:pos].hex(),length,sha(raw)))
        previous = 0
        while pos < end:
            begin = pos
            values = []
            for _ in range(4):
                x,pos = uleb(raw,pos,end)
                values.append(x)
            start,length,landing,action = values
            if length == 0 or start < previous or start+length > f['size']:
                raise ValueError('invalid LSDA call-site extent')
            if landing and landing >= f['size']:
                raise ValueError('invalid LSDA landing offset')
            rows.append((f['role'],va,va+begin,raw[begin:pos].hex(),f['start']+start,
                         f['start']+start+length, f['start']+landing if landing else None,action))
            previous = start+length
        if pos != end or any(raw[end:]):
            raise ValueError('unexpected LSDA trailing bytes')
    return headers,rows


def allocation_plan(count, limit=0xaaaa, stride=24):
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        raise ValueError('count outside modeled unsigned 32-bit range')
    if type(limit) is not int or type(stride) is not int or limit < 1 or stride < 1:
        raise ValueError('invalid allocation parameters')
    capacity = min(count,limit)
    return capacity,capacity*stride


def raw_probe(data, mode=0, limit=0xaaaa, stride=24):
    """Model only fresh c4/c5/c6 prefix + the selected raw collector.

    Assumes valid input slice, normal allocation and the previously documented
    tag-6 constructor contract. This is not target execution.
    """
    if not isinstance(data,bytes) or not data or type(mode) is not int or mode not in (0,1):
        raise ValueError('invalid raw probe')
    marker = data[0]
    widths = {0xc4:1,0xc5:2,0xc6:4}
    if marker not in widths:
        raise ValueError('marker outside raw probe')
    width = widths[marker]
    if len(data) < 1+width:
        return (1,len(data),0,0,'truncated_length')
    count = int.from_bytes(data[1:1+width],'big')
    pos = 1+width
    if len(data)-pos < count:
        return (1,pos,len(data)-pos,0,'truncated_payload')
    pos += count
    if mode:
        return (6,pos,len(data)-pos,0,'sequence_error_boundary')
    capacity,_ = allocation_plan(count,limit,stride)
    return (9 if count == 0 else 6,pos,len(data)-pos,capacity,
            'empty_vector' if count == 0 else 'first_byte_error_boundary')


def sequence_probe(count, depth, outcomes):
    """Model selected collector/parent transitions with abstract child outcomes."""
    if type(count) is not int or not 0 <= count <= 0xffffffff:
        raise ValueError('invalid element count')
    if type(depth) is not int or not 0 <= depth <= 0xffff:
        raise ValueError('invalid depth')
    if not isinstance(outcomes,tuple) or len(outcomes) > count or any(x not in ('ok','tag6','niche') for x in outcomes):
        raise ValueError('invalid child outcome sequence')
    if depth == 0:
        return ('underflow_boundary',None,0,count,0)
    if depth == 1:
        return ('depth_error',8,0,count,0)
    current_depth = depth-1
    if count == 0:
        return ('success',9,0,0,depth)
    inserted = 0
    for i,item in enumerate(outcomes):
        remaining = count-i-1
        if item == 'tag6':
            return ('child_error',6,inserted,remaining,current_depth)
        if item == 'niche':
            if remaining:
                return ('partial_drop',4,inserted,remaining,depth)
            return ('short_success',9,inserted,remaining,depth)
        inserted += 1
        if remaining == 0:
            return ('success',9,inserted,0,depth)
    return ('external_child_pending',None,inserted,count-len(outcomes),current_depth)


def sample_cases(limit=0xaaaa, stride=24):
    rows=[]
    for name,value,mode in (
        ('empty_c4','c400',0),('one_zero','c40100',0),('one_ascii','c40141',0),
        ('two_bytes','c4024142',0),('high_bit','c40180',0),('byte_ff','c401ff',0),
        ('truncated_c4_length','c4',0),
        ('truncated_c5_length','c500',0),('truncated_c6_length','c6000000',0),
        ('truncated_payload','c40241',0),('empty_c5','c50000',0),
        ('empty_c6','c600000000',0),('one_c5','c5000141',0),
        ('one_c6','c60000000141',0),('trailing_control','c400ff',0),
        ('alternate_mode_empty','c400',1),('alternate_mode_nonempty','c40141',1)):
        tag,pos,left,capacity,outcome=raw_probe(bytes.fromhex(value),mode,limit,stride)
        rows.append((name,value,mode,tag,pos,left,capacity,outcome))
    return rows


def sequence_cases():
    inputs=(('empty',0,2,()),('one_ok',1,2,('ok',)),('two_ok',2,2,('ok','ok')),
            ('first_error',2,2,('tag6',)),('second_error',2,2,('ok','tag6')),
            ('first_niche',2,2,('niche',)),('last_niche',2,2,('ok','niche')),
            ('one_niche',1,2,('niche',)),('child_pending',3,2,('ok',)),
            ('depth_zero',1,0,()),('depth_one',1,1,()),('depth_max',0,0xffff,()))
    return [(name,count,depth,','.join(outcomes),*sequence_probe(count,depth,outcomes))
            for name,count,depth,outcomes in inputs]


def collect(data, expected_digest=DIGEST):
    verify_identity(data,expected_digest)
    view = View(data)
    _, fdes = eh_frame_records(data,view.sections)
    selected = select_functions(view,fdes)
    parent = [f for f in fdes if f['start']==0x13b5630]
    if len(parent)!=1 or parent[0]['end']!=0x13b5df0:
        raise ValueError('prior boundary FDE changed')
    pins=[]
    for name,address,pattern in PINS:
        raw=require(view,address,bytes.fromhex(pattern),True)
        pins.append((name,address,view.offset(address,len(raw),True),len(raw),raw.hex()))
    branches=[branch(view,a,b) for a,b in BRANCHES]
    calls=[transfer(view,a,b) for a,b in CALLS]
    field_rows=fields(view)
    table_rows=tables(view,parent[0])
    reloc_rows=relocs(view)
    descriptors=error_descriptors(view,reloc_rows)
    lsda_headers,lsda_rows=exception_sites(view,fdes,selected)
    text=require(view,0x21c515,b'a sequence')
    template=require(view,0x20193e,bytes.fromhex('0e696e76616c696420747970653a20c00b2c20657870656374656420c000'))
    callback=view.read(0x14c3e9b,12,True)
    if callback[:3] != b'\x48\x8d\x35' or callback[7] != 0xba:
        raise ValueError('unexpected expected-type callback')
    literal_va=0x14c3e9b+7+struct.unpack('<i',callback[3:7])[0]
    literal_len=struct.unpack('<I',callback[8:12])[0]
    if literal_va!=0x21c515 or literal_len!=len(text):
        raise ValueError('expected-type literal binding changed')
    literals=[('expected_sequence',0x21c515,view.offset(0x21c515,len(text)),len(text),text.hex()),
              ('type_error_template',0x20193e,view.offset(0x20193e,len(template)),len(template),template.hex())]
    raw_limit=struct.unpack('<I',view.read(0x14c06c7,4,True))[0]
    seq_limit=struct.unpack('<I',view.read(0x14c08e8,4,True))[0]
    raw_form=view.read(0x14c06e4,7,True)
    seq_form=view.read(0x14c0903,12,True)
    raw_stride=(1 << raw_form[2])*(1+(1 << (raw_form[6] >> 6)))
    seq_stride=(1 << (seq_form[3] >> 6))*(1+(1 << (seq_form[11] >> 6)))
    if raw_limit!=seq_limit or raw_stride!=seq_stride or raw_limit!=0xaaaa or raw_stride!=24:
        raise ValueError('collector reservation operands disagree')
    reserves=[(n,*allocation_plan(n,raw_limit,raw_stride)) for n in (0,1,2,raw_limit-1,raw_limit,raw_limit+1,0xffffffff)]
    return dict(selected=selected,pins=pins,branches=branches,calls=calls,fields=field_rows,
                tables=table_rows,relocations=reloc_rows,descriptors=descriptors,lsda_headers=lsda_headers,lsda_sites=lsda_rows,
                literals=literals,raw_cases=sample_cases(raw_limit,raw_stride),sequence_cases=sequence_cases(),
                reservation_cases=reserves,reservation_limit=raw_limit,reservation_stride=raw_stride)


def hx(value):
    return '' if value is None else hex(value)


def write_tsv(out,name,header,rows):
    with (out/name).open('w',encoding='utf-8',newline='') as handle:
        writer=csv.writer(handle,delimiter='\t',lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def write_evidence(out,result):
    out.mkdir(parents=True,exist_ok=True)
    fs=result['selected']
    write_tsv(out,'functions.tsv',('role','start_va','end_va_exclusive','file_offset','bytes','fde_va','cie_va','lsda_va','sha256'),
              ((f['role'],hx(f['start']),hx(f['end']),hx(f['file_offset']),f['size'],hx(f['fde']),hx(f['cie']),hx(f['lsda']),f['sha256']) for f in fs))
    write_tsv(out,'bodies.tsv',('role','start_va','bytes_hex'),((f['role'],hx(f['start']),f['body']) for f in fs))
    write_tsv(out,'anchors.tsv',('label','va','file_offset','length','bytes_hex'),
              ((n,hx(a),hx(o),z,b) for n,a,o,z,b in result['pins']))
    write_tsv(out,'branches.tsv',('va','file_offset','bytes_hex','condition','fallthrough_va','taken_va'),
              ((hx(a),hx(o),b,c,hx(f),hx(t)) for a,o,b,c,f,t in result['branches']))
    write_tsv(out,'transfers.tsv',('site_va','file_offset','bytes_hex','kind','target_or_slot_va'),
              ((hx(a),hx(o),b,k,hx(t)) for a,o,b,k,t in result['calls']))
    write_tsv(out,'fields.tsv',('literal','literal_va','file_offset','length','leaf_va','leaf_bytes','tag','table_cell_va','relative_word','arm_va','call_va','call_bytes','non9_target_va'),
              ((name,hx(a),hx(o),z,hx(leaf),leafbytes,hx(tag),hx(slot),word,hx(arm),hx(call),callbytes,hx(error))
               for name,a,o,z,leaf,leafbytes,tag,slot,word,arm,call,callbytes,error in result['fields']))
    write_tsv(out,'marker-tables.tsv',('table','index','cell_va','file_offset','raw_le','target_va'),
              ((name,i,hx(a),hx(o),raw,hx(t)) for name,i,a,o,raw,t in result['tables']))
    write_tsv(out,'relocations.tsv',('label','slot_va','rela_file_offset','r_info','addend_va'),
              ((n,hx(a),hx(o),hx(info),hx(add)) for n,a,o,info,add in result['relocations']))
    write_tsv(out,'error-descriptors.tsv',('role','function_va','kind_va','kind_file_offset','kind_bytes','kind',
              'expected_lea_va','expected_lea_file_offset','expected_lea_bytes','expected_base_va','method_slot_va',
              'method_va','template_lea_va','template_lea_file_offset','template_lea_bytes','template_va'),
              ((n,hx(f),hx(k),hx(ko),kb,kind,hx(l),hx(lo),lb,hx(b),hx(s),hx(m),hx(t),hx(to),tb,hx(tv))
               for n,f,k,ko,kb,kind,l,lo,lb,b,s,m,t,to,tb,tv in result['descriptors']))
    write_tsv(out,'lsda-headers.tsv',('role','lsda_va','file_offset','upper_va','header_hex','table_bytes','sha256'),
              ((n,hx(a),hx(o),hx(u),b,z,h) for n,a,o,u,b,z,h in result['lsda_headers']))
    write_tsv(out,'lsda-sites.tsv',('role','lsda_va','record_va','bytes_hex','start_va','end_va_exclusive','landing_va','action'),
              ((n,hx(a),hx(r),b,hx(s),hx(e),hx(l),v) for n,a,r,b,s,e,l,v in result['lsda_sites']))
    write_tsv(out,'literals.tsv',('label','va','file_offset','length','bytes_hex'),
              ((n,hx(a),hx(o),z,b) for n,a,o,z,b in result['literals']))
    write_tsv(out,'raw-cases.tsv',('case','bytes_hex','mode','tag','consumed','remaining','initial_capacity','outcome'),result['raw_cases'])
    write_tsv(out,'sequence-cases.tsv',('case','declared_count','depth_before','abstract_child_outcomes','outcome','parent_tag','collected','remaining','depth_after'),result['sequence_cases'])
    write_tsv(out,'reserve-cases.tsv',('count','initial_capacity','initial_bytes'),result['reservation_cases'])
    summary={'artifact_sha256':DIGEST,'function_count':len(fs),'selected_bytes':sum(f['size'] for f in fs),
             'anchor_windows':len(result['pins']),'selected_conditional_branches':len(result['branches']),
             'selected_transfers':len(result['calls']),'field_handoffs':len(result['fields']),
             'marker_table_cells':len(result['tables']),'relocations':len(result['relocations']),
             'error_descriptors':len(result['descriptors']),
             'lsda_headers':len(result['lsda_headers']),'lsda_call_sites':len(result['lsda_sites']),
             'raw_cases':len(result['raw_cases']),'sequence_cases':len(result['sequence_cases']),
             'reservation_cases':len(result['reservation_cases']),
             'reservation_limit':result['reservation_limit'],'reservation_stride':result['reservation_stride'],
             'scope':'Selected FDE bodies, fixed byte windows, three bounded tables and static models; not target execution or whole-component coverage.'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    write_evidence(args.out,collect(TARGET.read_bytes()))

if __name__ == '__main__':
    main()
