#!/usr/bin/env python3
"""Pin what consumes the RE-015 merge delegate's entry tags 0/1/2/3
downstream of the exit reader in node 115.

Question (the recorded next question of the set-initializer packet
RE-015-node115-set-initializer / PR #2648, carried over unchanged
from the merge-delegate packet / PR #2615): what consumes the entry
tags 0/1/2/3 downstream of the exit reader (the 0x50-byte out struct
versus the {6, ...} form, and the destination object at
[rsp+0x278])?

The packet pins: (1) the exit reader 0x4749ab0 writes one of two
forms into its 0x50-byte out union -- when the delegate temp's entry
count (temp+0x60) is nonzero, out = {6, temp+0x50, temp+0x58,
temp+0x60} (discriminant 6 at +0x00, the entry vector's 24-byte
header at +0x08); when it is zero, temp[0..0x50] is copied verbatim;
(2) the reader's consumer 0x15a3b90 is the only reader caller and
branches on the out word at 0x15a5930: == 6 takes the assertion arm,
anything else copies 0x48 bytes (the +0x40 word, then out[0..0x40])
to the destination pointer saved at [rsp+0x278]; (3) the {6, ...}
form is a Rust Result Err: the assertion arm rebuilds the entry
vector header at [rsp+0xc0] and calls the unwrap-failed helper
0x1680c30 through slot 0x64df6a0 with the message "called
`Result::unwrap()` on an `Err` value" (0x468b3f, 43 bytes), the
error vtable 0x63ffe00 (drop 0x15ac470, size 24, align 8, Debug fmt
0x15b4420) and the Location 0x63ffb30 (base/src/log/handle.rs, line
167, column 60), and the helper forwards to the panic entry
0x1680e80, so the arm never returns (ud2 at 0x15a5c77); (4) no code
anywhere dispatches on an individual tag value: the tags are read
only through the reader's count gate, the consumer's discriminant
gate, the Err value's Debug formatting (vtable-dispatched, body
hash-pinned as a boundary), and the entry vector drop 0x15ac470,
which walks the entries at stride 0x20 and frees (entry+0x10,
entry+0x8) through the dealloc slot for every entry whose tag word
is <= 3 and whose +0x8 word is nonzero -- one uniform path for all
four tags, with the +0x18 word never loaded; the drop's only direct
call site in the binary is a landing pad of the consumer itself
(0x15a6042, on the header rebuilt at [rsp+0xc0]); (5) the
destination at [rsp+0x278] is the consumer's own rdi argument,
saved in the prologue (0x15a3ba1) and loaded only at the exit copy;
the consumer's sole direct caller, the wrapper 0x15a6510 (call site
0x15a6556), passes a 0x50-byte scratch buffer at its own
[rsp+0x48], and after the consumer returns it hands that scratch to
the registrar 0x474f6a0 through slot 0x64e1488 -- which forwards
the pointer unchanged to the refcount wrap constructor 0x4742470
(slot 0x64eaf70), whose payload constructor 0x4741180 is the first
code to read the struct's fields -- then stores a derived word in
the global cell behind slot 0x64eaf08, registers an 8-byte node,
and returns the wrap pointer (or 0, which the wrapper itself
unwrap-fails on); the wrapper stores the returned word at its own
out object +0x50.  Static evidence only; no captured code is
executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export, require

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'

OWNERS = {
    'exit_consumer': (
        0x15a3b90, 0x15a6509,
        '7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb'),
    'sole_caller_wrapper': (
        0x15a6510, 0x15a6674,
        'f89a14d39fba3e107a6f843895ed7bc4f718f8e462a3977f4b152265d2586f79'),
    'entry_vec_drop': (
        0x15ac470, 0x15ac4f0,
        'ab4363fc438acb9c0c21599a6f8b1f03c00f35427b75eb0f824e60527e7990a7'),
    'unwrap_failed': (
        0x1680c30, 0x1680c82,
        '2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a'),
    'panic_helper': (
        0x1680e80, 0x1680eac,
        '28fc3434a04bb9e49d5a0164306a5c31abf6bce26425d99d27031ac1c9beb2e3'),
    'registrar': (
        0x474f6a0, 0x474f7ff,
        'a26fb8c2033f2f6c6242755b86e5377a13bce19b1459d1761ddf9b56c8132c1e'),
    'arc_wrap_ctor': (
        0x4742470, 0x4742595,
        'fe91e95a97ff89e4df3823200e2973aeb23dd05dabf5737d48ce10a74798ef9c'),
}
BOUNDARIES = {
    'exit_reader': (
        0x4749ab0, 0x4749d71,
        '6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb'),
    'err_debug_fmt': (
        0x15b4420, 0x15b4545,
        'c64e11015ce72574b32d2da1bd6190eba3fc17807863d0c07bd4f1086ea3059f'),
    'payload_ctor': (
        0x4741180, 0x4741869,
        '8b5d5c27780fad807407377de2a30320bd15ad6a8902c960b9d0f5ccb4955e6a'),
    'registrar_lookup': (
        0x474fb00, 0x474fcab,
        'affacd8e00f02955fea148d136d213e52d070aeaffd068ee8755e4c0a47480f8'),
    'registrar_key': (
        0x47418d0, 0x474195a,
        '577008e25225f28944bdc6b56ae5cc42a5a35a33cfe202a64b89fa0dde35adbb'),
    'err_fmt_dispatch': (
        0x1687260, 0x1687270,
        '73a266c7c8ee86fa2addcc6aa746ed789ec1220b78c9de8360c56c6bd74aabbe'),
    'str_fmt': (
        0x1687590, 0x16875a3,
        'a787ddffe7b8a5b8fee9b747ab817d7d900e59e2148ab84a9055d174060b80d6'),
}

CONSUMER_PINS = {
    'dest_save': (0x15a3ba1, b'H\x89\xbc\x24\x78\x02\x00\x00'),
    'third_zero': (0x15a58f5, b'\x0f\x29\x84\x24\xc0\x00\x00\x00'),
    'third_cap': (0x15a58fd,
                  b'H\xc7\x84\x24\xd0\x00\x00\x00\x08\x00\x00\x00'),
    'out_arg': (0x15a5915, b'H\x8d\x7c\x24\x20'),
    'pair_arg': (0x15a591a, b'H\x8d\xb4\x24\x40\x02\x00\x00'),
    'third_arg': (0x15a5922, b'H\x8d\x94\x24\xc0\x00\x00\x00'),
    'disc_cmp': (0x15a5930, b'\x83\x7c\x24\x20\x06'),
    'disc_je': (0x15a5935, b'\x0f\x84\x51\x02\x00\x00'),
    'dest_load': (0x15a5940, b'H\x8b\x84\x24\x78\x02\x00\x00'),
    'dest_tail_word': (0x15a5948, b'\x0f\x11\x40\x40'),
    'assert_count_load': (0x15a5b8c, b'H\x8b\x44\x24\x38'),
    'assert_hdr_rebuild': (0x15a5b99, b'\x0f\x10\x44\x24\x28'),
    'assert_len': (0x15a5bc3, b'\xbe\x2b\x00\x00\x00'),
    'assert_ud2': (0x15a5c77, b'\x0f\x0b'),
    'pad_hdr_arg': (0x15a603a, b'H\x8d\xbc\x24\xc0\x00\x00\x00'),
}
CONSUMER_SLOT_CALLS = {
    'reader_call': (0x15a592a, 0x64e1480),
    'unwrap_call': (0x15a5bc8, 0x64df6a0),
    'unwrap_call_b': (0x15a59ef, 0x64df6a0),
    'unwrap_call_c': (0x15a5a72, 0x64df6a0),
}
CONSUMER_DIRECT_CALLS = {
    'pad_drop_call': (0x15a6042, 0x15ac470),
}
CONSUMER_LEAS = {
    'assert_msg': (0x15a5ba6, 0x468b3f),
    'assert_vtable': (0x15a5bad, 0x63ffe00),
    'assert_location': (0x15a5bb4, 0x63ffb30),
    'sibling_b_vtable': (0x15a59d4, 0x63ffde0),
    'sibling_b_location': (0x15a59db, 0x63ffca0),
    'sibling_c_vtable': (0x15a5a57, 0x63ffe40),
    'sibling_c_location': (0x15a5a5e, 0x63ffc58),
}
WRAPPER_PINS = {
    'id_load': (0x15a6540, b'\x8b\x6c\x24\x3c'),
    'id_test': (0x15a6544, b'\x85\xed'),
    'scratch_arg_consumer': (0x15a654c, b'H\x8d\x7c\x24\x48'),
    'record_arg': (0x15a6551, b'H\x89\xde'),
    'id_arg': (0x15a6554, b'\x89\xea'),
    'flag_load': (0x15a655b, b'D\x0f\xb6\x7b\x4c'),
    'scratch_arg_registrar': (0x15a6591, b'H\x8d\x7c\x24\x48'),
    'registrar_test': (0x15a659c, b'H\x85\xc0'),
    'copy_src40': (0x15a65a1, b'\x0f\x10\x43\x40'),
    'arc_store': (0x15a65e9, b'I\x89\x46\x50'),
    'id_store': (0x15a65ed, b'A\x89\xae\x80\x00\x00\x00'),
    'ret_ptr': (0x15a65f4, b'L\x89\xf0'),
}
WRAPPER_SLOT_CALLS = {
    0x15a6528: 0x64e0990, 0x15a653a: 0x64e0ab8,
    0x15a6596: 0x64e1488, 0x15a6618: 0x64df770,
    0x15a663f: 0x64df6a0, 0x15a665b: 0x64df4c0,
}
WRAPPER_DIRECT_CALLS = {
    'consumer_call': (0x15a6556, 0x15a3b90),
    'scratch_value_drop': (0x15a6654, 0x1553530),
    'record_drop': (0x15a6667, 0x15ac260),
}
DROP_PINS = {
    'buf_load': (0x15ac47c, b'H\x8b\x5f\x08'),
    'count_load': (0x15ac480, b'L\x8b\x7f\x10'),
    'dealloc_slot_load': (0x15ac48d, b'L\x8b\x2d\x0c\x30\xf3\x04'),
    'stride_step': (0x15ac4a0, b'I\x83\xc4\x20'),
    'tag_cmp': (0x15ac4a9, b'A\x83\x7c\x24\xf0\x03'),
    'tag_skip': (0x15ac4af, b'\x77\xef'),
    'size_load': (0x15ac4b1, b'I\x8b\x74\x24\xf8'),
    'size_test': (0x15ac4b6, b'H\x85\xf6'),
    'ptr_load': (0x15ac4bb, b'I\x8b\x3c\x24'),
    'dealloc_call': (0x15ac4c1, b'A\xff\xd5'),
    'cap_load': (0x15ac4c6, b'I\x8b\x36'),
    'cap_shl': (0x15ac4ce, b'H\xc1\xe6\x05'),
}
DROP_SLOT_JMPS = {
    'buffer_free': (0x15ac4e0, 0x64df4a0),
}
UNWRAP_PINS = {
    'msg_ptr_save': (0x1680c38, b'H\x89\x7d\xf0'),
    'msg_len_save': (0x1680c3c, b'H\x89\x75\xf8'),
    'err_ptr_save': (0x1680c40, b'H\x89\x55\xe0'),
    'err_meta_save': (0x1680c44, b'H\x89\x4d\xe8'),
}
UNWRAP_SLOT_CALLS = {
    'panic_call': (0x1680c7c, 0x64df6b8),
}
UNWRAP_LEAS = {
    'fmt_str': (0x1680c50, 0x1687590),
    'fmt_dyn': (0x1680c63, 0x1687260),
}
PANIC_PINS = {
    'pair_save': (0x1680e88, b'H\x89\x7d\xf0'),
    'kind_word': (0x1680e9c, b'f\xc7\x45\xe8\x01\x00'),
}
PANIC_SLOT_CALLS = {
    'runtime_call': (0x1680ea6, 0x64e1f30),
}
REGISTRAR_PINS = {
    'pair_store': (0x474f6b6, b'H\x89\x44\x24\x18'),
    'global_load': (0x474f71d, b'H\x8b\x05\xe4\xb7\xd9\x01'),
    'global_store': (0x474f724, b'L\x89\x30'),
    'refcount_inc': (0x474f727, b'\xf0H\xff\x03'),
    'node_alloc': (0x474f736, b'\xbf\x08\x00\x00\x00'),
    'zero_return': (0x474f770, b'\x31\xdb'),
}
REGISTRAR_SLOT_CALLS = {
    'forward_call': (0x474f6ad, 0x64eaf70),
    'weak_drop_call': (0x474f717, 0x64eaf50),
    'insert_call': (0x474f753, 0x64eaef0),
}
REGISTRAR_DIRECT_CALLS = {
    'lookup_call': (0x474f6c9, 0x474fb00),
    'key_call': (0x474f6e4, 0x47418d0),
}
ARC_PINS = {
    'input_save': (0x4742477, b'H\x89\xfe'),
    'box_count_init': (0x4742493, b'H\xc7\x04\x24\x01\x00\x00\x00'),
    'box_alloc': (0x47424a4, b'\xbf\x78\x00\x00\x00'),
    'wrap_alloc': (0x4742518, b'\xbf\x18\x00\x00\x00'),
}
ARC_DIRECT_CALLS = {
    'ctor_call': (0x474248e, 0x4741180),
}
ARC_LEAS = {
    'static_arg': (0x474247f, 0x6494c78),
}
CTOR_HEAD_PINS = {
    'field30_load': (0x47411a7, b'H\x8b\x6e\x30'),
    'field20_load': (0x47411b3, b'\x0f\x10\x46\x20'),
    'field48_load': (0x47411bf, b'H\x8b\x46\x48'),
    'field38_load': (0x47411cb, b'\x0f\x10\x46\x38'),
    'stride_shl': (0x47411df, b'H\xc1\xe5\x06'),
}
READER_PINS = {
    'delegate_out_arg': (0x4749ac4, b'H\x8d\x7c\x24\x70'),
    'count_load': (0x4749b1d, b'H\x8b\x84\x24\xd0\x00\x00\x00'),
    'count_test': (0x4749b25, b'H\x85\xc0'),
    'copy_branch': (0x4749b28, b'\x0f\x84\x96\x01\x00\x00'),
    'err_hdr_store': (0x4749b2e, b'H\x89\x73\x08'),
    'err_disc_store': (0x4749b3a, b'H\xc7\x03\x06\x00\x00\x00'),
}
READER_SLOT_CALLS = {
    'delegate_call': (0x4749ac9, 0x64eafd8),
}

ERR_VTABLE = 0x63ffe00
ERR_DROP = 0x15ac470
ERR_FMT = 0x15b4420
UNWRAP_MSG = 0x468b3f
UNWRAP_MSG_LEN = 43
UNWRAP_MSG_TEXT = 'called `Result::unwrap()` on an `Err` value'
LOCATION = 0x63ffb30
LOCATION_FILE = 0x43ab16
LOCATION_FILE_TEXT = 'base/src/log/handle.rs'
SIBLING_VTABLES = {
    'unwrap_site_b': {'vtable': 0x63ffde0, 'drop': 0x15ab120,
                      'size': 8, 'fmt': 0x1457040},
    'unwrap_site_c': {'vtable': 0x63ffe40, 'drop': 0x15ab660,
                      'size': 8, 'fmt': 0x5ca5610},
}
DEST_SLOT_PATTERN = b'\x24\x78\x02\x00\x00'


def read(data, va, n):
    for s in sections(data):
        if s['type'] != 8 and s['address'] <= va < s['address'] + s['size']:
            off = s['offset'] + va - s['address']
            if off + n > s['offset'] + s['size']:
                break
            return off, data[off:off + n]
    raise ValueError(f'unmapped {va:#x}')


def _pin(data, site, expected, label):
    if read(data, site, len(expected))[1] != expected:
        raise ValueError(f'{label} changed')


def _pins(data, table, role):
    for label, (site, expected) in table.items():
        _pin(data, site, expected, f'{role} {label}')


def _slot_call(data, site, slot, label):
    raw = read(data, site, 6)[1]
    require(raw[:2] in (b'\xff\x15', b'\xff%'),
            f'{label} is not a slot call')
    disp = struct.unpack('<i', raw[2:])[0]
    require(site + 6 + disp == slot, f'{label} slot changed')


def _slot_calls(data, table, role):
    for label, (site, slot) in table.items():
        _slot_call(data, site, slot, f'{role} {label}')


def _direct_call(data, site, target, label):
    raw = read(data, site, 5)[1]
    require(raw[:1] == b'\xe8', f'{label} is not a direct call')
    rel = struct.unpack('<i', raw[1:])[0]
    require(site + 5 + rel == target, f'{label} target changed')


def _direct_calls(data, table, role):
    for label, (site, target) in table.items():
        _direct_call(data, site, target, f'{role} {label}')


def _lea(data, site, target, label):
    raw = read(data, site, 7)[1]
    require(raw[2] == 0x3d or raw[2] in (0x05, 0x0d, 0x15, 0x1d, 0x25,
                                        0x2d, 0x35, 0x3d),
            f'{label} is not a lea')
    disp = struct.unpack('<i', raw[3:])[0]
    require(site + 7 + disp == target, f'{label} target changed')


def _leas(data, table, role):
    for label, (site, target) in table.items():
        _lea(data, site, target, f'{role} {label}')


def _relocations(data):
    s = next(s for s in sections(data) if s['name'] == '.rela.dyn')
    out = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        offset, info, addend = struct.unpack_from('<QQq', data, off)
        out[offset] = {'type': info & 0xffffffff,
                       'symbol': info >> 32, 'addend': addend}
    return out


def _dynsym_name(data, index):
    ds = next(s for s in sections(data) if s['name'] == '.dynsym')
    dstr = next(s for s in sections(data) if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, ds['offset'] + index * 24)[0]
    start = dstr['offset'] + name_off
    return data[start:data.index(b'\0', start)].decode()


def slot_bindings(data):
    rel = _relocations(data)
    wanted = {
        'unwrap_failed': 0x64df6a0, 'panic_entry': 0x64df6b8,
        'exit_reader': 0x64e1480, 'registrar': 0x64e1488,
        'merge_delegate': 0x64eafd8, 'arc_wrap': 0x64eaf70,
        'dealloc': 0x64df4a0, 'cleanup': 0x64df4c0,
        'assert_fail': 0x64df770, 'global_cell': 0x64eaf08,
        'registry_insert': 0x64eaef0, 'alloc': 0x64df480,
        'alloc_fail': 0x64df490, 'panic_runtime': 0x64e1f30,
        'weak_drop': 0x64eaf50,
    }
    out = {}
    for name, slot in wanted.items():
        entry = rel[slot]
        row = {'slot': hex(slot), 'type': entry['type'],
               'addend': hex(entry['addend'])}
        if entry['type'] == 6:
            row['symbol'] = _dynsym_name(data, entry['symbol'])
        out[name] = row
    return out


EXPECTED_BINDINGS = {
    'unwrap_failed': '0x1680c30', 'panic_entry': '0x1680e80',
    'exit_reader': '0x4749ab0', 'registrar': '0x474f6a0',
    'merge_delegate': '0x4748500', 'arc_wrap': '0x4742470',
    'dealloc': '0x635de30', 'cleanup': '0x1680cab',
    'assert_fail': '0x1680bd0', 'global_cell': '0x64ffef8',
    'registry_insert': '0x47359e0', 'alloc': '0x6355830',
    'alloc_fail': '0x141e251', 'panic_runtime': '0x5c826c0',
    'weak_drop': '0x474b3f0',
}


def vtable_row(data, rel, va):
    drop = rel[va]['addend']
    size = struct.unpack('<Q', read(data, va + 8, 8)[1])[0]
    align = struct.unpack('<Q', read(data, va + 0x10, 8)[1])[0]
    fmt = rel[va + 0x18]['addend']
    return {'address': hex(va), 'drop': hex(drop), 'size': size,
            'align': align, 'debug_fmt': hex(fmt)}


def err_facts(data):
    rel = _relocations(data)
    vt = vtable_row(data, rel, ERR_VTABLE)
    if vt['drop'] != hex(ERR_DROP) or vt['size'] != 24 \
            or vt['align'] != 8 or vt['debug_fmt'] != hex(ERR_FMT):
        raise ValueError('err vtable changed')
    msg = read(data, UNWRAP_MSG, UNWRAP_MSG_LEN)[1]
    if msg.decode() != UNWRAP_MSG_TEXT:
        raise ValueError('unwrap message changed')
    siblings = {}
    for role, want in SIBLING_VTABLES.items():
        row = vtable_row(data, rel, want['vtable'])
        if row['drop'] != hex(want['drop']) \
                or row['size'] != want['size'] \
                or row['debug_fmt'] != hex(want['fmt']):
            raise ValueError(f'{role} vtable changed')
        siblings[role] = row
    file_ptr = rel[LOCATION]['addend']
    length = struct.unpack('<Q', read(data, LOCATION + 8, 8)[1])[0]
    line = struct.unpack('<I', read(data, LOCATION + 0x10, 4)[1])[0]
    column = struct.unpack('<I', read(data, LOCATION + 0x14, 4)[1])[0]
    file_text = read(data, LOCATION_FILE, length)[1].decode()
    if file_ptr != LOCATION_FILE or length != 22 or line != 167 \
            or column != 60 or file_text != LOCATION_FILE_TEXT:
        raise ValueError('unwrap location changed')
    return {
        'err_vtable': vt,
        'sibling_unwrap_vtables': siblings,
        'unwrap_message': {'address': hex(UNWRAP_MSG),
                           'length': UNWRAP_MSG_LEN,
                           'text': UNWRAP_MSG_TEXT},
        'unwrap_location': {'address': hex(LOCATION),
                            'file': file_text,
                            'file_va': hex(LOCATION_FILE),
                            'length': length, 'line': line,
                            'column': column},
    }


def direct_call_census(data, targets):
    out = {t: [] for t in targets}
    for s in sections(data):
        if not (s['flags'] & 4) or s['type'] == 8 or not s['size']:
            continue
        base, raw = s['address'], data[s['offset']:s['offset'] + s['size']]
        for opcode in (b'\xe8', b'\xe9'):
            i = raw.find(opcode)
            while i != -1:
                if i + 5 <= len(raw):
                    rel = struct.unpack_from('<i', raw, i + 1)[0]
                    tgt = base + i + 5 + rel
                    if tgt in out:
                        out[tgt].append(base + i)
                i = raw.find(opcode, i + 1)
    return {hex(t): [hex(x) for x in sorted(v)] for t, v in out.items()}


def body_slot_calls(data, start, end):
    _, raw = read(data, start, end - start)
    calls = {}
    i = raw.find(b'\xff\x15')
    while i != -1:
        if i + 6 <= len(raw):
            disp = struct.unpack_from('<i', raw, i + 2)[0]
            calls[start + i] = start + i + 6 + disp
        i = raw.find(b'\xff\x15', i + 1)
    return calls


def wrapper_census(data):
    w = OWNERS['sole_caller_wrapper']
    calls = body_slot_calls(data, w[0], w[1])
    if calls != WRAPPER_SLOT_CALLS:
        raise ValueError('wrapper slot-call census changed')
    return {'slot_calls': {hex(k): hex(v) for k, v in
                           sorted(calls.items())}}


def dest_slot_census(data):
    c = OWNERS['exit_consumer']
    _, raw = read(data, c[0], c[1] - c[0])
    hits = []
    i = raw.find(DEST_SLOT_PATTERN)
    while i != -1:
        hits.append(c[0] + i - 3)
        i = raw.find(DEST_SLOT_PATTERN, i + 1)
    if hits != [0x15a3ba1, 0x15a5940]:
        raise ValueError('consumer [rsp+0x278] census changed')
    return {'access_sites': [hex(h) for h in hits],
            'roles': ['prologue save of rdi', 'exit copy load']}


def analyze(data):
    bindings = slot_bindings(data)
    for name, want in EXPECTED_BINDINGS.items():
        if bindings[name]['addend'] != want:
            raise ValueError(f'{name} slot binding changed')
    _pins(data, CONSUMER_PINS, 'exit_consumer')
    _slot_calls(data, CONSUMER_SLOT_CALLS, 'exit_consumer')
    _direct_calls(data, CONSUMER_DIRECT_CALLS, 'exit_consumer')
    _leas(data, CONSUMER_LEAS, 'exit_consumer')
    _pins(data, WRAPPER_PINS, 'sole_caller_wrapper')
    _direct_calls(data, WRAPPER_DIRECT_CALLS, 'sole_caller_wrapper')
    _pins(data, DROP_PINS, 'entry_vec_drop')
    for label, (site, slot) in DROP_SLOT_JMPS.items():
        _slot_call(data, site, slot, f'entry_vec_drop {label}')
    _pins(data, UNWRAP_PINS, 'unwrap_failed')
    _slot_calls(data, UNWRAP_SLOT_CALLS, 'unwrap_failed')
    _leas(data, UNWRAP_LEAS, 'unwrap_failed')
    _pins(data, PANIC_PINS, 'panic_helper')
    _slot_calls(data, PANIC_SLOT_CALLS, 'panic_helper')
    _pins(data, REGISTRAR_PINS, 'registrar')
    _slot_calls(data, REGISTRAR_SLOT_CALLS, 'registrar')
    _direct_calls(data, REGISTRAR_DIRECT_CALLS, 'registrar')
    _pins(data, ARC_PINS, 'arc_wrap_ctor')
    _direct_calls(data, ARC_DIRECT_CALLS, 'arc_wrap_ctor')
    _leas(data, ARC_LEAS, 'arc_wrap_ctor')
    _pins(data, CTOR_HEAD_PINS, 'payload_ctor')
    _pins(data, READER_PINS, 'exit_reader')
    _slot_calls(data, READER_SLOT_CALLS, 'exit_reader')
    facts = err_facts(data)
    census = direct_call_census(
        data, (0x15a3b90, 0x15ac470, 0x15b4420))
    if census['0x15a3b90'] != ['0x15a6556']:
        raise ValueError('consumer caller census changed')
    if census['0x15ac470'] != ['0x15a6042']:
        raise ValueError('entry vec drop call census changed')
    if census['0x15b4420'] != []:
        raise ValueError('err debug fmt gained a direct caller')
    wrap = wrapper_census(data)
    dest = dest_slot_census(data)
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}

    def frame_records(a, b, sha, role):
        if (a, b) not in fdes:
            raise ValueError(f'{role} scope FDE changed')
        offset, raw = read(data, a, b - a)
        digest = hashlib.sha256(raw).hexdigest()
        if sha is not None and digest != sha:
            raise ValueError(f'{role} body changed')
        records = {}
        for kind in ['fde', 'cie']:
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        return {'role': role, 'start': hex(a), 'end': hex(b),
                'file_offset': hex(offset), 'bytes': b - a,
                'sha256': digest, 'frames': records}

    owners = []
    for role, (a, b, sha) in OWNERS.items():
        owners.append(frame_records(a, b, sha, role))
    boundaries = []
    for role, (a, b, sha) in BOUNDARIES.items():
        boundaries.append(frame_records(a, b, sha, role))
    return {
        'target_sha256': SHA, 'owners': owners,
        'boundaries': boundaries, 'slot_bindings': bindings,
        'err_vtable': facts['err_vtable'],
        'sibling_unwrap_vtables': facts['sibling_unwrap_vtables'],
        'unwrap_message': facts['unwrap_message'],
        'unwrap_location': facts['unwrap_location'],
        'direct_call_census': census,
        'wrapper_census': wrap,
        'dest_slot_census': dest,
        'tag_consumption': {
            'reader_gate': 'the exit reader branches on the entry '
                           'count word alone (temp+0x60, loaded '
                           '0x4749b1d, tested 0x4749b25): zero '
                           'copies temp[0..0x50] to the out union, '
                           'nonzero writes {6, cap, buffer, count} '
                           'with the discriminant store at '
                           '0x4749b3a; no tag word is loaded',
            'consumer_gate': 'the consumer compares the out '
                             'union word at 0x15a5930 against 6 '
                             'only; the non-6 arm copies 0x48 '
                             'bytes to the [rsp+0x278] destination '
                             'without loading any entry',
            'debug_format': 'the Err value is formatted only '
                            'through its vtable Debug pointer '
                            '0x15b4420 (size-24 value = the entry '
                            'vector header), reached from the '
                            'unwrap helper through the dyn dispatch '
                            'shim 0x1687260; it has no direct call '
                            'site in the binary',
            'drop': 'the entry vector drop 0x15ac470 walks '
                    'entries at stride 0x20; for each entry it '
                    'compares the tag word at +0x00 against 3 '
                    '(unsigned <=, 0x15ac4a9) and, when the +0x8 '
                    'word is nonzero, frees (+0x10, +0x8) through '
                    'the dealloc slot 0x64df4a0; the +0x18 word '
                    'is never loaded and no tag value selects a '
                    'different path; the buffer is freed at '
                    'cap << 5',
            'per_tag_dispatch_found': False,
        },
        'destination_chain': [
            'consumer rdi argument, saved at [rsp+0x278] in the '
            'prologue (0x15a3ba1) and loaded once, at the exit '
            'copy (0x15a5940)',
            'the wrapper 0x15a6510 passes its own frame scratch '
            'at [rsp+0x48] as that rdi (0x15a654c), with its '
            'record pointer in rsi and the id scalar in edx',
            'after the call the wrapper passes the same scratch '
            'to the registrar 0x474f6a0 through slot 0x64e1488 '
            '(call site 0x15a6596) and requires a nonzero return',
            'the registrar forwards the pointer unchanged as '
            'rdi to the wrap constructor 0x4742470 through slot '
            '0x64eaf70 (call site 0x474f6ad); the constructor '
            'passes it on as rsi to the payload constructor '
            '0x4741180, whose head loads the struct words at '
            '+0x20/+0x30/+0x38/+0x48 and scales a count by '
            '0x40-byte records',
            'the registrar stores the derived word from its '
            'lookup/key helpers into the global cell behind '
            'slot 0x64eaf08 (store at 0x474f724), inserts an '
            '8-byte node {wrap pointer} through slot 0x64eaef0, '
            'and returns the wrap pointer, or 0 when the insert '
            'reports failure',
            'the wrapper stores the returned word at its own '
            'out object +0x50 (0x15a65e9) and the record copy '
            'at +0x00..+0x50 from its rsi argument; on a zero '
            'return it unwrap-fails through slot 0x64df6a0 '
            '(call site 0x15a663f)',
        ],
        'verdict':
            'What consumes the entry tags 0/1/2/3 downstream of '
            'the exit reader 0x4749ab0: nothing reads an '
            'individual tag value.  The reader itself branches '
            'only on the merged entry vector\'s count '
            '(temp+0x60): zero yields the plain 0x50-byte out '
            'struct (a verbatim copy of temp[0..0x50]), nonzero '
            'yields the {6, ...} form -- discriminant 6 at '
            'out+0x00 and the entry vector header {cap, buffer, '
            'count} at out+0x08.  The consumer 0x15a3b90, the '
            'reader\'s only caller (slot 0x64e1480, call site '
            '0x15a592a), tests the out word against 6 at '
            '0x15a5930.  On the {6, ...} arm the out union is a '
            'Rust Result in its Err variant: the consumer '
            'rebuilds the 24-byte entry vector header at '
            '[rsp+0xc0] and calls the unwrap-failed helper '
            '0x1680c30 (slot 0x64df6a0) with the message '
            '"called `Result::unwrap()` on an `Err` value", '
            'the error vtable 0x63ffe00 and Location '
            '0x63ffb30 (base/src/log/handle.rs:167:60); the '
            'helper formats the Err value through its vtable '
            'Debug pointer 0x15b4420 and the panic entry '
            '0x1680e80 aborts, so the arm ends at the ud2 at '
            '0x15a5c77 and the destination is never written.  '
            'The vector\'s storage is released by the vtable '
            'drop 0x15ac470, which treats every entry alike: '
            'tag <= 3 is only an upper-bound gate before '
            'freeing the entry\'s (+0x10, +0x8) pair, and its '
            'sole direct call site in the binary is the '
            'consumer\'s own landing pad at 0x15a6042.  On the '
            'plain arm the consumer copies 0x48 bytes (the '
            'word at out+0x40, then out[0..0x40]) to the '
            'destination pointer held at [rsp+0x278] -- its '
            'own rdi argument, saved at 0x15a3ba1.  The '
            'consumer\'s sole direct caller, the wrapper '
            '0x15a6510, supplies a 0x50-byte scratch buffer at '
            'its [rsp+0x48] as that destination and, after the '
            'return, hands the scratch to the registrar '
            '0x474f6a0 (slot 0x64e1488); the registrar forwards '
            'it untouched to the wrap constructor 0x4742470, '
            'whose payload constructor 0x4741180 is the first '
            'code to read the struct\'s fields, then registers '
            'the result globally and returns the wrap pointer '
            'the wrapper stores at its out object +0x50 (a '
            'zero return is itself unwrap-failed by the '
            'wrapper).  The delegate\'s per-tag production '
            'semantics (0 = vecA duplicate, 1 = third/sub-vector '
            'non-member, 2 = vecB duplicate, 3 = vecB '
            'colon-scan hit, per the merge-delegate packet) '
            'therefore survive downstream only as an aggregate: '
            'any leftover entry at all turns the call into an '
            'unwrap panic, and no consumer distinguishes '
            '0/1/2/3.',
    }


def _objdump(path, start, end):
    return subprocess.check_output(
        ['objdump', '-d', '-M', 'intel', '--insn-width=16',
         f'--start-address={start:#x}', f'--stop-address={end:#x}',
         str(path)]).decode('utf-8')


WINDOWS = [
    ('consumer_prologue_window_15a3b90_15a3bc0_objdump.txt',
     0x15a3b90, 0x15a3bc0,
     [s for s, _ in CONSUMER_PINS.values() if 0x15a3b90 <= s < 0x15a3bc0]),
    ('consumer_exit_window_15a58f2_15a5981_objdump.txt',
     0x15a58f2, 0x15a5981,
     [s for s, _ in CONSUMER_PINS.values() if 0x15a58f2 <= s < 0x15a5981]
     + [s for s, _ in CONSUMER_SLOT_CALLS.values()
        if 0x15a58f2 <= s < 0x15a5981]),
    ('consumer_unwrap_arm_window_15a5b8c_15a5c79_objdump.txt',
     0x15a5b8c, 0x15a5c79,
     [s for s, _ in CONSUMER_PINS.values() if 0x15a5b8c <= s < 0x15a5c79]
     + [s for s, _ in CONSUMER_SLOT_CALLS.values()
        if 0x15a5b8c <= s < 0x15a5c79]
     + [s for s, _ in CONSUMER_LEAS.values()
        if 0x15a5b8c <= s < 0x15a5c79]),
    ('consumer_landing_pad_window_15a6011_15a6057_objdump.txt',
     0x15a6011, 0x15a6057,
     [s for s, _ in CONSUMER_PINS.values() if 0x15a6011 <= s < 0x15a6057]
     + [s for s, _ in CONSUMER_DIRECT_CALLS.values()
        if 0x15a6011 <= s < 0x15a6057]),
    ('wrapper_objdump.txt', 0x15a6510, 0x15a6674,
     [s for s, _ in WRAPPER_PINS.values()]
     + [s for s, _ in WRAPPER_DIRECT_CALLS.values()]
     + list(WRAPPER_SLOT_CALLS)),
    ('entry_vec_drop_objdump.txt', 0x15ac470, 0x15ac4f0,
     [s for s, _ in DROP_PINS.values()]
     + [s for s, _ in DROP_SLOT_JMPS.values()]),
    ('unwrap_failed_objdump.txt', 0x1680c30, 0x1680c82,
     [s for s, _ in UNWRAP_PINS.values()]
     + [s for s, _ in UNWRAP_SLOT_CALLS.values()]
     + [s for s, _ in UNWRAP_LEAS.values()]),
    ('panic_helper_objdump.txt', 0x1680e80, 0x1680eac,
     [s for s, _ in PANIC_PINS.values()]
     + [s for s, _ in PANIC_SLOT_CALLS.values()]),
    ('registrar_objdump.txt', 0x474f6a0, 0x474f7ff,
     [s for s, _ in REGISTRAR_PINS.values()]
     + [s for s, _ in REGISTRAR_SLOT_CALLS.values()]
     + [s for s, _ in REGISTRAR_DIRECT_CALLS.values()]),
    ('arc_wrap_ctor_objdump.txt', 0x4742470, 0x4742595,
     [s for s, _ in ARC_PINS.values()]
     + [s for s, _ in ARC_DIRECT_CALLS.values()]
     + [s for s, _ in ARC_LEAS.values()]),
    ('exit_reader_objdump.txt', 0x4749ab0, 0x4749d71,
     [s for s, _ in READER_PINS.values()]
     + [s for s, _ in READER_SLOT_CALLS.values()]),
]


def generate(binary, output):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('wrong node115 capture')
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            dir=output, suffix='.elf', delete=False) as handle:
        handle.write(data)
        snapshot = Path(handle.name)
    try:
        native = subprocess.check_output(
            ['readelf', '--debug-dump=frames-interp',
             str(snapshot)]).decode('utf-8')
        lines = []
        for role, (a, b, _) in list(OWNERS.items()) + \
                list(BOUNDARIES.items()):
            rows = [l for l in native.splitlines()
                    if f'pc={a:016x}..{b:016x}' in l]
            if len(rows) != 1:
                raise ValueError('native FDE disagreement')
            lines.extend(rows)
        for name, start, end, sites in WINDOWS:
            asm = _objdump(snapshot, start, end)
            ins = decode_export(asm, start, end,
                                read(data, start, end - start)[1])
            if not set(sites) <= set(ins):
                raise ValueError(f'{name} evidence site not a '
                                 'native instruction start')
            (output / name).write_bytes(
                asm.replace(str(snapshot),
                            '<authenticated-node115>').encode('utf-8'))
    finally:
        snapshot.unlink()
    (output / 'frames.txt').write_bytes(
        ('\n'.join(lines) + '\n').encode('utf-8'))
    (output / 'records.json').write_bytes(
        (json.dumps(report, indent=2) + '\n').encode('utf-8'))
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=TARGET)
    p.add_argument('--output', type=Path,
                   default=ROOT / 'work/entry-tag-consumers115')
    args = p.parse_args()
    report = generate(args.binary, args.output)
    print(json.dumps({'functions': len(report['owners']),
                      'bytes': sum(x['bytes'] for x in report['owners']),
                      'executed': False}))
