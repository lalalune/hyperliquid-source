#!/usr/bin/env python3
"""Extract node 94 channel-selection and publication evidence from ELF bytes."""
import argparse
import csv
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
TARGET = ROOT / 'artifacts/node/94/hl-node'

def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 size or SHA-256 mismatch')

class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size']
                and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('virtual range lacks a unique allocated, file-backed section')
        offset = hits[0]['offset'] + va - hits[0]['address']
        if offset < 0 or offset + size > len(self.data):
            raise ValueError('file-backed range is truncated')
        return offset

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]


def require_bytes(actual, expected, label):
    if actual != expected:
        raise ValueError('byte contract changed: ' + label)


# Restricted x86 byte-pattern reader adapted from the MIT replica-route collector.
def _need(body, pos, count):
    if pos < 0 or count < 0 or pos + count > len(body):
        raise ValueError('truncated instruction')


def decode_one(body, off, base):
    """Decode one length and control-transfer form; no full mnemonic claim."""
    start = off
    prefix66 = False
    rex = 0
    while True:
        _need(body, off, 1)
        p = body[off]
        if p in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            prefix66 |= p == 0x66
            off += 1
        elif 0x40 <= p <= 0x4f:
            rex = p
            off += 1
        else:
            break
        if off - start > 8:
            raise ValueError('too many prefixes')
    op = body[off]
    off += 1
    kind = 'instruction'
    target = None
    rel_width = 0
    modrm_needed = False
    imm = 0
    op2 = None
    if op == 0x0f:
        _need(body, off, 1)
        op2 = body[off]
        off += 1
        if 0x80 <= op2 <= 0x8f:
            kind, rel_width = 'conditional', 4
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (op2 in (0x10, 0x11, 0x13, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xc1, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
              or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f):
            modrm_needed = True
        else:
            raise ValueError(f'unsupported 0f opcode {op2:02x} at {base + start:#x}')
    elif op in (0xe8, 0xe9):
        kind, rel_width = ('call' if op == 0xe8 else 'jump'), 4
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        kind, rel_width = ('jump' if op == 0xeb else 'conditional'), 1
    elif op in (0xc3, 0xcb):
        kind = 'return'
    elif op == 0xc2:
        kind, imm = 'return', 2
    elif op in (0xcc, 0xf4):
        kind = 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc9):
        pass
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else (2 if prefix66 else 4)
    elif 0xb0 <= op <= 0xb7 or op in (0x6a, 0xa8, 0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
        imm = 1
    elif op in (0x68, 0xa9, 0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        imm = 2 if prefix66 else 4
    elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f,
                0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3,
                0xf6, 0xf7, 0xfe, 0xff):
        modrm_needed = True
    else:
        raise ValueError(f'unsupported opcode {op:02x} at {base + start:#x}')

    rip_disp_pos = None
    modrm = None
    if modrm_needed:
        _need(body, off, 1)
        modrm = body[off]
        off += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        sib_base = None
        if mod != 3 and rm == 4:
            _need(body, off, 1)
            sib_base = body[off] & 7
            off += 1
        if mod == 0 and rm == 5:
            rip_disp_pos = off
            off += 4
        elif mod == 0 and sib_base == 5:
            off += 4
        elif mod == 1:
            off += 1
        elif mod == 2:
            off += 4
        if op == 0x0f and op2 in (0x70, 0x72, 0x73):
            imm = 1
        elif op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
            imm = 1
        elif op in (0x81, 0x69, 0xc7):
            imm = 2 if prefix66 else 4
        elif op == 0xf6 and reg in (0, 1):
            imm = 1
        elif op == 0xf7 and reg in (0, 1):
            imm = 2 if prefix66 else 4
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
    if rel_width:
        _need(body, off, rel_width)
        delta = int.from_bytes(body[off:off + rel_width], 'little', signed=True)
        off += rel_width
        target = base + off + delta
    else:
        _need(body, off, imm)
        off += imm
        if rip_disp_pos is not None:
            _need(body, rip_disp_pos, 4)
            target = base + off + struct.unpack_from('<i', body, rip_disp_pos)[0]
    if off - start > 15:
        raise ValueError('instruction exceeds x86 maximum')
    _need(body, start, off - start)
    return {'va': base + start, 'end': base + off, 'kind': kind,
            'target': target, 'bytes': bytes(body[start:off]),
            'opcode': (op, op2), 'modrm': modrm,
            'rip_relative': rip_disp_pos is not None}


def decode_body(body, base):
    result = []
    offset = 0
    while offset < len(body):
        row = decode_one(body, offset, base)
        result.append(row)
        offset = row['end'] - base
    if offset != len(body):
        raise ValueError('function decoding exceeded extent')
    starts = {r['va'] for r in result}
    end = base + len(body)
    for row in result:
        if row['kind'] in ('jump', 'conditional') and base <= row['target'] < end:
            if row['target'] not in starts:
                raise ValueError(f'branch into an instruction at {row["va"]:#x}')
        if row['kind'] == 'conditional' and row['end'] < end and row['end'] not in starts:
            raise ValueError('fallthrough is not an instruction boundary')
    return result




def reachable(decoded, source, destination, forbidden=()):
    """Over-approximate normal flow: all conditions feasible and calls return."""
    by_va = {ins['va']: ins for ins in decoded}
    if source not in by_va or destination not in by_va:
        raise ValueError('CFG query is not at an instruction boundary')
    forbidden = set(forbidden)
    if any(va not in by_va for va in forbidden):
        raise ValueError('CFG forbidden VA is not an instruction boundary')
    pending, seen = [source], set()
    while pending:
        va = pending.pop()
        if va in forbidden or va in seen or va not in by_va:
            continue
        if va == destination:
            return True
        seen.add(va)
        ins = by_va[va]
        kind = ins['kind']
        if kind in ('return', 'trap', 'indirect_jump'):
            continue
        if kind == 'jump':
            pending.append(ins['target'])
        elif kind == 'conditional':
            pending.extend((ins['target'], ins['end']))
        else:
            pending.append(ins['end'])
    return False

FUNCTIONS = (
    ('entry', 0x143c510, 0x143d00a, '89fffdda6c54d03564c7b577b85806e3a1564280cd8a7f88d41427b2feb09929'),
    ('once_callback_a', 0x143eab0, 0x143eb09, '5e0a8d2be50226b75ec40a245cfa8abcdd58b972376ba09d077848e914a803a9'),
    ('once_callback_b', 0x1437d90, 0x1437de9, '16e998d23079ef5fa1ad4a123bc7ad0b0366784f7a60b56796d0c33d94f31d4c'),
    ('cleanup', 0x143fa70, 0x143fac9, 'ec7cb9d71efc68793e963b95b03e7522713505f14e3e9e3a23ec7d1bafa30350'),
    ('aux_once', 0x145d111, 0x145d15d, 'b334dac24f93aaccbf1d97c6438daef76c7e9f7ba17db6ab9af83edc6b5c83e9'),
)
SLOTS = {
    0x5668248: 0x217ff1,
    0x5668258: 0x217ff6,
    0x5668268: 0x217ffd,
    0x5668278: 0x218004,
    0x576eb70: 0x577a898,
    0x577a898: 0x13d28e0,
    0x5669ff8: 0x143eab0,
    0x566a000: 0x1437d90,
    0x577acf0: 0x143f520,
    0x576e948: 0x13ca370,
    0x576e8b8: 0x4ee3b20,
}
# Pinned instruction witnesses; the decoded operands and targets are retained.
WITNESSES = {
    'network_table_address': (0x143c552, '488d0d9fceddfe'),
    'table_indexed_word': (0x143c559, '48630481'),
    'table_base_add': (0x143c55d, '4801c8'),
    'table_jump': (0x143c560, 'ffe0'),
    'sandbox_cell': (0x143c562, '488b1d07263304'),
    'sandbox_state': (0x143c569, '8b8368020000'),
    'sandbox_sentinel': (0x143c577, '4839ab00010000'),
    'sandbox_present': (0x143c57e, '0f8579020000'),
    'testnet_cell': (0x143c589, '488b1de0253304'),
    'testnet_sentinel': (0x143c59e, '4839abe8000000'),
    'testnet_absent': (0x143c5a5, '7453'),
    'mainnet_cell': (0x143c5d8, '488b1d91253304'),
    'mainnet_sentinel': (0x143c5ed, '4839abd0000000'),
    'mainnet_present': (0x143c5f4, '0f85e8000000'),
    'second_cell': (0x143c70d, '4c8b3d5c243304'),
    'second_sentinel': (0x143c71f, '4939afd0000000'),
    'second_present': (0x143c726, '7508'),
    'mutex_acquire': (0x143c93f, 'f00fb00dc1e33304'),
    'mutex_contended': (0x143c947, '0f859d040000'),
    'logger_sentinel': (0x143c94d, '48392dbce33304'),
    'logger_exists': (0x143c954, '7528'),
    'logger_factory': (0x143c95e, 'ff158ce33304'),
    'logger_destination': (0x143c964, '488d3da5e33304'),
    'logger_copy_length': (0x143c973, 'ba18010000'),
    'logger_copy': (0x143c978, 'ff1562163304'),
    'flag_set': (0x143c97e, 'c6059be4330401'),
    'state_acquire': (0x143c98d, 'ff15b51f3304'),
    'format_template': (0x143ca38, '488d35956ddafe'),
    'formatter': (0x143ca4f, 'ff15eb153304'),
    'message_tail_store': (0x143ca78, '488905a1e23304'),
    'message_head_store': (0x143ca87, '0f110582e23304'),
    'selected_a_tail_store': (0x143cab3, '488905f6e23304'),
    'selected_a_head_store': (0x143cabf, '0f1105dae23304'),
    'selected_b_tail_store': (0x143caef, '488905d2e23304'),
    'selected_b_head_store': (0x143cafa, 'f30f7f05b6e23304'),
    'production_flag': (0x143cb02, '803d17e3330401'),
    'production_skip': (0x143cb09, '750d'),
    'crash_flag': (0x143cb0b, 'f6050fe3330401'),
    'assertion_branch': (0x143cb12, '0f85e9020000'),
    'sanitize_replacement': (0x143ccb2, 'be5f000000'),
    'sanitize_compare': (0x143ccc5, '4080ff20'),
    'sanitize_replace': (0x143ccc9, '0f44fe'),
    'sanitize_store': (0x143cccc, '41883c0f'),
    'name_capacity_store': (0x143cd59, '48891dc8df3304'),
    'name_pointer_store': (0x143cd60, '4c893dc9df3304'),
    'name_length_store': (0x143cd67, '48891dcadf3304'),
    'mutex_release': (0x143cdb3, 'f00fb00d4ddf3304'),
    'release_contended': (0x143cdbb, '7565'),
    'local_return': (0x143cdc7, '4881c408020000'),
    'aux_call': (0x143cde0, 'e82c030200'),
    'assert_message': (0x143ce04, '488d3d55c8ddfe'),
    'assert_length': (0x143ce12, 'be3d000000'),
    'assert_call': (0x143ce17, 'ff15eb123304'),
    'alloc_error_1': (0x143ce93, 'ff151f113304'),
    'alloc_error_2': (0x143cea3, 'ff150f113304'),
    'alloc_error_3': (0x143ceb4, 'ff15fe103304'),
    'alloc_error_4': (0x143cec4, 'ff15ee103304'),
    'alloc_error_5': (0x143ced2, 'ff15e0103304'),
    'error_trap': (0x143ced8, '0f0b'),
}

def relocations(view):
    hits = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(hits) != 1:
        raise ValueError('missing relocation section')
    s = hits[0]
    if s['size'] % 24 or s['offset'] + s['size'] > len(view.data):
        raise ValueError('malformed relocations')
    found = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', view.data, off)
        if slot in SLOTS:
            if slot in found or info != 8:
                raise ValueError('duplicate or non-relative relocation')
            if addend != SLOTS[slot]:
                raise ValueError('wrong relocation target')
            found[slot] = (off, addend)
    if set(found) != set(SLOTS):
        raise ValueError('missing relocation')
    return found


def inspect(data, authenticate=True):
    if authenticate:
        verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    grouped = {}
    functions = []
    all_ins = []
    for role, start, end, digest in FUNCTIONS:
        matches = [x for x in fdes if x['start'] == start and x['end'] == end]
        if len(matches) != 1:
            raise ValueError('selected FDE missing or ambiguous')
        body = view.read(start, end-start)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('selected body mismatch: ' + role)
        rows = decode_body(body, start)
        grouped[role] = rows
        functions.append([role, hex(start), hex(end), hex(view.offset(start, len(body))), len(body), len(rows), digest])
        all_ins.extend((role, ins) for ins in rows)
    ins_by = {ins['va']: ins for role, ins in all_ins}
    witness = []
    for name, (va, expected) in WITNESSES.items():
        ins = ins_by.get(va)
        if ins is None or ins['bytes'].hex() != expected:
            raise ValueError('witness mismatch: ' + name)
        witness.append([name, hex(va), hex(view.offset(va, len(ins['bytes']))), expected,
                        ins['kind'], '' if ins['target'] is None else hex(ins['target'])])
    rels = relocations(view)
    callback_rows = []
    for role, base in [('once_callback_a', 0x143eab0), ('once_callback_b', 0x1437d90)]:
        rows = grouped[role]
        by = {x['va']: x for x in rows}
        expected = [(0x0d, '488b18'), (0x10, '48c70000000000'), (0x17, '4885db'),
                    (0x1c, '807e0401'), (0x28, 'ff13'), (0x2a, 'ba68020000')]
        for offset, raw in expected:
            if by.get(base+offset, {}).get('bytes', b'').hex() != raw:
                raise ValueError('callback shape mismatch')
        callback_rows.append([role, hex(base), int.from_bytes(by[base+0x2a]['bytes'][1:], 'little'),
                              hex(by[base+0x1a]['target']), hex(by[base+0x20]['target'])])
    raw = view.read(0x2193f8, 16)
    expected_targets = [0x143cdc7, 0x143c562, 0x143c589, 0x143c5d8]
    table_rows = []
    names = []
    for i in range(4):
        slot = 0x5668248 + 16*i
        length = struct.unpack('<Q', view.read(slot+8, 8))[0]
        if length not in (5, 7):
            raise ValueError('network descriptor length changed')
        names.append(view.read(rels[slot][1], length).decode('ascii'))
    if names != ['Local', 'Sandbox', 'Testnet', 'Mainnet']:
        raise ValueError('network descriptor bytes changed')
    for i in range(4):
        delta = struct.unpack_from('<i', raw, i*4)[0]
        target = 0x2193f8 + delta
        if target != expected_targets[i] or target not in ins_by:
            raise ValueError('bad selector table')
        cmpaddr = [None, 0x143c577, 0x143c59e, 0x143c5ed][i]
        offset = '' if cmpaddr is None else hex(int.from_bytes(ins_by[cmpaddr]['bytes'][-4:], 'little'))
        table_rows.append([i, names[i], hex(0x2193f8+i*4), raw[i*4:i*4+4].hex(), hex(target), offset])
    queries = [
        ('local_skips_publication', 0x143cdc7, 0x143c97e, False),
        ('sandbox_reaches_publication', 0x143c562, 0x143c97e, True),
        ('testnet_reaches_publication', 0x143c589, 0x143c97e, True),
        ('mainnet_reaches_publication', 0x143c5d8, 0x143c97e, True),
        ('publication_can_reach_assertion', 0x143c97e, 0x143ce17, True),
        ('publication_can_reach_name_store', 0x143c97e, 0x143cd59, True),
        ('publication_can_reach_release', 0x143c97e, 0x143cdb3, True),
    ]
    graph=[]
    for label, src, dst, expected in queries:
        got=reachable(grouped['entry'], src, dst)
        if got != expected:
            raise ValueError('CFG proposition changed: '+label)
        graph.append([label, hex(src), hex(dst), str(got).lower()])
    return view, functions, grouped, all_ins, witness, rels, callback_rows, table_rows, graph


def write_table(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        out = csv.writer(f, delimiter='\t', lineterminator='\n')
        out.writerow(header)
        out.writerows(rows)


def checked_data(view):
    data_rows=[]
    for name, va, expected in (
        ('format_entry', 0x1e37d4, bytes.fromhex('c00720636861696e3dc006206970733d5bc00120c0015d00')),
        ('assertion_text', 0x219660, b'assertion failed: !(self.is_production && self.crash_on_crit)'),
        ('callback_a_post_fde', 0x143eb09, b'\xcc'),
        ('callback_b_post_fde', 0x1437de9, b'\xcc'),
    ):
        observed=view.read(va,len(expected))
        if observed != expected:
            raise ValueError('data bytes changed: '+name)
        data_rows.append([name,hex(va),hex(view.offset(va,len(expected))),len(observed),observed.hex()])
    return data_rows


def generate(data, out):
    view, functions, grouped, all_ins, witness, rels, callback, table, graph = inspect(data)
    out.mkdir(parents=True, exist_ok=True)
    write_table(out/'functions.tsv', ['role','start_va','end_va_exclusive','file_offset','bytes','instructions','body_sha256'], functions)
    rows=[]
    transfers=[]
    for role, ins in all_ins:
        row=[role,hex(ins['va']),hex(view.offset(ins['va'],len(ins['bytes']))),ins['bytes'].hex(),ins['kind'],'' if ins['target'] is None else hex(ins['target'])]
        rows.append(row)
        if ins['kind'] != 'instruction':transfers.append(row)
    write_table(out/'instructions.tsv',['role','va','file_offset','hex','kind','target_va'],rows)
    write_table(out/'transfers.tsv',['role','va','file_offset','hex','kind','target_va'],transfers)
    write_table(out/'witnesses.tsv',['label','va','file_offset','hex','kind','target_va'],witness)
    write_table(out/'selector.tsv',['input_byte','prior_name','table_slot_va','slot_hex','target_va','config_offset'],table)
    write_table(out/'callbacks.tsv',['role','start_va','copy_bytes','null_target','state_one_target'],callback)
    write_table(out/'relocations.tsv',['slot_va','relocation_file_offset','addend'],[[hex(k),hex(rels[k][0]),hex(rels[k][1])] for k in sorted(rels)])
    write_table(out/'cfg.tsv',['query','source_va','destination_va','reachable'],graph)
    write_table(out/'data.tsv',['label','va','file_offset','length','hex'],checked_data(view))
    summary={'target':'node-94','sha256':DIGEST,'coordinate_system':'linked-elf-va','fde_count':len(functions),
             'selected_bytes':sum(x[4] for x in functions),'instructions':len(rows),'transfers':len(transfers),
             'witnesses':len(witness),'relocations':len(rels),'cfg_queries':len(graph)}
    (out/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n',encoding='utf-8')


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    generate(TARGET.read_bytes(),args.out)

if __name__ == '__main__':
    main()
