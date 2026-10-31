#!/usr/bin/env python3
"""RE-001: the actual Node94 0x4959020 writeback and its used address operands."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

from artifacts import ROOT, digest
from elf_index import sections
from fde_extents import eh_frame_records, sleb, uleb

TARGET = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END = 0x4959020, 0x495921e
BODY_SHA256 = '232579edc4097019206623ae6693dbcbf23086e2104e6c6df676034c9c95a3b7'
FDE, CIE, LSDA = 0x12aad24, 0xfbdc2c, 0xb87d34
CALLS = (0x4959081, 0x49590a7, 0x49590ff, 0x495916a, 0x49591a5, 0x49591c9,
         0x49591d9, 0x49591eb, 0x49591f7, 0x495920a, 0x4959213, 0x4959218)
BRANCHES = (0x495903f, 0x4959099, 0x49590b0, 0x4959112,
            0x49591ab, 0x49591e1, 0x49591e9, 0x4959202)
STORES = (0x495917a, 0x495917d, 0x4959181, 0x4959185)
CALL_BINDINGS = {
    0x4959081: ('direct', 0x4258c00), 0x49590a7: ('relocated-slot', 0x576dfd8),
    0x49590ff: ('relocated-slot', 0x576dfe0), 0x495916a: ('relocated-slot', 0x576dfe0),
    0x49591a5: ('relocated-slot', 0x576e020), 0x49591c9: ('relocated-slot', 0x576e108),
    0x49591d9: ('direct', 0x41d4ca0), 0x49591eb: ('relocated-slot', 0x576e128),
    0x49591f7: ('direct', 0x4906ec0), 0x495920a: ('relocated-slot', 0x576e010),
    0x4959213: ('direct', 0x5660110), 0x4959218: ('relocated-slot', 0x576e128),
}
CONTROLS = {
    0x4959031: '4989d74889f34989fe',
    0x495903a: '48837e2000745d',
    0x4959067: '4c8d4b384c8d4318488d7c2418488d742430488d5424504c89f9',
    0x4959081: 'e87afb8fff',
    0x4959086: '4c8b6b184c8b642418488b442420488b6c2428e9d4000000',
    0x495909e: '4c8b6b18bf381b0000ff152b4fe1004885c00f84e50000004989c4',
    0x4959105: '410fb7ac24321b00004883fd0b0f8395000000',
    0x4959155: '4869c5600200004c89e74801c7ba600200004c89feff15704ee10031c0',
    0x4959172: '49ff4510488b4b184d89264989460849896e1049894e18',
    0x4959189: '4881c4b80200005b415c415d415e415f5dc3',
    0x4956e63: '488d7c2458488d742420488d9424b8020000e8a62100004869442468600200004803442458',
}
# Actual selected ELF64 RELA records. Unnamed targets remain opaque.
RELOCATIONS = {
    0x576dfd8: (8, 0, 0x54c06b0, ''),
    0x576dfe0: (6, 6, 0, 'memcpy'),
    0x576e010: (8, 0, 0x54c8cb0, ''),
    0x576e020: (8, 0, 0x1345e2a, ''),
    0x576e108: (8, 0, 0x157b7f0, ''),
    0x576e128: (8, 0, 0x157b63b, ''),
    0x5778db0: (7, 7, 0, '_Unwind_Resume'),
    0x577a668: (8, 0, 0x4f14ca0, ''),
}
LSDA_ROWS = [[0, 379, 0, 0], [379, 16, 465, 0], [397, 34, 433, 0],
             [436, 10, 459, 1], [468, 8, 504, 1], [476, 34, 0, 0]]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, va, length):
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] <= va
                   and va + length <= s['address'] + s['size']]
        require(length >= 0 and len(matches) == 1, 'Selected range lacks one file-backed mapping')
        s = matches[0]
        offset = s['offset'] + va - s['address']
        return offset, bytes(self.data[offset:offset + length])

    def raw_record(self, va):
        offset, head = self.read(va, 4)
        length = struct.unpack('<I', head)[0] + 4
        require(8 <= length <= 4096, 'Unsupported selected CFI record length')
        raw = self.read(va, length)[1]
        return {'va': hex(va), 'file_offset': hex(offset), 'raw': raw.hex()}


def controls(image):
    for va, expected in CONTROLS.items():
        body = bytes.fromhex(expected)
        require(image.read(va, len(body))[1] == body, f'Writeback instruction changed at {va:#x}')


def relocations(image):
    sym = next(s for s in image.sections if s['name'] == '.dynsym')
    strings = next(s for s in image.sections if s['name'] == '.dynstr')
    found = {}
    for section in image.sections:
        if section['type'] != 4:
            continue
        require(section['size'] % 24 == 0, 'Incomplete RELA table')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, offset)
            if slot not in RELOCATIONS:
                continue
            require(slot not in found, 'Duplicate selected relocation')
            index, kind = info >> 32, info & 0xffffffff
            name = ''
            if index:
                require((index + 1) * 24 <= sym['size'], 'Selected symbol outside table')
                name_index = struct.unpack_from('<I', image.data, sym['offset'] + 24 * index)[0]
                require(name_index < strings['size'], 'Selected symbol string outside table')
                begin, limit = strings['offset'] + name_index, strings['offset'] + strings['size']
                end = image.data.find(b'\0', begin, limit)
                require(end >= begin, 'Unterminated selected symbol')
                name = bytes(image.data[begin:end]).decode('ascii')
            require((kind, index, addend, name) == RELOCATIONS[slot], f'Selected relocation changed at {slot:#x}')
            found[slot] = {'slot': hex(slot), 'type': kind, 'symbol_index': index, 'symbol': name,
                           'addend': hex(addend), 'file_offset': hex(offset),
                           'raw': bytes(image.data[offset:offset + 24]).hex()}
    require(set(found) == set(RELOCATIONS), 'Missing selected relocation')
    return [found[slot] for slot in sorted(found)]


def lsda(image):
    origin, header = image.read(LSDA, 5)
    require(header == bytes.fromhex('ff9b290122'), 'Selected LSDA header changed')
    section = next(s for s in image.sections if s['name'] == '.gcc_except_table')
    limit = section['offset'] + section['size']
    type_delta, pos = uleb(image.data, origin + 2, limit)
    type_base = pos + type_delta
    pos += 1  # The already checked call-site encoding is ULEB128.
    length, pos = uleb(image.data, pos, limit)
    end, decoded = pos + length, []
    require(end <= limit, 'LSDA call-site table exceeds section')
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(image.data, pos, end)
            values.append(value)
        decoded.append(values)
    require(pos == end and decoded == LSDA_ROWS, 'Selected LSDA call-site rows changed')
    action, after = sleb(image.data, end, limit)
    following, after = sleb(image.data, after, limit)
    require((action, following) == (-1, 0), 'Selected signed LSDA action changed')
    return {'va': hex(LSDA), 'file_offset': hex(origin), 'raw_prefix': bytes(image.data[origin:after]).hex(),
            'type_encoding': '0x9b', 'type_base_va': hex(LSDA + type_base - origin),
            'rows': [{'start': hex(START + a), 'end': hex(START + a + size),
                      'landing_pad': hex(START + pad) if pad else None, 'action': act,
                      'raw_uleb_values': [a, size, pad, act]} for a, size, pad, act in decoded],
            'first_action': {'type_filter': action, 'next_action': following},
            'limits': 'Type table, negative-filter interpretation, personality and exception behavior are not closed.'}


def observed_calls(image):
    result = []
    for va, (kind, expected) in CALL_BINDINGS.items():
        size = 5 if kind == 'direct' else 6
        raw = image.read(va, size)[1]
        require(raw[:1] == b'\xe8' if size == 5 else raw[:2] == b'\xff\x15',
                f'Selected call opcode changed at {va:#x}')
        target = va + size + struct.unpack_from('<i', raw, 1 if size == 5 else 2)[0]
        require(target == expected, f'Selected call target changed at {va:#x}')
        lookup = va + size - 1
        owner = next((i for i, (start, length, _, _) in enumerate(LSDA_ROWS)
                      if START + start <= lookup < START + start + length), None)
        result.append({'va': hex(va), 'kind': kind, 'target_or_slot': hex(target),
                       'return_pc': hex(va + size), 'unwind_lookup_pc': hex(lookup), 'lsda_row_index': owner})
    return result


def inspect_bytes(data):
    """Below-authentication seam for real-input corruption controls."""
    image = Image(data)
    controls(image)
    cies, frames = eh_frame_records(data, image.sections)
    matches = [f for f in frames if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == END, 'Selected exact FDE extent changed')
    fde = matches[0]
    require((fde['fde'], fde['cie'], fde['lsda']) == (FDE, CIE, LSDA), 'Selected FDE/CIE/LSDA binding changed')
    cie = cies[CIE]
    require((cie['augmentation'], cie['code_align'], cie['data_align'], cie['fde_encoding'],
             cie['lsda_encoding'], cie['personality_slot']) == ('zPLR', 1, -8, 0x1b, 0x1b, 0x577a668),
            'Selected CIE profile changed')
    offset, body = image.read(START, END - START)
    bridge_offset, bridge = image.read(0x4956e63, 37)
    _, stub = image.read(0x5660110, 6)
    require(stub[:2] == b'\xff\x25' and 0x5660116 + struct.unpack_from('<i', stub, 2)[0] == 0x5778db0,
            'Selected resume PLT binding changed')
    return {'schema': 're001-rate-result-writeback-94/1',
            'source_base': '1f8c67c63ca4794c9689235471c60297f8a5c985',
            'reference_revision': '999556f6e0a474b8312db96ec3149e1c44e97c23',
            'target': {'release': 94, 'bytes': SIZE, 'sha256': SHA256},
            'body': {'start': hex(START), 'end': hex(END), 'file_offset': hex(offset), 'bytes': len(body),
                     'sha256': hashlib.sha256(body).hexdigest()},
            'fde': image.raw_record(FDE), 'cie': {**cie, 'raw_record': image.raw_record(CIE)},
            'lsda': lsda(image), 'calls': observed_calls(image), 'relocations': relocations(image),
            'revisited_caller_bridge': {'start': '0x4956e63', 'end': '0x4956e88', 'bytes': 37,
                                        'file_offset': hex(bridge_offset), 'raw': bridge.hex()},
            'resume_stub': {'va': '0x5660110', 'bytes': 6, 'raw': stub.hex()},
            'observed_tail_writes': [{'va': hex(va), 'offset': off, 'width': 8, 'source_register': reg}
                                     for va, off, reg in zip(STORES, (0, 8, 16, 24), ('r12', 'rax', 'rbp', 'rcx'))],
            'zero_field_route': {'gate': 'input+0x20 equals zero', 'request_argument_edi': 0x1b38,
                                'index_load_va': '0x4959105', 'unsigned_bound_branch_va': '0x4959112',
                                'index_at_last_imported_call': 'u16 value below11, hence0..10',
                                'last_imported_call': '0x495916a', 'destination': 'R12+608*RBP modulo2**64',
                                'source_register': 'r15', 'byte_count_argument': 608,
                                'eax_zeroing_va': '0x4959170',
                                'limit': 'The call target is bound to memcpy, not a verified runtime implementation; returned-register bounds require ABI preservation.'},
            'delegated_route': {'gate': 'input+0x20 is nonzero', 'call': '0x4959081 ->0x4258c00',
                                'loaded_after_call': {'r12': 'stack+0x18', 'rax': 'stack+0x20', 'rbp': 'stack+0x28'},
                                'helper_argument_r9': 'input+0x38',
                                'limit': 'No local index bound or helper postcondition is established.'},
            'selected_contract': 'If the zero input+0x20 path reaches its last imported memcpy call, that call is supplied R12+608*RBP. '
                                 'The final output words+0/+16 hold those registers, so the earlier caller recomputes '
                                 'that destination if normal ABI/frame/register preservation holds. '
                                 'The delegated route has no locally established index bound.',
            'output_alias_observation': 'Delegated helper receives r9=input+0x38; in the revisited caller this equals its output pointer.',
            'assumptions': ['Shown calls return normally and preserve the native callee-saved registers and frame.',
                            'The memory accesses are valid and no outside write intervenes in the stated store/load path.',
                            'The recorded r9/output alias is preserved; no blanket argument-disjointness assumption is made.'],
            'unknowns': ['Opaque helper0x4258c00 values/effects', 'Actual library resolution and helper behavior',
                         'Allocation/table/object/Rust type and lifetime', 'Full exception/personality contract'],
            'denominator': 'One 510-byte unwind extent; 37 revisited caller bytes checked separately. No matched-function or gate claim.',
            'captured_binary_executed': False, 'component_gates_requested': False}


@contextmanager
def private_slice(body):
    expected = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix='rate-writeback-') as temporary:
        directory = Path(temporary)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Slice directory is not private')
        path = directory / 'slice.bin'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                'Slice is not an owned non-executable regular file')
        require(digest(path) == expected, 'Slice differs from admitted bytes')
        yield path
        after = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(identity(before) == identity(after) and digest(path) == expected, 'Owned slice changed during native decode')


def native_rows(text, body):
    rows, cursor = [], START
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
        if not match:
            continue
        va, raw, assembly = int(match[1], 16), bytes.fromhex(match[2]), match[3]
        require(va == cursor and 1 <= len(raw) <= 15 and va + len(raw) <= END, 'Native row coverage changed')
        require(raw == body[va - START:va - START + len(raw)] and '(bad)' not in assembly
                and not assembly.startswith('.byte'), 'Native row bytes/decode changed')
        rows.append({'va': va, 'raw': raw.hex(), 'assembly': assembly})
        cursor += len(raw)
    require(cursor == END, 'Native rows do not cover exact body')
    require(tuple(r['va'] for r in rows if r['assembly'].startswith('call ')) == CALLS, 'Native call census changed')
    require(tuple(r['va'] for r in rows if r['assembly'].split()[0].startswith('j')) == BRANCHES, 'Native branch census changed')
    require([r['va'] for r in rows if r['assembly'] == 'ret'] == [0x495919a], 'Native return census changed')
    starts = {r['va'] for r in rows}
    edges, calls, branches, boundary = {}, [], [], []
    for row in rows:
        va, raw = row['va'], bytes.fromhex(row['raw'])
        mnemonic = row['assembly'].split()[0]
        following = va + len(raw)
        if mnemonic.startswith('j'):
            delta = struct.unpack('<b' if len(raw) == 2 else '<i', raw[-1:] if len(raw) == 2 else raw[-4:])[0]
            target = following + delta
            require(target in starts and target == int(row['assembly'].split()[1], 16), 'Native branch target changed')
            edges[va] = [target] + ([] if mnemonic == 'jmp' else [following])
            branches.append({'va': hex(va), 'target': hex(target)})
        elif mnemonic in ('ret', 'ud2'):
            edges[va] = []
        else:
            edges[va] = [following] if following in starts else []
            if following == END:
                boundary.append(hex(va))
        if mnemonic == 'call':
            target = following + struct.unpack_from('<i', raw, 1 if raw[0] == 0xe8 else 2)[0]
            calls.append({'va': hex(va), 'kind': 'direct' if raw[0] == 0xe8 else 'relocated-slot',
                          'target_or_slot': hex(target), 'return_pc': hex(following)})
    def reachable(origin, forbidden=None):
        reached, pending = set(), [origin]
        while pending:
            va = pending.pop()
            if va == forbidden or va in reached:
                continue
            reached.add(va)
            pending.extend(edges[va])
        return reached
    dominance = {hex(store): 0x495919a not in reachable(START, store) for store in STORES}
    require(all(dominance.values()), 'A final output store does not dominate local normal return')
    bound_dominates = 0x495916a not in reachable(START, 0x4959112)
    error_rejoins = 0x495919a in reachable(0x49591ad)
    require(bound_dominates and not error_rejoins, 'Index-bound error route can bypass the checked local contract')
    return rows, {'calls': calls, 'branches': branches, 'normal_return': '0x495919a',
                  'tail_store_dominance': dominance, 'fallthrough_outside_extent': boundary,
                  'index_bound_branch_dominates_last_imported_call': bound_dominates,
                  'index_ge_11_route_reaches_local_return': error_rejoins,
                  'limits': 'Calls are treated as normally returning. Exceptional entries, feasibility and full function closure are not established.'}


def collect(binary, output):
    binary, output = Path(binary), Path(output)
    require(not output.exists() and not output.is_symlink(), 'Output must be a new directory')
    before = binary.stat()
    data = binary.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Node94 identity mismatch')
    record = inspect_bytes(data)
    image = Image(data)
    body = image.read(START, END - START)[1]
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Authenticated selected body differs')
    environment = {**os.environ, 'LC_ALL': 'C'}
    version = subprocess.check_output(['objdump', '--version'], encoding='utf-8', env=environment).splitlines()[0]
    require(version.startswith('GNU '), 'GNU objdump is required')
    argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
            '--show-raw-insn', '--insn-width=16', '--adjust-vma=' + hex(START), 'slice.bin']
    with private_slice(body) as path:
        text = subprocess.check_output(argv, cwd=path.parent, encoding='utf-8', env=environment)
        rows, graph = native_rows(text, body)
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    require(signature(before) == signature(binary.stat()) and digest(binary) == SHA256,
            'Source changed during static collection')
    record['native'] = {'tool': version, 'argv': argv, 'rows': len(rows), 'bytes': len(body), **graph}
    record['native_input_binding'] = 'Owned510-byte mode0600 slice in0700 directory from the admitted complete byte snapshot; no native source-path reopen.'
    output.mkdir(parents=True, exist_ok=False)
    for name, value in {'helper.objdump.txt': text, 'instructions.json': json.dumps(rows, indent=2) + '\n',
                        'records.json': json.dumps(record, indent=2, sort_keys=True) + '\n'}.items():
        (output / name).write_text(value, encoding='utf-8', newline='\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({'body_bytes': collect(args.binary, args.output)['body']['bytes'],
                      'captured_binary_executed': False, 'component_gate_change': False}))
