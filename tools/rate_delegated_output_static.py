#!/usr/bin/env python3
"""RE-001: conditional used-output equations of Node94's 0x4258c00."""
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
from fde_extents import eh_frame_records, uleb

TARGET = 'artifacts/node/94/hl-node'
SIZE = 91774280
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x4258c00, 0x4259d02
BODY_SHA256 = '4262a27f04f513c5d0bafd1bd95c9ddbb81b803ca6ceeda71beaab9f99df8284'
FDE, CIE, LSDA = 0x12295cc, 0xfbdc2c, 0xb24d60
FAST_CALLS = (0x4258c42, 0x4258cc8, 0x4258d2a, 0x4258d58, 0x4258d80, 0x4258da0)
STORES = (0x4258dd9, 0x4258ddc, 0x4258de0)
SPLIT_CONTROLS = {
    0x4258cd3: '4c8b6c24300f840b0100004883fb060f850801000041bc0500000040b50131dbe905010000',
    0x4258de9: '31ed4989dceb0d4883c3f941bc0600000040b501',
    0x4259001: '41ffc44869fb600200004c01f7488db424a0000000ba600200004c8b3dbe4f510141ffd7664589a6321b0000488b4424404889442450488dbc24500a0000488db42438030000ba5802000041ffd7488d84248800000031c9488b5424684c89f64c8b6c24304889084c8b7c24504983ff020f845cfdffff4889b42490000000488954246848895c2428',
    0x4259a0b: '488b442478488b8c2490000000488908488b4c246848894808488b4c242848894810',
}
# Actual encoded pointer carriers, branch operands and ordinary-return routes.
CONTROLS = {
    0x4258c00: '55415741564155415453',
    0x4258c0a: '4881eca80c00004c898424980000004989f748897c2478488b1a48895424084c8b6208488dbc2498050000ba6002000048894c24104889ceff1598535101',
    0x4258c48: '4d8b37450fb7ae321b00004983fd0b722b48895c24404c89742430498b5f104883fb054c89642438736141bc0400000031ed4c8b6c2430e979010000498b5f10488d6b01488d045b4d8d24c64981c4281a00004c39ed7658',
    0x4258ca0: '488b4c2408488b411049894424100f1001410f110424488dbc24a0000000ba60020000488b742410ff1512535101e9b3000000',
    0x4258cf8: '498d86281a0000488d0c6d000000004801e9488d3cc848895c24284c89eb482b5c2428488d04dd00000000488d14404c89e6ff15b0535101488b4424080f1000410f110424488b40104989442410488dbc24a0000000ba60020000488b742410ff15825251014869742428600200004c01f64869fd600200004c01f74869d360020000488b5c2428ff155a535101',
    0x4258d86: '41ffc54869fb600200004c01f7488db424a0000000ba60020000ff153a525101664589ae321b0000498b5708b902000000488d4424504c89f64d89f54889084c8b7c24504983ff020f85a4020000488b4424784889304889500848895810e9440c0000',
    0x4259a2d: '4881c4a80c00005b415c415d415e415f5dc3',
    # Revisited actual caller: R9=input+0x38 aliases its outer output argument.
    0x4959067: '4c8d4b384c8d4318488d7c2418488d742430488d5424504c89f9e87afb8fff4c8b6b184c8b642418488b442420488b6c2428',
    0x4956e63: '488d7c2458488d742420488d9424b8020000e8a62100004869442468600200004803442458',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data, self.sections = data, sections(data)

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
        require(8 <= length <= 4096, 'Unsupported selected CFI record')
        return {'va': hex(va), 'file_offset': hex(offset), 'raw': self.read(va, length)[1].hex()}


def import_records(image):
    wanted = {0x576dfe0: (6, 'memcpy'), 0x576e0e0: (9, 'memmove')}
    symbols = next(s for s in image.sections if s['name'] == '.dynsym')
    strings = next(s for s in image.sections if s['name'] == '.dynstr')
    found = {}
    for s in image.sections:
        if s['type'] != 4:
            continue
        require(s['size'] % 24 == 0, 'Incomplete RELA section')
        for offset in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, offset)
            if slot not in wanted:
                continue
            require(slot not in found, 'Duplicate selected import relocation')
            index, kind = info >> 32, info & 0xffffffff
            require((index, kind, addend) == (wanted[slot][0], 6, 0), 'Selected import relocation changed')
            require((index + 1) * 24 <= symbols['size'], 'Selected dynamic symbol outside table')
            name_offset = struct.unpack_from('<I', image.data, symbols['offset'] + 24 * index)[0]
            require(name_offset < strings['size'], 'Selected symbol name outside string table')
            lo, hi = strings['offset'] + name_offset, strings['offset'] + strings['size']
            end = image.data.find(b'\0', lo, hi)
            require(end >= lo and bytes(image.data[lo:end]) == wanted[slot][1].encode('ascii'),
                    'Selected imported name changed')
            found[slot] = {'slot': hex(slot), 'symbol_index': index, 'symbol': wanted[slot][1],
                           'type': kind, 'addend': addend, 'file_offset': hex(offset),
                           'raw': bytes(image.data[offset:offset + 24]).hex()}
    require(set(found) == set(wanted), 'Missing selected import relocation')
    return [found[k] for k in sorted(found)]


def exception_rows(image):
    origin, header = image.read(LSDA, 1)
    section = next(s for s in image.sections if s['name'] == '.gcc_except_table')
    limit = section['offset'] + section['size']
    require(header == b'\xff' and image.data[origin + 1] == 0x9b, 'Selected LSDA encoding changed')
    delta, pos = uleb(image.data, origin + 2, limit)
    type_base = pos + delta
    require(image.data[pos] == 1, 'Selected call-site encoding is not ULEB128')
    length, pos = uleb(image.data, pos + 1, limit)
    end, rows = pos + length, []
    require(end <= limit, 'Selected call-site table outside section')
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(image.data, pos, end)
            values.append(value)
        a, n, landing, action = values
        rows.append({'start': hex(START + a), 'end': hex(START + a + n),
                     'landing_pad': hex(START + landing) if landing else None,
                     'action': action, 'raw_uleb_values': values})
    require(pos == end, 'Incomplete selected call-site table')
    require(hashlib.sha256(bytes(image.data[origin:end])).hexdigest()
            == '64debca9cb939bb9171c05e94fb97cdd42b918168ecd6b1db551803aeff89e29',
            'Selected raw LSDA call-site table changed')
    return {'va': hex(LSDA), 'file_offset': hex(origin), 'raw_through_call_sites':
            bytes(image.data[origin:end]).hex(), 'type_base_va': hex(LSDA + type_base - origin),
            'rows': rows, 'limits': 'Actions, types, personality behavior and exceptional reachability are not interpreted.'}


def inspect_bytes(data):
    """Below-digest seam for corruption controls on the actual admitted target."""
    image = Image(data)
    for va, expected in {**CONTROLS, **SPLIT_CONTROLS}.items():
        require(image.read(va, len(expected) // 2)[1].hex() == expected,
                f'Selected delegated operand/route changed at {va:#x}')
    cies, frames = eh_frame_records(data, image.sections)
    matches = [f for f in frames if f['start'] == START]
    require(len(matches) == 1 and matches[0] == {'fde': FDE, 'cie': CIE, 'start': START,
            'end': END, 'lsda': LSDA}, 'Selected helper FDE changed')
    cie = cies[CIE]
    require((cie['augmentation'], cie['code_align'], cie['data_align'], cie['fde_encoding'],
             cie['lsda_encoding'], cie['personality_slot']) == ('zPLR', 1, -8, 0x1b, 0x1b, 0x577a668),
            'Selected CIE profile changed')
    raw_fde, raw_cie = image.raw_record(FDE), image.raw_record(CIE)
    require(raw_fde['raw'] == '50000000a4b926002cf60203021100000483b78fff410e10420e18420e20420e28420e30410e38470ee01983078c068d058e048f03860203230e0e38410e30420e28420e20420e18420e10410e08410ee0190000'
            and raw_cie['raw'] == '1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000',
            'Selected raw CFI changed')
    offset, body = image.read(START, END - START)
    imports, lsda = import_records(image), exception_rows(image)
    calls = []
    for va in FAST_CALLS:
        raw = image.read(va, 6)[1]
        require(raw[:2] == b'\xff\x15', 'Selected ordinary-route call opcode changed')
        slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        require(slot == (0x576e0e0 if va in (0x4258d2a, 0x4258d80) else 0x576dfe0),
                'Selected ordinary-route import slot changed')
        lookup = va + 5
        owners = [i for i, row in enumerate(lsda['rows'])
                  if int(row['start'], 16) <= lookup < int(row['end'], 16)]
        require(len(owners) <= 1, 'Overlapping selected call-site ownership')
        calls.append({'va': hex(va), 'slot': hex(slot), 'return_pc': hex(va + 6),
                      'unwind_lookup_pc': hex(lookup), 'lsda_row_index': owners[0] if owners else None})
    return {'schema': 're001-rate-delegated-output-94/2', 'source_base': '1f8c67c63ca4794c9689235471c60297f8a5c985',
            'reference_revision': '999556f6e0a474b8312db96ec3149e1c44e97c23',
            'target': {'release': 94, 'bytes': SIZE, 'sha256': SHA256},
            'body': {'start': hex(START), 'end': hex(END), 'bytes': len(body), 'file_offset': hex(offset),
                     'sha256': hashlib.sha256(body).hexdigest()},
            'fde': raw_fde, 'cie': {**cie, 'raw_record': raw_cie},
            'lsda': lsda, 'ordinary_route_calls': calls, 'imports': imports,
            'no_split_contract': {
                'count_load': {'va': '0x4258c4b', 'width_bits': 16, 'base_register': 'R14', 'offset': 0x1b32},
                'count_bound': {'va': '0x4258c53', 'unsigned_upper_exclusive': image.read(0x4258c56, 1)[1][0],
                                'taken_jb': '0x4258c57 ->0x4258c84'},
                'index_load': {'va': '0x4258c84', 'width_bits': 64, 'base_register': 'R15', 'offset': 16},
                'insertion_partition': {'va': '0x4258c9b', 'condition': '(index+1) modulo2**64 <= loaded_count',
                                        'taken': '0x4258cf8', 'fallthrough': '0x4258ca0'},
                'last_copy': {'va': '0x4258da0', 'base': 'R14', 'index': 'RBX',
                              'scale': struct.unpack('<i', image.read(0x4258d8c, 4)[1])[0],
                              'length': struct.unpack('<I', image.read(0x4258d9c, 4)[1])[0],
                              'source': 'own frame+0xa0'},
                'output': [{'va': hex(va), 'offset': off, 'width': 8, 'value': value}
                           for va, off, value in zip(STORES, (0, 8, 16), ('same R14 base', 'load64[R15+8] at0x4258dae', 'same RBX index'))],
                'used_address': '(output0 +608*output16) modulo2**64 equals the last-copy destination argument',
                'conditions': ['Selected loaded count is below11, after the initial opaque import',
                               'Imports return normally and preserve callee-saved registers',
                               'ALL memory effects, including explicit pointer stores and imported copy/move effects, preserve the listed live protected frame values except their shown intended definitions',
                               'Ordinary local sequential control flow; no exceptional/external entry claim'],
                'frame_proof_domain': {
                    'basis': 'SP means the own frame pointer after the encoded SUB RSP,0xca8',
                    'allocation_bytes': struct.unpack('<I', image.read(0x4258c0d, 4)[1])[0],
                    'protected_live_words': [
                        {'offset': 8, 'width': 8, 'value': 'saved incoming RDX', 'from': '0x4258c24', 'through': '0x4258d30'},
                        {'offset': 16, 'width': 8, 'value': 'saved incoming RCX', 'from': '0x4258c3a', 'through': '0x4258d53'},
                        {'offset': 40, 'width': 8, 'value': 'saved original RBX index on shift route', 'from': '0x4258d0e', 'through': '0x4258d7b'},
                        {'offset': 120, 'width': 8, 'value': 'saved entry output RDI', 'from': '0x4258c1c', 'through': '0x4258dd4'}],
                    'saved_register_and_return_area': {'start': 'SP+0xca8', 'end': 'SP+0xce0',
                                                      'basis': 'six encoded pushes and one return-address word; protected through their restores/RET'},
                    'intended_local_buffers_allowed': ['SP+0x598..SP+0x7f8', 'SP+0xa0..SP+0x300'],
                    'qualification': 'Unverified proof-domain assumption for all writes, not an observed property of actual runtime inputs. No blanket argument disjointness.'},
                'index_domain': 'Independent qword; not bounded by the loaded u16 count condition',
                'alias': 'The already observed incoming R9/output alias remains unclosed; no disjoint-argument assumption'},
            'revisited_callers': [{'va': hex(va), 'bytes': len(CONTROLS[va]) // 2,
                                  'file_offset': hex(image.read(va, len(CONTROLS[va]) // 2)[0]),
                                  'raw': CONTROLS[va]} for va in (0x4959067, 0x4956e63)],
            'limits': ['Split/loop ordinary used-output equation is conditional, not full split semantics or termination', 'No valid object, pointer range, lifetime, Rust/private type or actual copy effect',
                       'No blanket alias, exception, full-helper closure, target execution, reconstruction denominator or completed gate']}


@contextmanager
def private_slice(body):
    expected = hashlib.sha256(body).hexdigest()
    with tempfile.TemporaryDirectory(prefix='rate-output-') as directory:
        parent = Path(directory)
        require(stat.S_IMODE(parent.stat().st_mode) == 0o700, 'Native directory is not private')
        path = parent / 'slice.bin'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
        before = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and digest(path) == expected, 'Native slice differs from owned admitted bytes')
        yield path
        require(identity(before) == identity(path.lstat()) and digest(path) == expected,
                'Owned native slice changed')


def split_output_proof(rows, body, edges):
    """All finite ordinary-return cutsets, plus width-aware explicit-store provenance."""
    for va, expected in SPLIT_CONTROLS.items():
        require(body[va - START:va - START + len(expected) // 2].hex() == expected,
                'Split output operand/definition changed')
    def reach(origin, blocked=frozenset()):
        visited, pending = set(), [origin]
        while pending:
            va = pending.pop()
            if va in visited or va in blocked:
                continue
            visited.add(va)
            pending.extend(edges[va])
        return visited
    origin, ret = 0x4258c59, 0x4259a3e
    selected = reach(origin)
    require(ret in selected, 'Split ordinary return is not reachable in local graph')
    cutsets = {'first_split_insertion_copy': [0x4259022],
               'output0_stores': [0x4258dd9, 0x4259a18],
               'output8_stores': [0x4258ddc, 0x4259a20],
               'output16_stores': [0x4258de0, 0x4259a29]}
    require(all(ret not in reach(origin, set(sites)) for sites in cutsets.values()),
            'A split normal return bypasses the copy/output cutset')
    saves = (0x4259078, 0x4259080, 0x4259085)
    require(all(0x4259a0b not in reach(origin, {site}) for site in saves),
            'Alternate return can bypass a saved result definition')
    require(0x4258dd4 not in reach(saves[0]) and 0x4259a0b not in reach(0x4258dd4),
            'Split direct and saved return paths unexpectedly rejoin')
    widths = {'BYTE': 1, 'WORD': 2, 'DWORD': 4, 'QWORD': 8, 'XMMWORD': 16}
    writes = []
    for row in rows:
        assembly = row['assembly'].split('#', 1)[0].strip()
        match = re.match(r'(\S+)\s+(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR \[([^]]+)\](?:,|$)', assembly)
        if not match:
            continue
        mnemonic, width, address = match[1], widths[match[2]], match[3]
        if mnemonic in ('cmp', 'test', 'nop', 'call', 'jmp'):
            continue
        require(mnemonic in ('mov', 'movups', 'movaps', 'inc'), 'Unclassified first-memory-operand effect')
        own = re.fullmatch(r'rsp(?:\+0x([0-9a-f]+))?', address)
        offset = (int(own[1], 16) if own[1] else 0) if own else None
        writes.append({'va': hex(row['va']), 'raw': row['raw'], 'assembly': row['assembly'],
                       'width': width, 'address': address, 'sp_offset': offset,
                       'split_normal_graph': row['va'] in selected})
    protected = ((0x28, 0x30), (0x68, 0x70), (0x78, 0x80), (0x90, 0x98))
    overlap = [w for w in writes if w['split_normal_graph'] and int(w['va'], 16) >= saves[0]
               and w['sp_offset'] is not None and any(w['sp_offset'] < hi and lo < w['sp_offset'] + w['width']
                                                    for lo, hi in protected)]
    require([int(w['va'], 16) for w in overlap] == list(saves),
            'An explicit own-frame write overlaps the saved result/output slots')
    return {'count_branch': 'loaded u16 count>=11 successor0x4258c59; first import precedes count load',
            'initial_index_load': 'independent qword at0x4258c63; not bounded by count',
            'initial_partition_before_allocation': [
                {'index': 'unsigned<5', 'pivot_register': 4, 'low_byte_flag': 0, 'adjusted_index': 'index'},
                {'index': '==5', 'pivot_register': 5, 'low_byte_flag': 0, 'adjusted_index': '5'},
                {'index': '==6', 'pivot_register': 5, 'low_byte_flag': 1, 'adjusted_index': '0'},
                {'index': 'unsigned>=7', 'pivot_register': 6, 'low_byte_flag': 1, 'adjusted_index': 'index-7 modulo2**64'}],
            'later_count': 'Reload0x4258e31 follows opaque allocation and pointer stores; not equated to initialcount',
            'first_insertion_copy': {'va': '0x4259022', 'target_register': 'R15', 'loaded_slot_va': '0x425901b',
                                     'slot': '0x576dfe0', 'base': 'actual R14 at call', 'index': 'actual RBX at call',
                                     'scale': 608, 'length': 608, 'destination': 'R14+608*RBX modulo2**64'},
            'all_return_cutsets': {name: [hex(v) for v in sites] for name, sites in cutsets.items()},
            'raw_tag': 'qword loaded0x4259069, comparedwith2; no private type or feasible-tag claim',
            'direct_tail': {'branch': 'rawtag==2 at0x4259072 ->0x4258dd4',
                            'values': ['RSI=copy-baseR14', 'RDX loaded0x4259059', 'RBX=copy-index']},
            'saved_tail': {'branch': 'rawtag!=2', 'words': [
                {'save': '0x4259078', 'offset': 144, 'width': 8, 'value': 'copy-baseR14 throughRSI', 'reload': '0x4259a10', 'output_store': '0x4259a18', 'output_offset': 0},
                {'save': '0x4259080', 'offset': 104, 'width': 8, 'value': 'middleRDX', 'reload': '0x4259a1b', 'output_store': '0x4259a20', 'output_offset': 8},
                {'save': '0x4259085', 'offset': 40, 'width': 8, 'value': 'copy-indexRBX', 'reload': '0x4259a24', 'output_store': '0x4259a29', 'output_offset': 16}]},
            'equation': '(output0+608*output16) modulo2**64 equals first split insertion copy0x4259022 destination argument',
            'proof_domain': ['Finite ordinary-return path entered through count>=11 successor; no termination or EH-entry assertion',
                             'R14/RBX preserved by imports between0x4259022 and directwriteback/result saves',
                             'ALL memory effects including explicit indirect stores, imported effects AND final output stores preserve saved entry-outputSP78 and saved-register/RET area until use, except intendeddefinitions',
                             'After their definitions, ALL effects preserve live SP90/SP68/SP28 resultwords through respective reloads; intended other buffers remain writable',
                             'These are unverified runtime premises; known incomingR9/outputalias remains explicit; no blanket argument disjointness'],
            'scope': {'ordinary_reachable_instructions': len(selected), 'normal_return': hex(ret),
                      'explicit_memory_writes_full_context': len(writes),
                      'explicit_memory_writes_on_split_normal_graph': sum(w['split_normal_graph'] for w in writes)},
            'explicit_memory_writes': writes,
            'implicit_stack_effects': 'Six prologue pushes and call return-address writes; ABI/callee memory effects remain conditional',
            'limits': ['Actual copy-base/index at0x4259022 are not equated to entry values without further effect/spill premises',
                       'No index/capacity/type, successful copy, live object, lifetime, all-helper effects or exception closure',
                       'Caller linkage reuses prior conditional output-word consumption; no new whole-caller qualification']}


def native_rows(text, body):
    rows, cursor = [], START
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
        if not match:
            continue
        va, raw, assembly = int(match[1], 16), bytes.fromhex(match[2]), match[3]
        require(va == cursor and 1 <= len(raw) <= 15 and va + len(raw) <= END
                and raw == body[va - START:va - START + len(raw)] and '(bad)' not in assembly
                and not assembly.startswith('.byte'), 'Native rows do not bind complete instruction bytes')
        rows.append({'va': va, 'raw': raw.hex(), 'assembly': assembly})
        cursor += len(raw)
    require(cursor == END and len(rows) == 866, 'Native instruction extent/census changed')
    starts = {r['va'] for r in rows}
    edges, branches, boundary = {}, [], []
    for row in rows:
        va, raw = row['va'], bytes.fromhex(row['raw'])
        mnemonic, following = row['assembly'].split()[0], va + len(raw)
        if mnemonic.startswith('j'):
            require((len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f))
                    or (len(raw) == 5 and raw[0] == 0xe9)
                    or (len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f),
                    'Unsupported native branch form')
            displacement = struct.unpack('<b' if len(raw) == 2 else '<i', raw[-1:] if len(raw) == 2 else raw[-4:])[0]
            target = following + displacement
            require(target in starts and target == int(row['assembly'].split()[1], 16), 'Native branch target is not an admitted boundary')
            edges[va] = [target] + ([] if mnemonic == 'jmp' else [following])
            branches.append({'va': hex(va), 'target': hex(target)})
        elif mnemonic in ('ret', 'ud2'):
            edges[va] = []
        else:
            edges[va] = [following] if following in starts else []
            if following == END:
                boundary.append({'va': hex(va), 'fallthrough': hex(following), 'assembly': row['assembly']})
    require([r['va'] for r in rows if r['assembly'] == 'ret'] == [0x4259a3e], 'Local return changed')
    # This actual store/load/compare has no intervening call: constant2 selects fallthrough.
    by_va = {r['va']: r for r in rows}
    require([by_va[v]['raw'] for v in (0x4258db2, 0x4258dc2, 0x4258dc5, 0x4258dca)]
            == ['b902000000', '488908', '4c8b7c2450', '4983ff02'], 'Local constant-tag proof changed')
    require(edges[0x4258dce] == [0x4259078, 0x4258dd4], 'Constant-tag route changed')
    selected_edges = {**edges, 0x4258dce: [0x4258dd4]}

    def reach(origin, forbidden=None):
        visited, pending = set(), [origin]
        while pending:
            va = pending.pop()
            if va in visited or va == forbidden:
                continue
            visited.add(va)
            pending.extend(selected_edges[va])
        return visited

    selected = reach(0x4258c84)
    require(0x4259a3e in selected and all(0x4258c84 <= v < 0x4258de9 or 0x4259a2d <= v < 0x4259a3f for v in selected),
            'Selected route escapes the two insertion paths and return tail')
    required = (0x4258d86, 0x4258da0, *STORES)
    for origin in (0x4258ca0, 0x4258cf8):
        require(0x4259a3e in reach(origin) and all(0x4259a3e not in reach(origin, v) for v in required),
                'An insertion route bypasses the common copy/output contract')
    require(all(selected_edges[v] or v == 0x4259a3e for v in selected), 'Selected route has another terminal')
    active, done = set(), set()
    def acyclic(va):
        require(va not in active, 'Selected ordinary route contains a cycle')
        if va in done:
            return
        active.add(va)
        for nxt in selected_edges[va]:
            acyclic(nxt)
        active.remove(va)
        done.add(va)
    acyclic(0x4258c84)
    require([r['va'] for r in rows if r['va'] in selected and r['assembly'].startswith('call ')]
            == list(FAST_CALLS[1:]), 'Selected insertion call set changed')
    split = split_output_proof(rows, body, edges)
    return rows, {'branches': branches, 'selected_route_entry': '0x4258c84',
                  'partition_routes': ['0x4258ca0', '0x4258cf8'],
                  'both_routes_pass_common_sites_before_return': [hex(v) for v in required],
                  'constant2_branch_fallthrough': '0x4258dce ->0x4258dd4',
                  'selected_instruction_count': len(selected), 'selected_only_terminal': '0x4259a3e',
                  'fallthrough_outside_full_extent': boundary,
                  'split_output': split,
                  'limits': 'Calls have ordinary-return edges. Local no-split constant-tag and split saved-result proofs require explicit all-write frame conditions; no termination, exceptional or full object/helper proof.'}


def collect(binary, output):
    binary, output = Path(binary), Path(output)
    require(not output.exists() and not output.is_symlink(), 'Output must be a new directory')
    before = binary.stat()
    data = binary.read_bytes()
    require(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Node94 identity mismatch')
    record = inspect_bytes(data)
    body = Image(data).read(START, END - START)[1]
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, 'Selected body digest changed')
    env = {**os.environ, 'LC_ALL': 'C'}
    version = subprocess.check_output(['objdump', '--version'], encoding='utf-8', env=env).splitlines()[0]
    require(version.startswith('GNU '), 'GNU objdump is required')
    argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel', '--show-raw-insn',
            '--insn-width=16', '--adjust-vma=' + hex(START), 'slice.bin']
    with private_slice(body) as path:
        text = subprocess.check_output(argv, cwd=path.parent, encoding='utf-8', env=env)
        rows, graph = native_rows(text, body)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    require(identity(before) == identity(binary.stat()) and digest(binary) == SHA256, 'Source changed before output publication')
    record['native'] = {'tool': version, 'argv': argv, 'rows': len(rows), 'bytes': len(body), **graph}
    record['native_input_binding'] = 'Owned4354B mode0600 slice in0700 directory from authenticated full input bytes; native tools never reopen the source path.'
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
    record = collect(args.binary, args.output)
    print(json.dumps({'body_bytes': record['body']['bytes'], 'no_split_selected_instructions': record['native']['selected_instruction_count'],
                      'split_reachable_instructions': record['native']['split_output']['scope']['ordinary_reachable_instructions'],
                      'target_executed': False, 'component_gate_change': False}))
