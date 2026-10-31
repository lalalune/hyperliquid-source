#!/usr/bin/env python3
"""Derive one used integer-result projection from node94 bytes, without running it."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END = 0x151cba0, 0x151cca5
USE_START, USE_END = 0x46ced2c, 0x46ced5a
MASK64, MASK32 = (1 << 64) - 1, (1 << 32) - 1
MIN64, MAX64 = -(1 << 63), (1 << 63) - 1
SLOTS = {0x576e048: 0x157aa10, 0x576e470: 0x157a9f0, 0x576e890: 0x151f6f0,
         0x576e8a0: START, 0x577a668: 0x4f14ca0}
DIRECTS = {0x151cbaf: 0x4ee3800, 0x151cbdb: 0x4ee3730}
INDIRECTS = {0x151cc42: 0x576e890, 0x151cc92: 0x576e048, 0x151cc9f: 0x576e470,
             0x46ced31: 0x576e8a0}
# Structural transfer operands; constants are separately extracted, not assumed.
ANCHORS = {0x151cbaa: '4889fb', 0x151cbe0: '4c8b7424088b6c2410',
           0x151cbf9: '4c89f048f7e94889d0', 0x151cc0a: '4801c2',
           0x151cc14: '4929c64d89f7', 0x151cc1e: '498d0417',
           0x151cc37: '4c01fa', 0x151cc40: '89d7', 0x151cc48: '85c0',
           0x151cc53: '4501f7', 0x151cc5f: '4889d84883c4385b415e415f5dc3'}


def need(ok, message):
    if not ok: raise ValueError(message)


def authenticate(data):
    need(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Node94 identity mismatch')


def read_va(data, secs, va, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    need(size >= 0 and len(matches) == 1, 'Expected one bounded file mapping')
    offset = matches[0]['offset'] + va - matches[0]['address']
    return offset, data[offset:offset + size]


def extract(body, consumer):
    """Extract arithmetic/store operands; counterfactual tests call this below identity."""
    def b(va, n): return body[va - START:va - START + n]
    def u(va, n): return consumer[va - USE_START:va - USE_START + n]
    for va, raw in ANCHORS.items():
        need(b(va, len(bytes.fromhex(raw))).hex() == raw, f'Structural value transfer changed at {va:#x}')
    for va, raw in [(0x151cbef, '48b9'), (0x151cc02, '48c1e8'), (0x151cc06, '48c1fa'),
                    (0x151cc0d, '4869c2'), (0x151cc1a, '49c1ff'), (0x151cc22, '4805'),
                    (0x151cc28, '48b9'), (0x151cc3a, '81c2'), (0x151cc4c, '4181e7')]:
        need(b(va, len(bytes.fromhex(raw))).hex() == raw, f'Arithmetic operation changed at {va:#x}')
    need(b(0x151cbe9, 3) == b'\x83\x3c\x24', 'Raw status comparison changed')
    need(b(0x151cc32, 3) == b'\x48\x39\xc8', 'Unsigned index guard operands changed')
    need(b(0x151cc56, 2) == b'\x89\x03' and b(0x151cc58, 3) == b'\x44\x89\x7b'
         and b(0x151cc5c, 2) == b'\x89\x6b', 'Three DWORD store operations changed')
    need(u(USE_START, 4) == b'\x48\x8d\x7c\x24' and u(0x46ced37, 3) == b'\x8b\x44\x24'
         and u(0x46ced3b, 3) == b'\x89\x84\x24' and u(0x46ced42, 3) == b'\xc7\x84\x24'
         and u(0x46ced4d, 4) == b'\x48\x8b\x44\x24' and u(0x46ced52, 4) == b'\x48\x89\x84\x24', 'Actual consumer loads/stores changed')
    base = u(USE_START + 4, 1)[0]
    return {'multiplier': struct.unpack('<Q', b(0x151cbf1, 8))[0],
            'high_shift': b(0x151cc09, 1)[0], 'quotient_sign_shift': b(0x151cc05, 1)[0],
            'divisor': struct.unpack('<i', b(0x151cc10, 4))[0],
            'remainder_sign_shift': b(0x151cc1d, 1)[0],
            'repair_mask': struct.unpack('<I', b(0x151cc4f, 4))[0],
            'index_guard_add': struct.unpack('<i', b(0x151cc24, 4))[0],
            'index_threshold': struct.unpack('<Q', b(0x151cc2a, 8))[0],
            'index_offset': struct.unpack('<I', b(0x151cc3c, 4))[0],
            'excluded_status': b(0x151cbec, 1)[0],
            'output_offsets': [0, b(0x151cc5b, 1)[0], b(0x151cc5e, 1)[0]],
            'consumer': {'buffer': base, 'first_load': u(0x46ced3a, 1)[0] - base,
                         'pair_load': u(0x46ced51, 1)[0] - base,
                         'first_store': struct.unpack('<I', u(0x46ced3e, 4))[0],
                         'pair_store': struct.unpack('<I', u(0x46ced56, 4))[0],
                         'tag_store': struct.unpack('<I', u(0x46ced45, 4))[0],
                         'tag': struct.unpack('<I', u(0x46ced49, 4))[0]}}


def projection(s, p):
    """Closed integer equations from the observed transfers, not a CPU interpreter."""
    need(MIN64 <= s <= MAX64, 'Signed64 input outside stated domain')
    high = (s * p['multiplier']) >> 64
    q = (high >> p['high_shift']) + ((high & MASK64) >> p['quotient_sign_shift'])
    r = s - q * p['divisor']
    sign = r >> p['remainder_sign_shift']
    field = ((r & MASK32) + (sign & p['repair_mask'])) & MASK32
    index = q + sign
    return {'truncating_quotient': q, 'signed_remainder': r, 'floor_quotient': index,
            'second_field': field, 'index_guard': ((index + p['index_guard_add']) & MASK64) >= p['index_threshold'],
            'index_argument': (index + p['index_offset']) & MASK32}


def prove(p):
    m, d, shift = p['multiplier'], p['divisor'], p['high_shift']
    k = 64 + shift; delta = m * d - (1 << k)
    need(0 < m < (1 << 63) and m % 2 == 1 and 0 < shift < 64 and 0 < d < (1 << 32), 'Multiplier/divisor proof domain changed')
    need(p['quotient_sign_shift'] == p['remainder_sign_shift'] == 63, 'Observed sign repairs changed')
    need(0 <= delta and (1 << 63) * delta < (1 << k), 'Positive approximation bound fails')
    need(p['repair_mask'] == d, 'Remainder repair differs from divisor')
    need(p['index_threshold'] == (1 << 64) - (1 << 32)
         and p['index_guard_add'] == p['index_offset'] - (1 << 31), 'Index-bound identity changed')
    q_bound = ((1 << 63) + d - 1) // d
    need(q_bound + abs(p['index_guard_add']) < (1 << 63), 'Index guard may wrap outside its signed proof')
    return {'domain': {'min': MIN64, 'max': MAX64}, 'total_shift': k, 'delta': delta,
            'max_magnitude_times_delta': (1 << 63) * delta, 'strict_bound': 1 << k,
            'multiplier_odd': True,
            'observed_quotient_expression': '(signed_high64(s*M) >> high_shift) + (unsigned64(signed_high64(s*M)) >> quotient_sign_shift)',
            'observed_field_expression': 'low32(low32(s-q*D) + ((s-q*D) SAR remainder_sign_shift AND repair_mask))',
            'multiply_lemma': 'Signed64 times positive signed64 fits signed128; signed_high64 is floor(product/2^64). Two arithmetic shifts compose to floor(product/2^K).',
            'positive_lemma': 'For 0<=n<=2^63, 0<=n*M/2^K-n/D<1/D; fractional parts of n/D are multiples of1/D, so floors agree.',
            'negative_lemma': 'For 0<n<=2^63<2^K, oddM implies n*M not divisible by2^K. Signed-high shift plus unsigned-high sign bit is ceil(-n*M/2^K)=-floor(n/D). Zero separately gives0.',
            'product_lemma': 'The truncating quotient timesD lies within signed64; subtraction is exact and |remainder|<D.',
            'repair_lemma': 'SAR63 yields0 or-1; adding its AND-withD produces Euclidean remainder in[0,D). Low32 arithmetic preserves it because D<2^32.',
            'index_guard_lemma': 'No signed64 overflow in floor_quotient+guard_add; unsigned threshold is equivalent to signed32 containment of floor_quotient+index_offset.',
            'second_field_identity': 's mod D (Euclidean)',
            'normal_return_conditions': ['raw previous-helper status != excluded_status',
                                         'index guard passes', 'opaque index-callee EAX !=0',
                                         'normal calls/valid regions/native ABI and alias conditions hold']}


def validate(p):
    proof = prove(p)
    need((p['multiplier'], p['divisor'], p['high_shift'], p['index_offset'], p['excluded_status']) ==
         (0x1845c8a0ce512957, 86400, 13, 0xaf93b, 1), 'Target projection constants changed')
    need(p['output_offsets'] == [0, 4, 8], 'Observed output field placement changed')
    need(p['consumer'] == {'buffer': 0x60, 'first_load': 0, 'pair_load': 4,
                           'first_store': 0xbc, 'pair_store': 0xb4, 'tag_store': 0xb0, 'tag': 1}, 'Used consumer permutation changed')
    return proof


def frame_record(data, secs, address):
    _, head = read_va(data, secs, address, 4); length = struct.unpack('<I', head)[0] + 4
    need(8 <= length < 4096, 'Selected CFI record size changed')
    offset, raw = read_va(data, secs, address, length)
    return {'va': hex(address), 'file_offset': hex(offset), 'raw': raw.hex()}


def inspect(data):
    secs = sections(data); cies, fdes = eh_frame_records(data, secs)
    records = {}
    for name, start, end, fde_va, cie_va in [('helper', START, END, 0xcf6258, 0xce1518),
                                           ('caller_context', 0x46cea60, 0x46cf026, 0x127e83c, 0xfbdc2c)]:
        found = [f for f in fdes if f['start'] == start]
        need(len(found) == 1 and (found[0]['end'], found[0]['fde'], found[0]['cie']) == (end, fde_va, cie_va), 'Selected FDE binding changed')
        frame = frame_record(data, secs, fde_va); raw = bytes.fromhex(frame['raw'])
        need((fde_va + 4 - struct.unpack_from('<I', raw, 4)[0], fde_va + 8 + struct.unpack_from('<i', raw, 8)[0], struct.unpack_from('<i', raw, 12)[0]) == (cie_va, start, end - start), 'Independent CFI arithmetic differs')
        cie = cies[cie_va]
        need((cie['code_align'], cie['data_align'], cie['fde_encoding']) == (1, -8, 0x1b), 'CIE transfer profile changed')
        expected = ('zR', None, None) if name == 'helper' else ('zPLR', 0x1b, 0x577a668)
        need((cie['augmentation'], cie['lsda_encoding'], cie['personality_slot']) == expected, 'CIE personality/LSDA profile changed')
        need(found[0]['lsda'] == (None if name == 'helper' else 0xb6ac1c), 'LSDA binding changed')
        offset, raw_body = read_va(data, secs, start, end - start)
        records[name] = {'start': hex(start), 'end': hex(end), 'fde': frame, 'cie': {**cie, 'record': frame_record(data, secs, cie_va)},
                         'lsda': hex(found[0]['lsda']) if found[0]['lsda'] else None,
                         'body_sha256': hashlib.sha256(raw_body).hexdigest(), 'file_offset': hex(offset)}
    _, body = read_va(data, secs, START, END - START)
    _, consumer = read_va(data, secs, USE_START, USE_END - USE_START)
    p = extract(body, consumer); proof = validate(p)
    relas = {}
    for s in secs:
        if s['type'] != 4: continue
        for offset in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot not in SLOTS: continue
            need(slot not in relas and info == 8 and addend == SLOTS[slot], 'Selected RELATIVE binding changed')
            relas[slot] = {'slot': hex(slot), 'type': 8, 'addend': hex(addend), 'file_offset': hex(offset), 'raw': data[offset:offset + 24].hex()}
    need(set(relas) == set(SLOTS), 'Missing selected RELA')
    return {'schema': 're009-result-projection94/1', 'base': '1f8c67c63ca4794c9689235471c60297f8a5c985',
            'target': {'sha256': SHA256, 'bytes': SIZE, 'release': 94}, 'frames': records,
            'operands': p, 'proof': proof, 'relocations': [relas[k] for k in sorted(relas)],
            'scope': {'helper_bytes': 261, 'caller_context_bytes': 46, 'total_selected': 307,
                      'prior_521_prefix': 64, 'new_helper_tail': 197,
                      'credit': '#521 clock-prefix attribution excluded; #1019 caller bytes reused as actual consumer.'},
            'output': {'direct_writes': ['0x151cc56: opaque EAX -> DWORD0', '0x151cc58: Euclidean remainder -> DWORD1', '0x151cc5c: retained raw DWORD -> DWORD2'],
                       'direct_destination_loads': [], 'consumer_words': ['numeric1', 'DWORD1', 'DWORD2', 'DWORD0']},
            'limits': ['Conditional on normal calls, native ABI/callee-save/frame preservation, valid live distinct regions and no alias/concurrent destination or frame clobber.',
                       'No clock units, calendar internals, original Rust layout or filesystem effects inferred.',
                       'Raw failure arms and final-call boundary retained; no no-unwind/no-return or runtime success claim.',
                       'Caller full body/LSDA are metadata context only here, not newly decoded or re-claimed.'],
            'captured_target_executed': False, 'gate_changes_requested': False}


def native(raw, start):
    with tempfile.TemporaryDirectory(prefix='result-native-') as private:
        path = Path(private) / 'code.bin'; path.write_bytes(raw); path.chmod(0o400)
        text = subprocess.check_output(['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                                        '--insn-width=16', '--adjust-vma=' + hex(start), str(path)], text=True)
        need(path.read_bytes() == raw, 'Private native slice changed')
    rows = []; cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9.]*)\s*(.*)$', line)
        if not match: continue
        pc = int(match[1], 16); encoded = bytes.fromhex(match[2])
        need(pc == cursor and raw[pc - start:pc - start + len(encoded)] == encoded, 'Native selected-byte coverage differs')
        rows.append({'va': pc, 'raw': encoded.hex(), 'op': match[3], 'operand': match[4]}); cursor += len(encoded)
    need(cursor == start + len(raw), 'Native span incomplete')
    return text.replace(str(path), '<authenticated-result-slice>'), rows


def bind_native(helper, caller):
    boundaries = {r['va'] for r in helper}; calls = []; branches = []; edges = {}
    for r in helper + caller:
        pc = r['va']; raw = bytes.fromhex(r['raw']); after = pc + len(raw)
        if r['op'] == 'call':
            if raw[0] == 0xe8:
                target = pc + 5 + struct.unpack_from('<i', raw, 1)[0]
                need(DIRECTS.get(pc) == target and int(r['operand'].split()[0], 16) == target, 'Observed direct call changed')
                calls.append({'va': hex(pc), 'kind': 'direct', 'target': hex(target)})
            else:
                need(raw[:2] == b'\xff\x15', 'Unexpected indirect call')
                slot = pc + 6 + struct.unpack_from('<i', raw, 2)[0]
                parsed = re.search(r'#\s*(?:0x)?([0-9a-f]+)', r['operand'])
                need(INDIRECTS.get(pc) == slot and parsed and int(parsed[1], 16) == slot, 'Observed indirect call changed')
                calls.append({'va': hex(pc), 'slot': hex(slot), 'relative_target': hex(SLOTS[slot])})
        if pc >= USE_START: continue
        if r['op'].startswith('j'):
            target = after + struct.unpack('<b', raw[-1:])[0]
            need(target in boundaries and target == int(r['operand'].split()[0], 16), 'Branch not at validated native boundary')
            branches.append({'va': hex(pc), 'op': r['op'], 'target': hex(target), 'fallthrough': hex(after)})
            edges[pc] = [target, after]
        elif r['op'] == 'ret' or after == END: edges[pc] = []
        else: edges[pc] = [after]
    need({int(c['va'], 16) for c in calls} == set(DIRECTS) | set(INDIRECTS), 'Call census changed')
    need([(r['va'], r['op'], r['target']) for r in branches] == [('0x151cbed', 'je', '0x151cc6d'), ('0x151cc35', 'jb', '0x151cc98'), ('0x151cc4a', 'je', '0x151cc98')], 'Numeric failure guards changed')
    returns = [r['va'] for r in helper if r['op'] == 'ret']; need(returns == [0x151cc6c], 'Normal return census changed')
    stores = [r['va'] for r in helper if 'PTR [rbx' in r['operand']]
    need(stores == [0x151cc56, 0x151cc58, 0x151cc5c] and all(next(r for r in helper if r['va'] == p)['operand'].startswith('DWORD PTR [rbx') for p in stores), 'Direct destination memory access changed')
    def reaches_return(forbidden):
        seen = set(); todo = [START]
        while todo:
            pc = todo.pop()
            if pc == forbidden or pc in seen: continue
            seen.add(pc); todo.extend(edges[pc])
        return 0x151cc6c in seen
    need(not any(reaches_return(p) for p in stores), 'A field store no longer dominates the local normal return')
    return {'helper_instructions': len(helper), 'consumer_instructions': len(caller), 'total_instructions': len(helper) + len(caller),
            'calls': calls, 'branches': branches, 'normal_return': '0x151cc6c',
            'direct_destination_references': [hex(x) for x in stores], 'all_three_stores_dominate_local_return': True,
            'limits': 'Intraprocedural normal-return graph only; error calls may not return or may leave the selected FDE. No transitive no-read/no-clobber guarantee.'}


def collect(binary, output):
    output = Path(output)
    if output.exists(): raise FileExistsError('Output must be new')
    version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
    need('GNU' in version, 'GNU objdump required')
    with Path(binary).open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        authenticate(data); record = inspect(data); secs = sections(data)
        _, body = read_va(data, secs, START, END - START); _, consumer = read_va(data, secs, USE_START, USE_END - USE_START)
        helper_text, helper_rows = native(body, START); caller_text, caller_rows = native(consumer, USE_START)
        record['native'] = bind_native(helper_rows, caller_rows); authenticate(data)
    record['native_version'] = version
    record['native_input_binding'] = 'Only two private authenticated raw spans (261+46 bytes); native tool never reopens ELF pathname.'
    output.mkdir(parents=True, exist_ok=False)
    for name, text in [('helper.objdump.txt', helper_text), ('consumer.objdump.txt', caller_text),
                       ('records.json', json.dumps(record, sort_keys=True, indent=2) + '\n')]:
        (output / name).write_text(text, encoding='utf-8', newline='\n')
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); result = collect(args.binary, args.output)
    print(json.dumps({'scope': result['scope'], 'domain': result['proof']['domain'], 'delta': result['proof']['delta']}, sort_keys=True))


if __name__ == '__main__': main()
