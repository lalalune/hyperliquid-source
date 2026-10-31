#!/usr/bin/env python3
"""Bind one node94 null-path branch to actual calls and output copies; never run it."""
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
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
START, END = 0x46cea60, 0x46cf026
FDE, CIE, LSDA = 0x127e83c, 0xfbdc2c, 0xb6ac1c
SLOTS = {0x572e3e8: 0x1dd8eb, 0x572e400: 0x1dd8eb, 0x576dfb8: 0x1346068,
         0x576dfd8: 0x54c06b0, 0x576e010: 0x54c8cb0, 0x576e048: 0x157aa10,
         0x576e128: 0x157b63b, 0x576e8a0: 0x151cba0, 0x576e8b8: 0x4ee3b20,
         0x576e968: 0x4edba50, 0x576ea68: 0x144c180, 0x576f620: 0x144a3e0,
         0x576f670: 0x144c560, 0x5775058: 0x326aec0, 0x577a668: 0x4f14ca0}
DIRECTS = {0x46cea7c: 0x4ee3800, 0x46ceb62: 0x446c230, 0x46cec00: 0x446c320,
           0x46cec98: 0x4ee3800, 0x46cecda: 0x4ee3730, 0x46cef2d: 0x4722610,
           0x46cef53: 0x4722540, 0x46cf021: 0x5660110}
INDIRECTS = {0x46ceac1: 0x5775058, 0x46ceb14: 0x576f620, 0x46ceb97: 0x576dfd8,
             0x46cec39: 0x576ea68, 0x46cec5e: 0x576f670, 0x46cec74: 0x576e010,
             0x46ced31: 0x576e8a0, 0x46cee2e: 0x576e968, 0x46cee4a: 0x576e010,
             0x46ceeb1: 0x576e8b8, 0x46ceecd: 0x576e010, 0x46ceee2: 0x576dfb8,
             0x46cef0b: 0x576e010, 0x46cef45: 0x576e010, 0x46cef7f: 0x576e048,
             0x46cefb9: 0x576e010, 0x46cefd0: 0x576e128, 0x46cefe6: 0x576e010,
             0x46cf018: 0x576e010}
ANCHORS = {
    0x46cea71: '4889f34989fd',  # retained input RSI and output RDI
    0x46cea8d: '488b334c8b7628',  # state pointer and its word+0x28
    0x46ceab6: '488dbc24e00000004c89f2',  # upstream output-buffer argument
    0x46ceac7: '4c89b424f8000000',  # preserve state word in fourth buffer word
    0x46ceacf: '4c8b7b104c8b63184c897c24604c89642468',  # path pointer/length
    0x46ceae5: '4c89ac24c8000000',  # preserve final output pointer
    0x46ceb0e: '4c89ff4c89e6',  # ordinary predicate receives path words
    0x46cec33: '4c89ff4c89e6',
    0x46cec52: '4c89ef4889ee4c89fa4c89e1',  # buffer words then path words
    0x46cec83: '4c8bbc24e00000004c8ba424e8000000',
    0x46ced2c: '488d7c2460',  # common helper receives saved path descriptor
    0x46cee50: '0f108424e00000000f108c24f0000000488b8424c80000000f1148100f1100',
}


def need(ok, message):
    if not ok: raise ValueError(message)


def authenticate(data):
    need(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Node94 identity mismatch')


def mapped(data, secs, va, size):
    found = [s for s in secs if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    need(size >= 0 and len(found) == 1, 'No unique file mapping')
    offset = found[0]['offset'] + va - found[0]['address']
    return offset, data[offset:offset + size]


def predicate(body):
    def b(va, n): return body[va - START:va - START + n]
    need(b(0x46ceae1, 3) == b'\x49\x83\xfc', 'Length operand changed')
    need(b(0x46ceaef, 2) == b'\x48\xb8' and b(0x46ceaf9, 3) == b'\x49\x33\x07', 'Eight-byte equality operand changed')
    need(b(0x46ceafc, 5) == b'\x41\x0f\xb6\x4f\x08', 'Ninth-byte load changed')
    need(b(0x46ceb01, 3) == b'\x48\x83\xf1' and b(0x46ceb05, 3) == b'\x48\x09\xc1', 'XOR/OR predicate changed')
    ninth = b(0x46ceb04, 1)[0]
    need(ninth < 128, 'Expected positive sign-extended ninth-byte immediate')
    short, long = b(0x46ceaed, 2), b(0x46ceb08, 6)
    need(short[0] in (0x74, 0x75) and long[:2] in (b'\x0f\x84', b'\x0f\x85'), 'Predicate branch encoding changed')
    return {'length': b(0x46ceae4, 1)[0], 'bytes_hex': (b(0x46ceaf1, 8) + bytes([ninth])).hex(),
            'length_branch': {'va': '0x46ceaed', 'condition': 'ne' if short[0] == 0x75 else 'eq',
                              'target': hex(0x46ceaef + struct.unpack('<b', short[1:])[0])},
            'equality_branch': {'va': '0x46ceb08', 'condition': 'eq' if long[1] == 0x84 else 'ne',
                                'target': hex(0x46ceb0e + struct.unpack('<i', long[2:])[0])}}


def matches_path(raw, spec):
    # Model only the observed length/eight-byte XOR/ninth-byte XOR/OR test.
    literal = bytes.fromhex(spec['bytes_hex'])
    return len(raw) == spec['length'] and len(raw) >= 9 and (
        int.from_bytes(raw[:8], 'little') ^ int.from_bytes(literal[:8], 'little')
        | raw[8] ^ literal[8]) == 0


def forced_route(raw, spec):
    equal_length = len(raw) == spec['length']
    length_taken = equal_length if spec['length_branch']['condition'] == 'eq' else not equal_length
    result = {0x46ceaed: length_taken}
    if not length_taken:
        equality = matches_path(raw, spec)
        result[0x46ceb08] = equality if spec['equality_branch']['condition'] == 'eq' else not equality
    return result


def frame_record(data, secs, va):
    _, head = mapped(data, secs, va, 4); size = struct.unpack('<I', head)[0] + 4
    need(8 <= size < 4096, 'Selected frame record size changed')
    offset, raw = mapped(data, secs, va, size)
    return {'va': hex(va), 'file_offset': hex(offset), 'raw': raw.hex()}


def lsda_rows(data, secs):
    offset, head = mapped(data, secs, LSDA, 5)
    need(head[:2] == b'\xff\x9b', 'Observed LSDA encoding changed')
    section = next(s for s in secs if s['name'] == '.gcc_except_table')
    limit = section['offset'] + section['size']
    displacement, pos = uleb(data, offset + 2, limit); type_base = pos + displacement
    need(data[pos] == 1, 'Expected ULEB call-site encoding'); pos += 1
    length, pos = uleb(data, pos, limit); end = pos + length
    need(end <= type_base <= limit, 'LSDA table/type base outside section')
    rows = []
    while pos < end:
        fields = []
        for _ in range(4): value, pos = uleb(data, pos, end); fields.append(value)
        begin, size, pad, action = fields
        rows.append({'start': hex(START + begin), 'end': hex(START + begin + size),
                     'landing_pad': hex(START + pad) if pad else None, 'action': action})
    raw = data[offset:type_base]
    need(hashlib.sha256(raw).hexdigest() == '3bc346d8f7eacf0d76e3931c93df706469f3c82e913cfd171d8c0e564289138b',
         'Observed LSDA prefix changed')
    return {'va': hex(LSDA), 'file_offset': hex(offset), 'raw_prefix': raw.hex(),
            'type_encoding': 'indirect-pcrel-sdata4 (not interpreted)',
            'type_table_base': hex(LSDA + type_base - offset), 'rows': rows,
            'limits': 'Call-site associations only; action/type/personality semantics and exception feasibility remain unknown.'}


def inspect_bytes(data):
    """Local obligations, below the whole-image authentication used by collect()."""
    secs = sections(data); cies, fdes = eh_frame_records(data, secs)
    fs = [f for f in fdes if f['start'] == START]
    need(len(fs) == 1 and (fs[0]['end'], fs[0]['fde'], fs[0]['cie'], fs[0]['lsda']) == (END, FDE, CIE, LSDA), 'Selected FDE binding changed')
    cie = cies[CIE]
    need((cie['augmentation'], cie['code_align'], cie['data_align'], cie['fde_encoding'], cie['lsda_encoding'], cie['personality_slot']) == ('zPLR', 1, -8, 0x1b, 0x1b, 0x577a668), 'Selected CIE profile changed')
    frame = frame_record(data, secs, FDE); raw = bytes.fromhex(frame['raw'])
    # Independent fixed-encoding field arithmetic, not the record walk above.
    manual = {'cie': FDE + 4 - struct.unpack_from('<I', raw, 4)[0],
              'start': FDE + 8 + struct.unpack_from('<i', raw, 8)[0],
              'range': struct.unpack_from('<i', raw, 12)[0]}
    need(manual == {'cie': CIE, 'start': START, 'range': END - START}, 'Independent FDE arithmetic differs')
    _, index = unwind_index(data)
    need(any(row['start'] == START and row['fde'] == FDE for row in index), 'Unwind index binding differs')
    body_offset, body = mapped(data, secs, START, END - START)
    spec = predicate(body)
    need(spec == {'length': 9, 'bytes_hex': b'/dev/null'.hex(),
                  'length_branch': {'va': '0x46ceaed', 'condition': 'ne', 'target': '0x46ceb0e'},
                  'equality_branch': {'va': '0x46ceb08', 'condition': 'eq', 'target': '0x46cec83'}}, 'Observed null-path predicate changed')
    for va, expected in ANCHORS.items():
        need(body[va - START:va - START + len(bytes.fromhex(expected))].hex() == expected, f'Used dataflow changed at {va:#x}')
    locations = []
    location_targets = {r['slot']: int(r['addend'], 16) for r in relocations(data, secs, [0x572e3e8, 0x572e400])}
    for va, col in ((0x572e3e8, 17), (0x572e400, 35)):
        offset, raw_location = mapped(data, secs, va, 24)
        stored_ptr, size, line, column = struct.unpack('<QQII', raw_location)
        ptr = location_targets[hex(va)]
        _, path = mapped(data, secs, ptr, size)
        need(path == b'/home/ubuntu/hl/code_Mainnet/l1/src/abci/state.rs' and (line, column) == (145, col), 'Source Location changed')
        locations.append({'va': hex(va), 'file_offset': hex(offset), 'raw': raw_location.hex(),
                          'path': path.decode(), 'stored_pointer_bytes': hex(stored_ptr),
                          'relative_pointer_addend': hex(ptr), 'bytes': size, 'line': line, 'column': column})
    return {'schema': 're009-state-dump-null-route94/1', 'base': '1f8c67c63ca4794c9689235471c60297f8a5c985',
            'target': {'sha256': SHA256, 'bytes': SIZE, 'release': 94},
            'body': {'start': hex(START), 'end': hex(END), 'file_offset': hex(body_offset), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()},
            'predicate': spec, 'fde': frame, 'cie': {**cie, 'record': frame_record(data, secs, CIE)},
            'independent_fde_fields': manual, 'lsda': lsda_rows(data, secs), 'source_locations': locations}


def disassemble(body):
    # Only these 1478 authenticated code bytes are given to GNU objdump.
    with tempfile.TemporaryDirectory(prefix='state-null-native-') as private:
        path = Path(private) / 'selected-code.bin'; path.write_bytes(body); path.chmod(0o400)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(START), str(path)]
        text = subprocess.check_output(argv, text=True)
        need(path.read_bytes() == body, 'Private native slice changed')
    rows = []; cursor = START
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9.]*)\s*(.*)$', line)
        if not m: continue
        va = int(m[1], 16); raw = bytes.fromhex(m[2]); op = m[3]; operand = m[4]
        need(va == cursor and body[va - START:va - START + len(raw)] == raw, 'Native instruction coverage/bytes differ')
        need(op not in ('(bad)', '.byte'), 'Undecoded selected instruction')
        rows.append({'va': va, 'raw': raw.hex(), 'op': op, 'operand': operand}); cursor += len(raw)
    need(cursor == END, 'Native decoder left bytes outside complete coverage')
    return text.replace(str(path), '<authenticated-selected-code>'), rows


def control_flow(rows, forced=None):
    forced = forced or {}; boundaries = {r['va'] for r in rows}; edges = {}; branches = []
    for row in rows:
        va = row['va']; raw = bytes.fromhex(row['raw']); after = va + len(raw); op = row['op']
        if op.startswith('j'):
            target = after + (struct.unpack('<b', raw[-1:])[0] if len(raw) == 2 else struct.unpack('<i', raw[-4:])[0])
            need(target == int(row['operand'].split()[0], 16) and target in boundaries, 'Branch target not an independent native boundary')
            branches.append({'va': hex(va), 'op': op, 'target': hex(target), 'fallthrough': hex(after) if op != 'jmp' else None})
            edges[va] = [target] if op == 'jmp' or forced.get(va) is True else [after] if forced.get(va) is False else [target, after]
        else: edges[va] = [] if op in ('ret', 'ud2') or after == END else [after]
    seen = set(); todo = [START]
    while todo:
        va = todo.pop()
        if va not in seen: seen.add(va); todo.extend(edges[va])
    return seen, branches, edges


def call_records(rows):
    calls = []
    for row in rows:
        if row['op'] != 'call': continue
        pc = row['va']; raw = bytes.fromhex(row['raw']); record = {'va': hex(pc), 'raw': raw.hex(), 'return_pc': hex(pc + len(raw))}
        if raw[0] == 0xe8:
            target = pc + 5 + struct.unpack_from('<i', raw, 1)[0]
            need(int(row['operand'].split()[0], 16) == target, 'Native direct call target differs')
            need(DIRECTS.get(pc) == target, 'Observed direct call binding changed')
            record.update(kind='direct', target=hex(target))
        elif raw[:2] == b'\xff\x15':
            slot = pc + 6 + struct.unpack_from('<i', raw, 2)[0]
            native = re.search(r'#\s*(?:0x)?([0-9a-f]+)', row['operand'])
            need(native and int(native[1], 16) == slot, 'Native indirect slot differs')
            need(INDIRECTS.get(pc) == slot, 'Observed indirect call binding changed')
            record.update(kind='relocated-slot', slot=hex(slot))
        else:
            need(raw == b'\xff\x10' and pc == 0x46cefcc, 'Unexpected memory-indirect call')
            record.update(kind='opaque-memory-indirect', operand='[RAX]')
        calls.append(record)
    return calls


def relocations(data, secs, slots):
    records = {}; slots = set(slots)
    for s in secs:
        if s['type'] != 4: continue
        for offset in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot not in slots: continue
            need(slot not in records and info == 8 and addend == SLOTS[slot], 'Selected RELATIVE relocation changed')
            records[slot] = {'slot': hex(slot), 'type': 8, 'symbol_index': 0, 'addend': hex(addend),
                             'file_offset': hex(offset), 'raw': data[offset:offset + 24].hex()}
    need(set(records) == slots, 'Missing selected RELA row')
    return [records[slot] for slot in sorted(records)]


def derive(data, rows, record):
    calls = call_records(rows); secs = sections(data)
    need({int(c['va'], 16) for c in calls} == set(DIRECTS) | set(INDIRECTS) | {0x46cefcc}, 'Observed call census changed')
    slots = [int(c['slot'], 16) for c in calls if 'slot' in c] + [0x577a668, 0x572e3e8, 0x572e400]
    record['relocations'] = relocations(data, secs, slots)
    slotmap = {r['slot']: r['addend'] for r in record['relocations']}
    for c in calls:
        if 'slot' in c: c['relative_target'] = slotmap[c['slot']]
        lookup = int(c['return_pc'], 16) - 1
        c['lsda_rows'] = [i for i, row in enumerate(record['lsda']['rows']) if int(row['start'], 16) <= lookup < int(row['end'], 16)]
        need(len(c['lsda_rows']) <= 1, 'Call has overlapping LSDA associations')
    _, branches, edges = control_flow(rows)
    null, _, _ = control_flow(rows, forced_route(b'/dev/null', record['predicate']))
    length_other, _, _ = control_flow(rows, forced_route(b'ordinary', record['predicate']))
    mismatch, _, _ = control_flow(rows, forced_route(b'/dev/nulX', record['predicate']))
    need({int(c['va'], 16) for c in calls if int(c['va'], 16) in length_other} ==
         {int(c['va'], 16) for c in calls if int(c['va'], 16) in mismatch}, 'Ordinary path partitions have different call sets')
    for c in calls:
        pc = int(c['va'], 16)
        c['normal_route_class'] = 'common' if pc in null and pc in length_other else 'ordinary-only' if pc in length_other else 'exception/unreachable-from-normal-entry'
    need(not any(int(c['va'], 16) in null and int(c['va'], 16) not in length_other for c in calls), 'Unexpected null-only call')
    leaders = {START}
    for row in rows:
        after = row['va'] + len(bytes.fromhex(row['raw']))
        if row['op'].startswith('j') or row['op'] in ('ret', 'ud2'):
            leaders.update(edges[row['va']])
            if after < END: leaders.add(after)
    leaders.update(int(r['landing_pad'], 16) for r in record['lsda']['rows'] if r['landing_pad'])
    need(leaders <= {r['va'] for r in rows}, 'LSDA or branch enters an unvalidated instruction')
    blocks = []
    starts = sorted(leaders)
    for begin, end in zip(starts, starts[1:] + [END]):
        members = [r for r in rows if begin <= r['va'] < end]
        need(members and members[-1]['va'] + len(bytes.fromhex(members[-1]['raw'])) == end, 'Basic-block partition is incomplete')
        blocks.append({'start': hex(begin), 'end': hex(end), 'instructions': len(members),
                       'normal_successors': [hex(x) for x in edges[members[-1]['va']]],
                       'null_reachable': begin in null, 'ordinary_reachable': begin in length_other})
    need(sum(b['instructions'] for b in blocks) == len(rows), 'Basic blocks do not cover every selected instruction')
    record.update(calls=calls, branches=branches,
                  normal_cfg_blocks=blocks,
                  census={'bytes': END - START, 'instructions': len(rows), 'calls': len(calls), 'branches': len(branches),
                          'returns': sum(r['op'] == 'ret' for r in rows)},
                  route_instruction_counts={'null': len(null), 'ordinary': len(length_other)},
                  used_output={'upstream_call': '0x46ceac1', 'upstream_destination': 'RSP+0xe0',
                               'preserved_input_word_store': '0x46ceac7: input-state word+0x28 -> RSP+0xf8',
                               'common_copy': '0x46cee50..0x46cee6f copies 32 bytes from RSP+0xe0 to retained entry output pointer',
                               'path_descriptor': 'RSP+0x60/+0x68 receive path pointer/length before the predicate; common helper 0x46ced31 receives &descriptor'},
                  limits=['Normal CFG treats calls as normally returning and omits exceptional transfers; LSDA is retained separately.',
                          'The bounded graph stops at the FDE end; the final cleanup call has unclosed return behavior, not a proved no-return property.',
                          'Helpers, ABI/callee-saved register/frame preservation, valid live regions, and escaped-pointer alias effects remain unclosed.',
                          'Visible call/argument/copy observations do not establish filesystem writes, syscall effects, output type/value or runtime success.',
                          'Only one 1478-byte body; the twin 0x46cfe90 and all helper bodies are excluded.'],
                  captured_target_executed=False, gate_changes_requested=False)
    return record


def collect(binary, output):
    binary, output = Path(binary), Path(output)
    if output.exists(): raise FileExistsError('Output directory must be new')
    version = subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0]
    need('GNU' in version, 'GNU objdump required')
    with binary.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        authenticate(data); record = inspect_bytes(data)
        _, body = mapped(data, sections(data), START, END - START)
        native, rows = disassemble(body); record = derive(data, rows, record); authenticate(data)
    record['native_tool_version'] = version
    record['native_input_binding'] = 'Only private authenticated 1478-byte raw slice; ELF pathname is never reopened by native tool.'
    output.mkdir(parents=True, exist_ok=False)
    (output / 'body.objdump.txt').write_text(native, encoding='utf-8', newline='\n')
    (output / 'records.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(); result = collect(args.binary, args.output)
    print(json.dumps(result['census'], sort_keys=True))


if __name__ == '__main__': main()
