#!/usr/bin/env python3
"""Read one Node94 carrier producer/constructor/consumer chain; never run it."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from artifacts import ROOT
from elf_index import sections
from fde_extents import eh_frame_records, uleb

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280
SOURCE_BASE = '1f8c67c63ca4794c9689235471c60297f8a5c985'
RANGES = {'producer': (0x1704700, 0x17047a8),
          'constructor': (0x26bb3c0, 0x26bb405),
          'consumer': (0x16ca240, 0x16ca353)}
FDE_IDS = {'producer': (0x1006298, 0xfbdc2c, 0x94f808),
           'constructor': (0xd7e7e8, 0xce1518, None),
           'consumer': (0xd07378, 0xce1518, None)}
CALLS = {'producer': (0x170471e, 0x170472e, 0x170474d, 0x1704770, 0x170479a, 0x17047a3),
         'constructor': (0x26bb3ec, 0x26bb3f8), 'consumer': (0x16ca2ef, 0x16ca30a)}
BRANCHES = {'producer': (0x1704717, 0x1704729, 0x1704737, 0x170473c, 0x1704769, 0x1704788, 0x1704793),
            'constructor': (),
            'consumer': (0x16ca24b, 0x16ca250, 0x16ca25f, 0x16ca26e, 0x16ca27a, 0x16ca29e, 0x16ca316, 0x16ca320)}
RETURNS = {'producer': (0x1704782,), 'constructor': (0x26bb404,),
           'consumer': (0x16ca2af, 0x16ca2bd, 0x16ca2d4, 0x16ca2fc, 0x16ca352)}
SLOTS = {0x576dfb8: (8, 0, 0x1346068, ''), 0x576dfd8: (8, 0, 0x54c06b0, ''),
         0x576dfe0: (6, 6, 0, 'memcpy'), 0x576e010: (8, 0, 0x54c8cb0, ''),
         0x576e040: (8, 0, 0x1344760, ''), 0x576e9d0: (8, 0, 0x1570740, ''),
         0x577a668: (8, 0, 0x4f14ca0, ''), 0x5778db0: (7, 7, 0, '_Unwind_Resume')}
# These are observed dataflow instructions, independently read from the capture.
# No inferred reference implementation supplies them or their meaning.
ANCHORS = {
    0x1704709: ('4989f6488b5e084c8b6610', 'save input pointer and words+8/+16'),
    0x1704714: ('4d85e4790d', 'signed input-word test'),
    0x1704726: ('4989ff7413', 'retain entry output pointer and zero-word branch'),
    0x1704734: ('4885c0744a4989c5eb06', 'zero helper-return branch and selected word'),
    0x170473e: ('41bd01000000', 'zero-word selected constant1'),
    0x1704744: ('4c89ef4889de4c89e2', 'arguments before the memcpy import call'),
    0x1704753: ('4d8967084d896f104d89671841c60706', 'direct output writes+8/+16/+24 and byte6'),
    0x1704763: ('498b364885f6740b4889df31d2', 'conditional post-store helper arguments'),
    0x1704776: ('4c89f85b415c415d415e415fc3', 'return retained output pointer'),
    0x1704783: ('bf01000000eb91', 'helper-zero failure route'),
    0x170478a: ('4989c7498b364885f6740b4889df31d2', 'LSDA landing-pad argument flow'),
    0x17047a0: ('4c89ff', 'pass saved exception word before resume call'),
    0x26bb3c0: ('4156534883ec284889fb48893424', 'constructor frame and output-pointer retention'),
    0x26bb3d5: ('4889442408', 'retain opaque formatter pointer'),
    0x26bb3e1: ('4c8d7424104889e24c89f7', 'constructor local descriptor pointer'),
    0x26bb3f2: ('4889df4c89f6', 'pass original output and local descriptor to producer'),
    0x26bb3fd: ('4883c4285b415ec3', 'constructor has no later call or output write'),
    0x16ca296: ('48894424084885c0785d', 'selected signed route into constructor setup'),
    0x16ca2a4: ('c60709', 'separate consumer route directly writes byte9'),
    0x16ca2fd: ('4889fb488d7c2410488d742408', 'consumer passes its stack output+16 and value+8'),
    0x16ca30f: ('0fb64424103c09750d', 'consume the same byte and compare with9'),
    0x16ca318: ('488b4424184889dfe97bffffff', 'equality continuation'),
    0x16ca325: ('8b4c24118b5424144889df895304894b01', 'inequality-route opaque byte copies'),
    0x16ca336: ('488b4c24180f104424200f114310880348894b08', 'copy opaque words and forward loaded carrier byte'),
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def authenticate(data):
    need(len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256, 'Node94 identity mismatch')
    need(data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] == 62,
         'Expected authenticated ELF64-LE x86-64')


def read_va(data, secs, address, size):
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= address
               and address + size <= s['address'] + s['size']]
    need(size >= 0 and len(matches) == 1, f'No unique mapped bytes at {address:#x}')
    s = matches[0]; offset = s['offset'] + address - s['address']
    return offset, data[offset:offset + size]


def raw_frame(data, secs, address):
    _, length = read_va(data, secs, address, 4)
    size = struct.unpack('<I', length)[0]
    need(4 <= size < 4096, 'Unexpected selected CFI record size')
    offset, raw = read_va(data, secs, address, size + 4)
    return {'va': hex(address), 'file_offset': hex(offset), 'raw': raw.hex()}


def observed_relocations(data, secs):
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    found = {}
    for section in secs:
        if section['type'] != 4:
            continue
        need(section['size'] % 24 == 0, 'Incomplete RELA entry')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot not in SLOTS:
                continue
            need(slot not in found, 'Duplicate observed relocation')
            index, typ = info >> 32, info & 0xffffffff
            name = ''
            if index:
                need((index + 1) * 24 <= dynsym['size'], 'Dynamic symbol outside table')
                name_index = struct.unpack_from('<I', data, dynsym['offset'] + index * 24)[0]
                need(name_index < dynstr['size'], 'Dynamic string outside table')
                begin = dynstr['offset'] + name_index
                end = data.find(b'\0', begin, dynstr['offset'] + dynstr['size'])
                need(end >= begin, 'Unterminated dynamic symbol')
                name = data[begin:end].decode('utf-8')
            need((typ, index, addend, name) == SLOTS[slot], f'Observed relocation changed at {slot:#x}')
            found[slot] = {'slot': hex(slot), 'type': typ, 'symbol_index': index, 'symbol': name,
                           'addend': hex(addend), 'file_offset': hex(offset), 'raw': data[offset:offset + 24].hex()}
    need(set(found) == set(SLOTS), 'Missing observed relocation')
    return [found[s] for s in sorted(found)]


def producer_lsda(data, secs, va):
    need(va == 0x94f808, 'Observed producer LSDA address changed')
    origin, header = read_va(data, secs, va, 4)
    need(header[:3] == b'\xff\xff\x01', 'Observed omitted-type ULEB LSDA encoding changed')
    section = next(s for s in secs if s['name'] == '.gcc_except_table')
    limit = section['offset'] + section['size']; length, pos = uleb(data, origin + 3, limit)
    end = pos + length; need(end <= limit, 'LSDA table outside section')
    rows = []
    while pos < end:
        values = []
        for _ in range(4):
            value, pos = uleb(data, pos, end); values.append(value)
        begin, size, pad, action = values
        rows.append({'start': hex(0x1704700 + begin), 'end': hex(0x1704700 + begin + size),
                     'landing_pad': hex(0x1704700 + pad) if pad else None, 'action': action,
                     'raw_uleb_values': values})
    need([r['raw_uleb_values'] for r in rows] == [[27, 9, 138, 0], [36, 132, 0, 0]],
         'Observed producer LSDA rows changed')
    associations = []
    for pc in CALLS['producer']:
        call = call_binding(data, secs, pc)
        return_pc = pc + (5 if call['kind'] == 'direct' else 6)
        matches = [i for i, row in enumerate(rows) if int(row['start'], 16) <= return_pc - 1 < int(row['end'], 16)]
        need(len(matches) == 1, 'Producer call has no unique LSDA return-PC-minus-one association')
        associations.append({'call_va': hex(pc), 'return_pc': hex(return_pc),
                             'lookup_pc': hex(return_pc - 1), 'row_index': matches[0]})
    return {'va': hex(va), 'file_offset': hex(origin), 'decoded_prefix_bytes': end - origin,
            'raw': data[origin:end].hex(), 'lpstart': 'omitted/body start', 'type_encoding': 'omitted',
            'call_site_encoding': 'ULEB128', 'rows': rows, 'call_associations': associations,
            'limits': 'Static call-site/landing-pad association only; personality and exception behavior unclosed.'}


def call_binding(data, secs, pc):
    _, prefix = read_va(data, secs, pc, 2)
    if prefix[0] == 0xe8:
        _, raw = read_va(data, secs, pc, 5)
        return {'va': hex(pc), 'kind': 'direct', 'target': hex(pc + 5 + struct.unpack_from('<i', raw, 1)[0])}
    _, raw = read_va(data, secs, pc, 6)
    need(raw[:2] == b'\xff\x15', f'Unsupported observed call at {pc:#x}')
    return {'va': hex(pc), 'kind': 'relocated-slot', 'slot': hex(pc + 6 + struct.unpack_from('<i', raw, 2)[0])}


def inspect_bytes(data):
    """Local target-byte obligations; tests mutate copy-on-write mappings below identity."""
    secs = sections(data); cies, fdes = eh_frame_records(data, secs)
    bodies = {}
    for name, (start, end) in RANGES.items():
        rows = [f for f in fdes if f['start'] == start]
        need(len(rows) == 1 and rows[0]['end'] == end, 'Observed exact FDE extent changed: ' + name)
        fde = rows[0]; cie = cies[fde['cie']]; offset, body = read_va(data, secs, start, end - start)
        need((fde['fde'], fde['cie'], fde['lsda']) == FDE_IDS[name], 'Observed FDE/CIE/LSDA binding changed')
        need((cie['code_align'], cie['data_align'], cie['fde_encoding']) == (1, -8, 0x1b), 'Observed CIE profile changed')
        need(cie['personality_slot'] == (0x577a668 if name == 'producer' else None), 'Observed personality-slot binding changed')
        need((cie['lsda_encoding'] is not None) == (name == 'producer'), 'Observed CIE/LSDA profile changed')
        bodies[name] = {'start': hex(start), 'end': hex(end), 'bytes': len(body), 'file_offset': hex(offset),
                        'sha256': hashlib.sha256(body).hexdigest(), 'fde': raw_frame(data, secs, fde['fde']),
                        'cie': {**cie, 'raw_record': raw_frame(data, secs, cie['va'])},
                        'lsda': hex(fde['lsda']) if fde['lsda'] is not None else None}
    for va, (raw, meaning) in ANCHORS.items():
        _, actual = read_va(data, secs, va, len(bytes.fromhex(raw)))
        need(actual.hex() == raw, f'Carrier dataflow instruction changed at {va:#x}: {meaning}')
    calls = {name: [call_binding(data, secs, pc) for pc in pcs] for name, pcs in CALLS.items()}
    need(calls['constructor'][1]['target'] == '0x1704700' and calls['consumer'][1]['target'] == '0x26bb3c0',
         'Producer/constructor/consumer call bridge changed')
    expected_slots = [0x576dfb8, 0x576dfd8, 0x576dfe0, 0x576e010, 0x576e010]
    need([int(r['slot'], 16) for r in calls['producer'][:-1]] == expected_slots, 'Producer call slots changed')
    need(calls['producer'][-1]['target'] == '0x5660110' and calls['constructor'][0]['slot'] == '0x576e040',
         'Opaque/resume call binding changed')
    _, plt = read_va(data, secs, 0x5660110, 6)
    need(plt[:2] == b'\xff\x25' and 0x5660116 + struct.unpack_from('<i', plt, 2)[0] == 0x5778db0,
         'Resume PLT binding changed')
    return {'schema': 're001-wei-constructor-carrier-94/1', 'source_base': SOURCE_BASE,
            'target': {'release': 94, 'bytes': SIZE, 'sha256': SHA256}, 'bodies': bodies,
            'denominator': 'Three unwind-described ranges totaling 512 bytes; no whole-node/function-coverage claim.',
            'calls': calls, 'relocations': observed_relocations(data, secs),
            'producer_lsda': producer_lsda(data, secs, int(bodies['producer']['lsda'], 16)),
            'observed_output_writes': [
                {'va': '0x1704753', 'offset': 8, 'bytes': 8, 'source': 'input word+16'},
                {'va': '0x1704757', 'offset': 16, 'bytes': 8, 'source': 'selected helper-return word or constant1'},
                {'va': '0x170475b', 'offset': 24, 'bytes': 8, 'source': 'input word+16'},
                {'va': '0x170475f', 'offset': 0, 'bytes': 1, 'value': 6}],
            'direct_write_gap': 'Bytes 1..7 have no explicit output-pointer store in this body; initialization/type/padding is not established.',
            'post_store_opaque_call': '0x1704770 through 0x576e010; output alias/clobber behavior is unclosed.',
            'used_chain': ['constructor retains its entry output pointer and passes it to 0x1704700',
                           'consumer passes its stack+16, reloads that byte at 0x16ca30f and compares with 9 at 0x16ca314',
                           'unequal continuation forwards the loaded byte at 0x16ca344',
                           'another consumer route directly stores 9 at 0x16ca2a4; no unreachable/dead-9 claim'],
            'assumptions_for_conditional_six_flow': [
                'Shown calls return normally and preserve the native ABI callee-saved registers and stack frames.',
                'Observed input/output regions are valid, and selected frame buffers remain live and distinct.',
                'Opaque helper calls do not alias/clobber the output carrier or its saved pointer, especially the post-store call.'],
            'conclusion': 'A visible byte-6 producer store is linked to a real comparison with 9. Final returned carrier value remains qualified/unknown without the helper/private-frame assumptions.',
            'captured_binary_executed': False, 'component_gates_requested': False}


def native_instructions(binary, data, secs, name):
    start, end = RANGES[name]
    argv = ['objdump', '-d', '-M', 'intel', '--insn-width=16', '--start-address=' + hex(start),
            '--stop-address=' + hex(end), str(binary)]
    text = subprocess.check_output(argv, text=True)
    rows = []; cursor = start
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9.]*)\s*(.*)$', line)
        if not match:
            continue
        va = int(match[1], 16); raw = bytes.fromhex(match[2]); mnemonic, operands = match[3], match[4]
        need(va == cursor and va + len(raw) <= end, 'Native disassembly does not cover exact bounded bytes')
        _, actual = read_va(data, secs, va, len(raw)); need(raw == actual, 'Native instruction bytes differ')
        rows.append({'va': va, 'raw': raw.hex(), 'mnemonic': mnemonic, 'operands': operands}); cursor += len(raw)
    need(cursor == end, 'Native disassembly left trailing/unparsed bytes')
    need(tuple(r['va'] for r in rows if r['mnemonic'] == 'call') == CALLS[name], 'Native call census changed')
    need(tuple(r['va'] for r in rows if r['mnemonic'].startswith('j')) == BRANCHES[name], 'Native branch census changed')
    need(tuple(r['va'] for r in rows if r['mnemonic'] == 'ret') == RETURNS[name], 'Native return census changed')
    boundaries = {r['va'] for r in rows}; edges = {}
    for r in rows:
        va = r['va']; raw = bytes.fromhex(r['raw']); following = va + len(raw); successors = []
        if r['mnemonic'] == 'call':
            call = call_binding(data, secs, va)
            if call['kind'] == 'direct':
                need(int(r['operands'].split()[0], 16) == int(call['target'], 16), 'Native direct call target differs')
            else:
                slot = re.search(r'#\s*([0-9a-f]+)', r['operands'])
                need(slot and int(slot[1], 16) == int(call['slot'], 16), 'Native indirect call slot differs')
        if r['mnemonic'].startswith('j'):
            if len(raw) == 2: target = following + struct.unpack('<b', raw[-1:])[0]
            else: target = following + struct.unpack('<i', raw[-4:])[0]
            native_target = int(r['operands'].split()[0], 16)
            need(target == native_target and target in boundaries, 'Branch leaves/enters an unvalidated instruction boundary')
            successors = [target] + ([] if r['mnemonic'] == 'jmp' else [following])
        elif r['mnemonic'] not in ('ret', 'ud2'):
            successors = [following] if following < end else []
        edges[va] = successors
    def reachable(origin, forbidden=None):
        seen = set(); todo = [origin]
        while todo:
            pc = todo.pop()
            if pc == forbidden or pc in seen: continue
            seen.add(pc); todo.extend(edges[pc])
        return seen
    summary = {'instruction_count': len(rows), 'calls': [hex(x) for x in CALLS[name]],
               'branches': [hex(x) for x in BRANCHES[name]], 'returns': [hex(x) for x in RETURNS[name]],
               'traps': [hex(r['va']) for r in rows if r['mnemonic'] == 'ud2'],
               'limits': 'Intraprocedural graph treats calls as normally returning; it does not prove call effects or exception feasibility.'}
    if name == 'producer':
        stores = [r['va'] for r in rows if re.match(r'(?:BYTE|QWORD) PTR \[r15(?:\+0x[0-9a-f]+)?\],', r['operands'])]
        need(stores == [0x1704753, 0x1704757, 0x170475b, 0x170475f], 'Explicit output-pointer store census changed')
        summary['explicit_output_pointer_store_vas'] = [hex(x) for x in stores]
        summary['byte6_store_dominates_local_normal_return'] = 0x1704782 not in reachable(start, 0x170475f)
        need(summary['byte6_store_dominates_local_normal_return'], 'Byte6 store no longer dominates local return')
    return text.replace(str(binary), '<authenticated-node94>'), summary


def native_metadata(binary, data, secs, record):
    frames = subprocess.check_output(['readelf', '-wf', str(binary)], text=True)
    frame = next(s for s in secs if s['name'] == '.eh_frame'); wanted = set(); fde_ranges = {}
    for name, body in record['bodies'].items():
        fp = int(body['fde']['va'], 16) - frame['address']; cp = body['cie']['va'] - frame['address']
        wanted.update((fp, cp)); fde_ranges[fp] = RANGES[name]
    selected = []
    for block in frames.split('\n\n'):
        block = block.lstrip('\n')
        line = block.splitlines()[0] if block.splitlines() else ''
        match = re.match(r'^([0-9a-f]+)\s+.*\b(?:CIE|FDE)\b', line)
        if not match or int(match[1], 16) not in wanted: continue
        offset = int(match[1], 16)
        if offset in fde_ranges:
            pc = re.search(r'pc=([0-9a-f]+)\.\.([0-9a-f]+)', line)
            need(pc and tuple(int(x, 16) for x in pc.groups()) == fde_ranges[offset], 'Native FDE extent differs')
        selected.append((offset, block))
    need({p for p, _ in selected} == wanted and len(selected) == len(wanted), 'Native CFI records not unique/complete')
    reloc_text = subprocess.check_output(['readelf', '-rW', str(binary)], text=True); retained = []; found = set()
    for line in reloc_text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)\s+(.*)$', line)
        if not match or int(match[1], 16) not in SLOTS: continue
        slot = int(match[1], 16); typ, index, addend, symbol = SLOTS[slot]
        need(slot not in found and int(match[2], 16) == (index << 32 | typ), 'Native relocation identity differs')
        need((typ == 8 and match[3] == 'R_X86_64_RELATIVE' and int(match[4].split()[0], 16) == addend)
             or (typ in (6, 7) and symbol in match[4]), 'Native relocation target/name differs')
        found.add(slot); retained.append(line)
    need(found == set(SLOTS), 'Native selected relocation rows incomplete')
    return '\n\n'.join(b for _, b in sorted(selected)) + '\n', '\n'.join(retained) + '\n'


def collect(binary, output):
    binary = Path(binary); output = Path(output)
    if output.exists(): raise FileExistsError('Output must be a new directory: ' + str(output))
    exports = {}; versions = {tool: subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
                              for tool in ('objdump', 'readelf')}
    need(all('GNU' in v for v in versions.values()), 'GNU binutils required for bounded native cross-checks')
    # Native tools reopen their argument pathname. Bind them to our own private
    # snapshot, not the mutable caller-supplied pathname or a shared hard link.
    with tempfile.TemporaryDirectory(prefix='wei-carrier-native-') as private:
        snapshot = Path(private) / 'node94.read-only'
        with binary.open('rb') as source, snapshot.open('xb') as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
        snapshot.chmod(0o400)
        with snapshot.open('rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            authenticate(data); record = inspect_bytes(data); secs = sections(data)
            record['native'] = {}
            for name in RANGES:
                exports[name + '.objdump.txt'], record['native'][name] = native_instructions(snapshot, data, secs, name)
            exports['frames.txt'], exports['relocations.txt'] = native_metadata(snapshot, data, secs, record)
            record['native_tool_versions'] = versions
            record['native_input_binding'] = 'Private non-hardlinked snapshot authenticated before and after all native reads; source pathname is not reopened by native tools.'
            authenticate(data)
    exports['records.json'] = json.dumps(record, indent=2, sort_keys=True) + '\n'
    output.mkdir(parents=True, exist_ok=False)
    for name, text in exports.items(): (output / name).write_text(text, encoding='utf-8', newline='\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); collect(args.binary, args.output)
    print(json.dumps({'target_sha256': SHA256, 'ranges': len(RANGES), 'bytes': 512,
                      'captured_binary_executed': False, 'gates_requested': False}, indent=2))


if __name__ == '__main__': main()
