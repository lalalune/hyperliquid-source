#!/usr/bin/env python3
"""Static evidence for one node115 context field; never execute the target."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

RANGES = {
    'caller': (0x2b67e50, 0x2b69279),
    'producer': (0x2b782e0, 0x2b788de),
    'constructor': (0x4784d00, 0x4784e17),
    'socket-helper': (0x475b2e0, 0x475b3ef),
    'sender': (0x2b7a290, 0x2b7b523),
}
RELATIVE = {0x64e7540: 0x4784d00, 0x64e7788: 0x475b2e0}
IMPORTS = {0x64df508: 'memcpy', 0x64e8a10: 'socket',
           0x64e14d0: 'connect', 0x64dffc8: '__errno_location'}
INDIRECT = {
    0x2b680c8: 0x64df508, 0x2b6829f: 0x64df508,
    0x2b78605: 0x64e7788, 0x2b7877d: 0x64e7540,
    0x2b787a8: 0x64df508, 0x2b787cb: 0x64df508,
    0x475b303: 0x64e8a10, 0x475b38b: 0x64e14d0,
    0x475b335: 0x64dffc8, 0x475b395: 0x64dffc8,
}
DIRECT = {0x2b6809e: 0x2b782e0, 0x2b684b5: 0x2b7a290}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        _, self.fdes = eh_frame_records(data, self.sections)
        self.relocs = {}
        for s in self.sections:
            if s['type'] == 4:
                for slot, info, addend in struct.iter_unpack('<QQq', data[s['offset']:s['offset']+s['size']]):
                    self.relocs.setdefault(slot, []).append((info, addend))

    def offset(self, va, size):
        hits = [s for s in self.sections if s['type'] != 8
                and s['address'] <= va < va+size <= s['address']+s['size']]
        require(len(hits) == 1, 'Non-unique mapped range')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off+size]

    def symbol(self, index):
        sym = next(s for s in self.sections if s['name'] == '.dynsym')
        strings = next(s for s in self.sections if s['name'] == '.dynstr')
        name = struct.unpack_from('<I', self.data, sym['offset']+24*index)[0]
        start = strings['offset']+name
        require(start < strings['offset']+strings['size'], 'Symbol name outside string table')
        end = self.data.index(b'\0', start, strings['offset']+strings['size'])
        return self.data[start:end].decode('ascii')


def authenticate(data):
    require(len(data) == 105896032 and sha(data) == TARGET, 'Wrong node115 artifact')


def bindings(image, anchors):
    for row in anchors:
        va = int(row['va'], 16)
        require(image.read(va, len(bytes.fromhex(row['bytes_hex']))).hex() == row['bytes_hex'],
                'Changed anchor: '+row['name'])
    for va, dest in DIRECT.items():
        raw = image.read(va, 5)
        require(raw[0] == 0xe8 and va+5+struct.unpack('<i', raw[1:])[0] == dest, 'Direct call binding')
    for va, slot in INDIRECT.items():
        raw = image.read(va, 6)
        require(raw[:2] == b'\xff\x15' and va+6+struct.unpack('<i', raw[2:])[0] == slot,
                'Indirect call binding')
    rows = []
    for slot, dest in RELATIVE.items():
        require(image.relocs.get(slot) == [(8, dest)], 'Non-unique or wrong RELATIVE relocation')
        rows.append({'slot': hex(slot), 'kind': 8, 'symbol_index': 0, 'addend': hex(dest)})
    for slot, name in IMPORTS.items():
        rels = image.relocs.get(slot, [])
        require(len(rels) == 1, 'Non-unique import relocation')
        info, addend = rels[0]
        require(info & 0xffffffff == 6 and addend == 0 and image.symbol(info >> 32) == name,
                'Wrong imported symbol')
        rows.append({'slot': hex(slot), 'kind': 6, 'symbol_index': info >> 32,
                     'symbol': name, 'addend': addend})
    require(image.read(0x607018, 14).hex() == 'a10fa20fa30fa40fa50f9e0f9f0f', 'Changed selected table bytes')
    # The compiler's relative dispatch entries are offsets from the table base.
    for table, dest in [(0x604ac4, 0x2b67edf), (0x604c10, 0x2b78313), (0x604cbc, 0x2b7a2ca)]:
        require(table+struct.unpack('<i', image.read(table, 4))[0] == dest, 'Initial dispatch binding')
    return rows


# Preserve raw transcripts and qualify the sole portable formatting difference
# observed in the retained Windows GNU exports. This does not alter instruction
# or target bytes; every other transcript difference is still refused.
_NATIVE_PRIOR_COMPARISONS = []


def compare_prior_native(current, retained):
    raw_equal = current == retained
    require(current.replace(b'\r\n', b'\n') == retained.replace(b'\r\n', b'\n'),
            'Prior native transcript differs beyond CRLF/LF line endings')
    _NATIVE_PRIOR_COMPARISONS.append({
        'current_sha256': sha(current), 'retained_sha256': sha(retained),
        'raw_equal': raw_equal, 'line_ending_only_difference': not raw_equal,
    })
    return True


def native_rows(raw, image, start, end):
    cursor = start
    rows = []
    for line in raw.decode('utf-8').splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)', line)
        if m:
            va = int(m[1], 16)
            data = bytes.fromhex(m[2])
            require(va == cursor and data == image.read(va, len(data)), 'Native byte gap/overlap/mismatch')
            cursor += len(data)
            rows.append((va, data))
    require(cursor == end, 'Incomplete native interval')
    return rows


def compare_boundaries(rows, instructions):
    pos = splits = 0
    for ins in instructions:
        pieces = []
        size = 0
        while size < ins.size and pos < len(rows):
            va, raw = rows[pos]
            require(va == ins.address+size, 'Native instruction start mismatch')
            pieces.append(raw)
            size += len(raw)
            pos += 1
        require(b''.join(pieces) == bytes(ins.bytes), 'Native instruction partition mismatch')
        if len(pieces) > 1:
            require(len(pieces) == 2 and pieces[0] == b'\xf0', 'Unexpected native split')
            splits += 1
    require(pos == len(rows), 'Trailing native rows')
    return splits


def collect(out):
    import capstone
    from capstone.x86 import X86_OP_MEM, X86_REG_RBX, X86_REG_R14
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    authenticate(data)
    image = Image(data)
    anchors = json.loads((PACKET / 'anchors.json').read_text())
    rels = bindings(image, anchors)
    out.mkdir(parents=True, exist_ok=False)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    records, versions, commands, overlaps = [], {}, [], []
    versions.update(python=sys.version, platform=platform.platform(), capstone=capstone.__version__)
    for tool in ['objdump', 'llvm-objdump']:
        p = subprocess.run([tool, '--version'], cwd=ROOT, capture_output=True, check=True)
        versions[tool] = p.stdout.decode('utf-8')
    for name, (start, end) in RANGES.items():
        fdes = [f for f in image.fdes if f['start'] == start and f['end'] == end]
        require(len(fdes) == 1, 'Selected FDE extent mismatch')
        body = image.read(start, end-start)
        ins = list(md.disasm(body, start))
        require(sum(i.size for i in ins) == end-start, 'Incomplete Capstone interval')
        boundaries = {i.address for i in ins} | {end}
        for a in anchors:
            va = int(a['va'], 16)
            if start <= va < end:
                require(va in boundaries and va+len(bytes.fromhex(a['bytes_hex'])) in boundaries,
                        'Anchor not on instruction boundaries')
        text = '\n'.join(f'{i.address:x}: {i.bytes.hex():32} {i.mnemonic:8} {i.op_str}' for i in ins)+'\n'
        (out / (name+'.capstone.txt')).write_text(text, encoding='utf-8', newline='\n')
        record = {'name': name, 'start': hex(start), 'end': hex(end), 'fde': hex(fdes[0]['fde']),
                  'file_offset': image.offset(start, end-start), 'length': end-start,
                  'body_sha256': sha(body), 'instructions': len(ins), 'native': []}
        for tool, extra in [('objdump', ['-z', '--insn-width=16']), ('llvm-objdump', ['--disassemble-zeroes'])]:
            args = [tool, '-d', *extra, f'--start-address={start}', f'--stop-address={end}', 'artifacts/node/115/hl-node']
            p = subprocess.run(args, cwd=ROOT, capture_output=True, check=True)
            filename = name+('.gnu.objdump' if tool == 'objdump' else '.llvm.objdump')
            (out / filename).write_bytes(p.stdout)
            (out / (filename+'.stderr')).write_bytes(p.stderr)
            rows = native_rows(p.stdout, image, start, end)
            splits = compare_boundaries(rows, ins)
            record['native'].append({'file': filename, 'sha256': sha(p.stdout), 'rows': len(rows), 'lock_prefix_splits': splits})
            commands.append(args)
        # Directly encoded overlap only: helpers and indirect aliases remain open.
        if name in ('producer', 'constructor'):
            base, lo, hi = (X86_REG_RBX, 0x26, 0x28) if name == 'producer' else (X86_REG_R14, 0x90, 0x94)
            for i in ins:
                for op in i.operands:
                    if op.type == X86_OP_MEM and op.mem.base == base and not op.mem.index and op.mem.disp < hi and op.mem.disp+op.size > lo and i.mnemonic != 'lea':
                        overlaps.append({'range': name, 'va': hex(i.address), 'bytes_hex': i.bytes.hex(),
                                         'instruction': i.mnemonic+' '+i.op_str, 'decoder_access_flags': op.access,
                                         'operand_bytes': op.size})
        records.append(record)
    result = {'target_sha256': TARGET, 'source_base': '05bc2de303c05525b71e7e257426e741bc66a390',
              'coordinate_system': 'linked ELF virtual addresses before load bias',
              'captured_code_executed_or_emulated': False, 'normalization_masks': [],
              'ranges': records, 'relocations': rels, 'direct_operand_overlap': overlaps,
              'operand_access_caveat': 'Decoder flags are advisory: Capstone 5.0.7 reports READ for the MOVUPS destination at 0x2b7831e. Classify that operand from its pinned opcode and native disassembly as a store.',
              'table': {'va': '0x607018', 'bytes_hex': image.read(0x607018, 14).hex(),
                        'observed_u16': list(struct.unpack('<7H', image.read(0x607018, 14))),
                        'valid_index_domain_and_full_extent': 'unresolved'},
              'exported_bytes': sum(r['length'] for r in records),
              'exported_instructions': sum(r['instructions'] for r in records),
              'anchor_spans': len(anchors)}
    for name, obj in [('records.json', result), ('versions.json', versions), ('commands.json', commands)]:
        (out / name).write_text(json.dumps(obj, indent=2)+'\n', encoding='utf-8', newline='\n')
    print(json.dumps({'bytes': result['exported_bytes'], 'instructions': result['exported_instructions'], 'anchors': len(anchors)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='Fresh output directory')
    collect(parser.parse_args().out)
