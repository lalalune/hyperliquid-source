#!/usr/bin/env python3
"""Authenticate static sender evidence. Never execute or interpret target code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone import __version__ as capstone_version
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
RANGES = [(0x2b7a290, 0x2b7b523), (0x477e950, 0x477f036),
          (0x477f040, 0x477f746), (0x47855c0, 0x4785a0a)]

# Exact source operands and edges, independently checked against both native
# disassemblers. Some intervals contain several consecutive instructions.
PINS = {
    'input pointer/count': (0x2b7a2ce, '4c8b63184c8b6b20'),
    'length threshold': (0x2b7a2de, '4981fd010400000f93c2'),
    'low-word field predicate': (0x2b7a2e8, 'be60f0ffff03b0900000006683fefe400f92c64020d6'),
    'persist compression decision': (0x2b7a31f, '4088b308030000'),
    'initial bypass edge': (0x2b7a346, '4084f60f8463010000'),
    'checked size multiplier': (0x2b7a366, 'b96e0000004c89e848f7e10f80a7050000'),
    'allocation quotient': (0x2b7a377, '48c1e80248b9c3f5285c8fc2f52848f7e14989d649c1ee02'),
    'allocation extent': (0x2b7a38f, '498d7618'),
    'LE original length and sink reserve': (0x2b7a3ac, '4489284983c614'),
    'sink starts after prefix': (0x2b7a3b8, '4883c004'),
    'codec split': (0x2b7a3d8, '4981fdffff00000f832f010000'),
    'small scratch allocation': (0x2b7a3e5, '41be00200000bf01000000be00200000'),
    'small codec arguments': (0x2b7a425, '41b9010000004c89e74c89ee31d2ff1567d39603'),
    'restored decision predicate': (0x2b7a4a9, '80fa010f849dfeffff'),
    'raw marker and join': (0x2b7a4bc, '4531ffe9e5010000'),
    'large scratch allocation': (0x2b7a514, '41be00400000bf01000000be00400000'),
    'large codec arguments': (0x2b7a554, '41b9010000004c89e74c89ee31d2ff1540d29603'),
    'helper error branch': (0x2b7a583, '4983fe010f8426030000'),
    'prefix addition overflow': (0x2b7a58d, '4983fcfb0f87c10300004983c404'),
    'clamp to allocation': (0x2b7a59b, '488b4424404939c476054989c4eb25'),
    'compressed marker': (0x2b7a68a, '41b701'),
    'statistics arguments and binding': (0x2b7a68d, '4c89f74c89ee4c89e2ff15fcd09603'),
    'selected length and pointer': (0x2b7a69c, '4d89e5488b4424404c8b642458'),
    'selected u32 admission': (0x2b7a6b5, '4c89e848c1e8207444'),
    'outer length endian': (0x2b7a72d, '410fcd448928'),
    'outer marker byte': (0x2b7a758, '44887804'),
    'unwrap literal': (0x2b7a8b3, '488d3d88aca8fd'),
    'unwrap source location': (0x2b7a8c1, '4c8d0588038d03'),
    'unwrap call': (0x2b7a8cd, 'be2b000000ff15c84d9603'),
    'small codec reserve failure': (0x477e9bf, '4883c2144839d67314b801000000'),
    'large codec reserve failure': (0x477f0af, '4883c2144839d67314b801000000'),
    'statistics first counter': (0x47855d8, '488b07f048017010'),
    'statistics second counter': (0x47855e0, '488b4708f048015010'),
    'statistics event count': (0x47855e9, '488b4710f048ff4010'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def offset(self, address, size):
        hits = [s for s in self.sections if s['type'] != 8 and
                s['address'] <= address and address + size <= s['address'] + s['size']]
        require(size >= 0 and len(hits) == 1, 'ambiguous VA')
        return hits[0]['offset'] + address - hits[0]['address']

    def read(self, address, size):
        offset = self.offset(address, size)
        return self.data[offset:offset + size]


def obligations(image):
    for name, (address, expected) in PINS.items():
        require(image.read(address, len(bytes.fromhex(expected))) == bytes.fromhex(expected),
                'changed obligation: ' + name)
    return [{'name': name, 'va': hex(a), 'bytes': raw} for name, (a, raw) in PINS.items()]


def instruction_rows(text, join_lock=False):
    result = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
        if match:
            result.append((int(match[1], 16), bytes.fromhex(match[2])))
    if not join_lock:
        return result
    # LLVM prints LOCK as a separate row. Join only that literal prefix and
    # its contiguous instruction; preserve every byte and starting address.
    joined = []
    index = 0
    while index < len(result):
        address, raw = result[index]
        if raw == b'\xf0':
            require(index + 1 < len(result) and result[index + 1][0] == address + 1,
                    'orphan LOCK prefix')
            raw += result[index + 1][1]
            index += 1
        joined.append((address, raw))
        index += 1
    return joined


def collect(data, native=False):
    require(len(data) == 105896032 and sha(data) == SHA, 'wrong capture')
    image = Image(data)
    anchors = obligations(image)
    _, frames = eh_frame_records(data, image.sections)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    owners, calls, branches, exports = [], [], [], {}
    for start, end in RANGES:
        found = [f for f in frames if f['start'] < end and start < f['end']]
        require(len(found) == 1 and found[0]['start'] == start and found[0]['end'] == end,
                'missing, duplicate or overlapping FDE')
        frame = found[0]
        body = image.read(start, end-start)
        instructions = list(md.disasm(body, start))
        rows = [(i.address, bytes(i.bytes)) for i in instructions]
        require(b''.join(raw for _, raw in rows) == body, 'incomplete decode')
        bounds = {i.address for i in instructions}
        for ins in instructions:
            if ins.mnemonic.startswith('j') and ins.operands[0].type == X86_OP_IMM:
                dest = ins.operands[0].imm
                require(dest in bounds, 'nonlocal direct branch')
                branches.append({'site': hex(ins.address), 'op': ins.mnemonic, 'to': hex(dest)})
            if ins.mnemonic == 'call':
                op = ins.operands[0]
                record = {'site': hex(ins.address), 'bytes': bytes(ins.bytes).hex()}
                if op.type == X86_OP_IMM:
                    record['direct'] = hex(op.imm)
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    record['slot'] = hex(ins.address + ins.size + op.mem.disp)
                else:
                    record['dynamic'] = ins.op_str
                calls.append(record)
        unwind = {}
        for kind in ['fde', 'cie']:
            va = frame[kind]
            length = struct.unpack('<I', image.read(va, 4))[0] + 4
            unwind[kind] = {'va': hex(va), 'bytes': image.read(va, length).hex()}
        owners.append({'start': hex(start), 'end': hex(end), 'bytes': len(body),
                       'file_offset': image.offset(start, end-start), 'sha256': sha(body),
                       'instructions': len(instructions), 'unwind': unwind,
                       'lsda_va': hex(frame['lsda']) if frame['lsda'] else None})
        if native:
            for name, command in [('gnu', ['objdump', '-d', '-M', 'intel', '--insn-width=16']),
                                  ('llvm', ['llvm-objdump', '-d', '--x86-asm-syntax=intel'])]:
                text = subprocess.check_output([*command, f'--start-address={start}',
                                                f'--stop-address={end}', str(TARGET)], text=True)
                require(instruction_rows(text, join_lock=name == 'llvm') == rows,
                        name + ' partition mismatch')
                exports[f'{start:x}.{name}.txt'] = text.replace(str(TARGET), '<authenticated-node115>')
    location_vas = [0x644ac38, 0x644ac50, 0x644ac68, 0x644b020]
    slots = {int(c['slot'], 16) for c in calls if 'slot' in c} | set(location_vas)
    rela = next(s for s in image.sections if s['name'] == '.rela.dyn')
    bindings = {}
    for offset in range(rela['offset'], rela['offset'] + rela['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        if slot in slots:
            require(slot not in bindings, 'duplicate relocation writer')
            bindings[slot] = {'slot': hex(slot), 'info': info, 'addend': hex(addend),
                              'bytes': data[offset:offset+24].hex()}
    require(slots == set(bindings), 'missing relocation')
    for slot, target in [(0x64e77a0, 0x477e950), (0x64e77a8, 0x477f040),
                         (0x64e7798, 0x47855c0)]:
        require(bindings[slot]['info'] == 8 and int(bindings[slot]['addend'], 16) == target,
                'wrong codec/statistics binding')
    locations = []
    for va in location_vas:
        raw = image.read(va, 24)
        _, length, line, column = struct.unpack('<QQII', raw)
        require(bindings[va]['info'] == 8, 'source location relocation')
        pointer = int(bindings[va]['addend'], 16)
        locations.append({'va': hex(va), 'bytes': raw.hex(), 'pointer': hex(pointer),
                          'path': image.read(pointer, length).decode(), 'line': line, 'column': column})
    require([r['line'] for r in locations] == [629, 680, 682, 34], 'source lines changed')
    literal = image.read(0x605542, 43).decode()
    require(literal == 'called `Result::unwrap()` on an `Err` value', 'unwrap literal')
    tables = []
    # Full dispatcher table qualification is inherited, not reimplemented.
    # Bind the initial and restored selected arms explicitly.
    for va, expected in [(0x604cbc, 0x2b7a2ca), (0x604ccc, 0x2b7a480)]:
        raw = image.read(va, 4)
        dest = va + struct.unpack('<i', raw)[0]
        require(dest == expected, 'wrong initial dispatch arm')
        tables.append({'slot': hex(va), 'bytes': raw.hex(), 'to': hex(dest)})
    if native:
        text = subprocess.check_output(['readelf', '-wf', str(TARGET)], text=True)
        blocks = [b for b in text.split('\n\n') if any(
            f'pc={a:016x}..{b_:016x}' in b for a, b_ in RANGES)]
        require(len(blocks) == len(RANGES), 'native FDE mismatch')
        exports['frames.txt'] = '\n\n'.join(blocks) + '\n'
    return {'target_sha256': SHA, 'coordinate_system': 'ELF virtual address',
            'owners': owners, 'anchors': anchors, 'calls': calls, 'branches': branches,
            'bindings': list(bindings.values()), 'source_locations': locations,
            'initial_dispatch_slots': tables, 'unwrap_literal': literal,
            'limits': 'Static adapter only; no codec-body, async, allocator, telemetry, unwind or native ABI equivalence.'}, exports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    require(not args.out.exists(), 'output must be fresh')
    record, exports = collect(TARGET.read_bytes(), native=True)
    args.out.mkdir(parents=True)
    (args.out / 'records.json').write_text(dump(record))
    for name, text in exports.items():
        (args.out / name).write_text(text)
    versions = {'python': sys.version.split()[0], 'capstone': capstone_version}
    for tool in ['objdump', 'readelf', 'llvm-objdump']:
        lines = subprocess.check_output([tool, '--version'], text=True).splitlines()
        versions[tool] = (next(line.strip() for line in lines if 'LLVM version' in line)
                          if tool == 'llvm-objdump' else lines[0])
    (args.out / 'tools.json').write_text(dump(versions))
    print(dump({'owners': len(record['owners']), 'anchors': len(record['anchors']),
                'branches': len(record['branches']), 'calls': len(record['calls'])}))


if __name__ == '__main__':
    main()
