#!/usr/bin/env python3
"""Node115 BLST lazy thread-pool construction: static bytes, not instruction execution."""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-012-blst-threadpool-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON key')
    return result


class Image:
    def __init__(self, data):
        self.data = bytes(data)
        self.sections = sections(self.data)
        self.by_name = {s['name']: s for s in self.sections}
        require(len(self.by_name) == len(self.sections), 'duplicate section name')
        require(struct.unpack_from('<H', self.data, 18)[0] == 62, 'not x86-64')
        self.cies, self.fdes = eh_frame_records(self.data, self.sections)
        self.fdes.sort(key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.fdes]
        require(len(set(self.starts)) == len(self.starts), 'duplicate FDE start')
        self.relocations = {}
        for sec in self.sections:
            if sec['type'] != 4:
                continue
            require(sec['size'] % 24 == 0, 'partial RELA')
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                require(dst not in self.relocations, 'duplicate relocation destination')
                self.relocations[dst] = dict(slot=hex(dst), kind=info & 0xffffffff,
                    symbol_index=info >> 32, addend=addend, file_offset=hex(off),
                    record_hex=self.data[off:off + 24].hex())
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def offset(self, va, length):
        require(type(length) is int and length > 0, 'nonpositive read')
        hits = [s['offset'] + va - s['address'] for s in self.sections
                if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
        require(len(hits) == 1, f'unmapped/ambiguous read {va:#x}+{length}')
        return hits[0]

    def read(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]

    def owner(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index >= 0 and va < self.fdes[index]['end']:
            return self.fdes[index]
        return None

    def decode(self, start, end):
        raw = self.read(start, end - start)
        decoded = list(self.md.disasm(raw, start))
        require(decoded and sum(i.size for i in decoded) == len(raw), 'incomplete decode')
        starts = {i.address for i in decoded}
        for ins in decoded:
            if ins.group(CS_GRP_JUMP) and ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                require(not start <= target < end or target in starts, 'branch inside instruction')
        return decoded

    def binding(self, slot):
        row = self.relocations.get(slot)
        if row is None:
            return None
        row = dict(row)
        if row['symbol_index']:
            sym = self.by_name['.dynsym']
            index = row['symbol_index']
            require(index * 24 + 24 <= sym['size'], 'dynsym out of bounds')
            name = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
            strings = self.by_name['.dynstr']
            require(name < strings['size'], 'dynstr out of bounds')
            off = strings['offset'] + name
            end = self.data.find(b'\0', off, strings['offset'] + strings['size'])
            require(end >= 0, 'unterminated dynsym name')
            row['symbol'] = self.data[off:end].decode('ascii')
        elif row['kind'] == 8:
            row['target'] = hex(row['addend'])
            owner = self.owner(row['addend'])
            if owner:
                row['target_fde'] = [hex(owner['start']), hex(owner['end'])]
        return row


def instruction(ins):
    return {'va': hex(ins.address), 'bytes': bytes(ins.bytes).hex(),
            'mnemonic': ins.mnemonic, 'operands': ins.op_str}


def exception_sites(image, frame, starts):
    """Read the bounded LSDA header/call-site table; action semantics stay open."""
    va = frame['lsda']
    if va is None:
        return None
    sec = image.by_name['.gcc_except_table']
    require(sec['address'] <= va < sec['address'] + sec['size'], 'LSDA outside section')
    begin = image.offset(va, 1)
    pos, limit, data = begin, sec['offset'] + sec['size'], image.data
    require(data[pos] == 0xff, 'unsupported LPStart encoding')
    typ = data[pos + 1]
    pos += 2
    type_base = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, limit)
        type_base = pos + delta
        require(type_base <= limit, 'LSDA type table outside section')
    else:
        require(typ == 0xff, 'unsupported type encoding')
    require(data[pos] == 1, 'unsupported call-site encoding')
    size, pos = uleb(data, pos + 1, limit)
    end = pos + size
    require(end <= limit, 'truncated call-site table')
    rows, previous = [], frame['start']
    while pos < end:
        first, values = pos, []
        for _ in range(4):
            value, pos = uleb(data, pos, end)
            values.append(value)
        offset, length, landing, action = values
        start = frame['start'] + offset
        pad = frame['start'] + landing if landing else None
        require(previous <= start <= start + length <= frame['end'], 'LSDA interval invalid')
        require(pad is None or pad in starts, 'landing pad not an instruction')
        previous = start + length
        rows.append({'start': hex(start), 'end_exclusive': hex(start + length),
                     'landing_pad': hex(pad) if pad else None, 'action_index': action,
                     'hex': data[first:pos].hex()})
    require(pos == end, 'LSDA table overrun')
    return {'va': hex(va), 'header_and_call_sites_hex': data[begin:end].hex(),
            'type_encoding': typ, 'type_table_file_offset': hex(type_base) if type_base else None,
            'action_records_decoded': False, 'rows': rows}


def spec():
    value = json.loads((PACKET / 'spec.json').read_text(), object_pairs_hook=unique)
    require(value['schema'] == 1 and value['target_sha256'] == SHA256
            and value['target_bytes'] == 105896032, 'spec identity changed')
    return value


def unique_writer(image, slot):
    writers = [r for dst, r in image.relocations.items() if dst < slot + 8 and slot < dst + 8]
    require(len(writers) == 1 and int(writers[0]['slot'], 16) == slot, 'ambiguous or missing slot writer')
    return image.binding(slot)


def zero_fill(image, va, length):
    data = image.data
    off = struct.unpack_from('<Q', data, 32)[0]
    stride, count = struct.unpack_from('<HH', data, 54)
    require(stride >= 56 and off + stride * count <= len(data), 'invalid program headers')
    hits = []
    for i in range(count):
        kind, flags, _, base, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', data, off + i * stride)
        if kind == 1 and flags & 2 and base + filesz <= va and va + length <= base + memsz:
            hits.append({'zero_start': hex(base + filesz), 'zero_end': hex(base + memsz)})
    require(len(hits) == 1, 'global not uniquely writable zero-fill')
    require(not any(dst < va + length and va < dst + 8 for dst in image.relocations), 'global relocated')
    return {'va': hex(va), 'length': length, 'initial_zero_only': True, **hits[0]}


def extract(image, expected=None):
    """Static observation under identity admission; controls also exercise this layer."""
    expected = expected or spec()
    decoded, bodies, lsdas = {}, [], {}
    for name, pair in expected['ranges'].items():
        start, end = (int(a, 16) for a in pair)
        frame = image.owner(start)
        require(frame and (frame['start'], frame['end']) == (start, end), 'FDE extent changed: ' + name)
        require(not any(slot < end and start < slot + 8 for slot in image.relocations), 'relocation writer overlaps body')
        insns = image.decode(start, end)
        decoded[name] = insns
        row = {'name': name, 'role': 'primary' if name in expected['primary'] else 'context only',
               'start': hex(start), 'end_exclusive': hex(end), 'bytes': end - start,
               'sha256': digest(image.read(start, end - start)), 'instructions': len(insns)}
        for key in ('fde', 'cie'):
            va = frame[key]
            length = struct.unpack('<I', image.read(va, 4))[0] + 4
            row[key + '_va'] = hex(va)
            row[key + '_hex'] = image.read(va, length).hex()
        bodies.append(row)
        lsdas[name] = exception_sites(image, frame, {i.address for i in insns})
    sites = {i.address: i for insns in decoded.values() for i in insns}
    anchors = []
    for name, row in expected['anchors'].items():
        va, raw = int(row['va'], 16), bytes.fromhex(row['hex'])
        require(va in sites and bytes(sites[va].bytes) == raw, 'semantic instruction changed: ' + name)
        anchors.append({'name': name, **row})
    for row in bodies:
        require(row['sha256'] == expected['body_sha256'][row['name']], 'complete-body hash changed: ' + row['name'])
    constants = []
    for va, raw in expected['constants'].items():
        base, size = int(va, 16), len(bytes.fromhex(raw))
        require(image.read(base, size).hex() == raw, 'constant changed')
        require(not any(slot < base + size and base < slot + 8 for slot in image.relocations), 'constant relocation changed')
        constants.append({'va': va, 'hex': raw})
    bindings = []
    for va, exp in expected['bindings'].items():
        row = unique_writer(image, int(va, 16))
        require(all(row[k] == v for k, v in exp.items()), 'binding changed: ' + va)
        bindings.append(row)
    locations = []
    for name, row in expected['source_locations'].items():
        va = int(row['va'], 16)
        require(image.read(va, 24).hex() == row['raw_hex'], 'source location layout changed')
        require(not any(va + 8 <= slot < va + 24 for slot in image.relocations), 'source location scalar relocation')
        binding = unique_writer(image, va)
        require(binding['kind'] == 8 and binding['symbol_index'] == 0
                and binding['addend'] == int(row['text_va'], 16), 'source location pointer changed')
        raw = image.read(binding['addend'], row['length'])
        require(raw.decode() == row['text'], 'source path changed')
        locations.append({'name': name, **row, 'binding': binding})
    literals = []
    for name, row in expected['literals'].items():
        require(image.read(int(row['va'], 16), len(row['text'])).decode() == row['text'], 'literal changed')
        literals.append({'name': name, **row})
    calls, rip = [], []
    for name, insns in decoded.items():
        for ins in insns:
            if ins.mnemonic in ('call', 'jmp'):
                row = {'owner': name, **instruction(ins)}
                operand = ins.operands[0]
                if operand.type == X86_OP_IMM:
                    row['target'] = hex(operand.imm)
                elif operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    slot = ins.address + ins.size + operand.mem.disp
                    row['slot'] = hex(slot)
                    row['binding'] = image.binding(slot)
                    if row['binding'] and row['binding']['kind'] == 8:
                        row['target'] = hex(row['binding']['addend'])
                else:
                    row['unresolved_register_or_memory_edge'] = True
                calls.append(row)
            for operand in ins.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    va = ins.address + ins.size + operand.mem.disp
                    row = {'owner': name, **instruction(ins), 'referenced_va': hex(va), 'width': operand.size,
                           'binding': image.binding(va)}
                    rip.append(row)
    for va, target in expected['calls_expected'].items():
        matches = [r for r in calls if r['va'] == va and r['mnemonic'] == 'call']
        require(len(matches) == 1 and matches[0].get('target') == target, 'call boundary changed: ' + va)
    entries = {int(expected['ranges'][n][0], 16) for n in expected['primary']}
    naming = [unique_writer(image, slot) for slot, row in image.relocations.items()
              if row['kind'] == 8 and row['addend'] in entries]
    return {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses',
            'captured_binary_executed': False, 'emulator_used': False, 'source_build_compared': False,
            'primary_bytes': sum(r['bytes'] for r in bodies if r['role'] == 'primary'),
            'bodies': bodies, 'anchors': anchors, 'constants': constants, 'bindings': bindings,
            'source_locations': locations, 'literals': literals,
            'global': zero_fill(image, int(expected['global']['va'], 16), expected['global']['length']),
            'calls_and_jumps': calls, 'rip_references': rip, 'exception_tables': lsdas,
            'primary_naming_relocations': naming, 'relocations_scanned': len(image.relocations),
            'instructions': {n: [instruction(i) for i in v] for n, v in decoded.items()}}


def analyze(data):
    require(len(data) == 105896032 and digest(data) == SHA256, 'node115 identity mismatch')
    return extract(Image(data))


LLVM_LOCK_JOINS = {
    0x161a125: bytes.fromhex('f00fb10b'),
    0x161a165: bytes.fromhex('f048ff8280010000'),
    0x161a173: bytes.fromhex('f048ff06'),
    0x161a1c0: bytes.fromhex('f048ff8200020000'),
    0x161a1d4: bytes.fromhex('f048ff4270'),
    0x5cd6365: bytes.fromhex('f049ff4500'),
    0x5cd63d0: bytes.fromhex('f049ff4d00'),
    0x5cd5f78: bytes.fromhex('f048ff0b'),
    0x5cd5f8e: bytes.fromhex('f048ff08'),
    0x5cd5fe8: bytes.fromhex('f049ff0c24'),
    0x5cd600a: bytes.fromhex('f048ff08'),
    0x5cd959e: bytes.fromhex('f04c0fb13da96a8200'),
    0x5cd96ad: bytes.fromhex('f048ff00'),
    0x5cd96e3: bytes.fromhex('f048ff4718'),
    0x5cd9750: bytes.fromhex('f049ff0424'),
    0x5cd97c7: bytes.fromhex('f048ff08'),
    0x5cd97d8: bytes.fromhex('f049ff0c24'),
    0x5cd9a66: bytes.fromhex('f048ff08'),
    0x5cd9aa0: bytes.fromhex('f049ff0c24'),
    0x5cd9ad3: bytes.fromhex('f048ff08'),
    0x5cd9af6: bytes.fromhex('f048ff08'),
    0x5cd6a27: bytes.fromhex('f048ff4868'),
    0x5cd6a4d: bytes.fromhex('f048ff07'),
    0x5cd6a66: bytes.fromhex('f048ff4078'),
    0x1617155: bytes.fromhex('f048ff00'),
    0x16172f2: bytes.fromhex('f048ff08'),
    0x16173f4: bytes.fromhex('f048ff08'),
    0x161770b: bytes.fromhex('f049ff8780010000'),
    0x1617720: bytes.fromhex('f049ff8700020000'),
    0x1617730: bytes.fromhex('f049ff4770'),
    0x1617740: bytes.fromhex('f048ff00'),
    0x1617754: bytes.fromhex('f048ff01'),
    0x1617b72: bytes.fromhex('f048ff8b08020000'),
    0x1617bd1: bytes.fromhex('f048ff8b00020000'),
    0x1617bf6: bytes.fromhex('f0480fb19380000000'),
    0x1617c2f: bytes.fromhex('f048ff08'),
    0x1617c45: bytes.fromhex('f048ff08'),
    0x1617ec2: bytes.fromhex('f048ff08'),
    0x1617eff: bytes.fromhex('f048ff08'),
    0x1617fbe: bytes.fromhex('f048ff08'),
    0x1617fd4: bytes.fromhex('f048ff08'),
    0x1617fea: bytes.fromhex('f049ff4d00'),
    0x1618009: bytes.fromhex('f048ff08'),
    0x1618345: bytes.fromhex('f048ff00'),
    0x16184e2: bytes.fromhex('f048ff08'),
    0x1618630: bytes.fromhex('f048ff08'),
    0x161894b: bytes.fromhex('f049ff8780010000'),
    0x1618960: bytes.fromhex('f049ff8700020000'),
    0x1618970: bytes.fromhex('f049ff4770'),
    0x1618980: bytes.fromhex('f048ff00'),
    0x1618994: bytes.fromhex('f048ff01'),
    0x1618e03: bytes.fromhex('f048ff8b08020000'),
    0x1618e62: bytes.fromhex('f048ff8b00020000'),
    0x1618e86: bytes.fromhex('f0480fb19380000000'),
    0x1618ebf: bytes.fromhex('f048ff08'),
    0x1618ed5: bytes.fromhex('f048ff08'),
    0x1619161: bytes.fromhex('f048ff08'),
    0x16191a5: bytes.fromhex('f048ff08'),
    0x161926c: bytes.fromhex('f048ff08'),
    0x1619282: bytes.fromhex('f048ff08'),
    0x1619298: bytes.fromhex('f049ff4d00'),
    0x16192b7: bytes.fromhex('f048ff08'),
}

def native_bytes(text, start, end, llvm=False):
    """Only collect actual disassembler instruction byte columns; no text emulation."""
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
        if m and start <= int(m[1], 16) < end:
            raw = bytes.fromhex(m[2])
            rows.append((int(m[1], 16), raw))
    cursor = start
    for va, raw in rows:
        require(va == cursor and raw, 'native disassembly gap/overlap')
        cursor += len(raw)
    require(cursor == end, 'native disassembly incomplete')
    if llvm:
        joined, index = [], 0
        while index < len(rows):
            va, raw = rows[index]
            if va in LLVM_LOCK_JOINS and raw == b'\xf0':
                require(index + 1 < len(rows) and rows[index + 1][0] == va + 1
                        and raw + rows[index + 1][1] == LLVM_LOCK_JOINS[va],
                        'unexpected LLVM LOCK display split')
                joined.append((va, LLVM_LOCK_JOINS[va]))
                index += 2
            else:
                joined.append((va, raw))
                index += 1
        rows = joined
    return rows


def export(binary, output):
    data = Path(binary).read_bytes()
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    gnu = os.environ.get('GNU_OBJDUMP', 'objdump')
    llvm = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
    exports, commands = {}, []
    # Both providers consume exactly the already authenticated byte snapshot.
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node115'
        snapshot.write_bytes(data)
        for label, exe in [('gnu', gnu), ('llvm', llvm)]:
            for name, (start, end) in {n: tuple(int(v, 16) for v in r) for n, r in spec()['ranges'].items()}.items():
                args = [exe, '-d', '--start-address=' + hex(start), '--stop-address=' + hex(end)]
                args += ['-M', 'intel', '--insn-width=16'] if label == 'gnu' else ['--x86-asm-syntax=intel']
                args.append(str(snapshot))
                process = subprocess.run(args, capture_output=True)
                stdout = process.stdout.replace(str(snapshot).encode(), b'<authenticated-node115>')
                stderr = process.stderr.replace(str(snapshot).encode(), b'<authenticated-node115>')
                require(process.returncode == 0, f'{label} export failed: {stderr.decode(errors="replace")}')
                (output / f'{name}.{label}.txt').write_bytes(stdout)
                if stderr:
                    (output / f'{name}.{label}.stderr').write_bytes(stderr)
                rows = native_bytes(stdout.decode(), start, end, llvm=(label == 'llvm'))
                expected = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][name]]
                require(rows == expected, f'{label} {name} instruction boundaries/bytes disagree')
                exports[f'{name}.{label}.txt'] = stdout
                commands.append({'provider': label, 'name': name,
                    'argv': [str(x).replace(str(snapshot), '<authenticated-node115>') for x in args],
                    'exit_code': process.returncode, 'stdout_sha256': digest(stdout),
                    'stderr_hex': stderr.hex(), 'instruction_rows': len(rows),
                    'display_joins': [hex(a) for a in LLVM_LOCK_JOINS if start <= a < end] if label == 'llvm' else []})
    for name, value in exports.items():
        (output / name).write_bytes(value)
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'native-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    report = export(args.binary, args.output) if args.output else analyze(args.binary.read_bytes())
    if args.check:
        expected = json.loads((PACKET / 'static/records.json').read_text(), object_pairs_hook=unique)
        require(report == expected, 'committed static evidence differs')
    print(json.dumps({'primary_bytes': report['primary_bytes'], 'bodies': len(report['bodies']),
        'total_bytes': sum(r['bytes'] for r in report['bodies']),
        'instructions': sum(r['instructions'] for r in report['bodies']),
        'captured_binary_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
