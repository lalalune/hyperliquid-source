#!/usr/bin/env python3
"""Node115 root CLI/config construction: static bytes, not instruction execution."""
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
PACKET = ROOT / 'research/work-items/RE-012-cli-config-115'
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


def extract(image, expected=None):
    """Static observations below digest admission, also used by corruption controls."""
    expected = expected or spec()
    ranges = {name: tuple(int(a, 16) for a in pair) for name, pair in expected['ranges'].items()}
    bodies, decoded, lsdas = [], {}, {}
    for name, (start, end) in ranges.items():
        frame = image.owner(start)
        require(frame and (frame['start'], frame['end']) == (start, end), 'FDE extent changed: ' + name)
        insns = image.decode(start, end)
        decoded[name] = insns
        row = {'name': name, 'role': 'primary' if name in expected['primary'] else 'supporting context',
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
        require(va in sites and image.read(va, len(raw)) == raw, 'semantic anchor changed: ' + name)
        anchors.append({'name': name, **row})
    literals = []
    for name, row in expected['literals'].items():
        raw = row['text'].encode()
        require(image.read(int(row['va'], 16), len(raw)) == raw, 'literal changed: ' + name)
        literals.append({'name': name, **row, 'length': len(raw), 'hex': raw.hex()})
    vtables = []
    for name, row in expected['vtables'].items():
        va = int(row['va'], 16)
        require(image.read(va, 24) == struct.pack('<QQQ', 0, 0, 1), 'vtable header changed')
        allowed = {va + 24, va + 32, va + 40}
        require(not any(va - 7 <= slot < va + 48 and slot not in allowed
                        for slot in image.relocations), 'overlapping validator relocation')
        methods = []
        for slot, target in zip(sorted(allowed), row['targets']):
            binding = image.binding(slot)
            require(binding and binding['kind'] == 8 and binding['symbol_index'] == 0
                    and binding['addend'] == int(target, 16), 'validator slot binding changed')
            methods.append(binding)
        vtables.append({'name': name, 'va': hex(va), 'raw_hex': image.read(va, 48).hex(), 'methods': methods})
    table_va = int(expected['command_table']['va'], 16)
    table_raw = image.read(table_va, 76)
    entries = [hex(table_va + v) for v in struct.unpack('<19i', table_raw)]
    require(entries == expected['command_table']['entries']
            and all(int(a, 16) in sites for a in entries), 'length dispatch table changed')
    names = []
    for row in expected['commands']:
        value = [None] * len(row['name'])
        chunks = []
        for offset, width, kind, address in row['chunks']:
            va = int(address, 16)
            raw = image.read(va, 16 if kind == 'simd_tail' else width)
            require(kind in ('data', 'immediate', 'simd_tail'), 'unknown comparison kind')
            require(kind != 'simd_tail' or raw[width:] == bytes(16 - width), 'SIMD tail padding changed')
            require(0 <= offset and offset + width <= len(value), 'name chunk out of range')
            for k, byte in enumerate(raw[:width], offset):
                require(value[k] in (None, byte), 'overlapping name chunks disagree')
                value[k] = byte
            chunks.append({'input_offset': offset, 'input_bytes': width, 'kind': kind,
                           'constant_va': address, 'constant_hex': raw.hex()})
        require(None not in value and bytes(value) == row['name'].encode(), 'command spelling changed')
        require(int(row['compare'], 16) in sites and int(row['match'], 16) in sites,
                'command path boundary changed')
        va = int(row['store'], 16)
        if row['name'] == 'change-validator-profile':
            require(image.read(va, 7).hex() == '4c893b48896b08' and row['tags'] == [0, 1],
                    'profile presence output changed')
        else:
            require(image.read(va, 7) == bytes.fromhex('48c703') + struct.pack('<I', row['tags'][0]),
                    'command tag changed')
        names.append({k: v for k, v in row.items() if k != 'chunks'} | {'chunks': chunks})
    calls, rip, locations, options, stores = [], [], [], [], []
    for name, insns in decoded.items():
        for index, ins in enumerate(insns):
            if ins.mnemonic in ('call', 'jmp'):
                row = {'owner': name, **instruction(ins)}
                op = ins.operands[0]
                if op.type == X86_OP_IMM:
                    row['direct_target'] = hex(op.imm)
                    frame = image.owner(op.imm)
                    if frame:
                        row['target_fde'] = [hex(frame['start']), hex(frame['end'])]
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    slot = ins.address + ins.size + op.mem.disp
                    row['slot'] = hex(slot)
                    row['binding'] = image.binding(slot)
                else:
                    row['resolution'] = 'register/runtime indirect; no generic resolution claim'
                if ins.mnemonic == 'call' and lsdas[name]:
                    hits = [r for r in lsdas[name]['rows'] if int(r['start'], 16) <= ins.address
                            < int(r['end_exclusive'], 16)]
                    require(len(hits) <= 1, 'ambiguous exception interval')
                    row['exception_interval'] = hits[0] if hits else None
                calls.append(row)
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                va = ins.address + ins.size + op.mem.disp
                row = {'owner': name, 'site': hex(ins.address), 'referent': hex(va),
                       'width': op.size, 'binding': image.binding(va)}
                nobits = [s for s in image.sections if s['type'] == 8
                          and s['address'] <= va < s['address'] + s['size']]
                if nobits:
                    row['storage'] = 'NOBITS; runtime contents unknown'
                else:
                    row['hex'] = image.read(va, max(1, op.size)).hex()
                rip.append(row)
                rel = image.binding(va)
                if ins.mnemonic == 'lea' and rel and rel['kind'] == 8:
                    length, line, col = struct.unpack('<QII', image.read(va + 8, 16))
                    if 0 < length < 300 and 0 < line < 10000 and 0 < col < 10000:
                        try:
                            path = image.read(rel['addend'], length).decode('ascii')
                        except (ValueError, UnicodeDecodeError):
                            continue
                        if path.endswith('.rs'):
                            locations.append({'owner': name, 'site': hex(ins.address), 'record': hex(va),
                                'path': path, 'path_va': hex(rel['addend']), 'length': length,
                                'line': line, 'column': col, 'record_hex': image.read(va, 24).hex(), 'binding': rel})
            if name in ('config', 'commands') and ins.mnemonic == 'lea' and ins.op_str.startswith('rsi, [rip'):
                following = insns[index + 1]
                if following.mnemonic == 'mov' and following.op_str.startswith('edx, ') and following.operands[1].type == X86_OP_IMM:
                    length = following.operands[1].imm
                    va = ins.address + ins.size + ins.operands[1].mem.disp
                    require(0 < length < 100, 'unexpected option length')
                    literal = image.read(va, length)
                    options.append({'owner': name, 'site': hex(ins.address), 'length_site': hex(following.address),
                                    'va': hex(va), 'length': length, 'hex': literal.hex(), 'text': literal.decode('ascii'),
                                    'following': [instruction(i) for i in insns[index:index + 5]]})
            if name in expected['primary'] and ins.operands and ins.operands[0].type == X86_OP_MEM:
                mem = ins.operands[0].mem
                if ins.reg_name(mem.base) == 'rbx' and ins.mnemonic.startswith('mov'):
                    stores.append({'owner': name, **instruction(ins), 'offset': mem.disp, 'width': ins.operands[0].size})
    require([row['text'] for row in options] == expected['option_texts'], 'option literal/order changed')
    for site, (slot, target) in expected['bound_calls'].items():
        rows = [r for r in calls if r['va'] == site and r['mnemonic'] == 'call']
        require(len(rows) == 1 and rows[0].get('slot') == slot
                and rows[0].get('binding', {}).get('kind') == 8
                and rows[0]['binding']['addend'] == int(target, 16), 'bound call edge changed: ' + site)
    primary_entries = {ranges[n][0] for n in expected['primary']}
    naming = [image.binding(s) for s, row in image.relocations.items()
              if row['kind'] == 8 and row['addend'] in primary_entries]
    require([[r['slot'], hex(r['addend'])] for r in naming] == expected['primary_naming'], 'naming inventory changed')
    for row in naming:
        va = int(row['slot'], 16)
        require(not any(va - 7 <= slot < va + 8 and slot != va for slot in image.relocations),
                'overlapping entry-slot writer')
    return {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses',
            'captured_binary_executed': False, 'emulator_used': False,
            'primary_bytes': sum(r['bytes'] for r in bodies if r['role'] == 'primary'),
            'bodies': bodies, 'anchors': anchors, 'literals': literals, 'vtables': vtables,
            'commands': names, 'length_dispatch': expected['command_table'] | {'raw_hex': table_raw.hex()},
            'options': options, 'output_stores': stores, 'source_locations': locations,
            'calls_and_jumps': calls, 'rip_references': rip, 'exception_tables': lsdas,
            'primary_naming_relocations': naming, 'relocations_scanned': len(image.relocations),
            'instructions': {n: [instruction(i) for i in v] for n, v in decoded.items()}}


def analyze(data):
    require(len(data) == 105896032 and digest(data) == SHA256, 'node115 identity mismatch')
    return extract(Image(data))


LLVM_LOCK_JOINS = {0x2ae5dcb: bytes.fromhex('f048ff08'),
                   0x2ae5ddc: bytes.fromhex('f048ff08')}


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
        expected = json.loads((PACKET / 'records.json').read_text(), object_pairs_hook=unique)
        require(report == expected, 'committed static evidence differs')
    print(json.dumps({'primary_bytes': report['primary_bytes'], 'bodies': len(report['bodies']),
        'validator_tables': len(report['vtables']),
        'captured_binary_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
