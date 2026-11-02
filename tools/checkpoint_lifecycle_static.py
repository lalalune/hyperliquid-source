#!/usr/bin/env python3
"""Digest-bound node115 checkpoint command preparation; never executes the target."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-009-node115-checkpoint-lifecycle'
BOUNDS = [(0x44681e0, 0x4468b62), (0x15028f0, 0x1502b78),
          (0x1500a60, 0x1500b83), (0x1500d20, 0x1500e43)]


def mapping(data):
    secs = sections(data)

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('ambiguous or absent file mapping')
        s = matches[0]
        offset = s['offset'] + va - s['address']
        return offset, bytes(data[offset:offset + size])
    return secs, read


def predicates(data):
    """Read actual operands for local relations, not a node/command emulator."""
    _, read = mapping(data)
    checks = {0x44682e6: '4084ed', 0x44682e9: '0f84',
              0x15029fb: '84c0', 0x15029fd: '480f45d1',
              0x1502a01: '4883c0', 0x15029ed: '488d0d',
              0x15029f4: '488d15', 0x1502a05: '488d0d'}
    for pc, raw in checks.items():
        value = bytes.fromhex(raw)
        if read(pc, len(value))[1] != value:
            raise ValueError('local opcode changed')
    destination = 0x44682ef + struct.unpack('<i', read(0x44682eb, 4)[1])[0]
    def lea(pc):
        return pc + 7 + struct.unpack('<i', read(pc + 3, 4)[1])[0]
    return {'zero_mode_target': destination,
            'nonzero_flag_address': lea(0x15029ed),
            'zero_flag_address': lea(0x15029f4),
            'flag_length_bias': read(0x1502a04, 1)[1][0],
            'command_address': lea(0x1502a05),
            'directory_mask': struct.unpack('<I', read(0x1500b1b, 4)[1])[0],
            'directory_value': struct.unpack('<I', read(0x1500b24, 4)[1])[0],
            'file_mask': struct.unpack('<I', read(0x1500ddb, 4)[1])[0],
            'file_value': struct.unpack('<I', read(0x1500de4, 4)[1])[0]}


def command_projection(data, mode):
    if not 0 <= mode <= 255:
        raise ValueError('mode must be an input byte')
    p = predicates(data)
    _, read = mapping(data)
    address = p['nonzero_flag_address'] if mode else p['zero_flag_address']
    return {'command': read(p['command_address'], 2)[1].decode('ascii'),
            'flag': read(address, mode + p['flag_length_bias'])[1].hex()}


def analyze(data):
    if capstone.__version__ != '5.0.7':
        raise ValueError('Capstone 5.0.7 required')
    secs, read = mapping(data)
    names = [s['name'] for s in secs]
    if names.count('.rela.dyn') != 1:
        raise ValueError('ambiguous relocation section')
    section = next(s for s in secs if s['name'] == '.rela.dyn')
    relocs = {}
    for address, info, addend in struct.iter_unpack('<QQq', data[section['offset']:section['offset'] + section['size']]):
        if address in relocs:
            raise ValueError('duplicate relocation slot')
        relocs[address] = (info, addend)
    _, frames, _ = fde_extents(data)
    owners = {}
    for frame in frames:
        if frame['start'] in owners:
            raise ValueError('duplicate FDE start')
        owners[frame['start']] = frame
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    result = {'target_sha256': SHA, 'source_base': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
              'capstone': capstone.__version__, 'owners': [], 'predicates': predicates(data),
              'calls': [], 'rip_bindings': [], 'locations': []}
    for start, end in BOUNDS:
        frame = owners.get(start)
        if frame is None or frame['end'] != end:
            raise ValueError('FDE extent changed')
        offset, body = read(start, end - start)
        insns = list(md.disasm(body, start))
        cursor = start
        for insn in insns:
            if insn.address != cursor:
                raise ValueError('noncontiguous decode')
            cursor += insn.size
            if insn.mnemonic == 'call':
                operand = insn.operands[0]
                row = {'pc': hex(insn.address), 'raw': insn.bytes.hex(), 'operand': insn.op_str}
                if operand.type == X86_OP_IMM:
                    row['direct_target'] = hex(operand.imm)
                result['calls'].append(row)
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    address = insn.address + insn.size + operand.mem.disp
                    row = {'pc': hex(insn.address), 'raw': insn.bytes.hex(), 'address': hex(address)}
                    if address in relocs:
                        info, addend = relocs[address]
                        row['relocation'] = {'info': info, 'addend': hex(addend)}
                        if info == 8:
                            try:
                                _, source = read(addend, 17)
                                if source == b'db/src/db_home.rs':
                                    _, loc = read(address + 8, 16)
                                    length, line, column = struct.unpack('<QII', loc)
                                    result['locations'].append({'pc': hex(insn.address), 'slot': hex(address),
                                                                'length': length, 'line': line, 'column': column})
                            except ValueError:
                                pass
                    result['rip_bindings'].append(row)
        if cursor != end:
            raise ValueError('incomplete decode')
        result['owners'].append({'start': hex(start), 'end': hex(end), 'file_offset': offset,
                                 'bytes': len(body), 'instructions': len(insns),
                                 'sha256': hashlib.sha256(body).hexdigest(), 'fde': frame})
    result['literals'] = {hex(a): read(a, n)[1].hex() for a, n in
                          [(0x434739, 14), (0x44f3c9, 18), (0x465a05, 7)]}
    return result


def generate(target, output):
    data = Path(target).read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node115 identity mismatch')
    report = analyze(data)
    _, read = mapping(data)
    # Only GNU tools inspect a byte-identical private copy; no captured code is run.
    with tempfile.TemporaryDirectory() as directory:
        copy = Path(directory) / 'node115'
        copy.write_bytes(data)
        exports = {}
        for start, end in BOUNDS:
            command = ['objdump', '-d', '-M', 'intel', f'--start-address={start}', f'--stop-address={end}', 'node115']
            raw = subprocess.run(command, cwd=directory, check=True, capture_output=True, text=True).stdout
            decode_export(raw, start, end, read(start, end - start)[1])
            exports[f'{start:x}.objdump.txt'] = '\n'.join(line.rstrip() for line in raw.splitlines()) + '\n'
        version = subprocess.run(['objdump', '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'native-tools.txt').write_text(version + '\n')
    for name, raw in exports.items():
        (output / name).write_text(raw)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.target, args.output)
