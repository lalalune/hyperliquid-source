#!/usr/bin/env python3
"""Node115 startup end-height reduction and caller binding, without execution."""
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
PACKET = ROOT / 'research/work-items/RE-012-node115-startup-end-height'
BOUNDS = [(0x595b1a0, 0x595b512), (0x2b41b70, 0x2b43283)]


def reader(data):
    secs = sections(data)
    def read(address, size):
        rows = [s for s in secs if s['type'] != 8 and s['address'] <= address and
                address + size <= s['address'] + s['size']]
        if len(rows) != 1:
            raise ValueError('ambiguous file-backed mapping')
        s = rows[0]
        offset = s['offset'] + address - s['address']
        return offset, bytes(data[offset:offset + size])
    return secs, read


def parameters(data):
    _, read = reader(data)
    for address, raw in [(0x595b3a4, '4d39ce'), (0x595b3b5, '4d39ce'),
                         (0x595b3d3, '4939ce'), (0x2b41eb8, '493917'),
                         (0x2b41d42, '4883f8'), (0x2b41eb3, '48895424')]:
        if read(address, len(bytes.fromhex(raw)))[1] != bytes.fromhex(raw):
            raise ValueError('reduction/caller opcode changed')
    return {'cmov_conditions': [read(a, 1)[1][0] for a in [0x595b3a9, 0x595b3ba, 0x595b3d8]],
            'caller_error_tag': read(0x2b41d45, 1)[1][0],
            'caller_stack_store_offset': read(0x2b41eb7, 1)[1][0],
            'caller_unsigned_condition': read(0x2b41ebc, 1)[1][0],
            'caller_unsigned_destination': 0x2b41ec1 + struct.unpack('<i', read(0x2b41ebd, 4)[1])[0]}


def reduce_values(p, values):
    """Scalar unsigned selection relation; not target memory or helper emulation."""
    if any(not 0 <= value < 1 << 64 for value in values):
        raise ValueError('u64 candidate required')
    if not values:
        return None
    current = values[0]
    condition = p['cmov_conditions'][0]
    if len(set(p['cmov_conditions'])) != 1 or condition not in [0x46, 0x47]:
        raise ValueError('unsupported measured selection condition')
    for value in values[1:]:
        select = current <= value if condition == 0x46 else current > value
        if select:
            current = value
    return current


def analyze(data):
    if capstone.__version__ != '5.0.7':
        raise ValueError('Capstone 5.0.7 required')
    secs, read = reader(data)
    rows = [s for s in secs if s['name'] == '.rela.dyn']
    if len(rows) != 1:
        raise ValueError('ambiguous relocation section')
    s = rows[0]
    relocs = {}
    for a, i, v in struct.iter_unpack('<QQq', data[s['offset']:s['offset'] + s['size']]):
        if a in relocs:
            raise ValueError('duplicate relocation slot')
        relocs[a] = (i, v)
    if relocs.get(0x64e7720) != (8, 0x595b1a0):
        raise ValueError('startup selector relocation changed')
    _, frames, _ = fde_extents(data)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    result = {'target_sha256': SHA, 'source_base': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
              'parameters': parameters(data), 'owners': [], 'calls': [], 'branches': [],
              'rip_bindings': [], 'locations': []}
    for start, end in BOUNDS:
        selected = [f for f in frames if f['start'] == start]
        if len(selected) != 1 or selected[0]['end'] != end:
            raise ValueError('selected FDE extent changed')
        offset, body = read(start, end - start)
        insns = list(md.disasm(body, start))
        cursor = start
        for insn in insns:
            if cursor != insn.address:
                raise ValueError('noncontiguous decode')
            cursor += insn.size
            if insn.mnemonic == 'call' or insn.mnemonic.startswith('j'):
                row = {'pc': hex(insn.address), 'raw': insn.bytes.hex(), 'mnemonic': insn.mnemonic,
                       'operand': insn.op_str}
                if insn.operands[0].type == X86_OP_IMM:
                    row['destination'] = hex(insn.operands[0].imm)
                result['calls' if insn.mnemonic == 'call' else 'branches'].append(row)
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    a = insn.address + insn.size + operand.mem.disp
                    row = {'pc': hex(insn.address), 'raw': insn.bytes.hex(), 'address': hex(a)}
                    if a in relocs:
                        info, addend = relocs[a]
                        row['relocation'] = {'info': info, 'addend': hex(addend)}
                        if info == 8:
                            try:
                                if read(addend, 19)[1] == b'node/src/startup.rs':
                                    length, line, column = struct.unpack('<QII', read(a + 8, 16)[1])
                                    result['locations'].append({'pc': hex(insn.address), 'slot': hex(a),
                                                                'length': length, 'line': line, 'column': column})
                            except ValueError:
                                pass
                    result['rip_bindings'].append(row)
        if cursor != end:
            raise ValueError('incomplete decode')
        result['owners'].append({'start': hex(start), 'end': hex(end), 'bytes': len(body),
                                 'instructions': len(insns), 'file_offset': offset,
                                 'sha256': hashlib.sha256(body).hexdigest(), 'fde': selected[0]})
    result['literals'] = {hex(a): read(a, n)[1].hex() for a, n in
                          [(0x439f32, 24), (0x448b77, 10), (0x436a4e, 70)]}
    return result


def generate(target, output):
    data = Path(target).read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node115 identity mismatch')
    result = analyze(data)
    _, read = reader(data)
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / 'node115').write_bytes(data)
        exports = {}
        for start, end in BOUNDS:
            raw = subprocess.run(['objdump', '-d', '-M', 'intel', f'--start-address={start}',
                                  f'--stop-address={end}', 'node115'], cwd=directory,
                                 check=True, capture_output=True, text=True).stdout
            decode_export(raw, start, end, read(start, end - start)[1])
            exports[f'{start:x}.objdump.txt'] = '\n'.join(line.rstrip() for line in raw.splitlines()) + '\n'
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_text(json.dumps(result, indent=2) + '\n')
    for name, raw in exports.items():
        (output / name).write_text(raw)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.target, args.output)
