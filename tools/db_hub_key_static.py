#!/usr/bin/env python3
"""RE-009 db-hub byte-key lookup evidence; static parsing only."""
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
PACKET = ROOT / 'research/work-items/RE-009-node115-db-hub-byte-key'
START, END = 0x1692ca0, 0x1692fe9


def reader(data):
    secs = sections(data)
    def read(address, size):
        candidates = [s for s in secs if s['type'] != 8 and s['address'] <= address and
                      address + size <= s['address'] + s['size']]
        if len(candidates) != 1:
            raise ValueError('ambiguous file-backed address')
        s = candidates[0]
        offset = s['offset'] + address - s['address']
        return offset, bytes(data[offset:offset + size])
    return secs, read


def parameters(data):
    _, read = reader(data)
    patterns = {0x1692d0f: '498b47', 0x1692d1c: '498b4f', 0x1692d24: '0fb770',
                0x1692d4a: '440fb64410', 0x1692d61: '4180f8',
                0x1692d83: '4883e9', 0x1692d8d: '488b44d0', 0x1692d97: '488b6cd0'}
    for pc, raw in patterns.items():
        if read(pc, len(bytes.fromhex(raw)))[1] != bytes.fromhex(raw):
            raise ValueError('lookup opcode changed')
    result = {name: read(address, 1)[1][0] for name, address in
              [('root_offset', 0x1692d12), ('height_offset', 0x1692d1f),
               ('count_offset', 0x1692d27), ('key_biased_offset', 0x1692d4f),
               ('continue_comparison', 0x1692d64), ('height_decrement', 0x1692d86),
               ('child_offset', 0x1692d91), ('value_offset', 0x1692d9b)]}
    result['equal_value_adjustment'] = read(0x1692d9f, 1)[1][0]
    return result


def local_scan(p, keys, query):
    """Scalar loop relation only; no target memory, CPU state or helper execution."""
    if not 0 <= query <= 255 or any(not 0 <= k <= 255 for k in keys):
        raise ValueError('u8 keys required')
    for index, key in enumerate(keys):
        comparison = (query > key) - (query < key)
        if (comparison & 255) == p['continue_comparison']:
            continue
        return {'index': index, 'equal': comparison == 0}
    return {'index': len(keys), 'equal': False}


def analyze(data):
    if capstone.__version__ != '5.0.7':
        raise ValueError('Capstone 5.0.7 required')
    secs, read = reader(data)
    _, frames, _ = fde_extents(data)
    selected = [f for f in frames if f['start'] == START]
    if len(selected) != 1 or selected[0]['end'] != END:
        raise ValueError('lookup FDE extent changed')
    reloc_sections = [s for s in secs if s['name'] == '.rela.dyn']
    if len(reloc_sections) != 1:
        raise ValueError('ambiguous relocation section')
    s = reloc_sections[0]
    relocs = {}
    for a, i, v in struct.iter_unpack('<QQq', data[s['offset']:s['offset'] + s['size']]):
        if a in relocs:
            raise ValueError('duplicate relocation slot')
        relocs[a] = (i, v)
    offset, body = read(START, END - START)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns = list(md.disasm(body, START))
    cursor = START
    result = {'target_sha256': SHA, 'source_base': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
              'start': hex(START), 'end': hex(END), 'file_offset': offset,
              'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
              'instructions': len(insns), 'fde': selected[0], 'parameters': parameters(data),
              'calls': [], 'branches': [], 'rip_bindings': [], 'source_locations': []}
    for insn in insns:
        if insn.address != cursor:
            raise ValueError('noncontiguous decode')
        cursor += insn.size
        if insn.mnemonic == 'call' or insn.mnemonic.startswith('j'):
            row = {'pc': hex(insn.address), 'bytes': insn.bytes.hex(), 'mnemonic': insn.mnemonic,
                   'operand': insn.op_str}
            if insn.operands[0].type == X86_OP_IMM:
                row['destination'] = hex(insn.operands[0].imm)
            result['calls' if insn.mnemonic == 'call' else 'branches'].append(row)
        for operand in insn.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                a = insn.address + insn.size + operand.mem.disp
                row = {'pc': hex(insn.address), 'bytes': insn.bytes.hex(), 'address': hex(a)}
                if a in relocs:
                    info, addend = relocs[a]
                    row['relocation'] = {'info': info, 'addend': hex(addend)}
                    if info == 8:
                        try:
                            if read(addend, 16)[1] == b'db/src/db_hub.rs':
                                length, line, column = struct.unpack('<QII', read(a + 8, 16)[1])
                                result['source_locations'].append({'pc': hex(insn.address), 'slot': hex(a),
                                                                   'length': length, 'line': line, 'column': column})
                        except ValueError:
                            pass
                result['rip_bindings'].append(row)
    if cursor != END:
        raise ValueError('incomplete decode')
    return result


def generate(target, output):
    data = Path(target).read_bytes()
    if len(data) != 105896032 or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node115 identity mismatch')
    report = analyze(data)
    with tempfile.TemporaryDirectory() as directory:
        (Path(directory) / 'node115').write_bytes(data)
        raw = subprocess.run(['objdump', '-d', '-M', 'intel', f'--start-address={START}',
                              f'--stop-address={END}', 'node115'], cwd=directory, check=True,
                             capture_output=True, text=True).stdout
        decode_export(raw, START, END, reader(data)[1](START, END - START)[1])
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / '1692ca0.objdump.txt').write_text('\n'.join(line.rstrip() for line in raw.splitlines()) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    generate(args.target, args.output)
