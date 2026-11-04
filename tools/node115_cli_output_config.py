#!/usr/bin/env python3
"""Digest-bound RE-012 observations for the #115 CLI output constructor.

Static parsing/disassembly only. This is not a target interpreter or a CLI API.
Capstone supplies instruction boundaries; retained GNU output cross-checks them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = Path('artifacts/node/115/hl-node')
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
PRIMARY = 0x564d390
RANGES = [(PRIMARY, 0x564d6d8, 'output'),
          (0x4e4c8e0, 0x4e4ca21, 'presence-context'),
          (0x4e4ca30, 0x4e4cba7, 'value-context'),
          (0x5654bf0, 0x5655d5c, 'command-context')]


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


class Image:
    def __init__(self, data, authenticate=True):
        if authenticate:
            need(len(data) == 105896032 and sha(data) == DIGEST,
                 'Node115 artifact identity mismatch')
        self.data = data
        self.sections = sections(data)
        self.cies, self.fdes = eh_frame_records(data, self.sections)

    def offset(self, va, length):
        need(length >= 0, 'Negative read')
        hits = [s for s in self.sections if s['type'] != 8
                and s['address'] <= va and va + length <= s['address'] + s['size']]
        need(len(hits) == 1, 'Ambiguous or unbacked ELF VA')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, length):
        p = self.offset(va, length)
        return self.data[p:p + length]

    def extent(self, start, end):
        hits = [f for f in self.fdes if f['start'] == start]
        need(len(hits) == 1 and hits[0]['end'] == end, 'Changed selected FDE')
        f = hits[0]
        records = {}
        for key in ['fde', 'cie']:
            va = f[key]
            size = struct.unpack('<I', self.read(va, 4))[0] + 4
            records[key] = {'va': hex(va), 'bytes': self.read(va, size).hex()}
        return {**{k: hex(v) if v is not None else None for k, v in f.items()},
                'file_offset': self.offset(start, end - start),
                'length': end - start, 'sha256': sha(self.read(start, end - start)),
                'unwind_records': records}

    def relocations(self):
        rows = []
        for s in self.sections:
            if s['type'] != 4:
                continue
            need(s['size'] % 24 == 0, 'Truncated RELA')
            for p in range(s['offset'], s['offset'] + s['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', self.data, p)
                rows.append({'slot': slot, 'type': info & 0xffffffff,
                             'symbol_index': info >> 32, 'addend': addend,
                             'record_offset': p, 'bytes': self.data[p:p + 24].hex()})
        return rows

    def symbol(self, index):
        sym = next(s for s in self.sections if s['name'] == '.dynsym')
        strings = next(s for s in self.sections if s['name'] == '.dynstr')
        need(index * 24 + 24 <= sym['size'], 'Symbol index outside table')
        pos = sym['offset'] + index * 24
        name = struct.unpack_from('<I', self.data, pos)[0]
        need(name < strings['size'], 'Symbol name outside strings')
        lo = strings['offset'] + name
        hi = self.data.find(b'\0', lo, strings['offset'] + strings['size'])
        need(hi >= lo, 'Unterminated symbol')
        return self.data[lo:hi].decode('ascii')


def instructions(image, start, end):
    try:
        import capstone
    except ImportError as error:
        raise ValueError('Capstone Python bindings are required for native decoding') from error
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    result = list(md.disasm(image.read(start, end - start), start))
    cursor = start
    for i in result:
        need(i.address == cursor, 'Instruction boundary gap')
        need(bytes(i.bytes) == image.read(i.address, i.size), 'Decoder changed bytes')
        cursor += i.size
    need(cursor == end, 'Incomplete instruction decode')
    return result


def row(i):
    return {'va': hex(i.address), 'bytes': bytes(i.bytes).hex(),
            'mnemonic': i.mnemonic, 'operands': i.op_str}


def lsda(image, function, address):
    # The selected #115 table has omitted LPStart, omitted or indirect pcrel type table,
    # and ULEB128 call-site tuples. Action chains/type decoding remain unknown.
    pos = image.offset(address, 4)
    lo = pos
    data = image.data
    need(data[pos] == 0xff, 'Unsupported LSDA LPStart')
    pos += 1
    encoding = data[pos]
    pos += 1
    need(encoding in (0xff, 0x9b), 'Unsupported LSDA type encoding')
    type_base = None
    if encoding != 0xff:
        type_delta, pos = uleb(data, pos, len(data))
        type_base = pos + type_delta
    need(data[pos] == 1, 'Unsupported call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, len(data))
    end = pos + length
    rows = []
    while pos < end:
        a, pos = uleb(data, pos, end)
        b, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        rows.append({'start': hex(function + a), 'end': hex(function + a + b),
                     'landing': hex(function + landing) if landing else None,
                     'action_offset': action})
    section = next(s for s in image.sections if s['name'] == '.gcc_except_table')
    need(pos == end and end <= section['offset'] + section['size']
         and (type_base is None or end <= type_base <= section['offset'] + section['size']),
         'Invalid LSDA bounds')
    return {'va': hex(address), 'header_and_call_sites': data[lo:end].hex(),
            'call_sites': rows, 'type_table_file_offset': type_base,
            'limits': 'Action chains, types and transitive unwinding are not decoded.'}


def style_chunks(image, byva):
    # Reconstruct the actual overlapping constant chunks, not prose spellings.
    def immediate(va, width):
        i = byva[va]
        need(i.mnemonic in ('mov', 'movabs') and len(i.operands) == 2,
             'Changed style constant instruction')
        return int(i.operands[1].imm).to_bytes(width, 'little', signed=False)
    def assemble(length, chunks):
        out = bytearray(length)
        covered = set()
        for offset, value in chunks:
            need(offset >= 0 and offset + len(value) <= length, 'Style chunk outside value')
            for n, byte in enumerate(value, offset):
                need(n not in covered or out[n] == byte, 'Inconsistent style overlap')
                out[n] = byte
                covered.add(n)
        need(len(covered) == length, 'Style byte not covered')
        return bytes(out).decode('ascii')
    need(byva[0x564d583].mnemonic == 'xor' and byva[0x564d583].op_str == 'eax, eax',
         'Changed zero-style tag definition')
    return [
        {'tag': 0, 'length': byva[0x564d562].operands[1].imm, 'text': assemble(7, [(0, immediate(0x564d56c, 4)),
                                                  (3, immediate(0x564d573, 4))]),
         'tag_instruction': row(byva[0x564d583])},
        {'tag': byva[0x564d5a2].operands[1].imm, 'length': byva[0x564d55c].operands[1].imm, 'text': assemble(14, [(0, immediate(0x564d587, 8)),
                                                     (6, immediate(0x564d594, 8))]),
         'tag_instruction': row(byva[0x564d5a2])},
        {'tag': byva[0x564d65b].operands[1].imm, 'length': byva[0x564d552].operands[1].imm, 'text': assemble(21, [(0, image.read(0x450640, 16)),
                                                     (5, image.read(0x454130, 16))]),
         'tag_instruction': row(byva[0x564d65b])}]


def observe(image):
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    primary = instructions(image, PRIMARY, RANGES[0][1])
    byva = {i.address: i for i in primary}
    queries = []
    for index, i in enumerate(primary):
        if i.mnemonic != 'call' or i.operands[0].type != X86_OP_IMM:
            continue
        target = i.operands[0].imm
        if target not in (0x4e4c8e0, 0x4e4ca30):
            continue
        prefix = primary[index - 3:index]
        lea = next(x for x in prefix if x.mnemonic == 'lea' and x.op_str.startswith('rsi,'))
        need(lea.operands[1].type == X86_OP_MEM and
             lea.operands[1].mem.base == X86_REG_RIP, 'Lookup name is not RIP-relative')
        length = next(x.operands[1].imm for x in prefix
                      if x.mnemonic == 'mov' and x.op_str.startswith('edx,'))
        va = lea.address + lea.size + lea.operands[1].mem.disp
        queries.append({'call': hex(i.address), 'target': hex(target),
                        'kind': 'presence' if target == 0x4e4c8e0 else 'value',
                        'literal_va': hex(va), 'length': length,
                        'name': image.read(va, length).decode('ascii'),
                        'saved_result': row(primary[index + 1])})
    need(len(queries) == 14 and sum(q['kind'] == 'presence' for q in queries) == 12,
         'Changed output query inventory')
    # Destination offsets and packing are supported by the entire retained
    # straight-line block. Names are derived from the actual calls above.
    names = [q['name'] for q in queries if q['kind'] == 'presence']
    # The first eight byte lanes are packed by the retained mov/shl/or/
    # movd/pinsrw block into the native movq destination. The final four
    # scalar stores expose their actual destination displacements directly.
    packed_base = byva[0x564d60c].operands[0].mem.disp
    scalar_sites = [0x564d616, 0x564d619, 0x564d61d, 0x564d621]
    offsets = [packed_base + n for n in range(8)] + [
        byva[va].operands[0].mem.disp for va in scalar_sites]
    destinations = [{'name': name, 'offset': offset}
                    for name, offset in zip(names, offsets)]
    writes = [row(i) for i in primary if 0x564d5ad <= i.address <= 0x564d625]
    edges = []
    for i in primary:
        if i.mnemonic.startswith('j') or i.mnemonic == 'call':
            op = i.operands[0]
            value = {'instruction': row(i)}
            if op.type == X86_OP_IMM:
                value['target'] = hex(op.imm)
                value['inside_primary'] = PRIMARY <= op.imm < RANGES[0][1]
            elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                value['slot'] = hex(i.address + i.size + op.mem.disp)
            else:
                value['unresolved'] = True
            edges.append(value)
    caller = instructions(image, RANGES[3][0], RANGES[3][1])
    callers = []
    for index, i in enumerate(caller):
        if i.mnemonic == 'call' and i.operands[0].type == X86_OP_MEM:
            op = i.operands[0].mem
            if op.base == X86_REG_RIP and i.address + i.size + op.disp == 0x64ebcb8:
                callers.append({'call': hex(i.address),
                                'context': [row(x) for x in caller[index - 4:index + 4]]})
    need(len(callers) == 2, 'Changed run-command boundary count')
    return {'queries_in_execution_order': queries, 'presence_destinations': destinations,
            'complete_output_write_block': writes,
            'style': style_chunks(image, byva), 'primary_control_transfers': edges,
            'selected_command_callers': callers,
            'optional_value': {'name': queries[6]['name'],
                               'lookup_call': queries[6]['call'],
                               'capacity_offset': 0, 'pointer_offset': 8, 'length_offset': 16,
                               'absent_capacity_and_length': '0x8000000000000000',
                               'absent_pointer': 'inactive uninitialized scratch; not zero',
                               'empty': {'capacity': 0, 'pointer': 1, 'length': 0},
                               'present_nonempty': 'allocate length bytes; copy; capacity=length'},
            'style_offset': 36,
            'output_byte_span': 37,
            'scope': 'Static whole-constructor observations under normal helper returns; not a parser/CLI implementation.'}


def collect(data):
    import capstone
    image = Image(data)
    decoded = {}
    extents = []
    for start, end, label in RANGES:
        extents.append({'label': label, 'role': 'primary' if start == PRIMARY else 'context',
                        **image.extent(start, end)})
        decoded[label] = [row(i) for i in instructions(image, start, end)]
    observations = observe(image)
    slots = {0x64ebcb8, 0x64df9f8, 0x64dfca8, 0x64df770}
    for edge in observations['primary_control_transfers']:
        if 'slot' in edge:
            slots.add(int(edge['slot'], 16))
    relocs = []
    all_relocs = image.relocations()
    for r in all_relocs:
        if r['slot'] in slots or r['addend'] == PRIMARY:
            relocs.append({**r, 'slot': hex(r['slot']), 'addend': hex(r['addend']),
                           'symbol': image.symbol(r['symbol_index']) if r['symbol_index'] else None})
    need(len([r for r in relocs if r['slot'] == '0x64ebcb8' and r['addend'] == hex(PRIMARY)]) == 1,
         'Missing or ambiguous constructor relocation')
    f = next(f for f in image.fdes if f['start'] == PRIMARY)
    return {'schema': 1, 'target': {'release': 115, 'artifact': ARTIFACT.as_posix(),
                                  'sha256': DIGEST, 'bytes': len(data)},
            'coordinate_system': 'Linked ELF virtual addresses, before load bias',
            'decoder': {'binding_version': capstone.__version__,
                        'core_version': list(capstone.cs_version())},
            'ranges': extents, 'observations': observations,
            'instructions': decoded, 'selected_relocations': relocs,
            'primary_lsda': lsda(image, PRIMARY, f['lsda']),
            'new_primary_bytes': 840, 'context_bytes': sum(b-a for a,b,_ in RANGES[1:]),
            'no_target_execution': True, 'no_equivalence_or_gate_claim': True}


def native_crosscheck(image, records, executable, cwd, artifact):
    version = subprocess.run([str(executable), '--version'], cwd=cwd, check=True,
                             capture_output=True, timeout=15).stdout.decode('utf8')
    need('GNU objdump' in version, 'GNU objdump required')
    outputs = {}
    commands = []
    for start, end, label in RANGES:
        args = [str(executable), '-d', '-w', '-Mintel', '--start-address='+hex(start),
                '--stop-address='+hex(end), str(artifact)]
        p = subprocess.run(args, cwd=cwd, check=True, capture_output=True, timeout=30)
        text = p.stdout.decode('utf8')
        found = []
        for line in text.splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
            if m:
                found.append((int(m[1], 16), bytes.fromhex(m[2])))
        expected = [(int(x['va'], 16), bytes.fromhex(x['bytes'])) for x in records['instructions'][label]]
        need(found == expected, 'GNU/Capstone instruction address/byte disagreement: '+label)
        outputs[label+'.gnu.objdump'] = p.stdout
        commands.append({'range': label, 'options': args[1:-1],
                         'artifact': ARTIFACT.as_posix(), 'exit': p.returncode,
                         'instruction_rows': len(found), 'decoded_bytes': sum(len(x[1]) for x in found),
                         'stdout_sha256': sha(p.stdout), 'stderr_hex': p.stderr.hex()})
    return outputs, {'version_stdout': version, 'commands': commands,
                     'all_address_bytes_equal': True, 'operand_normalization': None}


def generate(out, artifact=ROOT/ARTIFACT, objdump='objdump'):
    out = Path(out)
    need(not out.exists() or not any(out.iterdir()), 'Output directory must be empty')
    data = Path(artifact).read_bytes()
    records = collect(data)
    # The normal repository-relative artifact argument keeps raw native exports
    # reproducible. No target command is ever launched.
    relative = Path(artifact).resolve().relative_to(ROOT.resolve())
    exports, native = native_crosscheck(Image(data), records, objdump, ROOT, relative)
    out.mkdir(parents=True, exist_ok=True)
    for name, value in exports.items():
        (out/name).write_bytes(value)
    for name, value in [('records.json', records), ('native-crosscheck.json', native)]:
        (out/name).write_bytes((json.dumps(value, indent=2, sort_keys=True)+'\n').encode())
    return records


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--objdump', default='objdump')
    args = p.parse_args()
    result = generate(args.out, objdump=args.objdump)
    print(json.dumps({'primary_bytes': result['new_primary_bytes'],
                      'output_byte_span': result['observations']['output_byte_span'],
                      'context_bytes': result['context_bytes'], 'captured_execution': False}))


if __name__ == '__main__':
    main()
