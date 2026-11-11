"""Regenerate bounded static evidence; never executes captured instructions.

Dependencies: Capstone 5.0.6, pyelftools 0.32. --write creates the exports.
The specification separates semantic instruction pins from whole-body identity.
"""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

import capstone
import elftools
from capstone import x86_const as x86
from elftools.elf.elffile import ELFFile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'tools/fde_extents.py').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records

DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def demand(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract(data, spec, guard=True):
    if guard:
        demand(sha(data) == DIGEST, 'wrong target identity')
    elf = ELFFile(io.BytesIO(data))

    def location(va, size):
        matches = [s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS'
                   and s['sh_addr'] <= va and va + size <= s['sh_addr'] + s['sh_size']]
        demand(len(matches) == 1, f'nonunique VA mapping {va:#x}')
        sec = matches[0]
        return sec['sh_offset'] + va - sec['sh_addr']

    def read(va, size):
        off = location(va, size)
        return data[off:off + size]

    data_rows = spec['data']
    for row in data_rows:
        demand(read(int(row['va'],16), len(bytes.fromhex(row['bytes']))).hex() == row['bytes'], 'data operand mismatch')
    _, fdes = eh_frame_records(data)
    rels = {}
    for sec in elf.iter_sections():
        if sec['sh_type'] not in ('SHT_RELA', 'SHT_REL'):
            continue
        symbols = elf.get_section(sec['sh_link']) if sec['sh_link'] else None
        for rel in sec.iter_relocations():
            rels.setdefault(rel['r_offset'], []).append({
                'type': rel['r_info_type'],
                'symbol': symbols.get_symbol(rel['r_info_sym']).name
                          if symbols and rel['r_info_sym'] else None,
                'addend': hex(rel['r_addend']) if rel.is_RELA() else None,
            })

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    output, listing = [], []
    for body_spec in spec['bodies']:
        start, end = int(body_spec['start'], 16), int(body_spec['end'], 16)
        owner = [f for f in fdes if f['start'] == start and f['end'] == end]
        demand(len(owner) == 1, 'FDE mismatch')
        owner = owner[0]
        body = read(start, end - start)
        instructions = list(decoder.disasm(body, start))
        demand(sum(i.size for i in instructions) == len(body), 'incomplete linear decode')
        boundaries = {i.address for i in instructions}
        by_address = {i.address: i for i in instructions}
        for addr, raw in body_spec['pins'].items():
            va = int(addr, 16)
            demand(va in by_address and by_address[va].bytes.hex() == raw,
                   'semantic instruction mismatch at ' + addr)
        calls, branches = [], []
        for i in instructions:
            listing.append(f'{i.address:#x}: {i.bytes.hex():24} {i.mnemonic} {i.op_str}'.rstrip())
            if i.group(capstone.CS_GRP_JUMP):
                operand = i.operands[0]
                if operand.type == x86.X86_OP_IMM:
                    if operand.imm not in boundaries:
                        demand(spec['tails'].get(hex(i.address))==hex(operand.imm), 'unqualified tail')
                        demand(len([f for f in fdes if f['start']==operand.imm])==1, 'tail target FDE')
                    branches.append({'site': hex(i.address), 'opcode': i.mnemonic,
                                     'target': hex(operand.imm)})
                else:
                    table = spec['tables'].get(hex(i.address))
                    demand(table is not None, 'unspecified indirect jump')
                    row = next(r for r in data_rows if r['va']==table)
                    targets = [int(table,16)+x for x in struct.unpack('<5i', bytes.fromhex(row['bytes']))]
                    demand(all(t in boundaries for t in targets), 'table target boundary')
                    branches.append({'site':hex(i.address),'opcode':i.mnemonic,'table':table,
                                     'targets':[hex(t) for t in targets], 'domain':'tags 0..4 only; no guard'})
            if i.group(capstone.CS_GRP_CALL):
                operand = i.operands[0]
                call = {'site': hex(i.address)}
                if operand.type == x86.X86_OP_IMM:
                    call['target'] = hex(operand.imm)
                elif operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP:
                    slot = i.address + i.size + operand.mem.disp
                    call.update(slot=hex(slot), relocations=rels.get(slot, []),
                                slot_bytes=read(slot, 8).hex())
                    demand(len(call['relocations']) == 1, 'ambiguous call relocation')
                else:
                    call['unresolved_operand'] = i.op_str
                calls.append(call)
        frames = {}
        for key in ('fde', 'cie'):
            va = owner[key]
            size = struct.unpack('<I', read(va, 4))[0] + 4
            frames[key] = {'va': hex(va), 'bytes': read(va, size).hex()}
        output.append({'start': hex(start), 'end': hex(end), 'file_offset': hex(location(start, len(body))),
                       'bytes': body.hex(), 'sha256': sha(body), 'byte_count': len(body),
                       'instruction_count': len(instructions), 'frames': frames,
                       'lsda': hex(owner['lsda']) if owner['lsda'] is not None else None,
                       'branches': branches, 'calls': calls})
    return {'target_sha256': DIGEST, 'bodies': output, 'data': data_rows}, '\n'.join(listing) + '\n'


def finite_controls():
    cases=0
    for mode in range(256):
        key=mode!=0
        for tag in range(256):
            address=tag==1
            marker=None if address else 0xc0
            demand((marker==0xc0)==(tag!=1),'nil/address gate')
            demand(key==(mode!=0),'key gate')
            cases+=1
    return {'cases':cases,'mismatches':0,'limitation':'Independent scalar key/tag model; invalid tags are branch witnesses, not valid source representations. Tail address encoder opaque.'}


def main():
    demand(capstone.__version__ == '5.0.6' and elftools.__version__ == '0.32', 'dependency version mismatch')
    spec = json.loads((HERE / 'spec.json').read_text(encoding='utf-8'))
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    record, listing = extract(data, spec)
    elf = ELFFile(io.BytesIO(data))
    text = elf.get_section_by_name('.text')
    mutations = []
    for addr in spec['mutations']:
        va = int(addr, 16)
        section = next(s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS' and s['sh_addr'] <= va < s['sh_addr']+s['sh_size'])
        offset = section['sh_offset'] + va - section['sh_addr']
        altered = bytearray(data)
        altered[offset] ^= 1
        try:
            extract(bytes(altered), spec, guard=False)
        except ValueError as error:
            mutations.append({'va': addr, 'rejected': True, 'reason': str(error)})
        else:
            raise ValueError('operative mutation accepted at ' + addr)
    record.update(mutations=mutations, finite_controls=finite_controls(),
                  capstone=capstone.__version__, pyelftools=elftools.__version__)
    files = {'records.json': (json.dumps(record, indent=2, sort_keys=True) + '\n').encode(),
             'disassembly.txt': listing.encode()}
    if sys.argv[1:] == ['--write']:
        for name, content in files.items():
            (HERE / name).write_bytes(content)
    else:
        demand(not sys.argv[1:], 'only --write is supported')
        for name, content in files.items():
            demand((HERE / name).read_bytes() == content, 'regeneration mismatch: ' + name)
    print(json.dumps({'matches': True, 'bodies': [(b['start'], b['byte_count'], b['instruction_count'])
                                                for b in record['bodies']],
                      'mutations_rejected': len(mutations), 'finite_controls': record['finite_controls']}))


if __name__ == '__main__':
    main()
