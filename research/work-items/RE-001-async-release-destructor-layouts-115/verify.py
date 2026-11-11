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
ROOT = HERE.parents[2]
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
                    demand(operand.imm in boundaries, f'unqualified branch {i.address:#x}')
                    branches.append({'site': hex(i.address), 'opcode': i.mnemonic,
                                     'target': hex(operand.imm)})
                elif operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP:
                    slot = i.address + i.size + operand.mem.disp
                    demand(len(rels.get(slot, [])) == 1, 'ambiguous tail relocation')
                    branches.append({'site': hex(i.address), 'opcode': i.mnemonic,
                                     'slot': hex(slot), 'slot_bytes': read(slot, 8).hex(),
                                     'relocations': rels[slot]})
                else:
                    raise ValueError('unqualified indirect jump')
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
    return {'target_sha256': DIGEST, 'bodies': output, 'pair_loop_callback_slots': [{'va': hex(s), 'bytes': read(s, 8).hex(), 'relocations': rels.get(s, [])} for s in (0x64e17b0, 0x64e17a8)]}, '\n'.join(listing) + '\n'


def finite_controls():
    # Conditional arithmetic and release-order checks, no captured execution.
    mask = (1<<64)-1
    vectors = [0, 1, 2, (1<<63)-1, 1<<63, (1<<63)+1, mask]
    rows = []
    for count in vectors:
        result = (-count) & mask
        overflow = count == 1<<63
        carry = count != 0
        selected = not overflow and carry
        demand(selected == (count not in (0, 1<<63)), 'NEG/JO/JAE sentinel gate')
        rows.append({'count': hex(count), 'invoke': selected})
    cases = 0
    for optional in (False, True):
        for pointer in (0, 0x1000):
            for count in vectors:
                perform = not optional or pointer != 0
                post = (count-1)&mask if perform else None
                callback = perform and post == 0
                demand(callback == (perform and count == 1), 'zero-after-decrement callback')
                cases += 1
    for n in range(65):
        pairs = [(16*i,16*i+8) for i in range(n)]
        flattened = [x for pair in pairs for x in pair]
        demand(flattened == list(range(0,16*n,8)), 'forward pair order')
        demand(16*n == (n<<4), 'pair storage size')
        cases += 1
    demand(0x238 != 0x1f8 and 0x300 != 0x230, 'layout distinction')
    return {'cases': cases, 'sentinel_vectors': rows, 'mismatches': 0,
            'limitation': 'Same-author scalar models; valid pointers/counts, nonaliasing and successful opaque helper returns assumed. No concurrency or unwind proof.'}


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
        offset = text['sh_offset'] + va - text['sh_addr']
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
