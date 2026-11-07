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
                else:
                    raise ValueError('indirect jump requires a separate specification')
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
    return {'target_sha256': DIGEST, 'bodies': output}, '\n'.join(listing) + '\n'


def finite_controls():
    # Conditional instruction lowerings only. No original instruction executes.
    def fast(word, mode):
        selected = (word & 0xffffffff) & ((5 * mode + 5) & 0xffffffff)
        stopped = (word >> 31) & 1
        if not (selected or stopped):
            return None
        return selected, (word >> 16) & 255, stopped

    def locked(word, mode):
        mask = 5 if (mode & 255) == 0 else 10
        if word & 0x80000000:
            return mask, (word >> 16) & 255, 1
        selected = word & mask
        if selected:
            return selected, (word >> 16) & 255, 0
        return None, None, 2

    cases = 0
    for mode in (0, 1):
        for low in range(16):
            for generation in range(256):
                for stopped in (0, 1):
                    word = (stopped << 31) | (generation << 16) | low
                    f, l = fast(word, mode), locked(word, mode)
                    mask = (5, 10)[mode]
                    if stopped:
                        demand(f == (low & mask, generation, 1), 'fast shutdown projection')
                        demand(l == (mask, generation, 1), 'locked shutdown projection')
                    elif low & mask:
                        demand(f == l == (low & mask, generation, 0), 'ready projection')
                    else:
                        demand(f is None and l == (None, None, 2), 'pending projection')
                    cases += 1
    demand(fast(1, 2) == (1, 0, 0) and locked(1, 2) == (None, None, 2),
           'out-of-contract mode witness')
    return {'cases': cases, 'mismatches': 0,
            'nonbinary_mode_witness': {'word': 1, 'mode': 2,
                                      'fast': [1, 0, 0], 'locked': [None, None, 2]},
            'limitation': 'Same-author finite branch models; opaque calls, concurrent changes, aliasing and target execution excluded.'}


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
