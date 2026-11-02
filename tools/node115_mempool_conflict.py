#!/usr/bin/env python3
"""Replay a static node115 mempool hit/miss evidence packet; never execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-001-node115-mempool-conflict'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x2e1fe30, 0x2e20047


def check_body(body):
    """Check instruction-boundary facts used by the bounded disposition claim."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x2e1fe47: ('mov', 'rax, r14'),
        0x2e1fe4a: ('neg', 'rax'),
        0x2e1fe4d: ('jno', '0x2e1fec7'),
        0x2e1fee2: ('test', 'al, 1'),
        0x2e1fee4: ('jne', '0x2e20020'),
        0x2e1feea: ('cmp', 'rdx, qword ptr [rdi + 0xd8]'),
        0x2e1fef1: ('jae', '0x2e20020'),
        0x2e1ff29: ('movdqu', 'xmm0, xmmword ptr [rax]'),
        0x2e1ff2d: ('movdqu', 'xmm1, xmmword ptr [rax + 0x10]'),
        0x2e1ff44: ('movdqu', 'xmm2, xmmword ptr [rdx]'),
        0x2e1ff48: ('movdqu', 'xmm3, xmmword ptr [rdx + 0x10]'),
        0x2e1ff4d: ('pcmpeqb', 'xmm3, xmm1'),
        0x2e1ff51: ('pcmpeqb', 'xmm2, xmm0'),
        0x2e1ff55: ('pand', 'xmm2, xmm3'),
        0x2e1ff59: ('pmovmskb', 'eax, xmm2'),
        0x2e1ff5d: ('cmp', 'eax, 0xffff'),
        0x2e1ff62: ('je', '0x2e2003a'),
        0x2e20018: ('call', 'qword ptr [rip + 0x36c0afa]'),
        0x2e2001e: ('jmp', '0x2e2003a'),
        0x2e20027: ('add', 'rdi, 0xa0'),
        0x2e20035: ('call', '0x2cacdb0'),
        0x2e20046: ('ret', ''),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Disposition instruction changed at {pc:#x}')
    return instructions


def produce(data=None):
    data = TARGET.read_bytes() if data is None else data
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node115 digest mismatch')
    secs = sections(data)

    def read(va, count):
        mapping = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + count <= s['address'] + s['size']]
        if len(mapping) != 1:
            raise ValueError('Ambiguous or missing VA mapping')
        off = mapping[0]['offset'] + va - mapping[0]['address']
        return data[off:off + count], off

    _, fdes = eh_frame_records(data)
    fde = [f for f in fdes if f['start'] == START and f['end'] == END]
    if len(fde) != 1:
        raise ValueError('Exact FDE missing')
    body, offset = read(START, END - START)
    instructions = check_body(body)
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))
    bindings = []
    for va in (0x6451c58, 0x6451c70):
        raw, location_offset = read(va, 24)
        raw_pointer, length, line, column = struct.unpack('<QQII', raw)
        relocation = [dict(offset=slot, info=info, addend=addend)
                      for slot, info, addend in relocs if slot == va]
        if len(relocation) != 1 or relocation[0]['info'] != 8:
            raise ValueError('Source Location relocation changed')
        pointer = relocation[0]['addend']
        path, path_offset = read(pointer, length)
        if path != b'node/src/consensus/mempool.rs' or line not in (818, 826):
            raise ValueError('Source Location changed')
        if relocation != [dict(offset=va, info=8, addend=pointer)]:
            raise ValueError('Source Location relocation changed')
        bindings.append(dict(va=va, file_offset=location_offset, raw_hex=raw.hex(),
                             path=path.decode(), path_va=pointer, path_offset=path_offset,
                             raw_pointer=raw_pointer, length=length, line=line,
                             column=column, relocation=relocation))
    edges = []
    for i in instructions:
        if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
            edges.append(dict(pc=i.address, bytes=i.bytes.hex(), mnemonic=i.mnemonic, operand=i.op_str))
    imports = []
    for slot in (0x64e0b18, 0x64e87e0, 0x64e87e8):
        raw, slot_offset = read(slot, 8)
        relocation = [dict(offset=place, info=info, addend=addend)
                      for place, info, addend in relocs if place == slot]
        imports.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                            relocations=relocation))
    direct_helpers = []
    for target in (0x24c5f50, 0x2cacdb0):
        extents = [f for f in fdes if f['start'] == target]
        direct_helpers.append(dict(target=target, fdes=extents,
                                   semantic_status='unmeasured; no helper behavior adopted'))
    return dict(target_sha256=SHA, target_bytes=len(data), component='consensus',
                base_commit='8fd8db680ec4bfef40996e5616bce3d5156d0b86',
                start=START, end=END, file_offset=offset, fde=fde[0],
                body_sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                native_instructions=len(instructions), source_locations=bindings,
                call_and_branch_edges=edges, indirect_slots=imports,
                direct_helpers=direct_helpers, raw_equal=None, normalized_only=None,
                unmatched=None, implementation='not implemented', gates_changed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = produce()
    expected = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        PACKET.mkdir(parents=True, exist_ok=True)
        (PACKET / 'records.json').write_text(expected)
        (PACKET / 'native.asm').write_bytes(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address={START}',
            f'--stop-address={END}', str(TARGET.relative_to(ROOT))], cwd=ROOT))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()
