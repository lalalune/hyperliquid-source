#!/usr/bin/env python3
"""Replay a static node115 signed-validation decision evidence packet; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-001-node115-signed-validation'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x59d6b80, 0x59d70ab


def check_body(body):
    """Check instruction-boundary facts used by the bounded validation-order claim."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x59d6c41: ('cmp', 'al, 0x2e'),
        0x59d6c43: ('jne', '0x59d6eb2'),
        0x59d6c76: ('movdqu', 'xmm1, xmmword ptr [r15 + 0x11c]'),
        0x59d6c7f: ('movd', 'xmm2, dword ptr [r15 + 0x12c]'),
        0x59d6c88: ('movq', 'xmm3, rax'),
        0x59d6c8d: ('pcmpeqb', 'xmm3, xmm2'),
        0x59d6c91: ('pcmpeqb', 'xmm1, xmm0'),
        0x59d6c95: ('pand', 'xmm1, xmm3'),
        0x59d6c99: ('pmovmskb', 'eax, xmm1'),
        0x59d6c9d: ('cmp', 'eax, 0xffff'),
        0x59d6ca2: ('je', '0x59d6f04'),
        0x59d6ead: ('mov', 'byte ptr [rbx], 0xd'),
        0x59d6f08: ('cmp', 'r14, 0x64'),
        0x59d6f0c: ('jbe', '0x59d6f17'),
        0x59d6f0e: ('mov', 'byte ptr [rbx], 0x29'),
        0x59d6f40: ('shl', 'r14, 5'),
        0x59d6f78: ('call', '0x51d28d0'),
        0x59d6f7d: ('add', 'rbp, 0x20'),
        0x59d6f83: ('je', '0x59d6f50'),
        0x59d6f9d: ('mov', 'byte ptr [rbx], 0x2a'),
        0x59d6fc7: ('call', '0x595fd20'),
        0x59d6ff1: ('jbe', '0x59d7078'),
        0x59d6ffe: ('jae', '0x59d7078'),
        0x59d7010: ('call', '0x5960390'),
        0x59d7015: ('cmp', 'byte ptr [rsp + 0x10], 0x2e'),
        0x59d701a: ('jne', '0x59d7042'),
        0x59d7031: ('call', '0x595fd20'),
        0x59d703d: ('mov', 'byte ptr [rbx], 0x2e'),
        0x59d7078: ('mov', 'byte ptr [rbx], 0xc'),
        0x59d7084: ('call', '0x5246b60'),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Validation instruction changed at {pc:#x}')
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
    for va in (0x64b6f38,):
        raw, location_offset = read(va, 24)
        raw_pointer, length, line, column = struct.unpack('<QQII', raw)
        relocation = [dict(offset=slot, info=info, addend=addend)
                      for slot, info, addend in relocs if slot == va]
        if len(relocation) != 1 or relocation[0]['info'] != 8:
            raise ValueError('Source Location relocation changed')
        pointer = relocation[0]['addend']
        path, path_offset = read(pointer, length)
        if path != b'node/src/consensus/signed.rs' or line != 194:
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
    for slot in (0x64e86f0, 0x64e0b18):
        raw, slot_offset = read(slot, 8)
        relocation = [dict(offset=place, info=info, addend=addend)
                      for place, info, addend in relocs if place == slot]
        imports.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                            relocations=relocation))
    direct_helpers = []
    for target in (0x57e8d40, 0x51d28d0, 0x595fd20, 0x5960390, 0x5246b60):
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
