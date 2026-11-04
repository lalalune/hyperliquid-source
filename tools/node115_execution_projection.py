#!/usr/bin/env python3
"""Replay a static node115 execution-state selection/projection evidence packet; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-008-node115-execution-projection'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x2af7150, 0x2af77ee


def check_body(body):
    """Check instruction-boundary facts used by the bounded state-layout claim."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x2af717a: ('cmp', 'byte ptr [rbx + 0x260], 1'),
        0x2af7186: ('jne', '0x2af7192'),
        0x2af7435: ('call', '0x2af6580'),
        0x2af7445: ('je', '0x2af7463'),
        0x2af744f: ('cmp', 'rax, 1'),
        0x2af7459: ('mov', 'rax, qword ptr [r14]'),
        0x2af745c: ('mov', 'qword ptr [rbx + 0x2d0], rax'),
        0x2af746e: ('je', '0x2af74ee'),
        0x2af74c6: ('call', '0x26a7880'),
        0x2af74cb: ('test', 'al, al'),
        0x2af74cd: ('cmovle', 'r15, rbp'),
        0x2af74d1: ('add', 'rbp, 0x40'),
        0x2af74da: ('mov', 'rax, qword ptr [r15]'),
        0x2af74e2: ('mov', 'qword ptr [rbx + 0x2d8], rax'),
        0x2af7558: ('and', 'r12, rax'),
        0x2af7560: ('add', 'r15, 0x20'),
        0x2af757e: ('jne', '0x2af758d'),
        0x2af7588: ('call', '0x23316c0'),
        0x2af758f: ('jg', '0x2af7560'),
        0x2af7591: ('mov', 'r14, r15'),
        0x2af75a5: ('lea', 'rdi, [r13 + 0x135]'),
        0x2af75c0: ('mov', 'r9d, dword ptr [rdi - 0xf0]'),
        0x2af75c7: ('movzx', 'r10d, byte ptr [rdi - 0xec]'),
        0x2af7612: ('add', 'rdi, 0x140'),
        0x2af7619: ('add', 'r8, 0x14'),
        0x2af7638: ('add', 'rsi, 0x45'),
        0x2af7650: ('mov', 'r8d, dword ptr [rsi + rdi]'),
        0x2af7654: ('movzx', 'r9d, byte ptr [rsi + rdi + 4]'),
        0x2af7661: ('add', 'rdx, 5'),
        0x2af7665: ('add', 'rdi, 0x50'),
        0x2af76af: ('call', '0x2502370'),
        0x2af76e6: ('call', '0x2cedc50'),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Projection instruction changed at {pc:#x}')
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
    for va in (0x6448148, 0x6448160, 0x6448178, 0x6448190, 0x64481a8, 0x64481c0):
        raw, location_offset = read(va, 24)
        raw_pointer, length, line, column = struct.unpack('<QQII', raw)
        relocation = [dict(offset=slot, info=info, addend=addend)
                      for slot, info, addend in relocs if slot == va]
        if len(relocation) != 1 or relocation[0]['info'] != 8:
            raise ValueError('Source Location relocation changed')
        pointer = relocation[0]['addend']
        path, path_offset = read(pointer, length)
        if path != b'node/src/consensus/execution_state.rs' or line not in (128, 138, 139, 153, 154, 155):
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
    for slot in (0x64e0990, 0x64e0008, 0x64e5bf0, 0x64e7408, 0x64df480,
                 0x64df508, 0x64e1010):
        raw, slot_offset = read(slot, 8)
        relocation = [dict(offset=place, info=info, addend=addend)
                      for place, info, addend in relocs if place == slot]
        imports.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                            relocations=relocation))
    direct_helpers = []
    for target in (0x2af6580, 0x23316c0, 0x26a7880, 0x2502370, 0x2cedc50):
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


def canonical_export(raw):
    # Text-only trailing whitespace; original instruction bytes remain unchanged.
    return b'\n'.join(line.rstrip() for line in raw.splitlines()) + b'\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    result = produce()
    expected = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.write:
        PACKET.mkdir(parents=True, exist_ok=True)
        (PACKET / 'records.json').write_text(expected)
        (PACKET / 'native.asm').write_bytes(canonical_export(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address={START}',
            f'--stop-address={END}', str(TARGET.relative_to(ROOT))], cwd=ROOT)))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()
