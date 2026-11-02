#!/usr/bin/env python3
"""Replay a static node115 retry poll-state evidence packet; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-012-node115-retry-state'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x2a64130, 0x2a64bd7
TABLES = {
    0x603058: [0x2a64168, 0x2a644b7, 0x2a644aa, 0x2a641e7],
    0x603068: [0x2a64205, 0x2a644d9, 0x2a644c4, 0x2a642ae],
    0x603078: [0x2a642df, 0x2a64500, 0x2a644ee, 0x2a643e4, 0x2a6440e],
    0x60308c: [0x2a64409, 0x2a64524, 0x2a64512, 0x2a64413],
    0x60309c: [0x2a64431, 0x2a64548, 0x2a64536, 0x2a64436],
}
CALLER_START, CALLER_END = 0x2aebde4, 0x2aebe10


def check_table(va, raw, starts):
    targets = [va + n[0] for n in struct.iter_unpack('<i', raw)]
    if targets != TABLES[va] or any(target not in starts for target in targets):
        raise ValueError('Retry dispatch table changed')
    return targets


def check_body(body):
    """Check retry state, counter and result-ownership instruction boundaries."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x2a6414c: ('movzx', 'eax, byte ptr [rsi + 0x195]'),
        0x2a64166: ('jmp', 'rax'),
        0x2a641c5: ('movabs', 'rax, 0x4000000000000000'),
        0x2a6420e: ('mov', 'qword ptr [rbx + 0x60], 0xffffffffffffffff'),
        0x2a64267: ('mov', 'qword ptr [rbx + 0x50], 0'),
        0x2a6426f: ('mov', 'qword ptr [rbx + 0x58], rax'),
        0x2a646a3: ('call', '0x2a90a50'),
        0x2a646aa: ('jne', '0x2a64a12'),
        0x2a6470f: ('call', 'qword ptr [rax]'),
        0x2a64719: ('cmp', 'rcx, rax'),
        0x2a6471c: ('jae', '0x2a6427e'),
        0x2a64722: ('lea', 'rax, [rcx + 1]'),
        0x2a64726: ('mov', 'qword ptr [rbx + 0x50], rax'),
        0x2a6472a: ('mov', 'qword ptr [rbx + 0x90], rcx'),
        0x2a64746: ('movups', 'xmmword ptr [rbx + 0xd0], xmm0'),
        0x2a6474d: ('movups', 'xmmword ptr [rbx + 0xe0], xmm1'),
        0x2a647c3: ('mov', 'word ptr [rbx + 0x130], 4'),
        0x2a647cf: ('je', '0x2a6444f'),
        0x2a64820: ('cmp', 'dword ptr [rsp], 1'),
        0x2a64824: ('jne', '0x2a64985'),
        0x2a64886: ('cmp', 'rbp, 2'),
        0x2a6488a: ('jne', '0x2a64a35'),
        0x2a64939: ('je', '0x2a6494f'),
        0x2a6493e: ('je', '0x2a6494f'),
        0x2a6494f: ('mov', 'byte ptr [rbx + 0xc9], 1'),
        0x2a6496c: ('movsd', 'xmm0, qword ptr [rax + 0x20]'),
        0x2a64971: ('movsd', 'qword ptr [rbx + 0xf0], xmm0'),
        0x2a64a27: ('mov', 'qword ptr [rax], 2'),
        0x2a64a2e: ('mov', 'al, 3'),
        0x2a64a8c: ('mov', 'rdi, qword ptr [rsp + 0x58]'),
        0x2a64a91: ('call', '0x2ab0370'),
        0x2a64ac7: ('mov', 'al, 1'),
        0x2a64ac9: ('mov', 'byte ptr [rbx + 0x195], al'),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Retry instruction changed at {pc:#x}')
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
    starts = {i.address for i in instructions}
    tables = []
    for va, expected in TABLES.items():
        raw, table_offset = read(va, len(expected) * 4)
        targets = check_table(va, raw, starts)
        tables.append(dict(va=va, file_offset=table_offset, raw_hex=raw.hex(),
                           signed_relative_targets=targets))
    caller_owner = [f for f in fdes if f['start'] <= CALLER_START
                    and CALLER_END <= f['end']]
    if len(caller_owner) != 1:
        raise ValueError('Caller context owner missing')
    owner = caller_owner[0]
    owner_body, _ = read(owner['start'], owner['end'] - owner['start'])
    decoded_owner = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(owner_body, owner['start']))
    if sum(i.size for i in decoded_owner) != len(owner_body):
        raise ValueError('Caller owner decode incomplete')
    caller_ins = {i.address: (i.mnemonic, i.op_str) for i in decoded_owner}
    caller_anchors = {
        0x2aebde4: ('lea', 'r13, [rbx + 0xae8]'),
        0x2aebdeb: ('lea', 'rdi, [rsp + 0x350]'),
        0x2aebdf3: ('mov', 'rsi, r13'),
        0x2aebdfb: ('call', '0x2a64130'),
        0x2aebe02: ('cmp', 'dword ptr [rsp + 0x350], 2'),
        0x2aebe0a: ('je', '0x2aeca04'),
    }
    if any(caller_ins.get(pc) != wanted for pc, wanted in caller_anchors.items()):
        raise ValueError('Caller state/result binding changed')
    caller_body, caller_offset = read(CALLER_START, CALLER_END - CALLER_START)
    caller = dict(start=CALLER_START, end=CALLER_END, file_offset=caller_offset,
                  body_hex=caller_body.hex(), sha256=hashlib.sha256(caller_body).hexdigest(),
                  owner_fde=owner, export_scope='interior context; not a complete function',
                  validated_owner_instructions=len(decoded_owner),
                  exported_instructions=sum(CALLER_START <= i.address < CALLER_END
                                            for i in decoded_owner))
    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))
    bindings = []
    for va in (0x644aed0, 0x644aee8, 0x644af00):
        raw, location_offset = read(va, 24)
        raw_pointer, length, line, column = struct.unpack('<QQII', raw)
        relocation = [dict(offset=slot, info=info, addend=addend)
                      for slot, info, addend in relocs if slot == va]
        if len(relocation) != 1 or relocation[0]['info'] != 8:
            raise ValueError('Source Location relocation changed')
        pointer = relocation[0]['addend']
        path, path_offset = read(pointer, length)
        if path != b'net_utils/src/async_sleep_retry.rs' or line not in (30, 32, 41):
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
    for slot in (0x64df4a0, 0x64e1360, 0x64e1368, 0x64e70a8):
        raw, slot_offset = read(slot, 8)
        relocation = [dict(offset=place, info=info, addend=addend)
                      for place, info, addend in relocs if place == slot]
        imports.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                            relocations=relocation))
    direct_helpers = []
    for target in (0x2a90a50, 0x2ab0370, 0x2a026d0):
        extents = [f for f in fdes if f['start'] == target]
        direct_helpers.append(dict(target=target, fdes=extents,
                                   semantic_status='unmeasured; no helper behavior adopted'))
    return dict(target_sha256=SHA, target_bytes=len(data), component='transport',
                base_commit='8fd8db680ec4bfef40996e5616bce3d5156d0b86',
                start=START, end=END, file_offset=offset, fde=fde[0],
                body_sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                native_instructions=len(instructions), source_locations=bindings,
                call_and_branch_edges=edges, indirect_slots=imports,
                direct_helpers=direct_helpers, dispatch_tables=tables,
                caller_context=caller, raw_equal=None, normalized_only=None,
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
        (PACKET / 'caller-context.asm').write_bytes(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address={CALLER_START}',
            f'--stop-address={CALLER_END}', str(TARGET.relative_to(ROOT))], cwd=ROOT))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()
