#!/usr/bin/env python3
"""Replay a static node115 consensus timer f64-conversion evidence packet; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-001-node115-consensus-timer-conversion'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x4eca5d0, 0x4eca82c
CALLER_START, CALLER_END = 0x2e1b6b0, 0x2e1da0e
LOCATION = 0x649dcf8
CALLER_LOCATION_LEA = 0x2e1d1cf
SELF_SLOT = 0x64e87d8
NANOS_PER_SEC = 0x3b9aca00


def check_body(body):
    """Check instruction-boundary facts used by the bounded conversion claim."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x4eca5dc: ('xor', 'r15d, r15d'),
        0x4eca5df: ('xorpd', 'xmm1, xmm1'),
        0x4eca5e3: ('ucomisd', 'xmm1, xmm0'),
        0x4eca5e7: ('ja', '0x4eca7dd'),
        0x4eca5ed: ('mov', 'rbx, rdi'),
        0x4eca5f8: ('shr', 'rcx, 0x34'),
        0x4eca5fc: ('and', 'ecx, 0x7ff'),
        0x4eca602: ('cmp', 'ecx, 0x3e0'),
        0x4eca608: ('jae', '0x4eca612'),
        0x4eca60a: ('xor', 'r14d, r14d'),
        0x4eca612: ('movabs', 'rdi, 0xfffffffffffff'),
        0x4eca622: ('lea', 'r14, [rdx + rdi]'),
        0x4eca626: ('inc', 'r14'),
        0x4eca62c: ('cmp', 'edx, 0x3ff'),
        0x4eca632: ('jae', '0x4eca6ad'),
        0x4eca64d: ('mov', 'ecx, 0x3b9aca00'),
        0x4eca655: ('mul', 'rcx'),
        0x4eca699: ('cmp', 'r15d, 0x3b9aca00'),
        0x4eca6a0: ('sete', 'r14b'),
        0x4eca6a4: ('cmove', 'r15d, esi'),
        0x4eca6ad: ('cmp', 'edx, 0x433'),
        0x4eca6b3: ('jae', '0x4eca731'),
        0x4eca6ce: ('mov', 'ecx, 0x3b9aca00'),
        0x4eca6d3: ('mul', 'rcx'),
        0x4eca71e: ('cmp', 'r15d, 0x3b9aca00'),
        0x4eca725: ('sete', 'al'),
        0x4eca728: ('cmove', 'r15d, ecx'),
        0x4eca72c: ('add', 'r14, rax'),
        0x4eca731: ('cmp', 'edx, 0x43f'),
        0x4eca737: ('jae', '0x4eca7da'),
        0x4eca740: ('shl', 'r14, cl'),
        0x4eca743: ('lea', 'rcx, [rip + 0x15d35ae]'),
        0x4eca74a: ('lea', 'rdi, [rsp + 0x10]'),
        0x4eca74f: ('mov', 'rsi, r14'),
        0x4eca752: ('mov', 'edx, r15d'),
        0x4eca755: ('call', 'qword ptr [rip + 0x1616c45]'),
        0x4eca75b: ('mov', 'edi, 0x70'),
        0x4eca760: ('call', 'qword ptr [rip + 0x1614d1a]'),
        0x4eca766: ('test', 'rax, rax'),
        0x4eca769: ('je', '0x4eca7c8'),
        0x4eca7a9: ('mov', 'qword ptr [rbx], r14'),
        0x4eca7ac: ('mov', 'dword ptr [rbx + 8], r15d'),
        0x4eca7b0: ('mov', 'qword ptr [rbx + 0x10], rax'),
        0x4eca7b4: ('mov', 'byte ptr [rbx + 0x18], 0'),
        0x4eca7da: ('mov', 'r15b, 1'),
        0x4eca7dd: ('mov', 'byte ptr [rsp + 0xf], r15b'),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Conversion instruction changed at {pc:#x}')
    return instructions


def check_caller(body, read):
    """Check the two call sites and their f64 inputs inside the caller FDE."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, CALLER_START))
    if sum(i.size for i in instructions) != CALLER_END - CALLER_START:
        raise ValueError('Incomplete caller decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x2e1c73c: ('lea', 'rdi, [rsp + 0x368]'),
        0x2e1c744: ('movsd', 'xmm0, qword ptr [rip - 0x29c2d2c]'),
        0x2e1c74c: ('call', 'qword ptr [rip + 0x36cc086]'),
        0x2e1c752: ('lea', 'rdi, [rsp + 0x388]'),
        0x2e1c75a: ('movsd', 'xmm0, qword ptr [rip - 0x29c3352]'),
        0x2e1c762: ('call', 'qword ptr [rip + 0x36cc070]'),
    }
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Caller instruction changed at {pc:#x}')
    by_addr = {i.address: i for i in instructions}
    constants = []
    for lea_pc, mov_pc, call_pc, out_disp in (
            (0x2e1c73c, 0x2e1c744, 0x2e1c74c, 0x368),
            (0x2e1c752, 0x2e1c75a, 0x2e1c762, 0x388)):
        mov = by_addr[mov_pc]
        disp = struct.unpack_from('<i', mov.bytes, len(mov.bytes) - 4)[0]
        va = mov_pc + mov.size + disp
        raw, offset = read(va, 8)
        bits = struct.unpack('<Q', raw)[0]
        slot_disp = struct.unpack_from('<i', by_addr[call_pc].bytes, 2)[0]
        slot = call_pc + by_addr[call_pc].size + slot_disp
        if slot != SELF_SLOT:
            raise ValueError('Caller does not reach the conversion through its recorded slot')
        constants.append(dict(lea_pc=lea_pc, output_offset=out_disp, movsd_pc=mov_pc,
                              constant_va=va, constant_offset=offset, bits=bits,
                              value=struct.unpack('<d', raw)[0], call_pc=call_pc,
                              call_slot=slot))
    return instructions, constants


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
    caller_fde = [f for f in fdes if f['start'] == CALLER_START and f['end'] == CALLER_END]
    if len(caller_fde) != 1:
        raise ValueError('Exact caller FDE missing')
    body, offset = read(START, END - START)
    instructions = check_body(body)
    caller_body, caller_offset = read(CALLER_START, CALLER_END - CALLER_START)
    caller_instructions, constants = check_caller(caller_body, read)

    rela = next(s for s in secs if s['name'] == '.rela.dyn')
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))

    def relocation_at(va):
        found = [dict(offset=slot, info=info, addend=addend)
                 for slot, info, addend in relocs if slot == va]
        if len(found) != 1 or found[0]['info'] != 8:
            raise ValueError(f'Relocation changed at {va:#x}')
        return found[0]

    raw, location_offset = read(LOCATION, 24)
    raw_pointer, length, line, column = struct.unpack('<QQII', raw)
    relocation = relocation_at(LOCATION)
    pointer = relocation['addend']
    path, path_offset = read(pointer, length)
    if path != b'node/src/consensus/timer.rs' or line != 17 or column != 30:
        raise ValueError('Source Location changed')
    bindings = [dict(va=LOCATION, file_offset=location_offset, raw_hex=raw.hex(),
                     path=path.decode(), path_va=pointer, path_offset=path_offset,
                     raw_pointer=raw_pointer, length=length, line=line,
                     column=column, relocation=relocation)]

    by_addr = {i.address: i for i in caller_instructions}
    lea = by_addr[CALLER_LOCATION_LEA]
    if (lea.mnemonic, lea.op_str) != ('lea', 'r8, [rip + 0x36349ca]'):
        raise ValueError('Caller Location instruction changed')
    disp = struct.unpack_from('<i', lea.bytes, len(lea.bytes) - 4)[0]
    caller_loc_va = CALLER_LOCATION_LEA + lea.size + disp
    raw, cl_offset = read(caller_loc_va, 24)
    _, clength, cline, ccolumn = struct.unpack('<QQII', raw)
    crelocation = relocation_at(caller_loc_va)
    cpath, cpath_offset = read(crelocation['addend'], clength)
    if cpath != b'node/src/consensus/state.rs' or cline != 123 or ccolumn != 106:
        raise ValueError('Caller Source Location changed')
    caller_binding = dict(va=caller_loc_va, file_offset=cl_offset, raw_hex=raw.hex(),
                          path=cpath.decode(), path_va=crelocation['addend'],
                          path_offset=cpath_offset, length=clength, line=cline,
                          column=ccolumn, relocation=crelocation, lea_pc=CALLER_LOCATION_LEA)

    imports = []
    for slot in (0x64e13a0, 0x64df480, 0x64df6b8, 0x64df4c0, 0x64e13a8, SELF_SLOT):
        raw, slot_offset = read(slot, 8)
        imports.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                            relocations=[relocation_at(slot)]))
    if relocation_at(SELF_SLOT)['addend'] != START:
        raise ValueError('Self slot does not resolve to the conversion FDE')

    edges = []
    for i in instructions:
        if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
            edges.append(dict(pc=i.address, bytes=i.bytes.hex(), mnemonic=i.mnemonic, operand=i.op_str))
    direct_helpers = []
    for target in (0x5cf2150, 0x4e50c80):
        extents = [f for f in fdes if f['start'] == target]
        direct_helpers.append(dict(target=target, fdes=extents,
                                   semantic_status='unmeasured; no helper behavior adopted'))
    return dict(target_sha256=SHA, target_bytes=len(data), component='consensus',
                base_commit='05bc2de303c05525b71e7e257426e741bc66a390',
                start=START, end=END, file_offset=offset, fde=fde[0],
                body_sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                native_instructions=len(instructions), source_locations=bindings,
                call_and_branch_edges=edges, indirect_slots=imports,
                direct_helpers=direct_helpers,
                caller=dict(start=CALLER_START, end=CALLER_END, file_offset=caller_offset,
                            fde=caller_fde[0], body_sha256=hashlib.sha256(caller_body).hexdigest(),
                            native_instructions=len(caller_instructions),
                            source_location=caller_binding, constants=constants),
                raw_equal=None, normalized_only=None, unmatched=None,
                implementation='not implemented', gates_changed=False)


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
        (PACKET / 'caller_excerpt.asm').write_bytes(canonical_export(subprocess.check_output([
            'objdump', '-d', '-M', 'intel', f'--start-address=0x2e1c73c',
            '--stop-address=0x2e1c768', str(TARGET.relative_to(ROOT))], cwd=ROOT)))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()
