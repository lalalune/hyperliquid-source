#!/usr/bin/env python3
"""Replay a static node115 sibling-gate release evidence packet; never execute it."""
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
PACKET = ROOT / 'research/work-items/RE-001-async-gate-release-52790-115'
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x5a52790, 0x5a5280e
SIBLING = 0x5a2f550
TAIL_RELEASE = 0x5a52490
RESUME_PLT = 0x63f0a50
RESUME_SLOT = 0x64ee178
DTOR_SLOTS = {0x64dfdb8: 0x5ce86d0, 0x64dfdc8: 0x5ce8da0}
CLEANUP_SHIM_SLOT = 0x64df4c0
CLEANUP_SHIM = 0x1680cab
PANIC_STRING_VA = 0x46e9bd
PANIC_STRING = b'panic in a destructor during cleanup'

# (site, caller FDE start, caller FDE end, register moved into rdi, excerpt window)
CALLERS = [
    (0x5a5ed9c, 0x5a5e290, 0x5a60a43, 'r12', (0x5a5ed90, 0x5a5eda1)),
    (0x5a607f4, 0x5a5e290, 0x5a60a43, 'r12', (0x5a607e2, 0x5a607f9)),
    (0x5a61e92, 0x5a61e40, 0x5a6221b, 'r15', (0x5a61e8c, 0x5a61e97)),
    (0x5a68b74, 0x5a64aa0, 0x5a69c05, 'r14', (0x5a68b6c, 0x5a68b79)),
    (0x5a6b0e6, 0x5a6a640, 0x5a6bfaa, 'r15', (0x5a6b0da, 0x5a6b0eb)),
    (0x5a6d236, 0x5a6d200, 0x5a6d385, 'r15', (0x5a6d223, 0x5a6d23b)),
    (0x5a71144, 0x5a71040, 0x5a7172a, 'r15', (0x5a7113e, 0x5a71149)),
    (0x5a794de, 0x5a794a0, 0x5a79722, 'r15', (0x5a794d8, 0x5a794e3)),
    (0x5a7e5ff, 0x5a7e540, 0x5a7f395, 'r15', (0x5a7e5f1, 0x5a7e604)),
    (0x5a85065, 0x5a82670, 0x5a89535, 'r15', (0x5a8505f, 0x5a8506a)),
    (0x5a89353, 0x5a82670, 0x5a89535, 'r15', (0x5a89344, 0x5a89358)),
    (0x5a8a15b, 0x5a897e0, 0x5a8a1cc, 'r13', (0x5a8a150, 0x5a8a160)),
]


def check_body(body):
    """Check every instruction of the 126-byte gate FDE against the claim."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, START))
    if sum(i.size for i in instructions) != END - START:
        raise ValueError('Incomplete native decode')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    anchors = {
        0x5a52790: ('push', 'r14'),
        0x5a52792: ('push', 'rbx'),
        0x5a52793: ('push', 'rax'),
        0x5a52794: ('cmp', 'byte ptr [rdi + 0x90], 3'),
        0x5a5279b: ('jne', '0x5a527c7'),
        0x5a5279d: ('cmp', 'byte ptr [rdi + 0x88], 3'),
        0x5a527a4: ('jne', '0x5a527c7'),
        0x5a527a6: ('mov', 'rax, rdi'),
        0x5a527a9: ('add', 'rdi, 0x20'),
        0x5a527ad: ('mov', 'r14, rax'),
        0x5a527b0: ('cmp', 'byte ptr [rax + 0x18], 0'),
        0x5a527b4: ('je', '0x5a527cf'),
        0x5a527b6: ('mov', 'rax, qword ptr [rdi]'),
        0x5a527b9: ('lock dec', 'qword ptr [rax]'),
        0x5a527bd: ('jne', '0x5a527de'),
        0x5a527bf: ('call', 'qword ptr [rip + 0xa8d603]'),
        0x5a527c5: ('jmp', '0x5a527de'),
        0x5a527c7: ('add', 'rsp, 8'),
        0x5a527cb: ('pop', 'rbx'),
        0x5a527cc: ('pop', 'r14'),
        0x5a527ce: ('ret', ''),
        0x5a527cf: ('mov', 'rax, qword ptr [rdi]'),
        0x5a527d2: ('lock dec', 'qword ptr [rax]'),
        0x5a527d6: ('jne', '0x5a527de'),
        0x5a527d8: ('call', 'qword ptr [rip + 0xa8d5da]'),
        0x5a527de: ('mov', 'rdi, r14'),
        0x5a527e1: ('add', 'rdi, 0x28'),
        0x5a527e5: ('add', 'rsp, 8'),
        0x5a527e9: ('pop', 'rbx'),
        0x5a527ea: ('pop', 'r14'),
        0x5a527ec: ('jmp', '0x5a52490'),
        0x5a527f1: ('mov', 'rbx, rax'),
        0x5a527f4: ('mov', 'rdi, r14'),
        0x5a527f7: ('add', 'rdi, 0x28'),
        0x5a527fb: ('call', '0x5a52490'),
        0x5a52800: ('mov', 'rdi, rbx'),
        0x5a52803: ('call', '0x63f0a50'),
        0x5a52808: ('call', 'qword ptr [rip + 0xa8ccb2]'),
    }
    if set(decoded) != set(anchors):
        raise ValueError('Gate instruction set changed')
    for pc, expected in anchors.items():
        if decoded.get(pc) != expected:
            raise ValueError(f'Gate instruction changed at {pc:#x}')
    return instructions


def check_window(body, start, site, register):
    """Check one caller excerpt window: it must end in mov rdi, <reg>; call gate."""
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(body, start))
    if sum(i.size for i in instructions) != len(body):
        raise ValueError(f'Incomplete caller window decode at {start:#x}')
    decoded = {i.address: (i.mnemonic, i.op_str) for i in instructions}
    if decoded.get(site) != ('call', '0x5a52790'):
        raise ValueError(f'Caller window does not call the gate at {site:#x}')
    moves = [pc for pc, v in decoded.items() if v == ('mov', f'rdi, {register}') and pc < site]
    if not moves:
        raise ValueError(f'Caller window lacks the rdi setup at {site:#x}')
    return instructions


def produce(data=None):
    data = TARGET.read_bytes() if data is None else data
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('Node115 digest mismatch')
    secs = sections(data)
    secmap = {s['name']: s for s in secs}

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

    def fde_extent(va):
        found = [f for f in fdes if f['start'] == va]
        if len(found) != 1:
            raise ValueError(f'Exact FDE missing at {va:#x}')
        return found[0]

    def enclosing(va):
        found = [f for f in fdes if f['start'] <= va < f['end']]
        if len(found) != 1:
            raise ValueError(f'Enclosing FDE ambiguous at {va:#x}')
        return found[0]

    body, offset = read(START, END - START)
    instructions = check_body(body)

    rela = secmap['.rela.dyn']
    relocs = list(struct.iter_unpack('<QQq', data[rela['offset']:rela['offset'] + rela['size']]))

    def relocation_at(va):
        found = [dict(offset=slot, info=info, addend=addend)
                 for slot, info, addend in relocs if slot == va]
        if len(found) != 1 or found[0]['info'] != 8:
            raise ValueError(f'Relocation changed at {va:#x}')
        return found[0]

    slots = []
    for slot, expected in sorted(DTOR_SLOTS.items()) + [(CLEANUP_SHIM_SLOT, CLEANUP_SHIM)]:
        raw, slot_offset = read(slot, 8)
        rel = relocation_at(slot)
        if rel['addend'] != expected:
            raise ValueError(f'Slot {slot:#x} does not resolve to {expected:#x}')
        slots.append(dict(slot=slot, file_offset=slot_offset, raw_hex=raw.hex(),
                          relocations=[rel], resolved=expected))

    # The cleanup shim loads the pinned panic string with length 0x24.
    shim_body, shim_offset = read(CLEANUP_SHIM, 0x14)
    shim = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(shim_body, CLEANUP_SHIM))
    shim_decoded = {i.address: (i.mnemonic, i.op_str) for i in shim}
    if shim_decoded.get(0x1680caf) != ('lea', 'rdi, [rip - 0x12122f9]'):
        raise ValueError('Cleanup shim string LEA changed')
    lea = shim[2]
    disp = struct.unpack_from('<i', lea.bytes, len(lea.bytes) - 4)[0]
    if lea.address + lea.size + disp != PANIC_STRING_VA:
        raise ValueError('Cleanup shim does not load the pinned string')
    raw, string_offset = read(PANIC_STRING_VA, len(PANIC_STRING))
    if raw != PANIC_STRING:
        raise ValueError('Cleanup panic string changed')
    panic_string = dict(va=PANIC_STRING_VA, file_offset=string_offset,
                        text=PANIC_STRING.decode(), length=len(PANIC_STRING),
                        shim_fde=fde_extent(CLEANUP_SHIM))

    # The pad's resume call goes through the _Unwind_Resume PLT stub.
    dynsym = secmap['.dynsym']
    dynstr = secmap['.dynstr']
    relaplt = secmap['.rela.plt']
    resume_name = None
    for r_off, r_info, _ in struct.iter_unpack(
            '<QQq', data[relaplt['offset']:relaplt['offset'] + relaplt['size']]):
        if r_off == RESUME_SLOT:
            sym = r_info >> 32
            name_off = struct.unpack_from('<I', data, dynsym['offset'] + sym * 24)[0]
            end = data.index(b'\0', dynstr['offset'] + name_off)
            resume_name = data[dynstr['offset'] + name_off:end].decode()
    if resume_name != '_Unwind_Resume':
        raise ValueError('Resume PLT slot does not name _Unwind_Resume')

    # Whole-text census for this routine and for the sibling transition.
    text = secmap['.text']
    blob = data[text['offset']:text['offset'] + text['size']]
    tbase = text['address']

    def direct_sites(target):
        found = []
        for op in (0xE8, 0xE9):
            i = blob.find(bytes([op]))
            while i != -1:
                if i + 5 <= len(blob):
                    disp = struct.unpack_from('<i', blob, i + 1)[0]
                    va = tbase + i
                    if va + 5 + disp == target:
                        found.append((va, 'call' if op == 0xE8 else 'jmp'))
                i = blob.find(bytes([op]), i + 1)
        return sorted(found)

    sites = direct_sites(START)
    calls = [va for va, kind in sites if kind == 'call']
    jumps = [va for va, kind in sites if kind == 'jmp']
    expected_sites = sorted(c[0] for c in CALLERS)
    if calls != expected_sites or jumps:
        raise ValueError('Direct census changed')
    sibling_sites = direct_sites(SIBLING)
    sibling_fdes = sorted({(enclosing(va)['start'], enclosing(va)['end'])
                           for va, _ in sibling_sites})
    caller_records = []
    for site, cs, ce, register, window in CALLERS:
        enc = enclosing(site)
        if (enc['start'], enc['end']) != (cs, ce):
            raise ValueError(f'Caller FDE changed at {site:#x}')
        wbody, woffset = read(window[0], window[1] - window[0])
        check_window(wbody, window[0], site, register)
        caller_records.append(dict(site=site, caller_fde=enc, kind='call',
                                   rdi_setup=f'mov rdi, {register}',
                                   excerpt_window=dict(start=window[0], end=window[1]),
                                   excerpt_file_offset=woffset,
                                   excerpt_sha256=hashlib.sha256(wbody).hexdigest()))
    caller_fdes = sorted({(c['caller_fde']['start'], c['caller_fde']['end'])
                          for c in caller_records})
    if [list(x) for x in caller_fdes] != [list(x) for x in sibling_fdes]:
        raise ValueError('Caller FDE set differs from the sibling transition set')
    stored = []
    needle = struct.pack('<Q', START)
    for s in secs:
        if s['type'] == 8 or s['size'] == 0:
            continue
        seg = data[s['offset']:s['offset'] + s['size']]
        i = seg.find(needle)
        while i != -1:
            stored.append(dict(section=s['name'], va=s['address'] + i))
            i = seg.find(needle, i + 1)
    addend_refs = [slot for slot, _, addend in relocs if addend == START]
    if stored or addend_refs:
        raise ValueError('Stored or relocated reference to the gate appeared')
    census = dict(direct_call_sites=calls, direct_tail_jumps=jumps,
                  caller_fdes=[dict(start=a, end=b) for a, b in caller_fdes],
                  stored_qwords=stored, relative_addends=addend_refs,
                  sibling=dict(target=SIBLING,
                               direct_sites=[va for va, _ in sibling_sites],
                               caller_fdes=[dict(start=a, end=b) for a, b in sibling_fdes],
                               same_caller_fde_set=True))

    edges = []
    for i in instructions:
        if i.mnemonic == 'call' or i.mnemonic.startswith('j'):
            edges.append(dict(pc=i.address, bytes=i.bytes.hex(),
                              mnemonic=i.mnemonic, operand=i.op_str))
    helpers = [dict(target=TAIL_RELEASE, fdes=[fde_extent(TAIL_RELEASE)],
                    semantic_status='shared +0x28 field release also called by the '
                                    'sibling transition; body unmeasured here'),
               dict(target=0x5ce86d0, fdes=[fde_extent(0x5ce86d0)],
                    semantic_status='flag==0 destructor reached through slot '
                                    '0x64dfdb8; body unmeasured'),
               dict(target=0x5ce8da0, fdes=[fde_extent(0x5ce8da0)],
                    semantic_status='flag!=0 destructor reached through slot '
                                    '0x64dfdc8; body unmeasured')]
    return dict(target_sha256=SHA, target_bytes=len(data),
                component='async environment sibling gate',
                base_commit='05bc2de303c05525b71e7e257426e741bc66a390',
                start=START, end=END, file_offset=offset, fde=fde[0],
                body_sha256=hashlib.sha256(body).hexdigest(), body_hex=body.hex(),
                native_instructions=len(instructions),
                call_and_branch_edges=edges, indirect_slots=slots,
                panic_string=panic_string,
                resume=dict(plt=RESUME_PLT, slot=RESUME_SLOT, symbol=resume_name),
                callers=caller_records, census=census,
                direct_helpers=helpers,
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
        chunks = []
        for site, _, _, _, window in CALLERS:
            chunks.append(subprocess.check_output([
                'objdump', '-d', '-M', 'intel', f'--start-address={window[0]}',
                f'--stop-address={window[1]}', str(TARGET.relative_to(ROOT))], cwd=ROOT))
        (PACKET / 'callers_excerpt.asm').write_bytes(
            canonical_export(b''.join(chunks)))
    elif (PACKET / 'records.json').read_text() != expected:
        raise ValueError('Retained records differ from authenticated input')
    print(json.dumps({k: result[k] for k in ('start', 'end', 'native_instructions', 'body_sha256')}))


if __name__ == '__main__':
    main()
