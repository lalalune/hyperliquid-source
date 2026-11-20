#!/usr/bin/env python3
"""Verify retained static evidence, not behavior of the captured executable."""
import argparse
import hashlib
import json
import re
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_handoff(rows, relocations, imports):
    def expect(address, spelling):
        require(rows[address][2] == spelling, f'unexpected instruction at {address:#x}')

    def slot_call(address, destination):
        encoded = bytes.fromhex(rows[address][1])
        require(len(encoded) == 6 and encoded[:2] == b'\xff\x15', 'expected indirect call')
        slot = address + len(encoded) + int.from_bytes(encoded[2:], 'little', signed=True)
        require(imports.get(slot, relocations.get(slot)) == destination,
                f'unexpected call destination at {address:#x}')

    def operands(address, pattern):
        result = re.fullmatch(pattern, rows[address][2])
        require(result is not None, f'unexpected operand at {address:#x}')
        return tuple(int(value, 0) for value in result.groups())

    # The builder result survives the second allocation made inside the join.
    slot_call(0x564680d, 'pthread_join')
    slot_call(0x5646ba2, 0x3c13610)
    expect(0x56467ef, 'mov r13, rdi')
    expect(0x5646ba8, 'cmp byte ptr [rax + 0xb9a], r15b')
    expect(0x5646bb7, 'jne 0x5646c37')
    expect(0x5646bc1, 'mov qword ptr [rsp + 0x48], rax')
    expect(0x5646c93, 'pcmpeqb xmm2, xmm0')
    expect(0x5646c9c, 'pcmpeqb xmm0, xmm1')
    expect(0x5646ca0, 'pand xmm0, xmm2')
    expect(0x5646ca4, 'pmovmskb eax, xmm0')
    expect(0x5646ca8, 'cmp eax, 0xffff')
    expect(0x5646cad, 'je 0x5646df7')
    expect(0x5646e9a, 'mov edi, 0xb0')
    slot_call(0x5646e9f, 0x6355830)
    expect(0x5646eae, 'mov rbx, rax')
    expect(0x5646eeb, 'mov rax, qword ptr [rsp + 0x48]')
    (joined_offset,) = operands(0x5646ef0, r'mov qword ptr \[r13 \+ (\w+)\], rax')
    expect(0x5646ef4, 'mov qword ptr [r13 + 0x30], rbx')
    expect(0x5646ef8, 'mov byte ptr [r13], 0x44')

    # The caller consumes the same qword it requested in its return buffer.
    slot_call(0x2ad9fcc, 0x56467d0)
    (result_base,) = operands(0x2ad9fa6, r'lea r12, \[rsp \+ (\w+)\]')
    expect(0x2ad9fc3, 'mov rdi, r12')
    expect(0x2ad9fd5, 'cmp byte ptr [rsp + 0x220], 0x44')
    expect(0x2ad9fdd, 'je 0x2ada41c')
    (result_field,) = operands(0x2ada440, r'mov rax, qword ptr \[rsp \+ (\w+)\]')
    require(result_field - result_base == joined_offset == 8, 'join field mismatch')
    expect(0x2ada448, 'mov qword ptr [rsp + 0x18], rax')
    expect(0x2ada503, 'cmp bpl, 0x44')
    expect(0x2ada52b, 'mov r13d, 2')
    expect(0x2ada53c, 'mov r14, qword ptr [rsp + 0x18]')
    expect(0x2ada550, 'mov rcx, r14')
    expect(0x2ada5e2, 'mov qword ptr [rsp + 0x28], rcx')
    expect(0x2ada5f5, 'jne 0x2ada67c')
    expect(0x2ada6f6, 'mov rcx, qword ptr [rsp + 0x28]')
    expect(0x2ada7d1, 'cmp r13, 3')
    expect(0x2ada7d5, 'jne 0x2adaa11')
    (record_base,) = operands(0x2adaa11, r'mov qword ptr \[rsp \+ (\w+)\], r13')
    (record_field,) = operands(0x2adaa69, r'mov qword ptr \[rsp \+ (\w+)\], rcx')
    expect(0x2adaae6, 'cmp r13, 2')
    expect(0x2adaaef, 'sete al')
    expect(0x2adaaf6, 'xor al, byte ptr [rbx + 0x54]')
    expect(0x2adaaf9, 'je 0x2adb3fc')

    # Derive the byte range carried through each actual memcpy.
    (source,) = operands(0x2adb58e, r'lea rsi, \[rsp \+ (\w+)\]')
    (temporary,) = operands(0x2adb586, r'lea rdi, \[rsp \+ (\w+)\]')
    (first_len,) = operands(0x2adb596, r'mov edx, (\w+)')
    slot_call(0x2adb59b, 'memcpy')
    (next_source,) = operands(0x2adb5bc, r'lea rsi, \[rsp \+ (\w+)\]')
    (second_len,) = operands(0x2adb5c4, r'mov edx, (\w+)')
    expect(0x2ad716b, 'mov qword ptr [rsp + 0x1b8], rdi')
    expect(0x2adb5c9, 'mov r14, qword ptr [rsp + 0x1b8]')
    expect(0x2adb5d1, 'mov rdi, r14')
    slot_call(0x2adb5d4, 'memcpy')
    offset = record_field - record_base
    require(source == record_base and next_source == temporary, 'broken copy chain')
    require(offset == 0x30 and offset + 8 <= min(first_len, second_len),
            'selected pointer does not reach outer result +0x30')


def negative_controls(rows, decoder, relocations, imports):
    # Mutate operands or branch polarity in local byte copies, then disassemble
    # and check the changed flow independently of the transcript comparison.
    controls = (
        (0x5646ef0, -1, 0x30),  # use the sibling allocation at +0x30
        (0x5646cad, 1, 0x85),   # take unequal digest lanes
        (0x2ada440, 4, 0x50),   # select the caller's join +0x30 word
        (0x2ada6f6, -1, 0x38),  # restore the adjacent stack word
        (0x2adaaf9, 1, 0x85),   # invert the mode gate
        (0x2adb5c4, 1, 0x30),   # truncate before the qword being traced
    )
    for address, index, replacement in controls:
        altered = bytearray.fromhex(rows[address][1])
        require(altered[index] != replacement, 'ineffective negative control')
        altered[index] = replacement
        instruction, = decoder.disasm(bytes(altered), address)
        candidate = rows.copy()
        candidate[address] = [hex(address), altered.hex(),
                              instruction.mnemonic + ' ' + instruction.op_str]
        try:
            check_handoff(candidate, relocations, imports)
        except ValueError:
            continue
        raise ValueError(f'altered evidence accepted at {address:#x}')
    print(f'PASS: rejected {len(controls)} changed instruction encodings')


def verify(target):
    packet = json.loads(Path(__file__).with_name('records.json').read_text())
    data = target.read_bytes()
    def check_target(candidate):
        require(len(candidate) == packet['target_size'], 'wrong target size')
        require(hashlib.sha256(candidate).hexdigest() == packet['target_sha256'], 'wrong target digest')
    check_target(data)
    require(capstone.__version__ == '5.0.7', 'use Capstone 5.0.7 for instruction spelling')
    with target.open('rb') as stream:
        elf = ELFFile(stream)
        sections = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                    for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS']
        fdes = {(e['initial_location'], e['initial_location'] + e['address_range'])
                for e in elf.get_dwarf_info().EH_CFI_entries() if isinstance(e, FDE)}
        relocations = {}
        imports = {}
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_RELA':
                for relocation in section.iter_relocations():
                    relocations[relocation['r_offset']] = relocation['r_addend']
                    if relocation['r_info_sym']:
                        table = elf.get_section(section['sh_link'])
                        imports[relocation['r_offset']] = table.get_symbol(relocation['r_info_sym']).name

    def read(address, count):
        for start, offset, size in sections:
            if start <= address and address + count <= start + size:
                return data[offset + address - start:offset + address - start + count]
        raise ValueError(f'unmapped range {address:x}+{count:x}')

    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoded = {}
    count = 0
    for window in packet['windows'] + packet['cited_only_not_claimed']:
        start, end = int(window['start'], 16), int(window['end'], 16)
        fde = tuple(int(v, 16) for v in window['fde'])
        require(fde in fdes and fde[0] <= start < end <= fde[1], 'wrong FDE boundary')
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window['sha256'], 'window bytes changed')
        observed = [[hex(i.address), i.bytes.hex(), (i.mnemonic + ' ' + i.op_str).rstrip()]
                    for i in decoder.disasm(raw, start)]
        require(observed == window['rows'], 'instruction transcript differs')
        require(sum(len(bytes.fromhex(r[1])) for r in observed) == len(raw), 'undecoded bytes')
        decoded.update({int(row[0], 16): row for row in observed})
        count += len(observed)
    for address, expected in packet['relocations'].items():
        require(relocations[int(address, 16)] == int(expected, 16), 'wrong callee')
    for address, expected in packet['imports'].items():
        require(imports.get(int(address, 16)) == expected, 'wrong import')
    for address, expected in packet['constants'].items():
        value = bytes.fromhex(expected)
        require(read(int(address, 16), len(value)) == value, 'wrong constant')
    check_handoff(decoded, relocations, imports)
    negative_controls(decoded, decoder, relocations, imports)
    print(f'PASS: {count} instructions verified against the pinned artifact')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    verify(parser.parse_args().target)
