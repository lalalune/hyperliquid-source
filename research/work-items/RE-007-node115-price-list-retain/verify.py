#!/usr/bin/env python3
"""Verify retained static evidence, not behavior of the captured executable."""
import argparse
import hashlib
import json
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    count = 0
    decoded = {}
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
        decoded.update({row[0]: row[2] for row in observed})
        count += len(observed)
    for address, expected in packet['relocations'].items():
        require(relocations[int(address, 16)] == int(expected, 16), 'wrong callee')
    for address, expected in packet['imports'].items():
        require(imports.get(int(address, 16)) == expected, 'wrong import')
    for address, expected in packet['constants'].items():
        value = bytes.fromhex(expected)
        require(read(int(address, 16), len(value)) == value, 'wrong constant')
    witnesses = [
        ('second list selector', '0x366ced6', 'mov byte ptr [rsp + 0xe], 1', 'mov byte ptr [rsp + 0xe], 2'),
        ('third list selector', '0x366cf66', 'mov byte ptr [rsp + 0xe], 2', 'mov byte ptr [rsp + 0xe], 1'),
        ('book record word', '0x3d9894d', 'mov rax, qword ptr [rax + rcx + 0x118]', 'mov rax, qword ptr [rax + rcx + 0x110]'),
        ('missing book supplies zero', '0x3d9896a', 'xor eax, eax', 'mov eax, 1'),
        ('post-callback context load', '0x447c6af', 'cmp qword ptr [rsi + 0x378], r12', 'cmp qword ptr [rsi + 0x370], r12'),
        ('final sentinel means retain', '0x3d98adf', 'sete al', 'setne al'),
        ('stable copy after rejection', '0x366d05d', 'movups xmmword ptr [r15 + rax], xmm0', 'movups xmmword ptr [r12], xmm0'),
    ]
    for name, address, expected, alternative in witnesses:
        require(decoded.get(address) == expected, f'{name}: evidence mismatch')
        require(decoded[address] != alternative, f'{name}: alternative accepted')
    print(f'PASS: {len(witnesses)} alternative instructions rejected; 0 witness mismatches')
    print(f'PASS: {count} instructions verified against the pinned artifact')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    verify(parser.parse_args().target)
