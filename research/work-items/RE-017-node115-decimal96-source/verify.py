#!/usr/bin/env python3
"""Verify retained static evidence, not behavior of the captured executable."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_facts(rows, expected):
    for address, instruction in expected.items():
        require(rows.get(address) == instruction, f"semantic witness changed: {address}")



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
    rows = {}
    count = 0
    for window in packet['windows']:
        start, end = int(window['start'], 16), int(window['end'], 16)
        fde = tuple(int(v, 16) for v in window['fde'])
        require(fde in fdes and fde[0] <= start < end <= fde[1], 'wrong FDE boundary')
        raw = read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == window['sha256'], 'window bytes changed')
        observed = [[hex(i.address), i.bytes.hex(), (i.mnemonic + ' ' + i.op_str).rstrip()]
                    for i in decoder.disasm(raw, start)]
        require(observed == window['rows'], 'instruction transcript differs')
        require(sum(len(bytes.fromhex(r[1])) for r in observed) == len(raw), 'undecoded bytes')
        rows.update({r[0]: r[2] for r in observed})
        count += len(observed)
    check_facts(rows, packet['facts'])
    for address, expected in packet['relocations'].items():
        require(relocations[int(address, 16)] == int(expected, 16), 'wrong producer relocation')
    for address, expected in packet['imports'].items():
        require(imports.get(int(address, 16)) == expected, 'wrong imported comparator/copy')
    for address, label in packet['labels'].items():
        require(read(int(address, 16), len(label)) == label.encode(), 'wrong native operation label')

    for address, raw_hex in packet['constants'].items():
        raw = bytes.fromhex(raw_hex)
        require(read(int(address, 16), len(raw)) == raw, 'wrong numeric constant')
    require(read(0x450e60, 8) != bytes.fromhex('000000000000e03f'),
            'exact-half countermodel accepted')

    # Negative controls reject plausible but incorrect interpretations of the
    # same selected path. They do not execute or emulate target instructions.
    mutations = [('wrong_coefficient_high_word', '0x5c44b51', 'mov r8d, dword ptr [rdi + 8]'), ('wrong_scale_field', '0x5c44b58', 'shr ebp, 8'), ('skip_integer_fraction_split', '0x5c44cea', None), ('skip_decimal_rescale', '0x5c44daf', None), ('skip_round_step', '0x5c44db3', None), ('wrong_sign_order', '0x5c44dc6', None), ('wrong_power_multiply_order', '0x63f00a0', None), ('round_without_half_predecessor', '0x63efe50', None)]
    for name, address, changed in mutations:
        altered = copy.copy(rows)
        altered[address] = changed
        try:
            check_facts(altered, packet['facts'])
        except ValueError:
            continue
        raise ValueError(f'negative control accepted: {name}')
    try:
        check_target(bytes([data[0] ^ 1]) + data[1:])
    except ValueError:
        pass
    else:
        raise ValueError('wrong-target control accepted')
    print(f'PASS: {len(packet["windows"])} windows, {count} instructions, '
          f'{len(packet["facts"])} instruction witnesses, 6 relocations, 4 constants, 10 negative controls')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    verify(parser.parse_args().target)
