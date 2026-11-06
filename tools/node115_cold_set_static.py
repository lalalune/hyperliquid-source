#!/usr/bin/env python3
'''Static evidence for the Node #115 cold set allocation path.'''
import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
from fde_extents import eh_frame_records
from merge_delegate_static import _relocations, _dynsym_name, descriptor_template, read

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OWNERS = {
    0x4743990: (0x4743ff0, 'eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef'),
    0x474ba60: (0x474bcd3, '4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44'),
}
ANCHORS = {
    0x474ba86: '48837b1000', 0x474ba8b: '0f84f0010000',
    0x474bc81: 'be01000000', 0x474bc8c: 'b901000000',
    0x474bc91: 'ff15f1f2d901', 0x474bc97: 'e9f5fdffff',
    0x47439a6: '488b4718', 0x47439dd: '4839fe', 0x47439e0: '7629',
    0x47439e2: '48ffc1', 0x47439ff: '41bd04000000', 0x4743a05: '4c0f43e8',
    0x4743a85: 'b918000000', 0x4743aa7: '498d6d10',
    0x4743ad9: 'ff15a1b9d901', 0x4743b1a: 'beff000000', 0x4743b22: 'ff1528bcd901',
    0x4743b5e: '4c8b6918', 0x4743b65: '0f84c7030000',
    0x4743f32: '31c0', 0x4743f3e: '4c8921', 0x4743f41: '4c894108',
    0x4743f45: '4c897910', 0x4743f49: '48894118', 0x4743f50: '742e',
}


def trace_cold_path(target):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    rows = {}
    relocs = _relocations(target)
    for address, encoded in ANCHORS.items():
        _, blob = read(target, address, len(bytes.fromhex(encoded)))
        if blob.hex() != encoded:
            raise ValueError(f'Unexpected bytes at {address:#x}')
        instruction, = decoder.disasm(blob, address)
        row = dict(bytes=encoded, mnemonic=instruction.mnemonic, operands=instruction.op_str)
        if instruction.mnemonic == 'call':
            operand, = instruction.operands
            if operand.type != CS_OP_MEM or instruction.reg_name(operand.mem.base) != 'rip':
                raise ValueError('Unexpected call operand')
            slot = address + instruction.size + operand.mem.disp
            relocation = relocs[slot]
            row['slot'] = hex(slot)
            row['relocation'] = relocation
            if relocation['type'] == 6:
                row['symbol'] = _dynsym_name(target, relocation['symbol'])
        rows[hex(address)] = row
    fill = rows['0x4743b22']
    if fill.get('symbol') != 'memset':
        raise ValueError(f'Unexpected fill binding {fill}')
    gate = rows['0x474bc91']
    if gate['slot'] != '0x64eaf88' or gate['relocation'] != dict(type=8, symbol=0, addend=0x4743990):
        raise ValueError(f'Unexpected initializer binding {gate}')
    template = descriptor_template(target)
    initial = [int(template[hex(addr)]['file_qword'], 16) for addr in (0x6495100, 0x6495108, 0x6495110)]
    if initial != [0, 0, 0]:
        raise ValueError(f'Unexpected cold fields {initial}')
    request = int(rows['0x474bc81']['operands'].split(', ')[1], 0)
    buckets = int(rows['0x47439ff']['operands'].split(', ')[1], 0)
    stride = int(rows['0x4743a85']['operands'].split(', ')[1], 0)
    padding = int(rows['0x4743aa7']['operands'].split(' + ')[1][:-1], 0)
    fill_byte = int(rows['0x4743b1a']['operands'].split(', ')[1], 0)
    if request != 1 or initial != [0, 0, 0]:
        raise ValueError('Cold path prerequisites changed')
    payload_bytes = (stride * buckets + 15) & ~15
    control_bytes = buckets + padding
    return dict(template=template, instructions=rows, cold_path=dict(
        bucket_count=buckets, allocation_bytes=payload_bytes + control_bytes,
        control_offset=payload_bytes, control_bytes=control_bytes, control_fill=fill_byte,
        mask=buckets - 1, growth_remaining=buckets - 1, item_count=0,
        old_elements_migrated=0, old_allocation_freed=False))


def extract(target):
    if len(target) != 105896032 or hashlib.sha256(target).hexdigest() != TARGET:
        raise ValueError('Unexpected Node #115 capture')
    _, frames = eh_frame_records(target)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    owners = {}
    for start, (end, digest) in OWNERS.items():
        extents = [frame['end'] for frame in frames if frame['start'] == start]
        if extents != [end]:
            raise ValueError(f'Unexpected unwind extent at {start:#x}')
        _, code = read(target, start, end - start)
        instructions = list(decoder.disasm(code, start))
        if hashlib.sha256(code).hexdigest() != digest or sum(i.size for i in instructions) != len(code):
            raise ValueError(f'Unexpected decoded body at {start:#x}')
        owners[hex(start)] = dict(end=hex(end), sha256=digest, instructions=len(instructions))
    return dict(target_sha256=TARGET, owners=owners, **trace_cold_path(target))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    options = parser.parse_args()
    print(json.dumps(extract(options.binary.read_bytes()), indent=2))
