"""Static, digest-bound send-helper evidence. Never executes target instructions.

Requires Capstone 5.0.6 and pyelftools 0.32. Run from the repository root.
--write writes records.json and disassembly.txt; default compares retained bytes.
"""
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

import capstone
import elftools
from capstone import x86_const as x86
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from fde_extents import eh_frame_records

PACKET = Path(__file__).resolve().parent
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
START, END = 0x5cdfc90, 0x5cdfe4b


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def collect(data, authenticate=True):
    if authenticate:
        require(sha(data) == TARGET, 'target SHA-256 mismatch')
    elf = ELFFile(io.BytesIO(data))

    def read(va, size):
        matches = [s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS'
                   and s['sh_addr'] <= va and va + size <= s['sh_addr'] + s['sh_size']]
        require(len(matches) == 1, f'ambiguous/unmapped VA {va:#x}')
        sec = matches[0]
        off = sec['sh_offset'] + va - sec['sh_addr']
        return data[off:off + size]

    _, fdes = eh_frame_records(data)
    owners = [f for f in fdes if f['start'] == START]
    require(len(owners) == 1 and owners[0]['end'] == END, 'FDE extent mismatch')
    fde = owners[0]
    frame_records = {}
    for label in ('fde', 'cie'):
        va = fde[label]
        length = struct.unpack('<I', read(va, 4))[0] + 4
        frame_records[label] = {'va': hex(va), 'bytes': read(va, length).hex()}

    body = read(START, END - START)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    insns = list(decoder.disasm(body, START))
    require(sum(i.size for i in insns) == len(body), 'incomplete instruction decode')
    boundaries = {i.address for i in insns}
    branches, calls = [], []
    relocations = {}
    for sec in elf.iter_sections():
        if sec['sh_type'] not in ('SHT_RELA', 'SHT_REL'):
            continue
        symbols = elf.get_section(sec['sh_link']) if sec['sh_link'] else None
        for rel in sec.iter_relocations():
            off = rel['r_offset']
            symbol = symbols.get_symbol(rel['r_info_sym']).name if symbols and rel['r_info_sym'] else None
            relocations.setdefault(off, []).append({
                'type': rel['r_info_type'], 'symbol': symbol,
                'addend': hex(rel['r_addend']) if rel.is_RELA() else None,
            })
    for i in insns:
        if i.group(capstone.CS_GRP_JUMP):
            require(i.operands[0].type == x86.X86_OP_IMM, 'indirect jump requires separate analysis')
            dest = i.operands[0].imm
            require(dest in boundaries, f'branch outside decoded boundaries {dest:#x}')
            branches.append({'site': hex(i.address), 'kind': i.mnemonic, 'target': hex(dest)})
        if i.group(capstone.CS_GRP_CALL):
            op = i.operands[0]
            row = {'site': hex(i.address)}
            if op.type == x86.X86_OP_IMM:
                row['direct_target'] = hex(op.imm)
            elif op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                slot = i.address + i.size + op.mem.disp
                row.update(slot=hex(slot), slot_bytes=read(slot, 8).hex(),
                           relocations=relocations.get(slot, []))
                require(len(row['relocations']) == 1, 'call slot requires a unique relocation')
            else:
                raise ValueError('unresolved call addressing')
            calls.append(row)

    # These are instruction observations, not names recovered from source.
    pins = {
        0x5cdfccc: '83fbff',       # fd sentinel
        0x5cdfcd5: 'be02000000',   # pending raw result
        0x5cdfd39: 'b900400000',   # send flags
        0x5cdfd53: '49c1e720',     # errno packing
        0x5cdfd57: '4983cf02',
        0x5cdfd63: '3c0d',        # retry classifier result
        0x5cdfd65: '0f8591000000',
        0x5cdfd72: '4183e433',    # sampled readiness projection
        0x5cdfd76: '4981f43f00ff00',
        0x5cdfd85: '4138cd',      # generation match
        0x5cdfd93: 'f0480fb18d90000000',
        0x5cdfdad: '4885c0',      # zero sends skip clear
        0x5cdfdb3: '4c397c2410',  # requested <= actual skips clear
        0x5cdfdb8: '0f96c1',
        0x5cdfdca: '4183e433',
        0x5cdfdce: '4981f43f00ff00',
        0x5cdfde5: '4138d5',
        0x5cdfdef: 'f0480fb19190000000',
    }
    by_address = {i.address: i for i in insns}
    for va, wanted in pins.items():
        require(va in by_address and by_address[va].bytes.hex() == wanted,
                f'semantic pin mismatch at {va:#x}')
    bindings = {c.get('slot'): c.get('relocations') for c in calls if 'slot' in c}
    require(bindings['0x64eb088'][0]['symbol'] == 'send', 'send import mismatch')
    require(bindings['0x64dffc8'][0]['symbol'] == '__errno_location', 'errno import mismatch')
    records = {
        'target_sha256': TARGET, 'start_va': hex(START), 'end_va': hex(END),
        'body_file_offset': hex(next(s['sh_offset'] + START - s['sh_addr'] for s in elf.iter_sections()
                                     if s.name == '.text')),
        'body_sha256': sha(body), 'body_bytes': body.hex(),
        'byte_count': len(body), 'instruction_count': len(insns),
        'frame_records': frame_records, 'lsda': fde['lsda'],
        'branches': branches, 'calls': calls,
        'semantic_pins': {hex(k): v for k, v in pins.items()},
        'tools': {'capstone': capstone.__version__, 'pyelftools': '0.32'},
    }
    listing = ''.join(f'{i.address:#x}: {i.bytes.hex():24} {i.mnemonic} {i.op_str}'.rstrip() + '\n'
                      for i in insns)
    return records, listing


def controls(data):
    # Bypass whole-file authentication only here, to show the local observations
    # reject operative operand changes independently of the whole-file guard.
    elf = ELFFile(io.BytesIO(data))
    text = elf.get_section_by_name('.text')
    results = []
    for va in (0x5cdfcd6, 0x5cdfd3b, 0x5cdfd66, 0x5cdfd75,
               0x5cdfd79, 0x5cdfdb9, 0x5cdfdcd):
        off = text['sh_offset'] + va - text['sh_addr']
        altered = bytearray(data)
        altered[off] ^= 1
        try:
            collect(bytes(altered), authenticate=False)
        except ValueError as error:
            results.append({'mutated_va': hex(va), 'rejected': True, 'reason': str(error)})
        else:
            raise ValueError(f'mutation accepted: {va:#x}')

    # Independent forms: native 32-bit instruction sequence versus a bit-field
    # description. Exhaust all low-six readiness values and all 8-bit generations.
    tested = 0
    for sampled in range(64):
        for generation in range(256):
            for observed in (0, 0xffffffffffffffff, 0xa5a55a5a12345678,
                             (generation << 16) | 0x3333):
                native_mask = (sampled & 0x33) ^ 0xff003f
                native = (observed & 0xffffffff) & native_mask
                described = (observed & 0xff0000) | (observed & 0x3f & ~(sampled & 0x33))
                require(native == described, 'bit projection disagreement')
                tested += 1
    return {'operative_mutations': results, 'projection_cases': tested,
            'projection_mismatches': 0,
            'caveat': 'Finite arithmetic checks, not execution of the target or a concurrency proof.'}


def main():
    require(capstone.__version__ == '5.0.6', 'Capstone 5.0.6 required')
    require(elftools.__version__ == '0.32', 'pyelftools 0.32 required')
    data = (ROOT / 'artifacts/node/115/hl-node').read_bytes()
    records, listing = collect(data)
    records['controls'] = controls(data)
    encoded = json.dumps(records, indent=2, sort_keys=True) + '\n'
    if sys.argv[1:] == ['--write']:
        (PACKET / 'records.json').write_bytes(encoded.encode())
        (PACKET / 'disassembly.txt').write_bytes(listing.encode())
    else:
        require(not sys.argv[1:], 'only --write is supported')
        require((PACKET / 'records.json').read_bytes() == encoded.encode(), 'record regeneration mismatch')
        require((PACKET / 'disassembly.txt').read_bytes() == listing.encode(), 'disassembly regeneration mismatch')
    print(json.dumps({'matches': True, 'bytes': records['byte_count'],
                      'instructions': records['instruction_count'], 'controls': records['controls']}))


if __name__ == '__main__':
    main()
