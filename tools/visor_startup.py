#!/usr/bin/env python3
"""RE-013: bounded captured-visor startup handoff, from static ELF bytes only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/visor/captured/hl-visor'
SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
SIZE = 8305392
BASE = '1f8c67c63ca4794c9689235471c60297f8a5c985'
RANGES = {
    0x4e4f70: (0x4e4f75, 'dfa92fdb18d3efd032329f2235d028649db70c80c85efbf1934b940879949131'),
    0x4e4f80: (0x4e4f8d, '5de063568fe2ea4eb1d1956e5c1125c062273a8e6583e275daa962fb9940397f'),
    0x4e4f90: (0x4e4faf, 'b1f9193f0ba8bc12c77cbbb0832ea7c64e2b48ba279f239232768aa4d45d866e'),
    0x4e4fb0: (0x4e4fd7, '042bc40eae8af4302e42a3c879ca30941f341dce8ed0693565a0e4fa8c37a059'),
    0x5e34c0: (0x5e44b3, 'cedc1786329ff1c085e54a94daca3e0d804bd0da5033478767d7d81572352464'),
}
CONTROLS = {
    0x2bd198: '488d3d117e2200ff1563795200f4',
    0x4e4f70: '50ffd758c3',
    0x4e4f80: '50488b3fe8e7ffffff31c059c3',
    0x4e4f90: '4881ecc8040000c68424f9010000004889e7e819e50f004881c4c8040000c3',
    0x4e4fb0: '504889f14863d7488d05d2ffffff48890424488d3527ec2d004889e74531c0ff15eb1e300059c3',
    0x5e34e5: '488dbc24980a0000be01000000e819740f0066c784247d0b00000101b301488dbc24880b0000488db424980a0000ff15bf22200083bc24880b0000020f84ce000000',
    0x5e35a2: '64410fb6464883f8010f849700000083f802757c',
    0x5e35f5: '488b8424900b00004889842400010000488d3d364dadff488d0ded341f004c8d05b6391f00488d942400010000be2b000000ff15b3152000',
    0x5e3648: '6449833e000f85b70600006449c706ffffffff',
    0x5e36eb: '4883bc2490000000010f8473080000',
    0x5e36fa: '488dbc24880b0000bac8040000488b742418ff1556142000',
    0x5e3ae9: 'e862440e004189c784c07412488dbc24880b0000488d742450e8b9090000',
    0x5e404c: '488d9c24880b0000bac80400004889df488b742418ff15010b2000',
    0x5e4100: '4889df4c89e6e8b5030000',
    0x5e4197: '0f0b',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _derive(data):
    """Private corruption-control seam; public build() also authenticates the ELF."""
    secs = sections(data)

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, f'ambiguous/non-file-backed span {va:#x}')
        offset = matches[0]['offset'] + va - matches[0]['address']
        return offset, data[offset:offset + size]

    def window(va, size):
        offset, raw = read(va, size)
        return {'va': hex(va), 'file_offset': offset, 'bytes': size,
                'hex': raw.hex(), 'sha256': digest(raw)}

    controls = []
    for va, encoded in CONTROLS.items():
        expected = bytes.fromhex(encoded)
        require(read(va, len(expected))[1] == expected, f'startup instruction control differs at {va:#x}')
        controls.append(window(va, len(expected)))
    entry = struct.unpack_from('<Q', data, 24)[0]
    require(entry == 0x2bd180, 'visor entry VA differs')

    dyn = next(s for s in secs if s['name'] == '.dynsym')
    strings = next(s for s in secs if s['name'] == '.dynstr')
    text = data[strings['offset']:strings['offset'] + strings['size']]
    reloc_section = next(s for s in secs if s['name'] == '.rela.dyn')
    require(reloc_section['size'] % 24 == 0, 'RELA stride differs')
    relocs = {}
    for offset in range(reloc_section['offset'], reloc_section['offset'] + reloc_section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, offset)
        require(slot not in relocs, f'duplicate relocation at {slot:#x}')
        symbol_index = info >> 32
        require(symbol_index * 24 + 24 <= dyn['size'], 'dynamic symbol outside table')
        name = struct.unpack_from('<I', data, dyn['offset'] + symbol_index * 24)[0]
        require(name < len(text) and b'\0' in text[name:], 'dynamic symbol name outside table')
        symbol = text[name:text.index(b'\0', name)].decode('utf-8')
        relocs[slot] = {'slot': hex(slot), 'relocation_file_offset': offset,
                        'type': info & 0xffffffff, 'addend': hex(addend), 'symbol': symbol}

    relocation_rows = []

    def relocation(slot, kind, addend, symbol=''):
        row = relocs.get(slot)
        require(row is not None and (row['type'], row['addend'], row['symbol'])
                == (kind, hex(addend), symbol), f'startup relocation differs at {slot:#x}')
        if row not in relocation_rows:
            relocation_rows.append(row)
        return row

    edges = []

    def direct(site, target):
        _, raw = read(site, 5)
        require(raw[0] == 0xe8 and site + 5 + struct.unpack_from('<i', raw, 1)[0] == target,
                f'direct call differs at {site:#x}')
        edges.append({'site': hex(site), 'kind': 'call-rel32', 'target': hex(target), **window(site, 5)})

    def indirect(site, slot, kind, addend, symbol=''):
        _, raw = read(site, 6)
        require(raw[:2] == b'\xff\x15' and site + 6 + struct.unpack_from('<i', raw, 2)[0] == slot,
                f'RIP call differs at {site:#x}')
        relocation(slot, kind, addend, symbol)
        edges.append({'site': hex(site), 'kind': 'call-rip-slot', 'slot': hex(slot),
                      'target': hex(addend) if kind == 8 else symbol, **window(site, 6)})

    for site, target in ((0x4e4f84,0x4e4f70),(0x4e4fa2,0x5e34c0),(0x5e34f2,0x6da910),
                         (0x5e372b,0x5a9020),(0x5e3ae9,0x6c7f50),(0x5e3b02,0x5e44c0),
                         (0x5e3f9e,0x5a9020),(0x5e4106,0x5e44c0)):
        direct(site,target)
    indirect(0x2bd19f,0x7e4b08,6,0,'__libc_start_main')
    indirect(0x4e4fcf,0x7e6ec0,8,0x684050)
    indirect(0x5e3513,0x7e57d8,8,0x6dab20)
    indirect(0x5e3627,0x7e4be0,8,0x49abb0)
    for site in (0x5e3589,0x5e370c,0x5e3f7f,0x5e3fdd,0x5e4061):
        indirect(site,0x7e4b68,6,0,'memcpy')
    relocation(0x7c3c08,8,0x4e4f80)
    relocation(0x7d6fd0,8,0x629f6)
    _, location = read(0x7d6fd0,24)
    length,line,column = struct.unpack_from('<QII',location,8)
    require((length,line,column) == (17,66,70), 'visor startup Location fields differ')
    require(read(0x629f6,length)[1] == b'node/src/utils.rs', 'startup Location path differs')
    require(read(0xb8342,43)[1] == b'called `Result::unwrap()` on an `Err` value', 'startup unwrap literal differs')

    branches = []
    for site, opcode, target in ((0x5e3521,'0f84',0x5e35f5),(0x5e35ab,'0f84',0x5e3648),
                                 (0x5e35b4,'75',0x5e3632),(0x5e364d,'0f85',0x5e3d0a),
                                 (0x5e36f4,'0f84',0x5e3f6d),(0x5e3af3,'74',0x5e3b07)):
        op = bytes.fromhex(opcode)
        size = 6 if len(op) == 2 else 2
        _,raw = read(site,size)
        displacement = struct.unpack_from('<i' if size == 6 else '<b',raw,len(op))[0]
        require(raw[:len(op)] == op and site + size + displacement == target,
                f'startup branch differs at {site:#x}')
        branches.append({'site':hex(site),'target':hex(target),**window(site,size)})

    _,fdes,_ = fde_extents(data)
    ranges = []
    for start,(end,expected) in RANGES.items():
        found = [f for f in fdes if f['start'] == start]
        require(len(found) == 1 and found[0]['end'] == end, f'startup FDE extent differs at {start:#x}')
        row = window(start,end-start)
        require(row['sha256'] == expected, f'startup FDE body differs at {start:#x}')
        ranges.append({**row,'end':hex(end),'fde_va':hex(found[0]['fde']),
                       'lsda_va':None if found[0]['lsda'] is None else hex(found[0]['lsda'])})
    endpoint = [f for f in fdes if f['start'] == 0x5e44c0]
    require(len(endpoint) == 1 and endpoint[0]['end'] == 0x5ea1c1, 'external poll endpoint FDE differs')
    return {'schema':1,'task':'RE-013','component':'visor','source_base':BASE,
            'target':{'bytes':len(data),'sha256':digest(data)},'coordinate_system':'linked ELF virtual addresses; no Ghidra rebasing',
            'entry':window(entry,0x26),'fde_ranges':ranges,'instruction_controls':controls,
            'selected_calls':edges,'selected_branches':branches,'relocations':relocation_rows,
            'startup_location':{'record':window(0x7d6fd0,24),'path':window(0x629f6,length),'line':line,'column':column},
            'unwrap_literal':window(0xb8342,43),
            'external_poll_endpoint':{'start':'0x5e44c0','end':'0x5ea1c1','attribution':'PR #45 c8c98b76ccf883fa4aa7aca9c4a4ccc8a8e00692; semantics excluded'},
            'coverage':{'fde_ranges':len(ranges),'instruction_control_windows':len(controls),
                        'selected_call_sites':len(edges),'selected_branch_sites':len(branches),
                        'complete_cfg_or_call_census':False},
            'limits':['FDEs are unwind-described ranges, not proof of original Rust function boundaries.',
                      'Selected byte/relocation/branch facts only; no complete CFG, path reachability or helper semantics proof.',
                      'No captured execution, networking, Ghidra analysis, source reconstruction, body comparison or accepted component gate.']}


def build(data):
    require(len(data) == SIZE and digest(data) == SHA256, 'captured visor size/SHA256 differs')
    return _derive(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.binary.read_bytes())
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'SCOPED_STATIC_STARTUP_PASS','target_sha256':SHA256,
                      'coverage':result['coverage'],'captured_binary_executed':False}))


if __name__ == '__main__':
    main()
