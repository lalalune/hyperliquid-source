#!/usr/bin/env python3
"""RE-013: static visor argument-name declarations and raw extraction fields."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT/'artifacts/visor/captured/hl-visor'
TARGET_SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
TARGET_SIZE = 8305392
RANGES = {
    0x5b5690:(0x5b5e1a,'04a36a111a23badd142339bbd4055e7d5857974fe90ca236bc2c8d6db63134da'),
    0x5b9070:(0x5b92a6,'435669a288a33a454f60952365691988fce6d144c4bc095fe4c39e260af0d4a4'),
}
CONTROLS = {
    0x5b5996:'488d052919b0ff48898424e001000048c78424e80100000d00000048c78424f00100000000000048c784240002000000000000c784241002000004040000488984243002000048c78424380200000d000000',
    0x5b5c5f:'488d056d16b0ff488984248006000048c78424880600000a00000048c78424900600000000000048c78424a006000000000000c78424b006000026040000',
    0x5b907d:'4889fbbf11000000',
    0x5b9094:'f30f6f0519e2affff30f7f00c640107248c744241811000000488944242048c744242811000000',
    0x5b90f6:'488d35c9e1afffba0d0000004c89f7e816a1010089c5',
    0x5b910c:'4883bc2498020000000f84d3000000488dbc24a0020000488d35a9e1afffba0a000000e82cd60600',
    0x5b9163:'48bf6368696c642d6172',
    0x5b9199:'4a837cc9c00a751f4e8d0cc94d8b51b84d8b1a4931fb450fb752084981f2677300004d09da744a',
    0x5b91d0:'660f74d166440fd7c24585c075104801f04883c0104883c610e97fffffff',
    0x5b91ee:'48c704240000000048c74424080800000048c744241000000000eb33',
    0x5b920a:'498b41e8498b49f0488d0c49488d0cc8488944241848894c2420488b0575d8220048894424284889e7488d742418e8d3470600',
    0x5b923d:'40886b18488b0424488903488b44240848894308488b44241048894310',
}


def require(value,message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _derive(data):
    """Private byte-corruption seam; public build additionally pins the artifact."""
    secs = sections(data)

    def read(va,n):
        rows = [s for s in secs if s['type'] != 8 and s['address'] <= va
                and va+n <= s['address']+s['size']]
        require(len(rows)==1,f'CLI span not uniquely file-backed: {va:#x}')
        offset = rows[0]['offset']+va-rows[0]['address']
        return offset,data[offset:offset+n]

    def window(va,n):
        offset,raw = read(va,n)
        return {'va':hex(va),'file_offset':offset,'bytes':n,'hex':raw.hex(),'sha256':sha(raw)}

    controls = []
    for va,encoded in CONTROLS.items():
        raw = bytes.fromhex(encoded)
        require(read(va,len(raw))[1] == raw,f'CLI instruction control differs at {va:#x}')
        controls.append(window(va,len(raw)))

    literals = []
    for va,value in ((0xb72b5,b'hyperliquid-visor'),(0xb72c6,b'skip-download'),(0xb72d3,b'child-args')):
        require(read(va,len(value))[1] == value,f'CLI literal differs at {va:#x}')
        literals.append({'text':value.decode('ascii'),**window(va,len(value))})

    settings = []
    for site,slot,expected in ((0x5b59c9,0x210,0x404),(0x5b5c92,0x6b0,0x426)):
        _,raw = read(site,11)
        require(raw[:3] == b'\xc7\x84\x24',f'CLI setting store opcode differs at {site:#x}')
        offset,value = struct.unpack_from('<iI',raw,3)
        require((offset,value) == (slot,expected),f'CLI numeric setting differs at {site:#x}')
        settings.append({'site':hex(site),'stack_displacement':offset,'value':value,'value_hex':hex(value)})

    references = []
    for site,register,target in ((0x5b5996,'rax',0xb72c6),(0x5b5c5f,'rax',0xb72d3),
                                  (0x5b90f6,'rsi',0xb72c6),(0x5b9123,'rsi',0xb72d3)):
        _,raw = read(site,7)
        opcode = b'\x48\x8d\x05' if register=='rax' else b'\x48\x8d\x35'
        require(raw[:3] == opcode and site+7+struct.unpack_from('<i',raw,3)[0] == target,
                f'CLI name reference differs at {site:#x}')
        references.append({'site':hex(site),'register':register,'target':hex(target),**window(site,7)})
    name_lengths = []
    for site,expected in ((0x5b90fd,13),(0x5b912a,10)):
        _,raw = read(site,5)
        require(raw[0] == 0xba,'CLI name-length opcode differs')
        length = struct.unpack_from('<I',raw,1)[0]
        require(length == expected,'CLI name-length operand differs')
        name_lengths.append({'site':hex(site),'register':'edx','length':length})
    fallback_sites = ((0x5b91ee,4),(0x5b91f6,5),(0x5b91ff,5))
    fallback = [struct.unpack_from('<i',read(site+skip,4)[1])[0] for site,skip in fallback_sites]
    require(fallback == [0,8,0],'CLI fallback words differ')
    prefix = read(0x5b9165,8)[1]
    tail = struct.unpack('<I',read(0x5b91b7,4)[1])[0]
    key = prefix + tail.to_bytes(4,'little')[:2]
    require(key == b'child-args' and tail < 65536,'CLI inline key equality constants differ')

    relsec = next(s for s in secs if s['name']=='.rela.dyn')
    require(relsec['size']%24 == 0,'CLI RELA table stride differs')
    relocations = {}
    for offset in range(relsec['offset'],relsec['offset']+relsec['size'],24):
        slot,info,addend = struct.unpack_from('<QQq',data,offset)
        require(slot not in relocations,'duplicate CLI relocation slot')
        relocations[slot] = {'slot':hex(slot),'file_offset':offset,'type':info&0xffffffff,
                             'symbol_index':info>>32,'addend':hex(addend)}
    selected_relocations = []
    calls = []
    for site,slot,target in ((0x5b90cb,0x7e6950,0x455340),(0x5b90dc,0x7e76e0,0x5b5690),
                             (0x5b90f0,0x7e69f0,0x478c40)):
        _,raw = read(site,6)
        require(raw[:2] == b'\xff\x15' and site+6+struct.unpack_from('<i',raw,2)[0] == slot,
                f'CLI indirect call differs at {site:#x}')
        r = relocations.get(slot)
        require(r is not None and (r['type'],r['symbol_index'],r['addend']) == (8,0,hex(target)),
                f'CLI relocation differs at {slot:#x}')
        selected_relocations.append(r)
        calls.append({'site':hex(site),'kind':'RIP-relative slot','slot':hex(slot),'target':hex(target)})
    callback = relocations.get(0x7e6aa0)
    require(callback is not None and (callback['type'],callback['symbol_index'],callback['addend']) == (8,0,'0x48dc00'),
            'CLI collection callback relocation differs')
    selected_relocations.append(callback)
    for site,target in ((0x5b9105,0x5d3220),(0x5b912f,0x626760),(0x5b9238,0x61da10)):
        _,raw = read(site,5)
        require(raw[0] == 0xe8 and site+5+struct.unpack_from('<i',raw,1)[0] == target,
                f'CLI direct call differs at {site:#x}')
        calls.append({'site':hex(site),'kind':'rel32','target':hex(target)})

    branches = []
    for site,opcode,target in ((0x5b9115,'0f84',0x5b91ee),(0x5b919f,'75',0x5b91c0),
                                (0x5b91be,'74',0x5b920a),(0x5b91dc,'75',0x5b91ee),
                                (0x5b9208,'eb',0x5b923d)):
        op = bytes.fromhex(opcode)
        n = 6 if len(op)==2 else 2
        _,raw = read(site,n)
        delta = struct.unpack_from('<i' if n==6 else '<b',raw,len(op))[0]
        require(raw[:len(op)] == op and site+n+delta == target,f'CLI branch differs at {site:#x}')
        branches.append({'site':hex(site),'target':hex(target),**window(site,n)})

    _,fdes,_ = fde_extents(data)
    ranges = []
    for start,(end,expected) in RANGES.items():
        fs = [f for f in fdes if f['start']==start]
        require(len(fs)==1 and fs[0]['end']==end,f'CLI FDE extent differs at {start:#x}')
        w = window(start,end-start)
        require(w['sha256']==expected,f'CLI FDE body differs at {start:#x}')
        ranges.append({**w,'end':hex(end),'fde_va':hex(fs[0]['fde'])})
    return {'schema':1,'task':'RE-013','component':'visor','target':{'bytes':len(data),'sha256':sha(data)},
            'coordinates':'linked ELF virtual addresses; file offsets also supplied',
            'fde_ranges':ranges,'controls':controls,'literals':literals,'numeric_builder_settings':settings,
            'name_references':references,'lookup_name_lengths':name_lengths,
            'inline_child_key_equality':{'prefix_imm64_bytes':prefix.hex(),'tail_imm32':tail,
                                          'compared_key_bytes':key.hex(),'length_operand':10,
                                          'equality_branch_site':'0x5b91be','target':'0x5b920a'},
            'selected_calls':calls,'relocations':selected_relocations,
            'selected_branches':branches,
            'observed_fallback_words':{'store_sites':[hex(site) for site,_ in fallback_sites],
                                       'stack_offsets':[0,8,16],'words':fallback},
            'observed_output_stores':{'base_register':'rbx copied from incoming rdi at0x5b907d',
                                     'byte_at_offset24':'low byte of lookup return EAX, saved in EBP at0x5b910a',
                                     'word_offsets':[0,8,16],'source_stack_offsets':[0,8,16],
                                     'complete_layout_or_Rust_type_proved':False},
            'coverage':{'FDE_ranges':len(ranges),'selected_control_windows':len(controls),
                        'name_references':len(references),'selected_calls':len(calls),'selected_branches':len(branches),
                        'full_CFG_or_parser_behavior':False},
            'limits':['Numeric settings0x404/0x426 are observed operands, not recovered parser policy names.',
                      'Raw fallback/output words do not establish a private Vec/struct layout or accepted syntax.',
                      'Generic parsing, lookup/hash and collection helper contracts remain external.',
                      'Normal-return def-use interpretation assumes ABI callee-saved registers are preserved; not runtime checked.',
                      'No captured execution, lifecycle consumption/effects, Rust reconstruction or accepted gate.']}


def build(data):
    require(len(data)==TARGET_SIZE and sha(data)==TARGET_SHA256,'captured visor identity differs')
    return _derive(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = build(args.binary.read_bytes())
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'SCOPED_STATIC_CLI_FIELDS_PASS','coverage':result['coverage'],
                      'captured_binary_executed':False}))
