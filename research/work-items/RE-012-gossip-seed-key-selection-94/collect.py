#!/usr/bin/env python3
"""Static node94 selector-to-20-byte-input evidence; no target execution."""
import hashlib
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BASE = 'e5c9b6436876b2a4a39daef813171f9879317699'
LLVM = '/Library/Developer/CommandLineTools/usr/bin/'
RANGES = [(0x4743490, 0x4744152), (0x4941fe0, 0x4942203)]
TABLE = 0x6f9ac4
ARMS = {0: 0x4743ffb, 1: 0x47434db, 2: 0x474361a, 3: 0x474354e}
# Load site, matching pool record, tail-store site, direct call site.
GROUPS = {
    1: [(0x47434ed, 0x6fb559, 0x47434fe, 0x4743516),
        (0x474351b, 0x6fb56d, 0x474352c, 0x4743544)],
    2: [(0x474362c, 0x6fb581, 0x474363d, 0x4743655),
        (0x474365a, 0x6fb595, 0x474366b, 0x4743683)],
    3: [(0x4743560, 0x6fb5a9, 0x4743571, 0x4743589),
        (0x474358e, 0x6fb5bd, 0x474359f, 0x47435b7),
        (0x47435bc, 0x6fb5d1, 0x47435cd, 0x47435e5),
        (0x47435ea, 0x6fb5e5, 0x47435fb, 0x4743613)],
}
PINS = {
    'selector_byte': (0x47434c4, '0fb686f2080000'),
    'table_load': (0x47434cb, '488d0df265fbfb486304814801c8ffe0'),
    'group1_empty_root': (0x47434db, '48c74424100000000048c744242000000000'),
    'group2_empty_root': (0x474361a, '48c74424100000000048c744242000000000'),
    'group3_empty_root': (0x474354e, '48c74424100000000048c744242000000000'),
    'capture_root': (0x4743688, 'f30f6f442410660f7f842420010000488b4424204889842430010000'),
    'following_lookup_root': (0x47436a4, '498b8770380000'),
    'zero_arm_pointer_length': (0x4743ffb, '488d3d4075fbfb488d15d7acfe00be2f000000'),
    'helper_input': (0x4941ff1, '4989f6'),
    'helper_comparison_import': (0x494200d, '4c8b2d74c4e200'),
    'helper_comparison_width': (0x494204e, 'ba14000000'),
    'helper_comparison_call': (0x4942056, '41ffd5'),
    'helper_equal_exit': (0x4942074, '85c0742c'),
    'helper_duplicate_result': (0x49420a4, 'b001e913010000'),
    'helper_input20_load': (0x49420ae, '498b06498b4e08418b5610'),
    'helper_count_increment': (0x49421b8, '48ff461031c0'),
}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    data = (ROOT / 'artifacts/node/94/hl-node').read_bytes()
    check(len(data) == 91774280 and hashlib.sha256(data).hexdigest() == DIGEST, 'input identity')
    secs = sections(data)

    def offset(va, n):
        rows = [s for s in secs if s['type'] != 8 and s['address'] <= va and
                va+n <= s['address']+s['size']]
        check(len(rows) == 1, 'VA mapping')
        return rows[0]['offset'] + va-rows[0]['address']

    def raw(va, n):
        o = offset(va, n)
        return data[o:o+n]

    expected_keys = {}
    # Source-record identities are independently retained, not inferred labels.
    for entries in GROUPS.values():
        for _, pool, _, _ in entries:
            expected_keys[pool] = raw(pool, 20).hex()

    def validate(reader):
        for name, (va, hx) in PINS.items():
            check(reader(va, len(bytes.fromhex(hx))).hex() == hx, name)
        for tag, arm in ARMS.items():
            check(TABLE + struct.unpack('<i', reader(TABLE+4*tag, 4))[0] == arm, 'table tag '+str(tag))
        for entries in GROUPS.values():
            for load, pool, tail, call in entries:
                bs = reader(load, 8)
                check(bs[:4] == bytes.fromhex('f30f6f05') and
                      load+8+struct.unpack('<i', bs[4:])[0] == pool, 'pool load '+hex(load))
                bs = reader(tail, 11)
                check(bs[:7] == bytes.fromhex('c78424a0000000'), 'tail operand '+hex(tail))
                check(reader(pool, 16)+bs[7:] == bytes.fromhex(expected_keys[pool]), 'material '+hex(pool))
                # The source pool's adjacent tail bytes corroborate immediate material.
                check(reader(pool, 20).hex() == expected_keys[pool], 'pool bytes '+hex(pool))
                bs = reader(call, 5)
                check(bs[0] == 0xe8 and call+5+struct.unpack('<i', bs[1:])[0] == 0x4941fe0,
                      'call '+hex(call))
                # All eight setup sequences pass the same destination and scratch layout.
                setup = bytes.fromhex('488d7c2410488db42490000000')
                check(reader(call-len(setup), len(setup)) == setup, 'arguments '+hex(call))

    validate(raw)
    cies, fdes = eh_frame_records(data, secs)
    _, index = unwind_index(data)
    frame = next(s for s in secs if s['name'] == '.eh_frame')
    exports, range_records, decoded = {}, [], {}
    for start, end in RANGES:
        fs = [f for f in fdes if f['start'] == start]
        check(len(fs) == 1 and fs[0]['end'] == end, 'FDE range')
        f = fs[0]
        rows = [i for i in index if i['start'] == start]
        check(len(rows) == 1 and rows[0]['fde'] == f['fde'], 'FDE index')
        cmd = [LLVM+'llvm-objdump', '-d', '--x86-asm-syntax=intel',
               '--start-address='+hex(start), '--stop-address='+hex(end), 'artifacts/node/94/hl-node']
        text = subprocess.check_output(cmd, cwd=str(ROOT), text=True)
        cursor, count = start, 0
        for line in text.splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$', line)
            if m:
                va, bs = int(m[1], 16), bytes.fromhex(m[2])
                check(va == cursor and raw(va,len(bs)) == bs and '<unknown>' not in m[3], 'LLVM gap/byte/unknown')
                cursor += len(bs)
                decoded[va] = (bs, m[3].strip())
                count += 1
        check(cursor == end, 'LLVM range end')
        exports[hex(start)[2:]+'.llvm.txt'] = ' '.join(cmd)+'\n'+text.rstrip('\n')+'\n'
        dcmd = [LLVM+'llvm-dwarfdump', '--eh-frame='+hex(f['fde']-frame['address']), 'artifacts/node/94/hl-node']
        dtext = subprocess.check_output(dcmd, cwd=str(ROOT), text=True)
        check('pc='+format(start,'08x')+'...'+format(end,'08x') in dtext, 'LLVM FDE')
        exports[hex(start)[2:]+'.fde.llvm.txt'] = ' '.join(dcmd)+'\n'+dtext.rstrip('\n')+'\n'
        range_records.append({**{k:hex(v) if isinstance(v,int) else v for k,v in f.items()},
                              'code_sha256': hashlib.sha256(raw(start,end-start)).hexdigest(),
                              'bytes':end-start,'instruction_rows':count,'file_offset':hex(offset(start,1))})
    for va,_ in PINS.values():
        check(va in decoded, 'pin boundary')
    for entries in GROUPS.values():
        for load,pool,tail,call in entries:
            check(all(v in decoded for v in (load,tail,call)), 'construction boundary')
    check(all(ARMS[t] in decoded for t in ARMS), 'table arm boundary')

    # Resolve the imported comparison slot as data, without dynamic loading.
    symtab = next(s for s in secs if s['name'] == '.dynsym')
    strtab = next(s for s in secs if s['name'] == '.dynstr')
    comparison_import = []
    for sec in secs:
        if sec['name'] not in ('.rela.dyn', '.rela.plt'):
            continue
        for o in range(sec['offset'],sec['offset']+sec['size'],24):
            target,info,addend = struct.unpack_from('<QQq',data,o)
            if target != 0x576e488:
                continue
            so=symtab['offset']+(info>>32)*24
            check(so+24<=symtab['offset']+symtab['size'], 'dynamic symbol range')
            name_offset=struct.unpack_from('<I',data,so)[0]
            no=strtab['offset']+name_offset
            check(strtab['offset']<=no<strtab['offset']+strtab['size'], 'dynamic string range')
            nul=data.find(bytes(1),no,strtab['offset']+strtab['size'])
            check(nul>=no, 'unterminated dynamic symbol')
            comparison_import.append({'slot_va':hex(target),'relocation_file_offset':hex(o),
                'relocation_hex':data[o:o+24].hex(),'type':info&0xffffffff,'symbol_index':info>>32,
                'symbol_record_hex':data[so:so+24].hex(),'symbol_name':data[no:nul].decode('ascii')})
    check(len(comparison_import)==1 and comparison_import[0]['type']==6 and
          comparison_import[0]['symbol_name']=='memcmp','comparison import identity')

    controls = []
    mutations = [('selector-field', 0x47434c7), ('table-tag1', TABLE+4),
                 ('pool-load-displacement',0x47434f1), ('tail-value',0x4743505),
                 ('pool-material',0x6fb559), ('call-displacement',0x4743517),
                 ('helper-width',0x494204f), ('helper-equality-edge',0x4942077)]
    for label, at in mutations:
        def changed(va,n):
            block=bytearray(raw(va,n))
            if va <= at < va+n:
                block[at-va] ^= 1
            return bytes(block)
        try:
            validate(changed)
        except ValueError as error:
            controls.append({'name':label,'mutated_va':hex(at),'result':'rejected','obligation':str(error)})
        else:
            raise ValueError('unrejected mutation '+label)

    groups=[]
    for tag, entries in GROUPS.items():
        groups.append({'selector':tag,'arm_va':hex(ARMS[tag]),'inputs':[
            {'load_va':hex(load),'pool_va':hex(pool),'pool_file_offset':hex(offset(pool,20)),
             'tail_store_va':hex(tail),'call_va':hex(call),'material_hex':expected_keys[pool],
             'tail_immediate_hex':raw(tail+7,4).hex()} for load,pool,tail,call in entries]})
    rec={'task':'RE-012','component':'node-runtime','target_sha256':DIGEST,'target_size':len(data),
         'source_base':BASE,'reference_gitlink':'999556f6e0a474b8312db96ec3149e1c44e97c23',
         'coordinates':'linked ELF virtual addresses; ends exclusive; file offsets mapped from sections',
         'selector_field':'input RSI + 0x8f2 (unvalidated raw byte; no local upper-bound check)',
         'table':{'va':hex(TABLE),'raw_first_four_entries_hex':raw(TABLE,16).hex(),
                  'entries':{str(k):hex(v) for k,v in ARMS.items()},
                  'adjacent_word_probes':[{'word_va':hex(TABLE+4*k), 'raw_hex':raw(TABLE+4*k,4).hex(),
                      'relative_destination':hex(TABLE+struct.unpack('<i',raw(TABLE+4*k,4))[0]),
                      'destination_in_owner':0x4743490<=TABLE+struct.unpack('<i',raw(TABLE+4*k,4))[0]<0x4744152}
                      for k in (4,5)],
                  'limits':'Only observed selector values 0..3 interpreted; table extent and valid input domain not inferred'},
         'range_records':range_records,'groups':groups,
         'helper_comparison_import':comparison_import[0],
         'zero_arm':{'va':'0x4743ffb','pointer':'0x6fb542','length_operand':47,
                     'raw_47_bytes_hex':raw(0x6fb542,47).hex(),
                     'call_slot':'0x576e098','following':'UD2 at 0x4744014; helper behavior not established'},
         'pins':{name:{'va':hex(va),'raw_hex':hx} for name,(va,hx) in PINS.items()},
         'negative_controls':controls,'python':platform.python_version(),
         'platform':platform.system()+' '+platform.machine(),
         'LLVM_version':subprocess.check_output([LLVM+'llvm-objdump','--version'],text=True).splitlines()[0],
         'parser_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in ('tools/elf_index.py','tools/fde_extents.py')},
         'limits':['No target execution or instruction evaluator','No Rust, byte equivalence, gate or full peer-selection claim',
                   'Opaque helpers and transitive aliases remain outside the claim','Identifier type, chain names and external usage unknown']}
    for name,text in exports.items():
        (HERE/name).write_text(text)
    (HERE/'records.json').write_text(json.dumps(rec,indent=2)+'\n')
    print('PASS: node94 identity; 2 FDE/index/LLVM bounds; complete contiguous decodes; selector 0..3; 8 material constructions; 8 rejected corruptions')


if __name__ == '__main__':
    main()
