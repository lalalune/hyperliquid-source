#!/usr/bin/env python3
"""Extract the node 94 app-hash quorum tracker snapshot path from ELF bytes."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# Selected whole unwind extents, not inferred full control-flow boundaries.
BODIES = {
    0x1ddc5b0: 'f8e94c5fb1e4279655497c2705eaecf6e26ab6bb527448caffabea62abf6cc38',
    0x1e10640: '2c910ef07be7162eb4d28f02db7f414b9ae5e0bf7c11dc43b5136d08cb4bfb3c',
    0x1eac430: '12d4abaeb8004463b77da48fa229dcbc2d07776242db4484d57ed6fe36fc797e',
    0x16a9410: '6fabf2dac213ce260f8aba65c2db8492f9971307736724acf5fbf215bd0e2b20',
    0x1a3ec40: '1c79067b1b415fa243cc58dd54a82684fd9555b8d33f8a80a280f4af107d6bac',
    0x24d94f0: 'b709565b1c1645fb03772f4a060d77a43e90c4c863262f056114879a261a3a73',
    0x1978910: 'a7b92898701aa582482b41547571a9d058650108a4fd37be828afcdab5dd4011',
    0x1eaa210: '071f297c61eb9411fa0cbe05ffcfd7685cd7d614617d5245142a23fa8c88b85c',
    0x2326d20: '3ecb4367be12efcd0a359b68b9adff7566a7656bd81e35bf32e8a5d8ba1ee98e',
    0x1e31c90: '80c8d1431ec2c02057f1e555d266a5011afd08bde766c08936343b33a4d2fa04',
    0x1dd1f90: 'a8d7bd2a76dccaeb7d3e6e3b061e429f89b9ff62fcc178517a843d4f3a4584b1',
    0x1ea9da0: '53e7d8e30710e385c25d8bd3ff4a7dd50287ed49220e75f9a82e01e5a29c6ec0',
    0x25ddba0: '77518ad1c163c080bd319818c1d42a449a24e013a37f5311d8d9e65117729d27',
    0x25de780: '243ff3556124d3a4dcfb758633643957837193b9a0425c77519e9bb33d24821f',
    0x1e2af60: '1dcb8706f3995c2f3d894a3188840ac38f25fe32958dbaf3602599a63ef500cd',
    0x17ea910: '97b869af39220af6c42c81131b2ac71d350f8cea0aa9bb00b72fa5e0c3078af9',
    0x188d500: '32a5b452d359b40573bba59daef391d90abca857160c201b443cb77ce1872968',
    0x16d1b50: 'd2eb1d74fd1df6cc4789ac987fe255329d19da3d32c7cee7c6bae673eaf192cb',
}
CALLS = [
 ('hash_capture_context',0x281b070,0x1eaa210),
 ('outer_map_header',0x1eaa243,0x25a8f80),('outer_array_header',0x1eaa275,0x25a9bd0),
 ('outer_tracker',0x1eaa2b5,0x2326d20),('outer_rows',0x1eaa2f7,0x1e31c90),
 ('outer_height',0x1eaa333,0x25ac0d0),
 ('tracker_map_header',0x2326d52,0x25a8f80),('tracker_array_header',0x2326d81,0x25a9bd0),
 ('tracker_name_value',0x2326dc6,0x25aa7f0),('tracker_hsc_empty_array',0x2326dfa,0x25a9bd0),
 ('tracker_i',0x2326e37,0x25ddba0),('tracker_i_collect',0x25ddc0a,0x25718a0),
 ('tracker_i_sequence',0x25ddc18,0x1e4b530),
 ('rows_header',0x1e31cf7,0x25a9bd0),('rows_first',0x1e31d4a,0x1dd1f90),
 ('rows_loop',0x1e31e79,0x1dd1f90),('row_pair_header',0x1dd1ff0,0x25a9bd0),
 ('row_height',0x1dd2049,0x1e103c0),('row_quorum',0x1dd211a,0x1ea9da0),
 ('row_height_alternate',0x1dd218f,0x1e10b70),
 ('quorum_map_header',0x1ea9dcf,0x25a8f80),('quorum_array_header',0x1ea9dfe,0x25a9bd0),
 ('quorum_hash_string',0x1ea9e6e,0x25aa7f0),('quorum_signature_map',0x1ea9ea7,0x25de780),
 ('signature_collect',0x25de7ea,0x2574300),('signature_sequence',0x25de7f8,0x1e2af60),
 ('signature_sequence_header',0x1e2afc7,0x25a9bd0),('signature_first',0x1e2b01f,0x1ddc5b0),
 ('signature_loop',0x1e2b14e,0x1ddc5b0),
 ('signature_pair_header',0x1ddc634,0x25a9bd0),('signature_pair_key',0x1ddc679,0x1e0d0a0),
 ('signature_pair_value',0x1ddc692,0x1e10640),('signature_value_adapter',0x1e10714,0x1eac430),
 ('signature_map_header',0x1eac463,0x25a8f80),('signature_array_header',0x1eac495,0x25a9bd0),
 ('signature_r_value',0x1eac4d5,0x219b770),('signature_s_value',0x1eac517,0x219b770),
 ('signature_v_value',0x1eac554,0x25ac0d0),
 ('reader_seq_first',0x17eaedd,0x16a9410),('reader_seq_second',0x17eafc5,0x1a3ec40),
 ('reader_seq_third',0x17eb093,0x16844a0),('reader_seq_length_error0',0x17eb227,0x1703e70),
 ('reader_seq_length_error1',0x17eaf97,0x1703e70),('reader_seq_length_error2',0x17eb023,0x1703e70),
 ('reader_seq_extra',0x17eb53e,0x16f26e0),('reader_key_classifier_a',0x17ec285,0x16d1b50),
 ('reader_key_classifier_b',0x17ec442,0x16d1b50),('reader_map_first',0x17ec619,0x16a9410),
 ('reader_map_second',0x17ec770,0x1a3ec40),('reader_map_third',0x17ec6e8,0x16844a0),
 ('reader_map_unknown',0x17ec72f,0x19682d0),
 ('nested_key_adapter',0x16a9af6,0x16f9d10),('nested_unknown',0x16a9b24,0x19682d0),
 ('nested_name_value',0x16a9b66,0x19822a0),('nested_hsc_value',0x16a9bbc,0x168f570),
 ('nested_i_value',0x16a9d3c,0x18e4250),
 ('rows_reader_sequence_visitor',0x1a3f120,0x24d94f0),
 ('rows_reader_item',0x24d95c0,0x1978910),('row_reader_height',0x1978e5c,0x16844a0),
 ('row_reader_quorum',0x1978e8e,0x188d500),
]
BRANCHES = [
 ('outer_mode_zero',0x1eaa234),('outer_map_header_ok',0x1eaa251),('outer_array_header_error',0x1eaa283),
 ('outer_tracker_name_bypass',0x1eaa28a),('outer_tracker_name_error',0x1eaa2a4),('outer_tracker_value_error',0x1eaa2c4),
 ('outer_rows_name_bypass',0x1eaa2cf),('outer_rows_name_error',0x1eaa2e9),('outer_rows_error',0x1eaa301),
 ('outer_height_name_bypass',0x1eaa30c),('outer_height_name_error',0x1eaa326),('outer_height_error',0x1eaa341),
 ('tracker_mode_zero',0x2326d45),('tracker_hsc_name_bypass',0x2326dd6),('tracker_empty_header_error',0x2326e07),
 ('rows_header_error',0x1e31d05),('rows_first_success',0x1e31d65),('rows_end',0x1e31e4b),
 ('rows_loop_error',0x1e31e86),('rows_loop_next',0x1e31e93),
 ('row_header_error',0x1dd1ffe),('row_height_error',0x1dd2057),('row_value_error',0x1dd2124),
 ('quorum_mode_zero',0x1ea9dc2),('quorum_hash_name_bypass',0x1ea9e12),('quorum_hash_error',0x1ea9e77),
 ('quorum_signatures_name_bypass',0x1ea9e7e),('quorum_signatures_error',0x1ea9eb4),
 ('reader_seq_zero',0x17eaec3),('reader_seq_one',0x17eaf7d),('reader_seq_two',0x17eb005),
 ('reader_seq_three',0x17eb194),('reader_map_first_duplicate',0x17ec5fc),
 ('reader_map_second_duplicate',0x17ec75d),('reader_map_third_duplicate',0x17ec6d7),
 ('reader_map_first_present',0x17eb8d7),('reader_map_second_present',0x17eb94a),
 ('reader_map_third_present',0x17eba0c),
 ('signature_pair_header_error',0x1ddc642),('signature_key_error',0x1ddc683),
 ('signature_value_error',0x1ddc69c),('signature_adapter_header_error',0x1e10695),
 ('signature_adapter_byte_error',0x1e106d9),('signature_adapter_byte_loop',0x1e106e1),
 ('signature_struct_mode_zero',0x1eac454),('signature_r_name_error',0x1eac4c4),
 ('signature_r_error',0x1eac4e4),('signature_s_name_error',0x1eac509),
 ('signature_s_error',0x1eac521),('signature_v_name_error',0x1eac547),
 ('signature_v_error',0x1eac562),
 ('nested_unknown_selector',0x16a9b12),('nested_name_duplicate',0x16a9b50),('nested_hsc_duplicate',0x16a9bab),
 ('rows_capacity_zero',0x24d9519),('rows_allocation_failure',0x24d9535),
 ('rows_input_exhausted',0x24d95ae),('rows_item_error',0x24d95cd),('rows_spare_capacity',0x24d9619),
 ('row_first_absent',0x1978e4b),('row_second_absent',0x1978e70),('row_quorum_success',0x1978e9b),('row_exact_two',0x197902b),
 ('quorum_hash_missing',0x188d8c8),('quorum_signatures_present',0x188e4e5),
 ('quorum_signatures_duplicate',0x188f36f),('quorum_hash_duplicate',0x188f5b8),
]
# Bounded windows were selected from a human instruction review; offsets are fixed.
WINDOWS = [
 ('hash_context',0x281b04c,0x281b075),('outer_writer',0x1eaa230,0x1eaa343),
 ('nested_tracker_writer',0x2326d41,0x2326e46),('rows_header_first',0x1e31ca9,0x1e31d6b),
 ('rows_loop',0x1e31e41,0x1e31e95),('row_pair_header',0x1dd1fe3,0x1dd205d),
 ('row_quorum_call',0x1dd2109,0x1dd212a),('quorum_writer',0x1ea9dbe,0x1ea9eb6),
 ('signature_map_wrapper',0x25de78f,0x25de7fd),('signature_sequence_loop',0x1e2b113,0x1e2b16a),
 ('signature_pair',0x1ddc624,0x1ddc6ad),('signature_value_adapter',0x1e1064e,0x1e10719),
 ('signature_struct',0x1eac450,0x1eac564),('key_classifier',0x16d1b50,0x16d1ced),
 ('seq_length0',0x17eaeb7,0x17eaedd),('seq_length1',0x17eaf7a,0x17eafca),
 ('seq_length2',0x17eb002,0x17eb098),('seq_length3',0x17eb191,0x17eb19a),
 ('seq_extra_error',0x17eb51b,0x17eb543),('map_dispatch',0x17ec5c5,0x17ec602),
 ('map_first',0x17ec5ea,0x17ec61e),('map_second',0x17ec74e,0x17ec775),
 ('map_third',0x17ec6ce,0x17ec6ed),('map_unknown',0x17ec71f,0x17ec734),
 ('missing_first_check',0x17eb8c8,0x17eb8e3),('missing_first',0x17ead39,0x17ead91),('missing_second',0x17eb947,0x17eb9ae),
 ('missing_third',0x17eba04,0x17eba69),('duplicate_second',0x17eca76,0x17ecae5),
 ('duplicate_third',0x17ecaea,0x17ecb59),('duplicate_first',0x17ecb5b,0x17ecbca),
 ('nested_tracker_dispatch',0x16a9af0,0x16a9bb1),('nested_tracker_value',0x16a9bb1,0x16a9bdf),
 ('nested_tracker_i',0x16a9d2d,0x16a9d50),('nested_after_i_dispatch',0x16a9d7f,0x16a9dda),
 ('nested_i_duplicate',0x16aa7b7,0x16aa85d),('rows_decode_capacity',0x24d9506,0x24d953b),
 ('rows_decode_loop',0x24d9558,0x24d95d3),('rows_decode_growth',0x24d9610,0x24d962d),
 ('row_decode_children',0x1978e46,0x1978ea1),('row_decode_exact_two',0x1979028,0x197902d),('tracker_type_ref',0x17eb217,0x17eb22c),('quorum_type_ref',0x188e1f2,0x188e207),
 ('quorum_missing_hash',0x188d93d,0x188d993),('quorum_missing_signatures',0x188e4cf,0x188e541),
 ('quorum_duplicate_signatures',0x188fa5d,0x188fad2),('quorum_duplicate_hash',0x188fad2,0x188fb4d),
]
FIELDS = [
 ('outer',0,0x1eaa28c,'tracker',0,'child'),
 ('outer',1,0x1eaa2d1,'quorum_app_hashes',0x30,'collection'),
 ('outer',2,0x1eaa30e,'highest_quorum_height',0x48,'qword'),
 ('tracker',0,0x2326d9f,'name',0x08,'pointer and length at +0x10'),
 ('tracker',1,0x2326dd8,'hsc',None,'empty sequence header'),
 ('tracker',2,0x2326e10,'i',0x18,'collection'),
 ('quorum',0,0x1ea9e14,'app_hash',0,'32-byte formatter input'),
 ('quorum',1,0x1ea9e80,'hot_user_to_signature',0x20,'collection'),
 ('signature',0,0x1eac4ac,'r',0,'child'),
 ('signature',1,0x1eac4f1,'s',0x20,'child'),
 ('signature',2,0x1eac52f,'v',0x40,'byte to integer helper'),
]


def identity(data):
    digest = hashlib.sha256(data).hexdigest()
    if digest != TARGET:
        raise ValueError('node 94 SHA-256 mismatch')
    return digest


def read_va(data, secs, va, size):
    if va < 0 or size < 0:
        raise ValueError('negative address or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address lacks one file-backed section')
    section = matches[0]
    off = section['offset'] + va - section['address']
    if off + size > len(data):
        raise ValueError('file-backed address exceeds file')
    return data[off:off + size]


def call(data, secs, site):
    raw = read_va(data, secs, site, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def branch(data, secs, site):
    raw = read_va(data, secs, site, 2)
    if 0x70 <= raw[0] <= 0x7f:
        size, condition, delta = 2, raw[0] & 15, struct.unpack('<b', raw[1:])[0]
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        size, condition = 6, raw[1] & 15
        delta = struct.unpack_from('<i', read_va(data, secs, site, size), 2)[0]
    else:
        raise ValueError('expected conditional jump')
    return {'site':hex(site), 'bytes':read_va(data,secs,site,size).hex(),
            'condition':condition, 'target':hex(site+size+delta), 'fallthrough':hex(site+size)}


def rip(data, secs, site, prefix, size=7):
    raw = read_va(data, secs, site, size)
    if not raw.startswith(prefix):
        raise ValueError('unexpected relative instruction')
    return site + size + struct.unpack_from('<i', raw, size - 4)[0]


def relocations(data, secs):
    candidates = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('invalid relocation section')
    sec = candidates[0]
    result = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        dest, info, addend = struct.unpack_from('<QQq', data, off)
        if info == 8:
            if dest in result:
                raise ValueError('duplicate relative relocation')
            result[dest] = addend
    return result


def compare_rows(data, secs):
    """Read fixed byte comparisons and their failure branches from the FDE."""
    bounds = [(0x16d1b67,0x16d1bac,0),(0x16d1bb5,0x16d1c60,1),
              (0x16d1c65,0x16d1ce4,2)]
    rows = []
    for start, end, selector in bounds:
        raw = read_va(data, secs, start, end-start)
        for i in range(len(raw)-4):
            if raw[i:i+2] == b'\x80\x3e':
                offset, value, width = 0, raw[i+2], 3
            elif raw[i:i+2] == b'\x80\x7e':
                offset, value, width = raw[i+2], raw[i+3], 4
            else:
                continue
            site = start+i
            test = branch(data, secs, site+width)
            last = selector == 2 and offset == 20
            if (test['condition'],test['target'],test['fallthrough']) != (
                (4,'0x16d1ce6','0x16d1ce4') if last else
                (5,'0x16d1ce4',hex(site+width+len(bytes.fromhex(test['bytes']))))):
                raise ValueError('classifier failure branch changed')
            rows.append({'selector':selector,'index':offset,'byte':value,'site':hex(site),
                         'compare_bytes':read_va(data,secs,site,width).hex(),'branch':test})
    keys = []
    for selector, length in enumerate((7,17,21)):
        subset = [x for x in rows if x['selector'] == selector]
        if [x['index'] for x in subset] != list(range(length)):
            raise ValueError('classifier does not cover each byte once')
        keys.append(bytes(x['byte'] for x in subset))
    # Length dispatch and selector returns are separately pinned.
    checks = [(0x16d1b50,'83fa15'),(0x16d1b59,'83fa11'),(0x16d1b5e,'83fa07'),
              (0x16d1bac,'31c0'),(0x16d1c54,'b001'),(0x16d1cdc,'b002'),
              (0x16d1ce4,'b003')]
    for site, expected in checks:
        if read_va(data,secs,site,len(bytes.fromhex(expected))).hex()!=expected:
            raise ValueError('classifier length or selector changed')
    return keys, rows


def classify(candidate, keys):
    for selector, key in enumerate(keys):
        if len(candidate) == len(key) and all(a == b for a,b in zip(candidate,key)):
            return selector
    return len(keys)


def reservation(count, cap, stride):
    if not 0 <= count <= 0xffffffff or cap < 0 or stride <= 0:
        raise ValueError('reservation input out of range')
    slots = min(count,cap)
    return slots, slots*stride


def extract(data, authenticate=True):
    if authenticate:
        identity(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    by_start = {f['start']:f for f in fdes if f['start'] in BODIES}
    indexed = {f['start']:f['fde'] for f in index}
    if set(by_start) != set(BODIES):
        raise ValueError('selected FDE missing')
    functions = []
    for start in sorted(BODIES):
        f = by_start[start]
        if indexed.get(start) != f['fde']:
            raise ValueError('unwind header and FDE disagree')
        body = read_va(data,secs,start,f['end']-start)
        digest = hashlib.sha256(body).hexdigest()
        if digest != BODIES[start]:
            raise ValueError('selected function bytes changed')
        functions.append({'start':hex(start),'end_exclusive':hex(f['end']),'fde':hex(f['fde']),
                          'size':len(body),'sha256':digest})
    calls=[]
    for role,site,expected in CALLS:
        dest=call(data,secs,site)
        if dest != expected:
            raise ValueError('unexpected call target')
        calls.append({'role':role,'site':hex(site),'bytes':read_va(data,secs,site,5).hex(),'target':hex(dest)})
    branches=[{'role':role,**branch(data,secs,site)} for role,site in BRANCHES]
    windows=[{'role':role,'start':hex(start),'end_exclusive':hex(end),
              'bytes':read_va(data,secs,start,end-start).hex()} for role,start,end in WINDOWS]
    keys, comparisons = compare_rows(data,secs)
    field_rows=[]
    # Addressing instructions determine offsets. A register-to-register move
    # denotes the base itself; the other selected instructions carry disp8.
    offset_instructions={
      ('outer',0):(0x1eaa2af,'4c89fe',False),('outer',1):(0x1eaa2eb,'498d57',True),
      ('outer',2):(0x1eaa303,'4d8b7f',True),('tracker',0):(0x2326d90,'4d8b67',True),
      ('tracker',2):(0x2326e2a,'4983c7',True),('quorum',0):(0x1ea9e5c,'4c89fa',False),
      ('quorum',1):(0x1ea9e9a,'4983c7',True),
      ('signature',0):(0x1eac4cf,'4c89fe',False),
      ('signature',1):(0x1eac50b,'498d77',True),('signature',2):(0x1eac523,'450fb67f',True),
    }
    for obj,order,site,name,offset,handoff in FIELDS:
        ptr=rip(data,secs,site,b'\x48\x8d\x35')
        op=read_va(data,secs,site+7,5)
        if op[0] != 0xba:
            raise ValueError('unexpected field length instruction')
        n=struct.unpack_from('<I',op,1)[0]
        if read_va(data,secs,ptr,n) != name.encode('ascii'):
            raise ValueError('writer field changed')
        offset_proof=None
        if offset is not None:
            offset_site,prefix,has_disp=offset_instructions[(obj,order)]
            opcode=bytes.fromhex(prefix)
            instruction=read_va(data,secs,offset_site,len(opcode)+int(has_disp))
            if not instruction.startswith(opcode):
                raise ValueError('field addressing instruction changed')
            actual_offset=instruction[-1] if has_disp else 0
            if actual_offset != offset:
                raise ValueError('field displacement changed')
            offset_proof={'site':hex(offset_site),'bytes':instruction.hex()}
        else:
            actual_offset=None
        field_rows.append({'object':obj,'order':order,'site':hex(site),'data':hex(ptr),'length':n,
                           'name':name,'input_offset':None if actual_offset is None else hex(actual_offset),
                           'handoff':handoff,'offset_proof':offset_proof})
    if [x.encode('ascii') for x in [f['name'] for f in field_rows[:3]]] != keys:
        raise ValueError('writer names and classifier disagree')
    # Map key jump table uses signed relative offsets from its table base.
    table_site=0x17ec5da
    table=rip(data,secs,table_site,b'\x48\x8d\x0d')
    offsets=struct.unpack('<iiii',read_va(data,secs,table,16))
    targets=[table+x for x in offsets]
    if targets != [0x17ec5ea,0x17ec74e,0x17ec6ce,0x17ec71f]:
        raise ValueError('map dispatch table changed')
    nested_site=0x16a9b3b
    nested_table=rip(data,secs,nested_site,b'\x48\x8d\x0d')
    nested_offsets=struct.unpack('<iii',read_va(data,secs,nested_table,12))
    nested_targets=[nested_table+x for x in nested_offsets]
    if nested_targets != [0x16a9b4b,0x16a9ba3,0x16a9d2d]:
        raise ValueError('nested tracker dispatch changed')
    nested_again_site=0x16a9dca
    nested_again_table=rip(data,secs,nested_again_site,b'\x48\x8d\x0d')
    nested_again_offsets=struct.unpack('<iii',read_va(data,secs,nested_again_table,12))
    nested_again_targets=[nested_again_table+x for x in nested_again_offsets]
    if nested_again_targets != [0x16a9dda,0x16a9e32,0x16aa7b7]:
        raise ValueError('nested after-i dispatch changed')
    cap_insn=read_va(data,secs,0x24d9509,6)
    stride_insn=read_va(data,secs,0x24d9525,4)
    if cap_insn[:2]!=bytes.fromhex('81fd') or stride_insn[:3]!=bytes.fromhex('41c1e7'):
        raise ValueError('reservation instruction changed')
    cap=struct.unpack_from('<I',cap_insn,2)[0]
    stride=1 << stride_insn[3]
    if (cap,stride)!=(0x4000,0x40):
        raise ValueError('reservation constant changed')
    rel=relocations(data,secs)
    indirect_calls=[]
    for role,site,slot,target in [('hash_format',0x1ea9e62,0x5773120,0x29ed380),
                                   ('rows_grow',0x24d9622,0x57744c8,0x32d6350)]:
        if rip(data,secs,site,b'\xff\x15',6)!=slot or rel.get(slot)!=target:
            raise ValueError('indirect-call relocation changed')
        indirect_calls.append({'role':role,'site':hex(site),'bytes':read_va(data,secs,site,6).hex(),
                               'slot':hex(slot),'target':hex(rel[slot])})
    descriptors=[]
    for label,site,slot,expected in [
      ('tracker',0x17eb217,0x5687798,b'struct AppHashVoteTracker with 3 elements'),
      ('quorum',0x188e1f2,0x56876a8,b'struct QuorumAppHash with 2 elements')]:
        if rip(data,secs,site,b'\x48\x8d\x15') != slot or slot not in rel:
            raise ValueError('type descriptor reference changed')
        length=struct.unpack('<Q',read_va(data,secs,slot+8,8))[0]
        text=read_va(data,secs,rel[slot],length)
        if text != expected:
            raise ValueError('type descriptor changed')
        descriptors.append({'role':label,'site':hex(site),'slot':hex(slot),'target':hex(rel[slot]),
                            'length':length,'text':text.decode('ascii')})
    diagnostics=[]
    for role,site,name in [('missing_tracker',0x17ead46,'tracker'),('missing_rows',0x17eb955,'quorum_app_hashes'),
      ('missing_height',0x17eba13,'highest_quorum_height'),('duplicate_tracker',0x17ecb77,'tracker'),
      ('duplicate_rows',0x17eca92,'quorum_app_hashes'),('duplicate_height',0x17ecb06,'highest_quorum_height'),
      ('nested_missing_name',0x16a9cae,'name'),('nested_duplicate_name',0x16aacee,'name'),
      ('nested_duplicate_hsc',0x16aac56,'hsc'),('nested_duplicate_i',0x16aa7f0,'i'),
      ('quorum_missing_hash',0x188d945,'app_hash'),('quorum_missing_signatures',0x188e4eb,'hot_user_to_signature'),
      ('quorum_duplicate_hash',0x188faf2,'app_hash'),('quorum_duplicate_signatures',0x188fa7d,'hot_user_to_signature')]:
        ptr=rip(data,secs,site,b'\x48\x8d\x05')
        if read_va(data,secs,ptr,len(name)) != name.encode('ascii'):
            raise ValueError('diagnostic field changed')
        diagnostics.append({'role':role,'site':hex(site),'target':hex(ptr),'name':name})
    for role,site,prefix in [('missing_template',0x17ead7d,b'\x0fmissing field'),
                              ('duplicate_template',0x17ecac6,b'\x11duplicate field')]:
        ptr=rip(data,secs,site,b'\x48\x8d\x35')
        if read_va(data,secs,ptr,len(prefix)) != prefix:
            raise ValueError('diagnostic template changed')
        diagnostics.append({'role':role,'site':hex(site),'target':hex(ptr),'prefix_hex':prefix.hex()})
    config=read_va(data,secs,0x281b055,8)
    if config[:4] != bytes.fromhex('c7442408') or config[4:] != bytes.fromhex('00040001'):
        raise ValueError('hash serializer configuration changed')
    # Pin the nonempty-stride, pair arity, zero-length hsc and 32-byte formatter inputs.
    anchors=[(0x1ddc62f,'ba02000000'),(0x1e2b161,'4883c510'),(0x2326d94,'4d8b6f10'),(0x1e31e8c,'4983c740'),(0x1dd1feb,'ba02000000'),(0x2326df8,'31d2'),
             (0x1ea9e52,'be42000000'),(0x1ea9e57,'b920000000')]
    for site,hexbytes in anchors:
        if read_va(data,secs,site,len(bytes.fromhex(hexbytes))).hex()!=hexbytes:
            raise ValueError('layout or constant instruction changed')
    return {'target_sha256':TARGET,'coordinate_system':'unrelocated ELF virtual address',
            'functions':functions,'calls':calls,'branches':branches,'windows':windows,
            'fields':field_rows,'comparisons':comparisons,'descriptors':descriptors,
            'diagnostics':diagnostics,'indirect_calls':indirect_calls,'dispatch':{'site':hex(table_site),'table':hex(table),
                'offset_bytes':read_va(data,secs,table,16).hex(),'targets':[hex(x) for x in targets]},
            'nested_dispatch':{'site':hex(nested_site),'table':hex(nested_table),
                'offset_bytes':read_va(data,secs,nested_table,12).hex(),
                'targets':[hex(x) for x in nested_targets]},
            'nested_after_i_dispatch':{'site':hex(nested_again_site),'table':hex(nested_again_table),
                'offset_bytes':read_va(data,secs,nested_again_table,12).hex(),
                'targets':[hex(x) for x in nested_again_targets]},
            'reservation':{'cap':cap,'stride':stride,'cap_site':'0x24d9509',
                'cap_bytes':cap_insn.hex(),'stride_site':'0x24d9525','stride_bytes':stride_insn.hex()},
            'hash_context_config_hex':config[4:].hex(),
            'anchors':[{'site':hex(s),'bytes':v} for s,v in anchors]}


def write_tsv(path, fields, rows):
    with path.open('w',encoding='utf-8',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter='\t',lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def generate(data, out):
    result=extract(data)
    out.mkdir(parents=True,exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    field_table=[{k:v for k,v in row.items() if k!='offset_proof'} for row in result['fields']]
    write_tsv(out/'fields.tsv',['object','order','site','data','length','name','input_offset','handoff'],field_table)
    write_tsv(out/'calls.tsv',['role','site','bytes','target'],result['calls'])
    write_tsv(out/'branches.tsv',['role','site','bytes','condition','target','fallthrough'],result['branches'])
    compares=[{'selector':x['selector'],'index':x['index'],'site':x['site'],
               'expected_hex':format(x['byte'],'02x'),'compare_bytes':x['compare_bytes'],
               'branch_site':x['branch']['site'],'branch_bytes':x['branch']['bytes'],
               'branch_target':x['branch']['target'],'fallthrough':x['branch']['fallthrough']}
              for x in result['comparisons']]
    write_tsv(out/'key-comparisons.tsv',['selector','index','site','expected_hex','compare_bytes',
              'branch_site','branch_bytes','branch_target','fallthrough'],compares)
    keys=[bytes(x['byte'] for x in result['comparisons'] if x['selector']==n) for n in range(3)]
    cases=[]
    for selector,key in enumerate(keys):
        for kind,value in [('exact',key),('short',key[:-1]),('extended',key+b'!'),
                           ('first_byte_changed',bytes([key[0]^1])+key[1:])]:
            cases.append({'key':key.decode('ascii'),'case':kind,'candidate_hex':value.hex(),
                          'selector':classify(value,keys)})
    write_tsv(out/'key-cases.tsv',['key','case','candidate_hex','selector'],cases)
    cap=result['reservation']['cap']; stride=result['reservation']['stride']
    sample_counts=[0,1,cap-1,cap,cap+1,0xffffffff]
    reserve=[]
    for count in sample_counts:
        slots,size=reservation(count,cap,stride)
        reserve.append({'input_count':count,'initial_slots':slots,'initial_bytes':size})
    write_tsv(out/'reservation-cases.tsv',['input_count','initial_slots','initial_bytes'],reserve)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    data=BINARY.read_bytes()
    identity(data)
    generate(data,args.out)


if __name__=='__main__':
    main()
