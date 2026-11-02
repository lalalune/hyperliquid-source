#!/usr/bin/env python3
"""Recover the #94 JSON post-value rejection and selected payload cleanup path."""

import argparse
import csv
import hashlib
import io
import json
import mmap
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
MASK64 = (1 << 64) - 1

# start: (exclusive FDE end, FDE VA, LSDA VA, code SHA-256, LSDA-header-and-table SHA-256)
# The first entry is a prior reader boundary. Its whole body is not re-owned.
FRAMES = {
    0x2fe2fe0: (0x2fe313b, 0x113da5c, 0xa5efe8, 'c90c5c14fca0b634da51ed7eab5fa2d8052284389e1dd2e8513fda1470bd27b6', 'd3f68fcfea5c5534e364f68c9d1df621b331fc8d65fb5fb63fa429f8bbb62790'),
    0x2fe32d0: (0x2fe3388, 0x113dabc, 0xa5f028, '6cf9ae1de4d7319dde7baf75daf8728323ebae198c7d0596e132415e1f3c913c', '864d9e951054c90b82a453e65822ce975514fe8239b7af427d471fe95390f06a'),
    0x2ff8b70: (0x2ff9627, 0x113f44c, 0xa5fcb8, 'c56995774735058d18657ece37bcc5f5e4dbd2a281734361b5d44ceeea6fffb3', '41ccac7825b84338cf4ff6ba871e1852728d4f47730321af81f0e1377c5dd7b5'),
    0x3005ef0: (0x30061f4, 0x11435a8, 0xa61410, 'b637fd40400a269bfa4bad9f200301852c53909abe9e91c3855285d4eece48d8', '5ff64052e2644025d666cfd28e6dbbd79f2f79956ac2d20ed7b52442c78416c1'),
    0x3bbd260: (0x3bbd379, 0x11e20d0, 0xae2328, 'd2195342e8fb520c241e8b4b49b0a5b777b3dae06ac2bd974931ce98d51ab0cb', '7e4e5fae49bc543a4ade357eb5ba2da82008601ac5224cb3cc62ccefba4822b5'),
    0x3bbe610: (0x3bbe81d, 0x11e2428, 0xae2518, '45417003eaeb16a311f38d419d285c8d76ee23e36edba2c4ba379934c330f5a8', 'ce2107e4d04f40dd007c7807e2a1e3eb061c3b5e2bbd2b27666629516ce356e7'),
    0x3bb9d50: (0x3bb9ea9, 0x11e15c8, 0xae1f3c, '41cf9decbea90fb410479b1c407f37402893f6c9b1b17fd9417f2f513c2125db', 'b8dc26367d4ad89e605c3d866b9898e34f6c0b98479a2dda51fc1c4d9e2b77b7'),
    0x3bbf380: (0x3bbf4d9, 0x11e284c, 0xae26a4, 'df303a461ea7391331e1b1af15b7a6e263b8af38659115c1fe1124b9f3777668', 'b8dc26367d4ad89e605c3d866b9898e34f6c0b98479a2dda51fc1c4d9e2b77b7'),
}
BOUNDARY = 0x2fe2fe0

# Each selected window's digest binds the annotated instruction sequence.
WINDOWS = [
    (0x2fe3042, 0x2fe3072, 'boundary_output_and_copy', 'ecff242473689b854e35c20145cc471dab06f42f4dc9bb1ddbe90b3040e3b00b'),
    (0x2fe3072, 0x2fe30b8, 'boundary_trailing_check', '00069e85cf39d4cf9d2296b29f00abe9e7fe3a89cde91ef124013fad8ab3e5be'),
    (0x2fe30b8, 0x2fe30e3, 'boundary_error_and_release', '6b776dbc366f954a3c173dc0f8c192e9bb3ef96e14120e8d2436f15311a0dfb9'),
    (0x2fe3105, 0x2fe311a, 'boundary_unwind', '1a72441cf2cc6b2f42c36ec5c1cba4be2fcf8fbb786650f87f0ff84033299f76'),
    (0x2fe32d0, 0x2fe336f, 'error_location', 'a79b5991482f8f5c6f762cf2ddfdc055949c2a04c70bceb68fc898eeebec78ed'),
    (0x2ff8b70, 0x2ff8c2c, 'outer_vectors', '0ac29b4b6cb4764970d608282a15f91de964ca75dd58a594e59cd5e5a23329df'),
    (0x2ff9423, 0x2ff94b3, 'outer_unwind_vectors', '4aac11b5a32a1d7dcd06f5e02b25138620047929fc26f41e372633126d3e0c85'),
    (0x3005ef0, 0x3005f58, 'payload_order_groups', 'f14a544676cf62b0bccb3e26890d93c58d38932e63588dfe1805634d1f863e47'),
    (0x3006132, 0x3006178, 'group_unwind', '804fa60094782ada123117541eeafd9d25e35f7f8b515a6d7e5317223d8ae3a1'),
    (0x3bbd260, 0x3bbd2b4, 'nested_vector', 'eb5caed6e152bcca68aa527cce6cee063e3331a9626ca637c4601419f584efb1'),
    (0x3bbd30a, 0x3bbd344, 'nested_unwind', '27c86660937c4daca6eb550037e119f52c788ce911a39c9f62262485840c9074'),
    (0x3bbe610, 0x3bbe678, 'group_children', 'bf12f6e19cca3ba67758fa3f5b048f8f264fceb06f07a6a7aebfa1110b7fb2bc'),
    (0x3bb9d50, 0x3bb9e4f, 'direct_vector_item', '6f9700eea0fd0ea8568e75650c80de5eb36c847f94a7dafaf9f1add5438916fa'),
    (0x3bbf380, 0x3bbf47f, 'nested_vector_item', '742dd952065dfd7c5421bdb716ef65b1232c7c345958a64be225a22921ec78a2'),
]

# Address, exact instruction, expected decoded target, explanation.
BRANCHES = [
    (0x2fe304a,'0f8493000000',0x2fe30e3,'parsed tag 2 bypasses tail test'),
    (0x2fe3070,'7371',0x2fe30e3,'cursor at or above length'),
    (0x2fe3099,'771d',0x2fe30b8,'byte exceeds 32'),
    (0x2fe309f,'7317',0x2fe30b8,'byte missing from bit mask'),
    (0x2fe30b4,'75da',0x2fe3090,'next suffix byte'),
    (0x2fe32df,'0f8481000000',0x2fe3366,'cursor increment overflow'),
    (0x2fe32f6,'7517',0x2fe330f,'nonzero length scan'),
    (0x2fe333d,'7511',0x2fe3350,'non-newline increments column'),
    (0x2fe3343,'7416',0x2fe335b,'line counter overflow'),
    (0x2fe3354,'7408',0x2fe335e,'column counter overflow'),
    (0x2ff8ba4,'7414',0x2ff8bba,'outer vector A exhausted'),
    (0x2ff8bc4,'7416',0x2ff8bdc,'outer vector A zero capacity'),
    (0x2ff8bf4,'7414',0x2ff8c0a,'outer vector B exhausted'),
    (0x2ff8c14,'7416',0x2ff8c2c,'outer vector B zero capacity'),
    (0x3005f24,'7414',0x3005f3a,'group vector exhausted'),
    (0x3005f44,'7412',0x3005f58,'group vector zero capacity'),
    (0x3006143,'7415',0x300615a,'remaining groups exhausted on unwind'),
    (0x3006164,'7412',0x3006178,'group capacity zero on unwind'),
    (0x3bbd284,'7414',0x3bbd29a,'nested vector exhausted'),
    (0x3bbd2a0,'7412',0x3bbd2b4,'nested vector zero capacity'),
    (0x3bbd313,'7415',0x3bbd32a,'remaining nested entries exhausted'),
    (0x3bbd330,'7412',0x3bbd344,'nested capacity zero on unwind'),
    (0x3bbe625,'7435',0x3bbe65c,'group child count zero'),
    (0x3bbe650,'74ee',0x3bbe640,'group child allocation size zero'),
    (0x3bbe662,'7414',0x3bbe678,'group child vector capacity zero'),
    (0x3bb9d77,'740f',0x3bb9d88,'two embedded fields exhausted'),
    (0x3bb9d8f,'742d',0x3bb9dbe,'auxiliary size zero'),
    (0x3bb9dd2,'7449',0x3bb9e1d,'inner vector count zero'),
    (0x3bb9e02,'74ec',0x3bb9df0,'inner entry tag 2'),
    (0x3bb9e0c,'74e2',0x3bb9df0,'inner allocation size zero'),
    (0x3bb9e23,'7412',0x3bb9e37,'inner vector capacity zero'),
    (0x3bbf3a7,'740f',0x3bbf3b8,'nested two embedded fields exhausted'),
    (0x3bbf3bf,'742d',0x3bbf3ee,'nested auxiliary size zero'),
    (0x3bbf402,'7449',0x3bbf44d,'nested inner vector count zero'),
    (0x3bbf432,'74ec',0x3bbf420,'nested inner entry tag 2'),
    (0x3bbf43c,'74e2',0x3bbf420,'nested inner allocation size zero'),
    (0x3bbf453,'7412',0x3bbf467,'nested inner vector capacity zero'),
]

# Only these specific instruction forms and their signed displacements are decoded.
EDGES = [
    (0x2fe3042,'e8',0x315ba80,'prior reader boundary'),
    (0x2fe305d,'ff15',0x576dfe0,'prior copy slot'),
    (0x2fe30c9,'e8',0x2fe32d0,'suffix error location'),
    (0x2fe30de,'e8',0x2ff8b70,'release parsed temporary'),
    (0x2fe310d,'e8',0x2ff8b70,'release temporary on error-constructor unwind'),
    (0x2fe3309,'ff25',0x576ef80,'prior located-error slot boundary'),
    (0x2fe335e,'ff15',0x576e118,'counter overflow diagnostic slot'),
    (0x2ff8b81,'e8',0x3005ef0,'first payload cleanup'),
    (0x2ff8bb0,'e8',0x3bbd260,'outer vector A item'),
    (0x2ff8c00,'e8',0x3bb9d50,'outer vector B item'),
    (0x2ff9435,'e8',0x3bb9d50,'remaining B items on unwind'),
    (0x2ff947b,'e8',0x3bbd260,'remaining A items on unwind'),
    (0x3005f30,'e8',0x3bbe610,'group item'),
    (0x3006150,'e8',0x3bbe610,'remaining group items on unwind'),
    (0x3bbd290,'e8',0x3bbf380,'nested item'),
    (0x3bbd320,'e8',0x3bbf380,'remaining nested items on unwind'),
    (0x3bbe672,'ff15',0x576e010,'prior release slot'),
    (0x3bb9d81,'e8',0x33f5270,'direct embedded field cleanup'),
    (0x3bbf3b1,'e8',0x33f5270,'nested embedded field cleanup'),
    (0x3bb9dc2,'e8',0x34d8950,'direct auxiliary cleanup'),
    (0x3bbf3f2,'e8',0x34d8950,'nested auxiliary cleanup'),
    (0x3bb9e4a,'e9',0x33fe8c0,'direct tail cleanup'),
    (0x3bbf47a,'e9',0x33fe8c0,'nested tail cleanup'),
]

# Extracted immediates/displacements, not host structures or reconstructed types.
# name, instruction VA, exact bytes, offset of operand, width, signed
OPERANDS = [
    ('copy_size',0x2fe3055,'bac81f0000',1,4,False),
    ('tail_allowed_mask',0x2fe307d,'48be0026000001000000',2,8,False),
    ('tail_max_byte',0x2fe3095,'4883ff20',3,1,False),
    ('location_initial_line',0x2fe3313,'be01000000',1,4,False),
    ('location_newline',0x2fe3338,'42803c010a',4,1,False),
    ('tail_error_code',0x2fe30b8,'48c744245016000000',5,4,False),
    ('outer_a_pointer_offset',0x2ff8b86,'488bbd50180000',3,4,False),
    ('outer_a_count_offset',0x2ff8b8d,'4c8ba558180000',3,4,False),
    ('outer_a_capacity_offset',0x2ff8bba,'488b8548180000',3,4,False),
    ('outer_a_stride',0x2ff8ba6,'4c8dbf38010000',3,4,False),
    ('outer_a_release_multiplier',0x2ff8bcd,'4869f038010000',3,4,False),
    ('outer_b_pointer_offset',0x2ff8bdc,'488bbd68180000',3,4,False),
    ('outer_b_count_offset',0x2ff8be3,'4c8ba570180000',3,4,False),
    ('outer_b_capacity_offset',0x2ff8c0a,'488b8560180000',3,4,False),
    ('outer_b_stride',0x2ff8bf6,'4c8dbfd8000000',3,4,False),
    ('outer_b_release_multiplier',0x2ff8c1d,'4869f0d8000000',3,4,False),
    ('group_pointer_offset',0x3005f01,'4c8bbfc0050000',3,4,False),
    ('group_count_offset',0x3005f08,'4c8bafc8050000',3,4,False),
    ('group_capacity_offset',0x3005f3a,'488b83b8050000',3,4,False),
    ('group_stride',0x3005f26,'4c8da7f0020000',3,4,False),
    ('group_release_multiplier',0x3005f46,'4869f0f0020000',3,4,False),
    ('nested_capacity_offset',0x3bbd29a,'488b03',2,0,False),
    ('nested_pointer_offset',0x3bbd26e,'4c8b7f08',3,1,False),
    ('nested_count_offset',0x3bbd272,'4c8b6f10',3,1,False),
    ('nested_stride',0x3bbd286,'4c8da7d8000000',3,4,False),
    ('nested_release_multiplier',0x3bbd2a2,'4869f0d8000000',3,4,False),
    ('group_child_capacity_offset',0x3bbe65c,'488b03',2,0,False),
    ('group_child_count_offset',0x3bbe61e,'4c8b7710',3,1,False),
    ('group_child_pointer_offset',0x3bbe627,'4c8b7b08',3,1,False),
    ('group_child_stride',0x3bbe640,'4983c730',3,1,False),
    ('group_child_release_shift',0x3bbe668,'48c1e004',3,1,False),
    ('group_child_release_sib',0x3bbe66c,'488d3440',3,1,False),
    ('item_vector_capacity_offset',0x3bb9e1d,'488b03',2,0,False),
    ('item_vector_pointer_offset',0x3bb9dc7,'4c8b7308',3,1,False),
    ('item_vector_count_offset',0x3bb9dcb,'4c8b7b10',3,1,False),
    ('item_pointer_in_row',0x3bb9dd4,'4d8d6658',3,1,False),
    ('item_tag_from_pointer',0x3bb9dfc,'41837c24a802',4,1,True),
    ('item_element_size_shift',0x3bb9e12,'48c1e603',3,1,False),
    ('item_inner_stride',0x3bb9df0,'4981c4f8000000',3,4,False),
    ('item_skip_tag',0x3bb9dfc,'41837c24a802',5,1,False),
    ('item_count_from_pointer',0x3bb9e04,'498b7424f8',4,1,True),
    ('item_inner_release_multiplier',0x3bb9e25,'4869f0f8000000',3,4,False),
    ('item_embedded_first_offset',0x3bb9d5c,'41bf80000000',2,4,False),
    ('item_embedded_end_offset',0x3bb9d70,'4981ffb0000000',3,4,False),
    ('item_embedded_stride',0x3bb9d7d,'4983c718',3,1,False),
]

# Paired functions use these and only these rel32 operands as a normalization.
# Each is independently decoded and required to have the same absolute target.
MASK_SITES = [0x31,0x68,0x72,0x88,0xe1,0xfa,0x117,0x120,0x129,0x131,0x140,0x148,0x14d,0x153]
MASK_TARGETS = [0x33f5270,0x576e010,0x34d8950,0x576e010,0x576e010,0x33fe8c0,
                0x33f5270,0x34d71f0,0x34d8950,0x3bb9b70,0x33fe8c0,0x5660110,
                0x576e128,0x576e128]

# Selected calls whose actual LSDA rows are linked to the separately pinned pads.
UNWIND_SITES = [
    (0x2fe2fe0,0x2fe3042,0x2fe311a,'reader call'),
    (0x2fe2fe0,0x2fe30c9,0x2fe3105,'error location construction'),
    (0x2fe2fe0,0x2fe30de,0x2fe311a,'temporary cleanup'),
    (0x2fe2fe0,0x2fe310d,0x2fe3114,'temporary cleanup during unwind'),
    (0x2fe32d0,0x2fe335e,0x2fe336f,'counter overflow diagnostic'),
    (0x2ff8b70,0x2ff8b81,0x2ff93ff,'group cleanup'),
    (0x2ff8b70,0x2ff8bb0,0x2ff9469,'outer A item cleanup'),
    (0x2ff8b70,0x2ff8c00,0x2ff9423,'outer B item cleanup'),
    (0x3005ef0,0x3005f30,0x3006132,'group item cleanup'),
    (0x3bbd260,0x3bbd290,0x3bbd30a,'nested item cleanup'),
    (0x3bbe610,0x3bbe67c,0x3bbe792,'group child cleanup'),
    (0x3bb9d50,0x3bb9d81,0x3bb9e54,'direct embedded cleanup'),
    (0x3bbf380,0x3bbf3b1,0x3bbf484,'nested embedded cleanup'),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_digest(data):
    if digest(data) != SHA256:
        raise ValueError('node #94 SHA-256 mismatch')


def map_offset(secs, va, size):
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
        raise ValueError('invalid address range')
    matches = [s for s in secs if s['type'] != 8 and s['flags'] & 2 and s['size']
               and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address is not in exactly one allocated file-backed section')
    section = matches[0]
    return section['offset'] + va - section['address'], section['name']


def read_va(data, secs, va, size):
    off, _ = map_offset(secs, va, size)
    if off + size > len(data):
        raise ValueError('mapped range exceeds file')
    return bytes(data[off:off + size])


def owner(va):
    matches = [a for a, (end, *_rest) in FRAMES.items() if a <= va < end]
    if len(matches) != 1:
        raise ValueError('selected VA not in exactly one chosen FDE')
    return matches[0]


def validate_frames(data, secs, rows, fdes):
    selected = {}
    for start, (end, fde_va, lsda_va, code_hash, _lsda_hash) in FRAMES.items():
        from_fde = [f for f in fdes if f['start'] == start]
        from_index = [r for r in rows if r['start'] == start]
        if len(from_fde) != 1 or len(from_index) != 1:
            raise ValueError('missing or duplicate FDE/index start')
        frame, indexed = from_fde[0], from_index[0]
        if (frame['end'],frame['fde'],frame['lsda']) != (end,fde_va,lsda_va) or indexed['fde'] != fde_va:
            raise ValueError('FDE/index mismatch')
        code = read_va(data, secs, start, end-start)
        if digest(code) != code_hash:
            raise ValueError('selected FDE bytes changed')
        selected[start] = frame
    return selected


def extract_windows(data, secs):
    result = []
    for start,end,role,pin in WINDOWS:
        if owner(start) != owner(end-1):
            raise ValueError('window crosses FDE')
        raw = read_va(data, secs, start, end-start)
        if digest(raw) != pin:
            raise ValueError('selected instruction window changed')
        off, section = map_offset(secs,start,end-start)
        result.append({'start_va':hex(start),'end_va':hex(end),'file_offset':hex(off),
                       'section':section,'fde_start_va':hex(owner(start)),
                       'ownership':'prior_boundary' if owner(start)==BOUNDARY else 'selected',
                       'role':role,'bytes':raw.hex(),'sha256':digest(raw)})
    return result


def branch_one(data, secs, site, expected_hex, expected_target, role):
    raw = read_va(data, secs, site, len(bytes.fromhex(expected_hex)))
    if raw.hex() != expected_hex:
        raise ValueError('branch bytes changed')
    if len(raw)==2 and 0x70 <= raw[0] <= 0x7f:
        displacement = struct.unpack('<b',raw[1:])[0]
    elif len(raw)==6 and raw[0]==0x0f and 0x80 <= raw[1] <= 0x8f:
        displacement = struct.unpack('<i',raw[2:])[0]
    else:
        raise ValueError('unsupported branch form')
    target = site + len(raw) + displacement
    if target != expected_target or owner(site) != owner(target):
        raise ValueError('branch target mismatch or outside FDE')
    off, _ = map_offset(secs, site, len(raw))
    return {'site_va':hex(site),'file_offset':hex(off),'fde_start_va':hex(owner(site)),
            'ownership':'prior_boundary' if owner(site)==BOUNDARY else 'selected',
            'bytes':raw.hex(),'displacement':displacement,'target_va':hex(target),'role':role}


def extract_branches(data, secs):
    return [branch_one(data,secs,*entry) for entry in BRANCHES]


def rel32(raw, site):
    if raw[:1] in (b'\xe8',b'\xe9') and len(raw)==5:
        pos=1
    elif raw[:2] in (b'\xff\x15',b'\xff\x25') and len(raw)==6:
        pos=2
    elif raw[:3]==b'\x4c\x8b\x2d' and len(raw)==7:
        pos=3
    else:
        raise ValueError('unsupported selected relative form')
    return site + len(raw) + struct.unpack_from('<i',raw,pos)[0], pos


def extract_edges(data, secs):
    out=[]
    for site,form,expected,role in EDGES:
        size = 5 if form in ('e8','e9') else 6
        raw=read_va(data,secs,site,size)
        if raw[:len(bytes.fromhex(form))].hex()!=form:
            raise ValueError('transfer opcode changed')
        target,_ = rel32(raw,site)
        if target != expected:
            raise ValueError('transfer target changed')
        off,_=map_offset(secs,site,size)
        out.append({'site_va':hex(site),'file_offset':hex(off),'fde_start_va':hex(owner(site)),
                    'ownership':'prior_boundary' if owner(site)==BOUNDARY else 'selected',
                    'form':form,'bytes':raw.hex(),'target_va':hex(target),'role':role})
    return out


def extract_operands(data, secs):
    out={}
    for name,site,want,at,width,signed in OPERANDS:
        raw=read_va(data,secs,site,len(bytes.fromhex(want)))
        if raw.hex()!=want or at < 0 or at+width>len(raw):
            raise ValueError('operand instruction changed')
        if width==0 and (raw != b'\x48\x8b\x03' or raw[2] & 0xc0):
            raise ValueError('unsupported no-displacement address')
        value=int.from_bytes(raw[at:at+width], 'little', signed=signed)
        off,_=map_offset(secs,site,len(raw))
        out[name]={'site_va':hex(site),'file_offset':hex(off),'fde_start_va':hex(owner(site)),
                   'ownership':'prior_boundary' if owner(site)==BOUNDARY else 'selected',
                   'bytes':raw.hex(),'operand_bytes':raw[at:at+width].hex(),'value':value}
    for first,second in [('outer_a_stride','outer_a_release_multiplier'),
                         ('outer_b_stride','outer_b_release_multiplier'),
                         ('group_stride','group_release_multiplier'),
                         ('nested_stride','nested_release_multiplier'),
                         ('item_inner_stride','item_inner_release_multiplier')]:
        if out[first]['value'] != out[second]['value']:
            raise ValueError('iteration and release multipliers disagree')
    return out


def derive_layout(operands, edges):
    """Project selected loop operands and edge targets; all numbers come from bytes."""
    value=lambda name: operands[name]['value']
    edge={int(row['site_va'],16):row['target_va'] for row in edges}
    def row(name, cap, pointer, count, stride, site):
        return {'name':name,'capacity_offset':value(cap),'pointer_offset':value(pointer),
                'count_offset':value(count),'stride_bytes':value(stride),
                'item_target_va':edge[site] if site is not None else ''}
    vectors=[
        row('state_groups','group_capacity_offset','group_pointer_offset','group_count_offset','group_stride',0x3005f30),
        row('state_outer_a','outer_a_capacity_offset','outer_a_pointer_offset','outer_a_count_offset','outer_a_stride',0x2ff8bb0),
        row('state_outer_b','outer_b_capacity_offset','outer_b_pointer_offset','outer_b_count_offset','outer_b_stride',0x2ff8c00),
        row('outer_a_nested','nested_capacity_offset','nested_pointer_offset','nested_count_offset','nested_stride',0x3bbd290),
        row('group_child','group_child_capacity_offset','group_child_pointer_offset','group_child_count_offset','group_child_stride',None),
        row('item_inner','item_vector_capacity_offset','item_vector_pointer_offset','item_vector_count_offset','item_inner_stride',None),
    ]
    sib=value('group_child_release_sib')
    release_multiplier=(1 << value('group_child_release_shift')) * (1 + (1 << (sib >> 6)))
    if release_multiplier != value('group_child_stride'):
        raise ValueError('group child advance and release multipliers disagree')
    base=value('item_pointer_in_row')
    tagged={'row_stride':value('item_inner_stride'),'tag_offset':base+value('item_tag_from_pointer'),
            'skip_tag':value('item_skip_tag'),'size_offset':base+value('item_count_from_pointer'),
            'pointer_offset':base,'element_size':1 << value('item_element_size_shift')}
    first=value('item_embedded_first_offset'); end=value('item_embedded_end_offset')
    step=value('item_embedded_stride')
    if step<=0 or first>end or (end-first)%step:
        raise ValueError('embedded field loop bounds disagree')
    return {'vectors':vectors,'tagged_item':tagged,'group_child_release_multiplier':release_multiplier,
            'embedded_field_offsets':list(range(first,end,step))}


def parse_lsda(data, secs, frame):
    sec=[s for s in secs if s['name']=='.gcc_except_table' and s['type']!=8]
    if len(sec)!=1 or frame['lsda'] is None:
        raise ValueError('missing or duplicate exception section or LSDA')
    sec=sec[0]; va=frame['lsda']; off,_=map_offset(secs,va,1)
    limit=sec['offset']+sec['size']
    if not sec['offset'] <= off < limit or off+2 > limit:
        raise ValueError('LSDA outside exception section')
    pos=off
    if data[pos]!=0xff or data[pos+1] not in (0xff,0x9b):
        raise ValueError('unsupported LSDA encoding')
    type_enc=data[pos+1]; pos+=2; type_base=None
    if type_enc!=0xff:
        distance,pos=uleb(data,pos,limit)
        type_base=pos+distance
        if type_base>limit:
            raise ValueError('LSDA type table outside section')
    if pos>=limit or data[pos]!=1:
        raise ValueError('unsupported call-site encoding')
    pos+=1; table_length,pos=uleb(data,pos,limit); table_start=pos; table_end=pos+table_length
    if table_end>limit or (type_base is not None and table_end>type_base):
        raise ValueError('truncated LSDA call-site table')
    if digest(data[off:table_end]) != FRAMES[frame['start']][4]:
        raise ValueError('LSDA header or table changed')
    rows=[]; previous=frame['start']
    while pos<table_end:
        row_start=pos; values=[]
        for _ in range(4):
            value,pos=uleb(data,pos,table_end); values.append(value)
        relative,size,landing_offset,action=values
        begin=frame['start']+relative; end=begin+size
        landing=frame['start']+landing_offset if landing_offset else None
        if not frame['start'] <= begin < end <= frame['end'] or begin<previous:
            raise ValueError('invalid or unordered LSDA call-site range')
        if landing is not None and not frame['start'] <= landing < frame['end']:
            raise ValueError('landing outside FDE')
        previous=end
        rows.append({'fde_start_va':hex(frame['start']),
                     'ownership':'prior_boundary' if frame['start']==BOUNDARY else 'selected',
                     'lsda_va':hex(va),'row_file_offset':hex(row_start),'raw':bytes(data[row_start:pos]).hex(),
                     'begin_va':hex(begin),'end_va':hex(end),
                     'landing_va':hex(landing) if landing is not None else '', 'action':action})
    return {'va':hex(va),'file_offset':hex(off),'header_bytes':bytes(data[off:table_start]).hex(),
            'table_bytes':table_length,'rows':rows}


def unwind_witnesses(lsdas):
    out=[]
    for start,site,pad,role in UNWIND_SITES:
        rows=[r for r in lsdas[start]['rows'] if int(r['begin_va'],16)<=site<int(r['end_va'],16)]
        size = 6 if site == 0x2fe335e else 5
        if (len(rows)!=1 or rows[0]['landing_va']!=hex(pad)
                or site+size > int(rows[0]['end_va'],16)):
            raise ValueError('selected LSDA witness mismatch')
        out.append({'site_va':hex(site),'role':role,**rows[0]})
    return out


def masked_pair(data, secs):
    left,right=0x3bb9d50,0x3bbf380
    n=FRAMES[left][0]-left
    if n != FRAMES[right][0]-right:
        raise ValueError('paired extents have different lengths')
    raw_l=read_va(data,secs,left,n); raw_r=read_va(data,secs,right,n)
    a=bytearray(raw_l); b=bytearray(raw_r); masks=[]; covered=set()
    if len(MASK_SITES)!=len(MASK_TARGETS):
        raise ValueError('normalization plan length mismatch')
    for off,expected_target in zip(MASK_SITES,MASK_TARGETS):
        prefix=bytes(a[off:off+3])
        if prefix[:1] in (b'\xe8',b'\xe9'):
            size=5
        elif prefix[:2] in (b'\xff\x15',b'\xff\x25'):
            size=6
        elif prefix==b'\x4c\x8b\x2d':
            size=7
        else:
            raise ValueError('unsupported normalization site')
        p=bytes(a[off:off+size]); q=bytes(b[off:off+size])
        target_l,field_l=rel32(p,left+off); target_r,field_r=rel32(q,right+off)
        if field_l!=field_r or target_l!=target_r or target_l!=expected_target:
            raise ValueError('normalized relative targets differ')
        field=off+field_l
        if covered.intersection(range(field,field+4)):
            raise ValueError('overlapping normalization masks')
        covered.update(range(field,field+4))
        masks.append({'instruction_offset':hex(off),'field_offset':hex(field),'field_size':4,
                      'left_bytes':p.hex(),'right_bytes':q.hex(),'target_va':hex(target_l)})
        a[field:field+4]=b'\0'*4; b[field:field+4]=b'\0'*4
    if a!=b:
        raise ValueError('normalized paired function bytes differ')
    differences=[{'offset':hex(i),'left_byte':format(x,'02x'),'right_byte':format(y,'02x'),
                  'inside_mask':i in covered} for i,(x,y) in enumerate(zip(raw_l,raw_r)) if x!=y]
    return {'left_va':hex(left),'right_va':hex(right),'length':n,
            'left_sha256':digest(raw_l),'right_sha256':digest(raw_r),
            'raw_equal':raw_l==raw_r,'different_raw_bytes':len(differences),
            'raw_differences':differences,'masked_byte_count':len(covered),'normalized_equal':True,
            'normalized_sha256':digest(a),'masks':masks}


def scan_suffix(payload, cursor, mask, maximum):
    """Synthetic selected continuation, conditional on a successful child parse."""
    if not isinstance(payload,bytes) or type(cursor) is not int or not 0<=cursor<=len(payload):
        raise ValueError('invalid synthetic suffix input')
    if type(mask) is not int or not 0<=mask<=MASK64 or type(maximum) is not int or not 0<=maximum<64:
        raise ValueError('invalid mask or maximum')
    while cursor<len(payload):
        byte=payload[cursor]
        if byte>maximum or not (mask >> byte) & 1:
            return {'status':'reject','cursor':cursor,'byte':byte}
        cursor+=1
    return {'status':'accept','cursor':cursor,'byte':None}


def locate_error(payload, cursor, newline, initial_line):
    """Synthetic byte-based line/column for the selected error helper."""
    if (not isinstance(payload,bytes) or type(cursor) is not int or not 0<=cursor<=MASK64
            or type(newline) is not int or not 0<=newline<=255
            or type(initial_line) is not int or not 0<=initial_line<=MASK64):
        raise ValueError('invalid synthetic position')
    if cursor==MASK64:
        raise ValueError('position increment overflows')
    line,column=initial_line,0
    for byte in payload[:min(cursor+1,len(payload))]:
        if byte==newline:
            if line==MASK64:
                raise ValueError('line counter overflows')
            line+=1; column=0
        else:
            if column==MASK64:
                raise ValueError('column counter overflows')
            column+=1
    return line,column


def collect(data):
    verify_digest(data)
    secs,idx=unwind_index(data)
    _cies,fdes=eh_frame_records(data,secs)
    selected=validate_frames(data,secs,idx,fdes)
    windows=extract_windows(data,secs)
    branches=extract_branches(data,secs)
    edges=extract_edges(data,secs)
    operands=extract_operands(data,secs)
    layout=derive_layout(operands,edges)
    lsdas={a:parse_lsda(data,secs,selected[a]) for a in sorted(selected)}
    witnesses=unwind_witnesses(lsdas)
    comparison=masked_pair(data,secs)
    mask=operands['tail_allowed_mask']['value']
    maximum=operands['tail_max_byte']['value']
    cases=[{'byte':i,'accepted':scan_suffix(bytes([i]),0,mask,maximum)['status']=='accept'}
           for i in range(1 << 8)]
    selected_bodies=[]
    for start in sorted(selected):
        f=selected[start]; off,section=map_offset(secs,start,f['end']-start)
        entry={'start_va':hex(start),'end_va':hex(f['end']),'fde_va':hex(f['fde']),
               'cie_va':hex(f['cie']),'lsda_va':hex(f['lsda']),
               'file_offset':hex(off),'section':section,'length':f['end']-start,
               'sha256':digest(read_va(data,secs,start,f['end']-start)),
               'ownership':'prior_boundary' if start==BOUNDARY else 'selected'}
        if start!=BOUNDARY:
            entry['raw_bytes']=read_va(data,secs,start,f['end']-start).hex()
        selected_bodies.append(entry)
    summary={'binary_sha256':SHA256,'selected_fdes':sum(x['ownership']=='selected' for x in selected_bodies),
             'prior_boundary_fdes':sum(x['ownership']=='prior_boundary' for x in selected_bodies),
             'windows':len(windows),'branches':len(branches),'transfers':len(edges),
             'operands':len(operands),'vector_layouts':len(layout['vectors']),'lsda_tables':len(lsdas),
             'lsda_call_site_rows':sum(len(v['rows']) for v in lsdas.values()),
             'selected_unwind_witnesses':len(witnesses),
             'suffix_byte_cases':len(cases),'accepted_byte_cases':sum(x['accepted'] for x in cases),
             'normalization_fields':len(comparison['masks']),
             'limitations':'Selected static patterns and unwind ranges only; no execution or reconstructed Rust.'}
    return {'functions':selected_bodies,'windows':windows,'branches':branches,'edges':edges,
            'operands':operands,'layout':layout,'lsdas':lsdas,'witnesses':witnesses,
            'comparison':comparison,'suffix_cases':cases,'summary':summary}


def json_bytes(value):
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode('utf-8')


def tsv_bytes(rows, fields):
    out=io.StringIO(newline='')
    writer=csv.DictWriter(out,fieldnames=fields,delimiter='\t',lineterminator='\n',extrasaction='ignore')
    writer.writeheader(); writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def render(result):
    operands=[{'name':name,**result['operands'][name]} for name in sorted(result['operands'])]
    unwind=[row for a in sorted(result['lsdas']) for row in result['lsdas'][a]['rows']]
    return {
        'functions.json':json_bytes(result['functions']),
        'windows.tsv':tsv_bytes(result['windows'],['start_va','end_va','file_offset','section','fde_start_va','ownership','role','bytes','sha256']),
        'branches.tsv':tsv_bytes(result['branches'],['site_va','file_offset','fde_start_va','ownership','bytes','displacement','target_va','role']),
        'edges.tsv':tsv_bytes(result['edges'],['site_va','file_offset','fde_start_va','ownership','form','bytes','target_va','role']),
        'operands.tsv':tsv_bytes(operands,['name','site_va','file_offset','fde_start_va','ownership','bytes','operand_bytes','value']),
        'layout.json':json_bytes(result['layout']),
        'unwind.json':json_bytes({'tables':[{'fde_start_va':hex(a),**result['lsdas'][a]} for a in sorted(result['lsdas'])],
                                  'witnesses':result['witnesses']}),
        'unwind.tsv':tsv_bytes(unwind,['fde_start_va','ownership','lsda_va','row_file_offset','raw','begin_va','end_va','landing_va','action']),
        'normalized-pair.json':json_bytes(result['comparison']),
        'suffix-byte-cases.tsv':tsv_bytes(result['suffix_cases'],['byte','accepted']),
        'summary.json':json_bytes(result['summary']),
    }


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args(argv)
    with BINARY.open('rb') as file:
        with mmap.mmap(file.fileno(),0,access=mmap.ACCESS_READ) as data:
            output=render(collect(data))
    args.out.mkdir(parents=True,exist_ok=True)
    for name in sorted(output):
        (args.out/name).write_bytes(output[name])
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (ValueError,OSError,struct.error) as error:
        print('abci_json_tail_cleanup94:',error,file=sys.stderr)
        raise SystemExit(1)
