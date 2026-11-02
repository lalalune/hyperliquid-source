#!/usr/bin/env python3
"""Extract selected node 94 interpreter-call evidence, without executing it."""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = TOOLS.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Each digest covers an entire unwind-described interval, not just a mnemonic.
FUNCTIONS = {
    0x32fe900: ('host result and error adapter', '0a12ceb2599e10de1c9adcb8d68c852886feca21ebc2c21e3b239bab1f1f92c7'),
    0x3291a00: ('descriptor method at offset 0x20', '57da46b1e555435b767fa797ecdf56935a351f3f0441a7ccf9f521a8999d35ae'),
    0x329a050: ('descriptor method at offset 0x18', '7d1fda58fbd36c8e91689a2d6d54e7ab65dfdc36ab5f1220e35971eb7a900ac0'),
    0x3587550: ('function-pointer opcode adapter', '7ce8c3ceb8a980887b004d072161257734141d9520028dae7a9b012969c6be5f'),
    0x37a5840: ('pair-table interpreter loop', '5bb51e156612120833fa4ab12ee29cfa24295e8e256280d388b4e739ba4e50a4'),
    0x37a59c0: ('function-table interpreter loop', '1f9137a6e7e7c6ccd27734dc8c129287b3483d249394ac1f74cbaa102501548d'),
    0x37b9060: ('interpreter input copy handler', 'ea6b5562ff009503e156880bce7fca59d87ce44431a0ae5d262c7cde6e89460e'),
    0x37bd260: ('four-word memory-range preparation', '88f03e72b3bf4c2fd82e6e50f57daf46a427b84d6ccc331ed8698b3410fa2425'),
    0x37be6a0: ('later table delegate-call handler', '793a7b56339309c09f3e54a66c6c5fbfad376bb55c31c659f17d077618166fc0'),
    0x37bf1d0: ('earlier table delegate-call handler', 'f9cff94cab470d479d61754d1617e9c0bc830a7b91e44e89918095cb60982cfc'),
    0x37d05b0: ('pair opcode adapter', '6c1d029b27fea3a4270baab541361976c9a9edbbae062dc3fc8f66a758ae1fbd'),
    0x37f9580: ('old interpreter-action drop', '0201918ffded4163985afeaf673e4593cc732acb29f501d783ab4f6c1047c5e6'),
}
TABLES = {'early': 0x56fdf80, 'late': 0x56fb780}
HANDLERS = {'early': 0x37bf1d0, 'late': 0x37be6a0}

# The expected patterns are reviewed x86-64 bytes, not disassembler output.
PINS = (
 ('method20_table_choice',0x3291a61,'49833800741d488dbc2480000000488d5424404c89fe4c89c14d89c8e8be3d5100eb1f4983c008488dbc2480000000488d5424404c89fe4c89c14d89c8e81d3f5100'),
 ('method18_table_choice',0x329a0b1,'49833800741d488dbc2480000000488d5424404c89fe4c89c14d89c8e86eb75000eb1f4983c008488dbc2480000000488d5424404c89fe4c89c14d89c8e8cdb85000'),
 ('raw_fetch_dispatch',0x37a5a70,'498b86d00100000fb60848ffc0498986d00100004c89f74c89e641ff54cd00'),
 ('pair_fetch_dispatch',0x37a58f0,'498b86d00100000fb60848ffc0498986d0010000c1e104498b7c0d00498b440d084c89f64c89e2ff5028'),
 ('pair_action_guard',0x37a5926,'4180be88010000707535'),
 ('raw_action_guard',0x37a5a9b,'4180be88010000707535'),
 ('raw_action_move',0x37a5ada,'488b04240f10000f1048100f1050200f1058300f115b300f1153200f114b100f110341c6868801000070'),
 ('pair_action_move',0x37a5965,'488b04240f10000f1048100f1050200f1058300f115b300f1153200f114b100f110341c6868801000070'),
 ('pair_entry_action_reset',0x37a585a,'488dbe5001000048893c24e8163d050041c6868801000070'),
 ('raw_entry_action_reset',0x37a59da,'488dbe5001000048893c24e8963b050041c6868801000070'),
 ('pair_entry_state_replace',0x37a5872,'498bb6e00000004885f6740f498bbee800000031d2ff158387fc014d8dbee0000000498bb6f80000004885f67413498bbe0001000048c1e60331d2ff155d87fc01488b4530498947300f1045000f104d100f105520410f115720410f114f10410f1107'),
 ('raw_entry_state_replace',0x37a59f2,'498bb6e00000004885f6740f498bbee800000031d2ff150386fc014d8dbee0000000498bb6f80000004885f67413498bbe0001000048c1e60331d2ff15dd85fc01488b4530498947300f1045000f104d100f105520410f115720410f114f10410f1107'),
 ('pair_default_result',0x37a5930,'498b8ee801000048894b30410f1086d80100000f114320488d0ddadbf40148890b48c74308010000000f57c00f114310884338eb2a'),
 ('raw_default_result',0x37a5aa5,'498b8ee801000048894b30410f1086d80100000f114320488d0d65daf40148890b48c74308010000000f57c00f114310884338eb2a'),
 ('pair_entry_drop_unwind',0x37a59a1,'4889c341c68688010000704889efe8bc3c05004889dfe854a7eb01'),
 ('raw_entry_drop_unwind',0x37a5b16,'4889c341c68688010000704889efe8473b05004889dfe8dfa5eb01'),
 ('function_pointer_wrapper',0x3587550,'488b86d0010000488d48ff48898ed001000080bef3010000007401c3488986d0010000488b074889f74889d6ffe0'),
 ('pair_pointer_wrapper',0x37d05b0,'488b86d0010000488d48ff48898ed001000080bef3010000007401c3488986d0010000488b07488b4f08488b49284889c7ffe1'),
 ('input_copy_stack_gate',0x37b906b,'4c8b9f280100004983fb03730cc687f30100005be9bc010000'),
 ('input_copy_size_gate',0x37b90ba,'4983c3fd4c899f2801000049c1e3054f8b7c1e104f0b7c1e084f0b7c1e18740cc687f301000054e95a010000'),
 ('input_copy_charge',0x37b90e6,'4f8b341e4d89f34983c31f49c7c7ffffffff4d0f43fb49c1ef054f8d3c7f4983c7034c8b9fe00100004d29fb730cc687f301000050e9200100004c899fe0010000'),
 ('input_copy_offsets',0x37b9127,'4d85f60f84100100004d09c84d09d075a24809c84809d048c7c2ffffffff480f45f2'),
 ('input_copy_memory_bounds',0x37b9149,'4989dd4d01f5490f43d5488b87f0000000482b87100100000f82f50000004839c20f879b000000'),
 ('input_copy_prefix',0x37b9170,'488b47504839c6735d4d89f74901f70f82e40000004c39f84c0f42f84929f74c89fd4801dd0f82b4000000480377484c8ba7e80000004c03a7100100004c01e34889df4c89faff15244efb01'),
 ('input_copy_zero_fill',0x37b91bc,'4d29fe0f82b10000004939ed0f82810000004901ec4c89e7eb1c4889d84c01f07271488b87e8000000480387100100004801d84889c731f64c89f24883c4085b415c415d415e415f5dff25ed4ffb01'),
 ('input_copy_grow',0x37b920b,'488d87e0000000488d8fd80100004989ff4889c74989f44889ceff1515adfb014c89e64c89ff84c00f8537ffffffc687f301000051'),
 ('range_stack_gate',0x37bd26e,'488b86280100004883f8047309c686f30100005beb5f'),
 ('range_input_length',0x37bd2a6,'4e8b7412c0'),
 ('range_stack_and_high_limb_gate',0x37bd2c4,'4883c0fc4e0b5c12c84e0b5c12d848898628010000b254741c8896f3010000'),
 ('range_resize_result',0x37bd3a3,'b25184c00f8430ffffffeb07'),
 ('range_output_guard',0x37bd4b9,'4909d5b1544d09d575114d85db742c480b5c2448480b5c24607429888ef3010000'),
 ('range_null_allocation',0x37bd5a8,'bf010000004c89f6ff15020afb01eb1c488d3db961f301ff15530bfb01eb0d488d3dfa5ff301ff157c0bfb010f0b'),
 ('range_length_publication',0x37bd4af,'4c8974243848894c2440'),
 ('range_allocation_and_copy',0x37bd402,'4c8ba6e800000048897424104c03a6100100004c89f7ff15ba0bfb014885c00f84810100004989c74901ec4889c74c89e64c89f2ff15a40bfb01'),
 ('range_success_words',0x37bd527,'4d01e30f82880000000f104424280f104c24380f114f100f11074c8967204c895f28e99cfdffff'),
 ('late_host_and_charge',0x37be94d,'b1653c02746689c1c1e9080fbae008ba280a0000be64000000480f42f231d280f902480f45d6488d4a644881c2280a0000a801480f44d1488b83e0010000b1504829d07227'),
 ('early_host_and_charge',0x37bf47d,'b1653c02743e488b83e0010000b150483dbc020000722d480544fdffff'),
 ('late_forward_gas',0x37be992,'488983e00100004889c248c1ea064889c64829d64839f5480f43ee4584ff480f45ee4829e8732f'),
 ('early_forward_gas',0x37bf49a,'488983e00100004889c248c1ea064889c64829d64839f5480f43ee4584ff480f45ee4829e873'),
 ('late_stack_failure',0x37be7ce,'c683f30100005be9fc010000'),
 ('early_stack_failure',0x37bf2fe,'c683f30100005be9d4010000'),
 ('late_publish',0x37beb54,'48c744244001000000888424dc00000066c78424dd0000000002bfa0000000ff155ff4fa014885c0744e4989c7488d742440baa00000004889c7ff154cf4fa01488dbb50010000e8e0a903004c89bb50010000c683880100006cc683f301000020'),
 ('early_publish',0x37bf66c,'66c78424dd0000000002bfa0000000ff1557e9fa014885c0744e4989c7488d742440baa00000004889c7ff1544e9fa01488dbb50010000e8d89e03004c89bb50010000c683880100006cc683f301000020'),
 ('host_call_and_tag',0x32fe900,'4156534883ec284889f24889fb488b8fe0000000488d7c24084889dee84fc9faff807c240805750c0fb64424090fb74c240aeb7d'),
 ('host_error_and_pack',0x32fe99c,'0f104424080f104c2418410f114e10410f1106b002c1e1080fb6c009c84883c4285b415ec3'),
 ('action_switch',0x37f9584,'0fb647388d48943c6c0fb6c9b8030000000f43c13c030f878b0000000fb6c0488d0dda11dafc486304814801c8ffe0'),
 ('action_call_drop',0x37f95b3,'4c8b37498b4628498b7630498d7e40498b5638ff5020bea0000000eb49'),
 ('late_drop_unwind_publish',0x37bebde,'4989c64c89bb50010000c683880100006c'),
 ('early_drop_unwind_publish',0x37bf6e6,'4989c64c89bb50010000c683880100006c'),
 ('late_payload_save',0x37be873,'0f104424400f104c24500f105424600f299424e00000000f294c24300f29442420'),
 ('late_payload_to_frame',0x37be9e8,'488983e00100000f284424200f284c24300f114c24780f11442468'),
 ('early_payload_save',0x37bf3a3,'0f104424400f104c24500f105424600f299424e00000000f294c24300f29442420'),
 ('early_payload_to_frame',0x37bf4f0,'488983e00100000f284424200f284c24300f114c24780f11442468'),
)

# Review-selected relative transfers; all destinations are derived from signed bytes.
EDGES = (
 ('method20_raw_table',0x3291a65,0x3291a84),('method20_pair_loop',0x3291a7d,0x37a5840),
 ('method20_raw_loop',0x3291a9e,0x37a59c0),('method18_raw_table',0x329a0b5,0x329a0d4),
 ('method18_pair_loop',0x329a0cd,0x37a5840),('method18_raw_loop',0x329a0ee,0x37a59c0),
 ('late_stack_zero',0x37be6be,0x37be7ce),('late_stack_one',0x37be6d1,0x37be7ce),
 ('late_range_call',0x37be862,0x37bd260),('late_range_empty',0x37be86d,0x37be9d6),
 ('late_host_call',0x37be948,0x32fe900),('late_host_error',0x37be951,0x37be9b9),
 ('late_charge_underflow',0x37be990,0x37be9b9),('late_alloc_null',0x37beb7c,0x37bebcc),
 ('late_drop_old_action',0x37beb9b,0x37f9580),
 ('early_stack_zero',0x37bf1ee,0x37bf2fe),('early_stack_one',0x37bf201,0x37bf2fe),
 ('early_range_call',0x37bf392,0x37bd260),('early_range_empty',0x37bf39d,0x37bf4de),
 ('early_host_call',0x37bf478,0x32fe900),('early_host_error',0x37bf481,0x37bf4c1),
 ('early_charge_underflow',0x37bf492,0x37bf4c1),('early_alloc_null',0x37bf684,0x37bf6d4),
 ('early_drop_old_action',0x37bf6a3,0x37f9580),
 ('range_four_available',0x37bd279,0x37bd284),('range_high_input',0x37bd2db,0x37bd2f9),
 ('range_empty_input',0x37bd31d,0x37bd3af),('range_resize_fail',0x37bd3a7,0x37bd2dd),
 ('range_alloc_null',0x37bd421,0x37bd5a8),('range_high_output',0x37bd4c1,0x37bd4d4),
 ('range_output_resize_ok',0x37bd573,0x37bd527),
 ('raw_loop_again',0x37a5a99,0x37a5a70),('pair_loop_again',0x37a5924,0x37a58f0),
 ('pair_loop_drop_old',0x37a5865,0x37f9580),('raw_loop_drop_old',0x37a59e5,0x37f9580),
 ('pair_loop_unwind_cleanup',0x37a59af,0x37f9670),('raw_loop_unwind_cleanup',0x37a5b24,0x37f9670),
 ('raw_wrapper_ready',0x3587569,0x358756c),('pair_wrapper_ready',0x37d05c9,0x37d05cc),
 ('host_external',0x32fe91c,0x32ab270),
 ('input_copy_stack_ok',0x37b9076,0x37b9084),('input_copy_size_ok',0x37b90d8,0x37b90e6),
 ('input_copy_paid',0x37b9112,0x37b9120),('input_copy_empty',0x37b912a,0x37b9240),
 ('input_copy_high_dest',0x37b9136,0x37b90da),('input_copy_bad_window',0x37b9161,0x37b925c),
 ('input_copy_expand',0x37b916a,0x37b920b),('input_copy_source_empty',0x37b9177,0x37b91d6),
 ('input_copy_source_overflow',0x37b917f,0x37b9269),('input_copy_dest_overflow',0x37b9195,0x37b924f),
 ('input_copy_count_borrow',0x37b91bf,0x37b9276),('input_copy_dest_end',0x37b91c8,0x37b924f),
 ('input_copy_zero_dest_overflow',0x37b91dc,0x37b924f),('input_copy_grow_ok',0x37b9233,0x37b9170),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def authenticate(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, 'node 94 digest mismatch')


def file_offset(secs, va, size, executable=False):
    require(type(va) is int and type(size) is int and va >= 0 and size > 0, 'invalid address range')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2
             and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    require(len(found) == 1, 'not one file-backed section')
    return found[0]['offset'] + va - found[0]['address']


def read(data, secs, va, size, executable=False):
    offset = file_offset(secs, va, size, executable)
    require(offset + size <= len(data), 'truncated file-backed range')
    return data[offset:offset + size]


def check_pin(data, secs, site, expected):
    raw = bytes.fromhex(expected)
    require(read(data, secs, site, len(raw), True) == raw, 'reviewed bytes changed')
    return raw


def relative(raw, site):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        delta = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
        delta = struct.unpack_from('<b', raw, 1)[0]
    elif len(raw) == 6 and raw[0] == 0xf and 0x80 <= raw[1] <= 0x8f:
        delta = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported transfer')
    return site + len(raw) + delta


def read_edge(data, secs, site, expected):
    first = read(data, secs, site, 2, True)
    n = 6 if first[0] == 0xf else 5 if first[0] in (0xe8,0xe9) else 2
    raw = read(data, secs, site, n, True)
    target = relative(raw, site)
    require(target == expected, 'reviewed transfer changed')
    return raw, target


def relocations(data, secs):
    out = {}
    for s in secs:
        if s['type'] != 4:
            continue
        require(s['size'] % 24 == 0, 'truncated RELA section')
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, pos)
            out.setdefault(slot, []).append((info, addend, pos))
    return out


def relative_slot(data, secs, rels, slot, expected=None):
    require(read(data, secs, slot, 8) == bytes(8), 'nonzero unrelocated slot')
    choices = rels.get(slot, ())
    require(len(choices) == 1, 'missing or duplicate relocation')
    info, addend, pos = choices[0]
    require(info == 8 and addend >= 0, 'non-relative or symbolic slot')
    if expected is not None:
        require(addend == expected, 'wrong relocated target')
    return {'slot':hex(slot), 'slot_file_offset':hex(file_offset(secs,slot,8)),
            'addend':hex(addend), 'rela_file_offset':hex(pos),
            'rela_bytes':data[pos:pos + 24].hex()}




def compare_adapters(left,right,left_va=0x3291a00,right_va=0x329a050):
    """Compare two captured intervals, masking only reviewed PC-relative fields."""
    require(len(left)==len(right)==369,'adapter length changed')
    offsets=(0x3c,0x46,0x51,0x7e,0x9f,0xd8,0xe7,0xf6)
    expected=(0x5854c0,0x5854d0,0x5854e0,0x37a5840,0x37a59c0,0x5854c0,0x5854d0,0x5854e0)
    l=bytearray(left);r=bytearray(right);masks=[]
    for i,target in zip(offsets,expected):
        for body,base in ((left,left_va),(right,right_va)):
            prefix=body[i-1:i] if i in (0x7e,0x9f) else body[i-3:i]
            require(prefix == (b'\xe8' if i in (0x7e,0x9f) else bytes.fromhex('0f1005')),
                    'unexpected relative instruction shape')
            dest=base+i+4+struct.unpack_from('<i',body,i)[0]
            require(dest==target,'adapter PC-relative target changed')
        masks.append({'offset':i,'length':4,'decoded_target':hex(target)})
        l[i:i+4]=r[i:i+4]=bytes(4)
    require(l==r,'unmasked adapter bytes differ')
    return {'left_va':hex(left_va),'right_va':hex(right_va),
            'left_sha256':hashlib.sha256(left).hexdigest(),
            'right_sha256':hashlib.sha256(right).hexdigest(),
            'masked_sha256':hashlib.sha256(l).hexdigest(),'masks':masks,
            'note':'Within-target byte-shape comparison only; these are PC-relative fields, not rebuild or relocation masks.'}

def imported_slot(data,secs,rels,slot,expected_name):
    require(read(data,secs,slot,8)==bytes(8), 'nonzero import slot')
    choices=rels.get(slot,())
    require(len(choices)==1, 'missing or duplicate import relocation')
    info,addend,pos=choices[0]
    index=info>>32
    require(info & 0xffffffff == 6 and index>0 and addend==0, 'invalid import relocation')
    syms=[x for x in secs if x['name']=='.dynsym' and x['type']!=8]
    strings=[x for x in secs if x['name']=='.dynstr' and x['type']!=8]
    require(len(syms)==len(strings)==1, 'dynamic symbol sections missing or ambiguous')
    sym,tab=syms[0],strings[0]
    require(sym['size']%24==0 and index<sym['size']//24, 'dynamic symbol index outside section')
    off=sym['offset']+index*24
    name_offset=struct.unpack_from('<I',data,off)[0]
    require(name_offset<tab['size'], 'dynamic string offset outside section')
    start=tab['offset']+name_offset;end=data.find(b'\0',start,tab['offset']+tab['size'])
    require(end>=0, 'unterminated dynamic name')
    name=data[start:end].decode('ascii')
    require(name==expected_name,'unexpected imported symbol')
    return {'slot':hex(slot),'slot_file_offset':hex(file_offset(secs,slot,8)),
            'info':hex(info),'addend':addend,'rela_file_offset':hex(pos),
            'rela_bytes':data[pos:pos+24].hex(),'symbol_index':index,
            'symbol_file_offset':hex(off),'symbol_bytes':data[off:off+24].hex(),
            'name':name,'name_file_offset':hex(start)}

def selected_fdes(data, secs, rows):
    result = {}
    for addr in sorted(FUNCTIONS):
        matches = [r for r in rows if r['start'] == addr]
        require(len(matches) == 1 and 'index' in matches[0], 'missing or ambiguous FDE')
        f = matches[0]
        code = read(data, secs, f['start'], f['end']-f['start'], True)
        require(hashlib.sha256(code).hexdigest() == FUNCTIONS[addr][1], 'selected FDE bytes changed')
        result[addr] = f
    return result


def record_bytes(data, secs, va):
    size = struct.unpack('<I', read(data,secs,va,4))[0]
    require(4 <= size < 0xffffffff, 'unsupported unwind record')
    return read(data,secs,va,size+4).hex()


def exceptions(data, secs, f):
    if f['lsda'] is None:
        return None
    candidates=[s for s in secs if s['name']=='.gcc_except_table' and s['type']!=8]
    require(len(candidates)==1, 'exception section missing or ambiguous')
    s=candidates[0]; start=file_offset(secs,f['lsda'],1); end=s['offset']+s['size']
    require(s['offset'] <= start < end and start+2 <= end and data[start] == 0xff, 'unsupported LSDA')
    kind=data[start+1]; p=start+2; type_table=None
    if kind==0x9b:
        delta,p=uleb(data,p,end);type_table=p+delta
        require(type_table <= end, 'type table outside section')
    else:
        require(kind==0xff, 'unsupported type encoding')
    require(p<end and data[p]==1, 'unsupported call-site encoding');p+=1
    length,p=uleb(data,p,end); stop=p+length; header_end=p
    require(stop<=end and (type_table is None or stop<=type_table), 'truncated LSDA')
    entries=[];last=0
    while p<stop:
        before=p
        off,p=uleb(data,p,stop); size,p=uleb(data,p,stop)
        landing,p=uleb(data,p,stop); action,p=uleb(data,p,stop)
        require(off>=last and f['start']+off+size<=f['end'], 'invalid call-site interval')
        require(not landing or f['start']+landing<f['end'], 'invalid landing')
        entries.append({'start':hex(f['start']+off),'size':size,
                        'landing':hex(f['start']+landing) if landing else None,
                        'action':action,'bytes':data[before:p].hex()})
        last=off+size
    return {'function':hex(f['start']),'lsda':hex(f['lsda']),'file_offset':hex(start),
            'header':data[start:header_end].hex(),'entries':entries}


def lane_rows(code, base, frame_start):
    """Read the fixed source/local/host/frame byte-move shapes for one handler."""
    loc={}; sites={}; p=0x51
    require(code[p:p+4] == bytes.fromhex('0fb63c02'), 'first source load shape')
    require(code[p+4:p+8] == bytes.fromhex('40887c24'), 'first source store shape')
    loc[code[p+8]]=0;sites[0]=base+p;p+=9
    for i in range(1,17):
        require(code[p:p+4] == bytes.fromhex('0fb67c02') and code[p+4] == i, 'source load lane')
        require(code[p+5:p+9] == bytes.fromhex('40887c24'), 'source spill shape')
        loc[code[p+9]]=i;sites[i]=base+p;p+=10
    require(code[p:p+9] == bytes.fromhex('0f10040a0f104c0a10'), 'gas word loads')
    p+=9
    require(code[p:p+9] == bytes.fromhex('0fb64c0211884c240e'), 'source seventeen')
    loc[0xe]=17;sites[17]=base+p;p+=9
    require(code[p:p+12] == bytes.fromhex('440fb6640212440fb66c0213'), 'source register lanes')
    sites[18],sites[19]=base+p,base+p+6
    require(len(loc)==18 and set(loc.values())==set(range(18)), 'ambiguous spills')
    p=0x1f4
    require(code[p:p+10] == bytes.fromhex('44886c24404488642441'), 'host register stores')
    host=[(19,base+p),(18,base+p+5)];p+=10
    for _ in range(18):
        require(code[p:p+4] == bytes.fromhex('0fb64424') and
                code[p+5:p+8] == bytes.fromhex('884424'), 'host spill-store shape')
        src=loc[code[p+4]]; dest=code[p+8]
        require(dest==0x40+len(host), 'host store lane')
        host.append((src,base+p));p+=9
    p=frame_start
    require(code[p:p+16] == bytes.fromhex('4488ac24a00000004488a424a1000000'), 'frame register stores')
    frame=[(19,base+p),(18,base+p+8)];p+=16
    for _ in range(18):
        require(code[p:p+4] == bytes.fromhex('0fb64424') and
                code[p+5:p+8] == bytes.fromhex('888424'), 'frame spill-store shape')
        src=loc[code[p+4]]; dest=struct.unpack_from('<I',code,p+8)[0]
        require(dest==0xa0+len(frame), 'frame store lane')
        frame.append((src,base+p));p+=12
    rows=[]
    for i in range(20):
        require(host[i][0] == frame[i][0] == 19-i, 'source lanes do not agree')
        rows.append([hex(base),i,host[i][0],hex(sites[host[i][0]]),hex(host[i][1]),hex(frame[i][1]),hex(0x60+i)])
    return rows



def payload_flow(data,secs):
    source=read(data,secs,0x37bd2a6,5,True)
    spill=read(data,secs,0x37bd4af,5,True)
    out=read(data,secs,0x37bd530,17,True)
    require(source==bytes.fromhex('4e8b7412c0'),'input length load shape')
    require(spill[:4]==bytes.fromhex('4c897424'),'input length spill shape')
    require(out[:4]==bytes.fromhex('0f104424') and out[5:9]==bytes.fromhex('0f104c24') and
            out[10:13]==bytes.fromhex('0f114f') and out[14:17]==bytes.fromhex('0f1107'),
            'range return copy shape')
    spill_offset=spill[4];out_load=out[9];helper_result=out[13]
    require(spill_offset==out_load and helper_result==0x10, 'range return does not read length spill')
    rows=[]
    for name,save_site,frame_site,base_site in (
        ('early',0x37bf3a8,0x37bf4f7,0x37bf689),
        ('late',0x37be878,0x37be9ef,0x37beb81)):
        save=read(data,secs,save_site,23,True)
        frame=read(data,secs,frame_site,19,True)
        base=read(data,secs,base_site,5,True)
        require(save[:4]==bytes.fromhex('0f104c24') and save[18:22]==bytes.fromhex('0f294c24'),
                'handler range-save shape')
        require(frame[5:9]==bytes.fromhex('0f284c24') and frame[10:14]==bytes.fromhex('0f114c24'),
                'handler frame-copy shape')
        require(base[:4]==bytes.fromhex('488d7424'),'frame base shape')
        source_word=save[4];saved_word=save[22];reload=frame[9];destination=frame[14];frame_base=base[4]
        require(source_word==frame_base+helper_result and saved_word==reload and destination-frame_base==0x38,
                'payload word copies do not compose')
        rows.append({'table':name,'source_stack_displacement':struct.unpack('<b',source[4:5])[0],
                     'helper_spill_offset':spill_offset,'helper_output_offset':helper_result,
                     'handler_save_stack':source_word,'handler_temp_stack':saved_word,
                     'handler_frame_stack':destination,'frame_base_stack':frame_base,
                     'frame_length_offset':destination-frame_base,
                     'source_site':hex(0x37bd2a6),'source_bytes':source.hex(),
                     'spill_site':hex(0x37bd4af),'spill_bytes':spill.hex(),
                     'helper_return_site':hex(0x37bd530),'helper_return_bytes':out.hex(),
                     'save_site':hex(save_site),'save_bytes':save.hex(),
                     'frame_site':hex(frame_site),'frame_bytes':frame.hex(),
                     'frame_base_site':hex(base_site),'frame_base_bytes':base.hex()})
    return rows

def read_costs(data,secs):
    early=read(data,secs,0x37bf48c,6,True)
    high=read(data,secs,0x37be95c,5,True)
    low=read(data,secs,0x37be961,5,True)
    require(early[:2]==bytes.fromhex('483d') and high[:1]==b'\xba' and low[:1]==b'\xbe', 'cost instruction shape')
    result={'early':struct.unpack_from('<I',early,2)[0],
            'high':struct.unpack_from('<I',high,1)[0],
            'low':struct.unpack_from('<I',low,1)[0]}
    require(result=={'early':700,'high':2600,'low':100},'cost immediates changed')
    return result


def input_copy_constants(data, secs):
    rounding=read(data,secs,0x37b90ed,4,True)
    shift=read(data,secs,0x37b90fc,4,True)
    times_three=read(data,secs,0x37b9100,4,True)
    base=read(data,secs,0x37b9104,4,True)
    require(rounding[:3]==bytes.fromhex('4983c3') and
            shift[:3]==bytes.fromhex('49c1ef') and
            times_three==bytes.fromhex('4f8d3c7f') and
            base[:3]==bytes.fromhex('4983c7'), 'input-copy arithmetic shape')
    result={'rounding_add':rounding[3], 'shift':shift[3],
            'per_word':3, 'base':base[3]}
    require(result=={'rounding_add':31,'shift':5,'per_word':3,'base':3},
            'input-copy constants changed')
    return result


def input_copy_plan(size, offset, input_len, constants):
    """Synthetic source/charge projection, not target-instruction execution."""
    u64=(1<<64)-1
    require(type(size) is int and 0<=size<=u64, 'size outside selected arm')
    require(type(offset) is int and 0<=offset<(1<<256), 'invalid source offset')
    require(type(input_len) is int and 0<=input_len<=u64, 'invalid input length')
    charge=constants['base']+constants['per_word']*(min(size+constants['rounding_add'],u64)>>constants['shift'])
    source=min(offset,u64)
    if not size or source>=input_len:
        prefix=0
    elif source+size>u64:
        return {'size':size,'offset':offset,'input_len':input_len,'charge':charge,
                'outcome':'source_add_failure','prefix':None,'zero_fill':None}
    else:
        prefix=min(size,input_len-source)
    return {'size':size,'offset':offset,'input_len':input_len,'charge':charge,
            'outcome':'continue','prefix':prefix,'zero_fill':size-prefix}


def input_copy_cases(constants):
    rows=[input_copy_plan(size,offset,213,constants)
          for size in (0,1,31,32,33,212,213,214)
          for offset in (0,1,212,213,1<<64)]
    rows.append(input_copy_plan(2,(1<<64)-2,(1<<64)-1,constants))
    return rows


def host_cost(host, costs, early=False):
    require(type(host) is int and 0<=host<=0xffffff, 'invalid host word')
    if host & 0xff == 2:
        return None
    if early:
        return costs['early']
    second_byte=(host>>8)&0xff
    first=costs['high'] if host&1 else costs['low']
    second=0 if second_byte==2 else (costs['high'] if host&0x100 else costs['low'])
    return first+second


def cases(costs):
    rows=[]
    for name, early in (('early',True),('late',False)):
        for host in (0,1,2,0x100,0x101,0x200,0x201):
            cost=host_cost(host,costs,early)
            amounts=(0,) if cost is None else (max(0,cost-1),cost,cost+1, cost+64)
            for available in amounts:
                if cost is None:
                    result='host_error'; remaining=None;forwarded=None
                elif available<cost:
                    result='underflow';remaining=None;forwarded=None
                else:
                    remaining=available-cost;forwarded=remaining-(remaining//64);result='continue'
                rows.append({'table':name,'host':host,'available':available,'cost':cost,
                             'result':result,'remaining_after_charge':remaining,
                             'maximum_forwarded':forwarded})
    return rows


def collect(data):
    authenticate(data)
    secs=sections(data)
    summary, all_fdes, _ = fde_extents(data)
    for key in ('duplicate_start','unwind_start_differs_from_fde_start','starts_inside_earlier_extent',
                'fde_records_not_in_unwind_table','extent_crosses_section_end'):
        require(summary[key]==0,'ambiguous unwind inventory')
    selected=selected_fdes(data,secs,all_fdes); rels=relocations(data,secs)
    functions=[];unwind=[];bodies={};exception_tables=[]
    hdr=next(s for s in secs if s['name']=='.eh_frame_hdr')
    for a,f in selected.items():
        raw=read(data,secs,a,f['end']-a,True);bodies[hex(a)]=raw.hex()
        functions.append([hex(a),hex(f['end']),len(raw),hex(file_offset(secs,a,len(raw),True)),
                          hex(f['fde']),hex(f['cie']),hex(f['lsda']) if f['lsda'] else '',
                          hashlib.sha256(raw).hexdigest(),FUNCTIONS[a][0]])
        ix=hdr['address']+12+8*f['index']
        unwind.append({'function':hex(a),'fde':hex(f['fde']),'fde_bytes':record_bytes(data,secs,f['fde']),
                       'cie':hex(f['cie']),'cie_bytes':record_bytes(data,secs,f['cie']),
                       'index':f['index'],'index_va':hex(ix),'index_bytes':read(data,secs,ix,8).hex()})
        ex=exceptions(data,secs,f)
        if ex:exception_tables.append(ex)
    windows=[]
    for label,site,expected in PINS:
        raw=check_pin(data,secs,site,expected)
        owner=[a for a,f in selected.items() if a<=site and site+len(raw)<=f['end']]
        require(len(owner)==1,'pin not inside selected FDE')
        windows.append([label,hex(owner[0]),hex(site),hex(file_offset(secs,site,len(raw),True)),raw.hex()])
    edges=[]
    for label,site,expected in EDGES:
        raw,dest=read_edge(data,secs,site,expected)
        owners=[a for a,f in selected.items() if a<=site and site+len(raw)<=f['end']]
        require(len(owners)==1,'edge outside selected FDEs')
        edges.append([label,hex(owners[0]),hex(site),raw.hex(),hex(dest)])
    tables=[]
    for name,base in sorted(TABLES.items()):
        for opcode in range(256):
            expected=HANDLERS[name] if opcode==0xf4 else 0x37b9060 if opcode==0x37 else None
            r=relative_slot(data,secs,rels,base+8*opcode,expected)
            tables.append([name,hex(base),opcode,r['slot'],r['slot_file_offset'],r['addend'],r['rela_file_offset'],r['rela_bytes']])
    wrappers=[]
    for desc,offset,want in ((0x56e70f0,0x18,0x329a050),(0x56e70f0,0x20,0x3291a00),
                             (0x56ee670,0x28,0x3587550),(0x56f38e0,0x28,0x37d05b0)):
        r=relative_slot(data,secs,rels,desc+offset,want);wrappers.append({'descriptor':hex(desc),'method_offset':hex(offset),**r})
    payload=payload_flow(data,secs)
    comparison=compare_adapters(bytes.fromhex(bodies['0x3291a00']),bytes.fromhex(bodies['0x329a050']))
    imports=[imported_slot(data,secs,rels,0x576dfe0,'memcpy'),
             imported_slot(data,secs,rels,0x576e1f8,'memset')]
    helper_slots=[]
    for slot,target in ((0x576dfd8,0x54c06b0),(0x576e010,0x54c8cb0),(0x576e020,0x1345e2a),(0x5773f40,0x4e8fcb0)):
        helper_slots.append(relative_slot(data,secs,rels,slot,target))
    lanes=[]
    for name in ('early','late'):
        a=HANDLERS[name]; f=selected[a];code=read(data,secs,a,f['end']-a,True)
        lanes.extend(lane_rows(code,a,0x39d if name=='early' else 0x3c5))
    targets=[];base=0x59a784
    expected_targets=(0x37f95b3,0x37f95fe,0x37f95d0,0x37f95e2)
    for i in range(4):
        raw=read(data,secs,base+i*4,4); target=base+struct.unpack('<i',raw)[0]
        require(target == expected_targets[i] and selected[0x37f9580]['start']<=target<selected[0x37f9580]['end'],'action table changed or outside FDE')
        targets.append({'index':i,'entry_va':hex(base+i*4),'bytes':raw.hex(),'target':hex(target)})
    costs=read_costs(data,secs)
    synthetic=cases(costs)
    copy_constants=input_copy_constants(data,secs)
    copy_cases=input_copy_cases(copy_constants)
    counts={'selected_fdes':len(functions),'selected_code_bytes':sum(x[2] for x in functions),
            'reviewed_windows':len(windows),'selected_transfers':len(edges),
            'opcode_relocations':len(tables),'opcode_tables':len(TABLES),
            'descriptor_relocations':len(wrappers),'symbolic_imports':len(imports),
            'helper_relocations':len(helper_slots),'address_lanes':len(lanes),
            'lsdas':len(exception_tables),'lsda_call_sites':sum(len(x['entries']) for x in exception_tables),
            'synthetic_cases':len(synthetic),'input_copy_cases':len(copy_cases),
            'action_table_entries':len(targets)}
    return {'summary':{'target_sha256':DIGEST,'counts':counts,
                       'coordinate_system':'linked ELF VA before load bias; end addresses exclusive',
                       'limitations':'Selected fixed patterns and FDE extents are not a full CFG, live execution, or component coverage.'},
            'functions':functions,'unwind':unwind,'bodies':bodies,'exceptions':exception_tables,
            'windows':windows,'edges':edges,'tables':tables,'wrappers':wrappers,'imports':imports,'helper_slots':helper_slots,'comparison':comparison,
            'lanes':lanes,'payload':payload,'action_table':targets,'costs':costs,'synthetic_cases':synthetic,
            'copy_constants':copy_constants,'copy_cases':copy_cases}


def tsv(header,rows):
    out=io.StringIO(newline='');writer=csv.writer(out,delimiter='\t',lineterminator='\n')
    writer.writerow(header);writer.writerows(rows);return out.getvalue()


def render(d):
    j=lambda x:json.dumps(x,indent=2,sort_keys=True)+'\n'
    return {'summary.json':j(d['summary']),'bodies.json':j(d['bodies']),'unwind.json':j(d['unwind']),
            'exceptions.json':j(d['exceptions']),'wrappers.json':j(d['wrappers']),
            'imports.json':j(d['imports']),'helper-relocations.json':j(d['helper_slots']),
            'adapter-comparison.json':j(d['comparison']),
            'action-table.json':j(d['action_table']),'payload-flow.json':j(d['payload']),'cost-constants.json':j(d['costs']),'synthetic-cases.json':j(d['synthetic_cases']),
            'input-copy-constants.json':j(d['copy_constants']),'input-copy-cases.json':j(d['copy_cases']),
            'functions.tsv':tsv(('start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','sha256','role_inferred'),d['functions']),
            'windows.tsv':tsv(('name','function_va','site_va','file_offset','bytes'),d['windows']),
            'edges.tsv':tsv(('name','function_va','site_va','bytes','target_va'),d['edges']),
            'opcode-tables.tsv':tsv(('table','base_va','opcode','slot_va','slot_file_offset','addend_va','rela_file_offset','rela_bytes'),d['tables']),
            'address-lanes.tsv':tsv(('handler_va','output_lane','stack_byte','source_site','host_site','frame_site','frame_offset'),d['lanes'])}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    d=collect(TARGET.read_bytes());outputs=render(d);args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(outputs.items()):
        (args.out/name).write_text(content,encoding='utf-8',newline='\n')
    print(json.dumps(d['summary'],sort_keys=True))


if __name__=='__main__':
    try: main()
    except (ValueError,OSError,struct.error) as e:
        print('re21_inspected_call94: '+str(e),file=sys.stderr);sys.exit(1)
