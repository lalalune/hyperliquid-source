#!/usr/bin/env python3
"""Bind a node 94 fill-user set insertion and its split helper to ELF bytes.

Static only: the target is read, never executed. Observations are selected
instruction encodings, not a complete x86 decoder or a whole-program census.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# The previously studied context entry is included only for byte comparison.
FUNCTIONS = (
    ('comparison_entry', 0x492d640, 0x492d863, 'e1905dda9e6b134e9119653d5a276c39c37a29a92e7f5171dba9393c9632a1bd'),
    ('split_helper', 0x41fb1d0, 0x41fbb7a, '52feab9ccac060ee6ce14677ce824aab19b17e0f3d8d0662dc03b75c32c02d51'),
    ('prior_fill_entry_context', 0x4941fe0, 0x4942203, 'da154e58fb20375269a37af8cf8f2518e7aa974e44e98c6e0574d006731422b6'),
)
MASKS = (0x30, 0x170, 0x185, 0x206, 0x20d, 0x214, 0x21f)
# Each selected branch is checked for both its x86 condition and destination.
BRANCHES = (
    ('empty_root',0x492d65a,'84',0x492d70b),
    ('search_end',0x492d6a8,'74',0x492d6e0),
    ('search_continue',0x492d6cf,'74',0x492d6a0),
    ('duplicate',0x492d6d6,'74',0x492d704),
    ('leaf_reached',0x492d6ed,'82',0x492d830),
    ('new_root',0x492d761,'74',0x492d7bb),
    ('first_allocation_failed',0x492d7cc,'74',0x492d83a),
    ('first_count_invalid',0x492d7f4,'73',0x492d84a),
    ('leaf_full',0x41fb1f5,'73',0x41fb26f),
    ('leaf_no_shift',0x41fb206,'77',0x41fb245),
    ('leaf_index_ge_5',0x41fb284,'73',0x41fb295),
    ('leaf_index_eq_5',0x41fb295,'74',0x41fb2b0),
    ('leaf_index_ne_6',0x41fb29b,'75',0x41fb2b9),
    ('leaf_alloc_failed',0x41fb2dc,'84',0x41fbacf),
    ('leaf_right_count_invalid',0x41fb32a,'83',0x41fbab9),
    ('leaf_shift_not_needed',0x41fb3ac,'76',0x41fb3cb),
    ('leaf_split_at_root',0x41fb407,'84',0x41fb7af),
    ('next_split_at_root',0x41fb44c,'84',0x41fb7b2),
    ('height_disagreement',0x41fb455,'85',0x41fba75),
    ('parent_not_full',0x41fb47c,'82',0x41fb890),
    ('parent_index_ge_5',0x41fb48b,'73',0x41fb4a0),
    ('parent_index_eq_5',0x41fb4a4,'74',0x41fb4be),
    ('parent_index_ne_6',0x41fb4a9,'75',0x41fb4ca),
    ('internal_alloc_failed',0x41fb4ee,'84',0x41fba8e),
    ('internal_right_count_invalid',0x41fb543,'83',0x41fba40),
    ('internal_child_count_invalid',0x41fb5a0,'83',0x41fba59),
    ('internal_copy_length_mismatch',0x41fb5ac,'85',0x41fba9e),
    ('no_parent_shift',0x41fb64a,'86',0x41fb6d0),
    ('repair_done',0x41fb702,'83',0x41fb420),
    ('old_root_missing',0x41fb7c6,'84',0x41fbadf),
    ('new_root_alloc_failed',0x41fb7de,'84',0x41fbaec),
    ('root_height_wrap',0x41fb804,'84',0x41fbafe),
    ('published_height_mismatch',0x41fb823,'85',0x41fbb0d),
    ('new_root_count_invalid',0x41fb835,'83',0x41fbb26),
    ('room_parent_no_shift',0x41fb8ae,'73',0x41fb920),
    ('context_fill_flag',0x4312383,'75',0x43123af),
    ('context_rest_flag',0x43130cd,'75',0x43130e6),
)
# Entries are instruction start, encoding kind, expected resolved VA.
CALLS = (
    ('fill_pair_producer',0x4312339,'e8',0x4a07df0),
    ('fill_user_0',0x4312395,'e8',0x4941fe0), ('fill_user_1',0x43123aa,'e8',0x4941fe0),
    ('rest_user',0x43130e1,'e8',0x4941fe0), ('selected_to_split',0x492d7af,'e8',0x41fb1d0),
    ('context_to_split',0x494214f,'e8',0x41fb1d0),
    ('entry_allocate',0x492d7c3,'ff15',0x576dfd8), ('entry_alloc_error',0x492d844,'ff15',0x576e020),
    ('leaf_shift',0x41fb234,'ff15',0x576e0e0), ('leaf_allocate',0x41fb2d3,'ff15',0x576dfd8),
    ('leaf_copy',0x41fb356,'ff15',0x576dfe0), ('leaf_shift_split',0x41fb3c5,'ff15',0x576e0e0),
    ('internal_allocate',0x41fb4e5,'ff15',0x576dfd8), ('internal_key_copy',0x41fb568,'ff15',0x576dfe0),
    ('internal_edge_copy',0x41fb5d2,'ff15',0x576dfe0), ('parent_key_shift',0x41fb67a,'ff15',0x576e0e0),
    ('parent_edge_shift',0x41fb6b4,'ff15',0x576e0e0), ('root_allocate',0x41fb7d5,'ff15',0x576dfd8),
    ('root_height_error',0x41fbb05,'ff15',0x576e470), ('cleanup_release',0x41fbb6c,'ff15',0x576e010),
    ('resume_unwind_plt',0x41fbb75,'e8',0x5660110),
)
# Selected complete instruction windows; byte strings are human-reviewed pins.
WINDOWS = (
 ('fill_pair_projection',0x431231e,'488dbc24a8090000488d9424200300004889d6488d8c2478010000e8b25a6f008b8424b8090000898424900800000f108424a80900000f29842480080000488d8424bc090000f30f6f00660f7f8424a00800008b4010898424b0080000'),
 ('fill_set_handoff',0x4312374,'898424b008000083bc240001000001752a488dbc2408010000488db42480080000e846fc6200488dbc2408010000488db424a0080000e831fc6200488b442440'),
 ('rest_set_handoff',0x43130b0,'ffe87a0a290031db4889c7488b742478e8ab97230083bc247002000001751731db488db42400010000488dbc2478020000e8faee6200b001c7442420000000004c8b742418'),
 ('entry_search',0x492d66d,'4c8b2d140ee400410fb787e600000048894424208d048500000000488d1c8048f7db48c7c5ffffffff41bc080000000f1f40004a8d04234883f80874364b8d3427ba14'),
 ('duplicate_or_descent',0x492d6cf,'74cf0fb6c085c0742ceb0b660f1f440000488b6c2420488b04244883e8010f823d010000488904244d8bbcefe8000000e970ffffffb001e9130100004531ff49'),
 ('split_call',0x492d7a5,'488d542460488d4c2428e81cda8cff488b742428eb5d4889fbbf'),
 ('empty_root_initialization',0x492d7bb,'4889fbbfe8000000ff150f08e4004885c0746c48c7000000000066c780e6000000000048890348c74308000000000fb788e60000004883f90b73544889de8d5101668990e6000000488d0c89418b561089548818410f10060f1144880848ff4610'),
 ('leaf_capacity',0x41fb1ea,'0fb79de60000004883fb0b73784c8d7508488b5610488d4a014839d9773d488d0492'),
 ('leaf_pivot',0x41fb26f,'4c8b7e104983ff0548898c24a00000004c89642438730f4c897c241041bf0400000031dbeb3574194983ff06751c41bf05000000b30148c744241000000000eb1a31db4c897c2410eb114983c7f94c897c241041bf06000000b301'),
 ('leaf_alloc',0x41fb2ca,'4c8b6608bfe8000000ff15ff2c57014885c00f84'),
 ('parent_pivot',0x41fb482,'6683fa054c896424387313488954241841bf0400000031dbeb440f1f40004883fa05741883fa06751fb30141bf0500000048c744241800000000eb2231db48895424184989d7eb164883c2f94889542418b30141bf060000000f1f440000'),
 ('internal_alloc',0x41fb4e0,'bf48010000ff15ed2a57014885c00f849a0500004989c44989c6'),
 ('internal_edge_bounds',0x41fb590,'410fb7aee6000000488d55014883fd0c0f83b30400004529fd4139d50f85ec04000048'),
 ('child_parent_repair',0x41fb5e0,'4889c14839e84883d000498b94cee80000004c893266898ae40000004839e973'),
 ('parent_insert_publish',0x41fb6e2,'488b7424488d4d01488d45024989b4d4f00000006641898c24e60000004839c3'),
 ('root_publication_order',0x41fb7c0,'4c8b234d85e40f84130300004c8b6b08bf48010000ff15fd2757014885c00f84080300004989c748c7000000000066c780e600000000004c89a0e80000004c89e848ffc00f84f40200004d893c246641c78424e400000000004c893b488943084c39ed0f85e4'),
 ('root_key_and_child',0x41fb83b,'8d48016641898fe6000000488d14808b74243041897497180f28442420410f114497084d89b4c7f00000004d893e6641898ee40000'),
 ('cleanup_path',0x41fbb3f,'be480100004c89ff31d2ff15c12457010f0b0f0b4889c3bee8000000eb0aeb004889c3be480100004c89f731d2ff159e2457014889dfe896454601'),
)
# Calls in diagnostic arms; a landing is only a local exception-table route.
FAILURES = (
    ('internal_right_count',0x41fba4e), ('internal_child_count',0x41fba6a),
    ('height_disagreement',0x41fba88), ('internal_alloc',0x41fba98),
    ('edge_count_disagreement',0x41fbab1), ('leaf_right_count',0x41fbac7),
    ('leaf_alloc',0x41fbad9), ('old_root_missing',0x41fbae6),
    ('root_alloc',0x41fbaf6), ('root_height_wrap',0x41fbb05),
    ('published_height_mismatch',0x41fbb20), ('new_root_count',0x41fbb39),
)
LSDA_SHA256 = '23b22427d09247b1814a216cdedc45df59e0a4d887129a60c98629f1fb560cc5'
EXPECTED_RELOCATIONS = {
    0x576dfd8:(8,0,0x54c06b0,''), 0x576dfe0:(6,6,0,'memcpy'),
    0x576e010:(8,0,0x54c8cb0,''), 0x576e020:(8,0,0x1345e2a,''),
    0x576e0e0:(6,9,0,'memmove'), 0x576e108:(8,0,0x157b7f0,''),
    0x576e2e0:(8,0,0x157a6f0,''), 0x576e470:(8,0,0x157a9f0,''),
    0x576e488:(6,12,0,'memcmp'),
}
SLOTS = tuple(EXPECTED_RELOCATIONS)
LOCATIONS = {
 0x571c408:(0x1eb80d,416,46,'library/alloc/src/collections/btree/map/entry.rs'),
 0x571c420:(0x1e2434,670,9,'library/alloc/src/collections/btree/node.rs'),
 0x571c438:(0x1e2434,694,9,'library/alloc/src/collections/btree/node.rs'),
 0x571c450:(0x1e2434,698,9,'library/alloc/src/collections/btree/node.rs'),
 0x571c468:(0x1e2434,240,77,'library/alloc/src/collections/btree/node.rs'),
 0x571c4b0:(0x1e2434,1876,5,'library/alloc/src/collections/btree/node.rs'),
 0x571c4c8:(0x1e2434,1232,35,'library/alloc/src/collections/btree/node.rs'),
 0x571c4e0:(0x1e2434,1299,36,'library/alloc/src/collections/btree/node.rs'),
 0x571c4f8:(0x1e2434,1027,9,'library/alloc/src/collections/btree/node.rs'),
}
MESSAGES = (
 ('parent_edge_height',0x6ee281,'assertion failed: edge.height == self.node.height - 1'),
 ('copy_length',0x6ee259,'assertion failed: src.len() == dst.len()'),
 ('root_edge_height',0x6ee1cb,'assertion failed: edge.height == self.height - 1'),
 ('node_capacity',0x20ca60,'assertion failed: idx < CAPACITY'),
)


def checked_image(data, expected=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('target SHA-256 mismatch')
    return digest


def va_offset(secs, va, size):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or length')
    matches = [s for s in secs if s['type'] != 8 and s['address'] <= va and
               va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('address does not have one file-backed section')
    s = matches[0]
    return s['offset'] + va - s['address']


def read_va(data, secs, va, size):
    off = va_offset(secs, va, size)
    if off + size > len(data):
        raise ValueError('file range outside image')
    return data[off:off + size]



def verify_window(data,secs,site,expected):
    wanted=bytes.fromhex(expected)
    actual=read_va(data,secs,site,len(wanted))
    if actual!=wanted:
        raise ValueError('window mismatch')
    return actual


def branch(data, secs, site, expected_condition, expected_target):
    first = read_va(data, secs, site, 2)
    op = int(expected_condition, 16)
    if 0x70 <= op <= 0x7f and first[0] == op:
        size, delta = 2, struct.unpack('<b', first[1:])[0]
    elif 0x80 <= op <= 0x8f and first == bytes((0x0f,op)):
        size, delta = 6, struct.unpack('<i', read_va(data,secs,site+2,4))[0]
    else:
        raise ValueError('branch opcode mismatch')
    target = site + size + delta
    if target != expected_target:
        raise ValueError('branch destination mismatch')
    return read_va(data,secs,site,size).hex(), target


def call(data,secs,site,kind,expected_target):
    prefix = bytes.fromhex(kind)
    ins = read_va(data,secs,site,len(prefix)+4)
    if not ins.startswith(prefix):
        raise ValueError('call opcode mismatch')
    target = site + len(ins) + struct.unpack('<i',ins[-4:])[0]
    if target != expected_target:
        raise ValueError('call destination mismatch')
    return ins.hex(), target


def pinned_functions(data,secs):
    _, fdes = eh_frame_records(data,secs)
    out=[]
    for label,start,end,digest in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('FDE extent mismatch or duplicate')
        code=read_va(data,secs,start,end-start)
        if hashlib.sha256(code).hexdigest() != digest:
            raise ValueError('function bytes mismatch')
        out.append((label,matches[0],code))
    return out


def compare_entries(a,b):
    if len(a)!=len(b):
        raise ValueError('entry lengths differ')
    left,right=bytearray(a),bytearray(b)
    rows=[]
    for off in MASKS:
        x=0x492d640+off+4+struct.unpack_from('<i',a,off)[0]
        y=0x4941fe0+off+4+struct.unpack_from('<i',b,off)[0]
        if x != y:
            raise ValueError('corresponding PC-relative operands differ')
        rows.append((off,a[off:off+4].hex(),b[off:off+4].hex(),x,y))
        left[off:off+4]=b'\0'*4
        right[off:off+4]=b'\0'*4
    if left != right:
        raise ValueError('unmasked entry bytes differ')
    return rows,hashlib.sha256(left).hexdigest()


def split_parameters(data,secs):
    # Extract the immediates from the selected leaf and parent encodings.
    specs=(
      ('capacity',0x41fb1f1,'4883fb',1,False),
      ('first_boundary',0x41fb273,'4983ff',1,False),
      ('second_boundary',0x41fb297,'4983ff',1,False),
      ('low_pivot',0x41fb28b,'41bf',4,False),
      ('middle_pivot',0x41fb29d,'41bf',4,False),
      ('high_pivot',0x41fb2c2,'41bf',4,False),
      ('right_adjust',0x41fb2b9,'4983c7',1,True),
      ('parent_first_boundary',0x41fb482,'6683fa',1,False),
      ('parent_second_boundary',0x41fb4a6,'83fa',1,False),
      ('parent_low_pivot',0x41fb492,'41bf',4,False),
      ('parent_middle_pivot',0x41fb4ad,'41bf',4,False),
      ('parent_high_pivot',0x41fb4d5,'41bf',4,False),
      ('parent_right_adjust',0x41fb4ca,'4883c2',1,True),
    )
    rows=[]
    for name,site,prefix,width,signed in specs:
        prefix_bytes=bytes.fromhex(prefix)
        raw=read_va(data,secs,site,len(prefix_bytes)+width)
        if not raw.startswith(prefix_bytes):
            raise ValueError('split immediate opcode mismatch')
        value=int.from_bytes(raw[len(prefix_bytes):],'little',signed=signed)
        rows.append((name,site,raw.hex(),value))
    p={name:value for name,_,_,value in rows}
    expected={'capacity':11,'first_boundary':5,'second_boundary':6,
              'low_pivot':4,'middle_pivot':5,'high_pivot':6,'right_adjust':-7}
    if any(p[name]!=value or (name!='capacity' and p['parent_'+name]!=value)
           for name,value in expected.items()):
        raise ValueError('split immediate mismatch')
    return p,rows


def split_case(pos,params):
    if not isinstance(pos,int) or not 0 <= pos <= params['capacity']:
        raise ValueError('invalid insertion position')
    if pos < params['first_boundary']:
        return params['low_pivot'],'left',pos
    if pos == params['first_boundary']:
        return params['middle_pivot'],'left',pos
    if pos == params['second_boundary']:
        return params['middle_pivot'],'right',0
    return params['high_pivot'],'right',pos+params['right_adjust']


def exception_table(data,secs,fde):
    tables=[s for s in secs if s['name']=='.gcc_except_table' and s['type']!=8]
    if len(tables)!=1 or fde['lsda'] is None:
        raise ValueError('missing exception table')
    section=tables[0]
    va=fde['lsda']
    if not section['address'] <= va < section['address']+section['size']:
        raise ValueError('exception table outside section')
    offset=va_offset(secs,va,1)
    raw=data[offset:section['offset']+section['size']]
    if raw[:3]!=b'\xff\xff\x01':
        raise ValueError('unsupported exception-table encoding')
    length,pos=uleb(raw,3,len(raw))
    end=pos+length
    if end>len(raw) or hashlib.sha256(raw[:end]).hexdigest()!=LSDA_SHA256:
        raise ValueError('exception call-site bytes mismatch')
    entries=[]
    previous=0
    while pos<end:
        record=pos
        start,pos=uleb(raw,pos,end)
        size,pos=uleb(raw,pos,end)
        landing,pos=uleb(raw,pos,end)
        action,pos=uleb(raw,pos,end)
        if not size or start<previous or start+size>fde['end']-fde['start']:
            raise ValueError('invalid exception call-site interval')
        if landing and landing>=fde['end']-fde['start']:
            raise ValueError('invalid exception landing')
        previous=start+size
        entries.append((va+record,fde['start']+start,fde['start']+start+size,
                        fde['start']+landing if landing else None,action,raw[record:pos].hex()))
    if pos!=end:
        raise ValueError('exception table length mismatch')
    return entries


def failure_rows(entries):
    rows=[]
    for label,site in FAILURES:
        matches=[e for e in entries if e[1]<=site<e[2]]
        if len(matches)!=1:
            raise ValueError('failure site has no unique exception row')
        row=matches[0]
        rows.append((label,site,row[1],row[2],row[3],row[4]))
    return rows


def relocation_rows(data,secs):
    rela=[s for s in secs if s['name']=='.rela.dyn' and s['type']==4]
    dynsym=[s for s in secs if s['name']=='.dynsym' and s['type']!=8]
    dynstr=[s for s in secs if s['name']=='.dynstr' and s['type']!=8]
    if len(rela)!=1 or len(dynsym)!=1 or len(dynstr)!=1 or rela[0]['size']%24:
        raise ValueError('unexpected relocation sections')
    found={}
    for off in range(rela[0]['offset'],rela[0]['offset']+rela[0]['size'],24):
        addr,info,addend=struct.unpack_from('<QQq',data,off)
        if addr not in SLOTS:
            continue
        if addr in found:
            raise ValueError('duplicate relocation')
        typ,sym=info & 0xffffffff,info >> 32
        symbol=''
        if sym:
            symoff=dynsym[0]['offset']+sym*24
            if symoff+24>dynsym[0]['offset']+dynsym[0]['size']:
                raise ValueError('dynamic symbol outside section')
            nameoff=struct.unpack_from('<I',data,symoff)[0]
            if nameoff>=dynstr[0]['size']:
                raise ValueError('dynamic symbol name outside section')
            pos=dynstr[0]['offset']+nameoff
            end=data.find(b'\0',pos,dynstr[0]['offset']+dynstr[0]['size'])
            if end<0:
                raise ValueError('unterminated symbol')
            symbol=data[pos:end].decode('ascii')
        found[addr]=(typ,sym,addend,symbol)
    if set(found)!=set(SLOTS):
        raise ValueError('missing relocation')
    if found!=EXPECTED_RELOCATIONS:
        raise ValueError('relocation data mismatch')
    return [(a,*found[a]) for a in sorted(found)]



def diagnostic_rows(data,secs):
    rela=[s for s in secs if s['name']=='.rela.dyn' and s['type']==4]
    if len(rela)!=1 or rela[0]['size']%24:
        raise ValueError('invalid relocation section')
    targets={}
    for off in range(rela[0]['offset'],rela[0]['offset']+rela[0]['size'],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in LOCATIONS:
            if slot in targets or info!=8:
                raise ValueError('unexpected Location relocation')
            targets[slot]=addend
    if set(targets)!=set(LOCATIONS):
        raise ValueError('missing Location relocation')
    rows=[]
    for slot in sorted(LOCATIONS):
        pointer,length,line,col=struct.unpack('<QQII',read_va(data,secs,slot,24))
        target=targets[slot]
        if pointer!=0 or not 0<length<=256:
            raise ValueError('unsupported Location representation')
        full_path=read_va(data,secs,target,length).decode('ascii')
        if 'library/' not in full_path:
            raise ValueError('unexpected Location path')
        suffix='library/'+full_path.split('library/',1)[1]
        if (target,line,col,suffix)!=LOCATIONS[slot]:
            raise ValueError('Location mismatch')
        rows.append((slot,target,length,line,col,suffix))
    messages=[]
    for label,va,expected in MESSAGES:
        raw=read_va(data,secs,va,len(expected))
        if raw!=expected.encode('ascii'):
            raise ValueError('diagnostic text mismatch')
        messages.append((label,va,raw.decode('ascii')))
    return rows,messages


def write_tsv(out,name,header,rows):
    with (out/name).open('w',encoding='utf-8',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def collect(data,out):
    digest=checked_image(data)
    secs=sections(data)
    functions=pinned_functions(data,secs)
    selected,split,context=(x[2] for x in functions)
    comparison,normalized=compare_entries(selected,context)
    branches=[]
    for name,site,op,dst in BRANCHES:
        raw,target=branch(data,secs,site,op,dst)
        branches.append((name,hex(site),raw,hex(target)))
    calls=[]
    for name,site,kind,dst in CALLS:
        raw,target=call(data,secs,site,kind,dst)
        calls.append((name,hex(site),kind,raw,hex(target)))
    windows=[]
    for name,site,expected in WINDOWS:
        actual=verify_window(data,secs,site,expected)
        windows.append((name,hex(site),hex(va_offset(secs,site,len(actual))),actual.hex()))
    relocs=relocation_rows(data,secs)
    exceptions=exception_table(data,secs,functions[1][1])
    failures=failure_rows(exceptions)
    locations,messages=diagnostic_rows(data,secs)
    params,parameter_rows=split_parameters(data,secs)
    out.mkdir(parents=True,exist_ok=True)
    write_tsv(out,'functions.tsv',('role','start_va','end_va','file_offset','fde_va','cie_va','lsda_va','bytes','sha256'),
      [(label,hex(f['start']),hex(f['end']),hex(va_offset(secs,f['start'],len(code))),hex(f['fde']),hex(f['cie']),hex(f['lsda']) if f['lsda'] is not None else '',len(code),hashlib.sha256(code).hexdigest()) for label,f,code in functions])
    write_tsv(out,'branches.tsv',('observation','site_va','instruction_hex','target_va'),branches)
    write_tsv(out,'calls.tsv',('observation','site_va','encoding','instruction_hex','target_or_slot_va'),calls)
    write_tsv(out,'windows.tsv',('observation','start_va','file_offset','bytes_hex'),windows)
    write_tsv(out,'operand-comparison.tsv',('relative_offset','selected_le','context_le','selected_target_va','context_target_va'),
              [(hex(o),a,b,hex(x),hex(y)) for o,a,b,x,y in comparison])
    write_tsv(out,'comparison-bytes.tsv',('role','sha256','bytes_hex'),
              [(functions[i][0],hashlib.sha256(code).hexdigest(),code.hex())
               for i,code in ((0,selected),(2,context))])
    masked_offsets={off+i for off in MASKS for i in range(4)}
    write_tsv(out,'comparison-differences.tsv',('relative_offset','selected_byte','context_byte','masked'),
              [(hex(i),f'{a:02x}',f'{b:02x}',str(i in masked_offsets).lower())
               for i,(a,b) in enumerate(zip(selected,context)) if a!=b])
    write_tsv(out,'exception-sites.tsv',('record_va','start_va','end_va','landing_va','action','bytes_hex'),
              [(hex(record),hex(start),hex(end),hex(landing) if landing is not None else '',action,raw)
               for record,start,end,landing,action,raw in exceptions])
    write_tsv(out,'failures.tsv',('reason','call_site_va','covered_start_va','covered_end_va','local_landing_va','action'),
              [(name,hex(site),hex(start),hex(end),hex(landing) if landing is not None else '',action)
               for name,site,start,end,landing,action in failures])
    write_tsv(out,'locations.tsv',('descriptor_va','path_va','path_length','line','column','path_suffix'),
              [(hex(slot),hex(target),length,line,col,path) for slot,target,length,line,col,path in locations])
    write_tsv(out,'diagnostics.tsv',('observation','text_va','text'),
              [(name,hex(va),text) for name,va,text in messages])
    write_tsv(out,'relocations.tsv',('slot_va','type','symbol_index','addend','dynamic_symbol'),
              [(hex(a),t,s,hex(v),n) for a,t,s,v,n in relocs])
    write_tsv(out,'split-parameters.tsv',('observation','site_va','instruction_hex','immediate'),
              [(name,hex(site),raw,value) for name,site,raw,value in parameter_rows])
    split_rows=[]
    for pos in range(params['capacity']+1):
        pivot,side,idx=split_case(pos,params)
        split_rows.append((pos,pivot,side,idx))
    write_tsv(out,'split-cases.tsv',('insertion_position','old_pivot_index','destination','destination_index'),split_rows)
    lsda_start=functions[1][1]['lsda']
    lsda_end=exceptions[-1][0]+len(bytes.fromhex(exceptions[-1][-1]))
    lsda_bytes=read_va(data,secs,lsda_start,lsda_end-lsda_start)
    summary={'exception_table':{'va':hex(lsda_start),'raw_hex':lsda_bytes.hex(),
                                'sha256':hashlib.sha256(lsda_bytes).hexdigest()},
      'target_sha256':digest,'coordinates':'linked ELF virtual addresses; FDE ends exclusive',
      'selected_functions':2,'context_functions':1,'selected_branches':len(branches),'selected_calls':len(calls),
      'selected_windows':len(windows),'relocations':len(relocs),'split_cases':len(split_rows),
      'exception_call_site_rows':len(exceptions),'failure_calls':len(failures),
      'location_records':len(locations),'diagnostic_texts':len(messages),
      'split_parameter_encodings':len(parameter_rows),
      'comparison':{'bytes':len(selected),'raw_equal':selected==context,
                    'raw_differing_bytes':sum(a!=b for a,b in zip(selected,context)),
                    'masked_operands':len(MASKS),
                    'masked_bytes':4*len(MASKS),'masked_equal':True,'masked_sha256':normalized},
      'limits':'Selected bytes and static projections only; no captured-node execution, helper closure, ABI or rollback proof.'}
    (out/'evidence.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    collect(TARGET.read_bytes(),args.out)

if __name__=='__main__':
    main()
