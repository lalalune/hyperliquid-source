#!/usr/bin/env python3
"""Extract node 94 request-budget state-root serialization evidence."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Selected FDEs, not a census or a claim that their CFGs are complete.
FUNCTIONS = (
 ('collection',0x20296f0,0x20297db,'b7bec97077dfc167d033f311f393cbe23205c27062a1477e49a6911641b058be'),
 ('collect_entries',0x256dd10,0x256df46,'3b864bb9d501bfdd141a20ec6a67a71c63c151a1e18592328de88b68a54a8177'),
 ('sort_entries',0x1fe87b0,0x1fe8fc5,'3db1e71ff37a7adddd3d21261efa7deb3953707af88e89cc63221f48a65cd067'),
 ('sequence_writer',0x1e4a430,0x1e4a6bb,'5f7e8938b4805d9bd674649fa907a490f507f99e5843c0b13b1b6991baebe5c9'),
 ('pair_writer',0x1dd8490,0x1dd8a2c,'4bf36f4cb0f51edf42ab3bbd7160c74132fc55339943f41694b935e43551dda2'),
 ('value_writer',0x275ce60,0x275d36c,'6d08b6b7e098d6e9f4e1d586579e56ff3e997c5b5c872eeec6d66664db764646'),
 ('enum_field_writer',0x27b18c0,0x27b191c,'8c92310f6bcf583a88dadc6a1f6227d3cebba10539ba31e545f625124db17909'),
 ('value_reader',0x1956bf0,0x1958628,'9c55be8d59a640f61d771c1d84cd2057768766ef957546dee667955141d7bd4c'),
 ('field_classifier',0x26bf820,0x26bf8b2,'509a01974cc65512a2d2a6563e77eaa572adf38861614c99ae8f4dac2ea1dd0a'),
 ('enum_writer',0x28e7990,0x28e7a0f,'e6c16007d9cdea839c876572c8ddc698ad27e640f5deef1dff2ca48228a0775c'),
)

WINDOWS = (
 ('collection_all',0x20296ff,0x202977d),
 ('sort_small_entry',0x1fe87cc,0x1fe884c),
 ('sort_small_shift',0x1fe884c,0x1fe88d4),
 ('sort_large_arms',0x1fe88d4,0x1fe892a),
 ('sequence_setup',0x1e4a449,0x1e4a4a7),
 ('sequence_loop',0x1e4a5e0,0x1e4a63a),
 ('pair_setup',0x1dd84aa,0x1dd8569),
 ('pair_value',0x1dd8775,0x1dd8835),
 ('value_count_and_header',0x275ce79,0x275cf72),
 ('value_first_two',0x275cf72,0x275d004),
 ('value_signed',0x275d004,0x275d09b),
 ('value_time',0x275d09b,0x275d123),
 ('value_no_flag',0x275d123,0x275d1ce),
 ('value_reserved_and_enum',0x275d1ce,0x275d24d),
 ('value_errors',0x275d24d,0x275d2d5),
 ('value_epoch_error',0x275d35f,0x275d36c),
 ('enum_field_all',0x27b18c0,0x27b191c),
 ('enum_dispatch_and_write',0x28e7990,0x28e7a0f),
 ('reader_classifier_call',0x1957ec8,0x1957ee4),
 ('reader_dispatch',0x1958111,0x19583d2),
 ('reader_duplicate_errors',0x1958565,0x19585fc),
 ('field_classifier',0x26bf820,0x26bf8b2),
)

CALLS = (
 ('collect',0x2029740,0x256dd10),('sort',0x2029755,0x1fe87b0),
 ('sequence',0x2029778,0x1e4a430),('array_header',0x1e4a497,0x25a9bd0),
 ('pair_first',0x1e4a4ef,0x1dd8490),('pair_loop',0x1e4a61e,0x1dd8490),
 ('pair_key',0x1dd8555,0x1e0d0a0),('pair_value',0x1dd8820,0x275ce60),
 ('value_map_header',0x275cf26,0x25a8f80),('value_array_header',0x275cf62,0x25a9bd0),
 ('ln_value',0x275cfa7,0x25ac0d0),('R_value',0x275cff0,0x25ac0d0),
 ('C_value',0x275d039,0x25aaf40),('P_value',0x275d087,0x25aaf40),
 ('time_value',0x275d10e,0x1dfca40),('no_value',0x275d158,0x25ac0d0),
 ('r_value',0x275d208,0x25ac0d0),('enum_field',0x275d22e,0x27b18c0),
 ('enum_string',0x28e79ea,0x25aa7f0),
 ('reader_from_map',0x2635305,0x1956bf0),('reader_from_pair',0x18e0796,0x1956bf0),
 ('reader_classifier',0x1957ed7,0x26bf820),('reader_skip_unknown',0x19581cc,0x19682d0),
 ('reader_duplicate_error',0x19585f7,0x1704040),('closure_writer',0x2819b20,0x20296f0),
)

BRANCHES = (
 ('small_sort_limit',0x1fe87d5),('small_sort_short',0x1fe87df),('sort_compare',0x1fe884a),
 ('sequence_empty',0x1e4a5ed),('sequence_child_failure',0x1e4a62b),('sequence_next',0x1e4a638),
 ('pair_key_failure',0x1dd8563),('pair_value_failure',0x1dd882f),
 ('epoch_unavailable',0x275ce95),('header_mode',0x275cf1c),('map_header_ok',0x275cf34),
 ('array_header_error',0x275cf70),('skip_ln',0x275cf75),('ln_name_error',0x275cf96),
 ('ln_value_error',0x275cfb5),('skip_R',0x275cfbe),('R_name_error',0x275cfdf),
 ('R_value_error',0x275cffe),('skip_C',0x275d007),('C_name_error',0x275d028),
 ('C_value_error',0x275d047),('skip_P',0x275d053),('P_name_error',0x275d074),
 ('P_value_error',0x275d095),('epoch_second_unavailable',0x275d0a8),('skip_t',0x275d0c7),
 ('time_name_error',0x275d0e8),('time_value_error',0x275d11d),('skip_no',0x275d126),
 ('no_name_error',0x275d147),('no_value_error',0x275d166),('skip_f',0x275d171),
 ('f_name_error',0x275d192),('skip_r',0x275d1d4),('r_name_error',0x275d1f5),
 ('r_value_error',0x275d216),('skip_a',0x275d21d),('enum_value_error',0x275d23d),
 ('reader_duplicate_ln',0x195813c),('reader_duplicate_R',0x19582e3),
 ('reader_duplicate_C',0x1958202),('reader_duplicate_P',0x195824d),
 ('reader_duplicate_t',0x1958183),('reader_duplicate_no',0x195832e),
 ('reader_duplicate_f',0x1958371),('reader_duplicate_r',0x1958298),
 ('reader_duplicate_a',0x19583a3),('reader_skip_success',0x19581d6),
 ('enum_name_error',0x27b18ef),('enum_string_ok',0x28e79f3),
)

# Field source offsets are relative to the 0x40-byte value, not the hash bucket.
FIELD_SITES = (
 ('ln',0x275cf7e,0x275cf85,0x00,'nonzero','unsigned'),
 ('R', 0x275cfc7,0x275cfce,0x08,'nonzero','unsigned'),
 ('C', 0x275d010,0x275d017,0x10,'nonzero','signed'),
 ('P', 0x275d05c,0x275d063,0x18,'nonzero','signed'),
 ('t', 0x275d0d0,0x275d0d7,0x30,'not_epoch','datetime helper'),
 ('no',0x275d12f,0x275d136,0x20,'nonzero','unsigned'),
 ('f', 0x275d17a,0x275d181,0x3d,'true','boolean'),
 ('r', 0x275d1dd,0x275d1e4,0x28,'nonzero','unsigned'),
 ('a', 0x27b18d1,0x27b18d8,0x3c,'nonzero','enum'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data, expected=DIGEST):
    if digest(data) != expected:
        raise ValueError('node 94 digest mismatch')


def va_bytes(data, secs, va, size):
    if size <= 0 or va < 0:
        raise ValueError('invalid range')
    hits = [s for s in secs if s['type'] != 8 and s['size'] and
            s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('VA is not uniquely file-backed')
    s = hits[0]
    start = s['offset'] + va - s['address']
    result = data[start:start + size]
    if len(result) != size:
        raise ValueError('truncated mapped range')
    return result


def expect(data, secs, va, pattern):
    observed = va_bytes(data, secs, va, len(pattern))
    if observed != pattern:
        raise ValueError('unexpected bytes at ' + hex(va))
    return observed


def direct_call(data, secs, va):
    raw = va_bytes(data, secs, va, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected direct call')
    return va + 5 + struct.unpack_from('<i', raw, 1)[0]


def checked_call(data, secs, va, target):
    actual = direct_call(data, secs, va)
    if actual != target:
        raise ValueError('direct call destination changed')
    return actual


def branch(data, secs, va):
    head = va_bytes(data, secs, va, 2)
    if 0x70 <= head[0] <= 0x7f:
        length, disp, condition = 2, struct.unpack('b', head[1:])[0], head[0] & 15
    elif head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        length, disp, condition = 6, struct.unpack('<i', va_bytes(data, secs, va+2, 4))[0], head[1] & 15
    else:
        raise ValueError('expected conditional branch')
    return va + length + disp, condition, length


def rip(data, secs, va, prefix):
    raw = va_bytes(data, secs, va, len(prefix)+4)
    if not raw.startswith(prefix):
        raise ValueError('unexpected RIP-relative instruction')
    return va + len(raw) + struct.unpack_from('<i',raw,len(prefix))[0]


def immediate(data, secs, va, prefix, size):
    raw = va_bytes(data, secs, va, len(prefix)+size)
    if not raw.startswith(prefix):
        raise ValueError('unexpected immediate instruction')
    return int.from_bytes(raw[len(prefix):],'little')


def field_names(data, secs):
    rows = []
    for wanted,site,size_site,offset,predicate,kind in FIELD_SITES:
        address = rip(data,secs,site,bytes.fromhex('488d35'))
        length = immediate(data,secs,size_site,b'\xba',4)
        if not 0 < length < 32:
            raise ValueError('unexpected field length')
        value = va_bytes(data,secs,address,length).decode('ascii')
        if value != wanted:
            raise ValueError('field name changed')
        rows.append({'name':value,'site':hex(site),'literal_va':hex(address),'length':length,
                     'value_offset':hex(offset),'presence':predicate,'writer':kind})
    return rows


def enum_rows(data, secs):
    table = rip(data,secs,0x28e79a7,bytes.fromhex('488d15'))
    if table != 0x3f5a20:
        raise ValueError('enum table changed')
    rows = []
    for tag in range(5):
        item = va_bytes(data,secs,table+tag*4,4)
        target = table + struct.unpack('<i',item)[0]
        if not 0x28e79b7 <= target <= 0x28e79db:
            raise ValueError('enum jump out of selected body')
        literal = rip(data,secs,target,bytes.fromhex('488d35'))
        value = va_bytes(data,secs,literal,1).decode('ascii')
        rows.append({'tag':tag,'table_slot':hex(table+tag*4),'displacement':item.hex(),
                     'target':hex(target),'literal_va':hex(literal),'value':value})
    if [r['value'] for r in rows] != ['e','i','d','u','p']:
        raise ValueError('enum names changed')
    return rows


def reader_tables(data, secs, fields):
    # 1-byte keys use a signed-offset jump table covering an inclusive byte range.
    base = immediate(data,secs,0x26bf849,bytes.fromhex('83c1'),1)
    if base != 0xbd:
        raise ValueError('classifier base changed')
    first = (-base) & 0xff
    limit = immediate(data,secs,0x26bf84c,bytes.fromhex('83f9'),1)
    table = rip(data,secs,0x26bf851,bytes.fromhex('488d15'))
    if (first,limit,table) != (0x43,0x31,0x3ecc48):
        raise ValueError('classifier table changed')
    single = {}
    table_rows = []
    for byte in range(256):
        target = 0x26bf83d
        displacement = ''
        if first <= byte <= first+limit:
            raw = va_bytes(data,secs,table+(byte-first)*4,4)
            displacement = raw.hex()
            target = table+struct.unpack('<i',raw)[0]
        if not 0x26bf83d <= target < 0x26bf8b2:
            raise ValueError('classifier jump outside body')
        op = va_bytes(data,secs,target,2)
        if op[0] != 0xb1:
            raise ValueError('unexpected classifier case')
        tag = op[1]
        single[byte] = tag
        table_rows.append({'byte':byte,'tag':tag,'target':hex(target),'displacement':displacement})
    two = {}
    for site,jump in ((0x26bf82f,0x26bf834),(0x26bf836,0x26bf83b)):
        raw = va_bytes(data,secs,site,5)
        if raw[:3] != bytes.fromhex('66813e'):
            raise ValueError('classifier word compare changed')
        target,cc,_ = branch(data,secs,jump)
        if cc != 4 or not 0x26bf820 <= target < 0x26bf8b2:
            raise ValueError('classifier word branch changed')
        op = va_bytes(data,secs,target,2)
        tag = 0 if op == bytes.fromhex('31c9') else op[1] if op[0] == 0xb1 else -1
        if tag < 0:
            raise ValueError('classifier tag changed')
        two[raw[3:]] = tag
    wanted = {f['name'].encode():i for i,f in enumerate(fields)}
    if {bytes([k]):v for k,v in single.items() if v != 9} | two != wanted:
        raise ValueError('reader and writer field tables differ')
    dispatch = rip(data,secs,0x1958123,bytes.fromhex('488d0d'))
    if dispatch != 0x35ccb8:
        raise ValueError('reader dispatch table changed')
    checks = (
        (0x1958133,0x195813c,0x1958589,0x16844a0),
        (0x19582da,0x19582e3,0x1958580,0x1684530),
        (0x19581f9,0x1958202,0x19585bb,0x1684240),
        (0x1958244,0x195824d,0x1958577,0x1684240),
        (0x195817e,0x1958183,0x19585b2,0x25a8b00),
        (0x1958325,0x195832e,0x195856e,0x1684530),
        (0x195836d,0x1958371,0x19585a9,0x1684650),
        (0x195828f,0x1958298,0x1958565,0x1684530),
        (0x195839b,0x19583a3,0x19585a0,0x16873b0),
        (0x19581bc,None,None,0x19682d0),
    )
    helper_sites = (0x195814d,0x19582f4,0x1958213,0x195825e,0x1958194,
                    0x195833f,0x1958382,0x19582a9,0x19583b4,0x19581cc)
    rows = []
    for tag,(target,duplicate_site,error,helper) in enumerate(checks):
        raw = va_bytes(data,secs,dispatch+tag*4,4)
        if dispatch+struct.unpack('<i',raw)[0] != target:
            raise ValueError('reader dispatch target changed')
        checked_call(data,secs,helper_sites[tag],helper)
        if tag < 9:
            dest,_,_ = branch(data,secs,duplicate_site)
            if dest != error:
                raise ValueError('duplicate branch changed')
            name_va = rip(data,secs,error,bytes.fromhex('488d05'))
            if va_bytes(data,secs,name_va,len(fields[tag]['name'])) != fields[tag]['name'].encode():
                raise ValueError('duplicate diagnostic field changed')
        rows.append({'tag':tag,'field':fields[tag]['name'] if tag < 9 else '<unknown>',
                     'table_slot':hex(dispatch+tag*4),'target':hex(target),
                     'duplicate_branch':hex(duplicate_site) if duplicate_site else '-',
                     'duplicate_target':hex(error) if error else '-',
                     'helper_call':hex(helper_sites[tag]),'helper':hex(helper)})
    template = rip(data,secs,0x19585e6,bytes.fromhex('488d35'))
    expect(data,secs,template,b'\x11duplicate field `')
    return single,two,table_rows,rows


def classify_field(value, single, two):
    if len(value) == 1:
        return single[value[0]]
    if len(value) == 2:
        return two.get(value,9)
    return 9


def small_sort(keys, threshold, key_size):
    """Only the inspected insertion-sort arm and exact-width keys."""
    items = list(keys)
    if len(items) >= threshold or any(len(x) != key_size for x in items):
        raise ValueError('outside small-sort domain')
    for i in range(len(items)-2,-1,-1):
        key = items[i]
        j = i
        while j+1 < len(items) and items[j+1] < key:
            items[j] = items[j+1]
            j += 1
        items[j] = key
    return items


def presence(mask, names):
    if not isinstance(mask,int) or not 0 <= mask < (1 << len(names)):
        raise ValueError('outside presence model domain')
    return [name for i,name in enumerate(names) if mask & (1 << i)]


def relocation(data, secs, slot):
    rela = next(s for s in secs if s['name'] == '.rela.dyn' and s['type'] != 8)
    if rela['size'] % 24:
        raise ValueError('invalid relocation section size')
    hits = []
    for p in range(rela['offset'],rela['offset']+rela['size'],24):
        address,info,addend = struct.unpack_from('<QQq',data,p)
        if address == slot:
            hits.append((info,addend))
    if len(hits) != 1:
        raise ValueError('relocation missing or ambiguous')
    return hits[0]


def dyn_symbol(data, secs, slot):
    info,addend = relocation(data,secs,slot)
    kind,index = info & 0xffffffff,info >> 32
    syms = next(s for s in secs if s['name']=='.dynsym' and s['type']!=8)
    strings = next(s for s in secs if s['name']=='.dynstr' and s['type']!=8)
    if index*24+24 > syms['size']:
        raise ValueError('invalid symbol index')
    offset = struct.unpack_from('<I',data,syms['offset']+index*24)[0]
    if offset >= strings['size']:
        raise ValueError('invalid symbol name')
    start = strings['offset']+offset
    end = data.find(b'\0',start,strings['offset']+strings['size'])
    if end < 0:
        raise ValueError('unterminated symbol')
    return {'slot':hex(slot),'type':kind,'symbol_index':index,
            'symbol':data[start:end].decode('ascii'),'addend':addend}


def collect(data, expected_digest=DIGEST):
    check_digest(data,expected_digest)
    secs,index = unwind_index(data)
    _,fdes = eh_frame_records(data,secs)
    indexed = {(e['start'],e['fde']) for e in index}
    starts = {}
    for fde in fdes:
        starts.setdefault(fde['start'],[]).append(fde)
    functions = []
    for label,start,end,want in FUNCTIONS:
        matches = starts.get(start,[])
        if len(matches)!=1 or matches[0]['end']!=end or (start,matches[0]['fde']) not in indexed:
            raise ValueError('selected FDE mismatch: '+label)
        raw = va_bytes(data,secs,start,end-start)
        if digest(raw)!=want:
            raise ValueError('selected body mismatch: '+label)
        functions.append({'label':label,'start':hex(start),'end_exclusive':hex(end),
                          'length':len(raw),'fde':hex(matches[0]['fde']),'sha256':digest(raw)})
    windows = []
    for label,start,end in WINDOWS:
        owners = [f for f in FUNCTIONS if f[1] <= start < end <= f[2]]
        if len(owners)!=1:
            raise ValueError('window has no unique owner: '+label)
        windows.append({'label':label,'owner':owners[0][0],'start':hex(start),
                        'end_exclusive':hex(end),'bytes':va_bytes(data,secs,start,end-start).hex()})
    calls = []
    for label,site,target in CALLS:
        checked_call(data,secs,site,target)
        calls.append({'label':label,'site':hex(site),'target':hex(target),
                      'bytes':va_bytes(data,secs,site,5).hex()})
    branches = []
    for label,site in BRANCHES:
        target,cc,length = branch(data,secs,site)
        owners = [f for f in FUNCTIONS if f[1] <= site and site+length <= f[2]]
        if len(owners)!=1 or not owners[0][1] <= target < owners[0][2]:
            raise ValueError('branch outside selected FDE: '+label)
        branches.append({'label':label,'site':hex(site),'target':hex(target),
                         'condition_code':cc,'bytes':va_bytes(data,secs,site,length).hex()})
    fields = field_names(data,secs)
    enums = enum_rows(data,secs)
    single,two,classifier,dispatch = reader_tables(data,secs,fields)
    tail = va_bytes(data,secs,0x27b18fc,5)
    if tail[0] != 0xe9 or 0x27b1901 + struct.unpack_from('<i',tail,1)[0] != 0x28e7990:
        raise ValueError('enum tail jump changed')
    # Bound the source offsets and presence checks used by the field table.
    expect(data,secs,0x275ce79,bytes.fromhex('488b1e4c8b6e084c8b6610488b6e18'))
    expect(data,secs,0x275cebd,bytes.fromhex('418b6e3031e8418b5634'))
    expect(data,secs,0x275cecd,bytes.fromhex('418b7638'))
    expect(data,secs,0x275cede,bytes.fromhex('498b4620'))
    expect(data,secs,0x275ceee,bytes.fromhex('498b4628410fb64e3d'))
    expect(data,secs,0x275cf09,bytes.fromhex('410fb6463c'))
    expect(data,secs,0x275cf72,bytes.fromhex('4885db7444'))
    expect(data,secs,0x275cfbb,bytes.fromhex('4d85ed7444'))
    expect(data,secs,0x275d004,bytes.fromhex('4d85e47444'))
    expect(data,secs,0x275d04d,bytes.fromhex('48837c2448007446'))
    expect(data,secs,0x275d0b8,bytes.fromhex('31c50b6c243c0b6c2438'))
    expect(data,secs,0x275d123,bytes.fromhex('4885db7444'))
    expect(data,secs,0x275d16c,bytes.fromhex('807c243400745b'))
    expect(data,secs,0x275d1ce,bytes.fromhex('48837c2440007442'))
    expect(data,secs,0x275d218,bytes.fromhex('807c240f007420'))
    expect(data,secs,0x275d1ab,bytes.fromhex('8b4424340cc2'))
    day = immediate(data,secs,0x275ce88,b'\xbf',4)
    slot = rip(data,secs,0x275ce8d,bytes.fromhex('ff15'))
    if slot != rip(data,secs,0x275d0a0,bytes.fromhex('ff15')):
        raise ValueError('epoch helpers differ')
    if day != 719163 or slot != 0x576e890:
        raise ValueError('epoch helper changed')
    cmp_size = immediate(data,secs,0x1fe883a,b'\xba',4)
    threshold = immediate(data,secs,0x1fe87cc,bytes.fromhex('4883fe'),1)
    pair_stride = immediate(data,secs,0x1e4a631,bytes.fromhex('4883c5'),1)
    compare_slot = rip(data,secs,0x1fe8842,bytes.fromhex('ff15'))
    symbol = dyn_symbol(data,secs,compare_slot)
    if (cmp_size,threshold,pair_stride,symbol['symbol'],symbol['type'],symbol['addend']) != (20,21,16,'memcmp',6,0):
        raise ValueError('sorting comparator or layout changed')
    offset = immediate(data,secs,0x2756640,bytes.fromhex('488d8d'),4)
    table = rip(data,secs,0x2756d13,bytes.fromhex('488d0d'))
    info,thunk = relocation(data,secs,table+24)
    checked_call(data,secs,thunk+4,0x2819ad0)
    config = immediate(data,secs,0x2819b05,bytes.fromhex('c7442408'),4)
    flag = immediate(data,secs,0x2819b0d,bytes.fromhex('c644240c'),1)
    expect(data,secs,0x2756647,bytes.fromhex('48898424a0010000488908'))
    expect(data,secs,0x2756d04,bytes.fromhex('488b8c24a001000048898b00010000'))
    if (offset,table,info,config,flag) != (0x740,0x56bdc38,8,0x01000400,0):
        raise ValueError('app-hash capture binding changed')
    marker_base = immediate(data,secs,0x25a8f9f,b'\xbd',4)
    string_base = immediate(data,secs,0x25aa80b,bytes.fromhex('40b5'),1)
    expect(data,secs,0x25aa806,bytes.fromhex('83fa207314'))
    expect(data,secs,0x25ac100,bytes.fromhex('84d20f8813010000'))
    expect(data,secs,0x25ac115,bytes.fromhex('881430'))
    if (marker_base,string_base) != (0x80,0xa0):
        raise ValueError('map or string marker changed')
    mask_rows = []
    names = [r['name'] for r in fields]
    for mask in range(1 << len(names)):
        active = presence(mask,names)
        mask_rows.append({'mask':mask,'count':len(active),'named_header':hex(marker_base+len(active)),
                          'fields':','.join(active)})
    example_R,example_r = fields[1]['name'].encode(),fields[7]['name'].encode()
    example = bytes([marker_base+2,string_base+len(example_R)])+example_R+bytes([1,string_base+len(example_r)])+example_r+bytes([2])
    return {'target_sha256':DIGEST,'coordinate_system':'unrelocated ELF virtual addresses',
            'scope':'selected FDEs and byte windows; no node execution',
            'functions':functions,'windows':windows,'calls':calls,'branches':branches,
            'fields':fields,'enums':enums,'masks':mask_rows,'classifier':classifier,'reader_dispatch':dispatch,
            'binding':{'state_offset':offset,'capture_site':hex(0x2756640),
                'vtable':hex(table),'call_slot':hex(table+24),'thunk':hex(thunk),
                'closure':hex(0x2819ad0),'closure_call':hex(0x2819b20),
                'config':hex(config),'extra_flag':flag,
                'capture_bytes':va_bytes(data,secs,0x2756640,0x1a).hex(),
                'table_bytes':va_bytes(data,secs,0x2756d04,0x1d).hex(),
                'closure_bytes':va_bytes(data,secs,0x2819b05,0x20).hex()},
            'enum_tail_jump':{'site':hex(0x27b18fc),'target':hex(0x28e7990),'bytes':tail.hex()},
            'sort':{'small_count_exclusive':threshold,'compare_bytes':cmp_size,
                    'entry_pointer_stride':pair_stride,'symbol':symbol},
            'epoch':{'day_argument':day,'helper_slot':hex(slot)},
            'examples':{'domain':'named value only; epoch time, other fields default, small unsigned integers',
                        'all_default_hex':bytes([marker_base]).hex(),
                        'R_1_r_2_hex':example.hex()},
            'limits':['FDE extents are unwind records, not complete CFG boundaries',
                      'only sort counts below the threshold are modelled',
                      'presence masks are static models for well-formed values, not node execution',
                      'reader defaults, full enum reader, datetime output and complete integer encodings are not recovered',
                      'no complete app hash, snapshot compatibility or Rust equivalence is established']}


def tsv(rows,columns):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream,fieldnames=columns,delimiter='\t',lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def generate(data):
    result = collect(data)
    separate = ('functions','windows','calls','branches','fields','enums','masks','classifier','reader_dispatch')
    summary = {k:v for k,v in result.items() if k not in separate}
    return {
        'summary.json':(json.dumps(summary,sort_keys=True,indent=2)+'\n').encode(),
        'functions.tsv':tsv(result['functions'],['label','start','end_exclusive','length','fde','sha256']),
        'windows.tsv':tsv(result['windows'],['label','owner','start','end_exclusive','bytes']),
        'calls.tsv':tsv(result['calls'],['label','site','target','bytes']),
        'branches.tsv':tsv(result['branches'],['label','site','target','condition_code','bytes']),
        'fields.tsv':tsv(result['fields'],['name','site','literal_va','length','value_offset','presence','writer']),
        'enum.tsv':tsv(result['enums'],['tag','table_slot','displacement','target','literal_va','value']),
        'presence.tsv':tsv(result['masks'],['mask','count','named_header','fields']),
        'classifier.tsv':tsv(result['classifier'],['byte','tag','target','displacement']),
        'reader-dispatch.tsv':tsv(result['reader_dispatch'],['tag','field','table_slot','target','duplicate_branch','duplicate_target','helper_call','helper']),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args = parser.parse_args()
    outputs = generate(BINARY.read_bytes())
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in outputs.items():
        (args.out/name).write_bytes(content)


if __name__ == '__main__':
    main()
