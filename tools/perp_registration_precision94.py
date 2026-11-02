#!/usr/bin/env python3
"""Extract node 94 perp registration precision and rollback evidence without execution."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

BINARY = 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
U64 = (1 << 64) - 1
FUNCTIONS = {0x342bb20: 0x342bd31, 0x36f7730: 0x36f7c3c, 0x3765fc0: 0x376602e,
             0x3c92430: 0x3c927d1}
# Fixed bytes are qualified independently of the file identity check. All
# positions and numbers in the exported records are read back from the ELF.
ANCHORS = {
    0x342bb5b: ('opening brace byte', 'c604017b'),
    0x342bb71: ('size decimals field call', '488d4b2a488d35851716fd4889e7ba0a000000e8b7ba8500'),
    0x342bb89: ('field result checks', '4885c00f851c010000803c24000f85fa000000'),
    0x342bbc6: ('margin table field call', '488d4b18488d353a1716fd4889e7ba0d000000e8e2918500'),
    0x36f7747: ('input fields', '488b09498b460848894424204d8b6610'),
    0x36f7757: ('name length gate', '4983fc657216'),
    0x36f775d: ('name length refusal tag', '6641bf4301'),
    0x36f7773: ('row count gate', '4c8b6e104981fd0f270000'),
    0x36f7785: ('row count refusal tag', '6641bf6000'),
    0x36f7792: ('identifier multiplication', 'b81027000048f76630'),
    0x36f77a0: ('multiplication overflow', '0f802d040000'),
    0x36f77b3: ('identifier addition', '4c01e8'),
    0x36f77be: ('addition carry', '0f821e040000'),
    0x36f77c4: ('input precision byte', '410fb64635880424'),
    0x36f77f6: ('duplicate comparator slot load', '4c8b357b6b0702'),
    0x36f7809: ('duplicate length test', '4d3b642f1075f0'),
    0x36f7810: ('duplicate byte compare', '498b742f08488b7c24204c89e241ffd685c075'),
    0x36f7824: ('duplicate refusal tag', '6641bf3b00'),
    0x36f7844: ('precision gate', '4180fd060f86a5000000'),
    0x36f784e: ('precision refusal tag', '6641bf3e00'),
    0x36f78f3: ('table selector gate', '448b4c24044183f932'),
    0x36f7908: ('text length gate', '498b56284883fa647671'),
    0x36f7912: ('text length refusal tag', '6641bf4301'),
    0x36f7920: ('custom table presence', '4885c00f8488010000'),
    0x36f7991: ('text parser call', 'ff1541b80702'),
    0x36f7997: ('parser result gate', '440fb77c24304181ff86010000'),
    0x36f79d5: ('row construction', '488b4424184889442430488b44242048894424384c8964244044886c245a8b442404894424480fb644240388442458c644245901c744244c00000000'),
    0x36f7a1e: ('row append', 'e89de50600'),
    0x36f7a33: ('conversion arguments and call', '4c89fe4889eae8d2b5ffff'),
    0x36f7a3e: ('conversion result gate', '6681bc24f800000086010f85ce000000'),
    0x36f7a6c: ('conditional post step', '4180bf3002000003740f'),
    0x36f7a80: ('conditional post call', 'e86b47caff'),
    0x36f7a9a: ('final post call', 'e891a0b6ff'),
    0x36f7a9f: ('success result', '48896b084c89631066c7038601'),
    0x36f7ab1: ('custom lookup refusal tag', '6641bf5401'),
    0x36f7b6d: ('rollback count', '498b4f104885c9743348ffc949894f10'),
    0x36f7b89: ('rollback owned row length', '488b3408488d1475000000004885d2740f4801c8488b780831d2'),
    0x36f7ba9: ('drop and rollback status', '488d7c2430e85da90600498b76186641bf3d01'),
    0x3765fc8: ('append capacity and destination', '4989fe4c8b7f104c3b3f75094c89f7ff1523e40002498b46084b8d0c7f48c1e104'),
    0x3765fe9: ('append row and count', '0f10030f104b100f1053200f115408200f114c08100f11040849ffc74d897e10'),
    0x3c92456: ('serializer vector pointer and count', '498b6f08498b5f10'),
    0x3c924c3: ('serializer length and row stride', '4885db0f8471010000488d045b48c1e0044801e8'),
    0x3c925c0: ('serialize current row and step', '488b6c24104889ef4c8b2c244c89eee84c9579ff4885c00f85880000004883c530'),
}
BRANCHES = [0x342bb33,0x342bb51,0x342bb8c,0x342bb96,0x342bbb6,0x342bbc0,
            0x342bbe1,0x342bbeb,0x36f775b,0x36f7768,0x36f7783,0x36f77a0,0x36f77be,0x36f77e0,
            0x36f7807,0x36f780e,0x36f7822,0x36f7848,0x36f7863,0x36f787c,
            0x36f7906,0x36f7910,0x36f7923,0x36f7943,0x36f7960,0x36f7968,
            0x36f7973,0x36f79ac,0x36f7a48,0x36f7a5d,0x36f7a74,0x36f7b74,
            0x36f7b98,0x36f7bbf,0x36f7c01,0x36f7c21,0x3765fd2,0x3766018,
            0x3c924c6,0x3c925d7,0x3c925ed]
CC = ('o','no','b','ae','e','ne','be','a','s','ns','p','np','l','ge','le','g')

class EvidenceError(ValueError):
    pass

class Image:
    def __init__(self, data, verify=True):
        self.data = data
        if verify:
            check_digest(data)
        self.sections = sections(data)
    def offset(self, va, size=1):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
            raise EvidenceError('invalid address or size')
        found = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2
                 and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise EvidenceError('address is not uniquely backed by file bytes')
        return found[0]['offset'] + va - found[0]['address']
    def read(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])
    def relative(self, slot):
        ss = [s for s in self.sections if s['name'] == '.rela.dyn' and s['type'] != 8]
        if len(ss) != 1 or ss[0]['size'] % 24:
            raise EvidenceError('invalid relocation section')
        sec = ss[0]
        rows = []
        for p in range(sec['offset'], sec['offset'] + sec['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', self.data, p)
            if where == slot:
                rows.append((info, addend))
        if len(rows) != 1 or rows[0][0] != 8:
            raise EvidenceError('missing, duplicate or non-relative slot')
        return rows[0][1]

def check_digest(data, expected=SHA256):
    if hashlib.sha256(data).hexdigest() != expected:
        raise EvidenceError('target sha256 mismatch')

def qualify(img):
    for va, (_, raw) in sorted(ANCHORS.items()):
        raw = bytes.fromhex(raw)
        if img.read(va, len(raw)) != raw:
            raise EvidenceError('qualified instruction mismatch at %#x' % va)
    _, fdes = eh_frame_records(img.data, img.sections)
    for start, end in FUNCTIONS.items():
        rows = [f for f in fdes if f['start'] == start]
        if len(rows) != 1 or rows[0]['end'] != end:
            raise EvidenceError('FDE mismatch at %#x' % start)
    return fdes

def branch(img, site):
    raw = img.read(site, 6)
    if 0x70 <= raw[0] <= 0x7f:
        length, cond, disp = 2, raw[0] & 15, struct.unpack('<b', raw[1:2])[0]
    elif raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        length, cond, disp = 6, raw[1] & 15, struct.unpack('<i', raw[2:6])[0]
    else:
        raise EvidenceError('expected a conditional branch at %#x' % site)
    return {'site': hex(site), 'bytes': raw[:length].hex(), 'condition': CC[cond],
            'target': hex(site + length + disp)}

def direct(img, site):
    raw = img.read(site, 5)
    if raw[0] != 0xe8:
        raise EvidenceError('expected direct call')
    return site + 5 + struct.unpack('<i', raw[1:])[0]

def indirect(img, site):
    raw = img.read(site, 6)
    if raw[:2] != b'\xff\x15':
        raise EvidenceError('expected indirect call')
    slot = site + 6 + struct.unpack('<i', raw[2:])[0]
    return slot, img.relative(slot)

def comparator_symbol(img):
    """Resolve this one GOT load through its dynamic relocation and symbol entry."""
    site = 0x36f77f6
    raw = img.read(site, 7)
    if raw[:3] != bytes.fromhex('4c8b35'):
        raise EvidenceError('unsupported comparator load')
    slot = site + 7 + struct.unpack('<i', raw[3:])[0]
    def section(name, typ):
        found = [s for s in img.sections if s['name'] == name and s['type'] == typ]
        if len(found) != 1:
            raise EvidenceError('missing or ambiguous dynamic section')
        return found[0]
    rel, sym, strings = section('.rela.dyn',4), section('.dynsym',11), section('.dynstr',3)
    if rel['size'] % 24 or sym['size'] % 24:
        raise EvidenceError('invalid dynamic entry sizes')
    matches = []
    for pos in range(rel['offset'],rel['offset'] + rel['size'],24):
        where, info, addend = struct.unpack_from('<QQq',img.data,pos)
        if where == slot:
            matches.append((pos,info,addend))
    if len(matches) != 1 or matches[0][1] & 0xffffffff != 6 or matches[0][2] != 0:
        raise EvidenceError('unsupported comparator relocation')
    pos,info,_ = matches[0]
    index = info >> 32
    if index >= sym['size'] // 24:
        raise EvidenceError('dynamic symbol index outside table')
    sympos = sym['offset'] + index * 24
    nameoff, _, _, shndx, _, _ = struct.unpack_from('<IBBHQQ',img.data,sympos)
    if shndx != 0 or nameoff >= strings['size']:
        raise EvidenceError('unsupported dynamic symbol')
    begin = strings['offset'] + nameoff
    end = img.data.find(b'\x00',begin,strings['offset'] + strings['size'])
    if end < 0:
        raise EvidenceError('unterminated dynamic symbol')
    name = bytes(img.data[begin:end]).decode('ascii')
    if name != 'bcmp':
        raise EvidenceError('unexpected comparator symbol')
    return {'load_site':hex(site),'indirect_call_site':hex(0x36f781d),
            'slot':hex(slot),'relocation_file_offset':hex(pos),
            'relocation_type':info & 0xffffffff,'symbol_index':index,
            'symbol_file_offset':hex(sympos),'symbol_name':name}

def field(img, lea, field_offset, key_len, call):
    """Verify the selected field-pointer, RIP-relative key, length, and call sequence."""
    raw = img.read(lea, 24)
    expected = bytes.fromhex('488d4b') + bytes([field_offset]) + bytes.fromhex('488d35')
    if raw[:7] != expected or raw[11:15] != bytes.fromhex('4889e7ba'):
        raise EvidenceError('unsupported field call sequence')
    length = struct.unpack('<I', raw[15:19])[0]
    if length != key_len or lea + 19 != call:
        raise EvidenceError('field length or call position mismatch')
    key_va = lea + 11 + struct.unpack('<i', raw[7:11])[0]
    key = img.read(key_va, length)
    return {'field_offset':hex(field_offset),'key_va':hex(key_va),
            'key_file_offset':hex(img.offset(key_va,length)),
            'key_ascii':key.decode('ascii'),'key_length':length,
            'call_site':hex(call),'call_target':hex(direct(img,call))}

def precision_step(img, precision):
    """Interpret the qualified cmp/jbe and immediate error tag on all byte values."""
    if type(precision) is not int or not 0 <= precision <= 255:
        raise EvidenceError('precision outside byte domain')
    op = img.read(0x36f7844, 10)
    if op[:3] != bytes.fromhex('4180fd') or op[4:6] != bytes.fromhex('0f86'):
        raise EvidenceError('unsupported precision compare/branch')
    reject = img.read(0x36f784e, 5)
    if reject[:3] != bytes.fromhex('6641bf'):
        raise EvidenceError('unsupported precision tag')
    return ('continue', 0x36f784e + struct.unpack('<i', op[6:10])[0]) if precision <= op[3] else ('refuse', struct.unpack('<H', reject[3:5])[0])

def identifier_step(img, dex, local):
    """Lift the checked unsigned product and addition from the qualified instructions."""
    if any(type(x) is not int or x < 0 or x > U64 for x in (dex, local)):
        raise EvidenceError('identifier input outside u64')
    op = img.read(0x36f7792, 9)
    if op[:1] != b'\xb8' or op[5:] != bytes.fromhex('48f76630'):
        raise EvidenceError('unsupported identifier multiply')
    base = struct.unpack('<I', op[1:5])[0] * dex
    if base > U64:
        return ('multiply-overflow', None)
    total = base + local
    if total > U64:
        return ('add-overflow', None)
    return ('ok', total)

def result_tag(img, site):
    raw = img.read(site, 5)
    if raw[:3] != bytes.fromhex('6641bf'):
        raise EvidenceError('unsupported result-tag instruction')
    return struct.unpack('<H', raw[3:])[0]

def model(img, case):
    """Selected scalar paths; parser, map lookup and converter results are inputs."""
    name_len, n, dex, precision = (case[k] for k in ('name_len','count','dex','precision'))
    selector, text_len = case['selector'], case['text_len']
    values = (name_len,n,dex,text_len)
    if any(type(x) is not int or not 0 <= x <= U64 for x in values):
        raise EvidenceError('invalid u64 input')
    if type(selector) is not int or not 0 <= selector < 1 << 32:
        raise EvidenceError('invalid selector')
    if type(precision) is not int or not 0 <= precision <= 255:
        raise EvidenceError('invalid precision')
    if any(type(case[k]) is not bool for k in ('duplicate','custom_found','convert_ok')):
        raise EvidenceError('expected boolean inputs')
    if n == 0 and case['duplicate']:
        raise EvidenceError('duplicate requires at least one existing row')
    parser = case['parser_tag']
    if type(parser) is not int or not 0 <= parser <= 65535:
        raise EvidenceError('invalid parser tag')
    if name_len >= img.read(0x36f7757, 4)[3]:
        return ('name-length',result_tag(img,0x36f775d),'unchanged',None)
    n_limit = struct.unpack('<I', img.read(0x36f7777, 7)[3:7])[0]
    if n > n_limit:
        return ('row-count',result_tag(img,0x36f7785),'unchanged',None)
    state, identifier = identifier_step(img,dex,n)
    if state != 'ok':
        return (state,'overflow-handler','unchanged',None)
    if case['duplicate']:
        return ('duplicate',result_tag(img,0x36f7824),'unchanged',identifier)
    outcome, value = precision_step(img,precision)
    if outcome == 'refuse':
        return ('precision',value,'unchanged',identifier)
    if selector >= img.read(0x36f78f8, 4)[3] and not case['custom_found']:
        return ('custom-missing',result_tag(img,0x36f7ab1),'unchanged',identifier)
    if text_len > img.read(0x36f790c, 4)[3]:
        return ('text-length',result_tag(img,0x36f7912),'unchanged',identifier)
    expected_parser = struct.unpack('<I',img.read(0x36f799d,7)[3:7])[0]
    if parser != expected_parser:
        return ('parse-refusal',parser,'unchanged',identifier)
    if not case['convert_ok']:
        return ('price-conversion-refusal',result_tag(img,0x36f7bb7),'append-then-pop',identifier)
    return ('success',expected_parser,'append',identifier)

def write_tsv(out, name, fields, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', lineterminator='\n')
        w.writeheader(); w.writerows(rows)

def generate(img, out):
    fdes = qualify(img)
    by_start = {f['start']: f for f in fdes}
    out.mkdir(parents=True, exist_ok=True)
    anchors=[]
    for va,(meaning, raw) in sorted(ANCHORS.items()):
        data=img.read(va,len(bytes.fromhex(raw)))
        anchors.append({'va':hex(va),'file_offset':hex(img.offset(va,len(data))),
                        'bytes':data.hex(),'meaning':meaning})
    write_tsv(out,'anchors.tsv',['va','file_offset','bytes','meaning'],anchors)
    br = [branch(img,p) for p in BRANCHES]
    write_tsv(out,'branches.tsv',['site','bytes','condition','target'],br)
    functions=[]
    with (out/'function-bytes.txt').open('w',encoding='ascii',newline='\n') as f:
        for requested_start in sorted(FUNCTIONS):
            row=by_start[requested_start]; start=row['start']; end=row['end']
            raw=img.read(start,end-start)
            functions.append({'start':hex(start),'end':hex(end),'fde':hex(row['fde']),
                              'lsda':hex(row['lsda']) if row['lsda'] is not None else None,
                              'file_offset':hex(img.offset(start,len(raw))), 'length':len(raw),
                              'sha256':hashlib.sha256(raw).hexdigest()})
            f.write('%s %s %s\n' % (hex(start),hex(end),raw.hex()))
    edges=[]
    for at in (0x36f7a1e,0x36f7a39,0x36f7a80,0x36f7a9a,0x36f7bae,0x3c925cf):
        edges.append({'site':hex(at),'kind':'direct','slot':'','target':hex(direct(img,at))})
    for at in (0x273b307,0x4d4a8c9,0x4d4ae69,0x36f786c,0x36f7884,0x36f7991,
               0x36f7ba3,0x3765fd7,0x3766020):
        slot,target=indirect(img,at)
        edges.append({'site':hex(at),'kind':'relative-slot','slot':hex(slot),'target':hex(target)})
    write_tsv(out,'edges.tsv',['site','kind','slot','target'],edges)
    fields=[field(img,0x342bb71,0x2a,10,0x342bb84),
            field(img,0x342bbc6,0x18,13,0x342bbd9)]
    if [row['key_ascii'] for row in fields] != ['szDecimals','marginTableId']:
        raise EvidenceError('field key bytes mismatch')
    write_tsv(out,'fields.tsv',['field_offset','key_va','key_file_offset','key_ascii',
                              'key_length','call_site','call_target'],fields)
    symbol = comparator_symbol(img)
    write_tsv(out,'symbols.tsv',['load_site','indirect_call_site','slot','relocation_file_offset',
                               'relocation_type','symbol_index','symbol_file_offset','symbol_name'],[symbol])
    rows=[]
    for d in range(256):
        decision, value=precision_step(img,d)
        rows.append({'input_byte':d,'decision':decision,'branch_target_or_tag':hex(value)})
    write_tsv(out,'precision-domain.tsv',['input_byte','decision','branch_target_or_tag'],rows)
    cases=[]
    def add(label,**kw):
        x={'name_len':0,'count':0,'dex':0,'precision':0,'selector':0,'text_len':0,
           'duplicate':False,'custom_found':True,'parser_tag':0x186,'convert_ok':True}
        x.update(kw); outcome,tag,mutation,identifier=model(img,x)
        cases.append({'case':label,**x,'outcome':outcome,'tag':hex(tag) if isinstance(tag,int) else tag,
                      'row_effect':mutation,'identifier':hex(identifier) if identifier is not None else ''})
    for d in range(256): add('precision-%03d'%d,precision=d)
    for name,kw in [
        ('name-100',dict(name_len=100)),('name-101',dict(name_len=101)),
        ('row-9999',dict(count=9999)),('row-10000',dict(count=10000)),
        ('duplicate-before-precision',dict(count=1,duplicate=True,precision=7)),
        ('precision-before-custom',dict(precision=7,selector=50,custom_found=False)),
        ('builtin-49',dict(selector=49,custom_found=False)),
        ('custom-50-present',dict(selector=50,custom_found=True)),
        ('custom-50-missing',dict(selector=50,custom_found=False)),
        ('text-100',dict(text_len=100)),('text-101',dict(text_len=101)),
        ('parse-refusal',dict(parser_tag=0xac)),('conversion-refusal',dict(convert_ok=False)),
        ('maximum-dex-safe',dict(dex=U64//10000,count=U64%10000)),
        ('addition-overflow',dict(dex=U64//10000,count=U64%10000+1)),
        ('multiply-overflow',dict(dex=U64//10000+1)),
        ('name-before-overflow',dict(name_len=101,dex=U64)),
    ]: add(name,**kw)
    keys=['case','name_len','count','dex','precision','selector','text_len','duplicate','custom_found','parser_tag','convert_ok','outcome','tag','row_effect','identifier']
    write_tsv(out,'cases.tsv',keys,cases)
    divisor=struct.unpack('<I',img.read(0x36f7793,4))[0]
    limit=img.read(0x36f7847,1)[0]
    local_max=struct.unpack('<I',img.read(0x36f7777,7)[3:7])[0]
    q,r=divmod(U64,divisor)
    # For d < q the worst admitted sum is (q-1)*divisor+local_max;
    # at q only n <= r fits; for d > q the multiplication already fails.
    if not (q > 0 and local_max == divisor-1 and
            (q-1)*divisor+local_max <= U64 and q*divisor+r == U64 and
            r < divisor and (q+1)*divisor > U64):
        raise EvidenceError('identifier-domain proof preconditions failed')
    bounds={'divisor':divisor,'max_dex':q,'max_dex_remainder':r,
            'last_all_locals_safe_dex':q-1,
            'last_all_locals_safe_max_sum':(q-1)*divisor+local_max,
            'first_overflow_dex':q+1,'largest_admitted_local':local_max,
            'max_precision':limit,'byte_values':len(rows),
            'precision_continue':sum(r['decision']=='continue' for r in rows),
            'precision_refuse':sum(r['decision']=='refuse' for r in rows)}
    summary={'target_sha256':SHA256,'coordinate_system':'linked ELF virtual addresses',
             'functions':functions,'anchor_count':len(anchors),'selected_branch_count':len(br),
             'edge_count':len(edges),'field_count':len(fields),'synthetic_case_count':len(cases),'arithmetic':bounds,
             'caveat':'FDEs describe unwind extents; models use abstract external results and do not execute the captured target.'}
    (out/'evidence.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    data=(ROOT/BINARY).read_bytes()
    generate(Image(data),args.out)

if __name__=='__main__':
    try: main()
    except (EvidenceError, OSError, struct.error) as e:
        print('perp_registration_precision94: %s'%e,file=sys.stderr)
        raise SystemExit(1)
