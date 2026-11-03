#!/usr/bin/env python3
"""Digest-bound numeric-selector projections, not an instruction interpreter."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET=ROOT/'artifacts/node/115/hl-node'
PACKET=ROOT/'research/work-items/RE-001-node115-numeric-selector'
SHA='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE=105896032
SPEC_SHA='09a6b1fe74fba181f75ced28188b6ecb3122b890dd707b727e60ef2151c61ce5'
U64=(1<<64)-1
FIELDS={
 'special_word':(0x46aa788,'Q'),'special_last':(0x46aa79a,'b'),
 'prefix_hash':(0x46aa7a9,'b'),'prefix_at':(0x46aa7ae,'b'),
 'zero_prefix':(0x46aa8e9,'B'),'numeric_tag':(0x46aa875,'H'),'string_tag':(0x46aa85a,'H'),
 'output_at_prefix':(0x46aab01,'B'),'format_small_threshold':(0x46aa903,'I'),'at_bound':(0x46aab07,'i'),'hash_sub_immediate':(0x46aab18,'i'),
 'hash_add_immediate':(0x46aab21,'i'),'hash_floor':(0x46aab35,'i'),
 'lookup_bound':(0x46aa586,'i'),'lookup_sub_immediate':(0x46aa5c6,'i'),
 'lookup_multiplier':(0x46aa5cc,'Q'),'lookup_shift':(0x46aa5dd,'B'),
 'lookup_second_remainder':(0x46aa5ee,'B'),'lookup_second_offset':(0x46aa5f6,'I'),
 'format_multiplier':(0x46aa90b,'Q'),'format_shift':(0x46aa929,'B'),
 'format_divisor':(0x46aa92c,'I'),'pair_multiplier':(0x46aa939,'I'),
 'pair_shift':(0x46aa93f,'B'),'tail_multiplier':(0x46aa982,'I'),
 'tail_shift':(0x46aa988,'B'),'tail_preshift':(0x46aa97c,'B'),
 'format_loop_limit':(0x46aa969,'I'),'short_digit_limit':(0x46aa8a1,'B'),
 'caller_tag_a':(0x2c6fa3c,'I'),'caller_tag_b':(0x2c6fdec,'I'),
 'caller_mask_a':(0x2c6fa58,'B'),'caller_mask_b':(0x2c6fe08,'B'),
 'caller_store_tag_a':(0x2c6fa6e,'H'),'caller_store_tag_b':(0x2c6fe1e,'H'),
 'caller_discriminator_a':(0x2c6fa63,'i'),'caller_discriminator_b':(0x2c6fe13,'i'),
 'caller_payload_offset_a':(0x2c6fa6a,'B'),'caller_payload_offset_b':(0x2c6fe1a,'B')}


def require(ok,message):
    if not ok:raise ValueError(message)


def specification():
    raw=(PACKET/'spec.json').read_bytes();require(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'numeric selector specification changed')
    return json.loads(raw)


def reader(data):
    ss=sections(data)
    def read(a,n):
        ms=[s for s in ss if s['type']!=8 and s['address']<=a and a+n<=s['address']+s['size']]
        require(len(ms)==1,'expected one complete file-backed mapping')
        s=ms[0];o=s['offset']+a-s['address'];return bytes(data[o:o+n])
    return ss,read


def parameters(data):
    _,read=reader(data)
    return {name:struct.unpack('<'+fmt,read(a,struct.calcsize('<'+fmt)))[0] for name,(a,fmt) in FIELDS.items()}


def render_integer(value,p,table):
    """Four-digit integer grouping equations; no instruction state or PC."""
    require(type(value)is int and 0<=value<=U64,'outside u64 rendering')
    original=value;parts=[]
    def pair(n):
        require(0<=n<100,'pair lookup outside proved domain')
        return table[2*n:2*n+2]
    if value>=p['format_small_threshold']:
        for _ in range(6):
            q=(value*p['format_multiplier'])>>(64+p['format_shift'])
            r=(value-p['format_divisor']*q)&0xffffffff
            high=((r*p['pair_multiplier'])&0xffffffff)>>p['pair_shift']
            low=(r-100*high)&0xffffffff
            parts.insert(0,pair(high)+pair(low))
            previous=value;value=q
            if previous<=p['format_loop_limit']:break
        else:raise ValueError('outside proved finite grouping domain')
    if value>9:
        q=(((((value>>p['tail_preshift'])&0xffff)*p['tail_multiplier'])&0xffffffff)>>p['tail_shift'])
        r=(value-100*q)&0xffffffff;parts.insert(0,pair(r));value=q
    if original==0 or value!=0:parts.insert(0,pair(value&15)[1:])
    return b''.join(parts)


def numeric_projection(value,p,table):
    """Conditional numeric-state equation; other states are not called errors."""
    require(isinstance(value,bytes),'byte-slice model requires bytes')
    fallback={'tag':p['string_tag'],'copied_bytes_hex':value.hex()}
    last=p['special_last'];special=p['special_word'].to_bytes(8,'little')+bytes([last]) if 0<=last<256 else None
    if value==special:return {'tag':p['numeric_tag'],'value':0}
    if len(value)<2 or value[0] not in (p['prefix_hash'],p['prefix_at']):return fallback
    digits=value[1:]
    # More than20 digits cannot equal a canonical u64 rendering, regardless of
    # how many leading zeros a successful checked accumulation consumes.
    if len(digits)>20 or not re.fullmatch(rb'(?:0|[1-9][0-9]*)',digits):return fallback
    n=int(digits)
    if n>U64:return fallback
    if value[0]==p['zero_prefix'] and n==0:return fallback
    rendered=render_integer(n,p,table)
    if rendered!=digits:return fallback
    if value[0]==p['output_at_prefix']:
        if n>=p['at_bound']:return fallback
        return {'tag':p['numeric_tag'],'value':n}
    offset=-p['hash_sub_immediate']
    require(offset==p['hash_add_immediate'] and offset>=p['hash_floor']>=0,'unsupported inconsistent projection constants')
    return {'tag':p['numeric_tag'],'value':min(U64,n+offset)}


def early_caller_gate(tag,al,p,which):
    """Only the selected early store branch, not the whole caller result."""
    require(which in ('a','b') and 0<=tag<65536 and 0<=al<256,'outside selected gate domain')
    return tag==p['caller_tag_'+which] and bool(al&p['caller_mask_'+which])


def lookup_projection(value,p):
    """Raw namespace cutpoints; context-dependent paths are left unresolved."""
    require(type(value)is int and 0<=value<=U64,'outside u64 namespace')
    if value<p['lookup_bound']:return {'path':'context-dependent-direct','index':value}
    n=(value+p['lookup_sub_immediate'])&U64
    q=((n*p['lookup_multiplier'])>>64)>>(p['lookup_shift']&63)
    r=(n-10*q)&U64
    if r==0:return {'path':'context-dependent-table','quotient':q,'remainder':r,'selector_offset':0}
    if r==p['lookup_second_remainder']:return {'path':'context-dependent-table','quotient':q,'remainder':r,'selector_offset':p['lookup_second_offset']}
    return {'path':'fast-zero','quotient':q,'remainder':r,'rax':0,'rdx':r}


def division_certificates(p):
    """Integer inequalities proving the observed reciprocal divisions."""
    rows=[]
    for name,m,d,s,maximum in [('lookup',p['lookup_multiplier'],10,64+p['lookup_shift'],U64),
       ('format',p['format_multiplier'],p['format_divisor'],64+p['format_shift'],U64),
       ('pair',p['pair_multiplier'],100,p['pair_shift'],9999),
       ('tail',p['tail_multiplier'],25,p['tail_shift'],249)]:
        e=m*d-(1<<s)
        require(0<=e and maximum*e<(1<<s),'reciprocal division certificate changed: '+name)
        rows.append({'name':name,'multiplier':m,'divisor':d,'shift':s,'maximum':maximum,'excess':e,'bound':maximum*e,'power':1<<s})
    require(p['tail_preshift']==2 and p['short_digit_limit']==17 and p['format_loop_limit']==9999999 and p['format_small_threshold']==1000,'format/accumulation domain changed')
    return rows


def caller_branches(data):
    _,read=reader(data);result={}
    for site in [0x2c6fa59,0x2c6fe09]:
        raw=read(site,6);require(raw[:2]==b'\x0f\x84','caller zero-branch opcode changed')
        result[str(site)]=site+6+int.from_bytes(raw[2:],'little',signed=True)
    return result


def extract(data):
    spec=specification();ss,read=reader(data);_,fs,_=fde_extents(data)
    sec=next(s for s in ss if s['name']=='.rela.dyn')
    rels={a:(i,v) for a,i,v in struct.iter_unpack('<QQq',data[sec['offset']:sec['offset']+sec['size']])}
    dyn=next(s for s in ss if s['name']=='.dynsym');strings_sec=next(s for s in ss if s['name']=='.dynstr');strings=data[strings_sec['offset']:strings_sec['offset']+strings_sec['size']]
    facts=[];bindings={};exports={};native_frames=[]
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'node115.elf';path.write_bytes(data)
        frames=subprocess.check_output(['readelf','-wf',str(path)],text=True)
        for owner in spec['functions']:
            a,b=owner['start'],owner['end'];found=[f for f in fs if (f['start'],f['end'])==(a,b)];require(len(found)==1,'numeric owner FDE changed');f=found[0]
            require(sum(s['type']==1 and bool(s['flags']&4) and s['address']<=a and b<=s['address']+s['size'] for s in ss)==1,'owner outside unique executable section')
            body=read(a,b-a);asm=subprocess.check_output(['objdump','-d','-M','intel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}',str(path)],text=True)
            decode_export(asm,a,b,body);calls={};rip={};rows=[]
            for line in asm.splitlines():
                m=re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(\S+)\s*(.*)$',line)
                if not m:continue
                va=int(m[1],16);raw=bytes.fromhex(m[2]);rows.append((va,raw))
                if raw[:1]==b'\xe8':calls[str(va)]=va+len(raw)+int.from_bytes(raw[1:],'little',signed=True)
                q=re.search(r'#\s*([0-9a-f]+)',m[4])
                if q:
                    target=int(q[1],16);rip[str(va)]=target
                    if target in rels:
                        info,value=rels[target];index=info>>32;name=None
                        if index:
                            o=struct.unpack_from('<I',data,dyn['offset']+24*index)[0]
                            try:
                                name=strings[o:strings.index(0,o)].decode()
                            except UnicodeDecodeError:
                                require(False,'dynamic symbol name is not valid UTF-8')
                        bindings[str(target)]={'kind':info&0xffffffff,'symbol_index':index,'addend':value,'symbol':name}
            matched=[l for l in frames.splitlines() if f'pc={a:016x}..{b:016x}' in l];require(len(matched)==1,'native FDE disagreement')
            meta={k:f[k] for k in ['start','end','fde','cie']};meta.update(body_sha256=hashlib.sha256(body).hexdigest(),instructions=len(rows),direct_calls=calls,rip_bindings=rip)
            for kind in ['fde','cie']:
                va=f[kind];n=int.from_bytes(read(va,4),'little')+4;meta[kind+'_bytes_hex']=read(va,n).hex()
            native_frames.append(matched[0])
            facts.append(meta);exports[f'{a:x}.objdump.txt']=asm.replace(str(path),'<authenticated-node115>')
    exports['frames.txt']='\n'.join(native_frames)+'\n'
    return {'target_sha256':SHA,'functions':facts,'relocations':bindings,'decimal_pair_table':{'address':0x46ea12,'bytes_hex':read(0x46ea12,200).hex()}},exports


def analyze(data):
    spec=specification();p=parameters(data);require(p==spec['parameters'],'numeric projection parameters changed')
    branches=caller_branches(data);require(branches==spec['caller_zero_branches'],'caller zero-branch destination changed')
    certificates=division_certificates(p);actual,exports=extract(data)
    for key in ['functions','relocations','decimal_pair_table']:require(actual[key]==spec[key],'numeric '+key+' bindings changed')
    table=bytes.fromhex(actual['decimal_pair_table']['bytes_hex']);require(table==''.join(f'{i:02d}' for i in range(100)).encode(),'decimal pair table changed')
    examples=[]
    for value in [b'PURR/USDC',b'@0',b'@1',b'@99999999',b'@100000000',b'#0',b'#1',b'#2',b'#10',b'#01',b'#+1',b'#18446744073709551615',b'#18446744073709551616']:
        state=numeric_projection(value,p,table);row={'input_hex':value.hex(),'numeric_projection':state}
        if state['tag']==p['numeric_tag']:row['lookup_projection']=lookup_projection(state['value'],p)
        examples.append(row)
    actual.update(parameters=p,caller_zero_branches=branches,division_certificates=certificates,examples=examples,captured_instructions_executed=False,
       limits='Conditional numeric-state/namespace projections, not a complete parser/runtime/type/ABI or lookup result. memcpy/bcmp obey their imported contracts; allocation returns valid disjoint memory or does not return normally. Opaque lookup/formatting/error helpers, context data and original types remain unclosed. No component gate or captured execution.')
    return actual,exports


def generate(binary,output):
    data=binary.read_bytes();require(len(data)==SIZE and hashlib.sha256(data).hexdigest()==SHA,'expected pinned node115')
    report,exports=analyze(data);output.mkdir(parents=True,exist_ok=True)
    for name,text in exports.items():(output/name).write_bytes(text.encode())
    (output/'records.json').write_bytes((json.dumps(report,indent=2)+'\n').encode())
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'work/numeric-selector')
    a=p.parse_args();r=generate(TARGET,a.output);print(json.dumps({'bytes':sum(f['end']-f['start'] for f in r['functions']),'instructions':sum(f['instructions'] for f in r['functions']),'captured_execution':False}))
