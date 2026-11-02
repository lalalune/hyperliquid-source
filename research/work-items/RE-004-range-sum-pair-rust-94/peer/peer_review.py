"""Independent interval-walk reviewer; never imports the packet oracle or validators."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import capstone

PACKET = Path(__file__).resolve().parents[1]
ROOT = PACKET.parents[2]
MASK = (1 << 64) - 1
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BOUNDS = [(0x514bc60,0x514bcc3),(0x514bcd0,0x514bd38),(0x5032f40,0x5032f4d)]


def check(ok, why):
    if not ok:
        raise ValueError(why)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def relation(record):
    member,base,obj,dest,incoming,length = struct.unpack_from('<6Q',record)
    snapshot = record[48:]; read_log=[]; visited=set(); last=obj; total=0; iterations=0
    check(member in (0,1) and length<=768, 'input framing')
    def reject(reason):
        return bytes(40)+snapshot, {'outcome':reason,'reads':read_log,'iterations':iterations}
    if base+length > 1<<64:
        return reject('image-overflow')
    def read(address,role):
        address &= MASK
        read_log.append((role,address))
        off=address-base
        if off<0 or off+8>length:
            raise LookupError(role)
        return struct.unpack_from('<Q',snapshot,off)[0]
    try:
        p=read(obj+0x788,'entry');q=read(p+0x30,'container')
        cursor=read(q+0xb18,'begin');endpoint=read(q+0xb20,'end');initial=cursor
        # Direct interval walk: no modular-distance quotient, count shortcut,
        # materialized pointer list, immutable address dictionary or whole sum.
        while cursor != endpoint:
            if cursor in visited:
                return reject('cycle')
            visited.add(cursor)
            slot=read(cursor,'slot');last=read(slot,'argument')
            helper=read(last+16,'helper')
            term=(helper+62)&MASK
            if member==1:
                slot_after_helper=read(cursor,'slot-reload')
                term=read(slot_after_helper+80,'field')
            total=(total+term)&MASK;iterations+=1;cursor=(cursor+16)&MASK
        off=dest-base
        if off<0 or off+8>length:
            return reject('output')
        updated=bytearray(snapshot);struct.pack_into('<Q',updated,off,total)
        return struct.pack('<5Q',1,1,incoming,last,dest)+updated, {
            'outcome':'admitted','reads':read_log,'iterations':iterations,
            'wrapped_terminal':initial+16*iterations>MASK,
            'empty_unmapped_endpoint':iterations==0 and not(base<=endpoint and endpoint+8<=base+length),
            'output_alias':any(dest<a+8 and a<dest+8 for _,a in read_log)}
    except LookupError as error:
        return reject('missing-'+str(error))


class ManualElf:
    def __init__(self,data):
        self.data=data
        check(data[:7]==b'\x7fELF\x02\x01\x01','ELF64LE')
        check(struct.unpack_from('<HH',data,16)==(3,62),'ET_DYN x86-64')
        phoff,shoff=struct.unpack_from('<QQ',data,32)
        phsize,phnum,shsize,shnum,names=struct.unpack_from('<5H',data,54)
        check(phsize==56 and shsize==64,'header sizes')
        rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*64) for i in range(shnum)]
        table=data[rows[names][4]:rows[names][4]+rows[names][5]]
        self.sections={table[r[0]:table.index(b'\0',r[0])].decode():r for r in rows}
        self.loads=[p for i in range(phnum) if (p:=struct.unpack_from('<IIQQQQQQ',data,phoff+i*56))[0]==1]
    def read(self,address,size,executable=False):
        matches=[s for s in self.sections.values() if s[1]!=8 and s[2]&2 and s[3]<=address and address+size<=s[3]+s[5]]
        check(len(matches)==1,'unique section')
        s=matches[0];off=s[4]+address-s[3]
        loads=[p for p in self.loads if p[3]<=address and address+size<=p[3]+p[5]]
        check(len(loads)==1 and (not executable or loads[0][1]&1),'file-backed load')
        check(off==loads[0][2]+address-loads[0][3],'section/load agreement')
        return self.data[off:off+size]
    def frames(self):
        s=self.sections['.eh_frame'];pos,end=s[4],s[4]+s[5];frames=[];cies={}
        while pos<end:
            length=struct.unpack_from('<I',self.data,pos)[0]
            if not length:
                check(not any(self.data[pos:end]),'frame terminator');break
            check(length!=0xffffffff and length>=4 and pos+4+length<=end,'record length')
            va=s[3]+pos-s[4];back=struct.unpack_from('<I',self.data,pos+4)[0]
            if back==0:cies[va]=self.data[pos:pos+4+length]
            else:
                cie=va+4-back;check(cie in cies,'backward CIE')
                pc_delta,extent=struct.unpack_from('<ii',self.data,pos+8)
                check(extent>=0 and pc_delta!=0,'FDE extent/PC')
                frames.append((va+8+pc_delta,va+8+pc_delta+extent,va,cie))
            pos+=4+length
        return frames,cies


def listing(raw):
    rows=[]
    for line in raw.decode().splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if match:rows.append((int(match[1],16),bytes.fromhex(match[2])))
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--objdump',required=True);args=ap.parse_args()
    out=Path(__file__).resolve().parent
    protected=[ROOT/'src/node94-range-sum-pair/lib.rs']+[PACKET/n for n in ['PROOF.md','oracle.py','frozen.json','inputs.bin.gz','expected.bin.gz','static.json','verify_static.py']]
    before={str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in protected}
    frozen=json.loads((PACKET/'frozen.json').read_bytes())
    inputs=gzip.decompress((PACKET/'inputs.bin.gz').read_bytes());expected=gzip.decompress((PACKET/'expected.bin.gz').read_bytes())
    check(digest(inputs)==frozen['inputs_sha256'] and digest(expected)==frozen['expected_sha256'],'frozen stream identity')
    check(len(inputs)==8316*816 and len(expected)==8316*808,'all fixture records')
    calculated=bytearray();coverage={'cases':8316,'admitted':[0,0],'refused':[0,0],'empty':[0,0],
                                   'output_aliases':[0,0],'terminal_wrap':[0,0],'empty_unmapped_endpoints':[0,0],
                                   'missing_discarded_helper':0,'image_overflow':[0,0]}
    for i in range(8316):
        row=inputs[i*816:(i+1)*816];member=struct.unpack_from('<Q',row)[0]
        output,info=relation(row);calculated.extend(output)
        if output!=expected[i*808:(i+1)*808]:
            failure={'index':i,'input_hex':row.hex(),'actual_hex':output.hex(),'expected_hex':expected[i*808:(i+1)*808].hex(),'info':info}
            (out/'relation-failure.json').write_bytes(encoded(failure));raise ValueError('independent relation mismatch')
        admitted=info['outcome']=='admitted';coverage['admitted' if admitted else 'refused'][member]+=1
        if admitted:
            coverage['empty'][member]+=info['iterations']==0;coverage['output_aliases'][member]+=info['output_alias']
            coverage['terminal_wrap'][member]+=info['wrapped_terminal'];coverage['empty_unmapped_endpoints'][member]+=info['empty_unmapped_endpoint']
        coverage['missing_discarded_helper']+=member==1 and info['outcome']=='missing-helper'
        coverage['image_overflow'][member]+=info['outcome']=='image-overflow'
    data=(ROOT/'artifacts/node/94/hl-node').read_bytes();check(len(data)==91774280 and digest(data)==TARGET,'target identity')
    elf=ManualElf(data);frames,cies=elf.frames();record=json.loads((PACKET/'static.json').read_bytes())
    decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);all_sites={};commands=[];fresh=[];body_bytes=0;caller_bytes=0;caller_instructions=0
    for kind,regions in [('member',record['members']),('caller',record['callers'])]:
        for r in regions:
            a,b=r['begin'],r['end'];code=elf.read(a,b-a,True);decoded=list(decoder.disasm(code,a))
            check(digest(code)==r['body_sha256'],'full body hash')
            check(sum(i.size for i in decoded)==b-a and len(decoded)==r['instructions'],'complete decode')
            overlaps=[f for f in frames if f[0]<b and a<f[1]]
            check(overlaps==[(a,b,r['frame']['fde'],r['frame']['cie'])],'manual unique FDE')
            for label in ['fde','cie']:
                x=r['records'][label];size=int.from_bytes(elf.read(x['va'],4),'little')+4
                check(elf.read(x['va'],size).hex()==x['hex'],'manual full unwind record')
            check(cies[r['frame']['cie']].hex()==r['records']['cie']['hex'],'manual CIE backlink')
            rows=[(i.address,bytes(i.bytes)) for i in decoded]
            for flavor in ['gnu','llvm']:
                check(listing((PACKET/f'{kind}{r["index"]}.{flavor}.txt').read_bytes())==rows,'retained listing boundary')
            if kind=='member':
                check((a,b)==BOUNDS[r['index']],'independent member bounds');body_bytes+=len(code)
                cmd=[args.objdump,'-d','-Mintel','--insn-width=16',f'--start-address={a:#x}',f'--stop-address={b:#x}','artifacts/node/94/hl-node']
                result=subprocess.run(cmd,cwd=ROOT,capture_output=True)
                check(result.returncode==0 and not result.stderr,'fresh GNU status')
                check(listing(result.stdout)==rows,'fresh GNU bytes');fresh.append(result.stdout)
                commands.append({'argv':cmd,'exit_code':result.returncode,'stdout_sha256':digest(result.stdout),'stderr_hex':result.stderr.hex()})
                callsites=[(i.address,int(i.op_str,16)) for i in decoded if i.mnemonic=='call']
                check(callsites==([] if r['index']==2 else [(0x514bca2 if r['index']==0 else 0x514bd12,0x5032f40)]),'helper closure')
                check(not any('rip' in i.op_str for i in decoded),'no static data operand')
            else:caller_bytes+=len(code);caller_instructions+=len(decoded)
            for i in decoded:
                if i.mnemonic=='call' and i.op_str.startswith('0x') and int(i.op_str,16) in [a for a,_ in BOUNDS]:all_sites[i.address]=int(i.op_str,16)
    text=elf.sections['.text'];code=elf.read(text[3],text[5],True);edges=[]
    for op in [0xe8,0xe9]:
        at=0
        while (at:=code.find(bytes([op]),at))>=0:
            if at+5<=len(code):
                target=text[3]+at+5+struct.unpack_from('<i',code,at+1)[0]
                if target in [a for a,_ in BOUNDS]:edges.append((op,text[3]+at,target))
            at+=1
    check(len(edges)==10 and all(op==0xe8 and target==0x5032f40 and all_sites.get(site)==target for op,site,target in edges),'complete direct encoding/caller closure')
    relas=0;protected_ranges=[(r['begin'],r['end']+(r.get('padding') or 0)) for r in record['members']+record['callers']]
    for s in elf.sections.values():
        check(s[1]!=9,'no unsupported REL')
        if s[1]!=4:continue
        check(s[9]==24 and s[5]%24==0,'RELA layout')
        for pos in range(s[4],s[4]+s[5],24):
            dst,info,addend=struct.unpack_from('<QQq',data,pos);relas+=1
            check(info&0xffffffff in (1,6,7,8,18),'reviewed relocation width')
            check(addend not in [a for a,_ in BOUNDS],'no entry-naming relocation')
            check(not any(dst<b and a<dst+8 for a,b in protected_ranges),'no selected code writer')
    check(relas==80300,'complete RELA count')
    check(before=={str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in protected},'reviewed source/evidence changed')
    (out/'fresh-members.gnu.txt').write_bytes(b'\n'.join(fresh));(out/'fresh-commands.json').write_bytes(encoded(commands))
    result={'target_sha256':TARGET,'reviewed_sha256':before,'independent_relation':'direct byte-slice interval walk, per-iteration snapshots including mandatory helper and explicit slot reload, incremental modular sum, deferred sole output store; no imported oracle/validator',
            'expected_sha256':digest(calculated),'coverage':coverage,'static':{'member_bytes':body_bytes,'member_instructions':65,'complete_fdes':len(record['members'])+len(record['callers']),'caller_bytes':caller_bytes,'caller_instructions':caller_instructions,'direct_calls':len(edges),'external_caller_fdes':len(record['callers']),'rela_records':relas,'manual_elf_frames_total':len(frames)},
            'findings':[],'limitations':['No native replay by reviewer.','No captured execution or instruction emulation.','Finite frozen inputs independently checked; full-domain termination/count bound reviewed mathematically.','Caller bodies checked as code/FDE/call-site context, not their algorithms or other helpers.','No hosted, original compiled-byte or whole-node equivalence claim.']}
    (out/'peer-review.json').write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
