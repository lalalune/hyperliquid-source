"""Independent event/snapshot value oracle and direct ELF/body/caller review.
No packet imports, captured execution, instruction emulation or native replay.
"""
import argparse,gzip,hashlib,json,re,struct
from pathlib import Path
import capstone
N=1<<64
STARTS=[0x5657540,0x56575a0,0x5657620,0x5657700,0x5657880,0x56579a0]
ENDS=[0x5657598,0x5657616,0x56576e4,0x5657866,0x5657998,0x5657bbd]
SIZES=[32,48,96,192,144,288]
TARGET='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
def need(ok,msg):
    if not ok:raise ValueError(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def listing(path):
    result=[]
    for line in path.read_text().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$',line)
        if m:result.append((int(m[1],16),bytes.fromhex(m[2])))
    return result

def inspect(repo):
    p=repo/'research/work-items/RE-004-simd-selection-family-rust-94'
    rawin=gzip.decompress((p/'inputs.bin.gz').read_bytes());rawout=gzip.decompress((p/'expected.bin.gz').read_bytes());frozen=json.loads((p/'frozen.json').read_text())
    need(len(rawin)%704==0 and len(rawout)==len(rawin)//704*688,'fixture framing')
    counts={'cases':0,'refusals':0,'admitted_per_member':[0]*6,'staged_alias_differences_per_member':[0]*6}
    witnesses={'nonzero_high_only_control':0,'preserved_high_rax':0,'nonaligned_addresses':0,'all_three_spans_overlap':0,'unselected_source_missing':0,'image_overflow_with_accesses_fitting':0}
    for number in range(len(rawin)//704):
        row=rawin[number*704:(number+1)*704];member,base,a,b,d,c,r,length=struct.unpack_from('<8Q',row);entry=row[64:]
        need(member<6 and length<=640,'descriptor');width=SIZES[member];blocks=width//16
        # Events are independent timestamped observations, not the source's
        # current/next buffer loop or the original oracle's byte-origin recursion.
        events=[]
        for block in range(blocks):events.extend([(3*block,'A',block),(3*block+1,'B',block),(3*block+5,'D',block)])
        events.sort();addresses={'A':a,'B':b,'D':d}
        spans={role:all(base<=start+16*j and start+16*j+16<=min(base+length,N) for j in range(blocks)) for role,start in addresses.items()}
        admitted=base+length<=N and all(spans.values())
        select='B' if c.to_bytes(8,'little')[:4]==bytes(4) else 'A'
        if admitted:
            memory=bytearray(entry);snapshots={}
            for _,role,block in events:
                offset=addresses[role]+16*block-base
                if role in ['A','B']:snapshots[role,block]=bytes(memory[offset:offset+16])
                else:memory[offset:offset+16]=snapshots[select,block]
            # Final observation arithmetic is computed from the explicit byte
            # displacement, with unbounded addition then reduction.
            registers=(1,r,c,*((x+width//2)%N for x in [d,a,b]))
            updated=bytes(memory);counts['admitted_per_member'][member]+=1
            selected=addresses[select]-base
            staged=updated[d-base:d-base+width]!=entry[selected:selected+width]
            counts['staged_alias_differences_per_member'][member]+=staged
            witnesses['nonzero_high_only_control']+=c!=0 and select=='B'
            witnesses['preserved_high_rax']+=r>=1<<32
            witnesses['nonaligned_addresses']+=any(x%16 for x in [a,b,d])
            witnesses['all_three_spans_overlap']+=max(a,b,d)<min(a+width,b+width,d+width)
        else:
            registers=(0,)*6;updated=entry;counts['refusals']+=1
            other='A' if select=='B' else 'B'
            witnesses['unselected_source_missing']+=base+length<=N and spans[select] and spans['D'] and not spans[other]
            witnesses['image_overflow_with_accesses_fitting']+=base+length>N and all(spans.values())
        wanted=struct.pack('<6Q',*registers)+updated
        need(wanted==rawout[number*688:(number+1)*688],f'event-oracle mismatch at fixture {number}')
        counts['cases']+=1
    need(all(counts[k]==frozen[k] for k in counts),'independent frozen counts')
    need(sha(rawin)==frozen['inputs_sha256'] and sha(rawout)==frozen['expected_sha256'],'fixture hashes')
    need(all(witnesses.values()),'required domain witnesses')

    binary=(repo/'artifacts/node/94/hl-node').read_bytes();need(len(binary)==91774280 and sha(binary)==TARGET,'target')
    shoff=struct.unpack_from('<Q',binary,40)[0];shsize,shnum,strings=struct.unpack_from('<HHH',binary,58);need(shsize==64,'ELF64 sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',binary,shoff+i*64) for i in range(shnum)];ns=sections[strings];names=binary[ns[4]:ns[4]+ns[5]]
    def name(s):return names[s[0]:].split(b'\0',1)[0].decode()
    def mapped(address,width):
        found=[s for s in sections if s[1]!=8 and s[3]<=address and address+width<=s[3]+s[5]];need(len(found)==1,'unique file mapping')
        s=found[0];at=s[4]+address-s[3];return binary[at:at+width],s
    static=json.loads((p/'static.json').read_text());need(len(static['members'])==6 and len(static['callers'])==34,'context counts')
    dec=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);dec.detail=True
    frame_records=[]
    def frame(record,start,end):
        fr=record['records']['fde'];at=fr['file_offset'];size,relative_cie,relative_pc,extent=struct.unpack_from('<IIiI',binary,at)
        need(at+8+relative_pc==start and extent==end-start,'actual relative FDE words')
        need(binary[at:at+size+4].hex()==fr['hex'],'full FDE bytes')
        cie=at+4-relative_cie;cr=record['records']['cie']
        need(cie==cr['file_offset'] and binary[cie:cie+24].hex()=='1400000000000000017a5200017810011b0c070890010000','actual zR CIE')
        frame_records.append({'start':start,'end':end,'fde':at,'cie':cie})
    bodies=[];all_leaf_rows=[]
    for i,(start,end,width,m) in enumerate(zip(STARTS,ENDS,SIZES,static['members'])):
        raw,section=mapped(start,end-start);need(name(section)=='.text' and raw.hex()==m['hex'] and sha(raw)==m['body_sha256'],'complete leaf bytes')
        frame(m,start,end);need(mapped(end,m['padding'])[0].hex()==m['padding_hex'],'padding')
        decoded=list(dec.disasm(raw,start));rows=[(x.address,bytes(x.bytes)) for x in decoded]
        need(rows==listing(p/f'member{i}.gnu.txt')==listing(p/f'member{i}.llvm.txt'),'leaf decoder boundaries')
        need(sum(len(x[1]) for x in rows)==end-start,'complete leaf decoding');all_leaf_rows.extend(rows)
        # Exact static grammar of the mask network, without evaluating vector
        # values or emulating instructions. Memory events are checked separately.
        arithmetic=[(x.mnemonic,x.op_str.replace(' ','')) for x in decoded if x.mnemonic not in ['movdqu','lea']]
        expected=[('endbr64',''),('movd','xmm5,ecx'),('pxor','xmm4,xmm4'),('pshufd','xmm5,xmm5,0'),('pcmpeqd','xmm5,xmm4'),('pcmpeqd','xmm4,xmm5')]
        for block in range(width//16):
            even=0 if block%2==0 else 2;expected.extend([('pand',f'xmm{even},xmm4'),('pand',f'xmm{even+1},xmm5'),('por',f'xmm{even},xmm{even+1}')])
        expected.append(('repz ret',''));need(arithmetic==expected,'complete selector/merge grammar')
        bias={};events=[];loads={'A':0,'B':0};stores=0
        for ins in decoded:
            if ins.mnemonic=='lea':
                dst,mem=ins.operands;reg=ins.reg_name(dst.reg)
                need(reg in ['rdi','rsi','rdx'] and reg not in bias and mem.type==capstone.CS_OP_MEM and ins.reg_name(mem.mem.base)==reg and mem.mem.index==0 and mem.mem.disp==width//2,'full-width LEA advance')
                bias[reg]=mem.mem.disp
            if ins.mnemonic=='movdqu':
                mems=[(j,o) for j,o in enumerate(ins.operands) if o.type==capstone.CS_OP_MEM];need(len(mems)==1,'memory operand')
                j,mem=mems[0];reg=ins.reg_name(mem.mem.base);role={'rsi':'A','rdx':'B','rdi':'D'}[reg]
                need(mem.mem.index==0 and mem.mem.segment==0 and mem.size==16,'memory width/address')
                offset=mem.mem.disp+bias.get(reg,0);events.append((role,offset))
                need((j==0)==(role=='D'),'load/store role')
                vector=ins.reg_name(ins.operands[1-j].reg)
                block=stores if role=='D' else loads[role];want=2*(block%2)+(role=='B')
                need(vector==f'xmm{want}','block snapshot register role')
                if role=='D':stores+=1
                else:loads[role]+=1
        need(bias=={'rsi':width//2,'rdx':width//2,'rdi':width//2},'all advances')
        wanted_events=sorted((time,role,block*16) for block in range(width//16) for time,role in [(3*block,'A'),(3*block+1,'B'),(3*block+5,'D')])
        need(events==[(role,off) for _,role,off in wanted_events],'snapshot event order')
        bodies.append({'start':start,'bytes':len(raw),'instructions':len(decoded),'sha256':sha(raw),'events':len(events),'advance':width//2})
    need(all_leaf_rows==listing(p/'peer/fresh-members.gnu.txt'),'fresh GNU leaf bytes/boundaries')
    caller_records=[];edge_boundaries={}
    for c in static['callers']:
        start,end=c['begin'],c['end'];raw,section=mapped(start,end-start);need(name(section)=='.text' and sha(raw)==c['body_sha256'],'full caller bytes');frame(c,start,end)
        decoded=list(dec.disasm(raw,start));rows=[(x.address,bytes(x.bytes)) for x in decoded]
        need(rows==listing(p/f'caller{c["index"]}.gnu.txt')==listing(p/f'caller{c["index"]}.llvm.txt'),'complete caller boundaries')
        need(sum(len(x[1]) for x in rows)==end-start and len(decoded)==c['instructions'],'full caller decoding')
        own=[]
        for ins in decoded:
            if ins.mnemonic in ['call','jmp'] and len(ins.bytes)==5 and ins.bytes[0] in [0xe8,0xe9]:
                target=ins.address+5+struct.unpack_from('<i',ins.bytes,1)[0]
                if target in STARTS:edge_boundaries[ins.address]=target;own.append(ins.address)
        need(own==c['sites'],'all selected caller edges')
        caller_records.append({'start':start,'bytes':len(raw),'instructions':len(decoded),'sha256':sha(raw),'sites':own})
    tx=next(s for s in sections if name(s)=='.text');code=binary[tx[4]:tx[4]+tx[5]];hits={};targets={}
    for opcode,label in [(b'\xe8','E8'),(b'\xe9','E9')]:
        pos=0;found=[]
        while (pos:=code.find(opcode,pos))>=0:
            if pos+5<=len(code):
                target=tx[3]+pos+5+struct.unpack_from('<i',code,pos+1)[0]
                if target in STARTS:found.append(tx[3]+pos);targets[tx[3]+pos]=target
            pos+=1
        need(found==static['direct_candidates'][label],'complete direct candidate census');hits[label]=found
    need(targets==edge_boundaries,'every direct candidate on a decoded caller boundary')
    relas=[]
    for s in sections:
        need(s[1]!=9,'unexpected REL')
        if s[1]==4:
            need(s[9]==24 and s[5]%24==0,'RELA shape')
            for at in range(s[4],s[4]+s[5],24):
                dst,info,add=struct.unpack_from('<QQq',binary,at);need(info&0xffffffff in [1,6,7,8,18],'known write width')
                need(add not in STARTS,'no entry naming relocation')
                need(not any(dst<m['end']+m['padding'] and m['begin']<dst+8 for m in static['members']),'no leaf/padding writer')
                relas.append((at,dst,info,add))
    need(len(relas)==80300,'RELA census')
    paths=[repo/'src/node94-simd-selection-family/lib.rs',repo/'src/node94-simd-selection-family/input_only_driver.rs']+[p/x for x in ['PROOF.md','oracle.py','frozen.json','verify_static.py','static.json']]
    if (p/'README.md').exists():paths.append(p/'README.md')
    return {'target_sha256':TARGET,'reviewed_hashes':{str(x.relative_to(repo)):sha(x.read_bytes()) for x in paths},'method':'Timestamped A/B block snapshots and staged stores; full register observations and per-block admission, no byte-origin recurrence. Independent struct ELF/FDE/RELA parsing and Capstone static instruction grammar; fresh GNU leaves and complete retained caller exports.',**counts,'witnesses':witnesses,'fixture_mismatches':0,'leaf_bodies':bodies,'caller_records':caller_records,'checked_fde_records':len(frame_records),'caller_total_bytes':sum(x['bytes'] for x in caller_records),'caller_total_instructions':sum(x['instructions'] for x in caller_records),'direct_e8':len(hits['E8']),'direct_e9':len(hits['E9']),'rela_records':len(relas),'captured_execution':False,'instruction_emulation':False,'native_replay':False,'assessment':'No blocker: staged aliases, low32 control, full five-register return and atomic finite-image admission agree. Caller checks bind boundaries/edges only; caller algorithms are not reconstructed.'}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=Path,default=Path.cwd());parser.add_argument('--out',type=Path);args=parser.parse_args()
    result=inspect(args.repo.resolve());result['review_script_sha256']=sha(Path(__file__).read_bytes());text=json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args.out:args.out.write_text(text)
    else:print(text,end='')
if __name__=='__main__':main()
