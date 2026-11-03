#!/usr/bin/env python3
"""Reproduce six native FDE observations. Static only: never execute the capture."""
import argparse,copy,hashlib,json,re,struct,subprocess,sys
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import fde_extents
import capstone

def require(ok,label):
    if not ok:raise ValueError(label)
def mapping(data,secs,va,n):
    matches=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    require(len(matches)==1,'ambiguous/unmapped bytes');s=matches[0];off=s['offset']+va-s['address'];return data[off:off+n]
def check(data,secs,cies,index,relocs,spec,bindings):
    require(hashlib.sha256(data).hexdigest()==spec['targetSHA256'],'target digest')
    starts=set()
    for row in spec['ranges']:
        f=row['fde'];a,b=f['start'],f['end'];found=index.get(a,[])
        require(len(found)==1 and found[0]==f,'unique FDE identity/extent');require(cies[f['cie']]==row['cie'],'CIE')
        body=mapping(data,secs,a,b-a);require(hashlib.sha256(body).hexdigest()==row['bodySHA256'],'body digest')
        offset=0
        for ins in row['instructions']:
            raw=bytes.fromhex(ins['bytes']);require(int(ins['va'],16)==a+offset,'complete instruction address sequence');require(body[offset:offset+len(raw)]==raw,'instruction bytes');starts.add(a+offset);offset+=len(raw)
        require(offset==b-a,'full FDE denominator')
    for binding in bindings:
        require(binding['targetSHA256']==spec['targetSHA256'],'binding target')
        for call in binding['indirectCalls']:
            va,slot=int(call['callVA'],16),int(call['slot'],16);raw=mapping(data,secs,va,6)
            require(va in starts and raw[:2]==b'\xff\x15' and raw.hex()==call['instructionBytes'],'indirect instruction')
            require(va+6+struct.unpack_from('<i',raw,2)[0]==slot,'actual call slot')
            expected=call['relocation'];require(relocs.get(slot)==[(expected['symbolIndex'],expected['type'],int(expected['addend'],16))],'unique RELATIVE binding')
            require(index.get(int(expected['addend'],16))==expected['fdeCandidates'],'callee FDE candidates')
        for table in binding['dispatchTables']:
            va,tableva=int(table['leaVA'],16),int(table['tableVA'],16);raw=mapping(data,secs,va,7)
            require(va in starts and raw[:3] in (b'\x4c\x8d\x05',b'\x4c\x8d\x0d'),'table LEA start')
            require(va+7+struct.unpack_from('<i',raw,3)[0]==tableva,'actual table LEA displacement')
            raw=mapping(data,secs,tableva,16);require(raw.hex()==table['bytes'],'table bytes')
            targets=[tableva+v for v in struct.unpack('<iiii',raw)]
            require(targets==[int(v,16) for v in table['targets']] and all(v in starts for v in targets),'table targets/instruction boundaries')
    # Close ordinary aggregate calls to the measured corresponding scalar bodies.
    for start,callee in [(0x2cd7d90,0x2cd7ac0),(0x5821540,0x5821250)]:
        row=next(r for r in spec['ranges'] if r['fde']['start']==start);targets=[]
        for ins in row['instructions']:
            raw=bytes.fromhex(ins['bytes'])
            if raw[0]==0xe8 and len(raw)==5:targets.append(int(ins['va'],16)+5+struct.unpack_from('<i',raw,1)[0])
        require(targets==[callee]*4,'four actual direct scalar calls')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');ap.add_argument('--objdump',default='objdump');ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    spec=json.loads((P/'spec.json').read_text());bindings=[json.loads((P/n).read_text()) for n in ['scalar-reader-bindings.json','slow-reader-bindings.json']]
    data=args.target.read_bytes();secs=fde_extents.sections(data);cies,fdes=fde_extents.eh_frame_records(data,secs);index={}
    for f in fdes:index.setdefault(f['start'],[]).append(f)
    section=next(s for s in secs if s['name']=='.rela.dyn');relocs={}
    for off in range(section['offset'],section['offset']+section['size'],24):
        slot,info,add=struct.unpack_from('<QQq',data,off);relocs.setdefault(slot,[]).append((info>>32,info&0xffffffff,add))
    check(data,secs,cies,index,relocs,spec,bindings);args.output.mkdir(parents=True,exist_ok=True)
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);rows=[]
    for row in spec['ranges']:
        a,b=row['fde']['start'],row['fde']['end'];want=[(int(i['va'],16),i['bytes']) for i in row['instructions']]
        decoded=[(i.address,i.bytes.hex()) for i in md.disasm(mapping(data,secs,a,b-a),a)];require(decoded==want,'Capstone complete byte pairs')
        command=[args.objdump,'-d','--wide','--insn-width=16','-M','intel','--start-address='+str(a),'--stop-address='+str(b),str(args.target)]
        run=subprocess.run(command,capture_output=True,check=True,timeout=30);(args.output/(hex(a)+'.objdump')).write_bytes(run.stdout);gnu=[]
        for line in run.stdout.decode().splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m and a<=int(m[1],16)<b:gnu.append((int(m[1],16),bytes.fromhex(m[2]).hex()))
        require(gnu==want,'GNU complete byte pairs');rows.append({'start':hex(a),'end':hex(b),'bytes':b-a,'instructionPairs':len(want),'bodySHA256':row['bodySHA256']})
    controls=[]
    def reject(name,mutation):
        s=copy.deepcopy(spec);bs=copy.deepcopy(bindings);mutation(s,bs)
        try:check(data,secs,cies,index,relocs,s,bs)
        except ValueError as e:controls.append({'name':name,'rejected':True,'reason':str(e)})
        else:raise ValueError('accepted corruption '+name)
    reject('wrong target',lambda s,b:s.update(targetSHA256='0'*64))
    reject('shifted start',lambda s,b:s['ranges'][0]['fde'].update(start=s['ranges'][0]['fde']['start']+1))
    reject('truncated end',lambda s,b:s['ranges'][0]['fde'].update(end=s['ranges'][0]['fde']['end']-1))
    reject('changed instruction',lambda s,b:s['ranges'][2]['instructions'][1].update(bytes='833e00'))
    reject('wrong call slot',lambda s,b:b[0]['indirectCalls'][0].update(slot='0x64e6c40'))
    reject('wrong RELATIVE callee',lambda s,b:b[0]['indirectCalls'][0]['relocation'].update(addend='0x5822700'))
    reject('dispatch entry changes',lambda s,b:b[0]['dispatchTables'][0].update(bytes='00'*16))
    reject('swapped valid dispatch targets',lambda s,b:b[1]['dispatchTables'][0]['targets'].reverse())
    result={'targetSHA256':spec['targetSHA256'],'rows':rows,'fullFDEs':len(rows),'bytes':sum(r['bytes'] for r in rows),'instructionPairs':sum(r['instructionPairs'] for r in rows),'masks':[],'metadataControls':controls,'scope':'static instruction/metadata correspondence only; no dynamic target behavior or compiled-source/target identity claim','targetExecutedOrEmulated':False}
    (args.output/'static-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result),flush=True)
if __name__=='__main__':main()
