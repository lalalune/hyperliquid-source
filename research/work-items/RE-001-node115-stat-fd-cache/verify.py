#!/usr/bin/env python3
"""Reproduce target-bound static observations; never executes the target."""
import argparse,copy,hashlib,json,os,re,shutil,struct,subprocess,sys
from pathlib import Path
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import fde_extents
import capstone

def require(ok,message):
    if not ok:raise ValueError(message)
def mapping(data,secs,va,n):
    choices=[s for s in secs if s['type']!=8 and s['address']<=va and va+n<=s['address']+s['size']]
    require(len(choices)==1,'ambiguous/unmapped bytes')
    s=choices[0];off=s['offset']+va-s['address'];return data[off:off+n]
def relocations(data,secs):
    section=lambda n:next(s for s in secs if s['name']==n)
    sy=section('.dynsym');st=section('.dynstr');rd=section('.rela.dyn');out={}
    for off in range(rd['offset'],rd['offset']+rd['size'],24):
        slot,info,add=struct.unpack_from('<QQq',data,off);typ=info&0xffffffff;symbol=info>>32
        row={'slot':hex(slot),'type':typ}
        if symbol:
            name=struct.unpack_from('<I',data,sy['offset']+symbol*24)[0]+st['offset'];end=data.index(b'\0',name,st['offset']+st['size']);row['symbol']=data[name:end].decode('ascii')
        else:row['addend']=hex(add)
        out[slot]=row
    return out

def check(data,spec,secs,cies,fdes,rels):
    require(hashlib.sha256(data).hexdigest()==spec['targetSHA256'],'target digest')
    for r in spec['ranges']:
        start,end=r['fde']['start'],r['fde']['end'];found=[f for f in fdes if f['start']==start]
        require(len(found)==1 and found[0]==r['fde'],'FDE identity/extent')
        require(cies[found[0]['cie']]==r['cie'],'CIE metadata')
        body=mapping(data,secs,start,end-start)
        require(hashlib.sha256(body).hexdigest()==r['bodySHA256'],'body digest')
        offset=0
        for ins in r['instructions']:
            b=bytes.fromhex(ins['bytes']);require(int(ins['va'],16)==start+offset,'instruction coverage/address');require(body[offset:offset+len(b)]==b,'instruction bytes');offset+=len(b)
        require(offset==len(body),'full FDE byte denominator')
    for a in spec['anchors']:
        b=bytes.fromhex(a['bytes']);require(mapping(data,secs,int(a['va'],16),len(b))==b,'semantic observation anchor')
    a=spec['literal'];b=bytes.fromhex(a['hex']);require(mapping(data,secs,int(a['va'],16),len(b))==b,'parent literal')
    for expected in spec['imports']+spec['relativeRelocations']:
        require(rels.get(int(expected['slot'],16))==expected,'import/relative relocation identity')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');ap.add_argument('--objdump',default='objdump');ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    spec=json.loads((P/'spec.json').read_text());data=args.target.read_bytes();secs=fde_extents.sections(data);cies,fdes=fde_extents.eh_frame_records(data,secs);rels=relocations(data,secs);check(data,spec,secs,cies,fdes,rels)
    out=args.output;out.mkdir(parents=True,exist_ok=True);md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);results=[]
    for row in spec['ranges']:
        start,end=row['fde']['start'],row['fde']['end'];body=mapping(data,secs,start,end-start);decoded=list(md.disasm(body,start));pairs=[(i.address,i.bytes.hex()) for i in decoded];want=[(int(i['va'],16),i['bytes']) for i in row['instructions']];require(pairs==want,'Capstone complete instruction pairs')
        command=[args.objdump,'-d','--wide','--insn-width=16','-M','intel','--start-address='+str(start),'--stop-address='+str(end),str(args.target)]
        run=subprocess.run(command,capture_output=True,check=True,timeout=30);text='\n'.join(line.rstrip() for line in run.stdout.decode().splitlines())+'\n';gnu=[]
        for line in text.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m and start<=int(m[1],16)<end:gnu.append((int(m[1],16),bytes.fromhex(m[2]).hex()))
        require(gnu==pairs,'GNU/Capstone complete instruction pairs')
        # Display path only; no instruction or operand bytes are normalized.
        (out/(row['label']+'.objdump.txt')).write_text(text.replace(str(args.target),'artifacts/node/115/hl-node'),encoding='utf-8',newline='\n')
        results.append({'label':row['label'],'start':hex(start),'end':hex(end),'bytes':len(body),'instructions':len(pairs),'bodySHA256':hashlib.sha256(body).hexdigest(),'dualDecoderBytePairsEqual':True})
    controls=[]
    def reject(name,change):
        bad=copy.deepcopy(spec);change(bad)
        try:check(data,bad,secs,cies,fdes,rels)
        except ValueError as e:controls.append({'name':name,'rejected':True,'reason':str(e)})
        else:raise ValueError('Comparator accepted corruption: '+name)
    reject('wrong target digest',lambda s:s.update(targetSHA256='0'*64))
    reject('shifted FDE start',lambda s:s['ranges'][0]['fde'].update(start=s['ranges'][0]['fde']['start']+1))
    reject('truncated FDE end',lambda s:s['ranges'][0]['fde'].update(end=s['ranges'][0]['fde']['end']-1))
    reject('changed instruction payload',lambda s:s['ranges'][0]['instructions'][0].update(bytes='90'))
    reject('resource immediate anchor7 to8',lambda s:s['anchors'][0].update(bytes='bf08000000'))
    reject('parent stat literal changed',lambda s:s['literal'].update(hex='73746178'))
    reject('close import swapped',lambda s:s['imports'][0].update(symbol='read'))
    reject('initializer relocation changed',lambda s:s['relativeRelocations'][0].update(addend='0x5cbae41'))
    version=subprocess.run([args.objdump,'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.splitlines()[0]
    record={'targetSHA256':spec['targetSHA256'],'sourceCommit':spec['sourceCommit'],'ranges':results,'completeFDEExtents':len(results),'decodedBytes':sum(r['bytes'] for r in results),'instructionPairs':sum(r['instructions'] for r in results),'compiledSourceComparisons':0,'normalizedOperands':[],'controls':controls,'controlScope':'Corrupted evidence records rejected against authenticated target; not execution, behavioral differential or source equivalence tests','tools':{'python':sys.version.split()[0],'capstoneReported':capstone.__version__,'objdump':version},'targetExecutedOrEmulated':False}
    (out/'verification.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(record),flush=True)
if __name__=='__main__':main()
