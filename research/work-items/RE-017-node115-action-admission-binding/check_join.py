#!/usr/bin/env python3
"""Bind all retained serializer strings/classes and owned Rust rows to original ELF data."""
import argparse, copy, hashlib, importlib.util, json, re, struct
from pathlib import Path
import capstone
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP, X86_REG_RSP
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PIN='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
CLASSES=['ValidatorOnly','ValidatorOrListedAddress','AnySigner','ResolveKnownUser','Refused']

def require(ok,label):
    if not ok: raise ValueError(label)

def check(image,decoder,bindings,source):
    source_rows=re.findall(r'Action\s*\{\s*index:\s*(\d+),\s*rust_variant:\s*"([^"]+)",\s*wire_name:\s*"([^"]+)",\s*admission:\s*(\w+),?\s*\}',source)
    require(len(source_rows)==92,'92 owned rows')
    require(len(bindings)==6,'six serializer copies')
    checked=0
    for binding in bindings:
        table=int(binding['table'],16)
        require(len(binding['rows'])==92,'92 serializer arms')
        for i,record in enumerate(binding['rows']):
            require(record['index']==i,'sequential arm identity')
            arm=table+struct.unpack('<i',image.get(table+4*i,4))[0]
            require(arm==int(record['arm'],16),'relative arm target')
            rows=list(decoder.disasm(image.get(arm,140),arm));actual=[]
            for k,r in enumerate(rows):
                if r.mnemonic=='lea' and len(r.operands)>1 and r.operands[1].type==X86_OP_MEM and r.operands[1].mem.base==X86_REG_RIP:
                    pointer=r.address+r.size+r.operands[1].mem.disp
                    store,length=rows[k+1:k+3]
                    require(store.mnemonic=='mov' and store.operands[0].type==X86_OP_MEM and store.operands[0].mem.base==X86_REG_RSP,'stack string pointer')
                    require(length.mnemonic=='mov' and length.operands[0].type==X86_OP_MEM and length.operands[0].mem.base==X86_REG_RSP and length.operands[1].type==X86_OP_IMM,'string length store')
                    require(length.operands[0].mem.disp==store.operands[0].mem.disp+8,'adjacent pointer-length pair')
                    size=length.operands[1].imm
                    actual.append(dict(pointer=hex(r.address),store=hex(store.address),length=hex(length.address),address=hex(pointer),size=size,text=image.get(pointer,size).decode('ascii')))
                    if len(actual)==4:break
            require(actual==record['refs'],'native serializer pointer/length/text join')
            require(actual[0]['text']=='Action' and actual[2]['text']=='type','enum and tag-key identity')
            cls=image.get(0x79dd60+i,1)[0]
            require(cls==record['admission_class'] and cls<5,'native admission class')
            expected=(str(i),actual[1]['text'],actual[3]['text'],CLASSES[cls])
            require(source_rows[i]==expected,'owned source row binding')
            checked+=1
    return checked

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--target',type=Path,default=ROOT/'artifacts/node/115/hl-node');args=parser.parse_args()
    data=args.target.read_bytes();require(hashlib.sha256(data).hexdigest()==PIN,'original target digest')
    require(capstone.__version__=='5.0.7','Capstone5.0.7')
    path=ROOT/'research/work-items/RE-001-node115-registry-row-labels/verify.py'
    spec=importlib.util.spec_from_file_location('elf_support',path);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    image=helper.Image(data);decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);decoder.detail=True
    bindings=json.loads((HERE/'bindings.json').read_text())
    source=(ROOT/'src/node115-action-admission-binding/table.rs').read_text()
    count=check(image,decoder,bindings,source)
    controls=[]
    for kind in ('wrong class','wrong source spelling','wrong arm'):
        bad=copy.deepcopy(bindings);badsource=source
        if kind=='wrong class':bad[0]['rows'][25]['admission_class']=2
        elif kind=='wrong source spelling':badsource=source.replace('"VoteGlobalAction"','"voteGlobal"')
        else:bad[5]['rows'][20]['arm']=bad[5]['rows'][19]['arm']
        try:check(image,decoder,bad,badsource)
        except ValueError:controls.append(kind)
        else:raise ValueError('accepted corruption '+kind)
    expected=['index\tnominal_tag\trust_variant\twire_name\tadmission_class']
    for r in bindings[0]['rows']:
        expected.append(f"{r['index']}\t{hex(0x86+r['index'])}\t{r['refs'][1]['text']}\t{r['refs'][3]['text']}\t{r['admission_class']}")
    require((HERE/'bindings.tsv').read_text()=='\n'.join(expected)+'\n','human-readable join view')
    print(json.dumps({'target_sha256':PIN,'original_serializer_source_joins':count,'source_rows':92,'join_corruptions_rejected':controls,'target_execution':False},indent=2))
if __name__=='__main__':main()
