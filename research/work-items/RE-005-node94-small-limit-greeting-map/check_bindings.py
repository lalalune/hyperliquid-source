"""Isolated native/data/RELA/transfer identity controls, not semantic execution."""
from pathlib import Path
import json,struct,argparse
from survey import Image,InvalidEvidence,DATA,TRANSFERS,RECIPE,require,json_bytes,sha
HERE=Path(__file__).resolve().parent
def instruction_check(image,anchors):
    for va,row in anchors.items():
        raw=bytes.fromhex(row['bytes']);require(image.at(int(va,16),len(raw))==raw,'Native identity differs')
def data_check(image):
    for va,raw in DATA.values():require(image.at(va,len(raw))==raw,'Bound data differs')
def transfers(image):
    for row in TRANSFERS:
        va=row['va'];raw=image.at(va,5)
        require(raw[0]==row['opcode'] and va+5+struct.unpack('<i',raw[1:])[0]==row['destination'],'Call/tail binding differs')
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);a=p.parse_args()
    require(not a.receipt.exists(),'Preserve receipt');image=Image(a.binary.read_bytes());anchors=json.loads((HERE/'anchors.json').read_bytes())
    instruction_check(image,anchors);data_check(image);image.relocations();transfers(image)
    def offset(va,n=1):
        found=[o+va-v for o,v,size in image.loads if v<=va and va+n<=v+size];require(len(found)==1,'Unique mutation mapping required');return found[0]
    controls=[]
    def reject(off,check,kind,site):
        raw=bytearray(image.data);raw[off]^=1
        c=object.__new__(Image);c.data=bytes(raw);c.loads=image.loads;c.sections=image.sections
        try:check(c)
        except InvalidEvidence:controls.append({'kind':kind,'site':site,'result':'rejected below full-image identity'})
        else:raise InvalidEvidence('Changed binding accepted')
    for va,row in anchors.items():
        n=len(bytes.fromhex(row['bytes']));reject(offset(int(va,16),n)+n-1,lambda c:instruction_check(c,anchors),'instruction',va)
    for va,raw in DATA.values():
        for i in range(len(raw)):reject(offset(va,len(raw))+i,data_check,'bound-data-byte',hex(va+i))
    for row in TRANSFERS:reject(offset(row['va'],5)+4,transfers,'direct-'+row['kind'],hex(row['va']))
    for slot in map(int,RECIPE['slots']):
        found=[]
        for section in image.sections:
            if section[1]!=4:continue
            for off in range(section[4],section[4]+section[5],24):
                if struct.unpack_from('<Q',image.data,off)[0]==slot:found.append(off+16)
        require(len(found)==1,'Unique RELA required');reject(found[0],lambda c:c.relocations(),'RELA-addend',hex(slot))
    receipt={'targetSha256':sha(image.data),'nativeIdentityRows':len(anchors),'controls':controls,
      'scope':'Byte identities supporting the addressed conditional proof; includes explicitly credited context. Not semantic coverage, CPU interpretation, target execution or recovered-byte credit.',
      'capturedExecution':False,'instructionEvaluation':False}
    a.receipt.write_bytes(json_bytes(receipt));print(json.dumps({'controls':len(controls),'nativeIdentityRows':len(anchors)}))
if __name__=='__main__':main()
