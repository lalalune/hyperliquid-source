"""Addressed byte/RELA binding controls; never evaluate captured instructions."""
import argparse
import json
from pathlib import Path
import struct
from survey import DATA, Image, InvalidEvidence, json_bytes, require, sha

HERE=Path(__file__).resolve().parent
CONTROL_SITES=[4901423, 4901426, 4901436, 4901518, 4901534, 4901641, 4901644, 4901649, 4885598, 4885622, 4885657, 4885660, 4885675, 4885686, 4885692, 4885694, 4885770, 4885809, 4885815, 4881455, 4881482, 4881505, 4901747, 4881411, 4891707, 4891711, 4891770, 4898456, 4898572, 4898817, 4898839, 4898843, 4899914, 4902472, 4902475, 4902763, 4902768, 4902770, 4903080, 4903083, 4903086, 4903089, 4901964, 4902062]

def bindings(image,anchors):
    for address,row in anchors.items():
        expected=bytes.fromhex(row['bytes'])
        require(image.at(int(address,16),len(expected))==expected,'Addressed native bytes differ: '+address)
    image.relocations()
    for name,(va,expected) in DATA.items():
        require(image.at(va,len(expected))==expected,'Bound data differs: '+name)

def mutated(image,offset):
    raw=bytearray(image.data);raw[offset]^=1
    candidate=object.__new__(Image)
    candidate.data=bytes(raw);candidate.loads=image.loads;candidate.sections=image.sections
    return candidate

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    args=parser.parse_args()
    try:
        require(not args.receipt.exists(),'Preserve existing receipt')
        image=Image(args.binary.read_bytes())
        anchors=json.loads((HERE/'anchors.json').read_bytes())
        bindings(image,anchors)
        controls=[]
        for address in CONTROL_SITES:
            size=len(bytes.fromhex(anchors[hex(address)]['bytes']))
            offsets=[offset+address-va+size-1 for offset,va,length in image.loads
                     if va<=address and address+size<=va+length]
            require(len(offsets)==1,'Mutation needs unique mapping')
            try:bindings(mutated(image,offsets[0]),anchors)
            except InvalidEvidence:controls.append({'instruction':hex(address),'result':'rejected below image identity'})
            else:raise InvalidEvidence('Instruction binding mutation accepted')
        for slot in (0x7e4cc8,0x7e4c20,0x7e4c50,0x7e5f38,0x7e6d38,0x7e6d40,0x7e6d48,0x7e6d50,0x7e6d58,0x7e6d60):
            offsets=[]
            for section in image.sections:
                if section[1]!=4:continue
                for offset in range(section[4],section[4]+section[5],24):
                    if struct.unpack_from('<Q',image.data,offset)[0]==slot:offsets.append(offset+16)
            require(len(offsets)==1,'RELA mutation needs unique record')
            try:bindings(mutated(image,offsets[0]),anchors)
            except InvalidEvidence:controls.append({'relocation':hex(slot),'result':'rejected below image identity'})
            else:raise InvalidEvidence('RELA binding mutation accepted')
        for name,(address,data) in DATA.items():
            offsets=[o+address-v for o,v,n in image.loads if v<=address and address+len(data)<=v+n]
            require(len(offsets)==1,'Data control needs unique mapping')
            try:bindings(mutated(image,offsets[0]),anchors)
            except InvalidEvidence:controls.append({'data':name,'result':'rejected below image identity'})
            else:raise InvalidEvidence('Data binding mutation accepted')
        receipt={'targetSha256':sha(image.data),'instructionIdentityInventory':len(anchors),
                 'controls':controls,'capturedExecution':False,'instructionEvaluation':False,
                 'scope':'Bindings supporting the addressed manual proof; no automatic semantic proof, target execution or new byte-recovery credit.'}
        args.receipt.write_bytes(json_bytes(receipt));print(json.dumps(receipt))
    except (InvalidEvidence,OSError,UnicodeError) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
