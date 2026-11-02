"""Addressed byte/RELA binding controls; never evaluate captured instructions."""
import argparse
import json
from pathlib import Path
import struct
from survey import Image, InvalidEvidence, json_bytes, require, sha

HERE=Path(__file__).resolve().parent
CONTROL_SITES=[0x3a1868,0x3a1884,0x3a1888,0x3a18ad,0x3a18b4,
    0x678e74,0x678edf,0x678f1f,0x678f41,0x694f27,0x694f33,
    0x67905d,0x679053,0x679130,0x679197,0x69505a,0x695076]

def bindings(image,anchors):
    for address,row in anchors.items():
        expected=bytes.fromhex(row['bytes'])
        require(image.at(int(address,16),len(expected))==expected,'Addressed native bytes differ: '+address)
    image.relocations()

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
        for slot in (0x7e5ef8,0x7e5f30,0x7e4d28):
            offsets=[]
            for section in image.sections:
                if section[1]!=4:continue
                for offset in range(section[4],section[4]+section[5],24):
                    if struct.unpack_from('<Q',image.data,offset)[0]==slot:offsets.append(offset+16)
            require(len(offsets)==1,'RELA mutation needs unique record')
            try:bindings(mutated(image,offsets[0]),anchors)
            except InvalidEvidence:controls.append({'relocation':hex(slot),'result':'rejected below image identity'})
            else:raise InvalidEvidence('RELA binding mutation accepted')
        receipt={'targetSha256':sha(image.data),'instructionIdentityInventory':len(anchors),
                 'controls':controls,'capturedExecution':False,'instructionEvaluation':False,
                 'scope':'Bindings supporting the addressed manual proof; no automatic semantic proof, target execution or new byte-recovery credit.'}
        args.receipt.write_bytes(json_bytes(receipt));print(json.dumps(receipt))
    except (InvalidEvidence,OSError,UnicodeError) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
