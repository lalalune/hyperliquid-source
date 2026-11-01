"""Addressed byte/RELA binding controls; never evaluate captured instructions."""
import argparse
import json
from pathlib import Path
import struct
from survey import DATA, Image, InvalidEvidence, json_bytes, require, sha

HERE=Path(__file__).resolve().parent
CONTROL_SITES=[4889312, 4889314, 4889318, 4889322, 4889328, 4889335, 4889339, 4889342, 4889344, 4889349, 4889355, 4889360, 4889366, 4889371, 4889377, 4889382, 4889388, 4889393, 4889399, 4889404, 4889410, 4889415, 4889421, 4889426, 4889432, 4889437, 4889443, 4889446, 4889452, 4889458, 4889464, 4889470, 4889473, 4889493, 4889500, 4889506, 4889520, 4889527, 4889533, 4889550, 4889557, 4889563, 4889580, 4889587, 4889593, 4889613, 4889620, 4889636, 4889643, 4889659, 4889666, 4889682, 4889689, 4889705, 4889712, 4889728, 4889735, 4889748, 4889755, 4889761, 4889771, 4889785, 4889792, 4889798, 4889815, 4889822, 4889828, 4889845, 4889852, 4889868, 4889875, 4889891, 4889898, 4889904, 4889922, 4889929, 4889942, 4889949, 4889955, 4889969, 4889976, 4889982, 4889996, 4890003, 4890009, 4890015, 4890025, 4890031, 4890040, 4890050, 4890056, 4890062, 4890065, 4890082, 4890092, 4890098, 4890115, 4890125, 4890131, 4890141, 4890155, 4890165, 4890171, 4890188, 4890198, 4890211, 4890221, 4890227, 4890244, 4890254, 4890260, 4890280, 4890290, 4890303, 4890313, 4890319, 4890336, 4890346, 4890352, 4890369, 4890379, 4890385, 4890402, 4890412, 4890418, 4890435, 4890445, 4890451, 4890454, 4890467, 4890484, 4890490, 4890500, 4890526, 4890532, 4890542, 4890553, 4890559, 4890569, 4890579, 4890589, 4890600, 4890606, 4890619, 4890636, 4890642, 4890655, 4890672, 4890688, 4890694, 4890710, 4890727, 4890739, 4890756, 4890765, 4890782, 4890788, 4890801, 4890818, 4890824, 4890827, 4890834, 4890844, 4890850, 4890857, 4890867, 4890873, 4890876, 4890889, 4890895, 4890905, 4890915, 4890921, 4890934, 4890940, 4890950, 4890956, 4890966, 4890972, 4890979, 4890988, 4890994, 4891004, 4891010, 4891020, 4891026, 4891036, 4891042, 4891052, 4891058, 4891065, 4891071, 4891081, 4891083, 4891086, 4891099, 4891109, 4891120, 4891126, 4891139, 4891149, 4891160, 4891167, 4891186, 4891196, 4891211, 4891221, 4891233, 4891243, 4891249, 4891265, 4891275, 4891281, 4891297, 4891307, 4891313, 4891329, 4891339, 4891345, 4891348, 4891351, 4891354, 4891357, 4891360, 4891363, 4891366, 4891369, 4891372, 4891375, 4891378, 4891381, 4891384, 4891387, 4891390, 4891393, 4891396, 4891399, 4891402, 4891405, 4891408, 4891411, 4891414, 4891417, 4891420, 4891423, 4891426, 4891429, 4891432, 4891435, 4891438, 4891441, 4891444, 4891447, 4891450, 4891453, 4891456, 4891459, 4891462, 4891465, 4891468, 4891471, 4891474, 4891477, 4891480, 4891483, 4891486, 4891489, 4891492, 4891495, 4891498, 4891501, 4891504, 4891507, 4891510, 4891513, 4891516, 4891519, 4891522, 4891525, 4891528, 4891531, 4891534, 4891537, 4891540, 4891543, 4891546, 4891549, 4891552, 4891555]

def bindings(image,anchors):
    for address,row in anchors.items():
        expected=bytes.fromhex(row['bytes'])
        require(image.at(int(address,16),len(expected))==expected,'Addressed native bytes differ: '+address)
    image.relocations()
    for name,(va,data) in DATA.items():require(image.at(va,len(data))==data,'Bound table differs')

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
        for i in range(12):
            address=0x87d20+i*4
            offsets=[o+address-v for o,v,n in image.loads if v<=address and address+4<=v+n]
            require(len(offsets)==1,'Table mutation needs unique mapping')
            try:bindings(mutated(image,offsets[0]),anchors)
            except InvalidEvidence:controls.append({'tableEntry':i,'result':'rejected below image identity'})
            else:raise InvalidEvidence('Changed dispatch entry accepted')
        receipt={'targetSha256':sha(image.data),'instructionIdentityInventory':len(anchors),
                 'controls':controls,'capturedExecution':False,'instructionEvaluation':False,
                 'scope':'Bindings supporting the addressed manual proof; no automatic semantic proof, target execution or new byte-recovery credit.'}
        args.receipt.write_bytes(json_bytes(receipt));print(json.dumps(receipt))
    except (InvalidEvidence,OSError,UnicodeError) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
