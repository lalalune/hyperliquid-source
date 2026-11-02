"""Below-full-identity negative controls on manually admitted proof obligations."""
import argparse,json,struct
from pathlib import Path
from survey import Image,InvalidEvidence,RECIPE,DATA,TRANSFERS,require,json_bytes,sha
HERE=Path(__file__).resolve().parent
def native(image,anchors):
    for va,row in anchors.items():
        raw=bytes.fromhex(row['bytes']);require(image.at(int(va,16),len(raw))==raw,'Native byte binding differs')
def data_check(image):
    for va,expected in DATA.values():require(image.at(va,len(expected))==expected,'Data binding differs')
def transfers(image):
    for row in TRANSFERS:
        va=row['va'];raw=image.at(va,5)
        require(raw[0]==row['opcode'] and va+5+struct.unpack('<i',raw[1:])[0]==row['destination'],'Direct transfer differs')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);args=p.parse_args()
    require(not args.receipt.exists(),'Preserve existing receipt')
    image=Image(args.binary.read_bytes());anchors=json.loads((HERE/'anchors.json').read_bytes())
    native(image,anchors);image.relocations();data_check(image);transfers(image)
    def offset(va,size=1):
        found=[o+va-v for o,v,n in image.loads if v<=va and va+size<=v+n]
        require(len(found)==1,'Mutation needs unique file mapping');return found[0]
    controls=[]
    def reject(off,check,kind,site):
        raw=bytearray(image.data);raw[off]^=1
        candidate=object.__new__(Image);candidate.data=bytes(raw);candidate.loads=image.loads;candidate.sections=image.sections
        try:check(candidate)
        except InvalidEvidence:controls.append({'kind':kind,'site':site,'result':'rejected below full-image identity'})
        else:raise InvalidEvidence('Changed proof obligation accepted')
    # Every literal site and success store plus manually addressed guards/tags.
    names=json.loads((HERE/'name-annotations.json').read_bytes())['entries']
    sites={int(f['literalSite'],16) for e in names for f in e['fragments']}
    sites.update(int(e['edge']['accept'],16) for e in names)
    selected=[0x4a7d78,0x4a7e13,0x4a8b20,0x4a8b23,0x4a8b3b,0x4a8bad,0x4a8bc3,
      0x4a8d83,0x4a8d9f,0x4a94fe,0x4a95df,0x4ab5fc,0x64ea49,0x64ea4c,
      0x64eb54,0x64eb57,0x64ebd3,0x64e00a,0x64db16,0x64db4a,0x64e02d]
    sites.update(selected)
    # Supplement all native control-flow, predicate, store and literal anchors
    # within the four string/Unicode/hex/scanner proof bodies. Identity inventory
    # is not a semantic proof count.
    for va,row in anchors.items():
        address=int(va,16)
        if any(a<=address<z for a,z in [(0x64ebe0,0x64ef08),(0x64f0d0,0x64f229),(0x64f440,0x64f6a6),(0x64f7f0,0x64f8c5)]):
            asm=row['instruction'];op=asm.split()[0]
            if op.startswith('j') or op in {'cmp','test','tzcnt','ret'} or ('PTR [' in asm and op=='mov'):sites.add(address)
    # Every original instruction row in the newly composed outer/wrapper,
    # skip helpers and cleanup/capacity context is independently byte-bound.
    # These are corruption controls, not semantic proof or recovered-byte counts.
    for va in anchors:
        a=int(va,16)
        if any(s<=a<e for s,e in [(0x4aa3b0,0x4aa4be),(0x4ab790,0x4ac58f),
            (0x4acb70,0x4acb83),(0x4aaa10,0x4aac5a),(0x4ad140,0x4ad1af),
            (0x4ab250,0x4ab29e),(0x4ab2a0,0x4ab392),(0x64f6b0,0x64f7eb),
            (0x4ad0c0,0x4ad138)]):sites.add(a)
    for va in sorted(sites):
        require(hex(va) in anchors,'Missing selected native boundary');size=len(bytes.fromhex(anchors[hex(va)]['bytes']))
        reject(offset(va,size)+size-1,lambda candidate:native(candidate,anchors),'instruction',hex(va))
    for slot in map(int,RECIPE['slots']):
        matches=[]
        for section in image.sections:
            if section[1]==4:
                for off in range(section[4],section[4]+section[5],24):
                    if struct.unpack_from('<Q',image.data,off)[0]==slot:matches.append(off+16)
        require(len(matches)==1,'RELA control needs unique record')
        reject(matches[0],lambda candidate:candidate.relocations(),'RELA-addend',hex(slot))
    for row in TRANSFERS:reject(offset(row['va'],5)+4,transfers,'direct-'+row['kind'],hex(row['va']))
    # Each entry of six dispatch/nibble tables; every SIMD literal byte;
    # one byte per remaining context extent. No table masking.
    widths={0x88050:4,0xbbac0:4,0x87a78:4,0x87bb4:4,0x87cf0:4,0xbb970:4,0xbbc10:2,0xbbe10:2,0x6dea0:1,0x6cd60:1}
    for va,expected in DATA.values():
        step=widths.get(va,len(expected))
        for relative in range(0,len(expected),step):reject(offset(va,len(expected))+relative,data_check,'bound-data',hex(va+relative))
    result={'targetSha256':sha(image.data),'nativeIdentityRows':len(anchors),'selectedInstructionControls':len(sites),
      'controls':controls,'capturedExecution':False,'instructionEvaluation':False,
      'scope':'Isolated byte/RELA/data/direct-transfer obligations supporting the addressed manual proof. Full identity bypass is only in corrupted in-memory evidence objects; never target execution or semantic interpretation.'}
    args.receipt.write_bytes(json_bytes(result));print(json.dumps({'controls':len(controls),'instructions':len(sites)}))
if __name__=='__main__':main()
