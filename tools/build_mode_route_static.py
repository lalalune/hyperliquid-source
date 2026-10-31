#!/usr/bin/env python3
"""Node94 buildmode bounded static evidence; never executes target."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'name-route': (20763664, 20764363)}
CONTROLS = {20763688: '4489c008c8744f', 20763695: '4883fa0a752148b872756e2d636c69654833060fb756084881f26e7400004809c20f8440010000', 20763743: '80f901742e0fb6c183f8020f85c6010000', 20763760: '488d0563c0e4feb907000000eb20', 20763794: '488d053cc0e4feb905000000', 20763981: 'c6431801', 20764135: '4c893b4c8973084c897b10c6431800', 20764243: '488d1566ca2904488d742408ff15330a3a04'}
LITERALS = {2098806: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6275696c645f6d6f64652e7273', 2200789: '646562756772656c65617365'}
RELATIVE = {90611904: 2098806}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'buildmode {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'buildmode relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing buildmode relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact buildmode FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One name-routing FDE. No complete build-mode enum, command builder, client startup, formatting/helper closure or runtime equivalence.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/buildmode-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
