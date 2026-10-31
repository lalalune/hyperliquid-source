#!/usr/bin/env python3
"""Node94 latency bounded static evidence; never executes target."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'sample-update': (64104736, 64105111)}
CONTROLS = {64104765: '4183bed0070000000f8482000000', 64104872: 'f20f100d48824efcf20f5dc8488d15fd', 64104884: '488d15fd699f01be010000004c89f7660f28c1ff15e3c5a401', 64104909: '4d8dbed00700004084ed74714981c660020000', 64105013: '488d1594699f01be010000004c89f7ff1566c5a401', 64105034: '8b430889442430488b034889442428488b44240c48894424348b4424148944243c488b4424284989078b442430418947088b4424344189470c488b44243849894710'}
LITERALS = {2048847: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6e65745f7574696c732f7372632f616263695f6c6174656e63795f73616d706c65722e7273', 2141176: '0000000000004e40'}
RELATIVE = {91329464: 2048847, 91329488: 2048847, 91678880: 22137760, 91678912: 21262640, 91680688: 20981680}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'latency {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'latency relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing latency relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact latency FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One sampler-update FDE. No clock units/ABI, complete metric accumulator, first-use initialization, input reachability, NaN exclusion or runtime equivalence.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/latency-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
