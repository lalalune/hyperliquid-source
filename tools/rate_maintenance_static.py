#!/usr/bin/env python3
"""Target94 rate-limiter-associated guarded maintenance/reset evidence."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'guarded-caller': (74533904, 74534907), 'maintenance-path': (80263264, 80263708), 'iterator-helper': (75992096, 75993472)}
CONTROLS = {74533921: '440fb677204180fe010f8533030000', 74533957: '4c89ffe8136c5700', 74534054: 'f00fb04d000f85a5000000', 74534446: 'ff1554960501489885c04c0f45f84d85ff0f98c00f9fc128c149', 74534712: 'e8131e2400', 74534738: 'ff1558a00501', 74534744: '31c9b001f00fb04d007550', 74534755: '4489f0', 80263274: '488b87780100004885c07472', 80263364: 'e857d3beff', 80263429: '498d5611beff000000ff15e428ae00', 80263444: '498d46014889c148c1e9034883e0f84829c84983fe08490f42c6eb02', 80263474: '48c783300100000000000048898328010000', 80263521: '498d5611beff000000ff158828ae00', 80263536: '498d46014889c148c1e9034883e0f84829c84983fe08490f42c6eb02', 80263566: '48c783780100000000000048898370010000', 80263584: '31c0483b43187010488d7b18488d359d77ab00e8383fa9ff', 80263637: '498d5611beff000000ff151428ae00', 80263652: '498d46014889c148c1e9034883e0f84829c84983fe08490f42c6eb02', 80263682: '48c783a801000000000000488983a0010000'}
LITERALS = {2106666: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f6e65745f7574696c732f7372632f726174655f6c696d697465722e7273'}
RELATIVE = {91500880: 2106666, 91679584: 91727928, 91680688: 20981680}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'Rate-maintenance {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        if section['size'] % 24:
            raise ValueError('Truncated relocation section')
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'Rate-maintenance relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing rate-maintenance relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact rate-maintenance FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in {*RELATIVE,0x576E1F8,0x576E488})+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'Guarded caller, maintenance body and iterator extent only. No full rate-limit decision/TTL, table type, allocation lifetime, helper/concurrency closure, runtime behavior or gate.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/rate-maintenance-init-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
