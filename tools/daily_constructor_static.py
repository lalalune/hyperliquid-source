#!/usr/bin/env python3
"""Authenticated node94 daily-liner constructor boundary and state mapping."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'constructor': (20979792, 20980666)}
CONTROLS = {20979816: '4889b424b000000048899424b8000000', 20979846: '4d85ff741643807c3eff2f0f844302000041803e2f0f8439020000', 20979873: '8bac24d40000004c8b3579c83604418b465085c00f8551020000', 20979978: '488d354b63e1fe488dbc24e0000000ba0b0000004c89f1ff1579ce3604', 20980202: '4d85f6790d31ff4c89f6ff15bebd36040f0b74174c89f7ff15d1bd36044885c00f84320100004989c4eb0641bc01000000', 20980266: '488d7c2410ff156bc63604', 20980301: '0f1153380f114b280f1143180f284424600f284c24700f289424800000000f289c24900000000f1143480f114b580f1153680f115b780f288424a00000000f118388000000', 20980370: '4c89334c8963084c89731089ab98000000488b4424104889839c0000008b4424188983a4000000c683a800000000c683aa00000000', 20980442: '488d8424b00000004889442410488d05c2b70d004889442418488d3d5381defe488d156f6a2604488d742410ff158cbd3604'}
LITERALS = {2013396: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6461696c795f6c696e65722e7273', 2196572: '6461696c795f6c696e6572'}
RELATIVE = {90606960: 2013396, 91678880: 22137760, 91679016: 91730568, 91679328: 21318144, 91679424: 20780832, 91680672: 21206720}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'Daily-constructor {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'Daily-constructor relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing daily-constructor relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact daily-constructor FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One constructor FDE. No rotation/flush behavior, complete format/clock/object ABI, filesystem action, ownership/helper closure or gate.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/daily-constructor-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
