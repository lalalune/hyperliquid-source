#!/usr/bin/env python3
"""Target94 configuration consistency/comparison and conditional counter evidence."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'configuration-path': (21210480, 21212780), 'value-comparator': (21256240, 21256526), 'handle-construction': (20860128, 20860475)}
CONTROLS = {21210507: '498d6f0148392f753a', 21210530: '803dc7053404024c897c24204c897c24380f9444246c66c744246d0001c74424680a0000004c897c2450eb2c', 21210644: 'f0410fb04d000f8505060000', 21210656: '49396d687531', 21210726: 'e8c5b1000084c00f85d8020000', 21211444: '498d7d68488db42488000000ba88000000ff1595363304', 21211599: 'e85cae000084c00f857b010000', 21211947: '4883f9ff0f84d3010000488d4101498945584883f9640f83a6010000', 21212098: '31c9b001f0410fb04d00756e', 21256240: '0fb6474c3a464c75720fb6474d3a464d75698b47483b464875610fb6474e3a464e7558', 21256290: '31c0483b07488b0671424839d80f85d1000000', 21256375: '488b5710483b56100f8581000000488b4608488b4f084989fe4889cf4989f74889c6ff15998a32044c89fe4c89f785c0755d', 21256432: '488b5728483b5628754c488b4620488b4f204989fe4889cf4989f74889c6ff15648a32044c89fe4c89f785c07528', 21256483: '488b5740483b56407519488b7638488b7f38ff153d8a320485c00f94c05b415e415fc331c05b415e415fc3cccc'}
LITERALS = {2103785: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f635f67756172642e7273'}
RELATIVE = {90612168: 2103785, 90612192: 2103785, 90612216: 2103785, 90612240: 2103785, 91682032: 91728800, 91682040: 21912991, 91682056: 21912889}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'CGuard {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'CGuard relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing cguard relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    missing=[field for field in ('size','sha256') if field not in identity]
    if missing: raise ValueError(f"provenance/artifacts.json entry for artifacts/node/94/hl-node is missing {'/'.join(missing)}")
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact cguard FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in {*RELATIVE,0x576E378})+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'Configuration path and two helper extents only. No full Rust type, complete initialization/concurrency/ownership, unconditional call-count bound, helper closure or progress gate.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/cguard-init-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
