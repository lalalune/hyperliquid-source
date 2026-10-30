#!/usr/bin/env python3
"""Target94 bucket_guard timing, fixed window roller, and guarded latency sampling evidence."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'bucket-duration-calculation': (20745744, 20746067), 'fixed-window-roller-debug': (20842912, 20843074), 'guarded-latency-sampler': (35814528, 35815713)}
CONTROLS = {20745758: '488b460848f726', 20745765: '0f8002010000', 20745889: '4169cfe80300004129ce', 20745899: '4169ce40420f00', 20745910: '4969d4805101004929d7', 20745976: '837c240801', 20745992: '488d3d8ee0e4fe', 20746006: '4c8d054bdc2904', 20746027: '0f0b', 20842929: '4c8d5720', 20842933: '4c8d7718', 20842937: '488d4f1c', 20842989: '488d35406ce3fe', 20843003: 'ba11000000', 35814545: '440fb677204180fe010f85d9030000', 35815507: '488d1546604703', 35815534: '31c9b001f0410fb00f754b'}
LITERALS = {1975440: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f6275636b65745f67756172642e7273', 2192948: '466978656457696e646f77526f6c6c6572', 2191261: '63616c6c65642060526573756c743a3a756e77726170282960206f6e20616e2060457272602076616c7565'}
RELATIVE = {90598248: 1975440, 90599256: 20786976, 90601168: 20869584, 90824864: 1975440}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'Bucket-guard {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'Bucket-guard relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing bucket-guard relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact bucket-guard FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in {*RELATIVE,0x576E048,0x576EB80,0x576EFB0})+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'Bucket duration calculation, FixedWindowRoller debug and guarded latency sampling extents only. No full rate limiting, scheduler, concurrency contract, runtime equivalence or network gate.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/bucket-guard-init-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
