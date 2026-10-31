#!/usr/bin/env python3
"""Target94 file-tracker initialization observations; static only."""
import argparse,hashlib,json,re,struct,subprocess
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'initializer': (20760960, 20762239), 'regular-mode-predicate': (21276432, 21276804), 'metadata-path': (21285168, 21285441), 'load-path': (21288048, 21289819), 'initial-write-path': (21295152, 21296189)}
CONTROLS = {20761120: 'ff15c21f3a0484c07423', 20761236: 'e8972508004885c00f85d2020000', 20761287: '48c743501a40f600c743580000000048b8000000000000144048894330', 20761376: 'ff15ca1e3a04837c24080175074c8b642410eb3a', 20761431: 'e814090800488b4424084c8b6424104889c148f7d97115', 20761610: '488d354cffe1fe488d0d70a02904488d7c2408488d542438', 20761640: '48b8000000000000144048894330c7433800000000', 20761677: '48c743501a40f600c743580000000048c743180000000048c743200800000048c743280000000048894348', 20761741: '48892b4c896b084c897310488b44246048894318488b44246848894320488b4424704889432848b8000000000000144048', 21276521: 'b800f00000234424483d00800000400f94c5', 21295197: '4883fa09752248b82f6465762f6e756c483345000fb64d084883f16c4809c1750c31c0e9e6020000'}
LITERALS = {2071479: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f66696c655f6d6f645f74696d655f747261636b65722e7273', 2018141: '31636f756c64206e6f74206c6f61642066696c652c207573696e672064656661756c742076616c75652e204572726f723a20c000', 2023486: 'c0c0172f66696c655f6d6f645f74696d655f747261636b65722fc0052e6a736f'}
RELATIVE = {90598536: 2071479, 91679208: 21276432, 91679216: 21285168, 91679016: 91730568, 91677936: 20348848}

def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'File-tracker {kind} changed at {va:#x}')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'File-tracker relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing file-tracker relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    manifest=json.loads((ROOT/'provenance/artifacts.json').read_text())
    if not isinstance(manifest,dict) or not isinstance(manifest.get('files'),list):raise ValueError('Invalid artifact manifest')
    for entry in manifest['files']:
        if not isinstance(entry,dict) or 'path' not in entry:raise ValueError('Invalid artifact record')
    identity=next((i for i in manifest['files'] if i['path']=='artifacts/node/94/hl-node'),None)
    if identity is None:raise ValueError('No provenance/artifacts.json entry for artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    frames=subprocess.check_output(['readelf','-wf',str(binary)],text=True)
    fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
    output.mkdir(parents=True,exist_ok=True);ranges={}
    for name,(start,end)in RANGES.items():
        if fdes.count((start,end))!=1:raise ValueError('Exact file-tracker FDE missing')
        offset,body=read_va(data,start,end-start)
        ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(binary)],text=True)
        (output/(name+'.objdump.txt')).write_text(raw.replace(str(binary),'<authenticated-node94>'))
    (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
    raw_rela=subprocess.check_output(['readelf','-rW',str(binary)],text=True)
    (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One initializer and four helper extents. No full tracker type/update protocol, filesystem execution, parser/schema equivalence, metadata clock/calendar proof, helper closure or progress gate.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/file-tracker-init-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
