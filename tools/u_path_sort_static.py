#!/usr/bin/env python3
"""Node94 bounded path preparation and unsigned word sort evidence; never executes target."""
import argparse,hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'body': (20750560, 20751202)}
CONTROLS = {20750592: '4885c9740b807c0aff2f0f8463010000', 20750859: '4983fc02737d', 20750963: '488d3d76cbe4fe488d1517c92904be2a000000ff157c3e3a04', 20750990: '4983fc15735d', 20751030: '4c8b41f8488b314c39c673e74889d74d89043f4883ff0874d44d8b443ff04883c7f84c39c672e84c01ffebc4', 20751089: '488d5424074c89ff4c89e6ff153e463a04'}
LITERALS = {2028254: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f752e7273', 2190832: '617373657274696f6e206661696c65643a2021626173655f6469722e656e64735f7769746828272f2729'}
RELATIVE = {90598296: 2028254, 91676936: 22525936, 91679040: 21557696}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'u {kind} changed at {va:#x}')

    location = struct.unpack('<QQII',read_va(data,90598296,24)[1])
    if location != (0, 42, 400, 9):
        raise ValueError('Location layout changed')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'u relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing u relocation')
    return [result[s] for s in sorted(result)]

def generate(binary,output):
    identity=next(i for i in json.loads((ROOT/'provenance/artifacts.json').read_text())['files'] if i['path']=='artifacts/node/94/hl-node')
    check(binary,identity)
    data=binary.read_bytes();controls(data);rela=relocations(data)
    # Bind external decoder input to the same bytes using a private snapshot:
    # readelf/objdump reopen their argument, so decoding the admitted path
    # would bind this packet to whatever the path serves at decode time.
    with tempfile.TemporaryDirectory() as temporary:
        snapshot=Path(temporary)/'node94.elf';snapshot.write_bytes(data)
        check(snapshot,identity)  # Authenticate the exact bytes the decoders reopen.
        frames=subprocess.check_output(['readelf','-wf',str(snapshot)],text=True)
        fdes=[(int(a,16),int(b,16))for a,b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)',frames)]
        output.mkdir(parents=True,exist_ok=True);ranges={}
        for name,(start,end)in RANGES.items():
            if fdes.count((start,end))!=1:raise ValueError('Exact u FDE missing')
            offset,body=read_va(data,start,end-start)
            ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(snapshot)],text=True)
            (output/(name+'.objdump.txt')).write_text(raw.replace(str(snapshot),'<authenticated-node94>'))
        (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
        raw_rela=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One path preparation/sort FDE; helper closure, complete object ABI, path enumeration semantics and runtime behavior unresolved.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/u-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
