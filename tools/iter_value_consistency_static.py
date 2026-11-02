#!/usr/bin/env python3
"""Node94 bounded iterator value consistency evidence; never executes target."""
import argparse,hashlib,json,re,struct,subprocess,tempfile
from pathlib import Path
from artifacts import ROOT,check
from elf_index import sections
RANGES = {'body': (53907648, 53908732)}
CONTROLS = {53907663: '4c8b463066b897004d85c00f84bc030000', 53908327: '4d89f349c1e306f3420f6f441b18f30f6f0a660f74c866420f6e441b28660f6e5210660f74d0660fdbd166440fd7da4181fbffff00000f85edfdffff', 53908476: 'f30f6f442441f30f6f4c2451f30f6f542461660f74d0f30f6f442471660f74c1660fdbc266440fd7c04181f8ffff00000f8580000000', 53908578: '66b82a00eb34', 53908604: '66b82a0041f6c00174160f284424400f284c24500f114f120f11470266b886016689074889f8', 53908692: '488d3d1340e8fc488d15560938024889e6ff15ad4b4002'}
LITERALS = {2015159: '2f686f6d652f7562756e74752f686c2f636f64655f4d61696e6e65742f626173652f7372632f697465722e7273', 2020590: '2e4368616d4974657261746f723a3a75'}
RELATIVE = {91135544: 2015159, 91676824: 22525968, 91677808: 22522352}
def read_va(data, va, length):
    matches=[s for s in sections(data) if s['type']!=8 and s['address']<=va and va+length<=s['address']+s['size']]
    if len(matches)!=1: raise ValueError('Expected one file-backed mapping')
    offset=matches[0]['offset']+va-matches[0]['address']
    return offset,data[offset:offset+length]

def controls(data):
    for kind,expected in [('instruction',CONTROLS),('literal',LITERALS)]:
        for va,value in expected.items():
            if read_va(data,va,len(bytes.fromhex(value)))[1]!=bytes.fromhex(value):
                raise ValueError(f'iter {kind} changed at {va:#x}')

    location = struct.unpack('<QQII',read_va(data,91135544,24)[1])
    if location != (0, 45, 132, 21):
        raise ValueError('Location layout changed')

def relocations(data):
    result={}
    for section in sections(data):
        if section['type']!=4:continue
        for offset in range(section['offset'],section['offset']+section['size'],24):
            slot,info,addend=struct.unpack_from('<QQq',data,offset)
            if slot in RELATIVE:
                if info!=8 or addend!=RELATIVE[slot]:raise ValueError(f'iter relocation changed at {slot:#x}')
                result[slot]={'slot_va':hex(slot),'info':hex(info),'addend':hex(addend)}
    if set(result)!=set(RELATIVE):raise ValueError('Missing iter relocation')
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
            if fdes.count((start,end))!=1:raise ValueError('Exact iter FDE missing')
            offset,body=read_va(data,start,end-start)
            ranges[name]={'start_va':hex(start),'end_va':hex(end),'file_offset':hex(offset),'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            raw=subprocess.check_output(['objdump','-d',f'--start-address={start:#x}',f'--stop-address={end:#x}',str(snapshot)],text=True)
            (output/(name+'.objdump.txt')).write_text(raw.replace(str(snapshot),'<authenticated-node94>'))
        (output/'frames.txt').write_text('\n'.join(line for line in frames.splitlines()if 'FDE'in line and any(f'pc={a:016x}..{b:016x}'in line for a,b in RANGES.values()))+'\n')
        raw_rela=subprocess.check_output(['readelf','-rW',str(snapshot)],text=True)
        (output/'relocations.txt').write_text('\n'.join(line for line in raw_rela.splitlines()if re.match(r'^[0-9a-f]+\s',line)and int(line.split()[0],16)in RELATIVE)+'\n')
    result={'target_sha256':identity['sha256'],'target_bytes':len(data),'ranges':ranges,'controls':{hex(a):b for a,b in CONTROLS.items()},'literal_bytes':{hex(a):b for a,b in LITERALS.items()},'relocations':rela,'captured_binary_executed':False,'limits':'One iterator-associated FDE; collection ownership/type, enclosing enum ABI, helper/panic closure and runtime equivalence unresolved.'}
    (output/'records.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');parser.add_argument('--output',type=Path,default=ROOT/'work/iter-94');args=parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(),args.output),indent=2))
