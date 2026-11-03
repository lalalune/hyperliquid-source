"""Independent GNU instruction bytes and actual FDE/CIE records for this packet."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import native
from fde_extents import eh_frame_records

def audit(objdump):
    data=native.TARGET.read_bytes();image=native.authenticate(data)
    text=subprocess.check_output([str(objdump),'-d','--wide','-M','intel',f'--start-address={native.START:#x}',f'--stop-address={native.END:#x}',str(native.TARGET)],text=True)
    # GNU's header contains only the capture path. Normalize just that path to
    # its repository-relative identity; no instruction bytes/operands masked.
    text=text.replace(str(native.TARGET),'artifacts/node/115/hl-node')
    rows=[]
    for line in text.splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)',line)
        if m:rows.append((int(m.group(1),16),bytes.fromhex(m.group(2)).hex()))
    cap=[]
    for line in (native.PACKET/'owner.capstone.tsv').read_text().splitlines():
        f=line.split('\t');cap.append((int(f[0],16),f[1]))
    if rows!=cap:raise ValueError('GNU and Capstone instruction boundaries/bytes differ')
    cies,fdes=eh_frame_records(data);matching=[f for f in fdes if (f['start'],f['end'])==(native.START,native.END)]
    if len(matching)!=1:raise ValueError('ambiguous FDE')
    fde=matching[0];cie=cies[fde['cie']]
    records={}
    for name,va in [('fde',fde['fde']),('cie',fde['cie'])]:
        off=image.file_offset(va);n=4+struct.unpack_from('<I',data,off)[0];records[name]={'va':hex(va),'file_offset':off,'raw_hex':data[off:off+n].hex()}
    (native.PACKET/'owner.gnu.txt').write_text(text)
    report={'target_sha256':native.SHA,'fde':fde,'cie':cie,'unwind_raw_records':records,'gnu_version':subprocess.check_output([str(objdump),'--version'],text=True).splitlines()[0],'matched_instruction_rows':len(rows),'matched_bytes':sum(len(bytes.fromhex(x[1])) for x in rows),'instruction_normalization':'none; output header path only','helper_and_abi_closure':False}
    (native.PACKET/'unwind-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--objdump',type=native.Path,required=True);a=p.parse_args();audit(a.objdump.resolve())
