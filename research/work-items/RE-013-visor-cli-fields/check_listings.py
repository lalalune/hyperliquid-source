#!/usr/bin/env python3
"""Check the two retained linear listings against authenticated visor bytes."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from visor_cli import TARGET, build, require


def verify(packet,data):
    record = json.loads((packet/'record.json').read_text(encoding='utf-8'))
    require(build(data)==record,'CLI record differs from actual target')
    audit = json.loads((packet/'BOUNDARY-AUDIT.json').read_text(encoding='utf-8'))
    require(len(audit['ranges'])==len(record['fde_ranges']),'CLI listing scope differs')
    secs = sections(data)
    rows = byte_count = 0
    boundaries = set()
    for row,body in zip(audit['ranges'],record['fde_ranges']):
        require((row['start'],row['end'])==(body['va'],body['end']),'CLI listing range differs')
        raw = (packet/'disassembly'/Path(row['file']).name).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==row['sha256'],'CLI listing digest differs')
        decoded = []
        for line in raw.decode('utf-8').splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$',line)
            if not m:
                continue
            va = int(m[1],16)
            insn = bytes.fromhex(m[2])
            sections_here = [s for s in secs if s['type']!=8 and s['address']<=va
                             and va+len(insn)<=s['address']+s['size']]
            require(len(sections_here)==1,'CLI listing instruction not uniquely file-backed')
            s = sections_here[0]
            offset = s['offset']+va-s['address']
            require(data[offset:offset+len(insn)]==insn,'CLI listing instruction bytes differ')
            decoded.append((va,len(insn)))
            boundaries.update((va,va+len(insn)))
        require(decoded and decoded[0][0]==int(row['start'],16)
                and sum(decoded[-1])==int(row['end'],16),'CLI listing endpoints differ')
        require(all(a+n==z for (a,n),(z,_) in zip(decoded,decoded[1:])),'CLI listing gap/overlap')
        n = sum(n for _,n in decoded)
        require(len(decoded)==row['decodedRows'] and n==row['rawBytesCompared'],'CLI listing count differs')
        rows += len(decoded)
        byte_count += n
    for control in record['controls']:
        va = int(control['va'],16)
        require(va in boundaries and va+control['bytes'] in boundaries,'CLI control boundary differs')
    require((rows,byte_count,len(record['controls'])) ==
            (audit['decodedRows'],audit['comparedRawBytes'],audit['controlWindows']),'CLI listing totals differ')
    return {'decodedRows':rows,'rawBytes':byte_count,'selectedWindows':len(record['controls']),
            'fullCFG':False,'targetExecuted':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
