#!/usr/bin/env python3
"""Recheck retained bounded GNU listings against the authenticated visor bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from elf_index import sections
from visor_startup import TARGET, build, require


def verify(packet, data):
    record = json.loads((packet/'record.json').read_text(encoding='utf-8'))
    require(build(data) == record, 'startup packet differs from target-derived record')
    audit = json.loads((packet/'BOUNDARY-AUDIT.json').read_text(encoding='utf-8'))
    secs = sections(data)
    boundaries = set()
    total_rows = total_bytes = 0
    expected_ranges = [(0x2bd180,0x2bd1a6)] + [
        (int(r['va'],16),int(r['end'],16)) for r in record['fde_ranges']]
    require(len(audit['ranges']) == len(expected_ranges), 'listing range count differs')
    for r,(start,end) in zip(audit['ranges'],expected_ranges):
        require((int(r['start'],16),int(r['end'],16)) == (start,end), 'listing scope differs')
        path = packet/'disassembly'/Path(r['file']).name
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == r['sha256'], 'listing digest differs')
        rows = []
        for line in raw.decode('utf-8').splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$',line)
            if not m:
                continue
            va = int(m[1],16)
            body = bytes.fromhex(m[2])
            matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                       and va+len(body) <= s['address']+s['size']]
            require(len(matches) == 1, 'listing instruction is not uniquely file-backed')
            offset = matches[0]['offset']+va-matches[0]['address']
            require(data[offset:offset+len(body)] == body, 'listing instruction bytes differ')
            rows.append((va,len(body)))
            boundaries.update((va,va+len(body)))
        require(rows and rows[0][0] == start and sum(rows[-1]) == end, 'listing endpoints differ')
        require(all(a+n == z for (a,n),(z,_) in zip(rows,rows[1:])), 'listing instruction gap/overlap')
        count = sum(n for _,n in rows)
        require(len(rows) == r['decodedRows'] and count == r['rawBytesCompared'], 'listing counts differ')
        total_rows += len(rows)
        total_bytes += count
    for r in record['instruction_controls']:
        va = int(r['va'],16)
        require(va in boundaries and va+r['bytes'] in boundaries, 'control is not on decoded boundaries')
    require(total_rows == audit['totalDecodedRows'] and total_bytes == audit['totalComparedRawBytes'],
            'listing total counts differ')
    require(audit['selectedControlWindowsOnDecodedBoundaries'] == len(record['instruction_controls']),
            'boundary control count differs')
    return {'decodedRows':total_rows,'comparedRawBytes':total_bytes,'controlWindows':len(record['instruction_controls']),
            'fullCFG':False,'capturedBinaryExecuted':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet',type=Path,default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    print(json.dumps(verify(args.packet,TARGET.read_bytes()),sort_keys=True))
