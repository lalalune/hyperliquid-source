#!/usr/bin/env python3
"""Re-derive this closed static packet; never execute the captured program."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

P=Path(__file__).resolve().parent
ROOT=P.parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import node115_cli_output_config as output


def verify(objdump='objdump'):
    entries={}
    for line in (P/'MANIFEST.sha256').read_text(encoding='utf8').splitlines():
        digest,name=line.split('  ',1)
        target=(P/name).resolve()
        output.need(target.is_relative_to(ROOT.resolve()) and target.is_file()
                    and not (P/name).is_symlink(),'Unsafe manifest path')
        output.need(name not in entries and re.fullmatch('[0-9a-f]{64}',digest),
                    'Invalid manifest entry')
        output.need(hashlib.sha256(target.read_bytes()).hexdigest()==digest,
                    'Manifest byte mismatch: '+name)
        entries[name]=digest
    local={name for name in entries if '/' not in name}
    actual={x.name for x in P.iterdir()}
    output.need(actual==local|{'MANIFEST.sha256'},'Unexpected or missing packet file')
    data=(ROOT/output.ARTIFACT).read_bytes()
    records=output.collect(data)
    expected=json.loads((P/'records.json').read_text(encoding='utf8'))
    output.need(records==expected,'Target observations changed')
    for label,rows in records['instructions'].items():
        raw=(P/(label+'.gnu.objdump')).read_text(encoding='utf8')
        pairs=[]
        for line in raw.splitlines():
            m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)',line)
            if m:pairs.append((int(m[1],16),bytes.fromhex(m[2])))
        output.need(pairs==[(int(x['va'],16),bytes.fromhex(x['bytes'])) for x in rows],
                    'Retained native instruction stream mismatch: '+label)
    _,native=output.native_crosscheck(output.Image(data),records,objdump,ROOT,output.ARTIFACT)
    output.need(native['all_address_bytes_equal'],'Fresh native comparison failed')
    print(json.dumps({'packet':'RE-012-node115-cli-output-config','primary_bytes':840,
                      'context_bytes':5156,'complete_selected_bytes':5996,
                      'raw_instruction_rows':1417,'captured_execution':False,
                      'fresh_native_address_bytes_equal':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--objdump',default='objdump')
    verify(parser.parse_args().objdump)
