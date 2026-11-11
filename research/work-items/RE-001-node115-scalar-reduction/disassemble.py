#!/usr/bin/env python3
"""Independent GNU/Capstone instruction-boundary cross-check; static only."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from analyze import ROOT, admit, require


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',required=True,type=Path)
    args = p.parse_args()
    data = (ROOT/'artifacts/node/115/hl-node').read_bytes()
    _,bodies,_ = admit(data)
    args.output.mkdir(parents=True,exist_ok=True)
    results = []
    # A byte-identical read-only snapshot keeps native tools bound to admission.
    with tempfile.TemporaryDirectory(prefix='scalar-static-',dir=ROOT/'work') as directory:
        snapshot = Path(directory)/'hl-node'
        snapshot.write_bytes(data)
        snapshot.chmod(0o400)
        for body in bodies:
            address = int(body['entry'],16)
            command = ['objdump','-w','-d','-Mintel',f'--start-address={address:#x}',f'--stop-address={address+body["length"]:#x}',str(snapshot)]
            output = subprocess.check_output(command)
            # Remove only the temporary input path in the objdump banner.
            output = output.replace(str(snapshot).encode(),b'<authenticated-node115-snapshot>')
            (args.output/f'{address:x}.gnu.txt').write_bytes(output)
            rows = []
            for line in output.decode().splitlines():
                match = re.match(r'^\s*([0-9a-f]+):\s*([0-9a-f]{2}(?: [0-9a-f]{2})*)\s+([a-z][a-z0-9]*)\b',line)
                if match:
                    rows.append((int(match[1],16),bytes.fromhex(match[2]).hex(),match[3]))
            expected = [(int(i['va'],16),i['bytes'],i['mnemonic']) for i in body['instructions']]
            require(rows==expected,'GNU/Capstone mismatch')
            results.append({'entry':body['entry'],'instruction_count':len(rows),'addresses_bytes_mnemonics_equal':True})
        frames = subprocess.check_output(['readelf','--debug-dump=frames-interp',str(snapshot)],text=True)
        selected = []
        for line in frames.splitlines():
            if any(f'pc={int(b["entry"],16):016x}..{int(b["end"],16):016x}' in line for b in bodies):
                selected.append(line)
        require(len(selected)==2,'GNU FDE confirmations')
        (args.output/'frames.txt').write_text('\n'.join(selected)+'\n')
    record = {'gnu_objdump':subprocess.check_output(['objdump','--version'],text=True).splitlines()[0],
              'gnu_readelf':subprocess.check_output(['readelf','--version'],text=True).splitlines()[0],
              'comparison':results,'normalization':'only temporary snapshot path in banner; no code operands masked',
              'scope':'boundary/bytes/mnemonic agreement, not independent operand-semantics proof'}
    (args.output/'decoder-crosscheck.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))


if __name__=='__main__':
    main()
