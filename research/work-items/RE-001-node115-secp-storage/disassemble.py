#!/usr/bin/env python3
"""Cross-check admitted Capstone boundaries/bytes/mnemonics with GNU objdump."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from analyze import ROOT, admit, require, cs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(cs.__version__ == '5.0.7', 'pinned Capstone version')
    target = ROOT / 'artifacts/node/115/hl-node'
    _, bodies, closure = admit(target.read_bytes())
    args.output.mkdir(parents=True, exist_ok=True)
    comparisons = []
    for body in bodies:
        address = int(body['address'], 16)
        command = ['objdump', '-w', '-d', '-Mintel', f'--start-address={address:#x}',
                   f'--stop-address={address + body["length"]:#x}', 'artifacts/node/115/hl-node']
        output = subprocess.check_output(command, cwd=ROOT)
        (args.output / f'{address:x}.gnu.txt').write_bytes(output)
        rows = []
        for line in output.decode().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s*([0-9a-f]{2}(?: [0-9a-f]{2})*)\s+([a-z][a-z0-9]*)\b', line)
            if match:
                rows.append((int(match[1], 16), bytes.fromhex(match[2]).hex(), match[3]))
        expected = [(int(i['address'], 16), i['bytes'], i['mnemonic']) for i in body['instructions']]
        require(rows == expected, f'GNU/Capstone mismatch at {address:x}')
        comparisons.append({'address': body['address'], 'instructions': len(rows),
                            'address_bytes_mnemonic_equal': True})
    plt = int(closure['failure_plt']['address'], 16)
    output = subprocess.check_output(['objdump', '-w', '-d', '-Mintel',
                                      f'--start-address={plt:#x}', f'--stop-address={plt + 16:#x}',
                                      'artifacts/node/115/hl-node'], cwd=ROOT)
    (args.output / f'{plt:x}.gnu.txt').write_bytes(output)
    result = {'gnu': subprocess.check_output(['objdump', '--version'], text=True).splitlines()[0],
              'capstone': cs.__version__, 'mode': 'objdump -w -d -Mintel; complete recorded extents',
              'comparison': comparisons}
    (args.output / 'decoder-crosscheck.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
