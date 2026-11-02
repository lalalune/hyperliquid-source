#!/usr/bin/env python3
"""Recheck frozen instruction boundaries with installed GNU and LLVM decoders."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import verify


def decoded(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+?)\s*$', line)
        if match:
            rows.append((int(match[1], 16), match[2].replace(' ', '')))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gnu', default='objdump')
    parser.add_argument('--llvm', required=True)
    parser.add_argument('--binary', type=Path, default=verify.ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    verify.require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == verify.SHA,
                   'target SHA-256 mismatch')
    args.out.mkdir(parents=True, exist_ok=True)
    report = []
    for provider, exe, options in (('gnu', args.gnu, ['-M', 'intel', '--insn-width=16']),
                                   ('llvm', args.llvm, ['--x86-asm-syntax=intel'])):
        version = subprocess.check_output([exe, '--version'], text=True).splitlines()[0]
        for f in verify.frozen():
            command = [exe, '-d', *options, '--start-address='+f['start'],
                       '--stop-address='+f['end'], str(args.binary)]
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            expected = [(int(i['va'], 16), i['bytes']) for i in f['instructions']]
            verify.require(decoded(result.stdout) == expected, provider+' instruction decode changed')
            name = f['role']+'.'+provider+'.txt'
            (args.out/name).write_text(result.stdout)
            report.append(dict(provider=provider, version=version, role=f['role'],
                               instruction_count=len(expected), start=f['start'], end=f['end'],
                               options=options, stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                               stderr=result.stderr, command=' '.join(command)))
    (args.out/'agreement.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    print('PASS: GNU and LLVM agree with all 185 frozen instruction boundaries and bytes')


if __name__ == '__main__':
    main()
