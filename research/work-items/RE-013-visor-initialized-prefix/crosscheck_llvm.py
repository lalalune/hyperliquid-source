#!/usr/bin/env python3
"""Compare independent LLVM/GNU instruction partitions, without target execution."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from survey import Image, InvalidEvidence, RANGES, collect, command, json_bytes, native_rows, require, sha, write_new

# LLVM18 prints these LOCK prefixes as separate rows. Preserve original output;
# join only their adjacent display rows, without changing any address/byte.
LOCK_SITES = {0x672423, 0x672458, 0x67251a, 0x672543,
              0x66c295, 0x66c313, 0x66c36d}

def joined_partition(rows):
    output=[]
    joins=[]
    i=0
    while i<len(rows):
        row=rows[i]
        if row['bytes']=='f0' and row['instruction']=='lock':
            site=int(row['va'],16)
            require(site in LOCK_SITES and i+1<len(rows),'Unexpected split LOCK row')
            nxt=rows[i+1]
            require(int(nxt['va'],16)==site+1,'Nonadjacent split LOCK row')
            output.append((row['va'],row['bytes']+nxt['bytes']))
            joins.append(row['va'])
            i+=2
        else:
            output.append((row['va'],row['bytes']))
            i+=1
    return output,joins

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists(), 'Existing output must be preserved')
        image = Image(args.binary.read_bytes())
        gnu = json.loads(collect(args.binary)['summary.json'])
        files = {}
        comparisons = []
        all_joins=[]
        with tempfile.TemporaryDirectory(prefix='visor-prefix-llvm-') as temporary:
            root = Path(temporary)
            snapshot = root / 'visor.elf'
            snapshot.write_bytes(image.data)
            snapshot.chmod(0o400)
            version = command(['llvm-objdump', '--version'], root).splitlines()[0]
            require('18.1.3' in version, 'Use the retained LLVM 18.1.3 recipe')
            for label, (start, end) in RANGES.items():
                text = command(['llvm-objdump', '-d', '--x86-asm-syntax=intel',
                                '--start-address=' + hex(start), '--stop-address=' + hex(end),
                                'visor.elf'], root)
                rows = native_rows(text, image, start, end)
                reference = next(row for row in gnu['ranges'] if row['label'] == label)['rows']
                partition = [(row['va'], row['bytes']) for row in rows]
                expected = [(row['va'], row['bytes']) for row in reference]
                joined,joins=joined_partition(rows)
                require(joined == expected, 'GNU/LLVM partitions differ beyond declared LOCK display: ' + label)
                all_joins.extend(joins)
                path = label + '.llvm.txt'
                files[path] = text.encode()
                comparisons.append({'label': label, 'bytes': end - start, 'instructionRows': len(rows),
                                    'rawBytePartitionsEqual': partition==expected,
                                    'llvmInstructionRows':len(rows),'lockDisplayJoins':joins,
                                    'joinedBytePartitionsEqual':True,'exportSha256': sha(files[path])})
            require(snapshot.read_bytes() == image.data, 'Private snapshot changed')
        require({int(x,16) for x in all_joins}==LOCK_SITES,'Declared LOCK display set differs')
        # The display rule may not silently discard or alter a prefix.
        try:
            joined_partition([{'va':'0x1','bytes':'f0','instruction':'lock'},
                              {'va':'0x2','bytes':'90','instruction':'nop'}])
        except InvalidEvidence:
            pass
        else:
            raise InvalidEvidence('Unknown split LOCK was accepted')
        receipt = {'targetSha256': gnu['targetSha256'], 'llvmVersion': version,
                   'gnuVersions': gnu['versions'], 'ranges': comparisons,
                   'bytes': sum(row['bytes'] for row in comparisons),
                   'instructionRows': sum(row['instructionRows'] for row in comparisons),
                   'llvmInstructionRows':sum(row['llvmInstructionRows'] for row in comparisons),
                   'displayRule':'Only seven explicitly addressed LLVM f0 LOCK display rows joined with adjacent rows; raw exports retained. No byte/operand masks.',
                   'unknownLockDisplayControl':'refused',
                   'scope': 'Decoder-boundary cross-check only; not semantic, runtime, atomicity or original-source equivalence.'}
        files['receipt.json'] = json_bytes(receipt)
        write_new(args.output, files)
        print(json.dumps(receipt))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
