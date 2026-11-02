#!/usr/bin/env python3
"""Compare independent LLVM/GNU instruction partitions, without target execution."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from survey import Image, InvalidEvidence, RANGES, collect, command, json_bytes, native_rows, require, sha, write_new

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
        with tempfile.TemporaryDirectory(prefix='visor-preparation-llvm-') as temporary:
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
                require(partition == expected, 'GNU/LLVM instruction partitions differ: ' + label)
                path = label + '.llvm.txt'
                files[path] = text.encode()
                comparisons.append({'label': label, 'bytes': end - start, 'instructionRows': len(rows),
                                    'identicalBytePartitions': True, 'exportSha256': sha(files[path])})
            require(snapshot.read_bytes() == image.data, 'Private snapshot changed')
        receipt = {'targetSha256': gnu['targetSha256'], 'llvmVersion': version,
                   'gnuVersions': gnu['versions'], 'ranges': comparisons,
                   'bytes': sum(row['bytes'] for row in comparisons),
                   'instructionRows': sum(row['instructionRows'] for row in comparisons),
                   'scope': 'Decoder-boundary cross-check only; not semantic, runtime or original-source equivalence.'}
        files['receipt.json'] = json_bytes(receipt)
        write_new(args.output, files)
        print(json.dumps(receipt))
    except (InvalidEvidence, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')

if __name__ == '__main__':
    main()
