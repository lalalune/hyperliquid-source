#!/usr/bin/env python3
"""Re-export the four pinned115 extents with native GNU/Capstone; static only."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=verify.ROOT/'artifacts/node/115/hl-node')
    parser.add_argument('--output', type=Path, default=verify.ROOT/'work/http-shutdown-115/raw')
    parser.add_argument('--objdump', default='objdump')
    args = parser.parse_args()
    import capstone
    data = args.target.read_bytes()
    verify.require(len(data) == verify.SIZE and hashlib.sha256(data).hexdigest() == verify.DIGEST,
                   'Wrong Node115 input')
    image = verify.Image(data)
    cies, fdes = verify.eh_frame_records(data, image.secs)
    byfde = {r['fde']: r for r in fdes}
    records = json.loads((HERE/'records.json').read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    exports = {}
    for row in records['ranges']:
        start, end = int(row['start'], 16), int(row['end'], 16)
        fr = byfde[int(row['fde'], 16)]
        verify.require((fr['start'], fr['end']) == (start, end), 'FDE changed')
        body = image.read(start, end-start)
        instructions = [{'va':hex(i.address), 'bytes':bytes(i.bytes).hex(),
                         'mnemonic':i.mnemonic, 'operands':i.op_str}
                        for i in md.disasm(body, start)]
        native = subprocess.run([args.objdump, '-d', '--wide', '--insn-width=16', '-M', 'intel',
                                 '--start-address='+str(start), '--stop-address='+str(end),
                                 str(args.target)], capture_output=True, check=True, timeout=30)
        # Only the display filename in the native header is redacted; instruction bytes untouched.
        text = native.stdout.replace(str(args.target).encode(), b'artifacts/node/115/hl-node')
        (args.output/(hex(start)+'.objdump.txt.gz')).write_bytes(gzip.compress(text, mtime=0))
        exports[hex(start)] = dict(start=hex(start), end=hex(end), fde=row['fde'],
                                  cie=cies[fr['cie']], lsda=fr['lsda'],
                                  bodySHA256=hashlib.sha256(body).hexdigest(), bytes=len(body),
                                  instructions=instructions)
    (args.output/'capstone.json.gz').write_bytes(gzip.compress(json.dumps(exports, indent=2).encode(), mtime=0))
    # Verify the newly generated exports and GNU files, rather than only the committed copies.
    verify.HERE = args.output
    result = verify.check_exports(image, exports, records)
    print(json.dumps(dict(capstoneWrapper=capstone.__version__, capstoneAPI=capstone.cs_version(),
                         objdump=subprocess.check_output([args.objdump,'--version']).decode().splitlines()[0],
                         **result), sort_keys=True))


if __name__ == '__main__':
    main()
