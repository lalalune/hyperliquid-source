#!/usr/bin/env python3
"""Verify this packet against the node #94 binary.

Usage: python3 verify.py [--binary PATH] [--packet-dir DIR]
Checks: target digest, function carve SHA, int3 padding, call targets
re-derived from raw rel32 encodings, caller census by byte scan, FDE
lines, GOT relocation, excerpt lines vs fresh objdump, semantic-record
shape (no per-instruction list), and MANIFEST.sha256 hashes.
Exits non-zero on the first failure.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

TARGET_SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FN_START, FN_END = 0x514C1C0, 0x514C51D
FN_SHA = 'b1ef129bc4668b404ab184a7f4149631948da307cb71c8585427b96e22fcd895'
PAD_SHA = 'e668f0a1b72560ced14c54488a25335d11336448950bb6485267ebc5eb3fecee'
NEXT_FDE = 0x514C520
SELF_SITE = 0x514C264
EXPECTED_EXTERNAL_CALLERS = [0x514C537, 0x5150DEC]
PLT_DELETE = 0x5660440


def fail(msg):
    print(f'FAIL: {msg}')
    sys.exit(1)


def objdump(binary, start, stop):
    r = subprocess.run(['objdump', '-d', f'--start-address={hex(start)}',
                        f'--stop-address={hex(stop)}', str(binary)],
                       capture_output=True, text=True, check=True)
    return r.stdout


def addr_lines(text):
    return [l.strip() for l in text.splitlines()
            if re.match(r'^\s*[0-9a-f]+:\t', l)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default=None)
    ap.add_argument('--packet-dir', default=None)
    args = ap.parse_args()
    pkt = Path(args.packet_dir) if args.packet_dir else Path(__file__).resolve().parent
    binary = Path(args.binary) if args.binary else pkt / '..' / '..' / '..' / 'work' / 'hl-node-94.bin'
    data = binary.read_bytes()
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail('target digest mismatch')
    fn = data[FN_START - 0x1000:FN_END - 0x1000]
    if hashlib.sha256(fn).hexdigest() != FN_SHA:
        fail('function carve SHA mismatch')
    pad = data[FN_END - 0x1000:NEXT_FDE - 0x1000]
    if pad != b'\xcc' * 3 or hashlib.sha256(pad).hexdigest() != PAD_SHA:
        fail('padding mismatch')
    records = json.loads((pkt / 'records.json').read_text())
    if 'instructions' in records or 'mnemonics' in records:
        fail('records.json must carry semantic records only')
    if records['function']['sha256'] != FN_SHA:
        fail('records function SHA mismatch')
    # Call targets re-derived from raw rel32 encodings inside the function.
    derived = {}
    for off in range(len(fn) - 5):
        if fn[off] == 0xE8:
            site = FN_START + off
            derived[site] = site + 5 + struct.unpack_from('<i', fn, off + 1)[0]
    recorded = {int(c['site'], 16): int(c['target'], 16)
                for c in records['calls']}
    if derived != recorded:
        fail(f'call targets mismatch: derived {len(derived)} vs recorded {len(recorded)}')
    if derived[SELF_SITE] != FN_START:
        fail('self-call target mismatch')
    if any(t != PLT_DELETE for s, t in derived.items() if s != SELF_SITE):
        fail('non-delete call target inside function')
    # Caller census by full .text byte scan.
    out = subprocess.run(['readelf', '-SW', str(binary)],
                         capture_output=True, text=True, check=True).stdout
    m = re.search(r'\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', out)
    tva, toff, tsize = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)
    tdata = data[toff:toff + tsize]
    calls = []
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack_from('<i', tdata, i + 1)[0]
            if tva + i + 5 + rel == FN_START:
                calls.append(tva + i)
    if calls != [SELF_SITE] + EXPECTED_EXTERNAL_CALLERS:
        fail(f'caller census mismatch: {[hex(c) for c in calls]}')
    # FDE lines and GOT relocation against fresh tool output.
    frames = subprocess.run(['readelf', '--debug-dump=frames-interp', str(binary)],
                            capture_output=True, text=True, check=True).stdout
    for line in (pkt / 'frames.txt').read_text().splitlines():
        if line not in frames:
            fail(f'FDE line not reproduced: {line}')
    rela = subprocess.run(['readelf', '-r', str(binary)],
                          capture_output=True, text=True, check=True).stdout
    reloc = (pkt / 'relocations.txt').read_text().strip()
    if reloc not in rela or '_ZdlPvm' not in reloc:
        fail('GOT relocation not reproduced')
    # Excerpt address lines vs fresh objdump for the same ranges.
    for name, start, stop in [('window.objdump.txt', FN_START, NEXT_FDE),
                              ('wrapper.objdump.txt', 0x514C520, 0x514C57F),
                              ('cleanup-caller.objdump.txt', 0x5150BB0, 0x5150E4E),
                              ('plt.objdump.txt', PLT_DELETE, 0x5660450)]:
        kept = addr_lines((pkt / name).read_text())
        fresh = addr_lines(objdump(binary, start, stop))
        if kept != fresh:
            fail(f'excerpt mismatch: {name}')
    # MANIFEST hashes.
    for line in (pkt / 'MANIFEST.sha256').read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        actual = hashlib.sha256((pkt / name.strip()).read_bytes()).hexdigest()
        if actual != digest:
            fail(f'manifest mismatch: {name}')
    print('ALL CHECKS PASSED')


if __name__ == '__main__':
    main()
