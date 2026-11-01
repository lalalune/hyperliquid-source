#!/usr/bin/env python3
"""Verify this packet against the node #94 binary.

Usage: python3 verify.py [--binary PATH] [--packet-dir DIR]
Checks: target digest, function carve SHA, int3 padding, format bytes,
call targets re-derived from raw rel32 encodings, FDE line, GOT relocation,
caller census by byte scan, window-excerpt lines vs fresh objdump, and
MANIFEST.sha256 hashes. Exits non-zero on the first failure.
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
FN_START, FN_END = 0x514C050, 0x514C1B5
FN_SHA = 'de35d4d1ea71805561f47405245dbb89e6834a3b4bb7dc645355639481612c4e'
PAD_SHA = '3682c0a62515050101266cc639bf81f5d8c5395f49e7da93fcc22603018e0943'
EXPECTED_CALLERS = [0x514CC9F, 0x5157E2E, 0x51586D1, 0x515956C, 0x515A035]
CALL_TARGETS = {0x514C12E: 0x5660A00, 0x514C15D: 0x56604D0,
                0x514C179: 0x5660100, 0x514C1B0: 0x5660430}


def fail(msg):
    print(f'FAIL: {msg}')
    sys.exit(1)


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
    # .text file offset: vaddr - 0x1000 for this binary (section table).
    fn = data[FN_START - 0x1000:FN_END - 0x1000]
    if hashlib.sha256(fn).hexdigest() != FN_SHA:
        fail('function carve SHA mismatch')
    pad = data[FN_END - 0x1000:0x514C1C0 - 0x1000]
    if pad != b'\xcc' * 11 or hashlib.sha256(pad).hexdigest() != PAD_SHA:
        fail('padding mismatch')
    if data[0x1DF3ED:0x1DF3F0] != b'%f\x00':
        fail('format string mismatch')
    for site, target in CALL_TARGETS.items():
        off = site - 0x1000
        if data[off] != 0xE8:
            fail(f'call site {hex(site)} is not e8')
        rel = struct.unpack_from('<i', data, off + 1)[0]
        if site + 5 + rel != target:
            fail(f'call target at {hex(site)}: {hex(site + 5 + rel)} != {hex(target)}')
    records = json.loads((pkt / 'records.json').read_text())
    if records['target']['sha256'] != TARGET_SHA:
        fail('records target digest mismatch')
    if records['function']['sha256'] != FN_SHA:
        fail('records function SHA mismatch')
    frames = subprocess.run(['objdump', '--dwarf=frames', str(binary)],
                            capture_output=True, text=True, check=True).stdout
    if not any('pc=000000000514c050..000000000514c1b5' in l for l in frames.splitlines()):
        fail('FDE line missing')
    if (pkt / 'frames.txt').read_text().strip() not in frames:
        fail('frames.txt not present in fresh frames output')
    rela = subprocess.run(['readelf', '-r', str(binary)], capture_output=True, text=True, check=True).stdout
    got = [l.strip() for l in rela.splitlines() if '5778378' in l]
    if len(got) != 1 or 'GLOB_DAT' not in got[0] or 'vsnprintf' not in got[0]:
        fail('GOT relocation mismatch')
    if (pkt / 'relocations.txt').read_text().strip() != got[0]:
        fail('relocations.txt mismatch')
    out = subprocess.run(['readelf', '-SW', str(binary)], capture_output=True, text=True, check=True).stdout
    m = re.search(r'\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', out)
    tva, toff, tsize = int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)
    tdata = data[toff:toff + tsize]
    calls = []
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack_from('<i', tdata, i + 1)[0]
            if tva + i + 5 + rel == FN_START:
                calls.append(tva + i)
    if calls != EXPECTED_CALLERS:
        fail(f'caller census mismatch: {[hex(c) for c in calls]}')
    fresh = subprocess.run(['objdump', '-d', '--start-address=0x514c050',
                            '--stop-address=0x514c1c0', str(binary)],
                           capture_output=True, text=True, check=True).stdout
    addr_re = re.compile(r'^\s*[0-9a-f]+:')
    fresh_lines = [l for l in fresh.splitlines() if addr_re.match(l)]
    kept_lines = [l for l in (pkt / 'window.objdump.txt').read_text().splitlines() if addr_re.match(l)]
    if fresh_lines != kept_lines:
        fail('window excerpt lines differ from fresh objdump')
    manifest = (pkt / 'MANIFEST.sha256').read_text().splitlines()
    for line in manifest:
        digest, name = line.split(None, 1)
        name = name.lstrip('*')
        actual = hashlib.sha256((pkt / name).read_bytes()).hexdigest()
        if actual != digest:
            fail(f'manifest mismatch for {name}')
    print('ALL CHECKS PASSED')


if __name__ == '__main__':
    main()
