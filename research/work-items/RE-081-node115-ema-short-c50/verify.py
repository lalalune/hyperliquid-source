#!/usr/bin/env python3
import hashlib, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4d3dcd0, 0x4d3ddd9, 0xf17794
W = {
    0x4d3dcd0: '55',
    0x4d3dd0d: '48894c2448',
    0x4d3dd7c: '488d5c2448',
    0x4d3dd90: '4889df',
    0x4d3dda2: 'e879d63f00',
    0x4d3ddac: '3b28',
    0x4d3ddba: 'e861d63f00',
}
want = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
if hashlib.sha256(BIN.read_bytes()).hexdigest() != want: raise SystemExit('target hash mismatch')
import tempfile
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable, str(ROOT/'tools/fde_extents.py'), '--release', '115', '--output-dir', td], stdout=subprocess.DEVNULL)
    rows = (pathlib.Path(td) / 'node-115-fde.tsv').read_text().splitlines()
    if not any(r.startswith(f'{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}\t') for r in rows):
        raise SystemExit('FDE boundary mismatch')
obj = subprocess.check_output(['objdump','-d','--insn-width=16','--start-address='+hex(START),'--stop-address='+hex(END),str(BIN)], text=True)
rows = {}
for line in obj.splitlines():
    if ':' not in line: continue
    a, rest = line.split(':',1)
    try: addr=int(a.strip(),16)
    except ValueError: continue
    fields = rest.split('\t')
    hx=''.join(fields[1].split()) if len(fields) > 1 else ''
    if hx: rows[addr]=hx
cursor = START
partition = bytearray()
for address, encoded in sorted(rows.items()):
    if address != cursor or not encoded:
        raise SystemExit('non-contiguous disassembly partition')
    instruction = bytes.fromhex(encoded)
    partition.extend(instruction)
    cursor += len(instruction)
if cursor != END or hashlib.sha256(partition).hexdigest() != 'ab377cbde4cd1b16230bbd7e51373905da9d6ddd2022b178efb223d905567f31':
    raise SystemExit('disassembly partition differs from the authenticated body')
def matches(witnesses):
    return all(rows.get(address, '').startswith(expected) for address, expected in witnesses.items())

if not matches(W):
    raise SystemExit('witness mismatch')
for address in (START, 0x4d3dda2):
    corrupted = dict(W)
    encoded = bytes.fromhex(corrupted[address])
    corrupted[address] = (bytes([encoded[0] ^ 1]) + encoded[1:]).hex()
    if matches(corrupted):
        raise SystemExit(f'witness mutation accepted at {address:#x}')
print(json.dumps({'fde_start':hex(START),'fde_end':hex(END),'fde_bytes':END-START,'eh_frame_offset':hex(FDE),'witnesses':len(W),'identity_controls':2}, sort_keys=True))
