#!/usr/bin/env python3
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END, FDE = 0x4D42FD0, 0x4D4312E, 0xF17F48
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D42FD0: '53', 0x4D42FD5: '4889fb', 0x4D42FD8: '488b4e20',
    0x4D4303C: "4183f96e",
    0x4D43066: "4080ff75",
    0x4D43082: "4180f86c",
    0x4D4309A: "48894628",
    0x4D4309E: "80f96c",
    0x4D430A3: '66c7030002', 0x4D430B6: 'e845c85100',
    0x4D4310A: 'c60301', 0x4D43115: 'c3',
}
if hashlib.sha256(BIN.read_bytes()).hexdigest() != TARGET:
    raise SystemExit('target hash mismatch')
with tempfile.TemporaryDirectory() as td:
    subprocess.check_call([sys.executable, str(ROOT/'tools/fde_extents.py'), '--release', '115', '--output-dir', td], stdout=subprocess.DEVNULL)
    rows = (pathlib.Path(td)/'node-115-fde.tsv').read_text().splitlines()
    if not any(r.startswith(f'{START:#x}\t{END:#x}\t{END-START}\t.text\t{FDE:#x}') for r in rows):
        raise SystemExit('FDE boundary mismatch')
obj = subprocess.check_output(['objdump', '-d', f'--start-address={START:#x}', f'--stop-address={END:#x}', str(BIN)], text=True)
got = {}
for line in obj.splitlines():
    if ':' not in line:
        continue
    a, rest = line.split(':', 1)
    try:
        a = int(a.strip(), 16)
    except ValueError:
        continue
    fields = rest.split('\t')
    got[a] = ''.join(fields[1].split()) if len(fields) > 1 else ''
def ok(w):
    return all(got.get(a, '').startswith(b) for a, b in w.items())
if not ok(W):
    raise SystemExit('witness mismatch')
mut = dict(W); mut[START] = '52'
if ok(mut):
    raise SystemExit('entry mutation not rejected')
mut = dict(W); mut[0x4D430A3] = '66c7030102'
if ok(mut):
    raise SystemExit('marker mutation not rejected')
print({'fde_start': hex(START), 'fde_end': hex(END), 'fde_bytes': END-START, 'eh_frame_offset': hex(FDE), 'witnesses': len(W), 'identity_controls': 2})
