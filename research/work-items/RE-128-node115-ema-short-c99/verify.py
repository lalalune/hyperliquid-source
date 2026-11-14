"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d43ee0, 0x4d43fca
FDE = '0x4d43ee0\t0x4d43fca\t234\t.text\t0xf18214'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4d43ee0: '53',
    0x4d43ee5: '4889fb',
    0x4d43ef0: 'c6462001',
    0x4d43f20: 'c60300',
    0x4d43f23: '488d05ee377501',
    0x4d43f74: '48894308',
    0x4d43fa5: 'c60309',
}

def check(ok, msg):
    if not ok: raise AssertionError(msg)

data = BIN.read_bytes()
check(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')
with tempfile.TemporaryDirectory() as td:
    out = pathlib.Path(td)
    subprocess.run(['python3', str(ROOT/'tools/fde_extents.py'), '--release', '115', '--output-dir', td], check=True, stdout=subprocess.DEVNULL)
    rows = (out/'node-115-fde.tsv').read_text().splitlines()
    check(any(row.startswith(FDE + '\t') for row in rows), 'exact FDE row missing')
    p = subprocess.run(['/opt/homebrew/opt/binutils/bin/objdump', '-d', f'--start-address={START:#x}', f'--stop-address={END:#x}', str(BIN)], check=True, text=True, capture_output=True)
    got = {}
    for line in p.stdout.splitlines():
        if ':' not in line or '\t' not in line: continue
        addr, rest = line.split(':', 1)
        try: a = int(addr.strip(), 16)
        except ValueError: continue
        fields = rest.split('\t')
        if len(fields) > 1: got[a] = ''.join(fields[1].split())
    for addr, prefix in W.items(): check(got.get(addr, '').startswith(prefix), f'witness {addr:#x}')
    for addr, prefix in ((0x4d43ee0, '52'), (0x4d43fa5, 'c60209')):
        check(not got.get(addr, '').startswith(prefix), f'mutation accepted {addr:#x}')
print('RE-128 static FDE verification passed; 7 witnesses and 2 mutation negatives')
