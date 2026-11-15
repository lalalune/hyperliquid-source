"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d441e0, 0x4d442d2
FDE = '0x4d441e0\t0x4d442d2\t242\t.text\t0xf18290'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D441E0: '53',
    0x4D441E5: '4889fb',
    0x4D44220: 'c60300',
    0x4D44223: '488d05ee347501',
    0x4D44266: '3cc0',
    0x4D44268: '750e',
    0x4D4426A: '66c7030903',
    0x4D4427E: '488d158d27bdfb',
    0x4D4428F: 'b913000000',
    0x4D44294: '41b903000000',
    0x4D4429A: 'e8a191a4ff',
    0x4D4429F: '803c2409',
    0x4D442AA: '884301',
    0x4D442AD: 'c60309',
}

def check(ok, msg):
    if not ok: raise AssertionError(msg)

data = BIN.read_bytes()
check(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')
with tempfile.TemporaryDirectory() as td:
    out = pathlib.Path(td)
    subprocess.run([sys.executable, str(ROOT/'tools/fde_extents.py'), '--release', '115', '--output-dir', td], check=True, stdout=subprocess.DEVNULL)
    rows = (out/'node-115-fde.tsv').read_text().splitlines()
    check(any(row.startswith(FDE + '\t') for row in rows), 'exact FDE row missing')
    p = subprocess.run(['objdump', '-d', '--insn-width=16', f'--start-address={START:#x}', f'--stop-address={END:#x}', str(BIN)], check=True, text=True, capture_output=True)
    got = {}
    for line in p.stdout.splitlines():
        if ':' not in line or '\t' not in line: continue
        addr, rest = line.split(':', 1)
        try: a = int(addr.strip(), 16)
        except ValueError: continue
        fields = rest.split('\t')
        if len(fields) > 1: got[a] = ''.join(fields[1].split())
    for addr, prefix in W.items(): check(got.get(addr) == prefix, f'witness {addr:#x}')
    for addr, prefix in ((0x4d441e0, '52'), (0x4d442ad, 'c60209')):
        check(got.get(addr) != prefix, f'mutation accepted {addr:#x}')
print('RE-131 static FDE verification passed; 14 witnesses and 2 mutation negatives')
