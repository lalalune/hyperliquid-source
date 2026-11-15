"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d43ee0, 0x4d43fca
FDE = '0x4d43ee0\t0x4d43fca\t234\t.text\t0xf18214'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D43EE0: '53',
    0x4D43EE5: '4889fb',
    0x4D43EF0: 'c6462001',
    0x4D43F20: 'c60300',
    0x4D43F23: '488d05ee377501',
    0x4D43F6A: '48b80000000000000080',
    0x4D43F74: '48894308',
    0x4D43F78: 'eb2b',
    0x4D43F83: 'ba01000000',
    0x4D43F88: 'e8b371d5ff',
    0x4D43F8D: '803c2409',
    0x4D43F98: '48894318',
    0x4D43FA1: '0f114308',
    0x4D43FA5: 'c60309',
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
    for addr, prefix in ((0x4d43ee0, '52'), (0x4d43fa5, 'c60209')):
        check(got.get(addr) != prefix, f'mutation accepted {addr:#x}')
print('RE-128 static FDE verification passed; 14 witnesses and 2 mutation negatives')
