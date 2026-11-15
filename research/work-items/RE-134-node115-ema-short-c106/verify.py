"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d444c0, 0x4d4459b
FDE = '0x4d444c0\t0x4d4459b\t219\t.text\t0x12f2820'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D444C0: '4157',
    0x4D444C9: '4889fb',
    0x4D444D2: '48f7d9',
    0x4D444D5: '7111',
    0x4D444D7: '48c70300000000',
    0x4D444E1: 'e8ba070b00',
    0x4D444E8: '48b90000000000000080',
    0x4D444F2: '4883c102',
    0x4D44502: '740d',
    0x4D44504: '83f801',
    0x4D44507: '752a',
    0x4D44509: 'f2480f2a4610',
    0x4D44516: '0f140df3cc70fb',
    0x4D4451D: '660f5c0d4bbc70fb',
    0x4D4452D: 'f20f58c1',
    0x4D44533: 'f20f104610',
    0x4D44538: 'f20f114308',
    0x4D4453D: 'b801000000',
    0x4D44577: '4c897b08',
    0x4D4457B: 'b802000000',
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
    for addr, prefix in ((0x4d444c0, '4057'), (0x4d44538, 'f20f104308')):
        check(got.get(addr) != prefix, f'mutation accepted {addr:#x}')
print('RE-134 static FDE verification passed; 20 witnesses and 2 mutation negatives')
