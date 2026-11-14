"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d446d0, 0x4d4486a
FDE = '0x4d446d0\t0x4d4486a\t410\t.text\t0xf18358'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D446D0: '4156',
    0x4D446D7: '4889fb',
    0x4D446DA: '488b4e20',
    0x4D446E5: '0f83d6000000',
    0x4D44710: '440fb64c02fe',
    0x4D4473F: '4183f96e',
    0x4D4474F: '49be0000000000000080',
    0x4D44773: '4080ff75',
    0x4D44793: '4180f86c',
    0x4D447B3: '80f96c',
    0x4D447BC: '4c8933',
    0x4D447C1: '488d15384a71fb',
    0x4D447D4: 'b908000000',
    0x4D447D9: '41b902000000',
    0x4D447DF: 'e8ac2f5200',
    0x4D447EB: '711b',
    0x4D44800: '48ffc0',
    0x4D44803: '488903',
    0x4D44817: '0f115320',
    0x4D4481F: '0f1103',
    0x4D44822: '4889d8',
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
    for addr, prefix in ((0x4d446d0, '4056'), (0x4d44822, '4889d9')):
        check(got.get(addr) != prefix, f'mutation accepted {addr:#x}')
print('RE-136 static FDE verification passed; 21 witnesses and 2 mutation negatives')
