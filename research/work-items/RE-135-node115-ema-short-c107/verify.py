"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / 'artifacts/node/115/hl-node'
START, END = 0x4d445a0, 0x4d446c2
FDE = '0x4d445a0\t0x4d446c2\t290\t.text\t0xf18334'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
W = {
    0x4D445A0: '53',
    0x4D445A5: '4889fb',
    0x4D445A8: '488b4e20',
    0x4D445B3: '0f83b2000000',
    0x4D445E0: '440fb64c02fe',
    0x4D4460C: '4183f96e',
    0x4D44632: '4080ff75',
    0x4D4464A: '4180f86c',
    0x4D44662: '80f96c',
    0x4D44667: '31c0',
    0x4D4466B: '4889f7',
    0x4D4466E: 'e89d5e5100',
    0x4D44673: '48ffc0',
    0x4D44676: '48895308',
    0x4D4467A: '488903',
    0x4D44686: '48c744240805000000',
    0x4D4469A: 'e801605100',
    0x4D446A3: 'b802000000',
    0x4D446AA: '48c744240809000000',
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
    for addr, prefix in ((0x4d445a0, '52'), (0x4d4467a, '488902')):
        check(got.get(addr) != prefix, f'mutation accepted {addr:#x}')
print('RE-135 static FDE verification passed; 19 witnesses and 2 mutation negatives')
