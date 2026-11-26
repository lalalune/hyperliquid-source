"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, re, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / "artifacts/node/115/hl-node"
START, END = 0x1806f40, 0x180713f
FDE = "0x1806f40\t0x180713f\t511\t.text"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

W = {
    0x1806f4a: "4883ec48",
    0x1806f76: "e8c54bffff",
    0x1806f7b: "48b80000000000000080",
    0x1806f5d: "4939ed",
    0x1806f57: "7409",
    0x1806f62: "488d7b08",
    0x1806fa5: "410fb67500",
}

def check(condition, message):
    if not condition:
        raise AssertionError(message)

data = BIN.read_bytes()
check(hashlib.sha256(data).hexdigest() == DIGEST, "digest")

with tempfile.TemporaryDirectory() as td:
    out = pathlib.Path(td)
    subprocess.run(["python3", str(ROOT / "tools/fde_extents.py"), "--release", "115", "--output-dir", td], check=True, stdout=subprocess.DEVNULL)
    rows = (out / "node-115-fde.tsv").read_text().splitlines()
    check(any(r.startswith(FDE + "\t") for r in rows), "fde")
    proc = subprocess.run(["objdump", "-d", f"--start-address={START:#x}", f"--stop-address={END:#x}", str(BIN)], check=True, text=True, capture_output=True)
    got = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", line)
        if m: got[int(m.group(1), 16)] = "".join(m.group(2).split())
    for address, expected in W.items():
        check(got.get(address, "").startswith(expected), f"witness {address:#x}")
    for address, rejected in ((0x1806f76, "9090909090"), (0x1806f7b, "000000000000000000")):
        check(not got.get(address, "").startswith(rejected), f"mutation {address:#x}")

print("RE-153 static FDE verification passed; 7 witnesses and 2 mutation negatives")
