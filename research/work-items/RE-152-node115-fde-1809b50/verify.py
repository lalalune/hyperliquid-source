"""Verify one pinned node115 FDE using static bytes only."""
import hashlib, pathlib, re, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
BIN = ROOT / "artifacts/node/115/hl-node"
START, END = 0x1809b50, 0x1809d69
FDE = "0x1809b50\t0x1809d69\t537\t.text"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# Seven instruction witnesses: address -> first bytes of the pinned encoding.
W = {
    0x1809b5a: "4883ec68",                 # subq $0x68, %rsp
    0x1809b86: "e8b51fffff",               # callq 0x17fbb40
    0x1809b8b: "48b80100000000000080",     # movabsq $0x8000000000000001,%rax
    0x1809baf: "0f845a010000",             # je 0x1809d0f
    0x1809bb5: "49bf0100000000000080",     # movabsq $0x8000000000000001,%r15
    0x1809bcc: "e81fb7f100",               # callq 0x27252f0
    0x1809d0f: "488d3da245c204",           # leaq 0x4c245a2(%rip),%rdi
}


def check(condition, message):
    if not condition:
        raise AssertionError(message)


data = BIN.read_bytes()
check(hashlib.sha256(data).hexdigest() == DIGEST, "digest")

with tempfile.TemporaryDirectory() as td:
    out = pathlib.Path(td)
    subprocess.run(
        ["python3", str(ROOT / "tools/fde_extents.py"), "--release", "115", "--output-dir", td],
        check=True, stdout=subprocess.DEVNULL,
    )
    rows = (out / "node-115-fde.tsv").read_text().splitlines()
    check(any(r.startswith(FDE + "\t") for r in rows), "fde")

    proc = subprocess.run(
        ["objdump", "-d", f"--start-address={START:#x}", f"--stop-address={END:#x}", str(BIN)],
        check=True, text=True, capture_output=True,
    )
    got = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", line)
        if m:
            got[int(m.group(1), 16)] = "".join(m.group(2).split())

    for address, expected in W.items():
        check(got.get(address, "").startswith(expected), f"witness {address:#x}")

    # Mutation negatives: corruption patterns that must NOT appear at the witnesses.
    for address, rejected in (
        (0x1809b86, "9090909090"),        # call replaced by NOPs
        (0x1809b8b, "000000000000000000"),  # immediate zeroed
    ):
        check(not got.get(address, "").startswith(rejected), f"mutation {address:#x}")

print("RE-152 static FDE verification passed; 7 witnesses and 2 mutation negatives")
