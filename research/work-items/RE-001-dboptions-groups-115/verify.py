#!/usr/bin/env python3
"""Self-checks for RE-001-dboptions-groups-115.

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration byte-for-byte vs fresh objdump, FDE ranges,
raw-binary spot bytes for cited instructions, RegisterOptions caller
census reproduction (37 sites, matching #3257), literals, semantic-only
records, and the model tests.

Run from the repo root:
    python3 research/work-items/RE-001-dboptions-groups-115/verify.py
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
VA_TO_OFF = 0x1000  # .text vaddr - file offset

FUNCS = {
    "fn-60a47f0-dboptions-configurable-ctor.objdump.txt": (0x60A47F0, 0x60A636B),
    "fn-6099ce0-register-options.objdump.txt": (0x6099CE0, 0x6099E34),
}

SPOTS = {
    0x60A47F0: bytes.fromhex("f30f1efa"),        # host endbr64
    0x60A486E: bytes.fromhex("48c7430800000000"),  # vector begin = 0
    0x60A4895: bytes.fromhex("48c7431000000000"),  # vector end = 0
    0x60A48A6: bytes.fromhex("48c7431800000000"),  # vector capacity = 0
    0x60A48AE: bytes.fromhex("488903"),           # first vtable store
    0x60A48F1: bytes.fromhex("660f6f05e7f83afa"),  # movdqa "MutableDBOptions"
    0x60A4901: bytes.fromhex("488d0db8244600"),   # lea mutable map 0x6506dc0
    0x60A492A: bytes.fromhex("e8b153ffff"),       # call RegisterOptions #1
    0x60A4958: bytes.fromhex("488903"),           # second vtable store
    0x60A50AA: bytes.fromhex("660f6f05eeb93afa"),  # movdqa "ImmutableDBOptio"
    0x60A50BA: bytes.fromhex("488d0dbf1c4600"),   # lea dboptions map 0x6506d80
    0x60A50C9: bytes.fromhex("ba6e730000"),       # mov $0x736e ("ns")
    0x60A50F2: bytes.fromhex("e8e94bffff"),       # call RegisterOptions #2
    0x6099CE0: bytes.fromhex("f30f1efa"),         # helper endbr64
    0x6099D7F: bytes.fromhex("660f6f442430"),     # movdqa base/map store
    0x6099D89: bytes.fromhex("4883431030"),       # end += 0x30
    0x6099E0A: bytes.fromhex("e881f9ffff"),       # call growth 0x6099790
}

FDEs = {
    0x60A47F0: 0x60A636B,
    0x6099CE0: 0x6099E34,
    0x6099790: 0x6099CAD,
}

CALLERS = {
    0x6099CE0: 37,  # direct E8 call sites; must match #3257 exactly
}

LITERALS = {
    0x4541E0: b"MutableDBOptions",
    0x450AA0: b"ImmutableDBOptio",
}

failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""))
    if not ok:
        failures.append(name)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def call_sites(data, target):
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = set()
    i = 0
    while True:
        i = seg.find(b"\xe8", i)
        if i == -1 or i + 5 > len(seg):
            break
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        site = TEXT_VA + i
        if site + 5 + rel == target:
            sites.add(site)
        i += 1
    return sites


def main() -> int:
    data = BIN.read_bytes()

    # 1. artifact digest
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    check("artifact digest", sha256_file(BIN) == want, want[:16])

    # 2. manifest
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    for line in manifest:
        digest, name = line.split(None, 1)
        if sha256_file(HERE / name) != digest:
            ok = False
            print(f"  manifest mismatch: {name}")
    check("MANIFEST.sha256", ok, f"{len(manifest)} files")

    # 3. excerpt regeneration
    ok = True
    for name, (start, stop) in FUNCS.items():
        out = subprocess.check_output(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        if (HERE / name).read_text() != out:
            ok = False
            print(f"  excerpt mismatch: {name}")
    check("excerpts regenerate byte-for-byte", ok, f"{len(FUNCS)} files")

    # 4. FDE ranges
    sys.path.insert(0, str(ROOT / "tools"))
    from fde_extents import eh_frame_records
    _, frames = eh_frame_records(data)
    fde = {f["start"]: f["end"] for f in frames}
    ok = all(fde.get(s) == e for s, e in FDEs.items())
    check("FDE ranges", ok, f"{len(FDEs)} functions")

    # 5. raw-binary spot bytes
    ok = True
    for va, want in SPOTS.items():
        if data[va - VA_TO_OFF:va - VA_TO_OFF + len(want)] != want:
            ok = False
            print(f"  spot mismatch: {va:#x}")
    check("raw-binary spot bytes", ok, f"{len(SPOTS)} sites")

    # 6. caller census (count + exact site set vs callers.tsv)
    sites = call_sites(data, 0x6099CE0)
    tsv = (HERE / "callers.tsv").read_text().splitlines()[1:]
    tsv_sites = {int(row.split("\t")[0], 16) for row in tsv}
    check("caller census", sites == tsv_sites and len(sites) == 37,
          f"{len(sites)} sites")

    # 7. literals in .rodata (fixed-length slices: these are literal
    # chunks inside longer runs, not NUL-terminated strings)
    ok = True
    for va, want in LITERALS.items():
        if data[va:va + len(want)] != want:
            ok = False
            print(f"  literal mismatch: {va:#x}")
    check("literals", ok, f"{len(LITERALS)} strings")

    # 8. semantic-only records, full digest
    raw = (HERE / "records.json").read_text()
    rec = json.loads(raw)
    bad = [k for k in ('"mnemonic"', '"instructions"', '"opcodes"') if k in raw]
    check("records are semantic-only", not bad, f"bad keys: {bad}")
    check("records bound to full node #115 digest",
          rec.get("artifact_sha256", "") == DIGEST
          and len(rec.get("artifact_sha256", "")) == 64)

    # 9. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_dboptions_groups_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    last = r.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip().splitlines()[-1] if r.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip() else ""
    check("model tests", r.returncode == 0, last)

    print(f"\n{len(failures)} failures" if failures else "\nALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
