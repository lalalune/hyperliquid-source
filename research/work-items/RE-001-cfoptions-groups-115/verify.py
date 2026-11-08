#!/usr/bin/env python3
"""Self-checks for RE-001-cfoptions-groups-115.

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration byte-for-byte vs fresh objdump, FDE ranges,
raw-binary spot bytes for cited instructions, RegisterOptions caller
census reproduction (37 sites, matching #3257/#4372), lea censuses for
the two name literals and two maps, literals, semantic-only records,
and the model tests.

Run from the repo root:
    python3 research/work-items/RE-001-cfoptions-groups-115/verify.py
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
VA_TO_OFF = 0x1000  # .text vaddr - file offset

FUNCS = {
    "fn-6086e00-cfoptions-configurable-ctor.objdump.txt": (0x6086E00, 0x608818D),
    "fn-6099ce0-register-options.objdump.txt": (0x6099CE0, 0x6099E34),
}

SPOTS = {
    0x6086E00: bytes.fromhex("f30f1efa"),        # host endbr64
    0x6086E28: bytes.fromhex("4889542420"),      # mov rdx,0x20(rsp) input map
    0x6087235: bytes.fromhex("488d4b20"),        # lea 0x20(rbx),rcx mutable base
    0x608723F: bytes.fromhex("48c7430800000000"),  # vector begin = 0
    0x608725C: bytes.fromhex("48c7431000000000"),  # vector end = 0
    0x6087268: bytes.fromhex("48c7431800000000"),  # vector capacity = 0
    0x608724A: bytes.fromhex("4989cf"),          # mov rcx,r15
    0x608724D: bytes.fromhex("488d05d4be4400"),   # lea vtable1 0x64d3128
    0x6087270: bytes.fromhex("488903"),          # vtable1 store
    0x6087473: bytes.fromhex("488d3517863bfa"),   # lea MutableCFOptions 0x43fa91
    0x6087485: bytes.fromhex("e86665ffff"),      # call string ctor 0x607d9f0
    0x608748A: bytes.fromhex("488d0d8ff64700"),   # lea map 0x6506b20
    0x6087491: bytes.fromhex("4c89fa"),          # mov r15,rdx
    0x608749A: bytes.fromhex("e841280100"),      # call RegisterOptions #1
    0x6087533: bytes.fromhex("488d056ebc4400"),   # lea vtable2 0x64d31a8
    0x6087541: bytes.fromhex("488903"),          # vtable2 store
    0x6087544: bytes.fromhex("488d8318020000"),   # lea 0x218(rbx) immutable base
    0x608754E: bytes.fromhex("4889442428"),      # mov rax,0x28(rsp)
    0x6087CB7: bytes.fromhex("488b442420"),      # mov 0x20(rsp),rax input map
    0x6087CC1: bytes.fromhex("488d3581b53afa"),   # lea ImmutableCFOptions 0x433249
    0x6087CC8: bytes.fromhex("48898330060000"),   # mov rax,0x630(rbx)
    0x6087CCF: bytes.fromhex("e81c5dffff"),      # call string ctor 0x607d9f0
    0x6087CDE: bytes.fromhex("488d0dfbed4700"),   # lea map 0x6506ae0
    0x6087CE8: bytes.fromhex("e8f31f0100"),      # call RegisterOptions #2
    0x6099CE0: bytes.fromhex("f30f1efa"),        # helper endbr64
    0x6099D7F: bytes.fromhex("660f6f442430"),     # movdqa base/map store
    0x6099D89: bytes.fromhex("4883431030"),       # end += 0x30
    0x6099E0A: bytes.fromhex("e881f9ffff"),       # call growth 0x6099790
}

FDEs = {
    0x6086E00: 0x608818D,
    0x6099CE0: 0x6099E34,
    0x6099790: 0x6099CAD,
    0x607D9F0: 0x607DAD3,
}

CALLERS = {
    0x6099CE0: 37,  # direct E8 call sites; must match #3257/#4372 exactly
}

LEA = {
    0x43FA91: [0x6087473],
    0x433249: [0x6087CC1],
    0x6506B20: [0x608748A, 0x608EC34, 0x608F329],
    0x6506AE0: [0x6087CDE, 0x6090E46],
}

LITERALS = {
    0x43FA91: b"MutableCFOptions",
    0x433249: b"ImmutableCFOptions",
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


def lea_sites(data, target):
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = set()
    i = 0
    while True:
        i = seg.find(b"\x8d", i)
        if i == -1 or i + 7 > len(seg):
            break
        if i >= 1 and seg[i - 1] in (0x48, 0x49, 0x4C, 0x4D):
            if seg[i + 1] & 0xC7 == 0x05:
                rel = struct.unpack_from("<i", seg, i + 2)[0]
                site = TEXT_VA + i - 1
                if site + 7 + rel == target:
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
             f"--stop-address={stop:#x}", "work/hl-node-115.bin"],
            cwd=ROOT, text=True)
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

    # 7. lea censuses for the two name literals and two maps
    ok = True
    for target, want in LEA.items():
        got = sorted(lea_sites(data, target))
        if got != want:
            ok = False
            print(f"  lea mismatch: {target:#x} got {[hex(s) for s in got]}")
    check("lea censuses", ok, f"{len(LEA)} targets")

    # 8. literals in .rodata (fixed-length slices: these are literal
    # chunks inside longer runs, not NUL-terminated strings)
    ok = True
    for va, want in LITERALS.items():
        if data[va:va + len(want)] != want:
            ok = False
            print(f"  literal mismatch: {va:#x}")
    check("literals", ok, f"{len(LITERALS)} strings")

    # 9. semantic-only records, full digest
    raw = (HERE / "records.json").read_text()
    rec = json.loads(raw)
    bad = [k for k in ('"mnemonic"', '"instructions"', '"opcodes"') if k in raw]
    check("records are semantic-only", not bad, f"bad keys: {bad}")
    check("records bound to full node #115 digest",
          rec.get("artifact_sha256", "") == DIGEST
          and len(rec.get("artifact_sha256", "")) == 64)

    # 10. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_cfoptions_groups_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    check("model tests", r.returncode == 0, last)

    print(f"\n{len(failures)} failures" if failures else "\nALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
