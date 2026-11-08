#!/usr/bin/env python3
"""Self-checks for RE-001-chrootfs-group-115.

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration byte-for-byte vs fresh objdump, FDE ranges,
raw-binary spot bytes for cited instructions, RegisterOptions caller
census reproduction (37 sites, matching #3257/#4372/#4551), lea
censuses for the chroot_dir map and the ChrootFileSystem vtable base,
the typeinfo literal, the host's sole E8 caller, semantic-only
records, and the model tests.

Run from the repo root:
    python3 research/work-items/RE-001-chrootfs-group-115/verify.py
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
VA_TO_OFF = 0x1000  # low-code vaddr - file offset

FUNCS = {
    "fn-5feeab0-chroot-filesystem-ctor.objdump.txt": (0x5FEEAB0, 0x5FEEC0D),
    "fn-5fef080-static-initializer.objdump.txt": (0x5FEF080, 0x5FEF25F),
    "fn-5fe7870-chroot-creator-invoke.objdump.txt": (0x5FE7870, 0x5FE79AB),
}

SPOTS = {
    # Host ctor 0x5feeab0.
    0x5FEEAB0: bytes.fromhex("f30f1efa"),        # endbr64
    0x5FEEAD8: bytes.fromhex("e8d3870100"),      # call base chain 0x60072b0
    0x5FEEADD: bytes.fromhex("488d0584094e00"),   # lea vtable base 0x64cf468
    0x5FEEAF4: bytes.fromhex("4883c010"),        # add rax,0x10 -> 0x64cf478
    0x5FEEAF8: bytes.fromhex("488903"),          # vtable store
    0x5FEEAC0: bytes.fromhex("4c8d6330"),        # lea 0x30(rbx),r12 group base
    0x5FEEB28: bytes.fromhex("48b86368726f6f745f64"),  # movabs "chroot_d"
    0x5FEEB41: bytes.fromhex("4889442420"),      # mov rax,0x20(rsp)
    0x5FEEB46: bytes.fromhex("488d0df3665100"),   # lea map 0x6505240
    0x5FEEB4D: bytes.fromhex("b869720000"),      # mov $0x7269,eax ("ir")
    0x5FEEB52: bytes.fromhex("48896c2410"),      # mov rbp,0x10(rsp) name ptr
    0x5FEEB57: bytes.fromhex("6689442428"),      # mov ax,0x28(rsp)
    0x5FEEB5C: bytes.fromhex("48c74424180a000000"),  # movq $0xa,0x18(rsp)
    0x5FEEB65: bytes.fromhex("c644242a00"),      # movb $0,0x2a(rsp)
    0x5FEEB25: bytes.fromhex("4c89e2"),          # mov r12,rdx base arg
    0x5FEEB36: bytes.fromhex("4c89ee"),          # mov r13,rsi name arg
    0x5FEEB6A: bytes.fromhex("e871b10a00"),      # call RegisterOptions
    0x5FEEB00: bytes.fromhex("4883fd0f"),        # cmp $0xf,rbp size gate
    0x5FEEB19: bytes.fromhex("884340"),          # mov al,0x40(rbx) size==1
    # Static initializer 0x5fef080.
    0x5FEF081: bytes.fromhex("660fefc0"),        # pxor xmm0,xmm0
    0x5FEF0E0: bytes.fromhex("48b86368726f6f745f64"),  # movabs "chroot_d"
    0x5FEF0F1: bytes.fromhex("48c78528feffff0a000000"),  # size 0xa
    0x5FEF0D2: bytes.fromhex("66898d38feffff"),   # mov cx,-0x1c8(rbp) "ir"
    0x5FEF19F: bytes.fromhex("48c785e8feffff09000000"),  # pack 0x9
    0x5FEF1AA: bytes.fromhex("c785f0feffff00000000"),  # flags 0x0
    0x5FEF1B4: bytes.fromhex("e8370fd5ff"),      # call pair ctor 0x5d400f0
    0x5FEF1CA: bytes.fromhex("4c8d2d6f605100"),   # lea map 0x6505240
    0x5FEF1E6: bytes.fromhex("e8c513d5ff"),      # call insert 0x5d405b0
    0x5FEF220: bytes.fromhex("488d3df905d5ff"),   # lea map dtor 0x5d3f820
    0x5FEF22E: bytes.fromhex("488d15eb075000"),   # lea __dso_handle 0x64efa20
    0x5FEF23D: bytes.fromhex("e93e1d4000"),      # jmp __cxa_atexit
    # Creator 0x5fe7870.
    0x5FE7870: bytes.fromhex("f30f1efa"),        # endbr64
    0x5FE7876: bytes.fromhex("bf50000000"),      # mov $0x50,edi alloc size
    0x5FE78A0: bytes.fromhex("e82b954000"),      # call operator new
    0x5FE78CC: bytes.fromhex("e8df710000"),      # call host 0x5feeab0
    0x5FE78F6: bytes.fromhex("48b80100000001000000"),  # movabs 0x100000001
    # Base ctors (cited).
    0x5FE708B: bytes.fromhex("48c7470800000000"),  # vector begin = 0
    0x5FE7093: bytes.fromhex("48c7471000000000"),  # vector end = 0
    0x5FE709F: bytes.fromhex("48c7471800000000"),  # vector capacity = 0
    0x5FE7249: bytes.fromhex("f30f6f4500"),      # movdqu 0(%rbp),xmm0
    0x5FE724E: bytes.fromhex("0f114320"),        # movups xmm0,0x20(rbx)
    0x5FE7292: bytes.fromhex("e8492a0b00"),      # base group RegisterOptions
    0x60072BD: bytes.fromhex("488d05d4924c00"),   # lea 0x64d0598
    0x60072C4: bytes.fromhex("4883c010"),        # add rax,0x10 -> 0x64d05a8
    0x60072C8: bytes.fromhex("488903"),          # vtable store
}

FDEs = {
    0x5FEEAB0: 0x5FEEC0D,
    0x5FEF080: 0x5FEF25F,
    0x5FE7870: 0x5FE79AB,
    0x6099CE0: 0x6099E34,
    0x5FE7210: 0x5FE72E8,
    0x5FE7080: 0x5FE70AB,
    0x60072B0: 0x60072CD,
    0x5D400F0: 0x5D40477,
    0x5D405B0: 0x5D40F32,
    0x5D3F950: 0x5D3F9D3,
}

LEA = {
    0x6505240: [0x5FEEB46, 0x5FEF1CA],
    0x64CF468: [0x5FEEADD, 0x5FEEC1D, 0x5FEECFD],
}

LITERALS = {
    # .rodata: file offset == vaddr there.
    0x9732F0: b"N7rocksdb16ChrootFileSystemE",
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

    # 7. lea censuses for the map and the vtable base
    ok = True
    for target, want in LEA.items():
        got = sorted(lea_sites(data, target))
        if got != want:
            ok = False
            print(f"  lea mismatch: {target:#x} got {[hex(s) for s in got]}")
    check("lea censuses", ok, f"{len(LEA)} targets")

    # 8. typeinfo literal in .rodata
    ok = True
    for va, want in LITERALS.items():
        if data[va:va + len(want)] != want:
            ok = False
            print(f"  literal mismatch: {va:#x}")
    check("literals", ok, f"{len(LITERALS)} strings")

    # 9. the host's sole E8 caller is the creator
    hosts = call_sites(data, 0x5FEEAB0)
    check("host sole caller", hosts == {0x5FE78CC},
          f"{[hex(s) for s in sorted(hosts)]}")

    # 10. semantic-only records, full digest
    raw = (HERE / "records.json").read_text()
    rec = json.loads(raw)
    bad = [k for k in ('"mnemonic"', '"instructions"', '"opcodes"') if k in raw]
    check("records are semantic-only", not bad, f"bad keys: {bad}")
    check("records bound to full node #115 digest",
          rec.get("artifact_sha256", "") == DIGEST
          and len(rec.get("artifact_sha256", "")) == 64)

    # 11. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_chrootfs_group_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    check("model tests", r.returncode == 0, last)

    print(f"\n{len(failures)} failures" if failures else "\nALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
