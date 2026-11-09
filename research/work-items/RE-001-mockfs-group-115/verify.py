#!/usr/bin/env python3
"""Self-checks for RE-001-mockfs-group-115.

Checks: artifact digest vs provenance/artifacts.json, MANIFEST.sha256,
excerpt regeneration byte-for-byte vs fresh objdump, FDE ranges,
raw-binary spot bytes for cited instructions, RegisterOptions caller
census reproduction (37 sites, matching #3257/#4372/#4551/#4565), lea
censuses for the supports_direct_io map, the key literal, the
MockFileSystem vtable base and the two sibling EmulatedSystemClock maps,
direct-E8 caller censuses for the host, MockEnv::Create and the invoker,
the 61-slot vtable from .rela.dyn, the typeinfo literal, semantic-only
records, and the model tests.

Run from the repo root:
    python3 research/work-items/RE-001-mockfs-group-115/verify.py
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
VA_TO_OFF = 0x1000  # low-code vaddr - file offset

FUNCS = {
    "fn-6028a60-mock-filesystem-ctor.objdump.txt": (0x6028A60, 0x6028BA4),
    "fn-6029d10-static-initializer.objdump.txt": (0x6029D10, 0x602A25D),
    "fn-5fe58b0-mockfs-creator-invoke.objdump.txt": (0x5FE58B0, 0x5FE590C),
    "fn-6028bb0-mockfs-dtor.objdump.txt": (0x6028BB0, 0x6028CEA),
    "fn-6028d80-mockenv-create.objdump.txt": (0x6028D80, 0x6028E80),
}

SPOTS = {
    # Host ctor 0x6028a60.
    0x6028A60: bytes.fromhex("f30f1efa"),        # endbr64
    0x6028A72: bytes.fromhex("4c8d6b20"),        # lea 0x20(rbx),r13 mutex
    0x6028A8A: bytes.fromhex("e8f1e5fbff"),      # call base ctor 0x5fe7080
    0x6028A8F: bytes.fromhex("488d05628f4a00"),   # lea vtable base 0x64d19f8
    0x6028A99: bytes.fromhex("4883c010"),        # add rax,0x10 -> 0x64d1a08
    0x6028A9D: bytes.fromhex("488903"),          # vtable store
    0x6028AA0: bytes.fromhex("488d05d5fc94fa"),   # lea 0x97877c
    0x6028AA7: bytes.fromhex("0fb630"),          # movzbl (%rax),%esi (dead)
    0x6028AAA: bytes.fromhex("e811c60a00"),      # call mutex ctor 0x60d50c0
    0x6028AAF: bytes.fromhex("488d4350"),        # lea 0x50(rbx),%rax map
    0x6028AB3: bytes.fromhex("c7435000000000"),   # movl $0,0x50(rbx) color
    0x6028ABA: bytes.fromhex("48894360"),        # mov rax,0x60(rbx) left
    0x6028ABE: bytes.fromhex("48894368"),        # mov rax,0x68(rbx) right
    0x6028AC2: bytes.fromhex("48c7435800000000"),  # movq $0,0x58(rbx) parent
    0x6028ACA: bytes.fromhex("48c7437000000000"),  # movq $0,0x70(rbx) count
    0x6028AD2: bytes.fromhex("f3410f6f0424"),     # movdqu (%r12),%xmm0 clock
    0x6028ADF: bytes.fromhex("0f114378"),        # movups xmm0,0x78(rbx)
    0x6028AED: bytes.fromhex("488b159c474c00"),   # mov 0x64ed290,%rdx
    0x6028AF9: bytes.fromhex("83400801"),        # addl $1,0x8(%rax) refcount
    0x6028AFD: bytes.fromhex("4088ab90000000"),   # mov %bpl,0x90(rbx) bool
    0x6028B0F: bytes.fromhex("488d9390000000"),   # lea 0x90(%rbx),%rdx base
    0x6028B16: bytes.fromhex("488d0dc3cd4d00"),   # lea map 0x65058e0
    0x6028B1D: bytes.fromhex("4c89e6"),          # mov %r12,%rsi name arg
    0x6028B20: bytes.fromhex("48892c24"),        # mov %rbp,(%rsp) name ptr
    0x6028B24: bytes.fromhex("660fd68b88000000"),  # movq %xmm1,0x88(%rbx)
    0x6028B2C: bytes.fromhex("48c744240800000000"),  # movq $0,0x8(%rsp)
    0x6028B35: bytes.fromhex("c644241000"),      # movb $0,0x10(%rsp)
    0x6028B3A: bytes.fromhex("e8a1110700"),      # call RegisterOptions
    # Static initializer 0x6029d10, block 3 (this map).
    0x602A093: bytes.fromhex("488d35e4c441fa"),   # lea key literal 0x44657e
    0x602A09D: bytes.fromhex("e84ec1ffff"),      # call string ctor 0x60261f0
    0x602A0B3: bytes.fromhex("48c78530feffff00000000"),  # movq $0,-0x1d0
    0x602A12F: bytes.fromhex("48c785d8feffff00000000"),  # pack 0x0
    0x602A13A: bytes.fromhex("c785e0feffff00000000"),  # flags 0x0
    0x602A167: bytes.fromhex("e8845fd1ff"),      # call pair ctor 0x5d400f0
    0x602A17B: bytes.fromhex("4c8d2d5eb74d00"),   # lea map 0x65058e0
    0x602A19A: bytes.fromhex("e81164d1ff"),      # call insert 0x5d405b0
    0x602A1D4: bytes.fromhex("488d3d4556d1ff"),   # lea map dtor 0x5d3f820
    0x602A1DF: bytes.fromhex("4c89ee"),          # mov %r13,%rsi map arg
    0x602A1E2: bytes.fromhex("488d1537584c00"),   # lea __dso_handle 0x64efa20
    0x602A1F3: bytes.fromhex("e9886d3c00"),      # jmp __cxa_atexit
    # Sibling blocks (context, #4528).
    0x6029E50: bytes.fromhex("4c8d3d09bb4d00"),   # lea map 0x6505960
    0x6029FE0: bytes.fromhex("4c8d3d39b94d00"),   # lea map 0x6505920
    # Invoker 0x5fe58b0.
    0x5FE58B0: bytes.fromhex("f30f1efa"),        # endbr64
    0x5FE58B5: bytes.fromhex("bf98000000"),      # mov $0x98,edi alloc size
    0x5FE58C2: bytes.fromhex("e809b54000"),      # call operator new
    0x5FE58CA: bytes.fromhex("e8b1cdffff"),      # call SystemClock::Default
    0x5FE58D2: bytes.fromhex("ba01000000"),      # mov $0x1,%edx bool true
    0x5FE58DA: bytes.fromhex("e881310400"),      # call host 0x6028a60
    0x5FE58E3: bytes.fromhex("48895d00"),        # mov %rbx,0x0(%rbp) slot
    0x5FE58EF: bytes.fromhex("ff5008"),          # call *0x8(%rax) slot 1
    # Dtor 0x6028bb0.
    0x6028BB0: bytes.fromhex("f30f1efa"),        # endbr64
    0x6028BB4: bytes.fromhex("488d053d8e4a00"),   # lea vtable base 0x64d19f8
    0x6028BC5: bytes.fromhex("4883c010"),        # add rax,0x10
    0x6028BD2: bytes.fromhex("488907"),          # vtable store
    0x6028BCE: bytes.fromhex("488b6f60"),        # mov 0x60(%rdi),%rbp left
    0x6028BF5: bytes.fromhex("488b5d40"),        # mov 0x40(%rbp),%rbx value
    0x6028C00: bytes.fromhex("e82bc60a00"),      # call mutex lock 0x60d5230
    0x6028C15: bytes.fromhex("e8d6c60a00"),      # call mutex unlock 0x60d52f0
    0x6028C37: bytes.fromhex("e834c50a00"),      # call mutex destroy
    0x6028C80: bytes.fromhex("e83bc4d0ff"),      # call clock release
    0x6028CD5: bytes.fromhex("e896c40a00"),      # call mutex destroy +0x20
    0x6028CE5: bytes.fromhex("e9c6e3fbff"),      # jmp base dtor 0x5fe70b0
    # MockEnv::Create 0x6028d80.
    0x6028D80: bytes.fromhex("f30f1efa"),        # endbr64
    0x6028D8B: bytes.fromhex("bfa8000000"),      # mov $0xa8,edi alloc size
    0x6028DAB: bytes.fromhex("e820803c00"),      # call operator new
    0x6028DB0: bytes.fromhex("ba01000000"),      # mov $0x1,%edx bool true
    0x6028DBB: bytes.fromhex("488b055e0d43fa"),   # mov 0x459b20,%rax counts
    0x6028DC6: bytes.fromhex("48894308"),        # mov %rax,0x8(%rbx)
    0x6028DCA: bytes.fromhex("488d058f8e4a00"),   # lea control vtable 0x64d1c60
    0x6028DD4: bytes.fromhex("4883c010"),        # add rax,0x10 -> 0x64d1c70
    0x6028DD8: bytes.fromhex("488903"),          # control vtable store
    0x6028DDB: bytes.fromhex("e880fcffff"),      # call host 0x6028a60
    0x6028DE0: bytes.fromhex("bf60000000"),      # mov $0x60,edi MockEnv
    0x6028E12: bytes.fromhex("e8d9fbffff"),      # call MockEnv ctor 0x60289f0
    # Base ctor (cited).
    0x5FE7084: bytes.fromhex("488d056d7f4e00"),   # lea base vtable 0x64ceff8
    0x5FE708B: bytes.fromhex("48c7470800000000"),  # vector begin = 0
    0x5FE7093: bytes.fromhex("48c7471000000000"),  # vector end = 0
    0x5FE709B: bytes.fromhex("4883c010"),        # add rax,0x10 -> 0x64cf008
    0x5FE709F: bytes.fromhex("48c7471800000000"),  # vector capacity = 0
    0x5FE70A7: bytes.fromhex("488907"),          # base vtable store
    # Mutex ctor (cited): the dead byte arg.
    0x60D50C5: bytes.fromhex("31f6"),            # xor %esi,%esi
    0x60D50DC: bytes.fromhex("e8cfc33100"),      # call pthread_mutex_init
    # Init-array stub (cited, #4528).
    0x602E4C0: bytes.fromhex("f30f1efa"),        # endbr64
    0x602E4C4: bytes.fromhex("e947b8ffff"),      # jmp 0x6029d10
}

FDEs = {
    0x6028A60: 0x6028BA4,
    0x6028A0E: 0x6028A5D,
    0x6029D10: 0x602A25D,
    0x5FE58B0: 0x5FE590C,
    0x6028BB0: 0x6028CEA,
    0x6028D80: 0x6028E80,
    0x60297A0: 0x60298F7,
    0x60289F0: 0x6028A0D,
    0x5FE7080: 0x5FE70AB,
    0x5FE70B0: 0x5FE7135,
    0x6099CE0: 0x6099E34,
    0x5D400F0: 0x5D40477,
    0x5D405B0: 0x5D40F32,
    0x5D3F950: 0x5D3F9D3,
    0x5D3F820: 0x5D3F94D,
    0x5E32920: 0x5E32B06,
    0x60261F0: 0x60262C0,
    0x60D50C0: 0x60D5157,
    0x60D5170: 0x60D5200,
    0x60D5230: 0x60D52C5,
    0x60D52F0: 0x60D5385,
    0x6027720: 0x6027A7D,
    0x5FE2680: 0x5FE2756,
    0x6029390: 0x60294F5,
    0x5FD7360: 0x5FD7466,
}

LEA = {
    0x65058E0: [0x6028B16, 0x602A17B],
    0x64D19F8: [0x6028A8F, 0x6028BB4],
    0x44657E: [0x602A093],
    0x6505960: [0x602942B, 0x6029E50],
    0x6505920: [0x6029471, 0x6029FE0],
}

CALLERS = {
    0x6028A60: [0x5FE58DA, 0x6028DDB],
    0x6028D80: [0x602982A],
    0x5FE58B0: [],
}

LITERALS = {
    # .rodata: file offset == vaddr there.
    0x44657E: b"supports_direct_io",
    0x974450: b"N7rocksdb14MockFileSystemE",
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

    # 7. lea censuses
    ok = True
    for target, want in LEA.items():
        got = sorted(lea_sites(data, target))
        if got != want:
            ok = False
            print(f"  lea mismatch: {target:#x} got {[hex(s) for s in got]}")
    check("lea censuses", ok, f"{len(LEA)} targets")

    # 8. direct-E8 caller censuses
    ok = True
    for target, want in CALLERS.items():
        got = sorted(call_sites(data, target))
        if got != want:
            ok = False
            print(f"  callers mismatch: {target:#x} got {[hex(s) for s in got]}")
    check("caller censuses", ok, f"{len(CALLERS)} targets")

    # 9. literals in .rodata
    ok = True
    for va, want in LITERALS.items():
        if data[va:va + len(want)] != want:
            ok = False
            print(f"  literal mismatch: {va:#x}")
    check("literals", ok, f"{len(LITERALS)} strings")

    # 10. vtable slots from .rela.dyn match vtables.tsv
    relocs = {}
    base, count = 0x6BE8, 0x163CC8 // 24
    for i in range(count):
        off, info, add = struct.unpack_from("<QQq", data, base + i * 24)
        relocs[off] = (info & 0xFFFFFFFF, add)
    slots = []
    addr = 0x64D1A08
    while True:
        r = relocs.get(addr)
        if not r or r[0] != 8:
            break
        slots.append((addr, r[1]))
        addr += 8
    vtsv = (HERE / "vtables.tsv").read_text().splitlines()[1:]
    vtsv_slots = [(int(row.split("\t")[1], 16), int(row.split("\t")[2], 16))
                  for row in vtsv]
    check("vtable slots", slots == vtsv_slots and len(slots) == 61,
          f"{len(slots)} slots")

    # 11. semantic-only records, full digest
    raw = (HERE / "records.json").read_text()
    rec = json.loads(raw)
    bad = [k for k in ('"mnemonic"', '"instructions"', '"opcodes"') if k in raw]
    check("records are semantic-only", not bad, f"bad keys: {bad}")
    check("records bound to full node #115 digest",
          rec.get("artifact_sha256", "") == DIGEST
          and len(rec.get("artifact_sha256", "")) == 64)

    # 12. model tests
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_mockfs_group_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    last = r.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip().splitlines()[-1] if r.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin").strip() else ""
    check("model tests", r.returncode == 0, last)

    print(f"\n{len(failures)} failures" if failures else "\nALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
