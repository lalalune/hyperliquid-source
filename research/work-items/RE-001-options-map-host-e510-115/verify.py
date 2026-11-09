#!/usr/bin/env python3
"""Verify this packet against the target binary (node #115).

Run from the repo root:
    python3 research/work-items/RE-001-options-map-host-e510-115/verify.py
Checks: artifact digest, manifest, excerpt regeneration, FDE ranges,
raw-binary spot bytes, literals, the caller census (including the
shared-helper counts and the base-predicate reloc count), the vtable
maps, semantic-only records, and the model tests. Exits non-zero on
any failure.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

CHECKS = []

HOST_CALLERS = [
    0x5EBA260, 0x5FD3672, 0x5FD3A73, 0x5FD489A, 0x5FED884, 0x5FFA85A,
    0x5FFBB5A, 0x60779AF, 0x60952CA, 0x61373EB, 0x613D996, 0x6197B55,
    0x61A7194, 0x61C02EA, 0x61CA53B, 0x61CF087, 0x61EA080, 0x61EC04B,
    0x61F457A, 0x61FD94A, 0x620A120,
]
BSS_LEA = [
    0x6077907, 0x607E8E0, 0x6086C84, 0x609E567, 0x60A7534, 0x60BBC99,
    0x60BF710, 0x60BF730, 0x61372C8, 0x61D2974,
]


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def va_to_off(va):
    return va - TEXT_VA + TEXT_OFF


def read_bytes(va, n):
    data = BIN.read_bytes()
    off = va_to_off(va)
    return data[off:off + n]


def scan_callers(data, target):
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits, idx = [], 0
    while True:
        i = seg.find(b"\xe8", idx)
        if i == -1 or i + 5 > len(seg):
            break
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        site = TEXT_VA + i
        if site + 5 + rel == target:
            hits.append(site)
        idx = i + 1
    return hits


def scan_lea(data, target):
    seg = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    hits, idx = [], 0
    while True:
        i = seg.find(b"\x48\x8d", idx)
        if i == -1:
            break
        if i + 7 <= len(seg) and (seg[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", seg, i + 3)[0]
            site = TEXT_VA + i
            if site + 7 + disp == target:
                hits.append(site)
        idx = i + 1
    return hits


def main() -> int:
    data = BIN.read_bytes()

    # 1. Artifact digest.
    check("artifact digest",
          hashlib.sha256(data).hexdigest() == EXPECTED_SHA256)

    # 2. Manifest: every packet file listed, hashes match.
    manifest = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    files = sorted(p.name for p in HERE.iterdir() if p.is_file())
    check("manifest lists every packet file",
          set(manifest) == set(files) - {"MANIFEST.sha256"},
          f"manifest={sorted(manifest)} files={files}")
    ok = True
    for name, digest in manifest.items():
        p = HERE / name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            ok = False
    check("manifest hashes match", ok)

    # 3. Excerpts byte-identical to fresh objdump.
    for name, (start, stop) in {
        "fn-609e510-host.objdump.txt": (0x609E510, 0x609F073),
        "fn-6098510-pre-step.objdump.txt": (0x6098510, 0x60985AF),
        "fn-5d35070-release-helper.objdump.txt": (0x5D35070, 0x5D350BC),
        "fn-5d36110-map-dtor.objdump.txt": (0x5D36110, 0x5D361D5),
        "fn-5d2e770-base-predicate.objdump.txt": (0x5D2E770, 0x5D2E832),
        "fn-609de80-slot12.objdump.txt": (0x609DE80, 0x609E29E),
        "fn-60c1190-map-parse.objdump.txt": (0x60C1190, 0x60C1887),
    }.items():
        fresh = subprocess.check_output(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "artifacts/node/115/hl-node"],
            cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
        check(f"excerpt {name} regenerates byte-identical",
              fresh == (HERE / name).read_text())

    # 3b. Re-shipped excerpts match the #4328 / #4320 packet bodies
    # (instruction lines only; the #4328 header carried an absolute
    # path, normalized here).
    body_new = (HERE / "fn-609de80-slot12.objdump.txt").read_text().splitlines()[2:]
    body_old = (ROOT / "research" / "work-items"
                / "RE-001-type22-delegates-115"
                / "fn-609de80-slot12-nested-serializer.objdump.txt").read_text().splitlines()[2:]
    check("slot-12 excerpt body matches #4328 packet", body_new == body_old)
    body_new = (HERE / "fn-60c1190-map-parse.objdump.txt").read_text().splitlines()[2:]
    body_old = (ROOT / "research" / "work-items"
                / "RE-001-optiontypeinfo-type2122-arm-115"
                / "fn-60c1190-map-parse.objdump.txt").read_text().splitlines()[2:]
    check("map-parse excerpt body matches #4320 packet", body_new == body_old)
    body_new = (HERE / "fn-6098510-pre-step.objdump.txt").read_text().splitlines()[2:]
    check("pre-step excerpt is whole-function (ends at 0x60985af)",
          any("60985a3" in line for line in body_new))

    # 4. FDE ranges from readelf.
    frames = subprocess.check_output(
        ["objdump", "--dwarf=frames", "artifacts/node/115/hl-node"],
        cwd=ROOT, text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    for start, stop in [(0x609E510, 0x609F073), (0x6098510, 0x60985AF),
                        (0x60985E0, 0x609865E), (0x5D35070, 0x5D350BC),
                        (0x5D36110, 0x5D361D5), (0x5D2E770, 0x5D2E832),
                        (0x609DE80, 0x609E29E), (0x60C1190, 0x60C1887)]:
        check(f"FDE {start:#x}..{stop:#x}",
              f"pc=000000000{start:x}..000000000{stop:x}" in frames)

    # 4b. frames.txt lists exactly those FDEs.
    listed = set()
    for line in (HERE / "frames.txt").read_text().splitlines():
        m = re.match(r"FDE pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            listed.add((int(m.group(1), 16), int(m.group(2), 16)))
    check("frames.txt matches the 8 FDEs",
          listed == {(0x609E510, 0x609F073), (0x6098510, 0x60985AF),
                     (0x60985E0, 0x609865E), (0x5D35070, 0x5D350BC),
                     (0x5D36110, 0x5D361D5), (0x5D2E770, 0x5D2E832),
                     (0x609DE80, 0x609E29E), (0x60C1190, 0x60C1887)})

    # 4c. The 0x609e0a9 correction: the call site is inside slot 12's
    # FDE, not inside 0x609e510's FDE.
    check("0x609e0a9 is inside FDE 0x609de80..0x609e29e, not 0x609e510",
          0x609DE80 <= 0x609E0A9 < 0x609E29E and not (0x609E510 <= 0x609E0A9 < 0x609F073))

    # 5. Raw-binary spot bytes for the pinned sites.
    spots = {
        0x609E510: bytes.fromhex("f30f1efa"),          # endbr64
        0x609E547: bytes.fromhex("c70700000000"),      # movl $0x0,(%rdi) kOk
        0x609E567: bytes.fromhex("488d0512a44600"),    # lea 0x6508980
        0x609E5A1: bytes.fromhex("ff5078"),            # call *0x78 GetId
        0x609E5BF: bytes.fromhex("e84cbeffff"),        # call 0x609a410
        0x609E644: bytes.fromhex("488b9080000000"),    # mov 0x80(%rax) slot 16
        0x609E64B: bytes.fromhex("483b1566e84400"),    # cmp GOT 0x64eceb8
        0x609E666: bytes.fromhex("ff5070"),            # call *0x70 Name
        0x609E68A: bytes.fromhex("ff9090000000"),      # call *0x90 NickName
        0x609E7C0: bytes.fromhex("488d0d00ee39fa"),    # lea 0x43d5c7 ';'
        0x609E7C7: bytes.fromhex("e8c4253500"),        # call _M_replace
        0x609E80F: bytes.fromhex("e8fc9cffff"),        # call 0x6098510
        0x609E896: bytes.fromhex("e8f5280200"),        # call 0x60c1190
        0x609E939: bytes.fromhex("e8d277c9ff"),        # call 0x5d36110
        0x609EB36: bytes.fromhex("ba07690fc7"),        # mov $0xc70f6907 hash seed
        0x609EC00: bytes.fromhex("bf50000000"),        # mov $0x50 new node
        0x609ECC5: bytes.fromhex("e826223500"),        # call _M_need_rehash
        0x609E976: bytes.fromhex("48b80100000001000000"),  # movabs $0x100000001
        0x609E999: bytes.fromhex("8b4508"),            # plain use_count dec
        0x609EF91: bytes.fromhex("e8da60c9ff"),        # call 0x5d35070
        0x609EF3F: bytes.fromhex("f00fc101"),          # lock xadd -1
        0x609E9F6: bytes.fromhex("e895233500"),        # call 0x5d5b300 clear
        0x609EA72: bytes.fromhex("e899b9ffff"),        # call 0x609a410 null path
        0x609E0A9: bytes.fromhex("e832a5ffff"),        # call 0x60985e0 in slot 12
        0x6098566: bytes.fromhex("e8c5f0ffff"),        # call 0x6097630 pre-step
        0x5D3507B: bytes.fromhex("ff5010"),            # call *0x10 dispose
        0x5D350A7: bytes.fromhex("488b4018"),          # mov 0x18 destroy slot
    }
    all_spots = True
    for va, want in spots.items():
        got = read_bytes(va, len(want))
        if got != want:
            all_spots = False
            print(f"  spot mismatch at {va:#x}: got {got.hex()} want {want.hex()}")
    check(f"raw-binary spot bytes ({len(spots)} sites)", all_spots)

    # 6. Literals from .rodata.
    check("literal ';' at 0x43d5c7", data[0x43D5C7:0x43D5C8] == b";")
    check("literal 0x4376fd starts with NUL + rust path",
          data[0x4376FD:0x4376FE] == b"\x00"
          and data[0x4376FE:0x4376FE + 68] == b"/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs")
    check("literal '={};' at 0x44b52b", data[0x44B52B:0x44B52F] == b"={};")
    check("literal '=' at 0x445245", data[0x445245:0x445246] == b"=")
    check("literal '; ' at 0x4409b0", data[0x4409B0:0x4409B2] == b"; ")

    # 7. Caller census reproduction (E8 rel32 scan).
    check("callers of 0x609e510 (21)", scan_callers(data, 0x609E510) == HOST_CALLERS)
    check("callers of 0x609a410 (3)",
          scan_callers(data, 0x609A410) == [0x609B190, 0x609E5BF, 0x609EA72])
    check("callers of 0x6098510 (5)",
          scan_callers(data, 0x6098510) ==
          [0x609D5EA, 0x609E80F, 0x60B96CD, 0x60B977F, 0x60D4187])
    check("callers of 0x60985e0 (1)", scan_callers(data, 0x60985E0) == [0x609E0A9])
    check("callers of 0x60c1190 (6)",
          scan_callers(data, 0x60C1190) ==
          [0x6099FC5, 0x609A499, 0x609E896, 0x60C1C2E, 0x60C3D69, 0x60C4769])
    check("base predicate 0x5d2e770 has no direct callers",
          scan_callers(data, 0x5D2E770) == [])
    check("release helper 0x5d35070 count (654)",
          len(scan_callers(data, 0x5D35070)) == 654)
    check("map dtor 0x5d36110 count (484)",
          len(scan_callers(data, 0x5D36110)) == 484)
    check("bss-string lea sites (10)", scan_lea(data, 0x6508980) == BSS_LEA)

    # 7b. Relocations: GOT guard + base-predicate reloc count + vtables.
    relocs = subprocess.check_output(
        ["readelf", "-rW", str(BIN)], text=True).replace("artifacts/node/115/hl-node", "work/hl-node-115.bin")
    rel_map = {}
    for m in re.finditer(r"^([0-9a-f]{16})\s+[0-9a-f]{16}\s+R_X86_64_RELATIVE\s+([0-9a-f]+)",
                         relocs, re.M):
        rel_map[int(m.group(1), 16)] = int(m.group(2), 16)
    check("GOT 0x64eceb8 -> base predicate 0x5d2e770",
          rel_map.get(0x64ECEB8) == 0x5D2E770)
    check("GOT 0x64ed290 -> __libc_single_threaded",
          "00000000064ed290" in relocs and "__libc_single_threaded" in relocs)
    check("base predicate reloc entries (44)",
          sum(1 for v in rel_map.values() if v == 0x5D2E770) == 44)
    check("both Configurable vtables carry 0x5d2e770 at slot 16",
          rel_map.get(0x64D39B8 + 0x80) == 0x5D2E770
          and rel_map.get(0x64CDAD0 + 0x80) == 0x5D2E770)
    check("both Configurable vtables carry GetId at slot 15",
          rel_map.get(0x64D39B8 + 0x78) == 0x5D32A30
          and rel_map.get(0x64CDAD0 + 0x78) == 0x5D32A30)

    # 8. Records are semantic-only.
    raw = (HERE / "records.json").read_text()
    check("records.json semantic-only",
          '"mnemonic"' not in raw and '"instructions"' not in raw
          and '"opcodes"' not in raw)
    records = json.loads(raw)
    check("records.json binds the artifact digest",
          records["artifact_sha256"] == EXPECTED_SHA256)
    check("records.json host caller count is 21",
          len(records["functions"]["0x609e510"]["callers"]) == 21)

    # 9. Model tests pass.
    res = subprocess.run(
        [sys.executable, "tests/test_options_map_host_e510_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    check("model tests pass", res.returncode == 0, res.stdout.replace("artifacts/node/115/hl-node", "work/hl-node-115.bin") + res.stderr)

    failed = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
