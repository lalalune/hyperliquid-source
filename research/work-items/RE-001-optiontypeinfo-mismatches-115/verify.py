#!/usr/bin/env python3
"""Verify the RE-001-optiontypeinfo-mismatches-115 packet.

Run from the repository root: python3 research/work-items/
RE-001-optiontypeinfo-mismatches-115/verify.py

Checks, in order:
 1. The artifact digest against provenance/artifacts.json.
 2. MANIFEST.sha256 hashes of every packet file.
 3. Byte-for-byte regeneration of every excerpt (export_excerpts.py).
 4. Byte-for-byte reproduction of entries.tsv (census.py) and
    census-21b.tsv (census_21b.py), and records.json (gen_records.py).
 5. Three seeded random gate spots, byte-for-byte against a fresh
    objdump run AND the raw binary bytes.
 6. The FDE ranges in frames.txt against readelf.
 7. Every cited ctor-pack / BuildDBOptions / default-ctor instruction
    against a fresh objdump run.
 8. The model constants (tools/optiontypeinfo_map_115.py) against
    records.json.
 9. The model tests (tests/test_optiontypeinfo_map_115.py).

Prints ALL CHECKS PASSED only when every check holds.
"""
import hashlib
import json
import random
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))

import export_excerpts  # noqa: E402
import optiontypeinfo_map_115 as model  # noqa: E402

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
TEXT_BASE = 0x1000  # .text file offset = vaddr - 0x1000

# (address, expected instruction text) for the cited instructions.
CITED = [
    # Ctor pack: the +0x158 word and +0x15c.
    ("0x60a3ff0", "mov    %eax,0x158(%rbx)"),
    ("0x60a3ffd", "mov    %al,0x15c(%rbx)"),
    # Ctor pack: the +0x190 word, +0x194, +0x196, +0x197 word.
    ("0x60a407e", "mov    %eax,0x190(%rbx)"),
    ("0x60a408b", "mov    %ax,0x194(%rbx)"),
    ("0x60a4099", "mov    %al,0x196(%rbx)"),
    ("0x60a40c3", "mov    %eax,0x197(%rbx)"),
    # Ctor pack: the EnvOptions bool cluster.
    ("0x60a3e5f", "mov    %eax,0x108(%rbx)"),
    ("0x60a3e73", "mov    %ax,0x10c(%rbx)"),
    ("0x60a3e88", "mov    %al,0x10e(%rbx)"),
    # BuildDBOptions: max_open_files from MutableDBOptions+0x40.
    ("0x60c2f0b", "mov    0x40(%r12),%eax"),
    ("0x60c2f10", "mov    %eax,0x44(%rbx)"),
    # Default ctor: the tail values.
    ("0x60b2fa6", "movl   $0x1010000,0x1d0(%rbx)"),
    ("0x60b2fd0", "movq   $0x0,0x210(%rbx)"),
    ("0x60b2fdb", "mov    %si,0x218(%rbx)"),
    ("0x60b2fe2", "movb   $0x0,0x21a(%rbx)"),
    ("0x60b2fe9", "movq   $0x0,0x220(%rbx)"),
    # The +0x21b struct-field sites (not DBOptions).
    ("0x5a89943", "movb   $0x1,0x21b(%rbx)"),
    ("0x5a899a2", "movb   $0x0,0x21b(%rbx)"),
    ("0x5a8a19d", "cmpb   $0x0,0x21b(%rbx)"),
]

INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")

failures = []


def check(ok, label):
    print(("  ok  " if ok else " FAIL ") + label)
    if not ok:
        failures.append(label)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def objdump(start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=" + start,
         "--stop-address=" + stop, "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    return out


def insn_at(text, addr):
    for line in text.splitlines():
        m = INSN.match(line)
        if m and int(m.group(1), 16) == int(addr, 16):
            return m
    return None


def main():
    print("== 1. artifact digest ==")
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entry = next((f for f in prov["files"]
                  if f["path"] == "artifacts/node/115/hl-node"), None)
    check(entry is not None, "provenance has artifacts/node/115/hl-node")
    digest = entry["sha256"] if entry else ""
    check(digest == ARTIFACT_SHA256, "provenance digest matches packet")
    check(sha256(BIN) == ARTIFACT_SHA256, "binary sha256 matches packet")

    print("== 2. manifest ==")
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    listed = {}
    for line in manifest:
        if not line.strip():
            continue
        h, name = line.split(None, 1)
        listed[name.strip()] = h
    for name, h in sorted(listed.items()):
        check(sha256(HERE / name) == h, f"manifest {name}")
    extra = {p.name for p in HERE.iterdir() if p.is_file()} - set(listed) \
        - {"MANIFEST.sha256"}
    check(not extra, f"no unlisted packet files ({sorted(extra)})")

    print("== 3. excerpt regeneration ==")
    for name, start, stop in export_excerpts.WINDOWS:
        fresh = objdump(start, stop)
        check((HERE / name).read_text() == fresh, f"regenerate {name}")

    print("== 4. census reproduction ==")
    import census as census_mod
    import census_21b
    import gen_records
    before = (HERE / "entries.tsv").read_bytes()
    census_mod.main()
    check((HERE / "entries.tsv").read_bytes() == before,
          "entries.tsv reproduces")
    before = (HERE / "census-21b.tsv").read_bytes()
    census_21b.main()
    check((HERE / "census-21b.tsv").read_bytes() == before,
          "census-21b.tsv reproduces")
    before = (HERE / "records.json").read_bytes()
    gen_records.main()
    check((HERE / "records.json").read_bytes() == before,
          "records.json reproduces")

    print("== 5. seeded random gate spots ==")
    data = BIN.read_bytes()
    lines = []
    for name, _s, _e in export_excerpts.WINDOWS:
        for line in (HERE / name).read_text().splitlines():
            m = INSN.match(line)
            if m:
                lines.append((name, int(m.group(1), 16),
                              m.group(2).replace(" ", ""),
                              m.group(3).strip()))
    rng = random.Random(0x115)
    spots = rng.sample(lines, 3)
    for name, addr, hexbytes, text in spots:
        # A +16 window so the instruction is fully inside the range;
        # a 1-byte window makes objdump truncate it to its first byte.
        fresh = objdump(hex(addr), hex(addr + 16))
        m = insn_at(fresh, hex(addr))
        ok = bool(m) and m.group(3).strip() == text
        check(ok, f"gate spot 0x{addr:x} ({name}) vs fresh objdump")
        off = addr - TEXT_BASE
        raw = data[off:off + len(bytes.fromhex(hexbytes))].hex()
        check(raw == hexbytes,
              f"gate spot 0x{addr:x} ({name}) vs raw binary")

    print("== 6. FDE ranges ==")
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    fdes = set()
    for m in re.finditer(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames):
        fdes.add((int(m.group(1), 16), int(m.group(2), 16)))
    for name, start, stop in export_excerpts.WINDOWS:
        check((int(start, 16), int(stop, 16)) in fdes,
              f"FDE {name} {start}..{stop}")

    print("== 7. cited instructions ==")
    windows = {}
    for name, start, stop in export_excerpts.WINDOWS:
        windows[name] = objdump(start, stop)
    all_text = "\n".join(windows.values())
    for addr, expected in CITED:
        m = insn_at(all_text, addr)
        ok = bool(m) and expected in m.group(3)
        check(ok, f"cited 0x{int(addr, 16):x}: {expected}")

    print("== 8. model vs records.json ==")
    rec = json.loads((HERE / "records.json").read_text())
    check(len(rec["map"]) == len(model.MAP) == 92, "92 map entries")
    mismatch = [
        e["name"] for e in rec["map"]
        if model.lookup(e["name"]) !=
        (int(e["offset"], 16), int(e["flags"], 16), e["group"])
    ]
    check(not mismatch, f"model map matches records ({mismatch[:3]})")
    for dst, srcs in model.CTOR_PACK.items():
        got = next((c for c in rec["ctor_pack"]
                    if int(c["dst"], 16) == dst), None)
        check(got is not None and
              [int(s, 16) for s in got["src"]] == list(srcs),
              f"ctor pack 0x{dst:x}")
    for name, off in model.BUILDDBOPTIONS_READS.items():
        got = next((b for b in rec["builddboptions"]
                    if b["name"] == name), None)
        check(got is not None and int(got["mutable"], 16) == off,
              f"builddboptions {name}")
    check(len(rec["padding_21b"]["sites"]) == 25, "25 +0x21b sites")
    check(rec["padding_21b"]["rsp_stack_slots"] == 20, "20 %rsp slots")
    check(rec["padding_21b"]["struct_field_uses"] == 5,
          "5 struct-field uses")

    print("== 9. model tests ==")
    res = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_optiontypeinfo_map_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    tail = res.stdout.strip().splitlines()[-1] if res.stdout.strip() \
        else "no output"
    check(res.returncode == 0,
          "pytest tests/test_optiontypeinfo_map_115.py: " + tail)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print("  - " + f)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
