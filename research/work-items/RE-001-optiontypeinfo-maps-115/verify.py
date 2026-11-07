#!/usr/bin/env python3
"""Verify the RE-001-optiontypeinfo-maps-115 packet.

Run from the repository root: python3 research/work-items/
RE-001-optiontypeinfo-maps-115/verify.py

Checks, in order:
 1. The artifact digest against provenance/artifacts.json.
 2. MANIFEST.sha256 hashes of every packet file.
 3. Byte-for-byte regeneration of every excerpt (export_excerpts.py).
 4. Byte-for-byte reproduction of blocks.tsv / ranges.tsv /
    midhelpers.tsv / atexit.tsv (census.py), enum_maps.tsv /
    special_pairs.tsv (special_pairs.py), consumers.tsv
    (census_consumers.py), and records.json (gen_records.py).
 5. Three seeded random gate spots, byte-for-byte against a fresh
    objdump run AND the raw binary bytes.
 6. The FDE ranges in frames.txt against readelf.
 7. Every cited instruction against a fresh objdump run.
 8. The model constants (tools/optiontypeinfo_maps_115.py) against
    records.json.
 9. The model tests (tests/test_optiontypeinfo_maps_115.py).

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

import census  # noqa: E402
import census_consumers  # noqa: E402
import export_excerpts  # noqa: E402
import gen_records  # noqa: E402
import optiontypeinfo_maps_115 as model  # noqa: E402
import special_pairs  # noqa: E402

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
TEXT_BASE = 0x1000  # .text file offset = vaddr - 0x1000

# (address, expected instruction text) for the cited instructions.
CITED = [
    # The verification-4 ignore gate (per-entry apply 0x60bedc0).
    ("0x60bedeb", "cmpl   $0x4,0xac(%rsi)"),
    ("0x60bedf2", "je     60bf000"),
    # The field-address computation (options_base + record->offset).
    ("0x60beeda", "movslq 0x0(%rbp),%rax"),
    ("0x60beee6", "add    %r13,%rax"),
    # The parse std::function invocation.
    ("0x60bef16", "call   *0x20(%rbp)"),
    # The type jump tables (parse 0x9786b4, serialize 0x978650).
    ("0x60bf03c", "mov    0xa8(%rbp),%eax"),
    ("0x60bf047", "# 9786b4"),
    ("0x60ba630", "# 978650"),
    # The mid helper hardcodes typeverif 0x12 (type 18, verif 0).
    ("0x60a6579", "movq   $0x12,0xa8(%rax)"),
    # wal_filter's value temp: offset 0x188.
    ("0x60ac4ed", "movl   $0x188,-0x4550(%rbp)"),
    # The two OptionTypeInfo map range-ctor calls.
    ("0x60aba7e", "call   5d405b0"),
    ("0x60b096c", "call   5d405b0"),
    # The four enum-map range-ctor calls.
    ("0x60aa4c2", "call   60a76c0"),
    ("0x60aa5a2", "call   60a7c90"),
    ("0x60aa64b", "call   60a8260"),
    ("0x60aa737", "call   60a8830"),
    # The pair-ctor 4-byte copy quirk (pair-ctor 0x5d400f0).
    ("0x5d4014f", "mov    0x0(%rbp),%eax"),
    ("0x5d4015a", "mov    %eax,0x20(%rbx)"),
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
    for name, start, stop in export_excerpts.EXCERPTS:
        fresh = objdump(f"0x{start:x}", f"0x{stop:x}")
        check((HERE / name).read_text() == fresh, f"regenerate {name}")

    print("== 4. census reproduction ==")
    for tsv, fn in [
            ("blocks.tsv", census.main),
            ("ranges.tsv", census.main),
            ("midhelpers.tsv", census.main),
            ("atexit.tsv", census.main)]:
        before = (HERE / tsv).read_bytes()
        fn()
        check((HERE / tsv).read_bytes() == before, f"{tsv} reproduces")
    for tsv in ("enum_maps.tsv", "special_pairs.tsv"):
        before = (HERE / tsv).read_bytes()
        special_pairs.main()
        check((HERE / tsv).read_bytes() == before, f"{tsv} reproduces")
    before = (HERE / "consumers.tsv").read_bytes()
    census_consumers.main()
    check((HERE / "consumers.tsv").read_bytes() == before,
          "consumers.tsv reproduces")
    before = (HERE / "records.json").read_bytes()
    gen_records.main()
    check((HERE / "records.json").read_bytes() == before,
          "records.json reproduces")

    print("== 5. seeded random gate spots ==")
    data = BIN.read_bytes()
    lines = []
    for name, _s, _e in export_excerpts.EXCERPTS:
        for line in (HERE / name).read_text().splitlines():
            m = INSN.match(line)
            if m:
                lines.append((name, int(m.group(1), 16),
                              m.group(2).replace(" ", ""),
                              m.group(3).strip()))
    rng = random.Random(0x115)
    spots = rng.sample(lines, 3)
    for name, addr, hexbytes, text in spots:
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
    for name, start, stop in export_excerpts.EXCERPTS:
        check((start, stop) in fdes, f"FDE {name} 0x{start:x}..0x{stop:x}")
    listed_frames = {}
    for line in (HERE / "frames.txt").read_text().splitlines()[2:]:
        if not line.strip():
            continue
        s, e = line.split("\t")
        listed_frames[int(s, 16)] = e
    for name, start, stop in export_excerpts.EXCERPTS:
        check(listed_frames.get(start) == f"0x{stop:x}",
              f"frames.txt {name}")

    print("== 7. cited instructions ==")
    windows = {}
    for name, start, stop in export_excerpts.EXCERPTS:
        windows[name] = objdump(f"0x{start:x}", f"0x{stop:x}")
    all_text = "\n".join(windows.values())
    for addr, expected in CITED:
        m = insn_at(all_text, addr)
        ok = bool(m) and expected in m.group(3)
        check(ok, f"cited 0x{int(addr, 16):x}: {expected}")

    print("== 8. model vs records.json ==")
    rec = json.loads((HERE / "records.json").read_text())
    check(len(rec["entries"]) == 100, "100 entries in records")
    check(len(model.MUTABLE_ENTRIES) == 19, "19 mutable entries")
    check(len(model.DBOPTIONS_ENTRIES) == 81, "81 dboptions entries")
    mismatch = []
    for e in rec["entries"]:
        found = model.lookup(e["name"])
        if found is None:
            mismatch.append(e["name"])
            continue
        _map, entry = found
        if _map != e["map"] or entry[1] != int(e["offset"], 16) or \
                entry[2] != e["type"] or entry[3] != e["verification"] or \
                entry[4] != int(e["flags"], 16):
            mismatch.append(e["name"])
    check(not mismatch, f"model matches records ({mismatch[:3]})")
    check(model.ARTIFACT_SHA256 == ARTIFACT_SHA256, "model digest")
    real, ignored = model.offset_zero_entries()
    check(len(real) == 2 and len(ignored) == 13,
          "offset-0 split is 2 real / 13 ignored")
    check(len(rec["enum_maps"]) == 4, "4 enum maps")
    check(sum(len(m["pairs"]) for m in rec["enum_maps"]) == 16,
          "16 enum-name pairs")
    check(len(rec["consumers"]["map_reference_sites"]) == 24,
          "24 consumer reference sites")

    print("== 9. model tests ==")
    res = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_optiontypeinfo_maps_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True,
    )
    tail = res.stdout.strip().splitlines()[-1] if res.stdout.strip() \
        else "no output"
    check(res.returncode == 0,
          "pytest tests/test_optiontypeinfo_maps_115.py: " + tail)

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
