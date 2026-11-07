#!/usr/bin/env python3
"""Verify the RE-001-cfoptions-maps-115 packet.

Run from the repository root: python3 research/work-items/
RE-001-cfoptions-maps-115/verify.py

Checks, in order:
 1. The artifact digest against provenance/artifacts.json.
 2. MANIFEST.sha256 hashes of every packet file.
 3. Byte-for-byte regeneration of every excerpt (export_excerpts.py).
 4. Byte-for-byte reproduction of blocks.tsv / ranges.tsv /
    helpers.tsv / atexit.tsv / specials.tsv / sections.tsv
    (census.py) and records.json / entries.tsv (gen_records.py).
 5. Three seeded random gate spots, byte-for-byte against a fresh
    objdump run AND the raw binary bytes.
 6. The FDE ranges in frames.txt against readelf.
 7. Every cited instruction against a fresh objdump run.
 8. The model constants (tools/cfoptions_maps_115.py) against
    records.json.
 9. The model tests (tests/test_cfoptions_maps_115.py).

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
sys.path.insert(0, str(ROOT))

import census  # noqa: E402
import export_excerpts  # noqa: E402
import gen_records  # noqa: E402
from tools import cfoptions_maps_115 as model  # noqa: E402

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# (address, expected instruction text) for the cited instructions.
CITED = [
    # The vector helpers hardcode type 20 at value+0xa8.
    ("0x6083606", "movl   $0x14,0xa8(%rdi)"),
    # The enum helper hardcodes type 18, verification 0 (movq $0x12).
    ("0x6083d39", "movq   $0x12,0xa8(%rax)"),
    # The type-19 nested builder hardcodes type 19 at value+0xa8.
    ("0x5e32d2c", "movl   $0x13,0xa8(%rdi)"),
    # The type-22 builder hardcodes type 22 into its stack temporary
    # (temp at rsp+0x20, so +0xa8 is rsp+0xc8).
    ("0x6083b4a", "movl   $0x16,0xc8(%rsp)"),
    # The factory helper stores the offset at value+0x00.
    ("0x607ea36", "mov    %esi,(%rdi)"),
    # The verification-4 ignore gate (per-entry apply 0x60bedc0).
    ("0x60bedeb", "cmpl   $0x4,0xac(%rsi)"),
    ("0x60bedf2", "je     60bf000"),
    # The five map range-ctor calls in the initializer.
    ("0x608a584", "call   5d405b0"),
    ("0x608aa76", "call   5d405b0"),
    ("0x608b23d", "call   5d405b0"),
    ("0x608ec56", "call   5d405b0"),
    ("0x6090e68", "call   5d405b0"),
    # Block 0 (window_bits) pair-ctor call.
    ("0x6089d55", "call   5d400f0"),
    # The .init_array[93] thunk jumps to the initializer.
    ("0x6093034", "jmp    6089b50"),
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
    want = addr if isinstance(addr, int) else int(addr, 16)
    for line in text.splitlines():
        m = INSN.match(line)
        if m and int(m.group(1), 16) == want:
            return m
    return None


def text_file_offset():
    """File offset of .text = vaddr - this delta (from readelf -S)."""
    out = subprocess.run(["readelf", "-S", str(BIN)],
                         capture_output=True, text=True,
                         check=True).stdout
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)",
                  out)
    return int(m.group(1), 16) - int(m.group(2), 16)


def main():
    print("== 1. artifact digest ==")
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entry = next((f for f in prov["files"]
                  if f["path"] == "artifacts/node/115/hl-node"), None)
    check(entry is not None, "provenance has artifacts/node/115/hl-node")
    digest = entry["sha256"] if entry else ""
    check(digest == ARTIFACT_SHA256, "provenance digest matches packet")
    check(sha256(BIN) == ARTIFACT_SHA256, "binary file matches digest")

    print("== 2. MANIFEST.sha256 ==")
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    ok = True
    seen = set()
    for line in manifest:
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        path = HERE / name
        seen.add(name)
        if not path.exists() or sha256(path) != digest:
            ok = False
            print(f"  mismatch: {name}")
    check(ok, "every manifest hash matches")
    packet_files = {p.name for p in HERE.iterdir()
                    if p.is_file() and p.name != "MANIFEST.sha256"}
    check(seen == packet_files,
          f"manifest lists every packet file ({len(seen)} files)")

    print("== 3. excerpt regeneration ==")
    before = {p.name: p.read_bytes()
              for p in HERE.glob("*.objdump.txt")}
    export_excerpts.main()
    after = {p.name: p.read_bytes()
             for p in HERE.glob("*.objdump.txt")}
    check(before == after, "all excerpts regenerate byte-for-byte")
    check(len(after) == len(export_excerpts.EXCERPTS),
          f"{len(after)} excerpts present")

    print("== 4. census / records reproduction ==")
    tsvs = ["blocks.tsv", "ranges.tsv", "helpers.tsv", "atexit.tsv",
            "specials.tsv", "sections.tsv"]
    before = {n: (HERE / n).read_bytes() for n in tsvs}
    census.main()
    after = {n: (HERE / n).read_bytes() for n in tsvs}
    check(before == after, "census TSVs reproduce byte-for-byte")
    before = {(HERE / "records.json").read_bytes(),
              (HERE / "entries.tsv").read_bytes()}
    gen_records.main()
    after = {(HERE / "records.json").read_bytes(),
             (HERE / "entries.tsv").read_bytes()}
    check(before == after, "records.json / entries.tsv reproduce")

    print("== 5. three seeded random gate spots ==")
    data = BIN.read_bytes()
    delta = text_file_offset()
    dump = (HERE / "static-initializer-6089b50.objdump.txt").read_text()
    addrs = []
    for line in dump.splitlines():
        m = INSN.match(line)
        if m:
            addrs.append(int(m.group(1), 16))
    rng = random.Random(115)
    spots = rng.sample(addrs, 3)
    for addr in spots:
        # A stop of addr+1 would truncate the instruction; decode a
        # full window so the instruction at addr is complete.
        fresh = objdump(f"{addr:#x}", f"{addr + 16:#x}")
        m = insn_at(fresh, addr)
        check(m is not None, f"gate spot {addr:#x} in fresh objdump")
        if m is None:
            continue
        raw_hex = m.group(2).replace(" ", "")
        file_off = addr - delta
        raw = data[file_off:file_off + len(raw_hex) // 2]
        check(raw.hex() == raw_hex,
              f"gate spot {addr:#x} matches raw binary bytes")
        # And the committed excerpt agrees with the fresh objdump line.
        committed = insn_at(dump, addr)
        check(committed is not None
              and committed.group(3) == m.group(3),
              f"gate spot {addr:#x} matches committed excerpt")

    print("== 6. FDE ranges ==")
    frames = (HERE / "frames.txt").read_text()
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    fdes = {(int(a, 16), int(b, 16)) for a, b in re.findall(
        r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out)}
    ok = True
    for a, b in re.findall(r"FDE pc=0x([0-9a-f]+)\.\.0x([0-9a-f]+)",
                           frames):
        if (int(a, 16), int(b, 16)) not in fdes:
            ok = False
            print(f"  not an FDE: 0x{a}..0x{b}")
    check(ok, "every frames.txt range is a real FDE")

    print("== 7. cited instructions ==")
    for addr, text in CITED:
        start = int(addr, 16)
        fresh = objdump(f"{start:#x}", f"{start + 16:#x}")
        m = insn_at(fresh, addr)
        check(m is not None and text in m.group(3),
              f"{addr}: {text}")

    print("== 8. model constants vs records.json ==")
    records = json.loads((HERE / "records.json").read_text())
    ok = True
    for e in records["entries"]:
        entry = model.ENTRIES.get((e["map"], e["name"]))
        if entry is None:
            ok = False
            print(f"  missing in model: {e['map']}/{e['name']}")
            continue
        for key in ("offset", "type", "verification", "flags"):
            if entry[key] != e[key]:
                ok = False
                print(f"  mismatch {e['map']}/{e['name']}.{key}: "
                      f"model {entry[key]} != records {e[key]}")
    check(ok, "model ENTRIES match records.json")
    check(model.MAPS == {m["name"]: m["global"]
                         for m in records["maps"]},
          "model MAPS match records.json")

    print("== 9. model tests ==")
    r = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_cfoptions_maps_115.py", "-q"],
        cwd=ROOT, capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
    check(r.returncode == 0, "model tests pass")

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for f in failures:
            print(f" - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
