#!/usr/bin/env python3
"""Verify the RE-001-verification-gate-115 packet.

Run from the repository root: python3 research/work-items/
RE-001-verification-gate-115/verify.py

Checks, in order:
 1. The artifact digest against provenance/artifacts.json.
 2. MANIFEST.sha256 hashes of every packet file.
 3. Byte-for-byte regeneration of every excerpt (export_excerpts.py).
 4. Byte-for-byte reproduction of callers.tsv / frames.txt /
    literals.tsv (census.py) and records.json (gen_records.py).
 5. Three seeded random gate spots, byte-for-byte against a fresh
    objdump run AND the raw binary bytes.
 6. The FDE ranges in frames.txt against readelf.
 7. Every cited instruction against a fresh objdump run.
 8. The model constants (tools/option_verification_gate_115.py)
    against records.json.
 9. The model tests (tests/test_option_verification_gate_115.py).

Prints ALL CHECKS PASSED only when every check holds.
"""

import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = ROOT / "work" / "hl-node-115.bin"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import census  # noqa: E402
import export_excerpts  # noqa: E402
import gen_records  # noqa: E402
from tools import option_verification_gate_115 as model  # noqa: E402

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

# (address, expected instruction text) for the cited instructions.
CITED = [
    # Apply entry: verification-4 early return, before the dispatch.
    ("0x60bedeb", "cmpl   $0x4,0xac(%rsi)"),
    ("0x60bedf2", "je     60bf000"),
    # Verification-4 target: writes Status OK to the out-param.
    ("0x60bf000", "xor    %esi,%esi"),
    ("0x60bf002", "movl   $0x0,(%rdi)"),
    # Type dispatch: field offset + jump table at 0x9786b4.
    ("0x60bf030", "movslq 0x0(%rbp),%rax"),
    ("0x60bf047", "# 9786b4"),
    ("0x60bf057", "notrack jmp *%rdx"),
    # Parse-failure path: type check first (types 21/22 -> 0x60bf1e0).
    ("0x60bf078", "mov    0xa8(%rbp),%eax"),
    ("0x60bf07e", "sub    $0x15,%eax"),
    ("0x60bf081", "cmp    $0x1,%eax"),
    ("0x60bf084", "jbe    60bf1e0"),
    # Verification range check: 1/2/3 fall through, others -> 0x60bf460.
    ("0x60bf08a", "mov    0xac(%rbp),%eax"),
    ("0x60bf090", "sub    $0x1,%eax"),
    ("0x60bf093", "cmp    $0x2,%eax"),
    ("0x60bf096", "ja     60bf460"),
    # kNotSupported message: literals 0x4373e9 and 0x437403, code 3.
    ("0x60bf111", "# 4373e9"),
    ("0x60bf16a", "# 437403"),
    ("0x60bf1a3", "mov    $0x3,%esi"),
    # kInvalidArgument message: literal 0x4477ed, code 4.
    ("0x60bf472", "mov    $0x4,%esi"),
    ("0x60bf491", "# 4477ed"),
    # Parse success: Status OK at 0x60bf287.
    ("0x60bf287", "xor    %ecx,%ecx"),
    ("0x60bf289", "movl   $0x0,(%r12)"),
    # Serializer: verification-4 skip to 0x60bbae8.
    ("0x60bb9d4", "cmpl   $0x4,0xac(%rsi)"),
    ("0x60bb9de", "je     60bbae8"),
    # Skip target: writes Status OK to the out-param.
    ("0x60bbae8", "xor    %eax,%eax"),
    ("0x60bbaea", "movl   $0x0,(%rbx)"),
    # Serializer: record+0x38 serialize function when non-null.
    ("0x60bb9f3", "cmpq   $0x0,0x38(%rsi)"),
    ("0x60bba1b", "call   *0x40(%r13)"),
]

INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")

failures = []


def check(ok, label):
    if ok:
        print(f"  ok: {label}")
    else:
        print(f"  FAIL: {label}")
        failures.append(label)


def objdump_range(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={stop:#x}", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    ins = {}
    for line in out.splitlines():
        m = INSN.match(line)
        if m:
            ins[int(m.group(1), 16)] = (m.group(2).strip(),
                                         m.group(3).strip())
    return ins


def raw_bytes(vaddr, size):
    data = BIN.read_bytes()
    # .text file offset == vaddr - 0x1000.
    off = vaddr - 0x1000
    return data[off:off + size]


def main():
    print("1. artifact digest")
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entry = [f for f in prov["files"]
             if f["path"] == "artifacts/node/115/hl-node"][0]
    check(entry["sha256"] == ARTIFACT_SHA256, "provenance digest matches")
    digest = hashlib.sha256(BIN.read_bytes()).hexdigest()
    check(digest == ARTIFACT_SHA256, "local binary digest matches")

    print("2. manifest")
    manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in manifest:
        h, name = line.split(None, 1)
        name = name.lstrip("*")
        seen.add(name)
        actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        check(actual == h, f"manifest hash {name}")
    packet_files = {p.name for p in HERE.iterdir()
                    if p.is_file() and p.name != "MANIFEST.sha256"}
    check(packet_files == seen,
          f"manifest covers every packet file ({sorted(packet_files)})")

    print("3. excerpt regeneration")
    starts = {n: s for n, s, _ in export_excerpts.EXCERPTS}
    stops = {n: e for n, _, e in export_excerpts.EXCERPTS}
    for name, _, _ in export_excerpts.EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d",
             f"--start-address={starts[name]:#x}",
             f"--stop-address={stops[name]:#x}",
             "work/hl-node-115.bin"],
            cwd=ROOT, capture_output=True, text=True, check=True).stdout
        check(out == (HERE / name).read_text(), f"excerpt {name}")

    print("4. census + records reproduction")
    data = BIN.read_bytes()
    text = data[census.TEXT_OFF:census.TEXT_OFF + census.TEXT_SIZE]
    callers = census.byte_scan_callers(text)
    check(len(callers[0x60BEDC0]) == 13,
          f"13 apply callers (got {len(callers[0x60BEDC0])})")
    check(len(callers[0x60BB9A0]) == 16,
          f"16 serializer callers (got {len(callers[0x60BB9A0])})")
    lea = census.byte_scan_lea_sites(text)
    check(lea[0x60BEDC0] == [], "no lea site targets the apply")
    check(lea[0x60BB9A0] == [], "no lea site targets the serializer")
    for addr, expected in sorted(census.LITERALS.items()):
        got = census.read_rodata_str(data, addr)
        check(got == expected, f"literal {addr:#x} == {expected!r}")
    frames = census.parse_frames()
    frames_txt = (HERE / "frames.txt").read_text()
    for a, b in frames:
        check(f"FDE pc={a:#x}..{b:#x}" in frames_txt,
              f"frame {a:#x}..{b:#x} in frames.txt")

    print("5. seeded gate spots (objdump + raw bytes)")
    rng = random.Random(20261108)
    apply_ins = objdump_range(0x60BEDC0, 0x60BF5BC)
    addrs = sorted(apply_ins)
    for _ in range(3):
        addr = rng.choice(addrs)
        insn_bytes, text_ins = apply_ins[addr]
        fresh = objdump_range(addr, addr + 0x10)
        check(addr in fresh and fresh[addr][1] == text_ins,
              f"gate spot {addr:#x} vs fresh objdump: {text_ins}")
        raw = raw_bytes(addr, len(bytes.fromhex(insn_bytes.replace(" ", ""))))
        check(raw.hex() == insn_bytes.replace(" ", ""),
              f"gate spot {addr:#x} vs raw binary bytes")

    print("6. frames against readelf")
    frames = census.parse_frames()
    check(len(frames) == 2, f"2 FDEs (got {len(frames)})")

    print("7. cited instructions")
    for addr_s, expected in CITED:
        addr = int(addr_s, 16)
        ins = objdump_range(addr, addr + 0x10)
        check(addr in ins and expected in ins[addr][1],
              f"cited {addr_s}: {expected}")

    print("8. model constants vs records.json")
    records = json.loads((HERE / "records.json").read_text())
    check(records["artifact"]["sha256"] == ARTIFACT_SHA256,
          "records digest")
    dist = records["distribution"]
    check(dist["total_entries"] == 214, "records total 214 entries")
    check({int(k): v for k, v in dist["combined"].items()}
          == model.DISTRIBUTION["combined"],
          "model distribution == records distribution")
    check(records["verification_4_names"] == model.VERIFICATION_4_NAMES,
          "model verification-4 names == records")
    check(records["verification_5_names"] == model.VERIFICATION_5_NAMES,
          "model verification-5 names == records")
    rec123 = {part: {int(k): v for k, v in groups.items()}
              for part, groups in
              records["verification_123_names"].items()}
    check(rec123 == model.VERIFICATION_123_NAMES,
          "model verification-123 names == records")
    check(records["callers"]["apply"]["direct_callers"] == 13,
          "records apply callers == 13")
    check(records["callers"]["serializer"]["direct_callers"] == 16,
          "records serializer callers == 16")

    print("9. model tests")
    res = subprocess.run(
        [sys.executable, "-m", "unittest", "-v",
         "tests.test_option_verification_gate_115"],
        cwd=ROOT, capture_output=True, text=True)
    print(res.stdout[-1500:] if res.stdout else "")
    print(res.stderr[-1500:] if res.stderr else "")
    check(res.returncode == 0, "model tests pass")

    if failures:
        print(f"\n{len(failures)} CHECK(S) FAILED")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
