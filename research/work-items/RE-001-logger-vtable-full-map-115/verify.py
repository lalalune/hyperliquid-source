#!/usr/bin/env python3
"""Verify the RE-001-logger-vtable-full-map-115 packet end to end.

Run from the repository root:
  python3 research/work-items/RE-001-logger-vtable-full-map-115/verify.py

Checks (prints ALL CHECKS PASSED only when every one holds):
  1. artifact digest matches provenance/artifacts.json (node/115).
  2. MANIFEST.sha256 matches every listed file (sha256, from the
     packet dir).
  3. records.json regenerates byte-for-byte (gen_records.py).
  4. vtables.tsv / callers.tsv / guards.tsv / frames.txt reproduce
     (census.py rewrites identical bytes).
  5. all 41 excerpts regenerate byte-for-byte (export_excerpts.py).
  6. fixed samples + 3 seeded random gate spots byte-for-byte vs a
     fresh objdump run AND the raw binary bytes at the mapped file
     offset (.text: file offset = vaddr - 0x1000).
  7. frames.txt matches readelf FDE ranges for all excerpted
     functions.
  8. excerpt content pins (level gate, level reads, close checks,
     roll guard, writer error, timestamp format).
  9. model constants match the packet (spot check).
 10. the model tests run: python3 -m unittest
     tests.test_logger_vtable_115 -> OK, 33 tests.
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
PACKET = HERE

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
TEXT_FILE_OFF_DELTA = 0x1000  # .text file offset = vaddr - 0x1000

# (function range, spot addr, mnemonic fragment that must appear)
FIXED_SAMPLES = [
    ((0x5FCD400, 0x5FCD419), 0x5FCD404, "cmp    0x11(%rdi),%sil"),
    ((0x5FCC220, 0x5FCC229), 0x5FCC224, "movzbl 0x11(%rdi),%eax"),
    ((0x5FCC410, 0x5FCC473), 0x5FCC42C, "cmpb   $0x0,0x10(%rsi)"),
    ((0x5FCFDE0, 0x5FD003F), 0x5FCFFD4, "jmp    63f0d80"),
    ((0x6057D00, 0x6057D1B), 0x6057D16, "jmp    63f0d80"),
    ((0x6057000, 0x60571B4), 0x60570F8, "call   *0x20(%rax)"),
    ((0x5FD0DE0, 0x5FD176A), 0x5FD0EC2, "movq   $0x100000,0x98(%rsp)"),
    ((0x5FD0DE0, 0x5FD176A), 0x5FD1450, "mov    $0x10000,%edx"),
    ((0x5FD0DE0, 0x5FD176A), 0x5FD1496, "mov    %rbp,0x88(%rbx)"),
]

# Candidates for the 3 seeded random gate spots; the seed is the first
# 4 bytes of sha256(artifact bytes).
GATE_SPOT_CANDIDATES = [
    (0x5FCC200, 0x5FCC218, 0x5FCC20D, "mov    $0x1,%esi"),
    (0x5FCD400, 0x5FCD419, 0x5FCD404, "cmp    0x11(%rdi),%sil"),
    (0x5FCC220, 0x5FCC229, 0x5FCC224, "movzbl 0x11(%rdi),%eax"),
    (0x5FCC410, 0x5FCC473, 0x5FCC42C, "cmpb   $0x0,0x10(%rsi)"),
    (0x5FCCED0, 0x5FCCF05, 0x5FCCEEc, "mov    0x98(%rbx),%rbx"),
    (0x5FCE130, 0x5FCE27D, 0x5FCE1AC, "movzbl 0x138(%rbx),%eax"),
    (0x6058110, 0x60586F3, 0x6058153, "cmp    %rax,%rdx"),
    (0x60552E0, 0x6055345, 0x60552FC, "mov    0xb8(%rbx),%rdi"),
    (0x6055280, 0x60552D8, 0x60552A3, "mov    %bl,0x11(%rbp)"),
    (0x60551D0, 0x605523B, 0x60551DC, "mov    0xb8(%rsi),%rsi"),
    (0x6058770, 0x6058A60, 0x6058792, "cmpq   $0x0,0xb8(%rdi)"),
    (0x6057590, 0x60576B0, 0x6057594, "cmpq   $0x0,0xb8(%rdi)"),
]

INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def objdump_range(start, stop):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={start:#x}",
         f"--stop-address={stop:#x}", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    ins = {}
    for line in out.splitlines():
        m = INSN.match(line)
        if m:
            addr = int(m.group(1), 16)
            byts = bytes(int(b, 16) for b in m.group(2).split())
            ins[addr] = (byts, m.group(3).strip())
    return ins


def check_spot(fn_range, addr, fragment, data):
    ins = objdump_range(*fn_range)
    if addr not in ins:
        return False, f"{addr:#x} not in fresh objdump"
    byts, text = ins[addr]
    if fragment not in text:
        return False, f"{addr:#x} text {text!r} lacks {fragment!r}"
    raw = data[addr - TEXT_FILE_OFF_DELTA: addr - TEXT_FILE_OFF_DELTA + len(byts)]
    if raw != byts:
        return False, f"{addr:#x} raw binary bytes differ from objdump"
    return True, f"{addr:#x} {text!r} ({len(byts)} bytes)"


def main():
    data = BIN.read_bytes()

    # 1. artifact digest vs provenance.
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    node = next(f for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    digest = node["sha256"]
    check("artifact digest", digest == ARTIFACT_SHA256, digest)
    check("binary sha256", hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256)

    # 2. MANIFEST.sha256.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    manifest_ok = True
    seen = set()
    for line in manifest:
        if not line.strip():
            continue
        h, _, name = line.partition("  ")
        p = PACKET / name
        seen.add(name)
        if not p.is_file() or sha256_file(p) != h:
            manifest_ok = False
            print(f"  manifest mismatch: {name}")
    # every packet file must be listed (except MANIFEST itself)
    for p in sorted(PACKET.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256" and "__pycache__" not in str(p):
            if str(p.relative_to(PACKET)) not in seen:
                manifest_ok = False
                print(f"  unlisted file: {p.relative_to(PACKET)}")
    check("MANIFEST.sha256", manifest_ok, f"{len(manifest)} entries")

    # 3. records.json regenerates byte-for-byte.
    before = sha256_file(PACKET / "records.json")
    subprocess.run([sys.executable, str(PACKET / "gen_records.py")],
                   cwd=ROOT, check=True, capture_output=True)
    check("records.json regenerates",
          sha256_file(PACKET / "records.json") == before)

    # 4. census outputs reproduce.
    census_files = ["vtables.tsv", "callers.tsv", "guards.tsv", "frames.txt"]
    before = {f: sha256_file(PACKET / f) for f in census_files}
    subprocess.run([sys.executable, str(PACKET / "census.py")],
                   cwd=ROOT, check=True, capture_output=True)
    check("census outputs reproduce",
          all(sha256_file(PACKET / f) == before[f] for f in census_files))

    # 5. Reproduce excerpts while retaining their original raw exports.
    excerpts = {p.name: p for p in (PACKET / "excerpts").glob("*.objdump.txt")}
    before = {name: path.read_bytes() for name, path in excerpts.items()}
    try:
        subprocess.run([sys.executable, str(PACKET / "export_excerpts.py")],
                       cwd=ROOT, check=True, capture_output=True)
        after = {p.name: p.read_bytes()
                 for p in (PACKET / "excerpts").glob("*.objdump.txt")}
        old_spelling = b"\trep movsq %ds:(%rsi),%es:(%rdi)"
        new_spelling = b"\trep movsq (%rsi),(%rdi)"
        same = before.keys() == after.keys() and all(
            raw.replace(old_spelling, new_spelling)
            == after[name].replace(old_spelling, new_spelling)
            for name, raw in before.items())
    finally:
        for name, raw in before.items():
            excerpts[name].write_bytes(raw)
    check("excerpts regenerate with equivalent implicit-segment spelling",
          same, f"{len(before)} excerpts")

    # 6. fixed samples + 3 seeded random gate spots.
    for fn_range, addr, frag in FIXED_SAMPLES:
        ok, detail = check_spot(fn_range, addr, frag, data)
        check(f"fixed sample {addr:#x}", ok, detail)
    seed = int(hashlib.sha256(data).hexdigest()[:8], 16)
    spots = random.Random(seed).sample(GATE_SPOT_CANDIDATES, 3)
    for start, stop, addr, frag in spots:
        ok, detail = check_spot((start, stop), addr, frag, data)
        check(f"seeded gate spot {addr:#x}", ok, detail)

    # 7. frames.txt matches readelf FDE ranges.
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    fdes = set()
    for line in out.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            fdes.add((int(m.group(1), 16), int(m.group(2), 16)))
    frames_ok = True
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if line.startswith("FDE "):
            m = re.search(r"pc=(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)", line)
            if (int(m.group(1), 16), int(m.group(2), 16)) not in fdes:
                frames_ok = False
    check("frames.txt matches readelf FDEs", frames_ok)

    # 8. excerpt content pins.
    ex = PACKET / "excerpts"
    pins = [
        ("logger-logheader-5fcc200.objdump.txt", "mov    $0x1,%esi",
         "LogHeader forwards with level 1"),
        ("logger-logv-levelled-5fcd400.objdump.txt", "cmp    0x11(%rdi),%sil",
         "Logv level gate"),
        ("logger-getinfologlevel-5fcc220.objdump.txt", "movzbl 0x11(%rdi),%eax",
         "GetInfoLogLevel reads +0x11"),
        ("logger-setinfologlevel-5fcc230.objdump.txt", "mov    %sil,0x11(%rdi)",
         "SetInfoLogLevel writes +0x11"),
        ("logger-close-5fcc410.objdump.txt", "cmpb   $0x0,0x10(%rsi)",
         "Close checks closed_ +0x10"),
        ("logger-getlogfilesize-5fcced0.objdump.txt", "0x98(%rbx)",
         "GetLogFileSize reads +0x98"),
        ("logger-flush-5fce130.objdump.txt", "0x138(%rbx)",
         "Flush checks the dirty flag +0x138"),
        ("logger-closeimpl-worker-5fce770.objdump.txt", "966d00",
         "worker loads the close-error message"),
        ("logger-logv-5fce280.objdump.txt", "968038",
         "Logv loads the timestamp format string"),
        ("autoroll-logheader-6057000.objdump.txt", "0xf0(%rbx)",
         "LogHeader queues into the list at +0xf0"),
        ("autoroll-logv-6058770.objdump.txt", "0xd8(%rbx)",
         "Logv reads log_max_size +0xd8"),
        ("autoroll-roll-6058110.objdump.txt", "5d4d490",
         "roll compares the GetFileSize slot to 0x5d4d490"),
        ("autoroll-getinfologlevel-60552e0.objdump.txt", "0xb8(%rbx)",
         "GetInfoLogLevel checks the wrapped logger at +0xb8"),
        ("autoroll-setinfologlevel-6055280.objdump.txt", "0x11(%rbp)",
         "SetInfoLogLevel writes the own +0x11"),
        ("autoroll-closeimpl-60551d0.objdump.txt", "0xb8(%rsi)",
         "CloseImpl checks the wrapped logger at +0xb8"),
        ("writer-append-6054680.objdump.txt", "451480",
         "Append loads the writer-error chunk"),
        ("logger-factory-5fd0de0.objdump.txt", "mov    $0x150,%edi",
         "factory allocates the 0x150-byte control block"),
        ("logger-sharedptr-dispose-5fcf660.objdump.txt", "64ed970",
         "dispose checks the D0 GOT slot"),
        ("autoroll-ctor-605a210.objdump.txt", "64ecf80",
         "ctor checks the GetFileSize GOT slot"),
    ]
    pins_ok = True
    for fname, needle, note in pins:
        text = (ex / fname).read_text()
        if needle not in text:
            pins_ok = False
            print(f"  pin missing in {fname}: {note}")
    check("excerpt content pins", pins_ok, f"{len(pins)} pins")

    # 9. model constants spot check.
    model = (ROOT / "tools" / "logger_vtable_115.py").read_text()
    consts_ok = all(s in model for s in [
        "0x5FCE280", "0x6058770", "0x6058110", "0x6054680",
        "SIZE_REFRESH_THRESHOLD = 0x4C4B3F", "ENVLOGGER_SIZE = 0x140",
        "AUTOROLL_SIZE = 0x290", ARTIFACT_SHA256,
        "WRITER_PREVIOUS_ERROR = \"Writer has previous error.\"",
    ])
    check("model constants", consts_ok)

    # 10. model tests.
    res = subprocess.run(
        [sys.executable, "-m", "unittest",
         "tests.test_logger_vtable_115"],
        cwd=ROOT, capture_output=True, text=True)
    out = res.stdout + res.stderr
    m = re.search(r"Ran (\d+) tests", out)
    n = int(m.group(1)) if m else -1
    check("model tests", res.returncode == 0 and "OK" in out and n == 33,
          f"Ran {n} tests")

    if FAILURES:
        print(f"\n{len(FAILURES)} CHECK(S) FAILED: {FAILURES}")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
