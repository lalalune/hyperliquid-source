"""Standalone verifier for RE-001-hash-merge-accs-61c27f0-115.

Usage (from a worktree whose work/hl-node-115.bin is the
materialized node binary, or from the cleanroom verifier):

    python3 research/work-items/RE-001-hash-merge-accs-61c27f0-115/verify.py

What is checked (each failure prints FAIL <label>):
  * The sha256 of artifacts/node/115/hl-node and
    work/hl-node-115.bin both equal the pinned node #115
    digest (the git-lfs pointer is expanded before hashing,
    so this passes on a fresh clone without manual smudge).
  * main.txt matches a fresh objdump of the routine window
    (0x61c27f0..0x61c2888) byte-for-byte.
  * Spot bytes at key instructions of the body (entry push,
    the four pair multiplications, the start-value addition,
    the avalanche movabs and the closing ret) decoded from the
    ELF bytes.
  * frames.txt FDE ranges all appear in a fresh
    readelf --debug-dump=frames (the routine, both caller
    bodies and the parent dispatch).
  * No RELATIVE relocation mentions the routine address, and
    relocations.txt records the same facts.
  * census.py reproduces exactly the pinned census: two
    direct calls (0x61c2c8e, 0x61c31fc), no tail jumps, and no
    internal calls or jumps of any kind.
  * callers.tsv lists exactly the pinned callers.
  * records.json matches the address, FDE ranges, census
    counts and the pinned consumers.
  * The packet model tests pass.
  * MANIFEST.sha256 covers the other packet files exactly.
"""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("main.txt", 0x61C27F0, 0x61C2888),
]

EXPECTED_CALLS = {0x61C27F0: ["0x61c2c8e", "0x61c31fc"]}
EXPECTED_JUMPS = {0x61C27F0: []}
EXPECTED_INTERNAL_CALLS = []
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = []
EXPECTED_INTERNAL_INDIRECT_JUMPS = []

SPOT_BYTES = {
    0x61C27F0: "4154",                 # push %r12 (entry)
    0x61C27F2: "4c8b07",               # mov (%rdi),%r8 (acc word 0)
    0x61C27F5: "4989d2",               # mov %rdx,%r10 (start saved)
    0x61C27FB: "4c3306",               # xor (%rsi),%r8 (secret word 0)
    0x61C2806: "415c",                 # pop %r12
    0x61C2808: "49f7e0",               # mul %r8 (pair 0 product)
    0x61C2824: "48f7e2",               # mul %rdx (pair 1 product)
    0x61C2835: "4801d6",               # add %rdx,%rsi (fold 2 into sum)
    0x61C2843: "4c01d6",               # add %r10,%rsi (start into sum)
    0x61C2868: "48c1e825",             # shr $0x25,%rax (avalanche)
    0x61C286F: "48baf979379eb1675616",  # movabs PRIME64_2,%rdx
    0x61C2879: "480fafc2",             # imul %rdx,%rax
    0x61C2887: "c3",                   # ret
}


def check(ok, label):
    if not ok:
        print("FAIL %s" % label)
        sys.exit(1)


def hash_file(path):
    checkout = subprocess.run(
        ["git", "lfs", "smudge"], input=path.read_bytes(),
        capture_output=True, cwd=ROOT)
    expanded = checkout.stdout if checkout.returncode == 0 else b""
    data = expanded if len(expanded) > 1024 else path.read_bytes()
    return hashlib.sha256(data).hexdigest()


def objdump_range(start, stop):
    return subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout


def check_digest():
    artifact = Path(subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True,
        text=True, check=True).stdout.strip())
    for label, path in (("digest", artifact / "artifacts/node/115/hl-node"),
                        ("work binary", ROOT / "work/hl-node-115.bin")):
        check(path.exists() and hash_file(path) == DIGEST, label)


def check_excerpts():
    for name, start, stop in WINDOWS:
        stored = (PACKET / name).read_text()
        check(objdump_range(start, stop) == stored, "excerpt %s" % name)


def check_spot_bytes():
    blob = (ROOT / "work/hl-node-115.bin").read_bytes()
    for address, want in SPOT_BYTES.items():
        raw = bytes.fromhex(want)
        got = blob[address - 0x1000:address - 0x1000 + len(raw)]
        check(got == raw, "spot bytes %#x" % address)


def check_frames():
    stored = (PACKET / "frames.txt").read_text()
    fresh = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    for line in stored.splitlines():
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        check(match is not None, "frames line shape: %s" % line)
        needle = "pc=%s..%s" % (match.group(1), match.group(2))
        check(needle in fresh, "frame %s" % needle)
    for start, stop in ((0x61C27F0, 0x61C2888),
                        (0x61C2890, 0x61C2CAD),
                        (0x61C2CB0, 0x61C3221),
                        (0x61C3530, 0x61C389D)):
        check("pc=%016x..%016x" % (start, stop) in fresh,
              "fde %#x" % start)


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    for target in EXPECTED_CALLS:
        for line in text.splitlines():
            check(not (("%x" % target) in line and "RELATIVE" in line),
                  "no RELATIVE record for %#x" % target)
    stored = (PACKET / "relocations.txt").read_text()
    check("no R_X86_64_RELATIVE record carries it as" in stored,
          "relocations records the no-relative fact")
    check("no whole-file stored qword equals it" in stored,
          "relocations records the no-stored-qword fact")


def frame_ranges():
    fresh = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    ranges = []
    for line in fresh.splitlines():
        match = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if match:
            ranges.append((int(match.group(1), 16),
                           int(match.group(2), 16)))
    return ranges


def check_census():
    venv = (Path.home() / "workspace/hl-1105-h30/scratch/venv/bin/python")
    python = str(venv) if venv.exists() else sys.executable
    out = subprocess.run([python, str(PACKET / "census.py")],
                         capture_output=True, text=True, check=True,
                         cwd=ROOT).stdout
    ranges = frame_ranges()

    def smallest_fde(site):
        enclosing = [(a, b) for (a, b) in ranges if a <= site < b]
        check(bool(enclosing), "caller fde for %#x" % site)
        return min(enclosing, key=lambda ab: ab[1] - ab[0])

    tsv_calls = {}
    for line in (PACKET / "callers.tsv").read_text().splitlines():
        if not line.strip():
            continue
        site, target, fde, kind = line.split("\t")
        site_value = int(site, 16)
        a, b = smallest_fde(site_value)
        check(fde == "%#x..%#x" % (a, b),
              "caller fde shape %s" % site)
        check(kind == "call", "caller kind %s" % site)
        tsv_calls.setdefault(target, []).append(site)

    for target, want in EXPECTED_CALLS.items():
        match = re.search(r"routine %#x: direct calls: (\[.*\])" % target,
                          out)
        check(match is not None and match.group(1) == str(want),
              "census calls %#x" % target)
        check(sorted(tsv_calls.get("%#x" % target, [])) == sorted(want),
              "callers.tsv calls %#x" % target)
    for target, want in EXPECTED_JUMPS.items():
        match = re.search(r"routine %#x: tail jumps: (\[.*\])" % target,
                          out)
        check(match is not None and match.group(1) == str(want),
              "census tail jumps %#x" % target)
    for label, expected in (("internal calls", EXPECTED_INTERNAL_CALLS),
                            ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                            ("internal indirect calls",
                             EXPECTED_INTERNAL_INDIRECT_CALLS),
                            ("internal indirect tail jumps",
                             EXPECTED_INTERNAL_INDIRECT_JUMPS)):
        for target in EXPECTED_CALLS:
            match = re.search(r"routine %#x: %s: (\[.*\])"
                              % (target, label), out)
            check(match is not None and match.group(1) == str(expected),
                  "census %s" % label)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    routine = records["routine"]
    check(records["task"] == "RE-001", "records task")
    check(records["artifact_sha256"] == DIGEST, "records digest")
    check(routine["address"] == "0x61c27f0", "records address")
    check(routine["fde"] == "0x61c27f0..0x61c2888", "records fde")
    check(routine["size_bytes"] == 152, "records size")
    check(routine["internal_calls"] == len(EXPECTED_INTERNAL_CALLS),
          "records internal calls")
    check(routine["internal_tail_jumps"] == len(EXPECTED_INTERNAL_JUMPS),
          "records internal tail jumps")
    check(routine["internal_indirect_calls"]
          == len(EXPECTED_INTERNAL_INDIRECT_CALLS),
          "records internal indirect calls")
    check(routine["internal_indirect_tail_jumps"]
          == len(EXPECTED_INTERNAL_INDIRECT_JUMPS),
          "records internal indirect tail jumps")
    census = records["census"]
    check(census["direct_call_count"]
          == sum(len(v) for v in EXPECTED_CALLS.values()),
          "records census calls")
    check(census["tail_jump_count"]
          == sum(len(v) for v in EXPECTED_JUMPS.values()),
          "records census tail jumps")
    check(census["relative_addends"] == 0, "records census relative")
    check(census["stored_qwords"] == 0, "records census stored qwords")
    consumers = records["consumers"]
    check(len(consumers) == 2, "records consumers count")
    check(sorted(c["site"] for c in consumers)
          == ["0x61c2c8e", "0x61c31fc"], "records consumer sites")
    check(sorted(c["caller_fde"] for c in consumers)
          == ["0x61c2890..0x61c2cad", "0x61c2cb0..0x61c3221"],
          "records consumer fdes")
    check(records["fold"]["pairs"] == 4, "records fold pairs")
    check("0x165667b19e3779f9" in records["avalanche"]["rule"],
          "records avalanche constant")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, str(ROOT / "tests/test_hash_merge_accs_61c27f0_115.py")],
        capture_output=True, text=True, cwd=ROOT)
    check(out.returncode == 0 and "checks pass" in out.stdout,
          "model tests")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        path = PACKET / name
        check(path.exists(), "manifest file %s" % name)
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
              "manifest hash %s" % name)
        seen.add(name)
    check(seen == {"README.md", "records.json", "main.txt",
                   "frames.txt", "relocations.txt", "callers.tsv",
                   "export_excerpts.py", "census.py", "verify.py",
                   "differential.py"},
          "manifest set")


def main():
    check_digest()
    check_excerpts()
    check_spot_bytes()
    check_frames()
    check_relocations()
    check_census()
    check_records()
    check_model_tests()
    check_manifest()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
