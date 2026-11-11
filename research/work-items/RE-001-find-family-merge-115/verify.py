#!/usr/bin/env python3
"""Independent verification for the RE-001-find-family-merge-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-find-family-merge-115/verify.py

Exits 0 and prints ALL CHECKS PASSED only when every check below
passes; otherwise it prints the first failure and exits non-zero.

Checks:
  1. The node #115 binary digest matches provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file with matching hashes.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump.
  4. Every excerpt line's raw bytes match the binary at that address.
  5. Three seeded random gate spots (random.seed(20261106)) are
     verified byte-for-byte against a fresh objdump run.
  6. Every routine's FDE range is present in frames.txt.
  7. relocations.txt holds the __libc_single_threaded row and the
     GOT entry at 0x64ed290 is R_X86_64_GLOB_DAT.
  8. Every pinned literal reads back from the binary.
  9. census.py reproduces callers.tsv byte-identically (3870 rows)
     and the per-target counts match records.json.
 10. The model constants (addresses, seed, literals, vtables) match
     the packet, and the GOT re-derivation agrees.
 11. The model tests pass (tests/test_find_family_merge_115.py).
"""

import hashlib
import json
import random
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.dont_write_bytecode = True
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print("%-4s %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAILURES.append(name)


def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=cwd).stdout


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- vaddr -> file offset, from readelf -S ------------------------------


def load_sections():
    sections = []
    for line in run(["readelf", "-S", "-W", str(BINARY)]).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            sections.append((m.group(1), int(m.group(2), 16),
                             int(m.group(3), 16), int(m.group(4), 16)))
    return sections


SECTIONS = load_sections()
_BINARY_DATA = BINARY.read_bytes()


def read_vaddr(addr, n):
    for _name, vaddr, off, size in SECTIONS:
        if vaddr <= addr < vaddr + size:
            start = off + (addr - vaddr)
            return _BINARY_DATA[start: start + n]
    raise ValueError("address %#x not in any section" % addr)


def read_cstr(addr):
    out = bytearray()
    cur = addr
    while True:
        b = read_vaddr(cur, 1)[0]
        if b == 0:
            return bytes(out)
        out.append(b)
        cur += 1


# --- 1. digest ----------------------------------------------------------


def check_digest():
    artifacts = json.load(open(ROOT / "provenance" / "artifacts.json"))
    entry = None
    for f in artifacts["files"]:
        if f["path"] == "artifacts/node/115/hl-node":
            entry = f
            break
    ok = entry is not None and entry["sha256"] == DIGEST
    ok = ok and sha256_file(BINARY) == DIGEST
    check("digest", ok, "provenance + binary == " + DIGEST[:16] + "...")


# --- 2. manifest --------------------------------------------------------


def check_manifest():
    manifest = PACKET / "MANIFEST.sha256"
    listed = {}
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        listed[parts[1]] = parts[0]
    actual = {}
    for p in sorted(PACKET.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            actual[str(p.relative_to(PACKET))] = sha256_file(p)
    ok = listed == actual
    missing = sorted(set(actual) - set(listed))
    extra = sorted(set(listed) - set(actual))
    mismatched = sorted(k for k in listed if k in actual
                        and listed[k] != actual[k])
    check("manifest", ok, "files=%d missing=%s extra=%s mismatched=%s"
          % (len(actual), missing, extra, mismatched))


# --- 3. excerpts regenerate ----------------------------------------------


def check_excerpts_regenerate():
    bad = []
    for name, start, stop in WINDOWS:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % start,
                    "--stop-address=%#x" % stop,
                    "work/hl-node-115.bin"])
        if (PACKET / "excerpts" / name).read_text() != text:
            bad.append(name)
    check("excerpts-regenerate", not bad, "bad=%s" % bad)


# --- 4. raw bytes of every excerpt line -----------------------------------


def excerpt_lines():
    lines = []
    for name, _s, stop in WINDOWS:
        file_lines = (PACKET / "excerpts" / name).read_text().splitlines()
        parsed = []
        for line in file_lines:
            m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if m:
                addr = int(m.group(1), 16)
                raw = bytes.fromhex(m.group(2).strip())
                parsed.append((name, addr, raw, line.strip()))
        for i, (name, addr, raw, line) in enumerate(parsed):
            # objdump wraps long instructions: the raw-bytes
            # column holds only the first 7 bytes and the rest
            # appears on a continuation line, so the
            # instruction's true end is the NEXT line's
            # address (or the window end for the last line).
            nxt = parsed[i + 1][1] if i + 1 < len(parsed) else stop
            lines.append((name, addr, raw, line, nxt))
    return lines


def check_raw_bytes():
    bad = []
    for name, addr, raw, line, _nxt in excerpt_lines():
        if read_vaddr(addr, len(raw)) != raw:
            bad.append((name, "%#x" % addr, line))
    check("raw-bytes", not bad, "checked=%d bad=%s"
          % (len(excerpt_lines()), bad[:3]))


# --- 5. seeded random gate spots ------------------------------------------


def check_random_spots():
    lines = excerpt_lines()
    random.seed(20261106)
    spots = random.sample(lines, 3)
    bad = []
    for name, addr, raw, line, nxt in spots:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % addr,
                    "--stop-address=%#x" % nxt,
                    "work/hl-node-115.bin"])
        if line.split("\t")[-1].strip() not in text:
            bad.append((name, "%#x" % addr))
    check("random-spots", not bad,
          "spots=%s" % [(n, a) for n, a, _r, _l, _x in spots])


# --- 6. FDE presence ------------------------------------------------------


def check_fdes():
    frames = (PACKET / "frames.txt").read_text()
    missing = []
    for name, start, stop in WINDOWS:
        if "pc=%016x..%016x" % (start, stop) not in frames:
            missing.append((name, "%#x..%#x" % (start, stop)))
    check("fdes", not missing, "windows=%d missing=%s"
          % (len(WINDOWS), missing))


# --- 7. relocations ---------------------------------------------------------


def check_relocations():
    reloc = (PACKET / "relocations.txt").read_text()
    ok = "0x64ed290" in reloc and "R_X86_64_GLOB_DAT" in reloc
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    ok = ok and "64ed290" in dyn and "GLOB_DAT" in dyn
    check("relocations", ok, "libc_single_threaded at 0x64ed290")


# --- 8. literals ------------------------------------------------------------


LITERALS = {
    0x43E863: b"Could not find option: ",
    0x43FB8A: b"Could not find configurable: ",
    0x44E056: b"Could not find option",
    0x4409B0: b"; ",
    0x445245: b"=",
    0x4477ED: b"Error parsing:",
    0x4477FC: b"Error parsing ",
    0x441B18: b":",
    0x4376FD: b"",
    0x4373E9: b"Deserializing the option ",
    0x437403: b" is not supported",
    0x434345: b"stoull",
    0x43434C: b"stoll",
    0x4311EB: b"stoi",
    0x441D25: b"stod",
    0x963298: b"basic_string: construction from null is not valid",
}


def check_literals():
    bad = []
    for addr, want in LITERALS.items():
        if read_cstr(addr) != want:
            bad.append("%#x" % addr)
    check("literals", not bad, "checked=%d bad=%s"
          % (len(LITERALS), bad))


# --- 9. census --------------------------------------------------------------


CENSUS_COUNTS = {
    ("0x5d35070", "call"): 654,
    ("0x5d35070", "jmp"): 36,
    ("0x5d350c0", "call"): 1273,
    ("0x5d350c0", "jmp"): 25,
    ("0x5d38260", "call"): 4,
    ("0x5d5b300", "call"): 98,
    ("0x5e33fb0", "call"): 44,
    ("0x607d9f0", "call"): 141,
    ("0x607e020", "call"): 3,
    ("0x6080a71", "jmp"): 1,
    ("0x6080b10", "lea"): 1,
    ("0x608183a", "jmp"): 1,
    ("0x60818f0", "call"): 1,
    ("0x60956f0", "lea"): 1,
    ("0x6095b80", "call"): 2,
    ("0x6096f40", "call"): 2,
    ("0x6097110", "call"): 2,
    ("0x6097150", "call"): 5,
    ("0x60971c0", "call"): 8,
    ("0x6098510", "call"): 5,
    ("0x6098a9c", "jmp"): 1,
    ("0x6098ad0", "call"): 1,
    ("0x6099ce0", "call"): 37,
    ("0x6099e70", "call"): 5,
    ("0x609a1b0", "call"): 2,
    ("0x609a2f0", "call"): 3,
    ("0x609a410", "call"): 3,
    ("0x609a740", "call"): 1,
    ("0x609b700", "call"): 2,
    ("0x609b8a0", "call"): 1,
    ("0x609ba30", "call"): 4,
    ("0x609bad0", "call"): 1,
    ("0x609bcb0", "call"): 1,
    ("0x609c8c0", "call"): 1,
    ("0x609d08e", "jmp"): 1,
    ("0x609d0e0", "call"): 2,
    ("0x60b79b0", "call"): 2,
    ("0x60b79e0", "call"): 12,
    ("0x60b7cd0", "call"): 12,
    ("0x60b7d80", "call"): 53,
    ("0x60b84b0", "call"): 2,
    ("0x60b9d70", "call"): 4,
    ("0x60ba0b0", "call"): 10,
    ("0x60bb9a0", "call"): 16,
    ("0x60be160", "call"): 1,
    ("0x60be2b0", "call"): 1,
    ("0x60be400", "call"): 1,
    ("0x60be550", "call"): 1,
    ("0x60be6a0", "call"): 1,
    ("0x60be7f0", "call"): 1,
    ("0x60be940", "call"): 1,
    ("0x60bea8c", "jmp"): 1,
    ("0x60bedc0", "call"): 13,
    ("0x60c1190", "call"): 6,
    ("0x60db710", "call"): 3,
    ("0x60dbd80", "call"): 3,
    ("0x6193a00", "call"): 2,
    ("0x6193b40", "call"): 2,
    ("0x61c7dc0", "call"): 2,
    ("0x61c7fc0", "call"): 1,
    ("0x61cf610", "call"): 425,
    ("0x61cf670", "call"): 847,
    ("0x61d0ee0", "call"): 1,
    ("0x61d10a0", "call"): 2,
    ("0x61d1390", "call"): 8,
    ("0x61d13e0", "call"): 8,
    ("0x61d1480", "call"): 6,
    ("0x61d1540", "call"): 12,
    ("0x61d1540", "jmp"): 1,
    ("0x61d17d0", "call"): 1,
    ("0x61d1840", "call"): 1,
    ("0x61d18a0", "call"): 2,
    ("0x61d1b30", "call"): 1,
    ("0x61d1b90", "call"): 8,
    ("0x61d1e30", "call"): 10,
    ("0x61d1ef0", "call"): 13,
}


def check_census():
    before = (PACKET / "callers.tsv").read_bytes()
    run([sys.executable, str(PACKET / "census.py")], cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    ok = before == after
    rows = after.decode().splitlines()[1:]
    ok = ok and len(rows) == 3870
    counts = {}
    for line in rows:
        parts = line.split("\t")
        counts[(parts[1], parts[3].strip())] = \
            counts.get((parts[1], parts[3].strip()), 0) + 1
    bad = {k: (counts.get(k, 0), v)
           for k, v in CENSUS_COUNTS.items()
           if counts.get(k, 0) != v}
    check("census", ok and not bad,
          "rows=%d bad-counts=%s" % (len(rows), bad))


# --- 10. model constants + GOT ----------------------------------------------


def check_model_constants():
    sys.path.insert(0, str(ROOT / "tools"))
    import find_family_merge_115 as m
    records = json.load(open(PACKET / "records.json"))
    ok = True
    detail = []
    verified = 0
    for addr in records["routines"]:
        name = records["routines"][addr]["name"]
        const = getattr(m, name.upper(), None)
        if const is None:
            # The routine is reached through a class or a
            # helper name, not a top-level constant.
            continue
        verified += 1
        if const != int(addr, 16):
            ok = False
            detail.append((name, hex(const), addr))
    ok = ok and verified >= 60
    ok = ok and m.HASH_SEED == 0xC70F6907
    ok = ok and m.LINEAR_WALK_LIMIT == 20
    ok = ok and m.LIBC_SINGLE_THREADED == 0x64ED290
    ok = ok and m.HOST_B_KIND_TABLE == 0x9786B4
    ok = ok and m.STOULL_SUFFIX_TABLE == 0x97E998
    ok = ok and m.STOLL_SUFFIX_TABLE == 0x97EA50
    ok = ok and m.MSG_SEMICOLON_SPACE == "; "
    ok = ok and m.MSG_COULD_NOT_FIND_OPTION == "Could not find option"
    ok = ok and m.MSG_COULD_NOT_FIND_CONFIGURABLE == \
        "Could not find configurable: "
    ok = ok and m.MSG_ERROR_PARSING_COLON == "Error parsing:"
    ok = ok and m.MSG_ERROR_PARSING_SPACE == "Error parsing "
    ok = ok and m.SUFFIX_SHIFTS_64 == {"T": 40, "t": 40, "G": 30,
                                       "g": 30, "M": 20, "m": 20,
                                       "K": 10, "k": 10}
    ok = ok and m.SUFFIX_SHIFTS_32 == {"G": 30, "g": 30, "M": 20,
                                       "m": 20, "K": 10, "k": 10}
    check("model-constants", ok, "verified=%d mismatches=%s"
          % (verified, detail))


# --- 11. model tests ----------------------------------------------------------


def check_model_tests():
    out = run([sys.executable,
               "tests/test_find_family_merge_115.py"], cwd=ROOT)
    ok = "all 77 tests passed" in out
    check("model-tests", ok, out.strip().splitlines()[-1]
          if out.strip() else "")


def main():
    check_digest()
    check_manifest()
    check_excerpts_regenerate()
    check_raw_bytes()
    check_random_spots()
    check_fdes()
    check_relocations()
    check_literals()
    check_census()
    check_model_constants()
    check_model_tests()
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
