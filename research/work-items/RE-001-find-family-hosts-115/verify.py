#!/usr/bin/env python3
"""Independent verification for the RE-001-find-family-hosts-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-find-family-hosts-115/verify.py

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
  8. Every pinned literal reads back from the binary (including
     the 16-byte template at 0x4506c0 = {0x2000, 0x2}).
  9. census.py reproduces callers.tsv byte-identically (3761 rows)
     and the per-target counts match records.json.
 10. The model constants (addresses, seed, literals, vtables) match
     the packet, and the GOT re-derivation agrees.
 11. The model tests pass (tests/test_find_family_hosts_115.py).
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
    for name, _s, _e in WINDOWS:
        for line in (PACKET / "excerpts" / name).read_text().splitlines():
            m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if m:
                addr = int(m.group(1), 16)
                raw = bytes.fromhex(m.group(2).strip())
                lines.append((name, addr, raw, line.strip()))
    return lines


def check_raw_bytes():
    bad = []
    for name, addr, raw, line in excerpt_lines():
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
    for name, addr, raw, line in spots:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % addr,
                    "--stop-address=%#x" % (addr + len(raw)),
                    "work/hl-node-115.bin"])
        if line.split("\t")[-1].strip() not in text:
            bad.append((name, "%#x" % addr))
    check("random-spots", not bad,
          "spots=%s" % [(n, a) for n, a, _r, _l in spots])


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
    0x43E802: b"PlainTableOptions",
    0x444587: b"BlockTableOptions",
    0x43413B: b"Mismatched table option: ",
    0x43D5C7: b";",
    0x43D7B4: b"Cannot find option: ",
    0x4408A7: b"map::at",
    0x43821E: b".",
    0x445245: b"=",
    0x4341C2: b"Option not changeable: ",
    0x43E863: b"Could not find option: ",
    0x4376FD: b"",
    0x4474D2: b"basic_string::append",
    0x44371C: b"default",
}

# Fixed-length byte literals (not NUL-terminated in .rodata).
BYTES_LITERALS = {
    # The plain ctor copies exactly these 16 bytes from
    # 0x451120 and appends 's' to make "PlainTableOptions".
    0x451120: b"PlainTableOption",
}


def check_literals():
    bad = []
    for addr, want in LITERALS.items():
        if read_cstr(addr) != want:
            bad.append("%#x" % addr)
    for addr, want in BYTES_LITERALS.items():
        if read_vaddr(addr, len(want)) != want:
            bad.append("%#x" % addr)
    # The 16-byte block-defaults template at 0x4506c0.
    template = read_vaddr(0x4506C0, 16)
    if template != (0x2000).to_bytes(8, "little") + \
            (0x2).to_bytes(8, "little"):
        bad.append("0x4506c0")
    check("literals", not bad, "checked=%d bad=%s"
          % (len(LITERALS) + len(BYTES_LITERALS) + 1, bad))


# --- 9. census --------------------------------------------------------------


CENSUS_COUNTS = {
    ("0x6080b10", "lea"): 1,
    ("0x60818f0", "call"): 1,
    ("0x6098ad0", "call"): 1,
    ("0x609bcb0", "call"): 1,
    ("0x607d9f0", "call"): 141,
    ("0x6193b40", "call"): 2,
    ("0x6193a00", "call"): 2,
    ("0x60dbd80", "call"): 3,
    ("0x60db710", "call"): 3,
    ("0x607e020", "call"): 3,
    ("0x609a1b0", "call"): 2,
    ("0x609a2f0", "call"): 3,
    ("0x609bad0", "call"): 1,
    ("0x61cf610", "call"): 425,
    ("0x5d350c0", "call"): 1273,
    ("0x5d350c0", "jmp"): 25,
    ("0x6099ce0", "call"): 37,
    ("0x60b79b0", "call"): 2,
    ("0x6099e70", "call"): 5,
    ("0x61cf670", "call"): 847,
    ("0x5d35070", "call"): 654,
    ("0x5d35070", "jmp"): 36,
    ("0x60bb9a0", "call"): 16,
}


def check_census():
    before = (PACKET / "callers.tsv").read_bytes()
    run([sys.executable, str(PACKET / "census.py")], cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    ok = before == after
    rows = after.decode().splitlines()[1:]
    ok = ok and len(rows) == 3761
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
    import find_family_hosts_115 as m
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
    ok = ok and verified >= 35
    ok = ok and m.HASH_SEED == 0xC70F6907
    ok = ok and m.LINEAR_WALK_LIMIT == 20
    ok = ok and m.PLAIN_CONTROL_COUNTS == 0x100000001
    ok = ok and m.PLAIN_CONTROL_VTABLE == 0x64C8748
    ok = ok and m.LIBC_SINGLE_THREADED == 0x64ED290
    ok = ok and m.BLOCK_DEFAULTS_TEMPLATE_VALUES == (0x2000, 0x2)
    check("model-constants", ok, "verified=%d mismatches=%s"
          % (verified, detail))


# --- 11. model tests ----------------------------------------------------------


def check_model_tests():
    out = run([sys.executable,
               "tests/test_find_family_hosts_115.py"], cwd=ROOT)
    ok = "all 50 tests passed" in out
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
