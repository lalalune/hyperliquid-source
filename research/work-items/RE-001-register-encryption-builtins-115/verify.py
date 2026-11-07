"""Checker for the RE-001-register-encryption-builtins-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-encryption-builtins-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary (three random ones
among them, seed 115: 0x5ff82ff, 0x5ff73c7, 0x5ffbd79); the FDE
ranges in frames.txt against a fresh frame dump; the relocation
set against a fresh relocation dump (the four vtables, their
typeinfos and the manager typeinfos); the string literals against
the raw binary; census consistency (callers.tsv against a fresh
census run: every pinned routine's direct calls, tail jumps, lea
references, stored qwords and RELATIVE addends, and the
callers.tsv caller function against the smallest enclosing FDE
range from a fresh frame dump); the semantic records
(re-deriving the census entries, the relocation rows, the caller
lists, the vtable map, the typeinfo names, the excerpt needles
and the model behaviour); and the model tests in
tests/test_register_encryption_builtins_115.py.
Prints ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import importlib.util
import json
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("host-5ff88c0.objdump.txt", 0x5FF88C0, 0x5FF9C50),
    ("host-cold-5ff844a.objdump.txt", 0x5FF844A, 0x5FF88B7),
    ("thunk-5ff9c50.objdump.txt", 0x5FF9C50, 0x5FF9C59),
    ("string-ctor-5ff0300.objdump.txt", 0x5FF0300, 0x5FF03E3),
    ("string-range-5fefd80.objdump.txt", 0x5FEFD80, 0x5FEFE23),
    ("vec-grow-5ff7420.objdump.txt", 0x5FF7420, 0x5FF7811),
    ("register-5ff8260.objdump.txt", 0x5FF8260, 0x5FF8449),
    ("mgr-e_-5fefa50.objdump.txt", 0x5FEFA50, 0x5FEFA7D),
    ("mgr-e0-5fefa80.objdump.txt", 0x5FEFA80, 0x5FEFAAD),
    ("mgr-cipher-5fefab0.objdump.txt", 0x5FEFAB0, 0x5FEFADD),
    ("invoke-e0-5ff6a00.objdump.txt", 0x5FF6A00, 0x5FF6C70),
    ("invoke-e_-5ff6d60.objdump.txt", 0x5FF6D60, 0x5FF70A7),
    ("invoke-cipher-5ff7120.objdump.txt", 0x5FF7120, 0x5FF7419),
    ("fe-enc-d2-5fefbc0.objdump.txt", 0x5FEFBC0, 0x5FEFC02),
    ("fe-enc-d0-5ff0060.objdump.txt", 0x5FF0060, 0x5FF00AA),
    ("fe-enc-matches-5fefca0.objdump.txt", 0x5FEFCA0, 0x5FEFCAE),
    ("fe-enc-accessor-5fefcb0.objdump.txt", 0x5FEFCB0, 0x5FEFCBE),
    ("fe-cipher-d2-5fefb70.objdump.txt", 0x5FEFB70, 0x5FEFBB2),
    ("fe-cipher-d0-5ff0010.objdump.txt", 0x5FF0010, 0x5FF005A),
    ("fe-cipher-matches-5fefc80.objdump.txt", 0x5FEFC80, 0x5FEFC8E),
    ("fe-cipher-accessor-5fefc90.objdump.txt", 0x5FEFC90, 0x5FEFC9E),
    ("libcb-dispose-5ff7900.objdump.txt", 0x5FF7900, 0x5FF7952),
    ("endswith-61d1390.objdump.txt", 0x61D1390, 0x61D13DB),
    ("cipher-jmp-61d1ef0.objdump.txt", 0x61D1EF0, 0x61D1EF9),
    ("once-a-5ffa710.objdump.txt", 0x5FFA710, 0x5FFAAD9),
    ("once-b-5ffba10.objdump.txt", 0x5FFBA10, 0x5FFBDD9),
]

# The three seeded random gate spots (seed 115) among the excerpt
# instruction addresses.
SPOTS = [0x5FF82FF, 0x5FF73C7, 0x5FFBD79]

TEXT_OFF = 0x1418300
TEXT_VA = 0x1419300
TEXT_SZ = 0x4FD7700


def load_segments():
    """PT_LOAD segments as (vaddr, offset, filesz), from readelf."""
    out = subprocess.run(
        ["readelf", "-l", "-W", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    segs = []
    for line in out.splitlines():
        m = re.match(
            r"\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+"
            r"0x([0-9a-f]+)\s+0x([0-9a-f]+)", line)
        if m:
            segs.append((int(m.group(2), 16), int(m.group(1), 16),
                         int(m.group(4), 16)))
    return segs


SEGMENTS = load_segments()


def vaddr_to_offset(addr):
    for vaddr, offset, filesz in SEGMENTS:
        if vaddr <= addr < vaddr + filesz:
            return offset + (addr - vaddr)
    fail("address 0x%x not in any LOAD segment" % addr)


def fail(msg):
    raise SystemExit("FAIL: " + msg)


def objdump(start, stop):
    return subprocess.run(
        ["objdump", "-d",
         "--start-address=%#x" % start,
         "--stop-address=%#x" % stop,
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout


def parse_instructions(text):
    """Yield (addr, bytes) for every instruction in objdump text,
    accumulating continuation lines."""
    current = None
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)", line)
        if m:
            if current is not None:
                yield current
            current = (int(m.group(1), 16),
                       bytes.fromhex(m.group(2).replace(" ", "")))
            continue
        m = re.match(r"^\s+((?:[0-9a-f]{2} )+)", line)
        if m and current is not None:
            current = (current[0],
                       current[1] + bytes.fromhex(m.group(1).replace(" ", "")))
    if current is not None:
        yield current


def main():
    data = BINARY.read_bytes()

    # 1. Binary digest.
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    print("digest ok")

    # 2. Manifest.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    listed = {}
    for line in manifest:
        digest, _, name = line.partition("  ")
        listed[name] = digest
    actual = {}
    for path in sorted(PACKET.rglob("*")):
        if not path.is_file() or path.name == "MANIFEST.sha256":
            continue
        rel = str(path.relative_to(PACKET))
        actual[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    if listed != actual:
        fail("manifest mismatch: listed=%s actual=%s" % (sorted(listed), sorted(actual)))
    print("manifest ok (%d files)" % len(actual))

    # 3. Excerpt regeneration byte-for-byte.
    for name, start, stop in WINDOWS:
        fresh = objdump(start, stop)
        committed = (PACKET / "excerpts" / name).read_text()
        if fresh != committed:
            fail("excerpt %s differs from fresh objdump" % name)
    print("excerpts ok (%d windows)" % len(WINDOWS))

    # 4. Every excerpt instruction byte-for-byte vs the raw binary.
    all_addrs = []
    for name, start, stop in WINDOWS:
        text = (PACKET / "excerpts" / name).read_text()
        for addr, insn in parse_instructions(text):
            off = vaddr_to_offset(addr)
            if data[off:off + len(insn)] != insn:
                fail("excerpt %s instruction at 0x%x mismatches raw binary"
                     % (name, addr))
            all_addrs.append(addr)
    print("excerpt bytes ok (%d instructions)" % len(all_addrs))

    # 5. Three seeded random gate spots vs fresh objdump + raw binary.
    spots = random.Random(115).sample(sorted(set(all_addrs)), 3)
    if spots != SPOTS:
        fail("seeded spots moved: %s" % [hex(s) for s in spots])
    for addr in SPOTS:
        fresh = objdump(addr, addr + 16)
        got = list(parse_instructions(fresh))
        if not got or got[0][0] != addr:
            fail("spot 0x%x not found in fresh objdump" % addr)
        off = vaddr_to_offset(addr)
        if data[off:off + len(got[0][1])] != got[0][1]:
            fail("spot 0x%x mismatches raw binary" % addr)
    print("gate spots ok (%s)" % ", ".join("0x%x" % s for s in SPOTS))

    # 6. Frames against a fresh frame dump.
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fdes = set()
    for m in re.finditer(
            r"FDE cie=\S+ pc=000000000([0-9a-f]+)\.\.000000000([0-9a-f]+)", out):
        fdes.add((int(m.group(1), 16), int(m.group(2), 16)))
    for line in (PACKET / "frames.txt").read_text().splitlines():
        rng, _, status = line.partition("\t")
        start, _, stop = rng.partition("..")
        have = (int(start, 16), int(stop, 16)) in fdes
        if (status == "FDE") != have:
            fail("frames.txt mismatch for %s" % rng)
    print("frames ok")

    # 7. Relocations against a fresh relocation dump.
    out = subprocess.run(
        ["readelf", "-r", "-W", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    rel = {}
    for line in out.splitlines():
        m = re.match(
            r"\s*([0-9a-f]+)\s+([0-9a-f]+)\s+(R_X86_64_RELATIVE)\s+([0-9a-f]+)",
            line)
        if m:
            rel[int(m.group(1), 16)] = int(m.group(4), 16)
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            fail("relocations.txt malformed line: %r" % line)
        off, what, value = int(parts[0], 16), parts[1], parts[2]
        if what == "typeinfo name":
            continue  # checked against the name strings below
        addend = rel.get(off)
        got = ("0x%x" % addend) if isinstance(addend, int) else "none"
        if got != value:
            fail("relocation 0x%x (%s): %s != %s" % (off, what, got, value))
    print("relocations ok")

    # 8. Typeinfo names and literals against the raw binary.
    records = json.loads((PACKET / "records.json").read_text())
    for ti, name in ((0x64D8E90, "N7rocksdb13ObjectLibrary12PatternEntryE"),
                     (0x64CF788, "N7rocksdb13ObjectLibrary12FactoryEntryINS_18EncryptionProviderEEE"),
                     (0x64CF7A0, "N7rocksdb13ObjectLibrary12FactoryEntryINS_11BlockCipherEEE"),
                     (0x64CF808, "St23_Sp_counted_ptr_inplaceIN7rocksdb13ObjectLibraryESaIvELN9__gnu_cxx12_Lock_policyE2EE")):
        ptr = rel.get(ti + 8)
        end = data.find(b"\x00", ptr)
        if data[ptr:end].decode() != name:
            fail("typeinfo 0x%x name mismatch" % ti)
    for lit in records["literals"]:
        addr = int(lit["addr"], 16)
        end = data.find(b"\x00", addr)
        if data[addr:end].decode() != lit["value"]:
            fail("literal %s mismatch" % lit["addr"])
    print("typeinfos and literals ok")

    # 9. Census reproduction (callers.tsv / relocations.txt / frames.txt).
    with tempfile.TemporaryDirectory() as tmp:
        tmp_pack = Path(tmp)
        census_src = (PACKET / "census.py").read_text()
        # Run the census with its PACKET pointed at the temp dir by
        # copying the script and patching the packet path.
        tmp_script = tmp_pack / "census.py"
        tmp_script.write_text(census_src.replace(
            'PACKET = Path(__file__).resolve().parent',
            'PACKET = Path(%r)' % str(tmp_pack)).replace(
            'ROOT = PACKET.parents[2]',
            'ROOT = Path(%r)' % str(ROOT)))
        subprocess.run([sys.executable, str(tmp_script)],
                       cwd=ROOT, check=True, capture_output=True)
        for name in ("callers.tsv", "relocations.txt", "frames.txt"):
            if (tmp_pack / name).read_bytes() != (PACKET / name).read_bytes():
                fail("census reproduction mismatch for %s" % name)
    print("census ok")

    # 10. Records regeneration.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_pack = Path(tmp)
        gen_src = (PACKET / "gen_records.py").read_text()
        tmp_script = tmp_pack / "gen_records.py"
        tmp_script.write_text(gen_src.replace(
            'PACKET = Path(__file__).resolve().parent',
            'PACKET = Path(%r)' % str(tmp_pack)))
        subprocess.run([sys.executable, str(tmp_script)],
                       cwd=ROOT, check=True, capture_output=True)
        if (tmp_pack / "records.json").read_bytes() != (PACKET / "records.json").read_bytes():
            fail("records.json regeneration mismatch")
    # Records cross-checks: the three entries, the vtable map, the
    # caller lists, and the excerpt needles.
    entries = records["entries"]
    if [(e["name"], e["pattern"], e["creator"]) for e in entries] != [
            ("EncryptionProvider", "CTR", "E_"),
            ("EncryptionProvider", "1://test", "E0"),
            ("BlockCipher", "ROT13", "Cipher")]:
        fail("records entries mismatch")
    if [e["elements"] for e in entries] != [
            [{"string": "://test", "mode": 2}], [], [{"string": ":", "mode": 3}]]:
        fail("records elements mismatch")
    vmap = {
        0x64D8ED0: [0x5FF2030, 0x5FF2150, 0x61F8670, 0x61F8120],
        0x64D0090: [0x5FEFBC0, 0x5FF0060, 0x5FEFCA0, 0x5FEFCB0],
        0x64D00C0: [0x5FEFB70, 0x5FF0010, 0x5FEFC80, 0x5FEFC90],
        0x64D00F0: [0x5FEFC70, 0x5FEFD00, 0x5FF7900, 0x5FEFD50, 0x5FEFF70],
    }
    for vtab, slots in vmap.items():
        for i, slot in enumerate(slots):
            if rel.get(vtab + 8 * i) != slot:
                fail("vtable 0x%x slot %d mismatch" % (vtab, i))
    callers = (PACKET / "callers.tsv").read_text()
    for needle in ("0x5ff9c54", "0x5ffa77f", "0x5ffba7f",
                   "0x5ff8fc4", "0x5ff9266", "0x5ff9791",
                   "0x5ff99bb", "0x5ff9a05", "0x5ff6db6", "0x5ff71ba"):
        if needle not in callers:
            fail("callers.tsv missing site %s" % needle)
    for name, _, _ in WINDOWS:
        if (PACKET / "excerpts" / name).stat().st_size == 0:
            fail("empty excerpt %s" % name)
    print("records ok")

    # 11. Model behaviour + tests.
    spec = importlib.util.spec_from_file_location(
        "register_encryption_builtins_115",
        ROOT / "tools" / "register_encryption_builtins_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    reg = mod.register_encryption_builtins()
    if len(reg.libraries) != 1 or len(reg.find_factory("EncryptionProvider")) != 2:
        fail("model registration mismatch")
    if reg.create("EncryptionProvider", "CTR://test")["resolved_rot13_options"] is not True:
        fail("model E_ dispatch mismatch")
    if reg.create("BlockCipher", "ROT13:42")["cipher"] != "ROT13BlockCipher":
        fail("model cipher dispatch mismatch")
    result = subprocess.run(
        [sys.executable, "tests/test_register_encryption_builtins_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print(result.stdout.strip())

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
