"""Checker for the RE-001-register-ttl-objects-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-register-ttl-objects-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary (three random ones
among them, seed 115: 0x620558e, 0x6202a4e, 0x620885c); the FDE
ranges in frames.txt against a fresh frame dump; the relocation
set against a fresh relocation dump (the five vtables, their
typeinfos, the three object vtables and the manager typeinfos);
the string literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned routine's
direct calls, tail jumps, lea references, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump); the
semantic records (re-deriving the census entries, the relocation
rows, the caller lists, the vtable map, the typeinfo names, the
excerpt needles and the model behaviour); and the model tests in
tests/test_register_ttl_objects_115.py.
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
    ("trigger-6205d20.objdump.txt", 0x6205D20, 0x6205E08),
    ("once-6202da0.objdump.txt", 0x6202DA0, 0x6202E78),
    ("register-62069f0.objdump.txt", 0x62069F0, 0x6206D29),
    ("regmgr-6201000.objdump.txt", 0x6201000, 0x6201035),
    ("reginvoke-6200a30.objdump.txt", 0x6200A30, 0x6200A3F),
    ("creator-6208290.objdump.txt", 0x6208290, 0x6208AFA),
    ("creator-cold-62080a4.objdump.txt", 0x62080A4, 0x620828D),
    ("mgr-mo-62009a0.objdump.txt", 0x62009A0, 0x62009CD),
    ("mgr-cff-62009d0.objdump.txt", 0x62009D0, 0x62009FD),
    ("mgr-cf-6200a00.objdump.txt", 0x6200A00, 0x6200A2D),
    ("invoke-mo-62056b0.objdump.txt", 0x62056B0, 0x620573D),
    ("invoke-mo-cold-620566b.objdump.txt", 0x620566B, 0x62056A4),
    ("invoke-cff-6205c60.objdump.txt", 0x6205C60, 0x6205CEF),
    ("invoke-cf-6202ca0.objdump.txt", 0x6202CA0, 0x6202D1A),
    ("invoke-cf-cold-6202c60.objdump.txt", 0x6202C60, 0x6202C99),
    ("ctor-mo-6205560.objdump.txt", 0x6205560, 0x620566B),
    ("ctor-cff-6205790.objdump.txt", 0x6205790, 0x62058F7),
    ("ctor-cff-cold-620573e.objdump.txt", 0x620573E, 0x6205788),
    ("ctor-cf-6202a10.objdump.txt", 0x6202A10, 0x6202B50),
    ("ctor-cf-cold-6202976.objdump.txt", 0x6202976, 0x6202A0A),
    ("string-build-6201040.objdump.txt", 0x6201040, 0x62010E3),
    ("string-assign-62010f0.objdump.txt", 0x62010F0, 0x62011D3),
    ("fe-mo-d2-61f06f0.objdump.txt", 0x61F06F0, 0x61F0732),
    ("fe-mo-d0-61f0990.objdump.txt", 0x61F0990, 0x61F09DA),
    ("fe-mo-matches-61f0770.objdump.txt", 0x61F0770, 0x61F077E),
    ("fe-mo-accessor-61f0780.objdump.txt", 0x61F0780, 0x61F078E),
    ("fe-cff-d2-6200a60.objdump.txt", 0x6200A60, 0x6200AA2),
    ("fe-cff-d0-6201240.objdump.txt", 0x6201240, 0x620128A),
    ("fe-cff-matches-6200b10.objdump.txt", 0x6200B10, 0x6200B1E),
    ("fe-cff-accessor-6200b20.objdump.txt", 0x6200B20, 0x6200B2E),
    ("fe-cf-d2-61e7cf0.objdump.txt", 0x61E7CF0, 0x61E7D32),
    ("fe-cf-d0-61e7e00.objdump.txt", 0x61E7E00, 0x61E7E4A),
    ("fe-cf-matches-61e7d70.objdump.txt", 0x61E7D70, 0x61E7D7E),
    ("fe-cf-accessor-61e7d80.objdump.txt", 0x61E7D80, 0x61E7D8E),
]

# The three seeded random gate spots (seed 115) among the excerpt
# instruction addresses.
SPOTS = [0x620558E, 0x6202A4E, 0x620885C]

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
    for ti, name in (
            (0x64D8E90, "N7rocksdb13ObjectLibrary12PatternEntryE"),
            (0x64D9350, "*Z18RegisterTtlObjectsEUlRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPSt10unique_ptrIN7rocksdb13MergeOperatorESt14default_deleteIS9_EEPS4_E_"),
            (0x64D9360, "*Z18RegisterTtlObjectsEUlRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPSt10unique_ptrIN7rocksdb23CompactionFilterFactoryESt14default_deleteIS9_EEPS4_E_"),
            (0x64D9370, "*Z18RegisterTtlObjectsEUlRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPSt10unique_ptrIN7rocksdb16CompactionFilterESt14default_deleteIS9_EEPS4_E_"),
            (0x64D85E0, "N7rocksdb13ObjectLibrary12FactoryEntryINS_13MergeOperatorEEE"),
            (0x64D9338, "N7rocksdb13ObjectLibrary12FactoryEntryINS_23CompactionFilterFactoryEEE"),
            (0x64D7D50, "N7rocksdb13ObjectLibrary12FactoryEntryINS_16CompactionFilterEEE"),
            (0x64CF808, "St23_Sp_counted_ptr_inplaceIN7rocksdb13ObjectLibraryESaIvELN9__gnu_cxx12_Lock_policyE2EE"),
            (0x64D9308, "N7rocksdb16TtlMergeOperatorE"),
            (0x64D92F0, "N7rocksdb26TtlCompactionFilterFactoryE"),
            (0x64D92D8, "N7rocksdb19TtlCompactionFilterE")):
        ptr = rel.get(ti + 8)
        end = data.find(b"\x00", ptr)
        if data[ptr:end].decode() != name:
            fail("typeinfo 0x%x name mismatch" % ti)
    for lit in records["literals"]:
        addr = int(lit["addr"], 16)
        if "length" in lit:
            # Fixed-length rodata copy (the creator copies exactly
            # this many bytes and NUL-terminates itself).
            if data[addr:addr + lit["length"]] != lit["value"].encode():
                fail("literal %s mismatch" % lit["addr"])
        else:
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
            ("MergeOperator", "TtlMergeOperator", "MO"),
            ("CompactionFilterFactory", "TtlCompactionFilterFactory", "CFF"),
            ("CompactionFilter", "TtlCompactionFilter", "CF")]:
        fail("records entries mismatch")
    if [e["elements"] for e in entries] != [[], [], []]:
        fail("records elements mismatch")
    vmap = {
        0x64D8ED0: [0x5FF2030, 0x5FF2150, 0x61F8670, 0x61F8120],
        0x64D86A0: [0x61F06F0, 0x61F0990, 0x61F0770, 0x61F0780],
        0x64D9D38: [0x6200A60, 0x6201240, 0x6200B10, 0x6200B20],
        0x64D7DA0: [0x61E7CF0, 0x61E7E00, 0x61E7D70, 0x61E7D80],
        0x64D00F0: [0x5FEFC70, 0x5FEFD00, 0x5FF7900, 0x5FEFD50, 0x5FEFF70],
    }
    for vtab, slots in vmap.items():
        for i, slot in enumerate(slots):
            if rel.get(vtab + 8 * i) != slot:
                fail("vtable 0x%x slot %d mismatch" % (vtab, i))
    callers = (PACKET / "callers.tsv").read_text()
    for needle in ("0x6205d61", "0x620615d", "0x6202df2",
                   "0x6206a4c", "0x6206a3d", "0x6206c78",
                   "0x620868a", "0x62088e1", "0x62056ea",
                   "0x6205c9c", "0x6202cdb", "0x6205aa0",
                   "0x6205b6c", "0x6202c01", "0x6205a5d"):
        if needle not in callers:
            fail("callers.tsv missing site %s" % needle)
    for name, _, _ in WINDOWS:
        if (PACKET / "excerpts" / name).stat().st_size == 0:
            fail("empty excerpt %s" % name)
    print("records ok")

    # 11. Model behaviour + tests.
    spec = importlib.util.spec_from_file_location(
        "register_ttl_objects_115",
        ROOT / "tools" / "register_ttl_objects_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    reg = mod.register_ttl_objects()
    if len(reg.libraries.items) != 1:
        fail("model registration mismatch")
    lib = reg.libraries.items[0]
    if len(lib.find_factory("MergeOperator")) != 1:
        fail("model MergeOperator entry mismatch")
    if lib.count() != (3, 3):
        fail("model count mismatch")
    slot = mod.OutSlot()
    if not isinstance(mod.create(reg, "MergeOperator",
                                 "TtlMergeOperator", slot),
                      mod.TtlMergeOperator):
        fail("model MO dispatch mismatch")
    if not isinstance(mod.create(reg, "CompactionFilter",
                                 "TtlCompactionFilter"),
                      mod.TtlCompactionFilter):
        fail("model CF dispatch mismatch")
    result = subprocess.run(
        [sys.executable, "tests/test_register_ttl_objects_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print(result.stdout.strip())

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
