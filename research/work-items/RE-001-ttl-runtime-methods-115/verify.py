"""Checker for the RE-001-ttl-runtime-methods-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ttl-runtime-methods-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary (three random ones
among them, seed 115: 0x620691b, 0x62019c8, 0x6200d0c); the FDE
ranges in frames.txt against a fresh frame dump; the relocation
set against a fresh relocation dump (the three TTL vtables, their
typeinfos, the three object typeinfo names, the GOT canonicals and
the DBWithTTLImpl boundary); the string literals against the raw
binary; census consistency (callers.tsv against a fresh census run:
every pinned routine's direct calls, tail jumps, lea references,
stored qwords and RELATIVE addends, and the callers.tsv caller
function against the smallest enclosing FDE range from a fresh
frame dump); the semantic records (re-deriving the census entries,
the relocation rows, the caller lists, the vtable map, the typeinfo
names, the excerpt needles and the model behaviour); and the model
tests in tests/test_ttl_runtime_methods_115.py.
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
    ("mo-d2-6203b80.objdump.txt", 0x6203B80, 0x6203C25),
    ("mo-d0-6203c30.objdump.txt", 0x6203C30, 0x6203CD3),
    ("mo-prepare-6200b70.objdump.txt", 0x6200B70, 0x6200BE1),
    ("mo-validate-6200e10.objdump.txt", 0x6200E10, 0x6200ED8),
    ("mo-name-6200930.objdump.txt", 0x6200930, 0x620093C),
    ("mo-isinstanceof-6202520.objdump.txt", 0x6202520, 0x62025F9),
    ("mo-slot17-6200940.objdump.txt", 0x6200940, 0x6200949),
    ("mo-fullmergev2-6206610.objdump.txt", 0x6206610, 0x6206923),
    ("mo-fullmergev2-cold-62065e6.objdump.txt", 0x62065E6, 0x620660E),
    ("mo-partialmerge-multi-6201c90.objdump.txt", 0x6201C90, 0x62022B1),
    ("mo-partialmerge-multi-cold-6201b74.objdump.txt", 0x6201B74, 0x6201C81),
    ("cf-d2-62018f0.objdump.txt", 0x62018F0, 0x6201995),
    ("cf-d0-62019a0.objdump.txt", 0x62019A0, 0x6201A43),
    ("cf-prepare-6200bf0.objdump.txt", 0x6200BF0, 0x6200C61),
    ("cf-validate-6200cf0.objdump.txt", 0x6200CF0, 0x6200D7F),
    ("cf-name-6200900.objdump.txt", 0x6200900, 0x620090C),
    ("cf-isinstanceof-6202440.objdump.txt", 0x6202440, 0x6202519),
    ("cf-slot17-62008e0.objdump.txt", 0x62008E0, 0x62008E9),
    ("cf-filter-6203520.objdump.txt", 0x6203520, 0x6203627),
    ("cf-expiry-6203400.objdump.txt", 0x6203400, 0x6203513),
    ("cf-filterv2-5d2e4a0.objdump.txt", 0x5D2E4A0, 0x5D2E53D),
    ("cf-filterv3-5d2f8a0.objdump.txt", 0x5D2F8A0, 0x5D2F999),
    ("cff-d2-6203ad0.objdump.txt", 0x6203AD0, 0x6203B75),
    ("cff-d0-6203ce0.objdump.txt", 0x6203CE0, 0x6203D83),
    ("cff-prepare-6200c70.objdump.txt", 0x6200C70, 0x6200CE1),
    ("cff-validate-6200d80.objdump.txt", 0x6200D80, 0x6200E0F),
    ("cff-name-6200910.objdump.txt", 0x6200910, 0x620091C),
    ("cff-slot17-6200920.objdump.txt", 0x6200920, 0x6200929),
    ("cff-slot19-5d2ca70.objdump.txt", 0x5D2CA70, 0x5D2CA7B),
    ("cff-create-6202ba0.objdump.txt", 0x6202BA0, 0x6202C60),
    ("cff-create-cold-6202b50.objdump.txt", 0x6202B50, 0x6202B9A),
    ("shared-empty-string-5d2ca10.objdump.txt", 0x5D2CA10, 0x5D2CA1C),
    ("shared-null-5d2ca00.objdump.txt", 0x5D2CA00, 0x5D2CA07),
    ("shared-ret0-5d2cd80.objdump.txt", 0x5D2CD80, 0x5D2CD87),
    ("shared-ret0-5d2cd90.objdump.txt", 0x5D2CD90, 0x5D2CD97),
    ("shared-ret0-5d2cda0.objdump.txt", 0x5D2CDA0, 0x5D2CDA7),
    ("shared-ret0-5d2cdb0.objdump.txt", 0x5D2CDB0, 0x5D2CDB7),
    ("shared-ret0-5d2ca30.objdump.txt", 0x5D2CA30, 0x5D2CA37),
    ("shared-ret0-5d2ca40.objdump.txt", 0x5D2CA40, 0x5D2CA47),
    ("shared-ret1-5df72f0.objdump.txt", 0x5DF72F0, 0x5DF72FA),
    ("shared-ret0-5d2ca50.objdump.txt", 0x5D2CA50, 0x5D2CA57),
    ("shared-ret8-5d2ca60.objdump.txt", 0x5D2CA60, 0x5D2CA6A),
    ("shared-isinst-default-5d2e770.objdump.txt", 0x5D2E770, 0x5D2E832),
    ("merge-error-logger-5fceda0.objdump.txt", 0x5FCEDA0, 0x5FCEE93),
]

# The three seeded random gate spots (seed 115) among the excerpt
# instruction addresses.
SPOTS = [0x620691B, 0x62019C8, 0x6200D0C]

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
            (0x64D9308, "N7rocksdb16TtlMergeOperatorE"),
            (0x64D92F0, "N7rocksdb26TtlCompactionFilterFactoryE"),
            (0x64D92D8, "N7rocksdb19TtlCompactionFilterE")):
        ptr = rel.get(ti + 8)
        end = data.find(b"\x00", ptr)
        if data[ptr:end].decode() != name:
            fail("typeinfo 0x%x name mismatch" % ti)
    for lit in records["literals"]:
        addr = int(lit["addr"], 16)
        end = data.find(b"\x00", addr)
        if data[addr:end].decode() != lit["value"]:
            fail("literal %s mismatch" % lit["addr"])
    # The legacy IsInstanceOf names are movabs immediates in the excerpts.
    mo_isinst = (PACKET / "excerpts" /
                 "mo-isinstanceof-6202520.objdump.txt").read_text()
    if "794220656772654d" not in mo_isinst.replace(" ", ""):
        fail("mo-isinstanceof excerpt missing 'Merge By' movabs")
    cf_isinst = (PACKET / "excerpts" /
                 "cf-isinstanceof-6202440.objdump.txt").read_text()
    if "42206574656c6544" not in cf_isinst.replace(" ", ""):
        fail("cf-isinstanceof excerpt missing 'Delete B' movabs")
    print("typeinfos and literals ok")

    # 9. Census reproduction (callers.tsv / relocations.txt / frames.txt).
    with tempfile.TemporaryDirectory() as tmp:
        tmp_pack = Path(tmp)
        census_src = (PACKET / "census.py").read_text()
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
    # Records cross-checks: the vtable maps against fresh relocations.
    vmap = {
        0x64D9558: [0x6203B80, 0x6203C30, 0x609D760, 0x609DC40, 0x5D32560,
                    0x6200B70, 0x6200E10, 0x5D2E090, 0x60956F0, 0x609D0E0,
                    0x60986B0, 0x6095710, 0x609DE80, 0x609D980, 0x6200930,
                    0x5D32A30, 0x6202520, 0x6200940, 0x5D2CA10, 0x5D2CD80,
                    0x6206610, 0x5D2CD90, 0x6201C90, 0x5D2CDA0, 0x5D2CDB0],
        0x64D9630: [0x62018F0, 0x62019A0, 0x609D760, 0x609DC40, 0x5D32560,
                    0x6200BF0, 0x6200CF0, 0x5D2E090, 0x60956F0, 0x609D0E0,
                    0x60986B0, 0x6095710, 0x609DE80, 0x609D980, 0x6200900,
                    0x5D32A30, 0x6202440, 0x62008E0, 0x5D2CA10, 0x6203520,
                    0x5D2CA30, 0x5D2E4A0, 0x5D2F8A0, 0x5D2CA40, 0x5DF72F0,
                    0x5D2CA50, 0x5D2CA60],
        0x64D9718: [0x6203AD0, 0x6203CE0, 0x609D760, 0x609DC40, 0x5D32560,
                    0x6200C70, 0x6200D80, 0x5D2E090, 0x60956F0, 0x609D0E0,
                    0x60986B0, 0x6095710, 0x609DE80, 0x609D980, 0x6200910,
                    0x5D32A30, 0x5D2E770, 0x6200920, 0x5D2CA10, 0x5D2CA70,
                    0x6202BA0],
    }
    for vtab, slots in vmap.items():
        for i, slot in enumerate(slots):
            if rel.get(vtab + 8 * i) != slot:
                fail("vtable 0x%x slot %d mismatch" % (vtab, i))
    # The CFF boundary: no relocation at the would-be slot 21.
    if 0x64D97C0 in rel:
        fail("CFF boundary: unexpected relocation at 0x64d97c0")
    if rel.get(0x64D97C8) != 0x64D92A8:
        fail("DBWithTTLImpl typeinfo mismatch")
    # The records vtable maps must match the same slots.
    for key, vtab in (("TtlMergeOperator", 0x64D9558),
                      ("TtlCompactionFilter", 0x64D9630),
                      ("TtlCompactionFilterFactory", 0x64D9718)):
        rec_slots = records["vtables"][key]["slots"]
        if [int(a, 16) for _, a, _ in rec_slots] != vmap[vtab]:
            fail("records vtable map mismatch for %s" % key)
    callers = (PACKET / "callers.tsv").read_text()
    for needle in ("0x620683f", "0x62068aa", "0x62068d3",
                   "0x62066c2", "0x6202c01", "0x620355f", "0x6202c43"):
        if needle not in callers:
            fail("callers.tsv missing site %s" % needle)
    for name, _, _ in WINDOWS:
        if (PACKET / "excerpts" / name).stat().st_size == 0:
            fail("empty excerpt %s" % name)
    print("records ok")

    # 11. Model behaviour + tests.
    spec = importlib.util.spec_from_file_location(
        "ttl_runtime_methods_115",
        ROOT / "tools" / "ttl_runtime_methods_115.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    clock = mod.Clock(500)
    wrapped = mod.RecordingMergeOperator(reply_value=b"merged-payload")
    ttl_mo = mod.TtlMergeOperator(wrapped, clock)
    log = mod.Logger()
    res = ttl_mo.full_merge_v2(b"k", b"old" + struct.pack("<I", 100),
                               [b"op1" + struct.pack("<I", 101)], log)
    if not res.ok or res.new_value != b"merged-payload" + struct.pack("<I", 500):
        fail("model full_merge_v2 mismatch")
    if wrapped.calls[0][2] != b"old" or wrapped.calls[0][3] != [b"op1"]:
        fail("model full_merge_v2 stripping mismatch")
    keep = mod.RecordingCompactionFilter(decision=mod.KEEP)
    ttl_cf = mod.TtlCompactionFilter(keep, 10, mod.Clock(200))
    if ttl_cf.filter(0, b"k", b"v" + struct.pack("<I", 100)) != (mod.REMOVE, None, False):
        fail("model filter expiry mismatch")
    if ttl_cf.filter(0, b"k", b"v" + struct.pack("<I", 195)) != (mod.KEEP, None, False):
        fail("model filter keep mismatch")
    if not ttl_mo.is_instance_of("Merge By TTL"):
        fail("model mo isinstance mismatch")
    if not ttl_cf.is_instance_of("Delete By TTL"):
        fail("model cf isinstance mismatch")
    if not mod.is_expired(b"v" + struct.pack("<I", 100), 10, mod.Clock(111)):
        fail("model expiry mismatch")
    if mod.is_expired(b"v" + struct.pack("<I", 0xFFFFFFF0), 0x20, mod.Clock(0x20)):
        fail("model expiry wrap mismatch (sum must not wrap)")
    result = subprocess.run(
        [sys.executable, "tests/test_ttl_runtime_methods_115.py"],
        cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        fail("model tests failed:\n" + result.stdout + result.stderr)
    print(result.stdout.strip())

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
