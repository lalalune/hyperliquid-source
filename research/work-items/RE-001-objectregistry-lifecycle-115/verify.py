"""Checker for the RE-001-objectregistry-lifecycle-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-objectregistry-lifecycle-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary
(three random ones among them, seed 115: 0x61f8ff6, 0x5ff7a7c,
0x61f8242); the FDE ranges in frames.txt against a fresh frame
dump; the relocation set against a fresh relocation dump (20
records: the PatternEntry + ObjectRegistry control-block
vtable region and the _Sp_make_shared_tag GOT slot); the
string literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned routine's
direct calls, tail jumps, lea references, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump); the
semantic records (re-deriving the census entries, the
relocation rows, the caller lists, the vtable map, the
typeinfo names, the excerpt needles and the model behaviour);
and the model tests in tests/test_objectregistry_lifecycle_115.py.
Prints ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("cb-d1-61f8130.objdump.txt", 0x61F8130, 0x61F8135),
    ("cb-d0-61f8140.objdump.txt", 0x61F8140, 0x61F814E),
    ("cb-dispose-61f8760.objdump.txt", 0x61F8760, 0x61F89DB),
    ("cb-destroy-61f8170.objdump.txt", 0x61F8170, 0x61F817E),
    ("cb-getdeleter-61f8180.objdump.txt", 0x61F8180, 0x61F81C7),
    ("rec-destroy-61f81d0.objdump.txt", 0x61F81D0, 0x61F8271),
    ("lockguard-61f814e.objdump.txt", 0x61F814E, 0x61F8165),
    ("vec-sp-destroy-61f89e0.objdump.txt", 0x61F89E0, 0x61F8AC1),
    ("vec-insert-5ff7960.objdump.txt", 0x5FF7960, 0x5FF7B45),
    ("add-library-61f8dc0.objdump.txt", 0x61F8DC0, 0x61F913D),
    ("add-library-landingpads-61f8d12.objdump.txt", 0x61F8D12, 0x61F8DB1),
    ("reg-ctor-61f91b0.objdump.txt", 0x61F91B0, 0x61F9277),
    ("ctor-landingpad-61f913e.objdump.txt", 0x61F913E, 0x61F91A6),
    ("reg-getter-61f92b0.objdump.txt", 0x61F92B0, 0x61F93C5),
    ("getter-landingpad-61f9278.objdump.txt", 0x61F9278, 0x61F92A2),
    ("clone-61f9400.objdump.txt", 0x61F9400, 0x61F963E),
    ("clone-landingpad-61f93c6.objdump.txt", 0x61F93C6, 0x61F93F2),
    ("ttl-register-62069f0.objdump.txt", 0x62069F0, 0x6206D29),
    ("registrar-init-620b470.objdump.txt", 0x620B470, 0x620B57D),
]

# (target, expected direct calls, expected tail jumps, expected leas)
EXPECTED_CENSUS = {
    0x5FF7960: (4, 0, 0),
    0x61F8130: (0, 0, 0),
    0x61F8140: (0, 0, 0),
    0x61F814E: (1, 0, 0),
    0x61F8170: (0, 0, 0),
    0x61F8180: (0, 0, 0),
    0x61F81D0: (3, 0, 0),
    0x61F8760: (0, 0, 0),
    0x61F89E0: (1, 0, 0),
    0x61F8DC0: (1, 0, 0),
    0x61F91B0: (1, 0, 0),
    0x61F92B0: (3, 0, 0),
    0x61F9400: (1, 0, 0),
    0x62069F0: (0, 0, 1),
    0x620B470: (0, 0, 0),
}

# File offsets of 8-byte-aligned qwords equal to the target.
EXPECTED_QWORDS = {
    0x61F8130: ['0x12bc80'],
    0x61F8140: ['0x12bc98'],
    0x61F8170: ['0x12bcc8'],
    0x61F8180: ['0x12bce0'],
    0x61F8760: ['0x12bcb0'],
    0x620B470: ['0x7ba0'],
}

# Number of RELATIVE records whose addend is the target.
EXPECTED_RELATIVE = {
    0x61F8130: 1,
    0x61F8140: 1,
    0x61F8170: 1,
    0x61F8180: 1,
    0x61F8760: 1,
    0x620B470: 1,
}

# The stored relocations.txt rows: (offset, addend).
EXPECTED_RELOCATIONS = [
    (0x64d8e80, 0x5d2cdb0), (0x64d8e88, 0x61f8100),
    (0x64d8e98, 0x97fbe0), (0x64d8ea0, 0x64cd990),
    (0x64d8eb0, 0x97fc20), (0x64d8eb8, 0x64c81a8),
    (0x64d8ec8, 0x64d8e90), (0x64d8ed0, 0x5ff2030),
    (0x64d8ed8, 0x5ff2150), (0x64d8ee0, 0x61f8670),
    (0x64d8ee8, 0x61f8120), (0x64d8ef8, 0x64d8ea8),
    (0x64d8f00, 0x61f8130), (0x64d8f08, 0x61f8140),
    (0x64d8f10, 0x61f8760), (0x64d8f18, 0x61f8170),
    (0x64d8f20, 0x61f8180), (0x64d8f30, 0x97fc80),
    (0x64d8f40, 0x97fcc0), (0x64ecdc8, 0x96cb48),
]

SPOT_BYTES = {
    0x61F8130: bytes.fromhex("f30f1efa"),
    0x61F8140: bytes.fromhex("f30f1efa"),
    0x61F8760: bytes.fromhex("f30f1efa"),
    0x61F8170: bytes.fromhex("f30f1efa"),
    0x61F8180: bytes.fromhex("f30f1efa"),
    0x61F81D0: bytes.fromhex("4885ff"),
    0x61F814E: bytes.fromhex("53"),
    0x61F89E0: bytes.fromhex("f30f1efa"),
    0x5FF7960: bytes.fromhex("f30f1efa"),
    0x61F8DC0: bytes.fromhex("f30f1efa"),
    0x61F8D12: bytes.fromhex("4885db"),
    0x61F91B0: bytes.fromhex("f30f1efa"),
    0x61F913E: bytes.fromhex("488b7d68"),
    0x61F92B0: bytes.fromhex("f30f1efa"),
    0x61F9278: bytes.fromhex("bed0000000"),
    0x61F9400: bytes.fromhex("f30f1efa"),
    0x61F93C6: bytes.fromhex("488b7c2408"),
    0x62069F0: bytes.fromhex("f30f1efa"),
    0x620B470: bytes.fromhex("f30f1efa"),
    # Seeded-random gate spots (seed 115).
    0x61F8FF6: bytes.fromhex("4889da"),
    0x5FF7A7C: bytes.fromhex("4829ee"),
    0x61F8242: bytes.fromhex("740c"),
}
TAB = chr(9)
LINE_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?)" + TAB + "(.*)$")
CONT_RE = re.compile("^ *([0-9a-f]+):" + TAB + "([0-9a-f ]+?) *$")


def fail(message):
    raise AssertionError(message)


def load_segments(data):
    """(offset, vaddr, filesz) for every PT_LOAD segment."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _f, p_offset, p_vaddr, _p, p_filesz,
         _m, _a) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            out.append((p_offset, p_vaddr, p_filesz))
    return out


def va_to_off(segments, va):
    for off, vaddr, size in segments:
        if vaddr <= va < vaddr + size:
            return off + (va - vaddr)
    return None


def parse_excerpt(text):
    """[(address, bytes)] for one excerpt, merging objdump
    continuation lines into the previous instruction."""
    ins = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            raw = m.group(2).replace(" ", "")
            ins.append([int(m.group(1), 16), bytes.fromhex(raw)])
            continue
        m = CONT_RE.match(line)
        if m and ins:
            raw = m.group(2).replace(" ", "")
            ins[-1][1] += bytes.fromhex(raw)
            continue
    return [(a, b) for a, b in ins]


def check_digest(data):
    got = hashlib.sha256(data).hexdigest()
    if got != DIGEST:
        fail("binary digest mismatch: %s != %s" % (got, DIGEST))
    print("digest ok")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    seen = set()
    for line in lines:
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        name = name.lstrip("*").strip()
        seen.add(name)
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != digest:
            fail("manifest mismatch for %s" % name)
    files = {p.name for p in PACKET.iterdir()
             if p.is_file() and p.name != "MANIFEST.sha256"}
    if seen != files:
        fail("manifest file set mismatch: extra=%s missing=%s"
             % (sorted(seen - files), sorted(files - seen)))
    print("manifest ok (%d files)" % len(seen))


def check_excerpts(segments, data):
    for name, start, stop in WINDOWS:
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if fresh != stored:
            fail("excerpt %s does not match a fresh objdump run" % name)
        for addr, raw in parse_excerpt(stored):
            off = va_to_off(segments, addr)
            if off is None:
                fail("excerpt %s: no file offset for %#x" % (name, addr))
            if data[off:off + len(raw)] != raw:
                fail("excerpt %s: bytes mismatch at %#x" % (name, addr))
    print("excerpts ok (%d windows)" % len(WINDOWS))


def check_spots(segments, data):
    for addr, expect in SPOT_BYTES.items():
        fresh = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % addr,
             "--stop-address=%#x" % (addr + 16),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True,
            cwd=ROOT).stdout
        ins = parse_excerpt(fresh)
        if not ins or ins[0][0] != addr:
            fail("spot %#x: no instruction at that address" % addr)
        raw = ins[0][1]
        if raw != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect.hex()))
        off = va_to_off(segments, addr)
        if data[off:off + len(raw)] != raw:
            fail("spot %#x: raw binary mismatch" % addr)
    print("spots ok (%d)" % len(SPOT_BYTES))


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    fresh = set()
    for m in re.finditer("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", text):
        fresh.add((int(m.group(1), 16), int(m.group(2), 16)))
    for line in (PACKET / "frames.txt").read_text().splitlines():
        m = re.search("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", line)
        if not m:
            if not line.strip() or line.startswith("start"):
                continue
            fail("frames.txt line has no pc range: %s" % line)
        pair = (int(m.group(1), 16), int(m.group(2), 16))
        if pair not in fresh:
            fail("FDE %#x..%#x not in a fresh frame dump" % pair)
    print("frames ok")


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if not m or m.group(3) != "RELATIVE" or m.group(4) is None:
            continue
        relocs[int(m.group(1), 16)] = int(m.group(4), 16)
    stored = []
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        stored.append((int(parts[0], 16), int(parts[3], 16)))
        if relocs.get(int(parts[0], 16)) != int(parts[3], 16):
            fail("relocation %s not in a fresh dump" % line)
    if len(stored) != len(EXPECTED_RELOCATIONS):
        fail("relocation count %d != %d"
             % (len(stored), len(EXPECTED_RELOCATIONS)))
    if sorted(stored) != sorted(EXPECTED_RELOCATIONS):
        fail("stored relocation set mismatch")
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    print("relocations ok (%d records)" % len(stored))


def check_literals(segments, data, records):
    for lit in records["literals"]:
        addr = lit["addr"]
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %#x: no file offset" % addr)
        if off != lit["offset"]:
            fail("literal %#x offset %#x != %#x" % (addr, off, lit["offset"]))
        if lit["text"].startswith("<"):
            if addr == 0x459B20:
                want = struct.pack("<Q", 0x100000001)
            else:
                fail("unknown special literal %#x" % addr)
        else:
            want = lit["text"].encode() + b"\x00"
        if data[off:off + len(want)] != want:
            fail("literal %#x mismatch" % addr)
    print("literals ok (%d)" % len(records["literals"]))


def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for target, (want_calls, want_jumps, want_leas) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        if (len(calls), len(jumps), len(leas)) != (want_calls, want_jumps, want_leas):
            fail("census for %#x: calls=%d jumps=%d leas=%d, want %d/%d/%d"
                 % (target, len(calls), len(jumps), len(leas),
                    want_calls, want_jumps, want_leas))
        qw = census.qwords(data, target)
        want_qw = [int(x, 16)
                   for x in EXPECTED_QWORDS.get(target, [])]
        if qw != want_qw:
            fail("qwords for %#x: %s != %s" % (target, qw, want_qw))
        rel = sorted(o for o, a in relocs.items() if a == target)
        want_rel = EXPECTED_RELATIVE.get(target, 0)
        if len(rel) != want_rel:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(rel), want_rel))
    rows = []
    for line in (PACKET / "callers.tsv").read_text().splitlines()[1:]:
        if not line.strip():
            continue
        site, target, caller, kind = line.split("\t")
        rows.append((int(site, 16), int(target, 16), caller, kind))
        want = census.enclosing_fde(ordered, starts, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        leas = sites.get(target, ([], [], []))[2]
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
        for site in leas:
            expect_rows.append((site, target, "lea"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


def check_records(segments, data, records):
    spec = importlib.util.spec_from_file_location(
        "packet_census_rel", PACKET / "census.py")
    census_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census_mod)
    full_relocs, _lines = census_mod.relative_records()
    sites = census_mod.disassembly_sites()

    # Census entries re-derive from a fresh run.
    for key, entry in records["census"]["targets"].items():
        target = int(key, 16)
        if target not in EXPECTED_CENSUS:
            fail("records census has an unexpected target %#x" % target)
        want = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"], entry["leas"]) != want:
            fail("records census for %#x: %s != %s"
                 % (target, (entry["calls"], entry["jumps"], entry["leas"]),
                    want))
        if entry["qwords"] != len(EXPECTED_QWORDS.get(target, [])):
            fail("records qword count for %#x: %d != %d"
                 % (target, entry["qwords"],
                    len(EXPECTED_QWORDS.get(target, []))))
        if entry["relative"] != EXPECTED_RELATIVE.get(target, 0):
            fail("records RELATIVE count for %#x: %d != %d"
                 % (target, entry["relative"],
                    EXPECTED_RELATIVE.get(target, 0)))
    if len(records["census"]["targets"]) != len(EXPECTED_CENSUS):
        fail("records census target count mismatch")
    if records["census"]["relocation_records"] != 20:
        fail("records relocation total != 20")
    if records["census"]["callers_tsv_rows"] != 16:
        fail("records callers.tsv row count != 16")
    if records["test_checks"] != 27:
        fail("records test_checks != 27")
    if records["target"]["sha256"] != DIGEST:
        fail("records target digest mismatch")

    # The relocation rows re-derive from a fresh readelf dump.
    for row in records["relocations"]:
        if full_relocs.get(row["offset"]) != row["addend"]:
            fail("records relocation %#x not in a fresh dump"
                 % row["offset"])
    if sorted((r["offset"], r["addend"]) for r in records["relocations"]) \
            != sorted(EXPECTED_RELOCATIONS):
        fail("records relocation set mismatch")

    # Caller lists re-derive from a fresh census run.
    def call_sites(target):
        return ["%#x" % s for s in
                census_mod.scan(sites, target)[0]]

    def lea_sites(target):
        return ["%#x" % s for s in
                sites.get(target, ([], [], []))[2]]

    def addr_list(entries):
        return [e.split()[0] for e in entries]

    if call_sites(0x61F92B0) != addr_list(records["reg_getter"]["callers"]):
        fail("getter caller mismatch")
    if call_sites(0x61F9400) != addr_list(records["clone"]["callers"]):
        fail("clone caller mismatch")
    if call_sites(0x61F8DC0) != addr_list(records["add_library"]["callers"]):
        fail("add-library caller mismatch")
    if call_sites(0x61F91B0) != addr_list(records["reg_ctor"]["callers"]):
        fail("ctor caller mismatch")
    if call_sites(0x5FF7960) != addr_list(records["vec_insert"]["callers"]):
        fail("vec-insert caller mismatch")
    if call_sites(0x61F81D0) != addr_list(records["rec_destroy"]["callers"]):
        fail("rec-destroy caller mismatch")
    if call_sites(0x61F814E) != addr_list(records["lockguard"]["callers"]):
        fail("lockguard caller mismatch")
    if call_sites(0x61F89E0) != addr_list(records["vec_sp_destroy"]["callers"]):
        fail("vec-sp-destroy caller mismatch")
    if lea_sites(0x62069F0) != addr_list(records["ttl_register"]["lea_sites"]):
        fail("TTL lea sites mismatch")

    # Vtable map re-derives from a fresh readelf dump.
    def vtable_map(base, nslots):
        return ["0x%x" % full_relocs.get(base + i * 8, 0)
                for i in range(nslots)]

    ob = records["object_registry_cb_vtable"]
    if vtable_map(0x64D8F00, 5) != [
            "0x%x" % s["addr"] for s in ob["slots"]]:
        fail("ObjectRegistry control-block vtable map mismatch")
    cb = records["control_block"]
    # The ObjectLibrary control-block vtable at 0x64d00f0 is
    # #3983's territory; this packet cites it by contract only.

    # Typeinfo names.
    if cb["typeinfo"] != ("St23_Sp_counted_ptr_inplace"
                          "IN7rocksdb14ObjectRegistryESaIvE"
                          "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("control-block typeinfo mismatch")
    if ob["typeinfo"] != ("St23_Sp_counted_ptr_inplace"
                          "IN7rocksdb14ObjectRegistryESaIvE"
                          "LN9__gnu_cxx12_Lock_policyE2EE"):
        fail("ObjectRegistry control-block typeinfo mismatch")

    # Excerpt needles for the pinned semantics.
    def excerpt(name):
        return (PACKET / name).read_text()

    getter = excerpt("reg-getter-61f92b0.objdump.txt")
    for needle in ("# 6509100", "# 459b20", "# 64d8ef0"):
        if needle not in getter:
            fail("getter line missing: %s" % needle)
    dispose = excerpt("cb-dispose-61f8760.objdump.txt")
    for needle in ("call   61f81d0", "call   5d35070"):
        if needle not in dispose:
            fail("cb dispose line missing: %s" % needle)
    rec = excerpt("rec-destroy-61f81d0.objdump.txt")
    if "call   61f81d0" not in rec:
        fail("rec-destroy must recurse on itself")
    add = excerpt("add-library-61f8dc0.objdump.txt")
    for needle in ("call   5ff7960", "# 64d00e0"):
        if needle not in add:
            fail("add-library line missing: %s" % needle)
    ctor = excerpt("reg-ctor-61f91b0.objdump.txt")
    for needle in ("# 6509540", "call   5ff7960", "call   61f8dc0"):
        if needle not in ctor:
            fail("ctor line missing: %s" % needle)
    clone = excerpt("clone-61f9400.objdump.txt")
    if "call   61f92b0" not in clone:
        fail("clone must call the getter")
    ttl = excerpt("ttl-register-62069f0.objdump.txt")
    for needle in ("call   61f92b0", "call   5ff7960"):
        if needle not in ttl:
            fail("TTL line missing: %s" % needle)
    vec = excerpt("vec-insert-5ff7960.objdump.txt")
    for needle in ("lock addl $0x1,0x8(%rax)", "shl    $0x4,%r14"):
        if needle not in vec:
            fail("vec-insert line missing: %s" % needle)
    init = excerpt("registrar-init-620b470.objdump.txt")
    for needle in ("# 965c68", "# 44eed4", "# 95b628"):
        if needle not in init:
            fail("registrar-init line missing: %s" % needle)

    # The model constants and behaviour.
    sys.path.insert(0, str(ROOT / "tools"))
    import objectregistry_lifecycle_115 as model
    if model.CONTROL_BLOCK_VTABLE != 0x64D8F00:
        fail("model control-block vtable mismatch")
    if model.FRESH_COUNTS != 0x100000001:
        fail("model fresh counts mismatch")
    if model.OBJECT_SIZE != 0xC0 or model.BLOCK_SIZE != 0xD0:
        fail("model size mismatch")
    if model.MUTEX_OFFSET != 0x98 or model.PARENT_OFFSET != 0x60:
        fail("model layout mismatch")
    registry = model.singleton()
    if [s.obj.name for s in registry.libraries.items] != ["default"]:
        fail("model singleton seed mismatch")
    child = registry.clone()
    if child.parent.obj is not registry:
        fail("model clone parent mismatch")
    if child.libraries.items or child.map.count != 0:
        fail("model clone must be otherwise empty")
    child.dispose()
    if child.parent is not None:
        fail("model clone dispose must release the parent")
    print("records ok (census, relocations, callers, vtable, "
          "typeinfo, excerpts, model)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "-m", "pytest",
         "tests/test_objectregistry_lifecycle_115.py", "-q"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "27 passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (27 tests)")


def main():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())
    check_digest(data)
    check_manifest()
    check_excerpts(segments, data)
    check_spots(segments, data)
    check_frames()
    check_relocations()
    check_literals(segments, data, records)
    check_census()
    check_records(segments, data, records)
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
