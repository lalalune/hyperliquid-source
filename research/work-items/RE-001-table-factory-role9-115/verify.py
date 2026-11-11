"""Checker for the RE-001-table-factory-role9-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-table-factory-role9-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary
(objdump splits a few long instructions across two lines; the
parser accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (81 records: the
five vtable groups plus the five typeinfo name pointers; no
pinned routine is installed by a RELATIVE record); the message
literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump);
the semantic records (re-deriving the lower_bound constants,
the tree-clone node size, the impl-ctor stores, the weak_ptr
self-initialization, the holder install, the vtable slot
tables against relocations.txt, and the typeinfo names via
c++filt); and the model tests in
tests/test_table_factory_role9_115.py.
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
    ("table_init.txt", 0x60DB710, 0x60DBD69),
    ("wrapper.txt", 0x60DBD80, 0x60DBDBB),
    ("tree_copy.txt", 0x60D7FB0, 0x60D8082),
    ("impl_ctor.txt", 0x5DB8800, 0x5DB886F),
    ("release.txt", 0x5D350C0, 0x5D35145),
    ("destroy_dispatch.txt", 0x5D35070, 0x5D350BC),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x60DB710: (3, 0), 0x60DBD80: (3, 0), 0x60D7FB0: (3, 0),
    0x5DB8800: (1, 0), 0x5D350C0: (1273, 25), 0x5D35070: (654, 36),
    0x63F0DD0: (1935, 0), 0x63F0D80: (11706, 898),
    0x63F1050: (28, 0), 0x63F0D70: (6391, 0),
}

EXPECTED_QWORDS = {}

EXPECTED_RELATIVE = {}

SPOT_BYTES = {
    0x60DB710: "f30f1efa",
    0x60DBD80: "f30f1efa",
    0x60D7FB0: "4155",
    0x5DB8800: "f30f1efa",
    0x5D350C0: "f30f1efa",
    0x5D35070: "f30f1efa",
    0x60DBA10: "83782008",
    0x60DBA54: "83782009",
    0x60DBAC0: "bf50000000",
    0x5DB8804: "488d0595197100",
    0x60D7FC5: "e8068e3100",
    0x60DBD0B: "e840533100",
    0x5D350C4: "48b80100000001000000",
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


def parse_text_excerpt(text):
    """[(address, mnemonic text)] for one excerpt."""
    out = []
    for line in text.splitlines():
        m = LINE_RE.match(line)
        if m:
            out.append((int(m.group(1), 16), m.group(3).strip()))
    return out


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
        if raw.hex() != expect:
            fail("spot %#x: %s != %s" % (addr, raw.hex(), expect))
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
    if len(stored) != 81:
        fail("relocation count %d != 81" % len(stored))
    for target, count in EXPECTED_RELATIVE.items():
        got = [o for o, a in relocs.items() if a == target]
        if len(got) != count:
            fail("RELATIVE count for %#x: %d != %d"
                 % (target, len(got), count))
    for target in EXPECTED_CENSUS:
        if target in EXPECTED_RELATIVE:
            continue
        got = [o for o, a in relocs.items() if a == target]
        if got:
            fail("unexpected RELATIVE records for %#x: %s" % (target, got))
    print("relocations ok (%d records)" % len(stored))


def check_literals(segments, data, records):
    for lit in records["literals"]:
        addr = int(lit["address"], 16)
        off = va_to_off(segments, addr)
        if off is None:
            fail("literal %s: no file offset" % lit["address"])
        if "bytes" in lit:
            want = bytes.fromhex(lit["bytes"])
            if data[off:off + len(want)] != want:
                fail("literal bytes mismatch at %s" % lit["address"])
        else:
            want = lit["text"].encode() + b"\x00"
            if data[off:off + len(want)] != want:
                fail("literal text mismatch at %s" % lit["address"])
    print("literals ok (%d)" % len(records["literals"]))


# ----------------------------------------------------------------
# Census re-derivation (imports the packet's census module).
# ----------------------------------------------------------------

def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", PACKET / "census.py")
    census = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(census)
    data = BINARY.read_bytes()
    sites = census.disassembly_sites()
    relocs, _lines = census.relative_records()
    ranges = census.frame_ranges()
    for target, (want_calls, want_jumps) in EXPECTED_CENSUS.items():
        calls, jumps = census.scan(sites, target)
        if len(calls) != want_calls or len(jumps) != want_jumps:
            fail("census for %#x: calls=%d jumps=%d, want %d/%d"
                 % (target, len(calls), len(jumps),
                    want_calls, want_jumps))
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
        want = census.enclosing_fde(ranges, int(site, 16))
        if caller != want:
            fail("callers.tsv caller for %s: %s != %s"
                 % (site, caller, want))
    expect_rows = []
    for target in sorted(EXPECTED_CENSUS):
        calls, jumps = census.scan(sites, target)
        for site in calls:
            expect_rows.append((site, target, "call"))
        for site in jumps:
            expect_rows.append((site, target, "tail jump"))
    expect_rows.sort()
    got_rows = sorted((s, t, k) for s, t, _c, k in rows)
    if got_rows != expect_rows:
        fail("callers.tsv rows do not match a fresh census run")
    print("census ok (%d rows)" % len(rows))


# ----------------------------------------------------------------
# Semantic-record re-derivation from the excerpts.
# ----------------------------------------------------------------

def _ins_by_addr(name):
    text = (PACKET / name).read_text()
    return dict(parse_text_excerpt(text))


def check_records(segments, data, records):
    # The records census section must agree with the verify
    # expectations, and every pinned routine has no stored
    # qwords and no RELATIVE records naming it.
    for addr_hex, entry in records["census"].items():
        target = int(addr_hex, 16)
        want_calls, want_jumps = EXPECTED_CENSUS[target]
        if (entry["calls"], entry["jumps"]) != (want_calls, want_jumps):
            fail("records census for %#x disagrees with verify" % target)
        if entry["qwords"] or entry["relative"]:
            fail("records census for %#x has qwords/relocations" % target)

    table = (PACKET / "table_init.txt").read_text()
    tree = (PACKET / "tree_copy.txt").read_text()
    ctor = (PACKET / "impl_ctor.txt").read_text()
    rel = (PACKET / "release.txt").read_text()

    # The lower_bound constants and the map::at throw.
    for needle in ("cmpl   $0x8,0x20(%rax)", "cmpl   $0x9,0x20(%rax)",
                   "# 4408a7", "call   60d7fb0", "call   5db8800",
                   "call   5d350c0", "# 459b20"):
        if needle not in table:
            fail("table_init line missing: %s" % needle)
    # The tree population call and the header wiring.
    for needle in ("call   60d7fb0", "mov    %rax,0xb0(%rbx)",
                   "mov    %rcx,0xb8(%rbx)", "mov    %rcx,0xc0(%rbx)",
                   "mov    %rdx,0xc8(%rbx)"):
        if needle not in table:
            fail("table_init tree line missing: %s" % needle)
    # The holder build: three allocations and the install.
    for needle in ("mov    $0x50,%edi", "mov    $0x78,%edi",
                   "mov    $0x18,%edi",
                   "mov    %rbp,0x118(%rbx)", "mov    %r12,0x120(%rbx)",
                   "mov    %r12,0x48(%rbp)",
                   "mov    %rbp,0x8(%rbp)", "mov    %rax,0x18(%r12)"):
        if needle not in table:
            fail("table_init holder line missing: %s" % needle)
    # The tree clone: 0x28-byte nodes, key+value copy.
    for needle in ("mov    $0x28,%edi", "mov    0x20(%rbx),%rax",
                   "mov    (%rbx),%eax"):
        if needle not in tree:
            fail("tree_copy line missing: %s" % needle)
    # The impl ctor: vtable install, shared_ptr copy, flag byte.
    for needle in ("# 64ca1a0", "movups %xmm0,0x18(%rdi)",
                   "mov    %dl,0x28(%rdi)", "movq   $0x0,0x50(%rdi)"):
        if needle not in ctor:
            fail("impl_ctor line missing: %s" % needle)
    # The release helper: the {1,1} fast path and the cross-FDE jump.
    for needle in ("movabs $0x100000001,%rax", "jmp    5d35070"):
        if needle not in rel:
            fail("release line missing: %s" % needle)
    if "call   *0x10(%rax)" not in (PACKET / "destroy_dispatch.txt").read_text():
        fail("destroy dispatch slot-2 call missing")
    # The wrapper: 0x260-byte allocation and the copy call.
    wrapper = (PACKET / "wrapper.txt").read_text()
    for needle in ("mov    $0x260,%edi", "call   60db710"):
        if needle not in wrapper:
            fail("wrapper line missing: %s" % needle)

    # The vtable slot tables in the model must match the
    # RELATIVE records stored in relocations.txt.
    sys.path.insert(0, str(ROOT / "tools"))
    from table_factory_role9_115 import VTABLE_SLOTS
    stored = {}
    for line in (PACKET / "relocations.txt").read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split()
        stored[int(parts[0], 16)] = int(parts[3], 16)
    for vptr, slots in VTABLE_SLOTS.items():
        for off, addend in slots.items():
            if stored.get(vptr + off) != addend:
                fail("vtable slot %#x+%#x: %#x != %#x"
                     % (vptr, off, stored.get(vptr + off, -1), addend))
    total = sum(len(s) for s in VTABLE_SLOTS.values())
    if total != 76:
        fail("vtable slot total %d != 76" % total)

    # The typeinfo names demangle to the recorded class names.
    expect = {
        "N7rocksdb22BlockBasedTableFactoryE": "BlockBasedTableFactory",
        "N7rocksdb33ConcurrentCacheReservationManagerE":
            "ConcurrentCacheReservationManager",
        "N7rocksdb27CacheReservationManagerImplILNS_14CacheEntryRoleE9EEE":
            "CacheReservationManagerImpl<(rocksdb::CacheEntryRole)9>",
        "St15_Sp_counted_ptrIPN7rocksdb33ConcurrentCacheReservationManagerELN9__gnu_cxx12_Lock_policyE2EE":
            "_Sp_counted_ptr<rocksdb::ConcurrentCacheReservationManager*",
        "St23_Sp_counted_ptr_inplaceIN7rocksdb27CacheReservationManagerImplILNS0_14CacheEntryRoleE9EEESaIvELN9__gnu_cxx12_Lock_policyE2EE":
            "_Sp_counted_ptr_inplace<rocksdb::CacheReservationManagerImpl",
    }
    for lit in records["literals"]:
        name = lit.get("text")
        if name is None or name not in expect:
            continue
        out = subprocess.run(["c++filt", "_ZTI" + name],
                             capture_output=True, text=True,
                             check=True).stdout.strip()
        if expect[name] not in out:
            fail("typeinfo %s demangles to %s" % (name, out))
    print("records ok (lookup, clone, holder, vtables, typeinfo)")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_table_factory_role9_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "all 99 checks passed" not in out.stdout:
        fail("model tests failed:\n%s\n%s" % (out.stdout, out.stderr))
    print("model tests ok (99 checks)")


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
