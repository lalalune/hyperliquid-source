"""Checker for the RE-001-ts-gate-ops-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-ts-gate-ops-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run (the
five inner appenders, the batch constructor/destructor, the
strdup helper, the Status builder and the default getter are
re-shipped byte-identical from PR #3209 and PR #3202, so they
are checked by their pinned SHA-256 instead); every excerpt
instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (the
WriteBatch vtable range plus every RELATIVE record naming a
pinned routine; the gate, hex/nibble helpers, resolver,
constructor, strdup helper, Status builder and four of the
implementations appear in none); the message literals against
the raw binary; census consistency (callers.tsv against a
fresh census run: every pinned routine's direct calls, tail
jumps, stored qwords and RELATIVE addends, and the
callers.tsv caller function against the smallest enclosing
FDE range from a fresh frame dump); the semantic records
(re-deriving the record-type bytes from the inner excerpts,
the vtable slots from the relocation set, the 0xe0 dispatch
from the implementation excerpts, the resolver call from
the middle excerpts, and the hex helper's nibble calls);
and the model tests. Prints ALL CHECKS PASSED on success,
else raises.
"""

import bisect
import hashlib
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

# Excerpts re-shipped byte-identical from PR #3209 (inners,
# batch ctor/dtor, strdup) and PR #3202 (status builder,
# default getter), pinned by SHA-256 of the source packets.
RESHIPPED_SHA256 = {
    "inner_put.txt":
        "1a45abb7ba99a2b2e55ce1224f47b6f5cf87ed1d6b648ceb6330dfc20d42a0fc",
    "inner_delete.txt":
        "6fc1e8fe37a085a16fdfae73b904e7dc92fd8355f45775f6c8d3c42cccc11ba9",
    "inner_singledelete.txt":
        "01e19a30a579af1636fbdd2fef31a320ac6b65d8f141c901b53bd9ff2e4f90ac",
    "inner_deleterange.txt":
        "ea29fddb329cc06cd0a62f14ebd662451db154f81fd581d2470223e2a470c360",
    "inner_merge.txt":
        "ad6c89fc451a22bd5f486b38f6e49dd0362ce31c952e22b69a655ee3297bcb42",
    "batch_ctor.txt":
        "d1f7b3fc0f4a7f0761d59669eb84850116dc060ff3504d1f6c54c81a4c2d47ae",
    "batch_dtor.txt":
        "4ff54457489286daa9dbef6faa6945a85fe0022f7165c383a41d34cd7ba97524",
    "strdup.txt":
        "33326ec0f3d23de6b82e0622858f82994d14a39dd900af9e43a3a07d6c9cec0f",
    "status_builder.txt":
        "5c716d61c200e269e3dd526816c760497c7ba042ee7eede755475c1cb3845f3d",
    "default_getter.txt":
        "381d79f37e54df2d07f8a2961b79ae24cc39b4c35008e1db07fb1d2985d49567",
}

WINDOWS = [
    ("gate_main.txt", 0x5E882B0, 0x5E8901D),
    ("hex_helper.txt", 0x61C7E30, 0x61C7FB6),
    ("nibble.txt", 0x61C7DA0, 0x61C7DB2),
    ("ok_stub.txt", 0x5D48400, 0x5D48407),
    ("resolver.txt", 0x5FB6910, 0x5FB6A30),
    ("wrap_put.txt", 0x5E94800, 0x5E9491C),
    ("wrap_delete.txt", 0x5E95040, 0x5E95156),
    ("wrap_singledelete.txt", 0x5E95560, 0x5E95676),
    ("wrap_deleterange.txt", 0x5E95AC0, 0x5E95BE0),
    ("wrap_merge.txt", 0x5E960A0, 0x5E961BC),
    ("impl_put.txt", 0x5E94690, 0x5E947B8),
    ("impl_delete.txt", 0x5E94EE0, 0x5E94FF8),
    ("impl_singledelete.txt", 0x5E95400, 0x5E95518),
    ("impl_deleterange.txt", 0x5E95950, 0x5E95A78),
    ("impl_merge.txt", 0x5E95F30, 0x5E96058),
    ("mid_put.txt", 0x5FBF7D0, 0x5FBF92F),
    ("mid_delete.txt", 0x5FC04F0, 0x5FC062F),
    ("mid_singledelete.txt", 0x5FC11E0, 0x5FC131F),
    ("mid_deleterange.txt", 0x5FC2080, 0x5FC21F7),
    ("mid_merge.txt", 0x5FC4220, 0x5FC437F),
    ("inner_put.txt", 0x5FBF0B0, 0x5FBF588),
    ("inner_delete.txt", 0x5FBFF40, 0x5FC02E8),
    ("inner_singledelete.txt", 0x5FC0C30, 0x5FC0FD8),
    ("inner_deleterange.txt", 0x5FC1980, 0x5FC1E23),
    ("inner_merge.txt", 0x5FC3B00, 0x5FC3FD8),
    ("batch_ctor.txt", 0x5FB9F90, 0x5FBA0BE),
    ("batch_dtor.txt", 0x5FB7EE0, 0x5FB7FB7),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("default_getter.txt", 0x5D48510, 0x5D4851C),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x5E882B0: (5, 0),
    0x5E94800: (0, 0), 0x5E95040: (0, 0), 0x5E95560: (0, 0),
    0x5E95AC0: (0, 0), 0x5E960A0: (0, 0),
    0x5E94690: (1, 0), 0x5E94EE0: (1, 0), 0x5E95400: (1, 0),
    0x5E95950: (1, 0), 0x5E95F30: (1, 0),
    0x5FBF7D0: (1, 0), 0x5FC04F0: (1, 0), 0x5FC11E0: (1, 0),
    0x5FC2080: (1, 0), 0x5FC4220: (1, 0),
    0x5FBF0B0: (4, 0), 0x5FBFF40: (4, 0), 0x5FC0C30: (4, 0),
    0x5FC1980: (4, 0), 0x5FC3B00: (4, 0),
    0x5FB6910: (5, 0), 0x61C7E30: (120, 0), 0x61C7DA0: (2, 0),
    0x5D48400: (0, 0), 0x5D48510: (0, 0),
    0x5FB9F90: (27, 0), 0x5FB7EE0: (65, 0),
    0x61CF610: (425, 0), 0x61CF670: (847, 0),
}

EXPECTED_QWORDS = {
    0x5E94800: ["0x103ea0", "0x1084a8", "0x109318", "0x10a488"],
    0x5E95040: ["0x103f18", "0x108520", "0x109390", "0x10a500"],
    0x5E95560: ["0x103f78", "0x108580", "0x1093f0", "0x10a560"],
    0x5E95AC0: ["0x103fd8", "0x1085e0", "0x109450", "0x10a5c0"],
    0x5E960A0: ["0x104020", "0x108628", "0x109498", "0x10a608"],
    0x5E95950: ["0x101800", "0x12d480"],
    0x5D48400: ["0x126d60", "0x127090", "0x15c5e0"],
    0x5D48510: ["0x104950", "0x108f58", "0x109dc8", "0x10af38"],
    0x5FB7EE0: ["0x10e310"],
    0x5FBF7D0: ["0x10e370"], 0x5FC04F0: ["0x10e478"],
    0x5FC11E0: ["0x10e4f0"], 0x5FC2080: ["0x10e568"],
    0x5FC4220: ["0x10e400"],
}

EXPECTED_RELATIVE = {
    0x5E94800: 4, 0x5E95040: 4, 0x5E95560: 4, 0x5E95AC0: 4,
    0x5E960A0: 4, 0x5E95950: 2, 0x5D48400: 3, 0x5D48510: 4,
    0x5FB7EE0: 1, 0x5FBF7D0: 1, 0x5FC04F0: 1, 0x5FC11E0: 1,
    0x5FC2080: 1, 0x5FC4220: 1,
}

SPOT_BYTES = {
    0x5E882B0: "4157",
    0x5E960A0: "f30f1efa",
    0x5FBF7D0: "f30f1efa",
    0x61C7E30: "f30f1efa",
    0x5FB6910: "55",
    0x5D48400: "f30f1efa",
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def check_digest():
    actual = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if actual != DIGEST:
        fail("digest mismatch: %s" % actual)
    provenance = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entries = [f for f in provenance["files"]
               if f["path"] == "artifacts/node/115/hl-node"]
    if not entries or entries[0]["sha256"] != DIGEST:
        fail("provenance entry mismatch")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    if not lines:
        fail("empty manifest")
    seen = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        seen.add(name)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)
    expected = {"README.md", "records.json", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
    expected |= {name for name, _s, _e in WINDOWS}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


_BINARY_DATA = None


def binary_data():
    global _BINARY_DATA
    if _BINARY_DATA is None:
        _BINARY_DATA = BINARY.read_bytes()
    return _BINARY_DATA


def va_bytes(vaddr, size):
    data = binary_data()
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            start = p_offset + (vaddr - p_vaddr)
            return data[start:start + size]
    fail("no LOAD segment for %#x" % vaddr)


def parse_excerpt(text):
    """Return [(address, bytes)] with split lines accumulated."""
    instructions = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if not mnemonic and instructions and address == instructions[-1][0] + len(instructions[-1][1]):
            instructions[-1] = (instructions[-1][0], instructions[-1][1] + raw)
        else:
            instructions.append((address, raw))
    return instructions


def check_excerpts():
    for name, start, stop in WINDOWS:
        stored = (PACKET / name).read_text()
        if name in RESHIPPED_SHA256:
            actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
            if actual != RESHIPPED_SHA256[name]:
                fail("%s is not the re-shipped excerpt" % name)
        else:
            text = subprocess.run(
                ["objdump", "-d", "--start-address=%#x" % start,
                 "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
                capture_output=True, text=True, check=True, cwd=ROOT).stdout
            if text != stored:
                fail("excerpt mismatch for %s" % name)
        instructions = parse_excerpt(stored)
        if not instructions or instructions[0][0] != start:
            fail("excerpt %s does not start at %#x" % (name, start))
        for address, raw in instructions:
            if va_bytes(address, len(raw)) != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if va_bytes(address, len(raw)) != raw:
            fail("spot raw byte mismatch at %#x" % address)
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % address,
             "--stop-address=%#x" % (address + 0x10),
             "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        instructions = parse_excerpt(text)
        if not instructions or instructions[0][0] != address:
            fail("spot objdump missing %#x" % address)
        if instructions[0][1] != raw:
            fail("spot objdump byte mismatch at %#x" % address)


_FRAME_RANGES = None


def frame_ranges():
    """All FDE pc ranges from a fresh frame dump (memoized: the
    dump is ~3.6M lines and parsing it dominates)."""
    global _FRAME_RANGES
    if _FRAME_RANGES is None:
        text = subprocess.run(
            ["readelf", "--debug-dump=frames", str(BINARY)],
            capture_output=True, text=True, check=True).stdout
        ranges = []
        for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
            ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
        _FRAME_RANGES = ranges
    return _FRAME_RANGES


def check_frames():
    fresh = set(frame_ranges())
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"(0x[0-9a-f]+)\.\.(0x[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without range: %s" % line)
        want = (int(match.group(1), 16), int(match.group(2), 16))
        if want not in fresh:
            fail("frame range missing: %s" % match.group(0))


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for target in (0x5E882B0, 0x61C7E30, 0x61C7DA0, 0x5FB6910,
                   0x5FB9F90, 0x61CF610, 0x61CF670,
                   0x5E94690, 0x5E94EE0, 0x5E95400, 0x5E95F30):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    targets = set(EXPECTED_CENSUS)
    want = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or "RELATIVE" not in line:
            continue
        offset = int(parts[0], 16)
        addend = int(parts[3], 16)
        if (0x64CD488 <= offset < 0x64CD600) or addend in targets:
            want.append(line)
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if stored != want:
        fail("relocations.txt mismatch: %d stored vs %d fresh"
             % (len(stored), len(want)))
    if len(want) != 74:
        fail("relocation count mismatch: %d" % len(want))


def check_literals():
    cases = [
        (0x960F08, 33, b"Timestamp sizes mismatch: expect "),
        (0x4360A5, 2, b", "),
        (0x4350BE, 6, b" given"),
        (0x9600B8, 41, b"cannot call this method on column family "),
        (0x95CCC0, 31, b" that does not enable timestamp"),
        (0x9600E8, 35, b"column family handle cannot be null"),
        (0x445389, 18, b"timestamp disabled"),
        (0x433186, 23, b"timestamp size mismatch"),
        (0x4350C5, 16, b"Read timestamp: "),
        (0x963E60, 38, b" is smaller than full_history_ts_low: "),
        (0x4376FD, 1, b"\x00"),
    ]
    for address, length, want in cases:
        if va_bytes(address, length) != want:
            fail("literal mismatch at %#x: %r" % (address, va_bytes(address, length)))


CENSUS_LINE_RE = re.compile(
    r"^0x([0-9a-f]+) calls=(\d+) (.*?) jumps=(\d+) (.*?) "
    r"qwords=(\d+) (.*?) relative=(\d+) (.*?)$")


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    census = {}
    for line in out.splitlines():
        match = CENSUS_LINE_RE.match(line)
        if not match:
            continue
        target = int(match.group(1), 16)
        calls = match.group(3).split() if int(match.group(2)) else []
        jumps = match.group(5).split() if int(match.group(4)) else []
        qwords = match.group(7).split() if int(match.group(6)) else []
        rels = match.group(9).split() if int(match.group(8)) else []
        census[target] = (calls, jumps, qwords, rels)
    if set(census) != set(EXPECTED_CENSUS):
        fail("census target set mismatch: %s"
             % sorted(set(census) ^ set(EXPECTED_CENSUS)))
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        elif kind == "tail jump":
            tsv_jumps.setdefault(target, []).append(site)
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    for target, (want_calls, want_jumps) in EXPECTED_CENSUS.items():
        calls, jumps, qwords, rels = census[target]
        if len(calls) != want_calls:
            fail("census call count mismatch for %#x: %d" % (target, len(calls)))
        if len(jumps) != want_jumps:
            fail("census jump count mismatch for %#x: %d" % (target, len(jumps)))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
        if sorted(qwords) != sorted(EXPECTED_QWORDS.get(target, [])):
            fail("census stored qwords mismatch for %#x: %s" % (target, qwords))
        if len(rels) != EXPECTED_RELATIVE.get(target, 0):
            fail("census RELATIVE mismatch for %#x: %d" % (target, len(rels)))
    ranges = frame_ranges()
    # FDEs are (nearly) disjoint, so the smallest enclosing
    # range for a site is found by bisect on the sorted
    # starts, with a bounded neighbourhood scan for duplicate
    # entries (.eh_frame + .debug_frame copies) and a full
    # scan as a correctness fallback.
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    for site, caller in tsv_callers.items():
        value = int(site, 16)
        idx = bisect.bisect_right(starts, value) - 1
        cands = []
        for j in range(max(0, idx - 2), min(len(ordered), idx + 3)):
            a, b = ordered[j]
            if a <= value < b:
                cands.append((a, b))
        if not cands:
            cands = [(a, b) for a, b in ranges if a <= value < b]
        if not cands:
            fail("no enclosing FDE for site %s" % site)
        a, b = min(cands, key=lambda ab: ab[1] - ab[0])
        if caller != "%#x..%#x" % (a, b):
            fail("caller mismatch for %s: %s vs %#x..%#x"
                 % (site, caller, a, b))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["gate"]["direct_calls"] != 5:
        fail("records gate call count mismatch")
    if records["gate"]["size_bytes"] != 3437:
        fail("records gate size mismatch")
    if records["resolver"]["size_bytes"] != 288:
        fail("records resolver size mismatch")
    if records["writebatch"]["typeinfo_name"] != "rocksdb::WriteBatch":
        fail("records typeinfo name mismatch")
    if records["writebatch"]["vtable"] != "0x64cd498":
        fail("records vtable address mismatch")
    # Re-derive the record-type bytes from the inner excerpts:
    # each inner writes its default-CF type byte and its with-CF
    # type byte at pinned sites (a movb into the rep_ buffer or
    # a stack slot, or a mov into %esi/%r8d before push_back).
    type_sites = {
        "put": ("inner_put.txt",
                "movb   $0x1,0x17(%rsp)", "mov    $0x5,%esi"),
        "delete": ("inner_delete.txt",
                   "movb   $0x0,(%rax,%r13,1)", "movb   $0x4,(%rax,%r13,1)"),
        "singledelete": ("inner_singledelete.txt",
                         "movb   $0x7,(%rax,%r13,1)", "movb   $0x8,(%rax,%r13,1)"),
        "deleterange": ("inner_deleterange.txt",
                        "movb   $0xf,(%rax,%r14,1)", "movb   $0xe,(%rax,%r14,1)"),
        "merge": ("inner_merge.txt",
                  "movb   $0x2,0x17(%rsp)", "mov    $0x6,%esi"),
    }
    type_bytes = {
        "put": (0x01, 0x05),
        "delete": (0x00, 0x04), "singledelete": (0x07, 0x08),
        "deleterange": (0x0F, 0x0E), "merge": (0x02, 0x06),
    }
    for op, (name, default_site, cf_site) in type_sites.items():
        text = (PACKET / name).read_text()
        if default_site not in text:
            fail("records %s default type site not in excerpt" % op)
        if cf_site not in text:
            fail("records %s CF type site not in excerpt" % op)
        rec = records["operations"][op]
        want_default, want_cf = type_bytes[op]
        if rec["record_type_default"] != "0x%02x" % want_default:
            fail("records %s default type mismatch" % op)
        if rec["record_type_cf"] != "0x%02x" % want_cf:
            fail("records %s CF type mismatch" % op)
        # The middle's vtable slot, re-derived from its RELATIVE
        # record in the census: slot = (offset - vtable base) / 8.
        rel = records["census"][rec["middle"]]["relative_offsets"]
        if len(rel) != 1:
            fail("records %s middle has %d RELATIVE records" % (op, len(rel)))
        slot = (int(rel[0], 16) - 0x64CD498) // 8
        if rec["vtable_slot"] != slot:
            fail("records %s vtable slot mismatch: %d vs %d"
                 % (op, rec["vtable_slot"], slot))
        # The implementation dispatches through virtual slot 0xe0.
        impl = (PACKET / ("impl_%s.txt" % op)).read_text()
        if "call   *0xe0(%rax)" not in impl:
            fail("records %s impl has no slot 0xe0 dispatch" % op)
        # The middle calls the resolver 0x5fb6910.
        mid = (PACKET / ("mid_%s.txt" % op)).read_text()
        if "call   5fb6910" not in mid:
            fail("records %s middle has no resolver call" % op)
        # Every wrapper passes flag 0 to the gate (xor %ecx,%ecx).
        wrap = (PACKET / ("wrap_%s.txt" % op)).read_text()
        if "xor    %ecx,%ecx" not in wrap:
            fail("records %s wrapper has no flag-0 setup" % op)
    # The hex helper calls the nibble helper twice.
    hex_text = (PACKET / "hex_helper.txt").read_text()
    if hex_text.count("call   61c7da0") != 2:
        fail("hex helper nibble calls missing")
    # The always-OK stub is endbr64; xor %eax,%eax; ret.
    stub = (PACKET / "ok_stub.txt").read_text()
    if "endbr64" not in stub or "xor    %eax,%eax" not in stub:
        fail("ok stub instructions missing")
    if "ret" not in stub:
        fail("ok stub has no ret")
    literal_keys = {
        "ts_mismatch_prefix": "Timestamp sizes mismatch: expect ",
        "ts_mismatch_sep": ", ",
        "ts_mismatch_suffix": " given",
        "no_timestamp_prefix": "cannot call this method on column family ",
        "no_timestamp_suffix": " that does not enable timestamp",
        "no_cf_handle": "column family handle cannot be null",
        "ts_disabled": "timestamp disabled",
        "ts_size_mismatch": "timestamp size mismatch",
        "read_ts_prefix": "Read timestamp: ",
        "read_ts_suffix": " is smaller than full_history_ts_low: ",
    }
    for key, literal in literal_keys.items():
        if records["literals"][key]["text"] != literal:
            fail("records literal mismatch for %s" % key)
    if records["status"]["invalid_argument_code"] != 4:
        fail("records code mismatch")
    if records["census"]["0x5e882b0"]["direct_calls"] != 5:
        fail("records census gate count mismatch")
    if records["census"]["0x5fb6910"]["direct_calls"] != 5:
        fail("records census resolver count mismatch")
    if records["census"]["0x61c7e30"]["direct_calls"] != 120:
        fail("records census hex-helper count mismatch")
    if records["census"]["0x61cf670"]["direct_calls"] != 847:
        fail("records census builder count mismatch")
    if records["census"]["0x5fbf7d0"]["direct_calls"] != 1:
        fail("records census put-middle count mismatch")
    if records["census"]["0x5d48400"]["direct_calls"] != 0:
        fail("records census ok-stub count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_ts_gate_ops_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks passed" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_literals()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
