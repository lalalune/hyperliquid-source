"""Checker for the RE-001-stats-version-fetch-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-version-fetch-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run (the
state initializer, bound getter, version-key initializer,
string constructor, Status builder and decimal parser are
re-shipped byte-identical from PR #3237 and PR #3196, so they
are checked by their pinned SHA-256 instead); every excerpt
instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (the seven
0x5d33a90 records, the two 0x5d2d0e0 records and the one
0x606f950 record; every other pinned routine appears in none);
the message literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump);
the semantic records (re-deriving the slot-0xe8 / slot-0xf0
registrations from the relocation set, the mode dispatch, the
produce dispatch, the chain chase, the forward rule, the aux
replace, the eight landing pads, the state-init stores, the
message composition and the caller gate); and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
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

# Excerpts re-shipped byte-identical from PR #3237 (state
# initializer, bound getter, version-key initializer, string
# constructor, Status builder) and PR #3196 (decimal parser,
# via #3237), pinned by SHA-256 of the source packets.
RESHIPPED_SHA256 = {
    "state_init.txt":
        "4d4a91f26b5ff047ccba54b44d2ca421c71dbb34c2a4125c4068af73ee7d8d95",
    "bound_getter.txt":
        "a3240307f805f20d70cabd3897c46d558ee848c2b3fe5f2b8726b1cd66edaee3",
    "initializer.txt":
        "330c4f6045baca86f9d5969240332a45d787d70fac9865cd23140689ec054e1d",
    "string_ctor.txt":
        "31061db44efc20c3149dda567a98fc007a6f3e9d144a3aaae7ce94054712d8fa",
    "status_builder.txt":
        "5c716d61c200e269e3dd526816c760497c7ba042ee7eede755475c1cb3845f3d",
    "parse_u64.txt":
        "19d1b7287e5da48ff55d04ccb14884ec7c3187b8e16791ceb2b45fbe7146994e",
}

WINDOWS = [
    ("main.txt", 0x606E3A0, 0x606EA29),
    ("cleanup.txt", 0x606E2EB, 0x606E39B),
    ("default_produce.txt", 0x5D33A90, 0x5D33C67),
    ("forward_produce.txt", 0x5D2D0E0, 0x5D2D127),
    ("chain_init.txt", 0x61BD0C0, 0x61BD0D4),
    ("chain_dtor.txt", 0x61BD0E0, 0x61BD131),
    ("site-5e61b9e.txt", 0x5E61B80, 0x5E61BA3),
    ("site-5e61bc6.txt", 0x5E61BA3, 0x5E61C54),
    ("state_init.txt", 0x60B21F0, 0x60B2262),
    ("bound_getter.txt", 0x5D532D0, 0x5D532DC),
    ("initializer.txt", 0x606F950, 0x606FA16),
    ("string_ctor.txt", 0x5F204E0, 0x5F205C3),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("parse_u64.txt", 0x61D1540, 0x61D178B),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x606E3A0: (2, 0), 0x5D33A90: (0, 0), 0x5D2D0E0: (0, 0),
    0x60B21F0: (61, 0), 0x5D532D0: (2, 0), 0x61BD0C0: (103, 0),
    0x61BD0E0: (223, 32), 0x61CF670: (847, 0), 0x61D1540: (12, 1),
    0x606F950: (0, 0), 0x5F204E0: (12, 0), 0x606E2EB: (0, 1),
}

EXPECTED_QWORDS = {
    0x5D33A90: ["0x101878", "0x104050", "0x108658", "0x1094c8",
                "0x10a638", "0x12d4f8", "0x15ce80"],
    0x5D2D0E0: ["0x101890", "0x15c838"],
    0x606F950: ["0x7468"],
}

EXPECTED_RELATIVE = {
    0x5D33A90: 7, 0x5D2D0E0: 2, 0x606F950: 1,
}

SPOT_BYTES = {
    0x606E3A0: "f30f1efa",
    0x606E2EB: "488b7c2438",
    0x5D33A90: "f30f1efa",
    0x5D2D0E0: "f30f1efa",
    0x61BD0C0: "f30f1efa",
    0x61BD0E0: "f30f1efa",
    0x60B21F0: "f30f1efa",
    0x5D532D0: "f30f1efa",
    0x606F950: "f30f1efa",
    0x61CF670: "f30f1efa",
    0x61D1540: "f30f1efa",
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
    for target in (0x606E3A0, 0x60B21F0, 0x5D532D0, 0x61BD0C0,
                   0x61BD0E0, 0x61CF670, 0x61D1540, 0x5F204E0, 0x606E2EB):
        for line in text.splitlines():
            if ("%x" % target) in line and "RELATIVE" in line:
                fail("unexpected RELATIVE line for %#x: %s" % (target, line))
    want = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or "RELATIVE" not in line:
            continue
        addend = int(parts[3], 16)
        if addend in (0x5D33A90, 0x5D2D0E0, 0x606F950):
            want.append(line)
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if stored != want:
        fail("relocations.txt mismatch: %d stored vs %d fresh"
             % (len(stored), len(want)))
    if len(want) != 10:
        fail("relocation count mismatch: %d" % len(want))


def check_literals():
    cases = [
        (0x440A1E, 29, b"Persistent stats version key "),
        (0x4383C8, 11, b" not found."),
        (0x95FBE8, 39, b"Invalid stats version key type provided"),
        (0x95C460, 36, b"__persistent_stats_format_version__\x00"),
        (0x96AE00, 40, b"__persistent_stats_compatible_version__\x00"),
        (0x4376FD, 1, b"\x00"),
        (0x95E370, 137,
         b"[%s:744] Recreating persistent stats column family since "
         b"reading persistent stats version key failed. "
         b"Format key: %s, compatible key: %s\x00"),
        (0x960600, 27, b"db/db_impl/db_impl_open.cc\x00"),
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
    if records["routine"]["size_bytes"] != 1673:
        fail("records fetch size mismatch")
    if records["caller"]["size_bytes"] != 30777:
        fail("records caller size mismatch")
    if records["default_produce"]["size_bytes"] != 727:
        fail("records default produce size mismatch")
    if records["forward_produce"]["size_bytes"] != 71:
        fail("records forward produce size mismatch")
    if records["cleanup"]["size_bytes"] != 176:
        fail("records cleanup size mismatch")
    if records["chain"]["init"]["size_bytes"] != 20:
        fail("records chain init size mismatch")
    if records["chain"]["dtor"]["size_bytes"] != 81:
        fail("records chain dtor size mismatch")
    # Re-derive the slot-0xe8 / slot-0xf0 registrations from the
    # census RELATIVE records: a slot-0xe8 registration sits at
    # vtable base + 0xe8, a slot-0xf0 registration at base + 0xf0.
    census = records["census"]
    regs = records["registrations"]
    e8_offsets = census["0x5d33a90"]["relative_offsets"]
    if "0x64ed288" not in e8_offsets:
        fail("records missing GOT entry for default produce")
    bases = sorted(int(o, 16) - 0xE8 for o in e8_offsets
                   if o != "0x64ed288")
    if ["%#x" % b for b in bases] != regs["slot_0xe8_vtables"]:
        fail("records slot-0xe8 vtables mismatch")
    f0_offsets = census["0x5d2d0e0"]["relative_offsets"]
    if "0x64ed070" not in f0_offsets:
        fail("records missing GOT entry for forward produce")
    bases = sorted(int(o, 16) - 0xF0 for o in f0_offsets
                   if o != "0x64ed070")
    if ["%#x" % b for b in bases] != regs["slot_0xf0_vtables"]:
        fail("records slot-0xf0 vtables mismatch")
    # The eight landing pads jump from main.txt into the cleanup
    # block 0x606e2eb..0x606e39b.
    main = (PACKET / "main.txt").read_text()
    for pad in records["landing_pads"]:
        if "jmp    %s" % pad["target"][2:] not in main:
            fail("landing pad missing jump to %s" % pad["target"])
    # The fetch dispatches on the mode, selects both version
    # keys, rejects mode > 2, and drives the produce protocol.
    for needle in ("cmp    $0x2,%edx", "# 65061c0", "# 65061a0",
                   "# 95fbe8", "# 64ed288", "mov    0xe8(%rax),%r12",
                   "call   *%r12", "call   *0xf0(%rax)",
                   "call   5d532d0", "call   60b21f0",
                   "call   61bd0c0", "call   61bd0e0",
                   "call   61cf670", "call   61d1540",
                   "# 440a1e", "# 4383c8",
                   "mov    $0x1,%esi", "mov    $0x4,%esi",
                   "movl   $0x0,0x0(%rbp)"):
        if needle not in main:
            fail("fetch missing %s" % needle)
    # The default produce chases the +0x8 chain against the
    # canonical slot 0xf0 and replaces the value from its aux
    # view; the forward produce forwards one hop.
    default = (PACKET / "default_produce.txt").read_text()
    for needle in ("# 64ed070", "call   *0xf0(%rax)",
                   "call   *%r10", "call   *%rax",
                   "mov    0x8(%rsi),%rsi", "call   63f0d90"):
        if needle not in default:
            fail("default produce missing %s" % needle)
    forward = (PACKET / "forward_produce.txt").read_text()
    for needle in ("mov    0x8(%rsi),%rsi", "call   *0xf0(%rax)"):
        if needle not in forward:
            fail("forward produce missing %s" % needle)
    # The chain initializer zeroes the callback and the next
    # link; the destructor calls the callback and walks the list.
    chain_init = (PACKET / "chain_init.txt").read_text()
    for store in ("movq   $0x0,(%rdi)", "movq   $0x0,0x18(%rdi)"):
        if store not in chain_init:
            fail("chain init missing store %s" % store)
    chain_dtor = (PACKET / "chain_dtor.txt").read_text()
    if "call   *%rax" not in chain_dtor:
        fail("chain dtor has no callback call")
    if "call   *(%rbx)" not in chain_dtor:
        fail("chain dtor has no list-walk call")
    # The state initializer writes the four pinned stores.
    state_init = (PACKET / "state_init.txt").read_text()
    for store in ("movq   $0x101,0x2c(%rdi)",
                  "movq   $0xffffffffffffffff,0x78(%rdi)",
                  "movl   $0x4,0x84(%rdi)",
                  "mov    %dx,0x88(%rdi)"):
        if store not in state_init:
            fail("state init missing store %s" % store)
    # The initializer builds both version-key records.
    init = (PACKET / "initializer.txt").read_text()
    if "# 95c460" not in init or "# 96ae00" not in init:
        fail("initializer has no version-key literal references")
    # The caller fetches mode 1 then mode 2, checks both Status
    # codes, and logs on failure.
    site1 = (PACKET / "site-5e61b9e.txt").read_text()
    if "mov    $0x1,%edx" not in site1 or "call   606e3a0" not in site1:
        fail("caller site 1 has no mode-1 fetch")
    site2 = (PACKET / "site-5e61bc6.txt").read_text()
    for needle in ("mov    $0x2,%edx", "call   606e3a0",
                   "or     0x40(%rsp),%al", "# 95e370", "# 960600"):
        if needle not in site2:
            fail("caller site 2 missing %s" % needle)
    if records["status"]["not_found_code"] != 1:
        fail("records code mismatch")
    if records["status"]["invalid_argument_code"] != 4:
        fail("records code mismatch")
    if records["version_keys"]["format_version"]["length"] != 35:
        fail("records format-version length mismatch")
    if records["version_keys"]["compatible_version"]["length"] != 39:
        fail("records compatible-version length mismatch")
    if records["census"]["0x606e3a0"]["direct_calls"] != 2:
        fail("records census fetch call count mismatch")
    if records["census"]["0x5d33a90"]["direct_calls"] != 0:
        fail("records census default produce call count mismatch")
    if records["census"]["0x60b21f0"]["direct_calls"] != 61:
        fail("records census state-init count mismatch")
    if records["census"]["0x61cf670"]["direct_calls"] != 847:
        fail("records census builder count mismatch")
    if records["census"]["0x61bd0e0"]["tail_jumps"] != 32:
        fail("records census chain dtor jump count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_stats_version_fetch_115.py"],
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
