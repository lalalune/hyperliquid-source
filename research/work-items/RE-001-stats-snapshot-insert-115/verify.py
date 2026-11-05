"""Checker for the RE-001-stats-snapshot-insert-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-snapshot-insert-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run (the
delimited-key parser, the decimal parser, the hex helper, the
Status builder and the strdup helper are re-shipped
byte-identical from PR #2592, PR #3196 and PR #3221, so they
are checked by their pinned SHA-256 instead); every excerpt
instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions
byte-for-byte against a fresh objdump run and the raw binary;
the FDE ranges in frames.txt against a fresh frame dump; the
relocation set against a fresh relocation dump (the two node
vtables plus every RELATIVE record naming a pinned routine;
the insert, the state initializer, the locked lookup, the
tree-free twins and the helpers appear in none); the message
literals against the raw binary; census consistency
(callers.tsv against a fresh census run: every pinned
routine's direct calls, tail jumps, stored qwords and
RELATIVE addends, and the callers.tsv caller function against
the smallest enclosing FDE range from a fresh frame dump);
the semantic records (re-deriving the vtable slot tables
from the relocation set, the wrapper and slot-3 tail jumps,
the %010d seek with its max() selection, the version-key
gate, the state-init stores, the slot-7 strdup call, the
node size from the deleting destructors and the flag getter);
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
    "key_parse.txt":
        "328df4160c08f32e6bb1317a495f1ea1b61b53a6d19d42f1ce839be1d6e1c9c6",
    "parse_u64.txt":
        "19d1b7287e5da48ff55d04ccb14884ec7c3187b8e16791ceb2b45fbe7146994e",
    "hex_helper.txt":
        "ea85fcd667e660ead254b8d0bf4310dcb19139eaf3e5d87c24c702c8cd0d5814",
    "status_builder.txt":
        "5c716d61c200e269e3dd526816c760497c7ba042ee7eede755475c1cb3845f3d",
    "strdup.txt":
        "33326ec0f3d23de6b82e0622858f82994d14a39dd900af9e43a3a07d6c9cec0f",
}

WINDOWS = [
    ("main.txt", 0x606EF50, 0x606F91F),
    ("caller.txt", 0x5D4CC80, 0x5D4CE6A),
    ("wrapper.txt", 0x606F920, 0x606F94B),
    ("state_init.txt", 0x60B21F0, 0x60B2262),
    ("bound_getter.txt", 0x5D532D0, 0x5D532DC),
    ("count_getter.txt", 0x606DE00, 0x606DE09),
    ("node_init.txt", 0x606C680, 0x606C6A5),
    ("locked_lookup.txt", 0x5D52660, 0x5D52765),
    ("map_copy.txt", 0x5D4E140, 0x5D4E257),
    ("lower_bound.txt", 0x5D6C600, 0x5D6C79B),
    ("comparator.txt", 0x5D498C0, 0x5D4990E),
    ("dtor_a.txt", 0x606C5E0, 0x606C657),
    ("dtor_b.txt", 0x606E250, 0x606E2C7),
    ("tree_free_a.txt", 0x606C280, 0x606C5DD),
    ("tree_free_b.txt", 0x606DEF0, 0x606E24D),
    ("slot1_a.txt", 0x606C660, 0x606C67B),
    ("slot1_b.txt", 0x606E2D0, 0x606E2EB),
    ("slot2_a.txt", 0x606C180, 0x606C189),
    ("slot2_b.txt", 0x606DDF0, 0x606DDF9),
    ("slot3_a.txt", 0x606C6B0, 0x606C6DB),
    ("slot4_a.txt", 0x606C190, 0x606C199),
    ("slot5.txt", 0x606C170, 0x606C17A),
    ("slot6_a.txt", 0x606C1A0, 0x606C1A9),
    ("slot6_b.txt", 0x606DE10, 0x606DE19),
    ("slot7_a.txt", 0x606C1E0, 0x606C278),
    ("slot7_b.txt", 0x606DE50, 0x606DEE8),
    ("initializer.txt", 0x606F950, 0x606FA16),
    ("string_ctor.txt", 0x5F204E0, 0x5F205C3),
    ("key_parse.txt", 0x606EB60, 0x606EEAC),
    ("parse_u64.txt", 0x61D1540, 0x61D178B),
    ("hex_helper.txt", 0x61C7E30, 0x61C7FB6),
    ("status_builder.txt", 0x61CF670, 0x61CF767),
    ("strdup.txt", 0x61CF610, 0x61CF64F),
]

# (target, expected direct calls, expected tail jumps)
EXPECTED_CENSUS = {
    0x5D498C0: (21, 0), 0x5D4CC80: (0, 0), 0x5D4E140: (2, 0),
    0x5D52660: (1, 0), 0x5D532D0: (2, 0), 0x5D6C600: (5, 0),
    0x5F204E0: (12, 0), 0x606C170: (0, 0), 0x606C180: (0, 0),
    0x606C190: (1, 0), 0x606C1A0: (0, 0), 0x606C1E0: (0, 0),
    0x606C280: (2, 0), 0x606C5E0: (1, 0), 0x606C660: (0, 0),
    0x606C680: (1, 1), 0x606C6B0: (0, 0), 0x606DDF0: (0, 0),
    0x606DE00: (1, 0), 0x606DE10: (0, 0), 0x606DE50: (0, 0),
    0x606DEF0: (4, 0), 0x606E250: (1, 0), 0x606E2D0: (0, 0),
    0x606EB60: (2, 0), 0x606EF50: (1, 1), 0x606F920: (0, 0),
    0x606F950: (0, 0), 0x60B21F0: (61, 0), 0x61C7E30: (120, 0),
    0x61CF610: (425, 0), 0x61CF670: (847, 0), 0x61D1540: (12, 1),
}

EXPECTED_QWORDS = {
    0x5D4CC80: ["0x104ab8", "0x1090c0", "0x109f30", "0x10b0a0"],
    0x606C170: ["0x11c920", "0x11ca28"],
    0x606C180: ["0x11c8d8"], 0x606C190: ["0x11c908"],
    0x606C1A0: ["0x11c938"], 0x606C1E0: ["0x11c950"],
    0x606C5E0: ["0x11c8a8"], 0x606C660: ["0x11c8c0"],
    0x606C6B0: ["0x11c8f0"], 0x606DDF0: ["0x11c9e0"],
    0x606DE00: ["0x11ca10"], 0x606DE10: ["0x11ca40"],
    0x606DE50: ["0x11ca58"], 0x606E250: ["0x11c9b0"],
    0x606E2D0: ["0x11c9c8"], 0x606F920: ["0x11c9f8"],
    0x606F950: ["0x7468"],
}

EXPECTED_RELATIVE = {
    0x5D4CC80: 4, 0x606C170: 2, 0x606C180: 1, 0x606C190: 1,
    0x606C1A0: 1, 0x606C1E0: 1, 0x606C5E0: 1, 0x606C660: 1,
    0x606C6B0: 1, 0x606DDF0: 1, 0x606DE00: 1, 0x606DE10: 1,
    0x606DE50: 1, 0x606E250: 1, 0x606E2D0: 1, 0x606F920: 1,
    0x606F950: 1,
}

SPOT_BYTES = {
    0x5D4CC80: "f30f1efa",
    0x606EF50: "f30f1efa",
    0x606F920: "f30f1efa",
    0x60B21F0: "f30f1efa",
    0x5D52660: "f30f1efa",
    0x606F950: "f30f1efa",
    0x5D498C0: "55",
    0x606C280: "4157",
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
    for target in (0x5D498C0, 0x5D4E140, 0x5D52660, 0x5D532D0,
                   0x5D6C600, 0x5F204E0, 0x606C280, 0x606C680,
                   0x606DEF0, 0x606EB60, 0x606EF50, 0x60B21F0,
                   0x61C7E30, 0x61CF610, 0x61CF670, 0x61D1540):
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
        if (0x64D2C28 <= offset < 0x64D2D20) or addend in targets:
            want.append(line)
    stored = (PACKET / "relocations.txt").read_text().splitlines()
    if stored != want:
        fail("relocations.txt mismatch: %d stored vs %d fresh"
             % (len(stored), len(want)))
    if len(want) != 30:
        fail("relocation count mismatch: %d" % len(want))


def check_literals():
    cases = [
        (0x960EE0, 32, b"stats_iterator not preallocated."),
        (0x444749, 6, b"%010d\x00"),
        (0x95C460, 36, b"__persistent_stats_format_version__\x00"),
        (0x96AE00, 40, b"__persistent_stats_compatible_version__\x00"),
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
    if records["routine"]["size_bytes"] != 2511:
        fail("records insert size mismatch")
    if records["caller"]["size_bytes"] != 490:
        fail("records caller size mismatch")
    if records["wrapper"]["size_bytes"] != 43:
        fail("records wrapper size mismatch")
    if records["node"]["size_bytes"] != 112:
        fail("records node size mismatch")
    if records["node"]["vtable_a"] != "0x64d2c28":
        fail("records vtable A mismatch")
    if records["node"]["vtable_b"] != "0x64d2c90":
        fail("records vtable B mismatch")
    # Re-derive the vtable slot tables from the census RELATIVE
    # records: slot i of vtable A lives at 0x64d2c28 + 0x10 + 8*i,
    # slot i of vtable B at 0x64d2c90 + 0x10 + 8*i.
    census = records["census"]
    for i, fn in enumerate(records["node"]["slots_a"]):
        rels = census[fn]["relative_offsets"]
        if ("0x%x" % (0x64D2C28 + 0x10 + 8 * i)) not in rels:
            fail("records vtable A slot %d mismatch" % i)
    for i, fn in enumerate(records["node"]["slots_b"]):
        rels = census[fn]["relative_offsets"]
        if ("0x%x" % (0x64D2C90 + 0x10 + 8 * i)) not in rels:
            fail("records vtable B slot %d mismatch" % i)
    # The wrapper tail-jumps to the insert; slot 3 A tail-jumps
    # to the node initializer.
    if "jmp    606ef50" not in (PACKET / "wrapper.txt").read_text():
        fail("wrapper has no tail jump to the insert")
    if "jmp    606c680" not in (PACKET / "slot3_a.txt").read_text():
        fail("slot 3 A has no tail jump to the node initializer")
    # The caller calls both the node initializer and the insert,
    # tests the flag at source+0x4c9 and loads the error format.
    caller = (PACKET / "caller.txt").read_text()
    if "call   606c680" not in caller:
        fail("caller has no node-init call")
    if "call   606ef50" not in caller:
        fail("caller has no insert call")
    if "cmpb   $0x0,0x4c9(%rsi)" not in caller:
        fail("caller has no flag test at source+0x4c9")
    if "# 960ee0" not in caller:
        fail("caller has no error-format reference")
    # The insert formats the seek key with %010d, selecting
    # max(node+0x8, bound) with a cmovae, and drives the
    # iterator protocol: produce at slot 0x198, seek at slot
    # 0x28, has-current 0x10, current key 0x48, current value
    # 0x50, advance 0x38, release 0x8.
    main = (PACKET / "main.txt").read_text()
    if "# 444749" not in main:
        fail("insert has no %010d format reference")
    if "cmovae %r15,%r9" not in main:
        fail("insert has no max() selection for the seek key")
    if "mov    0x198(%rax),%r14" not in main:
        fail("insert has no slot 0x198 produce load")
    if "mov    0x28(%rax),%r14" not in main:
        fail("insert has no slot 0x28 seek load")
    for slot in ("call   *0x10(%rax)", "call   *0x48(%rdx)",
                 "call   *0x50(%rax)", "call   *0x38(%rax)",
                 "call   *0x8(%rax)"):
        if slot not in main:
            fail("insert has no iterator slot call %s" % slot)
    if "call   606eb60" not in main:
        fail("insert has no delimited-key parse call")
    if "call   61c7e30" not in main:
        fail("insert has no hex-helper call")
    if "call   61d1540" not in main:
        fail("insert has no decimal-parse call")
    if "call   5d6c600" not in main:
        fail("insert has no lower-bound call")
    if "# 65061c0" not in main:
        fail("insert has no version-key table reference")
    # The state initializer writes the four pinned stores.
    state_init = (PACKET / "state_init.txt").read_text()
    for store in ("movq   $0x101,0x2c(%rdi)",
                  "movq   $0xffffffffffffffff,0x78(%rdi)",
                  "movl   $0x4,0x84(%rdi)",
                  "mov    %dx,0x88(%rdi)"):
        if store not in state_init:
            fail("state init missing store %s" % store)
    # The node initializer calls the locked lookup, which takes
    # the instrumented acquire; the lower bound calls the
    # comparator; the deleting destructors pass the 0x70 node
    # size; the flag getters read +0x60; slot 7 calls strdup;
    # the initializer builds both version-key records.
    if "call   5d52660" not in (PACKET / "node_init.txt").read_text():
        fail("node init has no locked-lookup call")
    if "call   606ca40" not in (PACKET / "locked_lookup.txt").read_text():
        fail("locked lookup has no acquire call")
    if (PACKET / "lower_bound.txt").read_text().count("call   5d498c0") != 5:
        fail("lower bound comparator calls missing")
    for name in ("slot1_a.txt", "slot1_b.txt"):
        if "mov    $0x70,%esi" not in (PACKET / name).read_text():
            fail("%s has no 0x70 node-size setup" % name)
    for name in ("slot2_a.txt", "slot2_b.txt"):
        if "movzbl 0x60(%rdi),%eax" not in (PACKET / name).read_text():
            fail("%s has no flag read" % name)
    for name in ("slot7_a.txt", "slot7_b.txt"):
        if "call   61cf610" not in (PACKET / name).read_text():
            fail("%s has no strdup call" % name)
    init = (PACKET / "initializer.txt").read_text()
    if "# 95c460" not in init or "# 96ae00" not in init:
        fail("initializer has no version-key literal references")
    if records["status"]["invalid_argument_code"] != 4:
        fail("records code mismatch")
    if records["version_keys"]["format_version"]["length"] != 35:
        fail("records format-version length mismatch")
    if records["version_keys"]["compatible_version"]["length"] != 39:
        fail("records compatible-version length mismatch")
    if records["census"]["0x606ef50"]["direct_calls"] != 1:
        fail("records census insert call count mismatch")
    if records["census"]["0x606ef50"]["tail_jumps"] != 1:
        fail("records census insert jump count mismatch")
    if records["census"]["0x5d4cc80"]["direct_calls"] != 0:
        fail("records census caller call count mismatch")
    if records["census"]["0x60b21f0"]["direct_calls"] != 61:
        fail("records census state-init count mismatch")
    if records["census"]["0x61cf670"]["direct_calls"] != 847:
        fail("records census builder count mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_stats_snapshot_insert_115.py"],
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
