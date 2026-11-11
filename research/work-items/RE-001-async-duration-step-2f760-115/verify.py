"""Checker for the RE-001-async-duration-step-2f760-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-async-duration-step-2f760-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run;
every excerpt instruction byte-for-byte against the raw
binary (objdump splits a few long instructions across two
lines; the parser accumulates those continuations); spot
instructions byte-for-byte against a fresh objdump run and
the raw binary; the FDE ranges against a fresh frame dump;
the relocation records against a fresh relocation dump;
the dispatch table entries recomputed from the binary;
the panic and guard message bytes and the three static
location records recomputed from the binary and its
relocations; census consistency (callers.tsv against a
fresh scan: 3 direct calls, 0 tail jumps, no stored qwords,
no RELATIVE addends) and each callers.tsv caller function
against the smallest enclosing FDE range from a fresh frame
dump; the semantic records; and the model tests.
Prints ALL CHECKS PASSED on success, else raises.
"""

import ast
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

WINDOWS = [
    ("main.txt", 0x5A2F760, 0x5A2FA70),
    ("formatter.txt", 0x1689370, 0x16893A2),
    ("guards.txt", 0x1681E60, 0x1681E99),
    ("builder.txt", 0x1680E80, 0x1680EAC),
]

EXPECTED_CALLS = {
    0x5A2F760: ["0x5a2f59e", "0x5a5fd20", "0x5a86a25"],
}

EXPECTED_JUMPS = {0x5A2F760: []}

SPOT_BYTES = {
    0x5A2F773: "0fb64778",
    0x5A2F7FF: "48f7e1",
    0x5A2F8F0: "ff15aa1aab00",
    0x5A2F980: "ff15d20eab00",
    0x5A2F9C2: "e8c92a0200",
    0x5A2FA24: "ff158efcaa00",
}

EXPECTED_SLOTS = {
    0x64B6F80: 0x44F1AC,
    0x64B81A8: 0x4326C1,
    0x64B81C0: 0x4326C1,
    0x64DF4C0: 0x1680CAB,
    0x64DF6B8: 0x1680E80,
    0x64DF720: 0x167FA70,
    0x64DFDB8: 0x5CE86D0,
    0x64DFDC8: 0x5CE8DA0,
    0x64E0858: 0x5CF2D30,
    0x64E1360: 0x1681E80,
    0x64E1368: 0x1681E60,
    0x64E13A0: 0x5CF2150,
    0x64E13A8: 0x1689370,
}

TABLE_BASE = 0x938F64
EXPECTED_TABLE = [0x5A2F787, 0x5A2F9E8, 0x5A2F9DB, 0x5A2F976]

MESSAGES = {
    0x4790E7: b"cannot convert float seconds to Duration: "
              b"value is negative",
    0x479122: b"cannot convert float seconds to Duration: "
              b"value is either too big or NaN",
    0x46F2ED: b"`async fn` resumed after completion",
    0x46F310: b"`async fn` resumed after panicking",
}

# static record address -> (file bytes, length, line, column)
LOCATIONS = {
    0x64B6F80: (b"/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860"
                b"/library/core/src/time.rs", 72, 962, 23),
    0x64B81A8: (b"base/src/lu.rs", 14, 75, 5),
    0x64B81C0: (b"base/src/lu.rs", 14, 74, 57),
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def v2o(segs, vaddr):
    for va, off, fsz in segs:
        if va <= vaddr < va + fsz:
            return off + (vaddr - va)
    fail("no segment for %#x" % vaddr)


def relative_slots():
    text = subprocess.run(
        ["readelf", "-rW", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    slots = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            try:
                slots[int(parts[0], 16)] = int(parts[3], 16)
            except ValueError:
                continue
    return slots, text


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
    expected = {"README.md", "records.json", "main.txt",
                "formatter.txt", "guards.txt", "builder.txt",
                "frames.txt", "relocations.txt", "callers.tsv",
                "export_excerpts.py", "census.py", "verify.py"}
    if seen != expected:
        fail("manifest file set mismatch: %s" % sorted(seen))


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
    data = BINARY.read_bytes()
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt mismatch for %s" % name)
        instructions = parse_excerpt(stored)
        if not instructions or instructions[0][0] != start:
            fail("excerpt %s does not start at %#x" % (name, start))
        for address, raw in instructions:
            # Executable LOAD segment: file offset = vaddr - 0x1000.
            if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if data[address - 0x1000:address - 0x1000 + len(raw)] != raw:
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


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for want in ("pc=0000000005a2f760..0000000005a2fa70",
                 "pc=0000000005a2f550..0000000005a2f661",
                 "pc=0000000005a5e290..0000000005a60a43",
                 "pc=0000000005a82670..0000000005a89535"):
        if want not in text:
            fail("frame range missing: %s" % want)
        if want not in (PACKET / "frames.txt").read_text():
            fail("frames.txt missing: %s" % want)


def check_relocations():
    slots, _text = relative_slots()
    stored = (PACKET / "relocations.txt").read_text()
    for slot, addend in EXPECTED_SLOTS.items():
        if slots.get(slot) != addend:
            fail("relocation mismatch for slot %#x: %r" % (slot, slots.get(slot)))
        if ("%016x" % slot) not in stored or ("%x" % addend) not in stored:
            fail("relocations.txt missing slot %#x" % slot)
    # The routine's own address is never a RELATIVE addend.
    if 0x5A2F760 in slots.values():
        fail("unexpected RELATIVE addend for the routine address")


def check_table_and_strings():
    data = BINARY.read_bytes()
    segs = segments(data)
    base_off = v2o(segs, TABLE_BASE)
    targets = []
    for i in range(4):
        entry = struct.unpack_from("<i", data, base_off + 4 * i)[0]
        targets.append(TABLE_BASE + entry)
    if targets != EXPECTED_TABLE:
        fail("dispatch table mismatch: %s" % [hex(t) for t in targets])
    for address, want in MESSAGES.items():
        off = v2o(segs, address)
        if data[off:off + len(want)] != want:
            fail("message mismatch at %#x" % address)
    slots, _text = relative_slots()
    for address, (want_file, want_len, want_line, want_col) in LOCATIONS.items():
        off = v2o(segs, address)
        stored_ptr, length, packed = struct.unpack_from("<QQQ", data, off)
        if stored_ptr != 0:
            fail("location record %#x has a non-zero stored pointer" % address)
        if slots.get(address) is None:
            fail("location record %#x has no RELATIVE slot" % address)
        file_off = v2o(segs, slots[address])
        if data[file_off:file_off + want_len] != want_file:
            fail("location file mismatch at %#x" % address)
        line = packed & 0xFFFFFFFF
        col = (packed >> 32) & 0xFFFFFFFF
        if (length, line, col) != (want_len, want_line, want_col):
            fail("location record mismatch at %#x: %r"
                 % (address, (length, line, col)))


def frame_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
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
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x: %s vs %s"
                 % (target, calls, want_calls))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x: %s vs %s"
                 % (target, jumps, want_jumps))
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
    for target in EXPECTED_CALLS:
        for want in ("routine %#x: stored qwords: []" % target,
                     "routine %#x: RELATIVE addends: 0" % target):
            if want not in out:
                fail("census mismatch, missing %r" % want)
    ranges = frame_ranges()
    for site, caller in tsv_callers.items():
        value = int(site, 16)
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
    if records["routine"]["address"] != "0x5a2f760":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5a2f760..0x5a2fa70":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 784:
        fail("records routine size mismatch")
    if records["census"]["direct_call_count"] != 3:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if records["census"]["direct_call_sites"] != EXPECTED_CALLS[0x5A2F760]:
        fail("records call sites mismatch")
    targets = records["dispatch"]["targets"]
    if [targets[str(i)] for i in range(4)] != [
            "0x5a2f787 (conversion arm)", "0x5a2f9e8 (completion guard arm)",
            "0x5a2f9db (panicking guard arm)",
            "0x5a2f976 (predicate step, direct entry)"]:
        fail("records dispatch targets mismatch")
    conv = records["conversion"]
    if conv["panics"]["location"]["line"] != 962:
        fail("records conversion location mismatch")
    if conv["panics"]["kind_0"]["message_length"] != 59:
        fail("records kind-0 message length mismatch")
    if conv["panics"]["kind_1"]["message_length"] != 72:
        fail("records kind-1 message length mismatch")
    if records["construction"]["location_argument"]["line"] != 75:
        fail("records construction location mismatch")
    if records["guards"]["record"]["line"] != 74:
        fail("records guard record mismatch")
    if records["predicate"]["address"] != "0x5cf2d30 through slot 0x64e0858":
        fail("records predicate mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_async_duration_step_2f760_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_table_and_strings()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
