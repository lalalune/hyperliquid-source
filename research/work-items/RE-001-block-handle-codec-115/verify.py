"""Checker for the RE-001-block-handle-codec-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-block-handle-codec-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary; the pinned
"bad block handle" literal against the raw binary; the FDE ranges
in frames.txt against a fresh frame dump; the twin-body equality
modulo the four position-dependent fields; census consistency
(callers.tsv against a fresh scan: per-target direct calls, tail
jumps, stored qwords, RELATIVE addends and internal transfers)
and the callers.tsv caller function against the smallest
enclosing FDE range from a fresh frame dump; the semantic
records (including each body sha256 against the raw binary); and
the model tests. Prints ALL CHECKS PASSED on success, else
raises.
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
    ("encode_str.txt", 0x6167D00, 0x6167DC8),
    ("encode_buf.txt", 0x6167DD0, 0x6167E2D),
    ("decode.txt", 0x6167E30, 0x6167F27),
    ("varint64.txt", 0x61BD540, 0x61BD58B),
    ("twin_encode_str.txt", 0x5F38B10, 0x5F38BD8),
]

BODIES = {
    "encode_str": (0x6167D00, 0x6167DC8),
    "encode_buf": (0x6167DD0, 0x6167E2D),
    "decode": (0x6167E30, 0x6167F27),
    "varint64": (0x61BD540, 0x61BD58B),
    "twin_encode_str": (0x5F38B10, 0x5F38BD8),
}

EXPECTED_CALLS = {
    0x6167D00: ["0x6144c0a", "0x6145df6", "0x6149f19", "0x6167f96",
                "0x61681f0", "0x61862e7"],
    0x6167DD0: ["0x616866b", "0x6168676"],
    0x6167E30: ["0x6104d1b", "0x611f247", "0x6168378", "0x6168fb2",
                "0x6168fd0", "0x6184058"],
    0x61BD540: ["0x5e11df7", "0x5e11e0b", "0x5e11e1f", "0x5e11e5b",
                "0x5f38c17", "0x5f38c3c", "0x5f3a36f", "0x5f54856",
                "0x5f5486b", "0x5f54883", "0x5f54c0c", "0x5f5b457",
                "0x5f5b482", "0x5f5b4e6", "0x5f5b511", "0x5f5b68b",
                "0x5f5b6b7", "0x5f5b85b", "0x5f5b880", "0x5f5b96c",
                "0x5f5cd5f", "0x5f5cd97", "0x5f5cee7", "0x5f5cf27",
                "0x5f5cf67", "0x5f5d932", "0x5f5d96b", "0x5f5dd31",
                "0x5f5ddae", "0x5f5dde0", "0x5f5de4f", "0x5f5de84",
                "0x5f5e19e", "0x5f5e20f", "0x5f5e27e", "0x5f5e2b3",
                "0x5f5fb19", "0x5f5fb3f", "0x5f5fb65", "0x5f60946",
                "0x5f6096b", "0x5f60990", "0x5fa6ab7", "0x5fa758c",
                "0x5fa7611", "0x6167e67", "0x6167e89", "0x616827d",
                "0x6187f43"],
    0x5F38B10: ["0x5f39a6e", "0x5f39b90"],
}

EXPECTED_INTERNAL = {
    0x6167D00: ["0x6167d8d", "0x6167dbe", "0x6167dc3"],
    0x6167DD0: [],
    0x6167E30: ["0x6167e67", "0x6167e89", "0x6167eff", "0x6167f22"],
    0x61BD540: [],
    0x5F38B10: ["0x5f38b9d", "0x5f38bce", "0x5f38bd3"],
}

SPOT_BYTES = {
    0x6167D00: "f30f1efa",
    0x6167D8D: "e8ae912800",
    0x6167DD0: "f30f1efa",
    0x6167DEA: "83c880",
    0x6167E30: "f30f1efa",
    0x6167E67: "e8d4560500",
    0x6167E89: "e8b2560500",
    0x6167EF6: "48c744240810000000",
    0x6167EFF: "e86c770600",
    0x61BD540: "f30f1efa",
    0x61BD564: "83f93f",
    0x5F38B10: "f30f1efa",
}

MESSAGE_ADDRESS = 0x437503
MESSAGE = b"bad block handle"

TWIN_FIELDS = [(142, 146), (186, 190), (191, 195), (196, 200)]

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))
    return segs


def voff(segs, vaddr):
    for p_vaddr, p_offset, p_filesz in segs:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return vaddr - p_vaddr + p_offset
    raise AssertionError("vaddr %#x not in any LOAD segment" % vaddr)


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
    expected = {"README.md", "records.json", "encode_str.txt",
                "encode_buf.txt", "decode.txt", "varint64.txt",
                "twin_encode_str.txt", "frames.txt", "relocations.txt",
                "callers.tsv", "export_excerpts.py", "census.py",
                "verify.py"}
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
    segs = segments(data)
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
            off = voff(segs, address)
            if data[off:off + len(raw)] != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    segs = segments(data)
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        off = voff(segs, address)
        if data[off:off + len(raw)] != raw:
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
    off = voff(segs, MESSAGE_ADDRESS)
    if data[off:off + len(MESSAGE)] != MESSAGE:
        fail("error message literal mismatch at %#x" % MESSAGE_ADDRESS)
    if data[off + len(MESSAGE)] != 0:
        fail("error message literal not NUL-terminated")


def check_frames():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    for line in (PACKET / "frames.txt").read_text().splitlines():
        match = re.search(r"pc=([0-9a-f]+\.\.[0-9a-f]+)", line)
        if not match:
            fail("frames.txt line without pc range: %s" % line)
        if ("pc=" + match.group(1)) not in text:
            fail("frame range missing: %s" % match.group(1))


def check_relocations_file():
    stored = (PACKET / "relocations.txt").read_bytes()
    if stored.strip():
        fail("relocations.txt must be empty for this packet")


def check_twin():
    data = BINARY.read_bytes()
    segs = segments(data)
    bodies = []
    for start in (0x6167D00, 0x5F38B10):
        off = voff(segs, start)
        bodies.append(bytearray(data[off:off + 200]))
    for body in bodies:
        for lo, hi in TWIN_FIELDS:
            body[lo:hi] = b"\x00\x00\x00\x00"
    if bytes(bodies[0]) != bytes(bodies[1]):
        fail("twin bodies differ beyond the position-dependent fields")


def frame_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def census_list(out, target, label):
    match = re.search(
        r"routine %#x: %s: (\[.*\])" % (target, label), out)
    if not match:
        fail("census output missing %s for %#x" % (label, target))
    return ast.literal_eval(match.group(1))


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    for target, want_calls in EXPECTED_CALLS.items():
        calls = census_list(out, target, "direct calls")
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x" % target)
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        if census_list(out, target, "tail jumps") != []:
            fail("census tail jumps not empty for %#x" % target)
        if census_list(out, target, "stored qwords") != []:
            fail("census stored qwords not empty for %#x" % target)
        internal = census_list(out, target, "internal calls")
        if sorted(internal) != sorted(EXPECTED_INTERNAL[target]):
            fail("census internal calls mismatch for %#x" % target)
        for label in ("internal tail jumps", "internal indirect calls",
                      "internal indirect tail jumps"):
            if census_list(out, target, label) != []:
                fail("census %s not empty for %#x" % (label, target))
        if ("routine %#x: RELATIVE addends: 0" % target) not in out:
            fail("census RELATIVE count not 0 for %#x" % target)
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
    data = BINARY.read_bytes()
    segs = segments(data)
    for key, (start, stop) in BODIES.items():
        body = records["bodies"][key]
        if body["address"] != "%#x" % start:
            fail("records %s address mismatch" % key)
        if body["fde"] != "%#x..%#x" % (start, stop):
            fail("records %s FDE mismatch" % key)
        if body["size_bytes"] != stop - start:
            fail("records %s size mismatch" % key)
        off = voff(segs, start)
        digest = hashlib.sha256(data[off:off + (stop - start)]).hexdigest()
        if body["sha256"] != digest:
            fail("records %s sha256 mismatch" % key)
        if sorted(body["internal_calls"]) != sorted(EXPECTED_INTERNAL[start]):
            fail("records %s internal calls mismatch" % key)
    for key, target in (("encode_str", 0x6167D00), ("encode_buf", 0x6167DD0),
                        ("decode", 0x6167E30), ("varint64", 0x61BD540),
                        ("twin_encode_str", 0x5F38B10)):
        census = records["census"][key]
        if sorted(census["direct_calls"]) != sorted(EXPECTED_CALLS[target]):
            fail("records census calls mismatch for %s" % key)
        if census["tail_jumps"] != [] or census["stored_qwords"] != []:
            fail("records census jumps/qwords mismatch for %s" % key)
        if census["relative_addends"] != 0:
            fail("records census RELATIVE mismatch for %s" % key)
    codec = records["codec"]
    if codec["max_encoded_length"] != 20:
        fail("records max encoded length mismatch")
    if codec["fields"]["offset"] != "this +0x0 (uint64)":
        fail("records offset field mismatch")
    if codec["fields"]["size"] != "this +0x8 (uint64)":
        fail("records size field mismatch")
    message = codec["error_message"]
    if (message["text"] != "bad block handle" or message["length"] != 16
            or message["address"] != "0x437503"):
        fail("records error message mismatch")
    if records["twin"]["position_dependent_fields"] != [
            list(pair) for pair in TWIN_FIELDS]:
        fail("records twin fields mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_block_handle_codec_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations_file()
    check_twin()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
