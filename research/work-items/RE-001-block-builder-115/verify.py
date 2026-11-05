"""Checker for the RE-001-block-builder-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-block-builder-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (objdump
splits a few long instructions across two lines; the parser
accumulates those continuations); spot instructions byte-for-byte
against a fresh objdump run and the raw binary; the pinned
"basic_string::append" and "vector::_M_realloc_insert" literals
against the raw binary; the FDE ranges in frames.txt against a
fresh frame dump; census consistency (callers.tsv against a
fresh scan: per-target direct calls, tail jumps, stored qwords,
RELATIVE addends and internal transfers) and the callers.tsv
caller function against the smallest enclosing FDE range from a
fresh frame dump; the semantic records (including each body
sha256 against the raw binary); and the model tests. Prints
ALL CHECKS PASSED on success, else raises.
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
    ("ctor.txt", 0x6129A00, 0x6129B0B),
    ("estimate.txt", 0x6129B10, 0x6129C0D),
    ("finish.txt", 0x6129C10, 0x6129D88),
    ("reset.txt", 0x6129F60, 0x612A000),
    ("add.txt", 0x612A1B0, 0x612A4F2),
    ("hash_add.txt", 0x612CA80, 0x612CC47),
    ("hash_finish.txt", 0x612CC80, 0x612CE0C),
    ("hash_reset.txt", 0x612CE10, 0x612CE2F),
    ("trailer.txt", 0x612CE90, 0x612CEA6),
    ("hash.txt", 0x61C34A0, 0x61C3525),
]

BODIES = {
    'ctor': (0x6129a00, 0x6129b0b),
    'estimate': (0x6129b10, 0x6129c0d),
    'finish': (0x6129c10, 0x6129d88),
    'reset': (0x6129f60, 0x612a000),
    'add': (0x612a1b0, 0x612a4f2),
    'hash_add': (0x612ca80, 0x612cc47),
    'hash_finish': (0x612cc80, 0x612ce0c),
    'hash_reset': (0x612ce10, 0x612ce2f),
    'trailer': (0x612ce90, 0x612cea6),
    'hash': (0x61c34a0, 0x61c3525),
}

EXPECTED_CALLS = {
    0x6129a00: ['0x60e9aaa', '0x60e9aed', '0x6145b95', '0x6145bbd', '0x6147067', '0x6147089', '0x61472a6', '0x61472c6', '0x6147413', '0x6147433', '0x6147531', '0x6147551', '0x614b0bb', '0x614b0df', '0x618363d', '0x6185174'],
    0x6129b10: ['0x613bafc'],
    0x6129c10: ['0x60e7ff2', '0x60ecf0b', '0x60ef062', '0x6143dee', '0x6143e2f', '0x6144b5c', '0x6144bcc', '0x6144ebb', '0x6144f0c', '0x6147b1d', '0x6147ca4'],
    0x6129f60: [],
    0x612a1b0: ['0x60f0b39', '0x6144d17', '0x6144df6', '0x61455d7', '0x6145623', '0x614592f', '0x614597b', '0x614606e', '0x61460c2', '0x6146738', '0x614678c', '0x614a023', '0x614a091', '0x61836df', '0x618378e'],
    0x612ca80: ['0x612a31b', '0x612a66c'],
    0x612cc80: ['0x6129d3b'],
    0x612ce10: [],
    0x612ce90: ['0x6129c9f'],
    0x61c34a0: ['0x5f08dd5', '0x5f09180', '0x5f0d2e1', '0x5f0d43d', '0x5f0da73', '0x5f0e695', '0x5f0eb87', '0x5f0eea7', '0x5f0f0bc', '0x5f0f21b', '0x612bf6a', '0x612c1ec', '0x612caca', '0x612ce6c', '0x612d821', '0x612d947', '0x61365e9', '0x618ef88', '0x61989f6', '0x619c44e', '0x619d834', '0x619e28b', '0x619e306', '0x61a02a6', '0x61a052b', '0x61a073c'],
}

EXPECTED_JUMPS = {
    0x6129a00: [],
    0x6129b10: [],
    0x6129c10: ['0x614a3ed', '0x6183714', '0x61837c2'],
    0x6129f60: ['0x612a015'],
    0x612a1b0: [],
    0x612ca80: [],
    0x612cc80: [],
    0x612ce10: ['0x6129fcc'],
    0x612ce90: [],
    0x61c34a0: [],
}

EXPECTED_INTERNAL = {
    0x6129a00: ['0x6129a47'],
    0x6129b10: [],
    0x6129c10: ['0x6129c79', '0x6129c9f', '0x6129ccd', '0x6129d3b', '0x6129d7e', '0x6129d83'],
    0x6129f60: ['0x6129ff9'],
    0x612a1b0: ['0x612a22e', '0x612a239', '0x612a272', '0x612a295', '0x612a2ce', '0x612a31b', '0x612a3d2', '0x612a3dd', '0x612a3e9', '0x612a42b', '0x612a4d9', '0x612a4ed'],
    0x612ca80: ['0x612caca', '0x612cb98', '0x612cbca', '0x612cc42'],
    0x612cc80: ['0x612cccf', '0x612cce5', '0x612cd5d', '0x612cd94', '0x612cdda', '0x612cddf', '0x612cdfb'],
    0x612ce10: [],
    0x612ce90: [],
    0x61c34a0: [],
}

EXPECTED_INTERNAL_JUMPS = {
    0x6129a00: ['0x6129b06'],
    0x6129b10: [],
    0x6129c10: [],
    0x6129f60: ['0x6129fcc'],
    0x612a1b0: ['0x612a49f'],
    0x612ca80: [],
    0x612cc80: ['0x612cdbe', '0x612ce07'],
    0x612ce10: [],
    0x612ce90: [],
    0x61c34a0: [],
}

SPOT_BYTES = {
    0x6129a00: 'f30f1efa',
    0x6129b10: 'f30f1efa',
    0x6129c10: 'f30f1efa',
    0x6129f60: 'f30f1efa',
    0x612a1b0: 'f30f1efa',
    0x612ca80: 'f30f1efa',
    0x612cc80: 'f30f1efa',
    0x612ce10: 'f30f1efa',
    0x612ce90: 'f30f1efa',
    0x61c34a0: 'f30f1efa',
    0x612a31b: 'e860270000',
    0x612caca: 'e8d1690900',
    0x6129c9f: 'e8ec310000',
    0x6129d3b: 'e8402f0000',
    0x6129ff9: 'e892fdffff',
    0x6129a47: 'e884732c00',
}

LITERALS = [
    (0x4474D2, b"basic_string::append"),
    (0x43D55A, b"vector::_M_realloc_insert"),
]

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
    expected = {"README.md", "records.json", "ctor.txt",
                "estimate.txt", "finish.txt", "reset.txt", "add.txt",
                "hash_add.txt", "hash_finish.txt", "hash_reset.txt",
                "trailer.txt", "hash.txt", "frames.txt",
                "relocations.txt", "callers.tsv", "export_excerpts.py",
                "census.py", "verify.py"}
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
    for address, message in LITERALS:
        off = voff(segs, address)
        if data[off:off + len(message)] != message:
            fail("literal mismatch at %#x" % address)
        if data[off + len(message)] != 0:
            fail("literal not NUL-terminated at %#x" % address)


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
    tsv_sites = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind not in ("call", "jmp"):
            fail("unknown callers.tsv kind: %s" % kind)
        tsv_sites.setdefault(target, []).append((site, kind))
    for target in EXPECTED_CALLS:
        calls = census_list(out, target, "direct calls")
        if sorted(calls) != sorted(EXPECTED_CALLS[target]):
            fail("census calls mismatch for %#x" % target)
        jumps = census_list(out, target, "tail jumps")
        if sorted(jumps) != sorted(EXPECTED_JUMPS[target]):
            fail("census tail jumps mismatch for %#x" % target)
        want = sorted([(s, "call") for s in EXPECTED_CALLS[target]]
                      + [(s, "jmp") for s in EXPECTED_JUMPS[target]])
        if sorted(tsv_sites.get("%#x" % target, [])) != want:
            fail("callers.tsv sites do not match census for %#x" % target)
        if census_list(out, target, "stored qwords") != []:
            fail("census stored qwords not empty for %#x" % target)
        internal = census_list(out, target, "internal calls")
        if sorted(internal) != sorted(EXPECTED_INTERNAL[target]):
            fail("census internal calls mismatch for %#x" % target)
        ijumps = census_list(out, target, "internal tail jumps")
        if sorted(ijumps) != sorted(EXPECTED_INTERNAL_JUMPS[target]):
            fail("census internal tail jumps mismatch for %#x" % target)
        for label in ("internal indirect calls",
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
        if sorted(body["internal_tail_jumps"]) != sorted(
                EXPECTED_INTERNAL_JUMPS[start]):
            fail("records %s internal tail jumps mismatch" % key)
    for key, (start, _stop) in BODIES.items():
        census = records["census"][key]
        if sorted(census["direct_calls"]) != sorted(EXPECTED_CALLS[start]):
            fail("records census calls mismatch for %s" % key)
        if sorted(census["tail_jumps"]) != sorted(EXPECTED_JUMPS[start]):
            fail("records census tail jumps mismatch for %s" % key)
        if census["stored_qwords"] != []:
            fail("records census qwords mismatch for %s" % key)
        if census["relative_addends"] != 0:
            fail("records census RELATIVE mismatch for %s" % key)
    builder = records["builder"]
    if builder["layout"]["estimate_field"] != (
            "this +0x40 (uint64): the bodies keep it equal to "
            "buffer.size + 4*len(restarts) + 4"):
        fail("records estimate field mismatch")
    literals = builder["literals"]
    append = literals["append_error"]
    if (append["text"] != "basic_string::append"
            or append["length"] != 20
            or append["address"] != "0x4474d2"):
        fail("records append literal mismatch")
    vector = literals["vector_error"]
    if (vector["text"] != "vector::_M_realloc_insert"
            or vector["length"] != 25
            or vector["address"] != "0x43d55a"):
        fail("records vector literal mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_block_builder_115.py"],
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
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
