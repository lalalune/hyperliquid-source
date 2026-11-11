"""Checker for the RE-001-shared-release-52490-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-shared-release-52490-115/verify.py

Checks, in order: the work binary digest against the provenance
entry; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against a fresh objdump run; every
excerpt instruction byte-for-byte against the raw binary (via
the ELF LOAD-segment map, since the packet's windows span two
segments); spot instructions byte-for-byte against a fresh
objdump run and the raw binary; the panic-message bytes at
0x46e9bd against the raw binary; the FDE ranges in frames.txt
against a fresh frame dump; the relocation records in
relocations.txt against a fresh relocation dump; the LSDA
call-site table of the routine's FDE, decoded from .eh_frame
and .gcc_except_table, against the pinned five entries; census
consistency (callers.tsv against a fresh scan: 82 direct calls,
14 tail jumps, no stored qwords, no RELATIVE addends for the
routine address, 2 internal calls, 0 internal direct tail
jumps, 5 internal indirect calls, 1 internal indirect tail
jump) and the callers.tsv caller function against the smallest
enclosing FDE range from a fresh frame dump; the semantic
records; and the model tests. Prints ALL CHECKS PASSED on
success, else raises.
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
    ("main.txt", 0x5A52490, 0x5A52518),
    ("cleanup.txt", 0x5A4F0E0, 0x5A4F10B),
    ("panic_shim.txt", 0x1680CAB, 0x1680CBF),
]

EXPECTED_CALLS = {
    0x5A52490: ['0x5a2f5e8', '0x5a2f622', '0x5a2f9c2', '0x5a2fa33',
                '0x5a3a42c', '0x5a3a46f', '0x5a3bf1c', '0x5a3c1a9',
                '0x5a3c381', '0x5a3c3c4', '0x5a3c48a', '0x5a3c4d8',
                '0x5a3c9db', '0x5a3ca17', '0x5a3ee54', '0x5a3eeaa',
                '0x5a3ef96', '0x5a3fc9b', '0x5a41232', '0x5a418b6',
                '0x5a41a52', '0x5a41ad6', '0x5a423ed', '0x5a449e6',
                '0x5a44dcb', '0x5a45944', '0x5a45ce7', '0x5a46340',
                '0x5a4635e', '0x5a466e7', '0x5a46705', '0x5a47170',
                '0x5a4718e', '0x5a47750', '0x5a4776e', '0x5a477d7',
                '0x5a477f5', '0x5a47a3d', '0x5a47a58', '0x5a4aabc',
                '0x5a4ab07', '0x5a4b83c', '0x5a4b881', '0x5a527fb',
                '0x5a55c10', '0x5a55ecf', '0x5a5701b', '0x5a57116',
                '0x5a5929e', '0x5a592d0', '0x5a5c888', '0x5a5c93d',
                '0x5a5ee0b', '0x5a5f518', '0x5a6009b', '0x5a60777',
                '0x5a61ef8', '0x5a6217b', '0x5a6703b', '0x5a68983',
                '0x5a6b153', '0x5a6be66', '0x5a6d2a3', '0x5a6d342',
                '0x5a711b0', '0x5a7167f', '0x5a7953f', '0x5a796d3',
                '0x5a7e692', '0x5a7f269', '0x5a850d3', '0x5a85145',
                '0x5a86a6e', '0x5a8905a', '0x5a89dee', '0x5a8a13f',
                '0x5ab4b2d', '0x5ab4fc9', '0x5ab547a', '0x5ab5a56',
                '0x5ab690d', '0x5ab6beb'],
}

EXPECTED_JUMPS = {
    0x5A52490: ['0x5a3ef87', '0x5a3fc52', '0x5a41223', '0x5a418a7',
                '0x5a41a43', '0x5a41ac7', '0x5a423de', '0x5a449d7',
                '0x5a44da9', '0x5a458fb', '0x5a45cb9', '0x5a527ec',
                '0x5a55bfe', '0x5a55ec0'],
}

EXPECTED_INTERNAL_CALLS = ["0x5a524f5", "0x5a5250d"]
EXPECTED_INTERNAL_JUMPS = []
EXPECTED_INTERNAL_INDIRECT_CALLS = ["0x5a5249c", "0x5a524b4",
                                    "0x5a524c5", "0x5a52507",
                                    "0x5a52512"]
EXPECTED_INTERNAL_INDIRECT_JUMPS = ["0x5a524df"]

SPOT_BYTES = {
    0x5A52490: "4156",
    0x5A52494: "833f02",
    0x5A5249C: "ff159ed9a800",
    0x5A524AE: "f048ff08",
    0x5A524B4: "ff150ed9a800",
    0x5A524C5: "ff15edd8a800",
    0x5A524DF: "ff6018",
    0x5A524F5: "e8e6cbffff",
    0x5A52507: "ff5018",
    0x5A5250D: "e83ee59900",
    0x5A52512: "ff15a8cfa800",
    0x5A527E1: "4883c728",
    0x5A2F5E4: "488d7b28",
    0x5A6D29C: "488dbba8000000",
    0x1680CB6: "6a24",
}

PANIC_MESSAGE_ADDRESS = 0x46E9BD
PANIC_MESSAGE = b"panic in a destructor during cleanup"

EXPECTED_LSDA = [
    (0x5A52499, 0x5A524A2, 0x5A524EF, 0),
    (0x5A524B4, 0x5A524CB, 0x5A524EA, 0),
    (0x5A524CB, 0x5A524F2, None, 0),
    (0x5A524F2, 0x5A5250A, 0x5A52512, 1),
    (0x5A5250A, 0x5A52518, None, 0),
]

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


def load_segments(data):
    """[(vaddr, file offset, file size)] for each PT_LOAD."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz,
         _memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            segments.append((p_vaddr, p_offset, p_filesz))
    return segments


def raw_at(data, segments, address, length):
    for vaddr, offset, filesz in segments:
        if vaddr <= address < vaddr + filesz:
            start = offset + (address - vaddr)
            return data[start:start + length]
    fail("address %#x not in any LOAD segment" % address)


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
                "cleanup.txt", "panic_shim.txt", "frames.txt",
                "relocations.txt", "callers.tsv",
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
    segments = load_segments(data)
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
            if raw_at(data, segments, address, len(raw)) != raw:
                fail("raw byte mismatch at %#x in %s" % (address, name))
        if instructions[-1][0] + len(instructions[-1][1]) != stop:
            fail("excerpt %s does not end at %#x" % (name, stop))


def check_spots():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    for address, hex_bytes in SPOT_BYTES.items():
        raw = bytes.fromhex(hex_bytes)
        if raw_at(data, segments, address, len(raw)) != raw:
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


def check_panic_message():
    data = BINARY.read_bytes()
    segments = load_segments(data)
    raw = raw_at(data, segments, PANIC_MESSAGE_ADDRESS,
                 len(PANIC_MESSAGE))
    if raw != PANIC_MESSAGE:
        fail("panic message bytes mismatch: %r" % raw)


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


def check_relocations():
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    stored_lines = [line for line in
                    (PACKET / "relocations.txt").read_text().splitlines()
                    if line.strip()]
    if len(stored_lines) != 5:
        fail("relocations.txt must hold exactly 5 records")
    expected = {"64dfe40": "5ceafd0", "64dfdc8": "5ce8da0",
                "64dfdb8": "5ce86d0", "64df4c0": "1680cab",
                "64e1f28": "1680e40"}
    seen = {}
    for line in stored_lines:
        if "RELATIVE" not in line:
            fail("relocations.txt line is not a RELATIVE record: %s" % line)
        if line not in text:
            fail("relocation record missing from fresh dump: %s" % line)
        parts = line.split()
        seen[hex(int(parts[0], 16))[2:]] = parts[-1]
    if seen != expected:
        fail("relocation slot map mismatch: %s" % seen)


def _uleb(data, off):
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, off
        shift += 7


def check_lsda():
    data = BINARY.read_bytes()
    # Section headers: locate .eh_frame and .gcc_except_table.
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
        "<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name_idx, _type, _flags, addr, offset, size) = \
            struct.unpack_from("<IIQQQQ", data, off)
        sections.append((name_idx, addr, offset, size))
    str_off = sections[e_shstrndx][2]
    by_name = {}
    for name_idx, addr, offset, size in sections:
        end = data.index(b"\x00", str_off + name_idx)
        name = data[str_off + name_idx:end].decode()
        by_name[name] = (addr, offset, size)
    eh_addr, eh_off, _ = by_name[".eh_frame"]
    gt_addr, gt_off, _ = by_name[".gcc_except_table"]
    # The routine's FDE: use the fresh frame dump to find its
    # .eh_frame offset and CIE offset.
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    match = re.search(
        r"^([0-9a-f]+) [0-9a-f]+ [0-9a-f]+ FDE cie=([0-9a-f]+) "
        r"pc=0000000005a52490\.\.0000000005a52518",
        text, re.MULTILINE)
    if not match:
        fail("routine FDE not found in fresh frame dump")
    fde_off = eh_off + int(match.group(1), 16)
    cie_off = eh_off + int(match.group(2), 16)
    # CIE record: length, id, version, augmentation string,
    # code/data alignment factors, return-address register, then
    # the 'z' augmentation (length + body). The body holds the
    # P, L, R entries in augmentation-string order.
    off = cie_off + 4 + 4 + 1
    aug_str = b""
    while data[off] != 0:
        aug_str += bytes([data[off]])
        off += 1
    off += 1
    _code_align, off = _uleb(data, off)
    # data_align is a signed LEB128; consume it byte-wise.
    while True:
        byte = data[off]
        off += 1
        if not (byte & 0x80):
            break
    _ra_reg, off = _uleb(data, off)
    aug_len, off = _uleb(data, off)
    encodings = {}
    pos = off
    for ch in aug_str:
        if ch == ord("z"):
            continue
        if ch == ord("P"):
            enc = data[pos]
            pos += 1
            fmt = enc & 0x0F
            if fmt == 0x01:
                _v, pos = _uleb(data, pos)
            elif fmt in (0x03, 0x0B):
                pos += 4
            elif fmt == 0x04:
                pos += 8
            else:
                fail("unexpected personality encoding %#x" % enc)
            encodings["P"] = enc
        elif ch == ord("L"):
            encodings["L"] = data[pos]
            pos += 1
        elif ch == ord("R"):
            encodings["R"] = data[pos]
            pos += 1
    if encodings.get("R") != 0x1B or encodings.get("L") != 0x1B:
        fail("unexpected CIE encodings: %s" % encodings)
    # FDE record: length, CIE pointer, initial location
    # (pcrel|sdata4), address range (udata4), augmentation
    # length, LSDA pointer (pcrel|sdata4).
    off = fde_off + 4 + 4
    init_loc = (eh_addr + (off - eh_off)) + \
        struct.unpack_from("<i", data, off)[0]
    off += 4
    addr_range = struct.unpack_from("<I", data, off)[0]
    off += 4
    if init_loc != 0x5A52490 or addr_range != 0x88:
        fail("FDE header mismatch: %#x + %#x" % (init_loc, addr_range))
    _a_len, off = _uleb(data, off)
    lsda = (eh_addr + (off - eh_off)) + \
        struct.unpack_from("<i", data, off)[0]
    off += 4
    # LSDA lives in .gcc_except_table (vaddr == file offset here,
    # but map through the section header regardless).
    loff = gt_off + (lsda - gt_addr)
    lp_enc = data[loff]
    loff += 1
    if lp_enc != 0xFF:
        fail("unexpected LPstart encoding %#x" % lp_enc)
    lpstart = init_loc
    tt_enc = data[loff]
    loff += 1
    if tt_enc != 0xFF:
        _tt, loff = _uleb(data, loff)
    cs_enc = data[loff]
    loff += 1
    if cs_enc != 0x01:
        fail("unexpected call-site encoding %#x" % cs_enc)
    cs_len, loff = _uleb(data, loff)
    entries = []
    end = loff + cs_len
    while loff < end:
        start, loff = _uleb(data, loff)
        length, loff = _uleb(data, loff)
        pad, loff = _uleb(data, loff)
        action, loff = _uleb(data, loff)
        entries.append((lpstart + start, lpstart + start + length,
                        (lpstart + pad) if pad else None, action))
    if entries != EXPECTED_LSDA:
        fail("LSDA call-site table mismatch: %s" % (entries,))


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
        for label, want in (
                ("internal calls", EXPECTED_INTERNAL_CALLS),
                ("internal tail jumps", EXPECTED_INTERNAL_JUMPS),
                ("internal indirect calls", EXPECTED_INTERNAL_INDIRECT_CALLS),
                ("internal indirect tail jumps", EXPECTED_INTERNAL_INDIRECT_JUMPS)):
            match = re.search(
                r"routine %#x: %s: (\[.*\])" % (target, label), out)
            if not match or sorted(ast.literal_eval(match.group(1))) != sorted(want):
                fail("census %s mismatch" % label)
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
    if records["routine"]["address"] != "0x5a52490":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5a52490..0x5a52518":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 136:
        fail("records routine size mismatch")
    if records["routine"]["internal_calls"] != 2:
        fail("records internal call count mismatch")
    if records["routine"]["internal_tail_jumps"] != 0:
        fail("records internal tail jump count mismatch")
    if records["routine"]["internal_indirect_calls"] != 5:
        fail("records internal indirect call count mismatch")
    if records["routine"]["internal_indirect_tail_jumps"] != 1:
        fail("records internal indirect tail jump count mismatch")
    if records["first_callee"]["callee"] != "0x5ceafd0":
        fail("records first callee mismatch")
    if records["first_callee"]["slot"] != "0x64dfe40":
        fail("records first callee slot mismatch")
    if records["destructors"]["nonzero_byte"] != "0x5ce8da0":
        fail("records nonzero destructor mismatch")
    if records["destructors"]["zero_byte"] != "0x5ce86d0":
        fail("records zero destructor mismatch")
    if records["pair_helper"]["address"] != "0x5a4f0e0":
        fail("records pair helper mismatch")
    if records["callback"]["entry_offset"] != "+0x18":
        fail("records callback entry offset mismatch")
    if records["unwind"]["panic_shim"]["address"] != "0x1680cab":
        fail("records panic shim mismatch")
    if records["unwind"]["panic_shim"]["message"] != \
            "panic in a destructor during cleanup":
        fail("records panic message mismatch")
    if records["census"]["direct_call_count"] != 82:
        fail("records call count mismatch")
    if records["census"]["tail_jump_count"] != 14:
        fail("records census jump count mismatch")
    if records["census"]["distinct_caller_fdes"] != 45:
        fail("records census caller FDE count mismatch")
    if len(records["callers"]) != 96:
        fail("records callers list length mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_shared_release_52490_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_panic_message()
    check_frames()
    check_relocations()
    check_lsda()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
