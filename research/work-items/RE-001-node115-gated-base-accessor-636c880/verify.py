"""Checker for the RE-001-node115-gated-base-accessor-636c880 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node115-gated-base-accessor-636c880/verify.py

Checks, in order: the work binary digest against the provenance entry;
MANIFEST.sha256 against every packet file; excerpt regeneration
byte-for-byte against a fresh objdump run; every excerpt instruction
byte-for-byte against the raw binary (objdump splits long instructions
across lines; continuations are accumulated); spot instructions
byte-for-byte; the FDE range in frames.txt against a fresh frame dump;
the relocation evidence (the single R_X86_64_RELATIVE record that
installs a pointer to the routine at .data.rel.ro slot 0x64ddc18, no
relocation whose offset falls inside the routine body, and the absence
of any relocation at the returned slot 0x64ddc20); the census
(0 direct calls, 0 tail jumps, exactly one stored qword at file offset
0x132eb0, exactly one RELATIVE addend, 0 internal transfers of every
kind); the trailing int3 padding; the semantic records; and the model
self-test. Prints ALL CHECKS PASSED on success, else raises.
"""

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

ROUTINE_START, ROUTINE_STOP = 0x636C880, 0x636C8B3
WINDOWS = [("main.txt", ROUTINE_START, ROUTINE_STOP)]

SPOT_BYTES = {
    0x636C880: "f30f1efa",                 # endbr64
    0x636C884: "488d057b6d3a00",           # lea 0x6713606(%rip),%rax
    0x636C88B: "803800",                   # cmpb $0x0,(%rax)
    0x636C897: "803a01",                   # cmpb $0x1,(%rdx)
    0x636C89C: "4883f923",                 # cmp $0x23,%rcx
    0x636C8A2: "488d0577131700",           # lea 0x64ddc20(%rip),%rax
    0x636C8A9: "c3",                       # ret
    0x636C8B0: "31c0",                     # xor %eax,%eax
}

RELATIVE_SLOT = 0x64DDC18     # where the routine pointer is installed
RETURNED_CONST = 0x64DDC20    # the constant the routine returns
STORED_QWORD_OFFSET = 0x132EB0

EXPECTED_MANIFEST = {
    "README.md", "records.json", "main.txt", "frames.txt",
    "relocations.txt", "callers.tsv", "export_excerpts.py",
    "census.py", "verify.py", "model.py",
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
    if seen != EXPECTED_MANIFEST:
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
        if (not mnemonic and instructions
                and address == instructions[-1][0] + len(instructions[-1][1])):
            instructions[-1] = (instructions[-1][0],
                                instructions[-1][1] + raw)
        else:
            instructions.append((address, raw))
    return instructions


def seg_params(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _pp, p_filesz,
         _pm, _pa) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            return p_offset, p_vaddr, p_filesz
    fail("no executable LOAD segment")


def vaddr_bytes(data, vaddr, length):
    p_off, p_va, _sz = seg_params(data)
    start = vaddr - p_va + p_off
    return data[start:start + length]


def check_excerpts(data):
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt mismatch for %s" % name)
        for address, raw in parse_excerpt(stored):
            if vaddr_bytes(data, address, len(raw)) != raw:
                fail("excerpt instruction bytes differ at %#x" % address)


def check_spot(data):
    for address, hexbytes in SPOT_BYTES.items():
        want = bytes.fromhex(hexbytes)
        if vaddr_bytes(data, address, len(want)) != want:
            fail("spot byte mismatch at %#x" % address)


def check_padding(data):
    # Bytes between the final ret (0x636c8b3) and the next FDE
    # (0x636c8c0) must be int3 (0xcc) padding.
    pad = vaddr_bytes(data, ROUTINE_STOP, 0x636C8C0 - ROUTINE_STOP)
    if pad != b"\xcc" * len(pad):
        fail("trailing padding is not int3: %s" % pad.hex())


def check_frames():
    dump = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    needed = "pc=000000000636c880..000000000636c8b3"
    if needed not in dump:
        fail("FDE range for the routine not found in a fresh frame dump")
    stored = (PACKET / "frames.txt").read_text()
    if needed not in stored:
        fail("frames.txt does not carry the routine FDE line")
    for line in stored.splitlines():
        line = line.strip()
        if line and line not in dump:
            fail("frames.txt line not present in a fresh dump: %s" % line)


def check_relocations(data):
    text = subprocess.run(["readelf", "-r", "work/hl-node-115.bin"],
                          capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout
    rel_lines = [l for l in text.splitlines()
                 if "636c880" in l and "RELATIVE" in l]
    if len(rel_lines) != 1:
        fail("expected exactly one RELATIVE record for the routine, got %d"
             % len(rel_lines))
    if ("%x" % RELATIVE_SLOT) not in rel_lines[0].split()[0].lstrip("0"):
        fail("RELATIVE record installs the pointer at an unexpected slot: %s"
             % rel_lines[0])
    # No relocation whose r_offset lands inside the routine body.
    for line in text.splitlines():
        head = line.split()
        if not head:
            continue
        try:
            off = int(head[0], 16)
        except ValueError:
            continue
        if ROUTINE_START <= off < ROUTINE_STOP:
            fail("unexpected relocation inside the routine body at %#x" % off)
    # The returned slot carries no relocation of its own.
    for line in text.splitlines():
        head = line.split()
        if head:
            try:
                if int(head[0], 16) == RETURNED_CONST:
                    fail("returned slot %#x unexpectedly has a relocation"
                         % RETURNED_CONST)
            except ValueError:
                pass
    # relocations.txt must carry exactly the installing record.
    stored = (PACKET / "relocations.txt").read_text().strip().splitlines()
    if len(stored) != 1 or "636c880" not in stored[0] or "RELATIVE" not in stored[0]:
        fail("relocations.txt does not carry exactly the installing record")


def check_census(data):
    p_off, p_va, p_sz = seg_params(data)
    calls, jmps = [], []
    for off in range(p_off, p_off + p_sz - 5):
        op = data[off]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        site = off - p_off + p_va
        if site + 5 + rel == ROUTINE_START:
            (calls if op == 0xE8 else jmps).append(site)
    if calls:
        fail("unexpected direct call sites: %s" % [hex(c) for c in calls])
    if jmps:
        fail("unexpected tail-jump sites: %s" % [hex(j) for j in jmps])
    qwords = [off for off in range(0, len(data) - 8, 8)
              if struct.unpack_from("<Q", data, off)[0] == ROUTINE_START]
    if qwords != [STORED_QWORD_OFFSET]:
        fail("stored-qword set mismatch: %s" % [hex(q) for q in qwords])
    # Internal control transfers: none leave the routine; no calls.
    dump = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % ROUTINE_START,
         "--stop-address=%#x" % ROUTINE_STOP, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    for line in dump.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        mnemonic = (match.group(3) or "").strip()
        parts = mnemonic.split(None, 1)
        if not parts:
            continue
        opcode, operand = parts[0], (parts[1] if len(parts) > 1 else "")
        if opcode == "call":
            fail("unexpected call inside the routine: %s" % mnemonic)
        if opcode == "jmp":
            dest = operand.split()[0] if operand.split() else ""
            try:
                dest_value = int(dest, 16)
            except ValueError:
                dest_value = None
            if dest_value is None or not (ROUTINE_START <= dest_value < ROUTINE_STOP):
                fail("unexpected tail jump inside the routine: %s" % mnemonic)


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["routine"]["address"] != "0x636c880":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x636c880..0x636c8b3":
        fail("records FDE mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["returns_constant"]["address"] != "0x64ddc20":
        fail("records returned-constant mismatch")
    census = records["census"]
    if (census["direct_call_count"] != 0 or census["tail_jump_count"] != 0
            or census["relative_addends"] != 1
            or census["relative_slots"] != ["0x64ddc18"]):
        fail("records census mismatch")
    if records["writes"] != []:
        fail("records writes must be empty")


def check_model():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "accessor_model_636c880", PACKET / "model.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    count = module.self_test()
    if count <= 0:
        fail("model self-test ran no assertions")
    # Cross-check the constants the model names against records.json.
    if module.BASE != 0x64DDC20:
        fail("model BASE mismatch")
    if module.GATE_A_ADDR != 0x6713606 or module.GATE_B_ADDR != 0x6717690:
        fail("model gate addresses mismatch")
    return count


def main():
    data = BINARY.read_bytes()
    check_digest()
    check_manifest()
    check_excerpts(data)
    check_spot(data)
    check_padding(data)
    check_frames()
    check_relocations(data)
    check_census(data)
    check_records()
    model_assertions = check_model()
    print("ALL CHECKS PASSED (model self-test: %d assertions)" % model_assertions)


if __name__ == "__main__":
    sys.exit(main())
