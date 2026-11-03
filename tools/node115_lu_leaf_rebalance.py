#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-leaf-rebalance.

Checks the node #115 binary (never executed) against the packet:
binary digest/size, FDE bytes and hashes, body/tail split, ret byte,
pinned opcode sites (via the packet objdump), GOT relocations, panic
Locations, direct-caller census, and packet/records agreement.
Returns exit 0 only when every check passes.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032
FDE_START = 0x4D24790
FDE_END = 0x4D24F68
RET_ADDR = 0x4D24A46
FDE_SHA256 = "01c9a71131bfd73b82c18f003c8eaef6d6916568be522e6f8dcbb27df46349c1"
BODY_SHA256 = "e04c61b08e03affa861426c717e4fa2b59bce128e0dca02eee4c06bbff1ddc0a"
BODY_BYTES = 695
TAIL_BYTES = 1313
TOTAL_INSTRS = 467
BODY_INSTRS = 168
TAIL_INSTRS = 299
NOPS = 5

# (address, substring that must appear in the objdump line)
SPOT_CHECKS = [
    (0x4D247AE, "mov    rbp,QWORD PTR [rsi]"),
    (0x4D247B5, "movzx  ebx,WORD PTR [rbp+0xe6]"),
    (0x4D247F4, "call   r14"),
    (0x4D24829, "call   r14"),
    (0x4D24832, "mov    WORD PTR [rbp+0xe6],ax"),
    (0x4D2483E, "cmp    ax,0x4"),
    (0x4D2485C, "movzx  edx,WORD PTR [rsi+0xe4]"),
    (0x4D2486F, "mov    rsi,QWORD PTR [rax+rdx*8+0xe0]"),
    (0x4D248BB, "cmp    ebx,0xc"),
    (0x4D24967, "call   4ca2500"),
    (0x4D2497B, "call   4c93c20"),
    (0x4D249AC, "call   4c9b3b0"),
    (0x4D24A65, "call   QWORD PTR [rip+"),
    (0x4D24A6B, "movzx  eax,WORD PTR [rbx+0xe6]"),
    (0x4D24A88, "je     4d24eec"),
    (0x4D24C08, "mov    DWORD PTR [r14+r13*4+0xb8],r15d"),
    (0x4D24DAA, "dec    WORD PTR [rbx+0xe6]"),
    (0x4D24EEC, "test   rax,rax"),
    (0x4D24EFA, "mov    BYTE PTR [rax],0x1"),
    (0x4D24F36, "lea    rdi,[rip+"),
    (0x4D24F49, "call   QWORD PTR [rip+"),
    (0x4D24F62, "call   QWORD PTR [rip+"),
]

# GOT slot -> expected relocation target description
GOT_CHECKS = {
    0x64DF568: "memmove@GLIBC_2.2.5",
    0x64DF508: "memcpy@GLIBC_2.14",
    0x64DF4A0: "635de30",
    0x64DF6B8: "1680e80",
    0x64DF730: "1680e60",
}

# Location struct VA -> (file string VA, file len, line, col)
LOCATIONS = {
    0x649A510: (0x4344F8, 91, 1360, 31),
    0x649A540: (0x4344F8, 91, 1876, 5),
}

E8_CALLERS = {
    0x4D35C75: "e816ebfeff",
    0x4D35D5B: "e830eafeff",
}


def fail(msg):
    raise AssertionError(msg)


def text_range(binary_path):
    out = subprocess.run(["readelf", "-S", binary_path],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s*$", line)
        if m and i + 1 < len(lines):
            size_m = re.search(r"^\s+([0-9a-f]+)\s+", lines[i + 1])
            if size_m:
                addr, off = (int(x, 16) for x in m.groups())
                return addr, off, int(size_m.group(1), 16)
    fail("no .text section found")


def relocations(binary_path):
    out = subprocess.run(["readelf", "-r", binary_path],
                         capture_output=True, text=True, check=True).stdout
    relocs = {}
    for line in out.splitlines():
        m = re.match(r"([0-9a-f]+)\s+\S+\s+(\S+)\s+(?:\S+\s+)?([0-9a-f]+)?", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        typ = m.group(2)
        addend = m.group(3)
        relocs[addr] = (typ, addend, line.strip())
    return out, relocs


def verify(root, packet_dir, binary_path):
    data = open(binary_path, "rb").read()
    if len(data) != BINARY_SIZE:
        fail(f"binary size {len(data)} != {BINARY_SIZE}")
    if hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        fail("binary digest mismatch")

    def va_bytes(va, n):
        # .text VA -> file offset VA - 0x1000
        return data[va - 0x1000:va - 0x1000 + n]

    fde = va_bytes(FDE_START, FDE_END - FDE_START)
    if len(fde) != 2008:
        fail("FDE length mismatch")
    if hashlib.sha256(fde).hexdigest() != FDE_SHA256:
        fail("FDE digest mismatch")
    body = va_bytes(FDE_START, BODY_BYTES)
    if hashlib.sha256(body).hexdigest() != BODY_SHA256:
        fail("body digest mismatch")
    if body[-1:] != b"\xc3":
        fail("body does not end with ret")
    if FDE_END - (RET_ADDR + 1) != TAIL_BYTES:
        fail("tail length mismatch")

    # Packet hex agreement.
    hex_text = open(os.path.join(packet_dir, "fde4790.hex")).read().strip()
    if bytes.fromhex(hex_text) != fde:
        fail("packet hex does not match binary FDE bytes")

    # Packet objdump agreement: pinned sites + counts.
    objdump_lines = open(os.path.join(packet_dir, "fde4790.objdump.txt")).read().splitlines()
    by_addr = {}
    for line in objdump_lines:
        m = re.match(r"\s+([0-9a-f]+):\t", line)
        if m:
            by_addr[int(m.group(1), 16)] = line
    for addr, needle in SPOT_CHECKS:
        line = by_addr.get(addr)
        if line is None or needle not in line:
            fail(f"spot check failed at {hex(addr)}: {line!r}")
    instrs = [l for l in objdump_lines if re.match(r"\s+[0-9a-f]+:\t", l)]
    if len(instrs) != TOTAL_INSTRS:
        fail(f"instruction count {len(instrs)} != {TOTAL_INSTRS}")
    body_instrs = [l for l in instrs
                   if int(l.split(":")[0].strip(), 16) < RET_ADDR + 1]
    if len(body_instrs) != BODY_INSTRS:
        fail(f"body instruction count {len(body_instrs)} != {BODY_INSTRS}")
    if len(instrs) - len(body_instrs) != TAIL_INSTRS:
        fail("tail instruction count mismatch")
    if sum(1 for l in instrs if "\tnop" in l or " nop " in l) != NOPS:
        fail("nop count mismatch")

    # GOT relocations.
    reloc_text, relocs = relocations(binary_path)
    for slot, want in GOT_CHECKS.items():
        typ, addend, raw = relocs.get(slot, (None, None, ""))
        if want.startswith("mem") or want.startswith("memcpy"):
            if want not in raw:
                fail(f"GOT {hex(slot)} resolution mismatch: {raw!r}")
        else:
            if addend != want:
                fail(f"GOT {hex(slot)} addend {addend} != {want}")

    # Panic Locations: inline len/line/col + file string via reloc addend.
    for loc_va, (file_va, file_len, line_no, col_no) in LOCATIONS.items():
        off = loc_va - 0x2000
        q0, ln, line, col = struct.unpack_from("<QQII", data, off)
        typ, addend, _ = relocs.get(loc_va, (None, None, ""))
        if addend != f"{file_va:x}":
            fail(f"Location {hex(loc_va)} file addend {addend} != {hex(file_va)}")
        if (ln, line, col) != (file_len, line_no, col_no):
            fail(f"Location {hex(loc_va)} fields {(ln, line, col)} != {(file_len, line_no, col_no)}")
        if data[file_va:file_va + file_len] != (
                b"/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860"
                b"/library/alloc/src/collections/btree/node.rs"):
            fail(f"Location {hex(loc_va)} file string mismatch")

    # Panic message leading literals.
    if data[0x9133DB:0x9133DB + 61] != (
            b"internal error: entered unreachable code: empty internal node"):
        fail("panic message 0x9133db mismatch")
    if data[0x913439:0x913439 + 40] != b"assertion failed: src.len() == dst.len()":
        fail("panic message 0x913439 mismatch")

    # Direct E8 caller census over all of .text.
    text_addr, text_off, text_size = text_range(binary_path)
    text = data[text_off:text_off + text_size]
    found = {}
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack_from("<i", text, i + 1)[0]
            va = text_addr + i
            if va + 5 + rel == FDE_START:
                found[va] = text[i:i + 5].hex()
    if found != {k: v for k, v in E8_CALLERS.items()}:
        fail(f"E8 caller census mismatch: {found}")

    # No GOT slot resolves to the leaf op.
    for addr, (typ, addend, raw) in relocs.items():
        if addend == f"{FDE_START:x}":
            fail(f"unexpected GOT relocation to leaf op at {hex(addr)}")

    # Records agreement on the headline numbers.
    rec = json.load(open(os.path.join(packet_dir, "records.json")))
    leaf = rec["leaf_op"]
    if (leaf["bytes"], leaf["body_bytes"], leaf["tail_bytes"],
            leaf["total_instructions"], leaf["body_instructions"],
            leaf["tail_instructions"], leaf["nops"],
            leaf["full_sha256"], leaf["body_sha256"]) != (
            2008, BODY_BYTES, TAIL_BYTES, TOTAL_INSTRS, BODY_INSTRS,
            TAIL_INSTRS, NOPS, FDE_SHA256, BODY_SHA256):
        fail("records.json headline numbers mismatch")

    print(json.dumps({
        "fde": {"start": hex(FDE_START), "end": hex(FDE_END), "bytes": 2008,
                "body_bytes": BODY_BYTES, "tail_bytes": TAIL_BYTES},
        "census": {"e8_callers": len(found), "got_sites": 0},
        "flag": {"store": "0x4d24efa", "condition": "root count == 0"},
        "second_counter": {"offset": "+0xe4", "meaning": "child index in parent"},
    }, indent=2))
    return 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    packet_dir = os.path.join(root, "research", "work-items",
                              "RE-001-node115-lu-leaf-rebalance")
    binary_path = os.path.join(root, "artifacts", "node", "115", "hl-node")
    try:
        return verify(root, packet_dir, binary_path)
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
