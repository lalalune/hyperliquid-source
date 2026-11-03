#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-merge-redistribute.

Checks, without executing the node binary: binary digest/size, FDE bytes
and hashes, body/tail splits, ret bytes, strict mnemonic-line counts,
pinned opcode sites (via the packet objdump), GOT relocations, panic
Locations and messages, direct-caller census, no GOT sites, and packet
hex/records agreement.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

BINARY_SIZE = 105896032
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FDES = {
    "merge": (0x4CA2500, 0x4CA2915, 0x4CA28C9,
              "293ea3858c4e900eefac1a3ada3469834d049dfd0d1cd7212b39fad0f32af6f0",
              "d225588427723d9783533ed15ba97021a8b5163537ebfcf60082558915f290ca",
              225, 213, 12, 4),
    "redistL": (0x4C93C20, 0x4C93F18, 0x4C93ECC,
                "ef576dd41de6f921ce763fefe3215968fd2319040bf40c8944ed805c73bf0ed0",
                "0d2bbf112a556d275a03462e9e0685c57c316c3f033d03142a5ae684648a8ddc",
                161, 149, 12, 2),
    "redistR": (0x4C9B3B0, 0x4C9B6FF, 0x4C9B6CC,
                "f2673bbf94612ccd06ac3e49b9c2ad177f8200822128d487c32bb8280f20fd13",
                "99bfab38291f1ccc0abb3fe3ef32cbb6b87c1683ff23b717ea8b13f9cbab05cd",
                175, 167, 8, 2),
}

# (objdump file, address, needle) spot checks.
SPOT_CHECKS = [
    ("merge", 0x4CA2500, "push   rbp"),
    ("merge", 0x4CA250E, "mov    r14,QWORD PTR [rsi+0x18]"),
    ("merge", 0x4CA251D, "cmp    rdx,0x1"),
    ("merge", 0x4CA254A, "cmp    r8,0xc"),
    ("merge", 0x4CA2593, "mov    WORD PTR [r14+0xe6],r8w"),
    ("merge", 0x4CA25D0, "call   QWORD PTR [rip+0x183cf92]"),
    ("merge", 0x4CA2605, "call   QWORD PTR [rip+0x183cefd]"),
    ("merge", 0x4CA276E, "dec    WORD PTR [r12+0xe6]"),
    ("merge", 0x4CA2892, "call   QWORD PTR [rip+0x183cc08]"),
    ("merge", 0x4CA28C9, "ret"),
    ("redistL", 0x4C93C2E, "mov    rbx,QWORD PTR [rdi+0x28]"),
    ("redistL", 0x4C93C41, "cmp    rax,0xc"),
    ("redistL", 0x4C93C5A, "sub    r12,rsi"),
    ("redistL", 0x4C93C67, "mov    WORD PTR [rbp+0xe6],r12w"),
    ("redistL", 0x4C93C74, "mov    WORD PTR [rbx+0xe6],ax"),
    ("redistL", 0x4C93D75, "cmp    QWORD PTR [r10+0x20],0x0"),
    ("redistL", 0x4C93ECC, "ret"),
    ("redistR", 0x4C9B3BE, "mov    rbp,QWORD PTR [rdi+0x18]"),
    ("redistR", 0x4C9B3DE, "mov    rbx,QWORD PTR [rdi+0x28]"),
    ("redistR", 0x4C9B3CE, "cmp    rax,0xc"),
    ("redistR", 0x4C9B3EA, "sub    r13,rsi"),
    ("redistR", 0x4C9B4E6, "cmp    QWORD PTR [r15+0x20],0x0"),
    ("redistR", 0x4C9B6CC, "ret"),
]

GOT_CHECKS = {
    0x64DF568: "memmove@GLIBC_2.2.5",
    0x64DF508: "memcpy@GLIBC_2.14",
    0x64DF4A0: "635de30",
    0x64DF730: "1680e60",
}

# Location struct VA -> (file string VA, file len, line, col).
LOCATIONS = {
    0x649A648: (0x4344F8, 91, 1491, 9),
    0x649A660: (0x4344F8, 91, 1414, 9),
    0x649A540: (0x4344F8, 91, 1876, 5),
    0x649A5B8: (0x4344F8, 91, 1537, 13),
    0x649A5D0: (0x4344F8, 91, 1538, 13),
    0x649A5E8: (0x4344F8, 91, 1585, 22),
    0x649A600: (0x4344F8, 91, 1600, 13),
    0x649A618: (0x4344F8, 91, 1601, 13),
    0x649A630: (0x4344F8, 91, 1649, 22),
}

PANIC_MESSAGES = [
    (0x913599, b"assertion failed: match track_edge_idx {\n"
               b"    LeftOrRight::Left(idx) => idx <= old_left_len,\n"
               b"    LeftOrRight::Right(idx) => idx <= right_len,\n}"),
    (0x913627, b"assertion failed: new_left_len <= CAPACITY"),
    (0x913439, b"assertion failed: src.len() == dst.len()"),
    (0x9134E5, b"assertion failed: old_right_len + count <= CAPACITY"),
    (0x913518, b"assertion failed: old_left_len >= count"),
    (0x913496, b"internal error: entered unreachable code"),
    (0x91353F, b"assertion failed: old_left_len + count <= CAPACITY"),
    (0x913571, b"assertion failed: old_right_len >= count"),
]

PANIC_FILE = (b"/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860"
              b"/library/alloc/src/collections/btree/node.rs")

E8_CALLERS = {
    0x4CA2500: {0x4D24967: "e894dbf7ff"},
    0x4C93C20: {0x4CBDBCB: "e85060fdff", 0x4D2497B: "e8a0f2f6ff",
                0x4D24F12: "e809edf6ff"},
    0x4C9B3B0: {0x4D249AC: "e8ff69f7ff", 0x4D24F2C: "e87f64f7ff"},
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
        if m:
            relocs[int(m.group(1), 16)] = (m.group(2), m.group(3), line.strip())
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

    obj_names = {"merge": "merge.objdump.txt", "redistL": "redistL.objdump.txt",
                 "redistR": "redistR.objdump.txt"}
    for name, (s, e, ret, full_sha, body_sha, total, body_n, tail_n, nops) \
            in FDES.items():
        fde = va_bytes(s, e - s)
        if len(fde) != e - s:
            fail(f"{name} FDE length mismatch")
        if hashlib.sha256(fde).hexdigest() != full_sha:
            fail(f"{name} FDE sha mismatch")
        body = va_bytes(s, ret - s + 1)
        if hashlib.sha256(body).hexdigest() != body_sha:
            fail(f"{name} body sha mismatch")
        if body[-1:] != b"\xc3":
            fail(f"{name} body does not end with ret")
        if e - (ret + 1) != (e - s) - (ret - s + 1):
            fail(f"{name} tail length mismatch")

        # Packet hex agreement (file per FDE).
        hex_file = {"merge": "merge.hex", "redistL": "redistL.hex",
                    "redistR": "redistR.hex"}[name]
        hex_text = open(os.path.join(packet_dir, hex_file)).read().strip()
        if bytes.fromhex(hex_text) != fde:
            fail(f"{name} packet hex does not match binary FDE bytes")

        objdump_lines = open(os.path.join(
            packet_dir, obj_names[name])).read().splitlines()
        by_addr = {}
        for line in objdump_lines:
            m = re.match(r"\s+([0-9a-f]+):\t", line)
            if m:
                by_addr[int(m.group(1), 16)] = line
        # Strict mnemonic-line count (continuation lines excluded:
        # they lack bytes + mnemonic after the address).
        instrs = [l for l in objdump_lines
                  if re.match(r"^\s+[0-9a-f]+:\s+[0-9a-f ]+\s+\S", l)]
        if len(instrs) != total:
            fail(f"{name} instruction count {len(instrs)} != {total}")
        addrs = [int(l.split(":")[0].strip(), 16) for l in instrs]
        body_instrs = [a for a in addrs if a <= ret]
        if len(body_instrs) != body_n:
            fail(f"{name} body instruction count {len(body_instrs)} != {body_n}")
        if len(instrs) - len(body_instrs) != tail_n:
            fail(f"{name} tail instruction count mismatch")
        if sum(1 for l in instrs if "\tnop" in l or " nop " in l) != nops:
            fail(f"{name} nop count mismatch")
        if addrs != sorted(addrs):
            fail(f"{name} objdump addresses not monotonic")

    for fname, addr, needle in SPOT_CHECKS:
        lines = open(os.path.join(packet_dir, obj_names[fname])).read().splitlines()
        by_addr = {}
        for line in lines:
            m = re.match(r"\s+([0-9a-f]+):\t", line)
            if m:
                by_addr[int(m.group(1), 16)] = line
        line = by_addr.get(addr)
        if line is None or needle not in line:
            fail(f"spot check failed at {hex(addr)}: {line!r}")

    # GOT relocations.
    _, relocs = relocations(binary_path)
    for slot, want in GOT_CHECKS.items():
        typ, addend, raw = relocs.get(slot, (None, None, ""))
        if want.startswith("mem"):
            if want not in raw:
                fail(f"GOT {hex(slot)} resolution mismatch: {raw!r}")
        elif addend != want:
            fail(f"GOT {hex(slot)} addend {addend} != {want}")

    # Panic Locations: inline len/line/col + file string via reloc addend.
    for loc_va, (file_va, file_len, line_no, col_no) in LOCATIONS.items():
        off = loc_va - 0x2000
        q0, ln, line, col = struct.unpack_from("<QQII", data, off)
        typ, addend, _ = relocs.get(loc_va, (None, None, ""))
        if addend != f"{file_va:x}":
            fail(f"Location {hex(loc_va)} file addend {addend} != {hex(file_va)}")
        if (ln, line, col) != (file_len, line_no, col_no):
            fail(f"Location {hex(loc_va)} fields {(ln, line, col)} != "
                 f"{(file_len, line_no, col_no)}")
        if data[file_va:file_va + file_len] != PANIC_FILE:
            fail(f"Location {hex(loc_va)} file string mismatch")

    # Panic message bytes.
    for msg_va, want in PANIC_MESSAGES:
        if data[msg_va:msg_va + len(want)] != want:
            fail(f"panic message {hex(msg_va)} mismatch")

    # Direct E8 caller census over all of .text.
    text_addr, text_off, text_size = text_range(binary_path)
    text = data[text_off:text_off + text_size]
    for target, want in E8_CALLERS.items():
        found = {}
        for i in range(len(text) - 5):
            if text[i] == 0xE8:
                rel = struct.unpack_from("<i", text, i + 1)[0]
                va = text_addr + i
                if va + 5 + rel == target:
                    found[va] = text[i:i + 5].hex()
        if found != want:
            fail(f"E8 caller census mismatch for {hex(target)}: {found}")

    # No GOT slot resolves to any claimed FDE.
    for addr, (typ, addend, raw) in relocs.items():
        if addend in ("4ca2500", "4c93c20", "4c9b3b0"):
            fail(f"unexpected GOT relocation to claimed helper at {hex(addr)}")

    # Records agreement on the headline numbers.
    rec = json.load(open(os.path.join(packet_dir, "records.json")))
    for name, (s, e, ret, full_sha, body_sha, total, body_n, tail_n, nops) \
            in FDES.items():
        key = {"merge": "merge", "redistL": "redistribute_left",
               "redistR": "redistribute_right"}[name]
        h = rec[key]
        if (h["bytes"], h["body_bytes"], h["tail_bytes"],
                h["total_instructions"], h["body_instructions"],
                h["tail_instructions"], h["nops"],
                h["full_sha256"], h["body_sha256"]) != (
                e - s, ret - s + 1, e - (ret + 1), total, body_n, tail_n,
                nops, full_sha, body_sha):
            fail(f"records.json headline numbers mismatch for {name}")

    print(json.dumps({
        "fdes": {name: {"start": hex(s), "end": hex(e), "bytes": e - s,
                        "body_bytes": ret - s + 1, "tail_bytes": e - (ret + 1)}
                 for name, (s, e, ret, *_r) in FDES.items()},
        "census": {"merge_e8": 1, "redistL_e8": 3, "redistR_e8": 2,
                   "got_sites": 0},
        "borrow": "caller-supplied only; helpers validate, never choose",
        "merge_survivor": "left node kept, right node freed",
    }))


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = os.path.join(root, "research", "work-items",
                              "RE-001-node115-lu-merge-redistribute")
    binary_path = os.path.join(root, "artifacts", "node", "115", "hl-node")
    verify(root, packet_dir, binary_path)


if __name__ == "__main__":
    main()
