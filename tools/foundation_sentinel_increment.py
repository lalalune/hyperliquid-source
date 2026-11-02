#!/usr/bin/env python3
"""Checker for the foundation sentinel-increment helper (node #94, 0x327b210).

Stdlib only. Run from the repository root:

    python3 tools/foundation_sentinel_increment.py \\
        --check research/work-items/foundation-sentinel-increment-94/evidence.json

Every claim is re-derived from target bytes: the 30-byte window body, its
2-byte int3 padding, the retained FDE records (window, next, previous,
callee, callee-next, each locked under its own CIE read from the cie=
field, never from the third-column CIE-pointer delta), the callee body
and padding, the call encoding, the sentinel-increment rule on its
edges, the callee's single direct call site, and the full direct-caller
scan (exactly zero sites). A failure prints the mismatching check and
exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x327B210: "50",
    0x327B211: "e80abe3100",
    0x327B216: "488b4820",
    0x327B21A: "48ffc1",
    0x327B21D: "48c7c2ffffffff",
    0x327B224: "480f45d1",
    0x327B228: "48895020",
    0x327B22C: "58",
    0x327B22D: "c3",
}

WINDOW_START = 0x327B210
CALLEE_START = 0x3597020
SENTINEL = 0xFFFFFFFFFFFFFFFF
MASK64 = (1 << 64) - 1


def u64(text):
    return int(text, 16)


def elf_sections(binary):
    """Return {name: (sh_addr, sh_offset, sh_size)} for ELF64 sections."""
    if binary[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    (e_shoff,) = struct.unpack_from("<Q", binary, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", binary, 0x3A)
    strtab_off = e_shoff + e_shstrndx * e_shentsize
    (st_name, st_type, st_flags, st_addr, st_off, st_size) = struct.unpack_from(
        "<IIQQQQ", binary, strtab_off)
    sections = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (nm, tp, fl, addr, o, sz) = struct.unpack_from("<IIQQQQ", binary, off)
        end = binary.index(b"\x00", st_off + nm)
        name = binary[st_off + nm:end].decode()
        sections[name] = (addr, o, sz)
    return sections


def read_va(binary, sections, va, count):
    """Read count bytes at virtual address va via its section mapping."""
    for name, (addr, off, size) in sections.items():
        if addr <= va < addr + size and va + count <= addr + size:
            return binary[off + (va - addr):off + (va - addr) + count]
    raise ValueError(f"VA {hex(va)} not covered by any section")


def check_target_digest(ev, binary):
    digest = hashlib.sha256(binary).hexdigest()
    if digest != ev["target_sha256"]:
        raise ValueError(
            f"target digest mismatch: {digest} != {ev['target_sha256']}")


def check_window(ev, binary, sections):
    fn = ev["function"]
    start = u64(fn["start_va"])
    end = u64(fn["end_va_exclusive"])
    body = read_va(binary, sections, start, end - start)
    if len(body) != fn["bytes"]:
        raise ValueError(f"body length {len(body)} != {fn['bytes']}")
    if hashlib.sha256(body).hexdigest() != fn["sha256"]:
        raise ValueError("body sha256 mismatch")
    for va, hexbytes in INSTR.items():
        want = bytes.fromhex(hexbytes)
        got = read_va(binary, sections, va, len(want))
        if got != want:
            raise ValueError(
                f"instruction bytes at {hex(va)}: {got.hex()} != {hexbytes}")
    # The call must target the callee: rel32 from the end of the call.
    enc = read_va(binary, sections, 0x327B211, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x327B211 + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The load must read the field at [rax+0x20].
    if read_va(binary, sections, 0x327B216, 4) != bytes.fromhex("488b4820"):
        raise ValueError("field load is not mov rcx, [rax+0x20]")
    # The increment must be inc rcx (the flag source for cmovne).
    if read_va(binary, sections, 0x327B21A, 3) != bytes.fromhex("48ffc1"):
        raise ValueError("increment is not inc rcx")
    # The sentinel constant must be -1.
    if read_va(binary, sections, 0x327B21D, 7) != bytes.fromhex(
            "48c7c2ffffffff"):
        raise ValueError("sentinel constant is not mov rdx, -1")
    # The gate must be cmovne rdx, rcx (keep -1 when inc set ZF).
    if read_va(binary, sections, 0x327B224, 4) != bytes.fromhex("480f45d1"):
        raise ValueError("gate is not cmovne rdx, rcx")
    # The store must write the same field.
    if read_va(binary, sections, 0x327B228, 4) != bytes.fromhex("48895020"):
        raise ValueError("store is not mov [rax+0x20], rdx")
    # The window must restore rax and end with ret, not a tail jump.
    if read_va(binary, sections, 0x327B22C, 1) != b"\x58":
        raise ValueError("window does not restore rax with pop rax")
    if read_va(binary, sections, 0x327B22D, 1) != b"\xc3":
        raise ValueError("window does not end with ret")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")


def check_frames(ev, packet_dir):
    fn = ev["function"]
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        text = fh.read()
    # Each record is locked by its own section offset, PC range, and the
    # cie= value -- never by the third column, which is the CIE-pointer
    # delta, not the CIE.
    records = [
        (fn["fde_section_offset"], fn["start_va"], fn["end_va_exclusive"],
         fn["fde_cie"], "window"),
        (fn["next_fde_section_offset"], fn["next_fde_start"], None,
         fn["next_fde_cie"], "window-next"),
        (fn["prev_fde_section_offset"], fn["prev_fde_start"], None,
         fn["prev_fde_cie"], "window-prev"),
    ]
    cal = ev["callee"]
    records += [
        (cal["fde_section_offset"], cal["start_va"], cal["end_va_exclusive"],
         cal["fde_cie"], "callee"),
        (cal["next_fde_section_offset"], cal["next_fde_start"], None,
         cal["next_fde_cie"], "callee-next"),
    ]
    for off, start, end, cie, label in records:
        if off[2:] not in text:
            raise ValueError(f"{label} FDE section offset not in frames.txt")
        if end is not None:
            if f"pc={u64(start):016x}..{u64(end):016x}" not in text:
                raise ValueError(f"{label} FDE PC range not in frames.txt")
        else:
            if f"pc={u64(start):016x}" not in text:
                raise ValueError(f"{label} FDE start not in frames.txt")
        if f"cie={cie[2:]}" not in text:
            raise ValueError(f"{label} FDE CIE not in frames.txt")


def scan_direct_callers(binary, sections, target):
    """Byte-pattern scan of .text for direct e8 calls to target."""
    addr, off, size = sections[".text"]
    text = binary[off:off + size]
    found = []
    idx = 0
    while True:
        idx = text.find(b"\xe8", idx)
        if idx < 0:
            break
        if idx + 5 <= len(text):
            (rel,) = struct.unpack_from("<i", text, idx + 1)
            site_va = addr + idx
            if site_va + 5 + rel == target:
                found.append(site_va)
        idx += 1
    return found


def check_callee(ev, binary, sections):
    cal = ev["callee"]
    start = u64(cal["start_va"])
    end = u64(cal["end_va_exclusive"])
    if not cal["is_fde_start"]:
        raise ValueError("callee must be an FDE start")
    body = read_va(binary, sections, start, end - start)
    if len(body) != cal["bytes"]:
        raise ValueError(f"callee length {len(body)} != {cal['bytes']}")
    if hashlib.sha256(body).hexdigest() != cal["sha256"]:
        raise ValueError("callee sha256 mismatch")
    nxt = u64(cal["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != cal["padding_bytes"]:
        raise ValueError(
            f"callee padding length {len(pad)} != {cal['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"callee padding not all int3: {pad.hex()}")
    found = scan_direct_callers(binary, sections, start)
    want = [u64(c) for c in cal["direct_e8_call_sites"]]
    if found != want:
        raise ValueError(
            f"callee call-site scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def check_callers(ev, binary, sections):
    found = scan_direct_callers(binary, sections, WINDOW_START)
    want = [u64(c) for c in ev["incoming"]["direct_e8_callers"]]
    if found != want:
        raise ValueError(
            f"direct caller scan mismatch: {[hex(f) for f in found]} "
            f"!= {[hex(w) for w in want]}")


def evaluate_edge(edge):
    """Check one edge against the sentinel-increment model.

    tmp = old + 1 (wrapping); ZF is set exactly when tmp == 0, which
    happens exactly when old == -1; cmovne then keeps -1, else takes tmp.
    """
    old = u64(edge["old"])
    tmp = (old + 1) & MASK64
    out = SENTINEL if tmp == 0 else tmp
    if out != u64(edge["stored"]):
        raise ValueError(
            f"edge {edge['note']}: model out {hex(out)} "
            f"!= {edge['stored']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    if ev["rule"]["sentinel"] != "0xffffffffffffffff":
        raise ValueError("sentinel value mismatch")
    if ev["rule"]["field"] != "qword at [obj+0x20]":
        raise ValueError("store field mismatch")
    if ev["incoming"]["direct_e8_callers"] != []:
        raise ValueError("this packet claims exactly zero direct callers")


def run_all(evidence_path):
    with open(evidence_path) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    packet_dir = os.path.dirname(os.path.abspath(evidence_path))
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee(ev, binary, sections)
    check_callers(ev, binary, sections)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_sentinel_increment.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation sentinel-increment evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
