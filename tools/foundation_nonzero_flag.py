#!/usr/bin/env python3
"""Checker for the foundation nonzero-flag helper (node #94, 0x5650a60).

Stdlib only. Run from the repository root:

    python3 tools/foundation_nonzero_flag.py \\
        --check research/work-items/foundation-nonzero-flag-94/evidence.json

Every claim is re-derived from target bytes: the 88-byte window body, its
8-byte int3 padding, the retained FDE records (window, next, previous,
callee, callee-next, caller, each locked under its own CIE read from the
cie= field, never from the third-column CIE-pointer delta), the callee
body and its exact NOP padding, the call and tail-jump encodings, the
table address, the nonzero-flag rule (both the direct test and the
bit-trick identity) on its edges, the single direct caller, and the full
47-site callee call list. A failure prints the mismatching check and
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
    0x5650A60: "f30f1efa",
    0x5650A64: "4863f6",
    0x5650A67: "4154",
    0x5650A69: "4889f2",
    0x5650A6C: "4883ee01",
    0x5650A70: "55",
    0x5650A71: "4889fd",
    0x5650A74: "48f7d2",
    0x5650A77: "53",
    0x5650A78: "4821f2",
    0x5650A7B: "48c1ea3f",
    0x5650A7F: "4c8d25ba7e2cfb",
    0x5650A86: "4889d3",
    0x5650A89: "488d7f60",
    0x5650A8D: "4883f301",
    0x5650A91: "4889fe",
    0x5650A94: "4c89e1",
    0x5650A97: "4889da",
    0x5650A9A: "e821650000",
    0x5650A9F: "488dbd90000000",
    0x5650AA6: "4c89e1",
    0x5650AA9: "4889da",
    0x5650AAC: "4889fe",
    0x5650AAF: "5b",
    0x5650AB0: "5d",
    0x5650AB1: "415c",
    0x5650AB3: "e908650000",
}

WINDOW_START = 0x5650A60
CALLEE_START = 0x5656FC0
TABLE_ADDRESS = 0x918940
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
    enc = read_va(binary, sections, 0x5650A9A, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x5650A9A + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The tail jump must target the same callee.
    jenc = read_va(binary, sections, 0x5650AB3, 5)
    (jrel,) = struct.unpack_from("<i", jenc, 1)
    if 0x5650AB3 + 5 + jrel != CALLEE_START:
        raise ValueError("tail-jump target is not the callee")
    # The table address must come from the lea's rip-relative offset.
    lenc = read_va(binary, sections, 0x5650A7F, 7)
    (disp,) = struct.unpack_from("<i", lenc, 3)
    if 0x5650A86 + disp != TABLE_ADDRESS:
        raise ValueError("table address is not 0x918940")
    if u64(ev["rule"]["table_address"]) != TABLE_ADDRESS:
        raise ValueError("recorded table address mismatch")
    # The window must end with a tail jump, not a ret.
    if read_va(binary, sections, 0x5650AB3, 1) != b"\xe9":
        raise ValueError("window does not end with a tail jump")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    nxt = u64(fn["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != fn["padding_bytes"]:
        raise ValueError(f"padding length {len(pad)} != {fn['padding_bytes']}")
    if any(b != 0xCC for b in pad):
        raise ValueError(f"padding not all int3: {pad.hex()}")
    if pad.hex() != fn["padding_hex"]:
        raise ValueError("padding hex mismatch")


def check_frames(ev, packet_dir):
    fn = ev["function"]
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        lines = fh.read().splitlines()
    # Each record is locked by its own section offset, PC range, and the
    # cie= value on the same FDE header line -- never by the third
    # column, which is the CIE-pointer delta, not the CIE.
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
    inc = ev["incoming"]
    records += [
        (inc["caller_fde_section_offset"], inc["caller_fde_start"],
         inc["caller_fde_end_exclusive"], inc["caller_fde_cie"], "caller"),
    ]
    for off, start, end, cie, label in records:
        header = None
        for line in lines:
            if line.startswith(off[2:] + " ") and " FDE " in line:
                header = line
                break
        if header is None:
            raise ValueError(f"{label} FDE header not in frames.txt")
        want_pc = (f"pc={u64(start):016x}..{u64(end):016x}" if end is not None
                   else f"pc={u64(start):016x}")
        if want_pc not in header:
            raise ValueError(f"{label} FDE PC range not on its header line")
        if f"cie={cie[2:]}" not in header:
            raise ValueError(f"{label} FDE CIE not on its header line")


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
    if pad.hex() != cal["padding_hex"]:
        raise ValueError(f"callee padding bytes mismatch: {pad.hex()}")
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


def check_caller_file(ev, packet_dir):
    path = os.path.join(packet_dir, "caller.objdump.txt")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        text = fh.read()
    if "call   5650a60" not in text:
        raise ValueError("caller.objdump.txt lacks the call to the window")


def movsxd(value32):
    """Sign-extend a 32-bit value to a Python int."""
    value32 &= 0xFFFFFFFF
    return value32 - (1 << 32) if value32 & 0x80000000 else value32


def bit_trick_flag(n):
    """The window's flag derivation: 1 ^ (((~n) & (n-1)) >> 63)."""
    return 1 ^ (((((~n) & MASK64) & ((n - 1) & MASK64)) >> 63) & 1)


def evaluate_edge(edge):
    """Check one edge against both the direct test and the bit trick."""
    esi = u64(edge["esi"])
    n = movsxd(esi)
    if n != int(edge["n"], 16):
        raise ValueError(
            f"edge {edge['note']}: movsxd {hex(n)} != {edge['n']}")
    direct = 1 if n != 0 else 0
    trick = bit_trick_flag(n)
    if direct != trick:
        raise ValueError(
            f"edge {edge['note']}: direct flag {direct} != trick {trick}")
    if direct != u64(edge["flag"]):
        raise ValueError(
            f"edge {edge['note']}: model flag {direct} != {edge['flag']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    if len(ev["incoming"]["direct_e8_callers"]) != 1:
        raise ValueError("this packet claims exactly one direct caller")


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
    check_caller_file(ev, packet_dir)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_nonzero_flag.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation nonzero-flag evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
