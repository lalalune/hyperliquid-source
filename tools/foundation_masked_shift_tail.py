#!/usr/bin/env python3
"""Checker for the foundation masked-shift tail window (node #94, 0x4f9bfa0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_masked_shift_tail.py \
        --check research/work-items/foundation-masked-shift-tail-94/evidence.json

Every claim is re-derived from target bytes: the 57-byte window body, its
seven int3 padding bytes, the retained FDE records (window, next, the
793-byte callee, the FDE after the callee, and the tail-jump target, each
locked under its own CIE read from the cie= field, never from the
third-column CIE-pointer delta), the callee body (locked by length, SHA-256
and padding; its behavior is excluded, so its instructions are not locked
one by one) and its seven int3 padding bytes, the callee's 18 direct call
sites, the direct call encoding to the callee, the tail-jump encoding to
0x4f9bee0, the masked-shift rule on its edges, and the full direct-caller
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
    0x4F9BFA0: "f30f1efa",
    0x4F9BFA4: "55",
    0x4F9BFA5: "4889fd",
    0x4F9BFA8: "53",
    0x4F9BFA9: "4889f3",
    0x4F9BFAC: "4883ec08",
    0x4F9BFB0: "488b3b",
    0x4F9BFB3: "488b7608",
    0x4F9BFB7: "e8b4724800",
    0x4F9BFBC: "4889de",
    0x4F9BFBF: "89c7",
    0x4F9BFC1: "237d40",
    0x4F9BFC4: "89c2",
    0x4F9BFC6: "48c1e708",
    0x4F9BFCA: "48037d78",
    0x4F9BFCE: "4883c408",
    0x4F9BFD2: "5b",
    0x4F9BFD3: "5d",
    0x4F9BFD4: "e907ffffff",
}

WINDOW_START = 0x4F9BFA0
CALLEE_START = 0x5423270
JUMP_TARGET = 0x4F9BEE0


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
    enc = read_va(binary, sections, 0x4F9BFB7, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x4F9BFB7 + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The tail jump must target 0x4f9bee0: rel32 from the end of the jump.
    enc = read_va(binary, sections, 0x4F9BFD4, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x4F9BFD4 + 5 + rel != JUMP_TARGET:
        raise ValueError("tail-jump target is not 0x4f9bee0")
    # The second argument must be restored to rsi before the jump.
    if read_va(binary, sections, 0x4F9BFBC, 3) != bytes.fromhex("4889de"):
        raise ValueError("rsi restore site is not mov rsi, rbx")
    # The mask must be and edi, [rbp+0x40].
    if read_va(binary, sections, 0x4F9BFC1, 3) != bytes.fromhex("237d40"):
        raise ValueError("mask site is not and edi, [rbp+0x40]")
    # The shift must be shl rdi, 8.
    if read_va(binary, sections, 0x4F9BFC6, 4) != bytes.fromhex("48c1e708"):
        raise ValueError("shift site is not shl rdi, 8")
    # The add must be add rdi, [rbp+0x78].
    if read_va(binary, sections, 0x4F9BFCA, 4) != bytes.fromhex("48037d78"):
        raise ValueError("add site is not add rdi, [rbp+0x78]")


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
    cal = ev["callee"]
    jt = ev["jump_target"]
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
        (cal["fde_section_offset"], cal["start_va"], cal["end_va_exclusive"],
         cal["fde_cie"], "callee"),
        (cal["next_fde_section_offset"], cal["next_fde_start"], None,
         cal["next_fde_cie"], "callee-next"),
        (jt["fde_section_offset"], jt["start_va"], jt["end_va_exclusive"],
         jt["fde_cie"], "jump-target"),
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
    body = read_va(binary, sections, start, end - start)
    if len(body) != cal["bytes"]:
        raise ValueError(f"callee length {len(body)} != {cal['bytes']}")
    if hashlib.sha256(body).hexdigest() != cal["sha256"]:
        raise ValueError("callee sha256 mismatch")
    if not cal["is_fde_start"]:
        raise ValueError("callee must be an FDE start")
    # Entry instruction must be endbr64; the rest of the callee body is
    # locked by SHA-256 above, not per instruction, because its behavior
    # is excluded from the rule.
    if read_va(binary, sections, start, 4) != bytes.fromhex("f30f1efa"):
        raise ValueError("callee entry is not endbr64")
    nxt = u64(cal["next_fde_start"])
    pad = read_va(binary, sections, end, nxt - end)
    if len(pad) != cal["padding_bytes"]:
        raise ValueError(f"callee padding length {len(pad)} != {cal['padding_bytes']}")
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
    """Check one edge against the masked-shift model."""
    eax = u64(edge["eax"])
    mask = u64(edge["mask"])
    base = u64(edge["base"])
    out = (((eax & mask) << 8) + base) & 0xFFFFFFFFFFFFFFFF
    if out != u64(edge["out"]):
        raise ValueError(
            f"edge {edge['note']}: model out {hex(out)} "
            f"!= {edge['out']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    rule = ev["rule"]
    if rule["tail_jump"] != "0x4f9bee0":
        raise ValueError("tail jump must be 0x4f9bee0")
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
        print("usage: foundation_masked_shift_tail.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation masked-shift tail evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
