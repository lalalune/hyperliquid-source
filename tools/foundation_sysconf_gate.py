#!/usr/bin/env python3
"""Checker for the foundation sysconf threshold gate (node #94, 0x5335bf0).

Stdlib only. Run from the repository root:

    python3 tools/foundation_sysconf_gate.py \\
        --check research/work-items/foundation-sysconf-gate-94/evidence.json

Every claim is re-derived from target bytes: the 48-byte window body, its
zero padding (the next FDE starts immediately at the window end), the
retained FDE records (window, next, previous, each locked under its own
CIE read from the cie= field, never from the third-column CIE-pointer
delta), the PLT stub bytes, its GOT slot and the relocation record naming
sysconf, the call and store encodings, the gate rule on its edges, the
callee's four direct call sites, and the full direct-caller scan (exactly
zero sites). A failure prints the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x5335BF0: "f30f1efa",
    0x5335BF4: "4883ec08",
    0x5335BF8: "bf1e000000",
    0x5335BFD: "e80ea63200",
    0x5335C02: "ba00100000",
    0x5335C07: "483dff030000",
    0x5335C0D: "480f4ec2",
    0x5335C11: "488d15889c4500",
    0x5335C18: "488902",
    0x5335C1B: "4883c408",
    0x5335C1F: "c3",
}

WINDOW_START = 0x5335BF0
CALLEE_START = 0x5660210
STORE_ADDR = 0x578F8A0
GOT_SLOT = 0x5778E30
PLT_STUB = "ff251a8c11006812000000e9c0feffff"


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


def section_of(sections, va):
    for name, (addr, off, size) in sections.items():
        if addr <= va < addr + size:
            return name
    raise ValueError(f"VA {hex(va)} not in any section")


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
    # The call must target the PLT stub: rel32 from the end of the call.
    enc = read_va(binary, sections, 0x5335BFD, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x5335BFD + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the PLT stub")
    # The first argument must be the constant 30.
    if read_va(binary, sections, 0x5335BF8, 5) != bytes.fromhex("bf1e000000"):
        raise ValueError("first argument is not mov edi, 30")
    # The floor constant must be 0x1000.
    if read_va(binary, sections, 0x5335C02, 5) != bytes.fromhex("ba00100000"):
        raise ValueError("floor constant is not mov edx, 0x1000")
    # The threshold compare must be cmp rax, 0x3ff.
    if read_va(binary, sections, 0x5335C07, 6) != bytes.fromhex("483dff030000"):
        raise ValueError("threshold compare is not cmp rax, 0x3ff")
    # The gate must be cmovle rax, rdx.
    if read_va(binary, sections, 0x5335C0D, 4) != bytes.fromhex("480f4ec2"):
        raise ValueError("gate is not cmovle rax, rdx")
    # The store address must resolve to the .bss global.
    enc = read_va(binary, sections, 0x5335C11, 7)
    (rel,) = struct.unpack_from("<i", enc, 3)
    if 0x5335C18 + rel != STORE_ADDR:
        raise ValueError("store address is not 0x578f8a0")
    if section_of(sections, STORE_ADDR) != ".bss":
        raise ValueError("store address is not in .bss")
    # The window must end with ret, not a tail jump.
    if read_va(binary, sections, 0x5335C1F, 1) != b"\xc3":
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


def dynsym_name(binary, sections, index):
    addr, off, size = sections[".dynsym"]
    saddr, soff, ssize = sections[".dynstr"]
    ent = off + index * 24
    (st_name,) = struct.unpack_from("<I", binary, ent)
    end = binary.index(b"\x00", soff + st_name)
    return binary[soff + st_name:end].decode()


def check_plt(ev, binary, sections):
    cal = ev["callee"]
    start = u64(cal["start_va"])
    if cal["is_fde_start"]:
        raise ValueError("callee must not be an FDE start (it is a PLT stub)")
    stub = read_va(binary, sections, start, cal["bytes"])
    if stub.hex() != cal["stub_bytes"]:
        raise ValueError(f"PLT stub bytes mismatch: {stub.hex()}")
    if hashlib.sha256(stub).hexdigest() != cal["sha256"]:
        raise ValueError("PLT stub sha256 mismatch")
    # The stub's indirect jump must target the recorded GOT slot.
    enc = read_va(binary, sections, start, 6)
    (rel,) = struct.unpack_from("<i", enc, 2)
    if start + 6 + rel != u64(cal["got_slot"]):
        raise ValueError("PLT stub GOT slot mismatch")
    if section_of(sections, u64(cal["got_slot"])) != cal["got_section"]:
        raise ValueError("GOT slot is not in .got.plt")
    # The GOT slot value is the lazy-binding fallback (the push site).
    (val,) = struct.unpack_from(
        "<Q", read_va(binary, sections, u64(cal["got_slot"]), 8))
    if val != u64(cal["got_value"]):
        raise ValueError(f"GOT slot value {hex(val)} != {cal['got_value']}")
    # The relocation record for the GOT slot must name sysconf.
    addr, off, size = sections[".rela.plt"]
    found = None
    for i in range(size // 24):
        r_off, r_info, _ = struct.unpack_from("<QQq", binary, off + i * 24)
        if r_off == u64(cal["got_slot"]):
            found = (r_info >> 32, r_info & 0xFFFFFFFF)
            break
    if found is None:
        raise ValueError("no .rela.plt entry for the GOT slot")
    symidx, rtype = found
    if rtype != cal["rela_type"]:
        raise ValueError(f"relocation type {rtype} != {cal['rela_type']}")
    if dynsym_name(binary, sections, symidx) != cal["rela_symbol"]:
        raise ValueError("relocation symbol is not sysconf")
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
    """Check one edge against the signed threshold-gate model."""
    ret = u64(edge["ret"])
    signed = ret - (1 << 64) if ret >= (1 << 63) else ret
    out = 0x1000 if signed <= 0x3FF else ret
    if out != u64(edge["stored"]):
        raise ValueError(
            f"edge {edge['note']}: model out {hex(out)} "
            f"!= {edge['stored']}")


def check_edges(ev):
    for edge in ev["rule"]["edges"]:
        evaluate_edge(edge)
    if ev["rule"]["gate"] != "signed ret <= 0x3ff ? 0x1000 : ret":
        raise ValueError("gate formula mismatch")
    if ev["store"]["address"] != "0x578f8a0":
        raise ValueError("store address mismatch")
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
    check_plt(ev, binary, sections)
    check_callers(ev, binary, sections)
    check_edges(ev)


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_sysconf_gate.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    try:
        run_all(argv[2])
    except (ValueError, KeyError, FileNotFoundError, OSError) as exc:
        print(f"check failed: {exc}", file=sys.stderr)
        return 1
    print("Foundation sysconf gate evidence reproduces exactly.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
