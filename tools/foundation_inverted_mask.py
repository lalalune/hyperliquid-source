#!/usr/bin/env python3
"""Checker for the foundation inverted-mask helper (node #94, 0x36f5790).

Stdlib only. Run from the repository root:

    python3 tools/foundation_inverted_mask.py \
        --check research/work-items/foundation-inverted-mask-94/evidence.json

Every claim is re-derived from target bytes: the 82-byte window body, its
14-byte int3 padding, the retained FDE records (window, next, previous,
callee, callee-next, each locked under its own CIE read from the cie=
field, never from the third-column CIE-pointer delta), the callee body
and its exact int3 padding, the call encoding, the descriptor layout
immediates, the inverted-mask rule on its edges, the zero direct callers
of the window, and the full 3-site callee call list. A failure prints
the mismatching check and exits nonzero.
"""

import hashlib
import json
import os
import struct
import sys

BINARY = os.path.join("artifacts", "node", "94", "hl-node")

# Instruction byte strings at fixed offsets, from the retained disassembly.
INSTR = {
    0x36F5790: "53",
    0x36F5791: "4883ec30",
    0x36F5795: "4889fb",
    0x36F5798: "488b06",
    0x36F579B: "488b4e08",
    0x36F579F: "488d4c0801",
    0x36F57A4: "660f6f00",
    0x36F57A8: "660fd7d0",
    0x36F57AC: "f7d2",
    0x36F57AE: "6689542420",
    0x36F57B3: "4889442408",
    0x36F57B8: "4883c010",
    0x36F57BC: "4889442410",
    0x36F57C1: "48894c2418",
    0x36F57C6: "488b4618",
    0x36F57CA: "4889442428",
    0x36F57CF: "488d742408",
    0x36F57D4: "e8b7ca4b00",
    0x36F57D9: "4889d8",
    0x36F57DC: "4883c430",
    0x36F57E0: "5b",
    0x36F57E1: "c3",
}

WINDOW_START = 0x36F5790
CALLEE_START = 0x3BB2290


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
    enc = read_va(binary, sections, 0x36F57D4, 5)
    (rel,) = struct.unpack_from("<i", enc, 1)
    if 0x36F57D4 + 5 + rel != CALLEE_START:
        raise ValueError("call target is not the callee")
    # The window must end with pop rbx; ret (it returns obj in rax).
    if read_va(binary, sections, 0x36F57E1, 1) != b"\xc3":
        raise ValueError("window does not end with ret")


def check_padding(ev, binary, sections):
    fn = ev["function"]
    end = u64(fn["end_va_exclusive"])
    pad = read_va(binary, sections, end, fn["padding_bytes"])
    if pad.hex() != fn["padding_hex"]:
        raise ValueError(f"window padding mismatch: {pad.hex()}")
    prev_end = 0x36F5782
    gap = read_va(binary, sections, prev_end, fn["prev_gap_bytes"])
    if gap.hex() != fn["prev_gap_hex"]:
        raise ValueError(f"previous gap mismatch: {gap.hex()}")
    cal = ev["callee"]
    cend = u64(cal["end_va_exclusive"])
    cpad = read_va(binary, sections, cend, cal["padding_bytes"])
    if cpad.hex() != cal["padding_hex"]:
        raise ValueError(f"callee padding mismatch: {cpad.hex()}")


def check_frames(ev, packet_dir):
    with open(os.path.join(packet_dir, "frames.txt")) as fh:
        lines = fh.read().splitlines()
    fn = ev["function"]
    cal = ev["callee"]
    # (section offset, pc start, pc end, cie value, label)
    records = [
        (fn["fde_section_offset"], fn["start_va"], fn["end_va_exclusive"],
         fn["fde_cie"], "window"),
        (fn["next_fde_section_offset"], fn["next_fde_start"], "0x36f5948",
         fn["next_fde_cie"], "window-next"),
        (fn["prev_fde_section_offset"], fn["prev_fde_start"], "0x36f5782",
         fn["prev_fde_cie"], "window-prev"),
        (cal["fde_section_offset"], cal["start_va"], cal["end_va_exclusive"],
         cal["fde_cie"], "callee"),
        (cal["next_fde_section_offset"], cal["next_fde_start"], "0x3bb27ba",
         cal["next_fde_cie"], "callee-next"),
    ]
    for off, start, end, cie, label in records:
        header = None
        for line in lines:
            if line.startswith(off[2:] + " ") and " FDE " in line:
                header = line
                break
        if header is None:
            raise ValueError(f"{label} FDE header not in frames.txt")
        want_pc = f"pc={int(start, 16):016x}..{int(end, 16):016x}"
        if want_pc not in header:
            raise ValueError(f"{label} FDE PC range not on its header line")
        if f"cie={cie[2:]}" not in header:
            raise ValueError(f"{label} FDE CIE not on its header line")


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


def check_callers(ev, binary, sections):
    taddr, toff, tsize = sections[".text"]
    text = binary[toff:toff + tsize]
    window_sites = []
    callee_sites = []
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            (rel,) = struct.unpack_from("<i", text, i + 1)
            tgt = taddr + i + 5 + rel
            if tgt == WINDOW_START:
                window_sites.append(hex(taddr + i))
            if tgt == CALLEE_START:
                callee_sites.append(hex(taddr + i))
    if window_sites != ev["incoming"]["direct_e8_callers"]:
        raise ValueError(f"window callers mismatch: {window_sites}")
    if callee_sites != ev["callee"]["direct_e8_call_sites"]:
        raise ValueError(f"callee call sites mismatch: {callee_sites}")


def check_edges(ev):
    # Model checks on the recorded mask arithmetic, not target executions.
    cases = [
        (0x0000, 0xFFFF),
        (0xFFFF, 0x0000),
        (0x0001, 0xFFFE),
        (0x5555, 0xAAAA),
        (0x8000, 0x7FFF),
    ]
    for msb, want in cases:
        got = (~msb) & 0xFFFF
        if got != want:
            raise ValueError(f"mask edge {hex(msb)}: {hex(got)} != {hex(want)}")
    edges = ev["rule"]["mask_edges"]
    if edges["0x0000_msb_none"] != "pmovmskb = 0x0000 -> mask = 0xffff":
        raise ValueError("mask edge record mismatch (none)")
    if edges["0xffff_all_set"] != "pmovmskb = 0xffff -> mask = 0x0000":
        raise ValueError("mask edge record mismatch (all)")


def run_all(ev_path):
    packet_dir = os.path.dirname(ev_path)
    with open(ev_path) as fh:
        ev = json.load(fh)
    with open(BINARY, "rb") as fh:
        binary = fh.read()
    sections = elf_sections(binary)
    check_target_digest(ev, binary)
    check_window(ev, binary, sections)
    check_padding(ev, binary, sections)
    check_frames(ev, packet_dir)
    check_callee(ev, binary, sections)
    check_callers(ev, binary, sections)
    check_edges(ev)
    print("Foundation inverted-mask evidence reproduces exactly.")


def main(argv):
    if len(argv) != 3 or argv[1] != "--check":
        print("usage: foundation_inverted_mask.py --check <evidence.json>",
              file=sys.stderr)
        return 2
    run_all(argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
