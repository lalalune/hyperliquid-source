#!/usr/bin/env python3
"""Verify the RE-001-node115-lu-tag-meaning packet against node #115.

Static only: reads the node binary and the packet files, never executes the
node. Exits non-zero on the first failed check.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-tag-meaning"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"

NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
NODE_SIZE = 105896032
HELPER = (0x5CF2D30, 0x5CF2FEF)
HELPER_SHA = "fb3fb193f0b14f251e01da509c670d299323482419d1edef4170d948604cbbb2"
CALLSITE = (0x15D5F37, 0x15D5F8E)
CALLSITE_SHA = "56fbd53f6667c43e9170489c9afa13064f9c88334123219dd640d03a3b6cdcbb"
GOT_EXPECTED = {
    0x64E0858: 0x5CF2D30,
    0x64E0510: 0x5CA0D20,
    0x64E0518: 0x5CE91B0,
    0x64E0520: 0x5CF3B90,
    0x64DF770: 0x1680BD0,
    0x64DF6B8: 0x1680E80,
    0x64DF4C0: 0x1680CAB,
}
LOC_EXPECTED = [
    (0x64C6158, "tokio/src/runtime/time/entry.rs", 549, 30),
    (0x64C6140, "tokio/src/runtime/time/entry.rs", 539, 9),
    (0x64C6700, "tokio/src/time/sleep.rs", 467, 23),
]
PANIC_MSG = (b"A Tokio 1.x context was found, but timers are disabled. Call "
             b"`enable_time` on the runtime builder to enable timers.")


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def text_at(va, n, delta):
    with NODE.open("rb") as fh:
        fh.seek(va - delta)
        return fh.read(n)


def main():
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA:
        fail("node digest mismatch")

    def body(va0, va1):
        off = va0 - 0x1000  # .text
        return data[off:off + (va1 - va0)]

    helper = body(*HELPER)
    if len(helper) != 703 or hashlib.sha256(helper).hexdigest() != HELPER_SHA:
        fail("helper body mismatch")
    pinned = bytes.fromhex((PACKET / "helper.hex").read_text().strip())
    if pinned != helper:
        fail("helper.hex does not match binary body")
    # Return-condition byte patterns.
    if helper[0x5CF2E9E - HELPER[0]:0x5CF2E9E - HELPER[0] + 4] != bytes.fromhex("4883f8ff"):
        fail("cmp rax,-1 pattern missing")
    if helper[0x5CF2EE7 - HELPER[0]:0x5CF2EE7 - HELPER[0] + 5] != bytes.fromhex("410fb64658"):
        fail("movzx [r14+0x58] pattern missing")
    if helper[0x5CF2EF0 - HELPER[0]:0x5CF2EF0 - HELPER[0] + 2] != bytes.fromhex("31c0"):
        fail("xor eax,eax (false path) missing")
    if helper[0x5CF2F14 - HELPER[0]] != 0xC3:
        fail("ret missing")
    # 10^9 validation constant present in the body.
    if bytes.fromhex("00ca9a3b") not in helper:
        fail("10^9 constant missing from helper")

    site = body(*CALLSITE)
    if len(site) != 87 or hashlib.sha256(site).hexdigest() != CALLSITE_SHA:
        fail("callsite excerpt mismatch")
    pinned_site = bytes.fromhex((PACKET / "callsite.hex").read_text().strip())
    if pinned_site != site:
        fail("callsite.hex does not match binary excerpt")
    if site[0x15D5F4A - CALLSITE[0]:0x15D5F4A - CALLSITE[0] + 4] != bytes.fromhex("84c0753c"):
        fail("test al,al / jne direction bytes missing")

    # FDE record via readelf.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", str(NODE)],
        capture_output=True, text=True, check=True).stdout
    if "pc=0000000005cf2d30..0000000005cf2fef" not in frames:
        fail("helper FDE record missing")
    if "pc=00000000015d5cb0..00000000015d606b" not in frames:
        fail("conversion FDE record missing")

    # RELATIVE relocations.
    rel = subprocess.run(["readelf", "-r", str(NODE)],
                         capture_output=True, text=True, check=True).stdout
    relocs = {}
    for m in re.finditer(r"([0-9a-f]{6,})\s+0+\d+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", rel):
        relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    for slot, target in GOT_EXPECTED.items():
        if relocs.get(slot) != target:
            fail(f"GOT {slot:#x} -> {relocs.get(slot)} != {target:#x}")

    # Location records: stored pointer is zero, addend is authoritative.
    for addr, suffix, line, col in LOC_EXPECTED:
        off = addr - 0x2000  # .data.rel.ro
        ptr, ln, ln_no, col_no = struct.unpack("<QQII", data[off:off + 24])
        addend = relocs.get(addr, ptr)
        fname = text_at(addend, ln, 0).decode()
        if not fname.endswith(suffix) or ln_no != line or col_no != col:
            fail(f"location {addr:#x} mismatch: {fname}:{ln_no}:{col_no}")

    # Panic strings.
    if text_at(0x94CA6B, 115, 0) != PANIC_MSG:
        fail("tokio timers-disabled message mismatch")
    if text_at(0x433ED3, 14, 0) != b"\rtimer error: ":
        fail("timer error fragment mismatch")
    if text_at(relocs.get(0x64C6648, 0), 64, 0) != (
            b"/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/task/coop/mod.rs"):
        fail("coop path string mismatch")

    # GOT census: ff 15 calls resolving to 0x64e0858; zero direct E8 callers.
    sec = subprocess.run(["readelf", "-S", str(NODE)],
                         capture_output=True, text=True, check=True).stdout
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)", sec)
    tva, toff, tsize = (int(m.group(i), 16) for i in (1, 2, 3))
    text = data[toff:toff + tsize]
    slot = 0x64E0858
    refs = 0
    for i in range(len(text) - 6):
        if text[i] == 0xFF and text[i + 1] == 0x15:
            rel32 = struct.unpack("<i", text[i + 2:i + 6])[0]
            if tva + i + 6 + rel32 == slot:
                refs += 1
    if refs != 27:
        fail(f"GOT census {refs} != 27")
    target = 0x5CF2D30
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel32 = struct.unpack("<i", text[i + 1:i + 5])[0]
            if tva + i + 5 + rel32 == target:
                fail("unexpected direct E8 caller of helper")

    # Packet records cross-check.
    rec = json.loads((PACKET / "records.json").read_text())
    if rec["helper"]["sha256"] != HELPER_SHA:
        fail("records.json helper hash mismatch")
    if rec["callsite_excerpt"]["sha256"] != CALLSITE_SHA:
        fail("records.json callsite hash mismatch")
    if len(rec["got_census"]["sites"]) != 27:
        fail("records.json census mismatch")

    print("Verified node #115 lu.rs tag-meaning packet: helper "
          "0x5cf2d30..0x5cf2fef (703B), callsite 87B, 3 Locations, "
          "27 GOT sites, 0 direct callers")


if __name__ == "__main__":
    main()
