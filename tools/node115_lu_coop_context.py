#!/usr/bin/env python3
"""Verify the RE-001-node115-lu-coop-context packet against node #115.

Static only: reads the node binary and the packet files, never executes the
node. Exits non-zero on the first failed check.
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-coop-context"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"

NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
NODE_SIZE = 105896032
COOP = (0x5CF3B90, 0x5CF3C32)
COOP_SHA = "4e1e4bdf5cc0958d8dcda1d39d881129a4e7da55b093d24049090e460c5c20ab"
PROCEED = (0x5CFC310, 0x5CFC3D3)
PROCEED_SHA = "324f8fca50735d84a2e13d3c3d667b274a06ccd412587091544846b7a3122a81"
GOT_EXPECTED = {
    0x64E0520: 0x5CF3B90,   # helper (and 51 other sites) -> coop callee
    0x64E0510: 0x5CA0D20,   # TLS init, shared with the helper
    0x64E1090: 0x1680BA0,   # coop budget panic
    0x64E12E0: 0x1680B70,   # proceed landing-pad call
    0x64DF4C0: 0x1680CAB,   # landing-pad cleanup
    0x64ECC20: 0x5CE7020,   # proceed vec grow
}
LOC_EXPECTED = [
    # (slot, file suffix, length, line, col)
    (0x64C6648, "tokio/src/task/coop/mod.rs", 0x40, 397, 13),
    (0x64C6380, "tokio/src/runtime/scheduler/multi_thread/worker.rs", 0x58, 922, 22),
    (0x64C6DE8, "tokio/src/runtime/scheduler/defer.rs", 0x4A, 16, 42),
]


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def main():
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA:
        fail("node digest mismatch")

    def body(va0, va1):
        off = va0 - 0x1000  # .text
        return data[off:off + (va1 - va0)]

    coop = body(*COOP)
    if len(coop) != 162 or hashlib.sha256(coop).hexdigest() != COOP_SHA:
        fail("coop body mismatch")
    pinned = bytes.fromhex((PACKET / "coop.hex").read_text().strip())
    if pinned != coop:
        fail("coop.hex does not match binary body")
    proceed = body(*PROCEED)
    if len(proceed) != 195 or hashlib.sha256(proceed).hexdigest() != PROCEED_SHA:
        fail("proceed body mismatch")
    pinned = bytes.fromhex((PACKET / "proceed.hex").read_text().strip())
    if pinned != proceed:
        fail("proceed.hex does not match binary body")

    # Coop key patterns (offsets relative to COOP[0]).
    def at(buf, va, n):
        return buf[va - COOP[0]:va - COOP[0] + n]
    if at(coop, 0x5CF3B90, 4) != bytes.fromhex("41565350"):
        fail("coop entry pushes missing")
    if at(coop, 0x5CF3B94, 7) != bytes.fromhex("48c7c3d0eeffff"):
        fail("coop TLS base -0x130 missing")
    if at(coop, 0x5CF3B9B, 5) != bytes.fromhex("640fb64348"):
        fail("coop TLS state byte load missing")
    if at(coop, 0x5CF3C0F, 5) != bytes.fromhex("e9fc860000"):
        fail("coop tail jmp to proceed missing")
    if at(coop, 0x5CF3C22, 3) != bytes.fromhex("ff6010"):
        fail("coop tail indirect jmp [rax+0x10] missing")
    if at(coop, 0x5CF3C25, 7) != bytes.fromhex("488d3d54277d00"):
        fail("coop panic lea to worker.rs Location missing")
    if data[0x5CF3C32 - 0x1000] != 0xCC:
        fail("coop int3 padding missing after body")

    # Proceed key patterns (offsets relative to PROCEED[0]).
    def pat(buf, va, n):
        return buf[va - PROCEED[0]:va - PROCEED[0] + n]
    if pat(proceed, 0x5CFC318, 4) != bytes.fromhex("48833f00"):
        fail("proceed guard cmp [rdi],0 missing")
    if pat(proceed, 0x5CFC325, 7) != bytes.fromhex("48c707ffffffff"):
        fail("proceed guard set -1 missing")
    if pat(proceed, 0x5CFC344, 5) != bytes.fromhex("4839440af0"):
        fail("proceed dedup cmp last-pair[0] missing")
    if pat(proceed, 0x5CFC34B, 5) != bytes.fromhex("48397c0af8"):
        fail("proceed dedup cmp last-pair[1] missing")
    if pat(proceed, 0x5CFC35A, 2) != bytes.fromhex("ff10"):
        fail("proceed call [rax] missing")
    if pat(proceed, 0x5CFC3A5, 1) != bytes.fromhex("c3"):
        fail("proceed ret missing")
    if pat(proceed, 0x5CFC3CE, 5) != bytes.fromhex("e87d466f00"):
        fail("proceed landing-pad _Unwind_Resume call missing")

    # .rela.dyn map: offset -> (type, addend).
    rela_off, rela_size = 0x6BE8, 0x163CC8
    relamap = {}
    for i in range(rela_size // 24):
        off, info, add = struct.unpack_from("<QQq", data, rela_off + i * 24)
        relamap[off] = (info & 0xFFFFFFFF, add)

    def va_to_off(va):
        if 0x1419300 <= va < 0x1419300 + 0x4FD7700:
            return 0x1418300 + (va - 0x1419300)
        if 0x430400 <= va < 0x430400 + 0x76E640:
            return va
        if 0x63F3C20 <= va < 0x63F3C20 + 0xEB628:
            return 0x63F1C20 + (va - 0x63F3C20)
        if 0x64DF458 <= va < 0x64DF458 + 0xED00:
            return 0x64DD458 + (va - 0x64DF458)
        if 0x64EE158 <= va < 0x64EE158 + 0x8C8:
            return 0x64EC158 + (va - 0x64EE158)
        return None

    def resolve_slot(va):
        off = va_to_off(va)
        v = struct.unpack_from("<Q", data, off)[0]
        if v:
            return v
        t = relamap.get(va)
        if t and t[0] == 8:
            return t[1]
        fail(f"slot 0x{va:x} unresolvable")

    for slot_va, want in GOT_EXPECTED.items():
        got = resolve_slot(slot_va)
        if got != want:
            fail(f"GOT 0x{slot_va:x} -> 0x{got:x} != 0x{want:x}")

    for slot_va, suffix, length, line, col in LOC_EXPECTED:
        fptr = resolve_slot(slot_va)
        off = va_to_off(slot_va + 8)
        flen = struct.unpack_from("<Q", data, off)[0]
        packed = struct.unpack_from("<Q", data, va_to_off(slot_va + 16))[0]
        if flen != length:
            fail(f"Location 0x{slot_va:x} length 0x{flen:x} != 0x{length:x}")
        if (packed & 0xFFFFFFFF) != line or (packed >> 32) != col:
            fail(f"Location 0x{slot_va:x} line/col mismatch")
        end = data.index(b"\0", fptr)
        if not data[fptr:end].decode(errors="replace").endswith(suffix):
            fail(f"Location 0x{slot_va:x} file mismatch")

    # Census byte-scans over .text.
    text = data[0x1418300:0x1418300 + 0x4FD7700]
    tva = 0x1419300

    def e8_sites(target):
        hits = []
        for m in re.finditer(b"\xe8", text):
            i = m.start()
            if i + 5 > len(text):
                break
            r = struct.unpack_from("<i", text, i + 1)[0]
            if tva + i + 5 + r == target:
                hits.append(tva + i)
        return hits

    def ff15_sites(got):
        hits = []
        for m in re.finditer(b"\xff\x15", text):
            i = m.start()
            if i + 6 > len(text):
                break
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if tva + i + 6 + disp == got:
                hits.append(tva + i)
        return hits

    got_sites = ff15_sites(0x64E0520)
    if len(got_sites) != 52:
        fail(f"coop GOT call sites {len(got_sites)} != 52")
    if 0x5CF2EFE not in got_sites:
        fail("helper coop call site 0x5cf2efe missing from GOT census")
    proc_sites = e8_sites(0x5CFC310)
    if proc_sites != [0x5A34BBC, 0x5A35859]:
        fail(f"proceed E8 sites { [hex(x) for x in proc_sites] } != [0x5a34bbc, 0x5a35859]")
    if e8_sites(0x5CF3B90):
        fail("coop callee has unexpected direct E8 callers")
    if e8_sites(0x15D6E00):
        fail("state machine has unexpected direct E8 callers")
    if e8_sites(0x15D5B00):
        fail("caller2 has unexpected direct E8 callers")
    rela_refs = [o for o, (ty, a) in relamap.items() if a in
                 (0x5CF3B90, 0x15D6E00, 0x15D5B00)]
    if sorted(rela_refs) != [0x6401300, 0x64014C0, 0x64E0520]:
        fail(f"RELATIVE refs mismatch: {[hex(x) for x in sorted(rela_refs)]}")

    print("Verified node #115 lu.rs coop-context packet: "
          "coop 0x5cf3b90..0x5cf3c32 (162B), proceed 0x5cfc310..0x5cfc3d3 (195B)")
    print("GOT slots: 6; Location records: 3; coop GOT sites: 52; "
          "proceed E8 sites: 2")


if __name__ == "__main__":
    main()
