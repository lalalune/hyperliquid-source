#!/usr/bin/env python3
"""Verifier for the RE-001-node115-lu-entry-word packet.

Checks the node #115 binary (never executes it) against the packet's
pinned records: target digest, helper body hash, word-transition sites
(claim/lock/push/futex), and the call-site census (2 direct E8 lookup
callers, 3 GOT park sites, 13 GOT helper sites, 44 GOT cleanup sites).
Exits nonzero naming the failing check.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-entry-word"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"
RECORDS = PACKET / "records.json"

TARGET_SIZE = 105896032
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
HELPER_LO, HELPER_HI = 0x5BB6790, 0x5BB68D9
HELPER_SHA = "a94378e14e8639339101729a199bd051e7795fc54c0ca9f2ff528bffcf902be8"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
LOOKUP = 0x5BB4D00
GOT_PARK, GOT_HELPER, GOT_CLEANUP = 0x64EC188, 0x64EC160, 0x64EC150


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    data = NODE.read_bytes()
    if len(data) != TARGET_SIZE:
        fail(f"node size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("node digest mismatch")
    records = json.loads(RECORDS.read_text())
    if records["bodies"]["helper"]["bytes"] != HELPER_HI - HELPER_LO:
        fail("records helper byte count mismatch (329 expected)")
    if records["bodies"]["helper"]["sha256"] != HELPER_SHA:
        fail("records helper sha mismatch")

    helper = data[HELPER_LO - 0x1000:HELPER_HI - 0x1000]
    if len(helper) != HELPER_HI - HELPER_LO:
        fail("helper body length mismatch")
    if hashlib.sha256(helper).hexdigest() != HELPER_SHA:
        fail("helper body hash mismatch")
    pinned = bytes.fromhex((PACKET / "helper.hex").read_text().strip())
    # Needle checks run on the pinned bytes first, so each corruption
    # control fails at its own check rather than at the equality check.
    def site(va):
        return va - HELPER_LO
    needles = [
        (site(0x5BB6790), bytes.fromhex("55415741564155415453"), "helper prologue"),
        (site(0x5BB67CB), bytes.fromhex("f0480fb10b"), "acquire cmpxchg bit 0"),
        (site(0x5BB67D7), bytes.fromhex("4883f804"), "spin cmp word,4"),
        (site(0x5BB67DE), bytes.fromhex("83fd0a"), "spin cmp rounds,10"),
        (site(0x5BB67E8), bytes.fromhex("83fd03"), "yield threshold cmp rounds,3"),
        (site(0x5BB6874), bytes.fromhex("83e103"), "push flags mask and ecx,3"),
        (site(0x5BB6877), bytes.fromhex("4c09f9"), "push or rcx,r15 (node | flags)"),
        (site(0x5BB687A), bytes.fromhex("f0480fb10b"), "push cmpxchg"),
        (site(0x5BB68A0), bytes.fromhex("bfca000000"), "futex nr 202"),
        (site(0x5BB68A8), bytes.fromhex("ba80000000"), "futex op 0x80"),
        (site(0x5BB68AD), bytes.fromhex("b901000000"), "futex count 1"),
        (site(0x5BB68B7), bytes.fromhex("41ffd5"), "futex syscall call"),
        (site(0x5BB68D8), bytes.fromhex("c3"), "helper ret"),
    ]
    for off, needle, name in needles:
        if pinned[off:off + len(needle)] != needle:
            fail(f"helper.hex missing {name} at body offset {hex(off)}")
    if pinned != helper:
        fail("helper.hex != binary body")
    if helper[0x148] != 0xC3 or helper[0x147] != 0x5D:
        fail("helper ret/pop rbp misplaced")

    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    e8_lookup = 0
    park_sites, helper_sites = [], []
    nc = 0
    for i in range(len(text) - 5):
        b = text[i]
        if b == 0xE8:
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VA + i + 5 + rel == LOOKUP:
                e8_lookup += 1
        elif b == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            slot = TEXT_VA + i + 6 + disp
            if slot == GOT_PARK:
                park_sites.append(TEXT_VA + i)
            elif slot == GOT_HELPER:
                helper_sites.append(TEXT_VA + i)
            elif slot == GOT_CLEANUP:
                nc += 1
    if e8_lookup != 2:
        fail("E8 lookup callers != 2")
    if len(park_sites) != 3:
        fail(f"GOT park call sites != 3 (got {len(park_sites)})")
    if len(helper_sites) != 13:
        fail(f"GOT helper call sites != 13 (got {len(helper_sites)})")
    if nc != 44:
        fail(f"GOT cleanup call sites != 44 (got {nc})")
    want_helper = [int(x, 16) for x in records["census"]["got_helper_call_sites"]]
    if helper_sites != want_helper:
        fail("GOT helper call sites mismatch records")
    print(f"Verified node #115 lu entry-word packet: helper 0x5bb6790..0x5bb68d9 "
          f"(329B, 104 instructions), census 2 E8 lookup / 3 GOT park / "
          f"13 GOT helper / 44 GOT cleanup sites")


if __name__ == "__main__":
    main()
