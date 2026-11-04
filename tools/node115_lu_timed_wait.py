#!/usr/bin/env python3
"""Verifier for the RE-001-node115-lu-timed-wait packet.

Checks the node #115 binary (never executes it) against the packet's
pinned records: target digest, timed-wait body hash, single ret, futex
numbers, xorshift shifts, division magic, deadline-add call, GOT census
inside the body, and the caller census (0 direct E8, 40 GOT sites).
Exits nonzero naming the failing check.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-timed-wait"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"
RECORDS = PACKET / "records.json"

TARGET_SIZE = 105896032
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY_LO, BODY_HI = 0x5BB2440, 0x5BB35ED
BODY_SHA = "4f25e4444597bae4621a1bbb55307355749ce1e2e970efdb90f4e47ed0de9f19"
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
GOT_CLEANUP, GOT_CREATE, GOT_HELPER = 0x64EC150, 0x64EC158, 0x64EC160
GOT_CTOR, GOT_DEADLINE_ADD = 0x64EC170, 0x64EC178
GOT_SYSCALL, GOT_YIELD, GOT_SELF = 0x64E06B8, 0x64E1558, 0x64E0FF0


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
    if records["bodies"]["timed_wait"]["bytes"] != BODY_HI - BODY_LO:
        fail("records body byte count mismatch (4525 expected)")
    if records["bodies"]["timed_wait"]["sha256"] != BODY_SHA:
        fail("records body sha mismatch")

    body = data[BODY_LO - 0x1000:BODY_HI - 0x1000]
    if len(body) != BODY_HI - BODY_LO:
        fail("body length mismatch")
    if hashlib.sha256(body).hexdigest() != BODY_SHA:
        fail("body hash mismatch")
    pinned = bytes.fromhex((PACKET / "fde2440.hex").read_text().strip())
    # Needle checks run on the pinned bytes first, so each corruption
    # control fails at its own check rather than at the equality check.
    def site(va):
        return va - BODY_LO
    needles = [
        (site(0x5BB2440), bytes.fromhex("55415741564155415453"), "body prologue"),
        (site(0x5BB2456), bytes.fromhex("48bb157c4a7fb979379e"), "golden-ratio constant load"),
        (site(0x5BB2490), bytes.fromhex("81fa00ca9a3b"), "deadline nanos cmp 10^9"),
        (site(0x5BB25BC), bytes.fromhex("bfca000000"), "first timed futex nr 202"),
        (site(0x5BB25C4), bytes.fromhex("ba80000000"), "futex wait op 0x80"),
        (site(0x5BB29A0), bytes.fromhex("bfca000000"), "first untimed futex nr 202"),
        (site(0x5BB2F14), bytes.fromhex("48c7c0f6ffffff"), "xadd -10 setup"),
        (site(0x5BB317B), bytes.fromhex("c1e60d"), "xorshift <<13"),
        (site(0x5BB3182), bytes.fromhex("c1ef11"), "xorshift >>17"),
        (site(0x5BB3189), bytes.fromhex("c1e105"), "xorshift <<5"),
        (site(0x5BB3192), bytes.fromhex("4869f183de1b43"), "division magic 0x431bde83"),
        (site(0x5BB3199), bytes.fromhex("48c1ee32"), "division shift 50"),
        (site(0x5BB319D), bytes.fromhex("69f640420f00"), "mod 10^6 multiply"),
        (site(0x5BB33E3), bytes.fromhex("bfca000000"), "wake futex nr 202"),
        (site(0x5BB33E8), bytes.fromhex("ba81000000"), "wake op 0x81"),
        (site(0x5BB3486), bytes.fromhex("c3"), "single ret"),
    ]
    for off, needle, name in needles:
        if pinned[off:off + len(needle)] != needle:
            fail(f"fde2440.hex missing {name} at body offset {hex(off)}")
    if pinned != body:
        fail("fde2440.hex != binary body")
    if body[0x1046] != 0xC3:
        fail("ret misplaced (expected c3 at body offset 0x1046)")

    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    # GOT census inside the body: exact slot matches only.
    counts = {}
    for i in range(BODY_LO - TEXT_VA, BODY_HI - TEXT_VA - 6):
        if text[i] == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            slot = TEXT_VA + i + 6 + disp
            counts[slot] = counts.get(slot, 0) + 1
    want = {GOT_CLEANUP: 10, GOT_CREATE: 3, GOT_HELPER: 3, GOT_CTOR: 2,
            GOT_DEADLINE_ADD: 1, GOT_SYSCALL: 3, GOT_YIELD: 2}
    for slot, n in want.items():
        if counts.get(slot, 0) != n:
            fail(f"GOT {hex(slot)} sites != {n} (got {counts.get(slot, 0)})")
    # Caller census for the body itself: 0 direct E8, 40 GOT-self sites.
    e8_self = 0
    got_self = 0
    for i in range(len(text) - 6):
        b = text[i]
        if b == 0xE8:
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VA + i + 5 + rel == BODY_LO:
                e8_self += 1
        elif b == 0xFF and text[i + 1] == 0x15:
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if TEXT_VA + i + 6 + disp == GOT_SELF:
                got_self += 1
    if e8_self != 0:
        fail(f"direct E8 callers != 0 (got {e8_self})")
    if got_self != 40:
        fail(f"GOT caller sites != 40 (got {got_self})")
    print(f"Verified node #115 lu timed-wait packet: body 0x5bb2440..0x5bb35ed "
          f"(4525B, single ret), 5 futex sites, xorshift 13/17/5 mod 10^6, "
          f"0 direct callers, 40 GOT caller sites")


if __name__ == "__main__":
    main()
