#!/usr/bin/env python3
"""Verify the digest-bound static BOLE caller dataflow packet; never execute the target."""
from pathlib import Path
import hashlib
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SLOT = 0x64E71B0
HELPER = 0x3699410
CALL_VA = 0x54B2724


def main():
    data = TARGET.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == EXPECTED_SHA256, f"target digest mismatch: {digest}"
    sec_list = sections(data)
    text = [s for s in sec_list if s["name"] == ".text"]
    assert len(text) == 1

    def at(va, size):
        matches = [s for s in text if s["address"] <= va and va + size <= s["address"] + s["size"]]
        assert len(matches) == 1, f"VA not uniquely mapped in .text: {va:#x}"
        s = matches[0]
        off = s["offset"] + va - s["address"]
        return data[off:off + size]

    checks = {
        0x54B259F: "4d8da770060000",
        0x54B25D1: "4c89642430",
        0x54B271A: "488d7c2460",
        0x54B271F: "488b742430",
        CALL_VA: "ff15864a0301",
        0x54B272A: "488b4c2460",
        0x54B272F: "440fb6642468",
        0x54B2754: "0fb64c246f",
        0x54B275C: "0fb754246d",
        0x54B2763: "8b6c2469",
        0x54B2767: "48c1e228",
        0x54B276B: "48c1e508",
        0x54B276F: "4809d5",
        0x54B2772: "4809c5",
        0x54B29E3: "488b4508",
        0x54B29E7: "4885c0",
        0x54B29EA: "0f8418010000",
        HELPER: "55415741564155415453",
        0x369941E: "4889f5",
        0x3699421: "4989fd",
        0x36995B7: "4c89e8",
        0x36995C8: "c3",
    }
    for va, expected in checks.items():
        actual = at(va, len(bytes.fromhex(expected))).hex()
        assert actual == expected, f"instruction bytes differ at {va:#x}: {actual}"

    call = at(CALL_VA, 6)
    displacement = struct.unpack("<i", call[2:6])[0]
    slot = CALL_VA + 6 + displacement
    assert slot == SLOT, f"RIP-relative call resolves to {slot:#x}, expected {SLOT:#x}"

    rela = [s for s in sec_list if s["name"] == ".rela.dyn"]
    assert len(rela) == 1
    found = []
    for off in range(rela[0]["offset"], rela[0]["offset"] + rela[0]["size"], 24):
        offset, info, addend = struct.unpack_from("<QQq", data, off)
        if offset == SLOT:
            found.append((info & 0xFFFFFFFF, info >> 32, addend))
    assert found == [(8, 0, HELPER)], f"unexpected slot relocation: {found}"

    _, fdes = eh_frame_records(data, sec_list)
    parent = [f for f in fdes if f["start"] <= 0x54B29EA < f["end"]]
    helper = [f for f in fdes if f["start"] == HELPER]
    assert [(f["start"], f["end"]) for f in parent] == [(0x54A9C70, 0x54B66A2)]
    assert len(helper) == 1 and helper[0]["end"] == 0x3699613

    corrupted = bytearray(call)
    corrupted[2] = (corrupted[2] + 1) & 0xFF
    corrupted_target = CALL_VA + 6 + struct.unpack("<i", corrupted[2:6])[0]
    assert corrupted_target != SLOT, "corrupted displacement unexpectedly kept the GOT slot"

    print(f"target SHA-256: {digest}")
    print(f"branch input bytes, GOT relocation, and parent/helper FDEs: verified")
    print(f"corrupted displacement negative control: rejected ({corrupted_target:#x})")


if __name__ == "__main__":
    main()
