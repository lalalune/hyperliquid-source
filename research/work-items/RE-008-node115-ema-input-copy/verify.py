#!/usr/bin/env python3
"""Digest-bound static check of one conditional owner-to-query input copy."""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x2E0A79E, 0x2E0A7FB
RAW = bytes.fromhex(
    "0fb68424200200003c2e0f852a020000488b842438020000"
    "0f108424280200000f298424d001000048898424e0010000"
    "488b04244c8da038050000488db424d00100004c89e7"
    "ff1526df6d03488db424d00100004c89e7ff151ddf6d03"
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def facts(raw, reloc):
    def at(va, hexbytes):
        expected = bytes.fromhex(hexbytes)
        require(raw[va-START:va-START+len(expected)] == expected, f"instruction differs at {va:#x}")
    require(len(raw) == END-START, "excerpt extent")
    at(0x2E0A79E, "0fb6842420020000")  # prior result tag
    at(0x2E0A7A6, "3c2e0f852a020000")  # only tag 0x2e takes selected arm
    at(0x2E0A7AE, "488b842438020000")  # source tail qword
    at(0x2E0A7B6, "0f10842428020000")  # source first 16 bytes
    at(0x2E0A7BE, "0f298424d0010000")  # destination first 16 bytes
    at(0x2E0A7C6, "48898424e0010000")  # destination tail qword
    at(0x2E0A7D2, "4c8da038050000")  # owner + 0x538
    at(0x2E0A7D9, "488db424d00100004c89e7")
    at(0x2E0A7EA, "488db424d00100004c89e7")
    for site, slot, target in ((0x2E0A7E4, 0x64E8710, 0x5A722F0),
                               (0x2E0A7F5, 0x64E8718, 0x5A71D90)):
        call = raw[site-START:site-START+6]
        require(call[:2] == b"\xff\x15" and site+6+struct.unpack_from("<i", call, 2)[0] == slot,
                f"call slot differs at {site:#x}")
        require(reloc.get(slot) == (8, 0, target), f"relocation differs at {slot:#x}")
    return {"selected_tag": "0x2e", "source": "rsp+0x228..0x23f",
            "prepared_destination": "rsp+0x1d0..0x1e7", "copy_bytes": 24,
            "first_call": "0x2e0a7e4 -> 0x5a722f0",
            "second_call": "0x2e0a7f5 -> 0x5a71d90"}


def inspect(data):
    require(hashlib.sha256(data).hexdigest() == DIGEST, "target digest")
    sections, _ = unwind_index(data)
    fdes = eh_frame_records(data, sections)[1]
    matches = [f for f in fdes if f["start"] <= START and END <= f["end"]]
    require(len(matches) == 1 and matches[0]["start"] == 0x2E098E0
            and matches[0]["end"] == 0x2E11140 and matches[0]["fde"] == 0x11B2110,
            "owner FDE extent")
    text = next(s for s in sections if s["name"] == ".text")
    off = text["offset"] + START - text["address"]
    require(text["address"] <= START and END <= text["address"]+text["size"], "text bounds")
    excerpt = data[off:off+END-START]
    require(excerpt == RAW, "retained excerpt")
    rela = next(s for s in sections if s["name"] == ".rela.dyn")
    reloc = {}
    for slot, info, addend in struct.iter_unpack("<QQq", data[rela["offset"]:rela["offset"]+rela["size"]]):
        if slot in (0x64E8710, 0x64E8718):
            require(slot not in reloc, "duplicate relocation")
            reloc[slot] = (info & 0xffffffff, info >> 32, addend)
    return facts(excerpt, reloc)


def main():
    data = TARGET.read_bytes()
    observed = inspect(data)
    # Controls target the selected relation after bypassing whole-image integrity.
    reloc = {0x64E8710: (8, 0, 0x5A722F0), 0x64E8718: (8, 0, 0x5A71D90)}
    controls = [(0x2E0A7A7, "tag"), (0x2E0A7B9, "source offset"),
                (0x2E0A7C2, "destination offset"), (0x2E0A7F7, "second slot")]
    for va, label in controls:
        changed = bytearray(RAW)
        changed[va-START] ^= 1
        try:
            facts(changed, reloc)
        except ValueError:
            continue
        raise AssertionError(f"corruption accepted: {label}")
    changed = dict(reloc)
    changed[0x64E8718] = (8, 0, 0x5A71D91)
    try:
        facts(RAW, changed)
    except ValueError:
        pass
    else:
        raise AssertionError("corruption accepted: relocation target")
    print(json.dumps({"target_sha256": DIGEST, "excerpt_bytes": len(RAW),
                      "fde": "0x2e098e0..0x2e11140", "observation": observed,
                      "negative_controls": 5, "captured_binary_executed": False}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
