#!/usr/bin/env python3
"""Static #115 proof of the first latency-EMA query wrapper's argument handoff."""
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
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x5A722F0, 0x5A72356
RAW = bytes.fromhex(
    "41574156534883ec404889f34989fe4c8d7c24344c89ffff1583e6a600"
    "498dbe08010000498d8688010000498d8e480100004981c668010000"
    "4c897c240848895c2410488944241848894c24204c89742428"
    "488d742408e804fe36ff4883c4405b415e415fc3"
)


def require(ok, what):
    if not ok:
        raise ValueError(what)


def facts(raw, reloc):
    require(len(raw) == END-START, "body extent")
    def pin(va, expected):
        b = bytes.fromhex(expected)
        require(raw[va-START:va-START+len(b)] == b, f"instruction at {va:#x}")
    pin(0x5A722F9, "4889f3")  # incoming RSI saved in RBX
    pin(0x5A722FC, "4989fe")  # incoming RDI saved in R14
    pin(0x5A722FF, "4c8d7c2434")
    first = raw[0x5A72307-START:0x5A7230D-START]
    require(first[:2] == b"\xff\x15" and 0x5A7230D + struct.unpack_from("<i", first, 2)[0] == 0x64E0990,
            "first helper slot")
    require(reloc.get(0x64E0990) == (8, 0, 0x1629690), "first helper relocation")
    for va, expected in {
        0x5A7230D: "498dbe08010000",  # RDI = owner + 0x108
        0x5A72314: "498d8688010000",  # owner + 0x188
        0x5A7231B: "498d8e48010000",  # owner + 0x148
        0x5A72322: "4981c668010000",  # owner + 0x168
        0x5A72329: "4c897c2408", 0x5A7232E: "48895c2410",
        0x5A72333: "4889442418", 0x5A72338: "48894c2420",
        0x5A7233D: "4c89742428", 0x5A72342: "488d742408",
    }.items():
        pin(va, expected)
    call = raw[0x5A72347-START:0x5A7234C-START]
    require(call[0] == 0xE8 and 0x5A7234C + struct.unpack_from("<i", call, 1)[0] == 0x4DE2150,
            "second helper target")
    return {"entry": hex(START), "first_helper": "0x1629690", "second_helper": "0x4de2150",
            "context_words": ["temporary output at rsp+0x34", "incoming RSI",
                              "incoming RDI+0x188", "incoming RDI+0x148", "incoming RDI+0x168"],
            "second_helper_rdi": "incoming RDI+0x108"}


def inspect(data):
    require(hashlib.sha256(data).hexdigest() == SHA, "target digest")
    sections, _ = unwind_index(data)
    fdes = eh_frame_records(data, sections)[1]
    require(sum(f["start"] == START and f["end"] == END and f["fde"] == 0xFC4C68
                for f in fdes) == 1, "actual FDE")
    text = next(s for s in sections if s["name"] == ".text")
    require(text["address"] <= START and END <= text["address"]+text["size"], "text bounds")
    off = text["offset"] + START - text["address"]
    raw = data[off:off+END-START]
    require(raw == RAW, "whole body")
    rela = next(s for s in sections if s["name"] == ".rela.dyn")
    rows = [(slot, info, add) for slot, info, add in struct.iter_unpack(
        "<QQq", data[rela["offset"]:rela["offset"]+rela["size"]]) if slot == 0x64E0990]
    require(len(rows) == 1, "unique relocation")
    _, info, add = rows[0]
    return facts(raw, {0x64E0990: (info & 0xffffffff, info >> 32, add)})


def main():
    result = inspect(TARGET.read_bytes())
    reloc = {0x64E0990: (8, 0, 0x1629690)}
    for va in (0x5A722F9, 0x5A72310, 0x5A72317, 0x5A7232F, 0x5A72348):
        altered = bytearray(RAW)
        altered[va-START] ^= 1
        try:
            facts(altered, reloc)
        except ValueError:
            continue
        raise AssertionError(f"accepted corruption at {va:#x}")
    print(json.dumps({"target_sha256": SHA, "body_bytes": len(RAW), "negative_controls": 5,
                      "observation": result, "captured_binary_executed": False}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
