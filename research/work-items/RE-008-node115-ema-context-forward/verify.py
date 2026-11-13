#!/usr/bin/env python3
"""Static #115 check of a selected context-forwarding arm; never runs the target."""
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
START, END = 0x4DE2150, 0x4DE2556
BODY_HASH = "7e6a95742e5b547a797dcbe13598164012c9e05d7ba4b2b296bda612dbfa51fb"
WINDOWS = {
    (0x4DE216E, 0x4DE21A0): bytes.fromhex(
        "31c0483b070f817e000000488d7b08488b462048898424e0000000"
        "0f10060f104e100f298c24d00000000f298424c0000000"),
    (0x4DE2321, 0x4DE236F): bytes.fromhex(
        "488d4b18488d9424c0000000488994249000000048898c2498000000"
        "4889b424a000000048898424a80000000f57c00f118424b0000000"
        "488d7c2458488db4249000000048897c2450e8d1cb3600"),
}


def require(ok, detail):
    if not ok:
        raise ValueError(detail)


def facts(body):
    require(len(body) == END-START, "body extent")
    for (a, z), raw in WINDOWS.items():
        require(len(raw) == z-a and body[a-START:z-START] == raw, f"selected instructions at {a:#x}")
    # At 0x4de2170, 0 - [rdi] overflows only for signed i64::MIN.
    require(body[0x4DE216E-START:0x4DE2179-START] == bytes.fromhex("31c0483b070f817e000000"),
            "sentinel branch")
    require(body[0x4DE217D-START:0x4DE21A0-START] == bytes.fromhex(
        "488b462048898424e00000000f10060f104e10"
        "0f298c24d00000000f298424c0000000"), "40-byte context copy")
    call = body[0x4DE236A-START:0x4DE236F-START]
    require(call[0] == 0xE8 and 0x4DE236F + struct.unpack_from("<i", call, 1)[0] == 0x514EF40,
            "selected helper edge")
    return {"sentinel": "0x8000000000000000", "copied_context_bytes": 40,
            "source": "incoming RSI+0..+0x27", "local_copy": "rsp+0xc0..+0xe7",
            "forwarded_context": "local copy via descriptor at rsp+0x90",
            "selected_helper": "0x514ef40"}


def inspect(data):
    require(hashlib.sha256(data).hexdigest() == SHA, "target digest")
    sections, _ = unwind_index(data)
    fdes = eh_frame_records(data, sections)[1]
    require(sum(f["start"] == START and f["end"] == END and f["fde"] == 0x12FAE40
                for f in fdes) == 1, "actual FDE")
    text = next(s for s in sections if s["name"] == ".text")
    require(text["address"] <= START and END <= text["address"]+text["size"], "text bounds")
    off = text["offset"] + START - text["address"]
    body = data[off:off+END-START]
    require(hashlib.sha256(body).hexdigest() == BODY_HASH, "complete body digest")
    return facts(body), body


def main():
    observation, body = inspect(TARGET.read_bytes())
    controls = (0x4DE2173, 0x4DE2180, 0x4DE2195, 0x4DE2328, 0x4DE236B)
    for va in controls:
        changed = bytearray(body)
        changed[va-START] ^= 1
        try:
            facts(changed)
        except ValueError:
            continue
        raise AssertionError(f"corruption accepted at {va:#x}")
    print(json.dumps({"target_sha256": SHA, "fde": "0x4de2150..0x4de2556",
                      "body_bytes_authenticated": len(body), "selected_bytes_compared": 50+78,
                      "negative_controls": len(controls), "observation": observation,
                      "captured_binary_executed": False}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
