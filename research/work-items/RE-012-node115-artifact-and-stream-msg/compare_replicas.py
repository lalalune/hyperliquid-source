#!/usr/bin/env python3
"""Compare the archived replica envelope's native writer route and complete project output."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from entry_start_static import read, relocations, rip_target
from fde_extents import eh_frame_records

# The enclosing writer, named block/record writers, and the selected generic format helpers.
BODIES = {
    0x4E09AB0: "40dc093b83857712c6fb54b8fa15cb762a3be1fbe115693277670fa933466e70",
    0x4D6D890: "d5377347f6624575e789b85523e266a9a0be8336c83c1b2e4f02f563d5d21c88",
    0x4E0BDB0: "7e14a022fd8880fffbe827ec0c7da442416fe8790efd761cf70539cbc4c51b25",
    0x4E0DFC0: "c09d0999c659e6185f01d4437c20a94c12c50d744552f588b55806b5078cf3da",
    0x5307510: "468c825b6a902fad5442f41039143e717ddf926e1cbfcde8c9da8a34a01fc46c",
    0x52AF290: "639181a0e2a87e30fafa0d8454d131824aae27006be69c2050ff9b1dc7498e82",
    0x52F0080: "a7f66ac777fb0a86d06150302405addbbb513737e6a6b3b436353f5a5eb039c1",
    0x57CE100: "cecbd66ced0d55e5289361ba57d8fabf9b9f97c6daef2c786ce166383020cd38",
    0x57CEBA0: "7a7c55ebf4eaa015fc8f6541163ba665be721633b0415814fd93793a82ef3f2b",
    0x57CF860: "27ffc606d1606ba84fff1619d494309645c747711e39d79bcc5ad202ab7bb3f3",
    0x57D00B0: "670d2c2c065027115cde30623f01649150037c55c346d3672c08eb7924f4be66",
}
# Each key's source pointer and the x86 instruction loading its byte count.
KEYS = {
    "abci_block": (0x4D6D90C, 0x4D6D913),
    "time": (0x4D6D97B, 0x4D6D982),
    "signed_action_bundles": (0x4D6D9D8, 0x4D6D9DF),
    "round": (0x4D6DA1B, 0x4D6DA22),
    "parent_round": (0x4D6DA60, 0x4D6DA67),
    "hardfork": (0x4E0BDD9, 0x4E0BDE0),
    "version": (0x4E0BE4E, 0x4E0BE55),
    "hardfork.round": (0x4E0BE87, 0x4E0BE8E),
    "proposer": (0x4E0DFE1, 0x4E0DFEB),
    "resps": (0x4D6DADF, 0x4D6DAE6),
    "height": (0x4D6DB46, 0x4D6DB4D),
}


def check_capture():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != json.loads((HERE / "records.json").read_text())["target"]["sha256"]:
        raise ValueError("wrong target")
    fdes = {r["start"]: r["end"] for r in eh_frame_records(data)[1]}
    for start, expected in BODIES.items():
        if (
            hashlib.sha256(read(data, start, fdes[start] - start)[1]).hexdigest()
            != expected
        ):
            raise ValueError(f"body differs at {start:#x}")
    for key, (lea, length) in KEYS.items():
        literal = key.split(".")[-1].encode()
        assert read(data, lea, 3)[1] == bytes.fromhex("488d35")
        assert read(data, length, 5)[1] == b"\xba" + struct.pack("<I", len(literal))
        assert read(data, rip_target(data, lea, 3), len(literal))[1] == literal
    assert read(data, 0x4E09ADE, 13)[1] == bytes.fromhex("c744243800040001c644243c00")
    assert read(data, 0x4D6D8B0, 6)[1] == bytes.fromhex("807a0b007432")
    for call, callee in {
        0x4E09AF5: 0x4D6D890,
        0x4D6D8C3: 0x57CE100,
        0x4D6D93E: 0x57CE100,
        0x4D6D9B9: 0x5307510,
        0x4D6DA01: 0x52AF290,
        0x52AF2F6: 0x57CEBA0,
        0x4D6DA45: 0x57D00B0,
        0x4D6DA8A: 0x57D00B0,
        0x4D6DAAE: 0x4E0BDB0,
        0x4E0BE09: 0x57CE100,
        0x4D6DAC9: 0x4E0DFC0,
        0x4D6DB0E: 0x52F0080,
        0x4D6DB2C: 0x4D6D450,
        0x4E0E031: 0x57CF860,
        0x4D6DB6B: 0x57D00B0,
    }.items():
        assert read(data, call, 1)[1] == b"\xe8" and rip_target(data, call, 1) == callee
    for site, count in ((0x4D6D8BE, 3), (0x4D6D939, 6), (0x4E0BE04, 2)):
        assert read(data, site, 5)[1] == b"\xba" + struct.pack("<I", count)
    # Short map and array markers, both size thresholds, and the optional-response discriminant.
    for site, expected in {
        0x57CE10E: "81fa000001000f92c034df83fa100fb6c0bd80000000",
        0x57CEBAE: "81fa000001000f92c034dd83fa100fb6c0bd90000000",
        0x4D6DB01: "803e02751e",
    }.items():
        raw = bytes.fromhex(expected)
        assert read(data, site, len(raw))[1] == raw
    # Native helpers write a nil response, a T separator, and a 42-byte address string.
    assert read(data, 0x4E0E018, 10)[1] == bytes.fromhex("be2a000000b914000000")
    assert read(data, 0x52F00B4, 4)[1] == bytes.fromhex("c60431c0")
    assert read(data, 0x5307581, 5)[1] == bytes.fromhex("be54000000")
    slot = rip_target(data, 0x4E0E025, 2)
    assert slot == 0x64E4D08 and relocations(data)[slot] == (8, 0x2EABB50)
    return {"target_sha256": digest, "complete_bodies": len(BODIES), "keys": list(KEYS)}


def project_frames():
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "Cargo.toml").write_text(
            '[package]\nname="replica-observation"\nversion="0.0.0"\nedition="2024"\n'
            '[[bin]]\nname="observe"\npath="observe.rs"\n[dependencies]\nnode-runtime={path='
            + json.dumps(str(ROOT / "src/node-runtime"))
            + "}\n"
        )
        (work / "observe.rs").write_bytes((HERE / "encode_replicas.rs").read_bytes())
        return subprocess.check_output(
            [
                "cargo",
                "run",
                "--release",
                "--offline",
                "--quiet",
                "--manifest-path",
                str(work / "Cargo.toml"),
            ]
        )


def compare():
    import msgpack

    edges = [0, 1, 127, 128, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**64 - 1]
    counts = [0, 1, 15, 16, 255, 256, 65535, 65536]
    fractions = ["", ".123", ".123456", ".123456789"]
    payload = project_frames()
    offset = 0
    total = 0
    for i, height in enumerate(edges):
        for j, count in enumerate(counts):
            samples = [[], {"x": True}, "q"]
            bundles = (samples * ((count + 2) // 3))[:count]
            block = {
                "time": "2024-02-29T12:34:56" + fractions[(i + j) % len(fractions)],
                "signed_action_bundles": bundles,
                "round": edges[(i + 1) % len(edges)],
                "parent_round": edges[(i + 2) % len(edges)],
                "hardfork": {
                    "version": edges[(i + 3) % len(edges)],
                    "round": edges[(i + 4) % len(edges)],
                },
                "proposer": "0x"
                + bytes((17 * k + i + j) % 256 for k in range(20)).hex(),
            }
            record = {
                "abci_block": block,
                "resps": [{"ok": True}] if j % 2 else None,
                "height": height,
            }
            reference = msgpack.packb(record, use_bin_type=True)
            (size,) = struct.unpack_from("<I", payload, offset)
            offset += 4
            actual = payload[offset : offset + size]
            if actual != reference or msgpack.unpackb(actual, raw=False) != record:
                raise ValueError(
                    f"mismatched replica, integer case {i}, bundle case {j}"
                )
            offset += size
            total += size
    if offset != len(payload):
        raise ValueError("unexpected extra frames")
    return {
        "reference": f"msgpack-python {msgpack.__version__}",
        "complete_records": len(edges) * len(counts),
        "encoded_bytes": total,
        "framed_stream_sha256": hashlib.sha256(payload).hexdigest(),
        "mismatched_records": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if not __debug__:
        raise SystemExit(
            "use Python with assertions enabled for native evidence checks"
        )
    result = {"native": check_capture(), "comparison": compare()}
    print(json.dumps(result, indent=2))
    if args.check and json.loads((HERE / "replica-results.json").read_text()) != result:
        raise SystemExit("retained observation differs")
