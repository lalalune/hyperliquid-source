"""Verify native leaf boundaries and build/run the selected Context comparison."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from compare import KEYS, compare, preimages, project

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent


def verify_binary():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA
    sections, head = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in head}
    bounds = {(row["start"], row["end"]) for row in frames if (row["start"], row["fde"]) in indexed}
    assert {(0x43037C0, 0x4303B6B), (0x141B1E0, 0x141B3A3), (0x1419D40, 0x1419DEB)} <= bounds
    anchors = {
        0x43038FD: "48837e100d", 0x4303ABA: "ff5318", 0x4303B17: "4883c118",
        0x43037D1: "488d4710", 0x43037FB: "488d4f28", 0x430381A: "488d4f30",
        0x4303832: "488d4f60", 0x430384D: "488d576c", 0x4303861: "488d4f38",
        0x4303875: "488d4f40", 0x4303889: "488d4f48", 0x430389D: "488d4750",
        0x43038B8: "488d4778", 0x43038D3: "4883c758",
        0x141B1F1: "488b17", 0x141B1FB: "48c1e920", 0x141B234: "8b6f08",
        0x141B273: "4869c080510100", 0x141B296: "4889040a",
        0x141B29A: "4883c108", 0x141B2BA: "892c01", 0x141B2BD: "4883c004",
        0x1419D45: "0fb60f", 0x1419D6B: "880c02",
        0x14199DC: "48890c02", 0x14199E0: "4883c008",
        0x45146F7: "833f01", 0x45146FC: "4883c708",
    }
    for address, value in anchors.items():
        raw = bytes.fromhex(value)
        assert read_va(data, address, len(raw)) == raw
    for address, opcode, target in (
        (0x43037DA, b"\x48\x8d\x05", 0x64828C8),
        (0x43037EF, b"\x48\x8d\x0d", 0x6484720),
        (0x430380E, b"\x48\x8d\x0d", 0x6482788),
        (0x4303823, b"\x48\x8d\x0d", 0x6484748),
        (0x430383E, b"\x48\x8d\x0d", 0x6482708),
        (0x43038A9, b"\x48\x8d\x05", 0x6484770),
        (0x43038C4, b"\x48\x8d\x05", 0x64828A0),
        (0x43038DF, b"\x48\x8d\x05", 0x6482968),
        (0x3D5E950, b"\xff\x25", 0x64DF5A0),
        (0x4306E8B, b"\xe8", 0x41AE280),
        (0x451475C, b"\xe8", 0x41AE280),
    ):
        assert rip_target(data, address, opcode, len(opcode) + 4) == target
    relocations = relative_relocations(data)
    for slot, target in (
        (0x6482720, 0x3D5E950), (0x64DF5A0, 0x141B1E0),
        (0x64828B8, 0x1419D40), (0x64828E0, 0x14199B0),
        (0x6482980, 0x14199B0), (0x6484788, 0x4303720),
        (0x6484738, 0x4306E30), (0x64827A0, 0x45146F0),
    ):
        assert relocations[slot] == target
    print(f"PASS: node #115 SHA-256 {SHA}", flush=True)
    print("PASS: 13-entry Context path; native qword, bool, and packed timestamp leaf writes", flush=True)


def build(rust, directory):
    lib = directory / "libnode115_abci_blake3.rlib"
    exe = directory / "hash_leaves"
    subprocess.run([rust, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", lib], check=True)
    subprocess.run([rust, "--edition=2024", PACKET / "hash_leaves.rs",
                    "--extern", f"node115_abci_blake3={lib}", "-o", exe], check=True)
    known = subprocess.check_output([exe], input="616263\n", text=True).strip()
    assert known == "0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    return exe


def fixture_controls(directory, hasher):
    context = {
        "hardfork_height": 17, "hardfork": {"version": 42, "round": 12}, "height": 30,
        "tx_index": None, "round": 500, "time": {"unix_seconds": 3, "subsec_nanos": 17},
        "prev_time": {"unix_seconds": -1, "subsec_nanos": 999999999},
        "next_oid": 26, "next_lid": 256, "next_twap_id": 66052,
        "system_nonce": 77, "use_system_nonce": False, "mac": 79,
    }
    inputs = preimages(context)
    assert inputs[1] == [1, [[0, b"\x2a" + b"\0" * 7], [1, b"\x0c" + b"\0" * 7]]]
    assert inputs[3] == [3, [[1, b"\0" * 8]]]
    assert inputs[5][1].hex() == "030000000000000011000000"
    assert inputs[6][1].hex() == "ffffffffffffffffffc99a3b"
    assert inputs[11] == [11, b"\0"]
    tree = project(context, hasher)
    export = {"height": 30, "abci_digest": "0x" + "12" * 32,
              "exchange_abci_hash": [[0, [[0, tree]]]]}
    assert compare(30, context, export, hasher)["matches"]
    for index, key in enumerate(KEYS):
        modified = deepcopy(export)
        children = modified["exchange_abci_hash"][0][1][0][1]
        children[index][1] = "0x" + "ff" * 32
        assert compare(30, context, modified, hasher)["different_fields"] == [key]
    modified = deepcopy(export)
    children = modified["exchange_abci_hash"][0][1][0][1]
    children[4], children[5] = children[5], children[4]
    swapped = compare(30, context, modified, hasher)
    assert not swapped["matches"] and not swapped["ordered_context_slots"] and swapped["different_fields"] == []
    files = []
    for filename, value in (("normalized-context.json", context), ("raw-export.jsonl", export)):
        data = (json.dumps(value, sort_keys=True) + "\n").encode()
        path = directory / filename
        path.write_bytes(data)
        files.extend((path, hashlib.sha256(data).hexdigest()))
    command = [sys.executable, "-B", PACKET / "compare.py", hasher, "30", *files]
    report = json.loads(subprocess.check_output(command, text=True))
    assert report["matches"]
    mismatched = subprocess.run(command[:-1] + ["0" * 64], text=True, capture_output=True)
    assert mismatched.returncode == 2 and "SHA-256 mismatch" in mismatched.stderr
    print("PASS: official BLAKE3 abc vector, 13 per-child mutations and ordered branch check")
    print("PASS: synthetic clock byte preimages, absent tx index, SHA-256 pin and comparison CLI")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rustc", default="rustc")
    options = parser.parse_args()
    verify_binary()
    subprocess.run([options.rustc, "--version"], check=True)
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        fixture_controls(directory, build(options.rustc, directory))


if __name__ == "__main__":
    main()
