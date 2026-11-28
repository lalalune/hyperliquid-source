"""Bind the Context input adapter to pinned observations and test its handoff."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from project import project

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, rip_target

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ROOT = Path(__file__).resolve().parent


def verify_binary():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {(row["start"], row["end"]) for row in frames if (row["start"], row["fde"]) in indexed}
    assert {(0x409C990, 0x409E092), (0x4D93030, 0x4D933B5),
            (0x4E0CAB0, 0x4E0CB41), (0x4E0BDB0, 0x4E0BEE0)} <= bounds
    for site, label in (
        (0x4D930B4, b"hardfork_height"), (0x4E0BDD9, b"hardfork"), (0x4D9311C, b"height"),
        (0x4D93160, b"tx_index"), (0x4D931FA, b"round"), (0x4D9323C, b"time"),
        (0x4D93264, b"prev_time"), (0x4D9328C, b"next_oid"), (0x4D932B4, b"next_lid"),
        (0x4D932DC, b"next_twap_id"), (0x4E0CACE, b"system_nonce"),
        (0x4D93318, b"use_system_nonce"), (0x4D9333C, b"mac"),
    ):
        opcode = read_va(data, site, 3)
        assert opcode in (b"\x48\x8d\x05", b"\x48\x8d\x15", b"\x48\x8d\x35")
        assert read_va(data, rip_target(data, site, opcode, 7), len(label)) == label
    for site, target in (
        (0x409D4EB, 0x3FD2100), (0x409D534, 0x3FD2100),
        (0x409D5FD, 0x3EF2DC0), (0x409D677, 0x3EF2DC0), (0x409D73D, 0x3EF2DC0),
        (0x4D9318C, 0x57D00B0), (0x4D931AE, 0x52F0080),
    ):
        assert rip_target(data, site, b"\xe8", 5) == target
    for address, raw in {
        0x409D891: "f68424b000000001", 0x409D89E: "4c0f44f8",
        0x4D9317A: "41833f01", 0x4D93180: "498b5708",
        0x4D93314: "458b4778", 0x4D93338: "4d8b4758",
    }.items():
        expected = bytes.fromhex(raw)
        assert read_va(data, address, len(expected)) == expected
    print(f"PASS: node #115 SHA-256 {TARGET_SHA}", flush=True)
    print("PASS: thirteen named Context keys; clock/counter reader and transaction branch bindings", flush=True)


def decoder_controls():
    fixture = ROOT / "fixture.json"
    raw = fixture.read_bytes()
    expected = json.loads((ROOT / "expected.json").read_bytes())
    assert project(raw, 30) == expected

    defaults = json.loads(raw)
    fields = defaults["exchange"]["locus"]["ctx"]
    for key in ("hardfork", "consensus_round", "next_twap_id"):
        del fields[key]
    fields["tx_index"] = None
    normalized = project(json.dumps(defaults), 30)
    assert normalized["hardfork"] == {"version": 0, "round": 0}
    assert normalized["round"] == normalized["next_twap_id"] == 0
    assert normalized["tx_index"] is None

    def reject(payload, label):
        try:
            project(payload, 30)
        except ValueError as error:
            assert label in str(error), error
        else:
            raise AssertionError(f"accepted input requiring rejection: {label}")

    for replacement, part in (
        (b'"round": 50, "consensus_round": 500', "both round"),
        (b'"consensus_round": 50, "consensus_round": 500', "duplicate ctx"),
    ):
        reject(raw.replace(b'"consensus_round": 500', replacement), part)
    reject(raw.replace(b'2000-02-29', b'1900-02-29'), "day is out of range")
    reject(raw.replace(b'.000123456', b'.120000'), "noncanonical")
    reject(raw.replace(b'"use_system_nonce": false', b'"use_system_nonce": 0'), "JSON boolean")
    reject(raw.replace(b'"next_oid": 26', b'"next_oid": 18446744073709551616'), "u64")
    reject(raw.replace(b'"height": 30', b'"height": 31'), "differs from requested")
    sha = hashlib.sha256(raw).hexdigest()
    command = [sys.executable, "-B", ROOT / "project.py", fixture, "--height", "30", "--sha256", sha]
    assert json.loads(subprocess.check_output(command, text=True)) == expected
    wrong = subprocess.run(command[:-1] + ["0" * 64], capture_output=True, text=True)
    assert wrong.returncode == 2 and "artifact SHA-256 mismatch" in wrong.stderr
    print("PASS: paired canonical clocks, exact nanos, signed pre-epoch seconds and all 13 schema fields")
    print("PASS: selected defaults, null/present zero, alias/duplicate, height, width and input SHA controls")
    return expected


def handoff(comparison, rustc, expected):
    """Run the independently existing #7352 comparator from its checkout."""
    with TemporaryDirectory() as tempdir:
        directory = Path(tempdir)
        library = directory / "libnode115_abci_blake3.rlib"
        hasher = directory / "hash_leaves"
        compare_path = comparison / "compare.py"
        subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                        "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                        "-o", library], check=True)
        subprocess.run([rustc, "--edition=2024", comparison / "hash_leaves.rs",
                        "--extern", f"node115_abci_blake3={library}", "-o", hasher], check=True)
        code = (
            "from pathlib import Path; import json,sys; "
            "sys.path.insert(0,sys.argv[1]); from compare import project; "
            "print(json.dumps(project(json.load(sys.stdin),Path(sys.argv[2]))))"
        )
        tree = json.loads(subprocess.check_output(
            [sys.executable, "-B", "-c", code, comparison, hasher],
            input=json.dumps(expected), text=True))
        raw = (ROOT / "fixture.json").read_bytes()
        result = project(raw, 30)
        capture = {
            "height": 30, "abci_digest": "0x" + "32" * 32,
            "exchange_abci_hash": [[0, [[0, tree]]]],
        }
        inputs = []
        for filename, contents in (("projection.json", result), ("synthetic-capture.jsonl", capture)):
            path = directory / filename
            encoded = json.dumps(contents).encode()
            path.write_bytes(encoded)
            inputs.extend((path, hashlib.sha256(encoded).hexdigest()))
        actual = json.loads(subprocess.check_output(
            [sys.executable, "-B", compare_path, hasher, "30", *inputs], text=True))
        assert actual["matches"] and actual["different_fields"] == []
        print("PASS: projected checkpoint fixture accepted by the #7352 Context comparator")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--comparison", type=Path)
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    verify_binary()
    expected = decoder_controls()
    if args.comparison:
        handoff(args.comparison.resolve(), args.rustc, expected)


if __name__ == "__main__":
    main()
