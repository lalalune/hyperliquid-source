"""Recheck native fields and test streaming Context projection on valid fixture bytes."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from project import load_projector, project_rmp

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent


def verify_binary():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}
    assert {(0x30D1C60, 0x30D3EE7), (0x332C430, 0x333208D),
            (0x5480950, 0x548168C), (0x5481900, 0x548263C)} <= extents
    for address, target in ((0x332C805, 0x30D1C60), (0x5480AC7, 0x4D93030)):
        assert rip_target(data, address, b"\xe8", 5) == target
    for address, encoding in {
        0x30D31AA: "48894b18", 0x30D31AE: "48895320", 0x30D31E2: "48894348",
        0x30D31FE: "896b60", 0x30D3209: "48894364", 0x30D320D: "4489636c",
        0x30D3219: "48894370", 0x4D9317A: "41833f01", 0x4D93180: "498b5708",
    }.items():
        raw = bytes.fromhex(encoding)
        assert read_va(data, address, len(raw)) == raw
    for site, literal in (
        (0x5480AA0, b"ctx"), (0x4D930B4, b"hardfork_height"),
        (0x4D9311C, b"height"), (0x4D93160, b"tx_index"),
        (0x4D931FA, b"round"), (0x4D9323C, b"time"), (0x4D93264, b"prev_time"),
    ):
        instruction = read_va(data, site, 3)
        assert instruction in (b"\x48\x8d\x15", b"\x48\x8d\x35")
        assert read_va(data, rip_target(data, site, instruction, 7), len(literal)) == literal
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: native named Context joins, hardfork pair and distinct 12-byte clock destinations")


def controls(projector_file, directory):
    import msgpack

    normalizer = load_projector(projector_file)

    def clock(seconds, nanos):
        return {"unix_seconds": seconds, "subsec_nanos": nanos}

    context = {
        "initial_height": 17, "hardfork": {"version": 42, "round": 12}, "height": 30,
        "tx_index": 0, "consensus_round": 500, "time": "2000-02-29T12:34:56.000123456",
        "prev_time": "1969-12-31T23:59:59.999999999", "next_oid": 26, "next_lid": 256,
        "next_twap_id": 66052, "system_nonce": 77, "use_system_nonce": False, "mac": 79,
    }
    expected = {
        "hardfork_height": 17, "hardfork": {"version": 42, "round": 12}, "height": 30,
        "tx_index": 0, "round": 500, "time": clock(951827696, 123456),
        "prev_time": clock(-1, 999999999), "next_oid": 26, "next_lid": 256,
        "next_twap_id": 66052, "system_nonce": 77, "use_system_nonce": False, "mac": 79,
    }

    def packed(fields, large_aux=False):
        locus = {"ctx": fields}
        if large_aux:
            locus = {"aux": [[i, b"x" * 1000] for i in range(2048)], **locus}
        return msgpack.packb({"exchange": {"locus": locus}}, use_bin_type=True)

    def save(name, data):
        file = directory / name
        file.write_bytes(data)
        return file, hashlib.sha256(data).hexdigest()

    data = packed(context, large_aux=True)
    path, sha = save("synthetic.rmp", data)
    got = project_rmp(path, sha, 30, normalizer)
    assert got == expected

    omitted = {key: value for key, value in context.items()
               if key not in ("hardfork", "consensus_round", "next_twap_id")}
    absent = project_rmp(*save("nil.rmp", packed(omitted | {"tx_index": None})), 30, normalizer)
    assert absent["tx_index"] is None and absent["round"] == absent["next_twap_id"] == 0
    assert absent["hardfork"] == {"version": 0, "round": 0}

    test_cases = (
        (*save("truncated.rmp", data[:-1]), 30, "incomplete named checkpoint"),
        (*save("trailing.rmp", data + b"\xc0"), 30, "trailing bytes"),
        (*save("double-height.rmp", packed(context | {"hardfork_height": 17})), 30, "same field"),
        (*save("double-round.rmp", packed(context | {"round": 0})), 30, "both round"),
        (path, sha, 31, "differs from requested"),
        (path, "0" * 64, 30, "SHA-256 mismatch"),
    )
    for source, pin, height, expected_error in test_cases:
        try:
            project_rmp(source, pin, height, normalizer)
        except ValueError as error:
            assert expected_error in str(error), error
        else:
            raise AssertionError(expected_error)
    command = [sys.executable, "-B", PACKET / "project.py", projector_file, path,
               "--sha256", sha, "--height", "30"]
    assert json.loads(subprocess.check_output(command, text=True)) == expected
    print(f"PASS: msgpack {msgpack.__version__}; streamed {len(data)} bytes with a skipped aux branch")
    print("PASS: all 13 fields, clocks, alias/defaults, nil/zero, SHA, trailing and CLI controls")
    return got, expected


def compare_fixture(root_packet, rustc, directory, normalized, expected):
    library = directory / "libnode115_abci_blake3.rlib"
    helper = directory / "hash_leaves"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3", "--crate-type",
                    "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", root_packet / "hash_leaves.rs",
                    "--extern", f"node115_abci_blake3={library}", "-o", helper], check=True)
    code = (
        "from pathlib import Path; import json,sys; "
        "sys.path.insert(0,sys.argv[1]); from compare import project; "
        "print(json.dumps(project(json.load(sys.stdin),Path(sys.argv[2]))))"
    )
    tree = json.loads(subprocess.check_output(
        [sys.executable, "-B", "-c", code, root_packet, helper],
        input=json.dumps(expected), text=True))
    synthetic = {"height": 30, "abci_digest": "0x" + "64" * 32,
                 "exchange_abci_hash": [[0, [[0, tree]]]]}
    args = []
    for file, contents in (("context.json", normalized), ("reference.jsonl", synthetic)):
        path = directory / file
        data = (json.dumps(contents) + "\n").encode()
        path.write_bytes(data)
        args.extend((path, hashlib.sha256(data).hexdigest()))
    result = json.loads(subprocess.check_output(
        [sys.executable, "-B", root_packet / "compare.py", helper, "30", *args], text=True))
    assert result["matches"] and result["different_fields"] == []
    print("PASS: streamed MessagePack projection accepted by the #7352 Context comparator")


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--normalizer", type=Path)
    cli.add_argument("--root-packet", type=Path)
    cli.add_argument("--rustc", default="rustc")
    args = cli.parse_args()
    verify_binary()
    if args.normalizer:
        with TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            observed, expected = controls(args.normalizer.resolve(), directory)
            if args.root_packet:
                compare_fixture(args.root_packet.resolve(), args.rustc, directory, observed, expected)


if __name__ == "__main__":
    main()
