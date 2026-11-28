"""Verify native boundaries and run the composed adjacent Context case."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_case import compare_case, hash_bytes, load_dependencies

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
HELPER_SOURCE = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"
PACKET = Path(__file__).resolve().parent


def native():
    assert hashlib.sha256(Path("artifacts/node/115/hl-node").read_bytes()).hexdigest() == TARGET
    print(f"PASS: node #115 SHA-256 {TARGET}", flush=True)
    for tool in ("abci_hashes_tree_json_115", "abci_hash_tree_encoding_115", "height_advance_115"):
        subprocess.run([sys.executable, "-B", f"tools/{tool}.py", "--check"], check=True)


def helper(folder, rustc, directory):
    library = directory / "libnode115_abci_blake3.rlib"
    executable = directory / "hash_tree"
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == HELPER_SOURCE
    fixed_source = directory / source.name
    fixed_source.write_bytes(data)
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", fixed_source, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def tests(folder, rustc, directory):
    import msgpack

    kit = load_dependencies(folder)
    executable = helper(folder, rustc, directory)
    assert hash_bytes(executable, kit["tree"], b"abc") == (
        "0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    )
    stored = {
        "hardfork_height": 17, "hardfork": {"version": 42, "round": 12}, "height": 30,
        "tx_index": None, "round": 500, "time": "1969-12-31T23:59:59.999999999",
        "prev_time": "1969-12-31T23:59:58", "next_oid": 26, "next_lid": 256,
        "next_twap_id": 66052, "system_nonce": 77, "use_system_nonce": False, "mac": 79,
    }

    def clock(s, nanos):
        return {"unix_seconds": s, "subsec_nanos": nanos}

    expected_base = stored | {"time": clock(-1, 999_999_999), "prev_time": clock(-2, 0)}
    expected_next = expected_base | {
        "height": 31, "round": 900, "time": clock(0, 17), "prev_time": clock(-1, 999_999_999),
        "tx_index": 0, "mac": 81,  # later state outside the four begin checks
    }

    def save(name, data):
        path = directory / name
        path.write_bytes(data)
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest()}

    def save_json(name, data):
        return save(name, (json.dumps(data) + "\n").encode())

    def row(values):
        preimages = kit["context"].preimages(values)
        hashes = (hash_bytes(executable, kit["tree"], item) for item in kit["context"].leaves(preimages))
        context = kit["context"].replace_leaves(preimages, hashes)
        tree = [[0, [[0, context]]], [58, "0x" + "f0" * 32]]
        return {"height": values["height"], "exchange_abci_hash": tree,
                "abci_digest": kit["tree"].digest(executable, kit["tree"].decode_tree(tree))}

    checkpoint = msgpack.packb({"exchange": {"locus": {"ctx": stored, "aux": [0] * 4000}}},
                              use_bin_type=True)
    entries = {
        "height": 30,
        "checkpoint_rmp": save("synthetic-checkpoint.rmp", checkpoint),
        "successor_header": save_json("header.json", {"height": 31, "round": 900, "time": clock(0, 17)}),
        "reference_h": save_json("h.jsonl", row(expected_base)),
        "reference_h_plus_one": save_json("h1.jsonl", row(expected_next)),
    }

    def verify(spec):
        case = save_json("case.json", spec)
        return compare_case(directory / case["path"], case["sha256"], kit, executable)

    good = verify(entries)
    assert good["selected_checks_pass"] and good["clock_rotated"]
    bad_h = verify(entries | {"reference_h": save_json("h-counter.jsonl", row(expected_base | {"mac": 9}))})
    assert not bad_h["selected_checks_pass"]
    assert bad_h["checkpoint_context"]["different_context_fields"] == ["mac"]
    assert all(bad_h["successor_begin"]["matched"].values())
    bad_h1 = row(expected_next | {"prev_time": clock(-2, 0)})
    revised = entries | {"reference_h_plus_one": save_json("h1-clock.jsonl", bad_h1)}
    case = save_json("case.json", revised)
    output = subprocess.run([sys.executable, "-B", PACKET / "compare_case.py",
                             folder, executable, directory / case["path"], case["sha256"]],
                            capture_output=True, text=True)
    assert output.returncode == 1
    assert json.loads(output.stdout)["successor_begin"]["matched"] == {
        "height": True, "round": True, "time": True, "prev_time": False,
    }
    for role, entry, expected in (
        ("checkpoint_rmp", entries["checkpoint_rmp"] | {"sha256": "0" * 64}, "SHA-256 mismatch"),
        ("successor_header", save_json("nonadjacent.json", {"height": 32, "round": 900,
                                                            "time": clock(0, 17)}), "immediate H+1"),
    ):
        try:
            verify(entries | {role: entry})
        except ValueError as error:
            assert expected in str(error)
        else:
            raise AssertionError(expected)
    print(f"PASS: msgpack {msgpack.__version__}, pinned RMP through 13 H leaves and four H+1 begin leaves")
    print("PASS: H-only MAC mismatch, H+1-only clock mismatch, exact pins and nonadjacent rejection")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--helpers", type=Path)
    parser.add_argument("--rustc", default="rustc")
    args = parser.parse_args()
    native()
    if args.helpers:
        with TemporaryDirectory() as directory:
            tests(args.helpers.resolve(), args.rustc, Path(directory))


if __name__ == "__main__":
    main()
