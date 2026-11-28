"""Authenticate optional end-gas and phantom leaves, then test all three root subtrees."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_subtrees import compare, load_scalars

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RUST_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    spans = [(row["start"], row["end"]) for row in frames if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x5A016D5: "41833f01", 0x5A016DB: "498b5708", 0x5A0174D: "c60430c0",
        0x3D1EBF4: "48897c2428", 0x45147F7: "833f01", 0x45147FC: "4883c708",
        0x451481B: "48c744241001000000", 0x4514836: "48c744241000000000",
        0x451484B: "48c744242001000000", 0x41AE2A9: "48837f1002",
        0x41AE31D: "41ff5520", 0x41AE39E: "ff5320",
        0x41AE36D: "ff5318", 0x43C6A68: "4883c708",
        0x430B920: "31c0483b060f90c0c0e002c3",
        0x14197FA: "48c7431000000000", 0x14198A9: "498906",
        0x141A14A: "48c7431000000000",
        0x141A2A4: "4d8b6f10", 0x141A2BF: "4d85ed7414",
    }.items():
        raw = bytes.fromhex(encoding)
        # Leaf writer 0x430b920 is a no-stack tiny function without an unwind row.
        if va != 0x430B920:
            assert any(begin <= va and va + len(raw) <= end for begin, end in spans), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, tag, expected in (
        (0x5A016E7, b"\xe8", 0x57D00B0), (0x451485C, b"\xe8", 0x41AE280),
        (0x43C6AAB, b"\xe8", 0x41AE280), (0x41AD060, b"\xff\x25", 0x64DF4F8),
    ):
        assert rip_target(data, va, tag, len(tag) + 4) == expected

    for va, tag, expected in (
        (0x5A016B7, b"\x48\x8d\x35", 0x93A595), (0x3D1EBF9, b"\x48\x8d\x15", 0x64787A0),
        (0x4514805, b"\x48\x8d\x0d", 0x648ED00), (0x4514824, b"\x48\x8d\x0d", 0x648E5D8),
        (0x451483F, b"\x48\x8d\x0d", 0x648E5E8), (0x43C6A71, b"\x48\x8d\x0d", 0x6487B30),
    ):
        assert rip_target(data, va, tag, 7) == expected

    assert read_va(data, 0x93A595, 11) == b"end_gas_wei"
    relocs = relative_relocations(data)
    for slot, target in {
        0x64787B8: 0x45147F0, 0x648ED18: 0x43C6A50,
        0x648E5D8: 0x459280, 0x648E5E0: 0x648E1F0,
        0x648E5E8: 0x459348, 0x648E5F0: 0x648E1F0, 0x648E208: 0x14199B0,
        0x6487B48: 0x430B920, 0x6487B50: 0x41AD060, 0x64DF4F8: 0x141A020,
    }.items():
        assert relocs[slot] == target, hex(slot)
    assert read_va(data, 0x459280, 8) == b"\x01" + bytes(7)
    assert read_va(data, 0x459348, 8) == bytes(8)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named end-gas nil/u64, raw Option tags and no-write phantom visitor")


def compiler(folder, rustc, temp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == RUST_SHA
    saved = temp / source.name
    saved.write_bytes(raw)
    library = temp / "libnode115_abci_blake3.rlib"
    hash_tree = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={library}", "-o", hash_tree], check=True)
    return hash_tree


def controls(folder, rustc, temp):
    import msgpack

    scalars = load_scalars(folder)
    kit = scalars.load_helpers(folder)
    tree = kit["tree"]
    helper = compiler(folder, rustc, temp)

    def word(value):
        return subprocess.check_output([helper], input=value.to_bytes(8, "little")).decode().strip()

    empty = "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert subprocess.check_output([helper], input=b"").decode().strip() == empty
    tag_0, tag_1 = word(0), word(1)
    height = 300
    names = list(scalars.SLOTS)
    normal = {"bucket_guard": {"last_bucket": 55, "bucket_millis": 1000}, "start_gas_wei": 1200,
              "end_gas_wei": None, "token": 4, "initial_gas_to_last_auction_gas_ratio": 91,
              "min_gas": 5}

    def save(name, raw):
        path = temp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    fields = {names[0]: normal, names[1]: normal | {"end_gas_wei": 0}, names[2]: None}

    def checkpoint(name, auctions):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, **auctions}}))

    def reference(name, second_optional, start_phantom=empty, wrong_digest=False):
        left = [[0, [[0, word(55)], [1, word(1000)]]], [1, [[0, word(1200)], [1, start_phantom]]]]
        right = [[3, word(4)], [4, word(91)], [5, [[0, word(5)], [1, empty]]]]
        ordered = [[0, [[4, word(200)]]],
                   [28, [[0, left + [[2, [[1, tag_0]]]] + right], [1, tag_1]]],
                   [29, [[0, left + [[2, second_optional]] + right], [1, tag_1]]],
                   [30, [[1, tag_0]]], [41, word(900)]]
        digest = tag_0 if wrong_digest else tree.digest(helper, tree.decode_tree(ordered))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": ordered}).encode()), digest

    restored = checkpoint("native.rmp", fields)
    correct, expected = reference("correct.json", [[0, [[0, word(0)], [1, empty]]], [1, tag_1]])
    result = compare(scalars, kit, helper, height, *restored, *correct)
    assert result["all_auction_subtrees_match"] and result["reference_with_projected_auctions_digest"] == expected
    assert all(path is None for path in result["first_different_paths"].values())

    nonzero = checkpoint("nonzero.rmp", fields | {names[1]: normal | {"end_gas_wei": 824}})
    nonzero_ref, _ = reference("nonzero.json", [[0, [[0, word(824)], [1, empty]]], [1, tag_1]])
    assert compare(scalars, kit, helper, height, *nonzero, *nonzero_ref)["all_auction_subtrees_match"]

    wrong_option, different = reference("wrong-option.json", [[1, tag_0]])
    result = compare(scalars, kit, helper, height, *restored, *wrong_option)
    assert not result["all_auction_subtrees_match"]
    assert result["first_different_paths"][names[1]] == (29, 0, 2)
    assert result["reference_raw_digest"] == different
    assert result["reference_with_projected_auctions_digest"] == expected

    wrong_phantom, _ = reference("wrong-phantom.json", [[0, [[0, word(0)], [1, empty]]], [1, tag_1]],
                                 start_phantom=word(0))
    result = compare(scalars, kit, helper, height, *restored, *wrong_phantom)
    assert result["first_different_paths"][names[0]] == (28, 0, 1, 1)
    assert result["reference_with_projected_auctions_digest"] == expected

    omitted = checkpoint("omitted.rmp", fields | {names[0]: {k: v for k, v in normal.items()
                                                            if k != "end_gas_wei"}})
    try:
        compare(scalars, kit, helper, height, *omitted, *correct)
    except ValueError as error:
        assert "omits end_gas_wei" in str(error)
    else:
        raise AssertionError("missing named Option was silently accepted")

    stale, _ = reference("stale.json", [[0, [[0, word(0)], [1, empty]]], [1, tag_1]], wrong_digest=True)
    try:
        compare(scalars, kit, helper, height, *restored, *stale)
    except ValueError as error:
        assert "stated raw ABCI digest" in str(error)
    else:
        raise AssertionError("stale export hash was silently accepted")

    cli = Path(__file__).with_name("compare_subtrees.py")
    result = subprocess.run([sys.executable, "-B", cli, folder, helper, str(height), *restored, *correct],
                            check=True, capture_output=True)
    assert json.loads(result.stdout)["all_auction_subtrees_match"]
    print(f"PASS: msgpack {msgpack.__version__}; all three ordered subtrees and full export digest match")
    print("PASS: nil, Some(0), Some(824), phantom mismatch, substitution, missing Option and stale root controls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
