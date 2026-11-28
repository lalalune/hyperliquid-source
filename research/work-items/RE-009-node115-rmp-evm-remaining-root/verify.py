"""Authenticate the #115 ledger writer and test its complete raw subtree offline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_remaining import FIELD, SLOT, compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    row = bind(data)["slots"][SLOT]
    assert (int(row["box_field"], 16), int(row["method_0"], 16),
            int(row["method_1"], 16)) == (0x4138, 0x4DA2E60, 0x4D9DB00)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x5481501: "4d8d8738410000", 0x5481512: "b91f000000",
        0x531084B: "c6043092", 0x53201FF: "488b12", 0x57CFD28: "4881fa00010000",
        0x4DA2E71: "488b5718", 0x4DA2EA5: "4889542438",
        0x4DA3079: "498d4520", 0x4DA3082: "498d6d18",
        0x4D9DB1E: "4889084889481848894830", 0x141B9F1: "4883c114",
        0x43C6A68: "4883c708", 0x430B920: "31c0483b060f90c0c0e002c3",
        0x141A14A: "48c7431000000000", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        if va != 0x430B920:
            assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, width, target in (
        (0x548151A, b"\xe8", 5, 0x5678EA0), (0x5678F9E, b"\xe8", 5, 0x52D3E50),
        (0x52D3EDD, b"\xe8", 5, 0x57CEBA0), (0x52D4048, b"\xe8", 5, 0x5133940),
        (0x52D40A0, b"\xe8", 5, 0x5310810), (0x5310887, b"\xe8", 5, 0x5320910),
        (0x531089D, b"\xe8", 5, 0x5320130), (0x5320208, b"\xe8", 5, 0x57CFD20),
        (0x4DA3095, b"\xe8", 5, 0x5133940), (0x4DA3160, b"\xe8", 5, 0x4E1BEA0),
        (0x4DA300A, b"\x4c\x8d\x35", 7, 0x649A790), (0x4DA3011, b"\x4c\x8d\x3d", 7, 0x649CBA0),
        (0x4DA3124, b"\x48\x8d\x05", 7, 0x649A6F0),
        (0x43C6A5C, b"\x48\x8d\x0d", 7, 0x6487B08), (0x43C6A71, b"\x48\x8d\x0d", 7, 0x6487B30),
        (0x43C6AAB, b"\xe8", 5, 0x41AE280), (0x41AD060, b"\xff\x25", 6, 0x64DF4F8),
    ):
        assert rip_target(data, va, prefix, width) == target, hex(va)
    name_addr = rip_target(data, 0x5481508, b"\x48\x8d\x15", 7)
    assert read_va(data, name_addr, len(FIELD)) == FIELD.encode()
    relocs = relative_relocations(data)
    for at, target in {
        0x649A7A8: 0x41F8050, 0x64DF600: 0x141B9B0,
        0x649CBB8: 0x43C6A50, 0x649CBC0: 0x43C6A00, 0x649A708: 0x14199B0,
        0x6487B20: 0x14199B0, 0x6487B48: 0x430B920, 0x6487B50: 0x41AD060,
        0x64DF4F8: 0x141A020,
    }.items():
        assert relocs[at] == target, hex(at)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named Address/u64 pair writer and separate native address, quantity and count leaves")


def driver(folder, rustc, temp):
    rust = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = rust.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = temp / rust.name
    staged.write_bytes(data)
    library = temp / "libnode115_abci_blake3.rlib"
    binary = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", binary], check=True)
    return binary


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 460
    addr_a, addr_b = ("0x" + prefix * 20 for prefix in ("1a", "b3"))
    rows = [[addr_a, 0], [addr_b, (1 << 64) - 1]]

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    empty = "0xaf1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert leaf(b"") == empty

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, pairs):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, FIELD: pairs}}))

    def reference(name, branch, stale=False):
        rows = [[0, [[4, leaf(b"unrelated")]]], [49, branch]]
        digest = leaf(b"wrong") if stale else tree.digest(helper, tree.decode_tree(rows))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": rows}).encode())

    address_bytes = bytes.fromhex(addr_a[2:] + addr_b[2:])
    amount_bytes = bytes(8) + b"\xff" * 8
    count = leaf(b"\x02" + bytes(7))
    expected = [[0, leaf(address_bytes)], [1, [[0, leaf(amount_bytes)], [1, empty]]], [2, count]]
    source = checkpoint("named.rmp", rows)
    good = reference("exact.json", expected)
    assert compare(kit, helper, height, *source, *good)["ordered_subtree_matches"]
    assert compare(kit, helper, height, *checkpoint("empty.rmp", []),
                   *reference("empty.json", [[2, leaf(bytes(8))]]))["ordered_subtree_matches"]

    wrong_marker = reference("wrong-marker.json", [expected[0], [1, [[0, leaf(amount_bytes)],
                                                                    [1, leaf(bytes(8))]]], expected[2]])
    mismatch = compare(kit, helper, height, *source, *wrong_marker)
    assert mismatch["address_stream_matches"] and mismatch["count_leaf_matches"]
    assert not mismatch["ordered_subtree_matches"] and not mismatch["amount_subtree_matches"]
    wrong_order = checkpoint("reverse.rmp", rows[::-1])
    changed = compare(kit, helper, height, *wrong_order, *good)
    assert not changed["address_stream_matches"] and not changed["amount_subtree_matches"]
    assert changed["count_leaf_matches"]

    duplicate = checkpoint("duplicate.rmp", [rows[0], rows[0]])
    wrong_type = checkpoint("wrong-type.rmp", [[addr_a, True]])
    stale = reference("stale.json", expected, stale=True)
    for candidate, raw, reason in ((duplicate, good, "duplicate ledger"), (wrong_type, good, "unsigned 64-bit"),
                                    (source, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *candidate, *raw)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_remaining.py"), folder, helper,
           str(height), *source, *wrong_marker]
    completed = subprocess.run(cmd, check=False, capture_output=True)
    assert completed.returncode == 1 and json.loads(completed.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; empty and populated slots with zero and max u64")
    print("PASS: byte-stream order, empty marker versus qword zero, duplicate/type and stale digest checks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
