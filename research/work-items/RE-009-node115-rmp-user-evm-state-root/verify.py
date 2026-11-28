"""Verify the complete named user EVM State map projection and defaults."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_user_state import FIELD, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x3FF8, 0x4D9FDA0)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    assert read_va(data, rip_target(data, 0x567603E, bytes.fromhex("488d05"), 7), len(FIELD)) == FIELD.encode()
    for site, field in ((0x55FD9C5, b"g"), (0x55FDA0E, b"t"), (0x55FDA57, b"b"), (0x55FDACA, b"T")):
        assert read_va(data, rip_target(data, site, bytes.fromhex("488d35"), 7), 1) == field
    for va, raw in {
        0x54812DD: "498d97f83f0000", 0x5287701: "c6043092", 0x531FF70: "b914000000",
        0x55FD927: "4c8b2e4c8b6608", 0x55FD93D: "0fb66e1c",
        0x55FD943: "b91a40f600334e100b4e14", 0x55FD953: "8b7618",
        0x55FD9B9: "4d85ed7444", 0x55FDA02: "4d85e47444", 0x55FDA4B: "4084ed745b",
        0x55FDA8A: "bfc3000000", 0x55FDAAB: "837c2424000f94c084442407",
        0x55FDAE4: "4983c610", 0x4D9FDB1: "488b5718", 0x4D9FFB9: "498d4538",
        0x4D9FFC2: "498d6d18", 0x3D27BDA: "48897c2408", 0x3D27BEB: "488d4f08",
        0x3D27C00: "488d4f1c", 0x3D27C15: "4883c710",
        0x141B9E6: "89740a100f10070f11040a4883c114", 0x14199DC: "48890c02",
        0x1419D6B: "880c02", 0x141B296: "4889040a", 0x141B2BA: "892c01",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    packed_epoch = 0xF6401A
    assert packed_epoch >> 13 == 1970 and (packed_epoch >> 4) & 511 == 1
    for va, prefix, target in (
        (0x54812EA, "e8", 0x5676020), (0x567612D, "e8", 0x5287460),
        (0x5287745, "e8", 0x531FE80), (0x531FEC7, "e8", 0x57CEBA0), (0x531FF0C, "e8", 0x57D00B0),
        (0x531FF78, "ff15", 0x64E4D08), (0x531FF84, "e8", 0x57CF860),
        (0x528780A, "e8", 0x55FD910), (0x55FDAFF, "e8", 0x52FD6D0),
        (0x4D9FF42, "4c8d35", 0x649A790), (0x4D9FF49, "4c8d3d", 0x649C948),
        (0x4DA0064, "488d05", 0x649A6F0), (0x4DA00A0, "e8", 0x4E1BEA0),
        (0x3D27BDF, "488d0d", 0x6477048), (0x3D27BF4, "488d0d", 0x6473FF8),
        (0x3D27C09, "488d0d", 0x6474380), (0x3D27C1E, "488d0d", 0x6474358),
        (0x3D27C81, "e8", 0x41AD9A0), (0x41F8050, "ff25", 0x64DF600), (0x3D5E950, "ff25", 0x64DF5A0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {0x649A7A8: 0x41F8050, 0x649C960: 0x3D27BD0, 0x649A708: 0x14199B0,
                         0x6477060: 0x14199B0, 0x6474010: 0x14199B0, 0x6474398: 0x1419D40,
                         0x6474370: 0x3D5E950, 0x64DF600: 0x141B9B0, 0x64DF5A0: 0x141B1E0}.items():
        assert reloc[site] == method, hex(site)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: slot 34 address, four named field defaults and four native ordered value streams")


def driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = tmp / source.name
    staged.write_bytes(data)
    library = tmp / "libnode115_abci_blake3.rlib"
    executable = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 110

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    first, second = bytes.fromhex("11" * 20), bytes.fromhex("22" * 20)
    default = ["0x" + first.hex(), {}]
    populated = [list(second), {"t": 18, "T": "1970-01-01T00:00:02.001", "g": 12, "b": True}]
    def checkpoint(name, values):
        body = {"exchange": {"locus": {"ctx": {"height": height}}, FIELD: values}}
        return save(name, msgpack.packb(body))

    def reference(name, subtree, stale=False):
        slots = [[0, [[4, leaf(b"outside-scope")]]], [34, subtree]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    count = leaf(struct.pack("<Q", 2))
    values = [[0, leaf(struct.pack("<QQ", 0, 12))], [1, leaf(struct.pack("<QQ", 0, 18))],
              [2, leaf(b"\x00\x01")], [3, leaf(struct.pack("<qIqI", 0, 0, 2, 1_000_000))]]
    expected = [[0, leaf(first + second)], [1, values], [2, count]]
    exact = reference("exact.json", expected)
    source = checkpoint("actual.rmp", [default, populated])
    assert compare(kit, helper, height, *source, *exact)["ordered_subtree_matches"]
    deduced = checkpoint("explicit-default.rmp", [[default[0], {"g": 0, "t": 0, "b": False,
                                                                   "T": "1970-01-01T00:00:00"}], populated])
    assert compare(kit, helper, height, *deduced, *exact)["ordered_subtree_matches"]
    empty = reference("empty.json", [[2, leaf(bytes(8))]])
    assert compare(kit, helper, height, *checkpoint("empty.rmp", []), *empty)["ordered_subtree_matches"]

    altered = reference("altered.json", [[0, expected[0][1]], [1, values[:2] + [[2, leaf(bytes(2))], values[3]]],
                                        [2, count]])
    comparison = compare(kit, helper, height, *source, *altered)
    assert not comparison["ordered_subtree_matches"] and not comparison["value_subtree_matches"]
    assert comparison["address_stream_matches"] and comparison["count_leaf_matches"]
    swapped = compare(kit, helper, height, *checkpoint("swapped.rmp", [populated, default]), *exact)
    assert not swapped["address_stream_matches"] and not swapped["value_subtree_matches"] and swapped["count_leaf_matches"]
    for candidate, ref, reason in (
        (checkpoint("duplicate.rmp", [default, [list(first), {}]]), exact, "duplicate user EVM Address"),
        (checkpoint("invalid-bool.rmp", [[default[0], {"b": 1}]]), exact, "expected a bool"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_user_state.py"), folder, helper,
           str(height), *source, *altered]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == comparison
    print(f"PASS: msgpack {msgpack.__version__}; complete empty, defaulted and populated map comparisons")
    print("PASS: raw order and bool changes detected; duplicated logical address and stale root rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
