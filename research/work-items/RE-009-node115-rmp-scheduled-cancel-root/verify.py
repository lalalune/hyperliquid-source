"""Verify scheduling collection preimages and run complete offline subtree controls."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_scheduled import FIELD, SLOT, compare, load_helpers

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
            int(row["method_1"], 16)) == (0x3FA8, 0x4D9DF80, 0x4D9DB00)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x54810EC: "498d97a83f0000", 0x52D0641: "c6043092", 0x52D0799: "c6040192",
        0x4D93611: "8b6e08", 0x4D93614: "4c8b3e", 0x4D9DF91: "488b5718",
        0x4D9E199: "498d4530", 0x4D9E1A2: "498d6d18", 0x4D9DB1E: "4889084889481848894830",
        0x3D38B07: "488d4f08", 0x3D38B1C: "48897c2418", 0x4513377: "833f00",
        0x4513397: "48c744241001000000", 0x45133B2: "48c744241000000000",
        0x45133C7: "48c744242001000000", 0x4512B5E: "48890848894818",
        0x141B296: "4889040a", 0x141B2BA: "892c01", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, width, target in (
        (0x54810F9, b"\xe8", 5, 0x5673CD0), (0x5673DE9, b"\xe8", 5, 0x52D03A0),
        (0x52D05B8, b"\xe8", 5, 0x5133D90), (0x52D074A, b"\xe8", 5, 0x4D935F0),
        (0x52D07FB, b"\xe8", 5, 0x5320910), (0x4D936AE, b"\xe8", 5, 0x5307510),
        (0x4D936EC, b"\xe8", 5, 0x57D00B0), (0x4D9E1B5, b"\xe8", 5, 0x5133D90),
        (0x4D9E280, b"\xe8", 5, 0x4E1BEA0), (0x3D38B5B, b"\xe8", 5, 0x41AE280),
        (0x45133D8, b"\xe8", 5, 0x41AE280), (0x3D5E950, b"\xff\x25", 6, 0x64DF5A0),
        (0x4D9E12E, b"\x4c\x8d\x35", 7, 0x649A790), (0x4D9E135, b"\x4c\x8d\x3d", 7, 0x649C7B8),
        (0x4D9E244, b"\x48\x8d\x05", 7, 0x649A6F0),
        (0x3D38B10, b"\x48\x8d\x0d", 7, 0x64787F8), (0x3D38B21, b"\x48\x8d\x0d", 7, 0x6473FF8),
        (0x4513381, b"\x48\x8d\x0d", 7, 0x648E7B0), (0x45133A0, b"\x48\x8d\x0d", 7, 0x648E5D8),
        (0x45133BB, b"\x48\x8d\x0d", 7, 0x648E5E8),
    ):
        assert rip_target(data, va, prefix, width) == target, hex(va)
    for va, prefix, literal in (
        (0x5673CEE, b"\x48\x8d\x05", FIELD.encode()),
        (0x4D93676, b"\x48\x8d\x35", b"t"), (0x4D936C9, b"\x48\x8d\x35", b"n"),
    ):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    reloc = relative_relocations(data)
    for at, target in {
        0x649C7D0: 0x3D38B00, 0x649C7D8: 0x3D38AB0, 0x6478810: 0x4513370, 0x6478818: 0x4512B40,
        0x6474010: 0x14199B0, 0x648E7C8: 0x3D5E950, 0x64DF5A0: 0x141B1E0,
        0x648E5D8: 0x459280, 0x648E5E8: 0x459348, 0x648E208: 0x14199B0,
    }.items():
        assert reloc[at] == target, hex(at)
    assert read_va(data, 0x459280, 8) == b"\x01" + bytes(7)
    assert read_va(data, 0x459348, 8) == bytes(8)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: scheduled-cancel ordered pair writer; raw optional Time and count-stream destinations")


def build_driver(folder, rustc, directory):
    rust = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = rust.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DRIVER_SHA
    staged = directory / rust.name
    staged.write_bytes(data)
    lib = directory / "libnode115_abci_blake3.rlib"
    binary = directory / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", lib], check=True)
    subprocess.run([rustc, "--edition=2024", staged, "--extern",
                    f"node115_abci_blake3={lib}", "-o", binary], check=True)
    return binary


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = build_driver(folder, rustc, tmp)
    tree = kit["tree"]
    height = 404
    addr_a, addr_b, addr_c = ("0x" + part * 20 for part in ("2a", "7b", "f6"))
    rows = [[addr_a, {"t": "1969-12-31T23:59:59.999999999", "n": 5}],
            [addr_b, {}], [addr_c, {"t": "1970-01-01T00:00:01.003"}]]

    def hash_raw(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def qwords(*values):
        return b"".join(value.to_bytes(8, "little") for value in values)

    def save(name, data):
        path = tmp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def checkpoint(name, pairs):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, FIELD: pairs}}))

    def reference(name, branch, stale=False):
        entries = [[0, [[4, hash_raw(b"unrelated")]]], [21, branch]]
        digest = hash_raw(b"wrong") if stale else tree.digest(helper, tree.decode_tree(entries))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": entries}).encode())

    addresses = bytes.fromhex(addr_a[2:] + addr_b[2:] + addr_c[2:])
    clocks = struct.pack("<qIqI", -1, 999_999_999, 1, 3_000_000)
    mixed = [[0, hash_raw(addresses)],
             [1, [[0, [[0, hash_raw(clocks)], [1, hash_raw(qwords(1, 0, 1))]]],
                  [1, hash_raw(qwords(5, 0, 0))]]], [2, hash_raw(qwords(3))]]
    named = checkpoint("named.rmp", rows)
    exact = reference("exact.json", mixed)
    assert compare(kit, helper, height, *named, *exact)["ordered_subtree_matches"]
    empty = checkpoint("empty.rmp", [])
    assert compare(kit, helper, height, *empty,
                   *reference("empty.json", [[2, hash_raw(qwords(0))]]))["ordered_subtree_matches"]

    no_clock = checkpoint("no-clock.rmp", [[addr_a, {"n": 1}], [addr_b, {}]])
    none_branch = [[0, hash_raw(addresses[:40])],
                   [1, [[0, [[1, hash_raw(qwords(0, 0))]]], [1, hash_raw(qwords(1, 0))]]],
                   [2, hash_raw(qwords(2))]]
    assert compare(kit, helper, height, *no_clock,
                   *reference("no-clock.json", none_branch))["ordered_subtree_matches"]

    wrong_inner = [[0, hash_raw(clocks)], [1, hash_raw(qwords(1, 1))]]
    wrong = reference("wrong-tags.json", [mixed[0], [1, [[0, wrong_inner], mixed[1][1][1]]], mixed[2]])
    result = compare(kit, helper, height, *named, *wrong)
    assert not result["ordered_subtree_matches"] and not result["value_subtree_matches"]
    assert result["address_stream_matches"] and result["count_leaf_matches"]
    wrong_order = checkpoint("wrong-order.rmp", [rows[1], rows[0], rows[2]])
    mismatch = compare(kit, helper, height, *wrong_order, *exact)
    assert not mismatch["address_stream_matches"] and not mismatch["value_subtree_matches"]
    assert mismatch["count_leaf_matches"]

    duplicate = checkpoint("duplicate.rmp", [rows[0], rows[0]])
    stale = reference("stale.json", mixed, stale=True)
    for source, ref, reason in ((duplicate, exact, "duplicate scheduled-cancel"),
                                (named, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *source, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_scheduled.py"), folder, helper,
           str(height), *named, *wrong]
    cli = subprocess.run(cmd, check=False, capture_output=True)
    assert cli.returncode == 1 and json.loads(cli.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; empty, all-absent and mixed optional schedules match")
    print("PASS: value tags include absent rows, omitted counts append zero, and order/stale digest are distinguished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
