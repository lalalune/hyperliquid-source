"""Verify the entire #115 named Locus qus Address/count subtree."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from tempfile import TemporaryDirectory

from compare_qus import compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native(folder):
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    witness = folder / "RE-009-node115-locus-context-root-captures/verify.py"
    raw = witness.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "19cc80a8e20a68b6ad9e471b2d92ea61dec0c2451a0b2414563e1808faabf993"
    capture = ModuleType("locus_capture")
    capture.__file__ = str(witness)
    exec(compile(raw, str(witness), "exec"), capture.__dict__)
    by_name = {row[1]: row for row in capture.first_fields(data)}
    assert by_name["qus"] == ("0.9", "qus", "0xb78", "0x6475a48", "0x4511e20", "0x450ed50")
    assert by_name["height"] == ("0.0.2", "height", "0x28", "0x64828c8", "0x14199b0", "0x14196d0")

    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for va, raw in {
        0x5480C5A: "4d8d87780b0000", 0x52CA201: "488b5010",
        0x52CA33F: "be2a000000b914000000", 0x513875B: "0fb791e6000000",
        0x51388F1: "488d0480488d04824883c008",
        0x450ED64: "48b9010000000000008048890848894818",
        0x450ED75: "48c70302000000", 0x450ED80: "48c7431002000000",
        0x4511E31: "4c8b6f10", 0x4511EA1: "488b0f4885c9", 0x4511EB8: "0f8563020000",
        0x4511ECA: "4d89ef", 0x4511ED0: "4c897c2420",
        0x4511EEB: "49ffcf4b8d04b6488d04834883c008",
        0x4511F16: "49ffc4", 0x4511F3C: "410fb785e6000000",
        0x45120E0: "498d6e01", 0x4512121: "4531e4",
        0x4512130: "4c8b6c24204c896c2430", 0x4512155: "4c89642450",
        0x4512164: "48c744246001000000", 0x141B9F1: "4883c114", 0x14199DC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5480C73, "e8", 0x5677400), (0x5677436, "e9", 0x52CA1D0),
        (0x52CA26A, "e8", 0x57CEBA0), (0x52CA313, "e8", 0x5138730), (0x52CA35A, "e8", 0x57CF860),
        (0x4511F0A, "488d05", 0x648E538), (0x4512144, "488d0d", 0x648E1F0),
        (0x4512175, "e8", 0x41AE280), (0x41F8050, "ff25", 0x64DF600),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {0x648E550: 0x41F8050, 0x648E208: 0x14199B0, 0x64DF600: 0x141B9B0}.items():
        assert reloc[site] == method
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named qus source, B-tree ordered Address visits, absent empty stream and original count")


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
    height = 899

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, keys):
        source = {"exchange": {"locus": {"ctx": {"height": height}, "qus": keys}}}
        return save(name, msgpack.packb(source))

    def reference(name, selected, root_height=height, stale=False):
        slots = [[0, [[0, [[2, word(root_height)], [4, word(321)]]], [9, selected]]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    addresses = [i.to_bytes(20, "big") for i in range(12)]
    keys = ["0x" + address.hex() for address in addresses]
    source = checkpoint("ordinary.rmp", keys)
    expected = [[0, leaf(b"".join(addresses))], [1, word(12)]]
    exact = reference("ordinary.json", expected)
    assert compare(kit, helper, height, *source, *exact)["ordered_qus_slot_matches"]
    empty = checkpoint("empty.rmp", [])
    assert compare(kit, helper, height, *empty,
                   *reference("empty.json", [[1, word(0)]]))["ordered_qus_slot_matches"]
    empty_stream = compare(kit, helper, height, *empty,
                           *reference("incorrect-empty.json", [[0, leaf(b"")], [1, word(0)]]))
    assert not empty_stream["ordered_address_stream_matches"] and empty_stream["count_matches"]
    reorder = reference("reordered.json", [[0, leaf(b"".join(addresses[::-1]))], [1, word(12)]])
    mismatch = compare(kit, helper, height, *source, *reorder)
    assert not mismatch["ordered_qus_slot_matches"] and not mismatch["ordered_address_stream_matches"]
    assert mismatch["count_matches"]
    wrong_count = compare(kit, helper, height, *source, *reference("count.json", [expected[0], [1, word(13)]]))
    assert wrong_count["ordered_address_stream_matches"] and not wrong_count["count_matches"]
    for candidate, ref, reason in (
        (checkpoint("duplicate.rmp", keys + keys[-1:]), exact, "duplicate qus Address"),
        (checkpoint("wrong-address.rmp", keys + ["0x01"]), exact, "Address string"),
        (source, reference("wrong-inner-h.json", expected, root_height=height + 1), "inner Context height"),
        (source, reference("stale.json", expected, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_qus.py"), folder, helper,
           str(height), *source, *reorder]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; 12-entry writer-order and empty-set controls")
    print("PASS: independent order, count, empty stream and exact inner H checks passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native(args.helpers)
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
