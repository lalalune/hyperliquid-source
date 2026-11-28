"""Verify the named empty vtg tracker against its complete raw subtree."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_empty_tracker import FIELD, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x3D40, 0x57C0C70)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for site, name in ((0x56784D1, b"vtg"), (0x5372585, b"name"), (0x53725C2, b"hsc"), (0x53725FD, b"i")):
        assert read_va(data, rip_target(data, site, bytes.fromhex("488d35"), 7), len(name)) == name
    for va, raw in {
        0x5481293: "498d97403d0000", 0x537252F: "ba03000000", 0x53725E4: "31d2",
        0x53727DE: "488d4b38", 0x5372809: "4883c318", 0x57C0C88: "488d4f38",
        0x57C0C9D: "4883c718", 0x141B61C: "488b7708488b5710",
        0x14CEAA3: "48c70700000000", 0x14CEAAB: "c7470808000000",
        0x14CEAB2: "48c7471000000000", 0x14CEACB: "48837e1001",
        0x4D9DB14: "48b901000000000000804889084889481848894830", 0x4DA1BB1: "488b5718", 0x4DA1BFC: "0f8486000000", 0x4DA1C88: "48c744240800000000",
        0x4DA1C9A: "48c744241800000000", 0x4DA1CA3: "48c744242000000000",
        0x4DA1E89: "48c744246801000000", 0x14199DC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x54812A0, "e8", 0x56784C0), (0x56784FC, "e9", 0x5372500),
        (0x53725AC, "e8", 0x57CF860), (0x53725E6, "e8", 0x57CEBA0),
        (0x537271E, "e8", 0x52EB9F0), (0x52EBA99, "e8", 0x57CEBA0),
        (0x57C0C7C, "488d0d", 0x64A61D8), (0x57C0C91, "488d0d", 0x64A6250),
        (0x57C0CA6, "488d0d", 0x64A6278), (0x57C0CF3, "e8", 0x4E1BEA0),
        (0x141B627, "e8", 0x141A8C0), (0x4DA1E63, "488d05", 0x649A6F0),
        (0x4DA1E9F, "e8", 0x4E1BEA0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    assert (reloc[0x64A61F0], reloc[0x64A6268], reloc[0x64A6270], reloc[0x64A6290], reloc[0x64A6298], reloc[0x649A708]) == (
        0x141B610, 0x14CEAC0, 0x14CEAA0, 0x4DA1BA0, 0x4D9DB00, 0x14199B0,
    )
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: named tracker fields, raw name bytes, zero-width branch and tracked-row count")


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
    height = 900

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, tracker, **packing):
        source = {"exchange": {"locus": {"ctx": {"height": height}}, FIELD: tracker}}
        return save(name, msgpack.packb(source, **packing))

    def reference(name, selected, stale=False):
        slots = [[0, [[4, leaf(bytes(8))]]], [32, selected]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    zero = leaf(bytes(8))
    for name, raw in (("", b""), ("abc", b"abc"), ("验证", bytes.fromhex("e9aa8ce8af81"))):
        exact = [[0, leaf(raw)], [1, []], [2, [[2, zero]]]]
        tracker = {"i": [], "hsc": [], "name": name}
        source = checkpoint("ordinary.rmp", tracker)
        good = compare(kit, helper, height, *source, *reference("ordinary.json", exact))
        assert good["ordered_vtg_slot_matches"] and all(good["fields"].values())
    distinct = [[0, leaf(b"other")], [1, []], exact[2]]
    bad = reference("different.json", distinct)
    mismatch = compare(kit, helper, height, *source, *bad)
    assert not mismatch["ordered_vtg_slot_matches"] and mismatch["fields"] == {"name": False, "hsc": True, "i": True}
    wrong_branch = [[0, exact[0][1]], [1, leaf(b"")], [2, [[0, []], [1, []], [2, zero]]]]
    mismatch = compare(kit, helper, height, *source, *reference("wrong-empty-shape.json", wrong_branch))
    assert not mismatch["ordered_vtg_slot_matches"] and mismatch["fields"] == {"name": True, "hsc": False, "i": False}

    for candidate, ref, expected in (
        (checkpoint("nonempty.rmp", tracker | {"i": [[None, {}]]}), bad, "i must be an empty sequence"),
        (checkpoint("bad-hsc.rmp", tracker | {"hsc": None}), bad, "empty hsc branch"),
        (source, reference("stale.json", exact, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert expected in str(error), error
        else:
            raise AssertionError(expected)

    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_empty_tracker.py"), folder, helper,
           str(height), *source, *bad]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and not json.loads(run.stdout)["ordered_vtg_slot_matches"]
    print(f"PASS: msgpack {msgpack.__version__}; empty, ASCII and multibyte name controls")
    print("PASS: full slot matches; wrong name, wrong empty shape, nonempty scope and stale digest differentiated")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
