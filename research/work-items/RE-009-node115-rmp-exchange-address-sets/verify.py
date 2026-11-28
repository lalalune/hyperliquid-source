"""Authenticate Address-set visitors and compare complete pinned test subtrees."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_sets import SETS, compare, load_helpers

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
    slots = bind(data)["slots"]
    for name, offset, method in (("allowed_liquidators", 0x41E8, 0x5330F90),
                                 ("disabled_precompiles", 0x4250, 0x5330B20)):
        row = slots[SETS[name]]
        assert (int(row["box_field"], 16), int(row["method_0"], 16),
                int(row["method_1"], 16)) == (offset, method, 0x5330220)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]
    for va, encoding in {
        0x5480ED6: "4d8d87e8410000", 0x5481441: "498d9750420000",
        0x52CA344: "b914000000", 0x52CA352: "ffd3", 0x4E2E05B: "66c744240e3078", 0x4E2E341: "ba2a000000",
        0x513875B: "0fb791e6000000", 0x5138892: "488d7001",
        0x51388F1: "488d0480488d04824883c008",
        0x5330FAB: "4c8b4710", 0x5330B3B: "4c8b4710", 0x53310BF: "410fb78de6000000",
        0x5330DF0: "4d8d7e01", 0x5331260: "4d8d7e01",
        0x5330BFE: "4b8d04b6488d048508000000",
        0x533106E: "4b8d04b6488d048508000000",
        0x53312BD: "4c89442420", 0x5330E4D: "4c89442420",
        0x533023E: "48890848894818", 0x141B9F1: "4883c114", 0x14199DC: "48890c02",
    }.items():
        raw = bytes.fromhex(encoding)
        assert any(begin <= va and va + len(raw) <= end for begin, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)
    for va, prefix, width, target in (
        (0x5480EEF, b"\xe8", 5, 0x5677400), (0x5677436, b"\xe9", 5, 0x52CA1D0),
        (0x548144E, b"\xe8", 5, 0x56773A0), (0x56773E4, b"\x0f\x84", 6, 0x52EE360),
        (0x52CA26A, b"\xe8", 5, 0x57CEBA0), (0x52EE3FE, b"\xe8", 5, 0x57CEBA0),
        (0x52CA313, b"\xe8", 5, 0x5138730), (0x52EE4CD, b"\xe8", 5, 0x5138730),
        (0x52EE4EB, b"\xe8", 5, 0x4E2E020),
        (0x4E2E349, b"\xe8", 5, 0x57CF5D0),
        (0x5330C1D, b"\x48\x8d\x05", 7, 0x64A47B0), (0x533108D, b"\x48\x8d\x05", 7, 0x64A47D8),
        (0x5330EF7, b"\xff\x15", 6, 0x64DF538), (0x5331367, b"\xff\x15", 6, 0x64DF538),
    ):
        assert rip_target(data, va, prefix, width) == target, hex(va)
    for va, prefix, literal in ((0x5480EDD, b"\x48\x8d\x15", b"allowed_liquidators"),
                                (0x56773AF, b"\x48\x8d\x05", b"disabled_precompiles")):
        assert read_va(data, rip_target(data, va, prefix, 7), len(literal)) == literal
    relocs = relative_relocations(data)
    for at, target in {0x64A47C8: 0x141B9B0, 0x64A47F0: 0x41F8050,
                       0x64DF600: 0x141B9B0, 0x64DF538: 0x14199B0}.items():
        assert relocs[at] == target, hex(at)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: both named Address set writers and native ordered member/count paths")


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
    height = 770
    synthetic = [bytes([n]) * 20 for n in (13, 44, 102, 224)]
    first, second = list(SETS)

    def leaf(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, a, b, h=height):
        fields = {"locus": {"ctx": {"height": h}}, first: ["0x" + p.hex() for p in a],
                  second: ["0x" + p.hex() for p in b]}
        return save(name, msgpack.packb({"exchange": fields}))

    def reference(name, a, b, stale=False):
        entries = [[0, [[4, leaf(b"other")]]], [7, a], [44, b]]
        digest = leaf(b"wrong") if stale else tree.digest(helper, tree.decode_tree(entries))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": entries}).encode())

    def expected(rows):
        branch = [[0, leaf(b"".join(rows))]] if rows else []
        return branch + [[1, leaf(len(rows).to_bytes(8, "little"))]]

    a, b = synthetic[:2], synthetic[2:]
    exact = reference("exact.json", expected(a), expected(b))
    named = checkpoint("named.rmp", a, b)
    assert compare(kit, helper, height, *named, *exact)["both_set_subtrees_match"]
    empty_first = checkpoint("empty-first.rmp", [], b)
    assert compare(kit, helper, height, *empty_first,
                   *reference("empty-first.json", expected([]), expected(b)))["both_set_subtrees_match"]
    empty_second = checkpoint("empty-second.rmp", a, [])
    assert compare(kit, helper, height, *empty_second,
                   *reference("empty-second.json", expected(a), expected([])))["both_set_subtrees_match"]
    reverse = checkpoint("order.rmp", a[::-1], b)
    result = compare(kit, helper, height, *reverse, *exact)
    assert not result["sets"][first]["address_stream_matches"] and result["sets"][first]["count_leaf_matches"]
    assert result["sets"][second]["ordered_subtree_matches"]
    wrong_count_ref = reference("wrong-count.json", expected(a), [expected(b)[0], expected([])[0]])
    wrong_count = compare(kit, helper, height, *named, *wrong_count_ref)
    assert wrong_count["sets"][second]["address_stream_matches"]
    assert not wrong_count["sets"][second]["count_leaf_matches"]

    duplicate = checkpoint("duplicate.rmp", [a[0], a[0]], b)
    wrong_height = checkpoint("later.rmp", a, b, height + 1)
    stale = reference("stale.json", expected(a), expected(b), stale=True)
    for source, export, phrase in ((duplicate, exact, "duplicate member"), (wrong_height, exact, "Context height"),
                                   (named, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *source, *export)
        except ValueError as error:
            assert phrase in str(error), error
        else:
            raise AssertionError(phrase)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_sets.py"), folder, helper,
           str(height), *reverse, *exact]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; both empty and nonempty Address-set subtrees")
    print("PASS: independent order and count mismatches, duplicate member, height and stale digest controls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
