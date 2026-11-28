"""Authenticate named BucketGuard joins and test ordered root subtrees on pinned fixtures."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_guards import GUARDS, compare, load_helpers

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
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def check(va, expected):
        raw = bytes.fromhex(expected)
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    sites = {
        "funding_distribute_guard": (0x4158, 0x5480E6D, 0x5480E4F, 0x5480E7A),
        "funding_update_guard": (0x4168, 0x5480E8C, 0x5480E93, 0x5480EA5),
        "cancel_aggressive_orders_at_open_interest_cap_guard": (0x4178, 0x5480FDC, 0x5480FE3, 0x5480FF5),
        "book_empty_user_states_pruning_guard": (0x4188, 0x54810C1, 0x54810C8, 0x54810DA),
        "begin_block_logic_guard": (0x4198, 0x54812B2, 0x54812B9, 0x54812CB),
        "hip3_stale_mark_px_guard": (0x41D8, 0x5481416, 0x548141D, 0x548142F),
    }
    for name, (offset, load, key, edge) in sites.items():
        row = slots[GUARDS[name]]
        assert (int(row["box_field"], 16), row["type_size"], int(row["vtable"], 16),
                int(row["method_0"], 16)) == (offset, 16, 0x64A8200, 0x46F4560)
        direct = name == "funding_distribute_guard"
        check(load, ("498db7" if direct else "4d8d87") + offset.to_bytes(4, "little").hex())
        prefix = b"\x48\x8d\x35" if direct else b"\x48\x8d\x15"
        length_opcode = "ba" if direct else "b9"
        check(key + (7 if direct else 10), length_opcode + len(name).to_bytes(4, "little").hex())
        assert read_va(data, rip_target(data, key, prefix, 7), len(name)) == name.encode("ascii")
        assert rip_target(data, edge, b"\xe8", 5) == (0x5617020 if direct else 0x56781F0)

    for va, literal in ((0x561709A, b"last_bucket"), (0x56170D3, b"bucket_millis")):
        assert read_va(data, rip_target(data, va, b"\x48\x8d\x35", 7), len(literal)) == literal
    for site in (0x56170BD, 0x56170F6):
        assert rip_target(data, site, b"\xe8", 5) == 0x57D00B0
    assert rip_target(data, 0x5678226, b"\xe9", 5) == 0x5617020
    assert rip_target(data, 0x46F45BF, b"\xff\x15", 6) == 0x64DF530
    assert rip_target(data, 0x46F45FF, b"\xff\x25", 6) == 0x64DF5D0
    for va, raw in {
        0x561708F: "4d8b6708", 0x56170ED: "498b17", 0x46F4586: "48837e1002",
        0x46F4590: "4c8d7708", 0x46F45C9: "4c89e7", 0x46F45CC: "4883c318",
        0x14199DC: "48890c02", 0x141B3EC: "48890c02",
    }.items():
        check(va, raw)
    relocs = relative_relocations(data)
    for slot, target in ((0x64A8218, 0x46F4560), (0x64DF530, 0x14199B0), (0x64DF5D0, 0x141B3C0)):
        assert relocs[slot] == target
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: six named writer and shared two-qword raw visitor bindings")


def make_driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DRIVER_SHA
    saved = tmp / source.name
    saved.write_bytes(raw)
    lib = tmp / "libnode115_abci_blake3.rlib"
    binary = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", lib], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={lib}", "-o", binary], check=True)
    return binary


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = make_driver(folder, rustc, tmp)

    def hashed(value):
        return subprocess.check_output([helper], input=value.to_bytes(8, "little")).decode().strip()

    pairs = [(7, 150), (1601, 100), (0, 20), (1 << 32, 1000), (94, 500), ((1 << 64) - 1, 3000)]
    height = 710
    guards = {name: {"bucket_millis": millis, "last_bucket": last}
              for name, (last, millis) in zip(GUARDS, pairs)}

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, fields, h=height):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": h}}, **fields}}))

    def reference(name, changed_values=False, wrong_root=False):
        rows = [[0, [[4, hashed(19)]]]]
        for slot, (last, millis) in zip((4, 5, 14, 20, 33, 43), pairs):
            if changed_values and slot == 33:
                millis += 1
            leaves = [[0, hashed(last)], [1, hashed(millis)]]
            rows.append([slot, leaves[::-1] if changed_values and slot == 43 else leaves])
        tree = kit["tree"]
        digest = hashed(700) if wrong_root else tree.digest(helper, tree.decode_tree(rows))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": rows}).encode())

    source = checkpoint("native.rmp", guards)
    exact = reference("exact.json")
    assert compare(kit, helper, height, *source, *exact)["all_guard_subtrees_match"]
    changed = reference("changed.json", changed_values=True)
    result = compare(kit, helper, height, *source, *changed)
    assert not result["all_guard_subtrees_match"]
    assert result["guards"]["begin_block_logic_guard"]["fields"] == {"last_bucket": True, "bucket_millis": False}
    stale_mark = result["guards"]["hip3_stale_mark_px_guard"]
    assert not stale_mark["ordered_children_match"] and all(stale_mark["fields"].values())
    assert sum(row["exact_subtree_match"] for row in result["guards"].values()) == 4

    omitted = checkpoint("omitted.rmp", {name: pair for name, pair in guards.items()
                                         if name != "funding_distribute_guard"})
    invalid = checkpoint("invalid.rmp", guards | {"funding_update_guard": {"last_bucket": True, "bucket_millis": 100}})
    wrong_height = checkpoint("wrong-height.rmp", guards, height + 1)
    stale = reference("stale.json", wrong_root=True)
    for candidate, ref, phrase in ((omitted, exact, "missing named guards"),
                                   (invalid, exact, "unsigned 64-bit"),
                                   (wrong_height, exact, "Context height"),
                                   (source, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert phrase in str(error), error
        else:
            raise AssertionError(phrase)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_guards.py"), folder, helper,
           str(height), *source, *changed]
    run = subprocess.run(cmd, capture_output=True, check=False)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; all twelve guard leaves and six ordered branches match")
    print("PASS: slot-33 millis and slot-43 order deviations isolated; named, height and digest errors rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as tmp:
        controls(args.helpers, args.rustc, Path(tmp))
