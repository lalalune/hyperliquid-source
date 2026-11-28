"""Authenticate six ordinary leaf joins and compare pinned fixtures offline."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_leaves import FIELDS, compare, load_helpers

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
RUST_HELPER = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


def native():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    slots = bind(data)["slots"]
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def check(va, expect):
        raw = bytes.fromhex(expect)
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for name, slots_and_site in {
        "spot_disabled": (0x42AC, 0x548112A),
        "prune_agent_idx": (0x4230, 0x5481156),
        "evm_enabled": (0x42AD, 0x548136E),
        "hip3_no_cross": (0x42AE, 0x548148B),
        "dex_abstraction_enabled": (0x42AF, 0x548152C),
        "pmn": (0x4270, 0x54815D4),
    }.items():
        offset, load = slots_and_site
        slot, kind = FIELDS[name]
        short = kind is bool
        width, table, raw_leaf = (1, 0x64A8458, 0x1419D40) if short else (8, 0x64A8480, 0x14199B0)
        row = slots[slot]
        assert (int(row["box_field"], 16), row["type_size"], int(row["vtable"], 16),
                int(row["method_0"], 16)) == (offset, width, table, raw_leaf)
        prefix = "450fb687" if short else "4d8b87"
        check(load, prefix + offset.to_bytes(4, "little").hex())
        key_site = load + len(bytes.fromhex(prefix)) + 4
        target = rip_target(data, key_site, b"\x48\x8d\x15", 7)
        assert read_va(data, target, len(name)) == name.encode("ascii")
        check(key_site + 10, "b9" + len(name).to_bytes(4, "little").hex())
        assert rip_target(data, key_site + 18, b"\xe8", 5) == (0x56783A0 if short else 0x56736B0)

    for va, raw in {
        0x56783AE: "4489c5", 0x56783EA: "4080cdc2", 0x5678404: "42880421",
        0x56736BB: "4d89c6", 0x56736F0: "4c89f2", 0x57D00BE: "4881fa00010000",
        0x1419D45: "0fb60f", 0x1419D6B: "880c02", 0x1419D6E: "48ffc0",
        0x14199DC: "48890c02", 0x14199E0: "4883c008",
    }.items():
        check(va, raw)
    assert rip_target(data, 0x56736F3, b"\xe8", 5) == 0x57D00B0
    relocs = relative_relocations(data)
    assert relocs[0x64A8470] == 0x1419D40 and relocs[0x64A8498] == 0x14199B0
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: six native name/offset/slot joins and separate one-byte/qword writers")


def rust_driver(folder, rustc, tmp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    data = source.read_bytes()
    assert hashlib.sha256(data).hexdigest() == RUST_HELPER
    saved = tmp / source.name
    saved.write_bytes(data)
    lib = tmp / "libnode115_abci_blake3.rlib"
    exe = tmp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs", "-o", lib], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={lib}", "-o", exe], check=True)
    return exe


def controls(folder, rustc, tmp):
    import msgpack

    kit = load_helpers(folder)
    helper = rust_driver(folder, rustc, tmp)

    def hash_input(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    height = 801
    fields = {"spot_disabled": True, "prune_agent_idx": 0x0102030405060708, "evm_enabled": False,
              "hip3_no_cross": True, "dex_abstraction_enabled": False, "pmn": (1 << 64) - 1}

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, state, local_height=height):
        encoded = msgpack.packb({"exchange": {"locus": {"ctx": {"height": local_height}},
                                             "extra": [1, {"skip": b"other"}], **state}})
        return save(name, encoded)

    def reference(name, evm, prune, wrong_digest=False):
        raw = [[0, [[4, hash_input(b"other slot")]]], [23, hash_input(b"\x01")], [24, hash_input(prune)],
               [38, hash_input(evm)], [46, hash_input(b"\x01")], [50, hash_input(b"\x00")],
               [55, hash_input(bytes.fromhex("ffffffffffffffff"))]]
        tree = kit["tree"]
        digest = hash_input(b"stale") if wrong_digest else tree.digest(helper, tree.decode_tree(raw))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": raw}).encode())

    prune = bytes.fromhex("0807060504030201")
    rmp = checkpoint("native.rmp", fields)
    correct = reference("correct.json", b"\x00", prune)
    result = compare(kit, helper, height, *rmp, *correct)
    assert result["all_direct_leaves_match"]
    assert tuple(row["slot"] for row in result["fields"].values()) == (23, 24, 38, 46, 50, 55)

    wrong_width = reference("wrong-width.json", bytes(8), prune[::-1])
    result = compare(kit, helper, height, *rmp, *wrong_width)
    assert not result["all_direct_leaves_match"]
    assert [name for name, row in result["fields"].items() if not row["matches"]] == ["prune_agent_idx", "evm_enabled"]

    misuse = checkpoint("wrong-type.rmp", fields | {"evm_enabled": 0})
    wrong_height = checkpoint("wrong-height.rmp", fields, height + 1)
    missing = checkpoint("missing.rmp", {name: val for name, val in fields.items() if name != "pmn"})
    stale = reference("stale.json", b"\x00", prune, wrong_digest=True)
    for source, ref, reason in ((misuse, correct, "native bool"), (wrong_height, correct, "Context height"),
                                (missing, correct, "omits pmn"), (rmp, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *source, *ref)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_leaves.py"), folder, helper,
           str(height), *rmp, *wrong_width]
    run = subprocess.run(cmd, capture_output=True, check=False)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; all six direct Exchange leaves match a verified synthetic export")
    print("PASS: false width and qword order differences localized; type, missing field, height and stale digest controls")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as tmp:
        controls(args.helpers, args.rustc, Path(tmp))
