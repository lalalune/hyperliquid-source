"""Authenticate numeric policy field joins and run the pinned fixture comparisons."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_limits import FIELDS, compare, load_helpers

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
        "max_order_distance_from_anchor": (0x4220, 0x5480F7D, 0x5480F86, 0x5480F98, 0x5678170, 0x1419900),
        "scheduled_freeze_height": (0x10E8, 0x5480FAA, 0x5480FB8, 0x5480FCA, 0x5675090, 0x4D3EBE0),
        "post_only_until_height": (0x4228, 0x548105D, 0x5481064, 0x5481071, 0x56771F0, 0x14199B0),
        "max_hlp_withdraw_fraction_per_day": (0x4238, 0x5481181, 0x548118A, 0x548119C, 0x5678170, 0x1419900),
    }
    for name, (offset, load, key, edge, writer, raw) in sites.items():
        row = slots[FIELDS[name]]
        assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (offset, raw)
        prefix = {0x1419900: "f3410f7e87", 0x4D3EBE0: "4d8b87", 0x14199B0: "498b8f"}[raw]
        check(load, prefix + offset.to_bytes(4, "little").hex())
        assert read_va(data, rip_target(data, key, b"\x48\x8d\x15", 7), len(name)) == name.encode("ascii")
        assert rip_target(data, edge, b"\xe8", 5) == writer

    for va, raw in {
        0x5480FB1: "4d8b8ff0100000", 0x56750D0: "4983ff01", 0x567511C: "c60430c0",
        0x5677214: "ba16000000", 0x4E380E9: "c60430cb", 0x4E38187: "480fc8",
        0x4E3818E: "48890431", 0x141992E: "f20f110401", 0x1419933: "4883c008",
        0x4D3EBF3: "833f01", 0x4D3EC18: "4883c708", 0x4D3EC5E: "4883c318",
        0x4D3ECAB: "488d5818", 0x14199DC: "48890c02", 0x14199E0: "4883c008",
    }.items():
        check(va, raw)
    for va, prefix, target in (
        (0x56781B2, b"\xe8", 0x4E380C0), (0x56750DE, b"\xe8", 0x57D00B0),
        (0x5677238, b"\xe8", 0x57D00B0), (0x4D3EC50, b"\xff\x15", 0x64DF530),
        (0x4D3ECE2, b"\xff\x15", 0x64DF538),
    ):
        assert rip_target(data, va, prefix, len(prefix) + 4) == target
    for va, tag in ((0x4D3EC8A, 1), (0x4D3ECD8, 0)):
        assert read_va(data, rip_target(data, va, b"\x48\x8d\x3d", 7), 8) == tag.to_bytes(8, "little")
    relocs = relative_relocations(data)
    assert relocs[0x64DF530] == relocs[0x64DF538] == 0x14199B0
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: native binary64 endian conversion, scheduled Option branch and post-only u64 writer")


def driver(folder, rustc, temp):
    source = folder / "RE-009-node115-context-root-isolation/hash_tree.rs"
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DRIVER_SHA
    saved = temp / source.name
    saved.write_bytes(raw)
    library = temp / "libnode115_abci_blake3.rlib"
    executable = temp / "hash_tree"
    subprocess.run([rustc, "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", "src/node115-abci-blake3/src/lib.rs",
                    "-o", library], check=True)
    subprocess.run([rustc, "--edition=2024", saved, "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    return executable


def controls(folder, rustc, temp):
    import msgpack

    kit = load_helpers(folder)
    helper = driver(folder, rustc, temp)

    def hash_raw(raw):
        return subprocess.check_output([helper], input=raw).decode().strip()

    height = 90
    fields = {"max_order_distance_from_anchor": -0.0, "scheduled_freeze_height": 0,
              "post_only_until_height": 0x0102030405060708, "max_hlp_withdraw_fraction_per_day": 0.125}

    def save(name, raw):
        path = temp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, state, single=False):
        return save(name, msgpack.packb({"exchange": {"locus": {"ctx": {"height": height}}, **state}},
                                         use_single_float=single))

    positive_zero = bytes(8)
    negative_zero = bytes.fromhex("0000000000000080")
    word_one = bytes.fromhex("0100000000000000")
    freeze_absent = [[1, hash_raw(positive_zero)]]
    freeze_some_zero = [[0, hash_raw(positive_zero)], [1, hash_raw(word_one)]]

    def reference(name, first, freeze, bad=False):
        raw = [[0, [[4, hash_raw(b"unrelated")]]], [12, hash_raw(first)], [13, freeze],
               [17, hash_raw(bytes.fromhex("0807060504030201"))], [25, hash_raw(bytes.fromhex("000000000000c03f"))]]
        tree = kit["tree"]
        digest = hash_raw(b"untrusted") if bad else tree.digest(helper, tree.decode_tree(raw))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": raw}).encode())

    named = checkpoint("named.rmp", fields)
    exact = reference("exact.json", negative_zero, freeze_some_zero)
    assert compare(kit, helper, height, *named, *exact)["all_limit_fields_match"]
    absent = checkpoint("absent.rmp", fields | {"scheduled_freeze_height": None})
    absent_ref = reference("absent.json", negative_zero, freeze_absent)
    assert compare(kit, helper, height, *absent, *absent_ref)["all_limit_fields_match"]
    wrong = reference("wrong.json", positive_zero, freeze_absent)
    result = compare(kit, helper, height, *named, *wrong)
    assert not result["all_limit_fields_match"]
    assert [key for key, row in result["fields"].items() if not row["matches"]] == [
        "max_order_distance_from_anchor", "scheduled_freeze_height",
    ]

    single = checkpoint("single.rmp", fields, single=True)
    infinite = checkpoint("infinite.rmp", fields | {"max_order_distance_from_anchor": float("inf")})
    stale = reference("stale.json", negative_zero, freeze_some_zero, bad=True)
    for source, raw, reason in ((single, exact, "finite MessagePack binary64"),
                                (infinite, exact, "finite MessagePack binary64"),
                                (named, stale, "stated raw ABCI digest")):
        try:
            compare(kit, helper, height, *source, *raw)
        except ValueError as error:
            assert reason in str(error), error
        else:
            raise AssertionError(reason)
    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_limits.py"), folder, helper,
           str(height), *named, *wrong]
    run = subprocess.run(cmd, capture_output=True, check=False)
    assert run.returncode == 1 and json.loads(run.stdout) == result
    print(f"PASS: msgpack {msgpack.__version__}; four complete slots and both freeze cases")
    print("PASS: signed zero and nil-versus-Some(0) localized; binary32, infinite and stale digest rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as tmp:
        controls(args.helpers, args.rustc, Path(tmp))
