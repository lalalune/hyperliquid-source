"""Verify named Hyperliquidity keys, count and independent guard projection."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_hyperliquidity import FIELD, GUARD, RANGES, SLOT, compare, load_helpers

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
    assert (int(row["box_field"], 16), int(row["method_0"], 16)) == (0x3FC8, 0x3917E00)
    sections, header = unwind_index(data)
    _, frames = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    extents = [(row["start"], row["end"]) for row in frames
               if (row["start"], row["fde"]) in indexed]

    def verify_bytes(va, raw):
        assert any(start <= va and va + len(raw) <= end for start, end in extents), hex(va)
        assert read_va(data, va, len(raw)) == raw, hex(va)

    for site, name in ((0x5677471, b"hyperliquidity"), (0x5188D8C, b"spot_to_range"),
                       (0x5188E91, b"ensure_order_bucket_guard"),
                       (0x561709A, b"last_bucket"), (0x56170D3, b"bucket_millis")):
        assert read_va(data, rip_target(data, site, bytes.fromhex("488d35"), 7), len(name)) == name
    for va, raw in {
        0x548110B: "498d97c83f0000", 0x5188D3E: "ba02000000", 0x5188EAB: "4983c720",
        0x529D329: "498d442428", 0x529D336: "4d8d6c2408", 0x561708F: "4d8b6708", 0x56170ED: "498b17",
        0x3917E07: "48897c2408", 0x3917E18: "4883c720", 0x3C6C151: "488b5718",
        0x3C6C199: "4d85f6", 0x41ADC99: "48837f1003", 0x41ADCE0: "4c8b6c2408",
        0x41ADCF7: "4c89eeff5318", 0x46F4590: "4c8d7708", 0x46F45CC: "4883c318",
        0x14199DC: "48890c02", 0x141B3EC: "48890c02",
    }.items():
        verify_bytes(va, bytes.fromhex(raw))
    for va, prefix, target in (
        (0x5481118, "e8", 0x5677460), (0x567749C, "e9", 0x5188D10), (0x5188E7A, "e8", 0x529D140),
        (0x5188EBA, "e8", 0x5617020), (0x529D474, "e8", 0x57CEBA0), (0x529D4AB, "e8", 0x57D00B0),
        (0x56170BD, "e8", 0x57D00B0), (0x56170F6, "e8", 0x57D00B0),
        (0x3917E0C, "488d0d", 0x646EF68), (0x3917E21, "488d0d", 0x646EF90),
        (0x3917E5B, "e8", 0x41AE280), (0x3C6C2E5, "4c8d35", 0x6474070),
        (0x3C6C2EC, "4c8d3d", 0x6478038), (0x3C6C404, "488d05", 0x6473FF8),
        (0x3C6C440, "e8", 0x41ADC70), (0x457D480, "ff25", 0x64DF538),
        (0x46F45BF, "ff15", 0x64DF530), (0x46F45FF, "ff25", 0x64DF5D0),
    ):
        op = bytes.fromhex(prefix)
        assert rip_target(data, va, op, len(op) + 4) == target, hex(va)
    reloc = relative_relocations(data)
    for site, method in {0x646EF80: 0x3C6C140, 0x646EFA8: 0x46F4560, 0x6474088: 0x457D480,
                         0x6474010: 0x14199B0, 0x64DF538: 0x14199B0, 0x64DF530: 0x14199B0,
                         0x64DF5D0: 0x141B3C0}.items():
        assert reloc[site] == method, hex(site)
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: raw Hyperliquidity key stream, separate count and two-word embedded guard")


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

    def word(value):
        return value.to_bytes(8, "little")

    def save(name, raw):
        path = tmp / name
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest()

    def checkpoint(name, rows):
        projection = {GUARD: {"bucket_millis": 305, "last_bucket": 11}, RANGES: rows}
        source = {"exchange": {"locus": {"ctx": {"height": height}}, FIELD: projection}}
        return save(name, msgpack.packb(source))

    def reference(name, ordered_keys, count, buckets=(11, 305), stale=False):
        rows = []
        if ordered_keys:
            rows.extend([[0, leaf(b"".join(map(word, ordered_keys)))],
                         [1, [[1, leaf(b"opaque independent range values")]]]])
        rows.append([2, leaf(word(count))])
        slots = [[0, [[4, leaf(word(height))]]], [22, [
            [0, rows], [1, [[i, leaf(word(val))] for i, val in enumerate(buckets)]],
        ]]]
        digest = leaf(b"stale") if stale else tree.digest(helper, tree.decode_tree(slots))
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": slots}).encode())

    keys = [7, 191, (1 << 64) - 1]
    source = checkpoint("ranges.rmp", [[key, None] for key in keys])
    exact = reference("ordinary.json", keys, 3)
    assert compare(kit, helper, height, *source, *exact)["scoped_match"]
    assert compare(kit, helper, height, *checkpoint("empty.rmp", []),
                   *reference("empty.json", [], 0))["scoped_match"]

    reversed_keys = reference("reversed.json", keys[::-1], 3)
    mismatch = compare(kit, helper, height, *source, *reversed_keys)
    assert not mismatch["ordered_range_keys_match"]
    assert mismatch["row_count_matches"] and mismatch["ensure_order_guard_matches"]

    changed = reference("changed.json", keys, 2, buckets=(305, 11))
    mismatch = compare(kit, helper, height, *source, *changed)
    assert mismatch["ordered_range_keys_match"]
    assert not mismatch["row_count_matches"] and not mismatch["ensure_order_guard_matches"]
    for candidate, ref, expected in (
        (checkpoint("bad-keys.rmp", [[7, None], [7, None]]), exact, "duplicate spot range key"),
        (source, reference("stale.json", keys, 3, stale=True), "stated raw ABCI digest"),
    ):
        try:
            compare(kit, helper, height, *candidate, *ref)
        except ValueError as error:
            assert expected in str(error), error
        else:
            raise AssertionError(expected)

    cmd = [sys.executable, "-B", Path(__file__).with_name("compare_hyperliquidity.py"), folder, helper,
           str(height), *source, *changed]
    run = subprocess.run(cmd, check=False, capture_output=True)
    assert run.returncode == 1 and json.loads(run.stdout) == mismatch
    print(f"PASS: msgpack {msgpack.__version__}; empty and 3-key ordered range projections")
    print("PASS: key order, count and guard differences isolated after canonical raw reference verification")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    native()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
