"""Exercise five pinned comparison implementations against one offline input pair."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from report import load_checks, report

DRIVER_SHA = "6791575648e65e8ef4fe42536b7327f85c57327cb2423255b598fb2b1d83828f"


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

    executable = driver(folder, rustc, tmp)
    direct = load_checks(folder)["direct"]
    tree = direct.load_helpers(folder)["tree"]
    height = 100

    def leaf(raw):
        return subprocess.check_output([executable], input=raw).decode().strip()

    def word(value):
        return leaf(value.to_bytes(8, "little"))

    def quantity(value):
        return [[0, word(value)], [1, leaf(b"")]]

    def save(name, data):
        path = tmp / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    fields = {
        "locus": {"ctx": {"height": height}},
        "spot_disabled": True, "prune_agent_idx": 7, "evm_enabled": False,
        "hip3_no_cross": True, "dex_abstraction_enabled": False, "pmn": 8,
        "funding_distribute_guard": {"bucket_millis": 13, "last_bucket": 0},
        "funding_update_guard": {"bucket_millis": 13, "last_bucket": 1},
        "cancel_aggressive_orders_at_open_interest_cap_guard": {"bucket_millis": 13, "last_bucket": 2},
        "book_empty_user_states_pruning_guard": {"bucket_millis": 13, "last_bucket": 3},
        "begin_block_logic_guard": {"bucket_millis": 13, "last_bucket": 4},
        "hip3_stale_mark_px_guard": {"bucket_millis": 13, "last_bucket": 5},
        "last_hlp_cancel_time": "1970-01-01T00:00:01",
        "post_only_until_time": "1970-01-01T00:00:02",
        "lvt": "1970-01-01T00:00:03",
        "max_order_distance_from_anchor": -0.0, "scheduled_freeze_height": None,
        "post_only_until_height": 40, "max_hlp_withdraw_fraction_per_day": 0.125,
        "hlp_start_of_day_account_value": 33, "pvs": {"ptc": 52, "mptc": 51},
        "initial_usdc_evm_system_balance": 53,
    }
    rows = {0: [[4, word(height)]],
            23: leaf(b"\x01"), 24: word(7), 38: leaf(b"\x00"),
            46: leaf(b"\x01"), 50: leaf(b"\x00"), 55: word(8),
            12: leaf(bytes.fromhex("0000000000000080")), 13: [[1, word(0)]],
            17: word(40), 25: leaf(bytes.fromhex("000000000000c03f")),
            26: [[0, quantity(33)], [1, word(1)]], 27: [[0, quantity(51)], [1, quantity(52)]],
            47: quantity(53)}
    rows.update({slot: [[0, word(idx)], [1, word(13)]]
                 for idx, slot in enumerate((4, 5, 14, 20, 33, 43))})
    rows.update({slot: leaf(struct.pack("<qI", secs, 0))
                 for secs, slot in enumerate((15, 16, 45), 1)})

    def checkpoint(name, selected):
        return save(name, msgpack.packb({"exchange": selected}))

    def reference(name, values, claimed=None):
        tree_rows = sorted(values.items())
        tree_rows = [[slot, child] for slot, child in tree_rows]
        digest = tree.digest(executable, tree.decode_tree(tree_rows)) if claimed is None else claimed
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": tree_rows}).encode())

    source = checkpoint("exchange.rmp", fields)
    exact = reference("exchange.json", rows)
    result = report(folder, executable, height, *source, *exact)
    assert result["all_scoped_groups_match"] and result["scoped_slot_count"] == 22
    assert result["checkpoint_sha256"] == source[1] and result["reference_sha256"] == exact[1]
    assert all(group["detail"]["reference_raw_digest"] == result["reference_raw_digest"]
               for group in result["groups"].values())

    changed = reference("changed.json", rows | {20: rows[20][::-1], 45: leaf(struct.pack("<qI", 4, 0))})
    result = report(folder, executable, height, *source, *changed)
    assert not result["all_scoped_groups_match"]
    assert [name for name, group in result["groups"].items() if not group["matches"]] == [
        "bucket_guards", "times",
    ]

    def cli(src, ref):
        return subprocess.run(
            [sys.executable, "-B", Path(__file__).with_name("report.py"), folder, executable,
             str(height), *src, *ref], check=False, capture_output=True,
        )

    good = cli(source, exact)
    assert good.returncode == 0 and json.loads(good.stdout)["scoped_slot_count"] == 22
    mismatch = cli(source, changed)
    assert mismatch.returncode == 1 and json.loads(mismatch.stdout) == result
    stale = reference("stale.json", rows, claimed=leaf(b"stale"))
    for ref, message in ((stale, b"stated raw ABCI digest"), ((exact[0], "0" * 64), b"SHA-256")):
        invalid = cli(source, ref)
        assert invalid.returncode == 2 and not invalid.stdout and message in invalid.stderr, invalid.stderr
    print(f"PASS: five byte-pinned comparators; msgpack {msgpack.__version__}; 22 disjoint ordered slots")
    print("PASS: one input pair and reference digest bound across all comparison receipts")
    print("PASS: two mismatched groups isolated, scoped results preserved, stale digest and pin rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
