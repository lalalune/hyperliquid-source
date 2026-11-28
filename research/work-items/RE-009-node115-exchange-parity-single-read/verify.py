"""Measure one complete source read and compare old and projected Exchange receipts."""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare_once import CHUNK_BYTES, FIELDS, MAX_FIELD_BYTES, compare_once, load_helpers, project

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
    kit = load_helpers(folder)
    report = kit["report"].report
    direct = kit["report"].load_checks(folder)["direct"]
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

    class CountedBytes(BytesIO):
        quantity = 0

        def read(self, size=-1):
            chunk = super().read(size)
            self.quantity += len(chunk)
            return chunk

    packer = msgpack.Packer(use_bin_type=True)

    def mapping(rows):
        return packer.pack_map_header(len(rows)) + b"".join(packer.pack(key) + value for key, value in rows.items())

    def source_data(selected, pack_float=packer.pack):
        payload = {name: packer.pack(value) for name, value in selected.items()}
        for key in ("max_order_distance_from_anchor", "max_hlp_withdraw_fraction_per_day"):
            payload[key] = pack_float(selected[key])
        padding = packer.pack(bytes(CHUNK_BYTES * 22))
        # Position max_order_distance_from_anchor's marker exactly at the end of a read.
        prefix = mapping({"exchange": packer.pack_map_header(len(payload) + 2)})
        keys = packer.pack("prefix") + packer.pack("max_order_distance_from_anchor")
        padding_bytes = CHUNK_BYTES - 1 - len(prefix) - len(keys) - 3
        before = {"prefix": packer.pack(bytes(padding_bytes)),
                  "max_order_distance_from_anchor": payload.pop("max_order_distance_from_anchor")}
        root = {"exchange": mapping(before | {"unselected": padding} | payload)}
        return mapping(root)

    def checkpoint(name, selected, pack_float=packer.pack):
        return save(name, source_data(selected, pack_float))

    def reference(name, values, claimed=None):
        tree_rows = sorted(values.items())
        tree_rows = [[slot, child] for slot, child in tree_rows]
        digest = tree.digest(executable, tree.decode_tree(tree_rows)) if claimed is None else claimed
        return save(name, json.dumps({"height": height, "abci_digest": digest,
                                      "exchange_abci_hash": tree_rows}).encode())

    source = checkpoint("exchange.rmp", fields)
    original = source[0].read_bytes()
    marker = packer.pack(-0.0)
    assert original.index(marker) % CHUNK_BYTES == CHUNK_BYTES - 1
    stream = CountedBytes(original)
    projection, counted = project(kit["rmp"], stream, source[1])
    projection_fields = msgpack.unpackb(projection)["exchange"]
    assert set(projection_fields) == set(FIELDS) | {"locus"}
    assert marker in projection and projection_fields["locus"] == fields["locus"]
    assert stream.quantity == counted == len(original) and len(projection) < 2000

    exact = reference("exchange.json", rows)
    changed = reference("changed.json", rows | {20: rows[20][::-1], 45: leaf(struct.pack("<qI", 4, 0))})
    for expected_reference, expected_match in ((exact, True), (changed, False)):
        original_result = report(folder, executable, height, *source, *expected_reference)
        projected_result = compare_once(folder, executable, height, *source, *expected_reference)
        assert projected_result["checkpoint_bytes_read"] == len(original)
        assert projected_result["projection_byte_count"] == len(projection)
        assert projected_result["projection_sha256"] == hashlib.sha256(projection).hexdigest()
        comparable = {k: v for k, v in projected_result.items() if k in original_result}
        assert comparable == original_result
        assert projected_result["all_scoped_groups_match"] is expected_match

    def cli(src, ref):
        return subprocess.run(
            [sys.executable, "-B", Path(__file__).with_name("compare_once.py"), folder, executable,
             str(height), *src, *ref], check=False, capture_output=True,
        )

    good = cli(source, exact)
    assert good.returncode == 0 and json.loads(good.stdout)["scoped_slot_count"] == 22
    assert cli(source, changed).returncode == 1

    float32 = msgpack.Packer(use_single_float=True).pack
    stale = reference("stale.json", rows, claimed=leaf(b"stale"))
    invalid = ((source, stale, b"stated raw ABCI digest"),
               ((source[0], "0" * 64), exact, b"SHA-256"),
               (checkpoint("float32.rmp", fields, float32), exact, b"binary64"),
               (checkpoint("wrong-height.rmp", fields | {"locus": {"ctx": {"height": height + 1}}}),
                exact, b"Context height"),
               (checkpoint("too-large.rmp", fields | {"pmn": bytes(MAX_FIELD_BYTES)}), exact, b"field exceeds"),
               (save("trailing.rmp", original + b"\xc0"), exact, b"trailing bytes"))
    for item, ref, message in invalid:
        rejected = cli(item, ref)
        assert rejected.returncode == 2 and not rejected.stdout and message in rejected.stderr, rejected.stderr
    print(f"PASS: original {counted} bytes read once; byte-exact selected projection {len(projection)} bytes")
    print("PASS: well-formed cases preserve all 22-slot report results including two mismatched groups")
    print("PASS: binary64 spanning a read boundary preserved; binary32, wrong heights/pins, stale roots rejected")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helpers", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    args = parser.parse_args()
    with TemporaryDirectory() as directory:
        controls(args.helpers, args.rustc, Path(directory))
