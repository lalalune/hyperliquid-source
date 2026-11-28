"""Run pinned Exchange parity checks after one scan of the original checkpoint."""

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import ModuleType

CHUNK_BYTES = 64 * 1024
MAX_FIELD_BYTES = 256 * 1024

SOURCES = {
    "rmp": ("RE-009-node115-msgpack-context-projection/project.py",
            "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "report": ("RE-009-node115-rmp-exchange-parity-report/report.py",
               "4a492dae817d6406287f6a1944985cc702db3792fd6dc3477383be94a18f535e"),
}
FIELDS = (
    "spot_disabled", "prune_agent_idx", "evm_enabled", "hip3_no_cross", "dex_abstraction_enabled", "pmn",
    "funding_distribute_guard", "funding_update_guard", "cancel_aggressive_orders_at_open_interest_cap_guard",
    "book_empty_user_states_pruning_guard", "begin_block_logic_guard", "hip3_stale_mark_px_guard",
    "last_hlp_cancel_time", "post_only_until_time", "lvt",
    "max_order_distance_from_anchor", "scheduled_freeze_height", "post_only_until_height",
    "max_hlp_withdraw_fraction_per_day", "hlp_start_of_day_account_value", "pvs", "initial_usdc_evm_system_balance",
)


def load_helpers(folder):
    modules = {}
    for name, (relative, expected) in SOURCES.items():
        path = folder / relative
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f"source pin mismatch for {relative}")
        module = ModuleType(f"node115_single_pass_{name}")
        exec(compile(raw, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


class RecentBytes:
    """Retain the tail needed for selected item bytes while hashing the source."""

    def __init__(self, stream):
        self.stream = stream
        self.count = 0
        self.digest = hashlib.sha256()
        self.chunks = deque()

    def read(self, size):
        data = self.stream.read(size)
        if data:
            self.chunks.append((self.count, data))
            self.count += len(data)
            self.digest.update(data)
            floor = self.count - MAX_FIELD_BYTES - CHUNK_BYTES
            while self.chunks and self.chunks[0][0] + len(self.chunks[0][1]) <= floor:
                self.chunks.popleft()
        return data

    def span(self, start, end):
        length = end - start
        if length > MAX_FIELD_BYTES:
            raise ValueError(f"selected MessagePack field exceeds {MAX_FIELD_BYTES} bytes")
        data = b"".join(chunk[max(start - offset, 0):end - offset]
                        for offset, chunk in self.chunks if offset < end and offset + len(chunk) > start)
        if len(data) != length:
            raise ValueError("selected MessagePack bytes lost from read window")
        return data


def project(rmp, stream, checkpoint_pin):
    import msgpack

    reader = RecentBytes(stream)
    unpacker = msgpack.Unpacker(reader, read_size=CHUNK_BYTES, raw=False)

    def capture(value):
        start = value.tell()
        value.skip()
        return reader.span(start, value.tell())

    def exchange(obj):
        return rmp.select(obj, {
            **dict.fromkeys(FIELDS, capture),
            "locus": lambda loc: rmp.require(loc, "ctx", lambda ctx: rmp.require(ctx, "height", capture)),
        })

    try:
        fields = rmp.require(unpacker, "exchange", exchange)
    except msgpack.OutOfData as error:
        raise ValueError("incomplete named checkpoint object") from error
    consumed = unpacker.tell()
    while reader.read(CHUNK_BYTES):
        pass
    if reader.digest.hexdigest() != checkpoint_pin:
        raise ValueError("checkpoint SHA-256 mismatch")
    if consumed != reader.count:
        raise ValueError("trailing bytes after checkpoint object")
    if "locus" not in fields:
        raise ValueError("missing checkpoint Context height")
    height = fields.pop("locus")
    packer = msgpack.Packer(use_bin_type=True)

    def mapping(rows):
        return packer.pack_map_header(len(rows)) + b"".join(packer.pack(key) + value for key, value in rows.items())

    fields["locus"] = mapping({"ctx": mapping({"height": height})})
    return mapping({"exchange": mapping(fields)}), reader.count


def compare_once(folder, executable, height, checkpoint, checkpoint_pin, reference, reference_pin):
    kit = load_helpers(folder)
    with checkpoint.open("rb") as stream:
        projection, source_count = project(kit["rmp"], stream, checkpoint_pin)
    projection_hash = hashlib.sha256(projection).hexdigest()
    with TemporaryDirectory() as directory:
        path = Path(directory) / "named-projection.rmp"
        path.write_bytes(projection)
        result = kit["report"].report(folder, executable, height, path, projection_hash, reference, reference_pin)
    result["checkpoint_sha256"] = checkpoint_pin
    result["checkpoint_bytes_read"] = source_count
    result["projection_sha256"] = projection_hash
    result["projection_byte_count"] = len(projection)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("driver", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    args = parser.parse_args()
    try:
        result = compare_once(args.helpers, args.driver, args.height, args.checkpoint,
                              args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["all_scoped_groups_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
