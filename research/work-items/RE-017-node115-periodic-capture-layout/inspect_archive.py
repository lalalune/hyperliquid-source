"""Inspect a local node #115 periodic snapshot and its separate status marker."""

import argparse
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import stat


def metadata(path):
    try:
        return path.stat()
    except FileNotFoundError:
        return None


def layout(root, day, height):
    if len(day) != 8 or not day.isascii() or not day.isdecimal():
        raise ValueError("snapshot date must be YYYYMMDD")
    date(int(day[:4]), int(day[4:6]), int(day[6:]))
    if not 0 <= height < 1 << 64:
        raise ValueError("snapshot height must fit in u64")
    return (
        root / "data" / "periodic_abci_states" / day / f"{height}.rmp",
        root / "data" / "periodic_abci_state_statuses" / day / str(height),
        root / "hyperliquid_data" / "abci_state.rmp",
    )


def inspect(root, day, height, expected_sha256):
    snapshot, status, rolling = layout(root, day, height)
    with os.fdopen(os.open(snapshot, os.O_RDONLY | os.O_NONBLOCK), "rb") as source:
        snapshot_stat = os.fstat(source.fileno())
        if not stat.S_ISREG(snapshot_stat.st_mode):
            raise ValueError("periodic snapshot must be a regular file")
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError("periodic snapshot SHA-256 does not match")

    marker = metadata(status)
    if marker is None:
        marker_kind = "absent"
    elif not stat.S_ISREG(marker.st_mode):
        marker_kind = "nonregular"
    elif marker.st_size == 0:
        marker_kind = "empty_regular_file"
    else:
        marker_kind = "nonempty_regular_file"

    current = metadata(rolling)
    if current is None:
        rolling_relation = "absent"
    elif not stat.S_ISREG(current.st_mode):
        rolling_relation = "nonregular"
    elif os.path.samestat(snapshot_stat, current):
        rolling_relation = "same_opened_file_identity"
    else:
        rolling_relation = "different_file_identity"

    return {
        "height": height,
        "capture_date": day,
        "snapshot": str(snapshot.relative_to(root)),
        "snapshot_sha256": actual_sha256,
        "status": str(status.relative_to(root)),
        "status_marker": marker_kind,
        "rolling": str(rolling.relative_to(root)),
        "rolling_relation": rolling_relation,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("date")
    parser.add_argument("height", type=int)
    parser.add_argument("--sha256", required=True, help="expected periodic .rmp SHA-256")
    args = parser.parse_args()
    try:
        result = inspect(args.root, args.date, args.height, args.sha256)
    except (OSError, ValueError) as error:
        parser.exit(1, f"periodic capture unavailable for this check: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
