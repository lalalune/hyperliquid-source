"""Project a pinned node #115 LtHash JSON sidecar into cache record bytes."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

LANES = ("accounts_hash", "contracts_hash", "storage_hash")
HASH_BYTES = 0x800
U64_MAX = (1 << 64) - 1


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"not a JSON constant: {value}")


def u64(value, field):
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    return value


def project(raw, expected_sha256):
    """Return the three native cache records in account, contract, storage order."""
    if sha256(raw).hexdigest() != expected_sha256.lower():
        raise ValueError("sidecar SHA-256 does not match")
    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                     parse_constant=reject_constant)
    if not isinstance(obj, dict) or set(obj) != set(LANES):
        raise ValueError("expected all three named LtHash records")
    records = {}
    for lane in LANES:
        row = obj[lane]
        if not isinstance(row, dict) or set(row) != {"hash", "n_elements", "n_bytes"}:
            raise ValueError(f"{lane} has an unsupported record shape")
        values = row["hash"]
        if not isinstance(values, list) or len(values) != HASH_BYTES:
            raise ValueError(f"{lane}.hash must contain exactly {HASH_BYTES} bytes")
        if any(type(value) is not int or not 0 <= value <= 255 for value in values):
            raise ValueError(f"{lane}.hash contains a value outside unsigned byte range")
        n_elements = u64(row["n_elements"], f"{lane}.n_elements")
        n_bytes = u64(row["n_bytes"], f"{lane}.n_bytes")
        records[lane] = bytes(values) + struct.pack("<QQ", n_elements, n_bytes)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sidecar", type=Path)
    parser.add_argument("--sha256", required=True, help="expected file SHA-256")
    args = parser.parse_args()
    try:
        records = project(args.sidecar.read_bytes(), args.sha256)
    except (OSError, ValueError) as error:
        parser.exit(1, f"LtHash cache unavailable for this offline check: {error}\n")
    summary = {}
    for name, record in records.items():
        n_elements, n_bytes = struct.unpack_from("<QQ", record, HASH_BYTES)
        summary[name] = {
            "n_elements": n_elements,
            "n_bytes": n_bytes,
            "layout_bytes": len(record),
            "layout_sha256": sha256(record).hexdigest(),
        }
    print(json.dumps({"sidecar_sha256": args.sha256.lower(), "records": summary}, indent=2))


if __name__ == "__main__":
    main()
