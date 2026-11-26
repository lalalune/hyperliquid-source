"""Compare the two node #115 log projections at one explicitly requested height."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

U64_MAX = (1 << 64) - 1
DIGEST = re.compile(r"0x[0-9a-f]{64}")


def unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError(f"duplicate JSON key {key!r}")
        fields[key] = value
    return fields


def invalid_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


def digest_at(path, file_sha256, wanted, field):
    checksum = hashlib.sha256()
    found = set()
    keys = {"height", field} if field == "d" else {"height", field, "exchange_abci_hash"}
    with path.open("rb") as stream:
        for number, line in enumerate(stream, 1):
            checksum.update(line)
            try:
                record = json.loads(line.decode("utf-8"), object_pairs_hook=unique_fields,
                                    parse_constant=invalid_constant)
                if not isinstance(record, dict) or record.keys() != keys:
                    raise ValueError("unexpected fields for this writer")
                height, digest = record["height"], record[field]
                if type(height) is not int or not 0 <= height <= U64_MAX:
                    raise ValueError("invalid u64 height")
                if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                    raise ValueError(f"invalid {field} digest")
                if not line.endswith(b"\n"):
                    raise ValueError("incomplete JSON line")
                if height == wanted:
                    found.add(digest)
            except ValueError as error:
                raise ValueError(f"{path}:{number}: {error}") from error
    if checksum.hexdigest() != file_sha256:
        raise ValueError(f"{path}: SHA-256 differs from the supplied commitment")
    if len(found) != 1:
        reason = "missing" if not found else "conflicting"
        raise ValueError(f"{path}: {reason} {field} at height {wanted}")
    return found.pop()


def compare(checkpoint_height, witness, witness_sha256, local, local_sha256):
    if type(checkpoint_height) is not int or not 0 <= checkpoint_height < U64_MAX:
        raise ValueError("checkpoint height must have a u64 successor")
    if witness.samefile(local):
        raise ValueError("the two inputs name the same file")
    wanted = checkpoint_height + 1
    expected = digest_at(witness, witness_sha256, wanted, "d")
    observed = digest_at(local, local_sha256, wanted, "abci_digest")
    return {"height": wanted, "expected": expected, "observed": observed,
            "comparison": "equal" if expected == observed else "mismatch"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkpoint_height", type=int)
    for role in ("witness", "local"):
        parser.add_argument(role, type=Path)
        parser.add_argument(role + "_sha256")
    args = parser.parse_args()
    try:
        result = compare(**vars(args))
    except (OSError, ValueError) as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(result))
    return int(result["comparison"] != "equal")


if __name__ == "__main__":
    sys.exit(main())
