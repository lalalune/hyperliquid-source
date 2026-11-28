"""Compare first-replay prepared group lengths against an archived replica row."""

from argparse import ArgumentParser
from dataclasses import asdict, dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class GroupMismatch:
    bundle_index: int
    archived_actions: int
    prepared_items: int


def _unique_pairs(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate JSON key: {key}")
        record[key] = value
    return record


def _invalid_constant(value):
    raise ValueError(f"{value} is outside JSON")


def _array(value, label):
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def compare_prepared_shape(archive_line: bytes, prepared_counts: list[int]) -> tuple[GroupMismatch, ...]:
    """Return positional count differences after checking the outer length."""
    row = json.loads(archive_line.decode("utf-8"), object_pairs_hook=_unique_pairs,
                     parse_constant=_invalid_constant)
    if not isinstance(row, dict) or not isinstance(row.get("abci_block"), dict):
        raise ValueError("archive row must contain an abci_block object")
    bundles = _array(row["abci_block"].get("signed_action_bundles"), "signed_action_bundles")
    if not isinstance(prepared_counts, list) or any(
        type(count) is not int or not 0 <= count < 2**64 for count in prepared_counts
    ):
        raise ValueError("prepared count vector must contain unsigned 64-bit lengths")
    if len(bundles) != len(prepared_counts):
        raise ValueError(f"outer bundle count: archive {len(bundles)}, prepared {len(prepared_counts)}")

    differences = []
    for index, (bundle, prepared) in enumerate(zip(bundles, prepared_counts)):
        if not isinstance(bundle, list) or len(bundle) != 2 or not isinstance(bundle[1], dict):
            raise ValueError(f"archive bundle {index} must contain a key and payload object")
        signed = len(_array(bundle[1].get("signed_actions"), f"bundle {index} signed_actions"))
        if signed != prepared:
            differences.append(GroupMismatch(index, signed, prepared))
    return tuple(differences)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("archive_line", type=Path)
    parser.add_argument("prepared_counts", type=Path, help="JSON array of observed lengths in bundle order")
    args = parser.parse_args()
    try:
        counts = json.loads(args.prepared_counts.read_text(encoding="utf-8"))
        result = compare_prepared_shape(args.archive_line.read_bytes(), counts)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps([asdict(item) for item in result], sort_keys=True))
    return 2 if result else 0


if __name__ == "__main__":
    raise SystemExit(main())
