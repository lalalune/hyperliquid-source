"""Select adjacent native replica rows from whole-file-pinned JSONL shards."""

from argparse import ArgumentParser
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re

MAX_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class Row:
    height: int
    shard: str
    shard_sha256: str
    line: int
    offset: int
    row_sha256: str
    raw: str


def unsigned(value):
    return type(value) is int and 0 <= value <= MAX_U64


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key}")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError(f"invalid JSON constant {value}")


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def rows_in_shard(root, path, sha256, heights):
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ValueError(f"{path}: expected a lowercase SHA-256")
    digest = hashlib.sha256()
    rows = []
    offset = 0
    with (root / path).open("rb") as stream:
        for number, raw in enumerate(stream, 1):
            digest.update(raw)
            if not raw.endswith(b"\n"):
                raise ValueError(f"{path} line {number}: incomplete native row")
            try:
                line = raw.decode("utf-8")
                event = parse_json(line)
                if not isinstance(event, dict) or not unsigned(event.get("height")):
                    raise ValueError("expected explicit native height")
                if "resps" not in event or not isinstance(event.get("abci_block"), dict):
                    raise ValueError("expected replica block and response")
                height = event["height"]
                block = event["abci_block"]
                if not unsigned(block.get("round")) or not unsigned(block.get("parent_round")):
                    raise ValueError("expected separate unsigned round values")
                if not isinstance(block.get("signed_action_bundles"), list):
                    raise ValueError("expected signed action bundle array")
            except ValueError as error:
                raise ValueError(f"{path} line {number}: {error}") from error
            if height in heights:
                rows.append(Row(height, path, sha256, number, offset, hashlib.sha256(raw).hexdigest(), line))
            offset += len(raw)
    if digest.hexdigest() != sha256:
        raise ValueError(f"{path}: shard SHA-256 mismatch")
    return rows


def select_pair(root, shards, height):
    """Return the two exact heights with source rows, independent of filename order."""
    if not unsigned(height) or height == MAX_U64:
        raise ValueError("invalid checkpoint height for an adjacent pair")
    if not isinstance(shards, list):
        raise ValueError("expected shard records")
    targets = (height, height + 1)
    matched = {}
    used = set()
    for shard in shards:
        if not isinstance(shard, dict) or set(shard) != {"path", "sha256"}:
            raise ValueError("each shard needs a path and SHA-256")
        path = shard["path"]
        if not isinstance(path, str) or not path or path in used:
            raise ValueError(f"missing or repeated shard path {path!r}")
        used.add(path)
        for row in rows_in_shard(root, path, shard["sha256"], targets):
            previous = matched.get(row.height)
            if previous is not None:
                raise ValueError(f"height {row.height} is ambiguous at {previous.shard}:{previous.line} and {row.shard}:{row.line}")
            matched[row.height] = row
    missing = [str(target) for target in targets if target not in matched]
    if missing:
        raise ValueError("missing native height " + ", ".join(missing))
    return tuple(matched[target] for target in targets)


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="local JSON list of file paths and decompressed SHA-256")
    parser.add_argument("checkpoint_height", type=int)
    args = parser.parse_args()
    try:
        manifest = parse_json(args.manifest.read_text(encoding="utf-8"))
        rows = select_pair(args.manifest.parent, manifest, args.checkpoint_height)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps([asdict(row) for row in rows], ensure_ascii=True))


if __name__ == "__main__":
    main()
