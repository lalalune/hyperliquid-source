#!/usr/bin/env python3
"""Read-only receipt inspection. Never executes or extracts archive members.

The surrounding public manifest authenticates this helper and index. This
helper checks the archive against that index, not target semantics or approval.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def load_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def inspect(index_path, archive_path):
    require(index_path.stat().st_size <= 4 << 20, "index size cap")
    require(archive_path.stat().st_size <= 64 << 20, "archive stored size cap")
    index = load_json(index_path.read_bytes())
    packed = archive_path.read_bytes()
    require(identity(packed) == index["archive"]["stored"], "archive stored identity")
    # Bounded in-memory reading only; never extract to the filesystem.
    require(len(packed) <= 64 << 20, "archive stored size cap")
    with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
        raw = stream.read((64 << 20) + 1)
    require(len(raw) <= 64 << 20, "archive uncompressed size cap")
    require(identity(raw) == index["archive"]["tar"], "tar identity")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for item in archive:
            path = PurePosixPath(item.name)
            require(item.type == tarfile.REGTYPE, "regular members only")
            require(not path.is_absolute() and ".." not in path.parts and str(path) == item.name, "member path")
            require(item.name not in members, "duplicate member")
            require((item.uid, item.gid, item.uname, item.gname, item.mtime, item.mode) == (0, 0, "", "", 0, 0o644), "deterministic member metadata")
            require(item.name in index["members"], "unindexed member")
            handle = archive.extractfile(item)
            require(handle is not None, "member reader")
            body = handle.read()
            expected = index["members"][item.name]
            require(identity(body) == {k: expected[k] for k in ["bytes", "sha256"]}, "member identity")
            members[item.name] = body
    require(set(members) == set(index["members"]), "complete member set")
    references = 0
    for name, run in index["runs"].items():
        for original, reference in run["metadata"].items():
            require(identity(members[reference["member"]]) == {k: reference[k] for k in ["bytes", "sha256"]}, "original metadata identity: " + original)
        commands = load_json(members[run["metadata"]["receipts/commands.json"]["member"]])
        require(len(commands) == run["command_count"], "command count: " + name)
        used = set()
        for command in commands:
            for stream in ["stdout", "stderr"]:
                reference = command[stream]
                mapped = run["rawref_map"][reference["gzip_ref"]]
                require(reference["bytes"] == mapped["raw"]["bytes"] and reference["sha256"] == mapped["raw"]["sha256"], "raw reference identity")
                packed_raw = members[mapped["member"]]
                require(identity(packed_raw) == mapped["stored"], "raw gzip identity")
                with gzip.GzipFile(fileobj=io.BytesIO(packed_raw)) as source:
                    body = source.read((16 << 20) + 1)
                require(len(body) <= 16 << 20 and identity(body) == mapped["raw"], "raw stream identity")
                references += 1
                used.add(reference["gzip_ref"])
        require(used == set(run["rawref_map"]), "unreferenced/missing raw mapping")
        require(len(commands) * 2 == run["raw_reference_count"], "per-run reference count")
    require(references == index["counts"]["command_raw_references"], "total raw references")
    return index, members


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=Path(__file__).with_name("BUNDLE-INDEX.json"))
    parser.add_argument("--archive", type=Path, default=Path(__file__).with_name("receipts.tar.gz"))
    parser.add_argument("--list", action="store_true", help="Verify, then list member names.")
    parser.add_argument("--show", metavar="MEMBER", help="Verify, then emit that member's exact stored bytes.")
    args = parser.parse_args()
    index, members = inspect(args.index, args.archive)
    if args.show is not None:
        require(args.show in members, "show requires an exact indexed member")
        sys.stdout.buffer.write(members[args.show])
    elif args.list:
        print("\n".join(sorted(members)))
    else:
        print(json.dumps({"status": "PASS indexed receipt bytes", "members": len(members), "command_raw_references": index["counts"]["command_raw_references"], "executes_contained_code": False, "extracts_files": False}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
