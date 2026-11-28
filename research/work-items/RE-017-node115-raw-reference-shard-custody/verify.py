"""Check source-byte identity and the existing adjacent Context reader."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from select_exports import digest, require, select, write_bundle

WIRE_CASE = "1cde76593a51988264643cf60747e48e493339a5"
WIRE_PACKET = "RE-017-node115-wire-adjacent-context-fixture"


def write(folder, name, raw):
    path = folder / name
    path.write_bytes(raw)
    return {"path": name, "sha256": digest(raw)}


def write_json(folder, name, row):
    return write(folder, name, (json.dumps(row) + "\n").encode())


def verify(repo, scratch):
    subprocess.run([sys.executable, "-B", "tools/abci_hashes_log_115.py", "--check"], cwd=repo, check=True)
    source = scratch / "existing-case"
    source.mkdir()
    for name in ("verify.py", "wire_case.py", "archive.jsonl", "wire.bin"):
        data = subprocess.check_output(["git", "show",
            f"{WIRE_CASE}:research/work-items/{WIRE_PACKET}/{name}"], cwd=repo)
        (source / name).write_bytes(data)
    sys.path.insert(0, str(source))
    spec = spec_from_file_location("existing_context_toolkit", source / "verify.py")
    runner = module_from_spec(spec)
    spec.loader.exec_module(runner)
    kit, compare_case, hash_bytes, helper = runner.toolkit(repo, scratch)
    base = runner.fixture(scratch, kit, helper, hash_bytes)
    raw_h = b"  " + (scratch / base["reference_h"]["path"]).read_bytes()
    raw_h1 = b"\t" + (scratch / base["reference_h_plus_one"]["path"]).read_bytes()
    neighbor = (json.dumps({"height": 44, "abci_digest": "0x" + "20" * 32,
                "exchange_abci_hash": "0x" + "21" * 32}) + "\n").encode()
    shard_h = write(scratch, "raw-export-a.jsonl", neighbor + raw_h)
    shard_h1 = write(scratch, "raw-export-b.jsonl", raw_h1 + neighbor)

    def selection(label, sources):
        manifest = write_json(scratch, f"{label}.json", {"height": 42, "shards": sources})
        return select(scratch / manifest["path"], manifest["sha256"])

    height, rows = selection("selected-reverse-file-order", [shard_h1, shard_h])
    output = scratch / "exact-rows"
    report = write_bundle(output, height, rows)
    for field, raw in (("reference_h", raw_h), ("reference_h_plus_one", raw_h1)):
        file = report["reference_files"][field]
        coordinate = report["source_coordinates"][field]
        require((output / file["path"]).read_bytes() == raw and file["sha256"] == digest(raw),
                "writer no longer uses original capture line")
        original = (scratch / coordinate["source_path"]).read_bytes()
        start = coordinate["byte_offset"]
        require(original[start:start+coordinate["byte_length"]] == raw, "wrong physical source range")
    print(json.dumps(report))
    header = write_json(output, "header.json", {"height": 43, "round": 41,
                "time": {"unix_seconds": 0, "subsec_nanos": 120_000_000}})
    case = write_json(output, "case.json", {
        "height": 42, "checkpoint_rmp": base["checkpoint_rmp"] | {
            "path": str(scratch / base["checkpoint_rmp"]["path"]),
        },
        "successor_header": header, **report["reference_files"],
    })
    compared = compare_case(output / case["path"], case["sha256"], kit, helper)
    require(compared["selected_checks_pass"], "original export bytes did not pass selected Context comparison")
    print(json.dumps(compared))

    modified_tail = write(scratch, "different-tail.jsonl", raw_h1 + b" " + neighbor)
    digest_only = write(scratch, "digest-only.jsonl", (json.dumps({
        "height": 43, "abci_digest": "0x" + "14" * 32,
    }) + "\n").encode())
    repeated = write(scratch, "repeated-target.jsonl", raw_h1)
    for label, sources, expected in (
        ("duplicate", [shard_h, shard_h1, repeated], "ambiguous raw reference height 43"),
        ("wrong-suffix", [shard_h, modified_tail | {"sha256": shard_h1["sha256"]}], "wrong complete shard SHA-256"),
        ("scalar-only", [shard_h, digest_only], "expected one complete abci_hashes row"),
        ("missing", [shard_h], "raw reference heights absent: [43]"),
    ):
        try:
            selection(label, sources)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified H/H+1 source intervals and pins, unchanged full trees, and downstream selected checks")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    with TemporaryDirectory() as folder:
        verify(args.repo.resolve(), Path(folder))
