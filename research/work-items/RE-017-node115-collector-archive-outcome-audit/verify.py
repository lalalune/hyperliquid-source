"""Verify the result-prefix comparison and optionally rebuild its observations."""

from argparse import ArgumentParser
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from audit import compare_prefix, dump, existing_comparator, load, require

PACKET = Path(__file__).resolve().parent
ALIGNMENT = "e83abddbed3bb133d04f0736120dfd0a2a11c6f5"
COLLECTOR = "1cc98eb2cdbe1479ad9d2e7070ce51fe042d61e1"
COMPARATOR_PATH = "research/work-items/RE-017-node115-replica-full-response-alignment/compare.py"
COLLECTOR_PACKET = "research/work-items/RE-017-node115-replica-result-prefix"


def blob(repo, commit, path):
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo)


def rebuild_observation(repo, scratch):
    crate = "src/node115-replica-response-json"
    for name in ("Cargo.toml", "src/lib.rs", "src/collector.rs"):
        path = scratch / crate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob(repo, COLLECTOR, f"{crate}/{name}"))
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text(f"""
[package]
name = "offline-collector-archive-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-replica-response-json = {{ path = "{crate}" }}

[[bin]]
name = "offline-collector-archive-probe"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    output = subprocess.check_output(["cargo", "run", "--locked", "--offline", "--quiet"], cwd=scratch)
    require(load(output) == load((PACKET / "observation.json").read_bytes()), "fresh collector output differs")
    print(f"reproduced collector snapshot {COLLECTOR}")
    print(output.decode().strip())


def verify_native(repo, scratch):
    packet = scratch / "static"
    packet.mkdir()
    for name in ("verify.py", "anchors.tsv"):
        (packet / name).write_bytes(blob(repo, COLLECTOR, f"{COLLECTOR_PACKET}/{name}"))
    subprocess.run(["python3", "-B", str(packet / "verify.py"), "--repo", str(repo)], check=True)


def verify_fixture(scratch, compare):
    manifest = PACKET / "fixture.json"
    standard = compare_prefix(manifest, compare)
    require(standard["coverage"] == "partial" and standard["differences"] == [], "unexpected partial result")
    missing_key = "0x" + "aa" * 32
    require(standard["missing"] == [missing_key] and standard["stop_position"] == 2
            and [row["source_ordinal"] for row in standard["observed"]] == [4, 7],
            "wrong missing group or retained source metadata")
    print(json.dumps(standard))

    archived = (PACKET / "archive.jsonl").read_bytes()
    recorded = load((PACKET / "observation.json").read_bytes())
    altered = scratch / "altered"
    altered.mkdir()
    (altered / "archive.jsonl").write_bytes(archived)

    def rewritten(observation, repin=True):
        raw = (dump(observation) + "\n").encode()
        meta = load(manifest.read_bytes())
        if repin:
            meta["observation"]["sha256"] = hashlib.sha256(raw).hexdigest()
        (altered / "observation.json").write_bytes(raw)
        target = altered / "fixture.json"
        target.write_text(json.dumps(meta))
        return target

    different = deepcopy(recorded)
    different["resps"]["Full"][0][1][0]["res"]["response"]["quantity"] = Decimal(
        "0.1234567890123456789012345679"
    )
    result = compare_prefix(rewritten(different), compare)
    require(result["differences"] == [{
        "bundle": "0x" + "cc" * 32, "source_ordinal": 4, "action_index": 0, "fields": ["response"],
    }], "exact decimal difference or source index lost")
    print(json.dumps(result))

    empty = {**recorded, "ordinals": [], "stop_position": 0, "resps": {"Full": []}}
    result = compare_prefix(rewritten(empty), compare)
    require(result["coverage"] == "none" and len(result["missing"]) == 3, "empty observation claimed coverage")
    complete = {**recorded, "ordinals": [4, 7, 11], "stop_position": None,
                "resps": {"Full": [*recorded["resps"]["Full"], load(archived)["resps"]["Full"][0]]}}
    result = compare_prefix(rewritten(complete), compare)
    require(result["coverage"] == "complete" and not result["missing"] and not result["differences"],
            "full coverage disagrees with #7345 baseline")

    for observation, repin, expected_error in (
        (different, False, "wrong artifact SHA-256"),
        ({**recorded, "height": 42}, True, "observation height H+1"),
        ({**recorded, "ordinals": [4], "stop_position": 1}, True, "metadata count differs"),
    ):
        try:
            compare_prefix(rewritten(observation, repin), compare)
        except ValueError as error:
            require(expected_error in str(error), str(error))
        else:
            raise ValueError(f"unrejected case {expected_error}")
    print("verified empty, partial and complete coverage, exact decimals, expected H+1 and artifact pins")


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--compile-collector", action="store_true")
    args = parser.parse_args()
    with TemporaryDirectory() as temporary:
        scratch = Path(temporary)
        comparator = scratch / "compare.py"
        comparator.write_bytes(blob(args.repo, ALIGNMENT, COMPARATOR_PATH))
        verify_native(args.repo, scratch)
        if args.compile_collector:
            rebuild_observation(args.repo, scratch)
        verify_fixture(scratch, existing_comparator(comparator))
