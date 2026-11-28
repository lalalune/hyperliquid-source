"""Build and run the empty replay Block fixture using pinned source snapshots."""

from argparse import ArgumentParser
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

PACKET = Path(__file__).resolve().parent
ENGINE = "419d40ecefa51bc56ee2d1510579b3cc20b47910"
DECODER = "e86354ccddec0b517ac5d239280d70adf520f355"
FIELD_MAP = "cde73d29ee210e19d96278eaa191103e9e6e22b8"
STATIC_PACKET = "research/work-items/RE-017-node115-replica-replay-header"
ENGINE_DIRS = [
    "abci", "abci-blake3", "abci-checkpoint-replay-fixture", "block-handle-codec",
    "chain-name-codec", "checkpoint-discovery", "db", "db-hub-byte-key",
    "digest-reference-handoff", "digest-support-gate", "digest-vote-admission",
    "indexed-artifact-variant", "owned-db-open", "replica-end-height",
    "reverse-path-components", "staking-weight-comparison", "startup-admission",
    "storage-value-decode",
]
DECODER_DIRS = [
    "replay-completed-payload", "client-block-success", "lz4-decode", "lz4-literal-encoder",
    "daycount-date", "gossip-response-record", "signed-scalar", "u32-varint",
]
IMPORTED_READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def export(repo, target, commit, *prefixes):
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", "-z", commit, *prefixes], cwd=repo
    ).decode().split("\0")
    for raw in filter(None, paths):
        path = Path(raw)
        require(not path.is_absolute() and ".." not in path.parts, "unexpected git tree path")
        require(path.parts[0] == "src" or raw == IMPORTED_READER or
                raw.startswith(STATIC_PACKET + "/"), "unexpected source namespace")
        dest = target / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(subprocess.check_output(["git", "show", f"{commit}:{raw}"], cwd=repo))


def build(repo, scratch):
    export(repo, scratch, ENGINE, *(f"src/node115-{name}" for name in ENGINE_DIRS))
    export(repo, scratch, DECODER, IMPORTED_READER,
           *(f"src/node115-{name}" for name in DECODER_DIRS))
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "node115-empty-block-pipeline-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-abci = { path = "src/node115-abci" }
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }

[[bin]]
name = "node115-empty-block-pipeline-probe"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)


def verify(repo, scratch):
    wire = PACKET / "wire.bin"
    archived = PACKET / "archive.jsonl"
    for path, expected in (
        (wire, "c82da12e8e06005294f523dd05c8765aad3a752b967771d14b2b1ab7a997b2cc"),
        (archived, "116a189e50f0029372154203e6b205fa1c71cc47014e63ea3a2ff9b6989fb20b"),
    ):
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
        require(expected == observed, f"wrong {path.name} SHA-256")
        print(f"{observed}  {path.name}")
    archive = json.loads(archived.read_bytes())
    require(archive["height"] == 43 and archive["abci_block"]["parent_round"] == 40
            and archive["abci_block"]["round"] == 41, "wrong archive coordinates")
    require(archive["abci_block"]["hardfork"] == {"version": 5, "round": 40},
            "unexpected archive hardfork")
    groups = archive["abci_block"]["signed_action_bundles"]
    require(groups == [], "expected an independently empty archive fixture")
    export(repo, scratch, FIELD_MAP, STATIC_PACKET)
    subprocess.run(["python3", "-B", str(scratch / STATIC_PACKET / "verify.py"),
                    "--repo", str(repo)], check=True)
    print(f"compile reconstructed ABCI {ENGINE} and replay decoder {DECODER} offline")
    build(repo, scratch)
    checkpoints = scratch / "checkpoint"
    candidate = checkpoints / "42"
    candidate.mkdir(parents=True)
    (candidate / "CHECKPOINT_COMPLETE").write_bytes(b"")
    subprocess.run(["cargo", "run", "--locked", "--offline", "--quiet", "--", str(wire),
                    str(checkpoints), str(len(groups))], cwd=scratch, check=True)


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    with TemporaryDirectory() as scratch:
        verify(args.repo.resolve(), Path(scratch))
