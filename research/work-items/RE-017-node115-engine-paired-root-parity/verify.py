"""Compare real Rust fixture engine roots with independently pinned synthetic references."""

from argparse import ArgumentParser
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from blake3 import blake3

PACKET = Path(__file__).resolve().parent
BASE = "2da45cb0a761cff6b478e40421699857d87a94df"
H = "729f9e30a260e54122cd4da579cdbf9c16de0491"
H1 = "a55c6d0bdbcb08b8dde8ac3121772b1e2d27ac53"
CAPTURE = "f87825aee4afe52323d416e3a0df087bb064eb9c"
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"
CRATES = (
    "abci", "abci-blake3", "abci-checkpoint-replay-fixture", "block-handle-codec",
    "checkpoint-discovery", "db", "db-hub-byte-key", "digest-reference-handoff",
    "digest-support-gate", "digest-vote-admission", "indexed-artifact-variant", "owned-db-open",
    "replica-end-height", "reverse-path-components", "staking-weight-comparison", "startup-admission",
    "storage-value-decode", "client-block-success", "daycount-date", "gossip-response-record",
    "signed-scalar", "u32-varint",
)
DIGEST = re.compile(r"0x[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(repo, commit, path):
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo)


def native(repo, scratch):
    for commit, item in (
        (H, "RE-009-node115-restored-root"), (H1, "RE-017-node115-deferred-successor-root"),
        (CAPTURE, "RE-009-node115-top-level-root-capture"),
    ):
        path = scratch / f"{item}.py"
        path.write_bytes(git_blob(repo, commit, f"research/work-items/{item}/verify.py"))
        subprocess.run([sys.executable, "-B", path], cwd=repo, check=True)
    subprocess.run([sys.executable, "-B", "tools/abci_hash_tree_encoding_115.py", "--check"],
                   cwd=repo, check=True)


def engine_merge(repo, scratch):
    engine = "src/node115-abci/src/engine.rs"
    for name, commit in (("before", BASE), ("restored", H), ("successor", H1)):
        (scratch / name).write_bytes(git_blob(repo, commit, engine))
    result = subprocess.run(["git", "merge-file", "-p", "-L", "restored", "-L", "base", "-L", "successor",
                             scratch / "restored", scratch / "before", scratch / "successor"],
                            text=True, capture_output=True)
    conflict = (
        "<<<<<<< restored\n"
        "            if let Some(digest) = block.synthetic_local_root {\n"
        "                let trace = self.select_and_record_root(post_height, digest, fallback_cpuid);\n"
        "=======\n"
        "            if let Some(digest) = root_source(&self.state) {\n"
        "                let trace = select_root_impl(\n"
        "                    &mut self.selector_cell,\n"
        "                    |cell, _| cell.words[0],\n"
        "                    fallback_cpuid,\n"
        "                );\n"
        "                self.local_raw_history.insert(post_height, digest);\n"
        ">>>>>>> successor\n"
    )
    require(result.returncode == 1 and result.stdout.count(conflict) == 1
            and result.stdout.count("<<<<<<<") == 1, "unexpected exact snapshot merge shape")
    combined = result.stdout.replace(conflict,
        "            if let Some(digest) = root_source(&self.state) {\n"
        "                let trace = self.select_and_record_root(post_height, digest, fallback_cpuid);\n")
    (scratch / engine).write_text(combined)
    (scratch / "src/node115-abci/src/abci_hash.rs").write_bytes(
        git_blob(repo, CAPTURE, "src/node115-abci/src/abci_hash.rs")
    )
    print(f"composed H {H}, deferred H+1 {H1}, sparse slots {CAPTURE} in temporary sources")


def build(repo, scratch):
    exported = subprocess.check_output(["git", "archive", BASE, READER, *(
        f"src/node115-{name}" for name in CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected archive source path")
        archive.extractall(scratch)
    engine_merge(repo, scratch)
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "offline-paired-engine-root"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-abci = { path = "src/node115-abci" }
node115-client-block-success = { path = "src/node115-client-block-success" }

[[bin]]
name = "offline-paired-engine-root"
path = "probe.rs"
""")
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/offline-paired-engine-root"


def unique(pairs):
    output = dict(pairs)
    require(len(output) == len(pairs), "duplicate JSON field")
    return output


def u64(value):
    return type(value) is int and 0 <= value < 1 << 64


def reference(line, height, enc_tree):
    row = json.loads(line, object_pairs_hook=unique)
    require(isinstance(row, dict) and set(row) == {"height", "abci_digest", "exchange_abci_hash"},
            "expected raw ABCI export shape")
    require(u64(row["height"]) and row["height"] == height, "raw reference height differs")

    def decode(value):
        if isinstance(value, str):
            require(DIGEST.fullmatch(value), "wrong 32-byte tree leaf")
            return bytes.fromhex(value[2:])
        require(type(value) is list, "wrong tree branch")
        indices = []
        children = []
        for item in value:
            require(type(item) is list and len(item) == 2 and u64(item[0]), "bad branch child")
            indices.append(item[0])
            children.append((item[0], decode(item[1])))
        require(len(set(indices)) == len(indices), "duplicate child index")
        return children

    tree = decode(row["exchange_abci_hash"])
    actual = "0x" + blake3(enc_tree(tree)).hexdigest()
    require(row["abci_digest"] == actual, "raw reference digest disagrees with independent byte encoding")
    return actual


def check(manifest, expected, scratch, probe, enc_tree):
    raw = manifest.read_bytes()
    require(sha(raw) == expected, "wrong fixture manifest SHA-256")
    spec = json.loads(raw, object_pairs_hook=unique)
    require(set(spec) == {"height", "checkpoint", "wire", "reference_h", "reference_h_plus_one"},
            "wrong paired root fixture roles")

    def read(role):
        item = spec[role]
        require(type(item) is dict and set(item) == {"path", "sha256"}, "wrong artifact entry")
        content = (manifest.parent / item["path"]).read_bytes()
        require(sha(content) == item["sha256"], f"wrong {role} SHA-256")
        return content

    height = spec["height"]
    require(u64(height) and height < (1 << 64) - 1, "wrong checkpoint pair height")
    expected_h = reference(read("reference_h"), height, enc_tree)
    expected_h1 = reference(read("reference_h_plus_one"), height + 1, enc_tree)
    fixture_state = read("checkpoint")
    state_terms = fixture_state.decode("ascii").split()
    require(len(state_terms) == 7 and int(state_terms[0]) == height, "incorrect checkpoint fixture height")
    fixture = scratch / "pinned-fixture.txt"
    fixture.write_bytes(fixture_state)
    wire = scratch / "pinned-wire.bin"
    wire.write_bytes(read("wire"))
    checkpoints = scratch / "checkpoint-marker"
    marker = checkpoints / str(height) / "CHECKPOINT_COMPLETE"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")
    actual = json.loads(subprocess.check_output([probe, wire, checkpoints, fixture]))
    require(actual["height"] == height and actual["successor_height"] == height + 1, "wrong Rust engine heights")
    return {**actual, "reference_h": expected_h, "reference_h_plus_one": expected_h1,
            "matches_h": actual["computed_h"] == expected_h,
            "matches_h_plus_one": actual["computed_h1"] == expected_h1}


def tests(scratch, probe, enc_tree):
    def save(name, data):
        (scratch / name).write_bytes(data)
        return {"path": name, "sha256": sha(data)}

    def make_reference(height, round_word):
        leaves = [(index, blake3(struct.pack("<Q", value)).digest())
                  for index, value in ((2, height), (4, round_word))]
        tree = [(0, [(0, leaves)]), (58, bytes([0xab] * 32))]

        def as_json(item):
            if isinstance(item, bytes):
                return "0x" + item.hex()
            return [[index, as_json(child)] for index, child in item]

        row = {"height": height, "abci_digest": "0x" + blake3(enc_tree(tree)).hexdigest(),
               "exchange_abci_hash": as_json(tree)}
        return save(f"raw-{height}-{round_word}.jsonl", (json.dumps(row) + "\n").encode())

    wire = (bytes(10) + bytes([0x31] * 20) + bytes([0, 0, 7, 0, 5, 40, 40, 4, 5])
            + bytes([0x71] * 32) + bytes(3))
    spec = {
        "height": 42, "checkpoint": save("checkpoint.txt", ("42 40 12 1 5 40 " + "ab" * 32).encode()),
        "wire": save("original.bin", wire),
        "reference_h": make_reference(42, 40), "reference_h_plus_one": make_reference(43, 41),
    }

    def run_case(name, data):
        manifest = save(name, json.dumps(data).encode())
        result = check(scratch / manifest["path"], manifest["sha256"], scratch, probe, enc_tree)
        print(json.dumps(result))
        return result

    positive = run_case("both-match.json", spec)
    require(positive["matches_h"] and positive["matches_h_plus_one"], "expected paired parity")
    alternate = run_case("successor-diverges.json", spec | {"reference_h_plus_one": make_reference(43, 42)})
    require(alternate["matches_h"] and not alternate["matches_h_plus_one"], "failed height-specific divergence")
    print("verified two engine-computed roots against independent BLAKE3; only H+1 diverges on alternate valid reference")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must be supplied together")
    sys.path.insert(0, str(args.repo.resolve() / "tools"))
    from abci_hash_tree_encoding_115 import enc_tree
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        native(args.repo.resolve(), scratch)
        probe = build(args.repo.resolve(), scratch)
        if args.case:
            result = check(args.case.resolve(), args.case_sha, scratch, probe, enc_tree)
            print(json.dumps(result))
            raise SystemExit(0 if result["matches_h"] and result["matches_h_plus_one"] else 1)
        tests(scratch, probe, enc_tree)
