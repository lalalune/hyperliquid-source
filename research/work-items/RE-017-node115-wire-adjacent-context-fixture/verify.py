"""Reproduce the offline wire-to-adjacent-Context comparison."""

from argparse import ArgumentParser
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from wire_case import export_case, normalized_clock, require, save, save_json

PACKET = Path(__file__).resolve().parent
DECODER = "e86354ccddec0b517ac5d239280d70adf520f355"
CASE = "17c2e34f1a3dc82ae8c23e4f2731f8390938adb0"
ROOT_PACKET = "RE-009-node115-rmp-adjacent-root-case"
BLAKE3 = "2da45cb0a761cff6b478e40421699857d87a94df"
HELPERS = {
    "RE-009-node115-msgpack-context-projection": "59b2f037d5a074b8bbb58d51d00972ddca7f900b",
    "RE-009-node115-checkpoint-context-projection": "5d79a3479712e0db9cc61ff1ff7e788b566254be",
    "RE-009-node115-context-subtree-compare": "4b9d111bdf95e0b235170199461fde12e9b83a9e",
    "RE-009-node115-adjacent-context-begin-roots": "aa541ff9a22748439a513548970c356f5d7c38e4",
    "RE-009-node115-context-root-isolation": "e398ce425ef2b446aaa96bf48608bc3a7fd314a2",
}
DECODER_CRATES = [
    "replay-completed-payload", "client-block-success", "lz4-decode", "lz4-literal-encoder",
    "daycount-date", "gossip-response-record", "signed-scalar", "u32-varint",
]
READER = "research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs"


def get(repo, commit, path):
    return subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo)


def decoder(repo, scratch):
    encoded = subprocess.check_output(["git", "archive", DECODER, READER, *(
        f"src/node115-{name}" for name in DECODER_CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isdir() or member.isfile()), "unexpected Git archive member")
        archive.extractall(scratch)
    (scratch / "probe.rs").write_bytes((PACKET / "probe.rs").read_bytes())
    (scratch / "Cargo.toml").write_text("""
[package]
name = "wire-context-probe"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }

[[bin]]
name = "wire-context-probe"
path = "probe.rs"
""")
    native = scratch / "decoder-evidence"
    native.mkdir()
    for name in ("anchors.tsv", "verify.py"):
        source = f"research/work-items/RE-017-node115-replay-wire-archive-header/{name}"
        (native / name).write_bytes(get(repo, DECODER, source))
    subprocess.run([sys.executable, "-B", str(native / "verify.py"), "--repo", str(repo)], check=True)
    print(f"compile completed-payload projection {DECODER} offline", flush=True)
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=scratch, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", scratch / "target"],
                   cwd=scratch, check=True)
    return scratch / "target/debug/wire-context-probe"


def toolkit(repo, scratch):
    for name in ("compare_case.py", "verify.py"):
        (scratch / name).write_bytes(get(repo, CASE, f"research/work-items/{ROOT_PACKET}/{name}"))
    subprocess.run([sys.executable, "-B", str(scratch / "verify.py")], cwd=repo, check=True)
    sys.path.insert(0, str(scratch))
    from compare_case import compare_case, hash_bytes, load_dependencies, DEPENDENCIES

    for relative, _digest in DEPENDENCIES.values():
        folder = relative.split("/", 1)[0]
        path = scratch / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(get(repo, HELPERS[folder], f"research/work-items/{relative}"))
    kit = load_dependencies(scratch)
    source = "RE-009-node115-context-root-isolation/hash_tree.rs"
    (scratch / "hash_tree.rs").write_bytes(get(repo, HELPERS[source.split("/")[0]], f"research/work-items/{source}"))
    source = "src/node115-abci-blake3/src/lib.rs"
    (scratch / "blake3.rs").write_bytes(get(repo, BLAKE3, source))
    library = scratch / "libnode115_abci_blake3.rlib"
    executable = scratch / "hash_tree"
    subprocess.run(["rustc", "--edition=2024", "--crate-name", "node115_abci_blake3",
                    "--crate-type", "rlib", scratch / "blake3.rs", "-o", library], check=True)
    subprocess.run(["rustc", "--edition=2024", scratch / "hash_tree.rs", "--extern",
                    f"node115_abci_blake3={library}", "-o", executable], check=True)
    require(hash_bytes(executable, kit["tree"], b"abc") ==
            "0x6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
            "BLAKE3 known answer mismatch")
    return kit, compare_case, hash_bytes, executable


def clock(seconds, nanos):
    return {"unix_seconds": seconds, "subsec_nanos": nanos}


def fixture(scratch, kit, helper, hash_bytes):
    import msgpack

    stored = {
        "hardfork_height": 500, "hardfork": {"version": 5, "round": 40}, "height": 42,
        "tx_index": None, "round": 40, "time": "1969-12-31T23:59:59.999999999",
        "prev_time": "1969-12-31T23:59:58", "next_oid": 26, "next_lid": 256,
        "next_twap_id": 66052, "system_nonce": 77, "use_system_nonce": False, "mac": 79,
    }
    before = stored | {"time": clock(-1, 999_999_999), "prev_time": clock(-2, 0)}
    after = before | {
        "height": 43, "round": 41, "time": clock(0, 120_000_000),
        "prev_time": clock(-1, 999_999_999), "mac": 81,
    }

    def root_row(value):
        context, tree = kit["context"], kit["tree"]
        preimages = context.preimages(value)
        leaves = (hash_bytes(helper, tree, leaf) for leaf in context.leaves(preimages))
        tree_nodes = [[0, [[0, context.replace_leaves(preimages, leaves)]]], [58, "0x" + "ab" * 32]]
        return {"height": value["height"], "exchange_abci_hash": tree_nodes,
                "abci_digest": tree.digest(helper, tree.decode_tree(tree_nodes))}

    return {
        "height": 42,
        "conversion_cutoff": 40,
        "ordered_pair": [5, 40],
        "checkpoint_rmp": save(scratch, "checkpoint.rmp", msgpack.packb(
            {"exchange": {"locus": {"ctx": stored}}}, use_bin_type=True
        )),
        "wire": save(scratch, "wire.bin", (PACKET / "wire.bin").read_bytes()),
        "archive": save(scratch, "archive.jsonl", (PACKET / "archive.jsonl").read_bytes()),
        "reference_h": save_json(scratch, "root-h.jsonl", root_row(before)),
        "reference_h_plus_one": save_json(scratch, "root-h1.jsonl", root_row(after)),
        "clock_control": save_json(scratch, "root-clock-control.jsonl", root_row(
            after | {"time": clock(0, 120_000_001)}
        )),
    }


def run_case(path, digest, kit, probe, compare_case, helper, scratch):
    case, generated, header = export_case(path, digest, kit, probe, scratch)
    print(json.dumps(header), flush=True)
    report = compare_case(case, generated, kit, helper)
    print(json.dumps(report), flush=True)
    return report


def test(scratch, kit, probe, compare_case, hash_bytes, helper):
    spec = fixture(scratch, kit, helper, hash_bytes)
    clock_control = spec.pop("clock_control")

    def run(name, value):
        saved = save_json(scratch, name, value)
        return run_case(scratch / saved["path"], saved["sha256"], kit, probe, compare_case, helper, scratch)

    result = run("case.json", spec)
    require(result["checkpoint_context"]["all_context_fields_match"] and result["selected_checks_pass"]
            and result["clock_rotated"], "wire-backed adjacent Context fixture did not match")
    different = run("case-different-root.json", spec | {"reference_h_plus_one": clock_control})
    require(different["checkpoint_context"]["all_context_fields_match"]
            and different["successor_begin"]["matched"] == {
                "height": True, "round": True, "time": False, "prev_time": True,
            }, "changed reference clock escaped the H+1 comparison")
    for label, expected in (("height", "not H+1"), ("clock", "archive clock differs")):
        wrong_archive = json.loads((PACKET / "archive.jsonl").read_bytes())
        if label == "height":
            wrong_archive["height"] = 41
        else:
            wrong_archive["abci_block"]["time"] = "1970-01-01T00:00:00.121"
        try:
            run(f"case-wrong-archive-{label}.json", spec | {
                "archive": save_json(scratch, "wrong-archive.jsonl", wrong_archive),
            })
        except ValueError as error:
            require(expected in str(error), str(error))
        else:
            raise ValueError(f"accepted inconsistent archive {label}")
    old_date = (1969 << 13) | (365 << 4) | 8
    require(normalized_clock({"date_word": old_date, "seconds": 86399, "nanos": 999999999})
            == clock(-1, 999999999), "pre-epoch clock normalization failed")
    print("verified full synthetic H Context, four H+1 begin leaves, H+1 reference clock mismatch and wrong archive height/clock")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must be supplied together")
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        kit, compare_case, hash_bytes, helper = toolkit(args.repo.resolve(), scratch)
        probe = decoder(args.repo.resolve(), scratch)
        if args.case:
            try:
                report = run_case(args.case.resolve(), args.case_sha, kit, probe, compare_case, helper, scratch)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            raise SystemExit(0 if report["selected_checks_pass"] else 1)
        test(scratch, kit, probe, compare_case, hash_bytes, helper)
