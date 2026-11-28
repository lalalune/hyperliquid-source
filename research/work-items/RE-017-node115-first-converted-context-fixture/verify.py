"""Reproduce the first converted Block selection and Context checks offline."""

from argparse import ArgumentParser
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from sequence import require, run

PACKET = Path(__file__).resolve().parent
CURSOR = "e9c51eacd8d19b0462b2d31b83c48caf613715cb"
WIRE_CONTEXT = "1cde76593a51988264643cf60747e48e493339a5"
CURSOR_PACKET = "RE-017-node115-replay-conversion-cursor"
WIRE_PACKET = "RE-017-node115-wire-adjacent-context-fixture"


def checkout_packet(repo, folder, commit, item, files):
    folder.mkdir()
    for name in files:
        path = f"research/work-items/{item}/{name}"
        (folder / name).write_bytes(subprocess.check_output(["git", "show", f"{commit}:{path}"], cwd=repo))


def build_cursor(repo, scratch, runner):
    source = scratch / "src-cursor"
    source.mkdir()
    tar = subprocess.check_output(["git", "archive", CURSOR, runner.READER, *(
        f"src/node115-{name}" for name in runner.DECODER_CRATES
    )], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts and
                    (member.isfile() or member.isdir()), "unexpected archive path")
        archive.extractall(source)
    (source / "cursor.rs").write_bytes((PACKET / "cursor.rs").read_bytes())
    (source / "Cargo.toml").write_text("""
[package]
name = "offline-replay-cursor"
version = "0.1.0"
edition = "2024"

[dependencies]
node115-replay-completed-payload = { path = "src/node115-replay-completed-payload" }
node115-client-block-success = { path = "src/node115-client-block-success" }

[[bin]]
name = "offline-replay-cursor"
path = "cursor.rs"
""")
    print(f"compiling conversion cursor snapshot {CURSOR} offline", flush=True)
    subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=source, check=True)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--quiet", "--target-dir", source / "target"],
                   cwd=source, check=True)
    return source / "target/debug/offline-replay-cursor"


def prepare(repo, scratch):
    cursor_evidence = scratch / CURSOR_PACKET
    checkout_packet(repo, cursor_evidence, CURSOR, CURSOR_PACKET, ("anchors.tsv", "verify.py"))
    subprocess.run([sys.executable, "-B", cursor_evidence / "verify.py", "--repo", str(repo)], check=True)
    wire_folder = scratch / WIRE_PACKET
    checkout_packet(repo, wire_folder, WIRE_CONTEXT, WIRE_PACKET,
                    ("archive.jsonl", "probe.rs", "verify.py", "wire.bin", "wire_case.py"))
    sys.path.insert(0, str(wire_folder))
    import verify as runner
    import wire_case

    kit, compare_case, hash_bytes, helper = runner.toolkit(repo, scratch)
    probe = runner.decoder(repo, scratch)
    cursor = build_cursor(repo, scratch, runner)
    return runner, wire_case, kit, cursor, probe, compare_case, hash_bytes, helper


def test(scratch, runner, wire_case, kit, cursor, probe, compare_case, hash_bytes, helper):
    base = runner.fixture(scratch, kit, helper, hash_bytes)
    wirerow = (scratch / base["wire"]["path"]).read_bytes()
    require(wirerow[37:43] == bytes([0,5,40,40,4,5]), "unexpected QC field boundary")
    records = [wire_case.save(scratch, f"row-{index}.bin", wirerow[:40] + bytes([40+index]) + wirerow[41:])
               | {"prepared_count": 0} for index in range(10)]

    original = json.loads((scratch / base["archive"]["path"]).read_bytes())
    archive = original | {"abci_block": original["abci_block"] | {"round": 50}}
    reference = json.loads((scratch / base["reference_h_plus_one"]["path"]).read_bytes())
    rows = reference["exchange_abci_hash"]
    # The independent synthetic H+1 reference uses the known word for round 50.
    rows[0][1][0][1][4][1] = hash_bytes(helper, kit["tree"], (50).to_bytes(8, "little"))
    reference["abci_digest"] = kit["tree"].digest(helper, kit["tree"].decode_tree(rows))
    spec = {
        "height": 42, "restored_round": 40, "ordered_pair": [5, 40], "records": records,
        "archive": wire_case.save_json(scratch, "converted-archive.jsonl", archive),
        "checkpoint_rmp": base["checkpoint_rmp"], "reference_h": base["reference_h"],
        "reference_h_plus_one": wire_case.save_json(scratch, "converted-root.jsonl", reference),
    }

    def evaluate(label, case):
        meta = wire_case.save_json(scratch, f"sequence-{label}.json", case)
        return run(scratch / meta["path"], meta["sha256"], scratch,
                   wire_case, kit, cursor, probe, compare_case, helper)

    report = evaluate("complete", spec)
    observations = report["cursor"]
    require([event["outcome"] for event in observations] == ["skipped"] * 9 + ["converted"],
            "wrong conversion sequence")
    require([event["expected_after"] for event in observations] == list(range(41, 51))
            and [event["cutoff_after"] for event in observations] == [40] * 9 + [50],
            "cursor and cutoff did not advance independently")
    require(observations[-1]["parent_round"] == 40 and report["selected_wire_header"]["height"] == 43
            and report["selected_wire_header"]["round"] == 50
            and report["selected_root_comparison"]["selected_checks_pass"], "wrong converted H+1 result")
    print(json.dumps(report))
    for label, variant, error in (
        ("restored-round", spec | {"restored_round": 39}, "restored round differs from checkpoint"),
        ("early-row", spec | {"archive": base["archive"]}, "archive round differs from decoded wire"),
        ("short-capture", spec | {"records": records[:-1]}, "ends before the first conversion"),
        ("missing-record", spec | {"records": records[:2] + records[3:]}, "identity mismatch before conversion"),
    ):
        try:
            evaluate(label, variant)
        except ValueError as observed:
            require(error in str(observed), str(observed))
            print(f"rejected {label}: {observed}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified nine skipped wire records, tenth conversion, H+1 Context match and four controls")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--case", type=Path)
    parser.add_argument("--case-sha")
    args = parser.parse_args()
    if bool(args.case) != bool(args.case_sha):
        parser.error("--case and --case-sha must be supplied together")
    with TemporaryDirectory() as working:
        scratch = Path(working)
        runner, wire_case, kit, cursor, probe, compare_case, hash_bytes, helper = prepare(
            args.repo.resolve(), scratch,
        )
        if args.case:
            try:
                report = run(args.case.resolve(), args.case_sha, scratch, wire_case, kit,
                             cursor, probe, compare_case, helper)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(report))
            raise SystemExit(0 if report["selected_root_comparison"]["selected_checks_pass"] else 1)
        test(scratch, runner, wire_case, kit, cursor, probe, compare_case, hash_bytes, helper)
