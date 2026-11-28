"""Verify the prefilter attachment-count boundary before first-conversion matching."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from Crypto.Hash import keccak

from prefilter import require, run

ATTACH_ARCHIVE = "1576c7af30a72e0df013a88c3cf1bb9b99230d00"
CONVERSION = "b5c57efaa22b79029d113aa6094435cfb8dec488"
HANDOFF = "f71c6add4d11c278d7b3bdccc86e64ebabcc833c"
ARCHIVE_PACKET = "RE-017-node115-attachment-archive-keys"
CONVERSION_PACKET = "RE-017-node115-first-converted-context-fixture"
HANDOFF_PACKET = "RE-017-node115-replay-attachment-owner-handoff"


def checkout(repo, scratch, commit, name, files):
    folder = scratch / name
    folder.mkdir()
    for file in files:
        raw = subprocess.check_output(
            ["git", "show", f"{commit}:research/work-items/{name}/{file}"], cwd=repo,
        )
        (folder / file).write_bytes(raw)
    return folder


def load(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    handoff = checkout(repo, scratch, HANDOFF, HANDOFF_PACKET, ("verify.py", "windows.txt"))
    subprocess.run([sys.executable, "-B", handoff / "verify.py"], cwd=repo, check=True)
    archive = checkout(repo, scratch, ATTACH_ARCHIVE, ARCHIVE_PACKET,
                       ("verify.py", "compare.py", "anchors.tsv", "probe.rs"))
    conversion = checkout(repo, scratch, CONVERSION, CONVERSION_PACKET, ("verify.py", "sequence.py", "cursor.rs"))
    sys.path[:0] = [str(archive), str(conversion)]
    attachment = load(archive / "verify.py", "existing_attachment_probe")
    audit = load(archive / "compare.py", "existing_archive_key_comparator")
    converter = load(conversion / "verify.py", "existing_converter_probe")
    run_converter = load(conversion / "sequence.py", "existing_first_conversion_runner")
    attachment.native(repo)
    attachment_probe = attachment.build(repo, archive)
    runner, wire_case, kit, cursor, decoder, compare_case, hash_bytes, helper = converter.prepare(repo, scratch)
    checks = (attachment_probe, audit.compare, run_converter.run, wire_case, kit,
              cursor, decoder, compare_case, helper)
    return checks, (runner, wire_case, kit, helper, hash_bytes)


def tests(scratch, operations, fixtures):
    runner, wire_case, kit, helper, hash_bytes = fixtures
    base = runner.fixture(scratch, kit, helper, hash_bytes)
    original = (scratch / base["wire"]["path"]).read_bytes()
    require(original[30] == original[-1] == 0, "expected zero-header-hash and absent-owner baseline")
    opaque = b"abc"
    fingerprint = keccak.new(digest_bits=256, data=opaque).digest()
    wire = original[:30] + b"\1" + fingerprint + original[31:-1] + b"\1\1" + fingerprint + b"\3" + opaque
    row = wire_case.save(scratch, "nonempty-prefilter-owner.bin", wire)
    spec = {key: base[key] for key in ("height", "ordered_pair", "archive",
                                      "checkpoint_rmp", "reference_h", "reference_h_plus_one")}
    spec.update(restored_round=40, records=[row], successful_rows=[])
    supplied = wire_case.save_json(scratch, "source-owner-case.json", spec)
    report = run(scratch / supplied["path"], supplied["sha256"], scratch, operations)
    require(report["prefilter_count"] == 1 and report["archive_output_count"] == 0
            and report["archive_keys"]["matched"], "wrong source/output shape distinction")
    require(report["cursor"][0]["outcome"] == "converted"
            and report["cursor"][0]["successor"] == 41
            and report["selected_wire_header"]["height"] == 43
            and report["selected_root_comparison"]["selected_checks_pass"], "wrong early first conversion")
    print(json.dumps(report))

    wrong = {key: spec[key] for key in spec if key != "successful_rows"}
    wrong["records"] = [{**row, "prepared_count": 0}]
    control = wire_case.save_json(scratch, "incorrect-output-count.json", wrong)
    _, _, first_converted, _, _, *replay = operations
    try:
        first_converted(scratch / control["path"], control["sha256"], scratch, wire_case, kit, *replay)
    except ValueError as error:
        require("ends before the first conversion" in str(error), str(error))
        print(f"using archive output count prevents conversion: {error}")
    else:
        raise ValueError("post-filter count was treated as the original owner count")
    print("verified original owner 1, converted output 0, threshold bypass and selected H/H+1 comparison")


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
        operations, fixtures = prepare(args.repo.resolve(), scratch)
        if args.case:
            result = run(args.case.resolve(), args.case_sha, scratch, operations)
            print(json.dumps(result))
            passed = result["archive_keys"]["matched"] and result["selected_root_comparison"]["selected_checks_pass"]
            raise SystemExit(0 if passed else 1)
        tests(scratch, operations, fixtures)
