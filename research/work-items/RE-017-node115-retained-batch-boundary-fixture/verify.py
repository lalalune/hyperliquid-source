"""Reproduce retained batch publication boundaries through one offline cursor."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from batches import require, run

PUBLISH = "46a2f5325af40151ba30d34d7cf17aa8a3c1fcf7"
LINKED = "a56e64a7bd8b78323f9c91224149ee16d8b4d356"
PUBLICATION_PACKET = "RE-017-node115-replay-block-publish-advance"
LINKED_PACKET = "RE-017-node115-linked-first-converted-fixture"


def materialize(repo, scratch, commit, name, files):
    directory = scratch / name
    directory.mkdir()
    for filename in files:
        locator = f"{commit}:research/work-items/{name}/{filename}"
        (directory / filename).write_bytes(subprocess.check_output(["git", "show", locator], cwd=repo))
    return directory


def load(path, name):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prepare(repo, scratch):
    publish = materialize(repo, scratch, PUBLISH, PUBLICATION_PACKET, ("verify.py", "windows.txt"))
    subprocess.run([sys.executable, "-B", publish / "verify.py"], cwd=repo, check=True)
    linked = materialize(repo, scratch, LINKED, LINKED_PACKET, ("verify.py", "bridge.py"))
    sys.path.insert(0, str(linked))
    retained = load(linked / "verify.py", "pinned_retained_fixture")
    operations, args = retained.prepare(repo, scratch)
    return operations, (retained, args)


def tests(scratch, operations, fixture):
    existing, args = fixture
    _, _, wire_case, *_ = operations
    spec = existing.fixtures(scratch, *args)
    records = spec.pop("records")
    oracle = args[-1]

    previous = bytes([0x82] * 32)  # Independently recorded predecessor outside this batch.
    second = []
    for index in range(4, 10):
        body = oracle.header(bytes([0x31] * 20), [], 0, 120_000_000,
                             (5, 40, 40 + index, 4, 5), previous)
        current = wire_case.save(scratch, f"second-source-{index}.bin", oracle.wire(body))
        second.append(current | {"prepared_count": 0})
        previous = oracle.keccak.new(digest_bits=256, data=oracle.DOMAIN + b"\0" + body).digest()
    groups = [{"baseline": 40, "records": records[:4]}, {"baseline": 44, "records": second}]

    def measured(label, groups):
        case = wire_case.save_json(scratch, f"case-{label}.json", spec | {"batches": groups})
        return run(scratch / case["path"], case["sha256"], scratch, operations)

    positive = measured("batches", groups)
    require(positive["retained_batches"] == [
        {"batch": 0, "position": 0, "baseline": 40, "checked_before_conversion": True},
        {"batch": 1, "position": 4, "baseline": 44, "checked_before_conversion": True},
    ], "wrong per-batch baseline evidence")
    require(len(positive["checked_same_batch_links"]) == 8, "same-batch links do not match grouping")
    require(positive["cursor"][4]["cutoff_after"] == 40 and
            positive["selected_wire_header"]["round"] == 50 and
            positive["selected_root_comparison"]["selected_checks_pass"], "converter cutoff reset at a batch boundary")
    print(json.dumps({key: value for key, value in positive.items() if key != "cursor"}))

    wrong = groups[1] | {"baseline": 43}
    for label, candidate, expected in (
        ("incorrect-baseline", [groups[0], wrong], "baseline disagrees with cursor at batch 1"),
        ("flattened", [{"baseline": 40, "records": records[:4] + second}], "same-batch identity or fingerprint mismatch at 0/4"),
    ):
        try:
            measured(label, candidate)
        except ValueError as error:
            require(expected in str(error), str(error))
            print(f"rejected {label}: {error}")
        else:
            raise ValueError(f"accepted {label}")
    print("verified independent publication baselines, eight intra-batch links and unchanged converter cutoff across the split")


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
            try:
                report = run(args.case.resolve(), args.case_sha, scratch, operations)
            except (ValueError, KeyError, TypeError, OverflowError, OSError, subprocess.SubprocessError) as error:
                parser.error(str(error))
            print(json.dumps(report))
            raise SystemExit(0 if report["selected_root_comparison"]["selected_checks_pass"] else 1)
        tests(scratch, operations, fixtures)
