"""Verify the selected normal replay preparation cardinalities."""

from argparse import ArgumentParser
import csv
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from check_shape import GroupMismatch, compare_prepared_shape

PACKET = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong target")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(name, va, n):
        section = sections[name]
        position = va - section["va"]
        require(0 <= position <= position + n <= section["size"], "outside ELF section")
        offset = section["offset"] + position
        return image[offset:offset + n]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in rows}
    spans = {}
    with (PACKET / "anchors.tsv").open() as file:
        for row in csv.DictReader(file, delimiter="\t"):
            start, end, address = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= address < address + len(raw) <= end,
                    f"wrong FDE for {address:#x}")
            require(address not in spans and read(".text", address, len(raw)) == raw,
                    f"wrong instruction bytes at {address:#x}")
            spans[address] = raw
            print(f"{start:#x}..{end:#x} {address:#x} {raw.hex()} {row['instruction']}")

    def target(site):
        raw = spans[site]
        size = 1 if len(raw) == 2 else 4
        return site + len(raw) + int.from_bytes(raw[-size:], "little", signed=True)

    for site, field in {0x4d6d625: b"signed_action_bundles", 0x53caf47: b"signed_actions"}.items():
        require(read(".rodata", target(site), len(field)) == field, "wrong archive field")
    for site, callee in {
        0x4d6d639: 0x5075db0, 0x5075f05: 0x53caf10, 0x53caf5b: 0x5090810,
        0x59edcc5: 0x3d9ce60, 0x3d9ce67: 0x4301e90, 0x4301f5b: 0x3ec1b80,
        0x3ec1c0c: 0x3713530, 0x37135da: 0x3d9d160, 0x3d9d167: 0x4301ce0,
        0x4301da7: 0x3ebdd10, 0x4301f71: 0x4301ffc, 0x4301dbd: 0x4301e2a,
    }.items():
        require(target(site) == callee, f"wrong preparation edge at {site:#x}")

    archived_count = spans[0x5075efe][-1] + spans[0x509089b][-1]
    prepared_count = spans[0x371359f][-1] + spans[0x3d9d163][-1]
    require(archived_count == prepared_count == 0x20, "routes disagree on bundle action count")
    require(spans[0x5075e3e][-1] == spans[0x59edc8c][-1] + spans[0x3d9ce63][-1] == 0x10,
            "routes disagree on outer count")
    require(spans[0x4301f64] == spans[0x4301db0] and spans[0x4301f6e] == spans[0x4301dba],
            "collectors no longer compare the corresponding count words")
    require(spans[0x4301f91] == spans[0x4301dbf] and spans[0x4301f94] == spans[0x4301dc2],
            "collectors disagree on length commitment")
    require(spans[0x3713626][-1] == spans[0x4301fac][-4] == 0x18, "wrong outer record stride")
    require(spans[0x4301d21][-1] == 0x70, "wrong prepared item stride")
    print(f"Pinned #115 SHA-256 {TARGET_SHA256}; {len(spans)} selected native witnesses")
    print("Successful outer and inner collectors check their input counts before committing lengths")


def verify_fixture():
    # Normal synthetic shape with two nonempty groups and one explicit empty group.
    bundles = [2, 1, 0]
    row = json.dumps({"abci_block": {"signed_action_bundles": [
        [f"0x{index:064x}", {"signed_actions": [{} for _ in range(count)]}]
        for index, count in enumerate(bundles)
    ]}}).encode() + b"\n"
    require(compare_prepared_shape(row, bundles) == (), "matching groups differ")
    require(compare_prepared_shape(row, [1, 2, 0]) == (
        GroupMismatch(0, 2, 1), GroupMismatch(1, 1, 2),
    ), "outer and summed totals hid a position mismatch")
    require(compare_prepared_shape(row, [2, 1, 1]) == (GroupMismatch(2, 0, 1),),
            "empty group was treated as absent")
    print("Per-position comparison distinguishes equal-total group drift and an explicit empty group")
    for counts, expected in (
        ([2, 1], "outer bundle count"),
        ([2, 1, False], "unsigned 64-bit"),
        ([2, 1, 2**64], "unsigned 64-bit"),
    ):
        try:
            compare_prepared_shape(row, counts)
        except ValueError as error:
            require(expected in str(error), f"unexpected fixture rejection: {error}")
        else:
            raise ValueError(f"accepted count control: {counts}")
    with TemporaryDirectory() as temporary:
        directory = Path(temporary)
        archive, observed = directory / "archive-row.jsonl", directory / "observed-counts.json"
        archive.write_bytes(row)
        command = [sys.executable, "-B", str(PACKET / "check_shape.py"), str(archive), str(observed)]
        for counts, code, action in (([2, 1, 0], 0, "match"), ([1, 2, 0], 2, "inner mismatch")):
            observed.write_text(json.dumps(counts))
            result = subprocess.run(command, capture_output=True, text=True)
            require(result.returncode == code, f"CLI {action}: {result.stderr}")
            print(f"CLI {action}: exit {code}, {result.stdout.strip()}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())
    verify_fixture()


if __name__ == "__main__":
    main()
