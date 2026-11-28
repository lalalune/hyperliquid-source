"""Verify the native archive bundle and replay descriptor pairing geometry."""

from argparse import ArgumentParser
import csv
import hashlib
from pathlib import Path
import struct
import sys

from project import BundleCounts, project_bundle_counts

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
        return site + len(raw) + struct.unpack("<i", raw[-4:])[0]

    for site, name in {0x4d6d625: b"signed_action_bundles", 0x53caf47: b"signed_actions"}.items():
        require(read(".rodata", target(site), len(name)) == name, "wrong field literal")
    for site, expected in {
        0x4d6d639: 0x5075db0,
        0x5075f05: 0x53caf10,
        0x53caf5b: 0x5090810,
        0x50908ec: 0x5923350,
        0x5618630: 0x5a04e40,
        0x5a04f4c: 0x5a06290,
        0x5a06714: 0x5a07af2,
        0x5a051a6: 0x5a0529c,
        0x5a069a7: 0x5a06a9e,
    }.items():
        require(target(site) == expected, f"wrong edge at {site:#x}")

    for site, stride in {
        0x5a0512a: 0x28, 0x5a0512e: 0x18,
        0x5a05177: 0x28, 0x5a0517b: 0x18,
        0x5a06926: 0x28, 0x5a0692a: 0x18,
        0x5a06977: 0x28, 0x5a0697b: 0x18,
    }.items():
        require(spans[site][-1] == stride, f"wrong pair stride at {site:#x}")
    require(spans[0x5a05199][-8:] == spans[0x5a0699a][-8:] == struct.pack("<Q", 1 << 63),
            "wrong descriptor marker")
    print(f"Pinned #115 digest {TARGET_SHA256}; {len(spans)} instruction witnesses")
    print("Bundle count source +0x10; paired replay descriptor count +0x10; strides 40 and 24 bytes")


def verify_fixture():
    two = ["key-a", {"signed_actions": [{"action": "fixture-0"}, {"action": "fixture-1"}]}]
    one = ["key-b", {"signed_actions": [{"action": "fixture-2"}]}]
    two_bundles = {"signed_action_bundles": [two, one]}
    counts = project_bundle_counts(two_bundles, payload_descriptors=2)
    require(counts == BundleCounts(2, 2, 3) and counts.aligned, "matched bundle/descriptor counts")
    print("Two bundles with three nested actions match two descriptors")
    false_guess = project_bundle_counts(two_bundles, payload_descriptors=3)
    require(false_guess == BundleCounts(2, 3, 3) and not false_guess.aligned, "nested count misused")
    print("Three nested actions fail as the expected descriptor count")
    empty_bundle = ["key-c", {"signed_actions": []}]
    counts = project_bundle_counts({"signed_action_bundles": [empty_bundle]}, payload_descriptors=1)
    require(counts == BundleCounts(1, 1, 0) and counts.aligned, "empty inner vector erased outer bundle")
    print("One bundle with zero signed actions still occupies a paired slot")
    empty = {"signed_action_bundles": []}
    require(project_bundle_counts(empty, payload_descriptors=0).aligned, "zero bundles and descriptors mismatch")
    require(not project_bundle_counts(empty, payload_descriptors=1).aligned, "orphan descriptor accepted")
    try:
        project_bundle_counts(two_bundles, payload_descriptors=True)
    except ValueError as error:
        require("must be a u64" in str(error), f"unexpected descriptor error: {error}")
    else:
        raise ValueError("accepted a boolean as a descriptor count")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())
    verify_fixture()


if __name__ == "__main__":
    main()
