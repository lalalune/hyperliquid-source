"""Verify the #115 archive response evidence and offline comparison."""

from argparse import ArgumentParser
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from compare import Difference, Unavailable, compare

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

    for site, field in {
        0x4d6d625: b"signed_action_bundles",
        0x4d6d7a4: b"resps",
        0x4d6d1c6: b"Hash",
        0x4d6d299: b"Full",
        0x548350b: b"user",
        0x548352d: b"res",
        0x5922800: b"status",
        0x5922835: b"response",
    }.items():
        require(read(".rodata", target(site), len(field)) == field, "wrong JSON field literal")
    for site, callee in {
        0x4d6d639: 0x5075db0, 0x5075ed1: 0x4e1c250,
        0x4d6d7b5: 0x506e230, 0x506e30d: 0x4d6d170,
        0x4d6d248: 0x4e1c250, 0x4d6d2f2: 0x502d0d0, 0x502d194: 0x4e1c250,
        0x502d1f9: 0x54834d0, 0x502d247: 0x54834d0,
        0x548351c: 0x5072c50, 0x5072d25: 0x4e1c250, 0x5483541: 0x507ac50, 0x507ad0a: 0x59227c0,
        0x5922849: 0x509a4c0, 0x59228c1: 0x5086930, 0x50869ea: 0x4d8e0a0,
    }.items():
        require(target(site) == callee, f"wrong archive response edge at {site:#x}")
    require(spans[0x506e2f6][-4:] == b"null", "wrong null response literal")
    require(spans[0x5075ec6][-4:] == spans[0x4d6d23d][-4:] == spans[0x502d186][-4:] == struct.pack("<I", 32),
            "wrong key width")
    require(spans[0x502d111][-1] == 0x38 and spans[0x502d24c][-1] == 0x40, "wrong Full row stride")
    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    require(spans[0x5072d1a][-4:] == struct.pack("<I", 20), "wrong user width")
    require(relocations.get(target(0x4e1c260)) == (8, 0x2eabb50), "wrong fixed-hex adapter")
    require(read(".rodata", target(0x2eabb89), 16) == b"0123456789abcdef", "wrong hex alphabet")
    for site, status in {0x5922807: b"err", 0x592288b: b"ok"}.items():
        slot = target(site) + 16
        tag, address = relocations[slot]
        require(tag == 8 and read(".rodata", address, len(status)) == status
                and read(".data.rel.ro", slot + 8, 8) == struct.pack("<Q", len(status)),
                "wrong action result status")
    print(f"Pinned #115 digest {TARGET_SHA256}; {len(spans)} instruction witnesses")


def verify_comparison():
    first = "0x" + "00" * 31 + "01"
    second = "0x" + "00" * 31 + "02"
    user = "0x" + "00" * 19 + "03"
    accepted = {"user": user, "res": {"status": "ok", "response": {"type": "order", "val": "EXACT"}}}
    rejected = {"user": user, "res": {"status": "err", "response": "example error"}}
    archive = {
        "abci_block": {"signed_action_bundles": [
            [first, {"signed_actions": [{"action": {}}, {"action": {}}]}],
            [second, {"signed_actions": []}],
        ]},
        "resps": {"Full": [[first, [accepted, rejected]], [second, []]]},
    }

    def encode(value):
        return json.dumps(value, separators=(",", ":")).encode().replace(b'"EXACT"', b"1.000000000000000001")

    row = encode(archive) + b"\n"
    replay = encode({"Full": [[second, []], [first, [accepted, rejected]]]})
    require(compare(row, replay) == (), "identical results must match across outer order")
    print("Full alignment preserved action order and an explicitly empty bundle")
    require(compare(row, replay.replace(b"1.000000000000000001", b"1.000000000000000002")) == (
        Difference(bytes.fromhex(first[2:]), 0, ("response",)),
    ), "precision loss hid a numeric delta")
    require(compare(row.replace(b"1.000000000000000001", b"1"),
                    replay.replace(b"1.000000000000000001", b"true")) == (
        Difference(bytes.fromhex(first[2:]), 0, ("response",)),
    ), "boolean/number distinction lost")
    require(compare(row, encode({"Full": [[second, []], [first, [rejected, accepted]]]})) == (
        Difference(bytes.fromhex(first[2:]), 0, ("status", "response")),
        Difference(bytes.fromhex(first[2:]), 1, ("status", "response")),
    ), "individual results must remain in action order")
    print("Exact decimal, JSON type and distinct action-index differences were detected")
    require(compare(row, b"null") == Unavailable("replay", "null"), "null conflation")
    require(compare(row, encode({"Hash": first})) == Unavailable("replay", "Hash"), "hash conflation")
    without_full = {**archive, "resps": {"Hash": first}}
    require(compare(encode(without_full), replay) == Unavailable("archive", "Hash"), "source lost")
    require(compare(b'{"abci_block":{"signed_action_bundles":[]},"resps":{"Full":[]}}',
                    b'{"Full":[]}') == (), "complete empty comparison")
    print("Null and Hash remain unavailable for per-action comparison; empty Full is a complete match")
    for label, value, expected in (
        ("missing bundle", {"Full": [[first, [accepted, rejected]]]}, "bundle keys"),
        ("duplicate bundle", {"Full": [[first, []], [first, []]]}, "duplicate bundle key"),
        ("missing result", {"Full": [[first, [accepted]], [second, []]]}, "action count differs"),
        ("conflicting variants", {"Hash": first, "Full": []}, "exactly one known variant"),
        ("wrong result shape", {"Full": [[first, [accepted, {"user": user, "res": {
            "status": "err", "response": {}}}]], [second, []]]}, "err string or an ok object"),
    ):
        try:
            compare(row, encode(value))
        except ValueError as error:
            require(expected in str(error), f"{label}: {error}")
        else:
            raise ValueError(f"accepted control {label}")
        print(f"Rejected comparison control: {label}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=PACKET.parents[2])
    args = parser.parse_args()
    verify_native(args.repo.resolve())
    verify_comparison()


if __name__ == "__main__":
    main()
