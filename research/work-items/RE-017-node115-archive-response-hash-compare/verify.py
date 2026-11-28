"""Verify the selected node #115 archived response hash projection."""

from argparse import ArgumentParser
import csv
import hashlib
from pathlib import Path
import struct
import sys

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

    for site, destination in {
        0x5a6ed0c: 0x4e36af0, 0x5a6f991: 0x595a6b0,
        0x4e36b48: 0x531bff0, 0x531c1c9: 0x531e200,
        0x531e2d1: 0x53228f0, 0x531e959: 0x54835f0,
        0x5483624: 0x57ce100, 0x548372c: 0x59229a0,
        0x5922b55: 0x4d8fcd0, 0x4d6d7b5: 0x506e230,
        0x506e30d: 0x4d6d170, 0x4d6d248: 0x4e1c250,
    }.items():
        require(target(site) == destination, f"wrong format edge at {site:#x}")
    for site, literal in {
        0x548366d: b"user", 0x5483707: b"res", 0x5922a47: b"status",
        0x5922a65: b"err", 0x5922a92: b"response", 0x4d6d7a4: b"resps",
        0x4d6d1c6: b"Hash",
    }.items():
        require(read(".rodata", target(site), len(literal)) == literal, f"wrong literal {literal!r}")

    writer = spans[0x4e36b25]
    require(writer[3] == 8 and writer[-1] == 1, "writer mode at +0xb must be named")
    require(spans[0x531e27c][-1] == 0x92, "wrong pair header")
    require(spans[0x548368b][-2:] == bytes.fromhex("2801"), "wrong user presence predicate")
    require(spans[0x52f7c40][-4:] == bytes.fromhex("2a000000"), "wrong user string length")
    require(spans[0x4e36bd9][-4:] == bytes.fromhex("88000000"), "wrong sponge rate")
    require(spans[0x4e36be5][-2:] == bytes.fromhex("0100"), "wrong sponge delimiter")
    require(spans[0x4e36c1b][-4:] == bytes.fromhex("20000000"), "wrong digest width")
    require(spans[0x5a6ede3][-1] == spans[0x4d6d17f][-1] == 1, "wrong Hash tag")
    require(spans[0x4d6d7a0][-1] == 0x58, "wrong resps field offset")

    rela = sections[".rela.dyn"]
    relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    for site, address in {
        0x4e36bf7: 0x5cda910, 0x4e36c23: 0x5cdad40,
        0x53229f4: 0x2eabb50, 0x52f7c50: 0x2eabb50,
    }.items():
        require(relocations.get(target(site)) == (8, address), f"wrong helper slot at {site:#x}")
    print(f"verified {len(spans)} archived outcome Hash instruction spans and named writer mode")


def verify_fixtures(repo):
    import json

    sys.path.insert(0, str(repo / "tools"))
    from compare import UnsupportedOutcome, compare, encode_rows

    old = json.loads((PACKET / "archive-synthetic.jsonl").read_text())
    local = json.loads((PACKET / "local-full.json").read_text())
    rows = local["Full"]
    known = (
        b"\x92\x92\xd9\x42" + b"0x" + b"01" * 32 + b"\x92"
        + b"\x82\xa4user\xc0\xa3res\x82\xa6status\xa2ok\xa8response\x81\xa4type\xa7default"
        + b"\x82\xa4user\xd9\x2a" + b"0x" + b"02" * 20
        + b"\xa3res\x82\xa6status\xa3err\xa8response\xb1order unavailable"
        + b"\x92\xd9\x42" + b"0x" + b"03" * 32 + b"\x90"
    )
    preimage, entries = encode_rows(rows)
    require(preimage == known and entries == 2, "wrong format for the two-row named preimage")
    digest = compare(old["resps"], local)
    require(digest.matches and digest.rows == 2 and digest.entries == 2, "wrong fixture fingerprint")
    require(not compare(old["resps"], {"Full": rows[::-1]}).matches, "lost native row order")
    require(not compare(old["resps"], {"Full": [[rows[0][0], rows[0][1][::-1]], rows[1]]}).matches,
            "lost native entry order")
    empty = {"Hash": "0x632315f5af09a9a7da25ae16c4f8560df2b48d94d524d354b69f35289c56e0ea"}
    require(compare(empty, {"Full": []}).matches, "wrong empty result fingerprint")
    cancel = {"status": "ok", "response": {"type": "cancel", "data": {"statuses": ["success", {"error": "x"}]}}}
    expected_cancel = (b"\x91\x92\xd9\x42" + b"0x" + b"03" * 32 + b"\x91\x82\xa4user\xc0\xa3res"
                       b"\x82\xa6status\xa2ok\xa8response\x82\xa4type\xa6cancel\xa4data\x81"
                       b"\xa8statuses\x92\xa7success\x81\xa5error\xa1x")
    require(encode_rows([[rows[1][0], [{"user": None, "res": cancel}]]])[0] == expected_cancel,
            "wrong selected cancel preimage")
    try:
        encode_rows([[rows[1][0], [{"user": None, "res": {"status": "ok", "response": {"type": "spot"}}}]]])
    except UnsupportedOutcome as error:
        require(str(error).startswith("row 0, entry 0"), "unlocated unsupported response")
    else:
        raise ValueError("unsupported outcome should remain unresolved")
    print(f"verified named preimage ({len(preimage)} bytes), ordered outcome controls, {digest.actual}")
    return preimage


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--preimage", type=Path)
    args = parser.parse_args()
    verify_native(args.repo)
    preimage = verify_fixtures(args.repo)
    if args.preimage is not None:
        args.preimage.write_bytes(preimage)
