"""Authenticate the compact #115 outcome writer and run the reconstructed writer."""

from argparse import ArgumentParser
import csv
import hashlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

PACKET = Path(__file__).resolve().parent
ENTRY = "4f2edd5fa24e2970fbece7caba77522b05892a9c"
CRATE = "src/node115-replica-response-json"


def require(condition, text):
    if not condition:
        raise ValueError(text)


def native(repo):
    sys.path.insert(0, str(repo / "tools"))
    from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

    image = (repo / TARGET).read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET_SHA256, "wrong #115 image")
    sections = {section["name"]: section for section in parse_sections(image)}

    def read(section_name, addr, size):
        section = sections[section_name]
        delta = addr - section["va"]
        require(0 <= delta <= delta + size <= section["size"], "wrong ELF section range")
        offset = section["offset"] + delta
        return image[offset:offset + size]

    eh = sections[".eh_frame"]
    _, rows = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in rows}
    spans = {}
    with (PACKET / "anchors.tsv").open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            start, end, address = (int(row[key], 16) for key in ("start", "end", "address"))
            raw = bytes.fromhex(row["bytes"])
            require((start, end) in bounds and start <= address < address + len(raw) <= end,
                    f"wrong instruction range at {address:#x}")
            require(address not in spans and read(".text", address, len(raw)) == raw, f"wrong bytes at {address:#x}")
            spans[address] = raw
            print(f"{address:#x} {raw.hex()} {row['instruction']}")

    def target(site):
        raw = spans[site]
        return site + len(raw) + struct.unpack("<i", raw[-4:])[0]

    for site, callee in {
        0x4d8e133: 0x5086350, 0x508640a: 0x518a360, 0x518a3a1: 0x5094fe0,
        0x50950bc: 0x51899c0, 0x5095106: 0x51899c0,
        0x5189ab4: 0x507efc0, 0x5189adf: 0x507efc0,
        0x5189b0a: 0x5077210, 0x5189dae: 0x5077210,
        0x5189b26: 0x5241910, 0x5241924: 0x507edc0, 0x5189de3: 0x507edc0,
        0x507ee97: 0x4e1c250, 0x507f07a: 0x57cdcf0,
        0x5189c12: 0x50a3510, 0x57cdd39: 0x50a3510, 0x50772c2: 0x50fc010,
    }.items():
        require(target(site) == callee, f"wrong edge at {site:#x}")
    for site, literal in {
        0x4d8e0ea: b"type", 0x4d8e11f: b"data", 0x518a392: b"statuses",
        0x5189a28: b"filled", 0x5189d1f: b"resting", 0x5189c70: b"waitingForFill",
        0x5189c9d: b"waitingForTrigger", 0x5189b8f: b"error", 0x5189aa5: b"totalSz",
        0x5189ad0: b"avgPx", 0x5189afb: b"oid", 0x5189d9d: b"oid",
        0x5241918: b"cloid", 0x5189dcf: b"cloid",
    }.items():
        require(read(".rodata", target(site), len(literal)) == literal, f"wrong literal at {site:#x}")
    table = target(0x51899d5)
    entries = [table + delta for delta in struct.unpack("<5i", read(".rodata", table, 20))]
    require(entries == [0x51899e5, 0x5189cdc, 0x5189c51, 0x5189c7e, 0x5189b41], "wrong status dispatch")
    require(spans[0x50950d2][-1] == 0x30 and spans[0x50950a2][-1] == 0x5b
            and spans[0x50950f5][-1] == 0x2c, "wrong order traversal")
    require(spans[0x507ee8c][-4:] == (16).to_bytes(4, "little")
            and spans[0x507ee87][-4:] == (34).to_bytes(4, "little"), "wrong cloid width")
    rela = sections[".rela.dyn"]
    relocations = {slot: (kind, value) for slot, kind, value in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    address = target(0x4d8e0f1) + 16
    require(relocations[address][0] == 8 and read(".rodata", relocations[address][1], 5) == b"order",
            "wrong order tag descriptor")
    require(relocations[target(0x57cdd05)] == (8, 0x44a61d0)
            and spans[0x57cdd25][-1] == 0x22, "wrong native normalized quantity text path")
    print(f"verified {len(spans)} static instruction spans and five named status arms")


def check(repo, scratch):
    archive = subprocess.check_output(["git", "archive", ENTRY, CRATE], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        for member in files.getmembers():
            name = Path(member.name)
            require(not name.is_absolute() and ".." not in name.parts
                    and (member.isfile() or member.isdir()), "unexpected checkout entry")
        files.extractall(scratch)
    crate = scratch / CRATE
    (crate / "src/order.rs").write_bytes((PACKET / "order.rs").read_bytes())
    (crate / "tests/order_wire.rs").write_bytes((PACKET / "order_wire.rs").read_bytes())
    module = crate / "src/lib.rs"
    original = module.read_text()
    require(original.count("pub mod entry;") == 1, "wrong original crate snapshot")
    module.write_text(original.replace("pub mod entry;", "pub mod entry;\npub mod order;"))
    entry = crate / "src/entry.rs"
    original = entry.read_text()
    for old, new in (
        ("    ValidatorVote(bool),", "    ValidatorVote(bool),\n    Order(&'a [crate::order::OrderStatus<'a>]),"),
        ("fn quoted_text(", "pub(super) fn quoted_text("),
        ("        ActionResult::Default =>", "        ActionResult::Order(rows) => crate::order::write_order(out, rows)?,\n        ActionResult::Default =>"),
    ):
        require(original.count(old) == 1, f"wrong previous writer at {old}")
        original = original.replace(old, new)
    entry.write_text(original)
    subprocess.run(["cargo", "test", "--offline", "--locked", "--manifest-path", crate / "Cargo.toml",
                    "--target-dir", scratch / "target"], check=True)


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    repo = args.repo.resolve()
    native(repo)
    with TemporaryDirectory() as folder:
        check(repo, Path(folder))
