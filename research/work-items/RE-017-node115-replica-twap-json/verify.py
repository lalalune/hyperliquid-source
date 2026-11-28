"""Authenticate the compact #115 TWAP writer and test the reconstructed results."""

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
        0x4d8e29f: 0x509e1f0, 0x4d8e60f: 0x5098c90,
        0x509e2aa: 0x5184090, 0x5098d4a: 0x5184170,
        0x51840d1: 0x508eb30, 0x51841b1: 0x50686f0,
        0x508ebea: 0x51833f0, 0x50687aa: 0x51837d0,
        0x5183406: 0x5183517, 0x51837da: 0x5183829,
        0x51834c7: 0x5077210, 0x5183452: 0x50a3510, 0x518380a: 0x50a3510,
        0x5183565: 0x50a3510, 0x51835bf: 0x50a3510, 0x5183877: 0x50a3510, 0x51838d1: 0x50a3510,
    }.items():
        if site == 0x51837da:
            raw = spans[site]
            actual = site + len(raw) + struct.unpack("<b", raw[1:])[0]
        else:
            actual = target(site)
        require(actual == callee, f"wrong branch at {site:#x}")
    for site, literal in {
        0x4d8e28b: b"data", 0x4d8e5fb: b"data",
        0x51840c2: b"status", 0x51841a2: b"status",
        0x5183443: b"running", 0x51834b3: b"twapId", 0x51837fb: b"success",
        0x5183556: b"error", 0x5183868: b"error",
    }.items():
        require(read(".rodata", target(site), len(literal)) == literal, f"wrong literal at {site:#x}")
    rela = sections[".rela.dyn"]
    relocations = {slot: (kind, value) for slot, kind, value in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"])
    )}
    for site, label in ((0x4d8e25d, b"twapOrder"), (0x4d8e5cd, b"twapCancel")):
        kind, value = relocations[target(site) + 16]
        require(kind == 8 and read(".rodata", value, len(label)) == label, f"wrong {label!r} dispatch")
    require(spans[0x5183401] == spans[0x51837d5] == b"\x31\xc0"
            and spans[0x5183403] == spans[0x51837d7] == b"\x48\x3b\x07"
            and spans[0x5183406][:2] == b"\x0f\x81" and spans[0x51837da][0] == 0x71,
            "wrong selected twap success representation")
    print(f"verified {len(spans)} static TWAP instruction spans and both named outcomes")


def check(repo, scratch):
    archive = subprocess.check_output(["git", "archive", ENTRY, CRATE], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        for member in files.getmembers():
            name = Path(member.name)
            require(not name.is_absolute() and ".." not in name.parts
                    and (member.isfile() or member.isdir()), "unexpected checkout entry")
        files.extractall(scratch)
    crate = scratch / CRATE
    (crate / "src/twap.rs").write_bytes((PACKET / "twap.rs").read_bytes())
    (crate / "tests/twap_wire.rs").write_bytes((PACKET / "twap_wire.rs").read_bytes())
    module = crate / "src/lib.rs"
    original = module.read_text()
    require(original.count("pub mod entry;") == 1, "wrong original crate snapshot")
    module.write_text(original.replace("pub mod entry;", "pub mod entry;\npub mod twap;"))
    entry = crate / "src/entry.rs"
    original = entry.read_text()
    for old, new in (
        ("    ValidatorVote(bool),", "    ValidatorVote(bool),\n"
         "    TwapOrder(Result<u64, &'a str>),\n    TwapCancel(Result<(), &'a str>),"),
        ("fn quoted_text(", "pub(super) fn quoted_text("),
        ("        ActionResult::Default =>", "        ActionResult::TwapOrder(r) => crate::twap::write_created(out, r)?,\n"
         "        ActionResult::TwapCancel(r) => crate::twap::write_cancelled(out, r)?,\n"
         "        ActionResult::Default =>"),
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
