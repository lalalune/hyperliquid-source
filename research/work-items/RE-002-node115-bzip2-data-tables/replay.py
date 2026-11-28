#!/usr/bin/env python3
"""Resolve the two public libbzip2 lookup arrays against node #115 offline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import compare, require
from elf_index import sections

CRATE = "bzip2-sys-0.1.13+1.0.8"
TABLES = {"BZ2_crc32Table": ("crctable.c", 256), "BZ2_rNums": ("randtable.c", 512)}


def digest(content):
    return hashlib.sha256(content).hexdigest()


def checked(path, checksum):
    content = path.read_bytes()
    require(digest(content) == checksum, f"wrong file identity: {path.name}")
    return content


def initializer(archive, symbol, filename, count):
    path = f"{CRATE}/bzip2-1.0.8/{filename}"
    source = archive.extractfile(path).read().decode("ascii")
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    match = re.search(rf"\b{symbol}\s*\[\s*{count}\s*\]\s*=\s*\{{([^}}]+)\}};", source)
    require(match is not None, f"missing initializer for {symbol}")
    values = [int(x.strip().rstrip("L"), 0) for x in match[1].strip().rstrip(",").split(",")]
    return struct.pack(f"<{count}I", *values)


def locate(image, section, data):
    offset = image.find(data)
    require(offset >= 0 and image.find(data, offset + 1) == -1, "expected one entire table in ELF")
    relative = offset - section["offset"]
    require(0 <= relative <= section["size"] - len(data), "table outside .data")
    return section["address"] + relative


def report(crate):
    image = checked(ROOT / "artifacts/node/115/hl-node",
                    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    source = checked(crate, "225bff33b2141874fe80d71e07d6eec4f85c5c216453dd96388240f96e1acc14")
    by_name = {s["name"]: s for s in sections(image)}
    targets = {}
    with tarfile.open(fileobj=io.BytesIO(source)) as archive:
        for symbol, (filename, count) in TABLES.items():
            data = initializer(archive, symbol, filename, count)
            address = locate(image, by_name[".data"], data)
            targets[address] = symbol
            print(f"# {symbol} {address:#x} {len(data)} bytes sha256={digest(data)}")

    directory = HERE.parent / "RE-002-node115-vendor-census"
    census = json.loads(checked(directory / "census.json",
                        "cf08908c4648115c71f5e323737047eb7ee0f0e5dc1a80ba7e33d9ec88c66f94"))
    blob = (directory / "bodies.bin").read_bytes()
    text = by_name[".text"]
    rows = [r for r in census["records"] if r["crate"] == "bzip2-sys"]
    print("function\tfield_va\tcensus_kind\tsource_instruction\tlinked_instruction\ttable")
    eligible = 0
    resolved = 0
    for row in sorted(rows, key=lambda r: r["start"]):
        size = row["end"] - row["start"]
        start = row["start"] - text["address"] + text["offset"]
        body = image[start:start + size]
        src = blob[row["source_offset"]:row["source_offset"] + size]
        require(digest(src) == row["source_body_sha256"] and digest(body) == row["target_body_sha256"],
                "historical body digest mismatch")
        require(compare(src, body, row["relocations"])["relocation_qualified"], "source body mismatch")
        for field in row["relocations"]:
            off = field["offset"]
            if field.get("relaxation") != "gotpcrelx-mov-lea":
                continue
            eligible += 1
            address = row["start"] + off + 4 + struct.unpack_from("<i", body, off)[0]
            if address in targets:
                resolved += 1
                require((field["kind"], field["width"], field["addend"]) == (42, 4, -4),
                        "unexpected GOTPCRELX form")
                old, new = src[off - 3:off + 4], body[off - 3:off + 4]
                require(new[0] & 0xf8 == 0x48 and new[1] == 0x8d and new[2] & 0xc7 == 5,
                        "expected RIP-relative 64-bit LEA")
                print(row["symbol"], hex(row["start"] + off), field["kind"],
                      old.hex(), new.hex(), targets[address], sep="\t")

    print(f"# {len(rows)} bzip2-sys roots; {resolved}/{eligible} MOV-to-LEA fields bind to the two tables")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate", type=Path, help=f"path to {CRATE}.crate")
    report(parser.parse_args().crate)
