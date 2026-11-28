#!/usr/bin/env python3
"""Bind zlib tree descriptors through their source-defined fields and ELF relocations."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import compare, require
from elf_index import sections

# Source declarations in trees.c and the generated trees.h of zlib 1.3.2.
ARRAYS = {
    "static_ltree": ("trees.h", 576, "H"), "static_dtree": ("trees.h", 60, "H"),
    "extra_lbits": ("trees.c", 29, "I"), "extra_dbits": ("trees.c", 30, "I"),
    "extra_blbits": ("trees.c", 19, "I"), "bl_order": ("trees.c", 19, "B"),
}
DESCRIPTORS = {
    (257, 286, 15): ("static_l_desc", "static_ltree", "extra_lbits"),
    (0, 30, 15): ("static_d_desc", "static_dtree", "extra_dbits"),
    (0, 19, 7): ("static_bl_desc", None, "extra_blbits"),
}


def checked(path, checksum):
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == checksum, f"input identity: {path.name}")
    return data


def section_bytes(image, section):
    return image[section["offset"]:section["offset"] + section["size"]]


def array_locations(archive, rodata, base):
    result = {}
    for name, (filename, count, code) in ARRAYS.items():
        source = archive.extractfile("libz-sys-1.1.31/src/zlib/" + filename).read().decode()
        source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
        match = re.search(rf"\b{name}\s*\[[^\]]+\]\s*=\s*\{{(.*?)\}};", source, flags=re.S)
        require(match is not None, f"missing static initializer: {name}")
        numbers = [int(n) for n in re.findall(r"\d+", match[1])]
        data = struct.pack(f"<{count}{code}", *numbers)
        offsets = []
        off = rodata.find(data)
        while off != -1:
            offsets.append(base + off)
            off = rodata.find(data, off + 1)
        require(bool(offsets), f"missing array: {name}")
        result[name] = offsets
        print("array", name, len(data), hashlib.sha256(data).hexdigest(),
              ",".join(hex(va) for va in offsets), sep="\t")
    return result


def descriptor(image, sec, va, relocations, arrays):
    offset = va - sec["address"]
    require(0 <= offset <= sec["size"] - 28, "descriptor outside .data.rel.ro")
    raw_tree, raw_extra, base, elements, bits = struct.unpack_from("<QQiii", image, sec["offset"] + offset)
    require(raw_tree == raw_extra == 0, "unexpected raw pointer values")
    require((base, elements, bits) in DESCRIPTORS, "descriptor scalar layout")
    name, tree, extra = DESCRIPTORS[base, elements, bits]
    pointers = []
    for field, expected in ((va, tree), (va + 8, extra)):
        if expected is None:
            require(field not in relocations, "null tree pointer has a relocation")
            pointers.append("NULL")
        else:
            info, addend = relocations[field]
            require(info == 8 and addend in arrays[expected], f"wrong linked array: {expected}")
            pointers.append(f"{expected}@{addend:#x}")
    return name, pointers, [base, elements, bits]


def replay(crate):
    image = checked(ROOT / "artifacts/node/115/hl-node",
                    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    source = checked(crate, "ff20308ecabd635a2dc1dd5834a86c462cca20efba1d5d3ddab1f8aea3455cb2")
    sec = {s["name"]: s for s in sections(image)}
    rodata = sec[".rodata"]
    with tarfile.open(fileobj=io.BytesIO(source)) as ar:
        arrays = array_locations(ar, section_bytes(image, rodata), rodata["address"])
    directory = PACKET.parent / "RE-002-node115-vendor-census"
    doc = json.loads(checked(directory / "census.json",
                     "cf08908c4648115c71f5e323737047eb7ee0f0e5dc1a80ba7e33d9ec88c66f94"))
    blob = (directory / "bodies.bin").read_bytes()
    rel = {where: (info, addend) for where, info, addend in struct.iter_unpack(
        "<QQq", section_bytes(image, sec[".rela.dyn"]))}
    seen = set()
    destinations = []
    for row in doc["records"]:
        if row["crate"] != "libz-sys" or row["symbol"] not in ("_tr_init", "_tr_flush_block"):
            continue
        start, end = row["start"], row["end"]
        p = sec[".text"]["offset"] + start - sec[".text"]["address"]
        body = image[p:p + end - start]
        reference = blob[row["source_offset"]:row["source_offset"] + end - start]
        require(hashlib.sha256(body).hexdigest() == row["target_body_sha256"] and
                hashlib.sha256(reference).hexdigest() == row["source_body_sha256"], "census window sha")
        require(compare(reference, body, row["relocations"])["relocation_qualified"], "census window mismatch")
        fields = [f for f in row["relocations"] if f["kind"] == 2]
        print("root", row["symbol"], hex(start), hex(end), len(fields), "PC32", sep="\t")
        for field in fields:
            off = field["offset"]
            require((field["addend"], field["width"]) == (-4, 4), "unsupported PC32 field")
            va = start + off + 4 + struct.unpack_from("<i", body, off)[0]
            if row["symbol"] == "_tr_init":
                name, pointers, scalars = descriptor(image, sec[".data.rel.ro"], va, rel, arrays)
                require(name not in seen, "duplicate descriptor")
                seen.add(name)
                print("descriptor", hex(start + off), hex(va), name, *pointers, *scalars, sep="\t")
            elif va in arrays["bl_order"]:
                destinations.append(va)
                print("ordering", hex(start + off), hex(va), body[off - 3:off + 4].hex(), sep="\t")
    require(len(seen) == 3 and len(destinations) == 1 and len(arrays["bl_order"]) == 2,
            "descriptor or code-length order ownership differs")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate", type=Path, help="pinned libz-sys 1.1.31 crate archive")
    replay(parser.parse_args().crate)
