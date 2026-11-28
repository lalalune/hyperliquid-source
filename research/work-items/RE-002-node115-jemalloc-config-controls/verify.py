#!/usr/bin/env python3
"""Walk node #115's actual jemalloc control dispatch tree without invoking it."""
import argparse
from hashlib import sha256
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
from fde_extents import eh_frame_records

CRATE_SHA = "cd8aa5b2ab86a2cefa406d889139c162cbb230092f7d1d7cbc1716405d852a3b"
NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CENSUS_SHA = "5fbf755f2590ef67eb974f560ec7b9412711f38ed909c4b320e44e0adfc80fb1"


def checked(path, checksum):
    b = path.read_bytes()
    require(sha256(b).hexdigest() == checksum, f"input hash: {path.name}")
    return b


def declaration(archive):
    checked(archive, CRATE_SHA)
    with tarfile.open(archive) as ar:
        ctl, = [n for n in ar.getnames() if n.endswith("/jemalloc/src/ctl.c")]
        source = ar.extractfile(ctl).read().decode()
    def names(table):
        entries = re.search(rf"\b{table}_node\[\]\s*=\s*\{{(.*?)\n\}};", source, re.S)[1]
        return re.findall(r'NAME\("([^"]+)"\)', entries)
    leaves = names("config")
    types = dict(re.findall(r"CTL_RO_CONFIG_GEN\(config_(\w+), (bool|const char \*)\)", source))
    require(set(leaves) == types.keys(), "source table and declarations differ")
    return names("root"), [(name, types[name]) for name in leaves]


def analyze(image, roots, leaves, census, blob):
    sec = {s["name"]: s for s in sections(image)}
    def read(section, addr, length):
        s = sec[section]
        relative = addr - s["address"]
        require(0 <= relative <= s["size"] - length, f"outside {section}")
        return image[s["offset"] + relative:s["offset"] + relative + length]

    def rel32(addr):
        return addr + 4 + struct.unpack("<i", read(".text", addr, 4))[0]

    def cstring(addr):
        b = read(".rodata", addr, 128)
        return b[:b.index(0)].decode("ascii")

    s = sec[".rela.dyn"]
    reloc = {addr: addend for addr, info, addend in struct.iter_unpack("<QQq", read(".rela.dyn", s["address"], s["size"])) if info == 8}
    # SysV x86-64 ctl_named_node_t: bool/padding, name, count, children, function.
    def node(addr):
        named, name, count, children, fn = struct.unpack("<B7xQQQQ", read(".data.rel.ro", addr, 40))
        require(named == 1 and name == children == fn == 0, "unexpected named-node representation")
        return cstring(reloc[addr + 8]), count, reloc.get(addr + 24), reloc.get(addr + 32)

    require(read(".text", 0x63a890c, 3) == bytes.fromhex("488d35") and
            read(".text", 0x63a891c, 1) == b"\xe8" and rel32(0x63a891d) == 0x636e340 and
            read(".text", 0x63a892f, 4) == bytes.fromhex("488b4020") and
            read(".text", 0x63a8952, 2) == bytes.fromhex("ffd0"), "ctl_byname dispatch changed")
    super_root = rel32(0x63a890f)
    name, count, table, fn = node(super_root)
    require((name, count, fn) == ("", len(roots), None), "wrong super-root")
    require([node(table + 40*i)[0] for i in range(count)] == roots, "root node ordering")
    parent = table + 40 * roots.index("config")
    name, count, children, fn = node(parent)
    require((name, count, fn) == ("config", len(leaves), None), "config parent")
    _, fdes = eh_frame_records(image)
    ends = {fde["start"]: fde["end"] for fde in fdes}
    result = []
    for i, (expected, typ) in enumerate(leaves):
        leaf = children + 40*i
        name, count, descendants, addr = node(leaf)
        require((name, count, descendants) == (expected, 0, None) and addr in ends, "unexpected terminal")
        body = read(".text", addr, ends[addr] - addr)
        if typ == "bool":
            require(body[34:38] == bytes.fromhex("c6442407") and
                    body[49:58] == bytes.fromhex("498b004883f801751e") and
                    body[58:60] == bytes.fromhex("c601") and body[38] == body[60] in (0, 1),
                    "bool temporary, caller length or output store differs")
            value = bool(body[60])
        else:
            require(body[35:38] == bytes.fromhex("488d15") and
                    body[59:68] == bytes.fromhex("498b084883f908752c") and
                    body[68:71] == bytes.fromhex("488910"), "expected C string pointer getter")
            value = cstring(rel32(addr + 38))
        result.append(dict(name="config." + name, leaf=hex(leaf), handler=hex(addr), end=hex(ends[addr]),
                           sha256=sha256(body).hexdigest(), value=value))

    # The old grouped source comparison authenticates code independently of the
    # table. Preserve the candidate set and use its five rows only for this test.
    rows = [r for r in census["records"] if r["symbol"] == "config_stats_ctl"]
    tied = {int(row["handler"], 16): row["name"].replace(".", "_") + "_ctl"
            for row in result if row["value"] is True}
    require(len(rows) == len(tied) == 5 and tied.keys() == {r["start"] for r in rows}, "group membership")
    for r in rows:
        body = read(".text", r["start"], r["end"] - r["start"])
        start = r["source_offset"]
        source = blob[start:start + len(body)]
        require(set(r["candidate_symbols"]) == set(tied.values()) and
                sha256(body).hexdigest() == r["target_body_sha256"] and
                sha256(source).hexdigest() == r["source_body_sha256"] and
                compare(source, body, r["relocations"])["relocation_qualified"], "group evidence")
    return dict(super_root=hex(super_root), root_table=hex(table), config_parent=hex(parent),
                config_table=hex(children), controls=result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate", type=Path)
    args = parser.parse_args()
    target = checked(ROOT / "artifacts/node/115/hl-node", NODE_SHA)
    directory = HERE.parent / "RE-002-node115-native-libs-wave2-census"
    census = json.loads(checked(directory / "census.json", CENSUS_SHA))
    output = analyze(target, *declaration(args.crate), census, (directory / "bodies.bin").read_bytes())
    print(json.dumps(output, indent=2))
