#!/usr/bin/env python3
"""Verify static CLI evidence; never load or execute captured machine code."""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
TARGET_SIZE = 91774280

def require(value, reason):
    if not value:
        raise ValueError(reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_va(ctx, va, size):
    data, secs, _ = ctx
    offsets = {s["offset"] + va - s["address"] for s in secs
               if s["type"] != 8 and s["address"] <= va
               and va + size <= s["address"] + s["size"]}
    require(len(offsets) == 1, "ambiguous address")
    off = offsets.pop()
    return data[off:off + size]

def anchor(ctx, value):
    raw = bytes.fromhex(value["bytes"])
    require(read_va(ctx, int(value["va"], 16), len(raw)) == raw, "instruction anchor differs")
    return raw

def branch_target(va, raw):
    if raw[:1] == b"\x74" and len(raw) == 2:
        return va + 2 + struct.unpack("<b", raw[1:])[0]
    if raw[:2] == b"\x0f\x84" and len(raw) == 6:
        return va + 6 + struct.unpack("<i", raw[2:])[0]
    raise ValueError("not the recorded equal branch")

def check(ctx, facts):
    data, secs, fdes = ctx
    require(facts["targetSHA256"] == TARGET_SHA256 and facts["targetBytes"] == TARGET_SIZE,
            "wrong target claim")
    require(facts["sourceBase"] == "966865f1637a29ce75b019e1bf11d5529cc6f519", "wrong source base")
    for rec in facts["ranges"]:
        start, end = int(rec["start"], 16), int(rec["end"], 16)
        found = [f for f in fdes if f["start"] == start]
        require(len(found) == 1 and found[0]["end"] == end
                and found[0]["fde"] == int(rec["fde"], 16), "canonical extent differs")
        require(digest(read_va(ctx, start, end - start)) == rec["bodySHA256"], "body digest differs")
        native = gzip.decompress((HERE / rec["nativeFile"]).read_bytes())
        require(digest(native) == rec["nativeStdoutSHA256"], "native export differs")
        pairs = []
        for line in native.decode("utf8").splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)\s*(.*)$", line)
            if m and start <= int(m[1], 16) < end:
                pairs.append((int(m[1], 16), bytes.fromhex(m[2])))
        position = start
        for va, raw in pairs:
            require(va == position and read_va(ctx, va, len(raw)) == raw,
                    "native decode coverage/bytes differ")
            position += len(raw)
        require(position == end and len(pairs) == rec["instructions"], "incomplete native export")

    require(len(facts["fields"]) == 12, "wrong field count")
    names = set()
    for index, field in enumerate(facts["fields"]):
        require(field["outputOffset"] == index and field["name"] not in names, "field identity differs")
        names.add(field["name"])
        raw = anchor(ctx, field["outputStore"])
        require(0x40 <= raw[0] < 0x50 and raw[1] == 0x88
                and raw[2] & 7 == 4 and raw[3] == 0x24
                and 4 + 8 * (raw[0] & 1) == 12, "output store base differs")
        mod = raw[2] >> 6
        offset = 0 if mod == 0 else struct.unpack("<b", raw[4:5])[0] if mod == 1 else None
        require(offset == index, "output displacement differs")
        for query in field["keyQueries"]:
            va = int(query["site"], 16)
            lea = read_va(ctx, va, 7)
            length = read_va(ctx, va + 7, 5)
            require(lea.hex() == query["instruction"] and lea[:3] == b"\x48\x8d\x35",
                    "key LEA differs")
            require(length.hex() == query["lengthInstruction"] and length[0] == 0xba,
                    "key length instruction differs")
            size = struct.unpack("<I", length[1:])[0]
            target = va + 7 + struct.unpack("<i", lea[3:])[0]
            require(size == len(field["name"].encode("ascii"))
                    and read_va(ctx, target, size) == field["name"].encode("ascii"),
                    "key pointer/length differs")
        if field["outputLoad"] is not None:
            load = anchor(ctx, field["outputLoad"])
            require(load == b"\x8b\x4c\x24" + bytes([int(field["outputLoad"]["stackOffset"], 16)]),
                    "output saved-slot load differs")
        edge = field["selectedNameEqualEdge"]
        raw = anchor(ctx, edge)
        require(branch_target(int(edge["va"], 16), raw) == int(edge["destination"], 16),
                "selected-name equal destination differs")
        raw = anchor(ctx, field["selectedNameTrueDefinition"])
        if 0x40 <= raw[0] < 0x50:
            raw = raw[1:]
        require(len(raw) == 2 and 0xb0 <= raw[0] <= 0xb7 and raw[1] == 1,
                "selected-name true byte differs")
        for point in field["comparisonAndFlowAnchors"]:
            anchor(ctx, point)

    for case in facts["style"]["cases"]:
        raw = anchor(ctx, case["tagWrite"])
        tag = 0 if raw == b"\x31\xc0" else raw[1] if len(raw) == 2 and raw[0] == 0xb0 else None
        require(tag == case["tag"], "style tag differs")
        result = [None] * case["length"]
        for fragment in case["fragments"]:
            if fragment["kind"] == "memory":
                part = read_va(ctx, int(fragment["va"], 16), fragment["size"])
            else:
                op = anchor(ctx, fragment["instruction"])
                size = fragment["size"]
                part = op[-size:]
            for n, value in enumerate(part):
                pos = fragment["offset"] + n
                require(0 <= pos < len(result), "style fragment exceeds length")
                require(result[pos] in (None, value), "style fragment overlap differs")
                result[pos] = value
        require(None not in result and bytes(result) == case["text"].encode("ascii"),
                "style literal coverage differs")
    for point in facts["style"]["controlAnchors"]:
        anchor(ctx, point)

    sym = facts["bcmpImport"]
    rela = next(s for s in secs if s["name"] == ".rela.dyn")
    matches = []
    for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
        row = struct.unpack_from("<QQq", data, pos)
        if row[0] == int(sym["slot"], 16):
            matches.append((pos, row))
    require(len(matches) == 1, "ambiguous equality import slot")
    pos, (_, info, addend) = matches[0]
    require(info & 0xffffffff == 6 and info >> 32 == sym["symbolIndex"] and addend == 0,
            "equality symbol relocation differs")
    symbols = next(s for s in secs if s["name"] == ".dynsym")
    strings = next(s for s in secs if s["name"] == ".dynstr")
    name = struct.unpack_from("<I", data, symbols["offset"] + 24 * (info >> 32))[0]
    begin = strings["offset"] + name
    require(data[begin:data.index(b"\0", begin)].decode("ascii") == sym["symbol"] == "bcmp",
            "equality symbol name differs")
    for point in facts["helperAndErrorAnchors"]:
        anchor(ctx, point)

def controls(ctx, facts):
    changes = [
        ("field-name", lambda f: f["fields"][1].__setitem__("name", "write-false")),
        ("field-offset", lambda f: f["fields"][1].__setitem__("outputOffset", 2)),
        ("selected-edge", lambda f: f["fields"][0]["selectedNameEqualEdge"].__setitem__("destination", "0x457936e")),
        ("true-byte", lambda f: f["fields"][0]["selectedNameTrueDefinition"].__setitem__("bytes", "b300")),
        ("style-tag", lambda f: f["style"]["cases"][0].__setitem__("tag", 2)),
        ("style-text", lambda f: f["style"]["cases"][1].__setitem__("text", "responses-and-actions")),
        ("style-fragment", lambda f: f["style"]["cases"][1]["fragments"][1].__setitem__("offset", 4)),
        ("fde-end", lambda f: f["ranges"][0].__setitem__("end", "0x457acee")),
        ("comparison-import", lambda f: f["bcmpImport"].__setitem__("symbol", "memcpy")),
        ("target-identity", lambda f: f.__setitem__("targetSHA256", "0" * 64)),
    ]
    rejected = []
    for name, change in changes:
        mutant = copy.deepcopy(facts)
        change(mutant)
        try:
            check(ctx, mutant)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError("corruption accepted: " + name)
    return rejected

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    args = parser.parse_args()
    facts = json.loads((HERE / "facts.json").read_text(encoding="utf8"))
    expected = {"README.md", "facts.json", "verify.py",
                *[r["nativeFile"] for r in facts["ranges"]]}
    listed = {}
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        value, path = line.split("  ", 1)
        require(path not in listed and path in expected, "foreign/duplicate manifest entry")
        listed[path] = value
    require(set(listed) == expected, "incomplete manifest")
    for path, value in listed.items():
        require(digest((HERE / path).read_bytes()) == value, "packet file changed: " + path)
    for path, value in facts["parserHashes"].items():
        require(digest((ROOT / "tools" / path).read_bytes()) == value, "parser changed: " + path)
    sys.path.insert(0, str(ROOT / "tools"))
    from elf_index import sections
    from fde_extents import eh_frame_records
    data = args.artifact.read_bytes()
    require(len(data) == TARGET_SIZE and digest(data) == TARGET_SHA256, "captured input identity differs")
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    ctx = (data, secs, fdes)
    check(ctx, facts)
    rejected = controls(ctx, facts)
    print(json.dumps({"staticBindingsVerified": True, "ranges": len(facts["ranges"]),
                      "outputBytes": 13, "corruptedClaimsRejected": rejected,
                      "targetExecuted": False, "nativeBehaviorOrEquivalence": False}))
if __name__ == "__main__":
    main()
