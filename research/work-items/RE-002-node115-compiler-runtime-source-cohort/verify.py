#!/usr/bin/env python3
"""Verify the rebuilt functions against the historical ELF, without executing it."""
import argparse
import json
import re
from hashlib import sha256
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import compare, require, unique_object
from elf_index import sections

CAPTURE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CENSUS_SHA = "08f67f5d5e55e50093f766f87a4ff858e8e9e589841c0fb3ed06578a7feccc5c"
STARTS = {
    "udivti3": 0x63EFEC0, "floattidf": 0x63F0160, "trunc": 0x63EFF80,
    "decimal-round": 0x167E8D0, "cstr-from-bytes-with-nul": 0x167E030,
    "memchr-aligned": 0x16818B0, "powidf2": 0x63F0080, "lemire-compute-float": 0x167C730,
    "count-chars": 0x1681020, "grapheme-extend": 0x1682BF0,
}

# Referent contents from the unlinked Rust 1.95.0 objects. The constant-pool
# symbols have zero st_size; their extents are the .rodata.cst{8,16} entry
# sizes. The three array lengths come from the defining ELF symbols/sections.
REFERENTS = {
    "one-f64": (8, "6c3c396ed6b5c36dcae172271f462051b1266b851e92df3deea8ac65478fd712"),
    "count-mask": (16, "771f3666f9791d1600c47ac05f075634e900a1f0b7e1fcd2a0c440989ac21d9b"),
    "count-lanes": (16, "814dd7b9784d57c15b9c2972e9b4fd6cf7e164f8162a934bdb2452a413dab1f7"),
    "count-ones": (16, "cc8cd41cef907c4d216069122c4b89936211361f9050a717a1e37ad1862e952f"),
    "SHORT_OFFSET_RUNS": (132, "74a57086cfa31046603dbd9303a69c7b479f87de8e4cdcdf407696733e32d7fd"),
    "OFFSETS": (767, "fd33f755f4392970b809c21f6207c5b16813db98c7e85fa1a029c2f620291ad7"),
    "POWER_OF_FIVE_128": (10416, "dae47e3594bb0b39d42660ef3fe3dc5de5885c0a29ae0e5c21a39e79669efe86"),
}

FIELD_REFERENTS = {
    "powidf2": {25: "one-f64", 57: "one-f64"},
    "count-chars": {108: "count-mask", 116: "count-lanes", 246: "count-mask",
                    254: "count-lanes", 594: "count-ones"},
    "grapheme-extend": {26: "SHORT_OFFSET_RUNS", 203: "OFFSETS"},
    "lemire-compute-float": {72: "POWER_OF_FIVE_128"},
}


SYMBOL_PATTERNS = {
    "one-f64": r"\.LCPI1_0", "count-mask": r"\.LCPI0_0",
    "count-lanes": r"\.LCPI0_1", "count-ones": r"\.LCPI0_2",
    "SHORT_OFFSET_RUNS": r"\.rodata\._RNvNtNtNtC[a-zA-Z0-9]+_4core7unicode12unicode_data15grapheme_extend17SHORT_OFFSET_RUNS",
    "OFFSETS": r"\.rodata\._RNvNtNtNtC[a-zA-Z0-9]+_4core7unicode12unicode_data15grapheme_extend7OFFSETS",
    "POWER_OF_FIVE_128": r"_RNvNtNtNtC[a-zA-Z0-9]+_4core3num7dec2flt5table17POWER_OF_FIVE_128",
}


def digest(data):
    return sha256(data).hexdigest()


def cut(image, section, va, length):
    delta = va - section["address"]
    require(0 <= delta and 0 < length <= section["size"] - delta,
            f"range {va:#x}+{length} outside {section['name']}")
    offset = section["offset"] + delta
    return image[offset:offset + length]


def verify_referents(ident, row, body, image, by_name, got):
    names = FIELD_REFERENTS.get(ident, {})
    require(set(names) == {r["offset"] for r in row["relocations"]}, f"{ident}: wrong field set")
    diagnostics = row["relocation_targets"]
    require([r["offset"] for r in diagnostics] == [r["offset"] for r in row["relocations"]],
            f"{ident}: objdump field order differs")
    for field, diagnostic in zip(row["relocations"], diagnostics):
        off = field["offset"]
        name = names[off]
        kind = 9 if name == "POWER_OF_FIVE_128" else 2
        require((field["kind"], field["width"], field["addend"]) == (kind, 4, -4),
                f"{ident}+{off}: unexpected x86-64 relocation")
        require(diagnostic["kind_name"] == ("GOTPCREL" if kind == 9 else "PC32") and
                re.fullmatch(SYMBOL_PATTERNS[name] + r"-0x0*4", diagnostic["expression"]),
                f"{ident}+{off}: source relocation expression differs")
        # disp32 = S + A - P (or GOT slot + A - P).
        address = row["start"] + off + struct.unpack_from("<i", body, off)[0] - field["addend"]
        if kind == 9:
            cut(image, by_name[".got"], address, 8)
            require(address in got and got[address][0] == 8,
                    "expected R_X86_64_RELATIVE with zero symbol index at GOT slot")
            address = got[address][1]
        size, expected = REFERENTS[name]
        require(digest(cut(image, by_name[".rodata"], address, size)) == expected,
                f"{ident}+{off} does not refer to {name}")


def index_rows(rows):
    by_id = {r["id"]: r for r in rows}
    require(len(rows) == len(by_id) and by_id.keys() == STARTS.keys(), "unexpected cohort")
    return by_id


def unpack_blob(blob, rows):
    parts = {}
    consumed = 0
    for row in rows:
        start, size = row["source_offset"], row["source_size"]
        require(type(start) is int and type(size) is int and start == consumed and size > 0,
                "invalid source extent")
        part = blob[start:start + size]
        require(len(part) == size and digest(part) == row["source_body_sha256"], "source body hash")
        parts[row["id"]] = part
        consumed += size
    require(consumed == len(blob), "unaccounted source bytes")
    return parts


def verify(packet=HERE):
    image = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    require(len(image) == 105896032 and digest(image) == CAPTURE_SHA, "node115 capture identity")
    census = (HERE.parent / "RE-002-node115-std-census/census.json").read_bytes()
    require(digest(census) == CENSUS_SHA, "historical census digest")
    prior = {r["start"]: r for r in json.loads(census)["records"]}
    by_name = {s["name"]: s for s in sections(image)}
    rela = by_name[".rela.dyn"]
    dynamic = struct.iter_unpack("<QQq", cut(image, rela, rela["address"], rela["size"]))
    # Only retain entries that may govern the selected GOTPCREL field.
    slots = by_name[".got"]
    got = {}
    for addr, info, addend in dynamic:
        if slots["address"] <= addr < slots["address"] + slots["size"]:
            require(addr not in got, "duplicate dynamic relocation on GOT slot")
            got[addr] = (info, addend)
    doc = json.loads((packet / "build-results.json").read_bytes(), object_pairs_hook=unique_object)
    builds = doc["builds"]
    require([b["label"] for b in builds] == ["build-a", "build-b", "control"], "build labels")
    require(doc["records"] == builds[0]["records"], "primary build record differs")
    require(doc["target"] == "x86_64-unknown-linux-gnu" and
            [(b["rust_release"], b["rustc_commit"]) for b in builds] ==
            [("1.95.0", "59807616e1fa2540724bfbac14d7976d7e4a3860")] * 2 +
            [("1.94.1", "e408947bfd200af42db322daf0fadfe7e26d3bd1")], "toolchain identities")
    require(builds[0]["records"] == builds[1]["records"] and
            builds[0]["archives"] == builds[1]["archives"], "replica build differs")
    rows = index_rows(doc["records"])
    refs = json.loads((packet / "source-referents.json").read_bytes(), object_pairs_hook=unique_object)
    expected = []
    for row in doc["records"]:
        for off, name in FIELD_REFERENTS.get(row["id"], {}).items():
            size, checksum = REFERENTS[name]
            expected.append({"id": row["id"], "offset": off, "source_size": size, "source_sha256": checksum})
    require(refs == {"rust_release": "1.95.0", "references": expected}, "rebuilt source referents differ")
    replica = index_rows(builds[1]["records"])
    control = index_rows(builds[2]["records"])
    blob = (packet / "bodies.bin").read_bytes()
    source = unpack_blob(blob, doc["records"])
    unpack_blob(blob, builds[1]["records"])
    older = unpack_blob((packet / "control-1.94.1.bin").read_bytes(), builds[2]["records"])
    raw, fields, controls = 0, 0, {}
    for ident, start in STARTS.items():
        row = rows[ident]
        historical = prior[start]
        for result in (row, replica[ident], control[ident]):
            require((result["start"], result["end"], result["target_body_sha256"]) ==
                    (start, historical["end"], historical["target_body_sha256"]), f"{ident}: target extent/hash")
        for result in (row, replica[ident]):
            require(result["census_symbol"] == historical["symbol"] and
                    result["dependency"] == historical["dependency"] and
                    result["relocations"] == historical["relocations"], f"{ident}: census identity or RELA mismatch")
        body = cut(image, by_name[".text"], start, row["end"] - start)
        require(digest(body) == historical["target_body_sha256"], f"{ident}: target function digest")
        matched = compare(source[ident], body, row["relocations"])
        require(matched["relocation_qualified"], f"{ident}: changed bytes outside relocation fields")
        raw += int(matched["raw_equal"])
        fields += len(row["relocations"])
        verify_referents(ident, row, body, image, by_name, got)
        old = older[ident]
        if len(old) != len(body):
            controls[ident] = "different extent"
        else:
            result = compare(old, body, control[ident]["relocations"])
            controls[ident] = ("raw equal" if result["raw_equal"] else
                               "qualified equal" if result["relocation_qualified"] else "different body")
    expected_controls = {ident: "different extent" for ident in STARTS}
    for ident in ("floattidf", "trunc", "cstr-from-bytes-with-nul", "memchr-aligned"):
        expected_controls[ident] = "raw equal"
    expected_controls["grapheme-extend"] = "qualified equal"
    require(controls == expected_controls, "unexpected 1.94.1 control outcomes")
    require(raw == 6 and fields == 10, "unexpected raw-equal/relocation totals")
    print(f"10 source functions verified; {raw} raw equal; {fields} resolved data references.")
    print("1.94.1 control: 5 different extents, 4 raw equal, 1 relocation-qualified equal.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", nargs="?", type=Path, default=HERE, help="rebuild output directory")
    verify(parser.parse_args().packet)
