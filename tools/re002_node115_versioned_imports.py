#!/usr/bin/env python3
"""Static named binding/version joins for three node115 imports; never executes it."""
import argparse
import json
from pathlib import Path
import struct

import foundation_libstdcxx_abi as elf

PACKET = Path(__file__).resolve().parents[1] / "research/work-items/RE-002-node115-versioned-imports/evidence.json"
VERSIONS = {"GLIBC_2.39", "GLIBCXX_3.4.30"}


def derive(data):
    sections = elf.read_elf_sections(data)
    section = lambda name: elf.single_section(sections, name)
    strings = section(".dynstr")
    def text(offset):
        elf.need(0 <= offset < strings["size"], "string outside .dynstr")
        start = strings["offset"] + offset
        end = data.find(b"\0", start, strings["offset"] + strings["size"])
        elf.need(end >= start, "unterminated .dynstr string")
        return data[start:end].decode("ascii")
    dynamic = elf.read_dynamic(data, sections)
    needs = elf.read_version_need(data, sections, dynamic, text)
    # Reuse the existing full-table shape/index validation before the named join.
    census = elf.read_symbols(data, sections, dynamic, needs["indices"])
    version_records = {}
    vr = section(".gnu.version_r")
    cursor = vr["offset"] + dynamic["values"][elf.DT_VERNEED] - vr["addr"]
    for position in range(needs["count"]):
        revision, count, file_name, aux, nxt = elf.VERNEED.unpack_from(data, cursor)
        entry = cursor + aux
        for number in range(count):
            name_hash, flags, index, name, following = elf.VERNAUX.unpack_from(data, entry)
            version_records[index & 0x7fff] = {
                "library": text(file_name), "version": text(name),
                "verneed_offset": cursor, "vernaux_offset": entry,
                "vernaux_va": vr["addr"] + entry - vr["offset"],
                "version_flags": flags, "version_hash": name_hash,
                "version_name_offset": strings["offset"] + name,
            }
            if number + 1 < count:
                entry += following
        if position + 1 < needs["count"]:
            cursor += nxt
    symbols, versions = section(".dynsym"), section(".gnu.version")
    result = []
    for index in range(census["symbols"]):
        so = symbols["offset"] + index * elf.SYM.size
        vo = versions["offset"] + index * 2
        raw, = struct.unpack_from("<H", data, vo)
        owner = version_records.get(raw & 0x7fff)
        if owner is None or owner["version"] not in VERSIONS:
            continue
        name, info, visibility, shndx, value, size = elf.SYM.unpack_from(data, so)
        result.append(dict(owner, dynsym_index=index, name=text(name),
            binding=info >> 4, symbol_type=info & 15, visibility=visibility,
            section_index=shndx, value=value, size=size, version_index=raw,
            dynsym_offset=so, dynsym_va=symbols["addr"] + so - symbols["offset"],
            versym_offset=vo, versym_va=versions["addr"] + vo - versions["offset"],
            symbol_name_offset=strings["offset"] + name))
    return {"table_census": census, "selected_versions": sorted(VERSIONS), "imports": result}


def observe(data):
    digest = elf.authenticate(data)
    return {"target": {"path": elf.TARGET_RELATIVE, "sha256": digest, "size": len(data)},
            "derived": derive(data)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = observe(Path(elf.target_path()).read_bytes())
    if args.check:
        elf.need(result == json.loads(PACKET.read_text()), "packet differs from authenticated target")
        print("packet matches authenticated target: %d selected imports" % len(result["derived"]["imports"]))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
