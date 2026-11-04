#!/usr/bin/env python3
"""Derive the node #115 dynamic symbol-version requirements from pinned bytes.

Static analysis only. The pinned capture in artifacts/node/115/hl-node is read
in place and never executed, copied or written. Every value printed or compared
here is computed from those bytes. The committed packet under
research/work-items/RE-002-node115-libstdcxx-abi/ records the same values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

TARGET_RELATIVE = os.path.join("artifacts", "node", "115", "hl-node")
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

SECTION_NAMES = (".dynsym", ".dynstr", ".dynamic", ".gnu.version", ".gnu.version_r", ".text")
SHT_NOBITS = 8
SH_SIZE_OFFSET = 32
DT_NULL = 0
DT_NEEDED = 1
DT_VERSYM = 0x6FFFFFF0
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF
SHDR = struct.Struct("<IIQQQQIIQQ")
SYM = struct.Struct("<IBBHQQ")
VERNEED = struct.Struct("<HHIII")
VERNAUX = struct.Struct("<IHHII")


class DerivationError(AssertionError):
    """Raised when the pinned bytes violate an invariant recorded by the packet."""


def need(condition, message):
    if not condition:
        raise DerivationError(message)


def read_elf_sections(data):
    need(len(data) >= 64, "file is shorter than the ELF header")
    need(data[:4] == b"\x7fELF", "missing ELF magic")
    need(data[4] == 2, "not an ELFCLASS64 file")
    need(data[5] == 1, "not an ELFDATA2LSB file")
    (shoff,) = struct.unpack_from("<Q", data, 0x28)
    (shentsize,) = struct.unpack_from("<H", data, 0x3A)
    (shnum,) = struct.unpack_from("<H", data, 0x3C)
    (shstrndx,) = struct.unpack_from("<H", data, 0x3E)
    need(shentsize == SHDR.size, "unexpected section header size %d" % shentsize)
    need(shnum >= 1, "no section header table")
    need(shstrndx < shnum, "section name table index %d is out of range" % shstrndx)
    need(shoff + shnum * shentsize <= len(data), "section header table is outside the file")
    headers = []
    for index in range(shnum):
        header_offset = shoff + index * shentsize
        headers.append((header_offset, SHDR.unpack_from(data, header_offset)))
    name_header = headers[shstrndx][1]
    need(name_header[4] + name_header[5] <= len(data), "section name table is outside the file")
    name_blob = data[name_header[4]:name_header[4] + name_header[5]]
    sections = {}
    for header_offset, values in headers:
        end = name_blob.find(b"\x00", values[0])
        need(end >= 0, "unterminated section name")
        label = name_blob[values[0]:end].decode("utf-8")
        entry = {
            "header_offset": header_offset,
            "type": values[1],
            "addr": values[3],
            "offset": values[4],
            "size": values[5],
            "entsize": values[9],
        }
        if entry["type"] != SHT_NOBITS:
            need(entry["offset"] + entry["size"] <= len(data), "section %r is outside the file" % label)
        else:
            need(entry["offset"] <= len(data), "section %r starts outside the file" % label)
        sections.setdefault(label, []).append(entry)
    return sections


def single_section(sections, name):
    found = sections.get(name, [])
    need(len(found) == 1, "expected exactly one %s section, found %d" % (name, len(found)))
    return found[0]


def read_dynamic(data, sections):
    section = single_section(sections, ".dynamic")
    need(section["entsize"] in (0, 16), "unexpected .dynamic entry size %d" % section["entsize"])
    need(section["size"] % 16 == 0, ".dynamic size is not a multiple of 16")
    needed = []
    values = {}
    offsets = {}
    terminated = False
    for index in range(section["size"] // 16):
        entry_offset = section["offset"] + index * 16
        need(entry_offset + 16 <= len(data), ".dynamic entry is outside the file")
        tag, value = struct.unpack_from("<qQ", data, entry_offset)
        if tag == DT_NULL:
            terminated = True
            break
        if tag == DT_NEEDED:
            needed.append((entry_offset, value))
            continue
        need(tag not in values, "duplicate .dynamic tag 0x%x" % tag)
        values[tag] = value
        offsets[tag] = entry_offset
    need(terminated, ".dynamic table is not DT_NULL-terminated")
    need(needed, ".dynamic has no DT_NEEDED entry")
    return {"needed": needed, "values": values, "offsets": offsets}


def read_version_need(data, sections, dynamic, dynstr):
    section = single_section(sections, ".gnu.version_r")
    values = dynamic["values"]
    need(DT_VERNEED in values, ".dynamic has no DT_VERNEED")
    need(DT_VERNEEDNUM in values, ".dynamic has no DT_VERNEEDNUM")
    addr = values[DT_VERNEED]
    count = values[DT_VERNEEDNUM]
    need(count >= 1, "DT_VERNEEDNUM is zero")
    need(section["addr"] <= addr < section["addr"] + section["size"], "DT_VERNEED points outside .gnu.version_r")
    cursor = section["offset"] + (addr - section["addr"])
    limit = section["offset"] + section["size"]
    records = []
    indices = {}
    for position in range(count):
        need(cursor + VERNEED.size <= limit, "version-need record %d is outside .gnu.version_r" % position)
        revision, entry_count, file_offset, aux_offset, next_offset = VERNEED.unpack_from(data, cursor)
        need(entry_count >= 1, "version-need record %d has no entries" % position)
        file_name = dynstr(file_offset)
        need(next_offset != 0 or position == count - 1, "version-need chain ends before record %d" % count)
        need(aux_offset >= VERNEED.size, "version-need aux offset points inside its own header")
        aux = cursor + aux_offset
        entries = []
        for entry in range(entry_count):
            need(aux + VERNAUX.size <= limit, "version-need aux record is outside .gnu.version_r")
            _entry_hash, _flags, other, entry_name_offset, entry_next = VERNAUX.unpack_from(data, aux)
            index = other & 0x7FFF
            need(index >= 2, "version-need index %d is reserved" % index)
            need(index not in indices, "duplicate version-need index %d" % index)
            name = dynstr(entry_name_offset)
            need(name != "", "empty version-need name at index %d" % index)
            indices[index] = (file_name, name)
            entries.append({"index": index, "name": name})
            if entry + 1 < entry_count:
                need(entry_next >= VERNAUX.size, "version-need aux chain does not advance")
                aux += entry_next
        records.append({"file": file_name, "revision": revision, "entries": entries})
        if position + 1 < count:
            need(next_offset >= VERNEED.size, "version-need chain does not advance")
            cursor += next_offset
    return {"addr": "0x%x" % addr, "count": count, "records": records, "indices": indices}


def read_symbols(data, sections, dynamic, indices):
    version = single_section(sections, ".gnu.version")
    symbols = single_section(sections, ".dynsym")
    values = dynamic["values"]
    need(DT_VERSYM in values, ".dynamic has no DT_VERSYM")
    need(values[DT_VERSYM] == version["addr"],
         "DT_VERSYM 0x%x does not match .gnu.version 0x%x" % (values[DT_VERSYM], version["addr"]))
    need(version["size"] % 2 == 0, ".gnu.version size is odd")
    need(symbols["size"] % SYM.size == 0, ".dynsym size is not a multiple of %d" % SYM.size)
    count = version["size"] // 2
    symbol_count = symbols["size"] // SYM.size
    need(count == symbol_count,
         "version index count %d does not match %d dynamic symbols" % (count, symbol_count))
    table = struct.unpack_from("<%dH" % count, data, version["offset"])
    carriers = 0
    defined = 0
    for index in range(symbol_count):
        raw = table[index]
        need((raw & 0x8000) == 0, "hidden version index at dynamic symbol %d" % index)
        if raw < 2:
            continue
        need(raw in indices, "version index %d has no version-need record" % raw)
        carriers += 1
        _name_offset, _info, _other, section_index, _value, size = SYM.unpack_from(
            data, symbols["offset"] + index * SYM.size)
        if section_index != 0 and size > 0:
            defined += 1
    return {
        "symbols": symbol_count,
        "version_indices": count,
        "version_carriers": carriers,
        "defined_nonempty_versioned": defined,
    }


def derive(data):
    sections = read_elf_sections(data)
    geometry = {}
    for name in SECTION_NAMES:
        section = single_section(sections, name)
        geometry[name] = {
            "addr": "0x%x" % section["addr"],
            "offset": "0x%x" % section["offset"],
            "size": "0x%x" % section["size"],
        }
    dynstr_section = single_section(sections, ".dynstr")
    need(dynstr_section["size"] > 0, ".dynstr is empty")
    dynstr_blob = data[dynstr_section["offset"]:dynstr_section["offset"] + dynstr_section["size"]]
    need(dynstr_blob.endswith(b"\x00"), ".dynstr does not end with a NUL byte")

    def dynstr(offset):
        need(0 <= offset < len(dynstr_blob), "string offset 0x%x is outside .dynstr" % offset)
        end = dynstr_blob.find(b"\x00", offset)
        need(end >= 0, "unterminated .dynstr string at 0x%x" % offset)
        return dynstr_blob[offset:end].decode("utf-8")

    dynamic = read_dynamic(data, sections)
    needed = [dynstr(value) for _offset, value in dynamic["needed"]]
    version_need = read_version_need(data, sections, dynamic, dynstr)
    symbols = read_symbols(data, sections, dynamic, version_need["indices"])
    return {
        "sections": geometry,
        "needed": needed,
        "version_need": {
            "addr": version_need["addr"],
            "num": version_need["count"],
            "records": version_need["records"],
            "indices": len(version_need["indices"]),
        },
        "dynsym": symbols,
    }


def corruption_controls(data):
    base = derive(data)
    sections = read_elf_sections(data)
    dynamic = read_dynamic(data, sections)
    dynstr_section = single_section(sections, ".dynstr")
    version_need_section = single_section(sections, ".gnu.version_r")
    start = version_need_section["offset"] + (dynamic["values"][DT_VERNEED] - version_need_section["addr"])
    _revision, _entries, file_offset, aux_offset, _next = VERNEED.unpack_from(data, start)
    aux = start + aux_offset
    _hash, _flags, _other, name_offset, _entry_next = VERNAUX.unpack_from(data, aux)
    first_file_byte = dynstr_section["offset"] + file_offset
    first_name_byte = dynstr_section["offset"] + name_offset
    need(data[first_name_byte:first_name_byte + 8] == b"GLIBCXX_",
         "first version-need name is not GLIBCXX_*")
    version_header = single_section(sections, ".gnu.version")["header_offset"]
    dynsym_header = single_section(sections, ".dynsym")["header_offset"]

    def mutate(offset, replacement):
        copy = bytearray(data)
        copy[offset:offset + len(replacement)] = replacement
        return bytes(copy)

    controls = []

    def expect_rejected(label, blob):
        try:
            derive(blob)
        except DerivationError as error:
            controls.append({"control": label, "outcome": "rejected", "detail": str(error)})
            return
        raise DerivationError("corruption control %r was accepted" % label)

    def expect_changed(label, blob, field):
        mutated = derive(blob)
        if mutated[field] == base[field]:
            raise DerivationError("corruption control %r did not change %s" % (label, field))
        controls.append({"control": label, "outcome": "changed", "detail": field})

    expect_rejected("truncated file", data[:len(data) // 2])
    expect_rejected("broken ELF magic", mutate(1, b"X"))
    expect_rejected("zero DT_VERNEED", mutate(dynamic["offsets"][DT_VERNEED], struct.pack("<Q", 0)))
    expect_rejected("zero DT_VERNEEDNUM", mutate(dynamic["offsets"][DT_VERNEEDNUM], struct.pack("<Q", 0)))
    expect_rejected(
        "short .gnu.version",
        mutate(version_header + SH_SIZE_OFFSET,
               struct.pack("<Q", single_section(sections, ".gnu.version")["size"] - 2)),
    )
    expect_rejected(
        "short .dynsym",
        mutate(dynsym_header + SH_SIZE_OFFSET,
               struct.pack("<Q", single_section(sections, ".dynsym")["size"] - SYM.size)),
    )
    expect_changed("altered needed-file name", mutate(first_file_byte, b"X"), "needed")
    expect_changed("altered version name", mutate(first_name_byte, b"X"), "version_need")
    return controls


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def target_path(root=None):
    return os.path.join(root or repo_root(), TARGET_RELATIVE)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def authenticate(data):
    need(len(data) == TARGET_SIZE, "target size %d does not match %d" % (len(data), TARGET_SIZE))
    digest = hashlib.sha256(data).hexdigest()
    need(digest == TARGET_SHA256, "target sha256 %s does not match %s" % (digest, TARGET_SHA256))
    return digest


def summary(path=None):
    data = read_bytes(path or target_path())
    digest = authenticate(data)
    result = {"target": {"sha256": digest, "size": len(data)}}
    result.update(derive(data))
    return result


def compare_packet(packet, derived):
    evidence_path = os.path.join(packet, "evidence.json")
    need(os.path.isfile(evidence_path), "missing %s" % evidence_path)
    with open(evidence_path, "r", encoding="utf-8") as handle:
        evidence = json.load(handle)
    recorded = evidence.get("derived")
    need(isinstance(recorded, dict), "evidence.json has no derived object")
    for key in sorted(set(recorded) | set(derived)):
        if recorded.get(key) != derived.get(key):
            raise DerivationError("packet value %r differs from the pinned bytes" % (key,))
    return True


def print_summary(derived):
    print("target size %d" % derived["target"]["size"])
    print("target sha256 %s" % derived["target"]["sha256"])
    for name in SECTION_NAMES:
        entry = derived["sections"][name]
        print("section %-15s addr %s offset %s size %s" % (name, entry["addr"], entry["offset"], entry["size"]))
    for name in derived["needed"]:
        print("DT_NEEDED %s" % name)
    version = derived["version_need"]
    print("DT_VERNEED %s DT_VERNEEDNUM %d" % (version["addr"], version["num"]))
    for record in version["records"]:
        print("verneed file %s revision %d entries %d" %
              (record["file"], record["revision"], len(record["entries"])))
        for entry in record["entries"]:
            print("  index %d %s" % (entry["index"], entry["name"]))
    symbols = derived["dynsym"]
    print("dynsym symbols %d version indices %d" % (symbols["symbols"], symbols["version_indices"]))
    print("symbols carrying a version-need index %d" % symbols["version_carriers"])
    print("defined non-empty versioned symbols %d" % symbols["defined_nonempty_versioned"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Derive node #115 dynamic symbol-version requirements.")
    parser.add_argument("--target", default=None, help="path to the pinned hl-node capture")
    parser.add_argument("--packet", default=None, help="packet directory holding evidence.json")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--skip-controls", action="store_true")
    args = parser.parse_args(argv)
    data = read_bytes(args.target or target_path())
    digest = authenticate(data)
    derived = derive(data)
    if not args.skip_controls:
        corruption_controls(data)
    result = {"target": {"sha256": digest, "size": len(data)}}
    result.update(derived)
    if args.format == "text":
        print_summary(result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    if args.packet:
        compare_packet(args.packet, result)
        print("packet matches the pinned bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
