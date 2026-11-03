#!/usr/bin/env python3
"""Checker for RE-001-node115-ehframe-hdr-index.

Reads artifacts/node/115/hl-node in place (read-only; never copied, never
executed) and re-derives every value recorded in the packet:

- the .eh_frame_hdr and .eh_frame section geometry (VA, file offset, size);
- the four .eh_frame_hdr header bytes (version, eh_frame_ptr encoding,
  fde_count encoding, binary-search table encoding);
- the resolved eh_frame pointer, the FDE count, and the table address and
  first-slice table bytes;
- the FDE start/size comparison for the first eight index entries.

Each derived value is compared with the packet record
research/work-items/RE-001-node115-ehframe-hdr-index/evidence.json and with
the recorded excerpts header.txt and index.txt. A corrupted copy of the
derived record must be rejected by the same comparison.
"""
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-ehframe-hdr-index")
PACKET_FILES = ("evidence.json", "header.txt", "index.txt")
SLICE = 8
SECTIONS = ("target", "eh_frame_hdr", "eh_frame", "index", "ends_from_fde")


def u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def i16(buf, off):
    return struct.unpack_from("<h", buf, off)[0]


def i32(buf, off):
    return struct.unpack_from("<i", buf, off)[0]


def i64(buf, off):
    return struct.unpack_from("<q", buf, off)[0]


def uleb(buf, pos):
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7


def sleb(buf, pos):
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos


def encoded(buf, pos, enc, field_va, section_va):
    fmt = enc & 0x0F
    base = enc & 0x70
    if fmt == 0x00:
        value = u64(buf, pos)
        pos += 8
    elif fmt == 0x01:
        value, pos = uleb(buf, pos)
    elif fmt == 0x02:
        value = u16(buf, pos)
        pos += 2
    elif fmt == 0x03:
        value = u32(buf, pos)
        pos += 4
    elif fmt == 0x04:
        value = u64(buf, pos)
        pos += 8
    elif fmt == 0x09:
        value, pos = sleb(buf, pos)
    elif fmt == 0x0A:
        value = i16(buf, pos)
        pos += 2
    elif fmt == 0x0B:
        value = i32(buf, pos)
        pos += 4
    elif fmt == 0x0C:
        value = i64(buf, pos)
        pos += 8
    else:
        raise AssertionError("unsupported DW_EH_PE format in 0x%02x" % enc)
    if base == 0x00:
        return value, pos
    if base == 0x10:
        return value + field_va, pos
    if base == 0x30:
        return value + section_va, pos
    raise AssertionError("unsupported DW_EH_PE application in 0x%02x" % enc)


def read_sections(data):
    assert data[:4] == b"\x7fELF", "not an ELF file"
    assert data[4] == 2, "not ELFCLASS64"
    assert data[5] == 1, "not little-endian"
    shoff = u64(data, 0x28)
    shentsize = u16(data, 0x3A)
    shnum = u16(data, 0x3C)
    shstrndx = u16(data, 0x3E)
    assert shentsize == 64, "unexpected section header size %d" % shentsize
    assert shnum > 0, "empty section header table"
    sections = []
    for index in range(shnum):
        off = shoff + index * shentsize
        sections.append({
            "index": index,
            "name_off": u32(data, off),
            "addr": u64(data, off + 16),
            "offset": u64(data, off + 24),
            "size": u64(data, off + 32),
        })
    strtab = sections[shstrndx]
    names = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
    for item in sections:
        end = names.index(b"\x00", item["name_off"])
        item["name"] = names[item["name_off"]:end].decode("ascii")
    return sections


def find_section(sections, name):
    for item in sections:
        if item["name"] == name:
            return item
    raise AssertionError("section %s is missing" % name)


def parse_cie(buf, pos, section_va):
    version = buf[pos]
    pos += 1
    end = buf.index(b"\x00", pos)
    augmentation = buf[pos:end].decode("latin-1")
    pos = end + 1
    _, pos = uleb(buf, pos)
    _, pos = sleb(buf, pos)
    if version == 1:
        pos += 1
    else:
        _, pos = uleb(buf, pos)
    fde_enc = 0x00
    if augmentation.startswith("z"):
        aug_len, pos = uleb(buf, pos)
        stop = pos + aug_len
        cursor = pos
        for char in augmentation[1:]:
            if cursor >= stop:
                break
            if char == "R":
                fde_enc = buf[cursor]
                cursor += 1
            elif char == "P":
                pointer_enc = buf[cursor]
                cursor += 1
                _, cursor = encoded(buf, cursor, pointer_enc, section_va + cursor, section_va)
            elif char == "L":
                cursor += 1
            elif char == "S":
                pass
            else:
                break
        pos = stop
    return {"version": version, "augmentation": augmentation, "fde_enc": fde_enc}


def parse_eh_frame(buf, section_va):
    cies = {}
    fdes = []
    pos = 0
    total = len(buf)
    while pos + 4 <= total:
        length = u32(buf, pos)
        body = pos + 4
        if length == 0:
            pos = body
            continue
        if length == 0xFFFFFFFF:
            length = u64(buf, pos + 4)
            body = pos + 12
        end = body + length
        assert end <= total, "record overruns .eh_frame at offset 0x%x" % pos
        cie_pointer = u32(buf, body)
        if cie_pointer == 0:
            cies[section_va + pos] = parse_cie(buf, body + 4, section_va)
        else:
            cie_va = section_va + body - cie_pointer
            cie = cies.get(cie_va)
            assert cie is not None, "FDE at 0x%x references unknown CIE 0x%x" % (section_va + pos, cie_va)
            cursor = body + 4
            start, cursor = encoded(buf, cursor, cie["fde_enc"], section_va + cursor, section_va)
            size, cursor = encoded(buf, cursor, cie["fde_enc"] & 0x0F, section_va + cursor, section_va)
            fdes.append({"record_va": section_va + pos, "start": start, "size": size})
        pos = end
    return fdes


def derive_records(data):
    digest = hashlib.sha256(data).hexdigest()
    assert digest == TARGET_SHA256, "pinned target digest mismatch: %s" % digest
    sections = read_sections(data)
    header = find_section(sections, ".eh_frame_hdr")
    ehframe = find_section(sections, ".eh_frame")
    assert header["size"] >= 12, ".eh_frame_hdr is shorter than its 12-byte header"
    header_buf = data[header["offset"]:header["offset"] + header["size"]]
    ehframe_buf = data[ehframe["offset"]:ehframe["offset"] + ehframe["size"]]
    version = header_buf[0]
    pointer_enc = header_buf[1]
    count_enc = header_buf[2]
    table_enc = header_buf[3]
    cursor = 4
    pointer, cursor = encoded(header_buf, cursor, pointer_enc, header["addr"] + 4, header["addr"])
    count, cursor = encoded(header_buf, cursor, count_enc, header["addr"] + cursor, header["addr"])
    table_offset = cursor
    entries = []
    offsets = []
    for _ in range(count):
        offsets.append(cursor)
        start, cursor = encoded(header_buf, cursor, table_enc, header["addr"] + cursor, header["addr"])
        fde, cursor = encoded(header_buf, cursor, table_enc, header["addr"] + cursor, header["addr"])
        entries.append({"start": start, "fde": fde})
    starts = [item["start"] for item in entries]
    fdes = parse_eh_frame(ehframe_buf, ehframe["addr"])
    nonzero = sorted(item["start"] for item in fdes if item["start"] != 0)
    slice_entries = entries[:SLICE]
    slice_end = offsets[SLICE] if len(offsets) > SLICE else cursor
    slice_bytes = header_buf[table_offset:slice_end]
    by_record = dict((item["record_va"], item) for item in fdes)
    checked = 0
    positive = 0
    start_mismatches = 0
    end_differs = 0
    for index, entry in enumerate(slice_entries):
        record = by_record.get(entry["fde"])
        if record is None:
            continue
        checked += 1
        if record["start"] != entry["start"]:
            start_mismatches += 1
        if record["size"] > 0:
            positive += 1
        if index + 1 < len(slice_entries):
            if record["start"] + record["size"] != slice_entries[index + 1]["start"]:
                end_differs += 1
    return {
        "target": {
            "release": "node115",
            "path": "artifacts/node/115/hl-node",
            "size": len(data),
            "sha256": digest,
        },
        "eh_frame_hdr": {
            "va": hex(header["addr"]),
            "file_offset": hex(header["offset"]),
            "size": header["size"],
            "version": version,
            "eh_frame_ptr_enc": "0x%02x" % pointer_enc,
            "fde_count_enc": "0x%02x" % count_enc,
            "table_enc": "0x%02x" % table_enc,
            "eh_frame_ptr": hex(pointer),
            "eh_frame_ptr_matches_section": pointer == ehframe["addr"],
            "fde_count": count,
            "table_va": hex(header["addr"] + table_offset),
            "header_hex": header_buf[:32].hex(),
            "header_sha256": hashlib.sha256(header_buf[:32]).hexdigest(),
        },
        "eh_frame": {
            "va": hex(ehframe["addr"]),
            "file_offset": hex(ehframe["offset"]),
            "size": ehframe["size"],
            "fde_records": len(fdes),
            "nonzero_start_records": len(nonzero),
        },
        "index": {
            "entries": count,
            "first_start": hex(starts[0]) if starts else None,
            "last_start": hex(starts[-1]) if starts else None,
            "monotonic_strict": all(starts[i] < starts[i + 1] for i in range(len(starts) - 1)),
            "duplicate_starts": len(starts) - len(set(starts)),
            "missing_fde_starts": len(set(nonzero) - set(starts)),
            "index_only_starts": len(set(starts) - set(nonzero)),
            "slice": [{"start": hex(item["start"]), "fde": hex(item["fde"])} for item in slice_entries],
            "slice_hex": slice_bytes.hex(),
            "slice_sha256": hashlib.sha256(slice_bytes).hexdigest(),
        },
        "ends_from_fde": {
            "records_checked": checked,
            "positive_ranges": positive,
            "start_mismatches": start_mismatches,
            "end_differs_from_next_index_start": end_differs,
        },
    }


def derive():
    assert os.path.isfile(TARGET), "pinned target %s is missing" % TARGET
    with open(TARGET, "rb") as handle:
        data = handle.read()
    return derive_records(data)


def read_packet_text(name):
    with open(os.path.join(PACKET, name), "rb") as handle:
        return handle.read().decode("utf-8")


def pick(node, keys):
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def compare(derived, recorded):
    for section in SECTIONS:
        for key in sorted(derived[section]):
            path = [section, key]
            expected = derived[section][key]
            found = pick(recorded, path)
            assert found == expected, "%s mismatch: derived %r recorded %r" % (".".join(path), expected, found)


def check_excerpts(derived):
    header_text = read_packet_text("header.txt")
    expected_header = derived["eh_frame_hdr"]["header_hex"] + "\n"
    assert header_text == expected_header, "header.txt does not match the derived header bytes"
    index_text = read_packet_text("index.txt")
    expected_index = "".join("%s %s\n" % (item["start"], item["fde"]) for item in derived["index"]["slice"])
    assert index_text == expected_index, "index.txt does not match the derived index slice"


def corruption_control(derived, recorded):
    broken = json.loads(json.dumps(derived))
    broken["eh_frame_hdr"]["version"] = derived["eh_frame_hdr"]["version"] + 1
    try:
        compare(broken, recorded)
    except AssertionError:
        return
    raise AssertionError("corrupted derived header version was accepted")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    derived = derive()
    if "--derive-json" in argv:
        print(json.dumps(derived, indent=2, sort_keys=True))
        return 0
    assert os.path.isdir(PACKET), "packet directory %s is missing" % PACKET
    for name in PACKET_FILES:
        assert os.path.isfile(os.path.join(PACKET, name)), "packet file %s is missing" % name
    recorded = json.loads(read_packet_text("evidence.json"))
    compare(derived, recorded)
    check_excerpts(derived)
    corruption_control(derived, recorded)
    print("packet=%s OK" % os.path.basename(PACKET))
    return 0


if __name__ == "__main__":
    sys.exit(main())
