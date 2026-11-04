#!/usr/bin/env python3
"""Offline checker for the node #115 .eh_frame window census packet.

Reads artifacts/node/115/hl-node in place; the captured binary is never
executed, copied or relocated. The ELF section table and every .eh_frame
CIE/FDE record are parsed from the pinned bytes without binutils. The FDE
census of the declared .text window, the smallest complete function in that
window and its body digest are re-derived from those bytes, and the recorded
evidence.json block must equal the derived block exactly. window.txt objdump
bytes are checked against the target bytes as well.
"""
import argparse
import hashlib
import json
import os
import re
import struct

TARGET_REL = os.path.join("artifacts", "node", "115", "hl-node")
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET_REL = os.path.join("research", "work-items", "RE-001-node115-unworked-leaf")
WINDOW_LO = 0x1A00000
WINDOW_HI = 0x1A40000
LEAF_LIMIT = 120
FORMAT_SIZE = {0x00: 8, 0x02: 2, 0x03: 4, 0x04: 8, 0x0A: 2, 0x0B: 4, 0x0C: 8}
ADDR_LINE = re.compile("^\\s*([0-9a-f]+):\\s+((?:[0-9a-f]{2}\\s+)+)")


def blob_sha256(data):
    return hashlib.sha256(data).hexdigest()


def uleb(data, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated uleb128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("uleb128 overflow")


def sleb(data, pos):
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated sleb128")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                value -= 1 << shift
            return value, pos
        if shift > 63:
            raise ValueError("sleb128 overflow")


def read_encoded(data, pos, encoding, field_va):
    if encoding == 0xFF:
        raise ValueError("DW_EH_PE_omit carries no value")
    fmt = encoding & 0x0F
    app = encoding & 0x70
    if fmt == 0x01:
        value, pos = uleb(data, pos)
    elif fmt == 0x09:
        value, pos = sleb(data, pos)
    elif fmt in FORMAT_SIZE:
        width = FORMAT_SIZE[fmt]
        raw = data[pos:pos + width]
        if len(raw) != width:
            raise ValueError("truncated encoded pointer")
        signed = fmt in (0x0A, 0x0B, 0x0C)
        value = int.from_bytes(raw, "little", signed=signed)
        pos += width
    else:
        raise ValueError("unsupported pointer format 0x%02x" % encoding)
    if app == 0x00:
        return value, pos
    if app == 0x10:
        return field_va + value, pos
    raise ValueError("unsupported pointer application 0x%02x" % encoding)


def read_range(data, pos, encoding):
    fmt = encoding & 0x0F
    if fmt == 0x01:
        return uleb(data, pos)
    if fmt == 0x09:
        return sleb(data, pos)
    if fmt in FORMAT_SIZE:
        width = FORMAT_SIZE[fmt]
        raw = data[pos:pos + width]
        if len(raw) != width:
            raise ValueError("truncated FDE range")
        return int.from_bytes(raw, "little"), pos + width
    raise ValueError("unsupported range format 0x%02x" % encoding)


def elf_sections(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("target is not an ELF image")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("target is not ELF64 little-endian")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shnum == 0 or shstrndx >= shnum:
        raise ValueError("unsupported section table shape")
    raw = []
    for index in range(shnum):
        base = shoff + index * shentsize
        fields = struct.unpack_from("<IIQQQQ", data, base)
        raw.append({"name_off": fields[0], "type": fields[1],
                    "addr": fields[3], "offset": fields[4], "size": fields[5]})
    strings = raw[shstrndx]
    table = data[strings["offset"]:strings["offset"] + strings["size"]]
    for section in raw:
        zero = table.index(b"\x00", section["name_off"])
        section["name"] = table[section["name_off"]:zero].decode("ascii")
    return raw


def section_named(sections, name):
    for section in sections:
        if section["name"] == name:
            return section
    raise ValueError("required section %s is missing" % name)


def section_for_va(sections, va):
    for section in sections:
        if section["addr"] and section["addr"] <= va < section["addr"] + section["size"]:
            return section
    raise ValueError("no section maps VA 0x%x" % va)


def va_to_offset(sections, va):
    section = section_for_va(sections, va)
    return section, section["offset"] + (va - section["addr"])


def parse_cie(data, id_pos, record_end, eh_off, eh_addr):
    pos = id_pos + 4
    version = data[pos]
    pos += 1
    zero = data.index(b"\x00", pos)
    augmentation = data[pos:zero].decode("ascii")
    pos = zero + 1
    code_align, pos = uleb(data, pos)
    data_align, pos = sleb(data, pos)
    if version == 1:
        return_reg = data[pos]
        pos += 1
    else:
        return_reg, pos = uleb(data, pos)
    fde_encoding = 0x00
    personality = None
    if augmentation.startswith("z"):
        aug_len, pos = uleb(data, pos)
        aug_end = pos + aug_len
        if aug_end > record_end:
            raise ValueError("CIE augmentation overruns its record")
        for marker in augmentation[1:]:
            if marker == "R":
                fde_encoding = data[pos]
                pos += 1
            elif marker == "P":
                encoding = data[pos]
                pos += 1
                personality, pos = read_encoded(data, pos, encoding,
                                                eh_addr + (pos - eh_off))
            elif marker == "L":
                pos += 1
            elif marker == "S":
                continue
            else:
                raise ValueError("unsupported CIE augmentation %r" % marker)
        if pos > aug_end:
            raise ValueError("CIE augmentation shorter than its fields")
        pos = aug_end
    return {"version": version, "augmentation": augmentation,
            "code_align": code_align, "data_align": data_align,
            "return_reg": return_reg, "fde_encoding": fde_encoding,
            "personality": personality}


def parse_eh_frame(data, eh_off, eh_addr, eh_size):
    records = []
    pos = eh_off
    end = eh_off + eh_size
    while pos + 4 <= end:
        length32, = struct.unpack_from("<I", data, pos)
        if length32 == 0:
            break
        if length32 == 0xFFFFFFFF:
            length, = struct.unpack_from("<Q", data, pos + 4)
            header = 12
        else:
            length = length32
            header = 4
        id_pos = pos + header
        record_end = id_pos + length
        if record_end > end:
            raise ValueError("truncated .eh_frame record at 0x%x" % pos)
        ident, = struct.unpack_from("<I", data, id_pos)
        records.append((pos, id_pos, ident, record_end))
        pos = record_end
    cies = {}
    for start, id_pos, ident, record_end in records:
        if ident == 0:
            cies[start] = parse_cie(data, id_pos, record_end, eh_off, eh_addr)
    fdes = []
    for _start, id_pos, ident, record_end in records:
        if ident == 0:
            continue
        cie_pos = id_pos - ident
        if cie_pos not in cies:
            raise ValueError("FDE at 0x%x names an unparsed CIE 0x%x" % (id_pos, cie_pos))
        cie = cies[cie_pos]
        pos = id_pos + 4
        field_va = eh_addr + (pos - eh_off)
        start, pos = read_encoded(data, pos, cie["fde_encoding"], field_va)
        length, pos = read_range(data, pos, cie["fde_encoding"])
        if pos > record_end:
            raise ValueError("FDE at 0x%x overruns its record" % id_pos)
        fdes.append({"start": start, "end": start + length, "cie": cie_pos})
    fdes.sort(key=lambda item: item["start"])
    return cies, fdes


def window_fdes(fdes, lo, hi):
    return [item for item in fdes if lo <= item["start"] and item["end"] <= hi]


def smallest_fde(fdes):
    if not fdes:
        raise ValueError("no FDE in the selected window")
    return min(fdes, key=lambda item: (item["end"] - item["start"], item["start"]))


def read_target(root):
    path = os.path.join(root, TARGET_REL)
    with open(path, "rb") as handle:
        data = handle.read()
    digest = blob_sha256(data)
    if digest != TARGET_SHA256:
        raise AssertionError("target digest mismatch: " + digest)
    return data


def derive(root):
    data = read_target(root)
    sections = elf_sections(data)
    eh = section_named(sections, ".eh_frame")
    text = section_named(sections, ".text")
    cies, fdes = parse_eh_frame(data, eh["offset"], eh["addr"], eh["size"])
    inside = window_fdes(fdes, WINDOW_LO, WINDOW_HI)
    leaves = [item for item in inside if item["end"] - item["start"] <= LEAF_LIMIT]
    chosen = smallest_fde(inside)
    _, body_off = va_to_offset(sections, chosen["start"])
    body = data[body_off:body_off + chosen["end"] - chosen["start"]]
    entries = []
    for item in inside:
        _, offset = va_to_offset(sections, item["start"])
        size = item["end"] - item["start"]
        entries.append({"start": "0x%x" % item["start"],
                        "end": "0x%x" % item["end"],
                        "bytes": size,
                        "sha256": blob_sha256(data[offset:offset + size])})
    return {
        "target_sha256": blob_sha256(data),
        "target_bytes": len(data),
        "eh_frame": {"addr": "0x%x" % eh["addr"], "size": eh["size"]},
        "text": {"addr": "0x%x" % text["addr"], "size": text["size"]},
        "cie_count": len(cies),
        "fde_total": len(fdes),
        "cie_augmentations": sorted({cie["augmentation"] for cie in cies.values()}),
        "fde_encodings": ["0x%02x" % value
                          for value in sorted({cie["fde_encoding"]
                                               for cie in cies.values()})],
        "window": {"start": "0x%x" % WINDOW_LO, "end": "0x%x" % WINDOW_HI,
                   "fde_count": len(inside), "leaf_limit_bytes": LEAF_LIMIT,
                   "leaf_count": len(leaves)},
        "smallest": {"start": "0x%x" % chosen["start"],
                     "end": "0x%x" % chosen["end"],
                     "bytes": chosen["end"] - chosen["start"],
                     "sha256": blob_sha256(body),
                     "at_or_below_leaf_limit": bool(leaves)},
        "window_fdes": entries,
    }


def verify_objdump(text, data, sections):
    checked = 0
    for line in text.splitlines():
        match = ADDR_LINE.match(line)
        if match is None:
            continue
        va = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2))
        _, offset = va_to_offset(sections, va)
        if data[offset:offset + len(raw)] != raw:
            raise AssertionError("window.txt bytes disagree at 0x%x" % va)
        checked += 1
    if checked == 0:
        raise ValueError("window.txt carries no instruction bytes")
    return checked


def verify_packet(root):
    derived = derive(root)
    packet = os.path.join(root, PACKET_REL)
    with open(os.path.join(packet, "evidence.json"), "r", encoding="utf-8") as handle:
        evidence = json.load(handle)
    recorded = evidence.get("derived")
    if recorded != derived:
        for key in sorted(set(derived) | set(recorded or {})):
            if (recorded or {}).get(key) != derived.get(key):
                print("mismatch field: %s" % key)
        raise AssertionError("evidence.json derived block disagrees with target bytes")
    expected_frames = []
    for entry in derived["window_fdes"]:
        expected_frames.append("0x%x..0x%x bytes=%d sha256=%s"
                               % (int(entry["start"], 16),
                                  int(entry["end"], 16),
                                  entry["bytes"], entry["sha256"]))
    frames_path = os.path.join(packet, "frames.txt")
    if not os.path.isfile(frames_path):
        raise AssertionError("frames.txt is missing from the packet")
    with open(frames_path, "r", encoding="utf-8") as handle:
        saved_frames = handle.read().splitlines()
    if saved_frames != expected_frames:
        shown = False
        for index in range(min(len(saved_frames), len(expected_frames))):
            if saved_frames[index] != expected_frames[index]:
                print("frames.txt first mismatch at line %d" % (index + 1))
                print("recorded: " + saved_frames[index])
                print("derived:  " + expected_frames[index])
                shown = True
                break
        if not shown:
            print("frames.txt lines recorded=%d derived=%d"
                  % (len(saved_frames), len(expected_frames)))
        raise AssertionError("frames.txt disagrees with the re-derived FDE lines")
    print("frames_txt_lines=%d" % len(expected_frames))
    checked = 0
    window_path = os.path.join(packet, "window.txt")
    if os.path.isfile(window_path):
        data = read_target(root)
        with open(window_path, "r", encoding="utf-8") as handle:
            checked = verify_objdump(handle.read(), data, elf_sections(data))
    return derived, checked


def main(argv=None):
    parser = argparse.ArgumentParser(description="node #115 .eh_frame window census checker")
    parser.add_argument("--root", default=".")
    parser.add_argument("--emit", action="store_true")
    args = parser.parse_args(argv)
    if args.emit:
        print(json.dumps(derive(args.root), indent=2, sort_keys=True))
        return 0
    derived, checked = verify_packet(args.root)
    print("target_sha256=" + derived["target_sha256"])
    print("fde_total=%d" % derived["fde_total"])
    print("window_fde_count=%d" % derived["window"]["fde_count"])
    print("leaf_count=%d" % derived["window"]["leaf_count"])
    print("smallest=%s..%s bytes=%d" % (derived["smallest"]["start"],
                                         derived["smallest"]["end"],
                                         derived["smallest"]["bytes"]))
    print("window_txt_lines=%d" % checked)
    print("checker: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
