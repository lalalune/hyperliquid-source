#!/usr/bin/env python3
"""Compare freshly compiled Decimal source symbols with two #115 display FDEs."""
import hashlib
from io import BytesIO
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import entry_start_static as target
from fde_extents import eh_frame_records

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
DIGITS = 0x5C43040
DISPLAY = 0x5C449C0
SYMBOLS = {
    "digits": re.compile(r"_ZN12rust_decimal3str15to_str_internal17h[0-9a-f]+E"),
    "display": re.compile(r"_ZN69_\$LT\$rust_decimal\.\.decimal\.\.Decimal\$u20\$as\$u20\$core\.\.fmt\.\.Display\$GT\$3fmt17h[0-9a-f]+E"),
}
COMPILER_STAMP = b"rustc version 1.95.0 (59807616e 2026-04-14)"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    require(digest(data) == TARGET_SHA, "wrong capture")
    frames = {r["start"]: r["end"] for r in eh_frame_records(data)[1]
              if r["start"] in (DIGITS, DISPLAY)}
    require(set(frames) == {DIGITS, DISPLAY}, "missing FDE")
    bindings = target.relocations(data)
    target.anchors_ok(data, [(0x41C5AEB, "ff15"), (0x5C449EF, "e8")])
    display_slot = target.rip_target(data, 0x41C5AEB, 2)
    require(bindings.get(display_slot) == (8, DISPLAY), "quantity no longer calls display")
    require(target.rip_target(data, 0x5C449EF, 1) == DIGITS, "display no longer calls digit worker")
    return data, frames, bindings


def symbols_in_archive(ar, archive):
    from elftools.elf.elffile import ELFFile

    members = subprocess.check_output([ar, "t", archive], text=True).splitlines()
    found, exported_data = {}, {}
    for member in members:
        if not member.endswith(".o"):
            continue
        obj = ELFFile(BytesIO(subprocess.check_output([ar, "p", archive, member])))
        require(obj["e_type"] == "ET_REL" and obj["e_machine"] == "EM_X86_64", "wrong public object")
        for sym in obj.get_section_by_name(".symtab").iter_symbols():
            if sym.name and sym["st_info"]["type"] == "STT_OBJECT" and isinstance(sym["st_shndx"], int):
                if sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                    exported_data.setdefault(sym.name, []).append((obj, sym))
            if sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] == "SHN_UNDEF":
                continue
            for key, pattern in SYMBOLS.items():
                if pattern.fullmatch(sym.name):
                    section = obj.get_section(sym["st_shndx"])
                    require(sym["st_value"] == 0 and sym["st_size"] == section["sh_size"]
                            and section.name == ".text." + sym.name, "unexpected symbol extent")
                    require(COMPILER_STAMP in obj.get_section_by_name(".comment").data().split(b"\0"),
                            "compiled object has wrong rustc stamp")
                    require(key not in found, f"ambiguous {key} definition")
                    found[key] = obj, section, sym
    require(found.keys() == SYMBOLS.keys(), "missing comparison symbol (use GNU ar or llvm-ar)")
    return found, exported_data


def underlying(obj, sym, exported_data, extra=0):
    if sym["st_shndx"] == "SHN_UNDEF":
        (obj, sym), = exported_data[sym.name]
    section = obj.get_section(sym["st_shndx"])
    return obj, section, sym["st_value"] + extra


def source_path_tail(raw):
    # Capture and reference may use a vendor tree or different registry roots.
    components = raw.decode("utf-8").split("/")[-3:]
    require(len(components) == 3, "unexpected Location path")
    components[0] = re.sub(r"-\d+\.\d+\.\d+$", "", components[0])
    return "/".join(components)


def location(obj, section, offset, exported_data, data, bindings, dest):
    words = section.data()[offset:offset + 24]
    length, line, column = struct.unpack_from("<QII", words, 8)
    source_rels = obj.get_section_by_name(".rela" + section.name)
    rel, = [r for r in source_rels.iter_relocations() if r["r_offset"] == offset]
    require(rel["r_info_type"] == 1, "expected source Location absolute pointer")
    source_symbols = obj.get_section(source_rels["sh_link"])
    _, path_section, path_offset = underlying(obj, source_symbols.get_symbol(rel["r_info_sym"]), exported_data, rel["r_addend"])
    source_path = path_section.data()[path_offset:path_offset + length]
    target_info, target_path_va = bindings[dest]
    require(target_info == 8, "expected target Location relative pointer")
    target_length, target_line, target_column = struct.unpack("<QII", target.read(data, dest + 8, 16)[1])
    target_path = target.read(data, target_path_va, target_length)[1]
    return {
        "source_tail": source_path_tail(source_path), "target_tail": source_path_tail(target_path),
        "source_line_column": [line, column], "target_line_column": [target_line, target_column],
        "path_bytes_equal": source_path == target_path,
        "tail_line_column_equal": (source_path_tail(source_path), line, column) ==
                                  (source_path_tail(target_path), target_line, target_column),
    }


# Widths come from the load instructions, and the message length from its call argument.
LITERALS = {0x151: 16, 0x31E: 16, 0x326: 16, 0x368: 4, 0x370: 4, 0x58E: 43}
LOCATIONS = {0x572, 0x57B, 0x5A7, 0x5B4, 0x5C4, 0x5D5, 0x5E6, 0x5F3, 0x5FF}


def compare_symbol(item, exported_data, data, frames, bindings, start):
    obj, section, symbol = item
    source = section.data()
    actual = target.read(data, start, frames[start] - start)[1]
    result = {
        "reference_bytes": len(source), "reference_body_sha256": digest(source),
        "target_bytes": len(actual), "target_body_sha256": digest(actual),
        "target_start": hex(start), "same_extent": len(source) == len(actual),
    }
    if len(source) != len(actual):
        return result
    relsec = obj.get_section_by_name(".rela" + section.name)
    require(relsec["sh_info"] == symbol["st_shndx"], "relocations for different section")
    symbols = obj.get_section(relsec["sh_link"])
    fields, rows = set(), []
    for rel in relsec.iter_relocations():
        at, typ = rel["r_offset"], rel["r_info_type"]
        require(typ in (2, 9) and rel["r_addend"] == -4, "unexpected source relocation")
        width = set(range(at, at + 4))
        require(not fields.intersection(width) and at + 4 <= len(source), "invalid relocation field")
        fields.update(width)
        sym = symbols.get_symbol(rel["r_info_sym"])
        dest = start + at + 4 + struct.unpack_from("<i", actual, at)[0]
        row = {"offset": hex(at), "kind": "PC32" if typ == 2 else "GOTPCREL", "destination": hex(dest)}
        if typ == 9:
            info, resolved = bindings[dest]
            require(info == 8 and sym["st_shndx"] == "SHN_UNDEF", "unexpected helper binding")
            row.update(reference_undefined=sym.name, target_relative_addend=hex(resolved))
        else:
            src_obj, src_section, offset = underlying(obj, sym, exported_data)
            if at in LITERALS:
                n = LITERALS[at]
                literal = src_section.data()[offset:offset + n]
                require(len(literal) == n and literal == target.read(data, dest, n)[1], "literal mismatch")
                row["literal_hex"] = literal.hex()
            elif at in LOCATIONS:
                row["location"] = location(src_obj, src_section, offset, exported_data, data, bindings, dest)
            elif at == 0x595:
                # Only the drop/size/alignment words are compared. Method bindings remain open.
                header = src_section.data()[offset:offset + 24]
                require(header == target.read(data, dest, 24)[1], "different vtable header")
                row["vtable_header"] = list(struct.unpack("<QQQ", header))
            else:
                raise ValueError(f"unclassified direct reference at {at:#x}")
        rows.append(row)
    differences = [i for i, (a, b) in enumerate(zip(source, actual)) if i not in fields and a != b]
    result.update(raw_equal_bytes=sum(a == b for a, b in zip(source, actual)),
                  bytes_outside_relocations=len(source) - len(fields), unmasked_difference_count=len(differences),
                  relocations=rows)
    return result


def compare(ar, archive, captured):
    data, frames, bindings = captured
    found, exported_data = symbols_in_archive(ar, archive)
    return {name: compare_symbol(found[name], exported_data, data, frames, bindings, start)
            for name, start in [("digits", DIGITS), ("display", DISPLAY)]}
