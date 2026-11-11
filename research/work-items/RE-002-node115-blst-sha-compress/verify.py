"""Verify three blst SHA compression bodies against the pinned node ELF."""

import hashlib
import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = (
    ("blst_sha256_block_data_order", 0x5D20100),
    ("blst_sha256_block_data_order_shaext", 0x5D21240),
    ("blst_sha256_block_ssse3", 0x5D21580),
)
CAP = 0x65000D0


def symbol_base(rel, obj, symbols, constants):
    symbol = symbols.get_symbol(rel["r_info_sym"])
    if symbol.name == "__blst_platform_cap":
        return CAP, symbol.name
    assert symbol["st_info"]["type"] == "STT_SECTION"
    section = obj.get_section(symbol["st_shndx"])
    assert section.name == ".rodata"
    return constants, section.name


def patched(body, fixups, start):
    result = bytearray(body)
    for offset, addend, target, _ in fixups:
        struct.pack_into("<i", result, offset, target + addend - (start + offset))
    return result


def verify(reference, binary):
    with reference.open("rb") as source, binary.open("rb") as target:
        assert hashlib.file_digest(target, "sha256").hexdigest() == SHA256
        target.seek(0)
        obj, elf = ELFFile(source), ELFFile(target)
        src_text = obj.get_section_by_name(".text").data()
        dst_text = elf.get_section_by_name(".text")
        src_data = obj.get_section_by_name(".rodata").data()
        dst_data = elf.get_section_by_name(".rodata")
        constants = dst_data.data().find(src_data)
        assert constants >= 0 and constants == dst_data.data().rfind(src_data)
        constants += dst_data["sh_addr"]
        print(f"unique .rodata match: {len(src_data)} bytes at {constants:#x}, "
              f"SHA-256 {hashlib.sha256(src_data).hexdigest()}")
        dst = dst_text.data()
        relocs = obj.get_section_by_name(".rela.text")
        symbols = obj.get_section(relocs["sh_link"])
        for name, start in WINDOWS:
            sym, = symbols.get_symbol_by_name(name)
            offset, length = sym["st_value"], sym["st_size"]
            body = src_text[offset:offset + length]
            actual = dst[start - dst_text["sh_addr"]:start - dst_text["sh_addr"] + length]
            fixups = []
            for rel in relocs.iter_relocations():
                position = rel["r_offset"] - offset
                if 0 <= position < length:
                    assert rel["r_info_type"] == 2 and position + 4 <= length
                    address, label = symbol_base(rel, obj, symbols, constants)
                    fixups.append((position, rel["r_addend"], address, label))
            assert fixups and patched(body, fixups, start) == actual
            first, *rest = fixups
            pos, addend, address, label = first
            assert patched(body, [(pos, addend, address + 1, label), *rest], start) != actual
            raw = sum(a == b for a, b in zip(body, actual))
            print(f"{name} {start:#x}..{start + length:#x}: {raw}/{length} raw-equal bytes, "
                  f"target SHA-256 {hashlib.sha256(actual).hexdigest()}")
            for pos, addend, address, label in fixups:
                print(f"  offset {pos:#x}: {label}={address:#x}, addend={addend}, R_X86_64_PC32")


if __name__ == "__main__":
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
