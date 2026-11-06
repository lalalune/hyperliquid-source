"""Reproduce the static node #115 finalizer evidence from the pinned ELF."""

import hashlib
import re
import struct
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FINALIZER = 0x14193A0


def rel32_references(code, base, target):
    for match in re.finditer(rb"[\xe8\xe9]", code):
        offset = match.start()
        if offset + 5 <= len(code):
            displacement = struct.unpack_from("<i", code, offset + 1)[0]
            if base + offset + 5 + displacement == target:
                yield base + offset


def inspect(stream):
    if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
        raise SystemExit("node #115 SHA-256 mismatch")
    stream.seek(0)
    elf = ELFFile(stream)
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True

    for tag in elf.get_section_by_name(".dynamic").iter_tags():
        if tag.entry.d_tag in {"DT_FINI_ARRAY", "DT_FINI_ARRAYSZ", "DT_FINI"}:
            print(f"{tag.entry.d_tag}: {tag.entry.d_val:#x}")

    fini = elf.get_section_by_name(".fini_array")
    print(f".fini_array: {fini['sh_addr']:#x} {fini.data().hex()}")
    references = {fini["sh_addr"]}
    for label, start, stop in [
        ("finalizer", FINALIZER, 0x14193D9),
        ("helper", 0x1419330, 0x1419359),
        ("PLT", 0x63F0A40, 0x63F0A50),
    ]:
        segment = next(
            s for s in elf.iter_segments(type="PT_LOAD")
            if s["p_vaddr"] <= start < stop <= s["p_vaddr"] + s["p_filesz"]
        )
        offset = start - segment["p_vaddr"] + segment["p_offset"]
        print(f"{label}: VA {start:#x}, file offset {offset:#x}")
        stream.seek(offset)
        for instruction in disassembler.disasm(stream.read(stop - start), start):
            end = instruction.address + instruction.size
            for operand in instruction.operands:
                if operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP:
                    references.add(end + operand.mem.disp)
            print(f"{instruction.address:#x} {instruction.bytes.hex():<16} {instruction.mnemonic} {instruction.op_str}".rstrip())
        assert end == stop

    for address in sorted(references):
        sections = [
            section.name for section in elf.iter_sections()
            if section["sh_flags"] & 2 and section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]
        ]
        print(f"data reference: {address:#x} {' '.join(sections)}")

    for name in (".rela.dyn", ".rela.plt"):
        table = elf.get_section_by_name(name)
        symbols = elf.get_section(table["sh_link"])
        for relocation in table.iter_relocations():
            if relocation["r_offset"] in references or relocation["r_addend"] == FINALIZER:
                symbol = symbols.get_symbol(relocation["r_info_sym"]).name
                print(f"{name}: {relocation['r_offset']:#x} type={relocation['r_info_type']} "
                      f"addend={relocation['r_addend']:#x} {symbol}".rstrip())

    text = elf.get_section_by_name(".text")
    code = text.data()
    base = text["sh_addr"]
    assert 0x14193C7 in list(rel32_references(code, base, 0x1419330))
    candidates = list(rel32_references(code, base, FINALIZER))
    print(f".text [{base:#x}, {base + len(code):#x}) rel32 E8/E9 candidates: {candidates}")
    frames = [
        entry["initial_location"] for entry in elf.get_dwarf_info().EH_CFI_entries()
        if isinstance(entry, FDE)
        and entry["initial_location"] <= FINALIZER < entry["initial_location"] + entry["address_range"]
    ]
    print(f".eh_frame covering FDE starts: {frames}")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node")
    with path.open("rb") as stream:
        inspect(stream)
