"""Reproduce the node #115 startup argument storage and reader excerpts."""

import hashlib
import sys
from pathlib import Path

import capstone
from elftools.dwarf.callframe import FDE
from elftools.elf.elffile import ELFFile


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = (
    ("array entry", 0x5CA55C0, 0x5CA55D2),
    ("second writer", 0x5C99E07, 0x5C99E19),
    ("reader", 0x5C9A530, 0x5C9A573),
)
CELLS = {0x6500000, 0x6500008}


def inspect(path):
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise SystemExit("node #115 SHA-256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".init_array")
        slot = table["sh_addr"]
        assert table.data()[:8] == bytes(8)
        records = [
            (rel["r_info_type"], rel["r_info_sym"], rel["r_addend"])
            for rel in elf.get_section_by_name(".rela.dyn").iter_relocations()
            if rel["r_offset"] == slot
        ]
        assert records == [(8, 0, WINDOWS[0][1])]
        print(f".init_array[0]: {slot:#x} RELATIVE {records[0][2]:#x}")

        bss = elf.get_section_by_name(".bss")
        assert bss["sh_type"] == "SHT_NOBITS"
        assert all(bss["sh_addr"] <= cell <= bss["sh_addr"] + bss["sh_size"] - 8 for cell in CELLS)
        print(f".bss: {bss['sh_addr']:#x} + {bss['sh_size']:#x} (NOBITS)")

        fdes = [entry for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry, FDE)]
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        disassembler.detail = True
        text = elf.get_section_by_name(".text")
        for label, start, stop in WINDOWS:
            extent, = [
                (entry["initial_location"], entry["initial_location"] + entry["address_range"])
                for entry in fdes
                if entry["initial_location"] <= start < entry["initial_location"] + entry["address_range"]
            ]
            assert stop <= extent[1]
            offset = text["sh_offset"] + start - text["sh_addr"]
            stream.seek(offset)
            print(f"{label}: FDE [{extent[0]:#x}, {extent[1]:#x}), file offset {offset:#x}")
            cells = set()
            end = start
            for insn in disassembler.disasm(stream.read(stop - start), start):
                end = insn.address + insn.size
                resolved = [
                    end + op.mem.disp for op in insn.operands
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP
                ]
                cells.update(resolved)
                suffix = "".join(f" -> {address:#x}" for address in resolved)
                print(f"{insn.address:#x} {insn.bytes.hex():<20} {insn.mnemonic} {insn.op_str}".rstrip() + suffix)
            assert end == stop and cells == CELLS


if __name__ == "__main__":
    inspect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node"))
