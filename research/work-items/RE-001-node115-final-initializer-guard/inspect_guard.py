"""Derive the final initializer, its guard, and its first mutex call."""

import hashlib
import struct
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
STATE = 0x64FFAB4
ENTRY = 0x635F320
HELPER = 0x634F0B0
TRYLOCK = 0x63F17B0
WRITES = ((0x634EF6A, 10), (0x634F2D0, 10), (0x634F680, 10))


def read(elf, address, size):
    offset, = elf.address_offsets(address, size)
    elf.stream.seek(offset)
    return elf.stream.read(size)


def inspect(path):
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise SystemExit("node #115 SHA-256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        array = elf.get_section_by_name(".init_array")
        index = array["sh_size"] // 8 - 1
        slot = array["sh_addr"] + index * 8
        binding, = [
            r for r in elf.get_section_by_name(".rela.dyn").iter_relocations()
            if r["r_offset"] == slot
        ]
        assert (binding["r_info_type"], binding["r_info_sym"], binding["r_addend"]) == (8, 0, ENTRY)
        print(f".init_array[{index}] {slot:#x} RELATIVE {ENTRY:#x}")

        data = elf.get_section_by_name(".data")
        assert data["sh_addr"] <= STATE <= data["sh_addr"] + data["sh_size"] - 4
        print(f".data {STATE:#x} initial bytes: {read(elf, STATE, 4).hex()}")

        code = read(elf, TRYLOCK, 6)
        assert code[:2] == bytes.fromhex("ff25")
        got = TRYLOCK + 6 + struct.unpack_from("<i", code, 2)[0]
        plt = elf.get_section_by_name(".rela.plt")
        relocation, = [r for r in plt.iter_relocations() if r["r_offset"] == got]
        assert relocation["r_info_type"] == 7
        name = elf.get_section(plt["sh_link"]).get_symbol(relocation["r_info_sym"]).name
        assert name == "pthread_mutex_trylock"
        print(f"PLT {TRYLOCK:#x} -> GOT {got:#x} -> {name}")

        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        windows = ((ENTRY, 20), (HELPER, 0x39), (0x634F10E, 14), *WRITES)
        for address, length in windows:
            print(f"window [{address:#x}, {address + length:#x})")
            end = address
            for instruction in decoder.disasm(read(elf, address, length), address):
                end = instruction.address + instruction.size
                refs = [
                    end + op.mem.disp for op in instruction.operands
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP
                ]
                if (address, length) in WRITES:
                    assert refs == [STATE]
                suffix = "".join(f" -> {ref:#x}" for ref in refs)
                print(f"{instruction.address:#x} {instruction.bytes.hex()} "
                      f"{instruction.mnemonic} {instruction.op_str}".rstrip() + suffix)
            assert end == address + length


if __name__ == "__main__":
    inspect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node"))
