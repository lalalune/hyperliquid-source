"""Identify the same zero-and-register sequence in node #115 initializer slots."""

import hashlib
import struct
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CALLBACK = 0x5D36020
REGISTER_PLT = 0x63F0F80
DELETE_PLT = 0x63F0D80
DSO_CELL = 0x64EFA20
SHAPE = bytes.fromhex(
    "f30f1efa 488d3d00000000 660fefc0 488d1500000000 488d3500000000 "
    "48c7050000000000000000 0f290500000000 e900000000"
)
FIELDS = ((7, 11), (18, 22), (25, 29), (32, 40), (43, 47), (48, 52))


def match(code, address):
    masked = bytearray(code)
    for offset, _ in FIELDS:
        masked[offset:offset + 4] = bytes(4)
    if masked != SHAPE:
        return None
    callback, dso, obj, qword, vector, target = (
        address + end + struct.unpack_from("<i", code, offset)[0]
        for offset, end in FIELDS
    )
    if (callback, dso, qword, vector, target) == (CALLBACK, DSO_CELL, obj + 16, obj, REGISTER_PLT):
        return obj
    return None


def read_va(elf, address, size):
    offset, = elf.address_offsets(address, size)
    elf.stream.seek(offset)
    return elf.stream.read(size)


def plt_symbol(elf, plt):
    code = read_va(elf, plt, 6)
    assert code[:2] == bytes.fromhex("ff25")
    got = plt + 6 + struct.unpack_from("<i", code, 2)[0]
    relocations = elf.get_section_by_name(".rela.plt")
    relocation, = [entry for entry in relocations.iter_relocations() if entry["r_offset"] == got]
    assert relocation["r_info_type"] == 7
    return got, elf.get_section(relocations["sh_link"]).get_symbol(relocation["r_info_sym"]).name


def scan(path):
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != DIGEST:
            raise SystemExit("node #115 SHA-256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".init_array")
        start, size = section["sh_addr"], section["sh_size"]
        slots = {}
        for rel in elf.get_section_by_name(".rela.dyn").iter_relocations():
            address = rel["r_offset"]
            if start <= address < start + size:
                assert address not in slots and (rel["r_info_type"], rel["r_info_sym"]) == (8, 0)
                slots[address] = rel["r_addend"]
        assert set(slots) == set(range(start, start + size, 8))

        bss = elf.get_section_by_name(".bss")
        assert bss["sh_type"] == "SHT_NOBITS"
        rows = []
        for slot, target in sorted(slots.items()):
            code = read_va(elf, target, len(SHAPE))
            obj = match(code, target)
            if obj is not None:
                assert bss["sh_addr"] <= obj <= bss["sh_addr"] + bss["sh_size"] - 24
                assert obj % 16 == 0
                rows.append(((slot - start) // 8, target, obj))
        assert len({row[2] for row in rows}) == len(rows)

        _, example, obj = rows[0]
        code = bytearray(read_va(elf, example, len(SHAPE)))
        assert match(code, example) == obj
        for offset in (0, FIELDS[2][0], FIELDS[-1][0]):
            changed = code.copy()
            changed[offset] ^= 1
            assert match(changed, example) is None
        for plt, expected in ((REGISTER_PLT, "__cxa_atexit"), (DELETE_PLT, "_ZdlPvm")):
            got, symbol = plt_symbol(elf, plt)
            assert symbol == expected
            print(f"{plt:#x} -> {got:#x} -> {symbol}")
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for address, length in ((example, len(SHAPE)), (CALLBACK, 0x21)):
            for insn in cs.disasm(read_va(elf, address, length), address):
                print(f"{insn.address:#x} {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}".rstrip())
        print(f"Matched {len(rows)} of {len(slots)} initializer slots")
        print("slot\tentry_va\tobject_va")
        for index, entry, obj in rows:
            print(f"{index}\t{entry:#x}\t{obj:#x}")


if __name__ == "__main__":
    scan(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node"))
