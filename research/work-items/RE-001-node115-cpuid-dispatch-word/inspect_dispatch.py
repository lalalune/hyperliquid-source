"""Trace the node #115 initializer's two-bit CPU dispatch word."""

import hashlib
import re
import struct
import sys
from collections import Counter
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
INIT = 0x5D20090
END = 0x5D200C3
WORD = 0x65000D0
TEST = re.compile(rb"\xf7\x05(?=.{4}[\x01\x02]\x00\x00\x00)", re.DOTALL)


def gates(code, base):
    for match in TEST.finditer(code):
        offset = match.start()
        end = offset + 10
        displacement, mask = struct.unpack_from("<iI", code, offset + 2)
        if base + end + displacement == WORD:
            yield offset, mask


def inspect(path):
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise SystemExit("node #115 SHA-256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        array = elf.get_section_by_name(".init_array")
        slot = array["sh_addr"] + 16
        rel, = [r for r in elf.get_section_by_name(".rela.dyn").iter_relocations() if r["r_offset"] == slot]
        assert (rel["r_info_type"], rel["r_info_sym"], rel["r_addend"]) == (8, 0, INIT)
        print(f".init_array[2] {slot:#x} RELATIVE {INIT:#x}")
        bss = elf.get_section_by_name(".bss")
        assert bss["sh_type"] == "SHT_NOBITS"
        assert bss["sh_addr"] <= WORD <= bss["sh_addr"] + bss["sh_size"] - 4
        print(f"dispatch word: {WORD:#x} in .bss")
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        text = elf.get_section_by_name(".text")
        base, code = text["sh_addr"], text.data()
        init = list(cs.disasm(code[INIT - base:END - base], INIT))
        assert init[-1].address + init[-1].size == END and init[-1].mnemonic == "ret"
        for insn in init:
            print(f"{insn.address:#x} {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}".rstrip())
        print("test_va\tmask\ttaken_va")
        counts = Counter()
        for offset, mask in gates(code, base):
            test, branch = list(cs.disasm(code[offset:offset + 16], base + offset, count=2))
            assert (test.mnemonic, branch.mnemonic) == ("test", "jne")
            counts[mask] += 1
            print(f"{test.address:#x}\t{mask:#x}\t{branch.op_str}")
        print(f".text [{base:#x}, {base + len(code):#x}) gate counts: mask 1={counts[1]}, mask 2={counts[2]}")

        known = 0x5D20108
        sample = bytearray(code[known - base:known - base + 10])
        assert list(gates(sample, known)) == [(0, 2)]
        sample[2] ^= 1
        assert list(gates(sample, known)) == []


if __name__ == "__main__":
    inspect(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node"))
