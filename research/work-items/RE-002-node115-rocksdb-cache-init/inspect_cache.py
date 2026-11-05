"""Bind #115 initializer slot 3 to the two RocksDB cache option tables."""

import hashlib
import sys
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile


SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ENTRY = 0x5D41FA0
START, END = 0x5D411E0, 0x5D41F9A
STRING_HELPER = 0x5D3F5F0
REGISTER = 0x63F0F80
KEYS = (
    ("capacity", "num_shard_bits", "strict_capacity_limit", "high_pri_pool_ratio", "low_pri_pool_ratio"),
    ("capacity", "num_shard_bits", "compression_type", "compress_format_version", "enable_custom_split_merge"),
)


def load(path):
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise SystemExit("node #115 SHA-256 mismatch")
        stream.seek(0)
        elf = ELFFile(stream)
        array = elf.get_section_by_name(".init_array")
        slot = array["sh_addr"] + 24
        binding, = [r for r in elf.get_section_by_name(".rela.dyn").iter_relocations() if r["r_offset"] == slot]
        assert (binding["r_info_type"], binding["r_info_sym"], binding["r_addend"]) == (8, 0, ENTRY)
        print(f".init_array[3] {slot:#x} RELATIVE {ENTRY:#x}")
        text = elf.get_section_by_name(".text")
        code = text.data()
        base = text["sh_addr"]
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        cs.detail = True
        entry = list(cs.disasm(code[ENTRY - base:ENTRY - base + 9], ENTRY))
        assert [i.mnemonic for i in entry] == ["endbr64", "jmp"] and entry[-1].operands[0].imm == START
        print(f"{entry[-1].address:#x} {entry[-1].bytes.hex()} jmp {START:#x}")
        decoded = list(cs.disasm(code[START - base:END - base], START))
        assert decoded[-1].address + decoded[-1].size == END
        rodata = elf.get_section_by_name(".rodata")
        constants = rodata.data()
        base = rodata["sh_addr"]

        groups = [[]]
        for index, insn in enumerate(decoded):
            if insn.mnemonic in {"call", "jmp"} and insn.op_str == f"{REGISTER:#x}":
                print(f"{insn.address:#x} {insn.bytes.hex()} {insn.mnemonic} {REGISTER:#x}")
                groups.append([])
            if insn.mnemonic != "lea" or not insn.op_str.startswith("rsi, [rip"):
                continue
            address = insn.address + insn.size + insn.operands[1].mem.disp
            if not base <= address < base + len(constants):
                continue
            calls = [i for i in decoded[index + 1:index + 21] if i.mnemonic == "call"]
            if not calls or calls[0].op_str != f"{STRING_HELPER:#x}":
                continue
            key = constants[address - base:address - base + 80].split(bytes(1))[0].decode("ascii")
            groups[-1].append(key)
            print(f"{insn.address:#x} {insn.bytes.hex()} -> {address:#x} {key}; helper call {calls[0].address:#x}")
        assert tuple(tuple(group) for group in groups) == (*KEYS, ())
        for insn in decoded:
            if insn.address in {0x5D41865, 0x5D4186C, 0x5D41873, 0x5D41CE6, 0x5D41E3B, 0x5D41E46, 0x5D41E49}:
                resolved = [insn.address + insn.size + o.mem.disp for o in insn.operands
                            if o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP]
                targets = "".join(f" -> {value:#x}" for value in resolved)
                print(f"{insn.address:#x} {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}{targets}")

        plt_offset = next(elf.address_offsets(REGISTER, 6))
        stream.seek(plt_offset)
        jump, = cs.disasm(stream.read(6), REGISTER)
        got = jump.address + jump.size + jump.operands[0].mem.disp
        rels = elf.get_section_by_name(".rela.plt")
        relocation, = [r for r in rels.iter_relocations() if r["r_offset"] == got]
        name = elf.get_section(rels["sh_link"]).get_symbol(relocation["r_info_sym"]).name
        assert relocation["r_info_type"] == 7 and name == "__cxa_atexit"
        print(f"PLT {REGISTER:#x} -> GOT {got:#x} -> {name}")


if __name__ == "__main__":
    load(Path(sys.argv[1]) if len(sys.argv) == 2 else Path("artifacts/node/115/hl-node"))
