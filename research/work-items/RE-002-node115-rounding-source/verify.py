"""Rebuild and compare the selected binary64 rounding helpers and their data."""
from hashlib import sha256
import importlib.util
from pathlib import Path
import re
import struct
import subprocess as sp
import sys
from tempfile import TemporaryDirectory

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
source = ROOT / "research/work-items/RE-002-node115-umodti3-source-build/build.py"
spec = importlib.util.spec_from_file_location("release_build", source)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
cache, tools = [Path(x).resolve() for x in sys.argv[1:3]]
node = (ROOT / "artifacts/node/115/hl-node").read_bytes()
assert sha256(node).hexdigest() == SHA
layout = {s["name"]: s for s in sections(node)}


def read(section, va, length):
    item = layout[section]
    delta = va - item["address"]
    assert 0 <= delta <= item["size"] - length
    off = item["offset"] + delta
    return node[off:off + length]


def command(tool, *args):
    return sp.check_output([str(tools / tool), *map(str, args)], stderr=sp.DEVNULL)


expected = {
    "ceil": (0x63f08e0, 119, 8, {0x69, 0x72}),
    "floor": (0x63effe0, 148, 8, {0x83}),
    "round": (0x63efe40, 113, 16, {0x8, 0x14}),
}
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    archive, compiler, cargo = build.cargo_job(work / "probe", cache, library, "1.95.0", False)
    print(compiler, cargo, sep="\n")
    symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
    for name, (va, length, width, fields) in expected.items():
        row, = [line.split() for line in symbols
                if re.search(fr"libm_math{len(name)}{name}{len(name)}{name}$", line)]
        coordinate, size, binding, symbol = row
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(offset, 16) == 0 and int(size, 16) == length and binding == "T"
        obj = work / f"{name}.o"
        obj.write_bytes(command("ar", "p", archive, member))
        section = ".text." + symbol

        def section_bytes(label):
            out = work / "section.bin"
            command("objcopy", "--dump-section", f"{label}={out}", obj)
            return out.read_bytes()

        body = section_bytes(section)
        target = read(".text", va, length)
        assert len(body) == length
        reloc = command("objdump", "-r", "-j", section, obj).decode()
        items = re.findall(r"^([0-9a-f]+)\s+R_X86_64_PC32\s+(\.LCPI\w+)-0x0*4$", reloc, re.M)
        assert {int(index, 16) for index, _ in items} == fields
        assert sum("R_X86_64_" in line for line in reloc.splitlines()) == len(fields)
        syms = command("objdump", "-t", obj).decode().splitlines()
        mask = set()
        for index, referent in items:
            index = int(index, 16)
            sym, = [line.split() for line in syms if line.split() and line.split()[-1] == referent]
            data_offset = int(sym[0], 16)
            constants = section_bytes(f".rodata.cst{width}")
            constant = constants[data_offset:data_offset + width]
            location = va + index + 4 + struct.unpack_from("<i", target, index)[0]
            assert len(constant) == width and read(".rodata", location, width) == constant
            mask.update(range(index, index + 4))
            print(name, f"PC32@+{index:#x}", f"-> {location:#x}", constant.hex())
        assert all(a == b for i, (a, b) in enumerate(zip(body, target)) if i not in mask)
        changed = bytes([body[0] ^ 1]) + body[1:]
        assert any(a != b for i, (a, b) in enumerate(zip(changed, target)) if i not in mask)
        print(name, f"{length-len(mask)}/{length} bytes outside relocation fields match",
              "source sha256", sha256(body).hexdigest())
