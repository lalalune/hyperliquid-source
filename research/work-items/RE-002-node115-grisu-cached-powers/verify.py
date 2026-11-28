"""Verify the rebuilt Grisu cached-power table and both target references."""
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


capture = build.capture


def force_frames(args, **kwargs):
    if "build" in args:
        kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"] += "\x1f-Cforce-frame-pointers=yes"
    return capture(args, **kwargs)


build.capture = force_frames
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    build.cargo_job(work / "probe", cache, library, "1.95.0", False)
    archive, = (work / "probe").glob("target/x86_64-unknown-linux-gnu/release/deps/libcore-*.rlib")
    symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()

    def get(suffix):
        row, = [line.split() for line in symbols if line.endswith(suffix)]
        coordinate, size, _, symbol = row
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(offset, 16) == 0
        path = work / "selected.o"
        path.write_bytes(command("ar", "p", archive, member))
        return path, int(size, 16), symbol

    obj, length, table = get("12CACHED_POW10")
    out = work / "table.bin"
    command("objcopy", "--dump-section", f".rodata.{table}={out}", obj)
    source_bytes = out.read_bytes()
    assert len(source_bytes) == length == 0x510
    slots = set()
    for suffix, va, extent, offset, opcode in [
        ("16format_exact_opt", 0x1682ee0, 0x408, 0x91, "488b3d"),
        ("19format_shortest_opt", 0x16832f0, 0x663, 0x103, "4c8b05"),
    ]:
        obj, actual, name = get(suffix)
        assert actual == extent
        reloc = command("objdump", "-r", "-j", ".text." + name, obj).decode()
        assert re.search(fr"^0*{offset:x}\s+R_X86_64_GOTPCREL\s+{re.escape(table)}-0x0*4$", reloc, re.M)
        operand = read(".text", va + offset - 3, 7)
        assert operand[:3].hex() == opcode
        slot = va + offset + 4 + struct.unpack_from("<i", operand, 3)[0]
        slots.add(slot)
        print(f"{va:#x}+{offset:#x} -> GOT {slot:#x}")
    slot, = slots
    rela = layout[".rela.dyn"]
    file_start = rela["offset"]
    row, = [r for r in struct.iter_unpack("<QQq", node[file_start:file_start + rela["size"]])
            if r[0] == slot]
    assert row[1] == 8
    table_va = row[2]
    target_bytes = read(".rodata", table_va, length)
    assert target_bytes == source_bytes
    assert source_bytes[:-1] + bytes([source_bytes[-1] ^ 1]) != target_bytes
    print(f"RELATIVE {slot:#x} -> {table_va:#x}; {length} exact bytes sha256 {sha256(source_bytes).hexdigest()}")
    print("table mutation rejected")
