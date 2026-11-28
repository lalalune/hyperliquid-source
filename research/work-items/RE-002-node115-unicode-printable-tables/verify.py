"""Rebuild Rust core and verify six Unicode printable lookup tables."""
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
target_va = 0x1681aa0
target = read(".text", target_va, 0x2b4)
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    build.cargo_job(work / "probe", cache, library, "1.95.0", False)
    archive, = (work / "probe").glob("target/x86_64-unknown-linux-gnu/release/deps/libcore-*.rlib")
    symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
    coordinate, length, _, symbol = next(line.split() for line in symbols if line.endswith("12is_printable"))
    _, member, offset = coordinate.rsplit(":", 2)
    assert int(offset, 16) == 0 and int(length, 16) == len(target)
    obj = work / "printable.o"
    obj.write_bytes(command("ar", "p", archive, member))
    section = ".text." + symbol
    lines = command("objdump", "-r", "-j", section, obj).decode()
    relocations = re.findall(r"^([a-f0-9]+)\s+(R_X86_64_\w+)\s+(\S+)-0x0*4$", lines, re.M)
    selected = [(int(f, 16), sym) for f, kind, sym in relocations
                if kind == "R_X86_64_PC32" and sym.startswith("anon.")]
    assert {offset for offset, _ in selected} == {0x35, 0x3c, 0xca, 0xd1, 0x1cd, 0x22c}
    print(f"body VA {target_va:#x} size {len(target)}; six lookup data edges")
    for offset, sym in selected:
        out = work / "table.bin"
        command("objcopy", "--dump-section", f".rodata.{sym}={out}", obj)
        data = out.read_bytes()
        location = target_va + offset + 4 + struct.unpack_from("<i", target, offset)[0]
        current = read(".rodata", location, len(data))
        assert current == data and data
        assert bytes([data[0] ^ 1]) + data[1:] != current
        print(f"PC32 +{offset:#x} -> {location:#x}, {len(data)} bytes sha256 {sha256(data).hexdigest()}")
    print("six single-byte table mutations fail the data comparisons")
