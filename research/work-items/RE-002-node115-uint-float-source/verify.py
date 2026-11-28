"""Compare Rust release builds of the unsigned u128-to-binary64 conversion."""
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


print("node #115 sha256", SHA)
target = read(".text", 0x63f00d0, 132)
manifest = build.MANIFEST
results = {}
with TemporaryDirectory() as scratch:
    root = Path(scratch)
    library = build.sources(cache, root, "1.95.0", False)
    for opt in (2, 3):
        work = root / f"opt-{opt}"
        build.MANIFEST = manifest.replace("opt-level = 3", f"opt-level = {opt}")
        archive, compiler, cargo = build.cargo_job(work, cache, library, "1.95.0", False)
        symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
        coordinate, size, _, symbol = next(
            line.split() for line in symbols if line.endswith("13___floatuntidf"))
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(offset, 16) == 0
        obj = work / "conversion.o"
        obj.write_bytes(command("ar", "p", archive, member))
        section = ".text." + symbol
        out = work / "conversion.bin"
        command("objcopy", "--dump-section", f"{section}={out}", obj)
        code = out.read_bytes()
        assert len(code) == int(size, 16)
        reloc = command("objdump", "-r", "-j", section, obj)
        reloc_count = reloc.count(b"R_X86_64_")
        match = code == target and reloc_count == 0
        results[opt] = match
        print(f"opt-{opt} source={len(code)} target={len(target)} relocations={reloc_count} raw-match={match}",
              "source sha256", sha256(code).hexdigest())
assert results[3]
