"""Compare source-built RawVec error dispatch and the linked diagnostic."""
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
build.BUILD_STD = "-Zbuild-std=core,compiler_builtins,alloc"
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    build.cargo_job(work / "probe", cache, library, "1.95.0", False)
    archive, = (work / "probe").glob("target/x86_64-unknown-linux-gnu/release/deps/liballoc-*.rlib")
    symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
    rela = layout[".rela.dyn"]
    relas = list(struct.iter_unpack("<QQq", node[rela["offset"]:rela["offset"] + rela["size"]]))
    for suffix, va, length, fields in [
        ("raw_vec12handle_error", 0x141e264, 21, {0xb, 0x11}),
        ("raw_vec17capacity_overflow", 0x141e280, 29, {7, 0xe, 0x19}),
    ]:
        row, = [line.split() for line in symbols if line.endswith(suffix)]
        coordinate, size, _, symbol = row
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(offset, 16) == 0 and int(size, 16) == length
        obj = work / "selected.o"
        obj.write_bytes(command("ar", "p", archive, member))
        section = ".text.unlikely." + symbol

        def dump(section_name):
            out = work / "out.bin"
            out.unlink(missing_ok=True)
            command("objcopy", "--dump-section", f"{section_name}={out}", obj)
            return out.read_bytes()

        body = dump(section)
        target = read(".text", va, length)
        assert len(body) == length
        reloc = command("objdump", "-r", "-j", section, obj).decode()
        items = [(int(pos, 16), kind, name) for pos, kind, name in re.findall(
            r"^([a-f0-9]+)\s+(R_X86_64_(?:GOTPCREL|PC32))\s+(\S+)-0x0*4$", reloc, re.M)]
        assert {offset for offset, _, _ in items} == fields
        assert reloc.count("R_X86_64_") == len(items)
        masked = {byte for offset, _, _ in items for byte in range(offset, offset + 4)}
        assert all(a == b for i, (a, b) in enumerate(zip(body, target)) if i not in masked)
        assert (body[0] ^ 1) != target[0] and 0 not in masked
        print(f"{va:#x} {suffix}: {length - len(masked)}/{length} match outside relocations")
        for offset, kind, name in items:
            dest = va + offset + 4 + struct.unpack_from("<i", target, offset)[0]
            if kind.endswith("GOTPCREL"):
                slot, = [r for r in relas if r[0] == dest]
                assert slot[1] == 8
                if name.endswith("raw_vec17capacity_overflow"):
                    assert slot[2] == 0x141e280
                print(f"  +{offset:#x}: GOT {dest:#x} -> {slot[2]:#x} ({name.split('_')[-1]})")
            elif name.startswith(".rodata."):
                literal = dump(name)
                assert literal == read(".rodata", dest, len(literal))
                print(f"  +{offset:#x}: diagnostic at {dest:#x}, {len(literal)} exact bytes")
            else:
                print(f"  +{offset:#x}: source-location record {dest:#x} (contents unqualified)")
    print("unmasked byte mutation rejected")
