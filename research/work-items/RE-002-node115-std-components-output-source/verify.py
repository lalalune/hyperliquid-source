"""Rebuild and verify selected std ELF linkage."""
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
CASES = [('10Components7as_path', 97052864, 598, {231: ('PLT32', 'parse_next_component_back', 97052560), 327: ('PLT32', 'parse_next_component_back', 97052560), 492: ('PLT32', 'parse_next_component_back', 97052560), 564: ('PC32', '.data.rel.ro.', 105658096), 578: ('GOTPCREL', 'slice_index_fail', 23599072), 585: ('PC32', '.data.rel.ro.', 105658168), 594: ('GOTPCREL', 'slice_index_fail', 23599072)})]

build.BUILD_STD = "-Zbuild-std=std,panic_unwind"
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    build.cargo_job(work / "probe", cache, library, "1.95.0", False)
    archive, = (work / "probe").glob("target/x86_64-unknown-linux-gnu/release/deps/libstd-*.rlib")
    symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
    dyn = command("readelf", "-rW", ROOT / "artifacts/node/115/hl-node").decode().splitlines()
    for stem, va, length, expected in CASES:
        entry, = [line.split() for line in symbols
                  if len(line.split()) == 4 and stem in line.split()[-1]
                  and int(line.split()[1], 16) == length]
        coordinate, size, _, name = entry
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(size, 16) == length and int(offset, 16) == 0
        obj = work / "selected.o"
        obj.write_bytes(command("ar", "p", archive, member))
        labels = command("objdump", "-t", obj).decode().splitlines()
        label, = [line.split() for line in labels if line.split() and line.split()[-1] == name]
        section, = [part for part in label if part.startswith(".text")]
        output = work / "section.bin"
        output.unlink(missing_ok=True)
        command("objcopy", "--dump-section", f"{section}={output}", obj)
        body = output.read_bytes()
        target = read(".text", va, length)
        assert len(body) == len(target)
        reloc = command("objdump", "-r", "-j", section, obj).decode()
        fields = [(int(pos, 16), kind, symbol) for pos, kind, symbol in re.findall(
            r"^([a-f0-9]+)\s+R_X86_64_(PC32|GOTPCREL|PLT32)\s+(\S+)-0x0*4$", reloc, re.M)]
        assert len(fields) == reloc.count("R_X86_64_")
        mask = {byte for offset, _, _ in fields for byte in range(offset, offset + 4)}
        assert all(a == b for i, (a, b) in enumerate(zip(body, target)) if i not in mask)
        assert (body[0] ^ 1) != target[0] and 0 not in mask
        print(f"{stem} {va:#x}: {length - len(mask)}/{length} equal outside fields")
        for field, (kind, reference, result) in expected.items():
            actual_kind, name = next((k, n) for off, k, n in fields if off == field)
            assert kind == actual_kind and reference in name
            location = va + field + 4 + struct.unpack_from("<i", target, field)[0]
            if kind == "GOTPCREL":
                row, = [line.split() for line in dyn if line.split() and line.split()[0] == f"{location:016x}"]
                if isinstance(result, int):
                    assert row[2] == "R_X86_64_RELATIVE" and int(row[3], 16) == result
                    verdict = hex(result)
                else:
                    assert row[2] == "R_X86_64_GLOB_DAT" and row[4] == result
                    verdict = result
            else:
                assert location == result
                verdict = hex(result)
            print(f"  +{field:#x}: {location:#x} -> {verdict}")
    print("unmasked byte mutation fails each body comparison")
