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



CASES = [(True, 'core', '12SocketAddrV4NtNtB9_3fmt7Display3fmt', 23626960, 282, {49: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv4AddrNtB6_7Display3fmtB8_', 23623024), 68: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 79: ('PC32', '.data.rel.ro..Lanon.', 104890256), 86: ('PC32', '.Lanon.', 4408689), 100: ('GOTPCREL', '4core3fmt5write', 23594240), 131: ('GOTPCREL', '4core3fmtNtB5_9Formatter3pad', 23591536), 165: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv4AddrNtB6_7Display3fmtB8_', 23623024), 184: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 202: ('PC32', '.Lanon.', 4408689), 212: ('GOTPCREL', '4core3fmt5write', 23594240), 226: ('PC32', '.data.rel.ro..Lanon.', 104890328), 242: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 249: ('PC32', '.rodata..Lanon.', 4647047), 256: ('PC32', '.data.rel.ro..Lanon.', 104888440), 263: ('PC32', '.data.rel.ro..Lanon.', 104890304), 278: ('GOTPCREL', '4core6result13unwrap_failed', 23596080)}), (True, 'core', '8Ipv4AddrNtNtB9_3fmt7Display3fmt', 23627248, 301, {58: ('GOTPCREL', '4core3fmt3num3imphNtB6_7Display3fmt', 23620304), 93: ('PC32', '.data.rel.ro..Lanon.', 104890352), 100: ('PC32', '.Lanon.', 4479670), 114: ('GOTPCREL', '4core3fmt5write', 23594240), 145: ('GOTPCREL', '4core3fmtNtB5_9Formatter3pad', 23591536), 179: ('GOTPCREL', '4core3fmt3num3imphNtB6_7Display3fmt', 23620304), 221: ('PC32', '.Lanon.', 4479670), 231: ('GOTPCREL', '4core3fmt5write', 23594240), 245: ('PC32', '.data.rel.ro..Lanon.', 104890328), 261: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 268: ('PC32', '.rodata..Lanon.', 4647047), 275: ('PC32', '.data.rel.ro..Lanon.', 104888440), 282: ('PC32', '.data.rel.ro..Lanon.', 104890400), 297: ('GOTPCREL', '4core6result13unwrap_failed', 23596080)}), (True, 'core', '12SocketAddrV6NtNtB9_3fmt7Display3fmt', 23627792, 528, {69: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv6AddrNtB6_7Display3fmtB8_', 23623040), 88: ('GOTPCREL', '4core3fmt3num3impmNtB9_7Display3fmt', 23628320), 107: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 118: ('PC32', '.data.rel.ro..Lanon.', 104890424), 125: ('PC32', '.Lanon.', 4515117), 174: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv6AddrNtB6_7Display3fmtB8_', 23623040), 199: ('GOTPCREL', '4core3fmt3num3impmNtB9_7Display3fmt', 23628320), 218: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 236: ('PC32', '.Lanon.', 4515117), 268: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv6AddrNtB6_7Display3fmtB8_', 23623040), 287: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 298: ('PC32', '.data.rel.ro..Lanon.', 104890424), 305: ('PC32', '.Lanon.', 4504016), 322: ('GOTPCREL', '4core3fmt5write', 23594240), 359: ('GOTPCREL', '4core3fmtNtB5_9Formatter3pad', 23591536), 399: ('PC32', '4core3fmtRNtNtNtB8_3net7ip_addr8Ipv6AddrNtB6_7Display3fmtB8_', 23623040), 424: ('GOTPCREL', '4core3fmt3num3imptNtB9_7Display3fmt', 23626400), 442: ('PC32', '.Lanon.', 4504016), 455: ('GOTPCREL', '4core3fmt5write', 23594240), 472: ('PC32', '.data.rel.ro..Lanon.', 104890328), 488: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 495: ('PC32', '.rodata..Lanon.', 4647047), 502: ('PC32', '.data.rel.ro..Lanon.', 104888440), 509: ('PC32', '.data.rel.ro..Lanon.', 104890472), 524: ('GOTPCREL', '4core6result13unwrap_failed', 23596080)})]

build.BUILD_STD = "-Zbuild-std=core"
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    build.MANIFEST = build.MANIFEST.replace("codegen-units = 256", "codegen-units = 1")
    archives = {}
    for enabled in sorted({row[0] for row in CASES}):
        build.capture = force_frames if enabled else capture
        workdir = work / ("frame" if enabled else "default")
        build.cargo_job(workdir, cache, library, "1.95.0", False)
        for dep in {row[1] for row in CASES if row[0] == enabled}:
            archive, = workdir.glob(f"target/x86_64-unknown-linux-gnu/release/deps/lib{dep}-*.rlib")
            symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
            archives[enabled, dep] = (archive, symbols)
    dyn = command("readelf", "-rW", ROOT / "artifacts/node/115/hl-node").decode().splitlines()
    for enabled, dep, stem, va, length, expected in CASES:
        archive, symbols = archives[enabled, dep]
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
            r"^([a-f0-9]+)\s+R_X86_64_(PC32|GOTPCREL|PLT32)\s+(\S+?)(?:-0x0*4)?$", reloc, re.M)]
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
