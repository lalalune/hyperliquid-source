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



CASES = [(True, 'core', '5grisu16format_exact_opt', 23604960, 1032, {145: ('GOTPCREL', '4core3num7flt2dec8strategy5grisu12CACHED_POW10', 4687728), 263: ('PC32', '4core3num7flt2dec8strategy6dragon5POW10', 4689300), 601: ('PC32', '.data.rel.ro..Lanon.', 104889320), 607: ('GOTPCREL', '4core9panicking11panic_const23panic_const_div_by_zero', 23600480), 667: ('PLT32', '4core3num7flt2dec8strategy5grisu16format_exact_opt14possibly_round', 23618304), 871: ('PLT32', '4core3num7flt2dec8strategy5grisu16format_exact_opt14possibly_round', 23618304), 900: ('PC32', '.rodata..Lanon.', 4689024), 907: ('PC32', '.data.rel.ro..Lanon.', 104889224), 918: ('GOTPCREL', '4core9panicking5panic', 23596640), 925: ('PC32', '.rodata..Lanon.', 4689052), 932: ('PC32', '.data.rel.ro..Lanon.', 104889248), 943: ('GOTPCREL', '4core9panicking5panic', 23596640), 950: ('PC32', '.rodata..Lanon.', 4647841), 957: ('PC32', '.data.rel.ro..Lanon.', 104889272), 968: ('GOTPCREL', '4core9panicking5panic', 23596640), 975: ('PC32', '.data.rel.ro..Lanon.', 104889344), 988: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223), 995: ('PC32', '.data.rel.ro..Lanon.', 104889368), 1007: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223), 1014: ('PC32', '.data.rel.ro..Lanon.', 104889296), 1028: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223)}), (True, 'core', '5grisu19format_shortest_opt', 23606000, 1635, {259: ('GOTPCREL', '4core3num7flt2dec8strategy5grisu12CACHED_POW10', 4687728), 721: ('PC32', '.data.rel.ro..Lanon.', 104889512), 727: ('GOTPCREL', '4core9panicking11panic_const23panic_const_div_by_zero', 23600480), 1381: ('PC32', '.data.rel.ro..Lanon.', 104888472), 1399: ('GOTPCREL', '4core9panicking13assert_failedyyEB4_', 23575531), 1406: ('PC32', '.rodata..Lanon.', 4689024), 1413: ('PC32', '.data.rel.ro..Lanon.', 104889392), 1424: ('GOTPCREL', '4core9panicking5panic', 23596640), 1431: ('PC32', '.rodata..Lanon.', 4689088), 1438: ('PC32', '.data.rel.ro..Lanon.', 104889416), 1449: ('GOTPCREL', '4core9panicking5panic', 23596640), 1456: ('PC32', '.rodata..Lanon.', 4689117), 1463: ('PC32', '.data.rel.ro..Lanon.', 104889440), 1474: ('GOTPCREL', '4core9panicking5panic', 23596640), 1481: ('PC32', '.rodata..Lanon.', 4689245), 1488: ('PC32', '.data.rel.ro..Lanon.', 104889608), 1499: ('GOTPCREL', '4core9panicking5panic', 23596640), 1506: ('PC32', '.rodata..Lanon.', 4689190), 1513: ('PC32', '.data.rel.ro..Lanon.', 104889584), 1524: ('GOTPCREL', '4core9panicking5panic', 23596640), 1531: ('PC32', '.rodata..Lanon.', 4646722), 1538: ('PC32', '.data.rel.ro..Lanon.', 104889464), 1549: ('GOTPCREL', '4core9panicking5panic', 23596640), 1556: ('PC32', '.rodata..Lanon.', 4689145), 1563: ('PC32', '.data.rel.ro..Lanon.', 104889488), 1574: ('GOTPCREL', '4core9panicking5panic', 23596640), 1581: ('PC32', '.data.rel.ro..Lanon.', 104889536), 1594: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223), 1601: ('PC32', '.data.rel.ro..Lanon.', 104889560), 1610: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223), 1617: ('PC32', '.data.rel.ro..Lanon.', 104889296), 1631: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223)}), (True, 'core', '14possibly_round', 23618304, 417, {205: ('GOTPCREL', 'memset', 'memset@GLIBC_2.2.5'), 270: ('GOTPCREL', 'memset', 'memset@GLIBC_2.2.5'), 357: ('PC32', '.data.rel.ro..Lanon.', 104890160), 371: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 378: ('PC32', '.data.rel.ro..Lanon.', 104890136), 392: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 399: ('PC32', '.data.rel.ro..Lanon.', 104890112), 413: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072)})]

build.BUILD_STD = "-Zbuild-std=core"
print("node #115 sha256", SHA)
with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    manifest = build.MANIFEST
    archives = {}
    for enabled in sorted({row[0] for row in CASES}):
        build.MANIFEST = manifest.replace("codegen-units = 256", "codegen-units = 1") if enabled else manifest
        build.capture = force_frames if enabled else capture
        workdir = work / ("frame" if enabled else "default")
        build.cargo_job(workdir, cache, library, "1.95.0", False)
        for dep in {row[1] for row in CASES if row[0] == enabled}:
            archive, = workdir.glob(f"target/x86_64-unknown-linux-gnu/release/deps/lib{dep}-*.rlib")
            symbols = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
            archives[enabled, dep] = (archive, symbols)
    frame_table = command("readelf", "-wf", ROOT / "artifacts/node/115/hl-node").decode()
    target_extents = {(int(start, 16), int(end, 16)) for start, end in
                      re.findall(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", frame_table)}
    assert all((address, address + size) in target_extents for _, _, _, address, size, _ in CASES)
    print("all selected ELF extents match independent FDE records")
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
