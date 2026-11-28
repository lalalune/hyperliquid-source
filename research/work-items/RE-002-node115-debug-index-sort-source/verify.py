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



CASES = [(True, 'std', '12sort8_stableTNtNt', 96966048, 887, {883: ('GOTPCREL', '4core5slice4sort6shared9smallsort22panic_on_ord_violation', 23617632)}), (True, 'std', '12LineSequence', 96977008, 2566, {183: ('PLT32', '3std', 96964464), 456: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 713: ('GOTPCREL', '3std', 96977008), 914: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 1177: ('PLT32', '3std', 96968672), 2484: ('PC32', '.rodata..Lanon.', 9736843), 2491: ('PC32', '.data.rel.ro..Lanon.', 105656296), 2502: ('GOTPCREL', '4core9panicking9panic_fmt', 23596672), 2514: ('GOTPCREL', '4core5slice4sort6shared9smallsort22panic_on_ord_violation', 23617632), 2523: ('PC32', '.data.rel.ro..Lanon.', 105656320), 2535: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 2554: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 2562: ('PLT32', '_Unwind_Resume', 104794704)}), (True, 'std', '9UnitRange', 96979584, 2566, {183: ('PLT32', '3std', 96964656), 456: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 713: ('GOTPCREL', '3std', 96979584), 914: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 1177: ('PLT32', '3std', 96970288), 2484: ('PC32', '.rodata..Lanon.', 9736843), 2491: ('PC32', '.data.rel.ro..Lanon.', 105656296), 2502: ('GOTPCREL', '4core9panicking9panic_fmt', 23596672), 2514: ('GOTPCREL', '4core5slice4sort6shared9smallsort22panic_on_ord_violation', 23617632), 2523: ('PC32', '.data.rel.ro..Lanon.', 105656320), 2535: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 2554: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 2562: ('PLT32', '_Unwind_Resume', 104794704)}), (True, 'std', '22InlinedFunctionAddress', 96984624, 2518, {180: ('PLT32', '3std', 96965040), 676: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 936: ('GOTPCREL', '3std', 96984624), 1183: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 1450: ('PLT32', '3std', 96973520), 1524: ('PLT32', '3std', 96965680), 1535: ('PLT32', '3std', 96965680), 2441: ('GOTPCREL', '4core5slice4sort6shared9smallsort22panic_on_ord_violation', 23617632), 2450: ('PC32', '.rodata..Lanon.', 9736843), 2457: ('PC32', '.data.rel.ro..Lanon.', 105656296), 2468: ('GOTPCREL', '4core9panicking9panic_fmt', 23596672), 2475: ('PC32', '.data.rel.ro..Lanon.', 105656320), 2487: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 2506: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 2514: ('PLT32', '_Unwind_Resume', 104794704)}), (True, 'std', '9quicksort9quicksortTNtNt', 96987152, 2721, {104: ('PLT32', '3std', 96966048), 134: ('PLT32', '3std', 96966048), 279: ('PLT32', '3std', 96965504), 723: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 955: ('GOTPCREL', '3std', 96987152), 1362: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 1614: ('PLT32', '3std', 96975264), 2643: ('GOTPCREL', '4core5slice4sort6shared9smallsort22panic_on_ord_violation', 23617632), 2652: ('PC32', '.rodata..Lanon.', 9736843), 2659: ('PC32', '.data.rel.ro..Lanon.', 105656296), 2670: ('GOTPCREL', '4core9panicking9panic_fmt', 23596672), 2677: ('PC32', '.data.rel.ro..Lanon.', 105656320), 2689: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 2709: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 2717: ('PLT32', '_Unwind_Resume', 104794704)})]

build.BUILD_STD = "-Zbuild-std=std,panic_unwind"
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
