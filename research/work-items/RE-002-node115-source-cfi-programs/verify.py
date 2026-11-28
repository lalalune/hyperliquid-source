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
from foundation_lsda_call_site import parse_fde, walk_eh_frame

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


def cfi_bytes(data, base, cies, fde, length):
    cie = cies[fde["cie_record_offset"]]
    off = fde["record_offset"]
    _, start = parse_fde(data, off + 8, cie, base)
    end = off + 4 + struct.unpack_from("<I", data, off)[0]
    assert end >= start + length
    assert not any(data[start + length:end])
    cie_end = cie["record_offset"] + 4 + struct.unpack_from("<I", data, cie["record_offset"])[0]
    initial = data[cie["size"]:cie_end]
    factors = tuple(cie[key] for key in ("code_alignment", "data_alignment", "return_address_register"))
    return data[start:start + length], initial, factors


capture = build.capture


def force_frames(args, **kwargs):
    if "build" in args:
        kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"] += "\x1f-Cforce-frame-pointers=yes"
    return capture(args, **kwargs)



CASES = [(True, 'core', '10mul_digits', 23583456, 836, {725: ('GOTPCREL', 'memcpy', 'memcpy@GLIBC_2.14'), 760: ('PC32', '.data.rel.ro..Lanon.', 104888544), 776: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 793: ('PC32', '.data.rel.ro..Lanon.', 104888544), 804: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223), 821: ('PC32', '.data.rel.ro..Lanon.', 104888544), 832: ('GOTPCREL', '4core9panicking18panic_bounds_check', 23596223)}), (True, 'core', '6memchr7memrchr', 23599504, 269, {235: ('PC32', '.data.rel.ro..Lanon.', 104889032), 246: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072), 253: ('PC32', '.data.rel.ro..Lanon.', 104889056), 265: ('GOTPCREL', '4core5slice5index16slice_index_fail', 23599072)}), (True, 'std', '4unix9try_statx', 97122176, 791, {23: ('PC32', '3std3sys2fs4unix9try_statx17STATX_SAVED_STATE.0', 105906312), 180: ('GOTPCREL', 'statx', 'statx@GLIBC_2.28'), 200: ('PC32', '3std3sys2fs4unix9try_statx17STATX_SAVED_STATE.0', 105906311), 552: ('GOTPCREL', 'syscall', 'syscall@GLIBC_2.2.5'), 567: ('GOTPCREL', '__errno_location', '__errno_location@GLIBC_2.2.5'), 592: ('PC32', '3std3sys2fs4unix9try_statx17STATX_SAVED_STATE.0', 105906312), 642: ('GOTPCREL', 'statx', 'statx@GLIBC_2.28'), 677: ('GOTPCREL', 'syscall', 'syscall@GLIBC_2.2.5'), 709: ('PLT32', '3std2io5error5ErrorEBM_', 96947088), 721: ('PC32', '3std3sys2fs4unix9try_statx17STATX_SAVED_STATE.0', 105906311), 730: ('PC32', '3std3sys2fs4unix9try_statx17STATX_SAVED_STATE.0', 105906311), 747: ('PLT32', '3std2io5error5ErrorEBM_', 96947088), 773: ('PLT32', '3std2io5error5ErrorEBM_', 96947088), 781: ('PLT32', '_Unwind_Resume', 104794704), 787: ('GOTPCREL', '4core9panicking16panic_in_cleanup', 23596203)})]

build.BUILD_STD = "-Zbuild-std=std,panic_unwind"
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
    frame = layout[".eh_frame"]
    linked_frame = read(".eh_frame", frame["address"], frame["size"])
    linked_cies, linked_fdes = walk_eh_frame(linked_frame, frame["address"])
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
        frame_relocs = command("objdump", "-r", "-j", ".eh_frame", obj).decode()
        matches = re.findall(rf"^([0-9a-f]+)\s+R_X86_64_PC32\s+{re.escape(section)}$", frame_relocs, re.M)
        field, = map(lambda value: int(value, 16), matches)
        obj_bytes = obj.read_bytes()
        local, = [item for item in sections(obj_bytes) if item["name"] == ".eh_frame"]
        local_frame = obj_bytes[local["offset"]:local["offset"] + local["size"]]
        local_cies, local_fdes = walk_eh_frame(local_frame, local["address"])
        source_rec, = [row for row in local_fdes if row["record_offset"] == field - 8]
        target_rec, = [row for row in linked_fdes if row["entry"] == va]
        assert source_rec["range"] == target_rec["range"] == length
        rule_count = {0x167dae0: 29, 0x1681990: 24, 0x5c9f780: 25}[va]
        source_cfi, source_init, source_factors = cfi_bytes(local_frame, local["address"], local_cies, source_rec, rule_count)
        target_cfi, target_init, target_factors = cfi_bytes(linked_frame, frame["address"], linked_cies, target_rec, rule_count)
        assert source_factors == target_factors == (1, -8, 16)
        assert source_init == target_init and source_cfi == target_cfi
        assert (bytes([target_cfi[0] ^ 1]) + target_cfi[1:]) != source_cfi
        print(f"equal CIE initial instructions and {len(source_cfi)} CFI program bytes {va:#x}")
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
