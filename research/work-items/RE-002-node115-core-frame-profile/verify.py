"""Compare explicit frame-pointer settings across a core formatting cohort."""
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


cases = {
    "escape_debug_ext": (0x167d1f0, 0x23f),
    "pad_formatted_parts": (0x167eed0, 0x25a),
    "write_prefix": (0x1686260, 0x54),
    "possibly_round": (0x1686300, 0x1a1),
    "fmt_decimals_0": (0x167cb20, 0x181),
}
print("node #115 sha256", SHA)
capture = build.capture


def measure(cache, case_dir, library, force):
    def with_flags(args, **kwargs):
        if "build" in args:
            kwargs["env"]["CARGO_ENCODED_RUSTFLAGS"] += f"\x1f-Cforce-frame-pointers={force}"
        return capture(args, **kwargs)

    build.capture = with_flags
    _, compiler, cargo = build.cargo_job(case_dir, cache, library, "1.95.0", False)
    archive, = case_dir.glob("target/x86_64-unknown-linux-gnu/release/deps/libcore-*.rlib")
    rows = command("nm-new", "-A", "-S", "--defined-only", archive).decode().splitlines()
    verdicts = {}
    for name, (va, expected) in cases.items():
        coordinate, length, _, symbol = next(line.split() for line in rows if name in line.split()[-1])
        _, member, offset = coordinate.rsplit(":", 2)
        assert int(offset, 16) == 0
        obj = case_dir / f"{name}.o"
        obj.write_bytes(command("ar", "p", archive, member))
        section = ".text." + symbol
        output = obj.with_suffix(".bin")
        command("objcopy", "--dump-section", f"{section}={output}", obj)
        body = output.read_bytes()
        assert len(body) == int(length, 16)
        target = read(".text", va, expected)
        raw_equal = body == target
        print(f"{force} {name} {va:#x}: source={len(body)} target={expected} raw_equal={raw_equal}")
        verdicts[name] = (len(body) == expected, raw_equal)
        if raw_equal:
            assert "RELOCATION RECORDS FOR" not in command("objdump", "-r", "-j", section, obj).decode()
    return verdicts


with TemporaryDirectory() as scratch:
    work = Path(scratch)
    library = build.sources(cache, work, "1.95.0", False)
    omitted = measure(cache, work / "force-no", library, "no")
    kept = measure(cache, work / "force-yes", library, "yes")
    assert not any(same for same, _ in omitted.values())
    assert all(same for same, _ in kept.values())
    assert kept["write_prefix"] == (True, True)
