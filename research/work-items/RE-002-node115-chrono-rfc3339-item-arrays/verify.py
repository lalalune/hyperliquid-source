"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import struct
import sys
import tarfile

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CACHE = Path(sys.argv[1])
TARGET = Path("artifacts/node/115/hl-node")
sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

data = TARGET.read_bytes()
assert sha256(data).hexdigest() == TARGET_SHA
layout = {section["name"]: section for section in sections(data)}


def read(section, address, size):
    row = layout[section]
    delta = address - row["address"]
    assert 0 <= delta <= row["size"] - size
    start = row["offset"] + delta
    return data[start:start + size]


def from_archive(name, digest, files):
    path = CACHE / f"{name}.crate"
    assert sha256(path.read_bytes()).hexdigest() == digest
    print(name, digest)
    with tarfile.open(path) as archive:
        return [archive.extractfile(f"{name}/{part}").read().decode() for part in files]


def rip_target(address, prefix):
    instruction = read(".text", address, len(prefix) + 4)
    assert instruction.startswith(prefix)
    return address + len(instruction) + struct.unpack_from("<i", instruction, len(prefix))[0]


print("node #115", TARGET_SHA)



TOOLS = Path(sys.argv[2])
rows = subprocess.check_output([TOOLS / "readelf", "-rW", TARGET], text=True)
relative = {
    int(slot, 16): int(addr, 16)
    for slot, addr in re.findall(
        r"^([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)$", rows, re.M
    )
}

source, parser = from_archive("chrono-0.4.38",
    "a21f936df1771bf62b77f047b726c4625ff2e8aa607c01ec06e5a05bd8463401",
    ["src/format/mod.rs", "src/format/parse.rs"])
units = []
for name in ("Void", "Pad", "Numeric", "InternalNumeric", "Fixed", "InternalFixed", "InternalInternal", "Item"):
    pattern = rf"(?:pub )?(?:enum|struct) {name}(?:<[^>]+>)? \{{(?:\}}|[\s\S]*?^\}})"
    units.append(re.search(pattern, source, re.M)[0])
groups = (("DATE", 0x6404588, 0x162173d), ("TIME", 0x6404648, 0x162179d))
for name, _, _ in groups:
    body = re.search(rf"const {name}_ITEMS: &\[Item<'static>\] = &\[(.*?)\];", parser, re.S)[1]
    count = body.count("Item::")
    units.append(f"#[unsafe(no_mangle)] pub static {name}_ITEMS: [Item<'static>; {count}] = [{body}];")
version = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
assert version.startswith("rustc 1.95.0 (59807616e")
print(version)
with TemporaryDirectory() as temp_dir:
    temp = Path(temp_dir)
    src, obj = temp / "format_items.rs", temp / "format_items.o"
    src.write_text("\n".join(units))
    subprocess.run(["rustc", "+1.95.0", "--target=x86_64-unknown-linux-gnu", "--crate-type", "lib",
                    "--cfg", 'feature="alloc"', "--emit=obj", "-O", "-A", "dead_code", str(src),
                    "-o", str(obj)], check=True)

    def dump(section):
        output = temp / "section.bin"
        output.unlink(missing_ok=True)
        subprocess.run([TOOLS / "objcopy", "--dump-section", f"{section}={output}", obj], check=True)
        return output.read_bytes()

    for name, addr, site in groups:
        section = f".data.rel.ro.{name}_ITEMS"
        expected = dump(section)
        actual = read(".data.rel.ro", addr, len(expected))
        assert actual == expected
        assert rip_target(site, bytes.fromhex("4c8d05")) == addr
        refs = subprocess.check_output([TOOLS / "objdump", "-r", "-j", section, obj], text=True)
        fields = dict((int(offset, 16), symbol) for offset, symbol in re.findall(
            r"^([0-9a-f]+)\s+R_X86_64_64\s+(\.rodata\.\S+)$", refs, re.M
        ))
        assert len(fields) == 2
        assert {slot - addr for slot in relative if addr <= slot < addr + len(actual)} == set(fields)
        for offset, field in fields.items():
            want = dump(field)
            target = relative[addr + offset]
            assert read(".rodata", target, len(want)) == want
            print(name, "literal", hex(addr + offset), hex(target), want.hex())
        assert bytes([actual[0] ^ 1]) + actual[1:] != expected
        print(name, hex(addr), hex(site), len(actual), sha256(actual).hexdigest())
print("both item arrays and all four literal bindings match")
