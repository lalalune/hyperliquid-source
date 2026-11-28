"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import re
import subprocess
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


source, = from_archive("zstd-sys-2.0.13+zstd.1.5.6",
    "38ff0f21cfee8f97d94cef41359e0c89aa6113028ab0291aa8ca0038995a95aa",
    ["zstd/lib/compress/zstd_compress.c"])
source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
frames = subprocess.check_output([TOOLS / "readelf", "-wf", TARGET], text=True)
starts = {int(address, 16) for address in re.findall(r"pc=([0-9a-f]+)\.\.", frames)}
expected_tables = (
    ("blockCompressor", 0x64d9ea0, 10, (0x620fa6c, 0x620fae5, 0x62137ef), "488d05"),
    ("rowBasedBlockCompressors", 0x64d9fe0, 3, (0x620fa4e, 0x620fc3e, 0x621380c), "488d15"),
)
bounded = []
for name, address, width, refs, opcode in expected_tables:
    block = re.search(rf"\b{name}\[[^]]+\]\[[^]]+\]\s*=\s*\{{(.*?)\}};", source, re.S)[1]
    source_rows = [re.findall(r"\b(?:NULL|ZSTD_\w+)\b", row)
                   for row in re.findall(r"\{([^}]+)\}", block)]
    assert len(source_rows) == 4 and all(len(row) == width for row in source_rows)
    symbols = [symbol for row in source_rows for symbol in row]
    targets = [relative.get(address + 8 * i, 0) for i in range(len(symbols))]
    for site in refs:
        assert rip_target(site, bytes.fromhex(opcode)) == address
    for i, (symbol, target) in enumerate(zip(symbols, targets)):
        assert (symbol == "NULL") == (target == 0)
        if target:
            assert target in starts
            read(".text", target, 1)
        else:
            assert read(".data.rel.ro", address + 8 * i, 8) == bytes(8)
        print(name, i // width, i % width, symbol, hex(target))
    for i, symbol in enumerate(symbols):
        for j in range(i):
            assert (symbol == symbols[j]) == (targets[i] == targets[j])
    bounded.extend(targets)
assert len(bounded) == 52 and sum(bool(target) for target in bounded) == 45
print("both matrices, six references and 45 FDE-bound relocations verified")
