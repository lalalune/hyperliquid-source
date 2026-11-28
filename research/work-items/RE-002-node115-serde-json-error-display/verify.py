"""Verify full data tables in the pinned node #115 ELF against released native-library sources."""
from hashlib import sha256
from pathlib import Path
import ast
import re
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



def check_dispatch(start, end, table, variants, literals, delegated):
    assert rip_target(start + 3, bytes.fromhex("488d0d")) == table
    entry = read(".text", start + 10, 9)
    assert entry == bytes.fromhex("486304814801c8ffe0")
    arms = struct.unpack(f"<{len(variants)}i", read(".rodata", table, 4 * len(variants)))
    assert len(set(arms)) == len(arms)
    for index, (variant, delta) in enumerate(zip(variants, arms)):
        address = table + delta
        assert start + 19 <= address < end
        if variant in delegated:
            expected = bytes.fromhex(delegated[variant])
            assert read(".text", address, len(expected)) == expected
            print(index, variant, hex(address), "delegated")
            continue
        want = literals[variant].encode()
        assert read(".text", address, 11) == bytes.fromhex("488b3e488b4608488b4018")
        string = rip_target(address + 11, bytes.fromhex("488d35"))
        size = read(".text", address + 18, 7)
        assert size[:1] == b"\xba" and size[5:] == b"\xff\xe0"
        assert struct.unpack("<I", size[1:5])[0] == len(want)
        actual = read(".rodata", string, len(want))
        assert actual == want
        assert bytes([actual[0] ^ 1]) + actual[1:] != want
        print(index, variant, hex(address), hex(string), len(want), sha256(actual).hexdigest())

source, = from_archive("serde_json-1.0.140",
    "20068b6e96dc6c9bd23e01df8827e6c7e1f2fddd43c21810382803c136b99373", ["src/error.rs"])
enum_source = re.search(r"enum ErrorCode \{(.*?)^\}", source, re.S | re.M)[1]
display_source = re.search(r"impl Display for ErrorCode \{(.*?)^\}", source, re.S | re.M)[1]
variants = re.findall(r"^    ([A-Z]\w*)[,(]", enum_source, re.M)
strings = {name: ast.literal_eval(text) for name, text in re.findall(
    r'(\w+)\s*=>\s*(?:\{\s*)?f\.write_str\(("(?:[^"\\]|\\.)*")\)', display_source
)}
assert len(variants) == 25 and len(strings) == 23
check_dispatch(0x5c54e90, 0x5c55104, 0x945f00, variants, strings,
               {"Message": "488b4708488b5710488b3e488b4e08488b49184889c6ffe1",
                "Io": "4883c708ff25d8a48800"})
print("literal dispatch payload mutation controls passed")
template, = re.search(r'impl Display for ErrorImpl.*?write!\(\s*f,\s*"([^"]+)"', source, re.S).groups()
parts = template.encode().split(b"{}")
assert len(parts) == 4 and not parts[0] and not parts[-1]
encoded = b"\xc0" + b"".join(bytes([len(part)]) + part + b"\xc0" for part in parts[1:-1]) + b"\0"
assert rip_target(0x5c54ba9, bytes.fromhex("488d15")) == 0x449418
assert read(".rodata", 0x449418, len(encoded)) == encoded
print("complete line/column format template", len(encoded), encoded.hex())
