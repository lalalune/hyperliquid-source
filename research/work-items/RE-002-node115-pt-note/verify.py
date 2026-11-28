"""Compare program- and section-header views of the pinned node's GNU notes."""
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import sections

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def notes(data, start, size):
    end = start + size
    if end > len(data):
        raise ValueError("segment outside file")
    pos = start
    while pos < end:
        if end - pos < 12:
            raise ValueError("partial note header")
        namesz, descsz, kind = struct.unpack_from("<III", data, pos)
        name = pos + 12
        desc = name + ((namesz + 3) & ~3)
        stop = desc + ((descsz + 3) & ~3)
        if stop > end:
            raise ValueError("note exceeds segment")
        yield pos, stop, data[name:name + namesz], kind, data[desc:desc + descsz]
        pos = stop


data = Path("artifacts/node/115/hl-node").read_bytes()
if hashlib.sha256(data).hexdigest() != SHA:
    raise ValueError("wrong node digest")
phoff = struct.unpack_from("<Q", data, 32)[0]
stride, count = struct.unpack_from("<HH", data, 54)
headers = [struct.unpack_from("<II6Q", data, phoff + n * stride) for n in range(count)]
(_, _, off, va, _, size, memsize, align), = (h for h in headers if h[0] == 4)
assert (off, va, size, memsize, align) == (0x2fc, 0x2fc, 68, 68, 4)
load, = (h for h in headers if h[0] == 1 and h[2] <= off and off + size <= h[2] + h[5])
assert load[3] + off - load[2] == va
rows = list(notes(data, off, size))
assert [(s, e, owner, kind) for s, e, owner, kind, _ in rows] == [
    (0x2fc, 0x31c, b"GNU\0", 1), (0x31c, 0x340, b"GNU\0", 3)]
note_sections = [s for s in sections(data) if s["type"] == 7]
assert [(s["offset"], s["offset"] + s["size"]) for s in note_sections] == [
    (start, end) for start, end, *_ in rows]
print("node #115 sha256", SHA)
print(f"one PT_NOTE [{off:#x},{off + size:#x}), mapped by PT_LOAD at {va:#x}")
for section, (start, end, _, kind, desc) in zip(note_sections, rows):
    assert section["address"] == va + start - off
    print(f"{section['name']} [{start:#x},{end:#x}) type={kind} descriptor={desc.hex()}")
try:
    list(notes(data, off, size - 1))
except ValueError as exc:
    print("one-byte shortened segment rejected:", exc)
else:
    raise RuntimeError("truncated note accepted")
