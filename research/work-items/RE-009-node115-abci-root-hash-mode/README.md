# RE-009 · Node #115 ABCI outer digest hash mode

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The [block-root packet](../RE-017-abci-block-root-115/README.md) recovers the 68-byte serialized leaf preimage. The [finalization packet](../RE-009-node115-root-digest-final-dispatch/README.md) resolves the implementation dispatch and leaves selector production open. This packet qualifies the hash mode independently of that dispatch, to give an offline root comparator an unambiguous reference for the selected leaf.

At `0x41c52f5` and `0x41c5301` the constructor loads the eight little-endian BLAKE3 IV words. It installs them in the selected working and stored IV positions. With context base `rsp+0x90`, the qword store at `0x41c535b` clears the initial counter, and the dword store at `0x41c5350` clears bytes `+0x67..+0x6a`, including the initial lengths and base flag. Byte `+0x6b` separately receives AL from the slot at `0x41c52d8`. That slot resolves to `0x160bee0`, which selects values 1–4 from feature-mask branches. This byte is an implementation selector. The preparation helper separately loads `+0x6a` into flag construction and `+0x6b` for implementation selection. The finalizer uses distinct stack bytes for OR-ing the root flag and indexing its relative dispatch table.

Consequently the IV and zero initial base flag match [ordinary unkeyed BLAKE3](https://github.com/BLAKE3-team/BLAKE3/blob/master/README.md) on this path. A reference leaf for input bytes `00..1f` has output `f7a1a4d12d289a818cffced598c41164543c9fa8bca63952f376cc552d91d98f` when the independent implementation hashes `d9 42` followed by the 66-byte lowercase prefixed hex string. Omitting the marker or uppercasing the string changes the result. This is a reference expectation derived from selected code, not a digest observed from executing #115, and it does not determine the complete state tree preimage.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on the selected [instruction spans](instructions.tsv).

```sh
PYTHONPATH=tools python3 -B - <<'PY'
import csv
import hashlib
from pathlib import Path
import struct
from elf_index import unwind_index
from fde_extents import eh_frame_records

data = Path("artifacts/node/115/hl-node").read_bytes()
assert hashlib.sha256(data).hexdigest() == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
sections, header = unwind_index(data)
_, fdes = eh_frame_records(data, sections)
indexed = {(row["start"], row["fde"]) for row in header}
bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}

def elf_bytes(section_name, address, size):
    section = next(row for row in sections if row["name"] == section_name)
    displacement = address - section["address"]
    assert 0 <= displacement <= displacement + size <= section["size"]
    offset = section["offset"] + displacement
    return data[offset:offset + size]

with Path("research/work-items/RE-009-node115-abci-root-hash-mode/instructions.tsv").open() as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))
spans = {}
for row in rows:
    start, end, address = (int(row[key], 16) for key in ("fde_start", "fde_end", "va"))
    raw = bytes.fromhex(row["bytes"])
    assert address not in spans
    assert (start, end) in bounds and start <= address < address + len(raw) <= end
    assert elf_bytes(".text", address, len(raw)) == raw
    spans[address] = raw

def rip_target(address):
    raw = spans[address]
    return address + len(raw) + struct.unpack_from("<i", raw, len(raw) - 4)[0]

section = next(row for row in sections if row["name"] == ".rela.dyn")
relocations = {slot: (info, addend) for slot, info, addend in struct.iter_unpack(
    "<QQq", data[section["offset"]:section["offset"] + section["size"]]
)}
assert rip_target(0x41c52f5) == 0x457ae0
assert rip_target(0x41c5301) == 0x457af0
assert struct.unpack("<8I", elf_bytes(".rodata", 0x457ae0, 32)) == (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)
for address, slot, target in ((0x41c52d8, 0x64df488, 0x160bee0),
                              (0x41c5387, 0x64df510, 0x160b3a0),
                              (0x41c539a, 0x64df518, 0x160bcd0)):
    assert rip_target(address) == slot
    assert relocations[slot] == (8, target)
assert rip_target(0x160bce0) == 0x160ab60
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```

With the independent Python `blake3` wheel 1.0.8 available outside the repository:

```python
from blake3 import blake3

preimage = b"\xd9\x42" + b"0x" + bytes(range(32)).hex().encode()
assert len(preimage) == 68
assert blake3(preimage).hexdigest() == "f7a1a4d12d289a818cffced598c41164543c9fa8bca63952f376cc552d91d98f"
assert blake3(preimage[2:]).digest() != blake3(preimage).digest()
assert blake3(preimage[:2] + preimage[2:].upper()).digest() != blake3(preimage).digest()
```
