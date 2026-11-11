# RE-017 · Node #115 replay bundle byte framing

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

The replay converter reads each row's object at row `+0x20` and passes the object's `+0x18/+0x20` as a pointer and length. Its decoder slot `0x64e87f0` resolves to `0x36abb10`. This packet identifies how to delimit those bytes for an offline fixture. It does not assume that the publicly exported JSON bundle is byte-identical to this input.

Let `N` be the byte length. An input shorter than 0x87 returns result word 0x8a. Otherwise the decoder hashes the first `N - 65` bytes. It separately reads two 32-byte signature limbs and the last byte from the trailing 65 bytes, byte-swapping each limb's selected words before the signer recovery call. The selected sponge uses rate 136 and domain byte 1 and requests 32 output bytes. Recovery tag 1 returns word 0x7e. The earlier vote signer packet describes the recovery helper's result layout in a different caller.

After recovery the decoder reserves the final 73 bytes for an eight-byte word and the signature. It reads a big-endian 32-bit header length `H` from input offset 0. If `H > N - 77` it returns word 0x8b. It passes exactly bytes `[4, 4+H)` to decoder `0x32679a0` and expects tag 9. The returned span lengths are added with overflow detection. A sum above 50,000,000 returns 0x8b. A sum unequal to `N - 77 - H` returns 0x8c. The selected loop then starts at input `4 + H`, calls `0x38d8420` with each bounded span, and only returns outer success word 0x1a2 on the selected all-success path. The replay converter uses that word as its selected row append condition.

The length rules distinguish malformed byte framing from a bad signer result and from an inner action parse failure. This is static evidence and synthetic boundary arithmetic. No signed record was generated, no real record was assumed valid, and the inner span decoder and action codec are separate boundaries.

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

with Path("research/work-items/RE-017-node115-replay-bundle-wire/instructions.tsv").open() as handle:
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
assert relocations[0x64e87f0] == (8, 0x36abb10)
for address, slot, target in ((0x36abc6b, 0x64e0148, 0x5cda910),
                              (0x36abc9a, 0x64e0150, 0x5cdad40),
                              (0x36abcd5, 0x64e0ad8, 0x1536a90)):
    assert rip_target(address) == slot
    assert relocations[slot] == (8, target)
assert rip_target(0x36abe33) == 0x32679a0
assert rip_target(0x36abff3) == 0x38d8420
assert int.from_bytes(spans[0x36abefa][-4:], "little") == 50_000_000
assert int.from_bytes(spans[0x36abb24][-4:], "little") == 135

def framing(length, header, spans):
    if length < 135:
        return 0x8a
    if header > length - 77 or sum(spans) > 50_000_000:
        return 0x8b
    if sum(spans) != length - 77 - header:
        return 0x8c
    return None

assert framing(134, 57, []) == 0x8a
assert framing(135, 59, []) == 0x8b
assert framing(135, 57, []) == 0x8c
assert framing(135, 57, [1]) is None
assert framing(50_000_078, 0, [50_000_001]) == 0x8b
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
