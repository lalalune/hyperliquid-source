# RE-017 · Node #115 replay queue initial segment and index

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [receive-descriptor packet](../RE-012-snapshot-replay-receive-descriptor-origin-115/README.md) projects the first replay probe through Q `+0x1a0` and Q `+0x80`, but leaves the initial segment and slot unresolved. [PR #5035](https://github.com/lalalune/hyperliquid-source/pull/5035) conditionally traces Q to the first word of result `+0x28` from `0x2cef6e0`, called at `0x2cc1827`. This packet examines that constructor and relates its initial fields to the existing probe.

The selected normal path first requests `0x220` bytes and zeroes segment `+0x200..+0x21f`. It constructs a `0x200`-byte object template at stack `+0x80`, requests an object through an indirect slot with arguments `(0x200, 7)`, and copies the template to the resulting object Q. The template stores the same new segment pointer at offsets Q `+0x80`, `+0x1a0`, and `+0x1a8`; it sets the producer reservation index at Q `+0x88` and reader index at Q `+0x1b0` to zero. After a separate small allocation and successful reference checks, `0x2cef84f` returns Q at result `+0x28`. The nonnull and reference-check failures take separate failure continuations; no particular allocator semantics beyond the observed calls are assumed.

If these constructor fields survive unchanged until the selected original-input probe in the earlier packet, the probe sees reader index 0, segment base 0 and the same current and old segment pointer. The selected slot is 0. Initially segment flag word `+0x210` is zero, so the slot bit and bit 33 are clear; under that unchanged, uninterleaved condition the probe returns tag 2, without accepting a row. This is a constructor-state result, **not** a claim that the actual first replay probe occurs before a producer writes or that checkpoint height implies any index. Intermediate calls, aliases, reference ownership, concurrency and real runtime reachability remain unresolved.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 92 selected instruction spans. Python 3.14.5 validates the target digest, FDE membership, call/branch bytes, two independent mutations, and synthetic pointer/index/readiness projections. LLVM separates lock prefixes, which must be concatenated when comparing the instruction bytes.

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

with Path("research/work-items/RE-017-node115-replay-queue-constructor/instructions.tsv").open() as handle:
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

assert rip_target(0x2cc1827)==0x2cef6e0
assert rip_target(0x2cef709)==0x64df480
assert rip_target(0x2cef7cf)==0x64df590
assert rip_target(0x2cef7f1)==0x64df508
assert rip_target(0x2cef712)==0x2cef895
assert rip_target(0x2cef7d8)==0x2cef871
assert spans[0x2cef84f]==bytes.fromhex('4d896e28')
assert spans[0x581a11b]==bytes.fromhex('7421')
assert spans[0x581a279]==bytes.fromhex('7320')
assert spans[0x581a29b]==bytes.fromhex('480fbae221')
for addr in (0x2cef84f,0x581a276):
    changed=bytearray(spans[addr]); changed[-1]^=1
    assert changed!=elf_bytes('.text',addr,len(changed))
segment=bytearray(0x220);q=bytearray(0x200);pointer=0x12345678
for off in (0x80,0x1a0,0x1a8):struct.pack_into('<Q',q,off,pointer)
for off in (0x88,0x1b0):struct.pack_into('<Q',q,off,0)
read=lambda off:struct.unpack_from('<Q',q,off)[0]
index=read(0x1b0);base=struct.unpack_from('<Q',segment,0x200)[0];flags=struct.unpack_from('<Q',segment,0x210)[0]
assert read(0x80)==read(0x1a0)==read(0x1a8)==pointer
assert read(0x88)==index==0 and (index&~31)==base and (index&31)==0
assert not(flags&(1<<(index&31))) and not(flags&(1<<33))
assert (1 if flags&(1<<33) else 2)==2
flags |= 1
assert flags & (1<<(index&31))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
