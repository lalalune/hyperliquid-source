# RE-017 · Node #115 replay queue stream-result source

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The existing [loader-handoff packet](../RE-017-abci-loader-handoff-115/README.md) identifies the `0x2cbbbe0 -> 0x2cc1120` call, while [PR #5033](https://github.com/lalalune/hyperliquid-source/pull/5033) conditionally traces the first qword of its caller's result `+0x388` into the replay callback. This packet identifies a selected producer of that result window.

In helper `0x2cc1120`, call `0x2cc1827` passes a result address at stack `+0x140`, literal address `0x60f46e`, length 28, and integer 5000 to `0x2cef6e0`. The target bytes of the literal read `nv stream client block or tx`. After this call, instructions `0x2cc186c/0x2cc1874` and `0x2cc185c/0x2cc1864` transfer result bytes `+0x28..+0x47` into stack `+0x1b90..+0x1baf`. On the selected later continuation those bytes move via stack `+0x15c0..+0x15df` into helper output `+0x388..+0x3a7` at `0x2cc2966/0x2cc296f`.

The calling helper's non-tag-2 branch copies `0x3b8` bytes from its inner-result stack buffer to an intermediate buffer, and, on the selected normal continuation, copies the same size to its own output. Thus this 32-byte window can be joined to #5033's `+0x388` window. The literal is an observed argument, not proof of the meaning of every field. The join assumes both selected continuations, normal copy returns, consistent stack/object identity and no intervening mutation or aliasing. The `0x2cef6e0` internals, the actual first-qword value Q, live producer identity, scheduling, and concrete checkpoint/slot remain unresolved. Tag 2 instead takes the caller's separate return branch.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 48 selected instruction spans; Python 3.14.5 verifies target SHA-256, FDEs, transfers, literal bytes, and a corruption control. The synthetic offset projection tests both halves of the 32-byte window and is not a runtime replay.

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

with Path("research/work-items/RE-017-node115-replay-queue-stream-source/instructions.tsv").open() as handle:
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

assert rip_target(0x2cc180e)==0x60f46e
assert elf_bytes('.rodata',0x60f46e,28)==b'nv stream client block or tx'
assert rip_target(0x2cc1827)==0x2cef6e0
assert rip_target(0x2cbc4b4)==0x2cc1120
assert rip_target(0x2cbc517)==0x64df508
assert rip_target(0x2cbc559)==0x64df508
assert spans[0x2cbc4c1]==bytes.fromhex('751b')
assert 0x2cbc4c1+2+0x1b==0x2cbc4de
source=bytes(range(72))
assert 0x168-0x140==0x28
out=bytearray(0x3b8);out[0x388:0x3a8]=source[0x28:0x48]
intermediate=out[:];outer=intermediate[:]
assert outer[0x388:0x3a8]==source[0x28:0x48]
assert outer[0x388:0x3a8]!=source[0x27:0x47]
mutated=bytearray(spans[0x2cc2966]);mutated[-1]^=1
assert mutated != elf_bytes('.text',0x2cc2966,len(mutated))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
