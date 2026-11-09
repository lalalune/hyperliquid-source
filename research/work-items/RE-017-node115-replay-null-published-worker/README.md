# RE-017 · Node #115 published null-first pair at the replay worker

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The existing [replay-record identity packet](../RE-017-node115-replay-record-identity/README.md) maps the worker's null-first-payload path; [#5040](https://github.com/lalalune/hyperliquid-source/pull/5040) identifies a selected producer that stages `(0, P)`, and [#5041](https://github.com/lalalune/hyperliquid-source/pull/5041) conditionally connects one publication to a probe. This packet joins the selected receiver output to the worker's previously described alternate arm.

The producer increments `[P]` at `0x5a88954`, stages `(0, P)`, and calls the queue publisher. If that same pair is returned by the selected ready probe, the receiver's selected normal publication copies it into its result `+8/+16` and writes tag 1. The worker accepts tag 1, loads the first and second payload words, and tests the first. A zero first word takes `0x5a6e380`, stages `(0, P)`, invokes callback `0x5a63100` with selector 1, and atomically decrements `[P]` after the call. A nonzero decrement result returns directly to retrieval; zero calls the release slot before that return. No explicit expected-word store appears on this local null-first arm.

This is a conditional composition, not proof that a real first replay item has this shape or that the callback leaves the expected word or reference count unchanged. The join assumes the same live queue object and pair, valid P, successful publication/receive, selected normal continuations and no intervening corruption or alias effects. The non-null record-validation path is not taken under the stated first-word condition; this observation neither validates a block nor establishes a state root. No captured binary is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 60 selected instruction spans (LLVM prints lock prefixes separately). Python 3 verifies target identity, FDE bounds, selected transfers and a corrupted instruction; synthetic branch and refcount examples are local controls, not runtime results.

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

with Path("research/work-items/RE-017-node115-replay-null-published-worker/instructions.tsv").open() as handle:
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

def short_target(address):
    raw=spans[address];return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x5a889db)==0x581b0c0
assert rip_target(0x5ab6f81)==0x581a100
assert rip_target(0x5ab6f8e)==0x5ab7030
assert rip_target(0x5a6e328)==0x5ab6df0
assert rip_target(0x5a6e335)==0x5a70087
assert short_target(0x5a6e34e)==0x5a6e380
assert rip_target(0x5a6e39c)==0x5a63100
assert rip_target(0x5a6e3a6)==0x5a6e318
assert rip_target(0x5a6e3b1)==0x64e4cb8
assert rip_target(0x5a6e3b7)==0x5a6e318
for first,refs in ((0,1),(0,2),(1,2)):
    null_arm=first==0
    if null_arm:
        assert (refs-1==0)==(refs==1)
        assert (0,0x1000)[0]==0
    else: assert first!=0
for addr in (0x5a6e34e,0x5a6e3a1):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
print(f"{len(spans)} authenticated instruction spans and selected edges match")
PY
```
