# RE-017 · Node #115 first published replay queue row

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

This combines the target-backed [segmented probe](../RE-017-node115-replay-segmented-probe/README.md), [receive poll](../RE-017-node115-replay-receive-poll/README.md), [producer publication](../RE-017-node115-replay-queue-publish/README.md), and the conditional constructor and capture chains in [#5038](https://github.com/lalalune/hyperliquid-source/pull/5038) and [#5040](https://github.com/lalalune/hyperliquid-source/pull/5040). It answers one integration question: if the selected producer publishes exactly once to the unchanged freshly constructed queue before the selected first original-input receiver probe, what pair does that probe yield?

The constructor starts the producer and reader indexes at zero, both segment pointers at the same zero-initialized segment, and object `+0x1c0` at zero. On the selected successful producer CAS, that word becomes 2; the producer stages a pair `(0, P)` and invokes `0x581b0c0`. Its atomic reservation returns old index 0, so the matching zero-base segment and slot 0 take the direct store; the helper writes the pair and sets bit 0 of segment `+0x210`. The receiver calls `0x581a100` on Q's reader and producer descriptors. The initial reader index and base select the same segment and slot; the now-set bit admits the two words, advances the reader index to 1 and returns probe tag 0. The receiver's selected no-borrow path subtracts 2 from object `+0x1c0`, stages the same pair and sets its local result tag 1.

The executable projection below tests these observations with synthetic pointer-sized values and a corruption control. It assumes the conditional identity chain, all stated paths, no helper or alias changes and a single producer followed by a consumer with no interleaving. It does not identify P or prove pointer validity, live scheduling, real replay acceptance, checkpoint height, or a state root. If a producer changes the descriptor or another operation intervenes, this test says nothing about that execution. The tags are internal helper results, not block validity.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 82 selected instructions; Python 3.14.5 validates the target digest, full FDE membership, selected direct edges, mutation controls, and the synthetic state transitions. LLVM separates lock prefixes in its listing.

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

with Path("research/work-items/RE-017-node115-replay-first-published-row/instructions.tsv").open() as handle:
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
    raw=spans[address]
    return address+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert rip_target(0x5a889db)==0x581b0c0
assert rip_target(0x5ab6f81)==0x581a100
assert rip_target(0x5ab6f8e)==0x5ab7030
assert short_target(0x581b0eb)==0x581b0f6
assert rip_target(0x581b0f1)==0x581b23e
assert short_target(0x581a11b)==0x581a13e
assert short_target(0x581a145)==0x581a26b if len(spans[0x581a145])==2 else rip_target(0x581a145)==0x581a26b
assert short_target(0x581a279)==0x581a29b
assert short_target(0x5ab703f)==0x5ab7075
for addr in (0x581b252,0x581a276,0x5ab7030):
    bad=bytearray(spans[addr]);bad[-1]^=1
    assert bad!=elf_bytes('.text',addr,len(bad))
for payload in (1,0x1000,0x123456789abcdef0):
    segment=bytearray(0x220);producer_index=reader_index=word=0
    assert struct.unpack_from('<Q',segment,0x200)[0]==(producer_index&~31)
    assert word&1==0 and word!=0xfffffffffffffffe
    word+=2
    reservation=producer_index;producer_index+=1
    slot=reservation&31
    struct.pack_into('<QQ',segment,slot*16,0,payload)
    flags=struct.unpack_from('<Q',segment,0x210)[0] | (1<<slot)
    struct.pack_into('<Q',segment,0x210,flags)
    assert slot==0 and flags&1
    assert struct.unpack_from('<Q',segment,0x200)[0]==(reader_index&~31)
    assert flags & (1<<(reader_index&31))
    observed=struct.unpack_from('<QQ',segment,(reader_index&31)*16)
    reader_index+=1;probe_tag=0
    assert observed==(0,payload) and probe_tag==0 and reader_index==1
    assert word>=2
    word-=2;receiver_tag=1
    assert word==0 and receiver_tag==1
    assert not ((flags&~1)&1)
print(f"{len(spans)} authenticated instruction spans and isolated publication/probe cases match")
PY
```
