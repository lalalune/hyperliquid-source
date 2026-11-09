# RE-009 · Node #115 checkpoint numeric sorting for 21–32 entries

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [canonical-height restore packet](../RE-017-node115-restore-canonical-heights/README.md) links checkpoint enumeration to this shared numeric ordering path but validates its insertion branch only through 20 entries. The [prune path packet](../RE-017-abci-prune-path-115/README.md) identifies the large-sort boundary. [#5923](https://github.com/lalalune/hyperliquid-source/pull/5923), conditional on [#5920](https://github.com/lalalune/hyperliquid-source/pull/5920), [#5921](https://github.com/lalalune/hyperliquid-source/pull/5921), and [#5922](https://github.com/lalalune/hyperliquid-source/pull/5922), models the selected smaller helper.

For a valid unsigned-word vector with N=21..32, the selected `0x15504d0` path returns immediately if it is nondecreasing; if it is strictly decreasing, it reverses the vector in four-pair groups and a scalar remainder. Equality breaks the strictly decreasing scan. A mixed run transfers to `0x15506d0`, whose N<33 branch tail-jumps to `0x14c6420`. Subject to the cited conditional helper composition, all three routes return ascending numeric words. The restore caller then reverses the resulting 24-byte rendered records as documented by the canonical-height packet; that further conclusion requires its existing formatting and no-interference assumptions.

This is not a standalone proof of the dependent helper, actual filesystem enumeration, physical checkpoint contents, or state-root equality. It assumes valid buffers, unchanged data across the selected calls and normal returns. No captured target code executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 95 selected spans. Python verifies target identity, FDEs, selected control transfers, vector/scalar reversal arithmetic and synthetic ordered, descending and mixed inputs. The mixed-route model assumes the cited helper returns ascending order; it does not execute the target.

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

with Path("research/work-items/RE-009-node115-checkpoint-enumeration-sort-21-32/instructions.tsv").open() as handle:
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

import random
assert len(spans)==95
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert short(0x15504ec)==0x1550516
assert short(0x155050a)==0x155051c
assert short(0x155054a)==0x155051c
assert short(0x155051f)==0x1550554
assert rip_target(0x1550536)==0x15506d0
assert short(0x15506e9)==0x1550708
assert rip_target(0x1550703)==0x14c6420
def selected(a):
 n=len(a);assert 21<=n<=32
 descending=a[1]<a[0]
 for i in range(2,n):
  if (a[i]>=a[i-1]) if descending else (a[i]<a[i-1]):
   return 'mixed',sorted(a) # dependent helper contract, not target execution
 if not descending:return 'ascending',a[:]
 out=a[:];h=n//2;groups=h//4*4
 for i in range(0,groups,4):
  for j in range(4):out[i+j],out[n-1-i-j]=out[n-1-i-j],out[i+j]
 for i in range(groups,h):out[i],out[n-1-i]=out[n-1-i],out[i]
 return 'descending',out
rng=random.Random(115)
for n in range(21,33):
 a=list(range(n));assert selected(a)==('ascending',a)
 d=list(reversed(a));assert selected(d)==('descending',a)
 equal=[5]*n;assert selected(equal)==('ascending',equal)
 mixed=d[:];mixed[2]=mixed[1]
 assert selected(mixed)[0]=='mixed' and selected(mixed)[1]==sorted(mixed)
 for _ in range(100):
  v=[rng.randrange(0,1<<64) for _ in range(n)]
  assert selected(v)[1]==sorted(v)
for a in (0x1550536,0x1550703):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans and selected ordering models pass')
PY
```
