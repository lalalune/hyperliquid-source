# RE-009 · Node #115 checkpoint two-ended small-sort merge

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [checkpoint prune small-sort packet](../RE-009-node115-checkpoint-prune-small-sort/README.md) identifies `0x14c6420` and its final copy without proving the merge. The distinct prefix networks in [#5920](https://github.com/lalalune/hyperliquid-source/pull/5920) and [#5921](https://github.com/lalalune/hyperliquid-source/pull/5921) do not establish whole-half sorting. This packet addresses the later merge, assuming both halves are already sorted as unsigned 64-bit words, valid contiguous input, and normal copy completion.

For a selected N=18..32 helper input, let L=floor(N/2). After the selected half-processing paths, `0x14c6a50` repeatedly compares both half fronts, writes the smaller word to the next front position of a local output, compares both half backs, and writes the larger word to its next back position. It advances the selected cursors and repeats L times. For odd N a separate branch supplies the middle word. Cursor exhaustion is checked before the N*8-byte copy back; the mismatch branch calls a failure slot instead. On a normal comparator/copy path, this joins two sorted halves into ascending unsigned order. Equality selects left at the front and right at the back. This contract is conditional: the packet does not establish that the earlier halves are sorted, live inputs reach the branch, the helper as a whole is correct, or a checkpoint state root matches. No target code is executed.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 83 selected spans. Python checks target identity, FDE bounds, selected branches and memcpy relocation, then models the two-ended cursor logic on all sorted binary half pairs for lengths 18–32, selected unsigned edge cases, and a reversed front-selection mutation. This model is derived from the cited instructions; it is not target execution.

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

with Path("research/work-items/RE-009-node115-checkpoint-small-sort-merge/instructions.tsv").open() as handle:
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

assert len(spans)==83
def short(a):
 raw=spans[a];return a+len(raw)+struct.unpack_from('<b',raw,len(raw)-1)[0]
assert short(0x14c6ab0)==0x14c6a50
assert short(0x14c6abe)==0x14c6af8
assert short(0x14c6acd)==0x14c6b2d
assert rip_target(0x14c6ae0)==0x64df508
info,_=relocations[0x64df508]
assert info & 0xffffffff == 6
symtab=next(s for s in sections if s['name']=='.dynsym')
strtab=next(s for s in sections if s['name']=='.dynstr')
name=struct.unpack_from('<I',data,symtab['offset']+(info>>32)*24)[0]+strtab['offset']
assert data[name:data.index(b'\0',name)]==b'memcpy'
def merge(a, mutate=False):
 n=len(a);h=n//2
 lf,lb,rf,rb=0,h-1,h,n-1
 out=[None]*n
 for i in range(h):
  assert all(0<=v<n for v in (lf,lb,rf,rb))
  if (a[rf]<a[lf]) != mutate:out[i]=a[rf];rf+=1
  else:out[i]=a[lf];lf+=1
  if a[rb]>=a[lb]:out[n-1-i]=a[rb];rb-=1
  else:out[n-1-i]=a[lb];lb-=1
 if n%2:
  if lf<=lb:out[h]=a[lf];lf+=1
  else:out[h]=a[rf];rf+=1
 assert lf==lb+1 and rf==rb+1
 return out
cases=0
for n in range(18,33):
 h=n//2
 for l in range(h+1):
  for r in range(n-h+1):
   a=[0]*l+[1]*(h-l)+[0]*r+[1]*(n-h-r)
   assert merge(a)==sorted(a)
   cases+=1
 a=sorted([2**64-1,2**63,0,4,4]*(h//5)+[7]*(h%5))+sorted([2**64-1,2**63,0,4,4]*((n-h)//5)+[8]*((n-h)%5))
 assert merge(a)==sorted(a)
a=[0]*9+[1]*9
try:
 result=merge(a,mutate=True)
except AssertionError:
 result=None
assert result!=sorted(a)
for address in (0x14c6ab0,0x14c6ae0):
 bad=bytearray(spans[address]);bad[-1]^=1
 assert bad!=elf_bytes('.text',address,len(bad))
print(f'{len(spans)} authenticated spans, {cases} binary half-pair models pass')
PY
```
