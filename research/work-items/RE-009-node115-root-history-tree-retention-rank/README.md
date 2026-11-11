# RE-009 · Node #115 tree root-history retention rank

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `0781ce04826eeefd89fe336cb8ea073be0c1de30`.

The [history retention walk](../RE-009-node115-root-history-retention-walk/README.md) establishes the threshold and later 43 successful advances but leaves the tree cursor and resulting rank open. [#5935](https://github.com/lalalune/hyperliquid-source/pull/5935) establishes the rank for the distinct flat-ring representation. This packet examines the selected non-owning tree cursor `0x514dc20`.

For a valid ordered tree, accurate remaining count and valid parent/child links, the wrapper initializes a tree cursor with its root, height and count. The cursor decrements remaining count; on its first advance it descends by each node's rightmost child to a leaf. It returns a node's key at slot−1 and updates its cursor to the preceding in-order position: a leaf decrements its slot, while an internal key stages the rightmost descendant of the child immediately before that key. Exhausted slots ascend through the stored parent and child-slot links. Invalid tag or unexpected missing parent reaches separate failure paths. This is a non-owning selected cursor; the owning cleanup cursor is not claimed here.

The selected wrapper makes seven successful initial tree advances, then 43 successful `0x4e2a530` calls which route the tree representation to this helper. For N>=51 valid rows, the cutoff is the 50th key in reverse in-order, equivalently logical ascending index N−50. This does not establish the tree cutoff's publication effects, runtime structure, persistence or state-root equivalence. The result assumes a well-formed tree, consistent count, no intervening mutation and normal returns. No captured binary executes.

## Reproduce

GNU objdump 2.45 and LLVM objdump 23.1.4 agree on 175 selected spans. Python verifies the pinned target, indexed FDEs, tree entry/projection and seven wrapper calls; it independently authenticates the 43 call/test/exit sequences used by the prior packet. A synthetic parent-linked tree model checks reverse traversal and cutoff rank with one or three keys per node, including duplicate keys. It is not target execution.

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

with Path("research/work-items/RE-009-node115-root-history-tree-retention-rank/instructions.tsv").open() as handle:
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

assert len(spans)==175
assert rip_target(0x4e2a533)==0x514dc20
assert rip_target(0x514dc35)==0x514dec6
assert rip_target(0x514dd6a)==0x514deb7
assert spans[0x514dc2a]==bytes.fromhex('48ffc8')
assert spans[0x514de82]==bytes.fromhex('488d04d1')
assert spans[0x514de86]==bytes.fromhex('480568010000')
for addr in (0x5a040b7,0x5a0410d,0x5a04166,0x5a041c3,0x5a0422d,0x5a04282,0x5a042ec):
 assert rip_target(addr)==0x514dc20
for i in range(43):
 a=0x5a042ff+i*0x13
 b=elf_bytes('.text',a,14)
 assert b[0]==0xe8 and a+5+struct.unpack_from('<i',b,1)[0]==0x4e2a530
 assert b[5:8]==bytes.fromhex('4885c0') and b[8:10]==bytes.fromhex('0f84')
 assert a+14+struct.unpack_from('<i',b,10)[0]==0x5a040aa
assert rip_target(0x5a0464a)==0x4de5ad0
class Node:
 def __init__(self,keys,parent=None,slot=0):self.keys=keys;self.parent=parent;self.slot=slot;self.children=[]
def size(width,height):return (width+1)**(height+1)-1
def build(vals,width,height,parent=None,slot=0):
 assert len(vals)==size(width,height)
 node=Node([],parent,slot)
 if not height:node.keys=list(vals);return node
 part=size(width,height-1);at=0
 for i in range(width):
  node.children.append(build(vals[at:at+part],width,height-1,node,i));at+=part
  node.keys.append(vals[at]);at+=1
 node.children.append(build(vals[at:],width,height-1,node,width))
 return node
def rightmost(node):
 while node.children:node=node.children[-1]
 return node,len(node.keys)
def walk(root,count):
 node,pos=rightmost(root);out=[]
 for _ in range(count):
  while pos==0:
   assert node.parent is not None
   pos=node.slot;node=node.parent
  out.append(node.keys[pos-1])
  if node.children:node,pos=rightmost(node.children[pos-1])
  else:pos-=1
 return out
for width,height in ((1,5),(1,6),(1,7),(3,2),(3,3)):
 n=size(width,height)
 for divisor in (1,3):
  vals=[i//divisor for i in range(n)]
  out=walk(build(vals,width,height),n)
  assert out==list(reversed(vals)) and out[49]==vals[n-50]
for a in (0x514dc35,0x5a0464a):
 bad=bytearray(spans[a]);bad[-1]^=1
 assert bad!=elf_bytes('.text',a,len(bad))
print(f'{len(spans)} authenticated spans, 43 further edges and tree models pass')
PY
```
