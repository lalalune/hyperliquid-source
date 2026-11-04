# RE-001: map node #115 list-append routine 0x5d54630 with its five-deep handler chain

Bounded question: what does the 583-byte routine at 0x5d54630 do
end to end — which handler produces the new node's payload, how is
the 0x48-byte node filled and linked, and when does it instead
destroy the node and return NULL?

## Answer, end to end

Arguments: rdi = holder, esi = one byte stored at node +0x40,
edx = flag byte selecting the mutex entry helper. The routine
returns the new node, or NULL on the destroy path.

### 1. Five-deep handler chain walk

The chain head is holder +0x540; each node links to the next at
+0x20 and carries a function value at +0xc0 (a vtable slot of the
node's object). The walk compares:

- node 0's slot against the qword stored at 0x64ed3e8 (whose
  relocation value is 0x5d4b100);
- each later node's slot against the previous node's slot.

The first node whose slot differs has its slot called; if the first
four slots all match, the fifth node's slot is called
unconditionally. The called handler receives (out_pair at rsp+0x10,
the chain node in rsi, aux slot at rsp+0x08). The handler's own body
is not pinned here — only the walk, the call shape and the use of
its outputs. After the call, the out pair's second element
(rsp+0x18) is freed with delete[] when non-null; the aux value
(rsp+0x08) becomes node +0x30.

### 2. Node allocation and mutex entry

A 0x48-byte node is allocated (operator new). Its vptr is
0x64c92d0 (relocation: slot 0 of that table is 0x5d484b0, slot
0x20 is 0x5d54f30) and node +0x10 is 1. Then:

- flag != 0: call 0x606ca40 on holder +0x700 (the acquire helper
  already pinned by call shape in the twin-guarded-query packet);
- flag == 0: call 0x60d5390 on the same holder +0x700 object.

0x60d5390's internal semantics are not pinned here; it is recorded
by call shape only, as the flag == 0 entry helper on the same mutex
object that 0x60d52f0 releases.

### 3. The destroy path (holder +0xc98 == 0)

When holder +0xc98 is zero, the node is destroyed through its
vtable slot 0x20 (relocation value 0x5d54f30) and the routine
returns NULL. The release pairing on this path is asymmetric, and
that asymmetry is literal:

- flag != 0: call 0x60d52f0 (release) on holder +0x700, then destroy;
- flag == 0: destroy directly, with no release call.

### 4. Node +0x08 selection (holder +0xc98 != 0)

- The holder's slot-0x480 function (from [holder] + 0x480) differs
  from the qword at 0x64ed550 (relocation value 0x5d48720): call it
  with the holder, and node +0x08 is its return value.
- Otherwise, when holder +0x17b2 is zero: node +0x08 is
  [[holder +0x68] + 0x120].
- Otherwise: node +0x08 is [[holder +0x68] + 0x108].

### 5. Fill, splice, return

- node +0x18 = holder +0x11e0 (address), node +0x20 =
  [holder +0x11f8] (anchor tail), node +0x28 = holder +0x11e0,
  node +0x30 = aux value from the produce call, node +0x38 = -1,
  node +0x40 = the esi byte.
- Splice, literally: [tail + 0x20] = node, [tail + 0x18] = node
  (the second write goes through node +0x20, i.e. the tail itself).
- holder +0x1228 count += 1.
- flag != 0: call 0x60d52f0 (release) on holder +0x700, then return
  the node. flag == 0: return the node with no release call.

The routine has a stack canary and no landing pads in its FDE
range; the chain walk itself never dereferences a null node on any
path the excerpt shows (every advance is unconditional).

## Consumers

Exactly two sites (exhaustive executable-LOAD-segment E8/E9 scan
with objdump confirmation, reproduced by census.py and re-run
inside verify.py; see callers.tsv):

1. 0x5d5488b, tail jump from the 16-byte wrapper at
   0x5d54880..0x5d54890 (pinned whole in wrapper.txt): holder
   passthrough in rdi, esi = 0, edx = 1 — the flag-set
   specialization, so wrapper callers take the acquire/release path.
2. 0x5dd8f05, direct call from 0x5dd8ea0..0x5dd9198 with rdi =
   rbp, esi = 0, edx = 0 — the flag-clear direct call; the caller
   keeps the returned node for the allocation that follows.

No stored qword or relocation references the routine
(relocations.txt is empty): it is reached only by code.

## Evidence and method

- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json (artifacts/node/115/hl-node).
- main.txt is the whole-function objdump excerpt for
  0x5d54630..0x5d54877, verbatim except the header normalized to
  the bare binary name; wrapper.txt is the whole-function excerpt
  for the 0x5d54880 wrapper. Detail at the single-step level lives
  only in those excerpts; records.json below carries semantic
  records, not a per-step list. The mnemonics in the excerpts
  (including `endbr64`) are genuine instructions present in the
  target binary, not placeholders.
- frames.txt holds the routine's FDE line plus one line per
  distinct caller FDE from the census.
- verify.py re-checks the digest, the manifest, byte-for-byte
  excerpt regeneration, every excerpt instruction line against the
  raw binary, every FDE line, the census, the relocation census,
  the semantic records and the model tests.
- Run the packet checker from the repository root:
  `python3 research/work-items/RE-001-node-link-54630-115/verify.py`
- Generate the excerpt with:
  `python3 research/work-items/RE-001-node-link-54630-115/export_excerpts.py`

## Unknowns (recorded, not claimed)

- The source names of the holder, the chain nodes and the node type.
- What each +0xc0 handler computes; only the walk and the use of
  the handler's outputs are pinned.
- The exact mutex semantics of 0x60d5390 beyond its call shape and
  pairing on the destroy path.
- The produced aux value's meaning; it is the handler's output, a
  model input, not a claim.
- The anchor's empty-list invariant: the splice is recorded as the
  four literal writes above, not as a named list operation.
- The body of the slot-0x20 destroy function 0x5d54f30 (pinned by
  relocation only).

## Environment limits

This packet was built on a VM with no cargo/rustc, no git-lfs and
no Ghidra/Java, using objdump/readelf against the materialized
node #115 binary only. No Rust reconstruction is claimed.
