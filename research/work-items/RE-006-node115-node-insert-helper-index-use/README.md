# RE-006: node 115 node insert/split helper's use of the forwarded slab slot index

## Claim

Forward 2 (`0x51d1b00`, packet
RE-006-node115-forward-callee-index-use) forwards the RE-006
slab slot index one level down when the sorted-set leaf is
full: to the node insert/split helper `0x4c49f90`, as `rdx` and
inside a stack context record passed in `rcx`. After the
helper returns, forward 2 increments the handle total
unconditionally. This packet traces the helper end to end and
settles the question that packet left open: **the index is
stored as a node key on every path that returns, so the
unconditional increment cannot diverge from an actual store.**

**Argument contract** (verified against forward 2's call site
`0x51d1c2a` and the helper's prologue): `rdi` = an out record
pointer; `rsi` = a cursor record `{+0x0: leaf node, +0x8: 0,
+0x10: insertion position}` (duplicated in `r8`, which the
helper never reads before overwriting); `rdx` = the index;
`rcx` = a context record `{+0x0: handle, +0x8: the index
again, +0x10: leaf node, +0x18: 0, +0x20: position}`.

**The helper** is a B-tree insert over the forward-2 node
layout (parent pointer at `+0x0`, sorted qword keys from
`+0x8`, at most 11, this node's child-index word at `+0x60`,
key-count word at `+0x62`, child pointers from `+0x68`; leaf
nodes `0x68` bytes, internal nodes `0xc8`). The index is
captured into `r12` at `0x4c49f9e`. An operand scan shows the
captured value is read at exactly two sites, both stores of
the index as a key at `node+0x8+position*8`:

1. **Fast path** (count < 11): the tail is shifted with
   `memmove` (slot `0x64df568`) and the index is stored at
   `0x4c49fee` into the node itself; the count word is
   incremented (`0x4c49ff3`) and the path jumps to the shared
   epilogue.
2. **Leaf split** (count >= 11): a fresh `0x68` node is
   allocated (slot `0x64df480`), keys above the separator are
   copied with `memcpy` (slot `0x64df508`), and the index is
   stored at `0x4c4a119` into the old or the new node -- split
   point by insertion position P: P < 5 -> separator 4, old
   node; P = 5 -> separator 5, old node; P = 6 -> separator 5,
   new node at 0; P >= 7 -> separator 6, new node at P-7 --
   **before any split propagation runs**.

Everything after the leaf-level store propagates the separator
key, never the index: `r12` is rewritten to a node pointer at
`0x4c4a1f4` (parent split) and `0x4c4a3fb` (root split), picked
as an insert target at `0x4c4a2c5`, and reused as a fixup-loop
counter from `0x4c4a4a3`; every later `r12` read uses one of
those values (the only `cmp`/`test` reads of `r12` are the
root null check and two loop counters). A full parent is split
the same way (fresh `0xc8` node, separator stored at
`0x4c4a32c`) and absorbs the separator when it has room
(`0x4c4a50b`); the root split builds a fresh `0xc8` root with
the separator as its only key (`0x4c4a483`), updating the
handle root/height through the context record's `+0x0` field.
**No instruction compares the captured index against a node
key: the helper has no duplicate path** and trusts the
caller's cursor position and counts.

**Every-path proof.** The claim is proven on the decoded
control-flow graph (473 instructions), not by reading order:
with the two store instructions removed from the graph,
neither the shared epilogue entry `0x4c4a5da` nor the body's
single `ret` (`0x4c4a5f6`) is reachable from the entry, so
every normal-return path executes exactly one of the two
stores. The only other reachable terminals are two `ud2`
sites (`0x4c4a6c8`, `0x4c4a70c`) behind the panic and
allocation-failure blocks (slots `0x64df570`, `0x64df730`,
`0x64df830`, `0x64df490`); on those paths the process aborts
and forward 2's increment does not run. The `_Unwind_Resume`
landing pads (`0x4c4a710`--`0x4c4a732`, cleanup via slot
`0x64df4a0`) are unreachable in the normal graph -- LSDA-only.

**Records.** The context record is saved at `0x4c4a00d` and
read exactly once (`0x4c4a3f3`, field `+0x0` only); it is
never written through, and its `+0x8` copy of the index is
never read -- the helper takes the index from `rdx`. The
cursor record is likewise read-only. The out record is
written once, by the shared epilogue (`[out] = rbp`,
`[out+0x8] = rcx`, `[out+0x10] = rax`, `rax = rdi` returned);
forward 2 discards it.

**Shared helper.** A whole-`.text` census finds exactly three
direct `E8` call sites into the helper and no `E9`
references: forward 2's (`0x51d1c2a`) and one in each of two
351-byte structural twins of forward 2 (`0x51d4920`,
`0x51d4a80`) whose call-site setup is instruction-identical.
The helper is a shared B-tree insert; this packet establishes
what it does with the key argument, which in the RE-006
caller is the slab slot index. The values the two twin
callers pass are not traced.

**Secondary: the lookup callees are not the forward-1 map
readback.** The two callees the RE-006 callers run between
forward 1 and forward 2 (`0x4da81b0` from callers 1/3,
`0x4da7880` from callers 2/4) contain no forward-1 probe
signature: the scrambled-hash constant `0xf1357aea2e62a9c5`
and any `rol ..., 0x14` are absent from both bodies. Each
instead resolves an element pointer by array-stride
arithmetic over the fields of the record at `rdi` (gated by
`dword [rdi] == 1`): a fast path returning
`[rdi+0x8] + [rdi+0x18]*0x58 + 0x8` (imul at `0x4da8289` /
`0x4da7959`), and a slow path that materialises the array
through a helper call and returns an element at a `0x70`
stride (imul at `0x4da834b` / `0x4da7a1b`) with a bounds abort
via slot `0x64df770`. The forward-2 handle is the field at
`result+0x40` of such an element. They are shared container
accessors: the census finds 14 direct call sites into
`0x4da81b0` and 12 into `0x4da7880`, four per RE-006 caller
plus further FDEs. Who reads the forward-1 map back remains
open.

## Scope

| Owner | FDE range | Bytes | SHA-256 | Index argument |
| --- | --- | ---: | --- | --- |
| `node_insert` | `0x4c49f90..0x4c4a737` | 1,959 | `b56c5f0edade1f99c0dc818624d46c29912660b712b382cdd0cfb206c861f265` | `rdx` |

The measured denominator is the one complete helper FDE:
1,959 bytes. Its full disassembly export is retained, as are
the full exports of the two lookup callees (472 bytes each).
Forward 2, the two twin helper callers, and the four RE-006
lookup callers are hash-pinned boundaries (call sites and
argument-setup instructions only); the seven slot-target FDEs
below the helper and the lookups are likewise hash-pinned
boundaries, cited by their slot bindings, not re-derived.

## Method

`tools/node_insert_helper_index_use_static.py` authenticates
the whole node 115 capture by size and SHA-256 before
generation. Analysis derives all seventeen FDE ranges from
the FDE extents, re-derives every body hash, scans the whole
`.text` for direct `E8`/`E9` references to the helper and the
two lookup callees, confirms no relative relocation reaches
or is held by any pinned body except through the recorded
slot bindings, and verifies every recorded slot binding
(including the two `GLOB_DAT` bindings, `memcpy`/`memmove`,
resolved through the dynamic symbol table). Every flow
instruction is pinned byte-exactly (each validated as a native
instruction start during generation). The helper's store
proof is computed on the decoded instruction-level
control-flow graph: reachability with the two store
instructions removed, the reachable terminal set, the
epilogue entry sets, and the landing pads' unreachability.
The index lifetime is an operand-level scan: the `r12` read
set is partitioned by reachability that may not pass a later
`r12` write, leaving exactly the two stores as index-valued
reads.

## Trace

1. **Entry.** `r12 = rdx` (the index); `rbp = [rsi]` (the
   leaf node); count word loaded; `count >= 0xb` branches to
   the leaf split.
2. **Fast path.** Tail memmove, index store at `0x4c49fee`,
   count store, jump to the epilogue at `0x4c4a5da`.
3. **Leaf split.** Records saved (`rdi` at `[rsp+0x38]`,
   `rcx` at `[rsp+0x50]`); position arithmetic selects the
   separator and target; allocation; separator load into
   `r13`; key copy; old count truncated; target picked by
   `cmove`; index store at `0x4c4a119`; count store.
4. **Propagation.** Separator inserted level by level:
   absorb (separator/child/count stores at
   `0x4c4a50b`/`0x4c4a514`/`0x4c4a519`) or split (fresh `0xc8`
   node, key/child copies, separator store at `0x4c4a32c`),
   with child parent/index fixup loops; the level counter
   seeded from `[cursor+0x8]` is incremented per split level
   and checked against the handle height at the root.
5. **Root split.** Handle read through the saved context
   record; fresh `0xc8` root; old root becomes child 0, the
   new node child 1, the separator the only key; handle root
   and height updated.
6. **Exits.** One shared epilogue and `ret`; panic and
   allocation-failure blocks converge on `ud2`; exception
   landing pads call the cleanup slot and `_Unwind_Resume`.
7. **Lookups.** Entry loads `[rdi+0x8]`/`[rdi+0x10]`/
   `[rdi+0x18]`, gate on `dword [rdi] == 1`, `0x58`-stride fast
   return, `0x70`-stride slow return after materialisation;
   no hash constant, no `rol 0x14`, no 24-byte entry walk.

## Boundary

The packet ends at the helper body and the two lookup
bodies. The internals of the allocation, panic, cleanup and
materialisation targets (`0x6355830`, `0x141e251`,
`0x16817e0`, `0x1680e60`, `0x1680c10`, `0x635de30`,
`0x1680bd0`, `0x51ecc40`, `0x57ebd20`, `0x51f4280`,
`0x57e95c0`) are recorded by address and binding only. The
values the helper's two twin callers and the lookups' other
callers pass, the contents of the lookup element records
beyond the `+0x40` handle field the RE-006 callers consume,
and the semantic payload of the helper's out record beyond
its fast-path values are not established here.

## Next question

Who reads the forward-1 map back -- which function probes the
24-byte-entry table with the scrambled hash of a key and
returns the stored slab slot index, and where is that returned
index consumed? And inside the sorted set the helper
maintains: who consumes the member keys on the read side (the
descend/search counterpart of forward 2's insert path)?

## Validation

```sh
python3 tools/node_insert_helper_index_use_static.py
python3 -m unittest tests.test_node_insert_helper_index_use_static
sha256sum -c MANIFEST.sha256  # run in this directory
```

The test regenerates the packet into a temporary directory
and requires byte identity with the retained files, checks
the census, trace facts (the two index store sites, the
capture/compare read sets, the exit sets, both lookup
verdicts) and the classification models, and mutates eight
pinned bytes or records -- the capture, both index stores,
the index-register rewrite, forward 2's helper call
displacement (census), a caller lookup call opcode (census),
lookup A's stride multiply, and an uncited byte in a
downstream body (body digest) -- requiring `analyze` to reject
each mutation.
