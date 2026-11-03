# RE-006 node 115 sibling cursor search (the 0x35bf460 layout)

## Scope

This packet answers the open question left by the variant cursor packet
(RE-006-node115-variant-cursor): which set instances and node layouts the
sibling cursor search at `0x35bf460` serves, and who consumes its records.
That packet counted 99 direct call sites for this body — more than the
clones and both variants combined — and showed that at the first site of
each 2816-byte caller its record overwrites the variant search's record
at the join before any field is read. This packet pins the sibling body
in full, traces all 99 call sites in 63 caller FDEs field by field, traces
the three join sites end to end, and settles whether any consumer reads
this search's height field as a number, using the same whole-FDE
slot-census method as the earlier RE-006 packets.

Static analysis only, against the authenticated node #115 ELF (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Function boundaries are the FDE ranges of the shared unwind index
(135,313 records, all starts unique). The packet retains:

- `records.json` — every claim below in machine-checkable form;
- `frames.txt` — the readelf frame lines for the sibling body and the
  63 caller FDEs;
- `sibling_search_full_body_35bf460_35bf4f2_objdump.txt` — the full-body
  disassembly export (146 bytes);
- `tools/sibling_search_static.py` and
  `tests/test_sibling_search_static.py` — the checks that regenerate
  and verify all of it.

## Short answer

The sibling is the family search over one more node layout: eleven u64
keys at node + 0x798, count word at node + 0x7f2, child edges from
node + 0x7f8. The record and the ABI are the family standard: `rdi` =
record out (returned in `rax`), `rsi` = root node, `rdx` = height,
`rcx` = key pointer, dereferenced once; the record is `{+0x00 flag
(0 hit / 1 miss), +0x08 node, +0x10 height remaining, +0x18 position}`;
a hit leaves the equal-key index in the position field, a miss the
insertion index; descent follows child edges while height remains.
The body calls nothing and stores nowhere except into the record.

It serves exactly one node layout. What varies across the 99 sites is
not the layout but how the caller presents the family's 32-byte set
handle `{tag, root, height, bound}` to the search: embedded in a larger
caller record at +0x6c8 (root at +0x6d0, height at +0x6d8) at 52 sites,
embedded at +0x58 (root at +0x60, height at +0x68) at 6 sites, carried
by pointer (handle argument or walked list element; root at +0x8,
height at +0x10) at 37 sites, and with the root already in a register
and the height reloaded from a frame slot at 4 sites. Where the handle
tag is not the sentinel, the callers do not search at all: they pass
the handle to the family fallback `0x4556410` instead.

Consumption partitions exactly on the flag test's form:

- 60 sites test the flag as a dword (`cmpl $0x1` against the record).
  Every one of them consumes **node and position on a hit**: the flag
  test gates the element-address computation
  `node + position × 0xb0`, and the block-walk check in the tool proves
  for each of the 60 that the scaling block is reached exactly on the
  flag == 0 side of the branch.
- 39 sites test the flag as a byte (`cmpb $0x0`). In their own post-call
  windows they read only the flag — branching on hit/miss without
  forming an element address — except one site (`0x2a414f0`) that also
  passes `&node` onward to an indirect callee on the hit path.

The height field is never consumed as a number by anyone (see the
consumption verdict below).

## Method

Call sites are a byte scan of the executable sections for E8/E9 rel32
branches naming `0x35bf460`, cross-checked against a decode of every
caller FDE so each retained site is a genuine instruction boundary
(99 direct sites, 0 tail calls, 0 `R_X86_64_RELATIVE` relocations
naming the body). Each site retains a window from its argument setup
through its flag test and consumption block, with every setup load,
the call, the flag test and the consumption instructions pinned by
bytes and text; the three join windows extend through the shared tail
(see the trace). Per (caller, record base) unit — 67 units over the
63 callers, four callers keeping two record slots — the packet
retains a whole-FDE textual census of reads of each record slot
(flag +0x0, node +0x8, height +0x10, position +0x18): an instruction
counts when the slot appears in its operand text, it is not an `lea`,
and it is not a mov-family store into an rsp slot. Every height-slot
read the census finds is attributed individually: wholesale vector
copies are classed by instruction form, and every scalar read retains
its own phase window. `analyze()` in the tool performs all of these
checks without authenticating the artifact, so a flipped byte fails
the specific check it breaks; `generate()` authenticates first.

## Trace

### The sibling body

`0x35bf460..0x35bf4f2`, 146 bytes, SHA-256
`10b3b34cb2182f4c9bba0efbb6750ada3ec101615535406c3663df2b09f840ca` —
the same boundary the variant packet pinned when it counted this
body's call sites. The body is instruction-parallel to the variants:
save the out pointer in `rax`, dereference the key once
(`mov (%rcx),%rcx` at `0x35bf463`), load the count word
(`movzwl 0x7f2(%rsi),%r8d` at `0x35bf466`), scan the node's keys with
the three-way compare against `0x7a0(%rsi,%rdi,8)` from index −1 —
i.e. keys at node + 0x798 — and descend via
`mov 0x7f8(%rsi,%rdi,8),%rsi` at `0x35bf4cc` while the height in `rdx`
lasts. The hit epilogue (flag 0, at `0x35bf4d9`) and the miss epilogue
(flag 1, at `0x35bf4eb`) share the four stores: node to record +0x8,
the remaining height to +0x10, the final index to +0x18, the flag to
+0x0. The child-index word at node + 0x7f0 implied by the family's
layout pair (index/edge arrays interleaved around the keys) is never
read by this body.

### Call sites and handle presentations

The 99 sites sit in 63 caller FDEs; 23 callers hold more than one
site, up to five (`0x2c62820`, `0x55e16d0`). Many callers are clone
families of each other — the 2816-byte triple `0x2a89500` /
`0x55a07e0` / `0x55a12e0`, the `0x2a84990` / `0x55817e0` / `0x5581cb0`
triple, the giant pair `0x54a9c70` / `0x54b66b0` (51,762 and 50,232
bytes) and their neighbours `0x54cfa90` / `0x54d57b0` — and every
digest is pinned, so the census is over bodies, not names. Every
record is an rsp-relative frame slot; no site receives its record by
pointer. The key pointer is always a frame slot too (sites `0x421b45d`
and `0x451d280` pass `%rsp` itself).

Setup follows the family pattern: root and height are loaded from
the handle — whose tag the phase checks against the
`0x8000000000000000` sentinel — the search is called, and the record
flag is tested. Only the handle's presentation varies, as counted in
the short answer.

### The three joins, in full

At `0x2a89910` (caller `0x2a89500`) and its clones `0x55a0bf0`
(`0x55a07e0`) and `0x55a16f0` (`0x55a12e0`) the sequence is
byte-parallel, and the retained window runs from the setup loads
through the shared tail:

1. The variant search's call earlier in the phase wrote its record at
   `rsp + 0x80`. The sibling's setup loads root/height from the handle
   embedded at the phase's record + 0x6c8 and calls `0x35bf460` with
   `rdi = rsp + 0x80` — the same record. No field of the variant
   record is read in between (the variant packet's census).
2. `cmpl $0x1, 0x80(%rsp)`; `je` on flag == 1 (miss) skips the rest of
   the visit entirely — there is no element to visit.
3. On a hit, `imul $0xb0, 0x98(%rsp)` and `add 0x88(%rsp)` form the
   element pointer `node + position × 0xb0` in `rdi`, and a `jmp`
   reaches the shared tail.
4. The phase's other route — the handle that did not go through
   either search — first calls the family fallback `0x4556410` with
   the handle and the key; on an odd return the visit is skipped.
   Otherwise it computes the same pointer from the handle itself:
   bound check against `[rbx + 0x6e0]`, index plus `[rbx + 0x6d8]`,
   clamp, then `root + index × 0xb8 + 8` with root `[rbx + 0x6d0]`.
5. Both routes converge on `call *0x64e7198(%rip)` with `rdi` = the
   element pointer: one indirect callee, reached through the same
   GOT slot in all three callers, visits the element whichever search
   (or fallback walk) produced it.

### The family

The sibling is the fourth distinct node layout of the RE-006 cursor
family, after the clones and variants A (keys at node +0x8) and
B (keys at node +0x168). Its 99 call sites are the family's largest consumer set —
the two variants together have 26 — and its callers overlap the
family's: seven of the 63 caller FDEs are also digest-pinned
boundaries of the variant packet (`0x2a84e60`, `0x2a89500`, `0x2c61b30`,
`0x5582180`, `0x5585290`, `0x55a07e0`, `0x55a12e0`), with identical
digests in both packets.

## Consumption verdict

Field by field, over the 67 (caller, record base) census units, the
whole-FDE slot census counts 373 flag reads, 244 node reads, 124
position reads and 137 height reads.

- **Flag**: read at every site (the test itself) and used as the
  hit/miss branch everywhere.
- **Node and position**: consumed together, as
  `node + position × 0xb0`, at exactly the 60 dword-test sites, on
  the hit branch in every case. No site reads position without node
  in its consumption block.
- **Height**: 47 of the 67 units never read the height slot at all.
  The 137 reads in the other 20 units are, without exception,
  **not** reads of the sibling's result:
  - 38 are wholesale vector copies (`movups`/`movupd`/`movapd`/
    `movaps`/`movdqu`/`movdqa` loads of the height slot as half of a
    16-byte pair) that relocate the record or a same-shaped struct;
  - 99 are scalar reads belonging to other phases of the same frame
    slot, each with its own retained window. The recurring shapes:
    the slot reused as a `{pointer, count}` descriptor (count ×24 or
    ×104 strides), as a time-like struct whose +0x10 field is
    converted with `cvtsi2sd` or scaled by 1e9, as a tagged enum whose
    +0x10 word is the discriminant compared against 2, and as a
    callee out-struct. In the three handle-copy callers
    (`0x2bb2ec0`, `0x547d430`, `0x547d910`) the slot is provably
    overwritten with a fresh handle copy — twice, each time as the
    argument of a following call; the overwrite blocks are retained
    as windows — before its only scalar height read, which copies the
    later struct out. In `0x296a390` the one scalar read precedes the
    sibling call inside its own phase, and the only backward jump in
    that phase lands after the read, so it cannot consume the call's
    output.

  **No consumer uses the sibling record's height as a number.** The
  height this search returns is written at all 99 sites and read as
  a height at none of them — the same verdict the variant packet
  reached for variants A and B, now closed for the family's largest
  body.

## Negative results

- No tail calls to `0x35bf460` (E9 census empty) and no
  `R_X86_64_RELATIVE` relocation names it: the body is not
  address-taken anywhere in the artifact.
- No second node layout: one body, one key offset; the layout
  question has a single answer, unlike the variant pair.
- No call site reads its record through a pointer, and no consumer
  reads the position field arithmetically except through the
  × 0xb0 scaling.
- The child-index word at node + 0x7f0 is never read by the body;
  descent uses the edge array alone.

## Boundaries

Static evidence only; nothing was executed. Phase attribution of the
99 other-phase height reads rests on the retained per-read windows
and the instruction-form check for vector copies; in the giant
callers the frame slot alternates between handle copies and search
records across dozens of phases, and the attribution of each scalar
read is to the phase its window shows, not to a reconstructed
control-flow proof for the whole FDE. What the 0xb0-byte elements
are — their field layout, and what the GOT-slot callee at
`0x64e7198` does with one — is not identified here; the slot is
named, the callee is not resolved to a body. Distinct set instances
behind the same handle presentation are data, not code, and are not
distinguished. The `0x4556410` fallback is identified by its call
sites in the site windows, as in the earlier family packets; its own
body is a different work item.

## Next question

The family's runner-up body, `0x35be560` — 50 direct call sites by
the variant packet's family census — is the largest cursor-family
member still without a packet: which node layout it walks, who
consumes its records, and whether its height is read anywhere.
Behind it: the field layout of the 0xb0-byte elements this packet's
consumers compute, and the identity of the join callee at GOT slot
`0x64e7198`.

## Reproduction

With node #115 materialised at `artifacts/node/115/hl-node`:

```sh
python3 -m unittest tests.test_sibling_search_static
python3 tools/sibling_search_static.py generate /tmp/sibling-out
diff -r /tmp/sibling-out research/work-items/RE-006-node115-sibling-search \
  --exclude=README.md --exclude=MANIFEST.sha256
(cd research/work-items/RE-006-node115-sibling-search && sha256sum -c MANIFEST.sha256)
```
