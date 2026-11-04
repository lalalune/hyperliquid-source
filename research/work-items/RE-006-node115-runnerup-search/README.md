# RE-006 node 115 runner-up cursor search (the 0x35be560 layout)

## Scope

This packet answers the open question left by the sibling cursor packet
(RE-006-node115-sibling-search): the family runner-up body `0x35be560` —
50 direct call sites by the variant packet's family census, second only
to the sibling's 99 — walks which node layout, who consumes its records,
and whether any consumer reads its height field as a number. This packet
pins the runner-up body in full, traces all 50 call sites in 29 caller
FDEs field by field, and settles the height question with the same
whole-FDE slot-census method as the earlier RE-006 packets.

Static analysis only, against the authenticated node #115 ELF (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Function boundaries are the FDE ranges of the shared unwind index
(135,313 records, all starts unique). The packet retains:

- `records.json` — every claim below in machine-checkable form;
- `frames.txt` — the readelf frame lines for the runner-up body and the
  29 caller FDEs;
- `runnerup_search_full_body_35be560_35be5f2_objdump.txt` — the
  full-body disassembly export (146 bytes);
- `tools/runnerup_search_static.py` and
  `tests/test_runnerup_search_static.py` — the checks that regenerate
  and verify all of it.

## Short answer

The runner-up is the family search over one more node layout: eleven
u64 keys at node + 0x2c8, count word at node + 0x322, child edges from
node + 0x328. The record and the ABI are the family standard: `rdi` =
record out (returned in `rax`), `rsi` = root node, `rdx` = height,
`rcx` = key pointer, dereferenced once; the record is `{+0x00 flag
(0 hit / 1 miss), +0x08 node, +0x10 height remaining, +0x18 position}`;
a hit leaves the equal-key index in the position field, a miss the
insertion index; descent follows child edges while height remains.
The body calls nothing and stores nowhere except into the record. It
is instruction-parallel to the sibling body — the same instruction
sequence, with only the three layout displacements changed.

It serves exactly one node layout. What varies across the 50 sites is
how the caller presents the family's 32-byte set handle `{tag, root,
height, bound}` to the search: by register-held handle (root at
handle + 0x8, height at handle + 0x10) at 43 sites, by frame-held
handle (root and height loaded from frame slots) at 4 sites, with root
and height already dissolved into registers at 2 sites, and split
across two objects (root from one object's + 0x0, height from
another's + 0x10) at 1 site. Every record is an rsp-relative frame
slot: addressed by `lea` at 48 sites, and carried in a register that
itself holds an `lea` of the same slot at 2 sites. Where the handle
tag is not the sentinel, the callers do not search at all: they pass
the handle to the family fallback `0x4556410` instead.

Consumption does **not** partition on the flag test's form here,
unlike the sibling:

- 49 of the 50 sites consume **node and position on a hit**: the flag
  test gates the element-address computation
  `node + position × 0x40` (`mov` the position slot, `shl $0x6`,
  `add` the node slot), and the block-walk check in the tool proves
  for each of the 49 that the scaling block is reached exactly on the
  hit side of the branch. The flag test is a dword test
  (`cmpl $0x1`) at 48 sites and a byte test (`cmpb $0x0`) at 2 sites
  (`0x4476202`, `0x44762e0`); node+position consumption occurs under
  both forms (47 of the dword sites and both byte sites).
- 1 site is flag-only: at `0x44781ad` (caller `0x4477d00`) the caller
  branches on the flag and never reads the record's node or position
  anywhere in its FDE (the unit census counts 0 node reads and
  0 position reads); on a hit it goes on to build other structures.

The height field is never consumed as a number by anyone (see the
consumption verdict below).

## Method

Call sites are a byte scan of the executable sections for E8/E9 rel32
branches naming `0x35be560`, cross-checked against a decode of every
caller FDE so each retained site is a genuine instruction boundary
(50 direct sites, 0 tail calls, 0 `R_X86_64_RELATIVE` relocations
naming the body). Each site retains a window from its argument setup
through its flag test and consumption block, with every setup load,
the call, the flag test and the consumption instructions pinned by
bytes and text. Per (caller, record base) unit — 31 units over the
29 callers, two callers keeping two record slots — the packet
retains a whole-FDE textual census of reads of each record slot
(flag +0x0, node +0x8, height +0x10, position +0x18): an instruction
counts when the slot appears in its operand text, it is not an `lea`,
and it is not a mov-family store into an rsp slot. Every height-slot
read the census finds is attributed individually: wholesale vector
copies are classed by instruction form, and every scalar read retains
its own phase window. `analyze()` in the tool performs all of these
checks without authenticating the artifact, so a flipped byte fails
the specific check it breaks; `generate()` authenticates first.

One site needs a note on method: at `0x26c9a6d` the flag test's
conditional jump is not the next instruction — the flags set by
`cmpl $0x1, 0x20(%rsp)` survive a `movabs` and six loads before a
`jne` branches to the consumption block. The tool's block-walk
therefore scans forward over flag-preserving instructions only
(`mov`/`lea`/`nop` forms) to find the jump whose flags the test set,
and fails if any flag-affecting instruction intervenes.

## Trace

### The runner-up body

`0x35be560..0x35be5f2`, 146 bytes, SHA-256
`b9544e43306382e72df633265f96c279104a2f0a6fe9170b3b6ec175efe4e79d` —
the same boundary and digest the variant packet pinned when it
counted this body's call sites. Save the out pointer in `rax`,
dereference the key once (`mov (%rcx),%rcx` at `0x35be563`), load the
count word (`movzwl 0x322(%rsi),%r8d` at `0x35be566`), scan the node's
keys with the three-way compare against `0x2d0(%rsi,%rdi,8)` from
index −1 — i.e. keys at node + 0x2c8 — and descend via
`mov 0x328(%rsi,%rdi,8),%rsi` at `0x35be5cc` while the height in `rdx`
lasts. The hit epilogue (flag 0, at `0x35be5d9`) and the miss epilogue
(flag 1, at `0x35be5eb`) share the four stores: node to record +0x8,
the remaining height to +0x10, the final index to +0x18, the flag to
+0x0. The child-index word at node + 0x320 implied by the family's
layout pair (index/edge arrays interleaved around the keys) is never
read by this body.

### Call sites and handle presentations

The 50 sites sit in 29 caller FDEs; 9 callers hold more than one
site, up to four (the clone pairs `0x4e86260` / `0x4e98260`, 6,129
bytes each, and `0x4f53680` / `0x4f9e290`, 6,134 bytes each, four
sites apiece; the giants `0x446c200`, 24,065 bytes with four sites,
`0x2bf2ed0`, `0x54cfa90` and `0x54d57b0`, 23,556–23,828 bytes). Three
of the 29 caller FDEs — the giants `0x2bf2ed0`, `0x54cfa90`,
`0x54d57b0` — are also digest-pinned boundaries of the sibling
packet, with identical digests in both packets: those callers run
both searches, each for its own set instance. Every digest is
pinned, so the census is over bodies, not names.

Setup follows the family pattern: the phase checks the handle tag
against the `0x8000000000000000` sentinel and the root against null,
loads root and height from the handle, and calls the search with the
key pointer in `rcx` — always a frame slot (three small callers pass
`%rsp` itself). Only the handle's presentation varies, as counted in
the short answer. Two sites deserve a line each:

- `0x4473681` and `0x44781ad` receive the record in a register
  (`mov %rbx,%rdi` / `mov %rbp,%rdi`); in both callers the register
  provably holds the record's frame address (`lea %rbx, 0x180(%rsp)`
  at `0x447359d`, `lea %rbp, 0x20(%rsp)` at `0x4478001`), and the
  callers read the record's fields from those very slots after the
  call. The `lea` and the `mov` are both pinned in the site windows.
- `0x44762e0` is the split-handle site: root is loaded from
  `[rsp + 0x40]`'s object at +0x0 and height from `[rsp + 0x10]`'s
  object at +0x10, two different parent structures feeding one call.

### The consumption block

The typical hit path is three instructions: load the position slot
into a register, shift it left by 6 (elements are 0x40 bytes), add
the node slot. What the consumers do with the element pointer is
visible in the retained windows: the small getter-shaped callers
(e.g. `0x446bcd0`) load `[element + 0x10]` and return it; the
walker-shaped callers (e.g. `0x4473440`) load `[element + 0x10]`
into a register and test it before continuing the walk. The element
layout beyond that field is not identified here (see Boundaries).

### The family

The runner-up is the fifth distinct node layout of the RE-006 cursor
family to be pinned, after the clones (keys at node + 0x8), variants
A (+ 0x8, capacity 22) and B (+ 0x168), and the sibling (+ 0x798).
Its 50 call sites are the family's second-largest consumer set. The
members still without a packet are the u32 twin of this very layout
(`0x35bf500`, u32 keys at node + 0x2c8, 6 sites) and six members with
one or two sites each (`0x35bd8a0`, `0x35bddb0`, `0x35be3b0`,
`0x35bf3c0`, `0x1d65b20`, `0x4d380a0`), per the variant packet's
family census.

## Consumption verdict

Field by field, over the 31 (caller, record base) census units, the
whole-FDE slot census counts 160 flag reads, 86 node reads, 51
position reads and 81 height reads.

- **Flag**: read at every site (the test itself) and used as the
  hit/miss branch everywhere.
- **Node and position**: consumed together, as
  `node + position × 0x40`, at 49 of the 50 sites, on the hit branch
  in every case. (Position reads beyond the consumption blocks are
  the same slot serving other phases of the giant callers, exactly
  as with the height slot below.)
- **Height**: 16 of the 31 units never read the height slot at all.
  The 81 reads in the other 15 units are, without exception, **not**
  reads of the runner-up's result:
  - 28 are wholesale vector copies (`movups`/`movupd`/`movapd`/
    `movaps`/`movdqu`/`movdqa` loads of the height slot as half of a
    16-byte pair) that relocate the record or a same-shaped struct;
  - 53 are scalar reads belonging to other phases of the same frame
    slot, each with its own retained window. The recurring shapes:
    the slot region reused as a `{pointer, index}` descriptor for
    differently-strided arrays (index scaled ×48, ×20 or ×0x78), as
    a tagged enum whose flag-slot word is the discriminant compared
    against 2 and whose +0x10 word is a payload field, as a callee
    out-struct, and as field-wise copies of a same-shaped struct.
    Four of the 53 sit after a search call in address order and were
    scrutinised individually; each is decisively separated from the
    record by an intervening overwrite or refill through the slot's
    address: in `0x4472010` the region is reinitialised
    (`0x44724e6`/`0x44724f0`) and passed to two calls before the
    read at `0x4472574` computes an absolute value; in `0x4473440`
    the region is overwritten (`0x4473819`/`0x447384c`, the height
    dword itself at `0x4473821`/`0x4473858`) before the read at
    `0x4473897` copies the new struct's field out; in `0x4473d10`
    the read at `0x4476710` is an index in a loop whose immediately
    preceding writer of the slot is the descriptor helper
    `0x3912ea0`, called with the slot's address at `0x44766ec` and
    again every iteration; in `0x44868f0` the flag slot is
    overwritten at `0x4486de3` and the slot's address is passed to a
    callee at `0x448708a` immediately before the read at `0x4487098`
    dereferences the height slot as a pointer.

  **No consumer uses the runner-up record's height as a number.**
  The height this search returns is written at all 50 sites and read
  as a height at none of them — the same verdict the variant and
  sibling packets reached for their bodies.

## Negative results

- No tail calls to `0x35be560` (E9 census empty) and no
  `R_X86_64_RELATIVE` relocation names it: the body is not
  address-taken anywhere in the artifact.
- No second node layout: one body, one key offset; the layout
  question has a single answer.
- No site receives its record by pointer to non-frame memory, and no
  consumer reads the position field arithmetically except through
  the × 0x40 scaling.
- The child-index word at node + 0x320 is never read by the body;
  descent uses the edge array alone.

## Boundaries

Static evidence only; nothing was executed. Phase attribution of the
53 other-phase height reads rests on the retained per-read windows
and the instruction-form check for vector copies; in the giant
callers the frame slot alternates between handle copies, descriptors
and search records across dozens of phases, and the attribution of
each scalar read is to the phase its window shows, not to a
reconstructed control-flow proof for the whole FDE. What the
0x40-byte elements are — their field layout, beyond the +0x10 word
the consumers load — is not identified here. Distinct set instances
behind the same handle presentation are data, not code, and are not
distinguished. The `0x4556410` fallback is identified by its call
sites in the callers, as in the earlier family packets; its own body
is a different work item.

## Next question

The u32 twin of this layout, `0x35bf500` (u32 keys at node + 0x2c8,
6 direct call sites by the family census): does it serve the same
consumers, and is its height likewise never read? Behind it: the
field layout of the 0x40-byte elements this packet's consumers
compute, and the family's six remaining one- and two-site members.

## Reproduction

With node #115 materialised at `artifacts/node/115/hl-node`:

```sh
python3 -m unittest tests.test_runnerup_search_static
python3 tools/runnerup_search_static.py generate /tmp/runnerup-out
diff -r /tmp/runnerup-out research/work-items/RE-006-node115-runnerup-search \
  --exclude=README.md --exclude=MANIFEST.sha256
(cd research/work-items/RE-006-node115-runnerup-search && sha256sum -c MANIFEST.sha256)
```
