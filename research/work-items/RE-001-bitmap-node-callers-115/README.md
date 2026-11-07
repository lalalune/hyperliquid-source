# RE-001: pin node #115 the nine bitmap-node ctor callers

## Task and bounded question

Task **RE-001** (node #115 reconstruction). Bounded question: for each
of the nine direct callers of the bitmap-node ctor `0x60f4a00`, what
does the caller pass (the 0x20-byte arg2 struct, the count, arg4) and
what does it do with the node afterwards?

This completes the open unknown left by #4156 (RE-001: the remaining
per-thread LCG-seed consumers): the nine `0x60f4a00` callers are now
pinned with their arguments and their immediate use of the node. The
other CPU-picker callers are exhausted — all six `0x60d5cd0` call sites
are already pinned (#3613 and merged packets) — so this packet turns to
the ctor's own callers instead.

Artifact: node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(provenance/artifacts.json artifacts/node/115/hl-node).

## Windows

| Window | FDE | Excerpt |
| --- | --- | --- |
| ctor `0x60f4a00` | `0x60f4a00..0x60f4cb5` | `ctor-60f4a00.objdump.txt` (re-shipped from #4156, byte-identical) |
| dtor `0x60f4900` | `0x60f4900..0x60f4966` | `dtor-60f4900.objdump.txt` |
| magnitude helper `0x60f4840` | `0x60f4840..0x60f48a0` | `mag-helper-60f4840.objdump.txt` |
| kind helper `0x60f48a0` | `0x60f48a0..0x60f4900` | `kind-helper-60f48a0.objdump.txt` |
| split helper `0x612ceb0` | `0x612ceb0..0x612cece` | `split-helper-612ceb0.objdump.txt` |
| trailing-u16 helper `0x612ce30` | `0x612ce30..0x612ce48` | `trail-u16-helper-612ce30.objdump.txt` |
| factory `0x60f4d10` | `0x60f4d10..0x60f5069` | `factory-60f4d10.objdump.txt` |
| materialize `0x60f50c0` | `0x60f50c0..0x60f55a1` | `materialize-60f50c0.objdump.txt` |
| slot release `0x6106790` | `0x6106790..0x6106834` | `slot-release-6106790.objdump.txt` |
| poll copy `0x61841a0` | `0x61841a0..0x618427d` | `poll-copy-61841a0.objdump.txt` |
| host table `0x60e3ad0` | `0x60e3ad0..0x60e3d01` | `host-60e3ad0.objdump.txt` |
| host slot replace `0x6117ed0` | `0x6117ed0..0x6119dad` | `host-6117ed0.objdump.txt` |
| host reset A `0x612a800` | `0x612a800..0x612a887` | `host-612a800.objdump.txt` |
| host reset B `0x612a8a0` | `0x612a8a0..0x612a91f` | `host-612a8a0.objdump.txt` |
| host reset C `0x612a940` | `0x612a940..0x612a9bf` | `host-612a940.objdump.txt` |
| host reset D `0x612a9e0` | `0x612a9e0..0x612aa5f` | `host-612a9e0.objdump.txt` |
| host reset E `0x612aa80` | `0x612aa80..0x612aaff` | `host-612aa80.objdump.txt` |
| host oneshot A `0x61849e0` | `0x61849e0..0x6184b7a` | `host-61849e0.objdump.txt` |
| host oneshot B `0x6186e30` | `0x6186e30..0x618a96f` | `host-6186e30.objdump.txt` |

Excerpts were produced with
`objdump -d --start-address=<fde start> --stop-address=<fde end> work/hl-node-115.bin`
(see `export_excerpts.py`, committed in this packet). The excerpts are
the raw objdump output, unmodified. Mnemonics such as `endbr64`,
`nopl`, `nopw` and `movups` are genuine instructions present in the
target binary, not placeholders.

## Observations

### The ctor `0x60f4a00`

The ctor takes `(rdi=node, rsi=arg2, rdx=count, rcx=arg4)`. It moves
the 0x20-byte arg2 struct into the node (`+0x00..+0x18` from
arg2 `+0x00..+0x18`; `+0x20` = arg2 `+0x00`, `+0x28` = arg2 `+0x08`;
`+0x30`/`+0x38` = 0, `+0x40` u16 = 0) and clears arg2 `+0x18`
(move semantics). A `0x4376fd` store to node `+0x00` is overwritten
by the 16-byte move that follows it.

If arg2 `+0x08` <= 3 the node is left with `+0x28` = 0 and the ctor
returns. Otherwise it decodes the trailing tag: `0x60f4840` reads the
trailing u32 at buffer + size − 4 and returns its low 31 bits when
size <= 0x10000 (the raw value otherwise); `0x60f48a0` returns the
sign bit under the same size condition (0 otherwise). The magnitude
goes to node `+0x34`, the kind selects the path:

- kind 0: `+0x30` = size − (4·magnitude + 4); if size − 4 <
  `+0x30` (unsigned) then `+0x28` = 0.
- kind 1 and size <= 5: `+0x28` = 0.
- kind 1 and size > 5: `0x612ce30` reads the trailing u16 T from the
  buffer tail; `+0x40` (u16) = T; `+0x30` = (len − 2 − T) − 4·magnitude
  where len = (u16)(arg2 `+0x08` − 4); underflow sets `+0x28` = 0.
- any other kind: `+0x28` = 0.

When count, arg4 and `+0x28` are all non-zero, the ctor allocates a
0x28-byte inner node: descriptor from `0x459a38` (low u32 4, high u32
32); inner `+0x18` = arg4; inner `+0x20` = seed % count, where the
seed is advanced once by the shared LCG fold
(seed = seed · 0x41a7 folded mod 0x7fffffff); inner `+0x10` (byte) =
floor(log2(count >> 1)) + 1 when count >= 2, else 0; the bitmap is
((`+0x30` − 1) >> shift) / 32 + 1 zeroed u32s; then the observer
`*(arg4 vtable + 0xb0)(arg4, 0x57, +0x30)` runs; node `+0x38` = the
inner node and any previous inner node is deleted.

### The nine hosts

1. **`0x60e3ad0`** — stack node (rsp+0x30). arg2 is a stack struct
   `{table qwords, 0, 0}` where the table is
   `*(vtable of arg2 + 0x708) + arg3<<5`; count 0, arg4 0. After the
   ctor it calls materialize `0x60f50c0(node, *(rax+8), -1, 0, 0, 0)`
   and stores the fresh 0x178-byte DataBlockIter into *arg1.
2. **`0x6117ed0`** — heap node (operator new 0x48). arg2 is a stack
   struct populated by `0x6108b70`; count =
   `*(u32)(*(arg1+0x08) + 0xdc)`; arg4 = `*(P+0x218)` where P is the
   4th entry argument. The fresh node replaces the slot at
   `*(*(arg1+0x08)+0x128)` (old node released via slot release
   `0x6106790`); if the fresh node equals the slot's node and the
   slot flag is set, the fresh node is destroyed as redundant.
3.–7. **Five reset siblings** — `0x612a800` (count =
   `*(u32)(*(arg1) + 0xcc)`, arg4 = `*(arg1+0x08)`) and `0x612a8a0` /
   `0x612a940` / `0x612a9e0` / `0x612aa80` (count 0, arg4 =
   `*(arg1+0x08)`). Each takes arg2 = arg3, allocates a heap node,
   stores it into the *arg2 unique_ptr slot and destroys the old node
   (dtor + sized delete 0x48). The four count-0 helpers are
   byte-identical modulo addresses. Their callers: A 4 sites in 3
   FDEs, B 4 in 3, C 4 in 3, D 1, E 1 (see `records.json`).
8. **`0x61849e0`** — stack node (rbp−0x80). arg2 =
   `{0x4376fd, 0, 0, 0}`; count 0, arg4 0. After oneshot prep
   `0x6184300` it calls the factory `0x60f4d10(node, 0)`, then poll
   copy `0x61841a0` into the out record, deletes the factory object
   via its vtable slot 0x8 and destroys the node.
9. **`0x6186e30`** — stack node (rbp−0x1a50). arg2 =
   `{0x4376fd, 0, 0, 0}`; count 0, arg4 0. After big prep
   `0x61572d0` it calls the factory, wraps the result in a 0x2a8-byte
   object and destroys the node.

### The consumers the hosts feed

- **Factory `0x60f4d10`** builds a 0x120-byte MetaBlockIter
  (`N7rocksdb13MetaBlockIterE`, vtable `0x64d43b0+0x10`) with
  `0x4376fd` at +0xd8/+0xf8 and the const `0x455f20` ({0, 0x20})
  at +0x58/+0xa0. Path A (node+0x28 > 7, node+0x34 != 0) wraps the
  `0x61be810` result in an InternalKeyComparator-vtable node linked
  into +0x28 and sets +0x30 = node+0x20, +0x110 = −1, +0x109 = esi
  byte, +0x38 = {node+0x34, node+0x34, node+0x30, node+0x30} (four
  u32s). Path B (node+0x28 > 7, node+0x34 == 0) tears the +0x08
  list down. Path C (node+0x28 <= 7) reports "bad block contents"
  (`0x434276`, len 0x12) with location {0x4376fd, 0} and tears the
  list down. A third caller exists at `0x6105cff`
  (FDE `0x6105b30..0x6105e38`), not pinned here.
- **Materialize `0x60f50c0`** returns its rcx argument when non-null
  and otherwise allocates a fresh 0x178-byte DataBlockIter
  (`N7rocksdb13DataBlockIterE`, vtable `0x64d42a8+0x10`). The fill
  path mirrors the factory's three paths: fill (node+0x28 > 7,
  node+0x34 != 0) builds the +0x28 list node from arg2 (rsi) and
  sets +0x110 = arg3, +0x109 = arg9 byte, +0x30/+0x120 = node+0x20,
  +0x170 = &(node+0x40) when node+0x40 (u16) != 0 else 0; teardown
  and report paths match the factory's B and C. A tail call exists
  at `0x60ff412`.
- **Slot release `0x6106790`** (16 callers): when slot+0x10 is
  non-null it walks the +0x38 chain against the `0x64ecd18` global
  (RELATIVE → `0x5d3f090`); when the slot+0x18 flag byte is set it
  destroys the node (dtor + sized delete 0x48).
- **Poll copy `0x61841a0`** (4 callers): copies the 0x10-byte
  result from `0x6183f20` into the out record, reporting "Cannot
  find the meta block" (`0x437514`, len 0x1a) first when the result
  and both arg2 qwords are zero.
- **Dtor `0x60f4900`** (84 direct call sites, re-derived by
  `census.py`; an earlier count of 82 was a miscount): delete[] the
  inner bitmap and sized-delete the inner node when +0x38 is set;
  when +0x18 is set, call vtable slot 0xa0 of *(+0x10) if +0x10 is
  set, else delete[] +0x18.

### Census

`callers.tsv` (from `census.py`, reproduced exactly): ctor 9 sites;
reset helpers A/B/C 4 each, D/E 1 each; dtor 84; factory 3; magnitude
helper 4; kind helper 1; split helper 2; trailing-u16 helper 1; tag
helper 1; materialize 1 direct + 1 tail (`0x60ff412`); slot release
16; poll copy 4; oneshot prep 1; big prep 19. No qword or RELATIVE
hits for the ctor address itself — the nine sites are direct calls
only, each verified as a real `call` instruction inside its
containing FDE by `gen_records.py`.

## Inferences

- The `0x4376fd` pointer is a location identity, not a string the
  consumers read: it is passed verbatim as arg2+0x00 into node
  +0x00/+0x20, stored by the factory into the MetaBlockIter +0xd8 /
  +0xf8 and (path A) +0x30, and handed to the report call as a
  location pair. No pinned consumer reads the string bytes at
  `0x4376fd`+1 (`/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs`).
  This resolves the #4156 open unknown.
- The five reset helpers are one logical operation (replace a
  unique_ptr slot's bitmap node) with five entry points; only reset A
  passes a non-zero count, so only its nodes can build a bitmap.
- The oneshot hosts (8, 9) always pass count 0 and arg4 0, so their
  nodes never build a bitmap — the ctor is used there purely as a
  move + tag-decode step feeding the factory.

## Unknowns

- Host `0x60e3ad0`: the identity of the +0x708 table and the
  typeinfo-gated field copies after the materialize call.
- Host `0x6117ed0`: the arg2 struct's populated field values (set by
  `0x6108b70`) and the wider purpose of the 0x1edd-byte host.
- Host `0x6186e30`: the 0x2a8-byte object's layout and use; the
  big-prep `0x61572d0` behavior.
- Factory path A: the `0x61be810` result's meaning and the
  InternalKeyComparator-vtable node's role in the +0x28 list.
- Factory path C / poll copy: the `0x61cf670` report call's full
  contract.
- The inner-node descriptor low u32 (4) has no pinned consumer; only
  the high u32 (32) is used as the bitmap-word divisor.
- The dtor's slot-0xa0 call target and the ctor's slot-0xb0 observer
  call target depend on the class of the object at node+0x10 / arg4,
  not established here.
- Not pinned here: factory caller `0x6105cff`; magnitude-helper
  callers `0x6108281`, `0x6115151`, `0x6116d71`; tag-helper caller
  `0x6129c9f`; poll-copy callers `0x611ec7d`, `0x6142d44`,
  `0x6142eb8`; the `0x612ce50` sibling helper.

## Model and tests

`tools/bitmap_node_callers_115.py` models the ctor (move, size gate,
kind/magnitude decode, LCG seed advance, shift/words math, bitmap
allocation, observer call), the dtor's free actions, the factory /
materialize path selection, the slot-release decision, the reset
helpers' slot replace and the poll-copy decision.
`tests/test_bitmap_node_callers_115.py` pins them with seeded random
inputs and boundary cases (count 0/1/2, arg+0x08 <= 3, kind 0/1,
size <= 5 vs > 5, size <= 0x10000 vs > 0x10000, underflow cases).
23 tests pass.

## Verification

`python3 research/work-items/RE-001-bitmap-node-callers-115/verify.py`
from the repository root checks: the work binary digest against
provenance/artifacts.json; MANIFEST.sha256 against every packet file;
byte-identical regeneration of the excerpts (`export_excerpts.py`),
the census (`census.py`) and the records (`gen_records.py`); three
seeded random instructions (seed 115) from the raw excerpts verified
byte-for-byte against a fresh objdump run; every window's FDE range
against `objdump --dwarf=frames`; the 65 vtable RELATIVE slots
against `readelf -r`; the typeinfo names and literal strings against
the raw binary; and the model tests. Result: ALL CHECKS PASSED.

## Environment limits

This work was done on a VM with no cargo/rustc, no git-lfs and no
Ghidra/Java, so `make verify`, `make test` and the catalogue checks
that need the Rust toolchain could not run here; the packet's own
`verify.py` and the Python model tests are the verification that ran.
`work/hl-node-115.bin` is the materialized node #115 binary and its
hash matches provenance/artifacts.json.
