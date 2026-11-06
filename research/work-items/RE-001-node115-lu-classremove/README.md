# RE-001: the node #115 lu class remove — unlink, merge, empty

Packet #240's next question: what `0x63b9d10` does with the
(entry, block) pair it receives from the neighbour caller, and
whether it removes, unlinks, or otherwise empties a size-class
entry — this decides what makes a class empty before the probe
clears its bitmap bit.

## Answer in one paragraph

It **removes exactly the given block** from the entry's chain
structure. The block's slot is filled by a key-ordered merge of
the block's two sub-chains (its `+0x30` forward chain and its
`+0x38` side subtree), using the same compare-and-rewire idiom
as #239's class insert. The function calls nothing, frees
nothing, and never writes a node's `+0x08` key. And yes, it
**can empty the entry**: precisely when the removed block is
the entry's head and has neither a forward successor nor a
side child, the head store at `0x63ba308` writes `0` into
`[entry]`. That is the only path on which `[entry]` becomes
`0` here, and it is exactly the condition the neighbour
caller's probe-then-clear sequence tests afterwards.

## Target and bounds

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032
  bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b9d10..0x63ba5fd`, 2285 bytes); `endbr64` entry;
  `int3` padding `0x63b9d0c..0x63b9d10` (4 bytes) and
  `0x63ba5fd..0x63ba600` (3 bytes, before the #236 consume
  helper at `0x63ba600`). Static analysis only; the binary
  was never executed.
- Single `ret` at `0x63b9f79`; zero `call` instructions; every
  direct jump target lies inside the FDE (verified by the
  static verifier's whole-FDE scan). Note the `ret` sits
  mid-FDE: blocks after it are other paths' tails that jump
  back to the shared epilogue at `0x63b9f6f` (pops) /
  `0x63b9f79` (`ret`).

## Entry contract

- `rdi` = 16-byte size-class entry: `[entry]` = head pointer,
  `[entry+8]` = count word (the same entries #238's size path
  computes as `first-arg + 16*index` and #239's class insert
  receives).
- `rsi` = block pointer: the block to remove. At the single
  call site it is the neighbour caller's block (cited only).
- No return value is established by these bytes: the function
  returns through the shared epilogue with no value set in
  `rax` on any traced path, and its only caller does not read
  a return (it probes the entry afterwards instead).
- Node fields, as used here (same layout as #239): `+0x08` =
  key (the consume-stamped counter from #236), `+0x28` =
  back/parent link, `+0x30` = forward/spine link, `+0x38` =
  side link. The `+0x50`/`+0x58` list links from #237's
  register tail and the `+0x00`/`+0x10`/`+0x60`/`+0x68`
  stamped fields are never read or written here.

## Dispatch: three entry cases

Entry (`rm_entry`): `rbp := block`, `r13 := &block+0x28`,
`rbx := [entry]`. If `[entry] == block`, take the head case.
Otherwise `r12 := [block+0x28]` (the block's parent) and
`rsi := [block+0x38]` (its side subtree):

- If the parent exists and `[parent+0x38] == block`, the
  parent-side-child path (`0x63ba190`) runs first: if the
  side subtree is null it splices the block's forward link
  into the parent's slot directly (`0x63ba2dc`); otherwise
  it joins the same merge loop as the general case.
- Otherwise the general case runs: the side subtree (if any)
  and the forward chain are merged by key, and the merged
  result is spliced into the block's former slot at the
  epilogue (below).

## The head case, traced end to end

`rm_head`: `rcx := [block+0x38]` (side child),
`rdx := [block+0x30]` (forward successor), `r8 := entry`.

- Side child null (`rcx == 0`) → `rm_empty`:
  `[entry] := rdx`; if `rdx` is nonzero,
  `[rdx+0x28] := 0`. **If `rdx` is also `0`, `[entry] := 0`:
  the entry is emptied.** This is the only emptying path in
  the FDE, and it requires the removed block to be the head
  with no forward successor and no side child.
- Side child present (`rcx != 0`): `[entry+8] := 0` — the
  count word is reset, mirroring #239's min-displacement
  reset. This is the only store to `[entry+8]` in the FDE.
  - Forward successor null (`rdx == 0`) → side promotion
    (`rm_side`): the side child's forward link is loaded;
    if it is null, `[entry] := rcx` — the side child becomes
    the head. Otherwise the side chain is merged (below) and
    the merged result becomes the head.
  - Forward successor present: the block's own `+0x28`/`+0x30`
    pair is zeroed, and the forward chain and the side chain
    are merged by key; the merged result becomes the head
    (`0x63ba328`, `0x63ba4c3`), and if the merged head still
    has a side child, that subtree is merged in turn
    (`0x63ba4c6` → `0x63ba330`), iteratively, until no side
    child remains.

## The merge loop, stated by invariant

`rm_merge` shows the loop head: load the next forward node,
load both keys (`[cur+8]`, `[next+8]`), compute the sign
(`-1`/`0`/`+1` via `setb`/`sbb`), and dispatch. The rewire
steps use the same `movups` pair-store idiom as #239: the
winner's `+0x28`/`+0x30` pair is written in one 16-byte
store, the loser's back link is fixed, and the loser's
`+0x38` side link is updated. The swap forms (e.g.
`0x63ba160`, `0x63ba474`, `0x63ba4a0`) and the second
loop bodies are verified by the static verifier's
whole-FDE jump-target check (every direct jump lands
inside the FDE), not exhibited, to keep the packet at 18
files — the same convention as #239.

Net effect of the loop, stated exactly: the two chains are
merged into one chain ordered by key, with the larger-key
node kept on the `+0x30` spine and the smaller tucked
under it via `+0x38`, exactly as #239's rotation pass
arranges pairs. What is **not** claimed: a global sortedness
proof for the merged chain as a whole (the same reservation
as #239's rotation pass), and the exact step count of any
one merge (it runs until a chain ends).

## The non-head epilogue

`rm_epi`: the merged result (`rdx`) is spliced into the
block's former slot — the parent's pair is updated
(`[parent-slot] := parent`, `[parent+0x38] := merged`) and
the block's former forward link is carried into the merged
node's `+0x30`, with back links fixed. The non-head path
never writes `[entry]` itself and never touches
`[entry+8]`; only the head path writes the entry head and
count. The block is left unlinked (no longer reachable
from the entry or its parent); no path frees it, and only
the head-with-forward path zeroes the block's own
`+0x28`/`+0x30` pair — on other paths its link words are
left as they were, which is stated here rather than
smoothed over.

## Caller context (cited only, not claimed)

The single caller is the neighbour FDE
`0x63d8630..0x63d8790`, site `0x63d870f`: it computes the
entry (`first-arg + 16*index`, same scheme as #238), calls
this function with `(entry, block)`, then calls the #240
probe (`0x63b9680`) at `0x63d8717`, tests `%al`, and on
nonzero (empty entry) clears the class bitmap bit at
`first-arg+0x400`. That sequence is now fully explained:
this function is the step that can make the entry empty,
and the probe afterwards is what observes it. The caller
also clears `[block+0x12]` on entry and handles the
`+0x1080`-queued blocks itself (unlinking them from the
queue directly, including writing `[first-arg+0x1080] := 0`
when the queued block is its own parent) — cited only,
as the caller's own logic is #242's question, not this
packet's claim.

## Evidence

- 6 exhibits, 259 bytes, 71 strict instructions (strict =
  mnemonic-line count: address + bytes field + tab +
  mnemonic; objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `rm_entry` | `0x63b9d10..0x63b9d31` | 33 | 12 | Entry, arg saves, head load, head==block dispatch |
| `rm_head` | `0x63b9fd0..0x63b9ff5` | 37 | 8 | Head path: side/forward loads, count reset, forward test |
| `rm_empty` | `0x63ba308..0x63ba321` | 25 | 5 | Emptying store: `[entry] := forward`, successor back-link clear |
| `rm_merge` | `0x63b9e1e..0x63b9e6f` | 81 | 20 | Merge loop head: forward load, key compare, sign dispatch |
| `rm_side` | `0x63ba330..0x63ba356` | 38 | 9 | Side promotion: side-child forward load, empty test |
| `rm_epi` | `0x63b9f4d..0x63b9f7a` | 45 | 17 | Epilogue: parent-slot splice, pops, single ret |

- Census: direct `E8` call sites to `0x63b9d10`: 1
  (`0x63d870f`, neighbour FDE, confirmed by rel32).
  Direct `E9` jump sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63b9d10`: 0 of 60,723
  entries. Internal calls within the FDE: 0. Internal jump
  targets: all lie inside `0x63b9d10..0x63ba5fd`.
  Single `ret` at `0x63b9f79`.
- Disjointness: this FDE overlaps no claimed range from
  packets #183–#240 and no other contributor's topic,
  addresses, or tables. The neighbour caller, the probe,
  the handoff, the register, the gate, the driver, the
  class insert, and the allocator thunk are cited by
  address, not claimed here.

## Corrections to earlier packets

- **#240 confirmed and completed.** Its unresolved
  `0x63b9d10` is this FDE: it removes the block, and the
  probe's empty verdict afterwards is explained — the entry
  is empty exactly when the removed block was the head with
  no forward successor and no side child.
- **#239 confirmed and completed.** The chains this function
  merges are the chains the class insert builds (same
  `+0x28`/`+0x30`/`+0x38` layout, same key at `+0x08`,
  same rewire idiom); the class insert's head/count entry
  is the entry this function receives.
- **#238 confirmed.** The handoff's size-class entries are
  the entries removed from here; the handoff never calls
  this function directly.
- **#237 confirmed.** The register's size-class entries are
  the entries probed and removed here; the register never
  calls this function directly.
- **#236 confirmed.** A consume-stamped block
  (`[block+0x68] == 0`) never reaches this function — the
  handoff queues it instead, and the neighbour caller
  unlinks queued blocks itself.
- **#235 confirmed.** The gate's paths reach this function
  only indirectly, through the register, the handoff, and
  the neighbour caller.
- **#234 confirmed.** The driver's gate-block path runs
  gate, then register, then handoff, then (for
  size-classified blocks) probe and class insert; removal
  runs through the neighbour caller, not the driver path.
- **#233 confirmed.** The loop caller is not involved with
  this function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the register, the handoff, and the
  neighbour caller, never directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- The exact step count and final ordering guarantee of any
  one merge: the loop merges by key until a chain ends,
  but no global sortedness proof for the merged chain is
  made here (same reservation as #239).
- Which of the merged chain's nodes, if any, still points
  at the removed block after the non-head epilogue: the
  block is unlinked from the entry/parent slot, but its own
  link words are left stale on the non-head path, and no
  reader of those words is decoded here.
- The domain meaning of the `[entry+8]` count word beyond
  its reset on the head-with-side-child path: it is not a
  plain element count (#239), and this function does not
  increment or decrement it anywhere.
- What the neighbour caller FDE `0x63d8630..0x63d8790`
  is in domain terms — its queue-unlink path, its
  size-class dispatch, and its bitmap clear are cited
  only here. This is #242's question.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.

## Next question (#242)

Decode the neighbour caller FDE `0x63d8630..0x63d8790` end
to end: what it does with the (first-arg, block) pair it
receives — its `+0x1080` queue unlink, its size-class
dispatch, and its probe-then-bitmap-clear tail — and
whether it is the removal entry point for both queued and
size-classified blocks.

## Verification

- `tools/node115_lu_classremove.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict
  counts, FDE bounds, single `ret`, zero calls, key stores
  and call rel32, full census, neighbour disjointness,
  MANIFEST coverage (17 entries).
- `tests/test_node115_lu_classremove.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7171 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
