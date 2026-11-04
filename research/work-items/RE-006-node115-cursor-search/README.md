# RE-006 node 115 cursor searches (forward_2's set)

## Scope

This packet works only against the authenticated Linux x86-64 node
115 artifact:

- `artifacts/node/115/hl-node`
- SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

The sorted-set read-side packet (#2493) completed the census of
the forward-2 B-tree layout's standalone readers - among FDEs of
at most 350 bytes carrying the walk signature there are exactly
sixteen: three byte-identical find clones, one boolean contains,
two byte-identical cursor searches, and ten remove bodies - and
traced find, contains and remove. The two cursor searches were
left as hash-pinned boundaries, recorded only as returning a
four-qword record to their callers. This packet owns them: what
the record contains on a hit and on a miss, who calls each
clone, and how each caller consumes the record.

The layout (from the forward-callee, split-helper and read-side
packets): handle `{root at +0x0, height at +0x8, total at
+0x10}`; node `{parent at +0x0, sorted qword keys from +0x8 (at
most 11), child-index word at +0x60, count word at +0x62, child
edges from +0x68}`; leaf nodes are `0x68` bytes, internal nodes
`0xc8`.

## Short answer

The two cursor searches are one body, twice: `0x1d65920` and
`0x35bdd20`, 143 bytes each, byte-identical (SHA-256
`4f7a495b...`). A cursor search is a pure B-tree search over
the layout that additionally materialises where the search
ended. The root node and the height arrive as separate
arguments (`rsi`, `rdx`) - the caller extracts them from its
handle - the probe key arrives by pointer (`rcx`) and is
dereferenced once, and the result is written through the out
pointer (`rdi`, also returned in `rax`) as a four-qword
record:

| offset | field    | contents |
| ------ | -------- | -------- |
| +0x00  | flag     | 0 when the key was found, 1 when not |
| +0x08  | node     | the node where the search ended |
| +0x10  | height   | the height remaining at that node (0 at a leaf; on a miss always 0) |
| +0x18  | position | on a hit, the index of the equal key; on a miss, the insertion index - the first key greater than the probe, or the node count when every key is less |

No traced caller reads the node, height or position fields of
a clone's record. Clone A's only caller (`0x23795c0`, two call
sites) runs an existence scan over successive computed keys and
tests only the flag byte after each call. Clone B's only
caller (`0x2667140`, one call site) probes a single key and
tests only the flag (a dword compare against 1). Where the
same two callers do load a record's node and position, the
record was written by a variant search (`0x35bd660` /
`0x35bd800`) running the same algorithm over a shifted node
layout - never by one of the clones.

## Method

Duplicate gate first: the merged records on `main` claim none
of the owner or caller FDEs below (the addresses occur nowhere
in the merged tree's `research/`, `tools/`, `tests/` or
`docs/`), and no open PR title, branch or file list claims them
either; the read-side packet (#2493) cites the two bodies as
census members and boundaries, not as owners, and the chain
packets (#2416, #2427, #2441, #2447, #2468, #2478) are cited
as boundaries, not re-claimed.

Census first, trace second:

1. The walk-signature census of the read-side packet is
   re-derived unchanged: 126 FDE carriers, and the ≤350-byte
   carrier set is exactly the same sixteen bodies; the
   cursor-search body hash has exactly two carriers among all
   FDEs (body-hash family over every FDE), so the two clones
   are the complete cursor-search family for this layout.
2. Every E8 call site for the two clones and for the two
   variant searches is re-derived from a raw scan and
   re-validated as an instruction start inside its containing
   FDE; an E9 tail-jump census for the clones is empty, and
   neither clone's address appears as an `R_X86_64_RELATIVE`
   addend (no relocation slot, no function-pointer table
   entry).
3. Consumption is pinned two ways: the flag-test instruction
   after every search call site (clones and variants) is
   byte-pinned, and a full slot-read census of each caller
   FDE lists every decoded instruction that reads the record's
   stack slots - so the absence of node/height/position reads
   is a checked census result, not a window impression.

## Trace

1. **The body (both clones).** Entry moves the out pointer to
   `rax` (pin `0x1d65920`) and dereferences the key pointer
   once (pin `0x1d65923`). The node loop loads the count word
   at node `+0x62` (loop head, pin `0x1d65926`) and scans the
   keys from `+0x10` in node-relative addressing (pin
   `0x1d65945`) with the same `seta`/`sbb` three-way compare
   as the sibling readers (pins `0x1d6594a`, `0x1d6594e`): the
   scan advances while the probe key is greater than the node
   key (unsigned) and stops at the first key greater than or
   equal to it, or when the keys are exhausted. When an
   internal level remains it descends through the child edge
   at `+0x68` at the stopped position (pin `0x1d6598c`); the
   scan-exhausted path descends through the rightmost child
   with the position set to the count (pin `0x1d65980`). On
   equality the epilogue is reached with the flag value 0
   (pin `0x1d65996`); the miss exits are reached only at leaf
   level (`rdx` == 0, where the decrement of the remaining
   height underflows), with the flag value 1 (pin
   `0x1d659a8`). The epilogue stores the flag, the final node,
   the remaining height and the position to the record
   (pins `0x1d659a4`, `0x1d65998`, `0x1d6599c`, `0x1d659a0`)
   and returns the out pointer. The body contains no call and
   no other store; it never reads the handle total - the
   caller supplies root and height directly, and the search
   itself is read-only.
2. **Caller A `0x23795c0..0x2379b6b` (1,451 bytes), clone A's
   only caller, two sites.** Both sites serve loops over a run
   of successively computed keys: a record field (loaded at
   pin `0x2379615`) times `0x2710` plus the loop index, stored
   to a stack key slot (pins `0x237962e`, `0x23798d3`). The
   searched set's root/height pair is loaded per iteration
   from a pointer taken from the caller's own argument `+0x18`
   (pin `0x23795f3`): root from pair `+0x0`, height from pair
   `+0x8` (pins `0x2379633`/`0x23798d8`, `0x237963c`/
   `0x23798e1`); a null root skips the search and takes the
   miss path. The out record is the stack slot at `rsp +0x68`
   at both sites (pins `0x2379640`, `0x23798e5`). After each
   call - sites `0x2379648` and `0x23798ed` - the first and
   only consumption is `cmpb $0x0, 0x68(%rsp)` on the flag
   byte (pins `0x237964d`, `0x23798f2`): a miss (flag != 0)
   breaks to the not-all-present path, a hit increments the
   loop index (pins `0x2379654`, `0x23798f9`) and probes the
   next key. The loop completes only when every key in the
   run was found: an existence scan. The slot-read census of
   the whole FDE shows the record's node slot (`rsp +0x70`)
   read at exactly two instruction starts and the position
   slot (`rsp +0x80`) at exactly two, all four inside the
   variant windows of stage 4 - where the record was written
   by the variant search - and the height slot (`rsp +0x78`)
   read nowhere.
3. **Caller B `0x2667140..0x2668202` (4,290 bytes), clone B's
   only caller, one site.** The probe key is copied from one
   stack slot to the key slot at `rsp +0x50` (pins
   `0x2667b5d`, `0x2667b62`) and the searched set's handle is
   embedded in the caller's record at `+0x290`: root from
   `+0x290`, height from `+0x298` (pins `0x2667b67`,
   `0x2667b73`), a null root skips the search. The out record
   is the stack slot at `rsp +0x140` (pin `0x2667b7a`). After
   the call at `0x2667b87` the first and only consumption is
   `cmpl $0x1, 0x140(%rsp)` (pin `0x2667b8c`): a miss
   (flag == 1) falls through into the following phase, a hit
   branches away to `0x2667c80`. The slot-read census of the
   whole FDE shows the node, height and position slots
   (`rsp +0x148`, `+0x150`, `+0x158`) read nowhere - the only
   occurrences of those displacements are stores from other
   phases that reuse the stack region.
4. **The variant searches (boundaries).** The same two
   callers also call sibling instantiations of the same
   algorithm over shifted node layouts, into the same stack
   record slots: caller A calls `0x35bd660` twice (sites
   `0x2379742`, `0x23799c0`; root/height from its record
   `+0xf8`/`+0x100`, pins `0x2379725`, `0x2379731`,
   `0x237999a`, `0x23799af`) - a 146-byte body whose count
   word sits at node `+0xba` and whose child edges sit at
   `+0xc0` - and caller B calls `0x35bd800` once (site
   `0x2667ac0`; root/height from `+0x4b40`/`+0x4b48`), a
   146-byte body with the count word at `+0x1c2`. After a
   variant call, both callers test the flag (caller A:
   `cmpl $0x1` at pins `0x2379747`, `0x23799c5`; caller B:
   `cmpb $0x0` at pin `0x2667ac5`) - and caller A then does
   what no clone caller does: on a hit it loads the record's
   node and position (pins `0x237974e`, `0x2379753`,
   `0x23799cc`, `0x23799d1`) and forms the address
   `node + position * 8 + 0x60`. The variants are shared
   helpers - 8 and 18 direct call sites across the binary -
   and each is a singleton body-hash family of its own; this
   packet pins only their three sites inside the two caller
   FDEs and claims nothing about their other callers.

## Consumption verdict

- Both clones are pure searches: no calls, no stores outside
  the four record fields, no handle-total read, no mutation
  of the tree.
- The record separates a search *result* (the flag) from a
  search *position* (node, remaining height, insertion-or-
  equal index). Every traced consumer of a clone's record
  uses the result only: caller A's two loops are existence
  scans over computed key runs, and caller B's single probe
  is a membership branch. The position half of a clone's
  record is written on every call and read by no one in the
  binary's traced call graph - the only node/position loads
  in either caller consume records written by the variant
  searches over their shifted layouts.
- Neither caller calls both clones, and no caller can
  distinguish them: the bodies are byte-identical, so the
  choice of clone is fixed per caller by codegen, not by
  behaviour.

## Negative results

- No caller reads a clone record's node, height or position
  field: caller A's field-slot reads are exactly the four
  variant-window loads (height: none), and caller B has no
  field-slot reads at all. Both facts are re-derived by the
  tool's slot-read census over the full caller FDEs.
- No other body carries the cursor-search hash: the family
  over all FDEs is exactly the two clones.
- Neither clone has a relocation slot, a tail-jump site, or
  any direct reference other than its listed E8 call sites:
  the clones are reachable only from their callers above.
- The clones never serve as an insertion-point provider for
  the insert path: the complete call-site census places every
  clone call in the two caller FDEs above, none of them an
  insert body - forward_2 (`0x51d1b00`) and the split helper
  (`0x4c49f90`) are hash-pinned here as the chain's insert
  side, cited from #2447/#2468, and neither calls a cursor
  search.

## Boundaries

Hash-pinned, one level deep: the two callers (`0x23795c0`,
`0x2667140`), the two variant searches (`0x35bd660`,
`0x35bd800`), forward_2 and the split helper (cited from
#2447/#2468). Decoded windows are retained for both clone
call sites of caller A, the variant call sites of both
callers, and caller B's clone call site. The internals of the
two callers beyond the search windows - what caller A's key
runs enumerate and what caller B's phases compute - are not
traced, and neither are the variant searches' other callers
or the set instances they serve.

## Next question

The variant cursor searches (`0x35bd660`, `0x35bd800`) run
the same algorithm over shifted node layouts (count words at
`+0xba` / `+0x1c2`, child edges at `+0xc0` / beyond), and
their cursors - unlike the clones' - are consumed for node
and position by the same callers. Which set instances and
node layouts do the variants serve, how large is their full
clone/variant family, and does any consumer read a variant
record's height field?

## Reproduction

```sh
python3 tools/cursor_search_static.py \
  artifacts/node/115/hl-node \
  research/work-items/RE-006-node115-cursor-search
python3 -m unittest tests/test_cursor_search_static.py
sha256sum -c research/work-items/RE-006-node115-cursor-search/MANIFEST.sha256
```
