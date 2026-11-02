# RE-004 pair-array escape — node #94

## Claim status

**Claimed.** #172's Next question — who reads the builder caller's
`[rsp+0x388]` copy of the pair array, and does any code dispatch
through element 6's slots — is answered in two parts:

- **The copy escapes.** #172 reported the chain going cold because
  `[rsp+0x388]` is not read later in the builder caller's FDE.
  That literal fact stands, but the chain does not go cold: the
  caller then copies `[rsp+0x2a0..0x1438]` (0x1198 bytes) into
  `[rbx+0x108..0x12a0]`, and the pair-array copy
  `[rsp+0x388..0x438]` lies entirely inside that swept span. The
  11 pairs — including the oc pair — land in the returned object
  at `[rbx+0x1f0..0x2a0]` (oc pair: `[rbx+0x210]` = cell C3,
  `[rbx+0x218]` = element `0x574bd30`), under the `[rbx+0x12a0] =
  0xff` end marker.
- **Nobody dispatches through it.** The builder's caller has no
  direct callers at all: zero `E8`/`E9` references in `.text`, zero
  RIP-relative references in `.text`, zero init/fini entries, and
  exactly one relocation — a RELATIVE entry pointing GOT slot
  `0x5773ff8` at it. Five indirect call sites dispatch through
  that GOT slot. Four of them (c1, c2, c4, c5) never read the pair
  region (their reads from the object stop at offset `0x108`, plus
  c4's later small-offset reads up to `0x54`); the fifth (c3)
  forwards the object to `0x37fb9e0`, which also never reads the
  pair region and forwards the object to destructor `0x37f7070`.
  The destructor's loop walks `[obj+0x198..0x11a8]` — which fully
  contains the pair array — and loads every pair including the oc
  pair, but for table-shaped elements both guarded actions are
  skipped (`[element+0x0] = 0`, `[element+0x8] = 0`), and the
  element function slots `[element+0x18/0x20/0x28]` (oc3/oc2/oc1)
  are never loaded. The pair array is read as pointers and dropped,
  never invoked.

**Not claimed.** No defect, exploitability, or security severity is
claimed. The destructor loop's guard value (`[obj+0x198] != 0`) is
not statically determined for this object (see Limitations), so the
walk is conditional: *if* the loop runs, it reads-but-skips the
pairs; it never dispatches through them on any iteration. c4's
vtable forward (`[r14+0x28]` with obj+8) is reported, not traced.

## Scope

Included:

- The builder's caller FDE `0x4e7d360..0x4e7d678` (792 B): the
  escape memcpys and the end marker.
- The reachability census of `0x4e7d360`: `.text` E8/E9 scan,
  `.text` RIP-relative census, all RELA sections, init/fini arrays.
- 5 indirect callers through GOT slot `0x5773ff8`, each read in
  full: c1 `0x2446ac0..0x2447970` (0xeb0), c2
  `0x247fd20..0x2480ef4` (0x11d4), c3 `0x326e540..0x326f350`
  (0xe10), c4 `0x37dc350..0x37e1581` (0x5231), c5
  `0x4463490..0x4464340` (0xeb0).
- The forward target `0x37fb9e0..0x37fd846` (0x1e66) and the
  destructor `0x37f7070..0x37f721a` (426 B).
- 28 byte segments in `segments.txt` (26 claim segments, 377
  bytes; 2 anchor segments, 44 bytes, #172's claims re-cited).

Excluded:

- The builder itself and the 11-element table (both #172's
  subjects; the table and the pair-array copy are anchors here,
  not re-claimed).
- The internals of the 33 table functions other than oc1/oc2/oc3,
  the `0x574be20` object and its 6 neighborhood references
  (still open, see Next question), the runtime initializer of
  `.data` objects `0x5786838`/`0x5786858` (still open from #169),
  and the `#157`–`#172` subjects and #1543's fixed-eight topic.

## Observations

### The escape: a sweep memcpy, not a read

The builder's caller (`rbx = rdi` at `0x4e7d38a`) fills its
output object with three memcpys through `r15` (GOT `0x576dfe0`,
`memcpy`):

| memcpy | site | dest | src | len |
|---|---|---|---|---|
| pair copy (anchor, #172) | `0x4e7d594` | `[rsp+0x388]` | `[rsp+0x1f0]` (builder output) | `0xb0` |
| head copy | `0x4e7d5ac` | `[rbx+0x0]` | `[rsp+0xe8]` | `0x108` |
| sweep copy | `0x4e7d5bf` | `[rbx+0x108]` | `[rsp+0x2a0]` | `0x1198` |

The sweep's source span `[rsp+0x2a0..0x1438]` contains the pair
copy `[rsp+0x388..0x438]` (`0x2a0 <= 0x388` and `0x438 <=
0x1438`). Offset arithmetic into the returned object:
`0x108 + (0x388 - 0x2a0) = 0x1f0`, so the pairs land at
`[rbx+0x1f0..0x2a0]`. Pair 3 (oc) sits at array offset `0x20`:
`[rbx+0x210]` = cell C3, `[rbx+0x218]` = element `0x574bd30`.
The caller then stores `[rbx+0x12a0] = 0xff` (`0x4e7d5d6`)
and returns `rbx`. #172's "not read later in the caller FDE"
is literally true — no instruction loads `[rsp+0x388..0x438]` —
but the sweep memcpy reads the whole span containing it, so the
array escapes in the returned object.

### Reachability: one GOT slot, five call sites

- Full `.text` scan for `E8` + rel32 and `E9` + rel32 resolving
  to `0x4e7d360`: **0 hits** (the generator performs this scan).
- Full `.text` objdump census for RIP-relative references to
  `0x4e7d360`: **0 hits** — the address appears exactly once in
  the whole `.text` disassembly, as the function's own first
  instruction (documented census, see Limitations).
- Relocation census over **all** SHT_RELA sections: exactly **1**
  entry references `0x4e7d360` — `.rela.dyn` entry 75886, slot
  `0x5773ff8`, type 8 (RELATIVE), addend `0x4e7d360`. The slot's
  file bytes are 0 (resolved at load), as with #172's table slots.
- `.init_array` (168 entries) and `.fini_array` (1 entry): no
  `0x4e7d360`.
- The five GOT-indirect call sites (`call QWORD PTR [rip+...] #
  5773ff8`):

| caller | FDE | site | object base |
|---|---|---|---|
| c1 | `0x2446ac0..0x2447970` | `0x2446b13` | `r13 = [rsp+0x27e8]` |
| c2 | `0x247fd20..0x2480ef4` | `0x247fd7b` | `r14 = [rsp+0x1580]` |
| c3 | `0x326e540..0x326f350` | `0x326e592` | `r12 = [rsp+0x1540]` |
| c4 | `0x37dc350..0x37e1581` | `0x37dc568` | `r15 = [rsp+0x2aa0]` |
| c5 | `0x4463490..0x4464340` | `0x44634e3` | `r13 = [rsp+0x27e8]` |

c1 and c5 share the same instruction skeleton and frame layout
(same FDE size `0xeb0`, same memcpy triples and destinations),
differing only in RIP-relative displacements and two `.rodata`
constants — structural twins, not byte clones.

### The caller census: 4 no-reads, 1 forward

c1, c2, c4, c5 all open with the same shape: three memcpys from
the object base with lengths `0x108`, `0xe0`, `0xb8` — all from
offset 0, none reaching the pair region at `0x1f0` — after which
the base register is repurposed and the object pointer is never
forwarded:

| caller | memcpy destinations | max object offset read |
|---|---|---|
| c1 | `[rsp+0x290]`, `[rsp+0x1540]`, `[rsp+0xa8]` | `0x108` |
| c2 | `[rsp+0x2d0]`, `[rsp+0x2838]`, `[rsp+0x1c0]` | `0x108` |
| c4 | `[rsp+0x17e0]`, `[rsp+0x640]`, `[rsp+0x360]` | `0x108` (+ later uses below) |
| c5 | `[rsp+0x290]`, `[rsp+0x1540]`, `[rsp+0xa8]` | `0x108` |

c4's later uses of the object (base re-lead at `0x37de349`)
still never reach the pair region: a write-back memcpy of
`0x118` bytes *into* `[obj+0x0..0x118]` from `[rsp+0x17e0]`, a
read of `[obj+0x0..0xb0]` to `[rsp+0x3d60]`, a `0x90`-byte copy
of `[obj+0x8..0x98]` followed by passing obj+8 as `rcx` to the
vtable call `[r14+0x28]` (head region only, callee not traced),
and 11 small loads through an obj+0x39 base covering object
offsets `0x18..0x54` only.

c3 is the exception that keeps the chain alive: it passes the
object as `rsi` to `0x37fb9e0` (`0x326e5a6`, with
`rdi = [rsp+0x290]`, `rdx = r15`) and never reads
`[obj+0x1f0..0x2a0]` itself.

### The forward target: same shape, then the destructor

`0x37fb9e0` (`rbx = rsi`, the object) repeats the shape: three
memcpys from the object base with lengths `0x108`, `0xe0`,
`0xb8` (to `[rsp+0x1a0]`, `[rsp+0x1448]`, `[rsp+0x1338]`), then
reads the end marker `[rbx+0x12a0]` (`0x37fbbab`; the builder
caller's `0xff`) and compares it against `0x13`, branching to
the `0x37fc644` block family when greater. All of those blocks
converge on the join block at `0x37fd237` (`rbx += 0x108`,
then `[r14] = [rsp+0x1338]` for `0x110` bytes), which falls
through to the tail: `[r14+0x110..0x12a8] = [rsp+0x1a0..0x1338]`
(`0x1198`), then `rdi = rbx` passed to destructor `0x37f7070`
(`0x37fd272`), and the function returns `r14`. The unwind path
instead passes `rbx + 0x108` (the +0x108 sub-object) to the same
destructor (`0x37fd830`). On no path does `0x37fb9e0` read
`[obj+0x1f0..0x2a0]`.

### The destructor: a walk that reads but never dispatches

`0x37f7070` (`rbx = rdi`, the object) guards its loop on
`[rdi+0x198] != 0` (`0x37f707e`, `je` skips the loop), then
iterates `r12` from `0x1b0` to `0x11b0` in steps of `0x10`,
loading per iteration `r15 = [rbx+r12-0x18]` (pair cell) and
`r13 = [rbx+r12-0x10]` (pair element). The walked range
`[rbx+0x198..0x11a8]` fully contains the pair array
`[rbx+0x1f0..0x2a0]`; the oc pair is loaded at iteration
`r12 = 0x228` (`[rbx+0x210]` cell, `[rbx+0x218]` element).
Per pair, the loop loads exactly three element slots and acts
on two guards:

- `rax = [r13+0x0]`; if nonzero, `call rax` with `rdi` = cell.
- `rsi = [r13+0x8]`; if nonzero, `call free` (GOT `0x576e010`)
  with `rdi` = cell.
- `rax = [r13+0x10]` is read only when `[r13+0x8] != 0`.

For table elements (`{0, 0, 1, fn, fn, fn}`), `[element+0x0] =
0` and `[element+0x8] = 0`, so both guarded actions are skipped
on every iteration — including the oc pair's. The element
function slots `[element+0x18]` (oc3), `[element+0x20]` (oc2),
`[element+0x28]` (oc1) are never loaded anywhere in the
destructor (full-FDE operand census: the only element-relative
loads are `[r13+0x0]`, `[r13+0x8]`, `[r13+0x10]`). The
destructor also frees a `[rbx]`/`[rbx+0x8]` vector and runs
sub-destructors at `[rbx+0x18]`, `[rbx+0x48]`, `[rbx+0x88]`,
then advances `rbx += 0xe8` and tail-jumps to `0x37f57c0` —
none of which touches the pair region either.

## Inferences (separated from observations)

- #172's "chain goes cold" needs the correction above: the pair
  array is not dead stack — it is carried in the returned object
  past the builder's caller, through one indirect-call boundary
  (c3) and one forward function, to a destructor that reads it.
- The residue's observability still ends there on this chain:
  every consumer that touches the pair array reads it only as
  (cell, element) pointers and takes no action on table-shaped
  elements. A dispatch through element 6 would need a consumer
  that loads `[element+0x18/0x20/0x28]`; none was found on this
  chain.
- The shape is caller-specific, as in #170: four of five indirect
  callers never touch the pair region at all, and the fifth only
  forwards it. Reader verdicts must be per-caller, not per-shape.

## Limitations

- The zero-RIP-reference census rests on the documented full
  `.text` objdump census, not on a generator proof (the generator
  proves the E8/E9 scan, the relocation scan, and the init/fini
  scan, and verifies every recorded instruction byte; it does not
  disassemble). A checker can reproduce the RIP census by
  grepping the full `.text` disassembly for the target address.
- The destructor loop's guard value (`[obj+0x198]`) is not
  statically determined for this object: it comes from the
  builder caller's `[rsp+0x330]`-equivalent region, whose writer
  was not traced. If the guard is zero, the loop is skipped and
  the pair array is not even read; if nonzero, the loop reads
  every pair but still dispatches nothing for table elements.
- c4's vtable forward (`[r14+0x28]`, obj+8 as `rcx`) is reported
  with its span but its callee is not traced; it receives only
  the head region (`[obj+0x8..0x98]` copy), never the pair region.
- Direct-call and RIP scans cover `.text` only; `.plt` stubs hold
  no reference to the target (the only relocation is the GOT
  slot). Static analysis only; no node execution, so no runtime
  values of any pair slot are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.got` uses VA − 0x2000; `.rela.dyn` entries are 24 bytes at
file offset `0x6bc0` (entry 75886 is the GOT slot). The generator
fails loudly on any digest, relocation, call-scan, or byte
mismatch.

```sh
# the escape memcpys and marker (builder's caller)
objdump -d -M intel --start-address=0x4e7d5ac --stop-address=0x4e7d5dd \
  artifacts/node/94/hl-node
# a GOT-indirect call site (c1)
objdump -d -M intel --start-address=0x2446b13 --stop-address=0x2446b19 \
  artifacts/node/94/hl-node
# the forward target's marker read and tail
objdump -d -M intel --start-address=0x37fbbab --stop-address=0x37fbbb2 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x37fd251 --stop-address=0x37fd277 \
  artifacts/node/94/hl-node
# the destructor loop
objdump -d -M intel --start-address=0x37f707e --stop-address=0x37f70d2 \
  artifacts/node/94/hl-node
python3 tools/pair_array_escape.py --out /tmp/pa-esc
diff -r /tmp/pa-esc research/work-items/RE-004-pair-array-escape-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/pair_array_escape.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/pair_array_escape.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- What fills the destructor loop's guard slot `[obj+0x198]` for
  this object — i.e. does the destructor loop actually run over
  the pair array on the c3 route, or is it skipped? That needs
  tracing the builder caller's `[rsp+0x330]`-equivalent writer
  (the `[rsp+0x88]` sub-object's +8 field at the builder-call
  site).
- What is the `0x574be20` object, and what do its 6 neighborhood
  references (`0x4e77xxx` region, carried from #172) do with it?
- Which runtime initializer fills `.data` objects `0x5786838`
  and `0x5786858` (carried from #169), and what does the
  `[r14+0x8]` callee family write? Settling either would resolve
  the trioB vtable header-0/2/3 extents and the header-1-nonzero
  `[0x68]` slot.

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — escape arithmetic, reachability census, segment inventory, counts
- `escape.tsv` — 7 rows: builder-caller memcpys, marker, pair/oc-pair landing offsets
- `callers.tsv` — 5 rows, one per indirect caller (FDE, GOT site, object base, memcpy triples, verdict)
- `forward.tsv` — 8 rows: forward-target memcpys, marker read, join, tail, destructor calls
- `dtor.tsv` — 10 rows: destructor guard, loop bounds, loads, oc-pair iteration, coverage
- `segments.txt` — 28 rows: 26 claim segments (377 bytes) + 2 anchor segments (44 bytes, #172's claims re-cited)
- `MANIFEST.sha256` — digests of the 7 files above
