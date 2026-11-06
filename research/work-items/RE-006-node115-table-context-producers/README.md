# RE-006 — node 115: table-context producers (gate edge 1, the ctx side)

Question: for the six context-embedded call sites pinned by
RE-006-node115-family-callers (PR #2652), the gate's table argument
is `lea [ctx+0x90]` — a table embedded inside a context object.
Who makes those ctx objects, and what fills the embedded table's
header at `ctx+0x90` (record base at `+0x20`, record count at
`+0x28`, i.e. `ctx+0xB0` / `ctx+0xB8` in ctx-relative offsets)?

Where the question comes from (RE-006-node115-family-callers,
README):

> "it also pins, for every call site, where the callee's table
> argument (`rcx`, the argument each inner body frame-saves and
> forwards as the gate's `r8`) comes from — the first fixed rung
> of #2608's open edge 1, the producer of the gate's table."

> "Table-argument provenance stops at each call site's last
> writer. Where the context at `+0x90`, the frame slots, and the
> forwarded registers themselves are filled — the table's
> producer, #2608's open edge 1 — remains open"

and its open edge 2:

> "The table behind the gate (#2608 edge 1, unchanged): who
> writes the `0x158`-stride records and the `+0x20`/`+0x28`
> header of the structure whose pointer this packet traces one
> level down."

This packet traces ctx backwards from the six callers — caller by
caller, the way the family packet traced the table argument — and
does not repeat the discarded gate-table preservation scan
(12,365 immediate-`0x158` sites, 334 `imul` FDEs, no
discriminator).

Headline answers:

- **No traced body creates ctx.** Across three fully censused
  levels — the 6 caller bodies, their 12 direct-call sites
  (9 frontier bodies plus 3 intra-family large→small edges), and
  the frontier bodies' 23 direct-call sites — ctx is always
  forwarded from a caller's own argument: as `rdi`, as `rsi`, as
  `[rsi]`, as `r8` (the six mid bodies all take ctx in `r8`), or
  reloaded from the frame slot where the body saved `[arg0]`.
  No allocation call and no store to the table header occurs in
  any of these bodies.
- **Three of the level-2 paths converge on one storage shape.**
  The three bodies `0x2d23610` / `0x5a06600` / `0x5a04e40` (one
  per mirror family) each obtain ctx as `[P+0x450]`, where `P`
  arrives as their `rsi`. Each of the three has exactly one
  caller — a 224-byte once-getter clone (`0x2774590` /
  `0x56186c0` / `0x56185e0`) — which passes `P = [Q+0x20]`, where
  `Q` is a `0x28`-byte descriptor its own caller builds on its
  stack. In the once-getters' four call sites, `P` itself is
  `[X+0x50]` on two paths, the embedded sub-object `X+0x6b0` of
  a heap object on one, and on the fourth (`0x2b1df60`) the
  embedded sub-object at `+0xd18` of a parent object the caller
  builds in its own frame (there `Q` is assembled at
  `[rsp+0x80]`, and the `P` store lands at `[rsp+0xa0]`).
- **The ctx install is not a plain scalar store anywhere in the
  binary.** A validated census of every non-frame store to a
  `+0x450` field finds exactly 14: two `+0x438`→`+0x450` field
  copies, three stores into embedded sub-objects, one store of
  the static constant `0xf6401a`, two stores of a packed-tag
  value returned by the 15-byte helper `0x5f54680`
  (`(rsi << 0x3e) | rdi`), and six plain field loads forwarded
  into `+0x450`. None stores a freshly allocated object, so the
  write that installs ctx into `[P+0x450]` goes through a form
  this census does not cover (bulk/vector copy or an indexed
  store) — or the field is written before `P` is reachable from
  these paths.
- **The table header is not written by any traced body either.**
  Scalar stores to `[reg+0xB0]` / `[reg+0xB8]` in the traced
  bodies: zero. The only touches are three `movups` stores, one
  per P-body, each inside a clone-shaped bulk copy that fills a
  small record's `+0x30..+0xF8` span from frame slots; the
  destination is a frame-reloaded pointer not identified as ctx,
  and the copy's `+0xB8` slot is one field of that record, not
  the gate table's count. Whether the record base at `ctx+0xB0`
  is a static table or a heap allocation is therefore **not
  fixed by this packet** — that part of edge 1 stays open, one
  level further up than where this trace stops.

Per-site closed range (all six context-embedded sites):

| site (call) | caller body | ctx at level 0 | closed through |
|---|---|---|---|
| `0x2a8a054` | `0x2a8a000` (851 B) | own `rdi` | frontier `0x2a892f0` / `0x2c31c70`, P-funnel via `0x2d23610` |
| `0x2be7e17` | `0x2bdf8f0` (46,769 B) | `[arg0]` via frame `0x18(%rsp)` | frontier `0x2bdf270` (`rdi`), then `0x2d23610` |
| `0x54b3288` | `0x54a9c70` (51,762 B) | `[arg0]` via frame `0x18(%rsp)` | frontier `0x5483f50` (`[rsi]`), P-funnel via `0x5a06600` |
| `0x54bf8a9` | `0x54b66b0` (50,232 B) | `[arg0]` via frame `0x18(%rsp)` | frontier `0x5483850` (`[rsi]`), P-funnel via `0x5a04e40` |
| `0x55a1e32` | `0x55a1de0` (612 B) | own `rdi` | frontier `0x55a05d0` / `0x55746e0`, P-funnel via `0x5a06600` |
| `0x55a20a2` | `0x55a2050` (612 B) | own `rdi` | frontier `0x55a03c0` / `0x5573d40`, P-funnel via `0x5a04e40` |

(`records.json` carries every censused site's register bindings;
bodies up to 2 KB are exported in full, larger bodies are
digest-pinned in `frames.txt` with their site rows in the
records.)

Open edges that remain:

1. The install edge: which body writes the ctx pointer into
   `[P+0x450]`, in a form other than a plain scalar store
   (bulk/vector copy or indexed addressing are the candidates
   this packet's census cannot see), and which body allocates
   the ctx object (at least `0x39b8` bytes: field reads reach
   `ctx+0x3f08` / `ctx+0x4a78` in the large callers) and writes
   the `+0x90` table header — record base at `ctx+0xB0`, count
   at `ctx+0xB8`. Static-vs-heap for the record base is decided
   there, not here.
2. The level-2 paths that do not pass through the P-funnel:
   the mid bodies' callers forward ctx in `r8` from their own
   `r15`/`r14`, and the wrap515 bodies' large callers
   (`0x2a84e60`, `0x5585290`, `0x5582180`, `0x54cfa90`,
   `0x54d57b0`) hold ctx in `r13` or a frame slot; their inputs
   are the next level up on those branches.
3. #2608's remaining edges (unchanged), and the record writers
   of the `0x158`-stride array itself (the append path), which
   neither this packet nor the family-callers packet classifies.
