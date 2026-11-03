# RE-015: node 115 flag-group first-byte writer in the large consumer 0x15a3b90

```text
Task: RE-015
Function: 0x15a3b90
Topic: who writes the flag group's first byte, and what values it can take
Input binary SHA-256: a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
Status: static evidence derived from authenticated native bytes
Executed: false
```

Why this item: the RE-015 pointer-formatter packet (#2440)
established that the pointer formatter `0x15eadd0` reads the
flag group's first byte exactly once, as an *unchecked* index
into two `.rodata` tables whose four established entries select
`0 → "Error"`, `1 → "Warn"`, `2 → "Info"`, `3 → "Debug"`, and
left open what value that byte takes on the chain call — who
writes that byte of the block the derived-byte callee's pair
record points at. This packet traces the block's construction
in the function that creates it: the large consumer
`0x15a3b90..0x15a6509`, which builds the four-byte flag group on
its own stack at `[rsp+0x14]` and passes its address in `rcx`
to the derived-byte callee `0x15ae430` at exactly four direct
call sites (a whole-`.text` census finds no others, binary-wide).

The answer: the consumer itself writes the first byte, at
exactly two immediate store sites, and every callee call is
gated behind one of them. A direct rsp-relative store census
over the whole 10,617-byte body (267 such stores) finds exactly
one store site per group byte — the cached flag byte at
`[rsp+0x16]` is stored at `0x15a3c55`, the derived byte at
`[rsp+0x15]` at `0x15a3c5e`, the loop counter byte at
`[rsp+0x17]` at `0x15a3d14` — and exactly two stores for the
first byte at `[rsp+0x14]`: `mov BYTE PTR [rsp+0x14],0x1` at
`0x15a3f10` and `mov BYTE PTR [rsp+0x14],0x0` at `0x15a420c`.
Each write is the entry instruction of a field segment whose
two callee calls it precedes: segment A
(`0x15a3f10..0x15a4023`, calls `0x15a3f5f`/`0x15a401e`) is
entered only through its gate's `jne` at `0x15a3ee2`, and
segment B (`0x15a420c..0x15a4321`, calls
`0x15a4263`/`0x15a431c`) only through its gate's `jne` at
`0x15a4161` or by fall-through past the repeated gate's `je`
at `0x15a4206`. Inside either segment window there is no
indirect store, no push/pop, and no store to the group byte
other than the segment's own entry write; every direct branch
into a segment interior originates inside that segment.

Composed with the pointer formatter's established selection
table, a chain call from field block A therefore selects
`"Warn"` (byte 1) and a chain call from field block B selects
`"Error"` (byte 0). Bytes 2 (`"Info"`) and 3 (`"Debug"`) are
never written by this consumer, and no out-of-range byte can
reach the formatter's unchecked index through this chain: the
only values the first byte can hold at a callee call are the
two immediates 0 and 1.

## Exact scope

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| consumer_large (owner) | `0x15a3b90..0x15a6509` | 10,617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |
| callee (boundary) | `0x15ae430..0x15ae5ae` | 382 | `4cfb1633d772df3d0e75abf5864ea242a85e7732e479b5351ae80c97842d7acf` |
| pointer_formatter (boundary) | `0x15eadd0..0x15eadff` | 47 | `4e4d3a1a67401cbceb6f4bdb72d100eca0676a13fa66f9c82f73f1a6d8d8aec3` |

Measured denominator: the complete owner FDE, **10,617 bytes**,
body-hash pinned with byte pins at every traced site and five
retained disassembly windows (group population, both segment
gates, both segments) covering every pinned site; the store
and branch censuses run over the fully decoded body, not over
the windows alone. Cited but not counted: the callee (pair
store pinned as a boundary: it stores the group pointer value
into its own frame at `0x15ae454` and does not store through
it) and the pointer formatter's two selection tables and four
strings (re-derived here only to bind index to name; the
formatter itself is owned by #2440).

Independence: the derived-byte-callee packet (#2396) already
pins the two first-byte store *instruction bytes* as sites (its
block A / block B tag stores) and records the group offsets,
but its records do not state the stored values, and it does
not prove the stores are the only writes to the byte, does
not prove the segment gating that makes them precede every
callee call, and does not compose the values with the
formatter's selection table. The scratch-name-pair packet
(#2317) pins the group bytes at `[rsp+0x15]`/`[rsp+0x16]` and
their branch use. This packet's claim is exactly the four
missing facts: the writer and its two values as recorded
data, the whole-body store census proving exclusivity, the
segment-entry gating proof, and the selection consequence
for the formatter's unchecked index.

## Trace stages

1. **Group population (head of the consumer).** Before its
   loop, the consumer builds three of the four group bytes:
   it loads the cached pair bytes from the cell at
   `0x64f01b0`/`0x64f01b1` (`0x15a3bc5`/`0x15a3bcc`/`0x15a3bcf`)
   and stores the flag byte to `[rsp+0x16]` at `0x15a3c55`;
   negates it, ORs in the input byte at `[rsi+0x4d]`
   (`0x15a3c59`/`0x15a3c5b`), and stores the derived byte to
   `[rsp+0x15]` at `0x15a3c5e`. At each loop head it stores
   the loop counter byte `cl` to `[rsp+0x17]` at `0x15a3d14`
   (counter reloaded from `[rsp+0x2c8]` at `0x15a3cf0`,
   incremented at `0x15a3cf8`, stored back at `0x15a3d1c`;
   initially zeroed at `0x15a3cc4`). The first byte at
   `[rsp+0x14]` is *not* written here — it is written only
   inside the two field segments below.
2. **Whole-body store census.** Decoding the full body and
   classifying every store: 267 direct rsp-relative stores
   and 81 indirect stores (through heap, map and allocation
   pointers). Exactly one direct store's byte range covers
   each of `[rsp+0x15]` (at `0x15a3c5e`), `[rsp+0x16]` (at
   `0x15a3c55`) and `[rsp+0x17]` (at `0x15a3d14`), and exactly
   two cover `[rsp+0x14]`: the immediate stores at
   `0x15a3f10` (value 1) and `0x15a420c` (value 0). No other
   direct store in the body can touch the first byte.
3. **Segment A gate and write.** The gate loads `r14` from
   `[rsp+0xc0]` (`0x15a3dbf`), later compares it against the
   sentinel `rbp = 0x8000000000000000` (`0x15a3edf`); the
   `jne` at `0x15a3ee2` jumps *to the write itself* at
   `0x15a3f10` when `r14 != sentinel`. On equality the flow
   runs a cleanup block that ends in an unconditional `jmp`
   to `0x15a44e0` (`0x15a3f0b`, after the conditional exit
   `je` at `0x15a3ef8`), so the write has no fall-through
   entry: it is reachable only through the gate branch, and
   the segment's two callee calls (`0x15a3f5f` via the
   sentinel-record variant, `0x15a401e` via the
   register-record variant selected by the derived-byte test
   at `0x15a3f1f`) both follow it, each with
   `lea rcx,[rsp+0x14]` (`0x15a3f52`/`0x15a400a`).
4. **Segment B gates and write.** Two gate blocks load `r14`
   from `[rsp+0x68]` (`0x15a4159`, repeated at `0x15a41fe`)
   and compare it against the sentinel (`0x15a415e`, repeated
   at `0x15a4203`). The first gate's `jne` at `0x15a4161`
   jumps to the write at `0x15a420c` when `r14 != sentinel`;
   on equality the flow passes through an intervening block
   and reaches the repeated gate, whose `je` at `0x15a4206`
   exits to `0x15a44e0` on equality and otherwise falls
   through *into the write*. Both entries are thus gated on
   the same comparison, and the segment's two callee calls
   (`0x15a4263`, `0x15a431c`; variants selected by the
   derived-byte test at `0x15a4220`, group `lea` at
   `0x15a4256`/`0x15a4308`) both follow the write of 0.
5. **Segment window scans.** For each segment, every direct
   branch whose target lies in the segment interior
   originates inside that segment (segment A: the field
   `jne` at `0x15a3f1d` and the derived-byte `je` at
   `0x15a3f24`; segment B: `0x15a421e` and `0x15a4225`), so
   no outside path can enter past the write. The only stores
   in each window are the segment's entry write and the
   record stores at `[rsp+0xc0]`/`[rsp+0xc8]`/`[rsp+0xd0]`;
   there is no indirect store and no push/pop in either
   window, so between the write and either callee call
   nothing overwrites or shifts the group byte.
6. **Selection consequence.** Re-deriving the pointer
   formatter's tables (length table `0x457fc0`,
   relative-pointer table `0x46a838`, strings read at their
   selected lengths) binds index 1 to `"Warn"`
   (`0x459e50`, 4) and index 0 to `"Error"` (`0x46a5c4`, 5),
   with 2 → `"Info"` and 3 → `"Debug"` as context. A chain
   call from block A therefore emits `"Warn"` and a chain
   call from block B emits `"Error"`, on exactly those calls
   where the callee takes its format path (its entry split
   on a nonzero `rsi` is owned by #2396 and cited). The
   formatter's unchecked index is provably in range for
   this chain: the index byte is an immediate 0 or 1 at
   every call that can reach it.

## Traced result

The flag group's first byte is a per-field constant written
by the large consumer itself: 1 for the first field block
and 0 for the second, each written as the first instruction
of a sentinel-gated segment whose callee calls it precedes.
That closes the last open end of the flag-group chain: the
record-0 dispatch through the pointer formatter emits
`"Warn"` for block-A calls and `"Error"` for block-B calls,
never `"Info"` or `"Debug"`, and the formatter's unchecked
table index cannot be driven out of range by this chain.

Reproduce from the repository root:

```bash
python3 -B tools/flag_group_first_byte_static.py
python3 -m unittest tests.test_flag_group_first_byte_static -v
```

Flag-group first byte only, in the large consumer
`0x15a3b90..0x15a6509`: the direct rsp-relative store census
over the whole body (exactly one store site per group byte;
exactly two immediate stores for the first byte, values 1
and 0), the two field segment gates and their entry modes,
the branch/store scans of the two segment windows, and the
composition of the two values with the pointer formatter's
established selection table. The store census covers direct
rsp-relative stores over the whole body and all stores
(direct or indirect) inside the two segment windows; the 81
indirect stores elsewhere in the body write through heap,
map and allocation pointers outside the segment windows and
are not claimed alias-free in general — the group address
itself is materialised only at the four lea sites inside the
segments, each after its segment's write, and is passed only
as the callee's rcx argument. Downstream, no function before
the pointer formatter dereferences the group pointer at all
(pointer formatter packet, #2440), so no downstream write
through the pointer can intervene. The callee's entry split
(its format path requires the consumer's rsi argument to be
nonzero) is owned by the derived-byte-callee packet (#2396)
and cited, not re-derived: this packet's selection claim
holds for every callee call, and reaches the formatter
exactly on those calls where the callee takes its format
path. What the two field blocks mean, what the gate words at
`[rsp+0xc0]` and `[rsp+0x68]` represent beyond the sentinel
comparison, and what the table method at descriptor `+0x18`
computes with the selected name are NOT established. The
next question is that table method (`0x141e8f0` for the
chain's consumer table) and its write behaviour — the other
open end of the chain. No captured code executed, no runtime
value, indirect-call recovery, #94 correspondence, or
reconstruction gate is claimed.
