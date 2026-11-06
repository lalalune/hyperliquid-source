# RE-001: min/max scan routine 0x5d52380 (node #115)

## Bounded question

What does the routine at `0x5d52380` do to the holder it takes in
`rsi` and the record it takes in `rdi`, and where is that routine used?

## Answer (established semantics)

The routine `0x5d52380` takes a record pointer in `rdi` and a holder
pointer in `rsi`, and returns the record pointer. It is a complete
behaviour end to end, not a lone-window fragment: the whole 592-byte
routine is pinned (including its landing pads and failure edges), its
circular-list scan, its emit call, its quotient computation, its
chain walk and its tail build are all pinned, and its 3 direct callers
across 3 caller functions are censused.

### Lock and circular-list scan

The routine first locks the `H+0x700` slot with the lock-shaped call
`0x606ca40`. It then walks a circular intrusive list: the sentinel
record is `[[H+0x68]+0x40]+0x110`, the first node is
`[sentinel+0x938]`, and each next node is `[node+0x938]`, until the
walk returns to the sentinel. If the first node is the sentinel
itself, the list is empty.

Per node, the routine reads the flag byte at `+0x3d` and the pair at
`+0x658` / `+0x660`. A node is skipped when its flag byte is nonzero.
Otherwise the node value is `v = min([node+0x658], [node+0x660])`
(unsigned minimum); a zero value is skipped. Across the qualifying
nodes the routine tracks `mn` (the running minimum, starting at -1)
and `mx` (the running maximum, starting at 0).

### Emit and unlock

- If no node qualified (`mn` still -1), the routine calls
  `0x5f3c510(H+0x18c8, 0, 0)`.
- Otherwise it calls `0x5f3c510(H+0x18c8, mn, mx)`.

It then unlocks the `H+0x700` slot with the unlock-shaped call
`0x60d52f0`, and zeroes the record: dword at `+0x00` = 0, word at
`+0x04` = 0, qword at `+0x08` = 0. Bytes `+0x06..+0x07` are not
written by this routine, so their values are not pinned here.

### Quotient (computed, not consumed)

In the non-empty case only, the routine then computes a quotient
from `mn`: `rbx = mn + 99`, then the multiply-shift sequence with
the constant `0x28f5c28f5c28f5c3` (`rbx >> 2`, multiply, `>> 64`,
`>> 2`) leaves `floor((mn + 99) / 100)` in `r8` for ordinary values
(verified: 1 -> 1, 100 -> 1, 101 -> 2, 12345 -> 124). That quotient
is not observably consumed anywhere else in this routine — no later
instruction in the routine reads `r8` — so it is recorded as a
computed-but-unconsumed value, not as an output. On 64-bit wrap
(`mn` within 99 of 2^64, so `mn + 99` wraps to 98 or less) the
quotient is 0 and the chain walk below is skipped.

### Chain walk (non-empty case, `mn + 99 > 99`)

When the walk is entered, it starts from the head at `[H+0x1790]`
with the sentinel `H+0x1788` and the base `H+0x1748`:

- If the head is null, the routine throws out_of_range immediately.
- Nodes carry a kind byte at `+0x20`, a `+0x10` link and a `+0x18`
  link, and a payload at `+0x28`. The walk descends via `+0x18`
  links while the kind byte is 2 or less; when it meets a node whose
  kind byte exceeds 2, it steps to that node's `+0x10` link and
  resumes; when a descent reaches a null `+0x18` link, it backs up
  to the node it last stepped from via `+0x10`.
- The walk ends at a node when that node is not the sentinel and
  its kind byte is 3 or less: the routine builds the stack temp by
  calling `0x5f22020(rsp, H+0x1748, 3, node+0x28)`.
- The walk throws out_of_range when it backs up to the sentinel
  itself, or when the node it ends at has a kind byte above 3.

The routine has no visited set, so a cyclic chain would loop forever
in the binary; the model reproduces the walk step for step and makes
the same assumption.

### Tail

When the chain walk is skipped (empty case, or the wrap corner), the
routine builds the stack temp by calling `0x5f20a00(rsp, H+0x1748,
3)` instead. In both cases it then assigns the temp into the record
with `0x5d49b10(record, rsp)`, frees the temp's heap buffer at
`[rsp+0x08]` with delete[] when non-null, checks the stack canary,
and returns the record pointer.

### Returns and failure edges

The single normal return is at `0x5d52567`, reached via the shared
epilogue at `0x5d5254a`. A canary mismatch reaches the
stack-failure handler at `0x5d525b3`. Two landing pads at
`0x5d525b8` and `0x5d525c4` save the in-flight exception in `rbx`
and jump to shared cleanup code at `0x5d52332` and `0x5d52352`
(outside this routine's FDE, not pinned here). The out_of_range
throw goes through the `__throw_out_of_range` PLT entry at
`0x5d525ae` (via the shared canary-checked path at `0x5d52597`).

### Inferred readings (separate from the observations above)

- The `0x606ca40` / `0x60d52f0` pair reads as lock / unlock of the
  `H+0x700` slot, from their call shape and argument; their
  internals are not pinned here.
- The `0x5f3c510` call reads as emitting the (min, max) pair, or
  (0, 0) for an empty scan, into the structure at `H+0x18c8`;
  its internals are not pinned here.
- The `0x5f20a00` / `0x5f22020` calls read as building a record
  from the base at `H+0x1748`, with the found node's `+0x28`
  field as the key in the found case; their internals are not
  pinned here.
- The holder's source-level name and owning class are not pinned.

### Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 3 direct calls + 0 tail jumps across 3 caller
FDEs (see callers.tsv); 0 stored qwords, 0 RELATIVE relocations —
reached only by code, never by data. Each caller site sets `rdi`
to a record and `rsi` to a holder immediately before the call.

## Evidence

- `main.txt`: whole-function verbatim objdump excerpt
  (`0x5d52380..0x5d525d0`), regenerated by `export_excerpts.py`.
- `frames.txt`: the routine FDE plus the 3 caller FDEs.
- `callers.tsv`, `relocations.txt`: the censuses above.
- `records.json`: semantic records only (no per-instruction list).
- `verify.py`, `census.py`, `export_excerpts.py`: the packet's own
  runnable checkers, committed in the packet.
- Binary: `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  as bound in `provenance/artifacts.json`.
- Objump command: `objdump -d --start-address=0x5d52380
  --stop-address=0x5d525d0 work/hl-node-115.bin` (header
  normalized to the bare binary name only).
- Note: mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders;
  verify.py checks every excerpt line byte-for-byte against the
  raw binary.

## Unknowns (not claimed)

- What the emit callee `0x5f3c510` does inside `H+0x18c8`.
- What the temp builders `0x5f20a00` / `0x5f22020` and the assign
  callee `0x5d49b10` do beyond their call shapes and arguments.
- Why the quotient is computed but not consumed in this routine.
- The source-level meanings of the list nodes' `+0x658` / `+0x660`
  pair, the flag byte at `+0x3d`, and the chain nodes' kind byte.
