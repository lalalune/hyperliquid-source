# RE-001: node #115 scaled pair total 0x5f09a50

Task: RE-001. Bounded question: what does the 183-byte function at
0x5f09a50 compute from its object and its two pass-through
arguments, and how do its two subobjects contribute?

## Source binary and commands

- Binary: `work/hl-node-115.bin`, node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (matches `provenance/artifacts.json`, path
  `artifacts/node/115/hl-node`).
- Main excerpt, verbatim as objdump emitted it:
  `objdump -d --start-address=0x5f09a50 --stop-address=0x5f09b07 work/hl-node-115.bin`
- Frames: `objdump --dwarf=frames work/hl-node-115.bin`, FDE at
  .eh_frame offset `0x358a5c` (length `0x40`, CIE 0, no LSDA, no
  landing pad). The excerpt file holds the whole function; no
  instruction was edited, reordered or replaced. Mnemonics such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- Regenerate with `export_excerpts.py`; check with `verify.py`
  (digest, provenance, manifest, excerpt regeneration, sampled
  instructions byte-for-byte against a fresh objdump run and the
  raw binary, frames, census, model tests).

## Semantics, stated literally

Arguments: rdi = object, rsi and rdx = pass-through arguments.

1. First subobject: rdi' = qword at object + 0xa50. Let
   fn1 = qword at (qword at rdi') + 0x68. If fn1 equals the
   sentinel address 0x5f04d70, the call is skipped and the
   running total starts at 0 (0x5f09a80). Otherwise the window
   calls fn1(rdi', rsi, rdx) and the total is that result
   (0x5f09aa9).
2. Second subobject: rdi'' = qword at object + 0xa58. Let
   fn2 = qword at (qword at rdi'') + 0x68. If fn2 equals
   0x5f04d70, nothing is added; otherwise the window calls
   fn2(rdi'', rsi, rdx) and adds the result to the total in
   64-bit wrapping arithmetic (0x5f09b00..0x5f09b05).
3. If the total is 0, the window returns (rax = 0, rdx = 0)
   (0x5f09a8e path).
4. Otherwise cap = qword at object + 0xa70. If cap is 0, the
   window returns (0, 0) as well (0x5f09acf..0x5f09ad9).
5. Otherwise clamped = min(total, cap), computed by
   `cmp %rbp,%rsi; cmovbe %rsi,%rbp` at 0x5f09ae2..0x5f09ae5
   (move when the cap is unsigned below-or-equal to the total).
6. scale = (qword at object + 0xa68) / cap, unsigned division
   with a zeroed high half (0x5f09af0). The remainder is
   discarded. The window returns rax = scale * clamped
   (64-bit wrapping `imul`) and rdx = clamped.

So the observable behavior is a complete pipeline, not a
fragment: two gated virtual contributions, summed, then
clamped to a per-object cap and scaled by a per-object
quotient. The Python model in `tools/scaled_pair_total_115.py`
implements exactly steps 1-6, and
`tests/test_scaled_pair_total_115.py` covers both-default,
single-contribution, both-contribution, zero-total, zero-cap,
exact-cap, quotient-vs-field, wrapping-add and packet checks.

## Callers / consumers

`census.py` finds 4 direct calls of 0x5f09a50, no tail jumps,
no whole-file qword hit and no RELATIVE slot (see `records.json`).
Each site was confirmed as a real `e8` call in objdump output:

- 0x5d6424c inside function 0x5d64100..0x5d6434d
- 0x5d646b0 and 0x5d64a1e inside function 0x5d643b0..0x5d64ce1
- 0x5f130ca inside function 0x5f13090..0x5f130ff (the neighbour
  just below the two-list aggregate 0x5f13130 mapped by #2182)

The callers' own internals were not read this cycle, so only
their call sites are claimed, not their purposes.

## Unknowns, recorded separately from observations

- The identities of fn1 and fn2 are by contract only: the
  window never names them, it only compares their pointers
  against 0x5f04d70 and calls them. 0x5f04d70 itself was read
  this cycle: it is 7 bytes (`endbr64; xor eax,eax; ret`),
  i.e. a stub returning 0 — so skipping it contributes exactly
  0, the same value a call would have returned, and the model's
  default-as-0 treatment is grounded, not assumed.
- The meanings of the + 0xa68 and + 0xa70 fields (dividend
  and cap) are not established by this window alone; the model
  takes them as inputs and names them only by offset.
- Whether a subobject pointer or its record pointer may be
  null is not guarded in-window: a null would fault on the
  first load, so the model assumes non-null subobjects.
- The window has no stack canary, no PLT call and no GOT
  load; its only rip-relative instruction is the `lea`
  computing the sentinel constant 0x5f04d70 itself.
