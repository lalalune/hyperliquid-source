# RE-001: node #115 checked power-of-ten scale select 0x5a01110

Task RE-001. Bounded question: what does the whole 507-byte
routine at `0x5a01110` (FDE `0x5a01110..0x5a0130b`) do with its
three arguments — an object pointer in `rdi`, a value in `rsi`,
and a reference in `rdx` — end to end, including its two
non-returning exits?

## Answer, pinned to the target binary

The routine returns one power of ten in `rax`, computed from
both integer arguments and gated by a checked decomposition of
the value against the object. In order:

1. **Scale cascade on the reference.** Starting from the
   reference in `rdx`, the routine computes
   `10 ** max(0, digits - 5)`, where `digits` is the reference's
   decimal digit count (a reference of 0 yields 1). The cascade
   is literal: direct compares against 10⁵…10⁹ assign
   1, 10, 100, 1000, 10000; the 10¹⁰…10¹³ bands are tested by
   shifting the reference right by 10…13 and comparing against
   9765625, 48828125, 244140625, 1220703125; the tail compares
   against 10¹⁴ − 1 and 10¹⁵ − 1 and then directly against
   10¹⁶…10¹⁹, taking the assigned band value as a
   (power − 1) constant that a shared `inc` at `0x5a01260`
   completes — including the 10¹⁸ band, where a `cmovb` reloads
   10¹⁴ − 1 before the same increment. The model transcribes
   the cascade instruction by instruction, and the tests prove
   the transcription equal to the closed form on every band
   boundary and on seeded random inputs.
2. **Checked decomposition of the value.** The value in `rsi`
   is divided by 10000 with the magic multiplier
   `0x346dc5d63886594b` (the quotient is the 128-bit product
   shifted right by 75; the remainder is
   value − quotient·10000). The quotient is compared against
   the qword at object `+0x50`, and the remainder against the
   qword at object `+0x10`. If the quotient differs, or the
   remainder is not strictly below the `+0x10` field, the
   routine takes the unwrap exit below — the table is not read
   on that path.
3. **Table byte.** Only after the check passes, the routine
   reads one byte at `*(object +0x8) + remainder·32 + 0x1d`:
   a table of 32-byte entries indexed by the remainder, the
   byte at offset `0x1d` of the entry. A byte of 7 or more
   takes the subtract-overflow exit below. A byte `b` in 0..6
   contributes `10 ** (6 - b)`, computed by exponentiation by
   squaring over the bits of `6 - b` (×10, ×100, ×10000, with
   early exits).
4. **Combine.** The result is the *smaller* of the cascade
   power and the table power: `cmp %rcx,%rdx` + `cmovb` at
   `0x5a012df` keeps the table power only when it is below the
   cascade power. The single `ret` is at `0x5a012ea`.

## The two panic exits

Both exits are indirect calls through relocated slots, and the
routine's bytes end immediately after the second one — the
compiler treats both as non-returning.

- **Unwrap exit** (`call *0x64df830` at `0x5a012f8`). The slot
  carries an `R_X86_64_RELATIVE` relocation to the shim at
  `0x1680c10` (shipped whole as `panic_unwrap.txt`). The
  routine passes `rdi` = `0x64768a8`, a static location record:
  its first qword relocates to `0x437df7`, the string
  `l1/src/perp_meta.rs` (19 bytes), and the packed line/column
  qword is 163 / 38. The shim substitutes the fixed message
  `called \`Option::unwrap()\` on a \`None\` value` (43 bytes
  at `0x46e992`) and calls the forwarder at `0x1680e60`
  (through the slot at `0x64df730`; shipped whole as
  `panic_encode.txt`), which rewrites the message length
  `len -> 2·len + 1` and calls the payload builder at
  `0x1680e80` (through the slot at `0x64df6b8`; shipped whole
  as `panic_unwind.txt`).
- **Subtract-overflow exit** (`call *0x64df848` at
  `0x5a01305`). The slot relocates to the shim at `0x1681e40`
  (shipped whole as `panic_sub_overflow.txt`). The routine
  passes `rdi` = `0x6478258`, a second location record for the
  same file, line 287, column 28. The shim substitutes the
  fixed message `attempt to subtract with overflow` (33 bytes
  at `0x46eb80`), passing the pre-encoded length
  `2·33 + 1 = 67` directly to the same payload builder at
  `0x1680e80`. This is the checked `6 - b` subtraction of
  step 3 surfacing: the byte's domain is exactly 0..6.

The panic locations name the source file `l1/src/perp_meta.rs`
— this routine belongs to the node's perp-metadata code, and
both of its failure modes are source-level panics in that file
(an unwrap on a failed lookup at line 163, a checked
subtraction at line 287), not generic traps.

## Transfers

The routine's own control transfers are exactly two indirect
calls (the two panic exits above), no direct call, and no tail
jump of any kind; every internal jump lands inside the
routine. It has no landing-pad block of its own in the shipped
window: the FDE ends at `0x5a0130b`, immediately after the
second panic call. Its first instruction is `push %rax` — it
does not begin with `endbr64`, consistent with being reached
only by direct calls.

## Consumers (site-only)

The census finds exactly 24 direct call sites in 20 caller
functions, no tail jumps, no stored qwords, and no RELATIVE
addend for the routine address itself. Every site moves three
registers into `rdi`/`rsi`/`rdx` within a few instructions of
the call (see `callers.tsv` for the per-site moves). One caller
sits immediately before the routine (`0x5a00f53`, inside
`0x5a00e70..0x5a00fb1`); the rest cluster in the
`0x517xxxx`, `0x543xxxx`, `0x58fxxxx`–`0x591xxxx` and
`0x5a2xxxx`–`0x5a3xxxx` ranges.

## What is not claimed

What the object, its table, or its fields denote beyond the
pinned offsets and reads; what the table byte encodes beyond
its pinned range 0..6 and the `10 ** (6 - b)` contribution;
what any caller does with the returned power; behaviour on a
null object pointer or a table pointer that does not cover the
remainder's entry (the binary faults on the same reads; the
model takes the byte through a lookup and does not invent
table contents); and the panic runtime past the payload
builder at `0x1680e80` (shipped whole; its own callee is not
modelled).
