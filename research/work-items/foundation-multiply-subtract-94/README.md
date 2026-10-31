# Foundation multiply-subtract store 0x565eea0 (node #94)

## Question

Bind one small, previously unclaimed window in node #94: a multiply-subtract
store whose rule reads directly from its own bytes. No component, type, or
caller-purpose claim is made.

## Target

- Release: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (91,774,280 bytes, digest and signature verified by `make verify`).
- Window: `[0x565eea0, 0x565eeba)`, 26 bytes, `.eh_frame` section offset
  `0x2dc47c`, confirmed with GNU `objdump --dwarf=frames`.
- Stride: 6 bytes of `nop`/`nopl` alignment padding (`90`, `0f 1f 44 00 00`)
  — not int3 — to stride end `0x565eec0`. The stride is not the FDE extent;
  the checker locks the body and the padding separately.
- Next FDE starts exactly at `0x565eec0` (range 129 bytes to `0x565efe9`,
  section offset `0x2dc490`). That next window is a different window and is
  not analyzed here.

## Scope

Included: this window's own bytes, its own FDE record, its stride padding,
its two direct call sites, and the relocation scan for this window.
Excluded: any census of similar windows, any shared routine, any caller
purpose beyond call site and argument setup, any component or type mapping,
and any progress gate (none requested, none claimed).

## Reproduce

```sh
objdump -d --start-address=0x565eea0 --stop-address=0x565eeba \
  artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node | grep 565eea0
python3 tools/foundation_multiply_subtract.py --check \
  research/work-items/foundation-multiply-subtract-94/evidence.json
python3 -m unittest tests.test_foundation_multiply_subtract
```

## Observations

Decoded behavior, verified from bytes, zero calls, zero branches:

```
endbr64
mov %rdx,%rax        # save the scalar
imul (%rsi),%rdx     # rdx = scalar * in[0], low 64 bits only
mov (%rdi),%r10      # load out[0]
sub %rdx,%r10        # subtract the product
mov %r10,(%rdi)      # store out[0]
mov %rax,0x8(%rdi)   # store the scalar to out[1]
repz ret
```

Rule: `out[0] -= scalar * in[0]` (mod 2^64, low product only);
`out[1] = scalar`. No return value is set: `rax` holds the saved scalar at
`ret`, but no return meaning is claimed.

Sharp edges, all locked by the checker:

- `imul r/m64` discards the high word of the product: with scalar
  `2^64 - 1` and input `2`, the kept product is `2^64 - 2`, so
  `0 - (2^64 - 2)` wraps to `2`.
- The entry second output word is never loaded: the store to `out + 0x8`
  unconditionally overwrites it with the scalar.
- The input's second word is never read: only `(rsi)` is loaded.

Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
exactly two direct `e8` call sites — `0x564a9fe` and `0x564aa26` — each
confirmed as an instruction start by linear disassembly from its caller FDE
start. Both sit in caller FDE `0x564a900..0x564ab48`. This scan is
explicitly not a complete xref census. Caller purpose beyond call site and
argument setup is not claimed.

Data edge: no relocation record of any type in any `.rela.*` section names
this window as addend (full-section scan). Absence of a naming relocation
does not identify the window's provenance.

## Adjacency, stated explicitly

This window is the next FDE after packet #37's window: #37's window is
`0x565ee40..0x565ee9b` with a 5-byte stride ending exactly at `0x565eea0`,
where this window starts. The two windows are adjacent but different:
#37 subtracts a 192-bit scalar product with a conditional add-back and a
scalar-or-scalar-minus-one top word; this window subtracts a single 64-bit
low product and stores the scalar. No shared routine is claimed.
The caller FDE `0x564a900..0x564ab48` also holds two of #37's call sites;
that shared caller is observed call-site evidence only, not a routine claim.

The RE-001 gap inventory lists gap `0x565ee9b–0x565eea0`, which ends where
this window starts. That gap line is not a claim about this window (same
precedent as packet #28's gap artifact).

Note on the unwind table: `.eh_frame` also contains longer overlapping
records (for example `0x565eaa0..0x565ec0b` at section offset `0x2dc404`)
that span this window's range. This packet locks only its own narrow record
at `0x2dc47c` (`0x565eea0..0x565eeba`); the overlapping records are not
analyzed and no claim is made about them.

## Inferences (kept separate from observations)

- The label "multiply-subtract store" is an inference from the observed
  instruction sequence, not a source-level function name.
- Argument roles (`rdi` = out pointer, `rsi` = in pointer, `rdx` = scalar)
  are inferred from operand positions, not from any type or signature.

## Unknowns

- The meaning of the input words, the output words, and the scalar.
- The identity or purpose of the caller in FDE `0x564a900..0x564ab48`.
- Why this window sits immediately after packet #37's window, and whether
  the two windows are related in any source-level sense.

## Limits

- The byte-pattern scan is not a complete xref census.
- The absence of a naming relocation does not identify provenance.
- GNU objdump prints this window under a nearest-symbol label with a
  tens-of-megabytes offset; that is stripped-binary arithmetic, not an
  identity.
- No stdlib type, source-level function, operand meaning, or caller purpose
  is claimed anywhere.
- The reference tree was a search lead only; no inferred implementation was
  copied, and every claim is grounded in target bytes for node #94.
- Static analysis only. The captured binary was never executed; no network,
  chain action, or signing was involved.
