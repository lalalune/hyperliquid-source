# RE-001: map node #115 twin signed-field getters 0x5eeb400/0x5eeb430 with their leaves 0x5f12a10/0x5f12a20

## Bounded question

Immediately below the mapped getter run at 0x5eeb490..0x5eeb741,
the binary holds a pair of adjacent getters that read the same
member at outer + 0x788 and delegate to the same sub-object at
member + 0x8f0: what signed field does each getter return, and how
do the two leaves it calls differ? This packet pins the whole
behavior end to end, not lone-window fragments: both getters whole,
both leaves whole, and every census-confirmed caller of each window.

## Windows

- Getter A: 0x5eeb400..0x5eeb427 (39 bytes), FDE at .eh_frame
  offset 0x356ef4, length 0x18, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb426; the `int3` padding from 0x5eeb427 is excluded.
- Getter B: 0x5eeb430..0x5eeb457 (39 bytes), FDE at .eh_frame
  offset 0x356f10, length 0x18, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb456; the `int3` padding from 0x5eeb457 is excluded.
- Leaf A: 0x5f12a10..0x5f12a1c (12 bytes), FDE at .eh_frame offset
  0x358eb0, length 0x10, CIE 0 (no LSDA). Ends at the `ret` at
  0x5f12a1b; the `int3` padding from 0x5f12a1c is excluded.
- Leaf B: 0x5f12a20..0x5f12a2c (12 bytes), FDE at .eh_frame offset
  0x358ec4, length 0x10, CIE 0 (no LSDA). Ends at the `ret` at
  0x5f12a2b; the `int3` padding from 0x5f12a2c is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb400 --stop-address=0x5eeb427 work/hl-node-115.bin
objdump -d --start-address=0x5eeb430 --stop-address=0x5eeb457 work/hl-node-115.bin
objdump -d --start-address=0x5f12a10 --stop-address=0x5f12a1c work/hl-node-115.bin
objdump -d --start-address=0x5f12a20 --stop-address=0x5f12a2c work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All
four windows start with `endbr64`; every mnemonic in the excerpts
is genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter A 0x5eeb400

Arguments (outer, out) in (rdi, rsi). It loads the member at
[outer + 0x788], forms arg = member + 0x8f0, calls leaf A
0x5f12a10 with that arg, sign-extends the leaf's 32-bit return
(`cltq`), stores it to *out, and returns 1 unconditionally. No
null check anywhere.

### Getter B 0x5eeb430

Identical shape, calling leaf B 0x5f12a20 instead of leaf A:
member = [outer + 0x788], arg = member + 0x8f0, *out =
sign_extend(leaf_B(arg)), return 1 unconditionally. No null check
anywhere.

### Leaf A 0x5f12a10

Argument (arg) in rdi. It loads inner = [arg + 0x8] and returns
the signed 32-bit value at [inner + 0x10] in eax. The leaf sets
only eax; the upper 32 bits of rax are whatever the caller left,
but both getters immediately apply `cltq`, so the observable
stored value is always the clean sign extension of the 32-bit
field. The leaf has no other effect.

### Leaf B 0x5f12a20

Identical shape, reading a different field of the same inner
object: inner = [arg + 0x8], return the signed 32-bit value at
[inner + 0x28] in eax. Same `cltq` cleanup by the caller.

### The twin structure

The two getters differ only in which leaf they call, and the two
leaves differ only in the field offset they read (0x10 versus
0x28) from the same inner object at [arg + 0x8]. Together they
are a pair of signed projections of two fields of one inner
object, reached through the member + 0x8f0 sub-object of the
outer + 0x788 member.

## Census (summary; full scan in census.py output)

- Both getters: 0 direct calls, 0 tail jumps, 0 qword hits in
  .text, 0 whole-file qword hits, 0 RELATIVE addends
  (virtual-getter shape, as in #2228/#2229/#2263/#2264/#2265/
  #2268/#2279/#2293). They are reached through a vtable slot,
  not by a direct call.
- Leaf A: 16 direct calls, 0 tail jumps, 0 qword hits, 0 RELATIVE
  addends. One call is getter A at 0x5eeb416; the other 15 are
  listed by site and containing function in records.json. Those
  other callers' internals were not read and nothing is claimed
  about them beyond the call site.
- Leaf B: exactly 1 direct call (getter B at 0x5eeb446), 0 tail
  jumps, 0 qword hits, 0 RELATIVE addends. Getter B is its sole
  direct caller.

## Boundaries, stated openly

- The neighbouring getter at 0x5eeb460 calls 0x5f132a0, which
  open PR #2228 already maps as a predicate gate; it is NOT
  re-claimed here, only noted as the adjacent boundary.
- The getter at 0x5eeb3a0 (member + 0x788, no +0x8f0 step) and its
  stub 0x5d8c9c0 to 0x5f90da0 belong to a different sub-object
  and were not examined; nothing is claimed about them.
- The leaves' non-getter callers are census sites only. In
  particular, leaf A is a shared leaf: its other 15 call sites
  pass their own arguments, which this packet does not pin.
- The inner object's identity (what struct lives at [arg + 0x8])
  is not named: the packet pins only the two field offsets and
  the sign-extension behavior.
- The model raises KeyError on a missing field, mirroring a
  fault in the binary, which has no null checks.

## Verification

Run from the repository root:

```
python3 research/work-items/RE-001-twin-signed-field-getters-115/verify.py
python3 tests/test_twin_signed_field_getters_115.py
```

verify.py prints ALL CHECKS PASSED only when the digest, the
manifest, the excerpt regeneration, the sampled instruction
bytes, the frames, the census, the call-site raw bytes and the
model tests all pass. pytest is not installed on this VM, so the
pytest-style test file runs under plain python3 via its `__main__`
runner. `make doctor` fails on missing providers here and
`make verify` / `make catalogue-check` fail on the LFS-pointer
artifact here; both are pre-existing environment limits, stated
honestly, and this packet binds to the materialized
work/hl-node-115.bin instead.
