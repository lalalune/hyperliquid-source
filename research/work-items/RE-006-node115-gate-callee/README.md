# RE-006 node 115: the gate callee behind slot 0x64e71b8 is a checked decimal-scaling primitive

PR #2605 packeted the two inner bodies `0x2bbbba0` / `0x2bbd0b0`
and recorded that each of them calls the body behind GOT slot
`0x64e71b8` twice per cursor item, requiring return value 1 (any
other return becomes failure code 7 in the body's result struct).
This packet pins that callee, every call site of the slot in the
binary, and what the two per-item calls each guard.

Headline answers:

- The callee (`0x434f790..0x434f901`, 369 B) is **not a
  predicate over its inputs alone**: it is a checked
  decimal-scaling primitive. It computes
  `Q = (A × C) / (100 × 10^d)`, where `d` is a byte difference
  read out of a table its fifth argument points to, returns
  `rax = 1` iff `Q < floor(2^64/100)`, and returns **Q itself in
  `rdx`** on the only return path. Every one of the 89 call
  sites in the binary consumes that `rdx` result.
- The two per-item calls in each inner body guard **different
  product terms**, not the same check twice: a flag-0 call over
  the `[element+0x78]` product and a flag-1 call over the
  `[element+0x58]` product, with different rounding.
- The slot's call family is larger than #2605's two bodies: six
  inner-body FDEs carry the identical six-site pattern (36
  sites), including a third body next to the two packeted ones
  and a full mirror triple in the `0x549xxxx` clone family.

Target artifact: HL node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(105,896,032 bytes). Every address below is a virtual address in
that artifact; every body is pinned by FDE extent and SHA-256
digest, and every string or file offset is resolved through the
section table (`.rodata` identity-mapped, `.text` delta `0x1000`,
`.data.rel.ro` delta `0x2000`). GOT slot references are resolved
from raw instruction bytes, never from objdump comments.

## The gate callee

Slot `0x64e71b8` holds exactly one relocation
(`R_X86_64_RELATIVE`, addend `0x434f790`, initialised content 0).
The body `0x434f790..0x434f901` (369 B, digest prefix
`0929c3bc21a0`) is pinned by its full 103-row instruction census.

Argument contract (argument registers in SysV order):

| arg | use inside the body |
| --- | --- |
| `rdi` | value `A` (u64), one multiplicand |
| `rsi` | record index into the table |
| `rdx` | value `C` (u64), the other multiplicand |
| `rcx` | only the low byte is read (`mov %ecx,%ebx` at `0x434f7a3`): a rounding flag — 0 = truncate, nonzero = round up on remainder |
| `r8`  | table pointer: `[r8+0x20]` = record base, `[r8+0x28]` = record count |
| `r9`  | never read (no row in the body references it) |

The body makes **no stores at all** and exactly four memory
reads, all through the fifth argument or the record it selects:

- `0x434f799`: `cmp 0x28(%r8),%rsi` — the count;
- `0x434f7a5`: `mov 0x20(%r8),%rcx` — the record base;
- `0x434f7b0`: `movzbl 0x49(%rcx,%rsi,1),%eax` — record byte
  at +0x49, record stride `0x158`;
- `0x434f7b5`: `sub 0x48(%rcx,%rsi,1),%al` — record byte at
  +0x48, subtracted from the +0x49 byte.

Decision rule, stated testably. Let `count = [r8+0x28]`,
`base = [r8+0x20]`, `b48 = base[idx*0x158 + 0x48]`,
`b49 = base[idx*0x158 + 0x49]`:

1. If `idx >= count` (unsigned), the body **traps** (below)
   with the bounds Location. This check precedes every other
   read of the arguments' values.
2. Let `d = b49 - b48` as an unsigned byte difference. If
   `b49 < b48`, or the accumulated exponent check fails
   (`d > 19`), the body traps with the scale Location.
3. Otherwise `S = 10^d` (`d` in 0..19), built by binary
   decomposition of `d`: bit 0 contributes ×10, bit 1 ×100,
   bit 2 ×10000, bit 3 ×10^8, bit 4 ×10^16 (the last via a
   `movabs` of `0x2386f26fc10000` and an overflow-checked
   `mul`, which is what caps the range at 19).
4. `P = A × C` (full 128-bit `mul` at `0x434f7cd`). The body
   calls the 128-bit unsigned divider behind slot `0x64dfaf8`
   (addend `0x63efec0`, the body packeted by #2561) at
   `0x434f7f3` with `(P.lo, P.hi, (100*S).lo, (100*S).hi)`,
   giving `Q = P / (100*S)`.
5. If the flag byte is nonzero, `Q` is rounded **up** by one
   when the division left a remainder: the body recomputes
   `Q × (100*S)`, subtracts it from `P`, and adds
   `(remainder != 0)` into `Q` (`0x434f803..0x434f828`). With
   flag 0, `Q` stays the floor.
6. Return: `rax = 1` iff `Q`'s high half is zero **and**
   `Q < 0x28f5c28f5c28f5c` — the constant is exactly
   `floor(2^64/100) = 184467440737095516` (verified
   arithmetically by the tool) — else `rax = 0`. Either way
   `rdx = Q` when the single `ret` at `0x434f853` executes;
   `rdx` is loaded from the quotient at `0x434f847`. The scaled
   check is therefore equivalent to "does `(A × C) / 10^d`
   fit under 2^64", with the /100 on both sides cancelling and
   the flag selecting floor vs ceiling at the boundary.

Traps. The body has exactly one `ret` and no direct (E8) calls.
Both failure arms end in a call through slot `0x64df830`
(addend `0x1680c10`) with a static descriptor in `rdi`:

- bounds arm (`0x434f8f4`, reached only from the `jae` at
  `0x434f79d`): descriptor at `0x64768d8` — a panic Location:
  file `l1/src/spot_meta.rs` (pointer `0x432b6f`, length 19,
  read through the section table), line 119, column 33;
- scale arm (`0x434f8e7`, reached from the `jb` at
  `0x434f7b9` and from every fall-through of the exponent
  checks): descriptor at `0x6476a48` — file
  `l1/src/spot_meta.rs`, line 1206, column 57.

The callee at `0x1680c10..0x1680c29` (25 B, fully exported) is
the compiler's `Option::unwrap()` panic stub: it forwards the
descriptor in `rdx`, loads the fixed message
`called \`Option::unwrap()\` on a \`None\` value`
(`0x46e992`, 43 bytes) and calls the panic-formatting callee
behind slot `0x64df730` (addend `0x1680e60`); the byte after
its body is `0xcc` (`int3`) and there is no return path. So a
gate "failure" of either kind is a panic in the source, not a
returned error — the two Locations are the only attribution
the artifact carries for which checked conversion failed. The
panic-formatting callee itself is not pinned by this packet.

## Binary-wide census of slot 0x64e71b8

Method: a raw byte scan of `.text` for every rip-relative
reference form (`ff15` call, `ff25` jmp, REX and non-REX
`8b`/`8d` loads and leas) targeting the slot, then validation
of each candidate against the decoded instruction rows of its
containing FDE. The scan is a superset of every
instruction-boundary reference, so the negative is exact:

- **89 references, all `ff15` calls**, in **43 FDEs**; zero
  `jmp`, zero register loads, zero `lea`s of the slot anywhere
  in `.text`. Nobody takes the callee's address; it is reached
  only through the slot.
- The argument contract is the same at all 89 sites in shape:
  five argument registers are bound immediately before the
  call and the return is tested (`cmp $0x1,%rax` / `jne`,
  `test $0x1,%al` / `je`, or a preset failure code plus
  `cmp`/`jne`). The flag byte is an immediate 0 at 64 sites,
  an immediate 1 at 24 sites, and register-supplied at exactly
  one site (`0x3698891` in FDE `0x36961e0`, `movzbl %r14b,%ecx`).
- **All 89 sites consume the `rdx` result** within the
  following 16 instruction rows: the callee is never used as a
  pure predicate anywhere in the binary.
- 15 sites use it branchlessly: after `test $0x1,%al`, a
  `cmovne %rdx,...` keeps the scaled value only when the gate
  returned 1 (FDEs `0x2bfd0c0`, `0x2c32960`, `0x4215360`,
  `0x54e3740`, `0x54e3f00`, `0x54e5f90`, `0x54e6250`,
  `0x54eeea0`, `0x54ef0b0`, `0x5575680`, `0x5575f60`, …). In
  these callers `r8` is typically `lea [ctx+0x90]` — the table
  embedded in a context struct — where the inner bodies pass
  a frame-saved table argument instead.

Every census FDE is digest-pinned in `records.json` (45 bodies
total: the 8 exported ones below plus 37 digest-only census
FDEs), and every site's argument bindings (last writer of each
of `rdi`/`rsi`/`rdx`/`rcx`/`r8`/`r9` in the 16 rows before the
call), flag classification, next four rows, and `rdx`-use flag
are recorded per site.

## The inner bodies' two calls

The identical six-site pattern appears in six FDEs — two clone
triples of the inner-body family:

| body | size | #2605 status |
| --- | --- | --- |
| `0x2bbbba0..0x2bbc74d` | 2,989 B | inner_ca, packeted |
| `0x2bbc750..0x2bbd0a3` | 2,387 B | **third body, new to this packet** |
| `0x2bbd0b0..0x2bbdb9a` | 2,794 B | inner_s3, packeted |
| `0x5493080..0x5493c2d` | 2,989 B | mirror triple, digest-pinned here |
| `0x5493c30..0x549471a` | 2,794 B | mirror triple |
| `0x5494720..0x5495073` | 2,387 B | mirror triple |

At all 36 family sites the bindings are uniform: `rsi` = the
current cursor item (the body's item register, or its frame
slot in the `0x2bbc750` triple member), `rdx` = the looked-up
element's +0x10 field (a `mov 0x10(%<element>),%rdx` load in
the rows before the call), `r8` = the body's frame-saved table
argument (the body's own `rcx` argument, saved in the
prologue), and a return ≠ 1 branches to the body's code-7
failure arm (`mov $0x7,%cl` rows are pinned per body).

Within each body the six sites form exactly the two shapes
the per-item processing invokes — at site positions 2 and 3
the flag is 1, at positions 1, 4, 5, 6 it is 0:

- **Flag 0 — the +0x78 term.** `rdi` is the low half of the
  divider quotient of `[element+0x78] × [context+0x18]` over
  10^14 (the same product #2605 pinned), computed with the
  slot divider with `ecx = 0`. The gate then scales that term
  by the record's `10^-d` and the caller accumulates the
  gate's `rdx` into the phase accumulator.
- **Flag 1 — the +0x58 term.** `rdi` is the quotient of
  `[context+0x8] × [element+0x58]` over 10^14, **already
  ceiling-adjusted inline by the caller** (the caller
  recomputes the remainder itself), and the gate is called
  with flag 1 so its own division also rounds up. Its `rdx`
  accumulates into the other phase accumulator.

So the two per-item calls are not the same check repeated:
different element fields (+0x78 vs +0x58), different context
fields (+0x18 vs +0x8), different rounding modes, different
accumulators, and each can independently fail the item with
code 7. What they share is the index (`rsi` = the item), the
multiplicand source (`[element+0x10]`), and the table.

## Boundaries (precise negatives)

- The gate's decision is fully pinned as a rule, but two of
  its inputs are **runtime data**: the record bytes at
  `[r8+0x20] + idx*0x158 + 0x48/+0x49` and the count at
  `[r8+0x28]`. The artifact does not contain the table
  instance any caller passes, so no per-asset `d` value can
  be stated from static evidence; who builds the table
  (stride `0x158`, count at +0x28, base at +0x20) is an open
  edge below.
- The two unwrap Locations identify file, line and column
  only. Which source-level checked conversion each
  corresponds to is not named anywhere in the artifact.
- For the 37 non-family census FDEs this packet pins
  boundaries, digests and site bindings, not their internal
  semantics; the classification above (branch-to-failure vs
  branchless select) is mechanical, from the rows after each
  call.

## Open edges

1. The table behind the gate: who writes the `0x158`-stride
   records (bytes +0x48/+0x49) and sets the +0x20/+0x28
   header — the producer of the structure every gate call
   reads (the Locations name its source file
   `l1/src/spot_meta.rs`).
2. The third inner body `0x2bbc750` and the `0x549xxxx`
   mirror triple: their caller censuses — which sub-lookups
   or helpers invoke each clone, as #2605 did for the two it
   packeted.
3. The branchless-select callers: which running value the
   gate's `rdx` conditionally replaces in each, and whether
   a 0 return leaves a stale value or a defined default.
4. The one register-supplied flag site (`0x3698891`): where
   its `r14b` comes from, i.e. when that caller asks for
   ceiling instead of floor.
5. The panic-formatting callee `0x1680e60` behind slot
   `0x64df730`, shared by every unwrap stub of this shape.

## Verification

- `tools/gate_callee_static.py` regenerates this packet from
  the authenticated artifact and fails closed on any drift
  (all 45 body digests, the gate's and stub's full row
  censuses, 138 family pins, the census FDE set and every
  site's call row are re-derived and compared on each run).
  `python3 tools/gate_callee_static.py verify` prints
  `{"matches": true, "packet": "RE-006-node115-gate-callee"}`.
- `tests/test_gate_callee_static.py`: 6 tests — byte-for-byte
  regeneration, counters and verdict, wrong-artifact
  rejection, and three mutation tests (gate body, a family
  call site, a census-only FDE).
- MANIFEST.sha256 covers 11 entries; the isolated-root packet
  verifier reports "Verified 1 evidence-packet manifests and
  11 entries".
