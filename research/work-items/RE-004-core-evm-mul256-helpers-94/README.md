# RE-004: the two 256-bit multiply helpers behind the core-to-EVM scaling loop in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made;
  the reference submodule was empty in this worktree
- Claim status: observation for the instructions, constants, windows,
  caller census and evaluated behaviour; inference for the flag
  semantics, the copy-1/copy-2/3 divergence and the consequence for
  #158's model; unresolved items are listed under Results and limitations
- Scope included: the two helpers' full bodies, trim trees, pair loops,
  carry propagation, epilogues and terminal panic blocks; the 14-site
  caller census; the copy-2/3 caller zeroing idiom; the 21-case
  adversarial grid (both helpers' models plus closed-form arithmetic)
- Scope excluded: the scaling handlers' loop bodies (#157/#158/#159
  packets), the non-scaling callers' bodies (recorded with enclosing
  FDE only), the panic callee's body beyond its range check and panic
  string, the exact role of the terminal blocks' rcx struct argument,
  and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel --no-show-raw-insn`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/core_evm_mul256_helpers94.py --out research/work-items/RE-004-core-evm-mul256-helpers-94
python3 -m unittest discover -s tests -p 'test_core_evm_mul256_helpers94.py'
(cd research/work-items/RE-004-core-evm-mul256-helpers-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x27a1150 --stop-address=0x27a1630 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4de5500 --stop-address=0x4de59d0 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the E8 census scan walks .text).
Outputs: `evidence.json`, `sites.tsv`, `loop_cases.tsv` and `windows.txt`.
The analysis completed and was not limited by a timeout.

## Evidence

Coordinates are ELF virtual addresses. The #158 packet mapped the
non-negative scaling loop at call-site level: three handler copies
(0x2715320, 0x4d0a6d0, 0x4d0bfa0) each call a 256-bit multiply helper
and fold its overflow signal into the loop flag, and #158 explicitly
left the helpers' inner schoolbook loops undecod­ed. This packet maps
those inner loops. The two helpers share a skeleton but differ in one
trim, and that one trim makes their overflow signals disagree.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the helper bodies are
transcribed byte-for-byte in `windows.txt` and hashed in
`evidence.json`. FDE bounds are unwind-described ranges, not validated
function boundaries. The trilogy end is the next FDE start, not the
exact `.eh_frame` record end.

| Helper | FDE (readelf) | Trilogy end | Length | SHA-256 (trilogy window) |
| --- | --- | --- | --- | --- |
| helper-1 | 0x27a1150..0x27a162f | 0x27a1630 | 1248 | 7f75ff37b1ecfcf33aade0a848fa4f4c9389a1504dd3981625510c8311379801 |
| helper-2 | 0x4de5500..0x4de59ca | 0x4de59d0 | 1232 | 189ebebb967715ee4bdec2501a1df85621c602d73466dc56d6f230cadbdef472 |
| panic callee | 0x157a6f0..0x157a7b8 | 0x157a7c0 | 208 | 6e28765c0de61365b02b65a2c923390287cf7d3781b90bfa798c2e9044a75fbe |

**Signatures (inference from prologue and call sites).**

| Helper | Signature | Overflow signal |
| --- | --- | --- |
| helper-1 | `(out: *mut u8[33], a: *const u64[4], b: *const u64[4])` | byte at `out+0x20`, conservative |
| helper-2 | `(out: *mut u64, count: u64, a: *const u64, b: *const u64) -> al` | `al` return, exact |

Helper-1 zeroes a 32-byte stack accumulator at entry (two `movaps`
xmm stores at 0x27a1164/0x27a1169) and copies the full 32 bytes plus
the flag byte to `out` at the epilogue, so `out` is fully written
regardless of input. Helper-2 accumulates directly into `out`: it
never zeroes `out`, it only adds into `out[shift..]`, and `out[0..shift]`
is never written. Its callers must therefore zero the out buffer; the
copy-2/3 scaling handlers do, with a `movdqa` pair directly before the
call (verified at the first copy-2 acc call, 0x4d0abd6/0x4d0abdf,
which writes xmm2 to `[rsp+0x120]` and `[rsp+0x110]` before
`call 0x4de5500` at 0x4d0abfb with `rsi = 4`).

**Shared skeleton (observation).** Both helpers: low-limb trim of `a`;
high-limb trim of `a`; trim of `b`; pair-unrolled schoolbook
multiply-accumulate (`mul` + `add`/`adc` chains, two limbs per inner
iteration, plus an odd-limb tail); carry propagation beyond the
accumulator; overflow accumulation into a flag; epilogue stores; a
terminal panic block. The outer loop is pointer-bounded (exit when the
outer pointer reaches the recorded end pointer), not count-bounded.
`r11` is decremented per outer iteration and `rbp` (initially
`r11*8`) decreases by 8 per iteration, with the inner window sized as
`min(r11, rbp/8)` plus a carry bit.

**The one trim that differs (observation).** Helper-1's `a` high-trim
chain (0x27a11b5/0x27a11fa/0x27a157e/0x27a1597/0x27a15a6) checks
`a[3]`, `a[2]`, `a[1]`, `a[0]` and sets only `dl` (0 when any limb is
nonzero); it never modifies `r15`, so helper-1's `a` count stays at
`4 - a_skip` even when `a` has high zero limbs. Helper-2's `a`
high-trim loop (0x4de55af/0x4de5664/0x4de5670/0x4de58f3) reduces `r9`
to the true significant count of the trimmed `a`. Everything else
about the flag follows from this.

**Flag semantics (inference, verified by faithful block-level
simulation on the 21-case grid).**

- Helper-1's flag is set at 0x27a13bb (`mov dl,1; mov [rsp],rdx`)
  whenever the outer head (0x27a138f) finds `r11 < r12`, where `r12`
  is the larger count and `r11` starts at `a_count - b_skip` and
  decrements per iteration. Because helper-1's `r12` uses the
  untrimmed `a` count (`4 - a_skip`), `r11 < r12` holds on the second
  outer iteration for every multi-limb input in the `jbe` case, and
  on the first iteration whenever `b` has a low zero limb. The flag is
  also set by carry propagation past the accumulator (0x27a145e
  block) and by the `r11 == 0` multiply-entry path (0x27a131c).
  Net: helper-1's flag is sound (flag 0 implies the product fits) but
  inexact (flag 1 does not imply overflow). It reports overflow for
  essentially every multi-limb multiply, even when the product fits.
- Helper-2's flag is set at 0x4de574a (`mov al,1`) under the same
  `r11 < r12` condition, but helper-2's `r12` is the true larger
  significant count, so the condition reduces exactly to true
  overflow: the room at the last outer iteration is
  `5 - a_skip - b_skip - min(a_sig, b_sig)`, which drops below the
  inner width `max(a_sig, b_sig)` exactly when
  `a_sig + b_sig + a_skip + b_skip > 5`, i.e. exactly when the
  product needs more than 4 limbs. The carry path (0x4de57fe block)
  fires exactly on carry past `out[3]`. Net: helper-2's `al` is exact
  overflow on every in-scope input.
- Both helpers return the product mod 2^256 correctly on every
  in-scope input: the L2 window truncation only ever drops inner
  limbs whose contributions land at `out[4]` or beyond, i.e. genuine
  overflow limbs. The value is right even when helper-1's flag is a
  false positive.

**Caller census (observation, re-derived by the tool from an E8 rel32
scan of `.text`).** 14 direct call sites: helper-1 has 6, helper-2 has
8. The scaling sites are the three per copy that #158 mapped (acc,
square, final); the remaining sites are recorded with enclosing FDE
only, not mapped, following #158's honesty rule for other-caller sites.

| Helper | Call site | Enclosing FDE | Role |
| --- | --- | --- | --- |
| helper-1 | 0x2715834 | 0x2715320..0x2716bc0 | scaling (copy-1 acc) |
| helper-1 | 0x271589b | 0x2715320..0x2716bc0 | scaling (copy-1 square) |
| helper-1 | 0x27159e0 | 0x2715320..0x2716bc0 | scaling (copy-1 final) |
| helper-1 | 0x279d1fc | 0x279d0c0..0x279d3e0 | other |
| helper-1 | 0x279d2ab | 0x279d0c0..0x279d3e0 | other |
| helper-1 | 0x279d51a | 0x279d3e0..0x279d5e0 | other |
| helper-2 | 0x4c90193 | 0x4c900a0..0x4c901e0 | other |
| helper-2 | 0x4c994ff | 0x4c99440..0x4c995c0 | other |
| helper-2 | 0x4d0abfb | 0x4d0a6d0..0x4d0bfa0 | scaling (copy-2 acc) |
| helper-2 | 0x4d0ac78 | 0x4d0a6d0..0x4d0bfa0 | scaling (copy-2 square) |
| helper-2 | 0x4d0add6 | 0x4d0a6d0..0x4d0bfa0 | scaling (copy-2 final) |
| helper-2 | 0x4d0c4cb | 0x4d0bfa0..0x4d0d870 | scaling (copy-3 acc) |
| helper-2 | 0x4d0c548 | 0x4d0bfa0..0x4d0d870 | scaling (copy-3 square) |
| helper-2 | 0x4d0c6a6 | 0x4d0bfa0..0x4d0d870 | scaling (copy-3 final) |

**Terminal panic blocks (observation).** Each helper's only internal
`call` is to GOT slot 0x576e2e0 (helper-1 at 0x27a1547, helper-2 at
0x4de58e6). The slot carries relocation `R_X86_64_RELATIVE` to
internal address 0x157a6f0 (not a PLT import). The callee's body builds
a stack struct and calls GOT 0x576e098 with `rdi` = the `.rodata`
string at 0x1f8cd2, which reads as a Rust slice-index panic message
("range start index ... out of range for slice of length ..."). Both
helpers' terminal blocks pass constant args (`edi` = 1, `esi` = 0,
`edx` = 0, `rcx` = 0x56c23d0 for helper-1 / 0x5746f10 for helper-2)
and the callee's check fails for those constants, so both blocks are
terminal panic paths. Normal exit is by pointer comparison to the
epilogue. The `0x27a15b2` arm (`lea rax,[r15-4]; cmp rax,1; sbb
edx,edx`) in helper-1's `a` high-trim chain appears unreachable given
the preceding branches (all-four-limbs-zero is already excluded by
the low-trim path taken) and is reported as a retained-but-dead arm.
The `r11 == 0` paths (helper-1 0x27a131c/0x27a1568, helper-2
0x4de58ec) are reachable: they fire when `a_skip + b_skip == 4`
(the product's lowest limb index is 4) and report flag 1.

**Case grid results (observation).** 21 cases in `loop_cases.tsv`,
covering single-limb, low/high zero limbs on both sides, internal
zero limbs, max values, the `2^128 x 2^128` boundary, the
`2^256 - 1` square, the #158 k=5 square and acc step, and helper-2's
nonzero out prefix. Both helpers' values match closed-form 256-bit
arithmetic on all 21 cases (helper-2's two prefix rows differ by
design: the prefix is preserved and product-position limbs accumulate
-- `out[0]` stays 99, and `out[1]` becomes 8 + 35 = 43 -- which is why
helper-2's value matches closed form on 19/21 rows, not 21/21).
Helper-2's flag is exact on 21/21 rows. Helper-1's flag is exact on
only 11/21 rows; it diverges from helper-2's flag on 10/21 rows, every
one a false positive (flag 1, true overflow 0). The divergences are:
`b_low_zero` (5 x 7*2^64), `b_zero` (product 0, flag 1 via the `r11
== 0` entry), `two_limb_fit`, `square_1p64`, `pow10_32_square`,
`one_times_pow10_32`, `both_low_zero`, `pow2_128_times_pow2_127`,
`internal_zero_fit`, and `max_single_limb_pair`.

## Inferences

- The helpers are two implementations of one 256-bit multiply
  contract (product mod 2^256 plus an overflow signal), differing in
  the `a` high-trim: helper-1 keeps the untrimmed count, helper-2
  reduces to the significant count. The flag divergence is a direct
  consequence of that one difference, not of different loop shapes:
  the L1/L2/imul/carry structure is the same in both.
- Consequence for #158's model (inference from these helpers'
  semantics, not a re-verification of #158): #158 treats both
  helpers' signals as exact overflow. For copies 2/3 that treatment
  is correct (helper-2's `al` is exact), so their success path keeps
  #158's `d <= 77`. For copy-1 it is not: copy-1 folds helper-1's
  conservative byte, so copy-1 takes the fallback whenever any
  acc x base or base x base step is multi-limb. The first such step
  is at k=5: the acc step when bit 5 is set, and the square step
  (base = 10^32, two limbs) in any case, since the loop reaches k=5
  exactly when `d >= 32`. So copy-1's success path covers `d <= 31`,
  not `d <= 77`. For `d` in [32, 77], copy-1
  takes the #159 float fallback while copies 2/3 return the exact
  power of ten: the three handler copies diverge in that range.
  This packet does not modify #158's packet; the correction is
  reported to the run owner for a decision on #158's PR #1669.
- Helper-1's false-positive flag is fail-safe for the scaling loop
  (it routes to the fallback, never to a wrong success value), but
  it is not free: for `d` in [32, 77] copy-1 returns the #159
  fallback double instead of the exact scaled amount.

## Results and limitations

- The flag divergence is established by two independent routes: a
  manual block-by-block trace of both helpers' outer heads, and
  faithful block-level simulations reproducing the flag behaviour
  on all 21 grid cases (the simulations are embedded in the
  generator and independently reimplemented in the tests).
- The value correctness claim (product mod 2^256) rests on the same
  simulations plus the L2 truncation argument (dropped contributions
  land at `out[4]` or beyond); it is not an execution of the node
  binary, which this task forbids.
- Out of scope, by precondition, not by oversight: inputs with
  `a_skip + b_skip > 4` (the `r11` count wraps and the real code
  reads/writes past the operand/out window); inputs where the
  caller's out buffer is not zeroed for helper-2 (the product limbs
  accumulate into stale contents); and the non-scaling callers'
  bodies. The scaling handlers never produce `a_skip + b_skip > 4`
  for `d <= 77` (loop operands `acc` and `base` have low skips of at
  most 1 each, so their sum is at most 2; the final multiply's
  amount operand has skip 0 unless the amount is zero) and they zero
  the out buffer before helper-2 calls.
- Unresolved: the exact role of the terminal blocks' `rcx` struct
  argument (0x56c23d0 reads as u64 LE `[0, 100, 0x1700000071, 0]`);
  whether the `0x27a15b2` dead arm is ever reachable through a path
  this trace missed; the bodies of the non-scaling callers; and
  whether helper-1's conservative flag affects any non-scaling
  caller (their flag use was not mapped).
- The `imul` single-limb tail (helper-1 0x27a151b, helper-2
  0x4de58ba) keeps only the low 64 bits of the single product. In
  the L2 path's context the dropped high part lands at `out[4]` or
  beyond (same truncation argument as above), so it does not change
  the value; it is reported here rather than assumed.

## Next question

- Do the non-scaling callers (the 0x279d... and 0x4c90.../0x4c99...
  sites) use helper-1's byte / helper-2's `al` as exact overflow, and
  does helper-1's false positive change their behaviour the way it
  changes copy-1's scaling loop? That is the natural follow-up: it
  decides whether the conservative flag is a scaling-loop-only quirk
  or a wider behavioural difference between the two helpers.
