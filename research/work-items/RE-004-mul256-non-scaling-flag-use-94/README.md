# RE-004: how the non-scaling callers consume the mul256 helpers' overflow signals in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Worktree baseline: HEAD 2993e46 (upstream sync forbidden for this run)
- Source commit / reference commit: n/a — no reference-tree claim is made
- Claim status: observation for the call sites, flag tests, sentinel
  stores, branches, FDE bounds and window digests; inference for the
  caller outcome models (faithful translations of the add/adc and
  sub/sbb chains) and for the false-positive consequence; unresolved
  items are listed under Results and limitations
- Scope included: the five non-scaling call sites of the #160 mul256
  helpers (three helper-1 sites in two sibling FDEs, two helper-2
  sites), their flag-consumption idioms, the sentinel propagation
  chains, and the 18-case outcome model
- Scope excluded: the helpers' inner loops (the #160 packet), the
  scaling handlers' loop bodies (#157/#158/#159 packets), the host
  functions' wider purpose and operand provenance, the second callee
  at caller-C (`0x4de4190`, FDE recorded only), the bit-length tail
  at caller-D beyond its branch structure, and node #115

## Reproduce

Platform: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (`-d -M intel`).
Run from the repository root. The binary is read and disassembled, never executed.

```
python3 tools/artifacts.py verify
python3 tools/mul256_non_scaling_flag_use94.py --out research/work-items/RE-004-mul256-non-scaling-flag-use-94
python3 -m unittest discover -s tests -p 'test_mul256_non_scaling_flag_use94.py'
(cd research/work-items/RE-004-mul256-non-scaling-flag-use-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x279d0c0 --stop-address=0x279d3e0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x279d3e0 --stop-address=0x279d5e0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4c900a0 --stop-address=0x4c901e0 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4c99440 --stop-address=0x4c995c0 artifacts/node/94/hl-node
```

The tool checks the input SHA-256 first and fails on a mismatch. It takes
about 20 seconds (the E8 census scan walks .text).
Outputs: `evidence.json`, `sites.tsv`, `cases.tsv` and `windows.txt`.

## Evidence

Coordinates are ELF virtual addresses. The #160 packet mapped the two
256-bit multiply helpers' inner loops and proved their overflow signals
disagree: helper-1 `0x27a1150` returns a CONSERVATIVE byte at `out+0x20`
(flag 1 does not imply overflow), helper-2 `0x4de5500` returns an EXACT
`al` (flag 1 if and only if overflow). The #160 packet left open what
the five non-scaling callers do with those signals. This packet answers
that question: the two helpers' flags are consumed asymmetrically, and
helper-1's conservatism is NOT fail-safe here.

**Boundaries.** The FDE bounds come from the binary's own unwind index
(via the repository shared ELF parser); the caller bodies are hashed in
`evidence.json` and `windows.txt`. FDE bounds are unwind-described
ranges, not validated function boundaries.

| Caller | FDE | Length | SHA-256 (FDE window) |
| --- | --- | --- | --- |
| caller-A | 0x279d0c0..0x279d3e0 | 800 | a2562dc539e8cef1365c9b8105c2d48edb4f69d658ca45a9b945fdc8ee19475e |
| caller-B | 0x279d3e0..0x279d5e0 | 512 | 699ed69f6e7784da5203ada2405da554a0faed1b8a07cc6d223d59d83ed3ad3a |
| caller-C | 0x4c900a0..0x4c901e0 | 320 | c1488b1cdd0010cc09d00b5233153fbfa955b6eea69817db3aa1ea6e1f37fbea |
| caller-D | 0x4c99440..0x4c995c0 | 384 | 869ba83530bbca3f01f2df357a1c42032946cc3def53ac8726ebba0a2562d6a8 |

**Caller census (observation, re-derived by the tool from an E8 rel32
scan of `.text`).** The full census is the same 14 sites as #160 (6
helper-1, 8 helper-2); the five non-scaling sites are:

| Call site | Enclosing FDE | Helper | Consumption |
| --- | --- | --- | --- |
| 0x279d1fc | 0x279d0c0..0x279d3e0 | helper-1 | flag byte tested, sentinel -1 |
| 0x279d2ab | 0x279d0c0..0x279d3e0 | helper-1 | flag byte tested, sentinel -1 |
| 0x279d51a | 0x279d3e0..0x279d5e0 | helper-1 | flag byte tested, sentinel -1 |
| 0x4c90193 | 0x4c900a0..0x4c901e0 | helper-2 | `al` never tested, discarded |
| 0x4c994ff | 0x4c99440..0x4c995c0 | helper-2 | `al` tested, early return 0 |

**Helper-1 sites: the flag is load-bearing, and the sentinel is -1
(observation).** All three sites share one idiom. Caller-A call 1
(out `[rsp]`, flag at `[rsp+0x20]`, test at 0x279d201) and call 2
(same out, test at 0x279d2b0); caller-B (out `[rsp+0x8]`, flag at
`[rsp+0x28]`, test at 0x279d51f). After each call the code sets all
four product registers to -1 (`mov ...,-1` block) and skips the
product load on flag != 0 (`jne` to the add/sub chain). So flag = 1
means the true product is discarded and replaced by -1 in every limb.

**Sentinel propagation (observation).** Caller-A adds the two
(effective) products with an add/adc chain; if the 4-limb sum carries
out, the sum is replaced by -1 (0x279d317 block). Caller-A and
caller-B then subtract the (effective) sum/product from the stored
4-limb value at `[rbx+0x40..0x58]` with a sub/sbb chain; if the top
stored limb is below the subtrahend's top limb, or the subtraction
borrows out, the result is replaced by 0 (0x279d362 / 0x279d587
blocks). Both callers then bump the counter at `[rbx+0x60]`
(increment, -1 on wrap) when the state byte at `[r14+0x294]` is 1,
and set bit 0x4 at `[rbx+0xb0]`.

**Helper-2 site caller-C: `al` is discarded (observation).** The
out buffer (8 limbs at `[rsp+0x80]`, count 8) is zeroed before the
call at 0x4c90193, as helper-2 requires. The very next instruction
is `mov rdx,rsp`; the code then calls `0x4de4190` (FDE
0x4de4190..0x4de5500, body not mapped) and stores from `[rsp]`.
No `test al,al` or any `al` read appears between the helper-2 call
and the second call, which clobbers `al`. The exact flag is
irrelevant to this caller.

**Helper-2 site caller-D: `al` is load-bearing and exactly right
(observation).** The out buffer (4 limbs at `[rsp]`, count 4) is
zeroed before the call at 0x4c994ff. Immediately after: `test al,al`
at 0x4c99504, `jne 0x4c9952e`, which returns eax = 0. On flag = 0 the
code adds 10 to the product (low limb compared against -10, carry
propagated with adc); if that addition carries out of the top limb,
it also returns 0 (`jae` falls through to the same return-0 block).
Otherwise it continues to a bit-length tail (bsr over the limbs from
the top; tail semantics out of scope).

## Inferences

- **Any helper-1 flag = 1 collapses caller-A and caller-B results to
  exactly 0.** Proof sketch from the translated chains: flag = 1
  replaces a product by -1; -1 plus anything is -1 with carry-out
  exactly when the other operand is nonzero, and -1 plus zero is -1
  without carry, so the effective sum/product is -1 in every case;
  and stored - (-1) always trips the zero rule — either the top
  stored limb is below -1 (every value except top limb = -1), or
  the subtraction borrows out (every stored value except the
  all-ones value, whose difference is 0 anyway). There is no
  stored-value corner that escapes to stored+1: the borrow-zero
  rule, not the arithmetic, decides. The case table verifies this
  across stored = (1000,100,100,0), (0,0,0,-1) and all-ones.
- **That collapse is a real behavior change on false positives,
  not a graceful fallback.** Case A2: helper inputs (5,0,0,0) x
  (0,7,0,0) — a fitting product (0,35,0,0) that helper-1 flags 1
  (#160's b_low_zero row) — with stored (1000,100,100,0) gives
  collapsed 0 against a flag-free 965,65,100,0. Case B2 is the same
  shape (collapsed 0 vs 1000,65,100,0). In the scaling loop (#158)
  a helper-1 false positive only reroutes copy-1 to the #159
  fallback double, a usable approximate value; here it destroys
  the result entirely. The conservative flag is fail-safe for
  scaling and fail-destructive for these callers.
- **On true overflow the same collapse is the designed path.**
  Cases A6 (max_times_two) and B5 (top_limb_product) collapse to 0
  with flag = 1 and true overflow; the sentinel path is doing what
  it was built for. The defect, if any, is not the sentinel but the
  flag's conservatism feeding it.
- **Caller-D cannot false-positive, and caller-C cannot care.**
  Caller-D's early return 0 fires exactly on true overflow because
  helper-2's `al` is exact, and its +10 carry path is a second,
  independent exact check. Caller-C ignores `al` altogether, so
  neither helper's flag semantics affect it. The asymmetry is
  complete: of the five non-scaling sites, three are corrupted by
  helper-1 false positives, one is exactly right, one is
  indifferent.

## Results and limitations

- The outcome models are faithful translations of the add/adc and
  sub/sbb chains, verified against the disassembly instruction by
  instruction for the flag, sentinel, carry and borrow paths; they
  are not executions of the node binary, which this task forbids.
- The case table's helper-behavior rows (products and flags) are
  reused from the #160 packet's loop_cases.tsv, whose block-level
  simulations established them; this packet does not re-derive the
  helpers' inner loops.
- Out of scope, by precondition, not by oversight: the host
  functions' wider purpose and operand provenance (what the stored
  value and the state byte mean); the second callee at caller-C;
  the bit-length tail at caller-D; the non-scaling callers' behavior
  under helper inputs outside #160's grid (e.g. `a_skip + b_skip > 4`
  inputs, where #160's precondition already excludes the helpers).
- Unresolved: whether any upstream caller of caller-A/caller-B
  distinguishes the collapsed 0 from a genuine 0 difference (that
  would decide whether the collapse is user-visible); the identity
  of the second callee at caller-C; whether the three helper-1
  sites' shared prologue (operand selection via cmovb against the
  `[r14+0x240..0x250]` values) constrains which helper inputs can
  actually reach them.

## Next question

- Do caller-A/caller-B have upstream callers that treat the
  collapsed 0 as a valid difference, and can the helper-1 flag
  inputs that reach them actually be multi-limb (the false-positive
  trigger)? That decides whether this is a live misbehavior or a
  latent one.
